// HALFKEY final program round: v2 escrows (integrator share, finisher tip, claim_to, direct
// payout), deposit-address orders (SOL -> XMR), direct-pay proofs with a payment id, open offers,
// integrator accounts, the pay-link owner's `ready`. Byte layouts mirror program/src/{escrow2,
// deposit,direct,offer}.rs.
import { sha256 } from '@noble/hashes/sha256';
import { keccak_256 } from '@noble/hashes/sha3';
import { concatBytes } from '@noble/hashes/utils';
import { ed25519 } from '@noble/curves/ed25519';
import { Connection, PublicKey, SystemProgram, TransactionInstruction, SYSVAR_INSTRUCTIONS_PUBKEY } from '@solana/web3.js';
import * as P from './program.ts';
import * as K from './keys.ts';
import * as X from './xmrproof.ts';
import { pdaV15, proofTerms } from './v15.ts';

export const IXF = { LOCK3: 42, CLAIM_TO: 43, FILL_DEPOSIT: 44, ORDER_REFUND: 45, PROVE_DIRECT: 46, INTEGRATOR: 56, OFFER_OPEN: 57, OFFER_TAKE: 58, OFFER_SETTLE: 59 } as const;
export const MAX_INTEGRATOR_BPS = 200;
export const MAX_TIP = 20_000_000n;
/** Mainnet floors (the e2e build uses 3 s / 10 s). */
export const MIN_PROOF_WINDOW = 6 * 3600;
export const MIN_UNBOND_SECS = 3 * 86_400;
export const FILL_DEPOSIT_BPS = 100n;
export const MIN_FILL_DEPOSIT = 10_000_000n;
export const INTEGRATOR_LEN = 80;
export const OFFER_LEN = 296;
export const ORDER_TERMS_LEN = 277;
export const XUSED_LEN = 48;
export const OF = { OPEN: 1, RESERVED: 2 } as const;
const enc = (s: string) => new TextEncoder().encode(s);

const ro = (pubkey: PublicKey, isSigner = false) => ({ pubkey, isSigner, isWritable: false });
const rw = (pubkey: PublicKey, isSigner = false) => ({ pubkey, isSigner, isWritable: true });

class W {
  parts: Uint8Array[] = [];
  u8(v: number) { this.parts.push(Uint8Array.of(v)); return this; }
  u16(v: number) { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, v, true); this.parts.push(b); return this; }
  u64(v: bigint | number) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(v), true); this.parts.push(b); return this; }
  i64(v: bigint | number) { const b = new Uint8Array(8); new DataView(b.buffer).setBigInt64(0, BigInt(v), true); this.parts.push(b); return this; }
  bytes(b: Uint8Array, len?: number) { if (len !== undefined && b.length !== len) throw new Error(`expected ${len} bytes, got ${b.length}`); this.parts.push(b); return this; }
  key(k: PublicKey) { return this.bytes(k.toBytes(), 32); }
  done() { return Buffer.concat(this.parts); }
}
class R {
  o = 0; d: Uint8Array; dv: DataView;
  constructor(d: Uint8Array) { this.d = d; this.dv = new DataView(d.buffer, d.byteOffset, d.byteLength); }
  u8() { return this.d[this.o++]; }
  u16() { const v = this.dv.getUint16(this.o, true); this.o += 2; return v; }
  u64() { const v = this.dv.getBigUint64(this.o, true); this.o += 8; return v; }
  i64() { const v = this.dv.getBigInt64(this.o, true); this.o += 8; return v; }
  b(n: number) { const v = this.d.slice(this.o, this.o + n); this.o += n; return v; }
  key() { return new PublicKey(this.b(32)); }
  skip(n: number) { this.o += n; }
}

// ---------------------------------------------------------------- PDAs
export const pdaF = {
  integrator: (pid: PublicKey, owner: PublicKey) => PublicKey.findProgramAddressSync([enc('integrator'), owner.toBytes()], pid)[0],
  order: (pid: PublicKey, hash: Uint8Array) => PublicKey.findProgramAddressSync([enc('order'), hash], pid)[0],
  offer: (pid: PublicKey, bidder: PublicKey, offerId: Uint8Array) => PublicKey.findProgramAddressSync([enc('offer'), bidder.toBytes(), offerId], pid)[0],
  /** One per proven Monero output (direct proofs and offer releases). */
  used: (pid: PublicKey, outKey: Uint8Array) => PublicKey.findProgramAddressSync([enc('xmrused'), outKey], pid)[0],
};

// ---------------------------------------------------------------- integrators
export function ixIntegratorRegister(pid: PublicKey, owner: PublicKey) {
  return new TransactionInstruction({ programId: pid, keys: [rw(owner, true), rw(pdaF.integrator(pid, owner)), ro(SystemProgram.programId)], data: Buffer.from([IXF.INTEGRATOR, 0]) });
}
export function ixIntegratorWithdraw(pid: PublicKey, owner: PublicKey) {
  return new TransactionInstruction({ programId: pid, keys: [rw(owner, true), rw(pdaF.integrator(pid, owner))], data: Buffer.from([IXF.INTEGRATOR, 1]) });
}
export interface IntegratorAccount { owner: PublicKey; earned: bigint; withdrawn: bigint; swaps: bigint; volume: bigint; createdAt: bigint }
export function decodeIntegrator(d: Uint8Array): IntegratorAccount {
  if (d.length !== INTEGRATOR_LEN || d[0] !== 0x1a) throw new Error('not an integrator account');
  const r = new R(d); r.skip(8);
  return { owner: r.key(), earned: r.u64(), withdrawn: r.u64(), swaps: r.u64(), volume: r.u64(), createdAt: r.i64() };
}

// ---------------------------------------------------------------- v2 escrows
export interface Shares { integrator?: PublicKey; integratorBps?: number; tip?: bigint }
export type Lock3Params = P.LockParams & Shares;

/** The v3 consent message: the v2 fields under "halfkey-consent-v3" (no link) + integrator, bps, tip. */
export function consentMessageV3(pid: PublicKey, locker: PublicKey, p: Lock3Params): Uint8Array {
  const escrow = P.pda.escrow(pid, locker, p.swapId);
  const wt = [...p.watchtowers, PublicKey.default, PublicKey.default].slice(0, 2);
  return new W().bytes(enc('halfkey-consent-v3')).key(pid).key(escrow).key(locker).key(p.claimer)
    .u8(p.direction).u64(p.amount).u64(p.xmrAmount).bytes(p.claimPoint, 32).bytes(p.refundPoint, 32)
    .bytes(p.viewPub, 32).bytes(p.quoteHash, 32).i64(p.t0Secs).i64(p.windowSecs).i64(p.consentExpiry).u16(p.feeBps)
    .u8(p.flags ?? 0).key(PublicKey.default).key(wt[0]).key(wt[1])
    .key(p.integrator ?? PublicKey.default).u16(p.integratorBps ?? 0).u64(p.tip ?? 0n).done();
}
export const consentDigestV3 = (pid: PublicKey, locker: PublicKey, p: Lock3Params) => sha256(consentMessageV3(pid, locker, p));

/** lock3: a v2 escrow (flags: PROOF for XMR->SOL, DIRECT for SOL->XMR direct payout). */
export function ixLock3(pid: PublicKey, locker: PublicKey, p: Lock3Params) {
  const wt = [...p.watchtowers, PublicKey.default, PublicKey.default].slice(0, 2);
  const integ = p.integrator ?? PublicKey.default;
  const keys = [rw(locker, true), rw(P.pda.escrow(pid, locker, p.swapId)), rw(P.pda.maker(pid, p.makerAuthority)), rw(P.pda.config(pid)), ro(SystemProgram.programId), ro(SYSVAR_INSTRUCTIONS_PUBKEY)];
  if (!integ.equals(PublicKey.default)) keys.push(ro(pdaF.integrator(pid, integ)));
  return new TransactionInstruction({
    programId: pid,
    keys,
    data: new W().u8(IXF.LOCK3).bytes(p.swapId, 32).key(p.claimer).u8(p.direction).u64(p.amount).u64(p.xmrAmount)
      .bytes(p.claimPoint, 32).bytes(p.refundPoint, 32).bytes(p.viewPub, 32).bytes(p.quoteHash, 32)
      .i64(p.t0Secs).i64(p.windowSecs).key(wt[0]).key(wt[1]).i64(p.consentExpiry).u8(p.flags ?? 0)
      .key(integ).u16(p.integratorBps ?? 0).u64(p.tip ?? 0n).done(),
  });
}

export interface ClaimToArgs { escrow: PublicKey; claimer: PublicKey; makerAuthority: PublicKey; integrator?: PublicKey; proof?: PublicKey }
/** claim_to: anyone submits the claimer's secret; the SOL goes only to the bound claimer, the tip to `submitter`. */
export function ixClaimTo(pid: PublicKey, submitter: PublicKey, a: ClaimToArgs, secret: Uint8Array) {
  const keys = [rw(submitter, true), rw(a.escrow), rw(a.claimer), rw(P.pda.maker(pid, a.makerAuthority)), rw(P.pda.config(pid)), rw(P.pda.feeVault(pid))];
  if (a.integrator && !a.integrator.equals(PublicKey.default)) keys.push(rw(pdaF.integrator(pid, a.integrator)));
  if (a.proof) keys.push(ro(a.proof));
  return new TransactionInstruction({ programId: pid, keys, data: new W().u8(IXF.CLAIM_TO).bytes(secret, 32).done() });
}
/** claim_to from a decoded escrow (adds the integrator and, when needed, the proof record). */
export function ixClaimToEscrow(pid: PublicKey, submitter: PublicKey, e: P.EscrowAccount, secret: Uint8Array, needProof: boolean) {
  const proof = needProof ? pdaV15.proof(pid, e.address!, e) : undefined;
  return ixClaimTo(pid, submitter, { escrow: e.address!, claimer: e.claimer, makerAuthority: e.maker, integrator: e.ext?.integrator, proof }, secret);
}
/** ready by a pay link's owner (the recipient), until t1. */
export function ixReadyPay(pid: PublicKey, owner: PublicKey, escrow: PublicKey, link: PublicKey) {
  return new TransactionInstruction({ programId: pid, keys: [ro(owner, true), rw(escrow), ro(link)], data: Buffer.from([7]) });
}
/** close a settled v2 escrow. Direct payout: anyone (rent to the locker); else the locker. */
export function ixCloseV2(pid: PublicKey, who: PublicKey, escrow: PublicKey, locker: PublicKey, direct: boolean) {
  const keys = direct ? [ro(who, true), rw(escrow), rw(locker)] : [rw(locker, true), rw(escrow)];
  return new TransactionInstruction({ programId: pid, keys, data: Buffer.from([11]) });
}

// ---------------------------------------------------------------- deposit orders
export interface OrderTerms {
  maker: PublicKey; amount: bigint; xmrAmount: bigint; claimPoint: Uint8Array; paySpend: Uint8Array; payView: Uint8Array;
  refund: PublicKey; deadline: bigint | number; t0Secs: number; windowSecs: number; feeBps: number;
  integrator?: PublicKey; integratorBps?: number; tip?: bigint; quoteHash: Uint8Array;
  /** Fund an OTC desk tranche (the escrow gets F.OTC: OTC range, cap and reputation). */
  otc?: boolean;
}
export function encodeOrderTerms(t: OrderTerms): Uint8Array {
  const b = new W().key(t.maker).u64(t.amount).u64(t.xmrAmount).bytes(t.claimPoint, 32).bytes(t.paySpend, 32).bytes(t.payView, 32)
    .key(t.refund).i64(t.deadline).i64(t.t0Secs).i64(t.windowSecs).u16(t.feeBps).key(t.integrator ?? PublicKey.default)
    .u16(t.integratorBps ?? 0).u64(t.tip ?? 0n).bytes(t.quoteHash, 32).u8(t.otc ? P.F.OTC : 0).done();
  if (b.length !== ORDER_TERMS_LEN) throw new Error('order terms length');
  return b;
}
export const orderHash = (pid: PublicKey, t: OrderTerms) => sha256(concatBytes(enc('halfkey-order-v1'), pid.toBytes(), encodeOrderTerms(t)));
/** The deposit address of an order: send SOL here (any wallet or exchange withdrawal). */
export const orderAddress = (pid: PublicKey, t: OrderTerms) => pdaF.order(pid, orderHash(pid, t));
/** The escrow a fill creates: ["swap", refund, order_hash]. */
export const orderEscrow = (pid: PublicKey, t: OrderTerms) => P.pda.escrow(pid, t.refund, orderHash(pid, t));
/** What the order address must hold for a fill: amount + tip + the escrow's rent. */
export const orderRequired = (t: OrderTerms, escrowRent: bigint) => t.amount + (t.tip ?? 0n) + escrowRent;
/** The maker's consent to an order: an ed25519 signature over the order hash. */
export const signOrder = (pid: PublicKey, t: OrderTerms, makerSecret32: Uint8Array) => ed25519.sign(orderHash(pid, t), makerSecret32);

export function ixFillDeposit(pid: PublicKey, filler: PublicKey, t: OrderTerms) {
  const h = orderHash(pid, t);
  const keys = [rw(filler, true), rw(pdaF.order(pid, h)), rw(P.pda.escrow(pid, t.refund, h)), rw(P.pda.maker(pid, t.maker)), rw(P.pda.config(pid)), ro(SystemProgram.programId), ro(SYSVAR_INSTRUCTIONS_PUBKEY)];
  if (t.integrator && !t.integrator.equals(PublicKey.default)) keys.push(ro(pdaF.integrator(pid, t.integrator)));
  return new TransactionInstruction({ programId: pid, keys, data: Buffer.concat([Buffer.from([IXF.FILL_DEPOSIT]), encodeOrderTerms(t)]) });
}
/** [ed25519 consent over the order hash, fill_deposit]. */
export function ixsFillDeposit(pid: PublicKey, filler: PublicKey, t: OrderTerms, makerSig: Uint8Array) {
  return [P.ixConsent(t.maker, orderHash(pid, t), makerSig), ixFillDeposit(pid, filler, t)];
}
/** order_refund; `rSigns`: R signs too (then refundable at any time before a fill). */
export function ixOrderRefund(pid: PublicKey, caller: PublicKey, t: OrderTerms, rSigns = false) {
  const h = orderHash(pid, t);
  return new TransactionInstruction({
    programId: pid,
    keys: [rw(caller, true), rw(pdaF.order(pid, h)), rw(t.refund, rSigns), ro(P.pda.escrow(pid, t.refund, h)), ro(SystemProgram.programId)],
    data: Buffer.concat([Buffer.from([IXF.ORDER_REFUND]), encodeOrderTerms(t)]),
  });
}
/** Refuse a refund address that can never receive SOL (default key, an executable account). */
export async function checkRefundAddress(c: Connection, r: PublicKey) {
  if (r.equals(PublicKey.default)) throw new Error('refund address is the default key');
  const a = await c.getAccountInfo(r);
  if (a?.executable) throw new Error('refund address is a program');
}

// ---------------------------------------------------------------- payment ids / direct proofs
const le64 = (n: bigint | number) => new W().i64(n).done();
const leu64 = (n: bigint | number) => new W().u64(n).done();
/** The payment id a direct payout to this escrow instance must carry. */
export const escrowPid = (escrow: PublicKey, createdAt: bigint | number) => sha256(concatBytes(enc('halfkey-pid-v1'), escrow.toBytes(), le64(createdAt), leu64(0))).slice(0, 8);
/** The payment id of an offer's fill number `seq` by `filler` (pay only after your own take landed). */
export const offerPid = (offer: PublicKey, createdAt: bigint | number, seq: bigint | number, filler: PublicKey) => sha256(concatBytes(enc('halfkey-offer-pid-v1'), offer.toBytes(), le64(createdAt), leu64(seq), filler.toBytes())).slice(0, 8);
/** Longest order life a fill accepts (deadline - now); further out is refundable at once. */
export const MAX_ORDER_LIFE = 7 * 86_400;

const INTEGRATED: Record<K.MoneroNet, number> = { mainnet: 19, stagenet: 25, testnet: 54 };
/** The integrated address a payer sends to: the payee's standard address + this release's payment id. */
export function integratedAddress(spendPub: Uint8Array, viewPub: Uint8Array, pid8: Uint8Array, net: K.MoneroNet): string {
  if (pid8.length !== 8) throw new Error('payment id must be 8 bytes');
  const body = concatBytes(Uint8Array.of(INTEGRATED[net]), spendPub, viewPub, pid8);
  return K.moneroBase58(concatBytes(body, keccak_256(body).slice(0, 4)));
}
/** A payout address for direct pay: standard addresses only (subaddresses cannot carry a payment id). */
export function payoutKeys(addr: string, net: K.MoneroNet): { spendPub: Uint8Array; viewPub: Uint8Array } {
  const a = K.parseMoneroAddress(addr, net);
  if (a.sub) throw new Error('subaddresses cannot be paid directly: use your primary (standard) address');
  if (!K.isGoodPoint(a.spendPub) || !K.isGoodPoint(a.viewPub)) throw new Error('address keys are not valid prime-order points');
  return { spendPub: a.spendPub, viewPub: a.viewPub };
}
/** Decrypt a tx's encrypted payment id with the proof's shared secret D (K = 8D, tail 0x8d). */
export function decryptPid(encPid: Uint8Array, D: Uint8Array): Uint8Array {
  const Kd = ed25519.ExtendedPoint.fromHex(D).multiply(8n).toRawBytes();
  const mask = keccak_256(concatBytes(Kd, Uint8Array.of(0x8d)));
  return encPid.map((x, i) => x ^ mask[i]);
}
/** The first tx_extra nonce's encrypted payment id (02 09 01 <8>), with its offset in tx_extra. */
export function encryptedPid(extra: Uint8Array): { pid: Uint8Array; off: number } | null {
  let i = 0;
  while (i < extra.length) {
    const tag = extra[i++];
    if (tag === 0x00) continue;
    if (tag === 0x01) { i += 32; continue; }
    if (tag === 0x02) { const n = extra[i]; if (n !== 9 || extra[i + 1] !== 0x01) return null; return { pid: extra.slice(i + 2, i + 10), off: i + 2 }; }
    if (tag === 0x04) { let n = 0, s = 0, x: number; do { x = extra[i++]; n |= (x & 0x7f) << s; s += 7; } while (x & 0x80); i += 32 * n; continue; }
    return null;
  }
  return null;
}

/** prove_direct: a payment to a direct escrow's payout address, with its payment id. */
export function ixProveDirect(pid: PublicKey, payer: PublicKey, escrow: PublicKey, e: { createdAt: bigint | number; claimPoint: Uint8Array; refundPoint: Uint8Array; viewPub: Uint8Array; flags?: number }, epoch: bigint, a: X.ProveArgs) {
  const t = proofTerms({ ...e, flags: (e.flags ?? 0) | P.F.DIRECT });
  const proof = PublicKey.findProgramAddressSync([enc('xmrout'), escrow.toBytes(), le64(e.createdAt), t], pid)[0];
  return new TransactionInstruction({
    programId: pid,
    keys: [rw(payer, true), ro(escrow), ro(pdaV15.attesters(pid)), ro(pdaV15.header(pid, epoch, a.blockId)), rw(proof), rw(pdaF.used(pid, a.outKey)), ro(SystemProgram.programId)],
    data: Buffer.concat([Buffer.from([IXF.PROVE_DIRECT]), X.encodeProve(a)]),
  });
}

// ---------------------------------------------------------------- open offers
export interface OfferOpenParams { offerId: Uint8Array; amount: bigint; xmrAmount: bigint; spendPub: Uint8Array; viewPub: Uint8Array; integrator?: PublicKey; integratorBps?: number; tip?: bigint; fillWindow: number; life: number }
export function ixOfferOpen(pid: PublicKey, bidder: PublicKey, p: OfferOpenParams) {
  const integ = p.integrator ?? PublicKey.default;
  const keys = [rw(bidder, true), rw(pdaF.offer(pid, bidder, p.offerId)), rw(P.pda.config(pid)), ro(SystemProgram.programId)];
  if (!integ.equals(PublicKey.default)) keys.push(ro(pdaF.integrator(pid, integ)));
  return new TransactionInstruction({
    programId: pid, keys,
    data: new W().u8(IXF.OFFER_OPEN).bytes(p.offerId, 32).u64(p.amount).u64(p.xmrAmount).bytes(p.spendPub, 32).bytes(p.viewPub, 32)
      .key(integ).u16(p.integratorBps ?? 0).u64(p.tip ?? 0n).i64(p.fillWindow).i64(p.life).done(),
  });
}
export function ixOfferTake(pid: PublicKey, filler: PublicKey, offer: PublicKey, bidder: PublicKey) {
  return new TransactionInstruction({ programId: pid, keys: [rw(filler, true), rw(offer), rw(bidder), ro(P.pda.config(pid)), ro(SystemProgram.programId)], data: Buffer.from([IXF.OFFER_TAKE]) });
}
export function ixOfferRelease(pid: PublicKey, submitter: PublicKey, o: OfferAccount, epoch: bigint, a: X.ProveArgs) {
  const keys = [rw(submitter, true), rw(o.address!), rw(o.filler), rw(o.bidder), rw(P.pda.config(pid)), rw(P.pda.feeVault(pid)),
    ro(pdaV15.attesters(pid)), ro(pdaV15.header(pid, epoch, a.blockId)), rw(pdaF.used(pid, a.outKey)), ro(SystemProgram.programId)];
  if (!o.integrator.equals(PublicKey.default)) keys.push(rw(pdaF.integrator(pid, o.integrator)));
  return new TransactionInstruction({ programId: pid, keys, data: Buffer.concat([Buffer.from([IXF.OFFER_SETTLE, 0]), X.encodeProve(a)]) });
}
export function ixOfferCancel(pid: PublicKey, who: PublicKey, offer: PublicKey, bidder: PublicKey) {
  return new TransactionInstruction({ programId: pid, keys: [rw(who, true), rw(offer), rw(bidder), rw(P.pda.config(pid))], data: Buffer.from([IXF.OFFER_SETTLE, 1]) });
}
export function ixOfferForfeit(pid: PublicKey, who: PublicKey, offer: PublicKey, bidder: PublicKey) {
  return new TransactionInstruction({ programId: pid, keys: [ro(who, true), rw(offer), rw(bidder)], data: Buffer.from([IXF.OFFER_SETTLE, 2]) });
}
export interface OfferAccount {
  address?: PublicKey; state: number; offerId: Uint8Array; bidder: PublicKey; amount: bigint; xmrAmount: bigint; spendPub: Uint8Array; viewPub: Uint8Array;
  feeBps: number; integratorBps: number; integrator: PublicKey; tip: bigint; fillWindow: bigint; expiresAt: bigint; createdAt: bigint;
  fillSeq: bigint; filler: PublicKey; deposit: bigint; reservedAt: bigint; deadline: bigint; forfeits: bigint;
}
export function decodeOffer(d: Uint8Array, address?: PublicKey): OfferAccount {
  if (d.length !== OFFER_LEN || d[0] !== 0x0f) throw new Error('not an offer account');
  const r = new R(d); r.skip(2);
  const state = r.u8(); r.skip(5);
  const offerId = r.b(32), bidder = r.key(), amount = r.u64(), xmrAmount = r.u64(), spendPub = r.b(32), viewPub = r.b(32);
  const feeBps = r.u16(), integratorBps = r.u16(); r.skip(4);
  return {
    address, state, offerId, bidder, amount, xmrAmount, spendPub, viewPub, feeBps, integratorBps, integrator: r.key(), tip: r.u64(),
    fillWindow: r.i64(), expiresAt: r.i64(), createdAt: r.i64(), fillSeq: r.u64(), filler: r.key(), deposit: r.u64(),
    reservedAt: r.i64(), deadline: r.i64(), forfeits: r.u64(),
  };
}
export const fillerDeposit = (amount: bigint) => { const d = amount * FILL_DEPOSIT_BPS / 10_000n; return d > MIN_FILL_DEPOSIT ? d : MIN_FILL_DEPOSIT; };
/** Open offers on chain (the board). */
export async function listOffers(c: Connection, pid: PublicKey): Promise<OfferAccount[]> {
  const xs = await c.getProgramAccounts(pid, { commitment: 'confirmed', filters: [{ dataSize: OFFER_LEN }] });
  return xs.map((x) => decodeOffer(x.account.data, x.pubkey));
}
