// Platform flows on Solana (adapter layer): pay links, OTC tranches, cashout vaults.
// Every check a payer / taker / owner depends on lives here, shared by the web client and the
// E2E runners. Chain-agnostic math is in pay.ts / otc.ts; this file talks to the program + makers.
import { Connection, PublicKey, TransactionInstruction } from '@solana/web3.js';
import { ed25519 } from '@noble/curves/ed25519';
import * as P from './program.ts';
import * as K from './keys.ts';
import * as T from './taker.ts';
import * as Pay from './pay.ts';
import * as O from './otc.ts';

// ---------------------------------------------------------------- maker API (platform additions)
export interface MakerPlatformInfo {
  /** Watchtowers this maker accepts on pay escrows (it trusts them not to abort a delivered swap). */
  payWatchtowers?: string[];
  /** OTC desk: tranche range (lamports) and whether quotes are automatic. */
  otc?: { minLamports: string; maxLamports: string; maxTranches: number; auto: boolean };
}

export interface PaySwapRequest {
  mode: 'pay' | 'vault';
  quote: K.Quote;
  sig: string;
  swapId: string;            // hex(32) = payment id (invoice id or random)
  locker: string;            // payer wallet, or the vault PDA
  link: string;              // link account
  watchtowers: string[];     // the escrow's watchtower slots (consent binds them)
}
export interface PaySwapResponse {
  direction: 1;
  makerSpendPub: string;
  feeBps: number;
  sharedAddress: string;
  t0Secs: number;
  windowSecs: number;
  consentExpiry: number;
  consentSig: string;
}

export interface OtcTrancheReq { swapId: string; takerSpendPub: string; viewSecret: string; watchtowers?: string[] }
export interface OtcAcceptReq { quote: O.OtcQuote; sig: string; taker: string; tranches: OtcTrancheReq[]; takerSig: string }
export interface OtcTrancheRes {
  index: number;
  makerSpendPub: string;
  sharedAddress: string;
  t0Secs: number;
  windowSecs: number;
  consentExpiry?: number;
  consentSig?: string;       // side 1
  escrow?: string;           // side 2 (the maker locked SOL)
  lockSig?: string;
  makerKeyProof?: string;    // side 2: proof the maker knows its key half (required)
}

async function j<T>(r: Response): Promise<T> {
  const body = await r.text();
  if (!r.ok) throw new Error(`maker ${r.status}: ${body.slice(0, 200)}`);
  return JSON.parse(body) as T;
}
const base = (ep: string) => ep.replace(/\/+$/, '');
const post = (url: string, body: unknown, ms = 20_000) => fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(ms) });

export const platformApi = {
  info: (ep: string) => fetch(`${base(ep)}/v1/info`).then((r) => j<T.MakerInfo & MakerPlatformInfo>(r)),
  /** SOL->XMR quote for an exact XMR amount (invoices). */
  quoteExactXmr: (ep: string, piconero: bigint) => fetch(`${base(ep)}/v1/quote?direction=1&piconero=${piconero}`).then((r) => j<T.SignedQuote>(r)),
  paySwap: (ep: string, req: PaySwapRequest) => post(`${base(ep)}/v1/swap`, req).then((r) => j<PaySwapResponse>(r)),
  otcRfq: (ep: string, rfq: O.Rfq, sig: string) => post(`${base(ep)}/v1/otc/rfq`, { rfq, sig }, 10_000).then((r) => j<{ status: 'quoted' | 'pending' | 'declined'; quote?: O.OtcQuote; sig?: string; reason?: string }>(r)),
  otcQuote: (ep: string, id: string) => fetch(`${base(ep)}/v1/otc/rfq/${id}`, { signal: AbortSignal.timeout(8000) }).then((r) => j<{ status: string; quote?: O.OtcQuote; sig?: string }>(r)),
  otcAccept: (ep: string, req: OtcAcceptReq) => post(`${base(ep)}/v1/otc/accept`, req, 60_000).then((r) => j<{ tranches: OtcTrancheRes[] }>(r)),
};

// ---------------------------------------------------------------- links
export async function getLink(conn: Connection, pid: PublicKey, name: string): Promise<P.LinkAccount | null> {
  if (!P.isLinkName(name)) return null;
  const addr = P.pda.link(pid, name);
  const a = await conn.getAccountInfo(addr, 'confirmed');
  if (!a || !a.owner.equals(pid)) return null;
  return P.decodeLink(a.data, addr);
}

export async function linksOf(conn: Connection, pid: PublicKey, owner: PublicKey): Promise<P.LinkAccount[]> {
  const xs = await conn.getProgramAccounts(pid, { filters: [{ dataSize: P.LINK_LEN }, { memcmp: { offset: P.OFF_LINK_OWNER, bytes: owner.toBase58() } }] });
  return xs.map((x) => P.decodeLink(x.account.data, x.pubkey));
}

/** Every pay escrow to a link (open or settled, until closed). */
export async function paymentsTo(conn: Connection, pid: PublicKey, link: PublicKey): Promise<P.EscrowAccount[]> {
  const xs = await conn.getProgramAccounts(pid, { commitment: 'confirmed', filters: [{ dataSize: P.ESCROW_LEN }, { memcmp: { offset: P.OFF_ESCROW_LINK, bytes: link.toBase58() } }] });
  return xs.map((x) => P.decodeEscrow(x.account.data, x.pubkey)).sort((a, b) => Number(b.createdAt - a.createdAt));
}

// ---------------------------------------------------------------- pay: payer side
export interface PreparedPay {
  escrow: PublicKey;
  lock: P.LockParams;
  ixs: TransactionInstruction[];   // [consent (ed25519), lock2]
  shared: { address: string; view: Uint8Array };
  watchtowers: PublicKey[];
}

/**
 * Pay a link: register the payment's view key with watchtowers the maker accepts, then ask the
 * maker for a v2 consent bound to the link + those watchtowers, and verify every term before
 * anything is signed. The payer never learns the recipient's key; the program re-derives it.
 */
export async function preparePay(args: {
  pid: PublicKey; endpoint: string; makerAuthority: PublicKey; cfg: P.ConfigAccount; policy: T.Policy;
  sq: T.SignedQuote; link: P.LinkAccount; payer: PublicKey; swapId: Uint8Array; net: K.MoneroNet;
  watchtowers: { url: string; pubkey: PublicKey }[]; acceptedTowers?: string[]; nowSecs: number; flags?: number;
}): Promise<PreparedPay> {
  const { pid, endpoint, makerAuthority, cfg, policy, sq, link, payer, swapId, net } = args;
  const err = T.checkQuote(sq, makerAuthority, 1, cfg, args.nowSecs);
  if (err) throw new Error(err);
  const escrow = P.pda.escrow(pid, payer, swapId);
  if (link.retired) throw new Error('this link is retired and takes no new payments');
  const qh = K.quoteHash(sq.quote);
  const keys = Pay.payKeys(link.master, escrow.toBytes(), qh);
  const towers = args.watchtowers.filter((w) => !args.acceptedTowers || args.acceptedTowers.includes(w.pubkey.toBase58())).filter((w) => !w.pubkey.equals(payer)).slice(0, 2);
  const acked = await T.registerWatchtowers(towers, escrow, keys.view);
  if (acked.length < Math.max(1, policy.minWatchtowers)) throw new Error(`only ${acked.length} watchtower(s) online; a pay link needs one (the payer cannot cancel on its own)`);
  const res = await platformApi.paySwap(endpoint, {
    mode: 'pay', quote: sq.quote, sig: sq.sig, swapId: K.toHex(swapId), locker: payer.toBase58(), link: link.address!.toBase58(),
    watchtowers: acked.map((w) => w.toBase58()),
  });
  if (res.direction !== 1) throw new Error('maker answered for the wrong direction');
  const makerSpendPub = K.fromHex(res.makerSpendPub);
  const w = Pay.payWallet(makerSpendPub, link.master, escrow.toBytes(), qh, net); // prime order, no cancellation
  if (w.address !== res.sharedAddress) throw new Error('shared address mismatch');
  if (res.feeBps !== sq.quote.feeBps || (res.feeBps !== cfg.feeBps && res.feeBps !== cfg.holderFeeBps)) throw new Error('fee does not match');
  if (res.t0Secs < Math.max(cfg.minT0, policy.minT0Secs) || res.t0Secs > cfg.maxT0) throw new Error('maker asked for an unsafe t0');
  if (res.windowSecs < Math.max(cfg.minWindow, policy.minWindowSecs) || res.windowSecs > cfg.maxWindow) throw new Error('maker asked for an unsafe window');
  if (res.consentExpiry < args.nowSecs || res.consentExpiry > args.nowSecs + 600) throw new Error('bad consent expiry');
  const lock: P.LockParams = {
    swapId, claimer: makerAuthority, direction: 1, amount: BigInt(sq.quote.lamports), xmrAmount: BigInt(sq.quote.piconero),
    claimPoint: makerSpendPub, refundPoint: w.spendPub, viewPub: w.viewPub, quoteHash: K.quoteHash(sq.quote),
    t0Secs: res.t0Secs, windowSecs: res.windowSecs, watchtowers: acked, makerAuthority, consentExpiry: res.consentExpiry,
    feeBps: res.feeBps, flags: (args.flags ?? 0) | P.F.PAY, link: link.address!,
  };
  const digest = P.consentDigest(pid, payer, lock);
  const sig = K.fromHex(res.consentSig);
  if (!ed25519.verify(sig, digest, makerAuthority.toBytes())) throw new Error('maker consent signature does not verify');
  return { escrow, lock, ixs: [P.ixConsent(makerAuthority, digest, sig), P.ixLock2(pid, payer, lock)], shared: { address: w.address, view: w.view }, watchtowers: acked };
}

/** Status of a payment as the payer / recipient sees it. */
/** 'paid' = the maker claimed; the recipient's collect is what proves the XMR (a sweep finds it or not). */
export type PayPhase = 'pending' | 'releasing' | 'paid' | 'refund' | 'refunded';
export function payPhase(e: P.EscrowAccount, chainNow: number): PayPhase {
  if (e.state === P.ST.CLAIMED) return 'paid';
  if (e.state === P.ST.REFUNDED) return 'refunded';
  if (e.state === P.ST.ABORTED || chainNow >= Number(e.t1)) return 'refund';
  if (e.state === P.ST.READY || chainNow >= Number(e.t0)) return 'releasing';
  return 'pending';
}

// ---------------------------------------------------------------- pay: recipient side
export interface Collectable { escrow: P.EscrowAccount; spendKey: Uint8Array; viewKey: Uint8Array; address: string }

/** The keys to sweep one claimed payment, rebuilt from the wallet root alone (any device). */
export function collectKeys(root: Uint8Array, link: P.LinkAccount, e: P.EscrowAccount, net: K.MoneroNet): Collectable {
  if (!(e.flags & P.F.PAY) || !e.link.equals(link.address!)) throw new Error('not a payment to this link');
  if (e.state !== P.ST.CLAIMED) throw new Error('not paid yet');
  const s = Pay.linkSecret(root, link.name);
  const spendKey = Pay.payFullSpend(s, link.master, e.address!.toBytes(), e.quoteHash, e.secret, e.claimPoint);
  const keys = Pay.payKeys(link.master, e.address!.toBytes(), e.quoteHash);
  if (!K.equalBytes(keys.viewPub, e.viewPub)) throw new Error('view key mismatch');
  return { escrow: e, spendKey, viewKey: keys.view, address: K.moneroAddress(K.pub(spendKey), keys.viewPub, net) };
}

// ---------------------------------------------------------------- OTC: taker side
export interface PreparedTranche { index: number; escrow: PublicKey; lock?: P.LockParams; ixs?: TransactionInstruction[]; half: K.KeyHalf; swapId: Uint8Array; sharedAddress: string; piconero: bigint; lamports: bigint; makerSpendPub: Uint8Array; makerKeyProof?: Uint8Array }

/**
 * Accept a firm OTC quote: derive one key half per tranche from the wallet root, send them to
 * the maker, and verify every tranche's terms. Side 1 returns [consent, lock2] per tranche for
 * one signAllTransactions prompt. Side 2: the maker locked SOL; each escrow is checked on chain
 * (finalized) before its deposit address is shown.
 */
export async function acceptOtc(args: {
  conn: Connection; pid: PublicKey; endpoint: string; makerAuthority: PublicKey; cfg: P.ConfigAccount; policy: T.Policy;
  quote: O.OtcQuote; sig: string; rfq: O.Rfq; root: Uint8Array; taker: PublicKey; net: K.MoneroNet; nowSecs: number;
  watchtowers: { url: string; pubkey: PublicKey }[]; capLamports: bigint;
  /** Watchtowers the desk accepts (its /v1/info payWatchtowers); others would be refused. */
  acceptedTowers?: string[];
  /** The taker's wallet signs the accept (signMessage). */
  signAccept: (bytes: Uint8Array) => Promise<Uint8Array>;
}): Promise<PreparedTranche[]> {
  const { pid, quote, rfq, taker, net, policy, cfg, makerAuthority } = args;
  const bad = O.checkOtcQuote(quote, args.sig, rfq, makerAuthority.toBytes(), { feeBps: [cfg.feeBps, cfg.holderFeeBps], capLamports: args.capLamports, now: args.nowSecs });
  if (bad) throw new Error(bad);
  const plan = O.planTranches(quote);
  const tr = plan.map((t) => { const swapId = K.newSwapId(); return { t, swapId, half: K.deriveHalf(args.root, swapId) }; });
  // SOL->XMR: watchtowers first, one registration per tranche
  const acked: PublicKey[][] = [];
  if (quote.side === 1) {
    const towers = args.watchtowers.filter((w) => !args.acceptedTowers || args.acceptedTowers.includes(w.pubkey.toBase58())).slice(0, 2);
    for (const x of tr) {
      const a = await T.registerWatchtowers(towers, P.pda.escrow(pid, taker, x.swapId), x.half.view);
      if (a.length < policy.minWatchtowers) throw new Error(`only ${a.length} watchtower(s) online; refusing to lock`);
      acked.push(a);
    }
  }
  const reqTr = tr.map((x, i) => ({ swapId: K.toHex(x.swapId), takerSpendPub: K.toHex(x.half.spendPub), viewSecret: K.toHex(x.half.view), watchtowers: (acked[i] ?? []).map((w) => w.toBase58()) }));
  const takerSig = K.toHex(await args.signAccept(O.acceptBytes(quote, reqTr)));
  const res = await platformApi.otcAccept(args.endpoint, { quote, sig: args.sig, taker: taker.toBase58(), tranches: reqTr, takerSig });
  if (res.tranches.length !== tr.length) throw new Error('maker answered for a different number of tranches');
  const out: PreparedTranche[] = [];
  for (const [i, x] of tr.entries()) {
    const r = res.tranches[i];
    if (r.index !== i) throw new Error('tranche order mismatch');
    const makerSpendPub = K.fromHex(r.makerSpendPub);
    if (!K.isGoodPoint(makerSpendPub) || K.equalBytes(makerSpendPub, x.half.spendPub)) throw new Error('maker key is not valid');
    if (!K.isGoodPoint(K.pointAdd(makerSpendPub, x.half.spendPub))) throw new Error('maker key cancels ours');
    const shared = K.sharedWallet(makerSpendPub, x.half.spendPub, x.half.view, net);
    if (shared.address !== r.sharedAddress) throw new Error('shared address mismatch');
    if (quote.side === 1) {
      if (r.t0Secs < Math.max(cfg.minT0, policy.minT0Secs) || r.t0Secs > cfg.maxT0) throw new Error('unsafe t0');
      if (r.windowSecs < Math.max(cfg.minWindow, policy.minWindowSecs) || r.windowSecs > cfg.maxWindow) throw new Error('unsafe window');
      if (!r.consentExpiry || r.consentExpiry < args.nowSecs || r.consentExpiry > args.nowSecs + 900) throw new Error('bad consent expiry');
      const lock: P.LockParams = {
        swapId: x.swapId, claimer: makerAuthority, direction: 1, amount: x.t.lamports, xmrAmount: x.t.piconero,
        claimPoint: makerSpendPub, refundPoint: x.half.spendPub, viewPub: shared.viewPub, quoteHash: x.t.quoteHash,
        t0Secs: r.t0Secs, windowSecs: r.windowSecs, watchtowers: acked[i], makerAuthority, consentExpiry: r.consentExpiry,
        feeBps: quote.feeBps, flags: P.F.OTC,
      };
      const digest = P.consentDigest(pid, taker, lock);
      const sig = K.fromHex(r.consentSig ?? '');
      if (!ed25519.verify(sig, digest, makerAuthority.toBytes())) throw new Error(`tranche ${i}: consent does not verify`);
      out.push({ index: i, escrow: P.pda.escrow(pid, taker, x.swapId), lock, ixs: [P.ixConsent(makerAuthority, digest, sig), P.ixLock2(pid, taker, lock)], half: x.half, swapId: x.swapId, sharedAddress: shared.address, piconero: x.t.piconero, lamports: x.t.lamports, makerSpendPub });
    } else {
      const escrow = P.pda.escrow(pid, makerAuthority, x.swapId);
      if (r.escrow !== escrow.toBase58()) throw new Error(`tranche ${i}: maker named a different escrow`);
      // The maker must prove it knows its key half (else it could pick it from ours: deposit spendable by the maker alone).
      const proof = K.fromHex(r.makerKeyProof ?? '');
      if (!K.verifyKeyProof(makerSpendPub, K.keyProofContext(pid.toBytes(), escrow.toBytes(), x.half.spendPub), proof)) throw new Error(`tranche ${i}: maker did not prove its key`);
      out.push({ index: i, escrow, half: x.half, swapId: x.swapId, sharedAddress: shared.address, piconero: x.t.piconero, lamports: x.t.lamports, makerSpendPub, makerKeyProof: proof });
    }
  }
  return out;
}

/**
 * XMR->SOL OTC: every tranche escrow must match its plan on chain (finalized) before any XMR is
 * sent. Returns the escrow and its deposit deadline (the same rule the desk aborts by, see
 * T.depositDeadline); refuses when less than 5 minutes are left to send.
 */
export async function verifyOtcSide2(conn: Connection, pid: PublicKey, makerAuthority: PublicKey, quote: O.OtcQuote, taker: PublicKey, t: PreparedTranche, policy: T.Policy, nowSecs: number, terms?: T.DepositTerms) {
  const a = await conn.getAccountInfo(t.escrow, 'finalized');
  if (!a || !a.owner.equals(pid)) throw new Error('escrow not finalized on chain yet');
  const e = P.decodeEscrow(a.data, t.escrow);
  const tr = O.planTranches(quote)[t.index];
  const bad = (m: string) => { throw new Error(`tranche ${t.index} escrow does not match: ${m}`); };
  if (e.direction !== 2 || e.state !== P.ST.LOCKED || !(e.flags & P.F.OTC)) bad('state');
  if (!e.claimer.equals(taker) || !e.locker.equals(makerAuthority)) bad('parties');
  if (!K.equalBytes(e.claimPoint, t.half.spendPub) || !K.equalBytes(e.refundPoint, t.makerSpendPub) || !K.equalBytes(e.viewPub, t.half.viewPub)) bad('keys');
  if (e.amount < tr.lamports || e.xmrAmount !== tr.piconero || !K.equalBytes(e.quoteHash, tr.quoteHash) || e.feeBps !== quote.feeBps) bad('terms');
  if (Number(e.t0) - nowSecs < policy.minT0Secs * 0.75) bad('too little time left to deposit');
  if (Number(e.t1) - Number(e.t0) < policy.minWindowSecs) bad('claim window too short');
  if (!t.makerKeyProof || !K.verifyKeyProof(e.refundPoint, K.keyProofContext(pid.toBytes(), t.escrow.toBytes(), t.half.spendPub), t.makerKeyProof)) bad('maker did not prove its key');
  const depositBy = T.depositDeadline(Number(e.createdAt), Number(e.t0), terms);
  if (depositBy - nowSecs < 5 * 60) bad('too little time left to send XMR safely');
  return Object.assign(e, { depositBy });
}

// ---------------------------------------------------------------- vaults
export async function vaultOf(conn: Connection, pid: PublicKey, owner: PublicKey): Promise<P.VaultAccount | null> {
  const addr = P.pda.vault(pid, owner);
  const a = await conn.getAccountInfo(addr, 'confirmed');
  return a && a.owner.equals(pid) ? P.decodeVault(a.data, addr) : null;
}

export async function vaultEscrows(conn: Connection, pid: PublicKey, vault: PublicKey): Promise<P.EscrowAccount[]> {
  const xs = await conn.getProgramAccounts(pid, { commitment: 'confirmed', filters: [{ dataSize: P.ESCROW_LEN }, { memcmp: { offset: P.OFF_ESCROW_LOCKER, bytes: vault.toBase58() } }] });
  return xs.map((x) => P.decodeEscrow(x.account.data, x.pubkey)).sort((a, b) => Number(b.createdAt - a.createdAt));
}

/** Free SOL in a vault (above its rent-exempt minimum). */
export async function vaultFree(conn: Connection, vault: PublicKey): Promise<bigint> {
  const [b, keep] = await Promise.all([conn.getBalance(vault, 'confirmed'), conn.getMinimumBalanceForRentExemption(P.VAULT_LEN)]);
  return BigInt(Math.max(0, b - keep));
}
