// HALFKEY stealth Solana addresses: Monero-style one-time keys on ed25519 (the curve Solana uses).
//
// The user holds a stealth meta-key, derived from the same wallet-signature root as the swap halves:
//   view scalar  v, view point  V = v·G      (lets you FIND your outputs; can be given to a scanner)
//   spend scalar s, spend point S = s·G      (lets you SPEND them; never leaves the browser)
// A payer (the maker in XMR->SOL, a pay link payer later) picks a fresh random r and publishes R = r·G:
//   D   = 8·r·V                               (= 8·v·R: Diffie-Hellman with the cofactor cleared)
//   h   = H_s("halfkey-stealth-v1" ‖ D ‖ i)   (wide SHA-512 reduced mod L, i = output index, 0 for swaps)
//   P_i = h·G + S                             (the one-time Solana address: an ed25519 public key)
// Only the holder of v can recognise P_i (scan), and only the holder of v and s can spend it:
//   s_i = h + s (mod L),  s_i·G == P_i.
// s_i is a raw scalar, not an RFC 8032 seed, so it signs through signRaw() below (same signature
// format; any ed25519 verifier, including the Solana runtime, accepts it).
//
// In a swap record R is the escrow's swap_id (the PDA seed), so nothing new is stored on chain and
// no program change is needed: scan = read XMR->SOL escrows, recompute P_i from swap_id, compare it
// with the escrow's claimer.
//
// Who picks r: in a SWAP the user's client does (stealthClaimerForSwap), never the maker. The swap
// id also seeds the user's Monero key half (deriveHalf(root, swap_id)), and a completed claim
// publishes that half; a maker allowed to choose R could replay an old (R, P) pair of the same user
// and learn the new half in advance (found in review). Third-party payers with no swap half
// involved (pay links) use deriveOneTime() on their side.
import { ed25519 } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils';
import bs58 from 'bs58';
import {
  Connection, PublicKey, SystemProgram, Transaction, VersionedTransaction, ComputeBudgetProgram,
} from '@solana/web3.js';
import * as K from './keys.ts';
import * as P from './program.ts';

const Point = ed25519.ExtendedPoint;
const L = K.L;
const DOMAIN = utf8ToBytes('halfkey-stealth-v1');
const META_PREFIX = 'hks1';
const META_VERSION = 1;

// ---------------------------------------------------------------- meta-key
export interface StealthMetaPub { viewPub: Uint8Array; spendPub: Uint8Array }
export interface StealthMeta extends StealthMetaPub { view: Uint8Array; spend: Uint8Array; account: number }

const u32le = (n: number) => {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new Error('index must be an integer in [0, 2^32)');
  const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, true); return b;
};

function wide(...parts: Uint8Array[]): Uint8Array {
  const s = K.reduce(sha512(concatBytes(...parts)));
  if (K.leToBig(s) === 0n) throw new Error('degenerate scalar');
  return s;
}

/**
 * Meta-key from the wallet root (root = SHA-512 of the wallet's signature over KEY_MESSAGE).
 * `account` lets one wallet keep several unlinkable meta-keys (for example one per maker).
 * The labels differ from deriveHalf's, so no swap half ever equals a stealth key.
 */
export function deriveStealthMeta(root: Uint8Array, account = 0): StealthMeta {
  if (root.length !== 64) throw new Error('expected the 64-byte wallet root');
  if (!Number.isInteger(account) || account < 0 || account > 0xffffffff) throw new Error('bad account index');
  const view = wide(root, utf8ToBytes('halfkey/stealth/view/v1'), u32le(account));
  const spend = wide(root, utf8ToBytes('halfkey/stealth/spend/v1'), u32le(account));
  return { view, spend, viewPub: K.pub(view), spendPub: K.pub(spend), account };
}

const metaChecksum = (body: Uint8Array) => sha256(concatBytes(utf8ToBytes('halfkey-stealth-meta'), body)).slice(0, 4);

/** Shareable meta address: "hks1" + base58(version ‖ V ‖ S ‖ checksum4). */
export function encodeMetaAddress(m: StealthMetaPub): string {
  if (!K.isGoodPoint(m.viewPub) || !K.isGoodPoint(m.spendPub)) throw new Error('meta key points must be prime-order');
  if (K.equalBytes(m.viewPub, m.spendPub)) throw new Error('stealth address view and spend keys are equal');
  const body = concatBytes(Uint8Array.of(META_VERSION), m.viewPub, m.spendPub);
  return META_PREFIX + bs58.encode(concatBytes(body, metaChecksum(body)));
}

export function decodeMetaAddress(s: string): StealthMetaPub {
  const t = s.trim();
  if (!t.startsWith(META_PREFIX)) throw new Error('not a HALFKEY stealth address');
  let raw: Uint8Array;
  try { raw = bs58.decode(t.slice(META_PREFIX.length)); } catch { throw new Error('bad stealth address encoding'); }
  if (raw.length !== 69) throw new Error('bad stealth address length');
  const body = raw.slice(0, 65);
  if (!K.equalBytes(metaChecksum(body), raw.slice(65))) throw new Error('bad stealth address checksum');
  if (body[0] !== META_VERSION) throw new Error('unknown stealth address version');
  const viewPub = body.slice(1, 33), spendPub = body.slice(33, 65);
  if (!K.isGoodPoint(viewPub) || !K.isGoodPoint(spendPub)) throw new Error('stealth address has an invalid key');
  if (K.equalBytes(viewPub, spendPub)) throw new Error('stealth address view and spend keys are equal');
  return { viewPub, spendPub };
}

// ---------------------------------------------------------------- one-time keys
/** 8·(k·Q). Q must already be a validated prime-order point; k a nonzero canonical scalar. */
function dh(k: Uint8Array, q: Uint8Array): Uint8Array {
  const n = K.leToBig(k);
  if (n === 0n || n >= L) throw new Error('bad scalar');
  return Point.fromHex(q).multiply(n).clearCofactor().toRawBytes();
}

/** h = H_s(domain ‖ D ‖ index). Exported for the test vectors. */
export function sharedScalar(d: Uint8Array, index = 0): Uint8Array {
  return wide(DOMAIN, d, u32le(index));
}

export interface OneTime {
  /** Ephemeral public key R = r·G. In a swap this is the swap_id (escrow PDA seed). */
  R: Uint8Array;
  /** One-time key P_i = h·G + S, as bytes and as the Solana address. */
  key: Uint8Array;
  address: PublicKey;
  index: number;
}

/**
 * PAYER side: derive a fresh one-time address for a recipient's meta key. `r` is for test vectors
 * only; in production it must be fresh randomness and is discarded after use (the payer never
 * needs it again).
 */
export function deriveOneTime(meta: StealthMetaPub, opts: { r?: Uint8Array; index?: number } = {}): OneTime {
  if (!K.isGoodPoint(meta.viewPub) || !K.isGoodPoint(meta.spendPub)) throw new Error('recipient meta key is not prime-order');
  const index = opts.index ?? 0;
  const r = opts.r ?? K.randomScalar();
  const R = K.pub(r);
  const h = sharedScalar(dh(r, meta.viewPub), index);
  const key = Point.BASE.multiply(K.leToBig(h)).add(Point.fromHex(meta.spendPub)).toRawBytes();
  if (!K.isGoodPoint(key)) throw new Error('degenerate one-time key');
  return { R, key, address: new PublicKey(key), index };
}

/**
 * RECIPIENT side, view key only: is `candidate` the one-time key for (R, index)? Rejects an R that
 * is not a canonical prime-order point (a torsion-tweaked or small-order R never matches).
 */
export function isMine(view: Uint8Array, spendPub: Uint8Array, R: Uint8Array, candidate: Uint8Array, index = 0): boolean {
  u32le(index);
  if (!K.isGoodPoint(R) || candidate.length !== 32) return false;
  const h = sharedScalar(dh(view, R), index);
  const want = Point.BASE.multiply(K.leToBig(h)).add(Point.fromHex(spendPub)).toRawBytes();
  return K.equalBytes(want, candidate);
}

/** RECIPIENT side, view + spend: the private scalar s_i = h + s for (R, index). Checks s_i·G. */
export function oneTimeSecret(meta: StealthMeta, R: Uint8Array, index = 0, expect?: Uint8Array): Uint8Array {
  if (!K.isGoodPoint(R)) throw new Error('ephemeral key is not a prime-order point');
  const h = sharedScalar(dh(meta.view, R), index);
  const s = K.scalarAdd(h, meta.spend);
  if (K.leToBig(s) === 0n) throw new Error('degenerate one-time secret');
  if (expect && !K.equalBytes(K.pub(s), expect)) throw new Error('this stealth key does not own that address');
  return s;
}

// ---------------------------------------------------------------- raw-scalar ed25519 signing
const modL = (n: bigint) => ((n % L) + L) % L;
const hashL = (...p: Uint8Array[]) => modL(K.leToBig(sha512(concatBytes(...p))));

/**
 * RFC 8032 Ed25519 signing from an expanded key (scalar a, 32-byte nonce prefix). With the a and
 * prefix that SHA-512(seed) gives, the output is bit-identical to standard Ed25519 (tested against
 * the RFC 8032 vectors).
 */
export function signExpanded(a: bigint, prefix: Uint8Array, msg: Uint8Array): Uint8Array {
  if (a <= 0n || modL(a) === 0n) throw new Error('bad scalar');
  if (prefix.length !== 32) throw new Error('prefix must be 32 bytes');
  // A is always recomputed from a: a caller-supplied A with the same nonce would leak a.
  const pubA = Point.BASE.multiply(modL(a)).toRawBytes();
  const k = hashL(prefix, msg);
  if (k === 0n) throw new Error('degenerate nonce');
  const Rs = Point.BASE.multiply(k).toRawBytes();
  const c = hashL(Rs, pubA, msg);
  const S = modL(k + c * modL(a));
  return concatBytes(Rs, K.bigToLe32(S));
}

/**
 * Sign with a raw scalar (no seed). The nonce prefix is derived from the scalar under a separate
 * domain, so it is as secret as the scalar and deterministic (same message, same signature).
 */
export function signRaw(msg: Uint8Array, scalar: Uint8Array): Uint8Array {
  if (!K.isCanonical(scalar) || K.leToBig(scalar) === 0n) throw new Error('signing scalar must be canonical and nonzero');
  const prefix = sha512(concatBytes(utf8ToBytes('halfkey-stealth-nonce-v1'), scalar)).slice(0, 32);
  return signExpanded(K.leToBig(scalar), prefix, msg);
}

/**
 * Transaction signer for a one-time address. Implements the signer shape the SDK already uses
 * (publicKey + sign(tx)), for legacy and v0 transactions. The scalar stays in memory only.
 */
export class StealthSigner {
  readonly publicKey: PublicKey;
  #s: Uint8Array;
  constructor(secret: Uint8Array) {
    this.#s = Uint8Array.from(secret);
    this.publicKey = new PublicKey(K.pub(this.#s));
  }
  signMessage(msg: Uint8Array): Uint8Array { return signRaw(msg, this.#s); }
  async sign<T extends Transaction | VersionedTransaction>(tx: T): Promise<T> { return this.signTransaction(tx); }
  signTransaction<T extends Transaction | VersionedTransaction>(tx: T): T {
    if (tx instanceof VersionedTransaction) {
      tx.addSignature(this.publicKey, this.signMessage(tx.message.serialize()));
    } else {
      const msg = (tx as Transaction).serializeMessage();
      (tx as Transaction).addSignature(this.publicKey, Buffer.from(this.signMessage(msg)));
    }
    return tx;
  }
  wipe() { this.#s.fill(0); }
}

// ---------------------------------------------------------------- swap records (XMR -> SOL)
/** A stealth receive found on chain (live escrow or lock history). */
export interface StealthHit {
  escrow: PublicKey;
  R: Uint8Array;             // = swap_id
  address: PublicKey;        // = escrow claimer = the one-time key
  amount?: bigint;           // escrow amount (lamports) when known
  state?: number;
  source: 'escrow' | 'history';
  signature?: string;
}

/** Pure filter over decoded escrows: XMR->SOL escrows whose claimer is our one-time key. */
export type ScanRecord = Pick<P.EscrowAccount, 'address' | 'direction' | 'state' | 'swapId' | 'claimer' | 'amount'>;
export function scanEscrows(escrows: ScanRecord[], view: Uint8Array, spendPub: Uint8Array): StealthHit[] {
  const out: StealthHit[] = [];
  for (const e of escrows) {
    if (e.direction !== P.DIR_XMR_TO_SOL) continue;
    if (isMine(view, spendPub, e.swapId, e.claimer.toBytes())) {
      out.push({ escrow: e.address!, R: e.swapId, address: e.claimer, amount: e.amount, state: e.state, source: 'escrow' });
    }
  }
  return out;
}

const OFF_DIRECTION = 3;

/** Every live XMR->SOL escrow of the program (one RPC call, the same query for every user). */
export async function fetchXmrToSolEscrows(conn: Connection, pid: PublicKey): Promise<P.EscrowAccount[]> {
  const xs = await conn.getProgramAccounts(pid, {
    commitment: 'confirmed',
    filters: [{ dataSize: P.ESCROW_LEN }, { memcmp: { offset: OFF_DIRECTION, bytes: bs58.encode(Uint8Array.of(P.DIR_XMR_TO_SOL)) } }],
  });
  const out: P.EscrowAccount[] = [];
  for (const x of xs) { try { out.push(P.decodeEscrow(x.account.data, x.pubkey)); } catch { /* not an escrow */ } }
  return out;
}

/**
 * Scan input without the full accounts: only bytes 0..144 of each XMR->SOL escrow (state,
 * direction, swap_id, locker, claimer, maker, amount), about a third of the download.
 */
export async function fetchStealthCandidates(conn: Connection, pid: PublicKey): Promise<ScanRecord[]> {
  const xs = await conn.getProgramAccounts(pid, {
    commitment: 'confirmed', dataSlice: { offset: 0, length: 144 },
    filters: [{ dataSize: P.ESCROW_LEN }, { memcmp: { offset: OFF_DIRECTION, bytes: bs58.encode(Uint8Array.of(P.DIR_XMR_TO_SOL)) } }],
  });
  const out: ScanRecord[] = [];
  for (const x of xs) {
    const d = x.account.data;
    if (d.length < 144 || d[0] !== 0xe5) continue;
    out.push({ address: x.pubkey, state: d[2], direction: d[3], swapId: new Uint8Array(d.subarray(8, 40)), claimer: new PublicKey(d.subarray(72, 104)), amount: Buffer.from(d).readBigUInt64LE(136) });
  }
  return out;
}

/** Lock instruction data: [6, swap_id 32, claimer 32, direction u8, amount u64, ...]. */
export function parseLockIx(data: Uint8Array): { swapId: Uint8Array; claimer: PublicKey; direction: number; amount: bigint } | null {
  if (data.length < 74 || data[0] !== 6) return null;
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return { swapId: new Uint8Array(data.subarray(1, 33)), claimer: new PublicKey(new Uint8Array(data.subarray(33, 65))), direction: data[65], amount: dv.getBigUint64(66, true) };
}

/**
 * Scan the program's transaction history for XMR->SOL locks paying us. Finds stealth receives
 * whose escrow was already closed (the maker may close a settled escrow and take its rent back).
 * Needs an RPC that serves history for the range you scan. Newest first; stops at `until` (unix s).
 */
export async function scanLockHistory(conn: Connection, pid: PublicKey, view: Uint8Array, spendPub: Uint8Array,
  opts: { until?: number; maxSignatures?: number; pageSize?: number } = {}): Promise<StealthHit[]> {
  const hits: StealthHit[] = [];
  const max = opts.maxSignatures ?? Infinity, page = Math.min(opts.pageSize ?? 500, 1000);
  let before: string | undefined, seen = 0;
  while (seen < max) {
    const sigs = await conn.getSignaturesForAddress(pid, { before, limit: page }, 'confirmed');
    if (!sigs.length) break;
    seen += sigs.length;
    before = sigs[sigs.length - 1].signature;
    const ok = sigs.filter((s) => !s.err);
    for (let i = 0; i < ok.length; i += 20) { // the site's RPC route takes batches of 20
      const chunk = ok.slice(i, i + 20);
      const txs = await conn.getTransactions(chunk.map((s) => s.signature), { commitment: 'confirmed', maxSupportedTransactionVersion: 0 });
      txs.forEach((tx, j) => {
        if (!tx || tx.meta?.err) return;
        // Account list: static keys, then loaded writable, then loaded readonly (v0 lookup tables).
        const keys = [...tx.transaction.message.staticAccountKeys,
          ...(tx.meta?.loadedAddresses?.writable ?? []), ...(tx.meta?.loadedAddresses?.readonly ?? [])];
        // Top-level instructions plus CPI (a multisig or router maker locks through another program).
        const ixs: { programIdIndex: number; accounts: number[]; data: Uint8Array }[] = [
          ...tx.transaction.message.compiledInstructions.map((ix) => ({ programIdIndex: ix.programIdIndex, accounts: ix.accountKeyIndexes, data: ix.data })),
          ...(tx.meta?.innerInstructions ?? []).flatMap((g) => g.instructions.map((ix: any) => ({ programIdIndex: ix.programIdIndex, accounts: ix.accounts, data: bs58.decode(ix.data) }))),
        ];
        for (const ix of ixs) {
          if (!keys[ix.programIdIndex]?.equals(pid)) continue;
          const l = parseLockIx(ix.data);
          if (!l || l.direction !== P.DIR_XMR_TO_SOL) continue;
          if (!isMine(view, spendPub, l.swapId, l.claimer.toBytes())) continue;
          const locker = keys[ix.accounts[0]];
          if (!locker) continue;
          hits.push({ escrow: P.pda.escrow(pid, locker, l.swapId), R: l.swapId, address: l.claimer, amount: l.amount, source: 'history', signature: chunk[j].signature });
        }
      });
    }
    if (opts.until && (sigs[sigs.length - 1].blockTime ?? Infinity) < opts.until) break;
    if (sigs.length < page) break;
  }
  return hits;
}

/** Live escrows plus (optionally) history, de-duplicated by one-time address. */
export async function scanStealth(conn: Connection, pid: PublicKey, meta: StealthMetaPub & { view: Uint8Array }, opts: { history?: boolean; until?: number } = {}): Promise<StealthHit[]> {
  const live = scanEscrows(await fetchStealthCandidates(conn, pid), meta.view, meta.spendPub);
  // History errors propagate: "nothing found" must never hide "could not search".
  const hist = opts.history ? await scanLockHistory(conn, pid, meta.view, meta.spendPub, { until: opts.until }) : [];
  const by = new Map<string, StealthHit>();
  for (const h of [...hist, ...live]) by.set(h.address.toBase58(), h);
  return [...by.values()];
}

/**
 * XMR->SOL with a stealth claimer. Before sending XMR the user checks that the escrow's claimer is
 * really the one-time key for swap_id under OUR meta key (and that we can sign for it). Throws if not.
 */
export function checkStealthClaimer(meta: StealthMeta, swapId: Uint8Array, claimer: PublicKey): Uint8Array {
  if (!isMine(meta.view, meta.spendPub, swapId, claimer.toBytes())) throw new Error('the escrow does not pay your stealth key');
  return oneTimeSecret(meta, swapId, 0, claimer.toBytes());
}

// ---------------------------------------------------------------- XMR -> SOL swap flow
/**
 * One-time claimer for an XMR->SOL swap. The client is the payer-side deriver here: fresh r,
 * R = swap id, P_i = claimer; the maker only ever sees (R, P_i), never the meta key or h. Then
 * defence in depth: the derived address and escrow must have no history at all (a reused swap id
 * would mean a reused Monero half).
 */
export async function stealthClaimerForSwap(conn: Connection, pid: PublicKey, meta: StealthMeta, makerAuthority: PublicKey): Promise<{ swapId: Uint8Array; claimer: PublicKey }> {
  const ot = deriveOneTime(meta);
  await assertFresh(conn, [ot.address, P.pda.escrow(pid, makerAuthority, ot.R)]);
  return { swapId: ot.R, claimer: ot.address };
}

/** Throws if any of these addresses exists or has any transaction history. */
export async function assertFresh(conn: Connection, addrs: PublicKey[]) {
  const infos = await conn.getMultipleAccountsInfo(addrs, 'confirmed');
  if (infos.some((a) => a)) throw new Error('derived address already exists on chain; refusing to reuse it');
  for (const a of addrs) {
    const h = await conn.getSignaturesForAddress(a, { limit: 1 }, 'confirmed');
    if (h.length) throw new Error('derived address already has history on chain; refusing to reuse it');
  }
}

/**
 * Smallest swap that can pay a fresh address: the claimer receives amount - protocol fee and must
 * end rent-exempt, plus room for one sweep fee (a claim that fails on rent still publishes the secret).
 */
export async function minStealthLamports(conn: Connection, feeBps: number): Promise<bigint> {
  const rentMin = BigInt(await conn.getMinimumBalanceForRentExemption(0));
  const need = rentMin + 10_000n;
  return (need * 10_000n + BigInt(10_000 - feeBps) - 1n) / BigInt(10_000 - feeBps);
}

// ---------------------------------------------------------------- sweep (fees paid from the proceeds)
export const SWEEP_CU = 600;          // system transfer (150 CU measured) + the two compute-budget ixs

/**
 * Move SOL out of a one-time address. The one-time address is its own fee payer: no other wallet
 * touches the transaction (that would link them). amount 'all' empties and closes the account.
 * A partial sweep must leave 0 or at least the rent-exempt minimum; a new destination must
 * receive at least the rent-exempt minimum.
 */
export async function buildSweep(args: {
  conn: Connection; from: PublicKey; to: PublicKey; amount: 'all' | bigint; priorityMicroLamports?: number;
}): Promise<{ tx: Transaction; amount: bigint; fee: bigint; lastValidBlockHeight: number }> {
  const { conn, from, to } = args;
  if (from.equals(to)) throw new Error('destination is the same address');
  const [bal, toInfo, rentMin, bh] = await Promise.all([
    conn.getBalance(from, 'confirmed').then(BigInt), conn.getAccountInfo(to, 'confirmed'),
    conn.getMinimumBalanceForRentExemption(0).then(BigInt), conn.getLatestBlockhash('confirmed'),
  ]);
  const mk = (lamports: bigint) => {
    const tx = new Transaction({ feePayer: from, blockhash: bh.blockhash, lastValidBlockHeight: bh.lastValidBlockHeight });
    if (args.priorityMicroLamports) {
      tx.add(ComputeBudgetProgram.setComputeUnitLimit({ units: SWEEP_CU }), ComputeBudgetProgram.setComputeUnitPrice({ microLamports: args.priorityMicroLamports }));
    }
    tx.add(SystemProgram.transfer({ fromPubkey: from, toPubkey: to, lamports }));
    return tx;
  };
  const feeRes = await conn.getFeeForMessage(mk(1n).compileMessage(), 'confirmed');
  if (feeRes.value == null) throw new Error('could not price the fee');
  const fee = BigInt(feeRes.value);
  const amount = args.amount === 'all' ? bal - fee : args.amount;
  if (amount <= 0n) throw new Error('balance does not cover the network fee');
  const left = bal - fee - amount;
  if (left < 0n) throw new Error('amount plus fee exceeds the balance');
  if (left > 0n && left < rentMin) throw new Error(`leave 0 or at least ${rentMin} lamports (rent-exempt minimum)`);
  if (!toInfo && amount < rentMin) throw new Error(`a new destination needs at least ${rentMin} lamports`);
  return { tx: mk(amount), amount, fee, lastValidBlockHeight: bh.lastValidBlockHeight };
}

/** Build, sign with the one-time key, send and confirm a sweep. */
export async function sweep(args: { conn: Connection; signer: StealthSigner; to: PublicKey; amount?: 'all' | bigint; priorityMicroLamports?: number; confirm?: (sig: string, lastValidBlockHeight: number) => Promise<void> }): Promise<{ sig: string; amount: bigint; fee: bigint }> {
  const b = await buildSweep({ conn: args.conn, from: args.signer.publicKey, to: args.to, amount: args.amount ?? 'all', priorityMicroLamports: args.priorityMicroLamports });
  args.signer.signTransaction(b.tx);
  const sig = await args.conn.sendRawTransaction(b.tx.serialize(), { preflightCommitment: 'confirmed' });
  if (args.confirm) await args.confirm(sig, b.lastValidBlockHeight); // the browser polls: its RPC route has no websocket
  else {
    const r = await args.conn.confirmTransaction({ signature: sig, blockhash: b.tx.recentBlockhash!, lastValidBlockHeight: b.lastValidBlockHeight }, 'confirmed');
    if (r.value.err) throw new Error(`sweep failed: ${JSON.stringify(r.value.err)}`);
  }
  return { sig, amount: b.amount, fee: b.fee };
}

