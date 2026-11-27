// Refund towers for XMR->SOL.
//
// The maker locks SOL; the user sends XMR to an address whose spend key is (user half + maker half).
// The claim (which reveals the user's half) is possible only after the maker's `ready`, until t1.
// If the maker never says ready (it went dark after a real deposit), the user needs the maker's half
// to take its XMR back. So the maker deals that half 2-of-3 to refund towers with Feldman commitments:
//   f(x) = m + a*x (mod L),  share_i = f(i),  C0 = m*G (the escrow's refund point),  C1 = a*G.
// Each tower checks share_i*G == C0 + i*C1 and signs an ack bound to the escrow's on-chain terms and to
// C1. The page shows a deposit address only with enough acks on the same C1 (so any two shares rebuild m).
// A tower releases its share only when a claim can no longer happen: the escrow is aborted or refunded,
// or a finalized clock is past t1 and it is not claimed, with every reader agreeing. Then the half
// helps only the user; a tower submits the existing permissionless `refund` (SOL back to the maker,
// the half lands on chain) and the page can also rebuild the half from two released shares itself.
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils';
import { Keypair, PublicKey } from '@solana/web3.js';
import * as K from './keys.ts';
import * as P from './program.ts';

const Point = ed25519.ExtendedPoint;
export const N_TOWERS = 3;
export const THRESHOLD = 2;
/** Seconds past t1, on a finalized clock, before a LOCKED/READY escrow counts as unclaimable. */
export const RELEASE_MARGIN_SECS = 120;

export interface Commitments { c0: Uint8Array; c1: Uint8Array }
export interface Share { i: number; s: Uint8Array }

/** Deal the maker's half m (canonical, nonzero) into 3 shares, threshold 2. */
export function deal(m: Uint8Array): { c: Commitments; shares: Share[] } {
  if (!K.isCanonical(m) || K.leToBig(m) === 0n) throw new Error('bad half');
  const a = K.randomScalar();
  const mv = K.leToBig(m), av = K.leToBig(a);
  const shares: Share[] = [];
  for (let i = 1; i <= N_TOWERS; i++) {
    const s = (mv + av * BigInt(i)) % K.L;
    if (s === 0n) return deal(m); // probability ~2^-252; a zero share would be refused by its tower
    shares.push({ i, s: K.bigToLe32(s) });
  }
  return { c: { c0: K.pub(m), c1: K.pub(a) }, shares };
}

/** share.s*G == C0 + i*C1, with canonical share, index 1..3, and prime-order, canonical commitments. */
export function verifyShare(sh: Share, c: Commitments): boolean {
  try {
    if (!Number.isInteger(sh.i) || sh.i < 1 || sh.i > N_TOWERS) return false;
    if (!K.isCanonical(sh.s) || K.leToBig(sh.s) === 0n) return false;
    if (!K.isGoodPoint(c.c0) || !K.isGoodPoint(c.c1)) return false;
    const lhs = Point.BASE.multiply(K.leToBig(sh.s));
    const rhs = Point.fromHex(c.c0).add(Point.fromHex(c.c1).multiply(BigInt(sh.i)));
    return lhs.equals(rhs);
  } catch {
    return false;
  }
}

const modInv = (x: bigint) => {
  // L is prime: x^(L-2)
  let r = 1n, b = ((x % K.L) + K.L) % K.L, e = K.L - 2n;
  while (e > 0n) { if (e & 1n) r = (r * b) % K.L; b = (b * b) % K.L; e >>= 1n; }
  return r;
};

/** Rebuild m from two shares at distinct indices (Lagrange at 0) and check it against the refund point. */
export function combine(shares: Share[], refundPoint: Uint8Array): Uint8Array {
  const uniq = new Map<number, Share>();
  for (const s of shares) if (!uniq.has(s.i)) uniq.set(s.i, s);
  const two = [...uniq.values()].slice(0, THRESHOLD);
  if (two.length < THRESHOLD) throw new Error('need two shares at distinct indices');
  const [p, q] = two;
  const xi = BigInt(p.i), xj = BigInt(q.i);
  // f(0) = s_i * xj/(xj - xi) + s_j * xi/(xi - xj)
  const li = (xj * modInv(xj - xi)) % K.L, lj = (xi * modInv(xi - xj)) % K.L;
  const m = (((K.leToBig(p.s) * li) % K.L + (K.leToBig(q.s) * lj) % K.L) % K.L + K.L) % K.L;
  if (m === 0n) throw new Error('shares do not rebuild the refund point');
  const out = K.bigToLe32(m);
  if (!K.equalBytes(K.pub(out), refundPoint)) throw new Error('shares do not rebuild the refund point');
  return out;
}

// ---------------------------------------------------------------- binding to the escrow
/** Everything a share and an ack are bound to. All of it is on chain except C1. */
export interface Terms {
  programId: PublicKey; escrow: PublicKey; createdAt: bigint; refundPoint: Uint8Array; c1: Uint8Array;
  locker: PublicKey; claimer: PublicKey; amount: bigint; t1: bigint;
}
export function termsOf(pid: PublicKey, escrow: PublicKey, e: P.EscrowAccount, c1: Uint8Array): Terms {
  return { programId: pid, escrow, createdAt: e.createdAt, refundPoint: e.refundPoint, c1, locker: e.locker, claimer: e.claimer, amount: e.amount, t1: e.t1 };
}
const le64 = (v: bigint) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigInt64(0, v, true); return b; };
function termsBytes(t: Terms): Uint8Array {
  return concatBytes(t.programId.toBytes(), t.escrow.toBytes(), le64(t.createdAt), t.refundPoint, t.c1, t.locker.toBytes(), t.claimer.toBytes(), le64(t.amount), le64(t.t1));
}
const ACK_DOMAIN = utf8ToBytes('halfkey-refund-tower-ack-v1');
const DEAL_DOMAIN = utf8ToBytes('halfkey-refund-tower-deal-v1');
export function ackMessage(t: Terms, index: number, tower: PublicKey): Uint8Array {
  return sha256(concatBytes(ACK_DOMAIN, termsBytes(t), new Uint8Array([index]), tower.toBytes()));
}
export function dealMessage(t: Terms, index: number, tower: PublicKey, share: Uint8Array): Uint8Array {
  return sha256(concatBytes(DEAL_DOMAIN, termsBytes(t), new Uint8Array([index]), tower.toBytes(), sha256(share)));
}

/**
 * What the maker POSTs to tower `index` (hex fields). `sig` binds the on-chain terms (checked after a chain read);
 * `auth` is the same maker's signature over the request itself, checked against the tower's maker list BEFORE any
 * chain read, so an unsigned flood costs the tower nothing and can't be pinned on the maker's IP.
 */
export interface DealReq { escrow: string; index: number; share: string; c1: string; sig: string; maker?: string; auth?: string }
const AUTH_DOMAIN = utf8ToBytes('halfkey-refund-tower-post-v1');
export function authMessage(r: Pick<DealReq, 'escrow' | 'index' | 'share' | 'c1' | 'sig'>): Uint8Array {
  return sha256(concatBytes(AUTH_DOMAIN, utf8ToBytes(`${r.escrow}|${r.index}|${r.share}|${r.c1}|${r.sig}`)));
}
export function signDeal(t: Terms, sh: Share, tower: PublicKey, makerSecret32: Uint8Array): DealReq {
  const base = { escrow: t.escrow.toBase58(), index: sh.i, share: K.toHex(sh.s), c1: K.toHex(t.c1), sig: K.toHex(ed25519.sign(dealMessage(t, sh.i, tower, sh.s), makerSecret32)) };
  return { ...base, maker: t.locker.toBase58(), auth: K.toHex(ed25519.sign(authMessage(base), makerSecret32)) };
}
/** The request's own signature by a maker on the list (no chain read). */
export function verifyDealAuth(r: DealReq, makers: string[]): boolean {
  try {
    if (!r.maker || !r.auth || !makers.includes(r.maker)) return false;
    return ed25519.verify(K.fromHex(r.auth), authMessage(r), new PublicKey(r.maker).toBytes());
  } catch {
    return false;
  }
}
export function verifyDeal(r: DealReq, t: Terms, tower: PublicKey): boolean {
  try {
    if (r.escrow !== t.escrow.toBase58() || r.c1 !== K.toHex(t.c1)) return false;
    return ed25519.verify(K.fromHex(r.sig), dealMessage(t, r.index, tower, K.fromHex(r.share)), t.locker.toBytes());
  } catch {
    return false;
  }
}

export interface Ack { index: number; tower: string; c1: string; sig: string }
export function signAck(t: Terms, index: number, tower: Keypair): Ack {
  return { index, tower: tower.publicKey.toBase58(), c1: K.toHex(t.c1), sig: K.toHex(ed25519.sign(ackMessage(t, index, tower.publicKey), tower.secretKey.slice(0, 32))) };
}

/** One ack on its own: from listed tower n at index n, on a valid C1, signed over this escrow's terms. */
export function verifyAck(a: Ack, listed: { pubkey: PublicKey }[], pid: PublicKey, escrow: PublicKey, e: P.EscrowAccount): boolean {
  try {
    if (!a || typeof a.c1 !== 'string' || typeof a.sig !== 'string') return false;
    const n = a.index;
    if (!Number.isInteger(n) || n < 1 || n > listed.length) return false;
    const tw = listed[n - 1].pubkey;
    if (a.tower !== tw.toBase58()) return false;
    const c1b = K.fromHex(a.c1);
    if (c1b.length !== 32 || !K.isGoodPoint(c1b)) return false;
    return ed25519.verify(K.fromHex(a.sig), ackMessage(termsOf(pid, escrow, e, c1b), n, tw), tw.toBytes());
  } catch {
    return false;
  }
}

/**
 * The page's check before it shows a deposit address: at least `minAcks` acks from distinct listed
 * towers (tower n of the list acks index n), every one on the same C1 and on this escrow's terms.
 */
export function checkAcks(
  acks: Ack[], listed: { pubkey: PublicKey }[], pid: PublicKey, escrow: PublicKey, e: P.EscrowAccount, minAcks: number,
): { ok: true; c1: Uint8Array; count: number } | { ok: false; why: string } {
  if (!Number.isInteger(minAcks) || minAcks < THRESHOLD) return { ok: false, why: 'fewer than two acks can never rebuild the half' };
  if (listed.length > N_TOWERS) return { ok: false, why: 'too many towers listed' };
  if (e.direction !== 2) return { ok: false, why: 'not an XMR->SOL escrow' };
  // Group by C1: one tower acking other commitments (a bad tower, or a bad maker) must not veto the rest.
  const groups = new Map<string, Set<number>>();
  for (const a of acks ?? []) {
    if (!verifyAck(a, listed, pid, escrow, e)) continue;
    const g = groups.get(a.c1) ?? new Set<number>();
    g.add(a.index);
    groups.set(a.c1, g);
  }
  let best: [string, number] | null = null;
  for (const [c1, g] of groups) if (!best || g.size > best[1]) best = [c1, g.size];
  if (!best || best[1] < minAcks) return { ok: false, why: `${best?.[1] ?? 0} of ${minAcks} refund towers confirmed` };
  return { ok: true, c1: K.fromHex(best[0]), count: best[1] };
}

// ---------------------------------------------------------------- release rule
/** One reader's view at finalized commitment: the escrow (or its absence) with that snapshot's clock. */
export type ChainRead = { kind: 'escrow'; e: P.EscrowAccount; clock: number } | { kind: 'missing'; clock: number } | { kind: 'error' };
export interface Held { createdAt: bigint; refundPoint: Uint8Array; t1: bigint }
/**
 *  'release' : a claim is impossible (aborted, refunded, or past t1 + margin and not claimed)
 *  'claimed' : claimed: the share must be destroyed and never released
 *  'gone'    : no escrow, or a different one at the address: never release on this record alone
 *  'wait'    : anything else, including readers that disagree or fail
 */
export function releaseDecision(reads: ChainRead[], held: Held, marginSecs = RELEASE_MARGIN_SECS): 'release' | 'claimed' | 'gone' | 'wait' {
  if (reads.length < 2 || reads.some((r) => r.kind === 'error')) return 'wait';
  const one = (r: ChainRead) => {
    if (r.kind === 'error') return 'wait' as const;
    if (r.kind === 'missing') return 'gone' as const;
    const e = r.e;
    if (e.createdAt !== held.createdAt || !K.equalBytes(e.refundPoint, held.refundPoint) || e.t1 !== held.t1 || e.direction !== 2) return 'gone' as const;
    if (e.state === P.ST.CLAIMED) return 'claimed' as const;
    if (e.state === P.ST.ABORTED || e.state === P.ST.REFUNDED) return 'release' as const;
    if (e.state === P.ST.LOCKED || e.state === P.ST.READY) return r.clock >= Number(held.t1) + marginSecs ? 'release' as const : 'wait' as const;
    return 'wait' as const;
  };
  const v = reads.map(one);
  return v.every((x) => x === v[0]) ? v[0] : 'wait';
}
