// HALFKEY OTC: request-for-quote for big size, settled as atomic-swap tranches.
//
// Privacy: there is no order book. The taker's browser sends a signed RFQ straight to each
// registered maker's endpoint (from the on-chain registry); each maker answers that taker only.
// Quotes are fetched by the RFQ id, a 128-bit secret only the taker and that maker know.
//
// Settlement: a firm quote covers `fill` of the requested size at one price, split into
// tranches. Each tranche is a normal HALFKEY escrow (flag OTC), so every tranche is atomic on
// its own. Rules (also in README):
//   * tranche size <= min(program OTC cap, maker OTC max); at most MAX_TRANCHES per trade.
//   * all tranches lock in one wallet prompt; the maker funds every locked tranche in ONE Monero
//     transaction (one output per tranche), so a big fill needs no chain of change outputs.
//   * partial fill: a maker may quote fill < size but >= the taker's minFill. Tranches that are
//     not locked before the consent expires lapse; tranches that fail (no XMR -> watchtower
//     abort -> refund) end the trade. Filled tranches stand. No penalty on chain beyond the
//     maker's OTC reputation (fills / failed / declined counters in its registry account).
//   * the price is per trade: tranche k gets floor(total * size_k / fill), the last tranche the
//     remainder, so the sum is exact.
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, concatBytes, hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils';

export const MAX_TRANCHES = 12;

export interface Rfq {
  v: 1;
  id: string;            // hex(16), the capability for reading quotes
  side: 1 | 2;           // 1 = taker sells SOL for XMR, 2 = taker sells XMR for SOL
  amount: string;        // size in the taker's input unit (lamports for side 1, piconero for side 2)
  minFill: string;       // smallest acceptable partial fill, same unit
  expiresAt: number;     // quotes accepted until (unix seconds)
  taker: string;         // base58 wallet
}

export function newRfq(side: 1 | 2, amount: bigint, minFill: bigint, taker: string, ttlSecs = 900, now = Math.floor(Date.now() / 1000)): Rfq {
  if (amount <= 0n || minFill <= 0n || minFill > amount) throw new Error('bad size');
  return { v: 1, id: bytesToHex(randomBytes(16)), side, amount: amount.toString(), minFill: minFill.toString(), expiresAt: now + ttlSecs, taker };
}

export function rfqBytes(r: Rfq): Uint8Array {
  const c = { v: r.v, id: r.id, side: r.side, amount: r.amount, minFill: r.minFill, expiresAt: r.expiresAt, taker: r.taker };
  return utf8ToBytes('halfkey-rfq-v1:' + JSON.stringify(c));
}
export const rfqHash = (r: Rfq) => bytesToHex(sha256(rfqBytes(r)));

/** The taker signs the RFQ with its wallet (signMessage over these bytes). */
export function verifyRfq(r: Rfq, sigHex: string, takerPub: Uint8Array): boolean {
  try { return ed25519.verify(hexToBytes(sigHex), rfqBytes(r), takerPub); } catch { return false; }
}

export function checkRfq(r: Rfq, now: number): string | null {
  if (r.v !== 1 || !/^[0-9a-f]{32}$/.test(r.id)) return 'bad rfq';
  if (r.side !== 1 && r.side !== 2) return 'bad side';
  if (!/^\d+$/.test(r.amount) || !/^\d+$/.test(r.minFill)) return 'bad size';
  const a = BigInt(r.amount), m = BigInt(r.minFill);
  if (a <= 0n || m <= 0n || m > a) return 'bad size';
  if (r.expiresAt <= now) return 'rfq expired';
  if (r.expiresAt > now + 86_400) return 'rfq expiry too far out';
  return null;
}

export interface OtcQuote {
  v: 1;
  kind: 'otc';
  rfq: string;           // rfq id
  rfqHash: string;       // binds the exact request
  maker: string;
  side: 1 | 2;
  lamports: string;      // SOL side of the whole fill
  piconero: string;      // XMR side of the whole fill
  tranches: number;      // number of escrows
  feeBps: number;
  expiresAt: number;     // firm until: lock (side 1) or accept (side 2) before this
  nonce: string;
}

export function otcQuoteBytes(q: OtcQuote): Uint8Array {
  const c = { v: q.v, kind: q.kind, rfq: q.rfq, rfqHash: q.rfqHash, maker: q.maker, side: q.side, lamports: q.lamports, piconero: q.piconero, tranches: q.tranches, feeBps: q.feeBps, expiresAt: q.expiresAt, nonce: q.nonce };
  return utf8ToBytes('halfkey-otc-quote-v1:' + JSON.stringify(c));
}
export const otcQuoteHash = (q: OtcQuote) => sha256(otcQuoteBytes(q));
export function signOtcQuote(q: OtcQuote, makerSecret32: Uint8Array): string { return bytesToHex(ed25519.sign(otcQuoteBytes(q), makerSecret32)); }
export function verifyOtcQuote(q: OtcQuote, sigHex: string, makerPub: Uint8Array): boolean {
  try { return ed25519.verify(hexToBytes(sigHex), otcQuoteBytes(q), makerPub); } catch { return false; }
}

export interface Tranche { index: number; lamports: bigint; piconero: bigint; quoteHash: Uint8Array }

/** The escrow quote_hash of tranche k: binds the trade quote, the tranche index and the count. */
export function trancheHash(q: OtcQuote, k: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint16(0, k, true);
  new DataView(b.buffer).setUint16(2, q.tranches, true);
  return sha256(concatBytes(utf8ToBytes('halfkey-otc-tranche-v1:'), otcQuoteHash(q), b));
}

/** Split a fill into `n` tranches: equal lamports (last takes the remainder), XMR pro rata, exact sums. */
export function planTranches(q: OtcQuote): Tranche[] {
  const n = q.tranches;
  if (!Number.isInteger(n) || n < 1 || n > MAX_TRANCHES) throw new Error('bad tranche count');
  const L = BigInt(q.lamports), X = BigInt(q.piconero);
  if (L <= 0n || X <= 0n) throw new Error('empty quote');
  const per = L / BigInt(n);
  if (per === 0n) throw new Error('fill too small for this many tranches');
  const out: Tranche[] = [];
  let lAcc = 0n, xAcc = 0n;
  for (let k = 0; k < n; k++) {
    const lam = k === n - 1 ? L - lAcc : per;
    const pic = k === n - 1 ? X - xAcc : (X * lam) / L;
    lAcc += lam; xAcc += pic;
    out.push({ index: k, lamports: lam, piconero: pic, quoteHash: trancheHash(q, k) });
  }
  return out;
}

/** How many tranches a fill needs under a per-escrow cap. */
export function tranchesFor(lamports: bigint, cap: bigint): number {
  if (cap <= 0n) throw new Error('no cap');
  return Number((lamports + cap - 1n) / cap);
}

/** Taker-side checks of a maker's firm quote before anything is signed. */
export function checkOtcQuote(q: OtcQuote, sig: string, r: Rfq, makerPub: Uint8Array, opts: { feeBps: number[]; capLamports: bigint; now: number }): string | null {
  if (q.v !== 1 || q.kind !== 'otc') return 'unknown quote';
  if (q.rfq !== r.id || q.rfqHash !== rfqHash(r)) return 'quote is for a different request';
  if (q.side !== r.side) return 'wrong side';
  if (!verifyOtcQuote(q, sig, makerPub)) return 'bad quote signature';
  if (q.expiresAt <= opts.now + 10) return 'quote expired';
  if (!opts.feeBps.includes(q.feeBps)) return 'quote fee does not match the program';
  let tr: Tranche[];
  try { tr = planTranches(q); } catch (e) { return (e as Error).message; }
  if (tr.some((t) => t.lamports > opts.capLamports)) return 'a tranche is above the per-escrow cap';
  const filled = r.side === 1 ? BigInt(q.lamports) : BigInt(q.piconero);
  if (filled > BigInt(r.amount)) return 'quote is larger than the request';
  if (filled < BigInt(r.minFill)) return 'quote is below your minimum fill';
  return null;
}

/** What the taker signs to accept a quote: binds the quote and every tranche's keys + watchtowers. */
export function acceptBytes(q: OtcQuote, tranches: { swapId: string; takerSpendPub: string; viewSecret: string; watchtowers?: string[] }[]): Uint8Array {
  const t = tranches.map((x) => ({ swapId: x.swapId, takerSpendPub: x.takerSpendPub, viewSecret: x.viewSecret, watchtowers: x.watchtowers ?? [] }));
  return utf8ToBytes('halfkey-otc-accept-v1:' + bytesToHex(otcQuoteHash(q)) + ':' + bytesToHex(sha256(utf8ToBytes(JSON.stringify(t)))));
}

/** Effective price of a quote, for ranking: XMR per SOL. */
export const otcRate = (q: OtcQuote) => Number(BigInt(q.piconero)) / 1e12 / (Number(BigInt(q.lamports)) / 1e9);
