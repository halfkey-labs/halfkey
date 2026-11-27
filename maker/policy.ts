// Maker admission policy for XMR->SOL, where the maker locks SOL first. Without limits anyone can
// make makers lock SOL and never deposit, tying up maker liquidity (and the global open-TVL cap)
// for free. Chosen mitigation, cheapest that works with a fresh zero-SOL wallet (a SOL bond from the
// taker would break exactly the "XMR into a brand-new wallet" flow):
//   1. a short deposit window: no deposit SEEN (even unconfirmed) within depositWindowSecs (+grace)
//      and the maker aborts and refunds itself (sdk/taker.ts makerAbortTimes), so one grief costs
//      the maker ~20 minutes of that SOL instead of ~an hour;
//   2. caps on UNFUNDED swaps (no deposit seen yet): per taker wallet, per client IP, and a total
//      lamport budget, so a griefer with many wallets still cannot lock more than the budget.
// Pure functions, unit-tested in maker/policy.test.ts.
export interface X2SLimits {
  perWallet: number; perIp: number; unfundedLamports: bigint;
  /** One client's share of the budget (default half), so one IP can't refuse everybody else. */
  perIpLamports?: bigint;
  maxOpenPerWallet?: number; maxOpenPerIp?: number; maxOpenLamports?: bigint;
}
export const DEFAULT_X2S_LIMITS: X2SLimits = { perWallet: 1, perIp: 3, unfundedLamports: 5_000_000_000n };
export interface OpenX2S { taker: string; ip?: string; lamports: bigint; funded: boolean }

/** A client that left the maker's SOL locked and never paid waits this long. */
export const NO_SHOW_REFUSE_SECS = 3600;
/** The wallet at once; an address after a second one, since an address can be shared by real users. */
export function noShowRefusal(swaps: Iterable<{ taker: string; ip?: string; noShowAt?: number }>, req: { taker: string; ip?: string }, now: number, pair = 'XMR->SOL'): string | null {
  let fromIp = 0;
  for (const s of swaps) {
    if (!s.noShowAt || now - s.noShowAt >= NO_SHOW_REFUSE_SECS) continue;
    if (s.taker === req.taker) return `this wallet left a recent ${pair} swap unpaid; try again in an hour`;
    if (req.ip && s.ip === req.ip) fromIp++;
  }
  return fromIp >= 2 ? `recent ${pair} swaps from this address went unpaid; try again in an hour` : null;
}

/** null = admit; otherwise the reason to refuse a new XMR->SOL lock. */
export function admitX2S(open: OpenX2S[], req: { taker: string; ip?: string; lamports: bigint }, lim: X2SLimits = DEFAULT_X2S_LIMITS): string | null {
  // Funded or not: a deposit can be seen and then vanish, or be real and never claimed, so nobody holds many at once.
  if (open.filter((o) => o.taker === req.taker).length >= (lim.maxOpenPerWallet ?? 2)) return 'this wallet already has XMR->SOL swaps open; finish those first';
  if (req.ip && open.filter((o) => o.ip === req.ip).length >= (lim.maxOpenPerIp ?? 6)) return 'too many XMR->SOL swaps open from this address; finish those first';
  // All of it: SOL parked by real deposits nobody claims still can't serve anyone else.
  const everything = open.reduce((a, o) => a + o.lamports, 0n);
  if (everything + req.lamports > (lim.maxOpenLamports ?? lim.unfundedLamports * 2n)) return 'this maker has too much SOL open on XMR->SOL swaps right now; try again later';
  const unfunded = open.filter((o) => !o.funded);
  if (unfunded.filter((o) => o.taker === req.taker).length >= lim.perWallet) return 'this wallet already has an XMR->SOL swap waiting for its deposit';
  if (req.ip && unfunded.filter((o) => o.ip === req.ip).length >= lim.perIp) return 'too many XMR->SOL swaps waiting for deposits from this address; send those first';
  const budget = lim.perIpLamports ?? lim.unfundedLamports / 2n;
  if (req.ip && unfunded.filter((o) => o.ip === req.ip).reduce((a, o) => a + o.lamports, 0n) + req.lamports > (budget > req.lamports ? budget : req.lamports)) return 'too much SOL waiting on deposits from this address; send those first';
  const locked = unfunded.reduce((a, o) => a + o.lamports, 0n);
  if (locked + req.lamports > lim.unfundedLamports) return 'this maker has too much SOL waiting on deposits right now; try again in a few minutes';
  return null;
}

// ---------------------------------------------------------------- SOL->XMR handshakes
// A handshake is an unsigned POST and costs the sender nothing. Two griefs follow if it counts for
// anything: reserving all of the maker's XMR (real users then read "not enough inventory") and filling
// the journal. So only a lock that exists on chain reserves XMR (xmrPromised), and open handshakes
// are capped per wallet and per client IP. If two real locks ever race for the last XMR, the second
// fails the transfer, the maker aborts it at lockDeadlineSecs and the user is refunded.
export interface S2XLimits { perWallet: number; perIp: number; total?: number }
// total: each open handshake costs RPC reads until it expires (~3.5 min), so its number has a ceiling.
export const DEFAULT_S2X_LIMITS: S2XLimits = { perWallet: 2, perIp: 6, total: 40 };
export function admitS2X(open: { taker: string; ip?: string }[], req: { taker: string; ip?: string }, lim: S2XLimits = DEFAULT_S2X_LIMITS): string | null {
  if (open.length >= (lim.total ?? 40)) return 'this maker is busy; try again in a few minutes';
  if (open.filter((o) => o.taker === req.taker).length >= lim.perWallet) return 'this wallet already has a swap waiting for its lock; finish it or wait a few minutes';
  if (req.ip && open.filter((o) => o.ip === req.ip).length >= lim.perIp) return 'too many swaps waiting for a lock from this address; wait a few minutes';
  return null;
}

/** XMR promised to live SOL->XMR locks and not yet sent. A handshake with no lock on chain is not one. */
export function xmrPromised(swaps: Iterable<{ done?: string; direction: number; xmrRelayed?: boolean; verified?: boolean; xmrAmount: string }>): bigint {
  let r = 0n;
  for (const s of swaps) if (!s.done && s.direction === 1 && !s.xmrRelayed && s.verified) r += BigInt(s.xmrAmount);
  return r;
}

// ---------------------------------------------------------------- client IP + rate window
/**
 * The client's IP for per-IP caps. Behind Cloudflare (trustProxy) only CF-Connecting-IP is trusted:
 * Cloudflare appends to X-Forwarded-For, so its first entry is whatever the client sent. Other proxies:
 * the LAST X-Forwarded-For entry, the one the proxy itself added.
 */
export function clientIp(req: { headers: Record<string, string | string[] | undefined>; socket: { remoteAddress?: string } }, trustProxy?: boolean): string {
  if (trustProxy) {
    const cf = req.headers['cf-connecting-ip'];
    if (typeof cf === 'string' && cf.trim()) return ipKey(cf.trim());
    const xff = req.headers['x-forwarded-for'];
    const parts = (Array.isArray(xff) ? xff.join(',') : xff ?? '').split(',').map((x) => x.trim()).filter(Boolean);
    if (parts.length) return ipKey(parts[parts.length - 1]);
  }
  return ipKey(req.socket.remoteAddress ?? '');
}

/** One customer holds a whole IPv6 /64, so a per-address cap on IPv6 caps nothing: count by the /64. */
export function ipKey(ip: string): string {
  const v = ip.replace(/^::ffff:/i, '');
  if (!v.includes(':')) return v;
  const [head, tail] = v.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const all = v.includes('::') ? [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill('0'), ...t] : h;
  return `${all.slice(0, 4).map((x) => x.toLowerCase().replace(/^0+(?=.)/, '')).join(':')}::/64`;
}

/** Fixed-window counter per key. Generous on purpose: a real user never reaches it. */
export class RateWindow {
  private hits = new Map<string, { n: number; at: number }>();
  private limit: number;
  private windowMs: number;
  private now: () => number;
  constructor(limit: number, windowMs: number, now: () => number = Date.now) { this.limit = limit; this.windowMs = windowMs; this.now = now; }
  take(key: string): boolean {
    const t = this.now(), h = this.hits.get(key);
    if (!h || t - h.at >= this.windowMs) { this.hits.set(key, { n: 1, at: t }); return true; }
    h.n++;
    return h.n <= this.limit;
  }
  sweep() { const t = this.now(); for (const [k, h] of this.hits) if (t - h.at >= this.windowMs) this.hits.delete(k); }
}

// ---------------------------------------------------------------- the free option
// A taker who locks SOL, waits to see the maker's XMR go out, and cancels if the price moved against
// it holds a free option on the maker's inventory for up to t0. The program lets it (cancel before t0 is
// the user's right, and the XMR comes back when it refunds). The maker's answer costs real users
// nothing: that wallet gets no quote honoured for a day. Each new wallet still has to lock real SOL.
export const WALK_REFUSE_SECS = 86_400;
export function walked(swaps: Iterable<{ taker: string; walkedAt?: number }>, taker: string, now: number): boolean {
  for (const s of swaps) if (s.taker === taker && s.walkedAt && now - s.walkedAt < WALK_REFUSE_SECS) return true;
  return false;
}
