// Maker price feed. Sources in order: Pyth (only with an API key: Hermes has required one since
// August 2026), Kraken's public ticker, CoinGecko. The first usable source sets the price and every
// other fresh source cross-checks it. No quote at all on a stale or disputed price: a maker that
// quotes a frozen price is a free arbitrage against its inventory, so a failed read never counts as
// "the last price is still fine".
//
//   const feed = new PriceFeed({ base: 'SOL', quote: 'XMR' });
//   await feed.refresh();
//   const s = feed.state();   // { ok: true, rate, source, at } | { ok: false, reason }
//
// `rate` is units of `quote` per one `base` (XMR per SOL here).

export const PYTH_IDS: Record<string, string> = {
  SOL: 'ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d',
  XMR: '46b8cc9347f04391764a0361e0b17c3ba394b001e7c304f7650f6376e37c321d',
  ZEC: 'be9b59d178f0d6a97ab4c343bff2aa69caa1eaae3e9048a65788c529b125bb24',
  HYPE: '4279e31cc369bbcc2faf022b382b080e32a8e689ff20fbc530d2a603eb6cd98b',
};
export const GECKO_IDS: Record<string, string> = { SOL: 'solana', XMR: 'monero', ZEC: 'zcash', HYPE: 'hyperliquid', USDC: 'usd-coin' };
export const KRAKEN_PAIRS: Record<string, string> = { SOL: 'SOLUSD', XMR: 'XMRUSD', ZEC: 'ZECUSD', HYPE: 'HYPEUSD', USDC: 'USDCUSD' };

export interface PriceLimits {
  maxAgeSecs: number;          // a source's price older than this is not used
  slowMaxAgeSecs: number;      // the same for CoinGecko, which updates about once a minute
  maxConfBps: number;          // a source's own band (Pyth confidence, Kraken bid/ask), per leg, as a share of the price
  maxDivergenceBps: number;    // two fresh sources further apart than this: nobody gets a quote
  maxSoloMoveBps: number;      // one source alone: how far it may move from the last cross-checked rate
}
export const DEFAULT_LIMITS: PriceLimits = { maxAgeSecs: 60, slowMaxAgeSecs: 180, maxConfBps: 100, maxDivergenceBps: 200, maxSoloMoveBps: 300 };

export interface Leg { usd: number; atMs: number; confBps?: number }
export type Legs = Record<string, Leg | undefined>;
export type Source = 'pyth' | 'kraken' | 'coingecko';
export type PriceState = { ok: true; rate: number; source: Source; atMs: number } | { ok: false; reason: string };
const ORDER: Source[] = ['pyth', 'kraken', 'coingecko'];

const good = (l: Leg | undefined, maxAgeSecs: number, maxConfBps: number, nowMs: number): l is Leg =>
  !!l && Number.isFinite(l.usd) && l.usd > 0 && nowMs - l.atMs <= maxAgeSecs * 1000 && (l.confBps ?? 0) <= maxConfBps;

/** The one decision: a usable rate, or a reason to stop. Pure (unit-tested). */
export function pickRate(a: { sources: Partial<Record<Source, Legs>>; base: string; quote: string; nowMs: number; limits?: PriceLimits }): PriceState {
  const L = a.limits ?? DEFAULT_LIMITS;
  const usable: { source: Source; rate: number; atMs: number }[] = [];
  for (const source of ORDER) {
    const legs = a.sources[source];
    if (!legs) continue;
    const age = source === 'coingecko' ? L.slowMaxAgeSecs : L.maxAgeSecs;
    const b = legs[a.base], q = legs[a.quote];
    if (good(b, age, L.maxConfBps, a.nowMs) && good(q, age, L.maxConfBps, a.nowMs)) usable.push({ source, rate: b.usd / q.usd, atMs: Math.min(b.atMs, q.atMs) });
  }
  if (!usable.length) return { ok: false, reason: 'no fresh price from any source' };
  const best = usable[0];
  for (const o of usable.slice(1)) {
    const gapBps = (Math.abs(best.rate - o.rate) / o.rate) * 10_000;
    if (gapBps > L.maxDivergenceBps) return { ok: false, reason: `${best.source} and ${o.source} disagree by ${gapBps.toFixed(0)} bps` };
  }
  return { ok: true, rate: best.rate, source: best.source, atMs: best.atMs };
}

export const PYTH_HERMES = 'https://pyth.dourolabs.app/hermes';
export async function readPyth(symbols: string[], apiKey: string, f: typeof fetch = fetch, base = PYTH_HERMES): Promise<Legs> {
  const ids = symbols.map((s) => PYTH_IDS[s]);
  if (ids.some((x) => !x)) throw new Error(`no Pyth feed for ${symbols.join(',')}`);
  const qs = ids.map((id) => `ids%5B%5D=${id}`).join('&');
  const r = await f(`${base}/v2/updates/price/latest?${qs}&parsed=true&encoding=hex`, { headers: { authorization: `Bearer ${apiKey}` }, signal: AbortSignal.timeout(8000) });
  if (!r.ok) throw new Error(`pyth HTTP ${r.status}`);
  const j = await r.json() as { parsed?: { id: string; price: { price: string; conf: string; expo: number; publish_time: number } }[] };
  const out: Legs = {};
  for (const p of j.parsed ?? []) {
    const sym = symbols.find((s) => PYTH_IDS[s] === p.id.replace(/^0x/, ''));
    if (!sym) continue;
    const usd = Number(p.price.price) * 10 ** p.price.expo;
    out[sym] = { usd, atMs: p.price.publish_time * 1000, confBps: (Number(p.price.conf) * 10 ** p.price.expo / usd) * 10_000 };
  }
  return out;
}

export async function readKraken(symbols: string[], nowMs: number, f: typeof fetch = fetch): Promise<Legs> {
  const pairs = symbols.map((s) => KRAKEN_PAIRS[s]);
  if (pairs.some((x) => !x)) throw new Error(`no Kraken pair for ${symbols.join(',')}`);
  const r = await f(`https://api.kraken.com/0/public/Ticker?pair=${pairs.join(',')}`, { signal: AbortSignal.timeout(8000) });
  if (!r.ok) throw new Error(`kraken HTTP ${r.status}`);
  const j = await r.json() as { error?: string[]; result?: Record<string, { a: string[]; b: string[] }> };
  if (j.error?.length) throw new Error(`kraken: ${j.error.join(',')}`);
  const out: Legs = {};
  // Kraken answers under its own names (SOLUSD, but XXMRZUSD and XZECZUSD).
  for (const s of symbols) {
    const row = j.result?.[KRAKEN_PAIRS[s]] ?? j.result?.[`X${s}ZUSD`];
    if (!row) continue;
    const bid = Number(row.b[0]), ask = Number(row.a[0]), usd = (bid + ask) / 2;
    if (bid > 0 && ask >= bid) out[s] = { usd, atMs: nowMs, confBps: ((ask - bid) / usd) * 10_000 };
  }
  return out;
}

export async function readGecko(symbols: string[], nowMs: number, f: typeof fetch = fetch): Promise<Legs> {
  const ids = symbols.map((s) => GECKO_IDS[s]);
  if (ids.some((x) => !x)) throw new Error(`no CoinGecko id for ${symbols.join(',')}`);
  const r = await f(`https://api.coingecko.com/api/v3/simple/price?ids=${ids.join(',')}&vs_currencies=usd`, { signal: AbortSignal.timeout(8000) });
  if (!r.ok) throw new Error(`coingecko HTTP ${r.status}`);
  const j = await r.json() as Record<string, { usd?: number }>;
  const out: Legs = {};
  for (const s of symbols) { const usd = j[GECKO_IDS[s]]?.usd; if (typeof usd === 'number') out[s] = { usd, atMs: nowMs }; }
  return out;
}

export interface FeedOptions { base: string; quote: string; pythApiKey?: string; limits?: PriceLimits; geckoEveryMs?: number; fetchImpl?: typeof fetch; now?: () => number }
export class PriceFeed {
  private o: FeedOptions;
  private sources: Partial<Record<Source, Legs>> = {};
  private geckoAt = 0;
  private checked: { rate: number; atMs: number } | null = null;
  lastError = '';
  constructor(o: FeedOptions) { this.o = o; }
  private nowMs() { return this.o.now ? this.o.now() : Date.now(); }
  /** One read of each source. A failed read leaves the old values to age out; it never refreshes them. */
  async refresh() {
    const syms = [this.o.base, this.o.quote], f = this.o.fetchImpl ?? fetch, errs: string[] = [];
    const merge = (s: Source, legs: Legs) => { this.sources[s] = { ...this.sources[s], ...legs }; };
    if (this.o.pythApiKey) { try { merge('pyth', await readPyth(syms, this.o.pythApiKey, f)); } catch (e) { errs.push(`pyth: ${(e as Error).message}`); } }
    try { merge('kraken', await readKraken(syms, this.nowMs(), f)); } catch (e) { errs.push(`kraken: ${(e as Error).message}`); }
    if (this.nowMs() - this.geckoAt >= (this.o.geckoEveryMs ?? 60_000)) {
      try { merge('coingecko', await readGecko(syms, this.nowMs(), f)); this.geckoAt = this.nowMs(); } catch (e) { errs.push(`coingecko: ${(e as Error).message}`); }
    }
    this.lastError = errs.join('; ');
  }
  state(): PriceState {
    const L = this.o.limits ?? DEFAULT_LIMITS, nowMs = this.nowMs();
    const s = pickRate({ sources: this.sources, base: this.o.base, quote: this.o.quote, nowMs, limits: L });
    if (!s.ok) return s;
    const fresh = (Object.keys(this.sources) as Source[]).filter((k) => pickRate({ sources: { [k]: this.sources[k] }, base: this.o.base, quote: this.o.quote, nowMs, limits: L }).ok);
    if (fresh.length >= 2) { this.checked = { rate: s.rate, atMs: nowMs }; return s; }
    // One source left and nothing to compare it with: only close to the last rate two sources agreed on.
    if (!this.checked) return { ok: false, reason: 'one price source and no earlier cross-check' };
    const gapBps = (Math.abs(s.rate - this.checked.rate) / this.checked.rate) * 10_000;
    if (gapBps > L.maxSoloMoveBps) return { ok: false, reason: `only ${s.source} is answering and it moved ${gapBps.toFixed(0)} bps from the last checked rate` };
    return s;
  }
}
