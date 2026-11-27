// Exchanger routes for auto-refill (maker/refill.ts). Each route implements the Exchanger interface,
// so a maker can switch routes in config without touching the refill logic.
//
// trocador: Trocador's aggregator API (api.trocador.app, header `API-Key`). One integration, both
//   directions, best quote of several instant exchangers, and a machine-readable KYC rating per
//   provider: by default only rating A (no KYC holds) is accepted. A refund address is set at create.
//   Endpoints (all GET): /new_rate (quotes, returns a trade id), /new_trade (deposit address),
//   /trade?id= (status: new, waiting, confirming, exchanging, sending, finished, failed, expired,
//   halted, refunded).
import type { Exchanger, ExQuote, ExState, ExStatus, ExTrade, Ticker } from './refill.ts';

export const DECIMALS: Record<Ticker, number> = { SOL: 9, XMR: 12 };

/** Base units -> decimal string (exact). */
export function toDec(v: bigint, decimals: number): string {
  const neg = v < 0n, a = neg ? -v : v, u = 10n ** BigInt(decimals);
  const frac = (a % u).toString().padStart(decimals, '0').replace(/0+$/, '');
  return `${neg ? '-' : ''}${a / u}${frac ? `.${frac}` : ''}`;
}
/** Decimal string or number -> base units (truncates extra digits). */
export function fromDec(x: unknown, decimals: number): bigint {
  const s = typeof x === 'number' ? x.toFixed(decimals) : String(x ?? '').trim();
  const m = /^(\d+)(?:\.(\d*))?$/.exec(s);
  if (!m) throw new Error(`not an amount: ${JSON.stringify(x)}`);
  return BigInt(m[1]) * 10n ** BigInt(decimals) + BigInt((m[2] ?? '').slice(0, decimals).padEnd(decimals, '0') || '0');
}

export interface TrocadorOptions {
  apiKey: string;
  base?: string;               // default https://api.trocador.app
  /** Lowest provider KYC rating to accept: A (no KYC) .. D. Default A. */
  minKycRating?: 'A' | 'B' | 'C' | 'D';
  /** Lowest log-policy rating: A .. C. Default B. */
  minLogPolicy?: 'A' | 'B' | 'C';
  /** Only these providers (by Trocador's name), if set. */
  providers?: string[];
  /** Network names as Trocador's /coins lists them. Default Mainnet for both. */
  networks?: Partial<Record<Ticker, string>>;
  fetch?: typeof fetch;        // tests
}

const STATE: Record<string, ExState> = {
  new: 'waiting', waiting: 'waiting', confirming: 'confirming', exchanging: 'exchanging', sending: 'sending',
  finished: 'finished', failed: 'failed', expired: 'expired', halted: 'hold', refunded: 'refunded',
};

export class Trocador implements Exchanger {
  name = 'trocador';
  private o: Required<Omit<TrocadorOptions, 'providers' | 'fetch' | 'networks'>> & TrocadorOptions;
  private f: typeof fetch;
  constructor(o: TrocadorOptions) {
    if (!o.apiKey) throw new Error('trocador: no API key');
    this.o = { base: 'https://api.trocador.app', minKycRating: 'A', minLogPolicy: 'B', ...o };
    this.f = o.fetch ?? fetch;
  }
  private net = (t: Ticker) => this.o.networks?.[t] ?? 'Mainnet';
  private async get(path: string, q: Record<string, string>): Promise<any> {
    const u = new URL(path, this.o.base);
    for (const [k, v] of Object.entries(q)) u.searchParams.set(k, v);
    const r = await this.f(u, { headers: { 'API-Key': this.o.apiKey, accept: 'application/json' }, signal: AbortSignal.timeout(30_000) });
    const text = await r.text();
    let j: any;
    try { j = JSON.parse(text); } catch { throw new Error(`trocador ${path}: HTTP ${r.status}, not JSON`); }
    if (!r.ok || (j && typeof j === 'object' && !Array.isArray(j) && j.error)) throw new Error(`trocador ${path}: ${j?.error ?? `HTTP ${r.status}`}`);
    return j;
  }
  private pair(from: Ticker, to: Ticker) {
    return { ticker_from: from.toLowerCase(), network_from: this.net(from), ticker_to: to.toLowerCase(), network_to: this.net(to) };
  }
  private okRating(x: any) {
    const kyc = String(x?.kycrating ?? 'D').toUpperCase(), log = String(x?.logpolicy ?? 'C').toUpperCase();
    return kyc <= this.o.minKycRating && log <= this.o.minLogPolicy && (!this.o.providers?.length || this.o.providers.includes(String(x?.provider)));
  }

  async quote(from: Ticker, to: Ticker, amountIn: bigint): Promise<ExQuote> {
    const j = await this.get('/new_rate', {
      ...this.pair(from, to), amount_from: toDec(amountIn, DECIMALS[from]), payment: 'False',
      min_kycrating: this.o.minKycRating, min_logpolicy: this.o.minLogPolicy, markup: '0',
    });
    const list: any[] = (j?.quotes?.quotes ?? []).filter((x: any) => this.okRating(x) && Number(x.amount_to) > 0);
    if (!list.length) throw new Error('trocador: no provider quote within the rating limits');
    list.sort((a, b) => Number(b.amount_to) - Number(a.amount_to));
    const best = list[0];
    return {
      amountOut: fromDec(best.amount_to, DECIMALS[to]), fixed: String(best.fixed).toLowerCase() === 'true', rateId: String(j.trade_id), provider: String(best.provider),
      min: j.min !== undefined ? fromDec(j.min, DECIMALS[from]) : undefined, max: j.max !== undefined ? fromDec(j.max, DECIMALS[from]) : undefined,
    };
  }

  async create(a: { from: Ticker; to: Ticker; amountIn: bigint; payout: string; refund: string; quote: ExQuote }): Promise<ExTrade> {
    if (!a.quote.rateId || !a.quote.provider) throw new Error('trocador: quote has no trade id/provider');
    const j = await this.get('/new_trade', {
      id: a.quote.rateId, provider: a.quote.provider, fixed: a.quote.fixed ? 'True' : 'False', ...this.pair(a.from, a.to),
      amount_from: toDec(a.amountIn, DECIMALS[a.from]), address: a.payout, address_memo: '0', refund: a.refund, refund_memo: '0',
      min_kycrating: this.o.minKycRating, min_logpolicy: this.o.minLogPolicy, markup: '0',
    });
    const dep = String(j?.address_provider ?? '');
    // "0" = the provider has no liquidity right now
    if (!dep || dep === '0') throw new Error('trocador: the provider gave no deposit address');
    const memo = j?.address_provider_memo;
    return {
      id: String(j.trade_id ?? a.quote.rateId), depositAddress: dep, depositMemo: memo && String(memo) !== '0' && String(memo) !== '' ? String(memo) : undefined,
      amountIn: fromDec(j.amount_from ?? toDec(a.amountIn, DECIMALS[a.from]), DECIMALS[a.from]),
      amountOut: fromDec(j.amount_to ?? toDec(a.quote.amountOut, DECIMALS[a.to]), DECIMALS[a.to]),
      fixed: String(j.fixed ?? a.quote.fixed).toLowerCase() === 'true', provider: String(j.provider ?? a.quote.provider),
    };
  }

  async status(id: string): Promise<ExStatus> {
    const j = await this.get('/trade', { id });
    const t = Array.isArray(j) ? j[0] : j;
    const raw = String(t?.status ?? '').toLowerCase();
    const state = STATE[raw];
    if (!state) return { state: 'waiting', detail: `unknown status ${raw}` };
    const out = t?.details?.hashout ?? t?.hashout ?? t?.details?.tx_to ?? undefined;
    const to = String(t?.ticker_to ?? '').toUpperCase() as Ticker;
    return { state, payoutTxid: out ? String(out) : undefined, amountOut: t?.amount_to !== undefined && DECIMALS[to] ? fromDec(t.amount_to, DECIMALS[to]) : undefined, detail: raw };
  }
}

/** Build the configured route. */
export function makeExchanger(route: string, apiKey: string, options: Record<string, unknown> = {}): Exchanger {
  if (route === 'trocador') return new Trocador({ ...(options as Partial<TrocadorOptions>), apiKey });
  throw new Error(`unknown refill route "${route}" (supported: trocador)`);
}
