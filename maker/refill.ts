// Auto-refill: when one side of the maker's inventory runs low, swap some of the maker's OWN surplus
// from the other side through an external instant exchanger, into the maker's own wallet.
//
// This never touches a user swap. User swaps stay atomic on chain (maker/daemon.ts); this only
// moves the maker's own coins between its own wallets, through a third party the operator picked.
// While a refill is out, the maker trusts that exchanger with the chunk: the caps below bound how
// much that can be, and anything unexpected pauses refills until the operator looks.
//
// Per refill:  plan (quote vs mid, caps) -> create the trade -> journal our tx id -> pay the
// deposit -> poll the exchanger -> detect the coins arriving in our own wallet -> done.
// Every step is journaled (fsync) as the receipt: exchange id, deposit address, our tx, their
// payout tx, what landed in our wallet and the cost against mid.
//
// Safety: one refill at a time; per-refill cap, rolling 24 h cap, max cost vs mid (abort if worse);
// a refill that fails or does not deliver within `deliverMins` after we paid alerts and PAUSES new
// refills (a pause file the operator deletes to resume). Nothing ever re-sends funds automatically:
// a crash between journaling our tx id and confirming it also pauses for a human.
import fs from 'node:fs';
import path from 'node:path';
import { Journal } from './lib.ts';

/** What a refill buys: 'coin' = buy XMR with SOL (XMR ran low); 'sol' = buy SOL with XMR. */
export type Leg = 'coin' | 'sol';

export interface RefillConfig {
  /** Off unless true. */
  enabled?: boolean;
  /** Exchanger route (maker/exchangers.ts): 'trocador' (default), or 'mock' in tests. */
  route?: string;
  /** File holding the route's API key (read at start, never logged). */
  apiKeyFile?: string;
  /** Route options (e.g. Trocador's minimum KYC rating, provider allow-list); see maker/exchangers.ts. */
  routeOptions?: Record<string, unknown>;
  /** Which way refills may go: 'both' (default), 'coin' (only buy XMR), 'sol' (only buy SOL). */
  directions?: 'both' | 'coin' | 'sol';
  /** Refill once a side is below this share of its target. Default 0.3. */
  triggerPct?: number;
  /** Each refill aims to bring the low side back up to this share of its target. Default 0.6. */
  refillToPct?: number;
  /** Per-refill cap, in SOL value. Default 5. */
  chunkSol?: number;
  /** Skip refills smaller than this (exchanger minimums, fixed network fees). Default 0.5. */
  minChunkSol?: number;
  /** Rolling 24 h cap on what leaves the maker for refills, in SOL value. Default 20. */
  dailyCapSol?: number;
  /** Abort if the exchanger pays more than this below mid (all its fees included). Default 150 (1.5%). */
  maxSlippageBps?: number;
  /** After we pay, the coins must be in our wallet within this long, else alert + pause. Default 90. */
  deliverMins?: number;
  /** Minimum gap between refills. Default 30. */
  cooldownMins?: number;
  /** The mid must be at most this old to start a refill. Default 300. */
  maxPriceAgeSecs?: number;
  /** Receipts journal. Default: refill.jsonl next to the maker journal. */
  journal?: string;
  /** While this file exists no new refill starts (written on any failure; delete it to resume). */
  pauseFile?: string;
  /** Optional webhook: POST {"text": ...} on every pause or failure. */
  alertUrl?: string;
}

export const REFILL_DEFAULTS = {
  enabled: false, route: 'trocador', directions: 'both' as 'both' | 'coin' | 'sol', triggerPct: 0.3, refillToPct: 0.6, chunkSol: 5, minChunkSol: 0.5, dailyCapSol: 20,
  maxSlippageBps: 150, deliverMins: 90, cooldownMins: 30, maxPriceAgeSecs: 300,
};

// ---------------------------------------------------------------- exchanger interface
export type Ticker = 'SOL' | 'XMR';
export interface ExQuote { amountOut: bigint; fixed: boolean; rateId?: string; min?: bigint; max?: bigint; provider?: string }
export interface ExTrade { id: string; depositAddress: string; depositMemo?: string; amountIn: bigint; amountOut: bigint; fixed: boolean; provider?: string }
/** waiting = no deposit yet; finished = paid out; failed/refunded/expired/hold = stop and pause. */
export type ExState = 'waiting' | 'confirming' | 'exchanging' | 'sending' | 'finished' | 'failed' | 'refunded' | 'expired' | 'hold';
export interface ExStatus { state: ExState; payoutTxid?: string; amountOut?: bigint; detail?: string }
/** Amounts are base units: lamports for SOL, piconero for XMR. */
export interface Exchanger {
  name: string;
  quote(from: Ticker, to: Ticker, amountIn: bigint): Promise<ExQuote>;
  create(a: { from: Ticker; to: Ticker; amountIn: bigint; payout: string; refund: string; quote: ExQuote }): Promise<ExTrade>;
  status(id: string): Promise<ExStatus>;
}

// ---------------------------------------------------------------- the maker's own wallets
export interface RefillWallets {
  /** Spendable now, base units, already net of what open swaps need. */
  balances(): Promise<{ coin: bigint; sol: bigint }>;
  /** Mid in coin per SOL, and when it was fetched (ms; 0 = not a live price). */
  mid(): { coinPerSol: number; at: number };
  /** A receiving address in the maker's own wallet for this refill, plus a handle to watch it. */
  receiveAddress(leg: Leg, id: string): Promise<{ address: string; ref: string }>;
  /** Where the exchanger refunds to: the maker's own address for the source coin. */
  refundAddress(leg: Leg): Promise<string>;
  /** Pay the exchanger's deposit. Must call onTxid(txid) BEFORE broadcasting; returns the txid. */
  pay(leg: Leg, to: string, amount: bigint, onTxid: (txid: string) => void): Promise<string>;
  /** Did that payment reach the network? null = cannot tell. */
  paid(leg: Leg, txid: string): Promise<boolean | null>;
  /** What has arrived for this refill in our own wallet: seen and spendable amounts + tx ids. */
  received(leg: Leg, ref: string, sinceMs: number): Promise<{ seen: bigint; spendable: bigint; txids: string[] }>;
}

// ---------------------------------------------------------------- state
export interface Refill {
  id: string; leg: Leg; from: Ticker; to: Ticker;
  amountIn: string; solValue: number; quoteOut: string; midOut: string; slippageBps: number;
  route: string; provider?: string; fixed?: boolean;
  exchangeId?: string; depositAddress?: string; tradeOut?: string;
  receiveAddress?: string; receiveRef?: string; refundAddress?: string;
  payTxid?: string; paidAt?: number; payoutTxid?: string;
  receivedTxids?: string[]; receivedAmount?: string; costBps?: number;
  stage: 'planned' | 'created' | 'paying' | 'paid' | 'delivered' | 'done' | 'failed';
  /** Memory only: what has already shown up in our wallet (so the skew does not count it twice). */
  seen?: string;
  why?: string; t: number;
}

const DAY = 86_400_000;
const bps = (got: bigint, want: bigint) => (want > 0n ? Number(((want - got) * 100_000n) / want) / 10 : 0);

export interface RefillerDeps {
  cfg: RefillConfig;
  /** The maker's target share of value in the coin (the skew target). */
  target: number;
  coin: Ticker;          // 'XMR'
  coinDecimals: number;  // 12
  exchanger: Exchanger;
  wallets: RefillWallets;
  defaultDir: string;    // where the journal and pause file go by default
  log?: (...a: unknown[]) => void;
  now?: () => number;    // ms; tests
  alert?: (text: string) => Promise<void>;
}

export class Refiller {
  readonly c: typeof REFILL_DEFAULTS & RefillConfig;
  readonly journalFile: string;
  readonly pauseFile: string;
  refills = new Map<string, Refill>();
  private journal: Journal;
  private d: RefillerDeps;
  private lastStart = 0;
  private preSendFails = 0;
  private busy = false;
  private log: (...a: unknown[]) => void;
  private now: () => number;

  constructor(d: RefillerDeps) {
    this.d = d;
    this.c = { ...REFILL_DEFAULTS, ...d.cfg };
    this.journalFile = d.cfg.journal ?? path.join(d.defaultDir, 'refill.jsonl');
    this.pauseFile = d.cfg.pauseFile ?? path.join(path.dirname(this.journalFile), 'refill.PAUSED');
    this.journal = new Journal(this.journalFile);
    this.log = d.log ?? (() => {});
    this.now = d.now ?? Date.now;
    for (const r of Journal.read(this.journalFile)) this.apply(r);
    for (const r of this.refills.values()) this.lastStart = Math.max(this.lastStart, r.t);
  }
  /** The refill a pause was raised for (journaled): deleting the pause file stops following it. */
  private pausedFor = '';

  private record(id: string, kind: string, fields: Record<string, unknown> = {}) {
    const r = { kind, id, ...fields };
    this.journal.append(r);
    this.apply({ t: this.now(), ...r });
  }
  private apply(r: Record<string, any>) {
    if (r.kind === 'paused') { this.pausedFor = r.refill ?? ''; return; }
    if (r.kind === 'planned') { this.refills.set(r.id, { ...(r.refill as Refill), stage: 'planned', t: r.t ?? this.now() }); return; }
    const x = this.refills.get(r.id);
    if (!x) return;
    switch (r.kind) {
      case 'created': Object.assign(x, { exchangeId: r.exchangeId, depositAddress: r.depositAddress, tradeOut: r.tradeOut, receiveAddress: r.receiveAddress, receiveRef: r.receiveRef, refundAddress: r.refundAddress, provider: r.provider ?? x.provider, fixed: r.fixed }); x.stage = 'created'; break;
      case 'paying': x.payTxid = r.txid; x.stage = 'paying'; break;
      case 'paid': x.payTxid = r.txid; x.paidAt = r.at; x.stage = 'paid'; break;
      case 'delivered': x.payoutTxid = r.payoutTxid; x.stage = 'delivered'; break;
      case 'received': x.receivedTxids = r.txids; x.receivedAmount = r.amount; x.costBps = r.costBps; x.stage = 'done'; break;
      case 'failed': x.why = r.why; x.stage = 'failed'; break;
    }
  }

  active(): Refill | undefined { return [...this.refills.values()].find((r) => r.stage !== 'done' && r.stage !== 'failed'); }
  paused(): string | null {
    if (fs.existsSync(this.pauseFile)) return fs.readFileSync(this.pauseFile, 'utf8').trim() || 'paused';
    return null;
  }

  /** What is on its way to us (target units) from refills we already paid: counted by the skew. */
  incoming(leg: Leg): bigint {
    const a = this.active();
    if (!a || a.leg !== leg || !(a.stage === 'paying' || a.stage === 'paid' || a.stage === 'delivered')) return 0n;
    const left = BigInt(a.tradeOut ?? a.quoteOut) - BigInt(a.seen ?? '0');
    return left > 0n ? left : 0n;
  }
  /** SOL value sent out for refills in the last 24 h. */
  spentToday(): number {
    const since = this.now() - DAY;
    return [...this.refills.values()].filter((r) => r.payTxid && r.t >= since).reduce((n, r) => n + r.solValue, 0);
  }

  private async pause(why: string, refill = '') {
    fs.mkdirSync(path.dirname(this.pauseFile), { recursive: true });
    fs.writeFileSync(this.pauseFile, `${new Date(this.now()).toISOString()} ${why}\nDelete this file to resume auto-refill.\n`);
    this.journal.append({ kind: 'paused', why, refill });
    this.pausedFor = refill;
    const text = `HALFKEY maker: auto-refill PAUSED: ${why}`;
    this.log(`!! ${text}`);
    await (this.d.alert ?? defaultAlert(this.c.alertUrl))(text).catch(() => {});
  }

  /** One step. Called from the maker's loop; never runs twice at once. */
  async tick(): Promise<void> {
    if (!this.c.enabled || this.busy) return;
    this.busy = true;
    try {
      const a0 = this.active();
      if (a0 && this.pausedFor === a0.id && !this.paused()) {
        // The operator deleted the pause file: they have dealt with this refill by hand.
        this.record(a0.id, 'failed', { why: 'operator resumed refills; stopped following this one' });
        this.pausedFor = '';
      }
      const a = this.active();
      if (a) { await this.follow(a); return; }
      if (this.paused()) return;
      await this.maybeStart();
    } finally { this.busy = false; }
  }

  private async recoverTorn(note: string) {
    const a = this.active();
    if (!a || a.stage !== 'paying') return;
    const seen = await this.d.wallets.paid(a.leg, a.payTxid!).catch(() => null);
    if (seen === true) { this.record(a.id, 'paid', { txid: a.payTxid, at: this.now() }); return; }
    // Not seen (or cannot tell): never re-send. A human checks the tx and the exchange.
    await this.pause(`${note} (tx ${a.payTxid}): restarted while paying and the tx is not on the network; nothing was re-sent. Check exchange ${a.exchangeId} at ${a.route}.`);
    this.record(a.id, 'failed', { why: 'restarted while paying; tx not seen' });
  }

  private async maybeStart() {
    const c = this.c, now = this.now();
    if (now - this.lastStart < c.cooldownMins * 60_000) return;
    const mid = this.d.wallets.mid();
    if (!(mid.coinPerSol > 0) || !mid.at || now - mid.at > c.maxPriceAgeSecs * 1000) return; // no fresh mid: no refill
    const b = await this.d.wallets.balances();
    const unit = 10 ** this.d.coinDecimals;
    const coinSol = Number(b.coin) / unit / mid.coinPerSol, sol = Number(b.sol) / 1e9;
    const total = coinSol + sol;
    if (!(total > 0)) return;
    const t = this.d.target;
    const coinRatio = coinSol / (t * total), solRatio = sol / ((1 - t) * total);
    let leg: Leg | null = null, gapSol = 0;
    if (coinRatio < c.triggerPct && c.directions !== 'sol') { leg = 'coin'; gapSol = c.refillToPct * t * total - coinSol; }
    else if (solRatio < c.triggerPct && c.directions !== 'coin') { leg = 'sol'; gapSol = c.refillToPct * (1 - t) * total - sol; }
    if (!leg) return;
    const room = c.dailyCapSol - this.spentToday();
    const chunk = Math.min(c.chunkSol, room, gapSol);
    if (!(chunk >= c.minChunkSol)) return;
    const from: Ticker = leg === 'coin' ? 'SOL' : this.d.coin, to: Ticker = leg === 'coin' ? this.d.coin : 'SOL';
    const amountIn = leg === 'coin' ? BigInt(Math.floor(chunk * 1e9)) : BigInt(Math.floor(chunk * mid.coinPerSol * unit));
    const midOut = leg === 'coin' ? BigInt(Math.floor(chunk * mid.coinPerSol * unit)) : BigInt(Math.floor(chunk * 1e9));
    const id = `${now.toString(36)}-${leg}`;
    this.lastStart = now;
    let q: ExQuote;
    try { q = await this.d.exchanger.quote(from, to, amountIn); } catch (e) { await this.preSendFail(`quote: ${errText(e)}`); return; }
    const slip = bps(q.amountOut, midOut);
    const base = { id, leg, from, to, amountIn: amountIn.toString(), solValue: chunk, quoteOut: q.amountOut.toString(), midOut: midOut.toString(), slippageBps: slip, route: this.d.exchanger.name, provider: q.provider, fixed: q.fixed };
    if (slip > c.maxSlippageBps) {
      this.journal.append({ kind: 'skipped', ...base, why: `quote ${slip} bps below mid > max ${c.maxSlippageBps}` });
      this.log(`refill skipped: ${from}->${to} quote is ${slip} bps below mid (max ${c.maxSlippageBps})`);
      return;
    }
    if ((q.min !== undefined && amountIn < q.min) || (q.max !== undefined && amountIn > q.max)) {
      this.journal.append({ kind: 'skipped', ...base, why: `outside the route's limits ${q.min}..${q.max}` });
      return;
    }
    this.record(id, 'planned', { refill: { ...base, stage: 'planned', t: now } });
    this.log(`refill ${id}: ${from}->${to} ${chunk.toFixed(3)} SOL worth via ${base.route}${q.provider ? `/${q.provider}` : ''}, ${slip} bps below mid`);
    let trade: ExTrade, recv: { address: string; ref: string }, refund: string;
    try {
      recv = await this.d.wallets.receiveAddress(leg, id);
      refund = await this.d.wallets.refundAddress(leg);
      trade = await this.d.exchanger.create({ from, to, amountIn, payout: recv.address, refund, quote: q });
    } catch (e) { this.record(id, 'failed', { why: `create: ${errText(e)}` }); await this.preSendFail(`create: ${errText(e)}`); return; }
    // The trade must be what we planned: same amount in, not worse out, no memo we would have to get right.
    const tradeSlip = bps(trade.amountOut, midOut);
    const why = trade.amountIn !== amountIn ? `trade wants ${trade.amountIn}, planned ${amountIn}`
      : tradeSlip > c.maxSlippageBps ? `trade pays ${tradeSlip} bps below mid > max ${c.maxSlippageBps}`
        : trade.depositMemo ? 'deposit needs a memo/tag (not supported)'
          : !trade.depositAddress ? 'no deposit address' : '';
    if (why) { this.record(id, 'failed', { why: `rejected trade ${trade.id}: ${why}` }); this.log(`refill ${id} rejected: ${why}`); return; }
    this.record(id, 'created', { exchangeId: trade.id, depositAddress: trade.depositAddress, tradeOut: trade.amountOut.toString(), receiveAddress: recv.address, receiveRef: recv.ref, refundAddress: refund, provider: trade.provider, fixed: trade.fixed });
    let announced = false;
    try {
      const txid = await this.d.wallets.pay(leg, trade.depositAddress, amountIn, (txid) => { announced = true; this.record(id, 'paying', { txid }); });
      this.record(id, 'paid', { txid, at: this.now() });
      this.preSendFails = 0;
      this.log(`refill ${id}: paid ${trade.id} with ${txid}`);
    } catch (e) {
      if (announced) {
        // We may have broadcast: never re-send; a human checks.
        await this.pause(`refill ${id}: paying ${trade.id} errored after signing (${errText(e)}); funds may have left`);
        this.record(id, 'failed', { why: `pay: ${errText(e)}` });
      } else {
        this.record(id, 'failed', { why: `pay (nothing sent): ${errText(e)}` });
        await this.preSendFail(`pay: ${errText(e)}`);
      }
    }
  }

  private async preSendFail(why: string) {
    this.preSendFails++;
    this.log(`refill: ${why} (nothing sent; ${this.preSendFails} in a row)`);
    if (this.preSendFails >= 3) { this.preSendFails = 0; await this.pause(`3 failed attempts in a row, last: ${why} (no funds were sent)`); }
  }

  /** Follow a paid refill until the coins are in our wallet. */
  private async follow(a: Refill) {
    if (a.stage === 'planned' || a.stage === 'created') {
      // A crash before paying: nothing left us. Drop it (the exchanger's order just expires).
      this.record(a.id, 'failed', { why: 'restarted before paying; nothing was sent' });
      return;
    }
    if (a.stage === 'paying') { await this.recoverTorn(`refill ${a.id}`); return; }
    const want = BigInt(a.tradeOut ?? a.quoteOut);
    // Our own wallet is the source of truth for delivery; the exchanger's status is the early signal.
    const got = await this.d.wallets.received(a.leg, a.receiveRef!, a.paidAt ?? a.t).catch(() => null);
    if (got) a.seen = got.seen.toString();
    let st: ExStatus | null = null;
    try { st = await this.d.exchanger.status(a.exchangeId!); } catch { /* their API down: keep watching our wallet */ }
    if (st?.state === 'finished' && a.stage !== 'delivered') this.record(a.id, 'delivered', { payoutTxid: st.payoutTxid, amountOut: st.amountOut?.toString() });
    if (got && got.seen > 0n && (got.spendable >= (want * 95n) / 100n || (st?.state === 'finished' && got.spendable > 0n && got.spendable >= got.seen))) {
      const cost = bps(got.spendable, BigInt(a.midOut));
      this.record(a.id, 'received', { txids: got.txids, amount: got.spendable.toString(), costBps: cost });
      this.log(`refill ${a.id}: ${got.spendable} ${a.to} base units in our wallet (${got.txids.join(',')}), ${cost} bps below mid`);
      if (cost > this.c.maxSlippageBps * 2) await this.pause(`refill ${a.id} delivered ${cost} bps below mid (quoted ${a.slippageBps}); check route ${a.route}`);
      return;
    }
    if (st && (st.state === 'failed' || st.state === 'refunded' || st.state === 'expired' || st.state === 'hold')) {
      if (!this.paused()) await this.pause(`refill ${a.id}: exchange ${a.exchangeId} at ${a.route} is ${st.state}${st.detail ? ` (${st.detail})` : ''}; our tx ${a.payTxid}`, st.state === 'hold' ? a.id : '');
      if (st.state !== 'hold') this.record(a.id, 'failed', { why: `exchange ${st.state}` });
      return;
    }
    if (this.now() - (a.paidAt ?? a.t) > this.c.deliverMins * 60_000 && !this.paused()) {
      // Keep following it (a late delivery is still recorded), but start nothing new.
      await this.pause(`refill ${a.id}: not delivered ${this.c.deliverMins} min after we paid (exchange ${a.exchangeId} at ${a.route}, our tx ${a.payTxid}, status ${st?.state ?? 'unknown'})`, a.id);
    }
  }
}

function errText(e: unknown) { return e instanceof Error ? e.message : String(e); }

function defaultAlert(url?: string) {
  return async (text: string) => {
    if (!url) return;
    await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ text }), signal: AbortSignal.timeout(5000) });
  };
}
