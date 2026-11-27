// Inventory skew: the maker's quotes lean against its own inventory so the price pulls in the
// flow it needs, instead of selling one coin until it runs out.
//
// A maker holds two things: the coin (XMR, ZEC) and SOL (or HYPE/USDC on the EVM side). It aims
// for a target split by value, 50/50 by default. Each side's "ratio" is what it holds over what it
// should hold at the target (1 = on target, 0.3 = 30% of target, 0 = empty).
//
//   * The side running low is quoted wider when the maker gives it away: up to +maxWidenBps.
//   * The same low side is quoted tighter when the maker takes it in: up to -maxImproveBps, and
//     never past mid (the spread never goes below zero).
//   * Below `floor` (after the trade) the maker stops quoting the direction that drains that side.
//
// The pressure is 0 inside the dead band (each side within `deadband` of its target), rises along
// a smoothstep curve, and reaches its cap at the floor. It is priced at the midpoint of the trade,
// so a large trade that moves inventory far pays for the part of the curve it walks through.
// Pure functions; unit-tested in maker/inventory.test.ts.

export interface SkewConfig {
  /** On by default; set false to quote the flat spread. */
  enabled?: boolean;
  /** Share of total value to hold in the coin (XMR, ZEC). Default 0.5. */
  target?: number;
  /** Most the spread widens for the side running low, in bps. Default 150 (1.5%). */
  maxWidenBps?: number;
  /** Most the spread tightens for the flow that refills a low side, in bps. Default 100; never past mid. */
  maxImproveBps?: number;
  /** No skew while each side is within this fraction of its target. Default 0.1. */
  deadband?: number;
  /** Stop quoting a direction that would leave a side below floor × its target. Default 0.1. */
  floor?: number;
}

export const DEFAULT_SKEW: Required<SkewConfig> = { enabled: true, target: 0.5, maxWidenBps: 150, maxImproveBps: 100, deadband: 0.1, floor: 0.1 };

/** Both sides valued in one unit (SOL on the Solana maker, XMR on the EVM maker). */
export interface Inventory { coin: number; sol: number }
/** giveCoin: the maker pays out the coin (SOL->XMR); takeCoin: the maker takes the coin in (XMR->SOL). */
export type Side = 'giveCoin' | 'takeCoin';

export interface Skewed {
  spreadBps: number;   // the spread to quote with (>= 0)
  widenBps: number;    // added because the side being paid out is low
  improveBps: number;  // taken off because this flow refills the low side (after the never-past-mid clamp)
  coinRatio: number;   // coin held / coin target, at the trade midpoint
  solRatio: number;
  stop?: 'coin' | 'sol'; // set when this direction is not quoted right now: the side that is too low
}

export function skewConfig(c?: SkewConfig): Required<SkewConfig> {
  const m = { ...DEFAULT_SKEW, ...(c ?? {}) };
  const clamp = (v: number, lo: number, hi: number, d: number) => (Number.isFinite(v) ? Math.min(Math.max(v, lo), hi) : d);
  m.target = clamp(m.target, 0.05, 0.95, DEFAULT_SKEW.target);
  m.maxWidenBps = clamp(m.maxWidenBps, 0, 1000, DEFAULT_SKEW.maxWidenBps);
  m.maxImproveBps = clamp(m.maxImproveBps, 0, 1000, DEFAULT_SKEW.maxImproveBps);
  m.floor = clamp(m.floor, 0, 0.5, DEFAULT_SKEW.floor);
  m.deadband = clamp(m.deadband, 0, 0.9 - m.floor, DEFAULT_SKEW.deadband);
  return m;
}

const smooth = (x: number) => x * x * (3 - 2 * x);

/** 0 inside the dead band, 1 at (or below) the floor, smooth in between. */
export function pressure(ratio: number, c: Required<SkewConfig>): number {
  const span = 1 - c.deadband - c.floor;
  if (span <= 0) return ratio < 1 - c.deadband ? 1 : 0;
  const x = Math.min(Math.max((1 - c.deadband - ratio) / span, 0), 1);
  return smooth(x);
}

/** Ratios (held / target) for each side. */
export function ratios(inv: Inventory, target: number): { coin: number; sol: number } {
  const total = inv.coin + inv.sol;
  if (!(total > 0)) return { coin: 0, sol: 0 };
  return { coin: Math.max(inv.coin, 0) / (target * total), sol: Math.max(inv.sol, 0) / ((1 - target) * total) };
}

/**
 * The spread for one quote. `trade` is the size in the same value unit: `coin` paid out or taken
 * in and `sol` taken in or paid out (both positive). Without a trade the current state is used.
 */
export function skew(cfg: SkewConfig | undefined, baseSpreadBps: number, inv: Inventory, side: Side, trade: { coin: number; sol: number } = { coin: 0, sol: 0 }): Skewed {
  const c = skewConfig(cfg);
  const flat: Skewed = { spreadBps: baseSpreadBps, widenBps: 0, improveBps: 0, coinRatio: 1, solRatio: 1 };
  if (!c.enabled || !Number.isFinite(inv.coin) || !Number.isFinite(inv.sol)) return flat;
  const total = inv.coin + inv.sol;
  if (!(total > 0)) return { ...flat, coinRatio: 0, solRatio: 0, stop: side === 'giveCoin' ? 'coin' : 'sol' };
  const sgn = side === 'giveCoin' ? 1 : -1;
  const after: Inventory = { coin: inv.coin - sgn * trade.coin, sol: inv.sol + sgn * trade.sol };
  const mid: Inventory = { coin: (inv.coin + after.coin) / 2, sol: (inv.sol + after.sol) / 2 };
  const rAfter = ratios(after, c.target), rMid = ratios(mid, c.target);
  // The side this direction pays out: the coin for giveCoin, SOL for takeCoin.
  const out = side === 'giveCoin' ? rMid.coin : rMid.sol;
  const inn = side === 'giveCoin' ? rMid.sol : rMid.coin;
  const outAfter = side === 'giveCoin' ? (after.coin <= 0 ? 0 : rAfter.coin) : (after.sol <= 0 ? 0 : rAfter.sol);
  const widenBps = Math.round(c.maxWidenBps * pressure(out, c));
  const wantImprove = Math.round(c.maxImproveBps * pressure(inn, c));
  const spreadBps = Math.max(0, baseSpreadBps + widenBps - wantImprove); // never better than mid
  const res: Skewed = { spreadBps, widenBps, improveBps: baseSpreadBps + widenBps - spreadBps, coinRatio: rMid.coin, solRatio: rMid.sol };
  if (outAfter < c.floor) res.stop = side === 'giveCoin' ? 'coin' : 'sol';
  return res;
}

/** What each side keeps back (same value unit): a fill may use only what is above this. 0 when skew is off. */
export function floorReserve(cfg: SkewConfig | undefined, inv: Inventory): Inventory {
  const c = skewConfig(cfg);
  const total = Math.max(inv.coin, 0) + Math.max(inv.sol, 0);
  if (!c.enabled || !(total > 0)) return { coin: 0, sol: 0 };
  return { coin: c.floor * c.target * total, sol: c.floor * (1 - c.target) * total };
}

/** The plain-English refusal for a paused direction (`coin` = XMR, ZEC; `sol` = SOL, HYPE, USDC). */
export const pausedMsg = (low: string, from: string, to: string) =>
  `this maker is low on ${low} right now, so ${from} -> ${to} is paused while its inventory rebalances; try another maker`;
