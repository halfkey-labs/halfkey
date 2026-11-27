// Any Solana coin <-> SOL through Jupiter, around the HALFKEY escrow (web swap, pay links; reusable by
// the maker, OTC and keeper). The program is unchanged: the escrow still only ever holds SOL.
//
// SELL (coin -> XMR): ExactIn. The user names the coin amount; the lock is Jupiter's guaranteed
// minimum out (otherAmountThreshold), quoted by the maker for exactly that many lamports. The swap can
// never leave the lock short, and whatever the route returns above the minimum (at most the slippage
// guard) stays in the wallet as SOL. ExactOut is not used: many coin pools (bonding curves, CPMMs)
// cannot route it, and Jupiter's current /swap/v2/build is ExactIn only.
//
// Shape: ONE v0 transaction [compute budget, jupiter setup, swap, cleanup (unwrap), consent, lock] when
// it fits (address lookup tables + maxAccounts); otherwise TWO transactions signed in one wallet prompt
// (signAllTransactions): the swap (with a memo naming the swap id) then the lock. The memo is what lets
// any device find SOL that was sold but never locked (findUnlocked) and resume or keep it.
//
// BUY (XMR -> coin, optional): after an XMR -> SOL claim, a plain ExactIn SOL -> coin route.
//
// The ZEC pair (HTLC kind) uses the same pieces: the lock instructions are [consent, htlc_lock]
// (zecswap.solToZecLockIxs), the "sold" memo says kind 'zec' so findUnlocked looks for the HTLC escrow
// (seed "htlc"), and the record rent is HTLC_RENT. ZEC -> SOL then optionally buys a coin like XMR -> SOL.
//
// Mainnet only (Jupiter has no devnet). Nothing in this module signs or sends a transaction.
import {
  AddressLookupTableAccount, ComputeBudgetProgram, Connection, Keypair, PublicKey, TransactionInstruction,
  TransactionMessage, VersionedTransaction,
} from '@solana/web3.js';
import { pda, ESCROW_LEN } from './program.ts';
import { htlcPda, HTLC_LEN, DISC_HTLC } from './htlc.ts';
import { toHex } from './keys.ts';

export const WSOL = 'So11111111111111111111111111111111111111112';
export const USDC = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
export const JUP_PROGRAM = 'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4';
export const MEMO_PROGRAM = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
const TOKEN = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const TOKEN22 = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
const ATA = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
const SYSTEM = '11111111111111111111111111111111';
const COMPUTE_BUDGET = 'ComputeBudget111111111111111111111111111111';

/** Keyless Jupiter (0.5 req/s, 60 s sliding window, per IP). An API key raises it. */
export const DEFAULT_API = 'https://api.jup.ag';

export const LIMITS = {
  /** Slippage guard on every route. The unused part comes back as SOL (sell) or the coin (buy). */
  slippageBps: 100,
  /** Above this price impact the quote shows a warning. */
  warnImpact: 0.03,
  /** Above this price impact the app refuses the route. */
  maxImpact: 0.10,
  /** Keeps routes small enough to share one transaction with the consent + lock. */
  maxAccounts: 20,
};

// Lamports (rent is fixed by the runtime: (bytes + 128) * 6960).
export const ESCROW_RENT = 4_008_960n;        // the 448-byte swap record; stays with it until closed
export const HTLC_RENT = 2_839_680n;          // the 280-byte HTLC record (ZEC pair); same rule
export const TOKEN_ACCOUNT_RENT = 2_039_280n;  // a 165-byte token account (wSOL during a route, a new coin account on buy)
export const SIG_FEE = 5_000n;
export const WALLET_RENT = 890_880n;           // a wallet that keeps any SOL must stay rent-exempt
export const CU = { one: 600_000, swap: 450_000, lock: 120_000, buy: 450_000 };
export const CU_PRICE = { fallback: 50_000, min: 10_000, max: 1_000_000 }; // micro-lamports per CU
/** SOL kept back on a buy: the new coin account rent, the temporary wSOL account and fees. */
export const BUY_RESERVE = 5_000_000n;

export interface JupOpts { api?: string; apiKey?: string; fetch?: typeof fetch; now?: () => number }

/** HTTP 429 from Jupiter: show "busy, retry" and try again at `retryAt` (ms). */
export class JupiterBusy extends Error {
  retryAt: number;
  constructor(retryAt: number) { super('Jupiter is busy right now. Retrying in a few seconds.'); this.name = 'JupiterBusy'; this.retryAt = retryAt; }
}
export class NoRoute extends Error { constructor(m = 'Jupiter has no route for this coin right now.') { super(m); this.name = 'NoRoute'; } }

async function jget(path: string, o: JupOpts = {}): Promise<any> {
  const f = o.fetch ?? fetch;
  const now = o.now ?? Date.now;
  let r: Response;
  try {
    r = await f(`${(o.api ?? DEFAULT_API).replace(/\/+$/, '')}${path}`, { headers: o.apiKey ? { 'x-api-key': o.apiKey } : {} });
  } catch {
    throw new Error('Could not reach Jupiter. Check your connection and try again.');
  }
  if (r.status === 429) {
    const reset = Number(r.headers.get('x-ratelimit-reset'));
    throw new JupiterBusy(Number.isFinite(reset) && reset > 0 ? Math.max(reset * 1000, now() + 1000) : now() + 2000);
  }
  const body = await r.text();
  if (!r.ok) {
    if (/route|tradable|liquidity|COULD_NOT_FIND|NO_ROUTES/i.test(body)) throw new NoRoute();
    throw new Error(`jupiter ${r.status}: ${body.slice(0, 160)}`);
  }
  try { return JSON.parse(body); } catch { throw new Error('Jupiter sent an unreadable answer.'); }
}

// ---------------------------------------------------------------- tokens
export interface Token {
  mint: string; symbol: string; name: string; decimals: number; icon?: string;
  verified: boolean; tags: string[]; liquidity?: number; usd?: number; tokenProgram?: string;
}
export const SOL_TOKEN: Token = { mint: WSOL, symbol: 'SOL', name: 'Solana', decimals: 9, verified: true, tags: ['verified'] };

export function normalizeToken(x: any): Token | null {
  if (!x || typeof x.id !== 'string' || !Number.isInteger(x.decimals) || x.decimals < 0 || x.decimals > 18) return null;
  try { new PublicKey(x.id); } catch { return null; }
  const tags: string[] = Array.isArray(x.tags) ? x.tags.filter((t: unknown) => typeof t === 'string') : [];
  const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);
  return {
    mint: x.id, symbol: String(x.symbol ?? '').slice(0, 16) || x.id.slice(0, 4), name: String(x.name ?? '').slice(0, 48),
    decimals: x.decimals, icon: typeof x.icon === 'string' && /^https:\/\//.test(x.icon) ? x.icon : undefined,
    verified: x.isVerified === true || tags.includes('verified'), tags, liquidity: num(x.liquidity), usd: num(x.usdPrice),
    tokenProgram: typeof x.tokenProgram === 'string' ? x.tokenProgram : undefined,
  };
}

/** Search by name, ticker or mint (Jupiter Tokens v2). A pasted mint comes first when Jupiter knows it. */
export async function searchTokens(query: string, o: JupOpts = {}): Promise<Token[]> {
  const q = query.trim();
  if (!q) return [];
  const xs = await jget(`/tokens/v2/search?query=${encodeURIComponent(q)}`, o);
  const out = (Array.isArray(xs) ? xs : []).map(normalizeToken).filter((t): t is Token => !!t);
  const exact = out.findIndex((t) => t.mint === q);
  if (exact > 0) out.unshift(...out.splice(exact, 1));
  return out.slice(0, 20);
}

// ---------------------------------------------------------------- routes
export interface RawIx { programId: string; accounts: { pubkey: string; isSigner: boolean; isWritable: boolean }[]; data: string }
export interface Route {
  inputMint: string; outputMint: string;
  inAmount: bigint; outAmount: bigint;
  /** Guaranteed minimum out (the swap fails below it). */
  minOut: bigint;
  slippageBps: number;
  /** Fraction (0.012 = 1.2%), as Jupiter reports it against its reference price. */
  priceImpact: number;
  labels: string[];
  taker: string;
  fetchedAt: number;
  raw: { computeBudget: RawIx[]; setup: RawIx[]; swap: RawIx; cleanup: RawIx | null; other: RawIx[]; alts: Record<string, string[]> };
}

/** A throwaway taker for quotes shown before a wallet is connected (its instructions are never used). */
export const QUOTE_TAKER = Keypair.generate().publicKey.toBase58();

/**
 * Quote + raw instructions in one call (Jupiter /swap/v2/build, ExactIn). Checks that the answer is
 * for what was asked and that the guaranteed minimum honours the slippage guard.
 */
export async function buildRoute(a: { inputMint: string; outputMint: string; amount: bigint; taker: string; slippageBps?: number; maxAccounts?: number }, o: JupOpts = {}): Promise<Route> {
  const slippageBps = a.slippageBps ?? LIMITS.slippageBps;
  if (a.inputMint === a.outputMint) throw new Error('pick two different coins');
  if (a.amount <= 0n) throw new Error('enter an amount');
  const qs = new URLSearchParams({
    inputMint: a.inputMint, outputMint: a.outputMint, amount: String(a.amount), taker: a.taker,
    slippageBps: String(slippageBps), maxAccounts: String(a.maxAccounts ?? LIMITS.maxAccounts),
  });
  const d = await jget(`/swap/v2/build?${qs}`, o);
  return parseRoute(d, { ...a, slippageBps }, (o.now ?? Date.now)());
}

export function parseRoute(d: any, a: { inputMint: string; outputMint: string; amount: bigint; taker: string; slippageBps: number }, fetchedAt: number): Route {
  if (!d || typeof d !== 'object') throw new Error('unexpected jupiter answer');
  if (d.error || d.errorCode) throw new NoRoute();
  if (d.inputMint !== a.inputMint || d.outputMint !== a.outputMint) throw new Error('jupiter answered for different coins');
  if (d.swapMode !== 'ExactIn') throw new Error('jupiter answered with a different swap mode');
  const big = (v: unknown, what: string) => { if (typeof v !== 'string' || !/^\d{1,30}$/.test(v)) throw new Error(`jupiter ${what} missing`); return BigInt(v); };
  const inAmount = big(d.inAmount, 'inAmount'), outAmount = big(d.outAmount, 'outAmount'), minOut = big(d.otherAmountThreshold, 'threshold');
  if (inAmount !== a.amount) throw new Error('jupiter quoted a different amount');
  if (outAmount <= 0n || minOut <= 0n) throw new NoRoute();
  if (minOut > outAmount) throw new Error('jupiter minimum is above its quote');
  if (Number(d.slippageBps) !== a.slippageBps) throw new Error('jupiter changed the slippage');
  // The minimum may sit below the quote by the slippage guard, never more (a low minimum invites sandwiches).
  if (minOut * 10_000n < outAmount * BigInt(10_000 - a.slippageBps) - 10_000n) throw new Error('jupiter minimum is below the slippage guard');
  if (!d.swapInstruction) throw new NoRoute();
  const impact = Number(d.priceImpactPct);
  return {
    inputMint: d.inputMint, outputMint: d.outputMint, inAmount, outAmount, minOut, slippageBps: a.slippageBps,
    priceImpact: Number.isFinite(impact) ? Math.abs(impact) : 1,
    labels: [...new Set((d.routePlan ?? []).map((r: any) => String(r?.swapInfo?.label ?? '')).filter(Boolean))] as string[],
    taker: a.taker, fetchedAt,
    raw: {
      computeBudget: d.computeBudgetInstructions ?? [], setup: d.setupInstructions ?? [], swap: d.swapInstruction,
      cleanup: d.cleanupInstruction ?? null, other: d.otherInstructions ?? [], alts: d.addressesByLookupTableAddress ?? {},
    },
  };
}

/** 'ok' | 'warn' (show a warning) | 'refuse' (above the max: the app does not lock). */
export function impactLevel(r: Pick<Route, 'priceImpact'>, l = LIMITS): 'ok' | 'warn' | 'refuse' {
  return r.priceImpact > l.maxImpact ? 'refuse' : r.priceImpact > l.warnImpact ? 'warn' : 'ok';
}

const ataOf = (owner: PublicKey, mint: string, program = TOKEN) =>
  PublicKey.findProgramAddressSync([owner.toBuffer(), new PublicKey(program).toBuffer(), new PublicKey(mint).toBuffer()], new PublicKey(ATA))[0];
export const wsolAccount = (owner: PublicKey) => ataOf(owner, WSOL);

const toIx = (r: RawIx) => new TransactionInstruction({
  programId: new PublicKey(r.programId),
  keys: r.accounts.map((x) => ({ pubkey: new PublicKey(x.pubkey), isSigner: x.isSigner, isWritable: x.isWritable })),
  data: Buffer.from(r.data, 'base64'),
});

export interface RouteIxs { ixs: TransactionInstruction[]; cuPrice: number }

/** The priority price Jupiter suggests for this route (micro-lamports per CU), clamped. */
export function routeCuPrice(route: Route): number {
  let cuPrice = CU_PRICE.fallback;
  for (const r of route.raw.computeBudget) {
    if (r.programId !== COMPUTE_BUDGET) throw new Error('unexpected compute budget instruction');
    const d = Buffer.from(r.data, 'base64');
    if (d[0] === 3 && d.length >= 9) cuPrice = Number(d.readBigUInt64LE(1));
  }
  return Math.min(Math.max(cuPrice, CU_PRICE.min), CU_PRICE.max);
}

/**
 * The route's instructions, checked: the user is the only signer; besides the Jupiter program itself
 * only the plumbing a route needs is allowed (create the user's token accounts, wrap SOL into the
 * user's own wSOL account, close the user's wSOL account back to the user). Jupiter's compute-budget
 * instructions are dropped (the caller sets its own) and only their price is read.
 * `swapProgram` / `allowPrograms` exist for the local-validator e2e (a fake route), never for mainnet.
 */
export function routeInstructions(route: Route, user: PublicKey, t: { swapProgram?: string; allowPrograms?: string[] } = {}): RouteIxs {
  if (route.taker !== user.toBase58()) throw new Error('this route was built for a different wallet');
  const wsol = wsolAccount(user);
  const allow = new Set(t.allowPrograms ?? []);
  const me = user.toBase58();
  const check = (r: RawIx, isSwap: boolean) => {
    for (const k of r.accounts) if (k.isSigner && k.pubkey !== me) throw new Error('jupiter route needs an unexpected signer');
    const p = r.programId;
    if (isSwap) { if (p !== (t.swapProgram ?? JUP_PROGRAM)) throw new Error('unexpected swap program'); return; }
    if (allow.has(p) || p === JUP_PROGRAM) return;
    const data = Buffer.from(r.data, 'base64');
    const acct = (i: number) => r.accounts[i]?.pubkey;
    if (p === ATA) {
      // create / createIdempotent: [payer, ata, owner, mint, system, token program]
      if (!(data.length === 0 || data[0] === 0 || data[0] === 1)) throw new Error('unexpected token-account instruction in route');
      if (acct(0) !== me || acct(2) !== me) throw new Error('route creates an account for someone else');
      return;
    }
    if (p === SYSTEM) {
      // transfer only, into the user's own wSOL account (wrapping SOL for a buy)
      if (data.length !== 12 || data.readUInt32LE(0) !== 2 || acct(0) !== me || acct(1) !== wsol.toBase58()) throw new Error('route moves SOL somewhere unexpected');
      return;
    }
    if (p === TOKEN || p === TOKEN22) {
      if (data[0] === 17 && acct(0) === wsol.toBase58()) return; // syncNative
      if (data[0] === 9 && acct(0) === wsol.toBase58() && acct(1) === me && acct(2) === me) return; // close wSOL back to the user
      throw new Error('route has an unexpected token instruction');
    }
    throw new Error('route calls an unexpected program');
  };
  const cuPrice = routeCuPrice(route);
  const order = [...route.raw.other, ...route.raw.setup, route.raw.swap, ...(route.raw.cleanup ? [route.raw.cleanup] : [])];
  for (const r of order) check(r, r === route.raw.swap);
  // The proceeds must land in the user's own account: wSOL (unwrapped by the cleanup) on a sell, the
  // user's coin account on a buy. A route naming someone else's output account is refused.
  const outs = route.outputMint === WSOL ? [wsol.toBase58()] : [TOKEN, TOKEN22].map((p) => ataOf(user, route.outputMint, p).toBase58());
  if (!route.raw.swap.accounts.some((k) => k.isWritable && outs.includes(k.pubkey))) throw new Error('route does not pay into your own account');
  return { ixs: order.map(toIx), cuPrice };
}

/**
 * The route's lookup tables, read from OUR RPC (not taken from Jupiter's answer), and checked to hold
 * the addresses Jupiter listed. A table that changed or vanished fails the build.
 */
export async function loadAlts(conn: Pick<Connection, 'getAddressLookupTable'>, route: Route): Promise<AddressLookupTableAccount[]> {
  const out: AddressLookupTableAccount[] = [];
  for (const [k, listed] of Object.entries(route.raw.alts)) {
    const a = (await conn.getAddressLookupTable(new PublicKey(k))).value;
    if (!a) throw new Error('a Jupiter lookup table is missing on chain');
    const onChain = a.state.addresses.map((x) => x.toBase58());
    if (listed.some((x, i) => onChain[i] !== x)) throw new Error('a Jupiter lookup table does not match the chain');
    out.push(a);
  }
  return out;
}

// ---------------------------------------------------------------- compose
export interface Composed {
  mode: 'one' | 'two';
  txs: VersionedTransaction[];
  /** Signature + priority fees across all transactions (lamports). */
  feeLamports: bigint;
}
const budget = (units: number, price: number) => [ComputeBudgetProgram.setComputeUnitLimit({ units }), ComputeBudgetProgram.setComputeUnitPrice({ microLamports: price })];
export const priorityLamports = (units: number, price: number) => (BigInt(units) * BigInt(price) + 999_999n) / 1_000_000n;
export const memoIx = (text: string) => new TransactionInstruction({ programId: new PublicKey(MEMO_PROGRAM), keys: [], data: Buffer.from(text, 'utf8') });

function v0(user: PublicKey, blockhash: string, ixs: TransactionInstruction[], alts: AddressLookupTableAccount[]) {
  return new VersionedTransaction(new TransactionMessage({ payerKey: user, recentBlockhash: blockhash, instructions: ixs }).compileToV0Message(alts));
}
/** Fits: <= 1232 bytes and <= 64 account locks. */
export function fits(tx: VersionedTransaction): boolean {
  try {
    const m = tx.message;
    const locks = m.staticAccountKeys.length + m.addressTableLookups.reduce((n, l) => n + l.writableIndexes.length + l.readonlyIndexes.length, 0);
    return tx.serialize().length <= 1232 && locks <= 64;
  } catch { return false; }
}

/**
 * Sell coin -> lock. `lockIxs` = [consent, lock] (taker.prepareSolToXmr / preparePay), prepared for
 * at most route.minOut lamports. `memo` = soldMemo(...) for the two-transaction fallback.
 */
export function composeSell(a: {
  user: PublicKey; blockhash: string; route: Route; swap: RouteIxs; alts: AddressLookupTableAccount[];
  lockIxs: TransactionInstruction[]; lockLamports: bigint; memo: string; force?: 'two';
}): Composed {
  if (a.lockLamports > a.route.minOut) throw new Error('the lock is larger than the route guarantees');
  if (a.lockIxs.length < 2) throw new Error('consent + lock expected');
  if (a.force !== 'two') {
    let one: VersionedTransaction | null = null;
    try { one = v0(a.user, a.blockhash, [...budget(CU.one, a.swap.cuPrice), ...a.swap.ixs, ...a.lockIxs], a.alts); } catch { /* too many accounts: two */ }
    if (one && fits(one)) return { mode: 'one', txs: [one], feeLamports: estimateSellFee('one', a.swap.cuPrice) };
  }
  let t1: VersionedTransaction | null = null;
  try { t1 = v0(a.user, a.blockhash, [...budget(CU.swap, a.swap.cuPrice), ...a.swap.ixs, memoIx(a.memo)], a.alts); } catch { /* below */ }
  if (!t1 || !fits(t1)) throw new Error('This route is too large for a transaction. Try a smaller amount or another coin.');
  const t2 = v0(a.user, a.blockhash, [...budget(CU.lock, a.swap.cuPrice), ...a.lockIxs], []);
  return { mode: 'two', txs: [t1, t2], feeLamports: estimateSellFee('two', a.swap.cuPrice) };
}

/** Buy SOL -> coin (after an XMR -> SOL claim). */
export function composeBuy(a: { user: PublicKey; blockhash: string; swap: RouteIxs; alts: AddressLookupTableAccount[] }): Composed {
  let tx: VersionedTransaction | null = null;
  try { tx = v0(a.user, a.blockhash, [...budget(CU.buy, a.swap.cuPrice), ...a.swap.ixs], a.alts); } catch { /* below */ }
  if (!tx || !fits(tx)) throw new Error('This route is too large for a transaction. Try another coin.');
  return { mode: 'one', txs: [tx], feeLamports: SIG_FEE + priorityLamports(CU.buy, a.swap.cuPrice) };
}

/** SOL to swap into a coin after a claim: what the claim paid, never eating the wallet's fee reserve. */
export function buyAmount(received: bigint, balance: bigint, reserve = BUY_RESERVE): bigint {
  const spendable = balance > reserve ? balance - reserve : 0n;
  return received < spendable ? received : spendable;
}

/**
 * Network fee of a sell (one or two transactions): the wallet signature(s), the maker's consent
 * (an ed25519 precompile signature is charged like one) and the priority fee.
 */
export function estimateSellFee(mode: 'one' | 'two', cuPrice = CU_PRICE.fallback): bigint {
  return mode === 'one' ? 2n * SIG_FEE + priorityLamports(CU.one, cuPrice) : 3n * SIG_FEE + priorityLamports(CU.swap, cuPrice) + priorityLamports(CU.lock, cuPrice);
}

/**
 * Simulate before signing and check the money moves as promised: on a sell the wallet's SOL may drop
 * by at most (lock + record rent + fees - guaranteed out); on a buy the coin account must grow by at
 * least the guaranteed minimum. Catches a route that pays someone else, whatever its shape.
 */
export async function simulateCheck(conn: Pick<Connection, 'simulateTransaction' | 'getMultipleAccountsInfo'>, tx: VersionedTransaction, user: PublicKey,
  want: { minLamportsDelta: bigint } | { tokenAccount: PublicKey; minTokenDelta: bigint }): Promise<void> {
  const addrs = 'tokenAccount' in want ? [user, want.tokenAccount] : [user];
  const pre = await conn.getMultipleAccountsInfo(addrs, 'confirmed');
  const sim = await conn.simulateTransaction(tx, { sigVerify: false, replaceRecentBlockhash: true, commitment: 'confirmed', accounts: { encoding: 'base64', addresses: addrs.map((a) => a.toBase58()) } });
  if (sim.value.err) throw new Error(`the transaction would fail: ${JSON.stringify(sim.value.err).slice(0, 120)}`);
  const post = sim.value.accounts ?? [];
  if ('tokenAccount' in want) {
    const amt = (d: Buffer | null | undefined) => (d && d.length >= 72 ? d.readBigUInt64LE(64) : 0n);
    const before = amt(pre[1]?.data as Buffer | undefined), after = amt(post[1] ? Buffer.from(post[1].data[0], 'base64') : null);
    if (after - before < want.minTokenDelta) throw new Error('the route would not pay the coin into your account');
  } else {
    const before = BigInt(pre[0]?.lamports ?? 0), after = BigInt(post[0]?.lamports ?? 0);
    if (after - before < want.minLamportsDelta) throw new Error('the route would not pay the SOL into your wallet');
  }
}
/**
 * The smallest SOL change a sell may cause (negative): what the lock + rent + fees cost beyond the
 * guaranteed out. `rent` is the record the lock creates: ESCROW_RENT (XMR) or HTLC_RENT (ZEC).
 */
export const sellMinDelta = (c: Composed, route: Route, lockLamports: bigint, rent = ESCROW_RENT) =>
  c.mode === 'one' ? route.minOut - lockLamports - rent - c.feeLamports - 10_000n : route.minOut - c.feeLamports - 10_000n;

/**
 * The coin amount to sell so the route's guaranteed minimum covers `lamports` again, after the price
 * moved (the ZEC pair sells at lock time, minutes after the quote). Scales the amount by what the
 * route now guarantees, plus `marginBps`; the caller re-routes it and checks minOut, never trusts this.
 */
export function coinFor(route: Pick<Route, 'inAmount' | 'minOut'>, lamports: bigint, marginBps = 50): bigint {
  if (route.minOut <= 0n || lamports <= 0n) throw new Error('empty route');
  if (route.minOut >= lamports) return route.inAmount;
  return (route.inAmount * lamports * BigInt(10_000 + marginBps) + route.minOut * 10_000n - 1n) / (route.minOut * 10_000n);
}

/** The most a price-fell top-up may sell, against the amount quoted: 1.25x (the price fell about 20%). Beyond it: lock SOL or start again. */
export const MAX_TOPUP_BPS = 12_500;
/** A top-up from `quoted` to `needed` coin: the extra share (bps, rounded up) and whether it stays within the cap. */
export function topUp(quoted: bigint, needed: bigint, maxBps = MAX_TOPUP_BPS): { ok: boolean; extraBps: number } {
  if (quoted <= 0n) throw new Error('empty amount');
  const extra = needed > quoted ? needed - quoted : 0n;
  return { ok: needed * 10_000n <= quoted * BigInt(maxBps), extraBps: Number((extra * 10_000n + quoted - 1n) / quoted) };
}
/** The coin account a buy pays into (classic token program or Token-2022). */
export const buyOutAccount = (user: PublicKey, mint: string, tokenProgram?: string) => ataOf(user, mint, tokenProgram === TOKEN22 ? TOKEN22 : TOKEN);

// ---------------------------------------------------------------- the all-in quote
export interface SellQuote {
  payAmount: bigint;                // coin base units
  xmrOut: bigint;                   // piconero
  routeOut: bigint;                 // Jupiter's expected SOL out
  routeMin: bigint;                 // guaranteed SOL out
  lockLamports: bigint;             // SOL locked in the escrow (the maker's quote)
  changeLamports: bigint;           // expected SOL left in the wallet (routeOut - lock)
  priceImpactBps: number;
  slippageBps: number;
  spreadBps: number;
  protocolFeeBps: number;
  /** Price impact + maker spread + protocol fee (the slippage guard comes back as change). */
  costBps: number;
  feeLamports: bigint;              // signatures + priority
  depositLamports: bigint;          // swap record rent (stays with it until closed)
  /** SOL the wallet must hold before signing. */
  solNeeded: bigint;
  usd?: { pay: number; get: number; change: number };
}

export function sellQuote(a: {
  route: Route; lockLamports: bigint; piconero: bigint; spreadBps: number; feeBps: number; feeLamports?: bigint;
  prices?: { coinUsd?: number | null; solUsd?: number | null; xmrUsd?: number | null }; coinDecimals?: number;
  /** The ZEC pair: `piconero` carries zatoshis (outDecimals 8), `prices.xmrUsd` the ZEC price, rent HTLC_RENT. */
  outDecimals?: number; rent?: bigint;
}): SellQuote {
  const r = a.route;
  if (a.lockLamports > r.minOut) throw new Error('the maker quoted more SOL than the route guarantees');
  if (a.lockLamports <= 0n || a.piconero <= 0n) throw new Error('empty quote');
  const impactBps = Math.round(r.priceImpact * 10_000);
  const feeLamports = a.feeLamports ?? estimateSellFee('one');
  const rent = a.rent ?? ESCROW_RENT;
  const p = a.prices;
  const usd = p?.coinUsd && p.solUsd && p.xmrUsd && a.coinDecimals != null
    ? { pay: Number(r.inAmount) / 10 ** a.coinDecimals * p.coinUsd, get: Number(a.piconero) / 10 ** (a.outDecimals ?? 12) * p.xmrUsd, change: Number(r.outAmount - a.lockLamports) / 1e9 * p.solUsd }
    : undefined;
  return {
    payAmount: r.inAmount, xmrOut: a.piconero, routeOut: r.outAmount, routeMin: r.minOut, lockLamports: a.lockLamports,
    changeLamports: r.outAmount - a.lockLamports, priceImpactBps: impactBps, slippageBps: r.slippageBps,
    spreadBps: a.spreadBps, protocolFeeBps: a.feeBps, costBps: impactBps + a.spreadBps + a.feeBps,
    feeLamports, depositLamports: rent,
    // the temporary wSOL account (created and closed inside the swap) needs its rent up front too
    solNeeded: feeLamports + (rent > TOKEN_ACCOUNT_RENT ? rent : TOKEN_ACCOUNT_RENT) + WALLET_RENT,
    usd,
  };
}

// ---------------------------------------------------------------- the in-between state
// Two-transaction sells: if the swap lands and the lock does not, the user holds SOL. The swap carries
// a memo with the swap id; a resumed lock carries a "lock" memo with the same id. Any device with the
// wallet finds what is still open from chain alone.
export const MEMO_TAG = 'halfkey:any:v1';
/** 'swap' / 'pay': an XMR escrow (seed "swap"); 'zec': an HTLC escrow (seed "htlc"), SOL -> ZEC. */
export type SoldKind = 'swap' | 'pay' | 'zec';
export interface SoldMemo { t: 'sold'; swapId: string; lamports: bigint; kind: SoldKind; link?: string }
export interface LockMemo { t: 'lock'; swapId: string }

export function soldMemo(m: { swapId: Uint8Array; lamports: bigint; kind?: SoldKind; link?: string }): string {
  const link = m.kind === 'pay' && m.link ? `:${m.link.toLowerCase().replace(/[^a-z0-9_-]/g, '').slice(0, 32)}` : '';
  return `${MEMO_TAG}:sold:${toHex(m.swapId)}:${m.lamports}:${m.kind ?? 'swap'}${link}`;
}
export const lockMemo = (swapId: Uint8Array | string) => `${MEMO_TAG}:lock:${typeof swapId === 'string' ? swapId : toHex(swapId)}`;

/** Parse the memo field of getSignaturesForAddress ("[len] text", several joined by "; "). */
export function parseMemos(field: string | null | undefined): (SoldMemo | LockMemo)[] {
  if (!field) return [];
  const out: (SoldMemo | LockMemo)[] = [];
  for (const m of field.matchAll(/halfkey:any:v1:(sold|lock):([0-9a-f]{64})(?::(\d{1,20}):(swap|pay|zec)(?::([a-z0-9_-]{1,32}))?)?/g)) {
    if (m[1] === 'lock') out.push({ t: 'lock', swapId: m[2] });
    else if (m[3] && m[4]) out.push({ t: 'sold', swapId: m[2], lamports: BigInt(m[3]), kind: m[4] as SoldKind, link: m[5] });
  }
  return out;
}

export interface Unlocked { sig: string; swapId: string; lamports: bigint; at: number; kind: SoldKind; link?: string; escrow: string }
/** The escrow a sale's lock creates: the XMR swap record, or the HTLC record for the ZEC pair. Both are seeded by the locker. */
export const soldEscrow = (pid: PublicKey, wallet: PublicKey, swapId: Uint8Array, kind: SoldKind) =>
  kind === 'zec' ? htlcPda(pid, wallet, swapId) : pda.escrow(pid, wallet, swapId);
type FindConn = Pick<Connection, 'getSignaturesForAddress' | 'getMultipleAccountsInfo' | 'getTransaction'>;

/**
 * Anyone can send a transaction that lists a wallet and carries a memo, so a memo only counts when the
 * wallet itself paid for and signed that transaction. Returns the wallet's SOL change in it (fee added
 * back), or null when the wallet did not sign it.
 */
async function ownTx(conn: Pick<Connection, 'getTransaction'>, sig: string, wallet: PublicKey): Promise<{ solGain: bigint } | null> {
  const t = await conn.getTransaction(sig, { commitment: 'confirmed', maxSupportedTransactionVersion: 0 });
  if (!t || t.meta?.err) return null;
  const m = t.transaction.message;
  if (!m.staticAccountKeys[0]?.equals(wallet) || m.header.numRequiredSignatures < 1) return null;
  const pre = BigInt(t.meta!.preBalances[0]), post = BigInt(t.meta!.postBalances[0]), fee = BigInt(t.meta!.fee);
  return { solGain: post - pre + fee };
}

/**
 * A real lock by this wallet at an escrow address: owned by the program, the kind's size and
 * discriminator (XMR 448 bytes 0xE5, HTLC 280 bytes 0x48), and the wallet as locker (offset 40 in
 * both). Anyone can send lamports to any address, so an account there proves nothing by itself.
 */
export function isOwnLock(acc: { owner: PublicKey; data: Uint8Array } | null | undefined, pid: PublicKey, wallet: PublicKey, kind: SoldKind): boolean {
  if (!acc || !acc.owner.equals(pid)) return false;
  const [len, disc] = kind === 'zec' ? [HTLC_LEN, DISC_HTLC] : [ESCROW_LEN, 0xe5];
  const d = acc.data;
  return d.length === len && d[0] === disc && wallet.equals(new PublicKey(d.subarray(40, 72)));
}

/** A successful transaction this wallet signed that calls the HALFKEY program (a stranger can list any address, never sign for the wallet). */
async function ownProgramTx(conn: Pick<Connection, 'getTransaction'>, sig: string, wallet: PublicKey, pid: PublicKey): Promise<boolean> {
  const t = await conn.getTransaction(sig, { commitment: 'confirmed', maxSupportedTransactionVersion: 0 });
  if (!t || t.meta?.err) return false;
  const m = t.transaction.message;
  const keys = m.staticAccountKeys;
  if (!keys.slice(0, m.header.numRequiredSignatures).some((k) => k.equals(wallet))) return false;
  // program ids are always static keys (never from a lookup table)
  return m.compiledInstructions.some((ix) => keys[ix.programIdIndex]?.equals(pid));
}

// ---------------------------------------------------------------- history, read in full
// Anyone can add transactions to any address's history (dust transfers), so a fixed window ("the last
// N signatures") can be pushed past what matters. History is paged back until it is older than the
// moment that matters (the sale); if a generous cap is hit first, the answer is "unknown", never a verdict.
type SigInfo = Awaited<ReturnType<Connection['getSignaturesForAddress']>>[number];
export const HISTORY = { pageSize: 1000, maxPages: 10, maxTxReads: 100, skewSecs: 600 };

/** Thrown when a history could not be read far enough back (cap) to give a verdict. */
export class HistoryUnknown extends Error { constructor(m = 'This wallet\'s history is too long to check right now.') { super(m); this.name = 'HistoryUnknown'; } }

/**
 * Signatures of `address`, newest first, back to `since` (unix seconds; a signature without a block
 * time counts as new). `complete` is false when the cap was hit before reaching `since` or the start.
 */
export async function historySince(conn: Pick<Connection, 'getSignaturesForAddress'>, address: PublicKey, since: number, o: { pageSize?: number; maxPages?: number } = {}): Promise<{ sigs: SigInfo[]; complete: boolean }> {
  const size = o.pageSize ?? HISTORY.pageSize, pages = o.maxPages ?? HISTORY.maxPages;
  const sigs: SigInfo[] = [];
  let before: string | undefined;
  for (let p = 0; p < pages; p++) {
    const page = await conn.getSignaturesForAddress(address, before ? { limit: size, before } : { limit: size });
    for (const s of page) {
      if (s.blockTime != null && s.blockTime < since) return { sigs, complete: true };
      sigs.push(s);
    }
    if (page.length < size) return { sigs, complete: true };
    before = page[page.length - 1].signature;
  }
  return { sigs, complete: false };
}

/**
 * An escrow that was locked by this wallet, even if settled and closed since: a successful transaction
 * in its history (since `since`, the sale) that the wallet signed and that calls the HALFKEY program.
 * A failed lock also lists the address (it does not count), and so can anyone's transfer to it (it does
 * not count either). null = unknown: the history is longer than the caps allow to check.
 */
export async function escrowEverLocked(conn: Pick<Connection, 'getSignaturesForAddress' | 'getTransaction'>, escrow: PublicKey, wallet: PublicKey, pid: PublicKey, o: { since?: number; maxTxReads?: number; pageSize?: number; maxPages?: number } = {}): Promise<boolean | null> {
  const h = await historySince(conn, escrow, (o.since ?? 0) - HISTORY.skewSecs, o);
  // oldest first: the lock is the escrow's first real transaction; later ones are settlement or noise
  const ok = h.sigs.filter((x) => !x.err).reverse();
  const reads = o.maxTxReads ?? HISTORY.maxTxReads;
  for (let i = 0; i < ok.length; i++) {
    if (i >= reads) return null;
    if (await ownProgramTx(conn, ok[i].signature, wallet, pid)) return true;
  }
  return h.complete ? false : null;
}

/**
 * This wallet's own "sold" and "lock" memos for one swap id (any device, from chain): whether its coin
 * was already sold for this swap (never sell it again), and whether that sale's SOL was already locked
 * into another swap (never resume it twice). Only memos the wallet signed count.
 */
export async function saleOnChain(conn: Pick<Connection, 'getSignaturesForAddress' | 'getTransaction'>, wallet: PublicKey, swapId: string, o: { since?: number; pageSize?: number; maxPages?: number } = {}): Promise<{ sold: boolean; lockMemo: boolean }> {
  // back to the swap's start (`since`): a sale or a lock for it can only be newer
  const h = await historySince(conn, wallet, (o.since ?? 0) - HISTORY.skewSecs, o);
  let sold = false, lockMemo = false;
  for (const s of h.sigs) {
    if (s.err) continue;
    for (const m of parseMemos(s.memo)) {
      if (m.swapId !== swapId || (m.t === 'sold' ? sold : lockMemo)) continue;
      if (!(await ownTx(conn, s.signature, wallet))) continue;
      if (m.t === 'sold') sold = true; else lockMemo = true;
    }
  }
  // a lock memo is always newer than its sale: once the sale is seen, everything after it was read
  if (!sold && !h.complete) throw new HistoryUnknown();
  return { sold, lockMemo };
}

/**
 * SOL this wallet got from a coin sale whose lock never landed (and was not resumed), newest first.
 * Locked means this wallet's own escrow is there (isOwnLock), or was and is closed now (escrowEverLocked).
 */
export async function findUnlocked(conn: FindConn, pid: PublicKey, wallet: PublicKey, o: { maxAgeSecs?: number; nowSecs?: number; pageSize?: number; maxPages?: number } = {}): Promise<Unlocked[]> {
  const now = o.nowSecs ?? Math.floor(Date.now() / 1000);
  // back to the oldest sale that may still be offered. A capped read only drops OLDER sales: a sale's
  // lock memo is newer than the sale, so every sale that is seen is seen with its lock memo.
  const { sigs } = await historySince(conn, wallet, now - (o.maxAgeSecs ?? 7 * 86_400), o);
  const sold: Unlocked[] = [], locks: { swapId: string; sig: string }[] = [];
  for (const s of sigs) {
    if (s.err) continue;
    for (const m of parseMemos(s.memo)) {
      if (m.t === 'lock') locks.push({ swapId: m.swapId, sig: s.signature });
      else if (!s.blockTime || now - s.blockTime <= (o.maxAgeSecs ?? 7 * 86_400)) {
        const escrow = soldEscrow(pid, wallet, Buffer.from(m.swapId, 'hex'), m.kind).toBase58();
        sold.push({ sig: s.signature, swapId: m.swapId, lamports: m.lamports, at: s.blockTime ?? now, kind: m.kind, link: m.link, escrow });
      }
    }
  }
  if (!sold.length) return [];
  // only memos the wallet signed itself (a stranger's memo can neither invent a sale nor hide one)
  const locked = new Set<string>();
  for (const l of locks) if (sold.some((x) => x.swapId === l.swapId) && (await ownTx(conn, l.sig, wallet))) locked.add(l.swapId);
  const open = sold.filter((x) => !locked.has(x.swapId));
  if (!open.length) return [];
  const accs = await conn.getMultipleAccountsInfo(open.map((x) => new PublicKey(x.escrow)));
  const out: Unlocked[] = [];
  for (let i = 0; i < open.length; i++) {
    if (isOwnLock(accs[i], pid, wallet, open[i].kind)) continue;
    // locked and closed since, or unknown (history too long to check): never offered as "lock it now"
    if ((await escrowEverLocked(conn, new PublicKey(open[i].escrow), wallet, pid, { since: open[i].at, pageSize: o.pageSize, maxPages: o.maxPages })) !== false) continue;
    const own = await ownTx(conn, open[i].sig, wallet);
    if (!own || own.solGain <= 0n) continue;
    // never more than the sale actually paid the wallet
    out.push({ ...open[i], lamports: open[i].lamports < own.solGain ? open[i].lamports : own.solGain });
  }
  return out.sort((a, b) => b.at - a.at);
}

/** A locally recorded two-transaction sell, from its transactions' status and the escrow. */
export type LocalSellState = 'sending' | 'failed' | 'unlocked' | 'locking' | 'locked';
type TxStatus = 'success' | 'failed' | 'unknown';
export function localSellState(a: {
  swapStatus: TxStatus; escrowSeen: boolean; ageSecs: number; maxPendingSecs?: number;
  /** the lock transaction, when one was sent: its status, and whether its blockhash can still land */
  lockStatus?: TxStatus | 'none'; lockCanLand?: boolean;
}): LocalSellState {
  if (a.escrowSeen || a.lockStatus === 'success') return 'locked';
  if (a.swapStatus === 'failed') return 'failed';
  if (a.swapStatus === 'success') return a.lockStatus === 'unknown' && a.lockCanLand ? 'locking' : 'unlocked';
  // unknown: still in flight until its blockhash must have expired (~150 slots), then it never landed
  return a.ageSecs > (a.maxPendingSecs ?? 180) ? 'failed' : 'sending';
}
