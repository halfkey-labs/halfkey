// HALFKEY maker daemon: quotes, handshake, the per-swap state machine, crash-safe journal,
// monero-wallet-rpc (main + per-swap wallets), auto-claim at t0, recovery after restart,
// gasless relays (refund for SOL->XMR users, claim for XMR->SOL fresh wallets).
//
//   node maker/daemon.ts maker/config.json
//
// Fault injection for tests only: HALFKEY_CRASH_AT=<point> exits the process at that point,
// HALFKEY_FAULT=no-xmr-lock makes the maker never lock XMR (watchtower test).
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { Connection, PublicKey } from '@solana/web3.js';
import * as P from '../sdk/program.ts';
import * as K from '../sdk/keys.ts';
import { formatEndpointField } from '../sdk/discovery.ts';
import { verifyLock, daemon } from '../sdk/xmrverify.ts';
import * as Pay from '../sdk/pay.ts';
import * as O from '../sdk/otc.ts';
import * as T from '../sdk/taker.ts';
import * as X from '../sdk/xmrproof.ts';
import { planProve } from '../sdk/prove.ts';
import { admitX2S, DEFAULT_X2S_LIMITS, type X2SLimits, admitS2X, DEFAULT_S2X_LIMITS, type S2XLimits, xmrPromised, clientIp, RateWindow, walked, WALK_REFUSE_SECS, noShowRefusal } from './policy.ts';
import { Journal, WalletRpc, chainNow, sendIxs, setPriority, scanEscrowHistory, pickSettlement, describeErr, loadKeypair, log, daemonHeight } from './lib.ts';
import { PriceFeed, type PriceState } from './price.ts';
import { Screen, loadList } from './sanctions.ts';
import { checkMainnet } from './launch-checks.ts';
import { ZecDesk, HttpError as ZecHttpError, type ZecConfig } from './zec.ts';
import { skew, skewConfig, pausedMsg, floorReserve, type SkewConfig, type Inventory } from './inventory.ts';
import { Refiller, type RefillConfig } from './refill.ts';
import { xmrRefillWallets } from './refill-wallets.ts';
import { makeExchanger } from './exchangers.ts';
import * as R from '../sdk/refundtowers.ts';
import { dealToTowers, type RefundTowersConfig } from './refund-deal.ts';

// ---------------------------------------------------------------- config
interface Config {
  rpcUrl: string; cluster: string; programId: string; keypair: string; endpoint: string; port: number;
  moneroNet: K.MoneroNet; daemonUri: string; walletRpc: string; swapWalletRpc: string; journal: string;
  spreadBps: number;
  /** Test clusters with livePrice off quote this fixed rate. Never used on mainnet. */
  fallbackXmrPerSol: number;
  livePrice: boolean;
  /** Optional Pyth API key file (first price source); without it: Kraken, cross-checked with CoinGecko. */
  pythApiKeyFile?: string;
  /** Transaction priority: on by default on mainnet (auto, clamped). `{ "auto": false, "microLamports": 0 }` turns it off. */
  priority?: { auto?: boolean; microLamports?: number; minMicroLamports?: number; maxMicroLamports?: number };
  /** Requests per IP per minute on the unsigned endpoints. */
  rateLimits?: { quotePerMin?: number; swapPerMin?: number; postPerMin?: number };
  /** Sanctions list (maker/sanctions.ts). Mainnet refuses to start without it. Default: the file in this kit. */
  sanctionsFile?: string;
  t0Secs: number; windowSecs: number; minConf: number;
  lockDeadlineSecs: number;   // must lock XMR within this long after the escrow appears, else decline
  claimMarginSecs: number;    // never reveal later than t1 - margin
  /**
   * v1.5, pay links / cashout vaults: the payer never sends `ready` and a pay refund reveals
   * nothing, so the XMR is recoverable only by claiming with an on-chain payment proof before t1.
   * Lock XMR only while t1 - now >= payProofSecs + claimMarginSecs (Monero confirmations, the
   * committee's attestation, prove_lock). Default 3600.
   */
  payProofSecs?: number;
  depositMarginSecs: number;  // XMR->SOL: abort if no confirmed deposit by t0 - margin
  depositWindowSecs?: number; // XMR->SOL: abort if no deposit is even seen by lock + window (+grace); default 900
  x2sLimits?: { perWallet: number; perIp: number; unfundedLamports: string }; // caps on unfunded XMR->SOL locks (policy.ts)
  s2xLimits?: S2XLimits; // caps on SOL->XMR handshakes whose lock has not appeared yet (policy.ts)
  pollMs: number;
  /**
   * Pay links / cashout vaults: watchtowers this maker trusts. On a pay escrow the payer cannot
   * cancel and a refund reveals nothing, so a watchtower that aborted a DELIVERED swap would strand
   * our XMR. We only consent to pay escrows whose watchtowers are all on this list.
   */
  payWatchtowers?: string[];
  /** URLs of trusted watchtowers (pubkey -> url): pay-escrow lock txs are pushed to them. */
  payWatchtowerUrls?: Record<string, string>;
  /**
   * Pay escrows: never relay XMR this close to t0 (must exceed the watchtowers' abort margin plus
   * a confirmation), since an abort after our lock strands the XMR. Default 1500 s.
   */
  payLateSecs?: number;
  /** OTC desk. Tranches are funded together in one Monero transaction. */
  otc?: { auto: boolean; spreadBps: number; maxTranches: number; quoteTtlSecs: number; lockWaitSecs: number; side2MaxOpen?: number };
  /** Extra public endpoints (onion, second host), published after `endpoint` in the registry entry. */
  endpoints?: string[];
  /** > 0: post the indicative rate on chain every N seconds (one tx fee each). Off by default. */
  publishRateSecs?: number;
  /**
   * Only behind your own reverse proxy: take the client IP (per-IP admission cap) from
   * X-Forwarded-For. Off by default: the header is client-supplied, so anyone could rotate it.
   */
  trustProxy?: boolean;
  /**
   * v1.5: URLs of the Monero header attesters (watchtower/attester.ts). Every SOL->XMR claim
   * without the user's `ready` needs an on-chain payment proof, so the daemon proves its XMR lock
   * (wallet OutProof + attested block) before claiming. Without attesters it can only claim after
   * the user's `ready`; otherwise the user refunds at t1 and the refund hands the XMR back.
   */
  attesters?: string[];
  /** Permit explicit per-swap proof claims only when enabled. Omitted/ready-only is the fallback. */
  claimMode?: 'ready-only' | 'payment-proof';
  /**
   * XMR->SOL refund towers (sdk/refundtowers.ts): after each SOL lock the daemon deals the swap's key half 2-of-3
   * to these three towers (in this order: tower n acks index n) and needs `minAcks` acks, or it aborts the lock.
   * The page checks the same acks before it shows a deposit address. Required for XMR->SOL on mainnet.
   */
  refundTowers?: RefundTowersConfig;
  /** XMR->SOL timing (ready-only with refund towers): t0 = last `ready`, then the claim window. Default t0Secs/windowSecs. */
  x2sT0Secs?: number; x2sWindowSecs?: number;
  /** Late finish (program with LATE_READY_MARGIN): XMR->SOL `ready` for a deposit that confirms after t0, until t1 - 30 min. */
  lateFinish?: boolean;
  /** SOL <-> ZEC desk (maker/zec.ts); off when absent. */
  zec?: ZecConfig;
  /**
   * Inventory skew (maker/inventory.ts), on by default: quotes lean against the side running low
   * so the price pulls in two-way flow, and a direction pauses below the floor. `{ "enabled": false }`
   * quotes the flat spread.
   */
  skew?: SkewConfig;
  /** Auto-refill (maker/refill.ts), off unless `enabled`: swaps the maker's own surplus SOL/XMR through an exchanger. */
  refill?: RefillConfig;
}
const cfg: Config = JSON.parse(fs.readFileSync(process.argv[2] ?? 'maker/config.json', 'utf8'));
for (const err of checkMainnet(cfg)) { console.error(`config: ${err}`); process.exitCode = 1; }
if (process.exitCode) process.exit(1);
const pid = new PublicKey(cfg.programId);
const me = loadKeypair(cfg.keypair);
/** Must match the program's LATE_READY_MARGIN (mainnet build). */
const LATE_READY_MARGIN = 30 * 60;
const x2sT0 = () => cfg.x2sT0Secs ?? cfg.t0Secs;
const x2sWindow = () => cfg.x2sWindowSecs ?? cfg.windowSecs;
const conn = new Connection(cfg.rpcUrl, 'confirmed');
const main = new WalletRpc(cfg.walletRpc);
const swapW = new WalletRpc(cfg.swapWalletRpc);
const journal = new Journal(cfg.journal);
const CRASH = process.env.HALFKEY_CRASH_AT ?? '';
const FAULT = process.env.HALFKEY_FAULT ?? '';
const crashPoint = (p: string) => { if (CRASH === p) { log(`!! simulated crash at ${p}`); process.exit(137); } };

// ---------------------------------------------------------------- swap state
interface Swap {
  escrow: string; direction: 1 | 2; swapId: string; taker: string;
  makerSpend: string; makerSpendPub: string; takerSpendPub: string; viewSecret: string; sharedAddress: string;
  quote: K.Quote; lamports: string; xmrAmount: string; t0Secs: number; windowSecs: number; consentExpiry: number;
  restoreHeight: number; createdAt: number;
  stage: string;                    // last journaled stage
  verified?: boolean;
  escrowSeenAt?: number;
  xmrTxHash?: string; xmrTxMeta?: string; xmrRelayed?: boolean;
  depositTx?: string;
  claimSig?: string; readySig?: string; abortSig?: string; refundSig?: string; solLockSig?: string;
  otherSecret?: string; sweepTxs?: string[];
  done?: string; lastError?: string;
  /** XMR->SOL: the refund towers' acks for this swap (the page checks them before it shows a deposit address). */
  refundAcks?: R.Ack[];
  /** Platform: escrow flags, pay link, OTC group (rfq id) and the escrow quote hash. */
  flags?: number; link?: string; group?: string; quoteHashHex?: string;
  /** v1.5: the on-chain payment-proof record of our XMR lock, once posted. */
  proofPda?: string;
  /** XMR->SOL: a deposit was seen (any confirmations); client IP for the admission caps (memory only). */
  depositSeen?: boolean; ip?: string; hints?: number;
  /** SOL->XMR: the taker cancelled after our XMR was sent (the free-option grief): when we saw it. */
  walkedAt?: number;
  /** XMR->SOL: we aborted because no deposit ever showed up. */
  noShowAt?: number;
  /** XMR->SOL: a deposit was seen at some point (keeps the account), and the confirmed transaction that pays in full (for a proof). */
  depositEver?: boolean; paidTx?: string;
  /** Memory only: what the last scan showed. */
  seenAmount?: bigint; seenTx?: string; lastSeenAt?: number; unseenReads?: number;
  /** XMR->SOL, settled and safe to remove (a claim, or a refund with no deposit ever seen): reclaim the rent from this time. */
  closeAfter?: number;
  /** The escrow account read as gone this many times in a row; where the history search has got to (memory only). */
  goneReads?: number; scanCursor?: string; scanAgainAt?: number;
}
const swaps = new Map<string, Swap>();
const usedNonces = new Set<string>();

function record(escrow: string, kind: string, fields: Record<string, unknown> = {}) {
  journal.append({ kind, escrow, ...fields });
  apply({ kind, escrow, ...fields });
}

function apply(r: Record<string, any>) {
  if (r.kind === 'handshake') {
    swaps.set(r.escrow, { ...(r.swap as Swap), stage: 'handshake' });
    usedNonces.add(r.swap.quote.nonce);
    return;
  }
  const s = swaps.get(r.escrow);
  if (!s) return;
  s.stage = r.kind;
  switch (r.kind) {
    case 'verified': s.verified = true; s.escrowSeenAt = r.seenAt; break;
    case 'xmr-lock-built': s.xmrTxHash = r.hash; s.xmrTxMeta = r.meta; break;
    case 'xmr-relayed': s.xmrRelayed = true; break;
    case 'sol-locked': s.solLockSig = r.sig; break;
    case 'towers-acked': s.refundAcks = r.acks; break;
    case 'deposit-hint': s.depositTx = r.txHash; break;
    case 'ready-sent': s.readySig = r.sig; break;
    case 'claim-sent': s.claimSig = r.sig; break;
    case 'proven': s.proofPda = r.proofPda; break;
    case 'abort-sent': s.abortSig = r.sig; break;
    case 'refund-sent': s.refundSig = r.sig; break;
    case 'other-secret': s.otherSecret = r.secret; break;
    case 'taker-walked': s.walkedAt = r.at; break;
    case 'no-show': s.noShowAt = r.at; break;
    case 'deposit-seen': s.depositSeen = true; s.depositEver = true; break;
    case 'deposit-paid': s.paidTx = r.txHash; s.depositSeen = true; s.depositEver = true; break;
    case 'close-after': s.closeAfter = r.at; break;
    case 'closed': s.closeAfter = undefined; break;
    case 'swept': s.sweepTxs = r.txHashes; break;
    case 'done': s.done = r.why; break;
  }
}

function replay() {
  const recs = Journal.read(cfg.journal);
  for (const r of recs) apply(r);
  const open = [...swaps.values()].filter((s) => !s.done).length;
  log(`journal replayed: ${recs.length} records, ${swaps.size} swaps, ${open} open`);
}

// ---------------------------------------------------------------- pricing + inventory
let xmrPerSol = cfg.fallbackXmrPerSol;
let priceAt = 0; // ms of the last live price (0 = the configured fallback): refills need a fresh one
const pythApiKey = cfg.pythApiKeyFile ? fs.readFileSync(cfg.pythApiKeyFile, 'utf8').trim() : undefined;
const feed = new PriceFeed({ base: 'SOL', quote: 'XMR', pythApiKey });
let priceNow: PriceState = cfg.livePrice ? { ok: false, reason: 'no price read yet' } : { ok: true, rate: cfg.fallbackXmrPerSol, source: 'kraken', atMs: 0 };
let lastPriceLog = '';
async function refreshPrice() {
  if (!cfg.livePrice) return;
  await feed.refresh();
  priceNow = feed.state();
  if (priceNow.ok && priceNow.rate > 0.001 && priceNow.rate < 100) { xmrPerSol = priceNow.rate; priceAt = priceNow.atMs; }
  else if (priceNow.ok) priceNow = { ok: false, reason: `rate ${priceNow.rate} out of bounds` };
  // Loud on every change of state: quotes stopped, or came back.
  const line = priceNow.ok ? `price ok (${priceNow.source})` : `!! NOT QUOTING: ${priceNow.reason}${feed.lastError ? ` (${feed.lastError})` : ''}`;
  if (line !== lastPriceLog) { log(line); lastPriceLog = line; }
}
/** The stop for every price this daemon signs. Never a frozen rate: see maker/price.ts. */
function requirePrice() { if (!priceNow.ok) throw new HttpError(503, 'this maker has no live price right now; try again in a minute'); }

const screen = new Screen(loadList(cfg.sanctionsFile));
const declined = (addr: string) => { if (screen.sol(addr)) { log(`declined listed wallet ${addr}`); throw bad('this maker cannot take this swap'); } };

/** XMR spoken for: only by locks that exist. A handshake costs nothing to send, so it reserves nothing. */
const xmrReserved = () => xmrPromised(swaps.values());
async function xmrAvailable(): Promise<bigint> {
  const b = await main.call('get_balance', { account_index: 0 });
  return BigInt(b.unlocked_balance) - xmrReserved();
}

const SOL_RESERVE = 50_000_000n; // kept back for fees (the same margin the quote check uses)
/**
 * Inventory for the skew, both sides valued in SOL at the mid: XMR held (still-locked change
 * included, XMR promised to unrelayed locks taken off, refills on their way added) and spendable SOL.
 */
let lastInv: (Inventory & { at: number }) | null = null;
let refiller: Refiller | null = null;
let solCache: { lam: number; at: number } | null = null;
/** Spendable SOL, read at most every 3 s: a flood of unsigned quotes must not burn RPC credits. */
async function solBalance() {
  if (solCache && Date.now() - solCache.at < 3000) return solCache.lam;
  const lam = await conn.getBalance(me.publicKey);
  solCache = { lam, at: Date.now() };
  return lam;
}
async function inventoryNow(): Promise<Inventory> {
  const [b, lam] = await Promise.all([main.call('get_balance', { account_index: 0 }), solBalance()]);
  const coinPico = BigInt(b.balance) - xmrReserved() + (refiller?.incoming('coin') ?? 0n);
  const solLam = BigInt(lam) - SOL_RESERVE + (refiller?.incoming('sol') ?? 0n);
  // SOL tied up by locks nobody has paid for is still ours: a griefer must not be able to move our prices by locking it.
  const parked = openX2S().filter((x) => !x.funded).reduce((a, x) => a + x.lamports, 0n);
  const inv = { coin: Number(coinPico) / 1e12 / xmrPerSol, sol: Number(solLam + parked) / 1e9 };
  lastInv = { ...inv, at: Date.now() };
  return inv;
}
/** The skewed spread for one quote; `stop` = this direction is paused (the low side). */
function skewFor(direction: 1 | 2, inv: Inventory, lamports: bigint, piconero: bigint, base = cfg.spreadBps) {
  const trade = { coin: Number(piconero) / 1e12 / xmrPerSol, sol: Number(lamports) / 1e9 };
  return skew(cfg.skew, base, inv, direction === 1 ? 'giveCoin' : 'takeCoin', trade);
}
/** Indicative spread for a small fill right now (null = paused). */
const spreadNow = (direction: 1 | 2, inv: Inventory) => { const k = skewFor(direction, inv, 0n, 0n); return k.stop ? null : k.spreadBps; };
const pausedErr = (direction: 1 | 2) => bad(direction === 1 ? pausedMsg('XMR', 'SOL', 'XMR') : pausedMsg('SOL', 'XMR', 'SOL'));

let makerAcct: P.MakerAccount | null = null;
let configAcct: P.ConfigAccount | null = null;
async function refreshChain() {
  const [m, c] = await Promise.all([
    conn.getAccountInfo(P.pda.maker(pid, me.publicKey)), conn.getAccountInfo(P.pda.config(pid)),
  ]);
  makerAcct = m ? P.decodeMaker(m.data) : null;
  configAcct = c ? P.decodeConfig(c.data) : null;
  // Holder perk: while >= holder_min $HALFKEY is bonded (no unstake pending), we pay the lower fee.
  feeBpsNow = configAcct && makerAcct && !configAcct.halfkeyMint.equals(PublicKey.default) &&
    makerAcct.staked >= configAcct.holderMin && makerAcct.stakeUnlockAt === 0n ? configAcct.holderFeeBps : (configAcct?.feeBps ?? 0);
}
let feeBpsNow = 0;

/** SOL->XMR for an exact XMR amount (pay-link invoices): the lamports that buy `piconero`. */
function priceExactXmr(piconero: bigint, spreadBps = cfg.spreadBps): K.Quote {
  const one = priceQuote(1, 1_000_000_000n, spreadBps);
  const lamports = (piconero * 1_000_000_000n + BigInt(one.piconero) - 1n) / BigInt(one.piconero); // round up: never short
  return { ...one, lamports: lamports.toString(), piconero: piconero.toString() };
}

function otcRange() {
  const m = makerAcct!, c = configAcct!;
  const cap = c.otcMaxSwap > 0n ? c.otcMaxSwap : c.maxSwap;
  const max = m.ext.otcMax > 0n ? (m.ext.otcMax < cap ? m.ext.otcMax : cap) : (m.max < c.maxSwap ? m.max : c.maxSwap);
  const min = m.ext.otcMax > 0n ? m.ext.otcMin : m.min;
  return { min, max };
}

function priceQuote(direction: 1 | 2, amount: bigint, spreadBps = cfg.spreadBps): K.Quote {
  if (!configAcct || !makerAcct) throw new Error('maker not registered');
  requirePrice();
  const feeBps = feeBpsNow;
  const spread = 1 - spreadBps / 10_000;
  const fee = 1 - feeBps / 10_000;
  let lamports: bigint, piconero: bigint;
  if (direction === 1) {
    lamports = amount;
    piconero = BigInt(Math.floor((Number(lamports) / 1e9) * fee * xmrPerSol * spread * 1e12));
  } else {
    piconero = amount;
    lamports = BigInt(Math.floor((Number(piconero) / 1e12 / xmrPerSol) * spread * 1e9));
  }
  return {
    v: 1, maker: me.publicKey.toBase58(), direction, lamports: lamports.toString(), piconero: piconero.toString(),
    feeBps, expiresAt: Math.floor(Date.now() / 1000) + 60, nonce: randomBytes(16).toString('hex'),
  };
}

// ---------------------------------------------------------------- HTTP API
class HttpError extends Error { code: number; constructor(code: number, m: string) { super(m); this.code = code; } }
const bad = (m: string) => new HttpError(400, m);

async function readBody(req: http.IncomingMessage): Promise<any> {
  let s = '';
  for await (const ch of req) { s += ch; if (s.length > 64_000) throw bad('body too large'); }
  try { return JSON.parse(s); } catch { throw bad('bad json'); }
}

async function handle(req: http.IncomingMessage): Promise<unknown> {
  const u = new URL(req.url ?? '/', 'http://x');
  if (u.pathname.startsWith('/v1/zec/')) {
    if (!zecDesk) throw new HttpError(404, 'no ZEC desk here');
    const zip = clientIp(req, cfg.trustProxy); // the desk applies the per-address limits itself
    try { return await zecDesk.handle(req.method ?? 'GET', u, () => readBody(req), zip); } catch (e) { if (e instanceof ZecHttpError) throw new HttpError(e.code, e.message); throw e; }
  }
  if (req.method === 'GET' && u.pathname === '/v1/info') {
    return {
      v: 1, maker: me.publicKey.toBase58(), programId: pid.toBase58(), cluster: cfg.cluster, moneroNet: cfg.moneroNet,
      directions: makerAcct?.directions ?? 0, minLamports: String(makerAcct?.min ?? 0), maxLamports: String(makerAcct?.max ?? 0),
      spreadBps: cfg.spreadBps, xmrPerSol, priceLive: priceNow.ok, feeBps: configAcct?.feeBps ?? 0, t0Secs: cfg.t0Secs, windowSecs: cfg.windowSecs,
      x2sT0Secs: x2sT0(), x2sWindowSecs: x2sWindow(), refundTowers: cfg.refundTowers ? { towers: cfg.refundTowers.towers.map((t) => t.pubkey), minAcks: cfg.refundTowers.minAcks } : undefined,
      // Indicative spread per direction right now after the inventory skew (null = paused). Firm quotes come from /v1/quote.
      spreadNow: lastInv ? { 1: spreadNow(1, lastInv), 2: spreadNow(2, lastInv) } : undefined,
      online: !!makerAcct?.active,
      depositMarginSecs: terms().depositMarginSecs, depositWindowSecs: terms().depositWindowSecs,
      payWatchtowers: makerAcct?.v2 ? (cfg.payWatchtowers ?? []) : [],
      claimModes: cfg.claimMode === 'payment-proof' && (cfg.attesters?.length ?? 0) >= 2 ? ['ready-only', 'payment-proof'] : ['ready-only'],
      otc: cfg.otc && makerAcct?.v2 ? { minLamports: String(otcRange().min), maxLamports: String(otcRange().max), maxTranches: Math.min(cfg.otc.maxTranches, O.MAX_TRANCHES), auto: cfg.otc.auto } : undefined,
    };
  }
  if (req.method === 'GET' && u.pathname === '/v1/quote') {
    if (!quoteRate.take(clientIp(req, cfg.trustProxy))) throw new HttpError(429, 'too many quote requests; slow down a little');
    const direction = Number(u.searchParams.get('direction')) as 1 | 2;
    if (direction !== 1 && direction !== 2) throw bad('direction');
    if (!makerAcct?.active || !(makerAcct.directions & direction)) throw bad('direction not offered');
    const exactXmr = direction === 1 && u.searchParams.has('piconero');
    const amount = BigInt(u.searchParams.get(direction === 1 && !exactXmr ? 'lamports' : 'piconero') ?? '0');
    // Size at the flat spread first, then price with the spread skewed for where the trade leaves inventory.
    const q0 = exactXmr ? priceExactXmr(amount) : priceQuote(direction, amount);
    const sk = FAULT === 'no-xmr-lock' ? null : skewFor(direction, await inventoryNow(), BigInt(q0.lamports), BigInt(q0.piconero));
    if (sk?.stop) throw pausedErr(direction);
    const q = !sk || sk.spreadBps === cfg.spreadBps ? q0 : exactXmr ? priceExactXmr(amount, sk.spreadBps) : priceQuote(direction, amount, sk.spreadBps);
    const lam = BigInt(q.lamports);
    if (lam < makerAcct.min || lam > makerAcct.max) throw bad(`amount outside ${makerAcct.min}..${makerAcct.max} lamports`);
    if (direction === 1 && FAULT !== 'no-xmr-lock' && BigInt(q.piconero) > (await xmrAvailable())) throw bad('not enough XMR inventory right now');
    if (direction === 2 && BigInt(await solBalance()) < lam + 50_000_000n) throw bad('not enough SOL inventory right now');
    return { quote: q, sig: K.signQuote(q, me.secretKey.slice(0, 32)), spreadBps: sk?.spreadBps ?? cfg.spreadBps };
  }
  const ip = clientIp(req, cfg.trustProxy);
  if (req.method === 'POST' && u.pathname === '/v1/swap') {
    if (!swapRate.take(ip)) throw new HttpError(429, 'too many swap requests; slow down a little');
    return startSwap(await readBody(req), ip);
  }
  const st = u.pathname.match(/^\/v1\/swap\/([1-9A-HJ-NP-Za-km-z]{32,44})$/);
  if (req.method === 'GET' && st) return status(st[1]);
  // Everything below is unsigned and costs reads or journal writes.
  if (req.method === 'POST' && !postRate.take(ip)) throw new HttpError(429, 'too many requests; slow down a little');
  const dep = u.pathname.match(/^\/v1\/swap\/([1-9A-HJ-NP-Za-km-z]{32,44})\/deposit$/);
  if (req.method === 'POST' && dep) {
    const s = swaps.get(dep[1]);
    const b = await readBody(req);
    if (!s || s.direction !== 2) throw new HttpError(404, 'unknown swap');
    if (!/^[0-9a-f]{64}$/.test(b.txHash)) throw bad('txHash');
    // The journal holds every secret and has to replay on restart: a repeated hint writes nothing.
    if (s.depositTx !== b.txHash && (s.hints = (s.hints ?? 0) + 1) <= 8) record(s.escrow, 'deposit-hint', { txHash: b.txHash });
    return { ok: true };
  }
  if (req.method === 'POST' && u.pathname === '/v1/relay/refund') return relayRefund(await readBody(req));
  if (req.method === 'POST' && u.pathname === '/v1/otc/rfq') return otcRfq(await readBody(req));
  const oq = u.pathname.match(/^\/v1\/otc\/rfq\/([0-9a-f]{32})$/);
  if (req.method === 'GET' && oq) { const x = otcQuotes.get(oq[1]); if (!x) throw new HttpError(404, 'unknown request'); return x.reply; }
  if (req.method === 'POST' && u.pathname === '/v1/otc/accept') return otcAccept(await readBody(req), ip);
  throw new HttpError(404, 'not found');
}

const quoteRate = new RateWindow(cfg.rateLimits?.quotePerMin ?? 120, 60_000);
const swapRate = new RateWindow(cfg.rateLimits?.swapPerMin ?? 20, 60_000);
const postRate = new RateWindow(cfg.rateLimits?.postPerMin ?? 60, 60_000);
setInterval(() => {
  quoteRate.sweep(); swapRate.sweep(); postRate.sweep();
  const t = Math.floor(Date.now() / 1000);
  for (const [k, v] of otcQuotes) if ((v.quote?.expiresAt ?? v.rfq?.expiresAt ?? 0) < t - 3600) otcQuotes.delete(k);
}, 60_000).unref();

const terms = (): T.DepositTerms => ({ depositMarginSecs: cfg.depositMarginSecs, depositWindowSecs: cfg.depositWindowSecs ?? T.DEFAULT_DEPOSIT_TERMS.depositWindowSecs });
const x2sLimits = (): X2SLimits => (cfg.x2sLimits ? { ...cfg.x2sLimits, unfundedLamports: BigInt(cfg.x2sLimits.unfundedLamports) } : DEFAULT_X2S_LIMITS);
/** Open XMR->SOL locks of ours (for the admission caps). */
/** SOL->XMR handshakes whose consent is still usable and whose lock has not appeared (for the admission caps). */
const openHandshakes = (now: number) => [...swaps.values()].filter((x) => !x.done && x.direction === 1 && !x.verified && !x.group && now <= x.consentExpiry + 120).map((x) => ({ taker: x.taker, ip: x.ip }));
const openX2S = () => [...swaps.values()].filter((x) => !x.done && x.direction === 2).map((x) => ({ taker: x.taker, ip: x.ip, lamports: BigInt(x.lamports), funded: !!x.depositSeen }));

async function startSwap(b: any, ip = '') {
  if (b.mode === 'pay' || b.mode === 'vault') return startPaySwap(b);
  requirePrice();
  const q = b.quote as K.Quote;
  if (!q || !K.verifyQuote(q, b.sig, me.publicKey.toBytes())) throw bad('not my quote');
  const now = Math.floor(Date.now() / 1000);
  if (q.expiresAt < now) throw bad('quote expired');
  if (usedNonces.has(q.nonce)) throw bad('quote already used');
  const swapId = K.fromHex(String(b.swapId));
  if (swapId.length !== 32) throw bad('swapId');
  const taker = new PublicKey(String(b.taker));
  const takerSpendPub = K.fromHex(String(b.takerSpendPub));
  const viewSecret = K.fromHex(String(b.viewSecret));
  if (!K.isGoodPoint(takerSpendPub)) throw bad('taker key is not a prime-order point');
  if (!K.isCanonical(viewSecret) || K.leToBig(viewSecret) === 0n) throw bad('view key');
  if (taker.equals(me.publicKey)) throw bad('taker is the maker');
  declined(taker.toBase58());
  if (q.direction === 1 && walked(swaps.values(), taker.toBase58(), now)) throw bad('this wallet cancelled a recent swap after the maker had paid; try again tomorrow');
  const escrowAddr = (q.direction === 1 ? P.pda.escrow(pid, taker, swapId) : P.pda.escrow(pid, me.publicKey, swapId)).toBase58();
  if (swaps.has(escrowAddr)) throw bad('swap id already used');
  if (q.feeBps !== feeBpsNow) throw bad('fee changed; ask for a new quote');
  const makerSpend = K.randomScalar();
  const makerSpendPub = K.pub(makerSpend);
  const shared = K.sharedWallet(makerSpendPub, takerSpendPub, viewSecret, cfg.moneroNet);
  const restoreHeight = (await daemonHeight(cfg.daemonUri)) - 5;
  // Checked again after every await and right before the record: two requests at once for one swap id would otherwise
  // both pass, and the second would overwrite the key half the first locked with (its refund then needs a key we lost).
  const taken = () => { if (swaps.has(escrowAddr) || usedNonces.has(q.nonce)) throw bad('swap id or quote already used'); };
  taken();
  const base = {
    direction: q.direction, swapId: K.toHex(swapId), taker: taker.toBase58(),
    makerSpend: K.toHex(makerSpend), makerSpendPub: K.toHex(makerSpendPub), takerSpendPub: K.toHex(takerSpendPub),
    viewSecret: K.toHex(viewSecret), sharedAddress: shared.address, quote: q, lamports: q.lamports, xmrAmount: q.piconero,
    t0Secs: cfg.t0Secs, windowSecs: cfg.windowSecs, restoreHeight, createdAt: now,
  };

  if (q.direction === 1) {
    const claimMode = b.claimMode ?? 'ready-only';
    if (claimMode !== 'ready-only' && claimMode !== 'payment-proof') throw bad('unknown claim mode');
    if (claimMode === 'payment-proof' && (cfg.claimMode !== 'payment-proof' || (cfg.attesters?.length ?? 0) < 2)) throw bad('payment-proof claims are not enabled on this maker');
    if (claimMode === 'ready-only' && !makerAcct?.v2) throw bad('this maker needs an account upgrade for ready-only swaps');
    const flags = claimMode === 'ready-only' ? P.F.READY_ONLY : 0;
    // The user's watchtowers: a flagged lock's v2 consent binds them. On a plain SOL->XMR escrow a watchtower can only
    // abort before t0 (the user's refund then hands our XMR back), so any one is acceptable; never the locker or us.
    const rawWts = b.watchtowers === undefined ? [] : b.watchtowers;
    if (!Array.isArray(rawWts) || rawWts.length > 2) throw bad('at most two watchtowers');
    const wts = rawWts.map((x: unknown) => { try { return new PublicKey(String(x)); } catch { throw bad('bad watchtower key'); } }) as PublicKey[];
    if (new Set(wts.map((w) => w.toBase58())).size !== wts.length || wts.some((w) => w.equals(taker) || w.equals(me.publicKey) || w.equals(PublicKey.default))) throw bad('bad watchtower list');
    if (FAULT !== 'no-xmr-lock' && BigInt(q.piconero) > (await xmrAvailable())) throw bad('not enough XMR inventory right now');
    const nope = admitS2X(openHandshakes(now), { taker: taker.toBase58(), ip }, cfg.s2xLimits ?? DEFAULT_S2X_LIMITS);
    if (nope) throw bad(nope);
    taken();
    const consentExpiry = now + 90;
    const lock: P.LockParams = {
      swapId, claimer: me.publicKey, direction: 1, amount: BigInt(q.lamports), xmrAmount: BigInt(q.piconero),
      claimPoint: makerSpendPub, refundPoint: takerSpendPub, viewPub: shared.viewPub, quoteHash: K.quoteHash(q),
      t0Secs: cfg.t0Secs, windowSecs: cfg.windowSecs, watchtowers: wts, makerAuthority: me.publicKey, consentExpiry, feeBps: q.feeBps, flags,
    };
    const escrow = escrowAddr;
    // Journal the secret BEFORE consenting: a crash after this point can always finish the swap.
    record(escrow, 'handshake', { swap: { ...base, escrow, consentExpiry, flags } });
    swaps.get(escrow)!.ip = ip;
    crashPoint('after-handshake');
    const digest = P.consentDigest(pid, taker, lock);
    const { ed25519 } = await import('@noble/curves/ed25519');
    const consentSig = K.toHex(ed25519.sign(digest, me.secretKey.slice(0, 32)));
    log(`swap ${escrow.slice(0, 8)} SOL->XMR handshake: ${K.fmtSol(BigInt(q.lamports))} SOL for ${K.fmtXmr(BigInt(q.piconero))} XMR`);
    return { direction: 1, makerSpendPub: K.toHex(makerSpendPub), sharedAddress: shared.address, t0Secs: cfg.t0Secs, windowSecs: cfg.windowSecs, consentExpiry, consentSig, feeBps: q.feeBps, flags, claimMode };
  }

  // XMR -> SOL: the maker locks SOL first, so admission is capped (maker/policy.ts) and the user
  // must be given time to send and confirm before we would abort (sdk/taker.ts depositDeadline).
  if (x2sT0() < T.minXmrToSolT0(terms())) throw bad('this maker\'s t0 is too short for XMR->SOL');
  if (!makerAcct?.v2) { log('XMR->SOL refused: this maker account is not upgraded. Run: node maker/register.ts <config> upgrade'); throw bad('this maker is not set up for XMR->SOL yet'); }
  const refuse = noShowRefusal(swaps.values(), { taker: taker.toBase58(), ip }, now) ?? admitX2S(openX2S(), { taker: taker.toBase58(), ip, lamports: BigInt(q.lamports) }, x2sLimits());
  if (refuse) throw bad(refuse);
  taken();
  const lock: P.LockParams = {
    swapId, claimer: taker, direction: 2, amount: BigInt(q.lamports), xmrAmount: BigInt(q.piconero),
    claimPoint: takerSpendPub, refundPoint: makerSpendPub, viewPub: shared.viewPub, quoteHash: K.quoteHash(q),
    t0Secs: x2sT0(), windowSecs: x2sWindow(), watchtowers: [], makerAuthority: me.publicKey, consentExpiry: 0, feeBps: q.feeBps,
    // Proof mode: past t0 the user's claim needs our ready or a proof of its own deposit. Without it, a maker outage
    // across t0 hands the SOL to anyone who locked and never paid.
    flags: P.F.PROOF,
  };
  const escrow = P.pda.escrow(pid, me.publicKey, swapId).toBase58();
  record(escrow, 'handshake', { swap: { ...base, t0Secs: x2sT0(), windowSecs: x2sWindow(), escrow, consentExpiry: 0, flags: P.F.PROOF } });
  swaps.get(escrow)!.ip = ip;
  crashPoint('after-handshake');
  const sig = await sendIxs(conn, me, [P.ixLock2(pid, me.publicKey, lock)]);
  record(escrow, 'sol-locked', { sig });
  const refundAcks = await coverWithTowers(escrow, makerSpend);
  log(`swap ${escrow.slice(0, 8)} XMR->SOL: locked ${K.fmtSol(BigInt(q.lamports))} SOL, waiting for ${K.fmtXmr(BigInt(q.piconero))} XMR`);
  return { direction: 2, makerSpendPub: K.toHex(makerSpendPub), sharedAddress: shared.address, escrow, lockSig: sig, makerKeyProof: keyProof(makerSpend, escrow, takerSpendPub), refundAcks };
}

/**
 * XMR->SOL with refund towers: deal our half right after the lock. Too few acks means the page will never show a
 * deposit address, so give the lock up at once (no deposit can exist yet) instead of parking the SOL.
 */
async function coverWithTowers(escrow: string, makerSpend: Uint8Array): Promise<R.Ack[] | undefined> {
  if (!cfg.refundTowers) return undefined;
  const pk = new PublicKey(escrow);
  try {
    const e = await loadEscrow(escrow);
    if (!e) throw new Error('lock not visible yet');
    const { acks } = await dealToTowers({ pid, escrow: pk, e, makerSpend, maker: me, towers: cfg.refundTowers.towers, minAcks: cfg.refundTowers.minAcks });
    record(escrow, 'towers-acked', { acks });
    return acks;
  } catch (err) {
    log(`!! swap ${escrow.slice(0, 8)} refund towers: ${describeErr(err)}; aborting the lock`);
    try { const sig = await sendIxs(conn, me, [P.ixAbort(pid, me.publicKey, pk, me.publicKey)]); record(escrow, 'abort-sent', { sig }); }
    catch (e2) { log(`!! swap ${escrow.slice(0, 8)} abort after the tower failure failed: ${describeErr(e2)} (the step loop retries the no-show abort)`); }
    throw bad('refund towers are not answering right now; try again in a few minutes');
  }
}

/** XMR->SOL: proof that we know our key half (sdk/keys.ts proveKey), bound to the escrow and the taker's half. */
function keyProof(makerSpend: Uint8Array, escrow: string, takerSpendPub: Uint8Array): string {
  return K.toHex(K.proveKey(makerSpend, K.keyProofContext(pid.toBytes(), new PublicKey(escrow).toBytes(), takerSpendPub)));
}

// ---------------------------------------------------------------- pay links + cashout vaults
async function startPaySwap(b: any) {
  if (!makerAcct?.v2) throw bad('this maker does not take pay links yet');
  if (cfg.t0Secs < (cfg.payLateSecs ?? 1500) + 600) throw bad('this maker\'s t0 is too short for pay links');
  // v1.5: the claim needs a payment proof, which needs Monero confirmations + an attested header before t1
  if (cfg.t0Secs + cfg.windowSecs < (cfg.payProofSecs ?? 3600) + cfg.claimMarginSecs + 600) throw bad('this maker\'s window is too short to prove a pay-link payment');
  const q = b.quote as K.Quote;
  if (!q || q.direction !== 1 || !K.verifyQuote(q, b.sig, me.publicKey.toBytes())) throw bad('not my quote');
  const now = Math.floor(Date.now() / 1000);
  if (q.expiresAt < now) throw bad('quote expired');
  if (usedNonces.has(q.nonce)) throw bad('quote already used');
  if (q.feeBps !== feeBpsNow) throw bad('fee changed; ask for a new quote');
  const swapId = K.fromHex(String(b.swapId));
  if (swapId.length !== 32) throw bad('swapId');
  const locker = new PublicKey(String(b.locker));
  if (locker.equals(me.publicKey)) throw bad('locker is the maker');
  declined(locker.toBase58());
  const linkPk = new PublicKey(String(b.link));
  const la = await conn.getAccountInfo(linkPk, 'confirmed');
  if (!la || !la.owner.equals(pid)) throw bad('unknown link');
  const link = P.decodeLink(la.data, linkPk);
  declined(link.owner.toBase58());
  let flags: number = P.F.PAY;
  let wts = (Array.isArray(b.watchtowers) ? b.watchtowers : []).map((x: unknown) => new PublicKey(String(x))) as PublicKey[];
  if (b.mode === 'vault') {
    const va = await conn.getAccountInfo(locker, 'confirmed');
    if (!va || !va.owner.equals(pid)) throw bad('unknown vault');
    const v = P.decodeVault(va.data, locker);
    if (!v.p.link.equals(linkPk)) throw bad('vault pays a different link');
    wts = v.p.watchtowers.filter((w) => !w.equals(PublicKey.default));
    flags |= P.F.VAULT;
  }
  // The payer cannot cancel a pay escrow and its refund reveals nothing, so a watchtower that
  // aborted after our XMR lock would strand it: consent only to watchtowers we trust.
  const trusted = new Set(cfg.payWatchtowers ?? []);
  if (wts.length < 1 || wts.length > 2) throw bad('one or two watchtowers');
  for (const w of wts) if (!trusted.has(w.toBase58()) || w.equals(locker) || w.equals(me.publicKey)) throw bad(`watchtower ${w.toBase58()} is not accepted by this maker`);
  const escrow = P.pda.escrow(pid, locker, swapId).toBase58();
  if (swaps.has(escrow)) throw bad('payment id already used');
  if (BigInt(q.piconero) > (await xmrAvailable())) throw bad('not enough XMR inventory right now');
  const makerSpend = K.randomScalar();
  const makerSpendPub = K.pub(makerSpend);
  if (link.retired) throw bad('this link is retired');
  const w = Pay.payWallet(makerSpendPub, link.master, P.pda.escrow(pid, locker, swapId).toBytes(), K.quoteHash(q), cfg.moneroNet);
  const restoreHeight = (await daemonHeight(cfg.daemonUri)) - 5;
  const consentExpiry = now + 90;
  const lock: P.LockParams = {
    swapId, claimer: me.publicKey, direction: 1, amount: BigInt(q.lamports), xmrAmount: BigInt(q.piconero),
    claimPoint: makerSpendPub, refundPoint: w.spendPub, viewPub: w.viewPub, quoteHash: K.quoteHash(q),
    t0Secs: cfg.t0Secs, windowSecs: cfg.windowSecs, watchtowers: wts, makerAuthority: me.publicKey, consentExpiry, feeBps: q.feeBps,
    flags, link: linkPk,
  };
  record(escrow, 'handshake', { swap: {
    escrow, direction: 1, swapId: K.toHex(swapId), taker: locker.toBase58(), makerSpend: K.toHex(makerSpend), makerSpendPub: K.toHex(makerSpendPub),
    takerSpendPub: K.toHex(w.spendPub), viewSecret: K.toHex(w.view), sharedAddress: w.address, quote: q, lamports: q.lamports, xmrAmount: q.piconero,
    t0Secs: cfg.t0Secs, windowSecs: cfg.windowSecs, consentExpiry, restoreHeight, createdAt: now, flags, link: linkPk.toBase58(),
  } });
  crashPoint('after-handshake');
  const { ed25519 } = await import('@noble/curves/ed25519');
  const consentSig = K.toHex(ed25519.sign(P.consentDigest(pid, locker, lock), me.secretKey.slice(0, 32)));
  log(`swap ${escrow.slice(0, 8)} ${b.mode} -> /pay/${link.name}: ${K.fmtSol(BigInt(q.lamports))} SOL for ${K.fmtXmr(BigInt(q.piconero))} XMR`);
  return { direction: 1, makerSpendPub: K.toHex(makerSpendPub), sharedAddress: w.address, t0Secs: cfg.t0Secs, windowSecs: cfg.windowSecs, consentExpiry, consentSig, feeBps: q.feeBps };
}

// ---------------------------------------------------------------- OTC desk
// Quotes live in memory and are readable by RFQ id only (a 128-bit secret of the taker).
const otcQuotes = new Map<string, { rfq: O.Rfq; quote?: O.OtcQuote; sig?: string; reply: unknown; used?: boolean }>();

async function otcRfq(b: any) {
  if (!cfg.otc || !makerAcct?.v2 || !makerAcct.active || !configAcct) throw bad('no OTC desk here');
  requirePrice();
  const r = b.rfq as O.Rfq;
  const now = Math.floor(Date.now() / 1000);
  const err = O.checkRfq(r, now);
  if (err) throw bad(err);
  declined(String(r.taker));
  if (!O.verifyRfq(r, String(b.sig), new PublicKey(r.taker).toBytes())) throw bad('the request is not signed by the taker');
  if (otcQuotes.has(r.id)) return otcQuotes.get(r.id)!.reply;
  const decline = (reason: string) => { const reply = { status: 'declined', reason }; otcQuotes.set(r.id, { rfq: r, reply }); return reply; };
  if (!(makerAcct.directions & r.side)) return decline('side not offered');
  const { min, max } = otcRange();
  const maxTr = Math.min(cfg.otc.maxTranches, O.MAX_TRANCHES);
  const ceiling = max * BigInt(maxTr);
  let lamports: bigint, piconero: bigint;
  let one = priceQuote(r.side, r.side === 1 ? 1_000_000_000n : 1_000_000_000_000n, cfg.otc.spreadBps);
  // Inventory skew on the desk too, priced for the full request (the size is only clipped down from
  // here), and fills never dip into what the floor keeps back.
  const invNow = await inventoryNow();
  const keep = floorReserve(cfg.skew, invNow);
  {
    const sizeL = r.side === 1 ? BigInt(r.amount) : (BigInt(r.amount) * BigInt(one.lamports)) / 1_000_000_000_000n;
    const sizeP = r.side === 1 ? (BigInt(r.amount) * BigInt(one.piconero)) / 1_000_000_000n : BigInt(r.amount);
    const sk = skewFor(r.side, invNow, sizeL < ceiling ? sizeL : ceiling, sizeP, cfg.otc.spreadBps);
    if (sk.stop && skewFor(r.side, invNow, 0n, 0n, cfg.otc.spreadBps).stop) return decline(r.side === 1 ? 'low on XMR right now' : 'low on SOL right now');
    if (sk.spreadBps !== cfg.otc.spreadBps) one = priceQuote(r.side, r.side === 1 ? 1_000_000_000n : 1_000_000_000_000n, sk.spreadBps);
  }
  if (r.side === 1) {
    lamports = BigInt(r.amount) < ceiling ? BigInt(r.amount) : ceiling;
    piconero = (lamports * BigInt(one.piconero)) / 1_000_000_000n;
    const inv = await xmrAvailable() - BigInt(Math.ceil(keep.coin * xmrPerSol * 1e12));
    if (piconero > inv) { lamports = inv > 0n ? (lamports * inv) / piconero : 0n; piconero = (lamports * BigInt(one.piconero)) / 1_000_000_000n; }
  } else {
    piconero = BigInt(r.amount);
    lamports = (piconero * BigInt(one.lamports)) / 1_000_000_000_000n;
    if (lamports > ceiling) { piconero = (piconero * ceiling) / lamports; lamports = ceiling; }
    let solBal = BigInt(await solBalance()) - 100_000_000n - BigInt(Math.ceil(keep.sol * 1e9));
    if (solBal < 0n) solBal = 0n;
    if (lamports > solBal) { piconero = (piconero * solBal) / lamports; lamports = solBal; }
  }
  const filled = r.side === 1 ? lamports : piconero;
  if (lamports <= 0n || filled < BigInt(r.minFill)) return decline('cannot fill the minimum size right now');
  const tranches = O.tranchesFor(lamports, max);
  if (lamports / BigInt(tranches) < min) return decline('below this desk\'s tranche minimum');
  const quote: O.OtcQuote = {
    v: 1, kind: 'otc', rfq: r.id, rfqHash: O.rfqHash(r), maker: me.publicKey.toBase58(), side: r.side,
    lamports: lamports.toString(), piconero: piconero.toString(), tranches, feeBps: feeBpsNow,
    expiresAt: Math.min(now + cfg.otc.quoteTtlSecs, r.expiresAt), nonce: randomBytes(16).toString('hex'),
  };
  const sig = O.signOtcQuote(quote, me.secretKey.slice(0, 32));
  const reply = { status: 'quoted', quote, sig };
  otcQuotes.set(r.id, { rfq: r, quote, sig, reply });
  log(`otc ${r.id.slice(0, 8)} quoted: ${K.fmtSol(lamports)} SOL <-> ${K.fmtXmr(piconero)} XMR in ${tranches} tranche(s)`);
  return reply;
}

async function otcAccept(b: any, ip = '') {
  const q = b.quote as O.OtcQuote;
  // The requester signs the accept (its wallet over the accept digest), so nobody who merely
  // learned the RFQ id can burn the quote or make us lock SOL to keys the taker cannot use.
  const taker0 = new PublicKey(String(b.taker));
  const { ed25519: ed } = await import('@noble/curves/ed25519');
  try {
    if (!ed.verify(K.fromHex(String(b.takerSig)), O.acceptBytes(q, b.tranches), taker0.toBytes())) throw new Error();
  } catch { throw bad('the accept is not signed by the requester'); }
  if (!q || q.maker !== me.publicKey.toBase58() || !O.verifyOtcQuote(q, String(b.sig), me.publicKey.toBytes())) throw bad('not my quote');
  const st = otcQuotes.get(q.rfq);
  if (!st || !st.quote || K.toHex(O.otcQuoteHash(st.quote)) !== K.toHex(O.otcQuoteHash(q))) throw bad('unknown quote');
  if (st.used) throw bad('quote already accepted');
  const now = Math.floor(Date.now() / 1000);
  if (q.expiresAt < now) throw bad('quote expired');
  if (q.feeBps !== feeBpsNow) throw bad('fee changed; ask for a new quote');
  const taker = new PublicKey(String(b.taker));
  if (taker.toBase58() !== st.rfq.taker || taker.equals(me.publicKey)) throw bad('not the requester');
  declined(taker.toBase58());
  const plan = O.planTranches(q);
  const reqs = b.tranches as { swapId: string; takerSpendPub: string; viewSecret: string; watchtowers?: string[] }[];
  if (!Array.isArray(reqs) || reqs.length !== plan.length) throw bad('one key set per tranche');
  // validate everything before any state changes
  const parsed = reqs.map((t) => {
    const swapId = K.fromHex(String(t.swapId)), takerSpendPub = K.fromHex(String(t.takerSpendPub)), viewSecret = K.fromHex(String(t.viewSecret));
    if (swapId.length !== 32 || !K.isGoodPoint(takerSpendPub) || !K.isCanonical(viewSecret) || K.leToBig(viewSecret) === 0n) throw bad('bad tranche keys');
    const wts = (t.watchtowers ?? []).slice(0, 2).map((x) => new PublicKey(String(x)));
    // A watchtower the taker controls could abort and charge the failure to this desk's record.
    const trusted = new Set(cfg.payWatchtowers ?? []);
    for (const w of wts) if (!trusted.has(w.toBase58())) throw bad(`watchtower ${w.toBase58()} is not accepted by this desk`);
    return { swapId, takerSpendPub, viewSecret, wts };
  });
  if (q.side === 1 && BigInt(q.piconero) > (await xmrAvailable())) throw bad('not enough XMR inventory right now');
  if (q.side === 2) {
    // The taker needs time to send and confirm before we would abort (the same rule as startSwap).
    if (x2sT0() < T.minXmrToSolT0(terms())) throw bad('this maker\'s t0 is too short for XMR->SOL');
    // We lock SOL first on this side; cap what one taker can make us lock before depositing.
    const open = [...swaps.values()].filter((x) => !x.done && x.group && x.direction === 2 && x.taker === taker.toBase58()).length;
    if (open + plan.length > (cfg.otc?.side2MaxOpen ?? 12)) throw bad('finish your open XMR->SOL trade first');
    // The same rules as a plain XMR->SOL swap: a free wallet must not lock the desk's SOL.
    const nope = noShowRefusal(swaps.values(), { taker: taker.toBase58(), ip }, now) ?? admitX2S(openX2S().filter((x) => x.taker !== taker.toBase58()), { taker: taker.toBase58(), ip, lamports: BigInt(q.lamports) }, x2sLimits());
    if (nope) throw bad(nope);
  }
  st.used = true;
  const restoreHeight = (await daemonHeight(cfg.daemonUri)) - 5;
  const { ed25519 } = await import('@noble/curves/ed25519');
  const out: unknown[] = [];
  for (const [k, t] of plan.entries()) {
    const x = parsed[k];
    const makerSpend = K.randomScalar(), makerSpendPub = K.pub(makerSpend);
    const shared = K.sharedWallet(makerSpendPub, x.takerSpendPub, x.viewSecret, cfg.moneroNet);
    const escrow = (q.side === 1 ? P.pda.escrow(pid, taker, x.swapId) : P.pda.escrow(pid, me.publicKey, x.swapId)).toBase58();
    if (swaps.has(escrow)) throw bad('swap id already used');
    const tq: K.Quote = { v: 1, maker: q.maker, direction: q.side, lamports: t.lamports.toString(), piconero: t.piconero.toString(), feeBps: q.feeBps, expiresAt: q.expiresAt, nonce: `${q.nonce}-${k}` };
    const consentExpiry = q.side === 1 ? now + 300 : 0;
    const lock: P.LockParams = {
      swapId: x.swapId, claimer: q.side === 1 ? me.publicKey : taker, direction: q.side, amount: t.lamports, xmrAmount: t.piconero,
      claimPoint: q.side === 1 ? makerSpendPub : x.takerSpendPub, refundPoint: q.side === 1 ? x.takerSpendPub : makerSpendPub,
      viewPub: shared.viewPub, quoteHash: t.quoteHash, t0Secs: q.side === 1 ? cfg.t0Secs : x2sT0(), windowSecs: q.side === 1 ? cfg.windowSecs : x2sWindow(),
      watchtowers: q.side === 1 ? x.wts : [], makerAuthority: me.publicKey, consentExpiry, feeBps: q.feeBps, flags: q.side === 1 ? P.F.OTC : P.F.OTC | P.F.PROOF,
    };
    record(escrow, 'handshake', { swap: {
      escrow, direction: q.side, swapId: K.toHex(x.swapId), taker: taker.toBase58(), makerSpend: K.toHex(makerSpend), makerSpendPub: K.toHex(makerSpendPub),
      takerSpendPub: K.toHex(x.takerSpendPub), viewSecret: K.toHex(x.viewSecret), sharedAddress: shared.address, quote: tq,
      lamports: t.lamports.toString(), xmrAmount: t.piconero.toString(), t0Secs: lock.t0Secs, windowSecs: lock.windowSecs, consentExpiry,
      restoreHeight, createdAt: now, flags: q.side === 1 ? P.F.OTC : P.F.OTC | P.F.PROOF, group: q.rfq, quoteHashHex: K.toHex(t.quoteHash),
    } });
    if (q.side === 1) {
      const consentSig = K.toHex(ed25519.sign(P.consentDigest(pid, taker, lock), me.secretKey.slice(0, 32)));
      out.push({ index: k, makerSpendPub: K.toHex(makerSpendPub), sharedAddress: shared.address, t0Secs: cfg.t0Secs, windowSecs: cfg.windowSecs, consentExpiry, consentSig });
    } else {
      const sig = await sendIxs(conn, me, [P.ixLock2(pid, me.publicKey, lock)]);
      record(escrow, 'sol-locked', { sig });
      const refundAcks = await coverWithTowers(escrow, makerSpend);
      out.push({ index: k, makerSpendPub: K.toHex(makerSpendPub), sharedAddress: shared.address, t0Secs: lock.t0Secs, windowSecs: lock.windowSecs, escrow, lockSig: sig, makerKeyProof: keyProof(makerSpend, escrow, x.takerSpendPub), refundAcks });
    }
  }
  log(`otc ${q.rfq.slice(0, 8)} accepted: ${plan.length} tranche(s), side ${q.side}`);
  return { tranches: out };
}

/**
 * OTC SOL->XMR: fund every locked tranche of a trade in ONE Monero transaction (one output each),
 * so a big fill does not wait on a chain of change outputs. Waits up to otc.lockWaitSecs after
 * the first tranche appears for the rest; tranches that never lock lapse (partial fill).
 */
async function lockXmrGroup(s: Swap) {
  const members = () => [...swaps.values()].filter((x) => x.group === s.group && x.direction === 1 && !x.done);
  for (const m of members()) if (m.xmrTxHash && !m.xmrRelayed) { await lockXmr(m); }
  const now = await chainNow(conn);
  const firstSeen = Math.min(...members().map((m) => m.escrowSeenAt ?? Number.MAX_SAFE_INTEGER));
  const unseen = members().filter((m) => !m.xmrTxHash && !m.verified);
  if (unseen.length && now < firstSeen + (cfg.otc?.lockWaitSecs ?? 120)) return;
  await main.exclusive(async () => {
    const ready: Swap[] = [];
    for (const m of members()) {
      if (m.xmrTxHash || !m.verified) continue;
      const fin = await loadEscrow(m.escrow, 'finalized');
      if (fin && (fin.state === P.ST.LOCKED || fin.state === P.ST.READY) && now < Number(fin.t0) - 60) ready.push(m);
    }
    if (!ready.length) return;
    let r: any = null;
    for (let i = 0; i < 4 && !r; i++) {
      const t = await main.call('transfer', {
        destinations: ready.map((m) => ({ amount: Number(m.xmrAmount), address: m.sharedAddress })), account_index: 0, priority: 0,
        do_not_relay: true, get_tx_metadata: true, get_tx_key: true, get_tx_hex: true,
      });
      if (!t.tx_blob || X.parseTx(K.fromHex(t.tx_blob)).nin <= MAX_LOCK_INPUTS) r = t;
    }
    if (!r) { log(`!! otc ${s.group!.slice(0, 8)}: no transaction small enough to prove on chain: split the wallet's outputs`); return; }
    for (const m of ready) record(m.escrow, 'xmr-lock-built', { hash: r.tx_hash, meta: r.tx_metadata, txKey: r.tx_key });
    crashPoint('after-xmr-build');
    await main.call('relay_tx', { hex: r.tx_metadata });
    for (const m of ready) record(m.escrow, 'xmr-relayed');
    log(`otc ${s.group!.slice(0, 8)} XMR locked for ${ready.length} tranche(s) in one tx: ${r.tx_hash}`);
  });
}

async function status(escrow: string) {
  const s = swaps.get(escrow);
  if (!s) throw new HttpError(404, 'unknown swap');
  let confirmations: number | undefined;
  const tx = s.direction === 1 ? s.xmrTxHash : s.paidTx ?? s.seenTx ?? s.depositTx;
  if (tx && s.xmrRelayed !== false) {
    try {
      const v = await verifyLock({ daemonUri: cfg.daemonUri, txHash: tx, spendPub: K.pointAdd(K.fromHex(s.makerSpendPub), K.fromHex(s.takerSpendPub)), viewSecret: K.fromHex(s.viewSecret), minAmount: BigInt(s.xmrAmount), minConf: cfg.minConf });
      confirmations = v.confirmations;
    } catch { /* daemon hiccup */ }
  }
  return { escrow, depositSeen: !!s.depositSeen, seenPiconero: s.seenAmount?.toString(), phase: s.done ? `done:${s.done}` : s.stage, xmrLockTx: s.direction === 1 && s.xmrRelayed ? s.xmrTxHash : undefined, depositTx: s.depositTx, confirmations, required: cfg.minConf, note: s.lastError,
    // XMR->SOL resume on another device: the key proof for this escrow (the maker's half is public).
    makerKeyProof: s.direction === 2 ? keyProof(K.fromHex(s.makerSpend), escrow, K.fromHex(s.takerSpendPub)) : undefined,
    refundAcks: s.direction === 2 ? s.refundAcks : undefined };
}

async function loadEscrow(addr: string, commitment: 'confirmed' | 'finalized' = 'confirmed') {
  const a = await conn.getAccountInfo(new PublicKey(addr), commitment);
  if (!a || !a.owner.equals(pid) || a.data.length !== P.ESCROW_LEN) return null;
  return P.decodeEscrow(a.data, new PublicKey(addr));
}

/** Gasless refund for a user: only when no claim can ever happen (finalized abort or past t1). */
async function relayRefund(b: any) {
  const e = await loadEscrow(String(b.escrow), 'finalized');
  if (!e) throw bad('unknown escrow');
  if (!e.maker.equals(me.publicKey)) throw bad('not my swap');
  const now = await chainNow(conn, 'finalized');
  const refundable = e.state === P.ST.ABORTED || ((e.state === P.ST.LOCKED || e.state === P.ST.READY) && now >= Number(e.t1));
  if (!refundable) throw bad('not refundable yet');
  const isPay = (e.flags & P.F.PAY) !== 0;
  const secret = isPay ? new Uint8Array(32) : K.fromHex(String(b.secret));
  if (!isPay && (!K.isCanonical(secret) || !K.equalBytes(K.pub(secret), e.refundPoint))) throw bad('wrong secret');
  const escrow = e.address!.toBase58();
  if (swaps.has(escrow) && !isPay) record(escrow, 'other-secret', { secret: K.toHex(secret) });
  const sig = await sendIxs(conn, me, [P.ixRefund(pid, me.publicKey, e.address!, e.locker, e.maker, secret)]);
  if (swaps.has(escrow)) record(escrow, 'refund-sent', { sig });
  log(`relayed refund ${escrow.slice(0, 8)} ${sig.slice(0, 12)}`);
  return { sig };
}

// XMR->SOL claims are relayed by neutral relayers (watchtowers), never by the maker: the claim
// carries the user's secret, and a counterparty relayer could sweep the XMR and drop the tx.

// ---------------------------------------------------------------- monero helpers
/** Pay escrows: the escrow must still be open and outside the late window right before relaying. */
async function payStillSafe(s: Swap): Promise<boolean> {
  if (!((s.flags ?? 0) & P.F.PAY)) return true;
  const e = await loadEscrow(s.escrow, 'confirmed');
  const now = await chainNow(conn);
  return !!e && e.state === P.ST.LOCKED && now < Number(e.t0) - (cfg.payLateSecs ?? 1500);
}

/** Push a pay escrow's lock tx to the trusted watchtowers listed in it (best effort). */
async function pushHint(s: Swap, txHash: string) {
  if (!((s.flags ?? 0) & P.F.PAY)) return;
  const { ed25519 } = await import('@noble/curves/ed25519');
  const hintSig = K.toHex(ed25519.sign(new TextEncoder().encode(`halfkey-hint-v1:${s.escrow}:${txHash}`), me.secretKey.slice(0, 32)));
  for (const [pk, url] of Object.entries(cfg.payWatchtowerUrls ?? {})) {
    (async () => {
      for (let i = 0; i < 20; i++) { // retry until acknowledged (a briefly-down watchtower still gets it)
        try {
          const r = await fetch(`${url.replace(/\/+$/, '')}/v1/hint`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ escrow: s.escrow, txHash, sig: hintSig }), signal: AbortSignal.timeout(8000) });
          if (r.ok) return;
        } catch { /* retry */ }
        await new Promise((x) => setTimeout(x, 15_000));
      }
      log(`hint to ${pk.slice(0, 8)} never acknowledged`);
    })();
  }
}

/**
 * The on-chain payment proof carries the transaction's inputs and must fit one Solana transaction, so a lock
 * with many inputs could never be proven and an offline user's swap could never be claimed. Nothing leaves until
 * it fits: a few tries (the wallet picks outputs at random), then the lock deadline aborts the swap.
 */
const MAX_LOCK_INPUTS = 3;
async function buildLockTx(s: Swap) {
  for (let i = 0; i < 4; i++) {
    const r = await main.call('transfer', {
      destinations: [{ amount: Number(s.xmrAmount), address: s.sharedAddress }], account_index: 0, priority: 0,
      do_not_relay: true, get_tx_metadata: true, get_tx_key: true, get_tx_hex: true,
    });
    if (!r.tx_blob || X.parseTx(K.fromHex(r.tx_blob)).nin <= MAX_LOCK_INPUTS) return r;
  }
  return null;
}

async function lockXmr(s: Swap) {
  await main.exclusive(async () => {
    if (!s.xmrRelayed && !(await payStillSafe(s))) { s.lastError = 'pay escrow too close to t0 (or no longer open): not locking XMR'; return; }
    if (!s.xmrTxHash) {
      const r = await buildLockTx(s);
      if (!r) { s.lastError = 'no transaction small enough to prove on chain: split the wallet\'s outputs'; log(`!! swap ${s.escrow.slice(0, 8)}: ${s.lastError}`); return; }
      record(s.escrow, 'xmr-lock-built', { hash: r.tx_hash, meta: r.tx_metadata, txKey: r.tx_key });
      crashPoint('after-xmr-build');
    }
    try {
      await main.call('relay_tx', { hex: s.xmrTxMeta });
    } catch (e) {
      // Already relayed before a crash? Then the daemon knows the tx.
      const v = await verifyLock({ daemonUri: cfg.daemonUri, txHash: s.xmrTxHash!, spendPub: K.pointAdd(K.fromHex(s.makerSpendPub), K.fromHex(s.takerSpendPub)), viewSecret: K.fromHex(s.viewSecret), minAmount: 1n, minConf: 0 });
      if (!v.amount) throw e;
    }
    crashPoint('after-xmr-relay');
    record(s.escrow, 'xmr-relayed');
    pushHint(s, s.xmrTxHash!).catch(() => {});
    log(`swap ${s.escrow.slice(0, 8)} XMR locked: ${s.xmrTxHash}`);
  });
}

/** Proof reads go to the first monerod that answers (daemonUri is a comma list): one public node down must not stall
 * a proof. Only network failures move on to the next node; a definite answer (e.g. "does not verify") is returned. */
async function eachDaemon<T>(f: (daemon: string) => Promise<T>): Promise<T> {
  const list = cfg.daemonUri.split(',').map((x) => x.trim()).filter(Boolean);
  let last: unknown;
  for (const d of list) {
    try { return await f(d); } catch (err) { last = err; if (!/fetch failed|ECONNREFUSED|ECONNRESET|ETIMEDOUT|timeout|aborted|socket|network|5\d\d|Bad Gateway/i.test(describeErr(err))) throw err; }
  }
  throw last;
}

/**
 * v1.5: put the payment proof of our XMR lock on chain. The wallet's OutProof (get_tx_proof, tx
 * key) bound to the escrow address; the block attested by the committee (sdk/prove.ts). Retried
 * every tick until the lock has the committee's confirmations.
 */
async function proveLock(s: Swap, e: P.EscrowAccount) {
  if (!P.allowsPaymentProof(e) || !s.xmrTxHash || !cfg.attesters?.length) return;
  try {
    const escrowPk = new PublicKey(s.escrow);
    const existing = await conn.getAccountInfo(escrowPk); // keep the escrow fresh in the log on errors
    if (!existing) return;
    const proofStr = (await main.call('get_tx_proof', { txid: s.xmrTxHash, address: s.sharedAddress, message: X.escrowMessage(escrowPk.toBytes()) })).signature as string;
    const { kind, sigs } = X.decodeProofString(proofStr);
    const plan = await eachDaemon((daemon) => planProve({ conn, pid, payer: me.publicKey, escrow: escrowPk, e, txid: s.xmrTxHash!, kind, sig: sigs[0], daemon, attesters: cfg.attesters! }));
    if (plan.status === 'pending') { s.lastError = `proof: ${plan.why}`; return; }
    if (plan.attestIxs) await sendIxs(conn, me, plan.attestIxs);
    if (!(await conn.getAccountInfo(plan.proofPda, 'confirmed'))) await sendIxs(conn, me, [plan.proveIx]);
    record(s.escrow, 'proven', { proofPda: plan.proofPda.toBase58() });
    log(`swap ${s.escrow.slice(0, 8)} XMR payment proven on chain (${K.fmtXmr(plan.args.amount)} XMR, block ${plan.args.height})`);
  } catch (err) {
    s.lastError = `proof: ${describeErr(err)}`;
  }
}

/** XMR->SOL in proof mode: the proof of the user's own deposit, from the shared view key we hold. Retried each tick. */
async function proveDeposit(s: Swap, e: P.EscrowAccount) {
  if (!cfg.attesters?.length) return;
  try {
    if (!s.paidTx) await depositOk(s); // finds the paying transaction once it has its confirmations
    if (!s.paidTx) return;
    const escrowPk = new PublicKey(s.escrow);
    const tx = await eachDaemon((d) => X.fetchTx(d, s.paidTx!));
    if (tx.inPool) return;
    const sig = X.inProofSig(tx.unprunable, K.fromHex(s.paidTx), escrowPk.toBytes(), K.fromHex(s.viewSecret), e.viewPub);
    let plan: Awaited<ReturnType<typeof planProve>>;
    try { plan = await eachDaemon((daemon) => planProve({ conn, pid, payer: me.publicKey, escrow: escrowPk, e, txid: s.paidTx!, kind: X.KIND_IN, sig, daemon, attesters: cfg.attesters! })); }
    catch (err) {
      // This transaction can't back a proof (split outputs, an extra tx key, or just not what it seemed): look for another.
      if (/does not verify|no output|proven amount|not provable|no tx public key/.test(describeErr(err))) { log(`swap ${s.escrow.slice(0, 8)} transaction ${s.paidTx} can't be proven: ${describeErr(err)}`); s.paidTx = undefined; return; }
      throw err;
    }
    if (plan.status === 'pending') { s.lastError = `proof: ${plan.why}`; return; }
    if (plan.attestIxs) await sendIxs(conn, me, plan.attestIxs);
    if (!(await conn.getAccountInfo(plan.proofPda, 'confirmed'))) await sendIxs(conn, me, [plan.proveIx]);
    record(s.escrow, 'proven', { proofPda: plan.proofPda.toBase58() });
    log(`swap ${s.escrow.slice(0, 8)} the user's deposit is proven on chain (block ${plan.args.height})`);
  } catch (err) { s.lastError = `proof: ${describeErr(err)}`; }
}

/** Sweep the shared wallet (both halves known) into the maker's main wallet. */
async function sweepShared(s: Swap, otherSecret: Uint8Array): Promise<string[] | null> {
  const full = K.scalarAdd(K.fromHex(s.makerSpend), otherSecret);
  const want = K.pointAdd(K.fromHex(s.makerSpendPub), K.fromHex(s.takerSpendPub));
  if (!K.equalBytes(K.pub(full), want)) throw new Error('secret does not complete the shared key');
  const mainAddr = (await main.call('get_address', { account_index: 0 })).address;
  return swapW.exclusive(async () => {
    // Full escrow address in the name (a prefix can be ground to collide) + the opened wallet must be this swap's.
    const filename = `sweep-${s.escrow}`;
    try { await swapW.call('open_wallet', { filename, password: '' }); }
    catch {
      await swapW.call('generate_from_keys', { filename, address: s.sharedAddress, spendkey: K.toHex(full), viewkey: s.viewSecret, password: '', restore_height: s.restoreHeight, autosave_current: true });
    }
    try {
      if ((await swapW.call('get_address', { account_index: 0 })).address !== s.sharedAddress) throw new Error(`wallet ${filename} is not this swap's shared wallet`);
      await swapW.call('refresh', {});
      const bal = await swapW.call('get_balance', { account_index: 0 });
      if (BigInt(bal.unlocked_balance) === 0n) {
        s.lastError = BigInt(bal.balance) > 0n ? 'shared output not yet spendable' : 'nothing to sweep yet';
        return null;
      }
      const r = await swapW.call('sweep_all', { address: mainAddr, account_index: 0, priority: 0 });
      return r.tx_hash_list as string[];
    } finally {
      await swapW.call('close_wallet', {}).catch(() => {});
    }
  });
}

/** XMR->SOL: has the user's deposit landed (>= minConf, exact amount, no time lock)? */
async function depositOk(s: Swap): Promise<boolean> {
  const spendPub = K.pointAdd(K.fromHex(s.makerSpendPub), K.fromHex(s.takerSpendPub));
  // "Seen" is what's true now, not what was once true: a pool transaction can vanish (a conflicting spend mines),
  // and it must not keep a swap out of the caps and the abort rule. Every path below sets it.
  if (s.depositTx) {
    // A hint is an unsigned claim from anyone: it can speed things up, never stand in the way of the scan below.
    try {
      const v = await verifyLock({ daemonUri: cfg.daemonUri, txHash: s.depositTx, spendPub, viewSecret: K.fromHex(s.viewSecret), minAmount: BigInt(s.xmrAmount), minConf: cfg.minConf });
      const pays = v.amount !== undefined && v.amount >= BigInt(s.xmrAmount) && v.unlockTime === 0;
      if (pays) s.depositSeen = true;
      if (v.ok) { if (s.paidTx !== s.depositTx) record(s.escrow, 'deposit-paid', { txHash: s.depositTx }); return true; }
      if (pays) return false; // this one pays us: only its confirmations are missing
    } catch { /* unknown tx or node hiccup: the scan decides */ }
  }
  // No (valid) hint: scan with a view-only wallet.
  return swapW.exclusive(async () => {
    const filename = `view-${s.escrow}`;
    try { await swapW.call('open_wallet', { filename, password: '' }); }
    catch { await swapW.call('generate_from_keys', { filename, address: s.sharedAddress, viewkey: s.viewSecret, password: '', restore_height: s.restoreHeight, autosave_current: true }); }
    try {
      if ((await swapW.call('get_address', { account_index: 0 })).address !== s.sharedAddress) throw new Error(`wallet ${filename} is not this swap's shared wallet`);
      await swapW.call('refresh', {});
      // A wallet or node that's behind reads as "no payment", and an abort on that kills a paid swap: unknown, so throw.
      const [wh, info] = await Promise.all([swapW.call('get_height', {}), daemon(cfg.daemonUri, 'json_rpc', { jsonrpc: '2.0', id: 0, method: 'get_info' }).then((r: any) => r.result)]);
      if (info?.synchronized === false) throw new Error('monerod is not synced');
      if (Number(wh?.height) < Number(info?.height) - 2) throw new Error(`the wallet is at block ${wh?.height}, monerod at ${info?.height}`);
      const t = await swapW.call('get_transfers', { in: true, pool: true });
      let sum = 0n, seen = 0n;
      for (const x of [...(t.in ?? []), ...(t.pool ?? [])]) if (x.unlock_time === 0) { seen += BigInt(x.amount); if (BigInt(x.amount) >= BigInt(s.xmrAmount)) s.seenTx = x.txid; }
      s.depositSeen = seen >= BigInt(s.xmrAmount);
      s.seenAmount = seen;
      for (const x of t.in ?? []) if (x.unlock_time === 0 && x.confirmations >= cfg.minConf) {
        sum += BigInt(x.amount);
        // One output that pays in full is what a proof can show. Dust from anyone can't take this place.
        if (BigInt(x.amount) >= BigInt(s.xmrAmount) && s.paidTx !== x.txid) record(s.escrow, 'deposit-paid', { txHash: x.txid });
      }
      return sum >= BigInt(s.xmrAmount);
    } finally {
      await swapW.call('close_wallet', {}).catch(() => {});
    }
  });
}

// ---------------------------------------------------------------- escrow gone
/** XMR->SOL, we are the locker: take the account's rent back. A failure costs only the rent. */
async function closeOwn(s: Swap): Promise<boolean> {
  try { await sendIxs(conn, me, [P.ixClose(pid, me.publicKey, new PublicKey(s.escrow))]); return true; }
  catch (e) { log(`swap ${s.escrow.slice(0, 8)} rent not reclaimed: ${describeErr(e)}`); return false; }
}
/** Did anything at all reach this swap's shared address? Throws if it can't tell. */
async function anyIncoming(s: Swap): Promise<boolean> {
  return swapW.exclusive(async () => {
    const filename = `view-${s.escrow}`;
    try { await swapW.call('open_wallet', { filename, password: '' }); }
    catch { await swapW.call('generate_from_keys', { filename, address: s.sharedAddress, viewkey: s.viewSecret, password: '', restore_height: s.restoreHeight, autosave_current: true }); }
    try {
      if ((await swapW.call('get_address', { account_index: 0 })).address !== s.sharedAddress) throw new Error('wrong swap wallet');
      await swapW.call('refresh', {});
      const t = await swapW.call('get_transfers', { in: true, pool: true });
      return (t.in?.length ?? 0) + (t.pool?.length ?? 0) > 0;
    } finally { await swapW.call('close_wallet', {}).catch(() => {}); }
  });
}

/**
 * SOL->XMR: an escrow we saw has no account any more. A locker may refund and close in one transaction, so
 * that is normal, and the key half that returns our XMR is then only in history. One empty read is
 * never proof (RPC lag): this needs several in a row, and a swap with XMR out only ends when the XMR is back.
 */
async function escrowGone(s: Swap, now: number) {
  s.goneReads = (s.goneReads ?? 0) + 1;
  if (s.goneReads < 3) return;
  const spend = K.fromHex(s.makerSpend);
  if (s.claimSig) { record(s.escrow, 'done', { why: 'claimed' }); return; }
  if (!s.xmrTxHash) { record(s.escrow, 'done', { why: 'cancelled-no-xmr' }); return; }
  if (!s.otherSecret) {
    if ((s.scanAgainAt ?? 0) > now) return;
    const r = await scanEscrowHistory(conn, pid, new PublicKey(s.escrow), pickSettlement(K.fromHex(s.takerSpendPub), spend), s.scanCursor);
    s.scanCursor = r.done ? undefined : r.cursor;
    if (r.found?.kind === 'claim') { record(s.escrow, 'done', { why: 'claimed' }); return; }
    if (!r.found) {
      if (r.done) s.scanAgainAt = now + 300; // read to the start: look again later
      s.lastError = 'escrow closed; its refund is not in the history read so far';
      if (r.done) log(`!! swap ${s.escrow.slice(0, 8)}: escrow closed after our XMR lock ${s.xmrTxHash}, no refund found in its history. Checking again.`);
      return;
    }
    record(s.escrow, 'other-secret', { secret: K.toHex(r.found.secret) });
  }
  if (s.xmrRelayed && !s.walkedAt && !s.abortSig) {
    record(s.escrow, 'taker-walked', { at: now });
    log(`swap ${s.escrow.slice(0, 8)} taker ${s.taker.slice(0, 8)} cancelled after our XMR lock: wallet refused for ${WALK_REFUSE_SECS / 3600} h`);
  }
  const txs = await sweepShared(s, K.fromHex(s.otherSecret!));
  if (txs) { record(s.escrow, 'swept', { txHashes: txs }); record(s.escrow, 'done', { why: 'refunded-xmr-recovered' }); log(`swap ${s.escrow.slice(0, 8)} XMR recovered ${txs[0]}`); }
}

// ---------------------------------------------------------------- the state machine
async function step(s: Swap) {
  const e = await loadEscrow(s.escrow);
  const now = await chainNow(conn);
  const escrowPk = new PublicKey(s.escrow);

  if (s.direction === 1) {
    if (!e) {
      // No lock was ever seen and no XMR left us: nothing of ours is at stake.
      if (!s.verified && !s.xmrTxHash) {
        if (now > s.consentExpiry + 120) record(s.escrow, 'done', { why: 'never-locked' });
        return;
      }
      await escrowGone(s, now);
      return;
    }
    s.goneReads = 0;
    if (!s.verified) {
      // Every field must match what we consented to (the program bound them; belt and braces).
      const okFields = e.direction === 1 && e.claimer.equals(me.publicKey) && e.locker.toBase58() === s.taker &&
        K.toHex(e.claimPoint) === s.makerSpendPub && K.toHex(e.refundPoint) === s.takerSpendPub &&
        K.equalBytes(e.viewPub, K.pub(K.fromHex(s.viewSecret))) && e.xmrAmount === BigInt(s.xmrAmount) && e.amount === BigInt(s.lamports) &&
        e.flags === (s.flags ?? 0) && (!s.link || e.link.toBase58() === s.link);
      if (!okFields) { record(s.escrow, 'done', { why: 'mismatch' }); return; }
      record(s.escrow, 'verified', { seenAt: now });
    }
    if (e.state === P.ST.CLAIMED) { record(s.escrow, 'done', { why: 'claimed' }); return; }

    if ((e.state === P.ST.LOCKED || e.state === P.ST.READY) && now < Number(e.t1)) {
      if (!s.xmrRelayed) {
        const lateMargin = (s.flags ?? 0) & P.F.PAY ? (cfg.payLateSecs ?? 1500) : 60;
        // A pay escrow can only be claimed with a proof (no ready, and its refund hands nothing
        // back): never send XMR without time left to prove it before t1.
        const proofLate = ((s.flags ?? 0) & P.F.PAY) !== 0 && now + (cfg.payProofSecs ?? 3600) + cfg.claimMarginSecs >= Number(e.t1);
        const late = now > (s.escrowSeenAt ?? now) + cfg.lockDeadlineSecs || now >= Number(e.t0) - lateMargin || proofLate;
        if (late || FAULT === 'no-xmr-lock') {
          if (late && !s.abortSig && !s.xmrTxHash) {
            // Too late to lock safely: give up our claim so the user is refunded at once.
            const sig = await sendIxs(conn, me, [P.ixAbort(pid, me.publicKey, escrowPk, me.publicKey)]);
            record(s.escrow, 'abort-sent', { sig });
          }
          if (!s.xmrTxHash) return;
        }
        const fin = await loadEscrow(s.escrow, 'finalized'); // lock XMR only on a finalized SOL lock
        if (!fin) return;
        if (s.group) await lockXmrGroup(s); else await lockXmr(s);
        return;
      }
      // v1.5: every SOL->XMR claim without the user's ready needs the payment proven on chain
      const proofMode = e.state === P.ST.LOCKED;
      if (proofMode && !P.allowsPaymentProof(e)) return;
      if (proofMode && !s.proofPda) await proveLock(s, e);
      const claimable = e.state === P.ST.READY || now >= Number(e.t0);
      if (claimable) {
        if (now >= Number(e.t1) - cfg.claimMarginSecs) { s.lastError = 'past claim margin: not revealing'; return; }
        if (proofMode && !s.proofPda) return; // no claim without the on-chain payment proof
        crashPoint('before-claim');
        const sig = await sendIxs(conn, me, [P.ixClaim(pid, me.publicKey, escrowPk, me.publicKey, K.fromHex(s.makerSpend), proofMode ? new PublicKey(s.proofPda!) : undefined)]);
        record(s.escrow, 'claim-sent', { sig });
        log(`swap ${s.escrow.slice(0, 8)} claimed (${e.state === P.ST.READY ? 'after ready' : 'auto at t0'}) ${sig.slice(0, 12)}`);
      }
      return;
    }
    // The taker cancelled after we paid: refuse that wallet for a day (free-option grief; policy.ts).
    if (s.xmrRelayed && !s.abortSig && !s.walkedAt && (e.state === P.ST.ABORTED || e.state === P.ST.REFUNDED) && !((s.flags ?? 0) & P.F.PAY)) {
      record(s.escrow, 'taker-walked', { at: now });
      log(`swap ${s.escrow.slice(0, 8)} taker ${s.taker.slice(0, 8)} cancelled after our XMR lock: wallet refused for ${WALK_REFUSE_SECS / 3600} h`);
    }
    // Aborted / expired / refunded: if we locked XMR, take it back once the user's half is public.
    if (!s.xmrTxHash) { if (e.state === P.ST.ABORTED || e.state === P.ST.REFUNDED || now >= Number(e.t1)) record(s.escrow, 'done', { why: 'cancelled-no-xmr' }); return; }
    if (e.state === P.ST.REFUNDED && (s.flags ?? 0) & P.F.PAY) {
      // Pay mode: the refund revealed nothing (the payer never had the recipient's key), so the
      // XMR we locked cannot come back. Only a watchtower abort of a delivered swap gets here.
      record(s.escrow, 'done', { why: 'pay-refunded-xmr-stranded' });
      log(`!! swap ${s.escrow.slice(0, 8)} pay escrow refunded after our XMR lock ${s.xmrTxHash}: XMR stranded (watchtower abort)`);
      return;
    }
    if (e.state === P.ST.REFUNDED) {
      if (!s.otherSecret) record(s.escrow, 'other-secret', { secret: K.toHex(e.secret) });
      const txs = await sweepShared(s, K.fromHex(s.otherSecret!));
      if (txs) { record(s.escrow, 'swept', { txHashes: txs }); record(s.escrow, 'done', { why: 'refunded-xmr-recovered' }); log(`swap ${s.escrow.slice(0, 8)} XMR recovered ${txs[0]}`); }
    }
    return; // aborted but the user has not refunded yet: nothing we can do but wait (no deadline)
  }

  // ---- XMR -> SOL (we are the locker)
  if (!e) { if (!s.solLockSig && now > s.createdAt + 300) record(s.escrow, 'done', { why: 'lock-failed' }); return; }
  if (e.state === P.ST.LOCKED) {
    if (now < Number(e.t0)) {
      // An unreadable deposit is unknown, not absent. Aborting on it would refund a swap the user may have paid;
      // proof mode means waiting costs us nothing: past t0 the user still has to prove a real deposit.
      const seenBefore = s.depositSeen;
      let deposited: boolean;
      try { deposited = await depositOk(s); }
      catch (err) { s.lastError = `deposit check: ${describeErr(err)}`; log(`swap ${s.escrow.slice(0, 8)} deposit check failed, not aborting: ${s.lastError}`); return; }
      if (s.depositSeen && !seenBefore && !s.depositEver) record(s.escrow, 'deposit-seen'); // survives a restart: it decides the rent below
      if (s.depositSeen) { s.lastSeenAt = now; s.unseenReads = 0; } else s.unseenReads = (s.unseenReads ?? 0) + 1;
      if (deposited) {
        const sig = await sendIxs(conn, me, [P.ixReady(pid, me.publicKey, escrowPk)]);
        record(s.escrow, 'ready-sent', { sig });
        log(`swap ${s.escrow.slice(0, 8)} deposit confirmed, ready ${sig.slice(0, 12)}`);
      } else {
        // Same rule the client shows the user (sdk/taker.ts depositDeadline / makerAbortTimes).
        const at = T.makerAbortTimes(Number(e.createdAt), Number(e.t0), terms());
        // A paying user whose confirmations run late isn't aborted: proof mode means waiting costs us nothing, and past
        // t0 we post the proof of its deposit ourselves (proveDeposit below).
        // "Not seen" must hold over several reads, and for a while after it was last seen: a block landing between the
        // wallet's refresh and its pool read hides a transaction for one read. Never call a payment gone on one read.
        const settledUnseen = (s.unseenReads ?? 0) >= 3 && now - (s.lastSeenAt ?? 0) >= 600;
        const why = s.depositSeen || !settledUnseen ? '' : now >= at.unconfirmedAt ? 'deposit not confirmed by the deadline' : now >= at.noShowAt ? 'no deposit seen in the deposit window' : '';
        if (why) {
          const sig = await sendIxs(conn, me, [P.ixAbort(pid, me.publicKey, escrowPk, me.publicKey)]);
          record(s.escrow, 'abort-sent', { sig });
          if (!s.depositSeen) record(s.escrow, 'no-show', { at: now });
          log(`swap ${s.escrow.slice(0, 8)} ${why}: aborted`);
        }
      }
      return;
    }
  }
  // Proof mode, past t0: a late ready isn't possible. If a real deposit is there (seen before, or found now, after an
  // outage), we put its proof on chain and the user claims with no SOL of its own. It can also do this itself.
  // Late finish: a deposit that confirmed after t0 still gets our ready, until t1 - 30 min (the program's margin).
  if (cfg.lateFinish && e.state === P.ST.LOCKED && now >= Number(e.t0) && now < Math.max(Number(e.t0), Number(e.t1) - LATE_READY_MARGIN)) {
    let deposited = false;
    try { deposited = await depositOk(s); } catch (err) { s.lastError = `deposit check: ${describeErr(err)}`; return; }
    if (deposited) {
      const sig = await sendIxs(conn, me, [P.ixReady(pid, me.publicKey, escrowPk)]);
      record(s.escrow, 'ready-sent', { sig });
      log(`swap ${s.escrow.slice(0, 8)} deposit confirmed late, ready ${sig.slice(0, 12)}`);
    }
    return;
  }
  // With refund towers there is no committee: no proof can exist, and an unready lock simply refunds at t1.
  if (!cfg.refundTowers && e.state === P.ST.LOCKED && now >= Number(e.t0) && now < Number(e.t1) && (e.flags & P.F.PROOF) && !s.proofPda) {
    await proveDeposit(s, e);
    if (now < Number(e.t1)) return;
  }
  if ((e.state === P.ST.LOCKED || e.state === P.ST.READY) && now >= Number(e.t1)) {
    const sig = await sendIxs(conn, me, [P.ixRefund(pid, me.publicKey, escrowPk, me.publicKey, me.publicKey, K.fromHex(s.makerSpend))]);
    record(s.escrow, 'refund-sent', { sig });
    if (!s.noShowAt) record(s.escrow, 'no-show', { at: now }); // parked our SOL to the very end and never claimed
    return;
  }
  if (e.state === P.ST.ABORTED) {
    const sig = await sendIxs(conn, me, [P.ixRefund(pid, me.publicKey, escrowPk, me.publicKey, me.publicKey, K.fromHex(s.makerSpend))]);
    record(s.escrow, 'refund-sent', { sig }); return;
  }
  if (e.state === P.ST.REFUNDED) {
    // The account holds the key half a user needs to sweep a late XMR deposit back, and the page reads it there. Never
    // close one where a deposit was seen; otherwise only after a day, for the rent griefed no-shows would leave behind.
    if (!s.depositEver) record(s.escrow, 'close-after', { at: now + 86_400 });
    record(s.escrow, 'done', { why: 'refunded-sol' });
    return;
  }
  if (e.state === P.ST.CLAIMED) {
    if (!s.otherSecret) record(s.escrow, 'other-secret', { secret: K.toHex(e.secret) });
    const txs = await sweepShared(s, K.fromHex(s.otherSecret!));
    if (txs) { record(s.escrow, 'swept', { txHashes: txs }); record(s.escrow, 'close-after', { at: now + 86_400 }); record(s.escrow, 'done', { why: 'completed-xmr-swept' }); log(`swap ${s.escrow.slice(0, 8)} user claimed; XMR swept ${txs[0]}`); }
  }
}

// ---------------------------------------------------------------- loop + server
const busy = new Set<string>();
async function tick() {
  await refreshChain().catch((e) => log('chain refresh', describeErr(e)));
  if (!lastInv || Date.now() - lastInv.at > 30_000) inventoryNow().catch(() => {}); // for /v1/info spreadNow
  for (const s of swaps.values()) {
    if (s.done || busy.has(s.escrow)) continue;
    busy.add(s.escrow);
    step(s)
      .catch((e) => { s.lastError = describeErr(e); log(`swap ${s.escrow.slice(0, 8)} step error: ${s.lastError}`); })
      .finally(() => busy.delete(s.escrow));
  }
}

// Indicative rate in the registry entry: clients that cannot reach any endpoint (or run without any
// HALFKEY server) still see a posted rate. Firm quotes always come from a live endpoint.
async function publishRate() {
  // Re-read the account first: update_maker with a stale view would undo an operator's pause,
  // range change or pending unbond (active = 1 clears withdraw_after on chain).
  const a = await conn.getAccountInfo(P.pda.maker(pid, me.publicKey), 'confirmed');
  if (!a) return;
  const m = P.decodeMaker(a.data);
  if (!m.active || m.withdrawAfter !== 0n) return;
  if (!priceNow.ok) return; // never post a frozen rate
  makerAcct = m;
  const endpoint = formatEndpointField({ endpoints: [cfg.endpoint, ...(cfg.endpoints ?? [])], px: xmrPerSol, ts: Math.floor(Date.now() / 1000) });
  await sendIxs(conn, me, [P.ixUpdateMaker(pid, me.publicKey, 0n, { min: makerAcct.min, max: makerAcct.max, directions: makerAcct.directions, spreadBps: makerAcct.spreadBps, endpoint }, makerAcct.active)]);
}

replay();
await refreshChain();
const zecDesk = cfg.zec ? new ZecDesk({ cfg: { ...cfg.zec, pythApiKeyFile: cfg.zec.pythApiKeyFile ?? cfg.pythApiKeyFile }, conn, me, pid, feeBps: () => feeBpsNow, maker: () => makerAcct, screen }) : null;
if (zecDesk) { await zecDesk.init(); setInterval(() => { zecDesk.tick().catch((e) => log('zec tick', describeErr(e))); }, cfg.pollMs); }
if (cfg.priority?.auto !== false && (cfg.priority || cfg.cluster === 'mainnet-beta')) setPriority(conn, cfg.priority);
else if (cfg.priority?.microLamports) setPriority(conn, cfg.priority);
await refreshPrice();
setInterval(() => { refreshPrice().catch((e) => log('price', describeErr(e))); }, 15_000);
setInterval(() => { // the list is a file the refresh tool rewrites: reload it, and say when it gets old
  try { screen.set(loadList(cfg.sanctionsFile)); } catch (e) { log(`!! sanctions list unreadable, keeping the last one: ${describeErr(e)}`); }
  if (screen.ageDays() > 14) log(`!! sanctions list is ${screen.ageDays().toFixed(0)} days old: run node maker/sanctions.ts --refresh`);
}, 3_600_000).unref();
// Auto-refill of the maker's OWN inventory through an external exchanger (opt-in; maker/refill.ts).
// Never touches a user swap. Mainnet only (exchangers only move real coins) and only on a live price.
if (cfg.refill?.enabled) {
  if (cfg.cluster !== 'mainnet-beta' || cfg.moneroNet !== 'mainnet' || !cfg.livePrice) log('refill: disabled (needs mainnet-beta, Monero mainnet and livePrice)');
  else {
    const key = cfg.refill.apiKeyFile ? fs.readFileSync(cfg.refill.apiKeyFile, 'utf8').trim() : '';
    refiller = new Refiller({
      cfg: cfg.refill, target: skewConfig(cfg.skew).target, coin: 'XMR', coinDecimals: 12, defaultDir: path.dirname(cfg.journal), log,
      exchanger: makeExchanger(cfg.refill.route ?? 'trocador', key, cfg.refill.routeOptions),
      wallets: xmrRefillWallets({ main, conn, me, reserved: xmrReserved, mid: () => ({ coinPerSol: xmrPerSol, at: priceAt }) }),
    });
    const p = refiller.paused();
    log(`refill: on via ${cfg.refill.route ?? 'trocador'}, receipts ${refiller.journalFile}${p ? `; PAUSED: ${p}` : ''}`);
    setInterval(() => { refiller!.tick().catch((e) => log('refill', describeErr(e))); }, 60_000);
  }
}
setInterval(() => { tick().catch(() => {}); }, cfg.pollMs);
setInterval(() => { // a slow, cheap sweep of rent from refunded no-shows
  (async () => {
    const now = await chainNow(conn);
    for (const s of swaps.values()) {
      if (!s.closeAfter || s.closeAfter > now) continue;
      // A refunded swap: the account holds the half a late depositor needs. Any incoming payment, or no answer, keeps it (rent is 0.004 SOL).
      const claimed = (await loadEscrow(s.escrow))?.state === P.ST.CLAIMED;
      if (!claimed) {
        let incoming = true;
        try { incoming = await anyIncoming(s); } catch (e) { log(`swap ${s.escrow.slice(0, 8)} rent sweep: can't read its wallet, will retry: ${describeErr(e)}`); continue; }
        if (incoming) { record(s.escrow, 'closed'); log(`swap ${s.escrow.slice(0, 8)} a payment reached this swap: its account stays`); continue; }
      }
      if (await closeOwn(s)) record(s.escrow, 'closed');
    }
  })().catch((e) => log('rent sweep', describeErr(e)));
}, (cfg as { rentSweepMs?: number }).rentSweepMs ?? 600_000).unref();
if ((cfg.publishRateSecs ?? 0) > 0) setInterval(() => { publishRate().catch((e) => log('publish rate', describeErr(e))); }, cfg.publishRateSecs! * 1000);

http.createServer(async (req, res) => {
  res.setHeader('access-control-allow-origin', '*');
  res.setHeader('access-control-allow-headers', 'content-type');
  res.setHeader('access-control-allow-methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') { res.writeHead(204).end(); return; }
  try {
    const out = await handle(req);
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(out));
  } catch (e) {
    const code = e instanceof HttpError ? e.code : 500;
    res.writeHead(code, { 'content-type': 'application/json' }).end(JSON.stringify({ error: e instanceof HttpError ? e.message : describeErr(e) }));
  }
}).listen(cfg.port, (cfg as any).bind ?? '127.0.0.1', () => log(`maker ${me.publicKey.toBase58()} on :${cfg.port} (${cfg.cluster}, ${cfg.moneroNet}) rate ${xmrPerSol.toFixed(5)} XMR/SOL`));
