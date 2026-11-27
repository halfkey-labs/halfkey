// HALFKEY maker: the ZEC leg (SOL <-> transparent ZEC HTLC swaps). Runs inside maker/daemon.ts
// (config `zec`) or alone (maker/zec-daemon.ts). Talks to zebrad JSON-RPC; holds a transparent
// hot wallet (P2PKH UTXOs) and derives every per-swap key from one seed, so the journal plus the
// seed reconstruct every swap after a crash.
//
// SOL -> ZEC (4): we hold x. On request we fund P2SH(HTLC(H, claim=user, refund=us, L)) at once
//   and sign the lock consent (expiry = now + consentSecs). Once the user's SOL lock is FINALIZED
//   (a rolled-back lock must never see x) we claim it with x, unless it is within claimMarginSecs
//   of t1. We refund the ZEC from height L only if we never claimed the SOL.
// ZEC -> SOL (8): the user holds x. We answer with our claim key and L. Once the deposit has
//   minConf confirmations (and L is still safely after the t1 we would set) we lock SOL with the
//   user as claimer. When the user claims (x published on Solana) we claim the ZEC. After t1 with
//   no claim we refund our SOL (permissionless; it can only pay us, the locker).
import fs from 'node:fs';
import type http from 'node:http';
import { Connection, Keypair, PublicKey, Transaction, ComputeBudgetProgram } from '@solana/web3.js';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes, bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils';
import { secp256k1 } from '@noble/curves/secp256k1';
import { ed25519 } from '@noble/curves/ed25519';
import * as Z from '../sdk/zec.ts';
import * as H from '../sdk/htlc.ts';
import * as S from '../sdk/zecswap.ts';
import * as P from '../sdk/program.ts';
import { Journal, chainNow, sendIxs, describeErr, log, priorityPrice } from './lib.ts';
import { skew, pausedMsg, type SkewConfig, type Inventory } from './inventory.ts';
import { PriceFeed, type PriceState } from './price.ts';
import { Screen, loadList } from './sanctions.ts';
import { RateWindow, clientIp, noShowRefusal } from './policy.ts';
import * as J from '../sdk/jupiter.ts';
import { waitForTx } from '../sdk/confirm.ts';

export interface ZecConfig {
  zebraRpc: string;
  /** user:password for zebrad's RPC, if cookie/basic auth is on. Never logged. */
  zebraAuth?: string;
  zecNet: Z.ZecNet;
  /** File holding a 32-byte hex seed: hot wallet key and every per-swap key derive from it. */
  seedFile: string;
  journal: string;
  directions: number;           // subset of 4 | 8
  zatPerSol: number;            // the mid on test networks; on a live price only the starting value for the display
  /** Price from the feed (SOL/ZEC, maker/price.ts): no fresh price, no quote. Default: on for ZEC mainnet, which refuses to start with it off. */
  livePrice?: boolean;
  pythApiKeyFile?: string;
  /** Sanctions list (maker/sanctions.ts). Default: the file in this kit. */
  sanctionsFile?: string;
  /** Requests per client address per minute. Defaults 120 / 20 / 60, as the XMR maker. */
  rateLimits?: { quotePerMin?: number; swapPerMin?: number; postPerMin?: number };
  spreadBps: number;
  t1Secs: number;               // Solana deadline offset for both directions
  minConf: number;
  marginSecs: number;           // gap between t1 and the ZEC refund height (wall clock)
  speed?: number;               // count only this share of the target block time (default 0.75)
  consentSecs: number;          // SOL->ZEC: the user must lock by funding + this
  payWindowSecs: number;        // ZEC->SOL: deposit window
  claimMarginSecs: number;      // never claim SOL this close to t1
  marginalFee?: string;         // ZIP 317 marginal fee, zatoshis (default 5000)
  quoteTtlSecs?: number;
  /**
   * SOL->ZEC admission (we lock ZEC first, so an offer the user never takes holds our ZEC until L):
   * funded-but-unlocked offers per taker wallet, per client IP, and in total (zatoshis). The taker
   * must also sign the request and hold the SOL it is about to lock. perIpZats is one address's share
   * of the budget. Defaults: 1, 3, 20 ZEC, half of the budget.
   */
  s2zLimits?: { perTaker: number; perIp: number; unlockedZats: string; perIpZats?: string };
  /** ZEC->SOL offers waiting for a deposit: total, per IP, per wallet. Defaults 50 / 5 / 2. */
  offerLimits?: { total: number; perIp: number; perTaker?: number };
  /** A full offer table gives up an unpaid offer once it is this old (seconds, default 60), oldest first. */
  offerMinAgeSecs?: number;
  /** Evicted offers kept scanning at once (default 2000); past this the oldest close, after a scan. */
  maxEvictedOffers?: number;
  /** Jupiter base URL and key, for valuing a coin payer's coin. Default: Jupiter's public API. */
  jupiterApi?: string;
  jupiterKey?: string;
  /** Inventory skew between ZEC and SOL (maker/inventory.ts), on by default. */
  skew?: SkewConfig;
}

type Phase =
  | 'offered'        // 8: waiting for the deposit
  | 'funded'         // 4: our HTLC is out, waiting for the user's SOL lock
  | 'sol-locked'     // 8: our SOL is locked for the user
  | 'sol-claimed'    // 4: we claimed the SOL (x public): done for us
  | 'zec-claimed'    // 8: we claimed the user's ZEC: done
  | 'refunding-zec'  // 4: no SOL claim will happen: refund our ZEC from L
  | 'done';

export interface ZSwap {
  swapId: string;
  direction: 4 | 8;
  taker: string;
  lamports: string;
  zats: string;
  feeBps: number;
  quoteHash: string;
  hashlock: string;
  redeem: string;
  lockHeight: number;
  escrow: string;
  phase: Phase;
  createdAt: number;
  consentExpiry?: number;
  payBy?: number;
  fundTxid?: string;
  fundVout?: number;
  depositHints?: { txid: string; vout: number }[];
  solSig?: string;
  zecTxid?: string;
  why?: string;
  lastError?: string;
  /** Random per-swap salt (journaled before funding): x and our per-swap keys derive from (seed, swapId, salt). */
  salt?: string;
  ip?: string;
  /** SOL->ZEC: the user's lock was seen (the offer no longer counts against the admission caps). */
  lockSeen?: boolean;
  /** SOL->ZEC: the offer ran out with no lock while our ZEC sat in it (that wallet waits, policy.ts noShowRefusal). */
  noShowAt?: number;
  /** SOL->ZEC, not journaled: empty reads of the lock in a row past its deadline. */
  noLockReads?: number;
  /** SOL->ZEC: the funding was found after an unknown send; the user never got this offer, so no lock is no no-show. */
  neverOffered?: boolean;
  /** The signed quote, for status and for the wallet's own list (another device rebuilds the swap from it). */
  quote?: S.ZecQuote;
  quoteSig?: string;
  /** ZEC->SOL: gave up its place in a full table, unpaid. Still honoured if paid, just scanned less often (journaled). */
  evictedAt?: number;
  /** ZEC->SOL, not journaled: a scan showed a full deposit. */
  depositSeen?: boolean;
  /** ZEC->SOL: closed with money at its address. Never pruned: the script is what the user's refund needs. */
  paid?: boolean;
  /** SOL->ZEC: last claim tx sent, valid until this block height (never abort before it expires). */
  claimLvbh?: number;
  /** Public preimage (ZEC->SOL claim rebroadcasts). */
  x?: string;
}

const now = () => Math.floor(Date.now() / 1000);
/** Maker ZEC keys from the seed: 'hot' (inventory wallet), per swap 'refund' (SOL->ZEC) and 'claim' (ZEC->SOL). */
export const deriveMakerKey = (seed: Uint8Array, role: 'hot' | 'refund' | 'claim', swapId = '') =>
  Z.privFrom(concatBytes(seed, utf8ToBytes(`halfkey-maker-zec/${role}/v1/${swapId}`)));
/** Tests only: HALFKEY_ZEC_FAULT=no-sol-claim makes the maker never claim a SOL->ZEC lock (refund-path test). */
const FAULT = process.env.HALFKEY_ZEC_FAULT ?? '';
export class HttpError extends Error { code: number; constructor(code: number, msg: string) { super(msg); this.code = code; } }
const bad = (m: string) => new HttpError(400, m);
/** A wallet paying with a coin needs at least this much SOL: the HTLC record's rent (the page asks for that plus the fee). */
const COIN_PAYER_MIN_LAMPORTS = 2_000_000n;
/** ZEC per SOL outside this range is a broken source, not a market. */
const RATE_BOUNDS = [0.001, 1000];
/** A coin payer's route must still cover this share of the lock (the page quoted the route's minimum moments ago). */
const COIN_COVER_PCT = 90n;
/** A funding send of unknown fate is looked for this many blocks past its lock height (it has no expiry, so it could mine late). */
const UNKNOWN_SEND_BLOCKS = 100;
/** Empty reads in a row before a user's lock counts as never coming: one is never proof (RPC lag). */
const NO_LOCK_READS = 3;
/** Inputs of a send whose fate is unknown stay out of new payments this long (ms); leaving the UTXO set frees them sooner. */
const RESERVE_MS = 30 * 60_000;
/** An evicted offer's scan: this many per tick, in turn, so a flood of them can't slow the swaps that are real. */
const EVICTED_SCANS_PER_TICK = 10;
/** Evicted offers kept scanning at once; past this the oldest close. Its payer still has the refund, which needs nothing from us. */
const MAX_EVICTED = 2000;
/** How many of them may close per tick (each needs a scan). */
const EVICT_CLOSES_PER_TICK = 10;
/** A request facing a full table scans at most this many of the oldest offers for one to evict. */
const EVICT_SCANS_PER_REQUEST = 3;
/** A closed, never-paid offer is forgotten this long after its refund height: until then its wallet can still ask for the script. */
const PRUNE_AFTER_REFUND_SECS = 86_400;
/** Each prune pass scans this many before forgetting them (one minute apart: well above any offer flood the rate limits let in). */
const PRUNE_SCANS_PER_PASS = 200;
/** The journal is rewritten without forgotten offers once this many are waiting, or at the latest hourly. */
const COMPACT_AFTER = 1000;
/** A signed list request is good this long either way (seconds), and once. */
const LIST_WINDOW_SECS = 120;
/** Nothing went out: the swap can be closed. Any other failure of a payment leaves its fate unknown. */
export class NotSent extends Error {}

/** A transparent P2PKH wallet over zebrad's address index. Reserves inputs until they leave the UTXO set. */
export class ZecWallet {
  readonly pub: Uint8Array;
  readonly script: Uint8Array;
  readonly address: string;
  private reserved = new Map<string, number>();
  private call: Z.Rpc;
  private priv: Uint8Array;
  private marginal: bigint;
  /** Only spend UTXOs this accepts (e.g. mature coinbase outputs on regtest). */
  filter: (u: { height: number }) => boolean = () => true;
  constructor(call: Z.Rpc, priv: Uint8Array, net: Z.ZecNet, marginal = 5000n) {
    this.call = call; this.priv = priv; this.marginal = marginal;
    this.pub = Z.pubOf(priv);
    this.script = Z.p2pkh(this.pub);
    this.address = Z.pubAddress(net, this.pub);
  }
  async utxos(): Promise<{ txid: string; vout: number; value: bigint; height: number }[]> {
    const r = await this.call('getaddressutxos', [{ addresses: [this.address] }]);
    const list = (Array.isArray(r) ? r : r?.utxos ?? []).map((u: any) => ({ txid: String(u.txid), vout: Number(u.outputIndex ?? u.index), value: BigInt(u.satoshis), height: Number(u.height ?? 0) }));
    const live = new Set(list.map((u: any) => `${u.txid}:${u.vout}`));
    for (const [k, at] of this.reserved) if (!live.has(k) || Date.now() - at > RESERVE_MS) this.reserved.delete(k);
    return list.filter((u: any) => !this.reserved.has(`${u.txid}:${u.vout}`) && this.filter(u));
  }
  async balance() { return (await this.utxos()).reduce((n, u) => n + u.value, 0n); }
  /** Pay `outs` (plus change back here); returns the txid. The branch is the one of the next block. */
  async pay(outs: Z.TxOut[], branch: number): Promise<{ txid: string; tx: Z.Tx }> {
    const all = (await this.utxos()).sort((a, b) => (a.value > b.value ? -1 : 1));
    const want = outs.reduce((n, o) => n + o.value, 0n);
    const vin: Z.TxIn[] = [], prev: Z.Prevout[] = [];
    let have = 0n;
    const mk = (change: bigint): Z.Tx => ({ branch, lockTime: 0, expiry: 0, vin: vin.map((i) => ({ ...i, scriptSig: Z.scriptSigP2PKH(new Uint8Array(72), this.pub) })), vout: change > 0n ? [...outs, { value: change, script: this.script }] : [...outs] });
    for (const u of all) {
      vin.push({ txid: Z.unhex(u.txid), vout: u.vout, sequence: Z.SEQ_FINAL, scriptSig: new Uint8Array() });
      prev.push({ value: u.value, script: this.script });
      have += u.value;
      const fee = Z.zip317Fee(mk(1n), this.marginal);
      if (have >= want + fee) break;
    }
    let fee = Z.zip317Fee(mk(1n), this.marginal);
    if (have < want + fee) throw new NotSent(`not enough ZEC in the hot wallet (${have} < ${want + fee} zats)`);
    let change = have - want - fee;
    if (change < Z.DUST) { fee += change; change = 0n; }
    const tx = mk(change);
    for (let i = 0; i < tx.vin.length; i++) tx.vin[i].scriptSig = new Uint8Array();
    for (let i = 0; i < tx.vin.length; i++) tx.vin[i].scriptSig = Z.scriptSigP2PKH(Z.sign(Z.sighash(tx, i, prev), this.priv), this.pub);
    for (const i of vin) this.reserved.set(`${Z.hex(i.txid)}:${i.vout}`, Date.now()); // before the send: an error may still mean it went out
    const id = await this.call('sendrawtransaction', [Z.hex(Z.serialize(tx))]);
    if (id !== Z.txid(tx)) throw new Error('node txid differs from ours');
    return { txid: id, tx };
  }
}

export interface DeskDeps {
  cfg: ZecConfig;
  conn: Connection;
  me: Keypair;
  pid: PublicKey;
  /** Effective protocol fee (config + holder discount), refreshed by the host daemon. */
  feeBps: () => number;
  /** The maker account's on-chain min/max/directions. */
  maker: () => P.MakerAccount | null;
  /** The host's sanctions screen, if it reloads one; otherwise the desk loads the list itself. */
  screen?: Screen;
  /** Injected in tests; otherwise a PriceFeed for SOL/ZEC when the live price is on. */
  feed?: Pick<PriceFeed, 'refresh' | 'state' | 'lastError'>;
  /** What `amount` of a coin sells for in lamports now. Injected in tests; otherwise a Jupiter route. */
  coinValue?: (mint: string, amount: bigint, taker: string) => Promise<bigint>;
}

export class ZecDesk {
  readonly call: Z.Rpc;
  readonly policy: S.ZecPolicy;
  wallet!: ZecWallet;
  ups: Z.Upgrade[] = [];
  swaps = new Map<string, ZSwap>();
  private seed: Uint8Array;
  private journal: Journal;
  private usedNonces = new Set<string>();
  /** Swap ids and hashlocks ever used (journal + in-flight requests): never fund or lock twice. */
  private usedIds = new Set<string>();
  /** Pruned offers' hashlocks, freed with their ids once compaction has removed their records. */
  private prunedHashes = new Map<string, string>();
  private usedHashes = new Set<string>();
  private inflight = new Map<string, { direction: number; taker: string; ip: string; zats: bigint }>();
  /** Consecutive "spent" observations per swap (a terminal step needs several). */
  private spentStreak = new Map<string, number>();
  private busy = new Set<string>();
  private zatPerSol: number;
  private d: DeskDeps;
  readonly screen: Screen;
  private feed: DeskDeps['feed'] | null = null;
  private lastPriceLog = '';
  private quoteRate: RateWindow;
  private swapRate: RateWindow;
  private postRate: RateWindow;
  private listNonces = new Map<string, number>();
  private evictedTurn = 0;
  /** When this process began. Used list nonces are in memory only, so a list request signed before that is refused: no replay across a restart. */
  private bootAt = now();
  private scanning = new Set<string>();
  private pruned = new Set<string>();
  private pruneAt = 0;
  private compactAt = Date.now();
  constructor(d: DeskDeps) {
    this.d = d;
    const c = d.cfg;
    this.call = Z.rpc(c.zebraRpc, c.zebraAuth);
    this.seed = hexToBytes(fs.readFileSync(c.seedFile, 'utf8').trim());
    if (this.seed.length !== 32) throw new Error('zec seed must be 32 bytes hex');
    this.journal = new Journal(c.journal);
    this.policy = { minConf: c.minConf, marginSecs: c.marginSecs, speed: c.speed ?? 0.75, claimMarginSecs: c.claimMarginSecs, maxRefundWaitSecs: 7 * 86_400 };
    this.zatPerSol = c.zatPerSol;
    this.screen = d.screen ?? new Screen(loadList(c.sanctionsFile));
    if (c.livePrice ?? c.zecNet === 'mainnet') this.feed = d.feed ?? new PriceFeed({ base: 'SOL', quote: 'ZEC', pythApiKey: c.pythApiKeyFile ? fs.readFileSync(c.pythApiKeyFile, 'utf8').trim() : undefined });
    this.quoteRate = new RateWindow(c.rateLimits?.quotePerMin ?? 120, 60_000);
    this.swapRate = new RateWindow(c.rateLimits?.swapPerMin ?? 20, 60_000);
    this.postRate = new RateWindow(c.rateLimits?.postPerMin ?? 60, 60_000);
  }

  /** Per-swap keys and the SOL->ZEC preimage, from the seed, the swap id and the swap's random salt. */
  key(role: 'hot' | 'refund' | 'claim', swapId = '', salt = ''): Uint8Array {
    return deriveMakerKey(this.seed, role, salt ? `${swapId}:${salt}` : swapId);
  }
  preimage(swapId: string, salt: string): Uint8Array {
    return sha256(concatBytes(this.seed, utf8ToBytes(`halfkey-maker-zec/x/v2/${swapId}:${salt}`)));
  }
  private sk = (s: ZSwap, role: 'refund' | 'claim') => this.key(role, s.swapId, s.salt ?? '');

  /** When the network upgrade list was last read: an upgrade scheduled while we run must pause quotes and change signing. */
  private upsAt = 0;
  private async refreshUpgrades(force = false) {
    if (!force && Date.now() - this.upsAt < 600_000) return;
    const ups = await Z.upgradesFromNode(this.call);
    if (ups.length) { this.ups = ups; this.upsAt = Date.now(); }
  }

  async init() {
    await this.refreshUpgrades(true);
    this.wallet = new ZecWallet(this.call, this.key('hot'), this.d.cfg.zecNet, BigInt(this.d.cfg.marginalFee ?? '5000'));
    for (const r of Journal.read(this.d.cfg.journal)) this.apply(r);
    log(`zec desk: hot ${this.wallet.address}, ${this.swaps.size} swaps in journal, ${this.d.cfg.zecNet}, price ${this.feed ? 'live' : 'fixed (test network)'}`);
    if (this.feed) {
      await this.refreshPrice().catch((e) => log('zec price', describeErr(e)));
      setInterval(() => { this.refreshPrice().catch((e) => log('zec price', describeErr(e))); }, 15_000).unref();
    }
  }

  private record(swapId: string, kind: string, fields: Record<string, unknown> = {}) {
    const r = { swapId, kind, ...fields };
    this.journal.append(r);
    this.apply(r);
  }
  private apply(r: Record<string, any>) {
    if (r.kind === 'new') {
      this.swaps.set(r.swapId, r.swap as ZSwap);
      this.usedIds.add(r.swapId);
      this.usedHashes.add(r.swap.hashlock);
      if (r.swap.quoteNonce) this.usedNonces.add(r.swap.quoteNonce);
      return;
    }
    const s = this.swaps.get(r.swapId);
    if (!s) return;
    switch (r.kind) {
      case 'funded': s.fundTxid = r.txid; s.fundVout = r.vout; s.phase = s.direction === 4 ? 'funded' : s.phase; if (r.recovered) s.neverOffered = true; break;
      case 'deposit-hint': s.depositHints = [...(s.depositHints ?? []), { txid: r.txid, vout: r.vout }].slice(-4); break;
      case 'sol-locked': s.solSig = r.sig; s.phase = 'sol-locked'; break;
      case 'lock-seen': s.lockSeen = true; break;
      case 'claim-sent': s.claimLvbh = r.lvbh; break;
      case 'sol-claimed': s.solSig = r.sig; s.phase = 'sol-claimed'; break;
      case 'refunding-zec': s.phase = 'refunding-zec'; s.why = r.why; if (r.noShowAt) s.noShowAt = r.noShowAt; break;
      case 'zec-claimed': s.zecTxid = r.txid; s.x = r.x; s.phase = 'zec-claimed'; break;
      case 'zec-refunded': s.zecTxid = r.txid; break;
      case 'done': s.phase = 'done'; s.why = r.why; if (r.paid) s.paid = true; break;
      case 'paid': s.paid = true; break;
      case 'evicted': s.evictedAt = r.at; break;
      case 'unevicted': s.evictedAt = undefined; break;
    }
  }

  // ------------------------------------------------------------------ pricing and HTTP
  info(): S.ZecInfo {
    const m = this.d.maker();
    const near = this.upgradeNear();
    return {
      v: 1, maker: this.d.me.publicKey.toBase58(), programId: this.d.pid.toBase58(), zecNet: this.d.cfg.zecNet,
      directions: (m?.directions ?? 0) & this.d.cfg.directions & 12, minLamports: String(m?.min ?? 0), maxLamports: String(m?.max ?? 0),
      zatPerSol: this.zatPerSol, feeBps: this.d.feeBps(), t1Secs: this.d.cfg.t1Secs, minConf: this.d.cfg.minConf,
      online: !!m?.active, paused: near ?? undefined, priceLive: this.price().ok,
    };
  }
  /** A fixed rate for test networks; a live feed is never overridden. */
  setPrice(zatPerSol: number) { if (!this.feed && Number.isFinite(zatPerSol) && zatPerSol > 0) this.zatPerSol = zatPerSol; }

  /** The price right now: read at the moment of asking, so a feed that stopped refreshing ages out by itself. */
  private price(): PriceState | { ok: true } {
    if (!this.feed) return { ok: true };
    const s = this.feed.state();
    if (!s.ok) return s;
    if (!(s.rate > RATE_BOUNDS[0] && s.rate < RATE_BOUNDS[1])) return { ok: false, reason: `rate ${s.rate} out of bounds` };
    this.zatPerSol = s.rate * 1e8;
    return s;
  }
  /** The stop for every price this desk signs or honours. Never a frozen rate: see maker/price.ts. */
  private requirePrice() { if (!this.price().ok) throw new HttpError(503, 'this maker has no live price right now; try again in a minute'); }
  async refreshPrice() {
    if (!this.feed) return;
    await this.feed.refresh();
    const s = this.price();
    // Loud on every change of state: quotes stopped, or came back.
    const line = s.ok ? 'zec price ok' : `!! ZEC NOT QUOTING: ${s.reason}${this.feed.lastError ? ` (${this.feed.lastError})` : ''}`;
    if (line !== this.lastPriceLog) { log(line); this.lastPriceLog = line; }
  }

  /**
   * Inventory for the skew, in SOL at the mid: spendable ZEC in the hot wallet and the maker's SOL
   * (less a fee reserve). Inside the full daemon the SOL is shared with the XMR desk; each desk
   * weighs its own coin against the whole SOL balance.
   */
  inv: (Inventory & { at: number }) | null = null;
  async refreshInventory(maxAgeMs = 15_000) {
    if (this.inv && Date.now() - this.inv.at < maxAgeMs) return;
    if (!this.wallet) return;
    const [zats, lam] = await Promise.all([this.wallet.balance(), this.d.conn.getBalance(this.d.me.publicKey)]);
    this.inv = { coin: Number(zats) / this.zatPerSol, sol: (lam - 50_000_000) / 1e9, at: Date.now() };
  }
  /** Skewed spread for a quote of `lamports` (null inventory = flat spread). */
  skewFor(direction: 4 | 8, lamports: bigint) {
    if (!this.inv) return null;
    const sol = Number(lamports) / 1e9;
    return skew(this.d.cfg.skew, this.d.cfg.spreadBps, this.inv, direction === 4 ? 'giveCoin' : 'takeCoin', { coin: sol, sol });
  }

  private tipCache = { at: 0, tip: 0 };
  async tip(): Promise<number> {
    if (Date.now() - this.tipCache.at > 3000) this.tipCache = { at: Date.now(), tip: Number((await this.call('getblockchaininfo')).blocks) };
    return this.tipCache.tip;
  }
  /** The refund heights `start` would pick now: SOL->ZEC and ZEC->SOL. */
  lockHeights(tip: number) {
    const c = this.d.cfg, sp = this.policy.speed;
    const s2z = Z.heightAfter(this.ups, tip, Math.ceil((c.consentSecs + c.t1Secs + this.policy.marginSecs) / sp)) + 1;
    const confSecs = Z.secondsUntil(this.ups, tip, tip + this.policy.minConf) * 2;
    const z2s = Z.heightAfter(this.ups, tip, Math.ceil((c.payWindowSecs + confSecs + c.t1Secs + this.policy.marginSecs) / sp)) + 1;
    return { s2z, z2s };
  }
  /**
   * Pause new swaps while a network upgrade (branch ID change: voids pre-signed spends) activates
   * before the refund height of a swap started now, plus the taker's buffer and one more hour.
   */
  upgradeNear(): string | null {
    const t = this.tipCache.tip;
    if (!t || !this.ups.length) return null;
    const { s2z, z2s } = this.lockHeights(t);
    const horizon = Z.heightAfter(this.ups, S.upgradeHorizon(this.ups, Math.max(s2z, z2s)), 3600);
    const up = Z.upgradeBetween(this.ups, t, horizon);
    return up ? `paused: Zcash ${up.name} activates at height ${up.height}` : null;
  }

  quote(direction: number, lamports: bigint): { quote: S.ZecQuote; sig: string } {
    this.requirePrice();
    if (direction !== 4 && direction !== 8) throw bad('direction');
    const m = this.d.maker();
    if (!m?.active || !(m.directions & direction & this.d.cfg.directions)) throw bad('direction not offered');
    if (lamports < m.min || lamports > m.max) throw bad(`amount outside ${m.min}..${m.max} lamports`);
    const near = this.upgradeNear();
    if (near) throw bad(near);
    const mid = this.zatPerSol * Number(lamports) / 1e9;
    const sk = this.skewFor(direction as 4 | 8, lamports);
    if (sk?.stop) throw bad(direction === 4 ? pausedMsg('ZEC', 'SOL', 'ZEC') : pausedMsg('SOL', 'ZEC', 'SOL'));
    const spreadBps = sk?.spreadBps ?? this.d.cfg.spreadBps;
    const k = direction === 4 ? 1 - spreadBps / 10_000 : 1 + spreadBps / 10_000;
    const zats = BigInt(Math.floor(mid * k));
    if (zats < 100_000n) throw bad('amount too small');
    const q: S.ZecQuote = {
      v: 1, kind: 'zec', maker: this.d.me.publicKey.toBase58(), direction: direction as 4 | 8, lamports: lamports.toString(), zats: zats.toString(),
      feeBps: this.d.feeBps(), expiresAt: now() + (this.d.cfg.quoteTtlSecs ?? 120), nonce: bytesToHex(randomBytes(16)), zecNet: this.d.cfg.zecNet,
    };
    return { quote: q, sig: S.signZecQuote(q, this.d.me.secretKey.slice(0, 32)) };
  }

  private checkQuote(b: any): S.ZecQuote {
    this.requirePrice();
    const q = b?.quote as S.ZecQuote;
    if (!q || q.kind !== 'zec' || !S.verifyZecQuote(q, String(b.sig), this.d.me.publicKey.toBytes())) throw bad('not my quote');
    if (q.expiresAt < now()) throw bad('quote expired');
    if (q.zecNet !== this.d.cfg.zecNet) throw bad('wrong network');
    if (q.feeBps !== this.d.feeBps()) throw bad('fee changed; ask for a new quote');
    if (this.usedNonces.has(q.nonce)) throw bad('quote already used');
    if (!/^[0-9a-f]{64}$/.test(String(b.swapId))) throw bad('swapId');
    if (this.usedIds.has(b.swapId) || this.inflight.has(b.swapId)) throw bad('swap id already used');
    const near = this.upgradeNear();
    if (near) throw bad(near);
    return q;
  }

  private admit(q: S.ZecQuote, taker: string, ip: string) {
    const open = [...this.swaps.values()].filter((s) => s.phase !== 'done');
    const fly = [...this.inflight.values()];
    if (q.direction === 4) {
      const l = this.d.cfg.s2zLimits ?? { perTaker: 1, perIp: 3, unlockedZats: String(20n * Z.ZAT) };
      // Our ZEC sat in an offer this wallet (or this address, twice) never locked against.
      const walked = noShowRefusal(this.swaps.values(), { taker, ip }, now(), 'SOL->ZEC');
      if (walked) throw bad(walked);
      const un = [...open.filter((s) => s.direction === 4 && s.phase === 'funded' && !s.lockSeen && s.fundTxid).map((s) => ({ taker: s.taker, ip: s.ip ?? '', zats: BigInt(s.zats) })), ...fly.filter((f) => f.direction === 4)];
      // The ZEC of an offer nobody locked stays in its HTLC until we refund it at the lock height: it still counts against the budget.
      // So does a funding send of unknown fate; that one is our failure, so it never counts against the user's own caps above.
      const held = [...un, ...open.filter((s) => s.direction === 4 && ((s.phase === 'refunding-zec' && s.noShowAt) || (s.phase === 'funded' && !s.fundTxid))).map((s) => ({ ip: s.fundTxid || s.noShowAt ? s.ip ?? '' : '', zats: BigInt(s.zats) }))];
      if (un.filter((u) => u.taker === taker).length >= l.perTaker) throw bad('you already have an offer waiting for your lock');
      if (ip && un.filter((u) => u.ip === ip).length >= l.perIp) throw bad('too many open offers from your address');
      // One address's share of the budget, so one client can't make everybody else read "busy".
      const share = l.perIpZats ? BigInt(l.perIpZats) : BigInt(l.unlockedZats) / 2n;
      if (ip && held.filter((u) => u.ip === ip).reduce((n, u) => n + u.zats, 0n) + BigInt(q.zats) > (share > BigInt(q.zats) ? share : BigInt(q.zats))) throw bad('too many open offers from your address');
      if (held.reduce((n, u) => n + u.zats, 0n) + BigInt(q.zats) > BigInt(l.unlockedZats)) throw bad('the maker is busy, try again in a few minutes');
    } else {
      const l = this.d.cfg.offerLimits ?? { total: 50, perIp: 5 };
      // An offer costs nothing to ask for: past its deposit window it holds no place, though a late deposit is still honoured.
      const off = [...this.liveOffers().map((s) => ({ ip: s.ip ?? '', taker: s.taker })), ...fly.filter((f) => f.direction === 8)];
      if (off.filter((o) => o.taker === taker).length >= (l.perTaker ?? 2)) throw bad('this wallet already has offers waiting for a deposit; pay those or wait for them to run out');
      if (ip && off.filter((o) => o.ip === ip).length >= l.perIp) throw bad('too many open offers from your address');
      if (off.length >= l.total) throw bad('the maker is busy, try again in a minute');
    }
  }

  /**
   * SOL spoken for: ZEC->SOL offers with a full deposit, waiting for their confirmations before we lock. Only those:
   * an offer costs nothing to ask for, so if an unpaid one reserved SOL, a flood could make real users read "not enough SOL".
   */
  private solPromised() { return [...this.swaps.values()].filter((s) => s.direction === 8 && s.phase === 'offered' && s.depositSeen).reduce((n, s) => n + BigInt(s.lamports), 0n); }

  /** ZEC->SOL offers holding a place in the table. */
  private liveOffers() { return [...this.swaps.values()].filter((s) => s.direction === 8 && s.phase === 'offered' && now() <= (s.payBy ?? 0) && !s.evictedAt); }

  /**
   * Signatures are free, so fresh keypairs can fill the offer table. A full table doesn't refuse the next
   * person: the oldest offer past a short minimum age gives up its place, once a scan of its address has just
   * answered and shows no full deposit. A payment found, or no answer, keeps the offer. Being evicted costs its owner
   * almost nothing: the offer stays valid and a deposit is still found, just less often. A griefer's flood mostly
   * evicts the griefer's own earlier offers.
   */
  private async makeRoom() {
    const l = this.d.cfg.offerLimits ?? { total: 50 }, live = this.liveOffers(), t = now(), minAge = this.d.cfg.offerMinAgeSecs ?? 60;
    if (live.length + [...this.inflight.values()].filter((f) => f.direction === 8).length < l.total) return;
    const cands = live.filter((s) => t - s.createdAt >= minAge && !s.depositSeen && !this.scanning.has(s.swapId)).sort((a, b) => a.createdAt - b.createdAt).slice(0, EVICT_SCANS_PER_REQUEST);
    for (const s of cands) {
      this.scanning.add(s.swapId);
      try {
        if (await this.findDeposit(s, true)) { s.depositSeen = true; continue; }
        if (s.phase === 'offered' && !s.evictedAt) { this.record(s.swapId, 'evicted', { at: now() }); return; }
      } catch { /* no answer is not "no deposit": it keeps its place */ } finally { this.scanning.delete(s.swapId); }
    }
  }

  /** Past the ceiling the oldest evicted offers close, each only on a scan that answered and shows no full deposit. */
  private async closeExcessEvicted() {
    const gone = [...this.swaps.values()].filter((s) => s.phase === 'offered' && s.evictedAt).sort((a, b) => a.createdAt - b.createdAt);
    for (const s of gone.slice(0, Math.min(EVICT_CLOSES_PER_TICK, Math.max(0, gone.length - (this.d.cfg.maxEvictedOffers ?? MAX_EVICTED))))) {
      try {
        if (await this.findDeposit(s, true)) { s.depositSeen = true; this.record(s.swapId, 'unevicted'); }
        else this.record(s.swapId, 'done', { why: 'evicted from a full table; no deposit seen (a later deposit refunds from the lock height)' });
      } catch { /* no answer: it stays open */ }
    }
  }

  /**
   * The journal must not grow without bound under an offer flood (signatures are free). A closed ZEC->SOL offer
   * that no money ever reached is forgotten a day after its refund height, after one more scan: anything at its
   * address marks it paid, and those stay for good (each one costs real ZEC). Its secret was never published and its
   * quote is long expired, so forgetting its ids allows nothing. Everything else stays.
   */
  async pruneJournal() {
    const tip = this.tipCache.tip;
    if (!tip || !this.ups.length || Date.now() < this.pruneAt) return;
    this.pruneAt = Date.now() + 60_000;
    const old = [...this.swaps.values()].filter((s) => s.direction === 8 && s.phase === 'done' && !s.paid && !s.fundTxid && !s.solSig && !s.x && tip > Z.heightAfter(this.ups, s.lockHeight, PRUNE_AFTER_REFUND_SECS)).slice(0, PRUNE_SCANS_PER_PASS);
    for (const s of old) {
      try {
        // Spent outputs don't show here, and that is fine: whoever spent them no longer needs the script.
        if ((await Z.htlcOutputs(this.call, this.d.cfg.zecNet, Z.unhex(s.redeem))).length) { this.record(s.swapId, 'paid'); continue; }
        this.swaps.delete(s.swapId);
        this.spentStreak.delete(s.swapId);
        // The id and hashlock stay used until compaction has removed the old records: compaction drops records by swap
        // id, so a new swap reusing the id before then would lose its records (and the desk its refund key) with them.
        this.pruned.add(s.swapId);
        this.prunedHashes.set(s.swapId, s.hashlock);
      } catch { /* no answer: keep it, ask next pass */ }
    }
    if (this.pruned.size && (this.pruned.size >= COMPACT_AFTER || Date.now() - this.compactAt >= 3_600_000)) this.compactJournal();
  }
  /** Rewrite the file without the forgotten offers. On a failure they come back at the next start and are pruned again. */
  compactJournal() {
    const gone = this.pruned;
    try {
      this.journal.compact((r) => !gone.has(r.swapId));
      log(`zec journal: ${gone.size} closed unpaid offers removed`);
      for (const id of gone) { this.usedIds.delete(id); const h = this.prunedHashes.get(id); if (h) this.usedHashes.delete(h); this.prunedHashes.delete(id); }
      this.pruned = new Set();
      this.compactAt = Date.now();
    } catch (e) { log(`!! zec journal compaction failed: ${describeErr(e)}`); }
  }

  /**
   * GET /v1/zec/swaps: the signer's own open swaps, so another device can resume one before anything is on
   * Solana. Only what that wallet's device got when it started the swap: no preimage, salt, keys or client address.
   */
  listSwaps(q: URLSearchParams): { swaps: S.ZecResumeItem[] } {
    const wallet = q.get('wallet') ?? '', at = Number(q.get('at')), nonce = q.get('nonce') ?? '', sig = q.get('sig') ?? '', t = now();
    if (!Number.isInteger(at) || Math.abs(t - at) > LIST_WINDOW_SECS) throw bad('that request is out of date; try again');
    if (!/^[0-9a-f]{32}$/.test(nonce)) throw bad('nonce');
    if (!S.verifyListSwaps(this.d.me.publicKey.toBase58(), wallet, at, nonce, sig)) throw bad('this request needs your wallet signature');
    if (at < this.bootAt) throw bad('that request is out of date; try again');
    for (const [k, exp] of this.listNonces) if (exp < t) this.listNonces.delete(k);
    const used = `${wallet}:${nonce}`;
    if (this.listNonces.has(used)) throw bad('that request was already used; try again');
    this.listNonces.set(used, t + 2 * LIST_WINDOW_SECS + 1);
    const swaps: S.ZecResumeItem[] = [];
    for (const s of this.swaps.values()) {
      if (s.taker !== wallet || !s.quote || !s.quoteSig) continue;
      const base = { swapId: s.swapId, direction: s.direction, createdAt: s.createdAt, quote: s.quote, sig: s.quoteSig };
      // A closed offer stays listed until it is forgotten, unless the swap completed: a payment to it is still the wallet's, and this may be the only copy of the script left.
      const closed = s.phase === 'done' && !s.x;
      if (s.direction === 8 && (s.phase === 'offered' || s.phase === 'sol-locked' || closed)) {
        swaps.push({ ...base, ...(closed ? { closed } : {}), offer: { direction: 8, escrow: s.escrow, redeem: s.redeem, htlcAddress: Z.htlcAddress(this.d.cfg.zecNet, Z.unhex(s.redeem)), lockHeight: s.lockHeight, payBy: s.payBy ?? 0 } });
      } else if (s.direction === 4 && s.phase === 'funded' && s.fundTxid && !s.lockSeen && (s.consentExpiry ?? 0) > t) {
        const consentSig = bytesToHex(ed25519.sign(H.htlcConsentDigest(this.d.pid, new PublicKey(s.taker), this.lockParams(s)), this.d.me.secretKey.slice(0, 32)));
        swaps.push({ ...base, offer: { direction: 4, escrow: s.escrow, hashlock: s.hashlock, redeem: s.redeem, htlcAddress: Z.htlcAddress(this.d.cfg.zecNet, Z.unhex(s.redeem)), fundTxid: s.fundTxid, fundVout: s.fundVout ?? 0, lockHeight: s.lockHeight, t1Secs: this.d.cfg.t1Secs, consentExpiry: s.consentExpiry!, consentSig, feeBps: s.feeBps } });
      }
    }
    return { swaps: swaps.sort((a, b) => b.createdAt - a.createdAt).slice(0, 20) };
  }

  async start(b: any, ip = ''): Promise<S.SolToZecOffer | S.ZecToSolOffer> {
    const q = this.checkQuote(b);
    let taker: PublicKey;
    try { taker = new PublicKey(String(b.taker)); } catch { throw bad('taker'); }
    if (taker.equals(this.d.me.publicKey)) throw bad('taker is the maker');
    if (this.screen.sol(taker.toBase58())) { log(`declined listed wallet ${taker.toBase58()}`); throw bad('this maker cannot take this swap'); }
    const key33 = (h: unknown, name: string) => {
      let k: Uint8Array;
      try { k = hexToBytes(String(h)); secp256k1.ProjectivePoint.fromHex(k); } catch { throw bad(name); }
      if (k.length !== 33) throw bad(name);
      return k;
    };
    // Validate everything synchronously, then burn the nonce before the first await: two
    // concurrent requests with one quote can never both fund an HTLC.
    const claimPubIn = q.direction === 4 ? key33(b.claimPub, 'claimPub') : null;
    const refundPubIn = q.direction === 8 ? key33(b.refundPub, 'refundPub') : null;
    let hashIn: Uint8Array | null = null;
    if (q.direction === 8) {
      try { hashIn = hexToBytes(String(b.hashlock)); } catch { throw bad('hashlock'); }
      if (hashIn.length !== 32 || hashIn.every((v) => v === 0)) throw bad('hashlock');
    }
    if (hashIn && this.usedHashes.has(bytesToHex(hashIn))) throw bad('hashlock already used');
    const swapId = String(b.swapId), swapIdB = hexToBytes(swapId);
    // SOL->ZEC locks real ZEC on request, so a request counts only with the wallet's signature: naming
    // someone else's rich wallet gets nothing, and every cap below applies to wallets actually held.
    const signedKey = q.direction === 4 ? String(b.claimPub) : S.zecToSolKeys(String(b.hashlock), String(b.refundPub));
    if (!S.verifyOfferRequest(q, swapId, signedKey, String(b.takerSig), taker.toBytes())) throw bad('this request needs your wallet signature');
    let coin: { mint: PublicKey; amount: bigint } | null = null;
    if (q.direction === 4 && b.coinMint != null) {
      try { coin = { mint: new PublicKey(String(b.coinMint)), amount: BigInt(String(b.coinAmount)) }; } catch { throw bad('coinMint'); }
      if (coin.amount <= 0n) throw bad('coinAmount');
    }
    // A full table scans before it evicts. Everything an await could have changed is checked again after it.
    if (q.direction === 8) {
      await this.makeRoom();
      this.checkQuote(b);
      if (hashIn && this.usedHashes.has(bytesToHex(hashIn))) throw bad('hashlock already used');
    }
    this.admit(q, taker.toBase58(), ip);
    // Burn the nonce and reserve the swap id synchronously, before the first await: two concurrent
    // requests (same quote or same swap id) can never both get through.
    this.usedNonces.add(q.nonce);
    this.inflight.set(swapId, { direction: q.direction, taker: taker.toBase58(), ip, zats: BigInt(q.zats) });
    try {
      return await this.startInner(q, String(b.sig), taker, swapId, swapIdB, ip, claimPubIn, refundPubIn, hashIn, coin);
    } finally {
      this.inflight.delete(swapId);
      this.usedIds.add(swapId); // stays used even if the request failed
    }
  }

  private async startInner(q: S.ZecQuote, quoteSig: string, taker: PublicKey, swapId: string, swapIdB: Uint8Array, ip: string, claimPubIn: Uint8Array | null, refundPubIn: Uint8Array | null, hashIn: Uint8Array | null, coin: { mint: PublicKey; amount: bigint } | null): Promise<S.SolToZecOffer | S.ZecToSolOffer> {
    const tip = await this.tip();
    const salt = bytesToHex(randomBytes(16));
    if (q.direction === 4) {
      // The taker must hold what pays for the lock (a random key cannot tie up our ZEC): the SOL, or
      // the coin it sells for that SOL plus the SOL for the record. A failed read is not an empty wallet.
      if (coin) await this.checkCoinPayer(taker, coin, BigInt(q.lamports));
      else if (BigInt(await this.readLamports(taker)) < BigInt(q.lamports) + 10_000_000n) throw bad('your wallet does not hold the SOL for this swap');
      const claimPub = claimPubIn!;
      const x = this.preimage(swapId, salt);
      const refundPriv = this.key('refund', swapId, salt);
      const consentExpiry = now() + this.d.cfg.consentSecs;
      const lockHeight = this.lockHeights(tip).s2z;
      const redeem = Z.htlcScript({ hashlock: sha256(x), claimPub, refundPub: Z.pubOf(refundPriv), lockHeight });
      const escrow = H.htlcPda(this.d.pid, taker, swapIdB);
      if (this.usedHashes.has(bytesToHex(sha256(x)))) throw new Error('hashlock collision');
      const s: ZSwap = {
        swapId, direction: 4, taker: taker.toBase58(), lamports: q.lamports, zats: q.zats, feeBps: q.feeBps, quoteHash: bytesToHex(S.zecQuoteHash(q)),
        hashlock: bytesToHex(sha256(x)), redeem: Z.hex(redeem), lockHeight, escrow: escrow.toBase58(), phase: 'funded', createdAt: now(), consentExpiry, salt, ip, quote: q, quoteSig,
      };
      this.record(swapId, 'new', { swap: { ...s, quoteNonce: q.nonce } });
      // Fund before answering: the user locks SOL only after it sees this output confirmed.
      const branch = Z.upgradeAt(this.ups, tip + 1).branch;
      let txid: string;
      try {
        ({ txid } = await this.wallet.pay([{ value: BigInt(q.zats), script: Z.p2sh(redeem) }], branch));
      } catch (e) {
        if (e instanceof NotSent) {
          this.record(swapId, 'done', { why: `funding failed: ${describeErr(e)}` });
          throw bad('not enough ZEC inventory right now');
        }
        // The node may have taken it: the swap stays open, and step() finds the funding on chain and refunds it, or closes it once the chain says it never went out.
        log(`zec swap ${swapId.slice(0, 8)} funding send unknown: ${describeErr(e)}`);
        throw new HttpError(503, 'the maker could not confirm its ZEC lock; try again in a minute');
      }
      this.record(swapId, 'funded', { txid, vout: 0 });
      const lock = this.lockParams(this.swaps.get(swapId)!);
      const consentSig = bytesToHex(ed25519.sign(H.htlcConsentDigest(this.d.pid, taker, lock), this.d.me.secretKey.slice(0, 32)));
      log(`zec swap ${swapId.slice(0, 8)} SOL->ZEC funded ${txid.slice(0, 12)} L=${lockHeight}`);
      return { direction: 4, escrow: s.escrow, hashlock: s.hashlock, redeem: s.redeem, htlcAddress: Z.htlcAddress(this.d.cfg.zecNet, redeem), fundTxid: txid, fundVout: 0, lockHeight, t1Secs: this.d.cfg.t1Secs, consentExpiry, consentSig, feeBps: q.feeBps };
    }
    // ZEC -> SOL
    const hashlock = hashIn!;
    const refundPub = refundPubIn!;
    if (BigInt(await this.d.conn.getBalance(this.d.me.publicKey)) < BigInt(q.lamports) + 50_000_000n + this.solPromised()) throw bad('not enough SOL inventory right now');
    const payBy = now() + this.d.cfg.payWindowSecs;
    const lockHeight = this.lockHeights(tip).z2s;
    const claimPub = Z.pubOf(this.key('claim', swapId, salt));
    if (Buffer.from(claimPub).equals(Buffer.from(refundPub))) throw bad('refundPub');
    const redeem = Z.htlcScript({ hashlock, claimPub, refundPub, lockHeight });
    const escrow = H.htlcPda(this.d.pid, this.d.me.publicKey, swapIdB);
    const s: ZSwap = {
      swapId, direction: 8, taker: taker.toBase58(), lamports: q.lamports, zats: q.zats, feeBps: q.feeBps, quoteHash: bytesToHex(S.zecQuoteHash(q)),
      hashlock: bytesToHex(hashlock), redeem: Z.hex(redeem), lockHeight, escrow: escrow.toBase58(), phase: 'offered', createdAt: now(), payBy, salt, ip, quote: q, quoteSig,
    };
    this.record(swapId, 'new', { swap: { ...s, quoteNonce: q.nonce } });
    log(`zec swap ${swapId.slice(0, 8)} ZEC->SOL offered, pay ${q.zats} zats to ${Z.htlcAddress(this.d.cfg.zecNet, redeem)} by ${payBy}`);
    return { direction: 8, escrow: s.escrow, redeem: s.redeem, htlcAddress: Z.htlcAddress(this.d.cfg.zecNet, redeem), lockHeight, payBy };
  }

  private readLamports(who: PublicKey) {
    return this.d.conn.getBalance(who).catch(() => { throw new HttpError(503, 'could not read your wallet right now; try again in a minute'); });
  }
  /** What a coin payer's lock is paid with: the coin in the wallet, and it must really sell for about that much SOL. */
  private async checkCoinPayer(taker: PublicKey, coin: { mint: PublicKey; amount: bigint }, lamports: bigint) {
    if (BigInt(await this.readLamports(taker)) < COIN_PAYER_MIN_LAMPORTS) throw bad('your wallet needs a little SOL for the network fees');
    const accts = await this.d.conn.getTokenAccountsByOwner(taker, { mint: coin.mint }).catch(() => { throw new HttpError(503, 'could not read your wallet right now; try again in a minute'); });
    // SPL layout, both token programs: the u64 amount sits at offset 64.
    const held = accts.value.reduce((n, a) => n + Buffer.from(a.account.data).readBigUInt64LE(64), 0n);
    if (held < coin.amount) throw bad('your wallet does not hold that much of the coin');
    let worth: bigint;
    try { worth = await this.coinValue(coin.mint.toBase58(), coin.amount, taker.toBase58()); }
    catch (e) {
      if (e instanceof J.NoRoute) throw bad('there is no route to sell that coin right now');
      throw new HttpError(503, 'could not price that coin right now; try again in a minute');
    }
    if (worth * 100n < lamports * COIN_COVER_PCT) throw bad('that coin amount does not cover this swap');
  }
  private coinValue(mint: string, amount: bigint, taker: string): Promise<bigint> {
    if (this.d.coinValue) return this.d.coinValue(mint, amount, taker);
    return J.buildRoute({ inputMint: mint, outputMint: J.WSOL, amount, taker }, { api: this.d.cfg.jupiterApi, apiKey: this.d.cfg.jupiterKey }).then((r) => r.outAmount);
  }

  funded(b: any) {
    const s = this.swaps.get(String(b.swapId));
    if (!s || s.direction !== 8) throw new HttpError(404, 'unknown swap');
    if (!/^[0-9a-f]{64}$/.test(String(b.txid)) || !Number.isInteger(b.vout) || b.vout < 0 || b.vout > 1000) throw bad('txid/vout');
    if ((s.depositHints ?? []).some((h) => h.txid === b.txid && h.vout === b.vout)) return { ok: true };
    if ((s.depositHints ?? []).length >= 4 || s.phase !== 'offered') throw bad('no more deposit hints for this swap');
    this.record(s.swapId, 'deposit-hint', { txid: b.txid, vout: b.vout });
    return { ok: true };
  }

  status(swapId: string): S.ZecSwapStatus {
    const s = this.swaps.get(swapId);
    if (!s) throw new HttpError(404, 'unknown swap');
    return { swapId, direction: s.direction, phase: s.phase, escrow: s.escrow, fundTxid: s.fundTxid, fundVout: s.fundVout, required: this.d.cfg.minConf, solSig: s.solSig, zecClaimTxid: s.phase === 'zec-claimed' ? s.zecTxid : undefined, zecRefundTxid: s.phase !== 'zec-claimed' ? s.zecTxid : undefined, note: s.why ?? s.lastError, redeem: s.redeem, lockHeight: s.lockHeight, quote: s.quote, sig: s.quoteSig };
  }

  /** Routes under /v1/zec/*. `body` is read lazily by the host. */
  async handle(method: string, u: URL, body: () => Promise<any>, ip = ''): Promise<unknown> {
    if (method === 'GET' && u.pathname === '/v1/zec/info') { await this.tip().catch(() => 0); return this.info(); }
    if (method === 'GET' && u.pathname === '/v1/zec/quote') {
      if (ip && !this.quoteRate.take(ip)) throw new HttpError(429, 'too many quote requests; slow down a little');
      await this.tip();
      await this.refreshInventory().catch(() => {});
      let lamports: bigint;
      try { lamports = BigInt(u.searchParams.get('lamports') ?? '0'); } catch { throw bad('lamports'); }
      const out = this.quote(Number(u.searchParams.get('direction')), lamports);
      // Refuse up front what could not be funded. Only an answer counts: a failed read leaves it to the swap request.
      if (out.quote.direction === 4) {
        const have = await this.wallet.balance().catch(() => null);
        if (have != null && BigInt(out.quote.zats) > have) throw bad('not enough ZEC inventory right now');
      } else {
        const have = await this.d.conn.getBalance(this.d.me.publicKey).catch(() => null);
        if (have != null && BigInt(have) < lamports + 50_000_000n + this.solPromised()) throw bad('not enough SOL inventory right now');
      }
      return out;
    }
    if (method === 'POST' && u.pathname === '/v1/zec/swap') {
      if (ip && !this.swapRate.take(ip)) throw new HttpError(429, 'too many swap requests; slow down a little');
      return this.start(await body(), ip);
    }
    if (method === 'POST' && u.pathname === '/v1/zec/funded') {
      if (ip && !this.postRate.take(ip)) throw new HttpError(429, 'too many requests; slow down a little');
      return this.funded(await body());
    }
    if (method === 'GET' && u.pathname === '/v1/zec/swaps') {
      if (ip && !this.postRate.take(ip)) throw new HttpError(429, 'too many requests; slow down a little');
      return this.listSwaps(u.searchParams);
    }
    const st = u.pathname.match(/^\/v1\/zec\/swap\/([0-9a-f]{64})$/);
    if (method === 'GET' && st) return this.status(st[1]);
    throw new HttpError(404, 'not found');
  }

  // ------------------------------------------------------------------ state machine
  lockParams(s: ZSwap): H.HtlcLockParams {
    return {
      swapId: hexToBytes(s.swapId), claimer: s.direction === 4 ? this.d.me.publicKey : new PublicKey(s.taker), direction: s.direction,
      amount: BigInt(s.lamports), zecAmount: BigInt(s.zats), hashlock: hexToBytes(s.hashlock), quoteHash: hexToBytes(s.quoteHash),
      t1Secs: this.d.cfg.t1Secs, consentExpiry: s.consentExpiry ?? 0, makerAuthority: this.d.me.publicKey, feeBps: s.feeBps,
    };
  }

  async loadHtlc(addr: string, commitment: 'confirmed' | 'finalized'): Promise<H.HtlcAccount | null> {
    const a = await this.d.conn.getAccountInfo(new PublicKey(addr), commitment);
    if (!a || !a.owner.equals(this.d.pid) || a.data.length !== H.HTLC_LEN) return null;
    return H.decodeHtlc(a.data, new PublicKey(addr));
  }

  async tick() {
    await this.tip().catch((e) => log('zec tip', describeErr(e)));
    await this.refreshUpgrades().catch((e) => log('zec upgrades', describeErr(e)));
    await this.refreshInventory(30_000).catch(() => {});
    for (const r of [this.quoteRate, this.swapRate, this.postRate]) r.sweep();
    await this.closeExcessEvicted();
    await this.pruneJournal().catch((e) => log('zec prune', describeErr(e)));
    // Evicted offers take turns: a flood of them can't slow the real swaps. Everything else goes every tick.
    const evicted = [...this.swaps.values()].filter((s) => s.phase === 'offered' && s.evictedAt);
    const turn = new Set(Array.from({ length: Math.min(EVICTED_SCANS_PER_TICK, evicted.length) }, (_, i) => evicted[(this.evictedTurn + i) % evicted.length].swapId));
    this.evictedTurn = evicted.length ? (this.evictedTurn + turn.size) % evicted.length : 0;
    for (const s of this.swaps.values()) {
      if (s.phase === 'done' || this.busy.has(s.swapId)) continue;
      if (s.phase === 'offered' && s.evictedAt && !turn.has(s.swapId)) continue;
      this.busy.add(s.swapId);
      try { await this.step(s); s.lastError = undefined; } catch (e) { s.lastError = describeErr(e); log(`zec swap ${s.swapId.slice(0, 8)} step: ${s.lastError}`); } finally { this.busy.delete(s.swapId); }
    }
  }

  private async refundSol(s: ZSwap, h: H.HtlcAccount) {
    const sig = await sendIxs(this.d.conn, this.d.me, [H.ixHtlcRefund(this.d.pid, this.d.me.publicKey, h.address!, h.locker, h.maker)]);
    log(`zec swap ${s.swapId.slice(0, 8)} SOL refunded to ${h.locker.toBase58().slice(0, 8)} ${sig.slice(0, 12)}`);
    return sig;
  }

  /** `spent` must be seen on several consecutive ticks before a terminal step (never one RPC answer). */
  private spentFor(s: ZSwap, spent: boolean, need = 3): boolean {
    const n = spent ? (this.spentStreak.get(s.swapId) ?? 0) + 1 : 0;
    this.spentStreak.set(s.swapId, n);
    return n >= need;
  }

  /** Re-sign (current branch) and send; "already known" counts as sent. */
  private async broadcast(raw: string) {
    try { return await this.call('sendrawtransaction', [raw]); } catch (e) {
      if (/already|known|duplicate|exists/i.test(String((e as Error).message))) return null;
      throw e;
    }
  }

  /**
   * Our ZEC refund from height L (SOL->ZEC). Only if the SOL can never be claimed by us any more:
   * the escrow never appeared (checked after the consent expiry) or is aborted/refunded. Never
   * after we claimed it (the user's ZEC claim may still be on its way).
   */
  private async refundZec(s: ZSwap) {
    const h = await this.loadHtlc(s.escrow, 'finalized');
    if (h && h.state === P.ST.CLAIMED) { this.record(s.swapId, 'sol-claimed', { sig: s.solSig ?? '' }); return; }
    if (h && h.state === P.ST.LOCKED) {
      if ((await chainNow(this.d.conn)) < Number(h.t1)) return;
      // The finalized view lags: our own refund (or a watchtower's) may already be confirmed, and
      // re-sending it fails with BadState forever. Past t1 no claim can land any more, so a
      // confirmed refund is enough to go on to the ZEC refund.
      try { await this.refundSol(s, h); return; } catch (e) {
        const now = await this.loadHtlc(s.escrow, 'confirmed');
        if (!now || now.state !== P.ST.REFUNDED) throw e;
      }
    }
    const tip = await this.tip();
    if (tip < s.lockHeight) return;
    const f = await Z.checkFunding(this.call, s.fundTxid!, s.fundVout!, Z.unhex(s.redeem));
    if (s.zecTxid && (await this.confs(s.zecTxid)) >= this.policy.minConf) { this.record(s.swapId, 'done', { why: 'zec-refunded' }); return; }
    if (f.spent) {
      if (!s.zecTxid && this.spentFor(s, true)) this.record(s.swapId, 'done', { why: 'htlc spent by the user (claimed with x)' });
      return;
    }
    this.spentFor(s, false);
    const p = Z.presign({ kind: 'refund', branch: Z.upgradeAt(this.ups, tip + 1).branch, txid: s.fundTxid!, vout: s.fundVout!, value: f.value, redeem: Z.unhex(s.redeem), outScript: this.wallet.script, priv: this.sk(s, 'refund'), marginal: BigInt(this.d.cfg.marginalFee ?? '5000') });
    const fin = Z.finalize(p);
    await this.broadcast(fin.raw);
    if (s.zecTxid !== fin.txid) { this.record(s.swapId, 'zec-refunded', { txid: fin.txid }); log(`zec swap ${s.swapId.slice(0, 8)} ZEC refund sent ${fin.txid.slice(0, 12)}`); }
  }

  private confs = (txid: string) => this.call('getrawtransaction', [txid, 1]).then((r: any) => Number(r.confirmations ?? 0), () => -1);

  /** Send the SOL claim, journaling its last valid block height first (an in-flight claim blocks any abort). */
  private async sendClaim(s: ZSwap, h: H.HtlcAccount) {
    const { blockhash, lastValidBlockHeight } = await this.d.conn.getLatestBlockhash('confirmed');
    this.record(s.swapId, 'claim-sent', { lvbh: lastValidBlockHeight });
    const tx = new Transaction().add(ComputeBudgetProgram.setComputeUnitLimit({ units: 60_000 }), H.ixHtlcClaim(this.d.pid, this.d.me.publicKey, h.address!, h.maker, this.preimage(s.swapId, s.salt ?? '')));
    const price = await priorityPrice(); // a claim that does not land before t1 is a loss, like every other maker send
    if (price) tx.instructions.unshift(ComputeBudgetProgram.setComputeUnitPrice({ microLamports: price }));
    tx.feePayer = this.d.me.publicKey;
    tx.recentBlockhash = blockhash;
    tx.sign(this.d.me);
    const sig = await this.d.conn.sendRawTransaction(tx.serialize(), { skipPreflight: true });
    await waitForTx(sig, lastValidBlockHeight, {
      status: async (x) => (await this.d.conn.getSignatureStatuses([x], { searchTransactionHistory: true })).value[0],
      height: () => this.d.conn.getBlockHeight('confirmed'),
    }, { timeoutMs: 120_000, intervalMs: 800 });
    return sig;
  }

  private async step(s: ZSwap) {
    const t = await chainNow(this.d.conn);
    if (s.direction === 4) {
      if (s.phase === 'refunding-zec') return this.refundZec(s);
      if (s.phase === 'sol-claimed') { this.record(s.swapId, 'done', { why: 'completed' }); return; }
      if (s.phase !== 'funded') return;
      if (!s.fundTxid) {
        // Crashed between broadcasting the funding and journaling it: find it on chain.
        const dep = await this.findDeposit(s, true); // an unreadable chain throws: it does not mean "never funded"
        if (dep) this.record(s.swapId, 'funded', { txid: dep.txid, vout: dep.vout, recovered: true });
        // It has no expiry and may mine late; our ZEC would then have no refund. Only the lock height ends the search.
        else if ((await this.tip()) > s.lockHeight + UNKNOWN_SEND_BLOCKS) this.record(s.swapId, 'done', { why: 'never funded' });
        return;
      }
      const h = await this.loadHtlc(s.escrow, 'finalized');
      if (!h) {
        // No lock by the consent expiry (plus finality slack): it can never appear any more. That ends the
        // offer and costs the wallet an hour, so it takes several empty reads in a row and nothing at 'confirmed' either.
        if (t <= (s.consentExpiry ?? 0) + 120) return;
        if (await this.loadHtlc(s.escrow, 'confirmed')) { s.noLockReads = 0; return; }
        s.noLockReads = (s.noLockReads ?? 0) + 1;
        if (s.noLockReads >= NO_LOCK_READS) this.record(s.swapId, 'refunding-zec', { why: 'user never locked', ...(s.neverOffered ? {} : { noShowAt: now() }) });
        return;
      }
      s.noLockReads = 0;
      if (!s.lockSeen) this.record(s.swapId, 'lock-seen');
      const okTerms = h.direction === 4 && h.claimer.equals(this.d.me.publicKey) && h.maker.equals(this.d.me.publicKey) && h.locker.toBase58() === s.taker
        && bytesToHex(h.hashlock) === s.hashlock && h.amount === BigInt(s.lamports) && h.zecAmount === BigInt(s.zats) && bytesToHex(h.quoteHash) === s.quoteHash;
      if (h.state === P.ST.CLAIMED) { this.record(s.swapId, 'sol-claimed', { sig: s.solSig ?? '' }); return; }
      if (h.state === P.ST.ABORTED || h.state === P.ST.REFUNDED) { this.record(s.swapId, 'refunding-zec', { why: `escrow ${P.ST_NAME[h.state]}` }); return; }
      if (h.state !== P.ST.LOCKED) return;
      // A claim of ours may still land: never abort (a claim failing after an abort would publish
      // x) and never give up until its blockhash has expired.
      const inFlight = s.claimLvbh !== undefined && (await this.d.conn.getBlockHeight('confirmed')) <= s.claimLvbh;
      if (inFlight) return;
      if (!okTerms) {
        // Consent binds the terms, so this cannot happen; never reveal x for anything else.
        if (s.claimLvbh === undefined) await sendIxs(this.d.conn, this.d.me, [H.ixHtlcAbort(this.d.pid, this.d.me.publicKey, h.address!, h.maker)]);
        this.record(s.swapId, 'refunding-zec', { why: 'escrow terms differ; declined' });
        return;
      }
      if (FAULT === 'no-sol-claim' && t < Number(h.t1)) return;
      if (t < Number(h.t1) - this.policy.claimMarginSecs) {
        const sig = await this.sendClaim(s, h);
        this.record(s.swapId, 'sol-claimed', { sig });
        log(`zec swap ${s.swapId.slice(0, 8)} SOL claimed ${sig.slice(0, 12)} (x public; the user's watchtowers claim the ZEC)`);
        return;
      }
      // Too late to claim safely. If we never sent a claim, give it up before t1 so the user can
      // refund at once; from t1 relay the user's refund. refundZec re-checks the escrow before
      // touching the ZEC, so an earlier claim that landed late is never followed by a ZEC refund.
      if (t < Number(h.t1)) { if (s.claimLvbh === undefined) await sendIxs(this.d.conn, this.d.me, [H.ixHtlcAbort(this.d.pid, this.d.me.publicKey, h.address!, h.maker)]).catch(() => {}); }
      else await this.refundSol(s, h).catch(() => {});
      this.record(s.swapId, 'refunding-zec', { why: 'missed the claim window; declined' });
      return;
    }

    // ZEC -> SOL
    if (s.phase === 'zec-claimed') {
      // Done only at minConf. Until then rebroadcast (re-signed for the current branch) while the
      // output is unspent: a dropped claim must not let the user's refund take it at L.
      if ((await this.confs(s.zecTxid!)) >= this.policy.minConf) { this.record(s.swapId, 'done', { why: 'completed' }); return; }
      const f = await Z.checkFunding(this.call, s.fundTxid!, s.fundVout!, Z.unhex(s.redeem));
      if (!f.spent) await this.claimZec(s, hexToBytes(s.x!), f.value);
      return;
    }
    if (s.phase === 'offered') {
      // Closing needs an answer: past that time a read that fails throws here and this comes round again.
      const closing = now() > (s.payBy ?? 0) + 3600;
      const dep = await this.findDeposit(s, closing);
      if (!dep) { if (closing) this.record(s.swapId, 'done', { why: 'no deposit' }); return; }
      s.depositSeen = true;
      if (s.evictedAt) this.record(s.swapId, 'unevicted'); // paid: back to a scan on every tick, at the same quote
      const tip = await this.tip();
      // When it was paid goes by its block, not by when we got round to it: our outage must not read as the user's lateness.
      const paidAt = now() - Z.secondsUntil(this.ups, Math.max(0, tip - dep.confirmations), tip);
      if (paidAt > (s.payBy ?? 0) + 3600) { this.record(s.swapId, 'done', { why: 'deposit came after this offer closed: no SOL will be locked, and the user refunds the ZEC from the lock height', paid: true }); return; }
      if (dep.confirmations < this.policy.minConf) return;
      // Paid after the window: the quote has run out. Honoured only if it still pays at least the live mid;
      // on no fresh price, wait: the user can't lose, its refund stands.
      if (paidAt > (s.payBy ?? 0)) {
        if (!this.price().ok) return;
        if (BigInt(s.zats) < BigInt(Math.ceil(this.zatPerSol * Number(s.lamports) / 1e9))) {
          this.record(s.swapId, 'done', { why: 'deposit came after the quote ran out and the price moved (the user refunds the ZEC from the lock height)', paid: true });
          return;
        }
      }
      const why = S.lockHeightSafe(this.ups, tip, now(), s.lockHeight, now() + this.d.cfg.t1Secs, this.policy);
      if (why) { this.record(s.swapId, 'done', { why: `not locking SOL: ${why} (the user refunds the ZEC from the lock height)`, paid: true }); return; }
      if (!s.fundTxid) this.record(s.swapId, 'funded', { txid: dep.txid, vout: dep.vout });
      if (await this.loadHtlc(s.escrow, 'confirmed')) { this.record(s.swapId, 'sol-locked', { sig: '' }); return; } // sent before a crash
      const sig = await sendIxs(this.d.conn, this.d.me, [H.ixHtlcLock(this.d.pid, this.d.me.publicKey, this.lockParams(s))]);
      this.record(s.swapId, 'sol-locked', { sig });
      log(`zec swap ${s.swapId.slice(0, 8)} deposit ${dep.txid.slice(0, 12)} confirmed; SOL locked ${sig.slice(0, 12)}`);
      return;
    }
    if (s.phase === 'sol-locked') {
      const h = await this.loadHtlc(s.escrow, 'confirmed');
      if (!h) return;
      if (h.state === P.ST.CLAIMED) {
        const x = H.revealedPreimage(h);
        if (!x) throw new Error('claimed without a valid preimage');
        const f = await Z.checkFunding(this.call, s.fundTxid!, s.fundVout!, Z.unhex(s.redeem));
        if (f.spent) {
          if (this.spentFor(s, true, 5)) this.record(s.swapId, 'done', { why: 'deposit already spent (user refunded after the lock height?)' });
          return;
        }
        this.spentFor(s, false);
        const id = await this.claimZec(s, x, f.value);
        this.record(s.swapId, 'zec-claimed', { txid: id, x: bytesToHex(x) });
        log(`zec swap ${s.swapId.slice(0, 8)} user claimed SOL; ZEC claim sent ${id.slice(0, 12)}`);
        return;
      }
      if (h.state === P.ST.REFUNDED) { this.record(s.swapId, 'done', { why: 'SOL refunded' }); return; }
      if (h.state === P.ST.ABORTED || (h.state === P.ST.LOCKED && t >= Number(h.t1))) {
        const sig = await this.refundSol(s, h);
        this.record(s.swapId, 'done', { why: `SOL refunded ${sig}` });
      }
    }
  }

  /** ZEC -> SOL: claim the user's deposit with the revealed x (re-signed for the next block's branch). */
  private async claimZec(s: ZSwap, x: Uint8Array, value: bigint): Promise<string> {
    const tip = await this.tip();
    const p = Z.presign({ kind: 'claim', branch: Z.upgradeAt(this.ups, tip + 1).branch, txid: s.fundTxid!, vout: s.fundVout!, value, redeem: Z.unhex(s.redeem), outScript: this.wallet.script, priv: this.sk(s, 'claim'), marginal: BigInt(this.d.cfg.marginalFee ?? '5000') });
    const fin = Z.finalize(p, x);
    await this.broadcast(fin.raw);
    return fin.txid;
  }

  /** ZEC -> SOL deposit: a reported outpoint, or a scan of the HTLC address. Must pay the full amount. */
  private async findDeposit(s: ZSwap, strict = false): Promise<{ txid: string; vout: number; confirmations: number } | null> {
    const redeem = Z.unhex(s.redeem);
    const cands = [...(s.depositHints ?? [])];
    if (s.fundTxid) cands.unshift({ txid: s.fundTxid, vout: s.fundVout! });
    try {
      const r = await this.call('getaddressutxos', [{ addresses: [Z.htlcAddress(this.d.cfg.zecNet, redeem)] }]);
      for (const u of (Array.isArray(r) ? r : r?.utxos ?? [])) cands.push({ txid: String(u.txid), vout: Number(u.outputIndex ?? u.index) });
    } catch (e) { if (strict) throw e; /* address index unavailable: hints only */ }
    let best: { txid: string; vout: number; confirmations: number } | null = null;
    for (const c of cands) {
      try {
        const f = await Z.checkFunding(this.call, c.txid, c.vout, redeem);
        if (f.spent || f.value < BigInt(s.zats)) continue;
        if (!best || f.confirmations > best.confirmations) best = { ...c, confirmations: f.confirmations };
      // A hint anyone can post, so an unknown txid is "not ours", never an unreadable chain: a made-up hint must not make an offer unevictable.
      } catch (e) { if (strict && !/no such|does not pay|coinbase|no tx|\b-5\b/i.test(String((e as Error).message))) throw e; /* not ours */ }
    }
    return best;
  }
}

/**
 * The HTTP side of a ZEC-only maker (maker/zec-daemon.ts). The client's address comes from clientIp, as
 * in the full daemon: behind a tunnel every client would otherwise be one address and the per-address
 * caps would lock real users out. /v1/info is what the site's maker discovery reads first.
 */
export function zecHttp(desk: ZecDesk, o: { trustProxy?: boolean } = {}): http.RequestListener {
  const readBody = async (req: http.IncomingMessage) => {
    let s = '';
    for await (const ch of req) { s += ch; if (s.length > 16_000) throw new HttpError(400, 'body too large'); }
    try { return JSON.parse(s); } catch { throw new HttpError(400, 'bad json'); }
  };
  return async (req, res) => {
    res.setHeader('access-control-allow-origin', '*');
    res.setHeader('access-control-allow-headers', 'content-type');
    res.setHeader('access-control-allow-methods', 'GET,POST,OPTIONS');
    if (req.method === 'OPTIONS') { res.writeHead(204).end(); return; }
    try {
      const u = new URL(req.url ?? '/', 'http://x');
      let out: unknown;
      if (req.method === 'GET' && u.pathname === '/v1/info') { const i = desk.info(); out = { v: 1, maker: i.maker, programId: i.programId, online: i.online, priceLive: i.priceLive, directions: i.directions, minLamports: i.minLamports, maxLamports: i.maxLamports, feeBps: i.feeBps }; }
      else if (!u.pathname.startsWith('/v1/zec/')) throw new HttpError(404, 'not found');
      else out = await desk.handle(req.method ?? 'GET', u, () => readBody(req), clientIp(req, o.trustProxy));
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(out));
    } catch (e) {
      const code = e instanceof HttpError ? e.code : 500;
      res.writeHead(code, { 'content-type': 'application/json' }).end(JSON.stringify({ error: e instanceof HttpError ? e.message : describeErr(e) }));
    }
  };
}
