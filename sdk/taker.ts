// Taker (user) side of the HALFKEY protocol. Shared by the web client and the E2E runner.
// Every check the user's safety depends on lives here, not in UI code.
import { Connection, PublicKey, TransactionInstruction } from '@solana/web3.js';
import { ed25519 } from '@noble/curves/ed25519';
import * as P from './program.ts';
import * as RT from './refundtowers.ts';
import * as K from './keys.ts';

// ---------------------------------------------------------------- maker HTTP API (v1)
export interface MakerInfo {
  v: 1;
  maker: string;            // authority, base58
  programId: string;
  cluster: string;          // 'mainnet-beta' | 'devnet' | 'localnet'
  moneroNet: K.MoneroNet;
  directions: number;       // bitmask 1 = SOL->XMR, 2 = XMR->SOL
  minLamports: string;
  maxLamports: string;
  spreadBps: number;
  xmrPerSol: number;        // indicative mid
  feeBps: number;
  t0Secs: number;
  windowSecs: number;
  online: boolean;
  /** XMR->SOL deposit terms (see depositDeadline); absent on older makers = the defaults. */
  depositMarginSecs?: number;
  depositWindowSecs?: number;
  /**
   * Indicative spread per direction right now, after the maker's inventory balancing (null = that
   * direction is paused while inventory rebalances). Absent on older makers. Firm prices are quotes.
   */
  spreadNow?: { 1: number | null; 2: number | null };
}
/** The maker's advertised deposit terms, clamped to sane values (a maker cannot make the client show a deadline past its own abort time by advertising nonsense). */
export const termsOf = (i: Partial<MakerInfo> | null | undefined): DepositTerms => {
  const n = (v: unknown, d: number, max: number) => (typeof v === 'number' && Number.isFinite(v) ? Math.min(Math.max(Math.floor(v), 0), max) : d);
  return {
    depositMarginSecs: n(i?.depositMarginSecs, DEFAULT_DEPOSIT_TERMS.depositMarginSecs, 86_400),
    depositWindowSecs: n(i?.depositWindowSecs, DEFAULT_DEPOSIT_TERMS.depositWindowSecs, 86_400),
  };
};

export interface SignedQuote { quote: K.Quote; sig: string }

export interface SwapRequest {
  quote: K.Quote;
  sig: string;
  swapId: string;           // hex(32)
  taker: string;            // SOL->XMR: locker; XMR->SOL: claimer (fresh wallet ok)
  takerSpendPub: string;    // hex(32)
  viewSecret: string;       // hex(32), the user-derived shared view key
  claimMode?: 'ready-only' | 'payment-proof';
  /** SOL->XMR: the watchtowers the user registered (base58). A flagged (v2) consent binds them, so the maker must know them. */
  watchtowers?: string[];
}

export interface SwapResponseSolToXmr {
  direction: 1;
  flags?: number;
  makerSpendPub: string;
  feeBps: number;                 // effective fee the maker consented to (holder fee while it has $HALFKEY bonded)
  sharedAddress: string;
  t0Secs: number;
  windowSecs: number;
  consentExpiry: number;
  consentSig: string;       // ed25519 over P.consentDigest(...)
}

export interface SwapResponseXmrToSol {
  direction: 2;
  makerSpendPub: string;
  sharedAddress: string;
  escrow: string;
  lockSig: string;
  /** hex(64): proof the maker knows its key half (K.verifyKeyProof); required before any deposit. */
  makerKeyProof: string;
  /** Refund towers' acks for this escrow (sdk/refundtowers.ts); required where the page lists refund towers. */
  refundAcks?: RT.Ack[];
}

export interface MakerSwapStatus {
  escrow: string;
  phase: string;
  xmrLockTx?: string;
  confirmations?: number;
  required?: number;
  note?: string;
  /** XMR->SOL: the maker's key proof for this escrow (resume on another device). */
  makerKeyProof?: string;
  refundAcks?: RT.Ack[];
}

async function j<T>(r: Response): Promise<T> {
  const body = await r.text();
  if (!r.ok) throw new Error(`maker ${r.status}: ${body.slice(0, 200)}`);
  return JSON.parse(body) as T;
}
const base = (endpoint: string) => endpoint.replace(/\/+$/, '');

export const api = {
  info: (ep: string) => fetch(`${base(ep)}/v1/info`).then((r) => j<MakerInfo>(r)),
  quote: (ep: string, direction: 1 | 2, amount: bigint) =>
    fetch(`${base(ep)}/v1/quote?direction=${direction}&${direction === 1 ? 'lamports' : 'piconero'}=${amount}`).then((r) => j<SignedQuote>(r)),
  swap: <T>(ep: string, req: SwapRequest) =>
    fetch(`${base(ep)}/v1/swap`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(req) }).then((r) => j<T>(r)),
  status: (ep: string, escrow: string) => fetch(`${base(ep)}/v1/swap/${escrow}`).then((r) => j<MakerSwapStatus>(r)),
  relayRefund: (ep: string, escrow: string, secretHex: string) =>
    fetch(`${base(ep)}/v1/relay/refund`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ escrow, secret: secretHex }) }).then((r) => j<{ sig: string }>(r)),
};

export const watchtowerApi = {
  info: (url: string) => fetch(`${base(url)}/v1/info`).then((r) => j<{ pubkey: string; watching: number }>(r)),
  watch: (url: string, escrow: string, viewSecretHex: string) =>
    fetch(`${base(url)}/v1/watch`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ escrow, viewSecret: viewSecretHex }), signal: AbortSignal.timeout(10_000) }).then((r) => j<{ ok: true }>(r)),
  /** Neutral gas relay for an XMR->SOL claim: the relayer pays the fee; it is never the maker. */
  relayClaim: (url: string, txBase64: string) =>
    fetch(`${base(url)}/v1/relay/claim`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ tx: txBase64 }), signal: AbortSignal.timeout(20_000) }).then((r) => j<{ sig: string }>(r)),
};

/**
 * Register the swap's view key with watchtowers BEFORE locking. Returns the pubkeys that
 * acknowledged; the caller must refuse to lock with fewer than policy.minWatchtowers.
 */
export async function registerWatchtowers(towers: { url: string; pubkey: PublicKey }[], escrow: PublicKey, viewSecret: Uint8Array): Promise<PublicKey[]> {
  const acks = await Promise.all(towers.map((t) => watchtowerApi.watch(t.url, escrow.toBase58(), K.toHex(viewSecret)).then(() => t.pubkey).catch(() => null)));
  return acks.filter((x): x is PublicKey => !!x);
}

// ---------------------------------------------------------------- policy
export interface Policy {
  /** Smallest t0 the client accepts (seconds). Mainnet: >= 40 min so 10 Monero confs fit. */
  minT0Secs: number;
  /** Smallest claim window after t0. */
  minWindowSecs: number;
  /** Stop claiming this long before t1 (a reveal that lands late leaks the secret). */
  claimMarginSecs: number;
  /** SOL->XMR: refuse to lock unless this many watchtowers acknowledged the view key. */
  minWatchtowers: number;
}
/** Priority price on relayed claims: the most the relayers accept (watchtower.ts relayClaim), 800 lamports at 40k CU. */
export const RELAY_PRICE_MICRO = 20_000;
// minWatchtowers 0: since v1.5 a maker can only claim with the user's ready or an on-chain payment proof, so a
// SOL->XMR swap is safe with no watchtower online; one only speeds up a refund. We still register with any that answer.
export const MAINNET_POLICY: Policy = { minT0Secs: 40 * 60, minWindowSecs: 60 * 60, claimMarginSecs: 15 * 60, minWatchtowers: 0 };
/** SOL->ZEC is different: a watchtower broadcasts the user's pre-signed claim if the page is closed. */
export const ZEC_MIN_WATCHTOWERS = 1;

// ---------------------------------------------------------------- quotes
export function checkQuote(sq: SignedQuote, makerAuthority: PublicKey, direction: 1 | 2, cfg: P.ConfigAccount, nowSecs: number): string | null {
  const q = sq.quote;
  if (q.v !== 1) return 'unknown quote version';
  if (q.maker !== makerAuthority.toBase58()) return 'quote is from a different maker';
  if (q.direction !== direction) return 'wrong direction';
  if (q.expiresAt < nowSecs + 5) return 'quote expired';
  if (q.feeBps !== cfg.feeBps && q.feeBps !== cfg.holderFeeBps) return 'quote fee does not match the program';
  if (!K.verifyQuote(q, sq.sig, makerAuthority.toBytes())) return 'bad quote signature';
  if (BigInt(q.lamports) <= 0n || BigInt(q.piconero) <= 0n) return 'empty quote';
  return null;
}

// ---------------------------------------------------------------- SOL -> XMR
export interface PreparedLock {
  escrow: PublicKey;
  lock: P.LockParams;
  ixs: TransactionInstruction[];  // [consent (ed25519), lock]
  shared: ReturnType<typeof K.sharedWallet>;
}

/**
 * Handshake + lock preparation. Verifies everything the maker returned before anything is signed.
 * `half` is deriveHalf(root, swapId); its view scalar becomes the shared view key.
 */
export async function prepareSolToXmr(args: {
  pid: PublicKey; endpoint: string; makerAuthority: PublicKey; cfg: P.ConfigAccount; policy: Policy;
  sq: SignedQuote; swapId: Uint8Array; locker: PublicKey; half: K.KeyHalf; net: K.MoneroNet;
  watchtowers: { url: string; pubkey: PublicKey }[]; nowSecs: number;
  /** Per-swap, consent-bound. Missing means ready-only; never accept a silent downgrade. */
  claimMode?: 'ready-only' | 'payment-proof';
}): Promise<PreparedLock & { watchtowers: PublicKey[] }> {
  const { pid, endpoint, makerAuthority, cfg, policy, sq, swapId, locker, half, net } = args;
  const err = checkQuote(sq, makerAuthority, 1, cfg, args.nowSecs);
  if (err) throw new Error(err);
  // Watchtowers first: no lock without at least policy.minWatchtowers acknowledgements. They go to the maker with the
  // request because a flagged (ready-only) lock's v2 consent binds them; a v1 consent ignores them.
  const escrow = P.pda.escrow(pid, locker, swapId);
  const acked = (await registerWatchtowers(args.watchtowers.slice(0, 2), escrow, half.view));
  if (acked.length < policy.minWatchtowers) throw new Error(`only ${acked.length} watchtower(s) online; refusing to lock without protection`);
  const res = await api.swap<SwapResponseSolToXmr>(endpoint, {
    quote: sq.quote, sig: sq.sig, swapId: K.toHex(swapId), taker: locker.toBase58(),
    takerSpendPub: K.toHex(half.spendPub), viewSecret: K.toHex(half.view), claimMode: args.claimMode ?? 'ready-only',
    watchtowers: acked.map((w) => w.toBase58()),
  });
  if (res.direction !== 1) throw new Error('maker answered for the wrong direction');
  const flags = args.claimMode === 'payment-proof' ? 0 : P.F.READY_ONLY;
  if ((res.flags ?? 0) !== flags) throw new Error('maker changed the selected claim mode');
  const makerSpendPub = K.fromHex(res.makerSpendPub);
  // Off-chain checks (the program re-checks prime order too).
  if (!K.isGoodPoint(makerSpendPub)) throw new Error('maker key is not a valid prime-order point');
  if (K.equalBytes(makerSpendPub, half.spendPub)) throw new Error('maker echoed our key');
  if (!K.isGoodPoint(K.pointAdd(makerSpendPub, half.spendPub))) throw new Error('maker key cancels ours (shared key would be unspendable)');
  if (res.feeBps !== sq.quote.feeBps) throw new Error('maker changed the fee');
  // The program computes the fee from the maker's on-chain $HALFKEY bond and the consent binds it,
  // so a wrong claim here only makes the lock fail; still reject anything outside the two tiers.
  if (res.feeBps !== cfg.feeBps && res.feeBps !== cfg.holderFeeBps) throw new Error('fee does not match the program');
  if (res.t0Secs < Math.max(cfg.minT0, policy.minT0Secs) || res.t0Secs > cfg.maxT0) throw new Error('maker asked for an unsafe t0');
  if (res.windowSecs < Math.max(cfg.minWindow, policy.minWindowSecs) || res.windowSecs > cfg.maxWindow) throw new Error('maker asked for an unsafe window');
  if (res.consentExpiry < args.nowSecs || res.consentExpiry > args.nowSecs + 600) throw new Error('bad consent expiry');
  const shared = K.sharedWallet(makerSpendPub, half.spendPub, half.view, net);
  if (shared.address !== res.sharedAddress) throw new Error('shared address mismatch');
  const lock: P.LockParams = {
    swapId, claimer: makerAuthority, direction: 1, amount: BigInt(sq.quote.lamports), xmrAmount: BigInt(sq.quote.piconero),
    claimPoint: makerSpendPub, refundPoint: half.spendPub, viewPub: shared.viewPub, quoteHash: K.quoteHash(sq.quote),
    t0Secs: res.t0Secs, windowSecs: res.windowSecs, watchtowers: acked,
    makerAuthority, consentExpiry: res.consentExpiry, feeBps: res.feeBps, flags,
  };
  const digest = P.consentDigest(pid, locker, lock);
  const sig = K.fromHex(res.consentSig);
  if (!ed25519.verify(sig, digest, makerAuthority.toBytes())) throw new Error('maker consent signature does not verify');
  return {
    escrow,
    lock,
    ixs: [P.ixConsent(makerAuthority, digest, sig), P.ixLockAny(pid, locker, lock)],
    shared,
    watchtowers: acked,
  };
}

// ---------------------------------------------------------------- XMR -> SOL deposit timing
/**
 * One rule, used by the maker (when it aborts) and the client (the deadline it shows):
 *   * the maker aborts a swap with no deposit SEEN (even unconfirmed) by createdAt + window + grace
 *     (taker no-show: frees the maker's SOL fast), and one whose deposit is not CONFIRMED by
 *     t0 - depositMarginSecs (it must be sure before the taker's claim opens at t0);
 *   * the client tells the user to send by min(createdAt + window, t0 - margin - CONFIRM_BUDGET):
 *     early enough that 10 confirmations (with variance) land before the maker's confirm deadline.
 */
export interface DepositTerms { depositMarginSecs: number; depositWindowSecs: number }
export const DEFAULT_DEPOSIT_TERMS: DepositTerms = { depositMarginSecs: 900, depositWindowSecs: 15 * 60 };
/** 10 Monero confirmations take ~20 min; budget 30 min for block-time variance. */
export const CONFIRM_BUDGET_SECS = 30 * 60;
/** Extra time the maker waits past the deposit window before calling a no-show (relay / mempool lag). */
export const NO_SHOW_GRACE_SECS = 5 * 60;
export function depositDeadline(createdAt: number, t0: number, t: DepositTerms = DEFAULT_DEPOSIT_TERMS): number {
  return Math.min(createdAt + t.depositWindowSecs, t0 - t.depositMarginSecs - CONFIRM_BUDGET_SECS);
}
export function makerAbortTimes(createdAt: number, t0: number, t: DepositTerms = DEFAULT_DEPOSIT_TERMS) {
  return { noShowAt: createdAt + t.depositWindowSecs + NO_SHOW_GRACE_SECS, unconfirmedAt: t0 - t.depositMarginSecs };
}
/** Smallest t0 a maker may use for XMR->SOL: the user gets at least 10 minutes to send. */
export const minXmrToSolT0 = (t: DepositTerms = DEFAULT_DEPOSIT_TERMS) => t.depositMarginSecs + CONFIRM_BUDGET_SECS + 10 * 60;

// ---------------------------------------------------------------- XMR -> SOL
/**
 * The maker locks SOL first. Before the user sends any XMR, verify the escrow on chain
 * (finalized) matches the deal exactly. Returns the deposit address.
 */
/**
 * XMR->SOL: check the maker's SOL lock before sending XMR. With the signed quote (`sq` +
 * `makerSpendPub` from the handshake) every term is checked against the deal. Resume mode (another
 * device, no quote): omit both; the escrow is checked against the keys this wallet derives (claim
 * point, view key, claimer), the maker's key on chain must be a good point that does not cancel
 * ours, and the timing rules are the same. Amounts are then whatever the escrow says (shown to the
 * user, who decides). Both modes need the maker's key proof (from the handshake, or the maker's
 * /v1/swap/<escrow>): without it the maker could pick its key from ours so that it alone can
 * spend the deposit.
 */
export async function verifyXmrToSolEscrow(args: {
  conn: Connection; pid: PublicKey; escrow: PublicKey; makerAuthority: PublicKey; sq?: SignedQuote;
  claimer: PublicKey; half: K.KeyHalf; makerSpendPub?: Uint8Array; net: K.MoneroNet; policy: Policy; nowSecs: number;
  /** The maker's advertised deposit terms (/v1/info); defaults are the protocol's. */
  terms?: DepositTerms;
  makerKeyProof: Uint8Array;
  /**
   * Refund towers: enough acks from the listed towers on this escrow's terms, or no deposit address. Without
   * them a paying user whose maker went dark could never get its XMR back (XMR->SOL is ready-only).
   */
  refundTowers?: { listed: { pubkey: PublicKey }[]; minAcks: number; acks: RT.Ack[]; maxT1Secs?: number };
}): Promise<{ escrow: P.EscrowAccount; depositAddress: string; depositBy: number }> {
  if (!!args.sq !== !!args.makerSpendPub) throw new Error('pass both the signed quote and the maker key, or neither (resume)');
  const a = await args.conn.getAccountInfo(args.escrow, 'finalized');
  if (!a || !a.owner.equals(args.pid)) throw new Error('escrow not finalized on chain yet');
  const e = P.decodeEscrow(a.data, args.escrow);
  const bad = (m: string) => { throw new Error(`escrow does not match the deal: ${m}`); };
  if (e.direction !== 2) bad('direction');
  if (e.state !== P.ST.LOCKED) bad('state');
  if (!e.claimer.equals(args.claimer)) bad('claimer');
  if (!e.locker.equals(args.makerAuthority) || !e.maker.equals(args.makerAuthority)) bad('maker');
  if (!K.equalBytes(e.claimPoint, args.half.spendPub)) bad('claim point');
  if (!K.equalBytes(e.viewPub, args.half.viewPub)) bad('view key');
  const makerSpendPub = args.makerSpendPub ?? e.refundPoint;
  if (args.sq) {
    const q = args.sq.quote;
    if (!K.equalBytes(e.refundPoint, makerSpendPub)) bad('refund point');
    if (e.amount < BigInt(q.lamports)) bad('amount');
    if (e.xmrAmount !== BigInt(q.piconero)) bad('xmr amount');
    if (!K.equalBytes(e.quoteHash, K.quoteHash(q))) bad('quote hash');
    if (e.feeBps !== q.feeBps) bad('fee');
    // An escrow created after the quote expired is not the one this quote opened (a closed escrow
    // re-locked at the same address would reuse a key half we already revealed).
    if (Number(e.createdAt) > q.expiresAt) bad('escrow is newer than the quote');
  } else if (!K.isGoodPoint(makerSpendPub)) bad('maker key on chain is not a valid point');
  if (!K.isGoodPoint(K.pointAdd(makerSpendPub, args.half.spendPub))) bad('maker key cancels ours');
  if (!K.verifyKeyProof(makerSpendPub, K.keyProofContext(args.pid.toBytes(), args.escrow.toBytes(), args.half.spendPub), args.makerKeyProof)) bad('maker did not prove its key');
  const t0 = Number(e.t0), t1 = Number(e.t1);
  if (t0 - args.nowSecs < args.policy.minT0Secs * 0.75) bad('too little time left to deposit');
  if (t1 - t0 < args.policy.minWindowSecs) bad('claim window too short');
  if (args.refundTowers) {
    // The XMR can sit until t1 before it comes back: bounded.
    if (t1 - args.nowSecs > (args.refundTowers.maxT1Secs ?? 12 * 3600)) bad('claim deadline too far out');
    const c = RT.checkAcks(args.refundTowers.acks ?? [], args.refundTowers.listed, args.pid, args.escrow, e, args.refundTowers.minAcks);
    if (!c.ok) bad(`refund towers: ${c.why}`);
  }
  const shared = K.sharedWallet(makerSpendPub, args.half.spendPub, args.half.view, args.net);
  const depositBy = depositDeadline(Number(e.createdAt), t0, args.terms);
  if (depositBy - args.nowSecs < 5 * 60) bad('too little time left to send XMR safely');
  return { escrow: e, depositAddress: shared.address, depositBy };
}

// ---------------------------------------------------------------- swap discovery + status
export async function findMySwaps(conn: Connection, pid: PublicKey, wallet: PublicKey): Promise<P.EscrowAccount[]> {
  const q = (offset: number, size: number) => conn.getProgramAccounts(pid, {
    commitment: 'confirmed',
    filters: [{ dataSize: size }, { memcmp: { offset, bytes: wallet.toBase58() } }],
  });
  // v1 and v2 (final round) escrows share the layout up to byte 448.
  const all = await Promise.all([P.ESCROW_LEN, P.ESCROW_LEN_V2].flatMap((n) => [q(P.OFF_ESCROW_LOCKER, n), q(P.OFF_ESCROW_CLAIMER, n)]));
  return all.flat().map((x) => P.decodeEscrow(x.account.data, x.pubkey))
    .sort((x, y) => Number(y.createdAt - x.createdAt));
}

export type Phase =
  | 'waiting-xmr'     // SOL locked, maker has not locked / confirmations pending
  | 'releasing'       // user said ready; maker claims any second
  | 'auto-release'    // past t0, maker can claim (hands-off path)
  | 'collect'         // maker claimed: user can collect XMR (no deadline)
  | 'refund'          // aborted or expired: user can take SOL back (no deadline)
  | 'refunded'
  | 'deposit'         // XMR->SOL: send XMR to the shared address
  | 'claim-sol'       // XMR->SOL: XMR confirmed / past t0: user claims SOL now
  | 'xmr-back'        // XMR->SOL refunded: user sweeps its XMR back
  | 'paid'            // pay link (payer side): the maker claimed, the recipient collects
  | 'done';

export function phaseOf(e: P.EscrowAccount, me: PublicKey, chainNow: number, policy: Policy): Phase {
  const iAmLocker = e.locker.equals(me);
  const past = (t: bigint) => chainNow >= Number(t);
  if ((e.flags & P.F.PAY) && iAmLocker) {
    // Pay link, payer side: the XMR belongs to the recipient; the payer only watches or refunds.
    switch (e.state) {
      case P.ST.LOCKED: return past(e.t1) ? 'refund' : past(e.t0) ? 'auto-release' : 'waiting-xmr';
      case P.ST.READY: return past(e.t1) ? 'refund' : 'releasing';
      case P.ST.CLAIMED: return 'paid';
      case P.ST.ABORTED: return 'refund';
      case P.ST.REFUNDED: return 'refunded';
    }
  }
  if (e.direction === 1 && iAmLocker) {
    switch (e.state) {
      // No committee: the maker can't claim without the user's release, which stays open until the late deadline.
      case P.ST.LOCKED: return past(e.t1) ? 'refund' : 'waiting-xmr';
      case P.ST.READY: return past(e.t1) ? 'refund' : 'releasing';
      case P.ST.CLAIMED: return 'collect';
      case P.ST.ABORTED: return 'refund';
      case P.ST.REFUNDED: return 'refunded';
    }
  }
  if (e.direction === 2 && !iAmLocker) {
    switch (e.state) {
      case P.ST.LOCKED:
      case P.ST.READY:
        if (chainNow >= Number(e.t1) - policy.claimMarginSecs) return 'xmr-back'; // too late to claim safely
        return e.state === P.ST.READY || past(e.t0) ? 'claim-sol' : 'deposit';
      case P.ST.CLAIMED: return 'done';
      case P.ST.ABORTED: return 'xmr-back';
      case P.ST.REFUNDED: return 'xmr-back';
    }
  }
  return 'done';
}

/**
 * The user's refund secret may leave the browser (to a relayer) only when no claim can ever
 * happen again: the escrow is Aborted, or t1 has passed, as seen at FINALIZED commitment.
 */
export async function refundSafe(conn: Connection, escrow: PublicKey): Promise<boolean> {
  const a = await conn.getAccountInfo(escrow, 'finalized');
  if (!a) return false;
  const e = P.decodeEscrow(a.data, escrow);
  if (e.state === P.ST.ABORTED) return true;
  if (e.state !== P.ST.LOCKED && e.state !== P.ST.READY) return false;
  const clock = await conn.getAccountInfo(new PublicKey('SysvarC1ock11111111111111111111111111111111'), 'finalized');
  const now = Number(clock!.data.readBigInt64LE(32));
  return now >= Number(e.t1);
}

/**
 * XMR->SOL claim with gas relayed by NEUTRAL relayers (watchtowers), never the maker: the claim
 * carries the user's secret, and a counterparty relayer could sweep the XMR and drop the tx.
 * The same claim is sent through every relayer at once (each as its own fee payer); one landing
 * is enough, the rest fail harmlessly. Refuses inside the claim margin.
 */
export async function relayClaimEverywhere(args: {
  conn: Connection; pid: PublicKey; escrow: P.EscrowAccount; claimer: { publicKey: PublicKey; sign: (tx: import('@solana/web3.js').Transaction) => Promise<import('@solana/web3.js').Transaction> };
  secret: Uint8Array; relayers: { url: string; pubkey: PublicKey }[]; policy: Policy; chainNowSecs: number;
  /** Proof mode past t0: the on-chain record of the user's deposit. */
  proof?: PublicKey;
}): Promise<string> {
  const { Transaction, ComputeBudgetProgram } = await import('@solana/web3.js');
  // Relaying needs extra headroom over a self-paid claim (3x the claim margin: 45 min on mainnet),
  // so a slow or dishonest relayer still leaves time to fund the wallet and claim directly.
  if (args.chainNowSecs >= Number(args.escrow.t1) - 3 * args.policy.claimMarginSecs) throw new Error('too close to the deadline to relay safely');
  const { blockhash } = await args.conn.getLatestBlockhash('confirmed');
  const attempts = args.relayers.map(async (r) => {
    const tx = new Transaction().add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: 40_000 }),
      ComputeBudgetProgram.setComputeUnitPrice({ microLamports: RELAY_PRICE_MICRO }),
      P.ixClaim(args.pid, args.claimer.publicKey, args.escrow.address!, args.escrow.maker, args.secret, args.proof),
    );
    tx.feePayer = r.pubkey;
    tx.recentBlockhash = blockhash;
    const signed = await args.claimer.sign(tx);
    return watchtowerApi.relayClaim(r.url, signed.serialize({ requireAllSignatures: false }).toString('base64')).then((x) => x.sig);
  });
  return Promise.any(attempts);
}

/** Rebuild this user's half for an escrow and prove it is the right one. */
export function myHalfFor(root: Uint8Array, e: P.EscrowAccount, me: PublicKey): K.KeyHalf {
  const half = K.deriveHalf(root, e.swapId);
  const mine = e.direction === 1 && e.locker.equals(me) ? e.refundPoint : e.claimPoint;
  if (!K.equalBytes(half.spendPub, mine)) throw new Error('this wallet did not create this swap (or signed a different key message)');
  if (!K.equalBytes(half.viewPub, e.viewPub)) throw new Error('view key mismatch');
  return half;
}

/** Full Monero spend key of the shared wallet once the other half is public on chain. */
export function fullSpendKey(e: P.EscrowAccount, half: K.KeyHalf): Uint8Array {
  if (e.state !== P.ST.CLAIMED && e.state !== P.ST.REFUNDED) throw new Error('other half not revealed yet');
  const s = K.scalarAdd(e.secret, half.spend);
  const want = K.pointAdd(e.claimPoint, e.refundPoint);
  if (!K.equalBytes(K.pub(s), want)) throw new Error('revealed secret does not complete the key');
  return s;
}

/** Monero restore height estimate from the escrow creation time (120 s blocks, with margin). */
export function restoreHeightFor(e: P.EscrowAccount, daemonHeight: number, nowSecs: number): number {
  const ago = Math.max(0, nowSecs - Number(e.createdAt));
  return Math.max(1, daemonHeight - Math.ceil(ago / 120) - 60);
}
