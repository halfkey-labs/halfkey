// Taker (user) side of HALFKEY's SOL <-> ZEC swaps (HTLC kind). Shared by the web client, the
// maker's tests and the regtest runner. Every check the user's safety depends on lives here, not
// in UI code. Chain access is passed in (a zebrad JSON-RPC `Rpc`, a Solana `Connection`).
//
// SOL -> ZEC (direction 4), the maker knows x:
//   1. quote -> POST /v1/zec/swap {claimPub}: the maker funds P2SH(HTLC(H, claim=user, refund=maker, L))
//      at once and signs the lock consent.
//   2. verifySolToZecOffer: script, keys, address, escrow, quote + consent signatures.
//   3. checkZecLock: >= minConf confirmations, unspent, value, and L far enough after t1 (no
//      network upgrade before L: it would void the pre-signed claim).
//   4. presignClaim -> watchtowers (POST /v1/zec/watch): signed now, completed with x later.
//   5. lock SOL ([consent, htlc_lock]). The maker claims with x; any watchtower (or this tab)
//      finishes the ZEC claim to the user's transparent address; the user's wallet shields it.
// ZEC -> SOL (direction 8), the user knows x (derived from the wallet signature, any device):
//   1. quote -> POST /v1/zec/swap {hashlock, refundPub}: the maker answers with its claim key and L.
//   2. verifyZecToSolOffer, then the user pays the HTLC address from any wallet.
//   3. presignRefund (after L) -> watchtowers. The maker sees minConf confirmations and locks SOL.
//   4. verifyZecToSolLock, then claim the SOL (relayed: the claim publishes x, which lets the
//      maker take the ZEC; the maker never relays it).
import { PublicKey, TransactionInstruction } from '@solana/web3.js';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils';
import * as Z from './zec.ts';
import * as H from './htlc.ts';
import { ixConsent } from './program.ts';

export const SOL_TO_ZEC = H.DIR_SOL_TO_ZEC;
export const ZEC_TO_SOL = H.DIR_ZEC_TO_SOL;

// ---------------------------------------------------------------- keys from the wallet root
/** Per-swap ZEC keys from the wallet root (keys.ts rootFromSignature): same wallet, same keys, any device. */
export function zecKeys(root: Uint8Array, swapId: Uint8Array) {
  const d = (label: string) => sha512(concatBytes(root, utf8ToBytes(label), swapId));
  const claimPriv = Z.privFrom(d('halfkey/zec/claim/v1'));
  const refundPriv = Z.privFrom(d('halfkey/zec/refund/v1'));
  const preimage = sha256(d('halfkey/zec/preimage/v1'));
  return { claimPriv, claimPub: Z.pubOf(claimPriv), refundPriv, refundPub: Z.pubOf(refundPriv), preimage, hashlock: sha256(preimage) };
}

// ---------------------------------------------------------------- quotes
export interface ZecQuote {
  v: 1;
  kind: 'zec';
  maker: string;          // maker authority (base58)
  direction: 4 | 8;
  lamports: string;       // SOL side, u64 as string
  zats: string;           // ZEC side, zatoshis
  feeBps: number;
  expiresAt: number;      // unix seconds
  nonce: string;          // hex
  zecNet: Z.ZecNet;
}
export function zecQuoteBytes(q: ZecQuote): Uint8Array {
  const c = { v: q.v, kind: q.kind, maker: q.maker, direction: q.direction, lamports: q.lamports, zats: q.zats, feeBps: q.feeBps, expiresAt: q.expiresAt, nonce: q.nonce, zecNet: q.zecNet };
  return utf8ToBytes('halfkey-zec-quote-v1:' + JSON.stringify(c));
}
export const zecQuoteHash = (q: ZecQuote) => sha256(zecQuoteBytes(q));
export const signZecQuote = (q: ZecQuote, makerSecret32: Uint8Array) => bytesToHex(ed25519.sign(zecQuoteBytes(q), makerSecret32));
export function verifyZecQuote(q: ZecQuote, sigHex: string, makerPub: Uint8Array): boolean {
  try { return ed25519.verify(hexToBytes(sigHex), zecQuoteBytes(q), makerPub); } catch { return false; }
}

// ---------------------------------------------------------------- maker HTTP API (v1, /v1/zec/*)
export interface ZecInfo {
  v: 1;
  maker: string;
  programId: string;
  zecNet: Z.ZecNet;
  directions: number;     // bitmask 4 = SOL->ZEC, 8 = ZEC->SOL
  minLamports: string;
  maxLamports: string;
  zatPerSol: number;      // indicative mid
  feeBps: number;
  t1Secs: number;
  minConf: number;
  online: boolean;
  paused?: string;        // set while near a network upgrade
  /** false: the desk's price feed is stale and it refuses quotes (HTTP 503). Undefined = older desk. */
  priceLive?: boolean;
}
export interface SolToZecRequest {
  quote: ZecQuote; sig: string; swapId: string; taker: string; claimPub: string;
  /** The taker's wallet over offerRequestMessage: this request makes the maker lock real ZEC. */
  takerSig: string;
  /** Paying with a coin (sold when the SOL locks, on mainnet): the wallet holds this mint rather than the SOL. */
  coinMint?: string;
  /** How much of it (base units): the maker checks the wallet holds that much and that it covers the lock. */
  coinAmount?: string;
}
/** What the taker's wallet signs to ask for a ZEC lock: readable in the wallet prompt, moves nothing, one quote and swap only. */
export function offerRequestMessage(q: ZecQuote, swapId: string, claimPub: string): Uint8Array {
  const ask = q.direction === ZEC_TO_SOL ? 'ask this maker for a ZEC deposit address' : 'ask this maker to lock ZEC for your swap';
  return new TextEncoder().encode(`HALFKEY: ${ask}.\nSigning sends nothing.\n\nQuote ${Z.hex(zecQuoteHash(q))}\nSwap ${swapId}\nKey ${claimPub}`);
}
export function verifyOfferRequest(q: ZecQuote, swapId: string, claimPub: string, takerSig: string, taker: Uint8Array): boolean {
  try { return ed25519.verify(Z.unhex(takerSig), offerRequestMessage(q, swapId, claimPub), taker); } catch { return false; }
}
export interface SolToZecOffer {
  direction: 4;
  escrow: string;
  hashlock: string;
  redeem: string;
  htlcAddress: string;
  fundTxid: string;
  fundVout: number;
  lockHeight: number;
  t1Secs: number;
  consentExpiry: number;
  consentSig: string;
  feeBps: number;
}
export interface ZecToSolRequest {
  quote: ZecQuote; sig: string; swapId: string; taker: string; hashlock: string; refundPub: string;
  /** The taker's wallet over offerRequestMessage(q, swapId, zecToSolKeys(hashlock, refundPub)). */
  takerSig: string;
}
export const zecToSolKeys = (hashlock: string, refundPub: string) => `${hashlock}:${refundPub}`;
export interface ZecToSolOffer {
  direction: 8;
  escrow: string;
  redeem: string;
  htlcAddress: string;
  lockHeight: number;
  /** Pay before this unix time; the maker refuses to lock SOL for later deposits. */
  payBy: number;
}
export interface ZecSwapStatus {
  swapId: string;
  direction: 4 | 8;
  phase: string;
  escrow: string;
  fundTxid?: string;
  fundVout?: number;
  confirmations?: number;
  required?: number;
  zecClaimTxid?: string;
  zecRefundTxid?: string;
  solSig?: string;
  note?: string;
  /** The HTLC and its signed quote: with the wallet's key they let another device finish or refund the swap. */
  redeem?: string;
  lockHeight?: number;
  quote?: ZecQuote;
  sig?: string;
}

// ---------------------------------------------------------------- policy
export interface ZecPolicy {
  /** Confirmations of the HTLC funding before the other side locks. */
  minConf: number;
  /** Required gap between the Solana deadline t1 and the ZEC refund height, in seconds. */
  marginSecs: number;
  /** Blocks may come faster than the target: count only this share of the target time. */
  speed: number;
  /** Never claim SOL this close to t1 (a failed claim still publishes x). */
  claimMarginSecs: number;
  /** Longest a user's ZEC may wait for its refund (ZEC -> SOL), seconds. */
  maxRefundWaitSecs: number;
}
/** Mainnet after NU7: 25 s blocks and a 600-block reorg cap; 60 blocks is ~25 minutes. */
export const MAINNET_POLICY: ZecPolicy = { minConf: 60, marginSecs: 2 * 3600, speed: 0.75, claimMarginSecs: 900, maxRefundWaitSecs: 24 * 3600 };

/** No network upgrade may activate this long after a refund height (a late refund broadcast must stay valid). */
export const REFUND_UPGRADE_BUFFER_SECS = 6 * 3600;
/** The last height a pre-signed spend of this HTLC may need to be mined at, plus the buffer. */
export const upgradeHorizon = (ups: Z.Upgrade[], lockHeight: number) => Z.heightAfter(ups, lockHeight, REFUND_UPGRADE_BUFFER_SECS);

/**
 * The ZEC refund height is safely after `t1Abs` (unix) as seen from `now` and the tip, and no
 * network upgrade activates before it (plus a buffer: a refund with nLockTime L is mined at L+1 or
 * later, and a branch change voids every pre-signed spend).
 */
export function lockHeightSafe(ups: Z.Upgrade[], tip: number, now: number, lockHeight: number, t1Abs: number, p: ZecPolicy): string | null {
  const up = Z.upgradeBetween(ups, tip, upgradeHorizon(ups, lockHeight));
  if (up) return `network upgrade ${up.name} at ${up.height} before the refund height: pre-signed spends would be void`;
  const est = Z.secondsUntil(ups, tip, lockHeight) * p.speed;
  if (now + est < t1Abs + p.marginSecs) return `ZEC refund height ${lockHeight} is too soon after the Solana deadline`;
  return null;
}

// ---------------------------------------------------------------- SOL -> ZEC
export interface SolToZecCtx {
  pid: PublicKey;
  taker: PublicKey;
  swapId: Uint8Array;
  quote: ZecQuote;
  quoteSig: string;
  claimPub: Uint8Array;
  zecNet: Z.ZecNet;
  now: number;
}

/** Check everything about the maker's offer that needs no chain; returns the lock params. */
export function verifySolToZecOffer(o: SolToZecOffer, x: SolToZecCtx): H.HtlcLockParams {
  const q = x.quote;
  const maker = new PublicKey(q.maker);
  if (q.direction !== SOL_TO_ZEC || o.direction !== SOL_TO_ZEC) throw new Error('wrong direction');
  if (q.zecNet !== x.zecNet) throw new Error('quote is for another Zcash network');
  if (!verifyZecQuote(q, x.quoteSig, maker.toBytes())) throw new Error('bad quote signature');
  const redeem = Z.unhex(o.redeem);
  const t = Z.parseHtlcScript(redeem);
  if (Z.hex(t.hashlock) !== o.hashlock) throw new Error('hashlock mismatch');
  if (Z.hex(t.claimPub) !== Z.hex(x.claimPub)) throw new Error('the HTLC does not pay your claim key');
  if (t.lockHeight !== o.lockHeight) throw new Error('lock height mismatch');
  if (Z.htlcAddress(x.zecNet, redeem) !== o.htlcAddress) throw new Error('HTLC address mismatch');
  const escrow = H.htlcPda(x.pid, x.taker, x.swapId);
  if (escrow.toBase58() !== o.escrow) throw new Error('escrow address mismatch');
  if (o.feeBps !== q.feeBps) throw new Error('fee differs from the quote');
  if (!(o.consentExpiry > x.now + 60)) throw new Error('consent about to expire');
  const lock: H.HtlcLockParams = {
    swapId: x.swapId, claimer: maker, direction: SOL_TO_ZEC, amount: BigInt(q.lamports), zecAmount: BigInt(q.zats),
    hashlock: t.hashlock, quoteHash: zecQuoteHash(q), t1Secs: o.t1Secs, consentExpiry: o.consentExpiry, makerAuthority: maker, feeBps: o.feeBps,
  };
  const digest = H.htlcConsentDigest(x.pid, x.taker, lock);
  if (!ed25519.verify(hexToBytes(o.consentSig), digest, maker.toBytes())) throw new Error('bad consent signature');
  return lock;
}

/** The ZEC lock on chain: confirmed, unspent, the full amount, and a refund height far enough after t1. */
/**
 * Run it right before signing the lock: `lockBy` is the latest time the lock will be sent (t1 is
 * counted from it). Default `now`; pass the consent expiry to check the worst case.
 */
export async function checkZecLock(call: Z.Rpc, ups: Z.Upgrade[], o: SolToZecOffer, lock: H.HtlcLockParams, now: number, p: ZecPolicy, lockBy = now): Promise<string | null> {
  const f = await Z.checkFunding(call, o.fundTxid, o.fundVout, Z.unhex(o.redeem));
  if (f.spent) return 'the HTLC output is already spent';
  if (f.value < lock.zecAmount) return 'the HTLC holds less ZEC than quoted';
  if (f.confirmations < p.minConf) return `waiting for confirmations (${f.confirmations}/${p.minConf})`;
  const tip = Number((await call('getblockchaininfo')).blocks);
  if (lockBy > lock.consentExpiry) return 'the maker\'s consent expires before the lock';
  return lockHeightSafe(ups, tip, now, o.lockHeight, Math.max(now, lockBy) + lock.t1Secs, p);
}

/** The user's ZEC claim, signed now (no x yet), paying `dest` (a transparent address). */
export function presignClaim(o: SolToZecOffer, value: bigint, claimPriv: Uint8Array, dest: string, net: Z.ZecNet, branch: number, marginal = 5000n): Z.Presigned {
  return Z.presign({ kind: 'claim', branch, txid: o.fundTxid, vout: o.fundVout, value, redeem: Z.unhex(o.redeem), outScript: Z.addressScript(dest, net), priv: claimPriv, marginal });
}

/** [consent, htlc_lock]: one wallet prompt. */
export function solToZecLockIxs(pid: PublicKey, taker: PublicKey, lock: H.HtlcLockParams, consentSig: string): TransactionInstruction[] {
  const digest = H.htlcConsentDigest(pid, taker, lock);
  return [ixConsent(lock.makerAuthority, digest, hexToBytes(consentSig)), H.ixHtlcLock(pid, taker, lock)];
}

// ---------------------------------------------------------------- ZEC -> SOL
export interface ZecToSolCtx {
  pid: PublicKey;
  swapId: Uint8Array;
  quote: ZecQuote;
  quoteSig: string;
  keys: ReturnType<typeof zecKeys>;
  zecNet: Z.ZecNet;
  now: number;
  tip: number;
  ups: Z.Upgrade[];
  policy: ZecPolicy;
}

/** The deposit address really is our HTLC (our hashlock, our refund key) with a sane refund height. */
export function verifyZecToSolOffer(o: ZecToSolOffer, x: ZecToSolCtx): Z.HtlcTerms {
  const q = x.quote;
  const maker = new PublicKey(q.maker);
  if (q.direction !== ZEC_TO_SOL || o.direction !== ZEC_TO_SOL) throw new Error('wrong direction');
  if (q.zecNet !== x.zecNet) throw new Error('quote is for another Zcash network');
  if (!verifyZecQuote(q, x.quoteSig, maker.toBytes())) throw new Error('bad quote signature');
  const redeem = Z.unhex(o.redeem);
  const t = Z.parseHtlcScript(redeem);
  if (Z.hex(t.hashlock) !== Z.hex(x.keys.hashlock)) throw new Error('the HTLC is not locked to your secret');
  if (Z.hex(t.refundPub) !== Z.hex(x.keys.refundPub)) throw new Error('the HTLC does not refund to your key');
  if (Z.htlcAddress(x.zecNet, redeem) !== o.htlcAddress) throw new Error('deposit address mismatch');
  if (H.htlcPda(x.pid, maker, x.swapId).toBase58() !== o.escrow) throw new Error('escrow address mismatch');
  const up = Z.upgradeBetween(x.ups, x.tip, upgradeHorizon(x.ups, t.lockHeight));
  if (up) throw new Error(`network upgrade ${up.name} before the refund height: try again after it`);
  if (Z.secondsUntil(x.ups, x.tip, t.lockHeight) > x.policy.maxRefundWaitSecs) throw new Error('refund height too far away');
  return t;
}

/** The user's ZEC refund (valid from the lock height), for the watchtowers. */
export function presignRefund(o: ZecToSolOffer, fundTxid: string, vout: number, value: bigint, refundPriv: Uint8Array, dest: string, net: Z.ZecNet, branch: number, marginal = 5000n): Z.Presigned {
  return Z.presign({ kind: 'refund', branch, txid: fundTxid, vout, value, redeem: Z.unhex(o.redeem), outScript: Z.addressScript(dest, net), priv: refundPriv, marginal });
}

/** Before revealing x: the maker's SOL lock pays us, for our hashlock, and is claimable now. */
/**
 * Another device, no local record: rebuild a ZEC -> SOL swap from the maker's status, trusting nothing
 * in it. The quote must be the maker's and the escrow's, and the script must pay this wallet's refund
 * key under this wallet's hash. Throws when anything differs.
 */
export function recoverZecToSol(h: H.HtlcAccount, st: ZecSwapStatus, keys: { hashlock: Uint8Array; refundPub: Uint8Array }, net: Z.ZecNet): { offer: ZecToSolOffer; quote: ZecQuote; sig: string } {
  if (h.direction !== ZEC_TO_SOL) throw new Error('not a ZEC -> SOL swap');
  if (!st.redeem || !st.quote || !st.sig || st.lockHeight == null) throw new Error('the maker has no record to rebuild this swap from');
  if (st.quote.direction !== ZEC_TO_SOL || st.quote.zecNet !== net || st.quote.maker !== h.maker.toBase58() || !verifyZecQuote(st.quote, st.sig, h.maker.toBytes())) throw new Error('not this maker\'s quote');
  if (Z.hex(zecQuoteHash(st.quote)) !== Z.hex(h.quoteHash)) throw new Error('that quote is not this swap\'s');
  const redeem = Z.unhex(st.redeem), t = Z.parseHtlcScript(redeem);
  if (Z.hex(t.hashlock) !== Z.hex(keys.hashlock) || Z.hex(h.hashlock) !== Z.hex(keys.hashlock)) throw new Error('this wallet did not start this swap');
  if (Z.hex(t.refundPub) !== Z.hex(keys.refundPub)) throw new Error('that script does not refund to this wallet');
  if (t.lockHeight !== st.lockHeight) throw new Error('the refund block differs from the script');
  return { offer: { direction: ZEC_TO_SOL, escrow: h.address!.toBase58(), redeem: st.redeem, htlcAddress: Z.htlcAddress(net, redeem), lockHeight: t.lockHeight, payBy: 0 }, quote: st.quote, sig: st.sig };
}

// ---------------------------------------------------------------- another device, before anything is on Solana
/**
 * What the wallet signs to read its own swaps from one maker. Bound to the maker (no replay at another desk),
 * the wallet (the desk lists only the signer's), a time and a one-use nonce (no replay at this desk).
 */
export function listSwapsMessage(maker: string, wallet: string, at: number, nonce: string): Uint8Array {
  return new TextEncoder().encode(`HALFKEY: list my ZEC swaps at this maker.\nSigning sends nothing.\n\nMaker ${maker}\nWallet ${wallet}\nTime ${at}\nNonce ${nonce}`);
}
export function verifyListSwaps(maker: string, wallet: string, at: number, nonce: string, sig: string): boolean {
  try { return ed25519.verify(Z.unhex(sig), listSwapsMessage(maker, wallet, at, nonce), new PublicKey(wallet).toBytes()); } catch { return false; }
}
/** The same for reading the copies a watchtower keeps: bound to that watchtower. */
export function listCopiesMessage(tower: string, wallet: string, at: number, nonce: string): Uint8Array {
  return new TextEncoder().encode(`HALFKEY: list my ZEC swaps at this watchtower.\nSigning sends nothing.\n\nWatchtower ${tower}\nWallet ${wallet}\nTime ${at}\nNonce ${nonce}`);
}
export function verifyListCopies(tower: string, wallet: string, at: number, nonce: string, sig: string): boolean {
  try { return ed25519.verify(Z.unhex(sig), listCopiesMessage(tower, wallet, at, nonce), new PublicKey(wallet).toBytes()); } catch { return false; }
}
/**
 * A copy of a ZEC -> SOL swap's script for the watchtowers, handed over before the deposit address is shown. The
 * chain only ever shows the script's hash, so without a copy a lost browser and a gone maker would lose the deposit.
 * Nothing in it can spend: a refund still needs the wallet's key. `takerSig` is the signature the wallet already gave for the request.
 */
export interface ZecScriptCopy { wallet: string; takerSig: string; swapId: string; hashlock: string; refundPub: string; quote: ZecQuote; sig: string; offer: ZecToSolOffer }
/** One open swap as the desk lists it: only what the taker's own device got when it started the swap. */
export interface ZecResumeItem {
  swapId: string; direction: 4 | 8; createdAt: number; quote: ZecQuote; sig: string; offer: SolToZecOffer | ZecToSolOffer;
  /** The maker closed this offer and won't lock SOL for it. Listed because a payment to it is still the wallet's, to refund. */
  closed?: boolean;
}
/**
 * Check a listed ZEC -> SOL swap against this wallet's keys, trusting nothing in it (the maker may be lying or
 * another maker's data may be replayed): the maker's own quote, this wallet's hash and refund key, the escrow
 * that maker and swap id derive to. Throws when anything differs.
 */
export function checkResumedZecToSol(item: ZecResumeItem, x: { pid: PublicKey; maker: PublicKey; keys: { hashlock: Uint8Array; refundPub: Uint8Array }; net: Z.ZecNet }): ZecToSolOffer {
  const o = item.offer as ZecToSolOffer, q = item.quote;
  if (item.direction !== ZEC_TO_SOL || o.direction !== ZEC_TO_SOL || q.direction !== ZEC_TO_SOL || q.zecNet !== x.net || q.maker !== x.maker.toBase58() || !verifyZecQuote(q, item.sig, x.maker.toBytes())) throw new Error('not this maker\'s quote');
  const redeem = Z.unhex(o.redeem), t = Z.parseHtlcScript(redeem);
  if (Z.hex(t.hashlock) !== Z.hex(x.keys.hashlock)) throw new Error('this wallet did not start this swap');
  if (Z.hex(t.refundPub) !== Z.hex(x.keys.refundPub)) throw new Error('that script does not refund to this wallet');
  if (t.lockHeight !== o.lockHeight) throw new Error('the refund block differs from the script');
  if (o.htlcAddress !== Z.htlcAddress(x.net, redeem)) throw new Error('the deposit address differs from the script');
  if (o.escrow !== H.htlcPda(x.pid, x.maker, Z.unhex(item.swapId)).toBase58()) throw new Error('the escrow is not this swap\'s');
  return o;
}

export function verifyZecToSolLock(h: H.HtlcAccount, x: { claimer: PublicKey; quote: ZecQuote; hashlock: Uint8Array; now: number; policy: ZecPolicy }): string | null {
  if (h.direction !== ZEC_TO_SOL) return 'not a ZEC -> SOL escrow';
  if (h.state !== 1) return 'escrow not open';
  if (!h.claimer.equals(x.claimer)) return 'escrow pays someone else';
  if (h.maker.toBase58() !== x.quote.maker || !h.locker.equals(h.maker)) return 'escrow not locked by the quoted maker';
  if (Z.hex(h.hashlock) !== Z.hex(x.hashlock)) return 'escrow hashlock differs';
  if (h.amount < BigInt(x.quote.lamports)) return 'less SOL than quoted';
  if (h.feeBps > x.quote.feeBps) return 'fee above the quote';
  if (x.now >= Number(h.t1) - x.policy.claimMarginSecs) return 'too close to the deadline to claim safely';
  return null;
}
