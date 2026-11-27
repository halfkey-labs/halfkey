// Shielded ZEC spends for HALFKEY's ZEC leg: the user's pre-signed HTLC claim (SOL -> ZEC) or
// refund (ZEC -> SOL) pays straight into an Ironwood note at the user's unified address. Built
// and Halo2-proven where the user is (browser Web Worker, or Node), by the WASM module in
// zecwasm/ (librustzcash: zcash_primitives 0.31 / orchard 0.16). Pure-JS parts here: the fee, the
// secp256k1 signature, the scriptSig splice, and every check a watchtower runs before holding one.
//
// What a watchtower gets (ShieldedPresigned) and what it can do with it:
//  * the funding outpoint and redeem script (public on chain anyway once spent),
//  * the full v6 transaction with an empty scriptSig: transparent input + Ironwood actions whose
//    note is encrypted to the user only (no outgoing viewing key: not even the user's own OVK),
//  * the user's signature over the ZIP 244 digest, which covers the Ironwood bundle digest.
// It can only add x (claim) or nothing (refund) to the scriptSig and broadcast. It never learns the
// recipient address, the note value is hidden in the pool (only the amount leaving the HTLC is
// public), and it cannot redirect or alter the output without voiding the signature.
import { sha256 } from '@noble/hashes/sha256';
import * as Z from './zec.ts';

/** The exports of zecwasm (wasm-bindgen, --target web). The caller initialises the module. */
export interface ZecWasm {
  prepareProver(): number;
  buildShieldedSpend(req: string): string;
  inspectSpend(req: string): string;
  uaReceiver(ua: string, net: string): string;
}

export const V6_HEADER = 0x80000006;
/** Ironwood actions in our spends (one output, padded to the default 2; both look alike). */
export const SHIELDED_ACTIONS = 2;
/**
 * Anchor depth: the dummy spends' anchor comes from a block this deep. A pre-signed spend's proof
 * commits to its anchor, so the anchor block must never be reorged away (zebrad finalises at 100
 * blocks; 720 leaves a wide margin). Any earlier final Ironwood root stays valid forever.
 */
export const ANCHOR_DEPTH_MAINNET = 720;
/** Testnet has had deep reorgs: never shallower than zebrad's finality depth. */
export const ANCHOR_DEPTH_TESTNET = 100;
export const anchorDepth = (net: Z.ZecNet) => (net === 'mainnet' ? ANCHOR_DEPTH_MAINNET : net === 'testnet' ? ANCHOR_DEPTH_TESTNET : 10);

/** A unified address (ZIP 316) on `net`, by its human-readable part. Full check: ZecWasm.uaReceiver. */
export function looksUnified(addr: string, net: Z.ZecNet): boolean {
  const hrp = net === 'mainnet' ? 'u1' : net === 'testnet' ? 'utest1' : 'uregtest1';
  return addr.trim().toLowerCase().startsWith(hrp);
}

export interface ShieldedPresigned {
  v: 2;
  shielded: true;
  kind: 'claim' | 'refund';
  branch: number;
  /** Funding outpoint (display-order txid) and its value in zatoshis. */
  txid: string;
  vout: number;
  value: string;
  redeem: string;     // hex
  lockTime: number;   // 0 for a claim, lockHeight for a refund
  /** The v6 transaction, input 0 with an EMPTY scriptSig, hex. */
  raw: string;
  /** Its txid (final: ZIP 244 does not hash scriptSigs). */
  spendTxid: string;
  /** Zatoshis entering the Ironwood pool (value - fee). */
  outValue: string;
  /** Height whose final Ironwood root is the proof's anchor (holders check it on their own node). */
  anchorHeight: number;
  sig: string;        // hex DER + sighash type
}
export type AnyPresigned = Z.Presigned | ShieldedPresigned;
export const isShielded = (p: AnyPresigned): p is ShieldedPresigned => (p as ShieldedPresigned).v === 2 && (p as ShieldedPresigned).shielded === true;

/** The final scriptSig for one of our HTLC spends (73-byte DER worst case when sizing). */
function scriptSigFor(kind: 'claim' | 'refund', sig: Uint8Array, redeem: Uint8Array, x?: Uint8Array) {
  return kind === 'claim' ? Z.scriptSigClaim(sig, x ?? new Uint8Array(32), redeem) : Z.scriptSigRefund(sig, redeem);
}

/** ZIP 317 for 1 transparent P2SH input (sized for its final scriptSig) + the Ironwood actions. */
export function shieldedFee(kind: 'claim' | 'refund', redeem: Uint8Array, marginal = 5000n, actions = SHIELDED_ACTIONS): bigint {
  const ss = scriptSigFor(kind, new Uint8Array(73), redeem);
  const inSize = 36 + Z.compactSize(ss.length).length + ss.length + 4;
  const logical = Math.ceil(inSize / 150) + actions;
  return marginal * BigInt(Math.max(2, logical));
}

/**
 * Ironwood anchor of the final root at `height`, from zebrad. For the Orchard-family trees zebrad
 * prints the root in its internal (little-endian repr) byte order, unlike Sapling: no reversal.
 */
export async function ironwoodAnchor(call: Z.Rpc, height: number): Promise<string> {
  const ts = await call('z_gettreestate', [String(height)]);
  const root = ts?.ironwood?.commitments?.finalRoot;
  if (typeof root !== 'string' || !/^[0-9a-f]{64}$/i.test(root)) throw new Error('the ZEC node has no Ironwood tree at that height (needs NU6.3)');
  return root.toLowerCase();
}
/** The anchor height for a pre-signed spend: deep enough that no reorg can remove it. */
export function anchorHeight(tip: number, net: Z.ZecNet, ups: Z.Upgrade[], depth = anchorDepth(net)): number {
  const nu63 = ups.find((u) => u.name === 'NU6.3')?.height ?? 1;
  return Math.max(nu63, tip - depth);
}

export interface ShieldedSpendArgs {
  kind: 'claim' | 'refund';
  branch: number;
  txid: string;
  vout: number;
  value: bigint;
  redeem: Uint8Array;
  /** The user's unified address (its Orchard-family receiver gets the note). */
  ua: string;
  net: Z.ZecNet;
  priv: Uint8Array;
  /** From ironwoodAnchor(anchorHeight(...)). */
  anchor: string;
  /** The height that anchor is the final root of. */
  anchorHeight: number;
  marginal?: bigint;
}

/**
 * Build + prove + sign one shielded spend of an HTLC output (slow: Halo2 proving, 10-30 s in a
 * browser). Run it in a Worker in the web client. The key must be the HTLC's claim/refund key.
 */
export function presignShielded(w: ZecWasm, a: ShieldedSpendArgs): ShieldedPresigned {
  const t = Z.parseHtlcScript(a.redeem);
  const want = a.kind === 'claim' ? t.claimPub : t.refundPub;
  if (Z.hex(Z.pubOf(a.priv)) !== Z.hex(want)) throw new Error(`key does not match the HTLC ${a.kind} key`);
  const recipient = w.uaReceiver(a.ua, a.net);
  const fee = shieldedFee(a.kind, a.redeem, a.marginal ?? 5000n);
  if (a.value - fee < Z.DUST) throw new Error('HTLC output too small to spend');
  const lockTime = a.kind === 'refund' ? t.lockHeight : 0;
  const tpl = JSON.parse(w.buildShieldedSpend(JSON.stringify({
    branch: a.branch, lockTime, sequence: a.kind === 'refund' ? Z.SEQ_LOCKTIME : Z.SEQ_FINAL,
    prevTxid: a.txid, vout: a.vout, value: Number(a.value), scriptPubKey: Z.hex(Z.p2sh(a.redeem)), scriptCode: Z.hex(a.redeem),
    recipient, fee: Number(fee), anchor: a.anchor,
  }))) as { raw: string; txid: string; sighash: string; outValue: number };
  if (BigInt(tpl.outValue) !== a.value - fee) throw new Error('builder output value mismatch');
  const sig = Z.sign(Z.unhex(tpl.sighash), a.priv);
  return {
    v: 2, shielded: true, kind: a.kind, branch: a.branch, txid: a.txid, vout: a.vout, value: a.value.toString(),
    redeem: Z.hex(a.redeem), lockTime, raw: tpl.raw, spendTxid: tpl.txid, outValue: (a.value - fee).toString(), anchorHeight: a.anchorHeight, sig: Z.hex(sig),
  };
}

export interface Inspection {
  txid: string; version: number; lockTime: number; expiryHeight: number;
  inputs: { prevTxid: string; vout: number; sequence: number; scriptSig: string }[];
  transparentOutputs: number; hasSapling: boolean; hasOrchard: boolean;
  ironwoodActions: number; ironwoodValueIn: number; sighash: string; anchor: string | null; proofOk: boolean | null;
}

/** Most a shielded HTLC spend may pay in fees (zatoshis); anything above is refused. */
export const MAX_SHIELDED_FEE = 200_000n;

/**
 * Everything a watchtower (or the user's other device) checks before holding a shielded spend:
 * the exact template, the outpoint, lock time and sequence, an empty scriptSig, no transparent or
 * other-pool outputs (all value goes into Ironwood), a sane fee, the user's signature over the
 * recomputed ZIP 244 digest, and (verifyProof) the Halo2 proof and the bundle signatures.
 */
export function verifyShieldedPresigned(w: ZecWasm, p: ShieldedPresigned, opts: { verifyProof?: boolean; hashlock?: Uint8Array } = {}): Z.HtlcTerms {
  if (!isShielded(p) || (p.kind !== 'claim' && p.kind !== 'refund')) throw new Error('bad presigned');
  if (!/^[0-9a-f]+$/i.test(p.raw) || p.raw.length > 64_000) throw new Error('bad presigned');
  const redeem = Z.unhex(p.redeem);
  const t = Z.parseHtlcScript(redeem);
  if (opts.hashlock && Z.hex(t.hashlock) !== Z.hex(opts.hashlock)) throw new Error('different hashlock');
  const wantLock = p.kind === 'refund' ? t.lockHeight : 0;
  if (p.lockTime !== wantLock) throw new Error('bad lock time');
  const raw = Z.unhex(p.raw);
  const dv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  if (raw.length < 60 || dv.getUint32(0, true) !== V6_HEADER || dv.getUint32(8, true) !== p.branch) throw new Error('not a v6 transaction for this branch');
  const ins = JSON.parse(w.inspectSpend(JSON.stringify({
    raw: p.raw, branch: p.branch, value: Number(p.value), scriptPubKey: Z.hex(Z.p2sh(redeem)), scriptCode: p.redeem, verifyProof: !!opts.verifyProof,
  }))) as Inspection;
  if (ins.version !== 6 || ins.txid !== p.spendTxid) throw new Error('txid mismatch');
  if (ins.lockTime !== wantLock || ins.expiryHeight !== 0) throw new Error('bad lock time or expiry');
  if (ins.inputs.length !== 1) throw new Error('must spend exactly the HTLC output');
  const i0 = ins.inputs[0];
  if (i0.prevTxid !== p.txid || i0.vout !== p.vout) throw new Error('spends another output');
  if (i0.sequence !== (p.kind === 'refund' ? Z.SEQ_LOCKTIME : Z.SEQ_FINAL)) throw new Error('bad sequence');
  if (i0.scriptSig !== '') throw new Error('scriptSig must be empty in the template');
  if (ins.transparentOutputs !== 0 || ins.hasSapling || ins.hasOrchard) throw new Error('must pay only into Ironwood');
  if (ins.ironwoodActions < 1 || ins.ironwoodActions > 4) throw new Error('unexpected Ironwood bundle');
  const fee = BigInt(p.value) - BigInt(ins.ironwoodValueIn);
  // ZIP 317 conventional fee at least: the spend can never be fee-bumped (SIGHASH_ALL, no change).
  if (BigInt(ins.ironwoodValueIn) !== BigInt(p.outValue) || fee < shieldedFee(p.kind, redeem) || fee > MAX_SHIELDED_FEE) throw new Error('bad fee');
  if (!Number.isSafeInteger(p.anchorHeight) || p.anchorHeight <= 0 || !ins.anchor) throw new Error('missing anchor');
  if (!Z.verifySig(Z.unhex(ins.sighash), Z.unhex(p.sig), p.kind === 'claim' ? t.claimPub : t.refundPub)) throw new Error('bad signature');
  if (opts.verifyProof && ins.proofOk !== true) throw new Error('bad shielded proof or signatures');
  return t;
}

/**
 * The anchor must be a real final Ironwood root: the proof commits to it but no signature does,
 * so a wrong one (a lagging or lying node, a byte-order slip) makes the spend valid on every other
 * check and dead on the network. Checked against the holder's own node; `minDepth` keeps the
 * anchor block out of reorg reach.
 */
export async function checkAnchor(w: ZecWasm, call: Z.Rpc, p: ShieldedPresigned, minDepth: number): Promise<void> {
  const ins = JSON.parse(w.inspectSpend(JSON.stringify({ raw: p.raw, branch: p.branch, value: Number(p.value), scriptPubKey: Z.hex(Z.p2sh(Z.unhex(p.redeem))), scriptCode: p.redeem }))) as Inspection;
  const tip = Number((await call('getblockchaininfo')).blocks);
  if (p.anchorHeight > tip - minDepth) throw new Error('anchor too recent');
  const root = await ironwoodAnchor(call, p.anchorHeight);
  if (!ins.anchor || root !== ins.anchor.toLowerCase()) throw new Error('the anchor is not the final Ironwood root at its height');
}

/**
 * The final transaction: put the scriptSig into input 0 (pure JS; no WASM). The txid does not
 * change. A claim needs x with sha256(x) == hashlock (checked here).
 */
export function finalizeShielded(p: ShieldedPresigned, x?: Uint8Array): { raw: string; txid: string } {
  const redeem = Z.unhex(p.redeem);
  const t = Z.parseHtlcScript(redeem);
  if (p.kind === 'claim' && (!x || x.length !== 32 || Z.hex(sha256(x)) !== Z.hex(t.hashlock))) throw new Error('wrong preimage');
  const raw = Z.unhex(p.raw);
  const dv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  // v6 layout: header(4) group(4) branch(4) lock_time(4) expiry(4) | vin count | outpoint(36) | scriptSig len | ...
  if (dv.getUint32(0, true) !== V6_HEADER || raw[20] !== 1 || raw[57] !== 0) throw new Error('not a HALFKEY shielded spend template');
  const ss = scriptSigFor(p.kind, Z.unhex(p.sig), redeem, x);
  const len = Z.compactSize(ss.length);
  const out = new Uint8Array(raw.length - 1 + len.length + ss.length);
  out.set(raw.subarray(0, 57), 0);
  out.set(len, 57);
  out.set(ss, 57 + len.length);
  out.set(raw.subarray(58), 57 + len.length + ss.length);
  return { raw: Z.hex(out), txid: p.spendTxid };
}

/** Finish either kind of pre-signed spend (v1 transparent or v2 shielded). */
export function finalizeAny(p: AnyPresigned, x?: Uint8Array): { raw: string; txid: string } {
  if (isShielded(p)) return finalizeShielded(p, x);
  const f = Z.finalize(p, x);
  return { raw: f.raw, txid: f.txid };
}
