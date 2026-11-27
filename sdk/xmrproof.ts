// HALFKEY v1.5: Monero payment proofs that the Solana program verifies (program/src/xmr.rs).
// Chain-agnostic Monero side: tx parsing, txid, Merkle path, block id, TXPROOF_V2 (OutProof /
// InProof) build/check/encode, and fetching the proof inputs from a monerod.
//
// A proof says: this Monero tx (its exact unprunable bytes + prunable hash -> txid) pays output
// `i` to the escrow's shared key B with view key A, the amount decoded from it opens its
// Pedersen commitment and is >= the escrow's xmr_amount, unlock_time is 0, and the tx sits in
// the block with this id (Merkle path). The program checks all of that itself. Whether that
// block is in the canonical Monero chain comes from the attester committee (attested header).
import { ed25519 } from '@noble/curves/ed25519';
import { keccak_256 } from '@noble/hashes/sha3';
import { concatBytes, utf8ToBytes, randomBytes } from '@noble/hashes/utils';
import * as K from './keys.ts';

const Point = ed25519.ExtendedPoint;
const H = Point.fromHex('8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94');
export const KIND_OUT = 0;
export const KIND_IN = 1;
export const TXPROOF_V2_SEP = keccak_256(utf8ToBytes('TXPROOF_V2'));

export const kec = (...parts: Uint8Array[]) => keccak_256(concatBytes(...parts));
export const hs = (...parts: Uint8Array[]) => K.leToBig(kec(...parts)) % K.L;
const le32 = (n: bigint) => K.bigToLe32(((n % K.L) + K.L) % K.L);
const mulG = (s: bigint) => Point.BASE.multiply(s);
const mulP = (p: Uint8Array, s: bigint) => (s === 0n ? Point.ZERO : Point.fromHex(p).multiply(s));

export function varint(n: number | bigint): Uint8Array {
  let x = BigInt(n);
  const out: number[] = [];
  while (x >= 0x80n) { out.push(Number((x & 0x7fn) | 0x80n)); x >>= 7n; }
  out.push(Number(x));
  return Uint8Array.from(out);
}

class Rd {
  b: Uint8Array; o: number;
  constructor(b: Uint8Array, o = 0) { this.b = b; this.o = o; }
  v(): bigint { let n = 0n, s = 0n, x: number; do { if (this.o >= this.b.length) throw new Error('truncated'); x = this.b[this.o++]; n |= BigInt(x & 0x7f) << s; s += 7n; } while (x & 0x80); return n; }
  u8() { if (this.o >= this.b.length) throw new Error('truncated'); return this.b[this.o++]; }
  take(n: number) { if (this.o + n > this.b.length) throw new Error('truncated'); const r = this.b.slice(this.o, this.o + n); this.o += n; return r; }
}

export interface ParsedTx {
  version: bigint; unlock: bigint; nin: number;
  vout: { key: Uint8Array; viewTag: number | null; off: number }[];
  extra: Uint8Array; extraOff: number; prefixLen: number; rctType: number;
  ecdh: Uint8Array[]; ecdhOff: number; outPk: Uint8Array[]; outPkOff: number; unprunableLen: number;
}

/** Parse a serialized tx (full, or pruned = prefix + RingCT base). */
export function parseTx(blob: Uint8Array): ParsedTx {
  const r = new Rd(blob);
  const version = r.v(); const unlock = r.v();
  const nin = Number(r.v());
  for (let i = 0; i < nin; i++) {
    const tag = r.u8();
    if (tag === 0xff) { r.v(); continue; }
    if (tag !== 0x02) throw new Error('vin tag ' + tag);
    r.v(); const k = Number(r.v()); for (let j = 0; j < k; j++) r.v(); r.take(32);
  }
  const nout = Number(r.v());
  const vout: ParsedTx['vout'] = [];
  for (let i = 0; i < nout; i++) {
    r.v(); const tag = r.u8(); const off = r.o; const key = r.take(32);
    let viewTag: number | null = null;
    if (tag === 0x03) viewTag = r.u8(); else if (tag !== 0x02) throw new Error('vout tag ' + tag);
    vout.push({ key, viewTag, off });
  }
  const elen = Number(r.v()); const extraOff = r.o; const extra = r.take(elen);
  const prefixLen = r.o;
  const rctType = r.u8();
  const ecdh: Uint8Array[] = [], outPk: Uint8Array[] = [];
  let ecdhOff = 0, outPkOff = 0;
  if (rctType !== 0) {
    r.v();
    if (rctType < 4) throw new Error('old RingCT type');
    ecdhOff = r.o; for (let i = 0; i < nout; i++) ecdh.push(r.take(8));
    outPkOff = r.o; for (let i = 0; i < nout; i++) outPk.push(r.take(32));
  }
  return { version, unlock, nin, vout, extra, extraOff, prefixLen, rctType, ecdh, ecdhOff, outPk, outPkOff, unprunableLen: r.o };
}

/** txid of prefix+base with the prunable hash (pruned txs from monerod come with `prunable_hash`). */
export function txidOf(unprunable: Uint8Array, prunableHash: Uint8Array): Uint8Array {
  const t = parseTx(unprunable);
  if (t.unprunableLen !== unprunable.length) throw new Error('trailing bytes after the RingCT base');
  return kec(kec(unprunable.slice(0, t.prefixLen)), kec(unprunable.slice(t.prefixLen)), prunableHash);
}

/** First tag-0x01 field of tx_extra (the main tx public key R), with its offset. */
export function txPubKey(extra: Uint8Array): { R: Uint8Array; off: number } | null {
  let i = 0;
  while (i < extra.length) {
    const tag = extra[i++];
    if (tag === 0x01) return { R: extra.slice(i, i + 32), off: i };
    if (tag === 0x02) { i += 1 + extra[i]; continue; }
    if (tag === 0x04) { const r = new Rd(extra, i); const n = Number(r.v()); i = r.o + 32 * n; continue; }
    if (tag === 0x00) continue;
    break;
  }
  return null;
}

// ---------------------------------------------------------------- Merkle tree / block id
function cnt2(count: number) { let p = 2; while (p < count) p <<= 1; return p >> 1; }
export function treeHash(leaves: Uint8Array[]): Uint8Array {
  const n = leaves.length;
  if (n === 1) return leaves[0];
  if (n === 2) return kec(leaves[0], leaves[1]);
  const c = cnt2(n);
  const ints = leaves.slice(0, 2 * c - n);
  for (let i = 2 * c - n; i < n; i += 2) ints.push(kec(leaves[i], leaves[i + 1]));
  let cur = ints;
  while (cur.length > 2) { const nx: Uint8Array[] = []; for (let i = 0; i < cur.length; i += 2) nx.push(kec(cur[i], cur[i + 1])); cur = nx; }
  return kec(cur[0], cur[1]);
}
export interface BranchStep { sib: Uint8Array; right: number }
/** Merkle path of leaf `idx` (right = 1: our node is the right child). */
export function treeBranch(leaves: Uint8Array[], idx: number): BranchStep[] {
  const n = leaves.length; const br: BranchStep[] = [];
  if (n === 1) return br;
  if (n === 2) return [{ sib: leaves[idx ^ 1], right: idx }];
  const c = cnt2(n); const first = 2 * c - n; const cur: Uint8Array[] = []; let pos = -1;
  for (let i = 0; i < first; i++) cur.push(leaves[i]);
  if (idx < first) pos = idx;
  for (let i = first, j = first; i < n; i += 2, j++) {
    cur.push(kec(leaves[i], leaves[i + 1]));
    if (idx === i || idx === i + 1) { br.push({ sib: leaves[idx === i ? i + 1 : i], right: idx === i ? 0 : 1 }); pos = j; }
  }
  let level = cur;
  while (level.length > 1) {
    const nx: Uint8Array[] = []; for (let i = 0; i < level.length; i += 2) nx.push(kec(level[i], level[i + 1]));
    br.push({ sib: level[pos ^ 1], right: pos & 1 }); pos >>= 1; level = nx;
  }
  return br;
}
export function foldBranch(leaf: Uint8Array, br: BranchStep[]) { let h = leaf; for (const { sib, right } of br) h = right ? kec(sib, h) : kec(h, sib); return h; }
/** Header bytes (major, minor, timestamp, prev_id, nonce) at the start of a block blob. */
export function blockHeaderBytes(blob: Uint8Array): Uint8Array { const r = new Rd(blob); r.v(); r.v(); r.v(); r.take(36); return blob.slice(0, r.o); }
export function blockId(header: Uint8Array, root: Uint8Array, ntx: number): Uint8Array {
  const hb = concatBytes(header, root, varint(ntx));
  return kec(varint(hb.length), hb);
}

// ---------------------------------------------------------------- TXPROOF_V2
/** The proof message for an escrow: its 32-byte address as lowercase hex (64 chars). */
export const escrowMessage = (escrow: Uint8Array) => K.toHex(escrow);
export const proofPrefix = (txid: Uint8Array, message: string) => kec(txid, utf8ToBytes(message));

/** The two transcript slots: OUT (sender) uses (R, A); IN (receiver) uses (A, R). */
const slots = (kind: number, R: Uint8Array, A: Uint8Array) => (kind === KIND_OUT ? [R, A] : [A, R]);

/**
 * Build a TXPROOF_V2 signature. OUT: `secret` = tx key r (R = rG, D = rA). IN: `secret` = view
 * key v (A = vG, D = vR). Same equations as crypto.cpp generate_tx_proof with no subaddress.
 */
export function genTxProof(kind: number, m: Uint8Array, R: Uint8Array, A: Uint8Array, D: Uint8Array, secret: Uint8Array) {
  const [P1, P2] = slots(kind, R, A);
  const x = K.leToBig(secret) % K.L;
  const k = (hs(randomBytes(64)) % K.L) || 1n;
  const X = mulG(k).toRawBytes(), Y = mulP(P2, k).toRawBytes();
  const c = hs(m, D, X, Y, TXPROOF_V2_SEP, P1, P2, new Uint8Array(32));
  const z = ((k - c * x) % K.L + K.L) % K.L;
  return { c: le32(c), z: le32(z) };
}
/** InProof from the receiver's view key: what a user holds for its own deposit (XMR->SOL in proof mode). */
export function inProofSig(unprunable: Uint8Array, txid: Uint8Array, escrow: Uint8Array, view: Uint8Array, viewPub: Uint8Array): ProofSig {
  const pk = txPubKey(parseTx(unprunable).extra);
  if (!pk) throw new Error('no tx public key');
  const D = mulP(pk.R, K.leToBig(view) % K.L).toRawBytes();
  return { D, ...genTxProof(KIND_IN, proofPrefix(txid, escrowMessage(escrow)), pk.R, viewPub, D, view) };
}
export function checkTxProof(kind: number, m: Uint8Array, R: Uint8Array, A: Uint8Array, D: Uint8Array, c: Uint8Array, z: Uint8Array): boolean {
  try {
    const cb = K.leToBig(c), zb = K.leToBig(z);
    if (cb >= K.L || zb >= K.L) return false;
    const [P1, P2] = slots(kind, R, A);
    const X = mulG(zb).add(mulP(P1, cb)).toRawBytes();
    const Y = mulP(P2, zb).add(mulP(D, cb)).toRawBytes();
    return hs(m, D, X, Y, TXPROOF_V2_SEP, P1, P2, new Uint8Array(32)) === cb;
  } catch { return false; }
}
export interface ProofSig { D: Uint8Array; c: Uint8Array; z: Uint8Array }
/** Decode a wallet `OutProofV2...` / `InProofV2...` string (one entry per tx pubkey; [0] is R). */
export function decodeProofString(s: string): { kind: number; sigs: ProofSig[] } {
  const kind = s.startsWith('OutProofV2') ? KIND_OUT : s.startsWith('InProofV2') ? KIND_IN : -1;
  if (kind < 0) throw new Error('not a TXPROOF_V2 string');
  const body = s.slice(kind === KIND_OUT ? 10 : 9);
  if (body.length % 132 !== 0 || body.length === 0) throw new Error('bad proof length');
  const sigs: ProofSig[] = [];
  for (let i = 0; i < body.length; i += 132) {
    const D = K.moneroBase58Decode(body.slice(i, i + 44));
    const sig = K.moneroBase58Decode(body.slice(i + 44, i + 132));
    sigs.push({ D, c: sig.slice(0, 32), z: sig.slice(32, 64) });
  }
  return { kind, sigs };
}
export function encodeProofString(kind: number, sigs: ProofSig[]): string {
  return (kind === KIND_OUT ? 'OutProofV2' : 'InProofV2') + sigs.map((x) => K.moneroBase58(x.D) + K.moneroBase58(concatBytes(x.c, x.z))).join('');
}

// ---------------------------------------------------------------- the output side
export interface OutputCheck { index: number; amount: bigint; s: Uint8Array }
/** Find the output of `t` that pays B for shared secret D (K = 8D), and open its amount. */
export function findOutput(t: ParsedTx, D: Uint8Array, B: Uint8Array): OutputCheck | null {
  const Kd = mulP(D, 8n).toRawBytes();
  for (let i = 0; i < t.vout.length; i++) {
    const vi = varint(i);
    const vo = t.vout[i];
    if (vo.viewTag !== null && kec(utf8ToBytes('view_tag'), Kd, vi)[0] !== vo.viewTag) continue;
    const s = hs(Kd, vi);
    if (!K.equalBytes(mulG(s).add(Point.fromHex(B)).toRawBytes(), vo.key)) continue;
    const sb = le32(s);
    const mask = kec(utf8ToBytes('amount'), sb);
    const a8 = t.ecdh[i].map((x, k) => x ^ mask[k]);
    const amount = K.leToBig(a8);
    const y = hs(utf8ToBytes('commitment_mask'), sb);
    const C = mulG(y).add(amount > 0n ? H.multiply(amount) : Point.ZERO).toRawBytes();
    if (!K.equalBytes(C, t.outPk[i])) return null; // forged amount
    return { index: i, amount, s: sb };
  }
  return null;
}
/** Output-side values for a lock to B (for building test vectors). */
export function outputFor(D: Uint8Array, i: number, B: Uint8Array, amount: bigint) {
  const Kd = mulP(D, 8n).toRawBytes();
  const sb = le32(hs(Kd, varint(i)));
  const P = mulG(K.leToBig(sb)).add(Point.fromHex(B)).toRawBytes();
  const mask = kec(utf8ToBytes('amount'), sb);
  const enc = new Uint8Array(8); let a = amount; for (let k = 0; k < 8; k++) { enc[k] = Number(a & 0xffn) ^ mask[k]; a >>= 8n; }
  const y = hs(utf8ToBytes('commitment_mask'), sb);
  const C = mulG(y).add(amount > 0n ? H.multiply(amount) : Point.ZERO).toRawBytes();
  const viewTag = kec(utf8ToBytes('view_tag'), Kd, varint(i))[0];
  return { P, enc, C, viewTag };
}

// ---------------------------------------------------------------- the instruction payload
export interface ProveArgs {
  kind: number;
  unprunable: Uint8Array;
  prunableHash: Uint8Array;
  outIndex: number;
  D: Uint8Array; c: Uint8Array; z: Uint8Array;
  header: Uint8Array;
  ntx: number;
  branch: BranchStep[];
  // for the caller (not sent): what the program will compute
  txid: Uint8Array;
  blockId: Uint8Array;
  outKey: Uint8Array;
  amount: bigint;
  height: number;
}

/** Block data as monerod `get_block` returns it. */
export interface BlockData { height: number; blob: Uint8Array; minerTxHash: Uint8Array; txHashes: Uint8Array[]; hash: Uint8Array; depth?: number }

/**
 * Everything `prove_lock` needs, checked off chain first with the same rules as the program:
 * the proof verifies for (escrow message, B, A), the output pays B with >= minAmount, and the
 * Merkle path folds to the block id.
 */
export function buildProve(o: {
  kind: number; sig: ProofSig; unprunable: Uint8Array; prunableHash: Uint8Array; block: BlockData;
  escrow: Uint8Array; spendPub: Uint8Array; viewPub: Uint8Array; minAmount: bigint;
}): ProveArgs {
  const t = parseTx(o.unprunable);
  if (t.version !== 2n || t.unlock !== 0n || (t.rctType !== 5 && t.rctType !== 6)) throw new Error('tx kind not provable (v2, unlock 0, CLSAG/BP+)');
  const txid = txidOf(o.unprunable, o.prunableHash);
  const pk = txPubKey(t.extra);
  if (!pk) throw new Error('no tx public key');
  const m = proofPrefix(txid, escrowMessage(o.escrow));
  if (!checkTxProof(o.kind, m, pk.R, o.viewPub, o.sig.D, o.sig.c, o.sig.z)) throw new Error('tx proof does not verify for this escrow');
  const out = findOutput(t, o.sig.D, o.spendPub);
  if (!out) throw new Error('no output of this tx pays the escrow');
  if (out.amount < o.minAmount) throw new Error(`proven amount ${out.amount} < required ${o.minAmount}`);
  const leaves = [o.block.minerTxHash, ...o.block.txHashes];
  const idx = leaves.findIndex((h) => K.equalBytes(h, txid));
  if (idx < 1) throw new Error('tx not in this block');
  const branch = treeBranch(leaves, idx);
  const header = blockHeaderBytes(o.block.blob);
  const bid = blockId(header, foldBranch(txid, branch), leaves.length);
  if (!K.equalBytes(bid, o.block.hash)) throw new Error('block id mismatch');
  return {
    kind: o.kind, unprunable: o.unprunable, prunableHash: o.prunableHash, outIndex: out.index, D: o.sig.D, c: o.sig.c, z: o.sig.z,
    header, ntx: leaves.length, branch, txid, blockId: bid, outKey: t.vout[out.index].key, amount: out.amount, height: o.block.height,
  };
}

/** prove_lock data after the tag (layout of program/src/zkproof.rs prove_lock). */
export function encodeProve(a: ProveArgs): Uint8Array {
  const u16 = Uint8Array.of(a.unprunable.length & 0xff, a.unprunable.length >> 8);
  const ntx = new Uint8Array(4); new DataView(ntx.buffer).setUint32(0, a.ntx, true);
  return concatBytes(
    Uint8Array.of(a.kind), u16, a.unprunable, a.prunableHash, Uint8Array.of(a.outIndex), a.D, a.c, a.z,
    Uint8Array.of(a.header.length), a.header, ntx, Uint8Array.of(a.branch.length), ...a.branch.map((b) => concatBytes(b.sib, Uint8Array.of(b.right))),
  );
}

// ---------------------------------------------------------------- monerod
async function rpc(uri: string, method: string, params: unknown) {
  const r = await fetch(`${uri.replace(/\/$/, '')}/json_rpc`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: '0', method, params }) });
  const j: any = await r.json();
  if (j.error) throw new Error(`${method}: ${j.error.message}`);
  return j.result;
}
async function other(uri: string, path: string, body: unknown) {
  const r = await fetch(`${uri.replace(/\/$/, '')}/${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return r.json() as Promise<any>;
}
/** Pruned tx (prefix + RingCT base) and its prunable hash, plus where it was mined. */
export async function fetchTx(daemon: string, txidHex: string) {
  const j = await other(daemon, 'get_transactions', { txs_hashes: [txidHex], prune: true, decode_as_json: false });
  const t = j.txs?.[0];
  if (!t) throw new Error('tx not found');
  if (t.in_pool) return { inPool: true as const };
  const unprunable = K.fromHex(t.pruned_as_hex);
  const prunableHash = K.fromHex(t.prunable_hash);
  if (K.toHex(txidOf(unprunable, prunableHash)) !== txidHex) throw new Error('daemon tx bytes do not hash to the txid');
  return { inPool: false as const, unprunable, prunableHash, height: Number(t.block_height) };
}
export async function fetchBlock(daemon: string, height: number): Promise<BlockData> {
  const b = await rpc(daemon, 'get_block', { height });
  const json = JSON.parse(b.json);
  return {
    height, blob: K.fromHex(b.blob), minerTxHash: K.fromHex(b.miner_tx_hash), txHashes: (b.tx_hashes ?? json.tx_hashes ?? []).map((h: string) => K.fromHex(h)),
    hash: K.fromHex(b.block_header.hash), depth: Number(b.block_header.depth),
  };
}
export async function tipHeight(daemon: string): Promise<number> {
  const r = await rpc(daemon, 'get_block_count', {});
  return Number(r.count) - 1;
}
