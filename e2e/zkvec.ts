// Test vectors for the v1.5 payment proofs: a REAL public stagenet transaction, byte for byte,
// with its tx key, output 0 key, view tag, encrypted amount and commitment replaced by a fresh
// lock to the escrow's shared key (B, A); the txid is recomputed and the tx spliced into the real
// stagenet block's tx list (new Merkle root and block id). The DLEQ uses Monero's exact
// TXPROOF_V2 transcript. The live stagenet run (e2e/zk-stagenet.ts) uses an untouched wallet tx.
import fs from 'node:fs';
import path from 'node:path';
import { ed25519 } from '@noble/curves/ed25519';
import * as K from '../sdk/keys.ts';
import * as X from '../sdk/xmrproof.ts';
import * as F from '../sdk/final.ts';
import { ROOT } from './harness.ts';

const fx = JSON.parse(fs.readFileSync(path.join(ROOT, 'e2e/fixtures/stagenet-block.json'), 'utf8'));

export interface Vec {
  args: X.ProveArgs;
  r: Uint8Array; // tx secret key
  height: number;
}

/**
 * A lock of `amount` piconero to (B = spendPub, A = viewPub = v*G) in output `outIdx`, proven
 * for `escrow`. kind OUT signs with the tx key r; IN with the view key v (needs `view`).
 */
export function makeVector(o: { spendPub: Uint8Array; viewPub: Uint8Array; view?: Uint8Array; escrow: Uint8Array; amount: bigint; outIdx?: number; kind?: number; unlock?: number; msgEscrow?: Uint8Array; pid?: Uint8Array }): Vec {
  const outIdx = o.outIdx ?? 0;
  const kind = o.kind ?? X.KIND_OUT;
  const src = fx.txs.find((t: any) => X.parseTx(K.fromHex(t.hex)).nin === 1) ?? fx.txs[0];
  const blob = K.fromHex(src.hex);
  const t = X.parseTx(blob);
  const r = K.randomScalar();
  const R = K.pub(r);
  // OUT: D = r*A. IN: D = v*R (the same point).
  const D = ed25519.ExtendedPoint.fromHex(o.viewPub).multiply(K.leToBig(r)).toRawBytes();
  const out = X.outputFor(D, outIdx, o.spendPub, o.amount);
  const nb = blob.slice();
  const pk = X.txPubKey(t.extra)!;
  nb.set(R, t.extraOff + pk.off);
  const vo = t.vout[outIdx];
  nb.set(out.P, vo.off);
  if (vo.viewTag !== null) nb[vo.off + 32] = out.viewTag;
  nb.set(out.enc, t.ecdhOff + 8 * outIdx);
  nb.set(out.C, t.outPkOff + 32 * outIdx);
  if (o.unlock !== undefined) nb[1] = o.unlock; // same 1-byte varint length
  if (o.pid) {
    // Direct pay (final round): the integrated address's payment id, encrypted like wallet2
    // (pid XOR keccak(8D || 0x8d)[..8]) into the tx's existing encrypted-pid nonce.
    const e = F.encryptedPid(t.extra);
    if (!e) throw new Error('fixture tx has no encrypted payment id nonce');
    nb.set(F.decryptPid(o.pid, D), t.extraOff + e.off);
  }
  const unprunable = nb.slice(0, t.unprunableLen);
  const prunableHash = X.kec(nb.slice(t.unprunableLen));
  const txid = X.txidOf(unprunable, prunableHash);
  const m = X.proofPrefix(txid, X.escrowMessage(o.msgEscrow ?? o.escrow));
  const sig = kind === X.KIND_OUT
    ? X.genTxProof(X.KIND_OUT, m, R, o.viewPub, D, r)
    : X.genTxProof(X.KIND_IN, m, R, o.viewPub, D, o.view!);
  // the real block, with our tx in place of its first non-miner tx
  const bblob = K.fromHex(fx.block.blob);
  const header = X.blockHeaderBytes(bblob);
  const leaves = [K.fromHex(fx.block.miner_tx_hash), ...fx.block.tx_hashes.map((h: string) => K.fromHex(h))];
  leaves[1] = txid;
  const branch = X.treeBranch(leaves, 1);
  const blockId = X.blockId(header, X.treeHash(leaves), leaves.length);
  const args: X.ProveArgs = {
    kind, unprunable, prunableHash, outIndex: outIdx, D, c: sig.c, z: sig.z, header, ntx: leaves.length, branch,
    txid, blockId, outKey: out.P, amount: o.amount, height: fx.header.height,
  };
  return { args, r, height: fx.header.height };
}
