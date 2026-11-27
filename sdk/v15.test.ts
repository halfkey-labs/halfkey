// v1.5 SDK unit tests: Monero proof side (parse, txid, Merkle path, block id, TXPROOF_V2 build /
// check / string codec, output opening), the burn auction and staking math mirrors, and the
// attestation picker. Real-data checks: the stagenet block fixture's txids and block id.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { Keypair, PublicKey } from '@solana/web3.js';
import { ed25519 } from '@noble/curves/ed25519';
import * as K from './keys.ts';
import * as X from './xmrproof.ts';
import * as V from './v15.ts';
import { pickAttestations } from './prove.ts';
import { makeVector } from '../e2e/zkvec.ts';

const fx = JSON.parse(fs.readFileSync(new URL('../e2e/fixtures/stagenet-block.json', import.meta.url), 'utf8'));

test('real stagenet block: every txid recomputes from its bytes, the Merkle root and block id match', () => {
  const leaves = [K.fromHex(fx.block.miner_tx_hash), ...fx.block.tx_hashes.map((h: string) => K.fromHex(h))];
  for (const t of fx.txs) {
    const blob = K.fromHex(t.hex);
    const p = X.parseTx(blob);
    const id = X.txidOf(blob.slice(0, p.unprunableLen), X.kec(blob.slice(p.unprunableLen)));
    assert.equal(K.toHex(id), t.hash);
  }
  const header = X.blockHeaderBytes(K.fromHex(fx.block.blob));
  assert.equal(K.toHex(X.blockId(header, X.treeHash(leaves), leaves.length)), fx.header.hash);
  for (let i = 0; i < leaves.length; i++) assert.ok(K.equalBytes(X.foldBranch(leaves[i], X.treeBranch(leaves, i)), X.treeHash(leaves)));
  // synthetic trees of every size up to 33
  for (let n = 1; n <= 33; n++) {
    const ls = Array.from({ length: n }, () => K.newSwapId());
    for (let i = 0; i < n; i++) assert.ok(K.equalBytes(X.foldBranch(ls[i], X.treeBranch(ls, i)), X.treeHash(ls)), `n=${n} i=${i}`);
  }
});

test('TXPROOF_V2: OutProof and InProof both verify, bind the message, and round-trip the wallet string format', () => {
  const B = K.pointAdd(K.randomHalf().spendPub, K.randomHalf().spendPub);
  const v = K.randomScalar(), A = K.pub(v);
  const escrow = K.newSwapId();
  for (const kind of [X.KIND_OUT, X.KIND_IN]) {
    const vec = makeVector({ spendPub: B, viewPub: A, view: v, escrow, amount: 777n, kind });
    const t = X.parseTx(vec.args.unprunable);
    const R = X.txPubKey(t.extra)!.R;
    const m = X.proofPrefix(vec.args.txid, X.escrowMessage(escrow));
    assert.ok(X.checkTxProof(kind, m, R, A, vec.args.D, vec.args.c, vec.args.z));
    assert.equal(X.checkTxProof(kind ^ 1, m, R, A, vec.args.D, vec.args.c, vec.args.z), false, 'kinds are not interchangeable');
    assert.equal(X.checkTxProof(kind, X.proofPrefix(vec.args.txid, X.escrowMessage(K.newSwapId())), R, A, vec.args.D, vec.args.c, vec.args.z), false);
    const str = X.encodeProofString(kind, [{ D: vec.args.D, c: vec.args.c, z: vec.args.z }]);
    assert.ok(str.startsWith(kind === X.KIND_OUT ? 'OutProofV2' : 'InProofV2'));
    const back = X.decodeProofString(str);
    assert.equal(back.kind, kind);
    assert.ok(K.equalBytes(back.sigs[0].D, vec.args.D) && K.equalBytes(back.sigs[0].c, vec.args.c) && K.equalBytes(back.sigs[0].z, vec.args.z));
    const o = X.findOutput(t, vec.args.D, B)!;
    assert.equal(o.amount, 777n);
    assert.equal(X.findOutput(t, vec.args.D, K.pub(K.randomScalar())), null);
  }
  assert.throws(() => X.decodeProofString('ReserveProofV2abc'));
  assert.throws(() => X.decodeProofString('OutProofV2' + 'x'.repeat(131)));
});

test('buildProve: checks the proof, the output, the minimum and the block before anything goes on chain', () => {
  const B = K.pointAdd(K.randomHalf().spendPub, K.randomHalf().spendPub);
  const v = K.randomScalar(), A = K.pub(v);
  const escrow = K.newSwapId();
  const vec = makeVector({ spendPub: B, viewPub: A, view: v, escrow, amount: 5_000n });
  const leaves = [K.fromHex(fx.block.miner_tx_hash), ...fx.block.tx_hashes.map((h: string) => K.fromHex(h))];
  leaves[1] = vec.args.txid;
  const block: X.BlockData = { height: vec.height, blob: K.fromHex(fx.block.blob), minerTxHash: leaves[0], txHashes: leaves.slice(1), hash: vec.args.blockId };
  const base = { kind: X.KIND_OUT, sig: { D: vec.args.D, c: vec.args.c, z: vec.args.z }, unprunable: vec.args.unprunable, prunableHash: vec.args.prunableHash, block, escrow, spendPub: B, viewPub: A, minAmount: 5_000n };
  const a = X.buildProve(base);
  assert.equal(a.amount, 5_000n);
  assert.ok(K.equalBytes(a.outKey, vec.args.outKey));
  assert.equal(X.encodeProve(a).length, X.encodeProve(vec.args).length);
  assert.throws(() => X.buildProve({ ...base, minAmount: 5_001n }), /proven amount/);
  assert.throws(() => X.buildProve({ ...base, escrow: K.newSwapId() }), /does not verify/);
  assert.throws(() => X.buildProve({ ...base, block: { ...block, hash: K.newSwapId() } }), /block id mismatch/);
  assert.throws(() => X.buildProve({ ...base, block: { ...block, txHashes: leaves.slice(2) } }), /not in this block/);
});

test('burn auction mirror: price halves per hour, floor holds, cost rounds up, lot is capped by the pot', () => {
  const s = 2_000_000_000n;
  assert.equal(V.burnPriceAt(s, 1n, 100n, 100n), s);
  assert.equal(V.burnPriceAt(s, 1n, 100n, 100n + 3600n), s / 2n);
  assert.equal(V.burnPriceAt(s, 1n, 100n, 100n + 1800n), s - s / 4n);
  assert.equal(V.burnPriceAt(s, 5n, 0n, 3600n * 80n), 5n);
  let last = s;
  for (let t = 0n; t < 3600n * 40n; t += 977n) { const p = V.burnPriceAt(s, 1n, 0n, t); assert.ok(p <= last); last = p; }
  assert.equal(V.burnCost(1n, 1n), 1n);
  assert.equal(V.burnCost(1_000_000_000n, 3n), 3n);
  assert.equal(V.burnCost(1_000_000_001n, 1_000_000_000n), 1_000_000_001n);
  const b: V.BurnAccount = { mint: PublicKey.default, startPrice: s, floorPrice: 1n, maxLot: 100n, startAt: 0n, takes: 0n, totalBurned: 0n, totalLamports: 0n, lastPrice: 0n, pot: 40n };
  assert.equal(V.burnQuote(b, 10_000n, 1_000n, 0n).lot, 40n);
  assert.equal(V.burnQuote({ ...b, pot: 10_000n }, 1_050n, 1_000n, 0n).lot, 50n);
});

test('staking mirror: claimable = settled + share of the unsplit half and of loose pool SOL', () => {
  const pool: V.PoolAccount = { mint: PublicKey.default, totalStaked: 4_096n, acc: 0n, distributed: 0n, claimed: 0n };
  const st: V.StakerAccount = { owner: PublicKey.default, staked: 1_024n, accAt: 0n, owed: 7n, unbonding: 0n, unlockAt: 0n };
  const o = { vaultLamports: 1_000_000n + 8_001n, vaultKeep: 1_000_000n, burnPot: 0n, poolLamports: 500n + 400n, poolKeep: 500n, burnOn: true };
  // unsplit 8,001 -> stakers 4,000; loose 400; this staker holds 1/4 (4,096 staked: exact in binary)
  assert.equal(V.claimableRewards(pool, st, o), 7n + 1_100n);
  assert.equal(V.claimableRewards(pool, st, { ...o, burnOn: false }), 7n + 100n);
  assert.equal(V.claimableRewards({ ...pool, totalStaked: 0n }, st, o), 7n);
  assert.equal(V.settledRewards({ ...pool, acc: 3n << 64n }, { ...st, accAt: 1n << 64n }), 7n + 2_048n);
});

test('attestations: only committee keys, once each, over exactly (net, height, block, confirmations)', () => {
  const ks = [Keypair.generate(), Keypair.generate(), Keypair.generate()];
  const bid = K.newSwapId();
  const sign = (k: Keypair, h = 10, conf = 10, id = bid) => ({ height: h, blockId: K.toHex(id), confirmations: conf, net: 2, pubkey: K.toHex(k.publicKey.toBytes()), signature: K.toHex(ed25519.sign(V.headerMessage(2, h, id, conf), k.secretKey.slice(0, 32))) });
  const want = { net: 2, height: 10, blockId: bid, conf: 10, keys: ks.map((k) => k.publicKey), threshold: 2 };
  const out = Keypair.generate();
  const got = pickAttestations([sign(ks[0]), sign(ks[0]), sign(out), sign(ks[1], 11), sign(ks[1], 10, 12), { ...sign(ks[2]), signature: K.toHex(new Uint8Array(64)) }, sign(ks[1])], want);
  assert.equal(got.length, 2);
  assert.ok(K.equalBytes(got[0].pubkey, ks[0].publicKey.toBytes()) && K.equalBytes(got[1].pubkey, ks[1].publicKey.toBytes()));
  const ix = V.ixEd25519Multi(V.headerMessage(2, 10, bid, 10), got);
  assert.equal(ix.data[0], 2);
  assert.equal(ix.data.length, 2 + 14 * 2 + 96 * 2 + 66);
});

test('proofTerms mirrors zkproof::proof_terms (fixed vector); the record PDA changes with the keys', () => {
  const e = { createdAt: 5n, claimPoint: new Uint8Array(32).fill(1), refundPoint: new Uint8Array(32).fill(2), viewPub: new Uint8Array(32).fill(3) };
  assert.equal(Buffer.from(V.proofTerms(e)).toString('hex'), '4d84182da017b6f9869f9e23537429611b4915c905e624a4292b435085b80619');
  const pid = new PublicKey('9BbjkoRkb9K4tFjZJsUEVkikRNYWC9wpLtqD3rmicCr6'), esc = PublicKey.unique();
  const a = V.pdaV15.proof(pid, esc, e);
  assert.ok(!a.equals(V.pdaV15.proof(pid, esc, { ...e, viewPub: new Uint8Array(32).fill(4) })));
  assert.ok(!a.equals(V.pdaV15.proof(pid, esc, { ...e, createdAt: 6n })));
  assert.ok(a.equals(V.pdaV15.proof(pid, esc, { ...e })));
});
