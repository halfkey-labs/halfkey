// v1.5 maker-side proof pipeline, offline: the attester's two-node rule (watchtower/attester.ts)
// and sdk/prove.ts planProve (what the daemon runs before claiming a proof-mode escrow) against a
// mocked monerod, mocked attesters and a mocked Solana connection.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { Keypair, PublicKey } from '@solana/web3.js';
import * as K from '../sdk/keys.ts';
import * as P from '../sdk/program.ts';
import * as X from '../sdk/xmrproof.ts';
import * as V from '../sdk/v15.ts';
import { planProve } from '../sdk/prove.ts';
import { attestHeight, checkAttestation } from '../watchtower/attester.ts';
import { makeVector } from '../e2e/zkvec.ts';

const fx = JSON.parse(fs.readFileSync(new URL('../e2e/fixtures/stagenet-block.json', import.meta.url), 'utf8'));
const json = (x: unknown) => new Response(JSON.stringify(x), { headers: { 'content-type': 'application/json' } });

/** A monerod that knows one block (with our tx) at `height`, tip `tip`, block id `id`. */
function monerod(o: { height: number; tip: number; id: string; tx?: { unprunable: Uint8Array; prunableHash: Uint8Array; txid: Uint8Array; inPool?: boolean }; txHashes?: string[] }) {
  return async (url: string | URL | Request, init?: RequestInit) => {
    const u = String(url);
    const body = JSON.parse(String(init?.body ?? '{}'));
    if (u.endsWith('/get_transactions')) {
      return json({ txs: o.tx ? [{ pruned_as_hex: K.toHex(o.tx.unprunable), prunable_hash: K.toHex(o.tx.prunableHash), block_height: o.height, in_pool: !!o.tx.inPool }] : [] });
    }
    switch (body.method) {
      case 'get_block_count': return json({ result: { count: o.tip + 1 } });
      case 'get_block_header_by_height': return json({ result: { block_header: { hash: o.id, height: body.params.height } } });
      case 'get_block': return json({ result: { blob: fx.block.blob, json: '{}', miner_tx_hash: fx.block.miner_tx_hash, tx_hashes: o.txHashes ?? [], block_header: { hash: o.id, depth: o.tip - o.height } } });
    }
    return json({ error: { message: 'unknown' } });
  };
}

test('attester: signs only when two nodes agree on the block and both see enough confirmations', async () => {
  const secret = Keypair.generate().secretKey.slice(0, 32);
  const id = K.toHex(K.newSwapId());
  const good = monerod({ height: 100, tip: 115, id });
  const fetchFor = (map: Record<string, any>) => (async (u: any, i: any) => map[new URL(String(u)).host](u, i)) as typeof fetch;
  const cfg = (m: Record<string, any>) => ({ nodes: Object.keys(m).map((h) => `http://${h}`), net: 'stagenet' as const, minConf: 10, secret, fetchImpl: fetchFor(m) });
  const a = await attestHeight(cfg({ a: good, b: good }), 100);
  assert.equal(a.confirmations, 16);
  assert.ok(checkAttestation(a, { net: 2, height: 100, blockId: id, keys: [a.pubkey] }));
  assert.equal(checkAttestation(a, { net: 0, height: 100, blockId: id, keys: [a.pubkey] }), false);
  const fixed = await attestHeight(cfg({ a: good, b: good }), 100, 10);
  assert.equal(fixed.confirmations, 10);
  await assert.rejects(attestHeight(cfg({ a: good, b: good }), 100, 17), /confirmations/);
  await assert.rejects(attestHeight(cfg({ a: good, b: monerod({ height: 100, tip: 115, id: K.toHex(K.newSwapId()) }) }), 100), /disagree/);
  await assert.rejects(attestHeight(cfg({ a: good, b: async () => { throw new Error('down'); } }), 100), /2 nodes/);
  await assert.rejects(attestHeight(cfg({ a: monerod({ height: 100, tip: 105, id }), b: good }), 100), /confirmations/);
});

test('planProve: pending until confirmed, then attest + prove; skips the attest when the block is already attested', async () => {
  const pid = Keypair.generate().publicKey;
  const payer = Keypair.generate().publicKey;
  const escrow = Keypair.generate().publicKey;
  const mk = K.randomHalf(), us = K.randomHalf(), v = K.randomScalar();
  const e = { direction: P.DIR_SOL_TO_XMR, flags: P.F.PROOF, claimPoint: mk.spendPub, refundPoint: us.spendPub, viewPub: K.pub(v), xmrAmount: 900n, createdAt: 123n } as unknown as P.EscrowAccount;
  const vec = makeVector({ spendPub: K.pointAdd(mk.spendPub, us.spendPub), viewPub: K.pub(v), view: v, escrow: escrow.toBytes(), amount: 900n });
  const txHashes = fx.block.tx_hashes.slice(); txHashes[0] = K.toHex(vec.args.txid);
  const id = K.toHex(vec.args.blockId);
  const att = [Keypair.generate(), Keypair.generate(), Keypair.generate()];
  const attData = new Uint8Array(V.ATTESTERS_LEN);
  attData[0] = 0xae; attData[3] = 2; attData[4] = 2; attData[5] = 3;
  new DataView(attData.buffer).setBigUint64(8, 4n, true);
  new DataView(attData.buffer).setUint32(16, 10, true);
  att.forEach((k, i) => attData.set(k.publicKey.toBytes(), 24 + 32 * i));
  const accounts = new Map<string, { data: Uint8Array }>([[V.pdaV15.attesters(pid).toBase58(), { data: attData }]]);
  const conn = { getAccountInfo: async (k: PublicKey) => accounts.get(k.toBase58()) ?? null } as any;
  const sig = { D: vec.args.D, c: vec.args.c, z: vec.args.z };
  const tx = { unprunable: vec.args.unprunable, prunableHash: vec.args.prunableHash, txid: vec.args.txid };
  const run = async (tip: number, attesters: Keypair[]) => {
    const daemon = monerod({ height: vec.height, tip, id, tx, txHashes });
    const realFetch = globalThis.fetch;
    globalThis.fetch = daemon as typeof fetch; // fetchTx / fetchBlock use the global fetch
    try {
      const attFetch = (async (u: any) => {
        const i = Number(new URL(String(u)).host.replace('att', ''));
        const conf = Number(new URL(String(u)).searchParams.get('conf'));
        const both = { a: daemon, b: daemon } as Record<string, any>;
        return json(await attestHeight({ nodes: ['http://a', 'http://b'], net: 'stagenet', minConf: 10, secret: attesters[i].secretKey.slice(0, 32), fetchImpl: (async (x: any, y: any) => both[new URL(String(x)).host](x, y)) as typeof fetch }, vec.height, conf));
      }) as typeof fetch;
      return await planProve({ conn, pid, payer, escrow, e, txid: K.toHex(vec.args.txid), kind: X.KIND_OUT, sig, daemon: 'http://d', attesters: attesters.map((_, i) => `http://att${i}`), fetchImpl: attFetch });
    } finally { globalThis.fetch = realFetch; }
  };
  const early = await run(vec.height + 4, att);
  assert.equal(early.status, 'pending');
  const outsiders = [Keypair.generate(), Keypair.generate()];
  assert.equal((await run(vec.height + 12, outsiders)).status, 'pending', 'signatures from non-members do not count');
  const plan = await run(vec.height + 12, att);
  assert.equal(plan.status, 'ready');
  if (plan.status !== 'ready') return;
  assert.equal(plan.attestIxs!.length, 2);
  assert.equal(plan.attestIxs![0].data[0], 2, 'threshold signatures in one precompile instruction');
  assert.ok(plan.proofPda.equals(V.pdaV15.proof(pid, escrow, e)));
  assert.equal(plan.args.amount, 900n);
  accounts.set(V.pdaV15.header(pid, 4n, vec.args.blockId).toBase58(), { data: new Uint8Array(V.XHDR_LEN) });
  const again = await run(vec.height + 12, att);
  assert.ok(again.status === 'ready' && again.attestIxs === null);
  await assert.rejects(planProve({ conn, pid, payer, escrow, e: { ...e, flags: 0, direction: 2 } as P.EscrowAccount, txid: '', kind: 0, sig, daemon: '', attesters: [] }), /proof-gated/);
});
