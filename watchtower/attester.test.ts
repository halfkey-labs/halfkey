// v1.5 header attester: the failure cases the committee must refuse (node offline, wrong/disagreeing header,
// reorg/orphan, too few confirmations) and the client-side checks that keep a bad signature out of a proof.
// Fake monerods only; no network.
import test from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519';
import { PublicKey } from '@solana/web3.js';
import * as K from '../sdk/keys.ts';
import { attestHeight, checkAttestation } from './attester.ts';
import { pickAttestations } from '../sdk/prove.ts';
import { MONERO_NET } from '../sdk/v15.ts';

const A = 'a'.repeat(64), B = 'b'.repeat(64);
type Node = { id?: string; tip?: number; orphan?: boolean; height?: number; down?: boolean };
/** fetch over named fake nodes: http://n1 ... answering get_block_header_by_height / get_block_count. */
function fakeNet(nodes: Record<string, Node>) {
  return (async (url: string, init: any) => {
    const n = nodes[new URL(url).host];
    if (!n || n.down) throw new Error('ECONNREFUSED');
    const { method, params } = JSON.parse(init.body);
    const result = method === 'get_block_count' ? { count: n.tip }
      : { block_header: { hash: n.id, height: n.height ?? params.height, orphan_status: !!n.orphan } };
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: '0', result }));
  }) as typeof fetch;
}
const secrets = [1, 2, 3].map((i) => Uint8Array.from({ length: 32 }, (_, j) => (i * 31 + j) % 256));
const cfg = (nodes: Record<string, Node>, s = secrets[0]) => ({ nodes: Object.keys(nodes).map((h) => `http://${h}`), net: 'stagenet' as const, minConf: 10, secret: s, fetchImpl: fakeNet(nodes) });

test('two agreeing nodes: signs the block id with the smaller confirmation count; signature verifies', async () => {
  const a = await attestHeight(cfg({ n1: { id: A, tip: 120 }, n2: { id: A, tip: 118 } }), 100);
  assert.equal(a.blockId, A);
  assert.equal(a.confirmations, 18);
  assert.equal(a.net, MONERO_NET.stagenet);
  assert.ok(checkAttestation(a, { net: a.net, height: 100, blockId: A, keys: [a.pubkey] }));
});

test('a pinned confirmation count is signed only if every answering node has at least that many', async () => {
  const net = { n1: { id: A, tip: 120 }, n2: { id: A, tip: 112 } };
  assert.equal((await attestHeight(cfg(net), 100, 10)).confirmations, 10);
  await assert.rejects(attestHeight(cfg(net), 100, 15), /only 12 confirmations/);
  await assert.rejects(attestHeight(cfg({ n1: { id: A, tip: 105 }, n2: { id: A, tip: 105 } }), 100), /only 5 confirmations/);
});

test('node offline: one of two down refuses; one of three down still signs', async () => {
  await assert.rejects(attestHeight(cfg({ n1: { id: A, tip: 120 }, n2: { down: true } }), 100), /need 2 nodes to agree, 1 answered/);
  const a = await attestHeight(cfg({ n1: { id: A, tip: 120 }, n2: { down: true }, n3: { id: A, tip: 120 } }), 100);
  assert.equal(a.blockId, A);
});

test('one node URL listed twice is still one node', async () => {
  const c = cfg({ n1: { id: A, tip: 120 } });
  await assert.rejects(attestHeight({ ...c, nodes: ['http://n1', 'http://n1/'] }, 100), /2 distinct node URLs/);
});

test('wrong header: nodes that disagree on the block at a height get no signature', async () => {
  await assert.rejects(attestHeight(cfg({ n1: { id: A, tip: 120 }, n2: { id: B, tip: 120 } }), 100), /disagree/);
  await assert.rejects(attestHeight(cfg({ n1: { id: A, tip: 120 }, n2: { id: A, tip: 120 }, n3: { id: B, tip: 120 } }), 100), /disagree/);
  await assert.rejects(attestHeight(cfg({ n1: { id: 'zz', tip: 120 }, n2: { id: 'zz', tip: 120 } }), 100), /need 2 nodes/);
  await assert.rejects(attestHeight(cfg({ n1: { id: A, tip: 120, height: 99 }, n2: { id: A, tip: 120, height: 99 } }), 100), /need 2 nodes/);
});

test('reorg: an orphaned block is refused, and after a reorg the attester signs the new block (nothing cached)', async () => {
  await assert.rejects(attestHeight(cfg({ n1: { id: A, tip: 120, orphan: true }, n2: { id: A, tip: 120, orphan: true } }), 100), /need 2 nodes/);
  const nodes = { n1: { id: A, tip: 120 }, n2: { id: A, tip: 120 } };
  const c = cfg(nodes);
  assert.equal((await attestHeight(c, 100, 10)).blockId, A);
  nodes.n1.id = B; nodes.n2.id = B; // the chain reorganised at height 100
  assert.equal((await attestHeight(c, 100, 10)).blockId, B);
});

test('client side: only threshold distinct committee keys over the exact header count; forged, duplicate, wrong-net and outsider signatures are dropped', async () => {
  const nodes = { n1: { id: A, tip: 120 }, n2: { id: A, tip: 120 } };
  const sigs = await Promise.all(secrets.map((s) => attestHeight(cfg(nodes, s), 100, 10)));
  const keys = secrets.map((s) => new PublicKey(ed25519.getPublicKey(s)));
  const want = { net: MONERO_NET.stagenet, height: 100, blockId: K.fromHex(A), conf: 10, keys, threshold: 2 };
  assert.equal(pickAttestations(sigs, want).length, 2);
  assert.equal(pickAttestations([sigs[0], sigs[0], sigs[0]], want).length, 1, 'one key counts once');
  const outsider = await attestHeight(cfg(nodes, Uint8Array.from({ length: 32 }, () => 9)), 100, 10);
  assert.equal(pickAttestations([sigs[0], outsider], want).length, 1);
  const forged = { ...sigs[1], blockId: B };
  assert.equal(pickAttestations([sigs[0], forged], want).length, 1, 'a signature over another block id does not count');
  assert.equal(pickAttestations([sigs[0], { ...sigs[1], net: MONERO_NET.mainnet }], want).length, 1);
  assert.equal(pickAttestations([sigs[0], { ...sigs[1], confirmations: 11 }], want).length, 1);
  // one attester offline: two of three still reach the threshold; two offline do not
  assert.equal(pickAttestations([sigs[0], sigs[2]], want).length, 2);
  assert.ok(pickAttestations([sigs[0]], want).length < want.threshold);
});
