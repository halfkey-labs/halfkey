// Maker side of the refund towers: deal after the lock, collect acks, refuse with too few.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Keypair, PublicKey } from '@solana/web3.js';
import * as K from '../sdk/keys.ts';
import * as P from '../sdk/program.ts';
import * as R from '../sdk/refundtowers.ts';
import { dealToTowers } from './refund-deal.ts';

const pid = Keypair.generate().publicKey;
function setup() {
  const maker = Keypair.generate(), m = K.randomScalar(), escrow = Keypair.generate().publicKey;
  const e: P.EscrowAccount = {
    address: escrow, state: P.ST.LOCKED, direction: 2, released: false, swapId: new Uint8Array(32), locker: maker.publicKey, claimer: Keypair.generate().publicKey,
    maker: maker.publicKey, amount: 1_000_000_000n, xmrAmount: 100_000_000_000n, feeBps: 30, claimPoint: K.pub(K.randomScalar()), refundPoint: K.pub(m),
    viewPub: K.pub(K.randomScalar()), quoteHash: new Uint8Array(32), watchtowers: [PublicKey.default, PublicKey.default],
    createdAt: 10n, t0: 21_610n, t1: 25_210n, settledAt: 0n, secret: new Uint8Array(32), flags: P.F.PROOF, link: PublicKey.default,
  };
  const keys = [Keypair.generate(), Keypair.generate(), Keypair.generate()];
  const towers = keys.map((k, n) => ({ url: `https://t${n}`, pubkey: k.publicKey.toBase58() }));
  const seen: R.DealReq[] = [];
  // honest towers: check the deal like the real one and ack
  const post = async (url: string, body: R.DealReq) => {
    const n = Number(url.match(/t(\d)/)![1]);
    seen.push(body);
    const t = R.termsOf(pid, escrow, e, K.fromHex(body.c1));
    assert.ok(R.verifyDeal(body, t, keys[n].publicKey));
    assert.ok(R.verifyShare({ i: body.index, s: K.fromHex(body.share) }, { c0: e.refundPoint, c1: K.fromHex(body.c1) }));
    return R.signAck(t, n + 1, keys[n]);
  };
  return { maker, m, e, escrow, keys, towers, post, seen };
}

test('deals one share per tower, at its own index, and returns acks the page accepts', async () => {
  const s = setup();
  const r = await dealToTowers({ pid, escrow: s.escrow, e: s.e, makerSpend: s.m, maker: s.maker, towers: s.towers, minAcks: 3, post: s.post, backoffMs: [0] });
  assert.equal(r.acks.length, 3);
  assert.deepEqual(s.seen.map((x) => x.index), [1, 2, 3]);
  assert.equal(new Set(s.seen.map((x) => x.c1)).size, 1, 'one polynomial for all towers');
  assert.equal(R.checkAcks(r.acks, s.towers.map((t) => ({ pubkey: new PublicKey(t.pubkey) })), pid, s.escrow, s.e, 3).ok, true);
  // no single request carries two shares: nobody but the maker ever sees two
  assert.equal(new Set(s.seen.map((x) => x.share)).size, 3);
});

test('one tower down: enough with minAcks 2, refused with minAcks 3', async () => {
  const s = setup();
  const post = async (url: string, b: R.DealReq) => { if (url.includes('t1')) throw new Error('down'); return s.post(url, b); };
  const r = await dealToTowers({ pid, escrow: s.escrow, e: s.e, makerSpend: s.m, maker: s.maker, towers: s.towers, minAcks: 2, post, backoffMs: [0] });
  assert.equal(r.acks.length, 2);
  await assert.rejects(dealToTowers({ pid, escrow: s.escrow, e: s.e, makerSpend: s.m, maker: s.maker, towers: s.towers, minAcks: 3, post, backoffMs: [0] }), /2 of 3/);
});

test('a tower that answers with a bad or foreign ack does not count', async () => {
  const s = setup();
  const post = async (url: string, b: R.DealReq) => {
    if (url.includes('t2')) return R.signAck(R.termsOf(pid, s.escrow, s.e, K.fromHex(b.c1)), 3, Keypair.generate());
    return s.post(url, b);
  };
  await assert.rejects(dealToTowers({ pid, escrow: s.escrow, e: s.e, makerSpend: s.m, maker: s.maker, towers: s.towers, minAcks: 3, post, backoffMs: [0] }), /2 of 3/);
});

test('refuses a half that does not match the escrow\'s refund point, and a listed set that is not three', async () => {
  const s = setup();
  await assert.rejects(dealToTowers({ pid, escrow: s.escrow, e: s.e, makerSpend: K.randomScalar(), maker: s.maker, towers: s.towers, minAcks: 3, post: s.post }), /refund point/);
  await assert.rejects(dealToTowers({ pid, escrow: s.escrow, e: s.e, makerSpend: s.m, maker: s.maker, towers: s.towers.slice(0, 2), minAcks: 2, post: s.post }), /three/);
  assert.equal(s.seen.length, 0, 'nothing sent');
});

test('a tower whose provider lags behind the lock is tried again after a pause', async () => {
  const s = setup();
  let first = true;
  const post = async (url: string, b: R.DealReq) => { if (url.includes('t2') && first) { first = false; throw new Error('404 escrow not found'); } return s.post(url, b); };
  const r = await dealToTowers({ pid, escrow: s.escrow, e: s.e, makerSpend: s.m, maker: s.maker, towers: s.towers, minAcks: 3, post, backoffMs: [0, 10] });
  assert.equal(r.acks.length, 3);
});
