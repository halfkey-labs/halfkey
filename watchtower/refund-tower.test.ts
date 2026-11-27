// Refund tower service against an in-memory chain: what it accepts, when it releases, what it destroys.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Keypair, PublicKey } from '@solana/web3.js';
import * as K from '../sdk/keys.ts';
import * as P from '../sdk/program.ts';
import * as R from '../sdk/refundtowers.ts';
import { RefundTower, TowerError, rpcReader, type Reader, type Rec } from './refund-tower.ts';

const pid = Keypair.generate().publicKey;

function world() {
  const maker = Keypair.generate();
  const m = K.randomScalar();
  const escrowPk = Keypair.generate().publicKey;
  const e: P.EscrowAccount = {
    address: escrowPk, state: P.ST.LOCKED, direction: 2, released: false, swapId: new Uint8Array(32), locker: maker.publicKey, claimer: Keypair.generate().publicKey,
    maker: maker.publicKey, amount: 5_000_000_000n, xmrAmount: 500_000_000_000n, feeBps: 30, claimPoint: K.pub(K.randomScalar()), refundPoint: K.pub(m),
    viewPub: K.pub(K.randomScalar()), quoteHash: new Uint8Array(32), watchtowers: [PublicKey.default, PublicKey.default],
    createdAt: 1_000n, t0: 1_000n + 21_600n, t1: 1_000n + 25_200n, settledAt: 0n, secret: new Uint8Array(32), flags: P.F.PROOF, link: PublicKey.default,
  };
  const chain = { e: e as P.EscrowAccount | null, clock: 1_100, lie: null as null | ((r: R.ChainRead) => R.ChainRead) };
  const reads = { n: 0 };
  const reader = (liar = false): Reader => ({
    async read() {
      reads.n++;
      const r: R.ChainRead = chain.e ? { kind: 'escrow', e: { ...chain.e }, clock: chain.clock } : { kind: 'missing', clock: chain.clock };
      return liar && chain.lie ? chain.lie(r) : r;
    },
  });
  const keys = [Keypair.generate(), Keypair.generate(), Keypair.generate()];
  const d = R.deal(m);
  const t = R.termsOf(pid, escrowPk, e, d.c.c1);
  const refunds: { secret: Uint8Array }[] = [];
  const towers: RefundTower[] = [];
  const store: Rec[][] = [[], [], []];
  for (let n = 0; n < 3; n++) {
    towers.push(new RefundTower({
      pid, index: n + 1, key: keys[n], makers: [maker.publicKey.toBase58()], readers: [reader(), reader(true)], peers: ['p0', 'p1', 'p2'].filter((_, k) => k !== n),
      submitRefund: async (_e, secret) => { refunds.push({ secret }); chain.e = { ...chain.e!, state: P.ST.REFUNDED, secret }; return 'sig' + n; },
      load: () => store[n], save: (r) => { store[n] = JSON.parse(JSON.stringify(r)); }, now: () => chain.clock,
      fetchJson: async (u) => { const k = Number(u.match(/p(\d)/)![1]); return towers[k].share(u.split('/').pop()!); },
      log: () => {},
    }));
  }
  const reqs = d.shares.map((sh, n) => R.signDeal(t, sh, keys[n].publicKey, maker.secretKey.slice(0, 32)));
  const history = { half: null as Uint8Array | null };
  for (const tw of towers) tw.o.findSettlement = async () => (history.half ? { kind: 'refund' as const, secret: history.half } : { kind: 'none' as const, done: true });
  return { maker, m, escrowPk, e, chain, keys, d, t, towers, reqs, refunds, store, reads, history };
}

test('a tower acks a share signed by the escrow\'s maker, and the page accepts the three acks', async () => {
  const w = world();
  const acks = [];
  for (let n = 0; n < 3; n++) acks.push(await w.towers[n].deal(w.reqs[n]));
  const listed = w.keys.map((k) => ({ pubkey: k.publicKey }));
  assert.equal(R.checkAcks(acks, listed, pid, w.escrowPk, w.e, 3).ok, true);
  // same request again: same ack (the maker retries after a timeout)
  assert.deepEqual(await w.towers[0].deal(w.reqs[0]), acks[0]);
  assert.deepEqual(w.towers[1].ack(w.escrowPk.toBase58()), acks[1]);
});

test('deals refused: stranger\'s signature, a different share for a held escrow, wrong index, bad share, unserved maker, not ready-only, far t1', async () => {
  const w = world();
  const stranger = Keypair.generate();
  const forged = R.signDeal(w.t, w.d.shares[0], w.keys[0].publicKey, stranger.secretKey.slice(0, 32));
  await assert.rejects(w.towers[0].deal(forged), (e: TowerError) => e.status === 401);
  // the signed terms must also match: a maker on the list signing over another escrow's terms
  await assert.rejects(w.towers[0].deal({ ...w.reqs[0], escrow: Keypair.generate().publicKey.toBase58() }), (e: TowerError) => e.status === 401);
  await assert.rejects(w.towers[0].deal(w.reqs[1]), /tower 1/);
  const bad = R.signDeal(w.t, { i: 1, s: K.scalarAdd(w.d.shares[0].s, K.bigToLe32(1n)) }, w.keys[0].publicKey, w.maker.secretKey.slice(0, 32));
  await assert.rejects(w.towers[0].deal(bad), /commitments/);
  await w.towers[0].deal(w.reqs[0]);
  const other = R.deal(w.m);
  const t2 = R.termsOf(pid, w.escrowPk, w.e, other.c.c1);
  await assert.rejects(w.towers[0].deal(R.signDeal(t2, other.shares[0], w.keys[0].publicKey, w.maker.secretKey.slice(0, 32))), (e: TowerError) => e.status === 409);

  const w2 = world();
  w2.chain.e = { ...w2.e, flags: 0 };
  await assert.rejects(w2.towers[0].deal(w2.reqs[0]), /ready-only/);
  w2.chain.e = { ...w2.e, direction: 1 };
  await assert.rejects(w2.towers[0].deal(w2.reqs[0]), /XMR->SOL/);
  w2.chain.e = { ...w2.e, t1: 1_100n + 200_000n };
  await assert.rejects(w2.towers[0].deal(w2.reqs[0]), /far/);
  w2.chain.e = { ...w2.e, state: P.ST.READY };
  await assert.rejects(w2.towers[0].deal(w2.reqs[0]), /not open/);
  w2.chain.e = null;
  await assert.rejects(w2.towers[0].deal(w2.reqs[0]), (e: TowerError) => e.status === 404);
  const w3 = world();
  w3.towers[0].o.makers = [Keypair.generate().publicKey.toBase58()];
  await assert.rejects(w3.towers[0].deal(w3.reqs[0]), /maker this tower serves/);
});

test('no share before a claim is impossible; past t1 on a finalized clock the towers rebuild the half and refund once', async () => {
  const w = world();
  for (let n = 0; n < 3; n++) await w.towers[n].deal(w.reqs[n]);
  const id = w.escrowPk.toBase58();
  // the maker said ready: the user can still claim until t1
  w.chain.e = { ...w.e, state: P.ST.READY };
  w.chain.clock = Number(w.e.t1) - 10;
  for (const t of w.towers) await t.tick();
  assert.throws(() => w.towers[0].share(id), (e: TowerError) => e.status === 403);
  w.chain.clock = Number(w.e.t1) + R.RELEASE_MARGIN_SECS - 1;
  for (const t of w.towers) await t.tick();
  assert.throws(() => w.towers[0].share(id), (e: TowerError) => e.status === 403, 'inside the margin');
  w.chain.clock = Number(w.e.t1) + R.RELEASE_MARGIN_SECS;
  await w.towers[1].tick(); // tower 2 releases first; no peer has released yet
  assert.equal(w.refunds.length, 0);
  await w.towers[0].tick(); // tower 1 releases, finds tower 2's share, refunds
  assert.equal(w.refunds.length, 1);
  assert.deepEqual(w.refunds[0].secret, w.m, 'the refund carries the maker\'s real half');
  await w.towers[2].tick();
  assert.equal(w.refunds.length, 1, 'already refunded: nobody sends it twice');
  // closed later: the latched release still serves the share (the page can rebuild from history-free shares)
  w.chain.e = null;
  for (const t of w.towers) await t.tick();
  assert.equal(w.towers[2].share(id).share, K.toHex(w.d.shares[2].s));
});

test('an aborted swap releases before t1 (it can never be claimed)', async () => {
  const w = world();
  for (let n = 0; n < 2; n++) await w.towers[n].deal(w.reqs[n]);
  w.chain.e = { ...w.e, state: P.ST.ABORTED };
  w.chain.clock = 1_300;
  await w.towers[0].tick(); await w.towers[1].tick();
  assert.equal(w.refunds.length, 1);
  assert.deepEqual(w.refunds[0].secret, w.m);
});

test('a claimed swap: the share is destroyed and never released, even after t1', async () => {
  const w = world();
  for (let n = 0; n < 3; n++) await w.towers[n].deal(w.reqs[n]);
  const id = w.escrowPk.toBase58();
  w.chain.e = { ...w.e, state: P.ST.CLAIMED };
  w.chain.clock = Number(w.e.t1) + 10_000;
  for (const t of w.towers) await t.tick();
  for (const t of w.towers) assert.throws(() => t.share(id), (e: TowerError) => e.status === 410);
  assert.ok(w.store.every((s) => s[0].share === '0'.repeat(64) && s[0].claimed), 'not even on disk');
  assert.equal(w.refunds.length, 0);
});

test('one lying reader (state or clock) blocks release and blocks destruction', async () => {
  const w = world();
  for (let n = 0; n < 3; n++) await w.towers[n].deal(w.reqs[n]);
  const id = w.escrowPk.toBase58();
  // the honest chain is still before t1; one RPC claims the clock is past it
  w.chain.clock = Number(w.e.t1) - 100;
  w.chain.lie = (r) => (r.kind === 'escrow' ? { ...r, clock: Number(w.e.t1) + 9_999 } : r);
  for (const t of w.towers) await t.tick();
  assert.throws(() => w.towers[0].share(id), (e: TowerError) => e.status === 403);
  // one RPC claims "claimed": no destruction either (a lie must not strand the user)
  w.chain.clock = Number(w.e.t1) + 9_999;
  w.chain.lie = (r) => (r.kind === 'escrow' ? { ...r, e: { ...r.e, state: P.ST.CLAIMED } } : r);
  for (const t of w.towers) await t.tick();
  assert.ok(w.store.every((s) => !s[0].claimed));
  assert.throws(() => w.towers[0].share(id), (e: TowerError) => e.status === 403);
  // the liar goes away: release
  w.chain.lie = null;
  for (const t of w.towers) await t.tick();
  assert.equal(w.towers[0].share(id).index, 1);
});

test('a different escrow re-created at the same address never gets the old share', async () => {
  const w = world();
  for (let n = 0; n < 3; n++) await w.towers[n].deal(w.reqs[n]);
  w.chain.e = { ...w.e, state: P.ST.ABORTED, createdAt: w.e.createdAt + 50n };
  for (const t of w.towers) await t.tick();
  assert.throws(() => w.towers[0].share(w.escrowPk.toBase58()), (e: TowerError) => e.status === 403);
});

test('a tower restarts from its store with its records intact', async () => {
  const w = world();
  await w.towers[0].deal(w.reqs[0]);
  const again = new RefundTower({ ...w.towers[0].o, load: () => w.store[0] });
  assert.deepEqual(again.ack(w.escrowPk.toBase58()), w.store[0][0].ack);
  assert.throws(() => new RefundTower({ ...w.towers[0].o, readers: [w.towers[0].o.readers[0]] }), /two independent/);
});

test('refund and close in one go (the escrow is gone before a tower saw it settle): released from the history, never on a bare "gone"', async () => {
  const w = world();
  for (let n = 0; n < 3; n++) await w.towers[n].deal(w.reqs[n]);
  const id = w.escrowPk.toBase58();
  w.chain.e = null; // closed
  for (const t of w.towers) await t.tick();
  assert.throws(() => w.towers[0].share(id), (e: TowerError) => e.status === 403, 'no refund in history: could have been a claim');
  // a refund with a wrong half in the history counts for nothing
  w.history.half = K.randomScalar();
  w.chain.clock += 3700;
  for (const t of w.towers) await t.tick();
  assert.throws(() => w.towers[0].share(id), (e: TowerError) => e.status === 403);
  w.history.half = w.m;
  w.chain.clock += 3700;
  for (const t of w.towers) await t.tick();
  const sh = w.towers[1].share(id);
  assert.equal(sh.index, 2);
  assert.equal(sh.swapId, K.toHex(w.e.swapId), 'enough for a page that finds the escrow closed');
  assert.equal(sh.claimPoint, K.toHex(w.e.claimPoint));
});

test('unsigned requests never reach the chain', async () => {
  const w = world();
  const before = w.reads.n;
  for (let i = 0; i < 50; i++) {
    await assert.rejects(w.towers[0].deal({ ...w.reqs[0], auth: '00'.repeat(64) }), (e: TowerError) => e.status === 401);
    await assert.rejects(w.towers[0].deal({ escrow: Keypair.generate().publicKey.toBase58(), index: 1, share: '11'.repeat(32), c1: '22'.repeat(32), sig: '33'.repeat(64) }), (e: TowerError) => e.status === 401);
  }
  assert.equal(w.reads.n, before);
});

test('a provider that has not seen the lock yet: the other one is asked', async () => {
  const w = world();
  w.chain.lie = (r) => ({ kind: 'missing', clock: (r as any).clock ?? 0 });
  // reader 0 honest here, reader 1 the liar: swap them so the first one lags
  w.towers[0].o.readers.reverse();
  const ack = await w.towers[0].deal(w.reqs[0]);
  assert.equal(ack.index, 1);
});

test('a swap id reused after the old escrow settled gets a new share; an open one does not', async () => {
  const w = world();
  await w.towers[0].deal(w.reqs[0]);
  // still open: a different share for the same address is refused
  const m2 = K.randomScalar(), d2 = R.deal(m2);
  const e2 = { ...w.e, createdAt: w.e.createdAt + 9_999n, refundPoint: K.pub(m2) };
  const t2 = R.termsOf(pid, w.escrowPk, e2, d2.c.c1);
  const req2 = R.signDeal(t2, d2.shares[0], w.keys[0].publicKey, w.maker.secretKey.slice(0, 32));
  w.chain.e = e2;
  await assert.rejects(w.towers[0].deal(req2), (e: TowerError) => e.status === 409);
  // the old one settled (claimed): the new escrow at that address is served
  w.towers[0].recs.get(w.escrowPk.toBase58())!.claimed = true;
  const ack = await w.towers[0].deal(req2);
  assert.equal(ack.index, 1);
});

test('settled records are pruned: claimed after a day, refunded after 30 days', async () => {
  const w = world();
  for (let n = 0; n < 3; n++) await w.towers[n].deal(w.reqs[n]);
  w.chain.e = { ...w.e, state: P.ST.CLAIMED };
  w.chain.clock = Number(w.e.t1) + 200;
  await w.towers[0].tick();
  assert.equal(w.towers[0].recs.size, 1);
  w.chain.clock += 86_401;
  await w.towers[0].tick();
  assert.equal(w.towers[0].recs.size, 0);
});

test('a read that hangs becomes an error after the timeout (so it can only ever mean "wait")', async () => {
  const hung = { getMultipleAccountsInfo: () => new Promise(() => {}) } as any;
  const r = await rpcReader(hung, pid, 50).read(Keypair.generate().publicKey, 'finalized');
  assert.deepEqual(r, { kind: 'error' });
});

test('two deals for one escrow at once: one wins, the other is refused, never two acks on two polynomials', async () => {
  const w = world();
  const other = R.deal(w.m);
  const tB = R.termsOf(pid, w.escrowPk, w.e, other.c.c1);
  const reqB = R.signDeal(tB, other.shares[0], w.keys[0].publicKey, w.maker.secretKey.slice(0, 32));
  const res = await Promise.allSettled([w.towers[0].deal(w.reqs[0]), w.towers[0].deal(reqB)]);
  const ok = res.filter((x) => x.status === 'fulfilled');
  assert.equal(ok.length, 1, JSON.stringify(res.map((x) => x.status)));
  const held = w.towers[0].recs.get(w.escrowPk.toBase58())!;
  assert.equal(held.c1, (ok[0] as PromiseFulfilledResult<R.Ack>).value.c1, 'the ack given is for the share kept');
});

test('closed while the tower was away, and the history shows a claim: the share is destroyed', async () => {
  const w = world();
  for (let n = 0; n < 3; n++) await w.towers[n].deal(w.reqs[n]);
  for (const tw of w.towers) tw.o.findSettlement = async () => ({ kind: 'claim' as const });
  w.chain.e = null;
  for (const t of w.towers) await t.tick();
  for (const t of w.towers) assert.throws(() => t.share(w.escrowPk.toBase58()), (e: TowerError) => e.status === 410);
  assert.ok(w.store.every((s) => s[0].share === '0'.repeat(64)));
});

test('released, then refunded and closed between ticks: the record settles instead of being read forever', async () => {
  const w = world();
  for (let n = 0; n < 3; n++) await w.towers[n].deal(w.reqs[n]);
  w.chain.e = { ...w.e, state: P.ST.ABORTED };
  w.towers[0].o.peers = []; // can't rebuild yet
  await w.towers[0].tick();
  const r = w.towers[0].recs.get(w.escrowPk.toBase58())!;
  assert.ok(r.releasable && !r.refundSig);
  w.chain.e = null;
  await w.towers[0].tick();
  assert.ok(r.refundSig, 'settled');
});
