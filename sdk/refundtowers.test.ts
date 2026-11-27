// Refund towers (XMR->SOL): the maker deals 2-of-3 Feldman shares of its key half; towers ack; the
// page checks the acks before it shows a deposit address; towers release only once a claim is impossible.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519';
import { Keypair, PublicKey } from '@solana/web3.js';
import * as K from './keys.ts';
import * as P from './program.ts';
import * as R from './refundtowers.ts';

const Point = ed25519.ExtendedPoint;
const pid = Keypair.generate().publicKey;

function escrowFor(refundPoint: Uint8Array, over: Partial<P.EscrowAccount> = {}): P.EscrowAccount {
  const maker = Keypair.generate().publicKey;
  return {
    state: P.ST.LOCKED, direction: 2, released: false, swapId: new Uint8Array(32).fill(7), locker: maker, claimer: Keypair.generate().publicKey,
    maker, amount: 2_500_000_000n, xmrAmount: 400_000_000_000n, feeBps: 30, claimPoint: K.pub(K.randomScalar()), refundPoint,
    viewPub: K.pub(K.randomScalar()), quoteHash: new Uint8Array(32), watchtowers: [PublicKey.default, PublicKey.default],
    createdAt: 1_800_000_000n, t0: 1_800_021_600n, t1: 1_800_025_200n, settledAt: 0n, secret: new Uint8Array(32), flags: P.F.PROOF,
    link: PublicKey.default, ...over,
  };
}
const towersN = () => [Keypair.generate(), Keypair.generate(), Keypair.generate()];

test('deal: every share checks against the commitments, any two rebuild the half, one alone does not', () => {
  const m = K.randomScalar();
  const d = R.deal(m);
  assert.equal(d.shares.length, 3);
  assert.deepEqual(d.c.c0, K.pub(m));
  for (const sh of d.shares) assert.ok(R.verifyShare(sh, d.c), `share ${sh.i}`);
  for (const [a, b] of [[0, 1], [0, 2], [1, 2], [2, 0]]) assert.deepEqual(R.combine([d.shares[a], d.shares[b]], d.c.c0), m);
  assert.throws(() => R.combine([d.shares[0]], d.c.c0), /two/);
  assert.throws(() => R.combine([d.shares[1], d.shares[1]], d.c.c0), /two/);
  // a single share is a uniformly random scalar, not the half
  for (const sh of d.shares) assert.notDeepEqual(sh.s, m);
});

test('deal at real magnitudes: halves near L and tiny halves round-trip', () => {
  for (const m of [K.bigToLe32(K.L - 1n), K.bigToLe32(1n), K.bigToLe32(K.L / 2n)]) {
    const d = R.deal(m);
    for (const sh of d.shares) assert.ok(R.verifyShare(sh, d.c));
    assert.deepEqual(R.combine([d.shares[2], d.shares[0]], d.c.c0), m);
  }
});

test('verifyShare refuses tampered, wrong-index, non-canonical, zero shares and bad commitments', () => {
  const d = R.deal(K.randomScalar());
  const sh = d.shares[1];
  assert.ok(!R.verifyShare({ i: 2, s: K.scalarAdd(sh.s, K.bigToLe32(1n)) }, d.c), 'tampered');
  assert.ok(!R.verifyShare({ i: 3, s: sh.s }, d.c), 'wrong index');
  assert.ok(!R.verifyShare({ i: 0, s: sh.s }, d.c), 'index 0 is the secret itself');
  assert.ok(!R.verifyShare({ i: 4, s: sh.s }, d.c), 'index out of range');
  assert.ok(!R.verifyShare({ i: 2, s: K.bigToLe32(K.leToBig(sh.s) + K.L) }, d.c), 'non-canonical (s + L)');
  assert.ok(!R.verifyShare({ i: 2, s: new Uint8Array(32) }, d.c), 'zero');
  // C1 = identity would make every share equal the half: one tower would hold it alone
  const ident = Point.ZERO.toRawBytes();
  const m = K.randomScalar();
  assert.ok(!R.verifyShare({ i: 1, s: m }, { c0: K.pub(m), c1: ident }), 'identity C1');
  // C1 with a torsion component
  const torsion = Point.fromHex('26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05');
  const c1t = Point.fromHex(d.c.c1).add(torsion).toRawBytes();
  assert.ok(!R.verifyShare(sh, { c0: d.c.c0, c1: c1t }), 'torsion C1');
  // order-2 torsion with index 2: 2*T = 0, so only the prime-order check stops it
  const t2 = Point.fromHex('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f');
  assert.ok(t2.multiply(2n).equals(Point.ZERO), 'order 2');
  assert.ok(!R.verifyShare(sh, { c0: d.c.c0, c1: Point.fromHex(d.c.c1).add(t2).toRawBytes() }), 'order-2 torsion C1 at index 2');
});

test('combine refuses shares that do not rebuild the on-chain refund point', () => {
  const d = R.deal(K.randomScalar());
  const other = R.deal(K.randomScalar());
  assert.throws(() => R.combine([d.shares[0], other.shares[1]], d.c.c0), /refund point/);
});

test('deal requests are signed by the escrow\'s locker and bound to tower, index, share and terms', () => {
  const m = K.randomScalar(), d = R.deal(m), maker = Keypair.generate(), towers = towersN();
  const e = escrowFor(d.c.c0, { locker: maker.publicKey, maker: maker.publicKey });
  const escrowPk = Keypair.generate().publicKey;
  const t = R.termsOf(pid, escrowPk, e, d.c.c1);
  const req = R.signDeal(t, d.shares[0], towers[0].publicKey, maker.secretKey.slice(0, 32));
  assert.ok(R.verifyDeal(req, t, towers[0].publicKey));
  assert.ok(!R.verifyDeal(req, t, towers[1].publicKey), 'other tower');
  assert.ok(!R.verifyDeal({ ...req, share: K.toHex(d.shares[1].s), index: 2 }, t, towers[0].publicKey), 'other share');
  assert.ok(!R.verifyDeal(req, { ...t, t1: t.t1 + 1n }, towers[0].publicKey), 'other t1');
  const stranger = Keypair.generate();
  const forged = R.signDeal(t, d.shares[0], towers[0].publicKey, stranger.secretKey.slice(0, 32));
  assert.ok(!R.verifyDeal(forged, t, towers[0].publicKey), 'not signed by the locker');
  // the request's own signature, checked before any chain read
  assert.ok(R.verifyDealAuth(req, [maker.publicKey.toBase58()]));
  assert.ok(!R.verifyDealAuth(req, [stranger.publicKey.toBase58()]), 'maker not on the list');
  assert.ok(!R.verifyDealAuth({ ...req, share: K.toHex(d.shares[1].s) }, [maker.publicKey.toBase58()]), 'altered body');
  assert.ok(!R.verifyDealAuth({ ...forged, maker: maker.publicKey.toBase58() }, [maker.publicKey.toBase58()]), 'stranger claiming to be the maker');
  assert.ok(!R.verifyDealAuth({ ...req, auth: undefined }, [maker.publicKey.toBase58()]));
});

test('acks: the page needs enough distinct listed towers, all on the same commitments, bound to this escrow', () => {
  const m = K.randomScalar(), d = R.deal(m), towers = towersN();
  const e = escrowFor(d.c.c0);
  const escrowPk = Keypair.generate().publicKey;
  const t = R.termsOf(pid, escrowPk, e, d.c.c1);
  const listed = towers.map((k) => ({ pubkey: k.publicKey }));
  const acks = towers.map((k, n) => R.signAck(t, n + 1, k));
  assert.deepEqual(R.checkAcks(acks, listed, pid, escrowPk, e, 3), { ok: true, c1: d.c.c1, count: 3 });
  assert.equal(R.checkAcks(acks.slice(0, 2), listed, pid, escrowPk, e, 3).ok, false, 'two of three when three are required');
  assert.equal(R.checkAcks(acks.slice(0, 2), listed, pid, escrowPk, e, 2).ok, true);
  assert.equal(R.checkAcks([acks[0], acks[0], acks[0]], listed, pid, escrowPk, e, 2).ok, false, 'one tower counted once');
  // a tower that isn't listed
  const rogue = Keypair.generate();
  const rogueAck = R.signAck(t, 2, rogue);
  assert.equal(R.checkAcks([acks[0], rogueAck], listed, pid, escrowPk, e, 2).ok, false, 'unlisted tower');
  // a listed tower acking at the wrong index
  assert.equal(R.checkAcks([acks[0], R.signAck(t, 3, towers[1])], listed, pid, escrowPk, e, 2).ok, false, 'wrong index');
  // inconsistent polynomials: the maker shows each tower a different C1
  const d2 = R.deal(m);
  const t2 = R.termsOf(pid, escrowPk, e, d2.c.c1);
  assert.equal(R.checkAcks([acks[0], R.signAck(t2, 2, towers[1])], listed, pid, escrowPk, e, 2).ok, false, 'different C1');
  // the escrow changed (re-locked at the same address, other refund point, other t1)
  assert.equal(R.checkAcks(acks, listed, pid, escrowPk, { ...e, createdAt: e.createdAt + 1n }, 2).ok, false, 'created_at');
  assert.equal(R.checkAcks(acks, listed, pid, escrowPk, { ...e, t1: e.t1 + 60n }, 2).ok, false, 't1');
  assert.equal(R.checkAcks(acks, listed, pid, escrowPk, { ...e, refundPoint: K.pub(K.randomScalar()) }, 2).ok, false, 'refund point');
  assert.equal(R.checkAcks(acks, listed, pid, Keypair.generate().publicKey, e, 2).ok, false, 'other escrow');
  assert.equal(R.checkAcks(acks, listed, Keypair.generate().publicKey, escrowPk, e, 2).ok, false, 'other program');
  // a tower acking other commitments can't veto two honest ones (2-of-3 with minAcks 2)
  assert.equal(R.checkAcks([acks[0], acks[1], R.signAck(t2, 3, towers[2])], listed, pid, escrowPk, e, 2).ok, true, 'bad C1 from one tower');
  assert.equal(R.checkAcks([acks[0], acks[1], R.signAck(t2, 3, towers[2])], listed, pid, escrowPk, e, 3).ok, false);
  // a missing or broken minAcks never fails open
  for (const bad of [undefined, NaN, 1, 0, 2.5]) assert.equal(R.checkAcks(acks, listed, pid, escrowPk, e, bad as any).ok, false, `minAcks ${bad}`);
  assert.equal(R.checkAcks(acks, [...listed, { pubkey: rogue.publicKey }], pid, escrowPk, e, 2).ok, false, 'four listed');
  // garbage never throws
  assert.equal(R.checkAcks([{ index: 1, tower: 'x', c1: 'zz', sig: '00' } as any], listed, pid, escrowPk, e, 1).ok, false);
});

test('release rule: only once a claim is impossible, every reader agreeing, at finalized', () => {
  const d = R.deal(K.randomScalar());
  const e = escrowFor(d.c.c0);
  const held = { createdAt: e.createdAt, refundPoint: e.refundPoint, t1: e.t1 };
  const at = (state: number, clock: number, over: Partial<P.EscrowAccount> = {}): R.ChainRead => ({ kind: 'escrow', e: { ...e, state, ...over }, clock });
  const t1 = Number(e.t1), M = R.RELEASE_MARGIN_SECS;
  assert.equal(R.releaseDecision([at(P.ST.LOCKED, t1 - 1), at(P.ST.LOCKED, t1 - 1)], held), 'wait');
  assert.equal(R.releaseDecision([at(P.ST.READY, t1 + M - 1), at(P.ST.READY, t1 + M - 1)], held), 'wait', 'inside the margin');
  assert.equal(R.releaseDecision([at(P.ST.READY, t1 + M), at(P.ST.READY, t1 + M)], held), 'release');
  assert.equal(R.releaseDecision([at(P.ST.LOCKED, t1 + M), at(P.ST.LOCKED, t1 + M)], held), 'release');
  assert.equal(R.releaseDecision([at(P.ST.ABORTED, t1 - 9999), at(P.ST.ABORTED, t1 - 9999)], held), 'release', 'aborted can never be claimed');
  assert.equal(R.releaseDecision([at(P.ST.REFUNDED, t1), at(P.ST.REFUNDED, t1)], held), 'release');
  assert.equal(R.releaseDecision([at(P.ST.CLAIMED, t1 + M), at(P.ST.CLAIMED, t1 + M)], held), 'claimed');
  // one reader lying about state or clock: wait, never release, never delete
  assert.equal(R.releaseDecision([at(P.ST.LOCKED, t1 + M), at(P.ST.CLAIMED, t1 + M)], held), 'wait');
  assert.equal(R.releaseDecision([at(P.ST.LOCKED, t1 + M), at(P.ST.LOCKED, t1 - 5)], held), 'wait');
  assert.equal(R.releaseDecision([at(P.ST.ABORTED, t1), { kind: 'missing', clock: t1 }], held), 'wait');
  assert.equal(R.releaseDecision([at(P.ST.LOCKED, t1 + M)], held), 'wait', 'one reader is not enough');
  assert.equal(R.releaseDecision([at(P.ST.LOCKED, t1 + M), { kind: 'error' }], held), 'wait');
  // gone, or a different escrow at the same address: never on this record
  assert.equal(R.releaseDecision([{ kind: 'missing', clock: t1 + M }, { kind: 'missing', clock: t1 + M }], held), 'gone');
  assert.equal(R.releaseDecision([at(P.ST.ABORTED, t1, { createdAt: e.createdAt + 5n }), at(P.ST.ABORTED, t1, { createdAt: e.createdAt + 5n })], held), 'gone');
  assert.equal(R.releaseDecision([at(P.ST.ABORTED, t1, { refundPoint: K.pub(K.randomScalar()) }), at(P.ST.ABORTED, t1, { refundPoint: K.pub(K.randomScalar()) })], held), 'gone');
});
