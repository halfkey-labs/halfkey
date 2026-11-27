// Offline unit tests for the SDK money paths: key derivation, key split, Monero addresses,
// quote signatures, point checks, and the view-key output scanner (incl. forged amounts).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519';
import { keccak_256 } from '@noble/hashes/sha3';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils';
import { Keypair, PublicKey } from '@solana/web3.js';
import * as K from './keys.ts';
import * as P from './program.ts';
import * as T from './taker.ts';
import { scanTx } from './xmrverify.ts';

const Point = ed25519.ExtendedPoint;

test('wallet-derived halves are deterministic per swap and differ across swaps', () => {
  const kp = Keypair.generate();
  const sig = ed25519.sign(utf8ToBytes(K.KEY_MESSAGE), kp.secretKey.slice(0, 32));
  assert.ok(K.checkDeterministic(sig, ed25519.sign(utf8ToBytes(K.KEY_MESSAGE), kp.secretKey.slice(0, 32))));
  const root = K.rootFromSignature(sig);
  const id1 = K.newSwapId(), id2 = K.newSwapId();
  assert.deepEqual(K.deriveHalf(root, id1), K.deriveHalf(root, id1));
  assert.notDeepEqual(K.deriveHalf(root, id1).spend, K.deriveHalf(root, id2).spend);
  const h = K.deriveHalf(root, id1);
  assert.ok(K.isCanonical(h.spend) && K.isCanonical(h.view));
  assert.notDeepEqual(h.spend, h.view);
  assert.ok(K.KEY_MESSAGE.includes('halfkey.xyz'), 'the message names the domain (phishing guard)');
});

test('2-of-2 split: the sum of the halves spends the shared address', () => {
  const a = K.randomHalf(), b = K.randomHalf();
  const w = K.sharedWallet(a.spendPub, b.spendPub, b.view, 'stagenet');
  const s = K.scalarAdd(a.spend, b.spend);
  assert.deepEqual(K.pub(s), w.spendPub);
  assert.equal(K.moneroAddress(K.pub(s), K.pub(b.view), 'stagenet'), w.address);
  // neither half alone works
  assert.notDeepEqual(K.pub(a.spend), w.spendPub);
});

test('Monero addresses: round trip, wrong network, bad checksum', () => {
  const h = K.randomHalf();
  for (const net of ['mainnet', 'stagenet', 'testnet'] as const) {
    const a = K.moneroAddress(h.spendPub, h.viewPub, net);
    const p = K.parseMoneroAddress(a, net);
    assert.deepEqual(p.spendPub, h.spendPub);
    assert.ok({ mainnet: ['4'], stagenet: ['5'], testnet: ['9', 'A'] }[net].includes(a[0]), `${net} prefix ${a[0]}`);
  }
  const a = K.moneroAddress(h.spendPub, h.viewPub, 'stagenet');
  assert.throws(() => K.parseMoneroAddress(a, 'mainnet'), /not a mainnet/);
  const flipped = a.slice(0, 20) + (a[20] === 'A' ? 'B' : 'A') + a.slice(21);
  assert.throws(() => K.parseMoneroAddress(flipped, 'stagenet'));
});

test('quotes: signed by the maker, tamper-evident, hash-bound', () => {
  const maker = Keypair.generate();
  const q: K.Quote = { v: 1, maker: maker.publicKey.toBase58(), direction: 1, lamports: '1000', piconero: '5', feeBps: 50, expiresAt: 9e9, nonce: 'ab' };
  const sig = K.signQuote(q, maker.secretKey.slice(0, 32));
  assert.ok(K.verifyQuote(q, sig, maker.publicKey.toBytes()));
  assert.ok(!K.verifyQuote({ ...q, piconero: '6' }, sig, maker.publicKey.toBytes()));
  assert.notDeepEqual(K.quoteHash(q), K.quoteHash({ ...q, nonce: 'ac' }));
  const cfg = { feeBps: 50, holderFeeBps: 25 } as P.ConfigAccount;
  assert.equal(T.checkQuote({ quote: q, sig }, maker.publicKey, 1, cfg, 100), null);
  assert.match(T.checkQuote({ quote: q, sig }, Keypair.generate().publicKey, 1, cfg, 100)!, /different maker/);
  assert.match(T.checkQuote({ quote: { ...q, expiresAt: 50 }, sig }, maker.publicKey, 1, cfg, 100)!, /expired/);
  assert.match(T.checkQuote({ quote: q, sig }, maker.publicKey, 2, cfg, 100)!, /direction/);
});

test('point checks reject identity, small order, torsion and non-canonical encodings', () => {
  const good = K.randomHalf().spendPub;
  assert.ok(K.isGoodPoint(good));
  const id = new Uint8Array(32); id[0] = 1;
  assert.ok(!K.isGoodPoint(id));
  const t8 = K.fromHex('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a');
  assert.ok(!K.isGoodPoint(t8));
  assert.ok(!K.isGoodPoint(K.pointAdd(good, t8)));
  const nonCanon = new Uint8Array(32).fill(0xff); nonCanon[31] = 0x7f; nonCanon[0] = 0xee; // y = p+? (>= p)
  assert.ok(!K.isGoodPoint(nonCanon));
});

// Build a synthetic Monero output exactly as a sender does, then scan it with the view key.
function fakeTx(spendPub: Uint8Array, viewPub: Uint8Array, amount: bigint, forgeAmount?: bigint) {
  const hs = (b: Uint8Array) => K.leToBig(keccak_256(b)) % K.L;
  const r = K.leToBig(K.randomScalar());
  const R = Point.BASE.multiply(r).toRawBytes();
  const D = Point.fromHex(viewPub).multiply(r).multiply(8n).toRawBytes();
  const s = hs(concatBytes(D, Uint8Array.of(0)));
  const outKey = Point.BASE.multiply(s).add(Point.fromHex(spendPub)).toRawBytes();
  const sb = K.bigToLe32(s);
  const mask = keccak_256(concatBytes(utf8ToBytes('amount'), sb));
  const shown = forgeAmount ?? amount;
  const amt = new Uint8Array(8); for (let i = 0; i < 8; i++) amt[i] = Number((shown >> BigInt(8 * i)) & 0xffn) ^ mask[i];
  const y = hs(concatBytes(utf8ToBytes('commitment_mask'), sb));
  const H = Point.fromHex('8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94');
  const C = Point.BASE.multiply(y).add(H.multiply(amount)).toRawBytes(); // commits to the REAL amount
  return {
    extra: [1, ...R], vout: [{ target: { tagged_key: { key: K.toHex(outKey), view_tag: '00' } } }],
    rct_signatures: { ecdhInfo: [{ amount: K.toHex(amt) }], outPk: [K.toHex(C)] }, unlock_time: 0,
  };
}

test('view-key scanner finds the output, decodes the amount, rejects a forged amount', () => {
  const maker = K.randomHalf(), user = K.randomHalf();
  const w = K.sharedWallet(maker.spendPub, user.spendPub, user.view, 'stagenet');
  const tx = fakeTx(w.spendPub, w.viewPub, 12_345_678_900n);
  const found = scanTx(tx, w.spendPub, w.view);
  assert.equal(found.length, 1);
  assert.equal(found[0].amount, 12_345_678_900n);
  // a maker that encrypts a bigger amount than it committed to is caught
  assert.equal(scanTx(fakeTx(w.spendPub, w.viewPub, 1n, 12_345_678_900n), w.spendPub, w.view).length, 0);
  // someone else's view key sees nothing
  assert.equal(scanTx(tx, w.spendPub, K.randomScalar()).length, 0);
});

test('phase machine: SOL->XMR user and XMR->SOL claimer', () => {
  const me = Keypair.generate().publicKey, other = Keypair.generate().publicKey;
  const base = { direction: 1, locker: me, claimer: other, t0: 100n, t1: 200n, state: P.ST.LOCKED } as unknown as P.EscrowAccount;
  const pol = { minT0Secs: 0, minWindowSecs: 0, claimMarginSecs: 30 };
  assert.equal(T.phaseOf(base, me, 50, pol), 'waiting-xmr');
  // No committee: past t0 the maker still needs the user's release (late finish keeps it open), so nothing auto-releases.
  assert.equal(T.phaseOf(base, me, 150, pol), 'waiting-xmr');
  assert.equal(T.phaseOf(base, me, 250, pol), 'refund');
  assert.equal(T.phaseOf({ ...base, state: P.ST.CLAIMED }, me, 250, pol), 'collect');
  assert.equal(T.phaseOf({ ...base, state: P.ST.ABORTED }, me, 50, pol), 'refund');
  const rev = { ...base, direction: 2, locker: other, claimer: me } as P.EscrowAccount;
  assert.equal(T.phaseOf(rev, me, 50, pol), 'deposit');
  assert.equal(T.phaseOf({ ...rev, state: P.ST.READY }, me, 50, pol), 'claim-sol');
  assert.equal(T.phaseOf(rev, me, 175, pol), 'xmr-back', 'inside the claim margin: never reveal');
});

test('fullSpendKey refuses a wrong revealed secret', () => {
  const maker = K.randomHalf(), user = K.randomHalf();
  const e = { state: P.ST.CLAIMED, secret: maker.spend, claimPoint: maker.spendPub, refundPoint: user.spendPub } as unknown as P.EscrowAccount;
  assert.deepEqual(K.pub(T.fullSpendKey(e, user)), K.pointAdd(maker.spendPub, user.spendPub));
  assert.throws(() => T.fullSpendKey({ ...e, secret: K.randomScalar() } as P.EscrowAccount, user), /does not complete/);
  assert.throws(() => T.fullSpendKey({ ...e, state: P.ST.LOCKED } as P.EscrowAccount, user), /not revealed/);
});

test('consent digest binds every field and the escrow address', () => {
  const pid = Keypair.generate().publicKey, locker = Keypair.generate().publicKey;
  const h = K.randomHalf();
  const p: P.LockParams = { swapId: K.newSwapId(), claimer: Keypair.generate().publicKey, direction: 1, amount: 5n, xmrAmount: 6n, claimPoint: h.spendPub, refundPoint: h.viewPub, viewPub: h.viewPub, quoteHash: new Uint8Array(32), t0Secs: 1, windowSecs: 2, watchtowers: [], makerAuthority: PublicKey.default, consentExpiry: 3, feeBps: 50 };
  const d = K.toHex(P.consentDigest(pid, locker, p));
  for (const tweak of [{ amount: 6n }, { xmrAmount: 7n }, { t0Secs: 2 }, { windowSecs: 3 }, { consentExpiry: 4 }, { feeBps: 25 }, { swapId: K.newSwapId() }]) {
    assert.notEqual(K.toHex(P.consentDigest(pid, locker, { ...p, ...tweak })), d);
  }
  assert.notEqual(K.toHex(P.consentDigest(pid, Keypair.generate().publicKey, p)), d);
  // watchtowers are the user's choice and deliberately not bound
  assert.equal(K.toHex(P.consentDigest(pid, locker, { ...p, watchtowers: [locker] })), d);
});

test('verifyXmrToSolEscrow resume mode (no quote): checks the escrow against this wallet only', async () => {
  const pid = Keypair.generate().publicKey, maker = Keypair.generate().publicKey, claimer = Keypair.generate().publicKey;
  const root = new Uint8Array(64).fill(7), swapId = K.newSwapId(), half = K.deriveHalf(root, swapId);
  const makerHalf = K.deriveHalf(new Uint8Array(64).fill(9), swapId);
  const now = 1_000_000, pol: T.Policy = { minT0Secs: 600, minWindowSecs: 600, claimMarginSecs: 60, minWatchtowers: 0 };
  const build = (o: { refund?: Uint8Array; claimPt?: Uint8Array; claimer?: PublicKey; t0?: number } = {}) => {
    const d = new Uint8Array(P.ESCROW_LEN), v = new DataView(d.buffer);
    d[0] = 0xe5; d[1] = 1; d[2] = P.ST.LOCKED; d[3] = 2;
    d.set(swapId, 8); d.set(maker.toBytes(), 40); d.set((o.claimer ?? claimer).toBytes(), 72); d.set(maker.toBytes(), 104);
    v.setBigUint64(136, 5n * 10n ** 9n, true); v.setBigUint64(144, 10n ** 12n, true); v.setUint16(152, 50, true);
    d.set(o.claimPt ?? half.spendPub, 160); d.set(o.refund ?? makerHalf.spendPub, 192); d.set(half.viewPub, 224);
    const t0 = o.t0 ?? now + 3600;
    v.setBigInt64(352, BigInt(now - 60), true); v.setBigInt64(360, BigInt(t0), true); v.setBigInt64(368, BigInt(t0 + 7200), true);
    return d;
  };
  const escrow = Keypair.generate().publicKey;
  const proof = K.proveKey(makerHalf.spend, K.keyProofContext(pid.toBytes(), escrow.toBytes(), half.spendPub));
  const run = (data: Uint8Array, makerKeyProof = proof) => T.verifyXmrToSolEscrow({
    conn: { getAccountInfo: async () => ({ owner: pid, data }) } as any, pid, escrow,
    makerAuthority: maker, claimer, half, net: 'stagenet', policy: pol, nowSecs: now, makerKeyProof,
  });
  const ok = await run(build());
  assert.equal(ok.depositAddress, K.sharedWallet(makerHalf.spendPub, half.spendPub, half.view, 'stagenet').address);
  await assert.rejects(run(build({ claimer: Keypair.generate().publicKey })), /claimer/);
  await assert.rejects(run(build({ claimPt: makerHalf.spendPub })), /claim point/);
  await assert.rejects(run(build({ refund: ed25519.ExtendedPoint.fromHex(half.spendPub).negate().toRawBytes() })), /maker key cancels ours/);
  await assert.rejects(run(build({ refund: new Uint8Array(32) })), /maker key/);
  await assert.rejects(run(build({ t0: now + 100 })), /too little time/);
  await assert.rejects(T.verifyXmrToSolEscrow({ conn: {} as any, pid, escrow: pid, makerAuthority: maker, claimer, half, net: 'stagenet', policy: pol, nowSecs: now, makerSpendPub: makerHalf.spendPub, makerKeyProof: proof }), /both/);
  // no proof, or a proof for another escrow / taker key: refused before any deposit
  await assert.rejects(run(build(), new Uint8Array(64)), /prove its key/);
  const other = K.proveKey(makerHalf.spend, K.keyProofContext(pid.toBytes(), Keypair.generate().publicKey.toBytes(), half.spendPub));
  await assert.rejects(run(build(), other), /prove its key/);
});

test('maker key proof: binds the key and the context; a key picked from ours cannot be proven', () => {
  const ctx = new Uint8Array(96).fill(3), m = K.randomScalar(), M = K.pub(m);
  const pr = K.proveKey(m, ctx);
  assert.ok(K.verifyKeyProof(M, ctx, pr));
  assert.ok(!K.verifyKeyProof(M, new Uint8Array(96).fill(4), pr), 'other context');
  assert.ok(!K.verifyKeyProof(K.pub(K.randomScalar()), ctx, pr), 'other key');
  const bad = pr.slice(); bad[40] ^= 1;
  assert.ok(!K.verifyKeyProof(M, ctx, bad), 'tampered');
  // rogue key M' = t*G - A: the maker knows t (the shared key) but not log(M'); a proof made with t is for t*G, not M'
  const A = K.pub(K.randomScalar()), t = K.randomScalar();
  const rogue = ed25519.ExtendedPoint.fromHex(K.pub(t)).subtract(ed25519.ExtendedPoint.fromHex(A)).toRawBytes();
  assert.ok(!K.verifyKeyProof(rogue, ctx, K.proveKey(t, ctx)));
});

test('verifyXmrToSolEscrow with refund towers: no deposit address without enough acks on this escrow; t1 bounded', async () => {
  const R = await import('./refundtowers.ts');
  const pid = Keypair.generate().publicKey, maker = Keypair.generate().publicKey, claimer = Keypair.generate().publicKey;
  const root = new Uint8Array(64).fill(3), swapId = K.newSwapId(), half = K.deriveHalf(root, swapId);
  const m = K.randomScalar(), M = K.pub(m);
  const now = 1_000_000, pol: T.Policy = { minT0Secs: 600, minWindowSecs: 600, claimMarginSecs: 60, minWatchtowers: 0 };
  const build = (t0 = now + 21_600, win = 3600) => {
    const d = new Uint8Array(P.ESCROW_LEN), v = new DataView(d.buffer);
    d[0] = 0xe5; d[1] = 1; d[2] = P.ST.LOCKED; d[3] = 2; d[6] = P.F.PROOF;
    d.set(swapId, 8); d.set(maker.toBytes(), 40); d.set(claimer.toBytes(), 72); d.set(maker.toBytes(), 104);
    v.setBigUint64(136, 5n * 10n ** 9n, true); v.setBigUint64(144, 10n ** 12n, true); v.setUint16(152, 50, true);
    d.set(half.spendPub, 160); d.set(M, 192); d.set(half.viewPub, 224);
    v.setBigInt64(352, BigInt(now - 60), true); v.setBigInt64(360, BigInt(t0), true); v.setBigInt64(368, BigInt(t0 + win), true);
    return d;
  };
  const escrow = Keypair.generate().publicKey;
  const proof = K.proveKey(m, K.keyProofContext(pid.toBytes(), escrow.toBytes(), half.spendPub));
  const keys = [Keypair.generate(), Keypair.generate(), Keypair.generate()];
  const listed = keys.map((k) => ({ pubkey: k.publicKey }));
  const data = build();
  const e = P.decodeEscrow(data, escrow);
  const dl = R.deal(m);
  const t = R.termsOf(pid, escrow, e, dl.c.c1);
  const acks = keys.map((k, n) => R.signAck(t, n + 1, k));
  const run = (refundTowers: any, d = data) => T.verifyXmrToSolEscrow({
    conn: { getAccountInfo: async () => ({ owner: pid, data: d }) } as any, pid, escrow,
    makerAuthority: maker, claimer, half, net: 'stagenet', policy: pol, nowSecs: now, makerKeyProof: proof, refundTowers,
  });
  const ok = await run({ listed, minAcks: 3, acks });
  assert.equal(ok.depositAddress, K.sharedWallet(M, half.spendPub, half.view, 'stagenet').address);
  await assert.rejects(run({ listed, minAcks: 3, acks: acks.slice(0, 2) }), /refund towers/);
  await assert.rejects(run({ listed, minAcks: 3, acks: [] }), /refund towers/);
  // acks for another escrow's terms (a longer t1) don't count
  await assert.rejects(run({ listed, minAcks: 2, acks }, build(now + 21_600, 7200)), /refund towers/);
  // the user's XMR could wait until t1: a maker that sets t1 days out is refused
  await assert.rejects(run({ listed, minAcks: 2, acks: [] }, build(now + 3 * 86_400)), /too far/);
});
