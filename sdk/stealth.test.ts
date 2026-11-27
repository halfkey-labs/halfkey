// Offline unit tests for stealth Solana addresses: derivation vectors (cross-checked against an
// independent recomputation), scan, spend key, raw-scalar signing (RFC 8032 vectors + OpenSSL
// verify), wrong-key negatives, torsion / small-order / non-canonical points, record parsing.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { utf8ToBytes, hexToBytes, bytesToHex } from '@noble/hashes/utils';
import { Keypair, PublicKey, SystemProgram, Transaction, TransactionMessage, VersionedTransaction } from '@solana/web3.js';
import * as K from './keys.ts';
import * as P from './program.ts';
import * as S from './stealth.ts';

const Point = ed25519.ExtendedPoint;
const L = K.L;

// Fixed inputs: a root and an r from labelled hashes, so anyone can rebuild them.
const ROOT = sha512(utf8ToBytes('halfkey stealth test vector root'));
const R_SCALAR = K.reduce(sha512(utf8ToBytes('halfkey stealth test vector r')));
const V = {
  view: '048a81b508bc794df802ea5c2cfc311681d3766c1f3b5a9d0a55439a84e1a40b',
  spend: 'f937bc864883e6412d7c5e5addd8331c9e68006e49d95bdc12603ae87aa6d200',
  viewPub: '933bad819765f1c6824d9cebce3fd9d8a420f7f3a1858deb04ea1ffdeea6d03f',
  spendPub: '65b749c6c3f3ccf990844885e9756511af0bd7877d1bb61f154f078d3666b89c',
  meta: 'hks1ukki6WexCJmsviof7MzJekDsSEjrLTJq67CEBFDug5tby18bSc2LNR6haaYPUhTMwsGuwtAz5vWTeKJ4m54fvS5ZADGr6',
  meta1: 'hks1ahZiQqassRs9vzb8vjHGt9DNpJVVjbGBjPqfA5QWxZ1mMUS5YZwNBAMk1CZLuQ43c7CwhYN2JmnHmqMeu6gt6zKV4mE4M',
  r: '0ce8b8febf82404f19c2d40d6a7862d34c035f91211f9cd6a36ff03810c55b04',
  R: '78880607291581f5c09ef9a1663bcf73a89ea733da2ef6d1a290c86667840245',
  key: '2dbdeefa4d2948862dabf17c89d2f22fecfdd67a908781e8877cd8e497c6d8ce',
  address: '45ZKpog9v81Gq6WjrKNH8AQBoL3q5d9eMTXF9DsD1KQH',
  secret: 'e0de9fb50bb92a8ca9b9a2394c318db272355fc3341408c58c4ba8e70821740b',
  sigHalfkey: 'e37b6e619ef7cfa86fc1925a226605d128afb78d74ac55ce07aacb15dd4fdbbd821225c5484c4c3c207aff37dfa686f15bf3d7fef29537ed775b9a519f378a09',
};

// Independent recomputation: node:crypto SHA-512, little-endian bigint, multiply in a different order.
const nodeSha512 = (...parts: Uint8Array[]) => new Uint8Array(crypto.createHash('sha512').update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest());
const le = (b: Uint8Array) => BigInt('0x' + Buffer.from(b).reverse().toString('hex'));
const u32 = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const indep = {
  scalar: (...p: Uint8Array[]) => le(nodeSha512(...p)) % L,
  meta(root: Uint8Array, acct: number) {
    const v = this.scalar(root, utf8ToBytes('halfkey/stealth/view/v1'), u32(acct));
    const s = this.scalar(root, utf8ToBytes('halfkey/stealth/spend/v1'), u32(acct));
    return { v, s, V: Point.BASE.multiply(v), S: Point.BASE.multiply(s) };
  },
  /** receiver view: D = v·(8·R) (cofactor first), h, P = h·G + S */
  oneTime(v: bigint, Spt: InstanceType<typeof Point>, Rbytes: Uint8Array, index = 0) {
    const D = Point.fromHex(Rbytes).multiplyUnsafe(8n).multiply(v).toRawBytes();
    const h = this.scalar(utf8ToBytes('halfkey-stealth-v1'), D, u32(index));
    return { h, P: Point.BASE.multiply(h).add(Spt) };
  },
};

// Openssl (node:crypto) verifier, independent of noble.
function opensslVerify(pub: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  const key = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(pub).toString('base64url') }, format: 'jwk' });
  return crypto.verify(null, Buffer.from(msg), key, Buffer.from(sig));
}

// An order-8 point (torsion) and helpers.
const T8 = Point.fromHex('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a');

test('torsion fixture really has order 8', () => {
  assert.ok(!T8.equals(Point.ZERO));
  assert.ok(T8.multiplyUnsafe(4n).equals(Point.ZERO) === false);
  assert.ok(T8.multiplyUnsafe(8n).equals(Point.ZERO));
});

test('meta-key derivation vectors (and an independent recomputation)', () => {
  const m = S.deriveStealthMeta(ROOT, 0);
  assert.equal(bytesToHex(m.view), V.view);
  assert.equal(bytesToHex(m.spend), V.spend);
  assert.equal(bytesToHex(m.viewPub), V.viewPub);
  assert.equal(bytesToHex(m.spendPub), V.spendPub);
  assert.equal(S.encodeMetaAddress(m), V.meta);
  assert.equal(S.encodeMetaAddress(S.deriveStealthMeta(ROOT, 1)), V.meta1);
  const i = indep.meta(ROOT, 0);
  assert.equal(i.v, le(m.view));
  assert.equal(i.s, le(m.spend));
  assert.equal(bytesToHex(i.V.toRawBytes()), V.viewPub);
  // stealth keys never equal the swap halves from the same root
  const half = K.deriveHalf(ROOT, new Uint8Array(32));
  assert.notEqual(bytesToHex(half.spend), V.spend);
  assert.notEqual(bytesToHex(half.view), V.view);
  assert.notEqual(V.view, V.spend);
});

test('one-time key vectors: payer (8·r·V) and receiver (v·8·R) agree, independent recomputation matches', () => {
  const m = S.deriveStealthMeta(ROOT, 0);
  assert.equal(bytesToHex(R_SCALAR), V.r);
  const ot = S.deriveOneTime(m, { r: R_SCALAR });
  assert.equal(bytesToHex(ot.R), V.R);
  assert.equal(bytesToHex(ot.key), V.key);
  assert.equal(ot.address.toBase58(), V.address);
  const i = indep.oneTime(le(m.view), Point.fromHex(m.spendPub), ot.R);
  assert.equal(bytesToHex(i.P.toRawBytes()), V.key);
  const s = S.oneTimeSecret(m, ot.R, 0, ot.key);
  assert.equal(bytesToHex(s), V.secret);
  assert.equal((i.h + le(m.spend)) % L, le(s), 's_i = h + s mod L');
  assert.deepEqual(K.pub(s), ot.key, 's_i·G == P_i');
  assert.ok(K.isGoodPoint(ot.key), 'P_i is canonical and prime-order');
});

test('raw-scalar signing: RFC 8032 vectors through signExpanded', () => {
  // RFC 8032 section 7.1, tests 1-3. a and prefix come from SHA-512(seed) exactly as the RFC says.
  const vecs = [
    ['9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', '', 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'],
    ['4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb', '72', '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'],
    ['c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7', 'af82', '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a'],
  ];
  for (const [seed, msg, sig] of vecs) {
    const h = sha512(hexToBytes(seed));
    const a = h.slice(0, 32); a[0] &= 248; a[31] &= 127; a[31] |= 64;
    const out = S.signExpanded(le(a), h.slice(32), hexToBytes(msg));
    assert.equal(bytesToHex(out), sig);
  }
});

test('raw-scalar signing: verifies under noble AND OpenSSL; deterministic; vector', () => {
  const m = S.deriveStealthMeta(ROOT, 0);
  const s = S.oneTimeSecret(m, hexToBytes(V.R), 0, hexToBytes(V.key));
  const msg = utf8ToBytes('halfkey');
  const sig = S.signRaw(msg, s);
  assert.equal(bytesToHex(sig), V.sigHalfkey);
  assert.deepEqual(S.signRaw(msg, s), sig, 'deterministic');
  assert.ok(ed25519.verify(sig, msg, hexToBytes(V.key)));
  assert.ok(opensslVerify(hexToBytes(V.key), msg, sig));
  // ZIP-215 off: the strict (RFC) noble verifier agrees too
  assert.ok(ed25519.verify(sig, msg, hexToBytes(V.key), { zip215: false }));
  // random scalars and messages
  for (let i = 0; i < 25; i++) {
    const k = K.randomScalar();
    const mm = crypto.randomBytes(i * 13);
    const sg = S.signRaw(mm, k);
    assert.ok(opensslVerify(K.pub(k), mm, sg), `openssl verify #${i}`);
    assert.ok(le(sg.slice(32)) < L, 'S is canonical');
  }
});

test('wrong keys: other view key, other spend key, other index, other scalar never match or verify', () => {
  const m = S.deriveStealthMeta(ROOT, 0);
  const other = S.deriveStealthMeta(sha512(utf8ToBytes('someone else')), 0);
  const m1 = S.deriveStealthMeta(ROOT, 1);
  const R = hexToBytes(V.R), key = hexToBytes(V.key);
  assert.ok(S.isMine(m.view, m.spendPub, R, key));
  assert.ok(!S.isMine(other.view, m.spendPub, R, key), 'wrong view key');
  assert.ok(!S.isMine(m.view, other.spendPub, R, key), 'wrong spend key');
  assert.ok(!S.isMine(m1.view, m1.spendPub, R, key), 'other account of the same wallet');
  assert.ok(!S.isMine(m.view, m.spendPub, R, key, 1), 'other output index');
  assert.ok(!S.isMine(m.view, m.spendPub, K.pub(K.randomScalar()), key), 'other R');
  assert.throws(() => S.oneTimeSecret(other, R, 0, key), /does not own/);
  assert.throws(() => S.checkStealthClaimer(other, R, new PublicKey(key)), /does not pay/);
  const wrong = S.oneTimeSecret(other, R, 0);
  const msg = utf8ToBytes('spend');
  assert.ok(!ed25519.verify(S.signRaw(msg, wrong), msg, key), 'wrong scalar does not sign for P_i');
  assert.ok(!opensslVerify(key, msg, S.signRaw(msg, wrong)));
  // view key alone (no spend scalar) gives h but not s_i: h·G != P_i
  const h = indep.oneTime(le(m.view), Point.fromHex(m.spendPub), R).h;
  assert.notEqual(bytesToHex(Point.BASE.multiply(h).toRawBytes()), V.key);
});

test('torsion: cofactor clearing makes D independent of a torsion part; tweaked/small-order/non-canonical R rejected', () => {
  const m = S.deriveStealthMeta(ROOT, 0);
  const R = Point.fromHex(V.R);
  const Rt = R.add(T8);
  // 8·v·(R + T) == 8·v·R (the property that makes payer and receiver agree)
  assert.ok(Rt.multiply(le(m.view)).clearCofactor().equals(R.multiply(le(m.view)).clearCofactor()));
  const key = hexToBytes(V.key);
  assert.ok(!S.isMine(m.view, m.spendPub, Rt.toRawBytes(), key), 'R with a torsion component is rejected');
  assert.throws(() => S.oneTimeSecret(m, Rt.toRawBytes()), /prime-order/);
  for (const bad of [
    T8.toRawBytes(),                                      // small order
    Point.ZERO.toRawBytes(),                              // identity
    hexToBytes('0100000000000000000000000000000000000000000000000000000000000080'), // identity, non-canonical sign bit
    hexToBytes('edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'), // y = p: non-canonical
    new Uint8Array(31),
  ]) {
    assert.ok(!S.isMine(m.view, m.spendPub, bad, key), `rejects ${bytesToHex(bad).slice(0, 8)}`);
  }
  // a meta address carrying a torsioned point is refused at decode and at derive
  const tweaked = { viewPub: Point.fromHex(m.viewPub).add(T8).toRawBytes(), spendPub: m.spendPub };
  assert.throws(() => S.encodeMetaAddress(tweaked), /prime-order/);
  assert.throws(() => S.deriveOneTime(tweaked), /prime-order/);
  // every derived key is torsion-free
  for (let i = 0; i < 50; i++) {
    const ot = S.deriveOneTime(m);
    assert.ok(K.isGoodPoint(ot.R) && K.isGoodPoint(ot.key));
    assert.ok(Point.fromHex(ot.key).isTorsionFree());
  }
});

test('meta address: round trip, checksum, prefix, version, equal keys', () => {
  const m = S.deriveStealthMeta(ROOT, 0);
  const d = S.decodeMetaAddress(V.meta);
  assert.deepEqual(d.viewPub, m.viewPub);
  assert.deepEqual(d.spendPub, m.spendPub);
  const flip = V.meta.slice(0, -2) + (V.meta.at(-2) === 'a' ? 'b' : 'a') + V.meta.at(-1);
  assert.throws(() => S.decodeMetaAddress(flip), /checksum|length|encoding/);
  assert.throws(() => S.decodeMetaAddress('x' + V.meta.slice(1)), /not a HALFKEY/);
  assert.throws(() => S.decodeMetaAddress(V.meta.slice(0, 40)), /length/);
  assert.throws(() => S.decodeMetaAddress(S.encodeMetaAddress({ viewPub: m.spendPub, spendPub: m.spendPub })), /equal/);
});

test('unlinkable outputs: fresh r gives a fresh R and a fresh address every time', () => {
  const m = S.deriveStealthMeta(ROOT, 0);
  const seen = new Set<string>();
  for (let i = 0; i < 20; i++) {
    const ot = S.deriveOneTime(m);
    assert.ok(!seen.has(ot.address.toBase58()));
    seen.add(ot.address.toBase58());
    assert.ok(!ot.address.equals(new PublicKey(m.spendPub)) && !ot.address.equals(new PublicKey(m.viewPub)));
    assert.ok(S.isMine(m.view, m.spendPub, ot.R, ot.key));
  }
});

test('third-party payer: derivation from the published meta address only the owner recognises', () => {
  const m = S.deriveStealthMeta(ROOT, 0);
  const ot = S.deriveOneTime(S.decodeMetaAddress(S.encodeMetaAddress(m)));
  const s = S.checkStealthClaimer(m, ot.R, ot.address);
  assert.ok(new PublicKey(K.pub(s)).equals(ot.address));
  assert.throws(() => S.decodeMetaAddress('hks1garbage'), /stealth address/);
});

test('output index is validated (no silent wrap), swap ids are points', () => {
  const m = S.deriveStealthMeta(ROOT, 0);
  for (const bad of [-1, 1.5, 2 ** 32, NaN]) {
    assert.throws(() => S.deriveOneTime(m, { index: bad }), /index/);
    assert.throws(() => S.isMine(m.view, m.spendPub, hexToBytes(V.R), hexToBytes(V.key), bad), /index/);
  }
  const ot = S.deriveOneTime(m, { index: 0xffffffff });
  assert.ok(S.isMine(m.view, m.spendPub, ot.R, ot.key, 0xffffffff));
  assert.ok(!S.isMine(m.view, m.spendPub, ot.R, ot.key, 0));
  // ordinary swap ids are random prime-order points too, so a stealth swap id does not stand out
  for (let i = 0; i < 20; i++) assert.ok(K.isGoodPoint(K.newSwapId()));
});

test('scanEscrows: finds only our XMR->SOL escrows; parseLockIx reads a real lock encoding', () => {
  const m = S.deriveStealthMeta(ROOT, 0);
  const other = S.deriveStealthMeta(sha512(utf8ToBytes('other')), 0);
  const pid = Keypair.generate().publicKey, maker = Keypair.generate().publicKey;
  const mine = S.deriveOneTime(m), theirs = S.deriveOneTime(other);
  const esc = (swapId: Uint8Array, claimer: PublicKey, direction: number): P.EscrowAccount => ({
    address: P.pda.escrow(pid, maker, swapId), state: 1, direction, released: false, swapId, locker: maker, claimer, maker,
    amount: 1n, xmrAmount: 1n, feeBps: 50, claimPoint: new Uint8Array(32), refundPoint: new Uint8Array(32), viewPub: new Uint8Array(32),
    quoteHash: new Uint8Array(32), watchtowers: [], createdAt: 0n, t0: 0n, t1: 0n, settledAt: 0n, secret: new Uint8Array(32),
  });
  const list = [esc(mine.R, mine.address, 2), esc(theirs.R, theirs.address, 2), esc(mine.R, mine.address, 1), esc(K.newSwapId(), Keypair.generate().publicKey, 2)];
  const hits = S.scanEscrows(list, m.view, m.spendPub);
  assert.equal(hits.length, 1);
  assert.ok(hits[0].address.equals(mine.address));
  const half = K.randomHalf(), mk = K.randomHalf();
  const ix = P.ixLock(pid, maker, {
    swapId: mine.R, claimer: mine.address, direction: 2, amount: 123_456_789n, xmrAmount: 1n, claimPoint: half.spendPub,
    refundPoint: mk.spendPub, viewPub: half.viewPub, quoteHash: new Uint8Array(32), t0Secs: 10, windowSecs: 10,
    watchtowers: [], makerAuthority: maker, consentExpiry: 0, feeBps: 50,
  });
  const l = S.parseLockIx(ix.data)!;
  assert.deepEqual(l.swapId, mine.R);
  assert.ok(l.claimer.equals(mine.address));
  assert.equal(l.direction, 2);
  assert.equal(l.amount, 123_456_789n);
  assert.equal(S.parseLockIx(new Uint8Array([9, ...new Uint8Array(80)])), null);
});

test('StealthSigner signs legacy and v0 transactions that verify for the one-time address', () => {
  const m = S.deriveStealthMeta(ROOT, 0);
  const ot = S.deriveOneTime(m);
  const signer = new S.StealthSigner(S.oneTimeSecret(m, ot.R, 0, ot.key));
  assert.ok(signer.publicKey.equals(ot.address));
  const to = Keypair.generate().publicKey;
  const bh = '11111111111111111111111111111111';
  const legacy = new Transaction({ feePayer: ot.address, blockhash: bh, lastValidBlockHeight: 1 }).add(SystemProgram.transfer({ fromPubkey: ot.address, toPubkey: to, lamports: 1 }));
  signer.signTransaction(legacy);
  assert.ok(legacy.verifySignatures(), 'legacy signature verifies');
  assert.ok(opensslVerify(ot.key, legacy.serializeMessage(), legacy.signature!));
  const v0 = new VersionedTransaction(new TransactionMessage({ payerKey: ot.address, recentBlockhash: bh, instructions: [SystemProgram.transfer({ fromPubkey: ot.address, toPubkey: to, lamports: 1 })] }).compileToV0Message());
  signer.signTransaction(v0);
  assert.ok(ed25519.verify(v0.signatures[0], v0.message.serialize(), ot.key));
  assert.ok(opensslVerify(ot.key, v0.message.serialize(), v0.signatures[0]));
  // a signer for another key cannot add a signature for this address
  const wrong = new S.StealthSigner(K.randomScalar());
  const tx2 = new Transaction({ feePayer: ot.address, blockhash: bh, lastValidBlockHeight: 1 }).add(SystemProgram.transfer({ fromPubkey: ot.address, toPubkey: to, lamports: 1 }));
  assert.throws(() => wrong.signTransaction(tx2), /unknown signer/);
  // raw-scalar input validation
  assert.throws(() => S.signRaw(utf8ToBytes('x'), new Uint8Array(32)), /nonzero/);
  assert.throws(() => S.signRaw(utf8ToBytes('x'), K.bigToLe32(L)), /canonical/);
});
