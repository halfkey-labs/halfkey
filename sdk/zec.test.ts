// Unit tests for sdk/zec.ts, sdk/htlc.ts and sdk/zecswap.ts (no network). The node-level checks
// (txids, signatures, CLTV, OP_SIZE) run against zebrad regtest in e2e/zec-swap.ts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Keypair, PublicKey } from '@solana/web3.js';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes, bytesToHex } from '@noble/hashes/utils';
import * as Z from './zec.ts';
import * as H from './htlc.ts';
import * as S from './zecswap.ts';

const priv = (l: string) => Z.privFrom(new TextEncoder().encode(l));
const x = sha256(new TextEncoder().encode('preimage'));
const terms = (o: Partial<Z.HtlcTerms> = {}): Z.HtlcTerms => ({ hashlock: sha256(x), claimPub: Z.pubOf(priv('c')), refundPub: Z.pubOf(priv('r')), lockHeight: 3_543_500, ...o });

test('HTLC script: 118-byte template at mainnet heights (117 below 32,768), exact parse round trip, mutations rejected', () => {
  const s = Z.htlcScript(terms());
  assert.equal(s.length, 118);
  assert.equal(Z.htlcScript(terms({ lockHeight: 600 })).length, 117);
  assert.deepEqual(Z.parseHtlcScript(s), terms());
  for (const h of [17, 255, 256, 65_535, 65_536, 8_388_607, 8_388_608, 499_999_999]) {
    assert.equal(Z.parseHtlcScript(Z.htlcScript(terms({ lockHeight: h }))).lockHeight, h);
  }
  for (let i = 0; i < s.length; i++) {
    const m = Uint8Array.from(s); m[i] ^= 0x01;
    let parsed: Z.HtlcTerms | null = null;
    try { parsed = Z.parseHtlcScript(m); } catch { /* rejected */ }
    // A flip inside a key, the hash or the height still parses, but to different terms.
    if (parsed) assert.notDeepEqual(parsed, terms());
  }
  assert.throws(() => Z.parseHtlcScript(Uint8Array.of(...s, 0x00)), /trailing/);
  assert.throws(() => Z.htlcScript(terms({ lockHeight: 500_000_000 })), /height/);
  assert.throws(() => Z.htlcScript(terms({ refundPub: Z.pubOf(priv('c')) })), /differ/);
  // Heights 1..16 encode as OP_N, which the parser (and our builder's callers) refuse.
  assert.throws(() => Z.parseHtlcScript(Z.htlcScript(terms({ lockHeight: 16 }))));
});

test('addresses: P2SH/P2PKH round trip per network; shielded, unified and wrong-net addresses refused', () => {
  const redeem = Z.htlcScript(terms());
  for (const net of ['mainnet', 'testnet', 'regtest'] as const) {
    const a = Z.htlcAddress(net, redeem);
    assert.deepEqual(Z.addressScript(a, net), Z.p2sh(redeem));
    const p = Z.pubAddress(net, Z.pubOf(priv('u')));
    assert.deepEqual(Z.addressScript(p, net), Z.p2pkh(Z.pubOf(priv('u'))));
  }
  assert.match(Z.htlcAddress('mainnet', redeem), /^t3/);
  assert.match(Z.pubAddress('mainnet', Z.pubOf(priv('u'))), /^t1/);
  assert.match(Z.pubAddress('regtest', Z.pubOf(priv('u'))), /^tm/);
  assert.throws(() => Z.addressScript(Z.pubAddress('testnet', Z.pubOf(priv('u'))), 'mainnet'), /mainnet/);
  assert.throws(() => Z.addressScript('u1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq', 'mainnet'), /transparent/);
  assert.throws(() => Z.addressScript('zs1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq', 'mainnet'), /transparent/);
  const good = Z.pubAddress('mainnet', Z.pubOf(priv('u')));
  const bad = good.slice(0, -1) + (good.endsWith('a') ? 'b' : 'a');
  assert.throws(() => Z.addressScript(bad, 'mainnet'));
});

test('pre-signed claim: verifies, needs the exact preimage, cannot be redirected; refund carries the CLTV height', () => {
  const redeem = Z.htlcScript(terms());
  const dest = Z.p2pkh(Z.pubOf(priv('dest')));
  const fund = bytesToHex(sha256(new TextEncoder().encode('fund')));
  const p = Z.presign({ kind: 'claim', branch: Z.BRANCH.NU7, txid: fund, vout: 0, value: 150_000_000n, redeem, outScript: dest, priv: priv('c') });
  assert.equal(BigInt(p.outValue), 150_000_000n - 10_000n); // ZIP 317: 2 logical actions x 5,000
  assert.equal(p.lockTime, 0);
  assert.deepEqual(Z.verifyPresigned(p, { outScript: dest, hashlock: sha256(x) }), terms());
  assert.throws(() => Z.verifyPresigned(p, { outScript: Z.p2pkh(Z.pubOf(priv('thief'))) }), /somewhere else/);
  assert.throws(() => Z.verifyPresigned({ ...p, outScript: Z.hex(Z.p2pkh(Z.pubOf(priv('thief')))) }), /signature/);
  assert.throws(() => Z.verifyPresigned({ ...p, outValue: (BigInt(p.outValue) + 1n).toString() }), /signature/);
  assert.throws(() => Z.verifyPresigned({ ...p, branch: Z.BRANCH.NU6_3 }), /signature/); // the branch id is signed
  assert.throws(() => Z.presign({ kind: 'claim', branch: Z.BRANCH.NU7, txid: fund, vout: 0, value: 1n, redeem, outScript: dest, priv: priv('c') }), /too small/);
  assert.throws(() => Z.presign({ kind: 'claim', branch: Z.BRANCH.NU7, txid: fund, vout: 0, value: 150_000_000n, redeem, outScript: dest, priv: priv('r') }), /key/);
  assert.throws(() => Z.finalize(p), /preimage/);
  assert.throws(() => Z.finalize(p, randomBytes(32)), /preimage/);
  const f = Z.finalize(p, x);
  assert.equal(f.tx.vin[0].scriptSig.length, 1 + Z.unhex(p.sig).length + 33 + 1 + 2 + 118); // <sig> <x> OP_TRUE <redeem>
  assert.deepEqual(Z.preimageFromScriptSig(Z.hex(f.tx.vin[0].scriptSig), sha256(x)), x);
  // Adding x does not change the txid (ZIP 244 does not hash the scriptSig).
  assert.equal(f.txid, Z.txid({ ...f.tx, vin: [{ ...f.tx.vin[0], scriptSig: new Uint8Array() }] }));
  const r = Z.presign({ kind: 'refund', branch: Z.BRANCH.NU7, txid: fund, vout: 1, value: 150_000_000n, redeem, outScript: dest, priv: priv('r') });
  assert.equal(r.lockTime, 3_543_500);
  Z.verifyPresigned(r);
  assert.equal(Z.finalize(r).tx.vin[0].sequence, Z.SEQ_LOCKTIME);
  assert.throws(() => Z.verifyPresigned({ ...r, lockTime: 3_543_499 }), /lock time/);
});

test('signatures: low-S DER + SIGHASH_ALL only', () => {
  const d = sha256(new Uint8Array([1]));
  const s = Z.sign(d, priv('k'));
  assert.ok(Z.verifySig(d, s, Z.pubOf(priv('k'))));
  assert.ok(!Z.verifySig(d, Uint8Array.of(...s.slice(0, -1), 0x81), Z.pubOf(priv('k'))));
  assert.ok(!Z.verifySig(d, s, Z.pubOf(priv('other'))));
});

test('upgrades: branch, straddle detection, NU-aware time', () => {
  const ups = Z.MAINNET_UPGRADES;
  assert.equal(Z.upgradeAt(ups, 3_543_404).branch, Z.BRANCH.NU6_3);
  assert.equal(Z.upgradeAt(ups, 3_543_405).branch, Z.BRANCH.NU7);
  assert.equal(Z.upgradeBetween(ups, 3_543_000, 3_543_500)?.name, 'NU7');
  assert.equal(Z.upgradeBetween(ups, 3_543_405, 3_544_000), null);
  assert.equal(Z.secondsUntil(ups, 3_543_403, 3_543_406), 75 + 25 + 25);
  assert.equal(Z.heightAfter(ups, 3_600_000, 3600), 3_600_144); // 1 h = 144 blocks after NU7
  // A swap whose refund height straddles NU7 is refused.
  assert.match(S.lockHeightSafe(ups, 3_543_000, 0, 3_543_900, 0, S.MAINNET_POLICY)!, /NU7/);
  // 3 h of blocks after NU7 at 75% speed vs t1 = 1 h + 2 h margin: too tight; 4 h of blocks is enough.
  const tip = 3_600_000;
  assert.match(S.lockHeightSafe(ups, tip, 0, Z.heightAfter(ups, tip, 3 * 3600), 3600, S.MAINNET_POLICY)!, /too soon/);
  assert.equal(S.lockHeightSafe(ups, tip, 0, Z.heightAfter(ups, tip, 4 * 3600), 3600, S.MAINNET_POLICY), null);
});

test('HTLC consent message: 250 bytes, own prefix, binds every term', () => {
  const pid = Keypair.generate().publicKey, locker = Keypair.generate().publicKey;
  const p: H.HtlcLockParams = { swapId: randomBytes(32), claimer: Keypair.generate().publicKey, direction: 4, amount: 5n, zecAmount: 6n, hashlock: randomBytes(32), quoteHash: randomBytes(32), t1Secs: 600, consentExpiry: 99, makerAuthority: PublicKey.default, feeBps: 50 };
  const m = H.htlcConsentMessage(pid, locker, p);
  assert.equal(m.length, 250);
  assert.equal(m.subarray(0, 23).toString(), 'halfkey-htlc-consent-v1');
  for (const k of ['amount', 'zecAmount', 't1Secs', 'consentExpiry', 'feeBps'] as const) {
    assert.notDeepEqual(H.htlcConsentMessage(pid, locker, { ...p, [k]: (p[k] as any) + (typeof p[k] === 'bigint' ? 1n : 1) }), m);
  }
});

test('decodeHtlc mirrors htlc.rs offsets', () => {
  const d = new Uint8Array(H.HTLC_LEN);
  d[0] = H.DISC_HTLC; d[2] = 4; d[3] = 8; d[5] = 1;
  d.fill(2, 40, 72); d.fill(3, 72, 104); d.fill(4, 104, 136);
  new DataView(d.buffer).setBigUint64(136, 7n, true);
  new DataView(d.buffer).setBigInt64(232, 1234n, true);
  d.fill(9, 248, 280);
  const h = H.decodeHtlc(d);
  assert.equal(h.state, 4); assert.equal(h.direction, 8); assert.equal(h.released, true);
  assert.deepEqual(h.locker.toBytes(), new Uint8Array(32).fill(2));
  assert.equal(h.amount, 7n); assert.equal(h.t1, 1234n);
  assert.throws(() => H.decodeHtlc(d.slice(1)));
});

// ---------------------------------------------------------------- zecswap
const pid = Keypair.generate().publicKey;
const makerKp = Keypair.generate();
const quote = (direction: 4 | 8): S.ZecQuote => ({ v: 1, kind: 'zec', maker: makerKp.publicKey.toBase58(), direction, lamports: '500000000', zats: '7000000', feeBps: 50, expiresAt: 2_000_000_000, nonce: '01', zecNet: 'regtest' });

test('zecKeys: deterministic per wallet root and swap, distinct roles', () => {
  const root = randomBytes(64), id = randomBytes(32);
  const a = S.zecKeys(root, id), b = S.zecKeys(root, id), c = S.zecKeys(root, randomBytes(32));
  assert.deepEqual(a, b);
  assert.notDeepEqual(a.claimPub, c.claimPub);
  assert.notDeepEqual(a.claimPub, a.refundPub);
  assert.deepEqual(a.hashlock, sha256(a.preimage));
});

test('SOL->ZEC offer: every field is checked against the quote, the keys and the consent', () => {
  const taker = Keypair.generate().publicKey, swapId = randomBytes(32);
  const keys = S.zecKeys(randomBytes(64), swapId);
  const q = quote(4), qs = S.signZecQuote(q, makerKp.secretKey.slice(0, 32));
  const mx = randomBytes(32);
  const redeem = Z.htlcScript({ hashlock: sha256(mx), claimPub: keys.claimPub, refundPub: Z.pubOf(priv('maker')), lockHeight: 500 });
  const now = 1_700_000_000;
  const lock: H.HtlcLockParams = { swapId, claimer: makerKp.publicKey, direction: 4, amount: 500_000_000n, zecAmount: 7_000_000n, hashlock: sha256(mx), quoteHash: S.zecQuoteHash(q), t1Secs: 900, consentExpiry: now + 600, makerAuthority: makerKp.publicKey, feeBps: 50 };
  const consentSig = bytesToHex(ed25519.sign(H.htlcConsentDigest(pid, taker, lock), makerKp.secretKey.slice(0, 32)));
  const offer: S.SolToZecOffer = { direction: 4, escrow: H.htlcPda(pid, taker, swapId).toBase58(), hashlock: Z.hex(sha256(mx)), redeem: Z.hex(redeem), htlcAddress: Z.htlcAddress('regtest', redeem), fundTxid: '00'.repeat(32), fundVout: 0, lockHeight: 500, t1Secs: 900, consentExpiry: now + 600, consentSig, feeBps: 50 };
  const ctx: S.SolToZecCtx = { pid, taker, swapId, quote: q, quoteSig: qs, claimPub: keys.claimPub, zecNet: 'regtest', now };
  const got = S.verifySolToZecOffer(offer, ctx);
  assert.deepEqual(got, lock);
  const bad = (o: Partial<S.SolToZecOffer>, re: RegExp, c: Partial<S.SolToZecCtx> = {}) => assert.throws(() => S.verifySolToZecOffer({ ...offer, ...o }, { ...ctx, ...c }), re);
  const otherRedeem = Z.htlcScript({ hashlock: sha256(mx), claimPub: Z.pubOf(priv('mallory')), refundPub: Z.pubOf(priv('maker')), lockHeight: 500 });
  bad({ redeem: Z.hex(otherRedeem), htlcAddress: Z.htlcAddress('regtest', otherRedeem) }, /claim key/);
  bad({ hashlock: Z.hex(randomBytes(32)) }, /hashlock/);
  bad({ lockHeight: 501 }, /lock height/);
  bad({ htlcAddress: Z.htlcAddress('mainnet', redeem) }, /address/);
  bad({ escrow: Keypair.generate().publicKey.toBase58() }, /escrow/);
  bad({ t1Secs: 901 }, /consent/);
  bad({ feeBps: 25 }, /fee/);
  bad({ consentExpiry: now + 30 }, /expire/);
  bad({}, /quote signature/, { quoteSig: S.signZecQuote({ ...q, zats: '1' }, makerKp.secretKey.slice(0, 32)) });
  bad({}, /network/, { zecNet: 'mainnet' });
  const ixs = S.solToZecLockIxs(pid, taker, got, consentSig);
  assert.equal(ixs.length, 2);
  assert.equal(ixs[1].data[0], H.IX.HTLC_LOCK);
});

test('ZEC->SOL offer and lock checks', () => {
  const swapId = randomBytes(32), keys = S.zecKeys(randomBytes(64), swapId);
  const q = quote(8), qs = S.signZecQuote(q, makerKp.secretKey.slice(0, 32));
  const ups = Z.MAINNET_UPGRADES, tip = 3_600_000;
  const lh = Z.heightAfter(ups, tip, 6 * 3600);
  const redeem = Z.htlcScript({ hashlock: keys.hashlock, claimPub: Z.pubOf(priv('maker')), refundPub: keys.refundPub, lockHeight: lh });
  const offer: S.ZecToSolOffer = { direction: 8, escrow: H.htlcPda(pid, makerKp.publicKey, swapId).toBase58(), redeem: Z.hex(redeem), htlcAddress: Z.htlcAddress('mainnet', redeem), lockHeight: lh, payBy: 0 };
  const ctx: S.ZecToSolCtx = { pid, swapId, quote: { ...q, zecNet: 'mainnet' }, quoteSig: S.signZecQuote({ ...q, zecNet: 'mainnet' }, makerKp.secretKey.slice(0, 32)), keys, zecNet: 'mainnet', now: 0, tip, ups, policy: S.MAINNET_POLICY };
  assert.equal(S.verifyZecToSolOffer(offer, ctx).lockHeight, lh);
  const theft = Z.htlcScript({ hashlock: keys.hashlock, claimPub: Z.pubOf(priv('maker')), refundPub: Z.pubOf(priv('maker2')), lockHeight: lh });
  assert.throws(() => S.verifyZecToSolOffer({ ...offer, redeem: Z.hex(theft), htlcAddress: Z.htlcAddress('mainnet', theft) }, ctx), /refund/);
  assert.throws(() => S.verifyZecToSolOffer(offer, { ...ctx, tip: 3_543_000 }), /NU7|too far/);
  assert.throws(() => S.verifyZecToSolOffer(offer, { ...ctx, quoteSig: qs }), /signature/);
  const claimer = Keypair.generate().publicKey;
  const h: H.HtlcAccount = { state: 1, direction: 8, released: false, swapId, locker: makerKp.publicKey, claimer, maker: makerKp.publicKey, amount: 500_000_000n, zecAmount: 7_000_000n, feeBps: 50, hashlock: keys.hashlock, quoteHash: new Uint8Array(32), createdAt: 0n, t1: 10_000n, settledAt: 0n, secret: new Uint8Array(32) };
  const lc = { claimer, quote: q, hashlock: keys.hashlock, now: 1000, policy: S.MAINNET_POLICY };
  assert.equal(S.verifyZecToSolLock(h, lc), null);
  assert.match(S.verifyZecToSolLock({ ...h, amount: 1n }, lc)!, /less SOL/);
  assert.match(S.verifyZecToSolLock({ ...h, claimer: Keypair.generate().publicKey }, lc)!, /someone else/);
  assert.match(S.verifyZecToSolLock({ ...h, hashlock: randomBytes(32) }, lc)!, /hashlock/);
  assert.match(S.verifyZecToSolLock(h, { ...lc, now: 10_000 - 899 })!, /deadline/);
  assert.match(S.verifyZecToSolLock({ ...h, state: 4 }, lc)!, /not open/);
});
