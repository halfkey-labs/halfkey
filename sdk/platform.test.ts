// Offline unit tests for the platform SDK: pay-link key derivation (additive, torsion checks),
// invoices, OTC RFQs / firm quotes / tranche plans, the v2 consent, and the new decoders.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils';
import { Keypair, PublicKey } from '@solana/web3.js';
import * as K from './keys.ts';
import * as P from './program.ts';
import * as Pay from './pay.ts';
import * as O from './otc.ts';

const Point = ed25519.ExtendedPoint;
const T8 = K.fromHex('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a'); // order-8 point

function rootOf(kp: Keypair) {
  return K.rootFromSignature(ed25519.sign(utf8ToBytes(K.KEY_MESSAGE), kp.secretKey.slice(0, 32)));
}

test('pay keys: s_i = s + H(S||i), S_i = S + H(S||i)*G, from public data on the payer side', () => {
  const root = rootOf(Keypair.generate());
  const { secret, master } = Pay.linkMaster(root, 'alice');
  assert.deepEqual(Pay.linkMaster(root, 'alice').master, master, 'same wallet, same link: same master (any device)');
  assert.notDeepEqual(Pay.linkMaster(root, 'bob').master, master, 'links are independent');
  for (let n = 0; n < 32; n++) {
    const id = K.newSwapId(), qh = K.newSwapId();
    const pub = Pay.payKeys(master, id, qh);                       // payer / maker / program side
    const { spend, keys } = Pay.paySecret(secret, id, qh);         // recipient side
    assert.deepEqual(keys.spendPub, pub.spendPub);
    assert.deepEqual(K.pub(spend), pub.spendPub);
    // the definition, spelled out
    const t = sha256(concatBytes(utf8ToBytes('halfkey-pay-spend-v1'), master, id, qh)); t[31] &= 0x0f;
    assert.deepEqual(pub.tweak, t);
    assert.equal(K.leToBig(spend), (K.leToBig(secret) + K.leToBig(t)) % K.L);
    assert.deepEqual(pub.spendPub, Point.fromHex(master).add(Point.BASE.multiply(K.leToBig(t))).toRawBytes());
    // canonical by construction (top nibble cleared): no reduction needed on chain
    assert.ok(K.leToBig(pub.tweak) < 1n << 252n && K.leToBig(pub.view) < 1n << 252n);
    assert.deepEqual(pub.viewPub, K.pub(pub.view));
    assert.ok(K.isGoodPoint(pub.spendPub) && K.isGoodPoint(pub.viewPub), 'one-time keys are torsion-free');
  }
});

test('pay keys: distinct per escrow AND per quote, so one XMR output never serves two escrows', () => {
  const { master } = Pay.linkMaster(rootOf(Keypair.generate()), 'shop');
  const e = K.newSwapId(), q = K.newSwapId();
  const a = Pay.payKeys(master, e, q);
  assert.notDeepEqual(a.spendPub, Pay.payKeys(master, K.newSwapId(), q).spendPub, 'same invoice, another payer escrow');
  assert.notDeepEqual(a.spendPub, Pay.payKeys(master, e, K.newSwapId()).spendPub, 'same escrow address reused after close, new quote');
  assert.notDeepEqual(a.view, Pay.payKeys(master, e, K.newSwapId()).view);
  assert.notDeepEqual(a.spendPub, master);
});

test('pay keys: torsion, identity and off-curve masters are refused', () => {
  const { master } = Pay.linkMaster(rootOf(Keypair.generate()), 'carol');
  const id = K.newSwapId(), qh = K.newSwapId();
  assert.throws(() => Pay.payKeys(K.pointAdd(master, T8), id, qh), /prime-order/);
  assert.throws(() => Pay.payKeys(T8, id, qh), /prime-order/);
  const ident = new Uint8Array(32); ident[0] = 1;
  assert.throws(() => Pay.payKeys(ident, id, qh), /prime-order/);
  assert.throws(() => Pay.payKeys(new Uint8Array(32).fill(0xff), id, qh), /prime-order/);
  // a maker key with a torsion component, or one that cancels S_i, never yields an address
  const mk = K.randomHalf().spendPub;
  assert.throws(() => Pay.payWallet(K.pointAdd(mk, T8), master, id, qh, 'stagenet'), /prime-order/);
  const si = Pay.payKeys(master, id, qh).spendPub;
  const neg = Point.fromHex(si).negate().add(Point.BASE.multiply(5n)).toRawBytes(); // P_maker = 5G - S_i
  assert.throws(() => Pay.payFullSpend(K.randomScalar(), master, id, qh, K.bigToLe32(5n), neg));
});

test('pay wallet: s_maker + s_i spends P_maker + S_i; the address uses v_i', () => {
  const root = rootOf(Keypair.generate());
  const { secret, master } = Pay.linkMaster(root, 'dave');
  const id = K.newSwapId(), qh = K.newSwapId();
  const maker = K.randomHalf();
  const w = Pay.payWallet(maker.spendPub, master, id, qh, 'stagenet');
  const full = Pay.payFullSpend(secret, master, id, qh, maker.spend, maker.spendPub);
  assert.deepEqual(K.pub(full), w.sharedSpendPub);
  assert.equal(K.moneroAddress(K.pub(full), K.pub(w.view), 'stagenet'), w.address);
  assert.throws(() => Pay.payFullSpend(secret, master, id, qh, K.randomScalar(), maker.spendPub), /maker secret/);
  assert.throws(() => Pay.payFullSpend(Pay.linkSecret(root, 'other'), master, id, qh, maker.spend, maker.spendPub), /does not own/);
});

test('invoices: the id is the hash of the terms; tampering changes it', () => {
  const inv: Pay.Invoice = { v: 1, link: 'shop', piconero: '1500000000000', memo: 'order 42', nonce: '00112233445566778899aabbccddeeff' };
  const enc = Pay.encodeInvoice(inv);
  const back = Pay.decodeInvoice(enc);
  assert.deepEqual(Pay.invoiceId(back), Pay.invoiceId(inv));
  assert.notDeepEqual(Pay.invoiceId({ ...inv, piconero: '1' }), Pay.invoiceId(inv));
  assert.notDeepEqual(Pay.invoiceId({ ...inv, memo: 'order 43' }), Pay.invoiceId(inv));
  assert.throws(() => Pay.decodeInvoice(Pay.encodeInvoice({ ...inv, memo: 'x'.repeat(121) })));
  assert.throws(() => Pay.decodeInvoice(Pay.encodeInvoice({ ...inv, piconero: '-5' })));
});

test('OTC: RFQ signature, firm quote binding, exact tranche sums, caps and partial fills', () => {
  const taker = Keypair.generate(), maker = Keypair.generate();
  const now = Math.floor(Date.now() / 1000);
  const rfq = O.newRfq(1, 500_000_000_000n, 100_000_000_000n, taker.publicKey.toBase58(), 600, now);
  const rsig = K.toHex(ed25519.sign(O.rfqBytes(rfq), taker.secretKey.slice(0, 32)));
  assert.ok(O.verifyRfq(rfq, rsig, taker.publicKey.toBytes()));
  assert.ok(!O.verifyRfq({ ...rfq, amount: '1' }, rsig, taker.publicKey.toBytes()));
  assert.equal(O.checkRfq(rfq, now), null);
  assert.ok(O.checkRfq({ ...rfq, expiresAt: now - 1 }, now));
  assert.ok(O.checkRfq({ ...rfq, minFill: '600000000000' }, now));

  const cap = 50_000_000_000n;
  const fill = 300_000_000_000n; // partial: 300 of 500 SOL
  const q: O.OtcQuote = { v: 1, kind: 'otc', rfq: rfq.id, rfqHash: O.rfqHash(rfq), maker: maker.publicKey.toBase58(), side: 1,
    lamports: fill.toString(), piconero: '47123456789012', tranches: O.tranchesFor(fill, cap), feeBps: 50, expiresAt: now + 120, nonce: 'ab'.repeat(16) };
  assert.equal(q.tranches, 6);
  const sig = O.signOtcQuote(q, maker.secretKey.slice(0, 32));
  const opts = { feeBps: [50, 25], capLamports: cap, now };
  assert.equal(O.checkOtcQuote(q, sig, rfq, maker.publicKey.toBytes(), opts), null);
  assert.match(O.checkOtcQuote({ ...q, lamports: '600000000000' }, sig, rfq, maker.publicKey.toBytes(), opts)!, /signature/);
  const big = { ...q, tranches: 5 }; // 60 SOL tranches > cap
  assert.match(O.checkOtcQuote(big, O.signOtcQuote(big, maker.secretKey.slice(0, 32)), rfq, maker.publicKey.toBytes(), opts)!, /cap/);
  const small = { ...q, lamports: '50000000000', tranches: 1 }; // below minFill
  assert.match(O.checkOtcQuote(small, O.signOtcQuote(small, maker.secretKey.slice(0, 32)), rfq, maker.publicKey.toBytes(), opts)!, /minimum/);
  assert.match(O.checkOtcQuote(q, sig, { ...rfq, id: 'ff'.repeat(16) }, maker.publicKey.toBytes(), opts)!, /different request/);

  const tr = O.planTranches(q);
  assert.equal(tr.length, 6);
  assert.equal(tr.reduce((a, t) => a + t.lamports, 0n), fill);
  assert.equal(tr.reduce((a, t) => a + t.piconero, 0n), BigInt(q.piconero));
  assert.ok(tr.every((t) => t.lamports <= cap));
  assert.equal(new Set(tr.map((t) => K.toHex(t.quoteHash))).size, 6, 'every tranche has its own escrow quote hash');
  // uneven split: remainder lands in the last tranche
  const odd = O.planTranches({ ...q, lamports: '100000000001', piconero: '7', tranches: 3 });
  assert.deepEqual(odd.map((t) => t.lamports), [33333333333n, 33333333333n, 33333333335n]);
  assert.equal(odd.reduce((a, t) => a + t.piconero, 0n), 7n);
  assert.throws(() => O.planTranches({ ...q, tranches: O.MAX_TRANCHES + 1 }));
});

test('consent v2 binds flags, link and watchtowers; v1 is unchanged for unflagged locks', () => {
  const pid = Keypair.generate().publicKey, locker = Keypair.generate().publicKey;
  const wt = [Keypair.generate().publicKey];
  const base: P.LockParams = {
    swapId: K.newSwapId(), claimer: Keypair.generate().publicKey, direction: 1, amount: 5n, xmrAmount: 7n,
    claimPoint: K.randomHalf().spendPub, refundPoint: K.randomHalf().spendPub, viewPub: K.randomHalf().spendPub,
    quoteHash: new Uint8Array(32), t0Secs: 60, windowSecs: 60, watchtowers: wt, makerAuthority: Keypair.generate().publicKey,
    consentExpiry: 100, feeBps: 50,
  };
  const v1 = P.consentMessage(pid, locker, base);
  assert.equal(v1.subarray(0, 18).toString(), 'halfkey-consent-v1');
  assert.equal(v1.length, 18 + 32 * 8 + 1 + 8 * 5 + 2);
  const link = Keypair.generate().publicKey;
  const pay = { ...base, flags: P.F.PAY, link };
  const v2 = P.consentMessage(pid, locker, pay);
  assert.equal(v2.subarray(0, 18).toString(), 'halfkey-consent-v2');
  assert.equal(v2.length, v1.length + 1 + 32 * 3);
  const d = (p: P.LockParams) => K.toHex(P.consentDigest(pid, locker, p));
  assert.notEqual(d(pay), d({ ...pay, watchtowers: [Keypair.generate().publicKey] }));
  assert.notEqual(d(pay), d({ ...pay, link: Keypair.generate().publicKey }));
  assert.notEqual(d(pay), d({ ...pay, flags: P.F.PAY | P.F.OTC }));
  // lock2 carries the flags byte and the link account
  const ix = P.ixLock2(pid, locker, pay);
  assert.equal(ix.data[0], 17);
  assert.equal(ix.data[ix.data.length - 1], P.F.PAY);
  assert.ok(ix.keys[6].pubkey.equals(link) && ix.keys[6].isWritable);
  assert.equal(P.ixLockAny(pid, locker, base).data[0], 6);
});

test('decoders: link and vault layouts', () => {
  const link = new Uint8Array(P.LINK_LEN);
  link[0] = 0x1c; link[1] = 1; link[3] = 5;
  link.set(utf8ToBytes('alice'), 8);
  const owner = Keypair.generate().publicKey;
  link.set(owner.toBytes(), 40);
  const L = P.decodeLink(link);
  assert.equal(L.name, 'alice');
  assert.ok(L.owner.equals(owner));
  assert.ok(P.isLinkName('alice') && P.isLinkName('my-shop-2') && !P.isLinkName('-bad') && !P.isLinkName('ab') && !P.isLinkName('Upper'));
  const v = new Uint8Array(P.VAULT_LEN); v[0] = 0x5a;
  v.set(owner.toBytes(), P.OFF_VAULT_OWNER);
  assert.ok(P.decodeVault(v).owner.equals(owner));
  assert.throws(() => P.decodeVault(new Uint8Array(P.VAULT_LEN)));
  assert.ok(new PublicKey(P.pda.link(Keypair.generate().publicKey, 'alice')));
});
