// Unit tests for sdk/final.ts (no validator): order terms and hash layout, payment ids,
// integrated addresses, subaddress refusal, the encrypted-pid parser, filler deposits, v3 consent.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PublicKey, Keypair } from '@solana/web3.js';
import { keccak_256 } from '@noble/hashes/sha3';
import * as K from './keys.ts';
import * as P from './program.ts';
import * as F from './final.ts';

const pid = new PublicKey('9BbjkoRkb9K4tFjZJsUEVkikRNYWC9wpLtqD3rmicCr6');

test('order terms: fixed 277-byte layout, hash binds every field, address and escrow follow the hash', () => {
  const t: F.OrderTerms = {
    maker: Keypair.generate().publicKey, amount: 5n, xmrAmount: 6n, claimPoint: K.randomHalf().spendPub, paySpend: K.randomHalf().spendPub, payView: K.randomHalf().viewPub,
    refund: Keypair.generate().publicKey, deadline: 1_800_000_000, t0Secs: 60, windowSecs: 21_600, feeBps: 50, integrator: Keypair.generate().publicKey, integratorBps: 100, tip: 7n, quoteHash: K.newSwapId(),
  };
  assert.equal(F.encodeOrderTerms(t).length, F.ORDER_TERMS_LEN);
  const h = F.orderHash(pid, t);
  for (const k of ['amount', 'xmrAmount', 'tip'] as const) assert.notDeepEqual(F.orderHash(pid, { ...t, [k]: (t[k] as bigint) + 1n }), h);
  assert.notDeepEqual(F.orderHash(pid, { ...t, refund: Keypair.generate().publicKey }), h);
  assert.notDeepEqual(F.orderHash(pid, { ...t, integratorBps: 101 }), h);
  assert.ok(F.orderAddress(pid, t).equals(F.pdaF.order(pid, h)));
  assert.ok(F.orderEscrow(pid, t).equals(P.pda.escrow(pid, t.refund, h)));
  assert.equal(F.orderRequired(t, 100n), 5n + 7n + 100n);
});

test('payment ids: per escrow instance, per offer fill, domain-separated', () => {
  const k = Keypair.generate().publicKey;
  assert.equal(F.escrowPid(k, 1).length, 8);
  assert.notDeepEqual(F.escrowPid(k, 1), F.escrowPid(k, 2));
  const f = Keypair.generate().publicKey;
  assert.notDeepEqual(F.offerPid(k, 1, 1, f), F.offerPid(k, 1, 2, f));
  assert.notDeepEqual(F.offerPid(k, 1, 1, f), F.offerPid(k, 1, 1, k));
  assert.notDeepEqual(F.offerPid(k, 1, 0, f), F.escrowPid(k, 1));
});

test('integrated address: 77 bytes, net prefix, checksum; payout addresses refuse subaddresses', () => {
  const h = K.randomHalf();
  const pid8 = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]);
  for (const [net, prefix] of [['mainnet', 19], ['stagenet', 25], ['testnet', 54]] as const) {
    const raw = K.moneroBase58Decode(F.integratedAddress(h.spendPub, h.viewPub, pid8, net));
    assert.equal(raw.length, 77);
    assert.equal(raw[0], prefix);
    assert.deepEqual(raw.slice(65, 73), pid8);
    assert.deepEqual(raw.slice(73), keccak_256(raw.slice(0, 73)).slice(0, 4));
  }
  const std = K.moneroAddress(h.spendPub, h.viewPub, 'stagenet');
  assert.deepEqual(F.payoutKeys(std, 'stagenet').spendPub, h.spendPub);
  // a stagenet subaddress (prefix 36) is refused
  const body = Uint8Array.from([36, ...h.spendPub, ...h.viewPub]);
  const sub = K.moneroBase58(Uint8Array.from([...body, ...keccak_256(body).slice(0, 4)]));
  assert.throws(() => F.payoutKeys(sub, 'stagenet'), /subaddress/);
});

test('encrypted payment id parser matches the program cases; decryption is its own inverse', () => {
  const r = new Uint8Array(32).fill(7);
  const e = Uint8Array.from([0x01, ...r, 0x02, 0x09, 0x01, 1, 2, 3, 4, 5, 6, 7, 8]);
  assert.deepEqual(F.encryptedPid(e)?.pid, Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]));
  assert.equal(F.encryptedPid(e)?.off, 36);
  assert.equal(F.encryptedPid(Uint8Array.from([0x02, 33, 0x00, ...new Uint8Array(32)])), null);
  assert.equal(F.encryptedPid(Uint8Array.from([0xde])), null);
  const D = K.pub(K.randomScalar());
  const pid8 = Uint8Array.from([9, 9, 9, 9, 1, 2, 3, 4]);
  assert.deepEqual(F.decryptPid(F.decryptPid(pid8, D), D), pid8);
});

test('filler deposit: 1% with a 0.01 SOL floor; v3 consent is 456 bytes and binds the shares', () => {
  assert.equal(F.fillerDeposit(10n ** 9n), 10_000_000n);
  assert.equal(F.fillerDeposit(5n * 10n ** 9n), 50_000_000n);
  assert.equal(F.fillerDeposit(1n), F.MIN_FILL_DEPOSIT);
  const lp: F.Lock3Params = {
    swapId: K.newSwapId(), claimer: Keypair.generate().publicKey, direction: 1, amount: 1n, xmrAmount: 2n, claimPoint: K.randomHalf().spendPub,
    refundPoint: K.randomHalf().spendPub, viewPub: K.randomHalf().viewPub, quoteHash: K.newSwapId(), t0Secs: 1, windowSecs: 2, watchtowers: [],
    makerAuthority: Keypair.generate().publicKey, consentExpiry: 3, feeBps: 50, flags: P.F.DIRECT, integrator: Keypair.generate().publicKey, integratorBps: 10, tip: 4n,
  };
  const locker = Keypair.generate().publicKey;
  const m = F.consentMessageV3(pid, locker, lp);
  assert.equal(m.length, 456);
  assert.equal(new TextDecoder().decode(m.slice(0, 18)), 'halfkey-consent-v3');
  assert.notDeepEqual(F.consentDigestV3(pid, locker, { ...lp, tip: 5n }), F.consentDigestV3(pid, locker, lp));
  assert.notDeepEqual(F.consentDigestV3(pid, locker, { ...lp, integratorBps: 11 }), F.consentDigestV3(pid, locker, lp));
});
