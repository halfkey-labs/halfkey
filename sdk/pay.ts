// HALFKEY pay links: one-time Monero key halves derived ADDITIVELY from a recipient's master point.
//
//   recipient master   s (secret scalar),  S = s*G  (published in the link)
//   payment i          t_i = H_spend(S || E_i || Q_i),  v_i = H_view(S || E_i || Q_i)
//                      S_i = S + t_i*G         (payer, maker, program: public data only)
//                      s_i = s + t_i  mod L    (recipient only)
//                      V_i = v_i*G, view key v_i (anyone holding the link: watchtowers get it per payment)
//
// H(x) = sha256(domain || x) with the top 4 bits cleared: a canonical scalar (< 2^252 < L) by
// construction, identical on chain (program/src/lib.rs pay_tweak) and here. E_i = the escrow's
// address (32 bytes), Q_i = the maker's quote hash it locks with: every escrow gets its own key,
// so one Monero output can never satisfy two escrows (an invoice paid twice, a reused id).
//
// Chain-agnostic: depends only on keys.ts. The shared XMR wallet of a pay payment is
// spend = P_maker + S_i, view = v_i; after the maker's claim reveals s_maker the recipient
// sweeps with s_maker + s_i. Because the derivation is additive, s_i - t_i = s: a one-time
// secret must never leave the recipient's process (collect sweeps in-process; no key export).
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils';
import * as K from './keys.ts';

export const SPEND_DOMAIN = utf8ToBytes('halfkey-pay-spend-v1');
export const VIEW_DOMAIN = utf8ToBytes('halfkey-pay-view-v1');

/** sha256(domain || master || escrow || quoteHash), top 4 bits cleared (same as the program's pay_tweak). */
export function payTweak(domain: Uint8Array, master: Uint8Array, escrow: Uint8Array, quoteHash: Uint8Array): Uint8Array {
  if (master.length !== 32 || escrow.length !== 32 || quoteHash.length !== 32) throw new Error('master, escrow and quote hash must be 32 bytes');
  const h = sha256(concatBytes(domain, master, escrow, quoteHash));
  h[31] &= 0x0f;
  return h;
}

/** The recipient's master scalar for one link, from the wallet key root (same wallet, any device). */
export function linkSecret(root: Uint8Array, name: string): Uint8Array {
  const s = K.reduce(sha512(concatBytes(root, utf8ToBytes('halfkey/link/v1/'), utf8ToBytes(name))));
  if (K.leToBig(s) === 0n) throw new Error('degenerate link key');
  return s;
}

export function linkMaster(root: Uint8Array, name: string): { secret: Uint8Array; master: Uint8Array } {
  const secret = linkSecret(root, name);
  return { secret, master: K.pub(secret) };
}

export interface PayKeys {
  /** One-time spend half S_i (goes in the escrow's refund_point slot). */
  spendPub: Uint8Array;
  /** View secret v_i and V_i = v_i*G. */
  view: Uint8Array;
  viewPub: Uint8Array;
  tweak: Uint8Array;
}

/** Public side of one payment (escrow + quote hash): what the payer, maker, watchtowers and program compute. */
export function payKeys(master: Uint8Array, escrow: Uint8Array, quoteHash: Uint8Array): PayKeys {
  if (!K.isGoodPoint(master)) throw new Error('link master is not a prime-order point');
  const tweak = payTweak(SPEND_DOMAIN, master, escrow, quoteHash);
  const view = payTweak(VIEW_DOMAIN, master, escrow, quoteHash);
  if (K.leToBig(tweak) === 0n || K.leToBig(view) === 0n) throw new Error('degenerate payment id');
  const spendPub = K.pointAdd(master, K.pub(tweak));
  if (!K.isGoodPoint(spendPub)) throw new Error('one-time key is not a prime-order point');
  return { spendPub, view, viewPub: K.pub(view), tweak };
}

/** Recipient side: the one-time spend secret s_i, checked against S_i. */
export function paySecret(linkSecretScalar: Uint8Array, escrow: Uint8Array, quoteHash: Uint8Array): { spend: Uint8Array; keys: PayKeys } {
  const master = K.pub(linkSecretScalar);
  const keys = payKeys(master, escrow, quoteHash);
  const spend = K.scalarAdd(linkSecretScalar, keys.tweak);
  if (!K.equalBytes(K.pub(spend), keys.spendPub)) throw new Error('one-time secret does not match');
  return { spend, keys };
}

/** Shared Monero wallet of a pay payment: spend = P_maker + S_i, view = v_i. */
export function payWallet(makerSpendPub: Uint8Array, master: Uint8Array, escrow: Uint8Array, quoteHash: Uint8Array, net: K.MoneroNet) {
  const k = payKeys(master, escrow, quoteHash);
  if (!K.isGoodPoint(makerSpendPub)) throw new Error('maker key is not a prime-order point');
  const spendPub = K.pointAdd(makerSpendPub, k.spendPub);
  if (!K.isGoodPoint(spendPub)) throw new Error('maker key cancels the one-time key');
  return { ...k, sharedSpendPub: spendPub, address: K.moneroAddress(spendPub, k.viewPub, net) };
}

/**
 * Full spend key once the maker's half is public: s_maker + s_i, proven against the shared key.
 * `master` is the link's on-chain master point (a wrong wallet or link name is caught here).
 */
export function payFullSpend(linkSecretScalar: Uint8Array, master: Uint8Array, escrow: Uint8Array, quoteHash: Uint8Array, makerSecret: Uint8Array, makerSpendPub: Uint8Array): Uint8Array {
  if (!K.equalBytes(K.pub(linkSecretScalar), master)) throw new Error('this wallet does not own this link');
  if (!K.isCanonical(makerSecret) || !K.equalBytes(K.pub(makerSecret), makerSpendPub)) throw new Error('maker secret does not match its key');
  const { spend, keys } = paySecret(linkSecretScalar, escrow, quoteHash);
  const full = K.scalarAdd(makerSecret, spend);
  if (!K.equalBytes(K.pub(full), K.pointAdd(makerSpendPub, keys.spendPub))) throw new Error('keys do not complete the shared wallet');
  return full;
}

// ---------------------------------------------------------------- invoices
/**
 * An invoice is identified by its own hash, which becomes the escrow swap id (the recipient
 * matches payments to invoices by it; the one-time key still differs per escrow). Changing the
 * amount or memo in the URL changes the id, so a tampered invoice never matches the original.
 */
export interface Invoice {
  v: 1;
  link: string;          // link name
  piconero: string;      // amount due in XMR base units
  memo: string;          // <= 120 chars, never on chain
  nonce: string;         // hex(16)
  expiresAt?: number;    // unix seconds, optional
}

export function invoiceBytes(inv: Invoice): Uint8Array {
  if (inv.memo.length > 120) throw new Error('memo too long');
  const c = { v: inv.v, link: inv.link, piconero: inv.piconero, memo: inv.memo, nonce: inv.nonce, expiresAt: inv.expiresAt ?? 0 };
  return utf8ToBytes('halfkey-invoice-v1:' + JSON.stringify(c));
}
export const invoiceId = (inv: Invoice) => sha256(invoiceBytes(inv));

const b64u = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

export function encodeInvoice(inv: Invoice): string {
  return b64u(utf8ToBytes(JSON.stringify(inv)));
}
export function decodeInvoice(s: string): Invoice {
  const inv = JSON.parse(new TextDecoder().decode(unb64u(s))) as Invoice;
  if (inv.v !== 1 || typeof inv.link !== 'string' || !/^\d+$/.test(inv.piconero) || typeof inv.memo !== 'string' || !/^[0-9a-f]{32}$/.test(inv.nonce)) throw new Error('bad invoice');
  invoiceBytes(inv); // validates the memo length
  return inv;
}

/** Deterministic random-looking id for a plain (non-invoice) payment. */
export function newPaymentId(): Uint8Array {
  return K.newSwapId();
}
