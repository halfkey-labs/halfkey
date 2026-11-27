// HALFKEY key math: the 2-of-2 Monero key split on ed25519 (same curve as Solana).
//  * Each side holds a spend scalar s_x and a view scalar v_x.
//  * Shared Monero wallet: spend pub P = P_a + P_b, view priv v = v_a + v_b (both sides know v).
//  * Whoever learns the other side's spend scalar can sweep: s = s_a + s_b (mod L).
// The user's half is derived deterministically from a wallet signature, so no recovery file exists.
import { ed25519 } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { sha256 } from '@noble/hashes/sha256';
import { keccak_256 } from '@noble/hashes/sha3';
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils';

export const L = ed25519.CURVE.n;
const Point = ed25519.ExtendedPoint;

export const KEY_MESSAGE = 'HALFKEY key v1 · only sign on halfkey.xyz\n\nThis signature creates your half of the swap keys. It moves no funds. Never sign it on any other site.';

export const toHex = bytesToHex;
export const fromHex = hexToBytes;

export function leToBig(b: Uint8Array): bigint {
  let n = 0n;
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]);
  return n;
}
export function bigToLe32(n: bigint): Uint8Array {
  if (n < 0n || n >= 1n << 256n) throw new Error('scalar out of range');
  const b = new Uint8Array(32);
  for (let i = 0; i < 32; i++) { b[i] = Number(n & 0xffn); n >>= 8n; }
  return b;
}
export const reduce = (b: Uint8Array) => bigToLe32(leToBig(b) % L);
export const isCanonical = (s: Uint8Array) => s.length === 32 && leToBig(s) < L;

export function scalarAdd(a: Uint8Array, b: Uint8Array): Uint8Array {
  return bigToLe32((leToBig(a) + leToBig(b)) % L);
}

/** s*G, compressed. s must be a nonzero canonical scalar. */
export function pub(s: Uint8Array): Uint8Array {
  const n = leToBig(s);
  if (n === 0n || n >= L) throw new Error('bad scalar');
  return Point.BASE.multiply(n).toRawBytes();
}

export function pointAdd(a: Uint8Array, b: Uint8Array): Uint8Array {
  return Point.fromHex(a).add(Point.fromHex(b)).toRawBytes();
}

/** Canonical encoding, on the curve, not identity, prime order (no torsion). */
export function isGoodPoint(p: Uint8Array): boolean {
  try {
    if (p.length !== 32) return false;
    const P = Point.fromHex(p);
    if (!equalBytes(P.toRawBytes(), p)) return false; // non-canonical encoding
    if (P.equals(Point.ZERO)) return false;
    if (P.isSmallOrder()) return false;
    return P.isTorsionFree();
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------- maker key proof
// XMR->SOL: the maker answers the handshake after it has seen the taker's key half A. Without a
// proof it could answer M = t*G - A, so the deposit address (M + A = t*G) would be spendable by the
// maker alone, and it could never refund its SOL either (it does not know m). A Schnorr proof of
// knowledge of m (M = m*G), bound to the context (program, escrow, A, M), rules that out: an
// M chosen as t*G - A has no known discrete log. Fiat-Shamir: R = k*G, c = H(dom || R || M || ctx),
// s = k + c*m; verify s*G == R + c*M.
const KEY_PROOF_DOMAIN = utf8ToBytes('halfkey-maker-key-proof-v1');
export function keyProofContext(programId: Uint8Array, escrow: Uint8Array, takerSpendPub: Uint8Array): Uint8Array {
  return concatBytes(programId, escrow, takerSpendPub);
}
export function proveKey(m: Uint8Array, ctx: Uint8Array): Uint8Array {
  const M = pub(m);
  const k = reduce(sha512(concatBytes(utf8ToBytes('halfkey-maker-key-proof-nonce-v1'), m, ctx, randomBytes(32))));
  const R = pub(k);
  const c = leToBig(sha512(concatBytes(KEY_PROOF_DOMAIN, R, M, ctx))) % L;
  const sv = (leToBig(k) + c * leToBig(m)) % L;
  return concatBytes(R, bigToLe32(sv));
}
export function verifyKeyProof(M: Uint8Array, ctx: Uint8Array, proof: Uint8Array): boolean {
  try {
    if (proof.length !== 64 || !isGoodPoint(M)) return false;
    const R = proof.slice(0, 32), sb = proof.slice(32);
    if (!isCanonical(sb) || !isGoodPoint(R)) return false;
    const c = leToBig(sha512(concatBytes(KEY_PROOF_DOMAIN, R, M, ctx))) % L;
    const sv = leToBig(sb);
    if (sv === 0n) return false;
    const lhs = Point.BASE.multiply(sv);
    const rhs = Point.fromHex(R).add(c === 0n ? Point.ZERO : Point.fromHex(M).multiply(c));
    return lhs.equals(rhs);
  } catch {
    return false;
  }
}

export function equalBytes(a: Uint8Array, b: Uint8Array) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

/** Random nonzero scalar (maker side, per swap). */
export function randomScalar(): Uint8Array {
  for (;;) {
    const s = reduce(sha512(randomBytes(64)));
    if (leToBig(s) !== 0n) return s;
  }
}

export interface KeyHalf { spend: Uint8Array; view: Uint8Array; spendPub: Uint8Array; viewPub: Uint8Array }

export function halfFromScalars(spend: Uint8Array, view: Uint8Array): KeyHalf {
  return { spend, view, spendPub: pub(spend), viewPub: pub(view) };
}

export function randomHalf(): KeyHalf {
  return halfFromScalars(randomScalar(), randomScalar());
}

/** root = SHA-512(signature over KEY_MESSAGE). Ed25519 signing is deterministic (RFC 8032). */
export function rootFromSignature(sig: Uint8Array): Uint8Array {
  if (sig.length !== 64) throw new Error('expected a 64-byte ed25519 signature');
  return sha512(sig);
}

/** Per-swap half derived from the wallet root. swapId is the 32-byte id stored in the escrow PDA seeds. */
export function deriveHalf(root: Uint8Array, swapId: Uint8Array): KeyHalf {
  const h = (label: string) => {
    const s = reduce(sha512(concatBytes(root, utf8ToBytes(label), swapId)));
    if (leToBig(s) === 0n) throw new Error('degenerate scalar');
    return s;
  };
  return halfFromScalars(h('halfkey/spend/v1'), h('halfkey/view/v1'));
}

/** Two signatures over the same message must match, or the wallet is not deterministic. */
export function checkDeterministic(sig1: Uint8Array, sig2: Uint8Array): boolean {
  return equalBytes(sig1, sig2);
}

/**
 * Random 32-byte swap id. Encoded as a random curve point (r·G for random r), so ordinary swap ids
 * look like the ephemeral keys of stealth swaps (sdk/stealth.ts) and do not single them out.
 */
export function newSwapId(): Uint8Array {
  return pub(randomScalar());
}

// ---------------------------------------------------------------- Monero addresses
export type MoneroNet = 'mainnet' | 'stagenet' | 'testnet';
const NET_PREFIX: Record<MoneroNet, number> = { mainnet: 18, stagenet: 24, testnet: 53 };
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const ENC_BLOCK = [0, 2, 3, 5, 6, 7, 9, 10, 11];

function encodeBlock(block: Uint8Array): string {
  let n = 0n;
  for (const b of block) n = (n << 8n) | BigInt(b);
  const len = ENC_BLOCK[block.length];
  let out = '';
  for (let i = 0; i < len; i++) { out = ALPHABET[Number(n % 58n)] + out; n /= 58n; }
  return out;
}

export function moneroBase58(data: Uint8Array): string {
  let out = '';
  for (let i = 0; i < data.length; i += 8) out += encodeBlock(data.slice(i, i + 8));
  return out;
}

function decodeBlock(s: string, size: number): Uint8Array {
  let n = 0n;
  for (const c of s) {
    const i = ALPHABET.indexOf(c);
    if (i < 0) throw new Error('bad base58 char');
    n = n * 58n + BigInt(i);
  }
  const out = new Uint8Array(size);
  for (let i = size - 1; i >= 0; i--) { out[i] = Number(n & 0xffn); n >>= 8n; }
  if (n !== 0n) throw new Error('base58 overflow');
  return out;
}

export function moneroBase58Decode(s: string): Uint8Array {
  const parts: Uint8Array[] = [];
  for (let i = 0; i < s.length; i += 11) {
    const chunk = s.slice(i, i + 11);
    const size = ENC_BLOCK.indexOf(chunk.length);
    if (size < 0) throw new Error('bad base58 length');
    parts.push(decodeBlock(chunk, size));
  }
  return concatBytes(...parts);
}

export function moneroAddress(spendPub: Uint8Array, viewPub: Uint8Array, net: MoneroNet): string {
  const body = concatBytes(Uint8Array.of(NET_PREFIX[net]), spendPub, viewPub);
  const check = keccak_256(body).slice(0, 4);
  return moneroBase58(concatBytes(body, check));
}

/** Validates a standard or subaddress (no integrated addresses) for the given net. */
export function parseMoneroAddress(addr: string, net: MoneroNet): { spendPub: Uint8Array; viewPub: Uint8Array; sub: boolean } {
  const raw = moneroBase58Decode(addr.trim());
  if (raw.length !== 69) throw new Error('not a standard Monero address');
  const body = raw.slice(0, 65);
  if (!equalBytes(keccak_256(body).slice(0, 4), raw.slice(65))) throw new Error('bad address checksum');
  const prefix = body[0];
  const sub = { mainnet: 42, stagenet: 36, testnet: 63 }[net];
  if (prefix !== NET_PREFIX[net] && prefix !== sub) throw new Error(`address is not a ${net} address`);
  return { spendPub: body.slice(1, 33), viewPub: body.slice(33, 65), sub: prefix === sub };
}

/**
 * The shared 2-of-2 wallet. Spend pub = P_maker + P_user (needs both secrets to spend).
 * The view key is derived by the USER alone (from the wallet signature + swap id) and handed to
 * the maker and watchtowers in the handshake. Viewing gives no spend power, and a user-derived
 * view key means a new device can always rebuild it: no maker cooperation, no file.
 */
export function sharedWallet(spendPubA: Uint8Array, spendPubB: Uint8Array, viewSecret: Uint8Array, net: MoneroNet) {
  const spendPub = pointAdd(spendPubA, spendPubB);
  const viewPub = pub(viewSecret);
  return { spendPub, view: viewSecret, viewPub, address: moneroAddress(spendPub, viewPub, net) };
}

// ---------------------------------------------------------------- quotes
export interface Quote {
  v: 1;
  maker: string;        // maker authority (base58)
  direction: 1 | 2;     // 1 = SOL->XMR, 2 = XMR->SOL
  lamports: string;     // SOL side, u64 as string
  piconero: string;     // XMR side, u64 as string
  feeBps: number;       // protocol fee the maker priced in
  expiresAt: number;    // unix seconds
  nonce: string;        // hex
}

export function quoteBytes(q: Quote): Uint8Array {
  // Canonical: fixed key order.
  const c = { v: q.v, maker: q.maker, direction: q.direction, lamports: q.lamports, piconero: q.piconero, feeBps: q.feeBps, expiresAt: q.expiresAt, nonce: q.nonce };
  return utf8ToBytes('halfkey-quote-v1:' + JSON.stringify(c));
}
export const quoteHash = (q: Quote) => sha256(quoteBytes(q));
export function signQuote(q: Quote, makerSecret32: Uint8Array): string {
  return bytesToHex(ed25519.sign(quoteBytes(q), makerSecret32));
}
export function verifyQuote(q: Quote, sigHex: string, makerPub: Uint8Array): boolean {
  try { return ed25519.verify(hexToBytes(sigHex), quoteBytes(q), makerPub); } catch { return false; }
}

export const PICO = 1_000_000_000_000n;
export const LAMPORTS = 1_000_000_000n;
export function fmtXmr(p: bigint, dp = 6) { const s = (Number(p) / 1e12).toFixed(dp); return s; }
export function fmtSol(l: bigint, dp = 4) { return (Number(l) / 1e9).toFixed(dp); }
