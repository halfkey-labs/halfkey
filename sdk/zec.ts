// Zcash transparent toolkit for HALFKEY's ZEC leg (SOL <-> ZEC HTLC swaps).
//  - HTLC redeem script (OP_SIZE 32 + OP_SHA256 hashlock, OP_CHECKLOCKTIMEVERIFY height refund),
//    exact-template parser for the counterparty's check, P2SH / P2PKH, t-addresses
//  - v5 transaction (ZIP 225, transparent only) serialisation, ZIP 244 txid and signature digest
//  - pre-signed claims and refunds (ZIP 244 does not commit to the scriptSig, so the claim can be
//    signed before the preimage exists and completed later by a watchtower), ZIP 317 fees
//  - a zebrad JSON-RPC client and upgrade-aware branch IDs / block spacing
// Written from ZIP 225/244/317 and checked against zcash_primitives 0.31 sighash_v5.rs (no code
// copied) and against zebrad 7.0.0 on regtest (e2e/zec-swap.ts).
import { blake2b } from '@noble/hashes/blake2b';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { secp256k1 } from '@noble/curves/secp256k1';
import bs58 from 'bs58';

export const OP = {
  FALSE: 0x00, PUSHDATA1: 0x4c, TRUE: 0x51, IF: 0x63, ELSE: 0x67, ENDIF: 0x68, DROP: 0x75, DUP: 0x76,
  SIZE: 0x82, EQUAL: 0x87, EQUALVERIFY: 0x88, SHA256: 0xa8, HASH160: 0xa9, CHECKSIG: 0xac, CLTV: 0xb1,
} as const;

/** Consensus branch IDs (ZIP 200 family). Pre-signed transactions commit to one (ZIP 244). */
export const BRANCH = { NU5: 0xc2d6d0b4, NU6: 0xc8e71055, NU6_1: 0x4dec4df0, NU6_2: 0x5437f330, NU6_3: 0x37a5165b, NU7: 0x77190ad9 } as const;
const V5_HEADER = 0x80000005; // fOverwintered | version 5
const V5_GROUP = 0x26a7270a;
export const SIGHASH_ALL = 0x01;
export const ZAT = 100_000_000n;
/** Final sequence disables nLockTime (and CLTV); refunds use this one. */
export const SEQ_LOCKTIME = 0xfffffffe;
export const SEQ_FINAL = 0xffffffff;

export type ZecNet = 'mainnet' | 'testnet' | 'regtest';
/** Base58Check two-byte prefixes: mainnet t1 / t3, testnet + regtest tm / t2. */
export const PREFIX: Record<ZecNet, { p2pkh: number[]; p2sh: number[] }> = {
  mainnet: { p2pkh: [0x1c, 0xb8], p2sh: [0x1c, 0xbd] },
  testnet: { p2pkh: [0x1d, 0x25], p2sh: [0x1c, 0xba] },
  regtest: { p2pkh: [0x1d, 0x25], p2sh: [0x1c, 0xba] },
};

/**
 * Network upgrades that change the branch ID or the block spacing, as far as HALFKEY cares.
 * Mainnet NU7: height 3,543,405 (zebrad 7.0.0 network tests), ~2026-11-06 02:35-03:00 UTC; block
 * spacing 75 s before it and 25 s from it (ZIP 218). Testnet/regtest come from the node itself
 * (`upgradesFromNode`), never from constants.
 */
export interface Upgrade { name: string; height: number; branch: number; spacing: number }
export const MAINNET_UPGRADES: Upgrade[] = [
  { name: 'NU6.3', height: 3_428_143, branch: BRANCH.NU6_3, spacing: 75 },
  { name: 'NU7', height: 3_543_405, branch: BRANCH.NU7, spacing: 25 },
];

// ------------------------------------------------------------------ bytes
export const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
export const unhex = (h: string) => {
  if (!/^([0-9a-f]{2})*$/i.test(h)) throw new Error('bad hex');
  return new Uint8Array(Buffer.from(h, 'hex'));
};
const cat = (...a: Uint8Array[]) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
const u32 = (n: number) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
const i64 = (n: bigint) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigInt64(0, n, true); return b; };
const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);
export function compactSize(n: number): Uint8Array {
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, n >> 8);
  return cat(Uint8Array.of(0xfe), u32(n));
}
const withLen = (b: Uint8Array) => cat(compactSize(b.length), b);
export const hash160 = (b: Uint8Array) => ripemd160(sha256(b));
const sha256d = (b: Uint8Array) => sha256(sha256(b));
const pers = (s: string) => new TextEncoder().encode(s);
const b2 = (p: string | Uint8Array, data: Uint8Array) => blake2b(data, { dkLen: 32, personalization: typeof p === 'string' ? pers(p) : p });

// ------------------------------------------------------------------ script
export function push(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return cat(Uint8Array.of(data.length), data);
  if (data.length <= 255) return cat(Uint8Array.of(OP.PUSHDATA1, data.length), data);
  throw new Error('push too large');
}
/** Minimal CScriptNum push (positive numbers). */
export function pushNum(n: number): Uint8Array {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error('bad script number');
  if (n === 0) return Uint8Array.of(OP.FALSE);
  if (n >= 1 && n <= 16) return Uint8Array.of(0x50 + n);
  const out: number[] = [];
  let v = n;
  while (v > 0) { out.push(v & 0xff); v = Math.floor(v / 256); }
  if (out[out.length - 1] & 0x80) out.push(0);
  return push(Uint8Array.from(out));
}

export interface HtlcTerms {
  /** sha256(x), x exactly 32 bytes. */
  hashlock: Uint8Array;
  /** 33-byte compressed secp256k1 key that may claim with x. */
  claimPub: Uint8Array;
  /** 33-byte compressed key that may refund from `lockHeight`. */
  refundPub: Uint8Array;
  /** Absolute block height (CLTV); never a timestamp (header times are miner-skewable). */
  lockHeight: number;
}

/**
 * HTLC redeem script.
 *   claim:  <sig> <x> OP_TRUE   needs |x| == 32, sha256(x) == H, a signature by claimPub
 *   refund: <sig> OP_FALSE      needs nLockTime >= lockHeight (a height), a signature by refundPub
 * OP_SIZE 32 pins the preimage length, so a secret of another length cannot satisfy one chain and
 * not the other (the Solana program takes exactly 32 bytes). SHA-256 on both chains (Solana has
 * no RIPEMD-160 syscall, so no HASH160 locks).
 */
export function htlcScript(t: HtlcTerms): Uint8Array {
  if (t.hashlock.length !== 32 || t.claimPub.length !== 33 || t.refundPub.length !== 33) throw new Error('bad htlc params');
  if (!Number.isSafeInteger(t.lockHeight) || t.lockHeight <= 0 || t.lockHeight >= 500_000_000) throw new Error('lockHeight must be a block height');
  if (eq(t.claimPub, t.refundPub)) throw new Error('claim and refund keys must differ');
  return cat(
    Uint8Array.of(OP.IF, OP.SIZE), pushNum(32), Uint8Array.of(OP.EQUALVERIFY, OP.SHA256), push(t.hashlock), Uint8Array.of(OP.EQUALVERIFY),
    push(t.claimPub), Uint8Array.of(OP.CHECKSIG),
    Uint8Array.of(OP.ELSE), pushNum(t.lockHeight), Uint8Array.of(OP.CLTV, OP.DROP), push(t.refundPub), Uint8Array.of(OP.CHECKSIG),
    Uint8Array.of(OP.ENDIF),
  );
}

/** Parse a redeem script: only the exact template `htlcScript` builds is accepted. */
export function parseHtlcScript(s: Uint8Array): HtlcTerms {
  let i = 0;
  const op = (o: number) => { if (s[i++] !== o) throw new Error('not a HALFKEY HTLC script'); };
  const data = (n: number) => { op(n); const d = s.slice(i, i + n); if (d.length !== n) throw new Error('truncated'); i += n; return d; };
  op(OP.IF); op(OP.SIZE); op(0x01); op(32); op(OP.EQUALVERIFY); op(OP.SHA256);
  const hashlock = data(32); op(OP.EQUALVERIFY);
  const claimPub = data(33); op(OP.CHECKSIG); op(OP.ELSE);
  // Height: minimal CScriptNum push of 1..4 bytes (heights > 16; 1..16 would be OP_N, rejected).
  const n = s[i++];
  if (!(n >= 1 && n <= 4)) throw new Error('bad lock height push');
  const hb = s.slice(i, i + n); i += n;
  let lockHeight = 0;
  for (let k = hb.length - 1; k >= 0; k--) lockHeight = lockHeight * 256 + hb[k];
  if (!eq(pushNum(lockHeight), cat(Uint8Array.of(n), hb))) throw new Error('non-minimal lock height');
  op(OP.CLTV); op(OP.DROP);
  const refundPub = data(33); op(OP.CHECKSIG); op(OP.ENDIF);
  if (i !== s.length) throw new Error('trailing bytes');
  const t = { hashlock, claimPub, refundPub, lockHeight };
  if (!eq(htlcScript(t), s)) throw new Error('not canonical');
  return t;
}

export const p2sh = (redeem: Uint8Array) => cat(Uint8Array.of(OP.HASH160), push(hash160(redeem)), Uint8Array.of(OP.EQUAL));
export const p2pkh = (pub: Uint8Array) => cat(Uint8Array.of(OP.DUP, OP.HASH160), push(hash160(pub)), Uint8Array.of(OP.EQUALVERIFY, OP.CHECKSIG));
const p2pkhOfHash = (h: Uint8Array) => cat(Uint8Array.of(OP.DUP, OP.HASH160), push(h), Uint8Array.of(OP.EQUALVERIFY, OP.CHECKSIG));
const p2shOfHash = (h: Uint8Array) => cat(Uint8Array.of(OP.HASH160), push(h), Uint8Array.of(OP.EQUAL));

export function tAddress(net: ZecNet, kind: 'p2pkh' | 'p2sh', h160: Uint8Array): string {
  const payload = cat(Uint8Array.from(PREFIX[net][kind]), h160);
  return bs58.encode(cat(payload, sha256d(payload).slice(0, 4)));
}
export const htlcAddress = (net: ZecNet, redeem: Uint8Array) => tAddress(net, 'p2sh', hash160(redeem));
export const pubAddress = (net: ZecNet, pub: Uint8Array) => tAddress(net, 'p2pkh', hash160(pub));

/**
 * Decode a transparent address (t1/t3 on mainnet, tm/t2 on testnet/regtest) to its output script.
 * Shielded and unified addresses are refused: the HTLC claim pays a transparent receiver, and the
 * user's wallet shields it (Zodl/Zashi prompt for it). Use the UA's transparent receiver.
 */
export function addressScript(addr: string, net: ZecNet): Uint8Array {
  let raw: Uint8Array;
  try { raw = bs58.decode(addr); } catch { throw new Error('not a transparent Zcash address (use your wallet\'s transparent receiver, t1...)'); }
  if (raw.length !== 26) throw new Error('not a transparent Zcash address (use your wallet\'s transparent receiver, t1...)');
  const payload = raw.slice(0, 22);
  if (!eq(sha256d(payload).slice(0, 4), raw.slice(22))) throw new Error('bad address checksum');
  const pre = [payload[0], payload[1]];
  const h = payload.slice(2);
  if (pre[0] === PREFIX[net].p2pkh[0] && pre[1] === PREFIX[net].p2pkh[1]) return p2pkhOfHash(h);
  if (pre[0] === PREFIX[net].p2sh[0] && pre[1] === PREFIX[net].p2sh[1]) return p2shOfHash(h);
  throw new Error(`address is not a ${net} transparent address`);
}

// ------------------------------------------------------------------ transaction v5 (transparent only)
export interface TxIn { txid: Uint8Array /* display order (RPC hex) */; vout: number; sequence: number; scriptSig: Uint8Array }
export interface TxOut { value: bigint; script: Uint8Array }
export interface Prevout { value: bigint; script: Uint8Array }
export interface Tx { branch: number; lockTime: number; expiry: number; vin: TxIn[]; vout: TxOut[] }

const outpoint = (i: TxIn) => cat(Uint8Array.from(i.txid).reverse(), u32(i.vout));
const ser = (o: TxOut) => cat(i64(o.value), withLen(o.script));

export function serialize(tx: Tx): Uint8Array {
  return cat(
    u32(V5_HEADER), u32(V5_GROUP), u32(tx.branch), u32(tx.lockTime), u32(tx.expiry),
    compactSize(tx.vin.length), ...tx.vin.map((i) => cat(outpoint(i), withLen(i.scriptSig), u32(i.sequence))),
    compactSize(tx.vout.length), ...tx.vout.map(ser),
    compactSize(0), compactSize(0), // no Sapling spends/outputs
    compactSize(0), // no Orchard actions
  );
}

/** Parse a transparent-only v5 transaction (the inverse of `serialize`); throws on anything else. */
export function parseTx(raw: Uint8Array): Tx {
  const dv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  let o = 0;
  const r32 = () => { const v = dv.getUint32(o, true); o += 4; return v; };
  const cs = () => { const x = raw[o++]; if (x < 0xfd) return x; if (x === 0xfd) { const v = dv.getUint16(o, true); o += 2; return v; } return r32(); };
  const take = (n: number) => { if (o + n > raw.length) throw new Error('truncated tx'); const b = raw.slice(o, o + n); o += n; return b; };
  if (r32() !== V5_HEADER || r32() !== V5_GROUP) throw new Error('not a v5 transaction');
  const branch = r32(), lockTime = r32(), expiry = r32();
  const vin: TxIn[] = [];
  for (let i = cs(); i > 0; i--) { const txid = take(32).reverse(); const vout = r32(); const scriptSig = take(cs()); vin.push({ txid, vout, scriptSig, sequence: r32() }); }
  const vout: TxOut[] = [];
  for (let i = cs(); i > 0; i--) { const value = dv.getBigInt64(o, true); o += 8; vout.push({ value, script: take(cs()) }); }
  if (cs() !== 0 || cs() !== 0 || cs() !== 0 || o !== raw.length) throw new Error('shielded parts are not supported');
  return { branch, lockTime, expiry, vin, vout };
}

function digests(tx: Tx) {
  const header = b2('ZTxIdHeadersHash', cat(u32(V5_HEADER), u32(V5_GROUP), u32(tx.branch), u32(tx.lockTime), u32(tx.expiry)));
  const prevouts = b2('ZTxIdPrevoutHash', cat(...tx.vin.map(outpoint)));
  const sequence = b2('ZTxIdSequencHash', cat(...tx.vin.map((i) => u32(i.sequence))));
  const outputs = b2('ZTxIdOutputsHash', cat(...tx.vout.map(ser)));
  const sapling = b2('ZTxIdSaplingHash', new Uint8Array());
  const orchard = b2('ZTxIdOrchardHash', new Uint8Array());
  return { header, prevouts, sequence, outputs, sapling, orchard };
}
const txPers = (branch: number) => cat(pers('ZcashTxHash_'), u32(branch));

/** ZIP 244 txid (display order, as RPCs print it). Non-malleable: the scriptSig is not hashed. */
export function txid(tx: Tx): string {
  const d = digests(tx);
  const transparent = b2('ZTxIdTranspaHash', cat(d.prevouts, d.sequence, d.outputs));
  return hex(Uint8Array.from(b2(txPers(tx.branch), cat(d.header, transparent, d.sapling, d.orchard))).reverse());
}

/**
 * ZIP 244 signature digest for transparent input `index`, SIGHASH_ALL. Commits to the branch ID
 * (a tx pre-signed before an upgrade is invalid after it) and to the SPENT scriptPubKey (for P2SH
 * the P2SH script, not the redeem script: unlike Bitcoin's BIP143). Not to any scriptSig.
 */
export function sighash(tx: Tx, index: number, prevouts: Prevout[]): Uint8Array {
  const d = digests(tx);
  const amounts = b2('ZTxTrAmountsHash', cat(...prevouts.map((p) => i64(p.value))));
  const scripts = b2('ZTxTrScriptsHash', cat(...prevouts.map((p) => withLen(p.script))));
  const txin = b2('Zcash___TxInHash', cat(outpoint(tx.vin[index]), i64(prevouts[index].value), withLen(prevouts[index].script), u32(tx.vin[index].sequence)));
  const transparent = b2('ZTxIdTranspaHash', cat(Uint8Array.of(SIGHASH_ALL), d.prevouts, amounts, scripts, d.sequence, d.outputs, txin));
  return b2(txPers(tx.branch), cat(d.header, transparent, d.sapling, d.orchard));
}

export function sign(digest: Uint8Array, priv: Uint8Array): Uint8Array {
  const sig = secp256k1.sign(digest, priv, { lowS: true });
  return cat(sig.toDERRawBytes(), Uint8Array.of(SIGHASH_ALL));
}
export function verifySig(digest: Uint8Array, sigWithType: Uint8Array, pub: Uint8Array): boolean {
  if (sigWithType.length < 9 || sigWithType[sigWithType.length - 1] !== SIGHASH_ALL) return false;
  try {
    const s = secp256k1.Signature.fromDER(sigWithType.slice(0, -1));
    if (s.hasHighS()) return false;
    return secp256k1.verify(s, digest, pub, { lowS: true });
  } catch { return false; }
}
export const pubOf = (priv: Uint8Array) => secp256k1.getPublicKey(priv, true);
/** A valid secp256k1 private key from 32+ bytes of key material (reduced, never zero). */
export function privFrom(material: Uint8Array): Uint8Array {
  const n = secp256k1.CURVE.n;
  let v = 0n;
  for (const b of sha256(material)) v = (v << 8n) | BigInt(b);
  v = (v % (n - 1n)) + 1n;
  return Uint8Array.from(Buffer.from(v.toString(16).padStart(64, '0'), 'hex'));
}

export const scriptSigP2PKH = (sig: Uint8Array, pub: Uint8Array) => cat(push(sig), push(pub));
export const scriptSigClaim = (sig: Uint8Array, x: Uint8Array, redeem: Uint8Array) => cat(push(sig), push(x), Uint8Array.of(OP.TRUE), push(redeem));
export const scriptSigRefund = (sig: Uint8Array, redeem: Uint8Array) => cat(push(sig), Uint8Array.of(OP.FALSE), push(redeem));

// ------------------------------------------------------------------ ZIP 317 fee
/** Conventional fee: marginal * max(grace=2, logical actions). Transparent-only. */
export function zip317Fee(tx: Tx, marginal = 5000n): bigint {
  const inSize = tx.vin.reduce((n, i) => n + 36 + compactSize(i.scriptSig.length).length + i.scriptSig.length + 4, 0);
  const outSize = tx.vout.reduce((n, o) => n + 8 + compactSize(o.script.length).length + o.script.length, 0);
  const logical = Math.max(Math.ceil(inSize / 150), Math.ceil(outSize / 34));
  return marginal * BigInt(Math.max(2, logical));
}
/** Dust floor for a transparent output (zcashd/zebrad standardness). */
export const DUST = 5_460n;

// ------------------------------------------------------------------ pre-signed spends
/** A spend of one HTLC output, signed but (for a claim) still missing the preimage. JSON-safe. */
export interface Presigned {
  v: 1;
  kind: 'claim' | 'refund';
  branch: number;
  /** Funding outpoint (display-order txid) and its value in zatoshis. */
  txid: string;
  vout: number;
  value: string;
  redeem: string;     // hex
  outScript: string;  // hex: where the ZEC goes
  outValue: string;   // zatoshis after the fee
  lockTime: number;   // 0 for a claim, lockHeight for a refund
  sig: string;        // hex DER + sighash type
}

function spendTx(p: Omit<Presigned, 'sig' | 'v'>): Tx {
  return {
    branch: p.branch, lockTime: p.lockTime, expiry: 0,
    vin: [{ txid: unhex(p.txid), vout: p.vout, sequence: p.kind === 'refund' ? SEQ_LOCKTIME : SEQ_FINAL, scriptSig: new Uint8Array() }],
    vout: [{ value: BigInt(p.outValue), script: unhex(p.outScript) }],
  };
}

export interface SpendArgs {
  kind: 'claim' | 'refund';
  branch: number;
  txid: string;
  vout: number;
  value: bigint;
  redeem: Uint8Array;
  outScript: Uint8Array;
  priv: Uint8Array;
  /** ZIP 317 marginal fee (zatoshis per logical action). */
  marginal?: bigint;
}

/** Sign a claim (without x) or a refund for one HTLC output. The fee is sized for the final scriptSig. */
export function presign(a: SpendArgs): Presigned {
  const t = parseHtlcScript(a.redeem);
  const want = a.kind === 'claim' ? t.claimPub : t.refundPub;
  if (!eq(pubOf(a.priv), want)) throw new Error(`key does not match the HTLC ${a.kind} key`);
  const base = { kind: a.kind, branch: a.branch, txid: a.txid, vout: a.vout, value: a.value.toString(), redeem: hex(a.redeem), outScript: hex(a.outScript), lockTime: a.kind === 'refund' ? t.lockHeight : 0 };
  const sized = spendTx({ ...base, outValue: '0' });
  sized.vin[0].scriptSig = a.kind === 'claim' ? scriptSigClaim(new Uint8Array(73), new Uint8Array(32), a.redeem) : scriptSigRefund(new Uint8Array(73), a.redeem);
  const fee = zip317Fee(sized, a.marginal ?? 5000n);
  const outValue = a.value - fee;
  if (outValue < DUST) throw new Error('HTLC output too small to spend');
  const p = { ...base, outValue: outValue.toString() };
  const tx = spendTx(p);
  const sig = sign(sighash(tx, 0, [{ value: a.value, script: p2sh(a.redeem) }]), a.priv);
  return { v: 1, ...p, sig: hex(sig) };
}

/** Check a pre-signed spend: the template, the key, the signature, and where it pays. */
export function verifyPresigned(p: Presigned, expect?: { outScript?: Uint8Array; hashlock?: Uint8Array }): HtlcTerms {
  if (p.v !== 1 || (p.kind !== 'claim' && p.kind !== 'refund')) throw new Error('bad presigned');
  const redeem = unhex(p.redeem);
  const t = parseHtlcScript(redeem);
  if (p.lockTime !== (p.kind === 'refund' ? t.lockHeight : 0)) throw new Error('bad lock time');
  if (BigInt(p.outValue) < DUST || BigInt(p.outValue) > BigInt(p.value)) throw new Error('bad output value');
  if (expect?.outScript && p.outScript !== hex(expect.outScript)) throw new Error('pays somewhere else');
  if (expect?.hashlock && !eq(t.hashlock, expect.hashlock)) throw new Error('different hashlock');
  const tx = spendTx(p);
  const d = sighash(tx, 0, [{ value: BigInt(p.value), script: p2sh(redeem) }]);
  if (!verifySig(d, unhex(p.sig), p.kind === 'claim' ? t.claimPub : t.refundPub)) throw new Error('bad signature');
  return t;
}

/** The final transaction: a claim needs x with sha256(x) == hashlock (checked here). */
export function finalize(p: Presigned, x?: Uint8Array): { tx: Tx; raw: string; txid: string } {
  const redeem = unhex(p.redeem);
  const t = parseHtlcScript(redeem);
  const tx = spendTx(p);
  if (p.kind === 'claim') {
    if (!x || x.length !== 32 || !eq(sha256(x), t.hashlock)) throw new Error('wrong preimage');
    tx.vin[0].scriptSig = scriptSigClaim(unhex(p.sig), x, redeem);
  } else {
    tx.vin[0].scriptSig = scriptSigRefund(unhex(p.sig), redeem);
  }
  return { tx, raw: hex(serialize(tx)), txid: txid(tx) };
}

/** The preimage from a confirmed claim's scriptSig (hex), if it is one for `hashlock`. */
export function preimageFromScriptSig(scriptSigHex: string, hashlock: Uint8Array): Uint8Array | null {
  const s = unhex(scriptSigHex);
  for (let i = 0; i + 33 <= s.length; i++) {
    if (s[i] === 32) {
      const x = s.slice(i + 1, i + 33);
      if (eq(sha256(x), hashlock)) return x;
    }
  }
  return null;
}

// ------------------------------------------------------------------ heights and upgrades
/** Branch ID and block spacing at `height` for a list of upgrades sorted by height. */
export function upgradeAt(ups: Upgrade[], height: number): Upgrade {
  let cur: Upgrade | undefined;
  for (const u of ups) if (height >= u.height) cur = u;
  if (!cur) throw new Error('height before every known upgrade');
  return cur;
}
/** An upgrade activating in (from, to]: a spend signed now and mined in that range would be invalid. */
export function upgradeBetween(ups: Upgrade[], from: number, to: number): Upgrade | null {
  return ups.find((u) => u.height > from && u.height <= to) ?? null;
}
/** Expected seconds until `height` from `tip`, using each upgrade's target spacing. */
export function secondsUntil(ups: Upgrade[], tip: number, height: number): number {
  let s = 0;
  for (let h = tip + 1; h <= height; h++) s += upgradeAt(ups, h).spacing;
  return s;
}
/** The height at least `secs` of target-spacing time after `tip`. */
export function heightAfter(ups: Upgrade[], tip: number, secs: number): number {
  let h = tip, s = 0;
  while (s < secs) { h++; s += upgradeAt(ups, h).spacing; }
  return h;
}

// ------------------------------------------------------------------ zebrad JSON-RPC
export type Rpc = (method: string, params?: unknown[]) => Promise<any>;
export function rpc(url: string, auth?: string): Rpc {
  let id = 0;
  return async (method: string, params: unknown[] = []) => {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...(auth ? { authorization: 'Basic ' + Buffer.from(auth).toString('base64') } : {}) },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }),
    });
    const j = await r.json() as { result?: unknown; error?: { code: number; message: string } };
    if (j.error) throw new Error(`${method}: ${j.error.code} ${j.error.message}`);
    return j.result as any;
  };
}

/** Upgrades (branch IDs, heights) as the node reports them; spacing 25 s from NU7, else 75 s. */
export async function upgradesFromNode(call: Rpc): Promise<Upgrade[]> {
  const info = await call('getblockchaininfo');
  const ups: Upgrade[] = [];
  for (const [branchHex, u] of Object.entries(info.upgrades ?? {}) as [string, any][]) {
    const name = String(u.name);
    ups.push({ name, height: Number(u.activationheight), branch: parseInt(branchHex, 16), spacing: /^NU7|^NU8/i.test(name) ? 25 : 75 });
  }
  ups.sort((a, b) => a.height - b.height);
  // Later upgrades keep the post-NU7 spacing.
  let fast = false;
  for (const u of ups) { if (u.spacing === 25) fast = true; if (fast) u.spacing = 25; }
  return ups;
}

export interface FundingCheck { confirmations: number; value: bigint; spent: boolean }
/**
 * Look up an HTLC funding output: it must pay P2SH(redeem), and not come from a transaction that
 * spends a coinbase (whose transparent outputs could never be spent by a transparent claim).
 * `spent` is true only when the node explicitly answers that the output is gone (gettxout null);
 * any RPC error is thrown, never read as "spent".
 */
/** Every output sitting at this HTLC's address, from the node's address index. A failed read throws: it is not "none". */
export async function htlcOutputs(call: Rpc, net: ZecNet, redeem: Uint8Array): Promise<{ txid: string; vout: number; value: bigint; height: number }[]> {
  const r = await call('getaddressutxos', [{ addresses: [htlcAddress(net, redeem)] }]);
  return (Array.isArray(r) ? r : r?.utxos ?? []).map((u: any) => ({ txid: String(u.txid), vout: Number(u.outputIndex ?? u.index), value: BigInt(u.satoshis), height: Number(u.height ?? 0) }));
}

export async function checkFunding(call: Rpc, txidHex: string, vout: number, redeem: Uint8Array): Promise<FundingCheck> {
  const tx = await call('getrawtransaction', [txidHex, 1]);
  if ((tx.vin ?? []).some((i: any) => i.coinbase !== undefined)) throw new Error('funded by a coinbase transaction');
  const o = tx.vout?.[vout];
  if (!o) throw new Error('no such output');
  if (o.scriptPubKey?.hex !== hex(p2sh(redeem))) throw new Error('output does not pay this HTLC');
  const value = BigInt(o.valueZat ?? Math.round(Number(o.value) * 1e8));
  const utxo = await call('gettxout', [txidHex, vout, true]);
  return { confirmations: Number(tx.confirmations ?? 0), value, spent: utxo === null };
}
