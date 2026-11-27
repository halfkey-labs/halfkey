// HALFKEY HTLC kind (SOL <-> transparent ZEC): PDAs, instruction encoders, account decoder.
// Byte layouts mirror program/src/htlc.rs exactly (Htlc::store, consent_message).
import { sha256 } from '@noble/hashes/sha256';
import { ed25519 } from '@noble/curves/ed25519';
import { PublicKey, SystemProgram, TransactionInstruction, SYSVAR_INSTRUCTIONS_PUBKEY } from '@solana/web3.js';
import { pda } from './program.ts';

export const DIR_SOL_TO_ZEC = 4;
export const DIR_ZEC_TO_SOL = 8;
/** Point-locked kinds (ZEC v2, unlinkable): `hashlock` holds the ed25519 point T, the claim reveals t. */
export const DIR_SOL_TO_ZEC_PT = 16;
export const DIR_ZEC_TO_SOL_PT = 32;
export const isPointDir = (d: number) => d === DIR_SOL_TO_ZEC_PT || d === DIR_ZEC_TO_SOL_PT;
export const isSolToZec = (d: number) => d === DIR_SOL_TO_ZEC || d === DIR_SOL_TO_ZEC_PT;
export const isHtlcDir = (d: number) => d === DIR_SOL_TO_ZEC || d === DIR_ZEC_TO_SOL || isPointDir(d);
export const HTLC_LEN = 280;
export const DISC_HTLC = 0x48;
export const HTLC_CONSENT_PREFIX = 'halfkey-htlc-consent-v1';
/** Same offsets as the XMR escrow, so one memcmp filter finds a party's swaps of both kinds. */
export const OFF_HTLC_LOCKER = 40;
export const OFF_HTLC_CLAIMER = 72;
export const OFF_HTLC_MAKER = 104;
/** Instruction tags (program/src/lib.rs `ix`). */
export const IX = { HTLC_LOCK: 47, HTLC_CLAIM: 48, HTLC_ABORT: 49, HTLC_REFUND: 50, HTLC_CLOSE: 51, HTLC_PT_CLAIM: 52 } as const;

export const htlcPda = (pid: PublicKey, locker: PublicKey, swapId: Uint8Array) =>
  PublicKey.findProgramAddressSync([Buffer.from('htlc'), locker.toBytes(), swapId], pid)[0];

export interface HtlcAccount {
  address?: PublicKey;
  state: number;          // P.ST: 1 locked, 3 aborted, 4 claimed, 5 refunded (never 2 'ready')
  direction: number;
  released: boolean;
  swapId: Uint8Array;
  locker: PublicKey;
  claimer: PublicKey;
  maker: PublicKey;
  amount: bigint;         // lamports
  zecAmount: bigint;      // zatoshis
  feeBps: number;
  hashlock: Uint8Array;   // sha256(x)
  quoteHash: Uint8Array;
  createdAt: bigint;
  t1: bigint;
  settledAt: bigint;
  /** The preimage once claimed, else zero. */
  secret: Uint8Array;
}

export function decodeHtlc(d: Uint8Array, address?: PublicKey): HtlcAccount {
  if (d.length !== HTLC_LEN || d[0] !== DISC_HTLC) throw new Error('not an HTLC escrow');
  const dv = new DataView(d.buffer, d.byteOffset, d.byteLength);
  const key = (o: number) => new PublicKey(d.slice(o, o + 32));
  return {
    address, state: d[2], direction: d[3], released: d[5] !== 0, swapId: d.slice(8, 40),
    locker: key(40), claimer: key(72), maker: key(104),
    amount: dv.getBigUint64(136, true), zecAmount: dv.getBigUint64(144, true), feeBps: dv.getUint16(152, true),
    hashlock: d.slice(160, 192), quoteHash: d.slice(192, 224),
    createdAt: dv.getBigInt64(224, true), t1: dv.getBigInt64(232, true), settledAt: dv.getBigInt64(240, true),
    secret: d.slice(248, 280),
  };
}

const u64 = (v: bigint | number) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b; };
const i64 = (v: bigint | number) => { const b = Buffer.alloc(8); b.writeBigInt64LE(BigInt(v)); return b; };
const u16 = (v: number) => { const b = Buffer.alloc(2); b.writeUInt16LE(v); return b; };
const b32 = (b: Uint8Array) => { if (b.length !== 32) throw new Error('expected 32 bytes'); return Buffer.from(b); };
const ro = (pubkey: PublicKey, isSigner = false) => ({ pubkey, isSigner, isWritable: false });
const rw = (pubkey: PublicKey, isSigner = false) => ({ pubkey, isSigner, isWritable: true });

export interface HtlcLockParams {
  swapId: Uint8Array;
  claimer: PublicKey;
  direction: number;
  amount: bigint;
  zecAmount: bigint;
  hashlock: Uint8Array;
  quoteHash: Uint8Array;
  /** Seconds from the lock to t1 (config bounds: min_t0 + min_window .. max_t0 + max_window). */
  t1Secs: number;
  /** Unix seconds; checked on chain only for SOL->ZEC. */
  consentExpiry: number;
  makerAuthority: PublicKey;
  /** Effective protocol fee the maker consents to. */
  feeBps: number;
}

/** The bytes a SOL->ZEC maker signs (as sha256) to consent to one lock. */
export function htlcConsentMessage(pid: PublicKey, locker: PublicKey, p: HtlcLockParams): Buffer {
  return Buffer.concat([
    Buffer.from(HTLC_CONSENT_PREFIX), pid.toBuffer(), htlcPda(pid, locker, p.swapId).toBuffer(), locker.toBuffer(),
    p.claimer.toBuffer(), Buffer.of(p.direction), u64(p.amount), u64(p.zecAmount), b32(p.hashlock), b32(p.quoteHash),
    i64(p.t1Secs), i64(p.consentExpiry), u16(p.feeBps),
  ]);
}
export const htlcConsentDigest = (pid: PublicKey, locker: PublicKey, p: HtlcLockParams) => sha256(htlcConsentMessage(pid, locker, p));

export function ixHtlcLock(pid: PublicKey, locker: PublicKey, p: HtlcLockParams) {
  return new TransactionInstruction({
    programId: pid,
    keys: [rw(locker, true), rw(htlcPda(pid, locker, p.swapId)), rw(pda.maker(pid, p.makerAuthority)), rw(pda.config(pid)),
      ro(SystemProgram.programId), ro(SYSVAR_INSTRUCTIONS_PUBKEY)],
    data: Buffer.concat([Buffer.of(IX.HTLC_LOCK), b32(p.swapId), p.claimer.toBuffer(), Buffer.of(p.direction), u64(p.amount),
      u64(p.zecAmount), b32(p.hashlock), b32(p.quoteHash), i64(p.t1Secs), i64(p.consentExpiry)]),
  });
}

/** Claim with the 32-byte preimage. Signed by the claimer (the fee payer may be a relayer). */
export function ixHtlcClaim(pid: PublicKey, claimer: PublicKey, escrow: PublicKey, makerAuthority: PublicKey, x: Uint8Array) {
  return new TransactionInstruction({
    programId: pid,
    keys: [rw(claimer, true), rw(escrow), rw(pda.maker(pid, makerAuthority)), rw(pda.config(pid)), rw(pda.feeVault(pid))],
    data: Buffer.concat([Buffer.of(IX.HTLC_CLAIM), b32(x)]),
  });
}

/** Point-lock claim (ZEC v2): reveals t (32 bytes little-endian, canonical) with t*G == T. */
export function ixHtlcPtClaim(pid: PublicKey, claimer: PublicKey, escrow: PublicKey, makerAuthority: PublicKey, t: Uint8Array) {
  return new TransactionInstruction({
    programId: pid,
    keys: [rw(claimer, true), rw(escrow), rw(pda.maker(pid, makerAuthority)), rw(pda.config(pid)), rw(pda.feeVault(pid))],
    data: Buffer.concat([Buffer.of(IX.HTLC_PT_CLAIM), b32(t)]),
  });
}

/** The claimer gives up its claim (the locker can then refund at once). */
export function ixHtlcAbort(pid: PublicKey, claimer: PublicKey, escrow: PublicKey, makerAuthority: PublicKey) {
  return new TransactionInstruction({
    programId: pid,
    keys: [ro(claimer, true), rw(escrow), rw(pda.maker(pid, makerAuthority)), rw(pda.config(pid))],
    data: Buffer.of(IX.HTLC_ABORT),
  });
}

/** Permissionless after t1 (or an abort): pays only the locker, reveals nothing. */
export function ixHtlcRefund(pid: PublicKey, payer: PublicKey, escrow: PublicKey, locker: PublicKey, makerAuthority: PublicKey) {
  return new TransactionInstruction({
    programId: pid,
    keys: [ro(payer, true), rw(escrow), rw(locker), rw(pda.maker(pid, makerAuthority)), rw(pda.config(pid))],
    data: Buffer.of(IX.HTLC_REFUND),
  });
}

export function ixHtlcClose(pid: PublicKey, locker: PublicKey, escrow: PublicKey) {
  return new TransactionInstruction({ programId: pid, keys: [rw(locker, true), rw(escrow)], data: Buffer.of(IX.HTLC_CLOSE) });
}

/** The preimage published by a claim (from the escrow account; zero until claimed). */
export function revealedPreimage(h: HtlcAccount): Uint8Array | null {
  if (h.state !== 4 || isPointDir(h.direction)) return null;
  return sha256(h.secret).every((b, i) => b === h.hashlock[i]) ? h.secret : null;
}

/** The scalar t a point-lock claim published (t*G == T, checked here), or null. */
export function revealedScalar(h: HtlcAccount): Uint8Array | null {
  if (h.state !== 4 || !isPointDir(h.direction)) return null;
  return scalarOpens(h.secret, h.hashlock) ? h.secret : null;
}
/** t (32 bytes little-endian) is canonical, non-zero and t*G == T (ed25519). */
export function scalarOpens(t: Uint8Array, T: Uint8Array): boolean {
  let v = 0n;
  for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(t[i]);
  if (v === 0n || v >= ed25519.CURVE.n) return false;
  try { return Buffer.from(ed25519.ExtendedPoint.BASE.multiply(v).toRawBytes()).equals(Buffer.from(T)); } catch { return false; }
}
