// HALFKEY program client: PDAs, instruction encoders, account decoders.
// Byte layouts mirror program/src/lib.rs exactly (see the Escrow/Maker/Config store() fns).
import { sha256 } from '@noble/hashes/sha256';
import { PublicKey, SystemProgram, TransactionInstruction, Ed25519Program, SYSVAR_INSTRUCTIONS_PUBKEY } from '@solana/web3.js';

export const DEFAULT_PROGRAM_ID = new PublicKey('11111111111111111111111111111111'); // overridden at runtime
export const BPF_UPGRADEABLE_LOADER = new PublicKey('BPFLoaderUpgradeab1e11111111111111111111111');

export const DIR_SOL_TO_XMR = 1;
export const DIR_XMR_TO_SOL = 2;
export const ST = { LOCKED: 1, READY: 2, ABORTED: 3, CLAIMED: 4, REFUNDED: 5 } as const;
export const ST_NAME: Record<number, string> = { 1: 'locked', 2: 'ready', 3: 'aborted', 4: 'claimed', 5: 'refunded' };

export const ESCROW_LEN = 448;
export const MAKER_LEN = 296;
/** Maker account with the platform extension (OTC/pay reputation, OTC size range). */
export const MAKER_LEN_V2 = 392;
export const CONFIG_LEN = 248;
export const LINK_LEN = 128;
export const VAULT_LEN = 448;
/** Escrow flags (header byte 6). PAY: XMR to a pay-link one-time key; OTC: an OTC tranche; VAULT: locker is a cashout vault. */
/** PROOF (v1.5): no claim at t0 without a verified Monero payment proof (sdk/v15.ts, sdk/xmrproof.ts). */
export const F = { PAY: 1, OTC: 2, VAULT: 4, PROOF: 8, DIRECT: 16, READY_ONLY: 32 } as const;
/** Immutable SOL->XMR opt-out: no committee/payment proof can replace the user's Ready. */
export const allowsPaymentProof = (e: { direction: number; flags: number }) =>
  !(e.flags & F.READY_ONLY) && (e.direction === DIR_SOL_TO_XMR || (e.direction === DIR_XMR_TO_SOL && !!(e.flags & F.PROOF)));
/** Late finish (program LATE_READY_MARGIN, mainnet build): `ready` stays open until max(t0, t1 - this). */
export const LATE_READY_MARGIN = 1800;
export const lateDeadline = (e: { t0: bigint; t1: bigint }) => Math.max(Number(e.t0), Number(e.t1) - LATE_READY_MARGIN);
/** v2 escrow (final round, sdk/final.ts): v1 layout + integrator share, tip, order deadline. */
export const ESCROW_LEN_V2 = 544;
export const OFF_ESCROW_FLAGS = 6;
export const OFF_ESCROW_WT0 = 288;
export const OFF_ESCROW_WT1 = 320;
export const OFF_ESCROW_LINK = 416;
export const OFF_LINK_OWNER = 40;
export const OFF_VAULT_OWNER = 8;
/** A claimed pay escrow can be closed by the payer only after this long (the recipient may close at once). */
export const PAY_CLOSE_GRACE = 90 * 86_400;
// memcmp offsets (escrow)
export const OFF_ESCROW_LOCKER = 40;
export const OFF_ESCROW_CLAIMER = 72;
export const OFF_ESCROW_MAKER = 104;

export const ERRORS: Record<number, string> = {
  1: 'BadInstruction', 2: 'NotSigner', 3: 'BadAccount', 4: 'BadPda', 5: 'AlreadyInitialized',
  6: 'Unauthorized', 7: 'Paused', 8: 'BadParam', 9: 'NonCanonicalScalar', 10: 'BadPoint',
  11: 'WrongSecret', 12: 'BadState', 13: 'TooEarly', 14: 'TooLate', 15: 'AmountOutOfRange',
  16: 'CapExceeded', 17: 'MakerInactive', 18: 'DirectionUnsupported', 19: 'OpenSwaps',
  20: 'BondLocked', 21: 'Overflow', 22: 'BondTooSmall', 23: 'NoConsent', 24: 'Staked',
  25: 'NotUpgraded', 26: 'RateTooLow', 27: 'NotDue', 28: 'NoWatchtower', 29: 'Timelocked', 30: 'NothingPending',
  40: 'NotProven', 41: 'BadXmrTx', 42: 'BadXmrProof', 43: 'WrongOutput', 44: 'BadAmount', 45: 'AmountTooLow',
  46: 'BadInclusion', 47: 'NotAttested', 48: 'Slippage',
  49: 'Underpaid', 50: 'Expired', 51: 'Reserved', 52: 'BadPaymentId', 53: 'FeeTooHigh', 54: 'WindowTooShort',
};

export const IX = {
  INIT_CONFIG: 0, UPDATE_CONFIG: 1, REGISTER_MAKER: 2, UPDATE_MAKER: 3, REQUEST_UNBOND: 4,
  WITHDRAW_MAKER: 5, LOCK: 6, READY: 7, ABORT: 8, CLAIM: 9, REFUND: 10, CLOSE: 11, SWEEP_FEES: 12, EXPIRE: 13, STAKE: 14, UNSTAKE_REQUEST: 15, UNSTAKE: 16,
  LOCK2: 17, CLOSE_PAY: 18, SET_CONFIG_EXT: 19, UPGRADE_MAKER: 20, REGISTER_LINK: 21, VAULT_CREATE: 22, VAULT_PROPOSE: 23,
  VAULT_APPLY: 24, VAULT_CANCEL: 25, VAULT_TIGHTEN: 26, VAULT_LOCK: 27, VAULT_WITHDRAW_REQUEST: 28, VAULT_WITHDRAW: 29, RETIRE_LINK: 30,
} as const;

// ---------------------------------------------------------------- byte writer / reader
class W {
  parts: Uint8Array[] = [];
  u8(v: number) { this.parts.push(Uint8Array.of(v)); return this; }
  u16(v: number) { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, v, true); this.parts.push(b); return this; }
  u64(v: bigint | number) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(v), true); this.parts.push(b); return this; }
  i64(v: bigint | number) { const b = new Uint8Array(8); new DataView(b.buffer).setBigInt64(0, BigInt(v), true); this.parts.push(b); return this; }
  bytes(b: Uint8Array, len?: number) {
    if (len !== undefined && b.length !== len) throw new Error(`expected ${len} bytes, got ${b.length}`);
    this.parts.push(b); return this;
  }
  key(k: PublicKey) { return this.bytes(k.toBytes(), 32); }
  done() { return Buffer.concat(this.parts); }
}
class R {
  o = 0;
  d: Uint8Array;
  dv: DataView;
  constructor(d: Uint8Array) { this.d = d; this.dv = new DataView(d.buffer, d.byteOffset, d.byteLength); }
  u8() { return this.d[this.o++]; }
  u16() { const v = this.dv.getUint16(this.o, true); this.o += 2; return v; }
  u32() { const v = this.dv.getUint32(this.o, true); this.o += 4; return v; }
  u64() { const v = this.dv.getBigUint64(this.o, true); this.o += 8; return v; }
  i64() { const v = this.dv.getBigInt64(this.o, true); this.o += 8; return v; }
  b(n: number) { const v = this.d.slice(this.o, this.o + n); this.o += n; return v; }
  key() { return new PublicKey(this.b(32)); }
  skip(n: number) { this.o += n; }
}

// ---------------------------------------------------------------- PDAs
export const pda = {
  config: (pid: PublicKey) => PublicKey.findProgramAddressSync([Buffer.from('config')], pid)[0],
  feeVault: (pid: PublicKey) => PublicKey.findProgramAddressSync([Buffer.from('fee_vault')], pid)[0],
  maker: (pid: PublicKey, authority: PublicKey) =>
    PublicKey.findProgramAddressSync([Buffer.from('maker'), authority.toBytes()], pid)[0],
  escrow: (pid: PublicKey, locker: PublicKey, swapId: Uint8Array) =>
    PublicKey.findProgramAddressSync([Buffer.from('swap'), locker.toBytes(), swapId], pid)[0],
  programData: (pid: PublicKey) =>
    PublicKey.findProgramAddressSync([pid.toBytes()], BPF_UPGRADEABLE_LOADER)[0],
  /** `/pay/<name>` link account. */
  link: (pid: PublicKey, name: string) => PublicKey.findProgramAddressSync([Buffer.from('link'), Buffer.from(name, 'utf8')], pid)[0],
  /** Auto-cashout vault of an owner. */
  vault: (pid: PublicKey, owner: PublicKey) => PublicKey.findProgramAddressSync([Buffer.from('vault'), owner.toBytes()], pid)[0],
};

/** Link names: 3..32 chars of a-z, 0-9 and '-', not starting or ending with '-'. */
export const isLinkName = (n: string) => /^[a-z0-9](?:[a-z0-9-]{1,30})[a-z0-9]$/.test(n);

// ---------------------------------------------------------------- types
export interface ConfigParams {
  feeRecipient: PublicKey;
  halfkeyMint: PublicKey;
  feeBps: number;
  holderFeeBps: number;
  holderMin: bigint;
  minBond: bigint;
  maxSwap: bigint;
  maxOpenTvl: bigint;
  minT0: number;
  maxT0: number;
  minWindow: number;
  maxWindow: number;
  unbondSecs: number;
}

export interface ConfigAccount extends ConfigParams {
  paused: boolean;
  admin: PublicKey;
  openTvl: bigint;
  totalSwaps: bigint;
  totalVolume: bigint;
  totalFees: bigint;
  /** Per-escrow cap for OTC tranches (0 = maxSwap). */
  otcMaxSwap: bigint;
  /** Smallest timelock a cashout vault may use. */
  vaultMinDelay: number;
  /** Final round: lamports locked in open offers (their own bucket, capped at maxOpenTvl). */
  offerTvl?: bigint;
}

export interface MakerAccount {
  address?: PublicKey;
  active: boolean;
  directions: number;
  authority: PublicKey;
  bond: bigint;
  min: bigint;
  max: bigint;
  openSwaps: number;
  openLamports: bigint;
  completed: bigint;
  aborted: bigint;
  expired: bigint;
  volume: bigint;
  createdAt: bigint;
  withdrawAfter: bigint;
  spreadBps: number;
  endpoint: string;
  cancelled: bigint;
  declined: bigint;
  /** $HALFKEY bonded in the maker's stake vault; stakeUnlockAt != 0 = unstake pending (no discount). */
  staked: bigint;
  stakeUnlockAt: bigint;
  /** Platform extension present (MAKER_LEN_V2). Flagged locks (OTC / pay / vault) need it. */
  v2: boolean;
  ext: MakerExt;
}

export interface MakerExt {
  otcFills: bigint; otcVolume: bigint; otcFailed: bigint; otcDeclined: bigint;
  payFills: bigint; payVolume: bigint; payFailed: bigint; payDeclined: bigint;
  /** OTC tranche size range (otcMax = 0: OTC uses min/max). */
  otcMin: bigint; otcMax: bigint;
}
const EMPTY_EXT: MakerExt = { otcFills: 0n, otcVolume: 0n, otcFailed: 0n, otcDeclined: 0n, payFills: 0n, payVolume: 0n, payFailed: 0n, payDeclined: 0n, otcMin: 0n, otcMax: 0n };

export interface LinkAccount {
  address?: PublicKey;
  name: string;
  /** Retired links take no new payments. */
  retired: boolean;
  owner: PublicKey;
  /** Master public point S (prime order, checked on chain). */
  master: Uint8Array;
  createdAt: bigint;
  payments: bigint;
  lockedLamports: bigint;
}

export interface VaultParams {
  /** PublicKey.default = anyone may trigger a conversion (the owner always may). */
  keeper: PublicKey;
  watchtowers: PublicKey[];
  link: PublicKey;
  minLamports: bigint;
  maxLamports: bigint;
  interval: number;
  /** Floor price, piconero per SOL. */
  minRate: bigint;
  delay: number;
}

export interface VaultAccount {
  address?: PublicKey;
  paused: boolean;
  /** The pending proposal also unpauses. */
  pendingUnpause: boolean;
  owner: PublicKey;
  p: VaultParams;
  nextAt: bigint;
  createdAt: bigint;
  pendingAt: bigint;
  pending: VaultParams;
  withdrawAt: bigint;
  withdrawAmount: bigint;
  conversions: bigint;
  lockedLamports: bigint;
  refunds: bigint;
  refundedLamports: bigint;
}

export interface EscrowAccount {
  address?: PublicKey;
  state: number;
  direction: number;
  released: boolean;
  swapId: Uint8Array;
  locker: PublicKey;
  claimer: PublicKey;
  maker: PublicKey;
  amount: bigint;
  xmrAmount: bigint;
  feeBps: number;
  claimPoint: Uint8Array;
  refundPoint: Uint8Array;
  viewPub: Uint8Array;
  quoteHash: Uint8Array;
  watchtowers: PublicKey[];
  createdAt: bigint;
  t0: bigint;
  t1: bigint;
  settledAt: bigint;
  secret: Uint8Array;
  /** F.PAY | F.OTC | F.VAULT */
  flags: number;
  /** PAY: the link account the one-time key derives from. */
  link: PublicKey;
  /** v2 escrow (final round): integrator share, finisher tip, order deadline. */
  v2?: boolean;
  ext?: { integrator: PublicKey; integratorBps: number; origin: number; tip: bigint; orderDeadline: bigint };
}

// ---------------------------------------------------------------- decoders
export function decodeConfig(d: Uint8Array): ConfigAccount {
  if (d.length !== CONFIG_LEN || d[0] !== 0xc1) throw new Error('not a config account');
  const r = new R(d);
  r.skip(2);
  const paused = r.u8() !== 0;
  r.skip(5);
  const admin = r.key(), feeRecipient = r.key(), halfkeyMint = r.key();
  const feeBps = r.u16(), holderFeeBps = r.u16();
  r.skip(4);
  return {
    paused, admin, feeRecipient, halfkeyMint, feeBps, holderFeeBps,
    holderMin: r.u64(), minBond: r.u64(), maxSwap: r.u64(), maxOpenTvl: r.u64(), openTvl: r.u64(),
    minT0: Number(r.i64()), maxT0: Number(r.i64()), minWindow: Number(r.i64()), maxWindow: Number(r.i64()),
    unbondSecs: Number(r.i64()), totalSwaps: r.u64(), totalVolume: r.u64(), totalFees: r.u64(),
    otcMaxSwap: r.u64(), vaultMinDelay: Number(r.i64()), offerTvl: r.u64(),
  };
}

export function decodeMaker(d: Uint8Array, address?: PublicKey): MakerAccount {
  if ((d.length !== MAKER_LEN && d.length !== MAKER_LEN_V2) || d[0] !== 0xa7) throw new Error('not a maker account');
  const r = new R(d);
  r.skip(2);
  const active = r.u8() !== 0, directions = r.u8();
  r.skip(1);
  const elen = r.u8();
  r.skip(2);
  const authority = r.key();
  const bond = r.u64(), min = r.u64(), max = r.u64();
  const openSwaps = r.u32(); r.skip(4);
  const openLamports = r.u64(), completed = r.u64(), aborted = r.u64(), expired = r.u64(), volume = r.u64();
  const createdAt = r.i64(), withdrawAfter = r.i64();
  const spreadBps = r.u16(); r.skip(6);
  const endpoint = Buffer.from(r.b(128).slice(0, elen)).toString('utf8');
  const cancelled = r.u64(), declined = r.u64(), staked = r.u64(), stakeUnlockAt = r.i64();
  const v2 = d.length === MAKER_LEN_V2;
  const ext: MakerExt = v2 ? {
    otcFills: r.u64(), otcVolume: r.u64(), otcFailed: r.u64(), otcDeclined: r.u64(),
    payFills: r.u64(), payVolume: r.u64(), payFailed: r.u64(), payDeclined: r.u64(), otcMin: r.u64(), otcMax: r.u64(),
  } : { ...EMPTY_EXT };
  return { address, active, directions, authority, bond, min, max, openSwaps, openLamports, completed, aborted, expired, volume, createdAt, withdrawAfter, spreadBps, endpoint, cancelled, declined, staked, stakeUnlockAt, v2, ext };
}

/** Maker accounts come in two sizes (with and without the platform extension). */
export const MAKER_SIZES = [MAKER_LEN, MAKER_LEN_V2];

export function decodeLink(d: Uint8Array, address?: PublicKey): LinkAccount {
  if (d.length !== LINK_LEN || d[0] !== 0x1c) throw new Error('not a link account');
  const r = new R(d);
  r.skip(3);
  const n = r.u8();
  const retired = r.u8() !== 0;
  r.skip(3);
  const name = Buffer.from(r.b(32).slice(0, n)).toString('utf8');
  return { address, name, retired, owner: r.key(), master: r.b(32), createdAt: r.i64(), payments: r.u64(), lockedLamports: r.u64() };
}

function readVp(r: R): VaultParams {
  return { keeper: r.key(), watchtowers: [r.key(), r.key()], link: r.key(), minLamports: r.u64(), maxLamports: r.u64(), interval: Number(r.i64()), minRate: r.u64(), delay: Number(r.i64()) };
}

export function decodeVault(d: Uint8Array, address?: PublicKey): VaultAccount {
  if (d.length !== VAULT_LEN || d[0] !== 0x5a) throw new Error('not a vault account');
  const r = new R(d);
  r.skip(3);
  const paused = r.u8() !== 0;
  const pendingUnpause = r.u8() !== 0;
  r.skip(3);
  const owner = r.key();
  const p = readVp(r);
  const nextAt = r.i64(), createdAt = r.i64(), pendingAt = r.i64();
  const pending = readVp(r);
  return { address, paused, pendingUnpause, owner, p, nextAt, createdAt, pendingAt, pending, withdrawAt: r.i64(), withdrawAmount: r.u64(), conversions: r.u64(), lockedLamports: r.u64(), refunds: r.u64(), refundedLamports: r.u64() };
}

export function decodeEscrow(d: Uint8Array, address?: PublicKey): EscrowAccount {
  if ((d.length !== ESCROW_LEN && d.length !== ESCROW_LEN_V2) || d[0] !== 0xe5) throw new Error('not an escrow account');
  const r = new R(d);
  r.skip(2);
  const state = r.u8(), direction = r.u8();
  r.skip(1);
  const released = r.u8() !== 0;
  const flags = r.u8();
  r.skip(1);
  const swapId = r.b(32), locker = r.key(), claimer = r.key(), maker = r.key();
  const amount = r.u64(), xmrAmount = r.u64(), feeBps = r.u16();
  r.skip(6);
  return {
    address, state, direction, released, swapId, locker, claimer, maker, amount, xmrAmount, feeBps,
    claimPoint: r.b(32), refundPoint: r.b(32), viewPub: r.b(32), quoteHash: r.b(32),
    watchtowers: [r.key(), r.key()],
    createdAt: r.i64(), t0: r.i64(), t1: r.i64(), settledAt: r.i64(), secret: r.b(32),
    flags, link: r.key(),
    v2: d.length === ESCROW_LEN_V2,
    ext: d.length === ESCROW_LEN_V2
      ? (() => { const integrator = r.key(); const integratorBps = r.u16(); const origin = r.u8(); r.skip(5); return { integrator, integratorBps, origin, tip: r.u64(), orderDeadline: r.i64() }; })()
      : undefined,
  };
}

// ---------------------------------------------------------------- instructions
const ro = (pubkey: PublicKey, isSigner = false) => ({ pubkey, isSigner, isWritable: false });
const rw = (pubkey: PublicKey, isSigner = false) => ({ pubkey, isSigner, isWritable: true });

function configParams(w: W, p: ConfigParams) {
  return w.key(p.feeRecipient).key(p.halfkeyMint).u16(p.feeBps).u16(p.holderFeeBps).u64(p.holderMin)
    .u64(p.minBond).u64(p.maxSwap).u64(p.maxOpenTvl).i64(p.minT0).i64(p.maxT0).i64(p.minWindow)
    .i64(p.maxWindow).i64(p.unbondSecs);
}

export function ixInitConfig(pid: PublicKey, admin: PublicKey, p: ConfigParams) {
  return new TransactionInstruction({
    programId: pid,
    keys: [rw(admin, true), rw(pda.config(pid)), rw(pda.feeVault(pid)), ro(pda.programData(pid)), ro(SystemProgram.programId)],
    data: configParams(new W().u8(IX.INIT_CONFIG), p).done(),
  });
}

export function ixUpdateConfig(pid: PublicKey, admin: PublicKey, p: ConfigParams, paused: boolean, newAdmin: PublicKey) {
  return new TransactionInstruction({
    programId: pid,
    keys: [ro(admin, true), rw(pda.config(pid))],
    data: configParams(new W().u8(IX.UPDATE_CONFIG), p).u8(paused ? 1 : 0).key(newAdmin).done(),
  });
}

export interface MakerParams { min: bigint; max: bigint; directions: number; spreadBps: number; endpoint: string }

export function ixRegisterMaker(pid: PublicKey, authority: PublicKey, bond: bigint, m: MakerParams) {
  const ep = Buffer.from(m.endpoint, 'utf8');
  return new TransactionInstruction({
    programId: pid,
    keys: [rw(authority, true), rw(pda.maker(pid, authority)), ro(pda.config(pid)), ro(SystemProgram.programId)],
    data: new W().u8(IX.REGISTER_MAKER).u64(bond).u64(m.min).u64(m.max).u8(m.directions).u16(m.spreadBps)
      .u8(ep.length).bytes(ep).done(),
  });
}

export function ixUpdateMaker(pid: PublicKey, authority: PublicKey, addBond: bigint, m: MakerParams, active: boolean) {
  const ep = Buffer.from(m.endpoint, 'utf8');
  return new TransactionInstruction({
    programId: pid,
    keys: [rw(authority, true), rw(pda.maker(pid, authority)), ro(pda.config(pid)), ro(SystemProgram.programId)],
    data: new W().u8(IX.UPDATE_MAKER).u64(addBond).u64(m.min).u64(m.max).u8(m.directions).u16(m.spreadBps)
      .u8(active ? 1 : 0).u8(ep.length).bytes(ep).done(),
  });
}

export function ixRequestUnbond(pid: PublicKey, authority: PublicKey) {
  return new TransactionInstruction({
    programId: pid,
    keys: [ro(authority, true), rw(pda.maker(pid, authority)), ro(pda.config(pid))],
    data: Buffer.from([IX.REQUEST_UNBOND]),
  });
}

export function ixWithdrawMaker(pid: PublicKey, authority: PublicKey) {
  return new TransactionInstruction({
    programId: pid,
    keys: [rw(authority, true), rw(pda.maker(pid, authority))],
    data: Buffer.from([IX.WITHDRAW_MAKER]),
  });
}

export interface LockParams {
  swapId: Uint8Array;
  claimer: PublicKey;
  direction: number;
  amount: bigint;
  xmrAmount: bigint;
  claimPoint: Uint8Array;
  refundPoint: Uint8Array;
  viewPub: Uint8Array;
  quoteHash: Uint8Array;
  t0Secs: number;
  windowSecs: number;
  watchtowers: PublicKey[]; // up to 2
  makerAuthority: PublicKey;
  consentExpiry: number; // unix seconds; ignored on chain for XMR->SOL
  /** Effective protocol fee the maker consents to (config fee, or the holder fee while it has $HALFKEY bonded). */
  feeBps: number;
  /** Escrow flags including F.READY_ONLY (lock2). 0 or absent = a phase-1 lock with the v1 consent. */
  flags?: number;
  /** PAY: the link account (refundPoint/viewPub must be its derived one-time keys). */
  link?: PublicKey;
}

/**
 * The bytes a maker signs to consent to a lock (must match program consent_message / _v2).
 * Flagged locks use v2, which also binds the flags, the link and both watchtower slots.
 */
export function consentMessage(pid: PublicKey, locker: PublicKey, p: LockParams): Buffer {
  const escrow = pda.escrow(pid, locker, p.swapId);
  const flags = p.flags ?? 0;
  const w = new W().bytes(Buffer.from(flags ? 'halfkey-consent-v2' : 'halfkey-consent-v1')).key(pid).key(escrow).key(locker).key(p.claimer)
    .u8(p.direction).u64(p.amount).u64(p.xmrAmount).bytes(p.claimPoint, 32).bytes(p.refundPoint, 32)
    .bytes(p.viewPub, 32).bytes(p.quoteHash, 32).i64(p.t0Secs).i64(p.windowSecs).i64(p.consentExpiry).u16(p.feeBps);
  if (flags) {
    const wt = [...p.watchtowers, PublicKey.default, PublicKey.default].slice(0, 2);
    w.u8(flags).key(flags & F.PAY ? p.link! : PublicKey.default).key(wt[0]).key(wt[1]);
  }
  return w.done();
}

/** What the maker actually signs: sha256(consentMessage). */
export function consentDigest(pid: PublicKey, locker: PublicKey, p: LockParams): Uint8Array {
  return sha256(consentMessage(pid, locker, p));
}

/** Ed25519 precompile ix carrying the maker's consent (over the digest); must sit directly before the lock ix. */
export function ixConsent(makerAuthority: PublicKey, message: Uint8Array, signature: Uint8Array) {
  return Ed25519Program.createInstructionWithPublicKey({ publicKey: makerAuthority.toBytes(), message, signature });
}

export function ixLock(pid: PublicKey, locker: PublicKey, p: LockParams) {
  const wt = [...p.watchtowers, PublicKey.default, PublicKey.default].slice(0, 2);
  const keys = [
    rw(locker, true), rw(pda.escrow(pid, locker, p.swapId)), rw(pda.maker(pid, p.makerAuthority)),
    rw(pda.config(pid)), ro(SystemProgram.programId), ro(SYSVAR_INSTRUCTIONS_PUBKEY),
  ];
  return new TransactionInstruction({
    programId: pid,
    keys,
    data: new W().u8(IX.LOCK).bytes(p.swapId, 32).key(p.claimer).u8(p.direction).u64(p.amount).u64(p.xmrAmount)
      .bytes(p.claimPoint, 32).bytes(p.refundPoint, 32).bytes(p.viewPub, 32).bytes(p.quoteHash, 32)
      .i64(p.t0Secs).i64(p.windowSecs).key(wt[0]).key(wt[1]).i64(p.consentExpiry).done(),
  });
}

/** Lock with flags (OTC tranche, pay link). PAY adds the link account (writable: payment counters). */
export function ixLock2(pid: PublicKey, locker: PublicKey, p: LockParams) {
  const flags = p.flags ?? 0;
  const wt = [...p.watchtowers, PublicKey.default, PublicKey.default].slice(0, 2);
  const keys = [
    rw(locker, true), rw(pda.escrow(pid, locker, p.swapId)), rw(pda.maker(pid, p.makerAuthority)),
    rw(pda.config(pid)), ro(SystemProgram.programId), ro(SYSVAR_INSTRUCTIONS_PUBKEY),
  ];
  if (flags & F.PAY) keys.push(rw(p.link!));
  return new TransactionInstruction({
    programId: pid,
    keys,
    data: new W().u8(IX.LOCK2).bytes(p.swapId, 32).key(p.claimer).u8(p.direction).u64(p.amount).u64(p.xmrAmount)
      .bytes(p.claimPoint, 32).bytes(p.refundPoint, 32).bytes(p.viewPub, 32).bytes(p.quoteHash, 32)
      .i64(p.t0Secs).i64(p.windowSecs).key(wt[0]).key(wt[1]).i64(p.consentExpiry).u8(flags).done(),
  });
}

/** The right lock instruction for these params (v1 when unflagged, so phase-1 makers keep working). */
export const ixLockAny = (pid: PublicKey, locker: PublicKey, p: LockParams) => ((p.flags ?? 0) ? ixLock2(pid, locker, p) : ixLock(pid, locker, p));

/** Close a pay escrow (recipient at any time once claimed; locker after PAY_CLOSE_GRACE or once refunded). */
export function ixClosePay(pid: PublicKey, who: PublicKey, escrow: PublicKey, locker: PublicKey, link: PublicKey) {
  return new TransactionInstruction({ programId: pid, keys: [ro(who, true), rw(escrow), rw(locker), ro(link)], data: Buffer.from([IX.CLOSE_PAY]) });
}

export function ixSetConfigExt(pid: PublicKey, admin: PublicKey, otcMaxSwap: bigint, vaultMinDelay: number) {
  return new TransactionInstruction({ programId: pid, keys: [ro(admin, true), rw(pda.config(pid))], data: new W().u8(IX.SET_CONFIG_EXT).u64(otcMaxSwap).i64(vaultMinDelay).done() });
}

/** Grow the maker account to MAKER_LEN_V2 (first call) and set the OTC tranche range. */
export function ixUpgradeMaker(pid: PublicKey, authority: PublicKey, otcMin: bigint, otcMax: bigint) {
  return new TransactionInstruction({
    programId: pid,
    keys: [rw(authority, true), rw(pda.maker(pid, authority)), ro(SystemProgram.programId)],
    data: new W().u8(IX.UPGRADE_MAKER).u64(otcMin).u64(otcMax).done(),
  });
}

export function ixRegisterLink(pid: PublicKey, owner: PublicKey, name: string, master: Uint8Array) {
  const n = Buffer.from(name, 'utf8');
  return new TransactionInstruction({
    programId: pid,
    keys: [rw(owner, true), rw(pda.link(pid, name)), ro(SystemProgram.programId)],
    data: new W().u8(IX.REGISTER_LINK).u8(n.length).bytes(n).bytes(master, 32).done(),
  });
}

function vaultParams(w: W, p: VaultParams) {
  const wt = [...p.watchtowers, PublicKey.default, PublicKey.default].slice(0, 2);
  return w.key(p.keeper).key(wt[0]).key(wt[1]).key(p.link).u64(p.minLamports).u64(p.maxLamports).i64(p.interval).u64(p.minRate).i64(p.delay);
}

export function ixVaultCreate(pid: PublicKey, owner: PublicKey, p: VaultParams) {
  return new TransactionInstruction({
    programId: pid,
    keys: [rw(owner, true), rw(pda.vault(pid, owner)), ro(p.link), ro(pda.config(pid)), ro(SystemProgram.programId)],
    data: vaultParams(new W().u8(IX.VAULT_CREATE), p).done(),
  });
}
/** Timelocked change; `unpause` also lifts a pause when it applies (unpausing is never instant). */
export function ixVaultPropose(pid: PublicKey, owner: PublicKey, p: VaultParams, unpause = false) {
  return new TransactionInstruction({
    programId: pid,
    keys: [ro(owner, true), rw(pda.vault(pid, owner)), ro(p.link), ro(pda.config(pid))],
    data: vaultParams(new W().u8(IX.VAULT_PROPOSE), p).u8(unpause ? 1 : 0).done(),
  });
}
/** One-way: the link takes no new payments (if the wallet root ever leaks). */
export function ixRetireLink(pid: PublicKey, owner: PublicKey, link: PublicKey) {
  return new TransactionInstruction({ programId: pid, keys: [ro(owner, true), rw(link)], data: Buffer.from([IX.RETIRE_LINK]) });
}
export function ixVaultApply(pid: PublicKey, who: PublicKey, vault: PublicKey) {
  return new TransactionInstruction({ programId: pid, keys: [ro(who, true), rw(vault)], data: Buffer.from([IX.VAULT_APPLY]) });
}
export function ixVaultCancel(pid: PublicKey, owner: PublicKey) {
  return new TransactionInstruction({ programId: pid, keys: [ro(owner, true), rw(pda.vault(pid, owner))], data: Buffer.from([IX.VAULT_CANCEL]) });
}
/** Instant, safe-direction changes only: pause, raise the floor, lower the size cap, slow the schedule (unpause: ixVaultPropose). */
export function ixVaultTighten(pid: PublicKey, owner: PublicKey, paused: boolean, minRate: bigint, maxLamports: bigint, interval: number) {
  return new TransactionInstruction({
    programId: pid,
    keys: [ro(owner, true), rw(pda.vault(pid, owner))],
    data: new W().u8(IX.VAULT_TIGHTEN).u8(paused ? 1 : 0).u64(minRate).u64(maxLamports).i64(interval).done(),
  });
}
export interface VaultLockParams {
  swapId: Uint8Array; amount: bigint; xmrAmount: bigint; claimPoint: Uint8Array; quoteHash: Uint8Array;
  t0Secs: number; windowSecs: number; consentExpiry: number; makerAuthority: PublicKey;
}
export function ixVaultLock(pid: PublicKey, keeper: PublicKey, vault: PublicKey, link: PublicKey, p: VaultLockParams) {
  return new TransactionInstruction({
    programId: pid,
    keys: [ro(keeper, true), rw(vault), rw(pda.escrow(pid, vault, p.swapId)), rw(pda.maker(pid, p.makerAuthority)), rw(pda.config(pid)),
      rw(link), ro(SystemProgram.programId), ro(SYSVAR_INSTRUCTIONS_PUBKEY)],
    data: new W().u8(IX.VAULT_LOCK).bytes(p.swapId, 32).u64(p.amount).u64(p.xmrAmount).bytes(p.claimPoint, 32).bytes(p.quoteHash, 32)
      .i64(p.t0Secs).i64(p.windowSecs).i64(p.consentExpiry).done(),
  });
}
export function ixVaultWithdrawRequest(pid: PublicKey, owner: PublicKey, amount: bigint) {
  return new TransactionInstruction({ programId: pid, keys: [ro(owner, true), rw(pda.vault(pid, owner))], data: new W().u8(IX.VAULT_WITHDRAW_REQUEST).u64(amount).done() });
}
export function ixVaultWithdraw(pid: PublicKey, owner: PublicKey) {
  return new TransactionInstruction({ programId: pid, keys: [rw(owner, true), rw(pda.vault(pid, owner))], data: Buffer.from([IX.VAULT_WITHDRAW]) });
}

// ---------------------------------------------------------------- $HALFKEY maker bond (stake)
export const TOKEN_PROGRAM = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
export const TOKEN_2022_PROGRAM = new PublicKey('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'); // canonical (was a P7 typo); pinned by program/src/lib.rs tests::client_program_ids_match
export const ATA_PROGRAM = new PublicKey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');
export const ata = (owner: PublicKey, mint: PublicKey, tokenProgram = TOKEN_PROGRAM) =>
  PublicKey.findProgramAddressSync([owner.toBytes(), tokenProgram.toBytes(), mint.toBytes()], ATA_PROGRAM)[0];
export const stakeOwner = (pid: PublicKey, authority: PublicKey) =>
  PublicKey.findProgramAddressSync([Buffer.from('stake'), authority.toBytes()], pid)[0];
export const stakeVault = (pid: PublicKey, authority: PublicKey, mint: PublicKey, tokenProgram = TOKEN_PROGRAM) =>
  ata(stakeOwner(pid, authority), mint, tokenProgram);

/**
 * $HALFKEY stake. Since v1.5 the maker bond is a stake in the reward pool (program/src/rewards.rs,
 * open to anyone, same vault and unbond delay); the maker-only instructions 14-16 are retired.
 * These keep their old names; sdk/v15.ts has the same calls plus claim, split and deposit.
 */
const stakeOwnerOf = (pid: PublicKey, a: PublicKey) => PublicKey.findProgramAddressSync([Buffer.from('stake'), a.toBytes()], pid)[0];
const poolOf = (pid: PublicKey) => PublicKey.findProgramAddressSync([Buffer.from('stake_pool')], pid)[0];
const stakerOf = (pid: PublicKey, a: PublicKey) => PublicKey.findProgramAddressSync([Buffer.from('staker'), a.toBytes()], pid)[0];
export function ixStake(pid: PublicKey, authority: PublicKey, mint: PublicKey, source: PublicKey, amount: bigint, tokenProgram = TOKEN_PROGRAM) {
  const so = stakeOwnerOf(pid, authority);
  return new TransactionInstruction({
    programId: pid,
    keys: [rw(authority, true), ro(pda.config(pid)), ro(mint), rw(source), rw(ata(so, mint, tokenProgram)), ro(so), ro(tokenProgram), ro(ATA_PROGRAM),
      ro(SystemProgram.programId), rw(poolOf(pid)), rw(stakerOf(pid, authority)), rw(pda.feeVault(pid)), rw(pda.maker(pid, authority))],
    data: new W().u8(36).u64(amount).done(),
  });
}
/** amount 0 = everything staked. */
export function ixUnstakeRequest(pid: PublicKey, authority: PublicKey, amount = 0n) {
  return new TransactionInstruction({
    programId: pid,
    keys: [ro(authority, true), ro(pda.config(pid)), rw(poolOf(pid)), rw(stakerOf(pid, authority)), rw(pda.feeVault(pid)), rw(pda.maker(pid, authority))],
    data: new W().u8(37).u64(amount).done(),
  });
}
export function ixUnstake(pid: PublicKey, authority: PublicKey, mint: PublicKey, dest: PublicKey, tokenProgram = TOKEN_PROGRAM) {
  const so = stakeOwnerOf(pid, authority);
  return new TransactionInstruction({
    programId: pid,
    keys: [ro(authority, true), ro(pda.config(pid)), ro(mint), rw(dest), rw(ata(so, mint, tokenProgram)), ro(so), ro(tokenProgram), rw(stakerOf(pid, authority)), rw(pda.maker(pid, authority)), ro(poolOf(pid))],
    data: Buffer.from([38]),
  });
}

export function ixReady(pid: PublicKey, locker: PublicKey, escrow: PublicKey) {
  return new TransactionInstruction({ programId: pid, keys: [ro(locker, true), rw(escrow)], data: Buffer.from([IX.READY]) });
}

export function ixAbort(pid: PublicKey, who: PublicKey, escrow: PublicKey, makerAuthority: PublicKey) {
  return new TransactionInstruction({
    programId: pid,
    keys: [ro(who, true), rw(escrow), rw(pda.maker(pid, makerAuthority)), rw(pda.config(pid))],
    data: Buffer.from([IX.ABORT]),
  });
}

export function ixExpire(pid: PublicKey, who: PublicKey, escrow: PublicKey, makerAuthority: PublicKey) {
  return new TransactionInstruction({
    programId: pid,
    keys: [ro(who, true), rw(escrow), rw(pda.maker(pid, makerAuthority)), rw(pda.config(pid))],
    data: Buffer.from([IX.EXPIRE]),
  });
}

/** `proof`: the payment-proof record (sdk/v15.ts pdaV15.proof); required for a proof-mode escrow claimed without `ready`. */
export function ixClaim(pid: PublicKey, claimer: PublicKey, escrow: PublicKey, makerAuthority: PublicKey, secret: Uint8Array, proof?: PublicKey) {
  const keys = [rw(claimer, true), rw(escrow), rw(pda.maker(pid, makerAuthority)), rw(pda.config(pid)), rw(pda.feeVault(pid))];
  if (proof) keys.push(ro(proof));
  return new TransactionInstruction({
    programId: pid,
    keys,
    data: new W().u8(IX.CLAIM).bytes(secret, 32).done(),
  });
}

export function ixRefund(pid: PublicKey, payer: PublicKey, escrow: PublicKey, locker: PublicKey, makerAuthority: PublicKey, secret: Uint8Array) {
  return new TransactionInstruction({
    programId: pid,
    keys: [ro(payer, true), rw(escrow), rw(locker), rw(pda.maker(pid, makerAuthority)), rw(pda.config(pid))],
    data: new W().u8(IX.REFUND).bytes(secret, 32).done(),
  });
}

export function ixClose(pid: PublicKey, locker: PublicKey, escrow: PublicKey) {
  return new TransactionInstruction({ programId: pid, keys: [rw(locker, true), rw(escrow)], data: Buffer.from([IX.CLOSE]) });
}

export function ixSweepFees(pid: PublicKey, who: PublicKey, feeRecipient: PublicKey) {
  return new TransactionInstruction({
    programId: pid,
    keys: [ro(who, true), ro(pda.config(pid)), rw(pda.feeVault(pid)), rw(feeRecipient)],
    data: Buffer.from([IX.SWEEP_FEES]),
  });
}

/** Extract `Custom(n)` from a web3.js error/log and name it. */
export function errName(e: unknown): string {
  const s = String((e as any)?.message ?? e) + JSON.stringify((e as any)?.logs ?? (e as any)?.transactionLogs ?? '');
  const m = s.match(/custom program error: 0x([0-9a-f]+)/i) || s.match(/"Custom":(\d+)/);
  if (!m) return s.slice(0, 200);
  const n = m[0].includes('0x') ? parseInt(m[1], 16) : parseInt(m[1], 10);
  return ERRORS[n] ?? `Custom(${n})`;
}
