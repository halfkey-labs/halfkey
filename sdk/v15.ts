// HALFKEY v1.5 program client: payment-proof accounts and instructions (program/src/zkproof.rs)
// and the $HALFKEY burn auction (program/src/burn.rs). Layouts mirror the Rust store() fns.
import { PublicKey, SystemProgram, TransactionInstruction, SYSVAR_INSTRUCTIONS_PUBKEY, Connection } from '@solana/web3.js';
import { ed25519 } from '@noble/curves/ed25519';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils';
import { sha256 } from '@noble/hashes/sha256';
import { pda, TOKEN_PROGRAM, ATA_PROGRAM, ata } from './program.ts';
import * as X from './xmrproof.ts';

export const IX15 = { SET_ATTESTERS: 31, ATTEST_HEADER: 32, PROVE_LOCK: 33, BURN_INIT: 34, BURN_TAKE: 35, POOL_STAKE: 36, POOL_UNSTAKE_REQUEST: 37, POOL_UNSTAKE: 38, POOL_CLAIM: 39, SPLIT_FEES: 40, DEPOSIT_STAKERS: 41 } as const;
export const POOL_LEN = 96;
export const STAKER_LEN = 104;
export const ATTESTERS_LEN = 248;
export const XHDR_LEN = 104;
export const XPROOF_LEN = 176;
export const BURN_LEN = 112;
export const HALF_LIFE_SECS = 3600;
export const MIN_XMR_CONF = 10;
export const MONERO_NET = { mainnet: 0, testnet: 1, stagenet: 2 } as const;
const ED25519 = new PublicKey('Ed25519SigVerify111111111111111111111111111');

const u64le = (v: bigint | number) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(v), true); return b; };
const i64le = (v: bigint | number) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigInt64(0, BigInt(v), true); return b; };
const u32le = (v: number) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, v, true); return b; };
const ro = (pubkey: PublicKey, isSigner = false) => ({ pubkey, isSigner, isWritable: false });
const rw = (pubkey: PublicKey, isSigner = false) => ({ pubkey, isSigner, isWritable: true });

export const pdaV15 = {
  attesters: (pid: PublicKey) => PublicKey.findProgramAddressSync([Buffer.from('attesters')], pid)[0],
  header: (pid: PublicKey, epoch: bigint, blockId: Uint8Array) => PublicKey.findProgramAddressSync([Buffer.from('xmrhdr'), u64le(epoch), blockId], pid)[0],
  /** The proof record of one escrow instance: seeded by the escrow, its lock time and its terms
   *  (proofTerms: both key halves and the view key), mirroring zkproof.rs. */
  proof: (pid: PublicKey, escrow: PublicKey, inst: ProofInstance) =>
    PublicKey.findProgramAddressSync([Buffer.from('xmrout'), escrow.toBytes(), i64le(inst.createdAt), proofTerms(inst)], pid)[0],
  /** $HALFKEY staking reward pool (also the address pump.fun fee sharing can pay into). */
  pool: (pid: PublicKey) => PublicKey.findProgramAddressSync([Buffer.from('stake_pool')], pid)[0],
  staker: (pid: PublicKey, owner: PublicKey) => PublicKey.findProgramAddressSync([Buffer.from('staker'), owner.toBytes()], pid)[0],
  stakeOwner: (pid: PublicKey, owner: PublicKey) => PublicKey.findProgramAddressSync([Buffer.from('stake'), owner.toBytes()], pid)[0],
};

/** What a proof record is bound to: the escrow's lock time and its keys (a decoded EscrowAccount fits). */
export interface ProofInstance { createdAt: bigint | number; claimPoint: Uint8Array; refundPoint: Uint8Array; viewPub: Uint8Array; flags?: number }
/** sha256("halfkey-proof-terms-v1" || claim_point || refund_point || view_pub), zkproof::proof_terms. */
/** A direct-payout escrow (flags & 16, final round) appends one byte 16, so its record has its own seeds. */
export function proofTerms(e: Pick<ProofInstance, 'claimPoint' | 'refundPoint' | 'viewPub' | 'flags'>): Uint8Array {
  const direct = ((e.flags ?? 0) & 16) ? Uint8Array.of(16) : new Uint8Array(0);
  return sha256(concatBytes(utf8ToBytes('halfkey-proof-terms-v1'), e.claimPoint, e.refundPoint, e.viewPub, direct));
}

// ---------------------------------------------------------------- decoders
const dv = (d: Uint8Array) => new DataView(d.buffer, d.byteOffset, d.byteLength);
export interface AttestersAccount { net: number; threshold: number; n: number; epoch: bigint; minConf: number; keys: PublicKey[] }
export function decodeAttesters(d: Uint8Array): AttestersAccount {
  if (d.length !== ATTESTERS_LEN || d[0] !== 0xae) throw new Error('not an attesters account');
  const v = dv(d); const n = d[5];
  return { net: d[3], threshold: d[4], n, epoch: v.getBigUint64(8, true), minConf: v.getUint32(16, true),
    keys: Array.from({ length: n }, (_, i) => new PublicKey(d.slice(24 + 32 * i, 56 + 32 * i))) };
}
export interface HeaderAccount { net: number; epoch: bigint; height: bigint; confirmations: number; attestedAt: bigint; blockId: Uint8Array; payer: PublicKey }
export function decodeHeader(d: Uint8Array): HeaderAccount {
  if (d.length !== XHDR_LEN || d[0] !== 0x8d) throw new Error('not a header account');
  const v = dv(d);
  return { net: d[3], epoch: v.getBigUint64(8, true), height: v.getBigUint64(16, true), confirmations: v.getUint32(24, true),
    attestedAt: v.getBigInt64(32, true), blockId: d.slice(40, 72), payer: new PublicKey(d.slice(72, 104)) };
}
export interface ProofAccount { address?: PublicKey; kind: number; outIndex: number; escrow: PublicKey; escrowCreated: bigint; amount: bigint; provenAt: bigint; height: bigint; epoch: bigint; txid: Uint8Array; blockId: Uint8Array; outKey: Uint8Array }
export function decodeProof(d: Uint8Array, address?: PublicKey): ProofAccount {
  if (d.length !== XPROOF_LEN || d[0] !== 0x9f) throw new Error('not a proof account');
  const v = dv(d);
  return { address, kind: d[3], outIndex: d[4], escrow: new PublicKey(d.slice(8, 40)), escrowCreated: v.getBigInt64(40, true), amount: v.getBigUint64(48, true), provenAt: v.getBigInt64(56, true),
    height: v.getBigUint64(64, true), epoch: v.getBigUint64(72, true), txid: d.slice(80, 112), blockId: d.slice(112, 144), outKey: d.slice(144, 176) };
}
/** The proof record of an escrow, if any (one getProgramAccounts call, filtered on the escrow). */
/** The proof record of an escrow. With `inst` (the decoded escrow) it reads that instance's own
 *  record, so a record of an earlier escrow at a reused address is never shown for this one. */
export async function findProof(c: Connection, pid: PublicKey, escrow: PublicKey, inst?: ProofInstance): Promise<ProofAccount | null> {
  if (inst) {
    const k = pdaV15.proof(pid, escrow, inst);
    const a = await c.getAccountInfo(k, 'confirmed');
    return a ? decodeProof(a.data, k) : null;
  }
  const r = await c.getProgramAccounts(pid, { filters: [{ dataSize: XPROOF_LEN }, { memcmp: { offset: 8, bytes: escrow.toBase58() } }] });
  return r.length ? decodeProof(r[0].account.data, r[0].pubkey) : null;
}
export interface BurnAccount { mint: PublicKey; startPrice: bigint; floorPrice: bigint; maxLot: bigint; startAt: bigint; takes: bigint; totalBurned: bigint; totalLamports: bigint; lastPrice: bigint; pot: bigint }
/** The fee vault once the burn auction is on (null while it is a plain account). */
export function decodeBurn(d: Uint8Array): BurnAccount | null {
  if (d.length === 0) return null;
  if (d.length !== BURN_LEN || d[0] !== 0xb0) throw new Error('not a burn auction');
  const v = dv(d); const q = (o: number) => v.getBigUint64(o, true);
  return { mint: new PublicKey(d.slice(8, 40)), startPrice: q(40), floorPrice: q(48), maxLot: q(56), startAt: v.getBigInt64(64, true),
    takes: q(72), totalBurned: q(80), totalLamports: q(88), lastPrice: q(96), pot: q(104) };
}

// ---------------------------------------------------------------- burn auction math (mirror of burn.rs)
export function burnPriceAt(start: bigint, floor: bigint, startAt: bigint, t: bigint): bigint {
  const el = t > startAt ? t - startAt : 0n;
  const k = el / BigInt(HALF_LIFE_SECS);
  const p = k >= 64n ? 0n : start >> k;
  const drop = (p / 2n) * (el % BigInt(HALF_LIFE_SECS)) / BigInt(HALF_LIFE_SECS);
  const q = p - drop;
  return q > floor ? q : floor;
}
export const burnCost = (price: bigint, lot: bigint) => (price * lot + 999_999_999n) / 1_000_000_000n;
/** What a take would move right now. */
export function burnQuote(b: BurnAccount, vaultLamports: bigint, rentKeep: bigint, now: bigint) {
  const free = vaultLamports > rentKeep ? vaultLamports - rentKeep : 0n;
  let lot = free < b.maxLot ? free : b.maxLot;
  if (b.pot < lot) lot = b.pot; // the auction sells only the burn pot (run split_fees first)
  const price = burnPriceAt(b.startPrice, b.floorPrice, b.startAt, now);
  return { lot, price, burn: burnCost(price, lot) };
}

// ---------------------------------------------------------------- attestation
export function headerMessage(net: number, height: bigint | number, blockId: Uint8Array, confirmations: number): Uint8Array {
  if (blockId.length !== 32) throw new Error('block id must be 32 bytes');
  return concatBytes(utf8ToBytes('halfkey-xmr-header-v1'), Uint8Array.of(net), u64le(height), blockId, u32le(confirmations));
}
export interface Attestation { pubkey: Uint8Array; signature: Uint8Array }
/** One Ed25519 precompile instruction carrying several signatures over one message (all inline). */
export function ixEd25519Multi(message: Uint8Array, sigs: Attestation[]) {
  const n = sigs.length;
  const head = 2 + 14 * n;
  const body: Uint8Array[] = [];
  const table = new Uint8Array(14 * n);
  const tv = new DataView(table.buffer);
  let off = head;
  const msgOff = head + 96 * n;
  sigs.forEach((s, i) => {
    tv.setUint16(14 * i, off + 32, true); tv.setUint16(14 * i + 2, 0xffff, true);
    tv.setUint16(14 * i + 4, off, true); tv.setUint16(14 * i + 6, 0xffff, true);
    tv.setUint16(14 * i + 8, msgOff, true); tv.setUint16(14 * i + 10, message.length, true); tv.setUint16(14 * i + 12, 0xffff, true);
    body.push(s.pubkey, s.signature);
    off += 96;
  });
  return new TransactionInstruction({ programId: ED25519, keys: [], data: Buffer.from(concatBytes(Uint8Array.of(n, 0), table, ...body, message)) });
}
/** An attester's signature (the attester service does this after its own two-node check). */
export const signHeader = (secret32: Uint8Array, msg: Uint8Array): Attestation => ({ pubkey: ed25519.getPublicKey(secret32), signature: ed25519.sign(msg, secret32) });

// ---------------------------------------------------------------- instructions
export function ixSetAttesters(pid: PublicKey, admin: PublicKey, net: number, threshold: number, minConf: number, keys: PublicKey[]) {
  return new TransactionInstruction({
    programId: pid,
    keys: [rw(admin, true), ro(pda.config(pid)), rw(pdaV15.attesters(pid)), ro(SystemProgram.programId)],
    data: Buffer.from(concatBytes(Uint8Array.of(IX15.SET_ATTESTERS, net, threshold), u32le(minConf), Uint8Array.of(keys.length), ...keys.map((k) => k.toBytes()))),
  });
}
/** [Ed25519 multi-sig precompile, attest_header]: send both in one transaction, in this order. */
export function ixsAttestHeader(pid: PublicKey, payer: PublicKey, epoch: bigint, net: number, height: number, blockId: Uint8Array, confirmations: number, sigs: Attestation[]) {
  const msg = headerMessage(net, height, blockId, confirmations);
  return [
    ixEd25519Multi(msg, sigs),
    new TransactionInstruction({
      programId: pid,
      keys: [rw(payer, true), ro(pdaV15.attesters(pid)), rw(pdaV15.header(pid, epoch, blockId)), ro(SystemProgram.programId), ro(SYSVAR_INSTRUCTIONS_PUBKEY)],
      data: Buffer.from(concatBytes(Uint8Array.of(IX15.ATTEST_HEADER), u64le(height), blockId, u32le(confirmations))),
    }),
  ];
}
export function ixProveLock(pid: PublicKey, payer: PublicKey, escrow: PublicKey, inst: ProofInstance, epoch: bigint, a: X.ProveArgs) {
  return new TransactionInstruction({
    programId: pid,
    keys: [rw(payer, true), ro(escrow), ro(pdaV15.attesters(pid)), ro(pdaV15.header(pid, epoch, a.blockId)), rw(pdaV15.proof(pid, escrow, inst)), ro(SystemProgram.programId)],
    data: Buffer.from(concatBytes(Uint8Array.of(IX15.PROVE_LOCK), X.encodeProve(a))),
  });
}
export function ixBurnInit(pid: PublicKey, admin: PublicKey, mint: PublicKey, startPrice: bigint, floorPrice: bigint, maxLot: bigint) {
  return new TransactionInstruction({
    programId: pid,
    keys: [rw(admin, true), ro(pda.config(pid)), rw(pda.feeVault(pid)), ro(mint), ro(SystemProgram.programId), ro(pdaV15.pool(pid))],
    data: Buffer.from(concatBytes(Uint8Array.of(IX15.BURN_INIT), u64le(startPrice), u64le(floorPrice), u64le(maxLot))),
  });
}
export function ixBurnTake(pid: PublicKey, buyer: PublicKey, mint: PublicKey, source: PublicKey, maxBurn: bigint, minLamports: bigint, tokenProgram = TOKEN_PROGRAM) {
  return new TransactionInstruction({
    programId: pid,
    keys: [rw(buyer, true), ro(pda.config(pid)), rw(pda.feeVault(pid)), rw(mint), rw(source), ro(tokenProgram)],
    data: Buffer.from(concatBytes(Uint8Array.of(IX15.BURN_TAKE), u64le(maxBurn), u64le(minLamports))),
  });
}

// ---------------------------------------------------------------- $HALFKEY staking (program/src/rewards.rs)
export interface PoolAccount { mint: PublicKey; totalStaked: bigint; acc: bigint; distributed: bigint; claimed: bigint }
export function decodePool(d: Uint8Array): PoolAccount {
  if (d.length !== POOL_LEN || d[0] !== 0x5b) throw new Error('not a stake pool');
  const v = dv(d); const q = (o: number) => v.getBigUint64(o, true);
  return { mint: new PublicKey(d.slice(8, 40)), totalStaked: q(40), acc: q(48) | (q(56) << 64n), distributed: q(64), claimed: q(72) };
}
export interface StakerAccount { owner: PublicKey; staked: bigint; accAt: bigint; owed: bigint; unbonding: bigint; unlockAt: bigint }
export function decodeStaker(d: Uint8Array): StakerAccount {
  if (d.length !== STAKER_LEN || d[0] !== 0x5c) throw new Error('not a staker account');
  const v = dv(d); const q = (o: number) => v.getBigUint64(o, true);
  return { owner: new PublicKey(d.slice(8, 40)), staked: q(40), accAt: q(48) | (q(56) << 64n), owed: q(64), unbonding: q(72), unlockAt: v.getBigInt64(80, true) };
}
/** Settled rewards right now (what a claim pays before the next split), mirror of rewards.rs. */
export const settledRewards = (pool: PoolAccount, st: StakerAccount) => st.owed + ((st.staked * (pool.acc - st.accAt)) >> 64n);
/**
 * What a claim would pay now, including this staker's share of fees waiting in the fee vault
 * (half of the unsplit balance) and of loose SOL in the pool. Pass the live lamport balances.
 */
export function claimableRewards(pool: PoolAccount, st: StakerAccount, o: { vaultLamports: bigint; vaultKeep: bigint; burnPot: bigint; poolLamports: bigint; poolKeep: bigint; burnOn: boolean }) {
  if (pool.totalStaked === 0n) return st.owed;
  const sub = (a: bigint, b: bigint) => (a > b ? a - b : 0n);
  const unsplit = o.burnOn ? sub(sub(o.vaultLamports, o.vaultKeep), o.burnPot) : 0n;
  const extra = sub(sub(o.poolLamports, o.poolKeep), pool.distributed - pool.claimed);
  const inc = (((unsplit / 2n) + extra) << 64n) / pool.totalStaked;
  return settledRewards({ ...pool, acc: pool.acc + inc }, st);
}
export function ixPoolStake(pid: PublicKey, owner: PublicKey, mint: PublicKey, source: PublicKey, amount: bigint, tokenProgram = TOKEN_PROGRAM) {
  const so = pdaV15.stakeOwner(pid, owner);
  return new TransactionInstruction({
    programId: pid,
    keys: [rw(owner, true), ro(pda.config(pid)), ro(mint), rw(source), rw(ata(so, mint, tokenProgram)), ro(so), ro(tokenProgram), ro(ATA_PROGRAM),
      ro(SystemProgram.programId), rw(pdaV15.pool(pid)), rw(pdaV15.staker(pid, owner)), rw(pda.feeVault(pid)), rw(pda.maker(pid, owner))],
    data: Buffer.from(concatBytes(Uint8Array.of(IX15.POOL_STAKE), u64le(amount))),
  });
}
/** amount 0 = everything staked. It stops earning now and can be withdrawn after the unbond delay. */
export function ixPoolUnstakeRequest(pid: PublicKey, owner: PublicKey, amount = 0n) {
  return new TransactionInstruction({
    programId: pid,
    keys: [ro(owner, true), ro(pda.config(pid)), rw(pdaV15.pool(pid)), rw(pdaV15.staker(pid, owner)), rw(pda.feeVault(pid)), rw(pda.maker(pid, owner))],
    data: Buffer.from(concatBytes(Uint8Array.of(IX15.POOL_UNSTAKE_REQUEST), u64le(amount))),
  });
}
export function ixPoolUnstake(pid: PublicKey, owner: PublicKey, mint: PublicKey, dest: PublicKey, tokenProgram = TOKEN_PROGRAM) {
  const so = pdaV15.stakeOwner(pid, owner);
  return new TransactionInstruction({
    programId: pid,
    keys: [ro(owner, true), ro(pda.config(pid)), ro(mint), rw(dest), rw(ata(so, mint, tokenProgram)), ro(so), ro(tokenProgram), rw(pdaV15.staker(pid, owner)), rw(pda.maker(pid, owner)), ro(pdaV15.pool(pid))],
    data: Buffer.from([IX15.POOL_UNSTAKE]),
  });
}
/**
 * Pay all staking rewards to the owner's wallet. One instruction with no return value to read, so
 * a caller can put it first in a transaction and follow it with a swap lock of the same SOL
 * (e.g. claim -> SOL->XMR); quote the amount with `claimableRewards` before building the lock.
 */
export function ixPoolClaim(pid: PublicKey, owner: PublicKey) {
  return new TransactionInstruction({
    programId: pid,
    keys: [rw(owner, true), ro(pda.config(pid)), rw(pdaV15.pool(pid)), rw(pdaV15.staker(pid, owner)), rw(pda.feeVault(pid))],
    data: Buffer.from([IX15.POOL_CLAIM]),
  });
}
/** The permissionless crank: 50% of new fees to stakers, 50% to the burn pot. */
export function ixSplitFees(pid: PublicKey, who: PublicKey) {
  return new TransactionInstruction({ programId: pid, keys: [rw(who, true), ro(pda.config(pid)), rw(pda.feeVault(pid)), rw(pdaV15.pool(pid)), ro(SystemProgram.programId)], data: Buffer.from([IX15.SPLIT_FEES]) });
}
/** Outside SOL straight to the stakers (all of it; nothing to the burn). */
export function ixDepositStakers(pid: PublicKey, payer: PublicKey, lamports: bigint) {
  return new TransactionInstruction({
    programId: pid,
    keys: [rw(payer, true), ro(pda.config(pid)), rw(pda.feeVault(pid)), rw(pdaV15.pool(pid)), ro(SystemProgram.programId)],
    data: Buffer.from(concatBytes(Uint8Array.of(IX15.DEPOSIT_STAKERS), u64le(lamports))),
  });
}
