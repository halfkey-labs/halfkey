// HALFKEY EVM chain adapter (HyperEVM first; any EVM chain with the same contract).
// Sits beside the Solana adapter (sdk/program.ts + sdk/taker.ts) and reuses the chain-agnostic
// layer unchanged: sdk/keys.ts (key split, Monero addresses), sdk/xmrverify.ts, sdk/collect.ts.
// No new dependencies: ABI, EIP-712, RLP and secp256k1 signing are done with @noble (already used).
import { secp256k1 } from '@noble/curves/secp256k1';
import { ed25519 } from '@noble/curves/ed25519';
import { keccak_256 } from '@noble/hashes/sha3';
import { sha512 } from '@noble/hashes/sha512';
import { bytesToHex, hexToBytes, concatBytes, utf8ToBytes } from '@noble/hashes/utils';
import * as K from './keys.ts';

// ---------------------------------------------------------------- constants
export const NATIVE = '0x0000000000000000000000000000000000000000';
export const DIR = { TO_XMR: 1, FROM_XMR: 2 } as const;
export const ST = { LOCKED: 1, READY: 2, ABORTED: 3, CLAIMED: 4, REFUNDED: 5 } as const;
export const ST_NAME: Record<number, string> = { 0: 'None', 1: 'Locked', 2: 'Ready', 3: 'Aborted', 4: 'Claimed', 5: 'Refunded' };

/** Known deployments of the asset contracts (the escrow address is per deployment). */
export const CHAINS = {
  hyperevm: { chainId: 999, rpc: 'https://rpc.hyperliquid.xyz/evm', usdc: '0xb88339CB7199b77E23DB6E890353E22632Ba630f', coreDepositWallet: '0x6B9E773128f453f5c2C60935Ee2DE2CBc5390A24' },
  'hyperevm-testnet': { chainId: 998, rpc: 'https://rpc.hyperliquid-testnet.xyz/evm', usdc: '0x2B3370eE501B4a559b57D449569354196457D8Ab', coreDepositWallet: '0x0B80659a4076E9E93C7DbE0f10675A16a3e5C206' },
} as const;

// ---------------------------------------------------------------- bytes
export type Hex = `0x${string}`;
export const hx = (b: Uint8Array): Hex => `0x${bytesToHex(b)}`;
export const unhx = (h: string): Uint8Array => { const s = h.replace(/^0x/, ''); return hexToBytes(s.length % 2 ? '0' + s : s); };
export const keccak = (b: Uint8Array) => keccak_256(b);
const W = 32;

function word(n: bigint): Uint8Array {
  if (n < 0n || n >= 1n << 256n) throw new Error('uint out of range');
  const b = new Uint8Array(W);
  for (let i = W - 1; i >= 0; i--) { b[i] = Number(n & 0xffn); n >>= 8n; }
  return b;
}
const toBig = (b: Uint8Array) => { let n = 0n; for (const x of b) n = (n << 8n) | BigInt(x); return n; };
export function checksum(addr: string): Hex {
  const a = addr.toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{40}$/.test(a)) throw new Error(`bad address ${addr}`);
  const h = bytesToHex(keccak_256(utf8ToBytes(a)));
  let out = '0x';
  for (let i = 0; i < 40; i++) out += parseInt(h[i], 16) >= 8 ? a[i].toUpperCase() : a[i];
  return out as Hex;
}
export const sameAddr = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

// ---------------------------------------------------------------- ABI (the subset HALFKEY needs)
type T = 'address' | 'uint' | 'bool' | 'bytes32' | 'bytes' | 'string' | { tuple: T[] } | { fixed: [T, number] };
const isDyn = (t: T): boolean => t === 'bytes' || t === 'string' || (typeof t === 'object' && 'tuple' in t && t.tuple.some(isDyn)) || (typeof t === 'object' && 'fixed' in t && isDyn(t.fixed[0]));

function encodeOne(t: T, v: any): Uint8Array {
  if (t === 'address') return word(BigInt(checksum(String(v))));
  if (t === 'uint') return word(BigInt(v));
  if (t === 'bool') return word(v ? 1n : 0n);
  if (t === 'bytes32') { const b = typeof v === 'string' ? unhx(v) : v as Uint8Array; if (b.length !== 32) throw new Error('bytes32'); return b; }
  if (t === 'bytes' || t === 'string') {
    const b = t === 'string' ? utf8ToBytes(String(v)) : (typeof v === 'string' ? unhx(v) : v as Uint8Array);
    const pad = new Uint8Array(Math.ceil(b.length / W) * W); pad.set(b);
    return concatBytes(word(BigInt(b.length)), pad);
  }
  if ('tuple' in t) return encode(t.tuple, v);
  return encode(Array(t.fixed[1]).fill(t.fixed[0]), v);
}

/** Standard head/tail ABI encoding. */
export function encode(types: T[], values: any[]): Uint8Array {
  const heads: Uint8Array[] = [], tails: Uint8Array[] = [];
  let headLen = 0;
  for (const t of types) headLen += isDyn(t) ? W : (typeof t === 'object' && 'tuple' in t ? t.tuple.length * W : typeof t === 'object' && 'fixed' in t ? t.fixed[1] * W : W);
  let tailLen = 0;
  types.forEach((t, i) => {
    const enc = encodeOne(t, values[i]);
    if (isDyn(t)) { heads.push(word(BigInt(headLen + tailLen))); tails.push(enc); tailLen += enc.length; }
    else heads.push(enc);
  });
  return concatBytes(...heads, ...tails);
}

export const selector = (sig: string) => keccak_256(utf8ToBytes(sig)).slice(0, 4);
export const calldata = (sig: string, types: T[], values: any[]) => hx(concatBytes(selector(sig), encode(types, values)));

/** Read 32-byte words. */
export function words(data: string | Uint8Array): Uint8Array[] {
  const b = typeof data === 'string' ? unhx(data) : data;
  const out: Uint8Array[] = [];
  for (let i = 0; i + W <= b.length; i += W) out.push(b.slice(i, i + W));
  return out;
}
const wAddr = (w: Uint8Array) => checksum(bytesToHex(w.slice(12)));
const wNum = (w: Uint8Array) => toBig(w);
const wHex = (w: Uint8Array) => hx(w);

// ---------------------------------------------------------------- the contract interface
const LOCK_TUPLE: T = { tuple: ['bytes32', 'address', 'uint', 'address', 'uint', 'uint', 'bytes32', 'bytes32', 'bytes32', 'bytes32', 'uint', 'uint', 'address', 'address', 'uint'] };
const LOCK_SIG = 'lock((bytes32,address,uint8,address,uint128,uint64,bytes32,bytes32,bytes32,bytes32,uint32,uint32,address,address,uint64),bytes32[3],bytes)';
const PARAMS_SIG = '(address,address,uint16,uint16,uint32,uint32,uint32,uint32,uint32,uint128,uint128)';

export interface LockArgs {
  swapId: Uint8Array; claimer: string; direction: 1 | 2; asset: string; amount: bigint; xmrAmount: bigint;
  claimPoint: Uint8Array; refundPoint: Uint8Array; viewPub: Uint8Array; quoteHash: Uint8Array;
  t0Secs: number; windowSecs: number; watchtowers: string[]; consentExpiry: number;
}
const lockTuple = (a: LockArgs) => [a.swapId, a.claimer, a.direction, a.asset, a.amount, a.xmrAmount, a.claimPoint, a.refundPoint, a.viewPub, a.quoteHash, a.t0Secs, a.windowSecs, a.watchtowers[0] ?? NATIVE, a.watchtowers[1] ?? NATIVE, a.consentExpiry];

export interface Params {
  feeRecipient: Hex; bondToken: Hex; feeBps: number; holderFeeBps: number; minT0: number; maxT0: number;
  minWindow: number; maxWindow: number; unbondSecs: number; holderMin: bigint; minBond: bigint;
}
const paramsTuple = (p: Params) => [p.feeRecipient, p.bondToken, p.feeBps, p.holderFeeBps, p.minT0, p.maxT0, p.minWindow, p.maxWindow, p.unbondSecs, p.holderMin, p.minBond];
const PARAMS_T: T = { tuple: ['address', 'address', 'uint', 'uint', 'uint', 'uint', 'uint', 'uint', 'uint', 'uint', 'uint'] };

export const ix = {
  lock: (a: LockArgs, witnesses: Uint8Array[], consentSig: Uint8Array | string) => calldata(LOCK_SIG, [LOCK_TUPLE, { fixed: ['bytes32', 3] }, 'bytes'], [lockTuple(a), witnesses, consentSig]),
  ready: (key: string) => calldata('ready(bytes32)', ['bytes32'], [key]),
  abort: (key: string) => calldata('abort(bytes32)', ['bytes32'], [key]),
  claim: (key: string, secret: Uint8Array) => calldata('claim(bytes32,bytes32)', ['bytes32', 'bytes32'], [key, secret]),
  claimWithSig: (key: string, secret: Uint8Array, relayer: string, fee: bigint, deadline: number, sig: Uint8Array | string) =>
    calldata('claimWithSig(bytes32,bytes32,address,uint128,uint64,bytes)', ['bytes32', 'bytes32', 'address', 'uint', 'uint', 'bytes'], [key, secret, relayer, fee, deadline, sig]),
  refund: (key: string, secret: Uint8Array) => calldata('refund(bytes32,bytes32)', ['bytes32', 'bytes32'], [key, secret]),
  expire: (key: string) => calldata('expire(bytes32)', ['bytes32'], [key]),
  withdrawOwed: (asset: string) => calldata('withdrawOwed(address)', ['address'], [asset]),
  withdrawOwedTo: (asset: string, to: string) => calldata('withdrawOwedTo(address,address)', ['address', 'address'], [asset, to]),
  sweepFees: (asset: string) => calldata('sweepFees(address)', ['address'], [asset]),
  registerMaker: (directions: number, spreadBps: number, endpoint: string) => calldata('registerMaker(uint8,uint16,string)', ['uint', 'uint', 'string'], [directions, spreadBps, endpoint]),
  updateMaker: (directions: number, spreadBps: number, active: boolean, endpoint: string) => calldata('updateMaker(uint8,uint16,bool,string)', ['uint', 'uint', 'bool', 'string'], [directions, spreadBps, active, endpoint]),
  setMakerLimits: (asset: string, min: bigint, max: bigint) => calldata('setMakerLimits(address,uint128,uint128)', ['address', 'uint', 'uint'], [asset, min, max]),
  requestUnbond: () => calldata('requestUnbond()', [], []),
  withdrawMaker: () => calldata('withdrawMaker()', [], []),
  setAsset: (asset: string, enabled: boolean, maxSwap: bigint, maxOpenTvl: bigint) => calldata('setAsset(address,bool,uint128,uint128)', ['address', 'bool', 'uint', 'uint'], [asset, enabled, maxSwap, maxOpenTvl]),
  setParams: (p: Params, paused: boolean) => calldata(`setParams(${PARAMS_SIG},bool)`, [PARAMS_T, 'bool'], [paramsTuple(p), paused]),
  // views
  getEscrow: (key: string) => calldata('getEscrow(bytes32)', ['bytes32'], [key]),
  getMaker: (a: string) => calldata('getMaker(address)', ['address'], [a]),
  params: () => calldata('params()', [], []),
  assets: (a: string) => calldata('assets(address)', ['address'], [a]),
  effectiveFeeBps: (a: string) => calldata('effectiveFeeBps(address)', ['address'], [a]),
  makerLimits: (m: string, a: string) => calldata('makerLimits(address,address)', ['address', 'address'], [m, a]),
  swapsOfLength: (a: string) => calldata('swapsOfLength(address)', ['address'], [a]),
  swapsOf: (a: string, start: number, count: number) => calldata('swapsOf(address,uint256,uint256)', ['address', 'uint', 'uint'], [a, start, count]),
  owed: (who: string, asset: string) => calldata('owed(address,address)', ['address', 'address'], [who, asset]),
  paused: () => calldata('paused()', [], []),
  // ERC20
  erc20Approve: (spender: string, amt: bigint) => calldata('approve(address,uint256)', ['address', 'uint'], [spender, amt]),
  erc20BalanceOf: (a: string) => calldata('balanceOf(address)', ['address'], [a]),
  erc20Allowance: (o: string, s: string) => calldata('allowance(address,address)', ['address', 'address'], [o, s]),
};

/** Deployment calldata: creation bytecode + abi.encode(admin, Params). */
export const deployData = (bytecode: string, admin: string, p: Params) => hx(concatBytes(unhx(bytecode), encode(['address', PARAMS_T], [admin, paramsTuple(p)])));

export const escrowKey = (locker: string, swapId: Uint8Array): Hex => hx(keccak_256(encode(['address', 'bytes32'], [locker, swapId])));

// ---------------------------------------------------------------- decoders
export interface Escrow {
  key: Hex; state: number; direction: number; released: boolean; feeBps: number; createdAt: bigint; t0: bigint; t1: bigint; settledAt: bigint;
  asset: Hex; locker: Hex; claimer: Hex; maker: Hex; amount: bigint; xmrAmount: bigint; swapId: Uint8Array;
  claimPoint: Uint8Array; refundPoint: Uint8Array; viewPub: Uint8Array; quoteHash: Uint8Array; watchtowers: Hex[]; secret: Uint8Array;
}
export function decodeEscrow(key: string, data: string): Escrow {
  const w = words(data);
  return {
    key: key as Hex, state: Number(wNum(w[0])), direction: Number(wNum(w[1])), released: wNum(w[2]) === 1n, feeBps: Number(wNum(w[3])),
    createdAt: wNum(w[4]), t0: wNum(w[5]), t1: wNum(w[6]), settledAt: wNum(w[7]), asset: wAddr(w[8]), locker: wAddr(w[9]), claimer: wAddr(w[10]),
    maker: wAddr(w[11]), amount: wNum(w[12]), xmrAmount: wNum(w[13]), swapId: w[14], claimPoint: w[15], refundPoint: w[16], viewPub: w[17],
    quoteHash: w[18], watchtowers: [wAddr(w[19]), wAddr(w[20])], secret: w[21],
  };
}
export interface Maker {
  registered: boolean; active: boolean; directions: number; spreadBps: number; openSwaps: number; createdAt: bigint; withdrawAfter: bigint;
  stakeUnlockAt: bigint; bond: bigint; staked: bigint; stakeToken: Hex; completed: bigint; aborted: bigint; expired: bigint; cancelled: bigint; declined: bigint; endpoint: string;
}
export function decodeMaker(data: string): Maker {
  const b = unhx(data);
  const base = Number(toBig(b.slice(0, 32)));
  const w = words(b.slice(base));
  const eoff = base + Number(wNum(w[16]));
  const elen = Number(toBig(b.slice(eoff, eoff + 32)));
  return {
    registered: wNum(w[0]) === 1n, active: wNum(w[1]) === 1n, directions: Number(wNum(w[2])), spreadBps: Number(wNum(w[3])), openSwaps: Number(wNum(w[4])),
    createdAt: wNum(w[5]), withdrawAfter: wNum(w[6]), stakeUnlockAt: wNum(w[7]), bond: wNum(w[8]), staked: wNum(w[9]), stakeToken: wAddr(w[10]),
    completed: wNum(w[11]), aborted: wNum(w[12]), expired: wNum(w[13]), cancelled: wNum(w[14]), declined: wNum(w[15]),
    endpoint: new TextDecoder().decode(b.slice(eoff + 32, eoff + 32 + elen)),
  };
}
export function decodeParams(data: string): Params {
  const w = words(data);
  return {
    feeRecipient: wAddr(w[0]), bondToken: wAddr(w[1]), feeBps: Number(wNum(w[2])), holderFeeBps: Number(wNum(w[3])), minT0: Number(wNum(w[4])),
    maxT0: Number(wNum(w[5])), minWindow: Number(wNum(w[6])), maxWindow: Number(wNum(w[7])), unbondSecs: Number(wNum(w[8])), holderMin: wNum(w[9]), minBond: wNum(w[10]),
  };
}
export interface AssetInfo { enabled: boolean; maxSwap: bigint; maxOpenTvl: bigint; openTvl: bigint; accruedFees: bigint; totalVolume: bigint; totalSwaps: bigint }
export function decodeAsset(data: string): AssetInfo {
  const w = words(data);
  return { enabled: wNum(w[0]) === 1n, maxSwap: wNum(w[1]), maxOpenTvl: wNum(w[2]), openTvl: wNum(w[3]), accruedFees: wNum(w[4]), totalVolume: wNum(w[5]), totalSwaps: wNum(w[6]) };
}

/** Custom-error selectors -> names (for readable failures). */
const ERRORS = ['Unauthorized', 'Paused', 'BadParam', 'NonCanonicalScalar', 'BadPoint', 'WrongSecret', 'BadState', 'TooEarly', 'TooLate', 'AmountOutOfRange', 'CapExceeded',
  'MakerInactive', 'DirectionUnsupported', 'OpenSwaps', 'BondLocked', 'BondTooSmall', 'NoConsent', 'StillStaked', 'AssetDisabled', 'BadValue', 'Exists', 'NotFound', 'TransferFailed', 'NoReady'];
const ERR_BY_SEL = new Map(ERRORS.map((e) => [bytesToHex(selector(`${e}()`)), e]));
export function errName(e: unknown): string {
  const s = String((e as any)?.data ?? (e as any)?.message ?? e);
  const m = s.match(/0x([0-9a-f]{8})/i);
  if (m && ERR_BY_SEL.has(m[1].toLowerCase())) return ERR_BY_SEL.get(m[1].toLowerCase())!;
  return s.slice(0, 300);
}

// ---------------------------------------------------------------- EIP-712
const typeHash = (s: string) => keccak_256(utf8ToBytes(s));
const CONSENT_TYPE = 'Consent(address locker,address claimer,bytes32 swapId,uint8 direction,address asset,uint128 amount,uint64 xmrAmount,bytes32 claimPoint,bytes32 refundPoint,bytes32 viewPub,bytes32 quoteHash,uint32 t0Secs,uint32 windowSecs,uint64 expiry,uint16 feeBps)';
const CLAIM_TYPE = 'ClaimAuth(bytes32 key,address relayer,uint128 relayerFee,uint64 deadline)';
export function domainSeparator(chainId: number, contract: string): Uint8Array {
  return keccak_256(encode(['bytes32', 'bytes32', 'bytes32', 'uint', 'address'], [
    typeHash('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'), keccak_256(utf8ToBytes('HALFKEY')), keccak_256(utf8ToBytes('1')), chainId, contract,
  ]));
}
const typed = (ds: Uint8Array, structHash: Uint8Array) => keccak_256(concatBytes(Uint8Array.of(0x19, 0x01), ds, structHash));
export function consentDigest(chainId: number, contract: string, locker: string, a: LockArgs, feeBps: number): Uint8Array {
  const sh = keccak_256(encode(['bytes32', 'address', 'address', 'bytes32', 'uint', 'address', 'uint', 'uint', 'bytes32', 'bytes32', 'bytes32', 'bytes32', 'uint', 'uint', 'uint', 'uint'], [
    typeHash(CONSENT_TYPE), locker, a.claimer, a.swapId, a.direction, a.asset, a.amount, a.xmrAmount, a.claimPoint, a.refundPoint, a.viewPub, a.quoteHash, a.t0Secs, a.windowSecs, a.consentExpiry, feeBps,
  ]));
  return typed(domainSeparator(chainId, contract), sh);
}
export function claimAuthDigest(chainId: number, contract: string, key: string, relayer: string, fee: bigint, deadline: number): Uint8Array {
  return typed(domainSeparator(chainId, contract), keccak_256(encode(['bytes32', 'bytes32', 'address', 'uint', 'uint'], [typeHash(CLAIM_TYPE), key, relayer, fee, deadline])));
}
/** eth_signTypedData_v4 payload for browser wallets (same digest as consentDigest). */
export function consentTypedData(chainId: number, contract: string, locker: string, a: LockArgs, feeBps: number) {
  return {
    domain: { name: 'HALFKEY', version: '1', chainId, verifyingContract: checksum(contract) },
    primaryType: 'Consent',
    types: {
      EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' }, { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' }],
      Consent: CONSENT_TYPE.slice(8, -1).split(',').map((f) => { const [type, name] = f.split(' '); return { name, type }; }),
    },
    message: { locker: checksum(locker), claimer: checksum(a.claimer), swapId: hx(a.swapId), direction: a.direction, asset: checksum(a.asset), amount: a.amount.toString(), xmrAmount: a.xmrAmount.toString(), claimPoint: hx(a.claimPoint), refundPoint: hx(a.refundPoint), viewPub: hx(a.viewPub), quoteHash: hx(a.quoteHash), t0Secs: a.t0Secs, windowSecs: a.windowSecs, expiry: a.consentExpiry, feeBps },
  };
}
export function claimAuthTypedData(chainId: number, contract: string, key: string, relayer: string, fee: bigint, deadline: number) {
  return {
    domain: { name: 'HALFKEY', version: '1', chainId, verifyingContract: checksum(contract) },
    primaryType: 'ClaimAuth',
    types: {
      EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' }, { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' }],
      ClaimAuth: [{ name: 'key', type: 'bytes32' }, { name: 'relayer', type: 'address' }, { name: 'relayerFee', type: 'uint128' }, { name: 'deadline', type: 'uint64' }],
    },
    message: { key, relayer: checksum(relayer), relayerFee: fee.toString(), deadline },
  };
}

// ---------------------------------------------------------------- secp256k1
export const addressOf = (priv: Uint8Array): Hex => checksum(bytesToHex(keccak_256(secp256k1.getPublicKey(priv, false).slice(1)).slice(12)));
/** 65-byte r||s||v (v = 27/28), low-s (RFC 6979 deterministic). */
export function signDigest(priv: Uint8Array, digest: Uint8Array): Uint8Array {
  const s = secp256k1.sign(digest, priv, { lowS: true });
  return concatBytes(s.toCompactRawBytes(), Uint8Array.of(27 + s.recovery));
}
/** Recover the signer; null on malformed or high-s signatures (the contract rejects those too). */
export function recoverAddress(digest: Uint8Array, sig: Uint8Array): Hex | null {
  try {
    if (sig.length !== 65) return null;
    const v = sig[64] >= 27 ? sig[64] - 27 : sig[64];
    if (v > 1) return null;
    const S = secp256k1.Signature.fromCompact(sig.slice(0, 64));
    if (S.hasHighS()) return null;
    const pub = S.addRecoveryBit(v).recoverPublicKey(digest).toRawBytes(false);
    return checksum(bytesToHex(keccak_256(pub.slice(1)).slice(12)));
  } catch { return null; }
}
export const personalDigest = (msg: Uint8Array) => keccak_256(concatBytes(utf8ToBytes(`\x19Ethereum Signed Message:\n${msg.length}`), msg));

/**
 * Root for the user's key halves from an EVM wallet: SHA-512 over a domain tag and the 65-byte
 * personal_sign signature of keys.ts KEY_MESSAGE. Wallets sign with RFC 6979 (deterministic), and the
 * client signs twice and refuses a wallet whose signatures differ (K.checkDeterministic).
 * The tag keeps EVM roots apart from Solana roots even for the same human.
 */
export function rootFromEvmSignature(sig: Uint8Array): Uint8Array {
  if (sig.length !== 65) throw new Error('expected a 65-byte secp256k1 signature');
  return sha512(concatBytes(utf8ToBytes('halfkey/evm-root/v1'), sig));
}

// ---------------------------------------------------------------- ed25519 helpers for the contract
const INV8 = (() => { let r = 1n, b = 8n, e = K.L - 2n; while (e) { if (e & 1n) r = (r * b) % K.L; b = (b * b) % K.L; e >>= 1n; } return r; })();
/** Cofactor witness Q = 8^-1 * P (so 8*Q == P) that the contract checks at lock instead of l*P. */
export function witness(point: Uint8Array): Uint8Array {
  return ed25519.ExtendedPoint.fromHex(point).multiply(INV8).toRawBytes();
}

// ---------------------------------------------------------------- maker key proof (rogue-key fix)
// The maker answers the handshake after it has seen the user's half A. Without a proof it could
// answer M = t*G - A: the shared address M + A = t*G is then the maker's alone. XMR->HYPE: the user's
// deposit is stolen and the maker never needs to claim or refund. HYPE->XMR: the "lock" the user
// sees is still the maker's own money, and the maker could never claim either (no m) - a griefing
// lock. A Schnorr proof of knowledge of m (keys.ts proveKey/verifyKeyProof), bound to the chain,
// the escrow contract, the escrow key and A, rules both out. The tag keeps EVM contexts apart from
// Solana ones (keys.ts keyProofContext: 96 bytes, no tag).
const EVM_KP_TAG = utf8ToBytes('halfkey-evm-key-proof-ctx-v1');
export function evmKeyProofContext(chainId: number, contract: string, key: string, takerSpendPub: Uint8Array): Uint8Array {
  const k = unhx(key);
  if (k.length !== 32 || takerSpendPub.length !== 32) throw new Error('key proof context: bad length');
  return concatBytes(EVM_KP_TAG, word(BigInt(chainId)), unhx(checksum(contract)), k, takerSpendPub);
}
export const proveEvmKey = (m: Uint8Array, chainId: number, contract: string, key: string, takerSpendPub: Uint8Array) =>
  K.proveKey(m, evmKeyProofContext(chainId, contract, key, takerSpendPub));
export function verifyEvmKeyProof(M: Uint8Array, chainId: number, contract: string, key: string, takerSpendPub: Uint8Array, proof: Uint8Array | string | undefined): boolean {
  if (!proof) return false;
  const pr = typeof proof === 'string' ? (/^(0x)?[0-9a-fA-F]{128}$/.test(proof) ? unhx(proof) : new Uint8Array(0)) : proof;
  return K.verifyKeyProof(M, evmKeyProofContext(chainId, contract, key, takerSpendPub), pr);
}

// ---------------------------------------------------------------- JSON-RPC + signer
export class Rpc {
  url: string;
  private id = 0;
  constructor(url: string) { this.url = url; }
  async call<R = any>(method: string, params: unknown[] = []): Promise<R> {
    const r = await fetch(this.url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: ++this.id, method, params }, (_k, v) => (typeof v === 'bigint' ? '0x' + v.toString(16) : v)), signal: AbortSignal.timeout(30_000) });
    const j = await r.json() as any;
    if (j.error) { const e = new Error(`${method}: ${j.error.message} ${j.error.data ?? ''}`); (e as any).data = j.error.data; throw e; }
    return j.result as R;
  }
  chainId = async () => Number(await this.call('eth_chainId'));
  balance = async (a: string, tag = 'latest') => BigInt(await this.call('eth_getBalance', [a, tag]));
  ethCall = (to: string, data: string, tag = 'latest', from?: string) => this.call<string>('eth_call', [{ to, data, ...(from ? { from } : {}) }, tag]);
  async block(tag = 'latest'): Promise<{ number: bigint; timestamp: bigint; hash: string }> {
    const b = await this.call('eth_getBlockByNumber', [tag, false]);
    return { number: BigInt(b.number), timestamp: BigInt(b.timestamp), hash: b.hash };
  }
  async receipt(hash: string, timeoutMs = 120_000): Promise<any> {
    const end = Date.now() + timeoutMs;
    for (;;) {
      const r = await this.call('eth_getTransactionReceipt', [hash]).catch(() => null); // flaky RPCs: keep polling
      if (r) return r;
      if (Date.now() > end) throw new Error(`no receipt for ${hash}`);
      await new Promise((x) => setTimeout(x, 500));
    }
  }
}

function rlp(x: Uint8Array | Uint8Array[] | any[]): Uint8Array {
  if (x instanceof Uint8Array) {
    if (x.length === 1 && x[0] < 0x80) return x;
    return concatBytes(rlpLen(x.length, 0x80), x);
  }
  const body = concatBytes(...x.map((y) => rlp(y)));
  return concatBytes(rlpLen(body.length, 0xc0), body);
}
function rlpLen(n: number, off: number): Uint8Array {
  if (n < 56) return Uint8Array.of(off + n);
  const b: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) b.unshift(v & 0xff);
  return Uint8Array.of(off + 55 + b.length, ...b);
}
const rlpInt = (n: bigint) => { if (n === 0n) return new Uint8Array(0); let h = n.toString(16); if (h.length % 2) h = '0' + h; return hexToBytes(h); };

export interface TxFields { chainId: number; nonce: bigint; tip: bigint; maxFee: bigint; gas: bigint; to: string | null; value: bigint; data: string }
/** Sign an EIP-1559 transaction offline: the hash is known before anything is broadcast. */
export function signTx(priv: Uint8Array, f: TxFields): { raw: Hex; hash: Hex } {
  const fields = [rlpInt(BigInt(f.chainId)), rlpInt(f.nonce), rlpInt(f.tip), rlpInt(f.maxFee), rlpInt(f.gas), f.to ? unhx(f.to) : new Uint8Array(0), rlpInt(f.value), unhx(f.data), []];
  const unsigned = concatBytes(Uint8Array.of(2), rlp(fields));
  const sig = secp256k1.sign(keccak_256(unsigned), priv, { lowS: true });
  const raw = concatBytes(Uint8Array.of(2), rlp([...fields, rlpInt(BigInt(sig.recovery)), rlpInt(sig.r), rlpInt(sig.s)]));
  return { raw: hx(raw), hash: hx(keccak_256(raw)) };
}

/** Anything that can send a transaction: a local key (daemon, tests) or a browser wallet adapter. */
export interface EvmSigner {
  address: Hex;
  send(tx: { to: string | null; data: string; value?: bigint; gas?: bigint }): Promise<Hex>;
  signDigest?(digest: Uint8Array): Promise<Uint8Array>;
  signMessage(msg: Uint8Array): Promise<Uint8Array>;
}

/** A raw-key signer (EIP-1559 txs). Nonces are serialized per instance. */
export class LocalSigner implements EvmSigner {
  address: Hex;
  rpc: Rpc;
  chainId: number;
  private priv: Uint8Array;
  private chain: Promise<unknown> = Promise.resolve();
  constructor(rpc: Rpc, priv: Uint8Array | string, chainId: number) {
    this.rpc = rpc;
    this.chainId = chainId;
    this.priv = typeof priv === 'string' ? unhx(priv) : priv;
    this.address = addressOf(this.priv);
  }
  async signDigest(d: Uint8Array) { return signDigest(this.priv, d); }
  async signMessage(m: Uint8Array) { return signDigest(this.priv, personalDigest(m)); }
  send(tx: { to: string | null; data: string; value?: bigint; gas?: bigint }): Promise<Hex> {
    const run = this.chain.then(() => this.sendNow(tx), () => this.sendNow(tx));
    this.chain = run.catch(() => {});
    return run;
  }
  private async sendNow(tx: { to: string | null; data: string; value?: bigint; gas?: bigint }): Promise<Hex> {
    const value = tx.value ?? 0n;
    const callObj = { from: this.address, to: tx.to ?? undefined, data: tx.data, value };
    const gas = tx.gas ?? (BigInt(await this.rpc.call('eth_estimateGas', [callObj])) * 12n) / 10n;
    const [nonce, base, tip] = await Promise.all([
      this.rpc.call('eth_getTransactionCount', [this.address, 'pending']).then(BigInt),
      this.rpc.call('eth_getBlockByNumber', ['latest', false]).then((b) => BigInt(b.baseFeePerGas ?? '0x0')),
      this.rpc.call('eth_maxPriorityFeePerGas').then(BigInt).catch(() => 0n),
    ]);
    const maxFee = base * 2n + tip + 1n;
    const { raw } = signTx(this.priv, { chainId: this.chainId, nonce, tip, maxFee, gas, to: tx.to, value, data: tx.data });
    const hash = await this.rpc.call<Hex>('eth_sendRawTransaction', [raw]);
    const rc = await this.rpc.receipt(hash);
    if (rc.status !== '0x1') {
      // re-run as a call to surface the revert reason
      let why = 'reverted';
      try { await this.rpc.call('eth_call', [callObj, rc.blockNumber]); } catch (e) { why = errName(e); }
      const err = new Error(`tx ${hash} failed: ${why}`); (err as any).hash = hash; (err as any).reason = why; throw err;
    }
    return hash;
  }
}

// ---------------------------------------------------------------- contract client
export class Escrow712 {
  rpc: Rpc;
  address: Hex;
  chainId: number;
  constructor(rpc: Rpc, address: Hex, chainId: number) { this.rpc = rpc; this.address = address; this.chainId = chainId; }
  private async view(data: string, tag = 'latest') { return this.rpc.ethCall(this.address, data, tag); }
  getEscrow = async (key: string, tag = 'latest') => decodeEscrow(key, await this.view(ix.getEscrow(key), tag));
  getMaker = async (a: string) => decodeMaker(await this.view(ix.getMaker(a)));
  params = async () => decodeParams(await this.view(ix.params()));
  asset = async (a: string) => decodeAsset(await this.view(ix.assets(a)));
  effectiveFeeBps = async (a: string) => Number(BigInt(await this.view(ix.effectiveFeeBps(a))));
  makerLimits = async (m: string, a: string) => { const w = words(await this.view(ix.makerLimits(m, a))); return { min: wNum(w[0]), max: wNum(w[1]) }; };
  paused = async () => BigInt(await this.view(ix.paused())) === 1n;
  owed = async (who: string, asset: string) => BigInt(await this.view(ix.owed(who, asset)));
  async swapKeysOf(who: string): Promise<Hex[]> {
    const n = Number(BigInt(await this.view(ix.swapsOfLength(who))));
    const out: Hex[] = [];
    for (let i = 0; i < n; i += 100) {
      const w = words(await this.view(ix.swapsOf(who, i, 100)));
      const len = Number(wNum(w[1]));
      for (let k = 0; k < len; k++) out.push(wHex(w[2 + k]));
    }
    return out;
  }
  /** Chain time (seconds) at the given block tag. */
  now = async (tag = 'latest') => Number((await this.rpc.block(tag)).timestamp);
}

// ---------------------------------------------------------------- maker HTTP API (EVM, v1)
export interface EvmQuote {
  v: 1; chain: string; chainId: number; contract: string; maker: string; direction: 1 | 2;
  asset: string; amount: string; piconero: string; feeBps: number; expiresAt: number; nonce: string;
}
export function evmQuoteBytes(q: EvmQuote): Uint8Array {
  const c = { v: q.v, chain: q.chain, chainId: q.chainId, contract: q.contract.toLowerCase(), maker: q.maker.toLowerCase(), direction: q.direction, asset: q.asset.toLowerCase(), amount: q.amount, piconero: q.piconero, feeBps: q.feeBps, expiresAt: q.expiresAt, nonce: q.nonce };
  return utf8ToBytes('halfkey-evm-quote-v1:' + JSON.stringify(c));
}
export const evmQuoteHash = (q: EvmQuote) => keccak_256(evmQuoteBytes(q));
export const signEvmQuote = (q: EvmQuote, priv: Uint8Array) => hx(signDigest(priv, personalDigest(evmQuoteBytes(q))));
export const verifyEvmQuote = (q: EvmQuote, sig: string, maker: string) => { const a = recoverAddress(personalDigest(evmQuoteBytes(q)), unhx(sig)); return !!a && sameAddr(a, maker); };

export interface EvmMakerInfo {
  v: 1; chain: string; chainId: number; contract: string; maker: string; moneroNet: K.MoneroNet; directions: number;
  assets: { address: string; symbol: string; decimals: number; min: string; max: string; xmrPerUnit: number }[];
  spreadBps: number; feeBps: number; t0Secs: number; windowSecs: number; online: boolean;
  /** FROM_XMR deposit terms: confirmations before the maker's ready; it aborts at t0 - depositMarginSecs without them. */
  minConf?: number; depositMarginSecs?: number;
}
export interface EvmSwapRequest { quote: EvmQuote; sig: string; swapId: string; taker: string; takerSpendPub: string; viewSecret: string }
/** makerKeyProof: hex(64), verifyEvmKeyProof over (chainId, contract, escrow key, takerSpendPub). Required in both directions. */
export interface EvmSwapResponseToXmr { direction: 1; makerSpendPub: string; feeBps: number; sharedAddress: string; t0Secs: number; windowSecs: number; consentExpiry: number; consentSig: string; makerKeyProof: string }
export interface EvmSwapResponseFromXmr { direction: 2; makerSpendPub: string; sharedAddress: string; key: string; lockTx: string; makerKeyProof: string }

async function j<R>(r: Response): Promise<R> {
  const body = await r.text();
  if (!r.ok) throw new Error(`maker ${r.status}: ${body.slice(0, 200)}`);
  return JSON.parse(body) as R;
}
const base = (ep: string) => ep.replace(/\/+$/, '') + '/evm';
export const evmApi = {
  info: (ep: string) => fetch(`${base(ep)}/v1/info`).then((r) => j<EvmMakerInfo>(r)),
  quote: (ep: string, direction: 1 | 2, asset: string, amount: bigint) =>
    fetch(`${base(ep)}/v1/quote?direction=${direction}&asset=${asset}&${direction === 1 ? 'amount' : 'piconero'}=${amount}`).then((r) => j<{ quote: EvmQuote; sig: string }>(r)),
  swap: <R>(ep: string, req: EvmSwapRequest) => fetch(`${base(ep)}/v1/swap`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(req) }).then((r) => j<R>(r)),
  status: (ep: string, key: string) => fetch(`${base(ep)}/v1/swap/${key}`).then((r) => j<{ key: string; phase: string; xmrLockTx?: string; confirmations?: number; required?: number; note?: string; makerKeyProof?: string }>(r)),
  deposit: (ep: string, key: string, txHash: string) => fetch(`${base(ep)}/v1/swap/${key}/deposit`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ txHash }) }).then((r) => j<{ ok: true }>(r)),
  relayRefund: (ep: string, key: string, secretHex: string) => fetch(`${base(ep)}/v1/relay/refund`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ key, secret: secretHex }) }).then((r) => j<{ tx: string }>(r)),
};

// ---------------------------------------------------------------- taker (user) side
export interface Policy { minT0Secs: number; minWindowSecs: number; claimMarginSecs: number; minWatchtowers: number; maxT0Secs?: number; maxWindowSecs?: number }
/**
 * minWatchtowers: under the ready-only rule a watchtower only speeds up a refund (abort before t0);
 * the user's funds never depend on one, so none is required.
 * maxT0Secs / maxWindowSecs: how long a maker may park a FROM_XMR deposit / the claim window.
 */
export const MAINNET_POLICY: Policy = { minT0Secs: 40 * 60, minWindowSecs: 60 * 60, claimMarginSecs: 15 * 60, minWatchtowers: 0, maxT0Secs: 3 * 3600, maxWindowSecs: 6 * 3600 };

export function checkEvmQuote(sq: { quote: EvmQuote; sig: string }, maker: string, direction: 1 | 2, chainId: number, contract: string, p: Params, nowSecs: number): string | null {
  const q = sq.quote;
  if (q.v !== 1) return 'unknown quote version';
  if (!sameAddr(q.maker, maker)) return 'quote is from a different maker';
  if (q.chainId !== chainId || !sameAddr(q.contract, contract)) return 'quote is for another chain/contract';
  if (q.direction !== direction) return 'wrong direction';
  if (q.expiresAt < nowSecs + 5) return 'quote expired';
  if (q.feeBps !== p.feeBps && q.feeBps !== p.holderFeeBps) return 'quote fee does not match the contract';
  if (!verifyEvmQuote(q, sq.sig, maker)) return 'bad quote signature';
  if (BigInt(q.amount) <= 0n || BigInt(q.piconero) <= 0n) return 'empty quote';
  return null;
}

export interface PreparedEvmLock { key: Hex; lock: LockArgs; witnesses: Uint8Array[]; consentSig: Uint8Array; data: Hex; value: bigint; shared: ReturnType<typeof K.sharedWallet> }

/**
 * TO_XMR handshake + lock preparation. Verifies everything the maker returned before anything is
 * signed: key validity, shared address, fee tier, windows, and the maker's EIP-712 consent.
 */
export async function prepareToXmr(args: {
  esc: Escrow712; endpoint: string; maker: string; params: Params; policy: Policy; sq: { quote: EvmQuote; sig: string };
  swapId: Uint8Array; locker: string; half: K.KeyHalf; net: K.MoneroNet; watchtowers: string[]; nowSecs: number;
}): Promise<PreparedEvmLock> {
  const { esc, params: p, policy, sq, half } = args;
  const err = checkEvmQuote(sq, args.maker, 1, esc.chainId, esc.address, p, args.nowSecs);
  if (err) throw new Error(err);
  const res = await evmApi.swap<EvmSwapResponseToXmr>(args.endpoint, {
    quote: sq.quote, sig: sq.sig, swapId: K.toHex(args.swapId), taker: args.locker, takerSpendPub: K.toHex(half.spendPub), viewSecret: K.toHex(half.view),
  });
  if (res.direction !== 1) throw new Error('maker answered for the wrong direction');
  const makerSpendPub = K.fromHex(res.makerSpendPub);
  if (!K.isGoodPoint(makerSpendPub)) throw new Error('maker key is not a valid prime-order point');
  if (K.equalBytes(makerSpendPub, half.spendPub)) throw new Error('maker echoed our key');
  if (!K.isGoodPoint(K.pointAdd(makerSpendPub, half.spendPub))) throw new Error('maker key cancels ours (shared key would be unspendable)');
  const key = escrowKey(args.locker, args.swapId);
  if (!verifyEvmKeyProof(makerSpendPub, esc.chainId, esc.address, key, half.spendPub, res.makerKeyProof)) throw new Error('maker did not prove its key half (refusing to lock)');
  if (res.feeBps !== sq.quote.feeBps) throw new Error('maker changed the fee');
  if (res.feeBps !== p.feeBps && res.feeBps !== p.holderFeeBps) throw new Error('fee does not match the contract');
  if (res.t0Secs < Math.max(p.minT0, policy.minT0Secs) || res.t0Secs > p.maxT0) throw new Error('maker asked for an unsafe t0');
  if (res.windowSecs < Math.max(p.minWindow, policy.minWindowSecs) || res.windowSecs > p.maxWindow) throw new Error('maker asked for an unsafe window');
  if (res.consentExpiry < args.nowSecs || res.consentExpiry > args.nowSecs + 600) throw new Error('bad consent expiry');
  const shared = K.sharedWallet(makerSpendPub, half.spendPub, half.view, args.net);
  if (shared.address !== res.sharedAddress) throw new Error('shared address mismatch');
  if (args.watchtowers.length < policy.minWatchtowers) throw new Error(`need ${policy.minWatchtowers} watchtower(s) before locking`);
  const lock: LockArgs = {
    swapId: args.swapId, claimer: args.maker, direction: 1, asset: sq.quote.asset, amount: BigInt(sq.quote.amount), xmrAmount: BigInt(sq.quote.piconero),
    claimPoint: makerSpendPub, refundPoint: half.spendPub, viewPub: shared.viewPub, quoteHash: evmQuoteHash(sq.quote),
    t0Secs: res.t0Secs, windowSecs: res.windowSecs, watchtowers: args.watchtowers.slice(0, 2), consentExpiry: res.consentExpiry,
  };
  const consentSig = K.fromHex(res.consentSig.replace(/^0x/, ''));
  const signer = recoverAddress(consentDigest(esc.chainId, esc.address, args.locker, lock, res.feeBps), consentSig);
  if (!signer || !sameAddr(signer, args.maker)) throw new Error('maker consent signature does not verify');
  const witnesses = [witness(lock.claimPoint), witness(lock.refundPoint), witness(lock.viewPub)];
  return {
    key, lock, witnesses, consentSig, shared,
    data: ix.lock(lock, witnesses, consentSig), value: sameAddr(lock.asset, NATIVE) ? lock.amount : 0n,
  };
}

/**
 * FROM_XMR: before the user sends any XMR, the maker-locked escrow must match the deal exactly, and
 * the maker must have proven that it knows its key half (no deposit without makerKeyProof).
 * Read `e` at a final block of the contract the quote names.
 */
export function checkFromXmrEscrow(e: Escrow, a: { maker: string; sq: { quote: EvmQuote }; claimer: string; half: K.KeyHalf; makerSpendPub: Uint8Array; makerKeyProof: Uint8Array | string | undefined; policy: Policy; nowSecs: number }): void {
  const q = a.sq.quote;
  const bad = (m: string) => { throw new Error(`escrow does not match the deal: ${m}`); };
  if (e.direction !== 2) bad('direction');
  if (e.state !== ST.LOCKED) bad('state');
  if (!sameAddr(e.claimer, a.claimer)) bad('claimer');
  if (!sameAddr(e.locker, a.maker) || !sameAddr(e.maker, a.maker)) bad('maker');
  if (!sameAddr(e.asset, q.asset)) bad('asset');
  if (!K.equalBytes(e.claimPoint, a.half.spendPub)) bad('claim point');
  if (!K.equalBytes(e.refundPoint, a.makerSpendPub)) bad('refund point');
  if (!K.equalBytes(e.viewPub, a.half.viewPub)) bad('view key');
  if (e.amount < BigInt(q.amount)) bad('amount');
  if (e.xmrAmount !== BigInt(q.piconero)) bad('xmr amount');
  if (!K.equalBytes(e.quoteHash, evmQuoteHash(q))) bad('quote hash');
  if (e.feeBps !== q.feeBps) bad('fee');
  if (!K.isGoodPoint(K.pointAdd(a.makerSpendPub, a.half.spendPub))) bad('maker key cancels ours');
  if (!verifyEvmKeyProof(e.refundPoint, q.chainId, q.contract, e.key, a.half.spendPub, a.makerKeyProof)) bad('maker did not prove its key half (do not send XMR)');
  if (Number(e.t0) - a.nowSecs < a.policy.minT0Secs * 0.75) bad('too little time left to deposit');
  if (Number(e.t1 - e.t0) < a.policy.minWindowSecs) bad('claim window too short');
  if (Number(e.t0) - a.nowSecs > (a.policy.maxT0Secs ?? 3 * 3600)) bad('t0 too far away (the deposit would be parked too long)');
  if (Number(e.t1 - e.t0) > (a.policy.maxWindowSecs ?? 6 * 3600)) bad('claim window too long');
}

export type Phase = 'waiting-xmr' | 'refund-wait' | 'releasing' | 'collect' | 'refund' | 'refunded' | 'deposit' | 'claim' | 'xmr-back' | 'done';
export function phaseOf(e: Escrow, me: string, chainNow: number, policy: Policy): Phase {
  const iAmLocker = sameAddr(e.locker, me);
  const past = (t: bigint) => chainNow >= Number(t);
  if (e.direction === 1 && iAmLocker) {
    switch (e.state) {
      // Ready-only rule (HalfKeyEscrow v1.1): the maker can never claim without our `ready`, and
      // `ready` closes at t0. Locked past t0 = nothing can happen until the refund opens at t1.
      case ST.LOCKED: return past(e.t1) ? 'refund' : past(e.t0) ? 'refund-wait' : 'waiting-xmr';
      case ST.READY: return past(e.t1) ? 'refund' : 'releasing';
      case ST.CLAIMED: return 'collect';
      case ST.ABORTED: return 'refund';
      case ST.REFUNDED: return 'refunded';
    }
  }
  if (e.direction === 2 && !iAmLocker) {
    switch (e.state) {
      case ST.LOCKED: case ST.READY:
        if (chainNow >= Number(e.t1) - policy.claimMarginSecs) return 'xmr-back';
        return e.state === ST.READY || past(e.t0) ? 'claim' : 'deposit';
      case ST.CLAIMED: return 'done';
      case ST.ABORTED: case ST.REFUNDED: return 'xmr-back';
    }
  }
  return 'done';
}

/** The refund secret may leave the client only when no claim can ever happen again. */
export async function refundSafe(esc: Escrow712, key: string, tag = 'latest'): Promise<boolean> {
  const e = await esc.getEscrow(key, tag);
  if (e.state === ST.ABORTED) return true;
  if (e.state !== ST.LOCKED && e.state !== ST.READY) return false;
  return (await esc.now(tag)) >= Number(e.t1);
}

/** Every swap of this wallet (locker or claimer), newest first. Works from any device. */
export async function findMySwaps(esc: Escrow712, me: string): Promise<Escrow[]> {
  const keys = await esc.swapKeysOf(me);
  const all = await Promise.all([...new Set(keys)].map((k) => esc.getEscrow(k)));
  return all.sort((a, b) => Number(b.createdAt - a.createdAt));
}

export function myHalfFor(root: Uint8Array, e: Escrow, me: string): K.KeyHalf {
  const half = K.deriveHalf(root, e.swapId);
  const mine = e.direction === 1 && sameAddr(e.locker, me) ? e.refundPoint : e.claimPoint;
  if (!K.equalBytes(half.spendPub, mine)) throw new Error('this wallet did not create this swap (or signed a different key message)');
  if (!K.equalBytes(half.viewPub, e.viewPub)) throw new Error('view key mismatch');
  return half;
}

export function fullSpendKey(e: Escrow, half: K.KeyHalf): Uint8Array {
  if (e.state !== ST.CLAIMED && e.state !== ST.REFUNDED) throw new Error('other half not revealed yet');
  const s = K.scalarAdd(e.secret, half.spend);
  if (!K.equalBytes(K.pub(s), K.pointAdd(e.claimPoint, e.refundPoint))) throw new Error('revealed secret does not complete the key');
  return s;
}

export function restoreHeightFor(e: Escrow, daemonHeight: number, nowSecs: number): number {
  const ago = Math.max(0, nowSecs - Number(e.createdAt));
  return Math.max(1, daemonHeight - Math.ceil(ago / 120) - 60);
}
