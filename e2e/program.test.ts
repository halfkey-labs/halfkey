// HALFKEY program tests on a local solana-test-validator (run e2e/validator.sh first).
// Covers every instruction, every failure path, the timeout windows and the claim/refund race.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { Keypair, PublicKey, SystemProgram, TransactionInstruction, LAMPORTS_PER_SOL } from '@solana/web3.js';
import { ed25519 } from '@noble/curves/ed25519';
import * as P from '../sdk/program.ts';
import * as K from '../sdk/keys.ts';
import { conn, send, newFunded, loadKeypair, PROGRAM_ID as pid, chainTime, waitChainTime, sleep, transferIx } from './harness.ts';
import { ProofKit } from './proofkit.ts';

const c = conn();
const SOL = BigInt(LAMPORTS_PER_SOL);
const TOKEN = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');

let admin: Keypair, feeRecipient: Keypair, maker: Keypair, maker2: Keypair, user: Keypair, wt: Keypair, rando: Keypair;
let mint: Keypair;
/** v1.5: on-chain payment proofs for SOL->XMR claims without ready (e2e/proofkit.ts). */
let kit: ProofKit;
const cus: Record<string, number> = {};

const params = (o: Partial<P.ConfigParams> = {}): P.ConfigParams => ({
  feeRecipient: feeRecipient.publicKey,
  halfkeyMint: mint.publicKey,
  feeBps: 50,
  holderFeeBps: 25,
  holderMin: 1000n,
  minBond: 2n * SOL,
  maxSwap: 5n * SOL,
  maxOpenTvl: 40n * SOL,
  minT0: 1,
  maxT0: 3600,
  minWindow: 1,
  maxWindow: 7200,
  unbondSecs: 12,
  ...o,
});

const makerParams = (o: Partial<P.MakerParams> = {}): P.MakerParams => ({
  min: SOL / 100n, max: 5n * SOL, directions: 3, spreadBps: 100, endpoint: 'https://maker.example/api', ...o,
});

async function bal(k: PublicKey) { return BigInt(await c.getBalance(k, 'confirmed')); }
async function escrowOf(addr: PublicKey) { const a = await c.getAccountInfo(addr, 'confirmed'); return a ? P.decodeEscrow(a.data, addr) : null; }
async function makerOf(auth: PublicKey) { return P.decodeMaker((await c.getAccountInfo(P.pda.maker(pid, auth), 'confirmed'))!.data); }
async function configOf() { return P.decodeConfig((await c.getAccountInfo(P.pda.config(pid), 'confirmed'))!.data); }

interface Swap {
  locker: Keypair; claimer: Keypair; makerAuth: Keypair; swapId: Uint8Array; escrow: PublicKey;
  claimHalf: K.KeyHalf; refundHalf: K.KeyHalf; lock: P.LockParams; amount: bigint;
}

function buildSwap(o: { direction?: number; amount?: bigint; t0?: number; window?: number; watchtowers?: PublicKey[]; makerAuth?: Keypair; user?: Keypair } = {}): Swap {
  const direction = o.direction ?? 1;
  const makerAuth = o.makerAuth ?? maker;
  const u = o.user ?? user;
  const locker = direction === 1 ? u : makerAuth;
  const claimer = direction === 1 ? makerAuth : u;
  const swapId = K.newSwapId();
  const claimHalf = K.randomHalf();
  const refundHalf = K.randomHalf();
  const amount = o.amount ?? SOL / 2n;
  const shared = K.sharedWallet(claimHalf.spendPub, refundHalf.spendPub, refundHalf.view, 'stagenet');
  const lock: P.LockParams = {
    swapId, claimer: claimer.publicKey, direction, amount, xmrAmount: 123_456_789n,
    claimPoint: claimHalf.spendPub, refundPoint: refundHalf.spendPub, viewPub: shared.viewPub,
    quoteHash: new Uint8Array(32).fill(7), t0Secs: o.t0 ?? 3, windowSecs: o.window ?? 3,
    watchtowers: o.watchtowers ?? [wt.publicKey], makerAuthority: makerAuth.publicKey,
    consentExpiry: Math.floor(Date.now() / 1000) + 120, feeBps: 50,
  };
  return { locker, claimer, makerAuth, swapId, escrow: P.pda.escrow(pid, locker.publicKey, swapId), claimHalf, refundHalf, lock, amount };
}

function consentIx(s: Swap, signerKp = s.makerAuth, msgOverride?: Uint8Array) {
  const msg = msgOverride ?? P.consentDigest(pid, s.locker.publicKey, s.lock);
  return P.ixConsent(signerKp.publicKey, msg, ed25519.sign(msg, signerKp.secretKey.slice(0, 32)));
}

async function lockSwap(s: Swap) {
  const pre = s.lock.direction === 1 ? [consentIx(s)] : [];
  const r = await send(c, [...pre, P.ixLock(pid, s.locker.publicKey, s.lock)], [s.locker]);
  if (r.ok) cus.lock = r.cu!;
  return r;
}

const claimIx = (s: Swap, secret = s.claimHalf.spend, who = s.claimer.publicKey) =>
  P.ixClaim(pid, who, s.escrow, s.makerAuth.publicKey, secret, kit?.proofs.get(s.escrow.toBase58()));
const refundIx = (s: Swap, payer: PublicKey, secret = s.refundHalf.spend) =>
  P.ixRefund(pid, payer, s.escrow, s.locker.publicKey, s.makerAuth.publicKey, secret);

function expectErr(r: { ok: boolean; err?: string }, name: string) {
  assert.equal(r.ok, false, `expected ${name} but tx succeeded`);
  assert.equal(r.err, name);
}

before(async () => {
  admin = loadKeypair('.run/keys/admin.json');
  await (await import('./harness.ts')).fund(c, admin.publicKey, 50);
  [feeRecipient, maker, maker2, user, wt, rando] = await Promise.all([1, 50, 50, 100, 2, 10].map((s) => newFunded(c, s)));
  kit = new ProofKit(c, pid, admin, rando);
  // $HALFKEY test mint (SPL token, hand-encoded ixs).
  mint = Keypair.generate();
  const mintRent = await c.getMinimumBalanceForRentExemption(82);
  const r = await send(c, [
    SystemProgram.createAccount({ fromPubkey: admin.publicKey, newAccountPubkey: mint.publicKey, lamports: mintRent, space: 82, programId: TOKEN }),
    new TransactionInstruction({ programId: TOKEN, keys: [{ pubkey: mint.publicKey, isSigner: false, isWritable: true }], data: Buffer.concat([Buffer.from([20, 6]), admin.publicKey.toBuffer(), Buffer.from([0])]) }),
  ], [admin, mint]);
  assert.ok(r.ok, r.err);
});

// ------------------------------------------------------------------ config
test('init_config: only the upgrade authority, only once', async () => {
  expectErr(await send(c, [P.ixInitConfig(pid, rando.publicKey, params())], [rando]), 'Unauthorized');
  expectErr(await send(c, [P.ixInitConfig(pid, admin.publicKey, params({ feeBps: 101 }))], [admin]), 'BadParam');
  const ok = await send(c, [P.ixInitConfig(pid, admin.publicKey, params())], [admin]);
  assert.ok(ok.ok, ok.err);
  const again = await send(c, [P.ixInitConfig(pid, admin.publicKey, params())], [admin]);
  assert.equal(again.ok, false);
  const cfg = await configOf();
  assert.equal(cfg.feeBps, 50);
  assert.ok(cfg.admin.equals(admin.publicKey));
});

test('update_config: admin only, bounds enforced', async () => {
  expectErr(await send(c, [P.ixUpdateConfig(pid, rando.publicKey, params(), false, rando.publicKey)], [rando]), 'Unauthorized');
  expectErr(await send(c, [P.ixUpdateConfig(pid, admin.publicKey, params({ holderFeeBps: 60 }), false, admin.publicKey)], [admin]), 'BadParam');
  expectErr(await send(c, [P.ixUpdateConfig(pid, admin.publicKey, params({ minT0: 0 }), false, admin.publicKey)], [admin]), 'BadParam');
  expectErr(await send(c, [P.ixUpdateConfig(pid, admin.publicKey, params({ maxOpenTvl: 1n }), false, admin.publicKey)], [admin]), 'BadParam');
  const ok = await send(c, [P.ixUpdateConfig(pid, admin.publicKey, params(), false, admin.publicKey)], [admin]);
  assert.ok(ok.ok, ok.err);
});

// ------------------------------------------------------------------ maker registry
test('register_maker: bond, params, duplicate', async () => {
  expectErr(await send(c, [P.ixRegisterMaker(pid, maker.publicKey, SOL, makerParams())], [maker]), 'BondTooSmall');
  expectErr(await send(c, [P.ixRegisterMaker(pid, maker.publicKey, 2n * SOL, makerParams({ directions: 64 }))], [maker]), 'BadParam');
  expectErr(await send(c, [P.ixRegisterMaker(pid, maker.publicKey, 2n * SOL, makerParams({ min: 10n, max: 5n }))], [maker]), 'BadParam');
  expectErr(await send(c, [P.ixRegisterMaker(pid, maker.publicKey, 2n * SOL, makerParams({ endpoint: 'has space' }))], [maker]), 'BadParam');
  const ok = await send(c, [P.ixRegisterMaker(pid, maker.publicKey, 2n * SOL, makerParams())], [maker]);
  assert.ok(ok.ok, ok.err);
  assert.equal((await send(c, [P.ixRegisterMaker(pid, maker.publicKey, 2n * SOL, makerParams())], [maker])).ok, false);
  const m = await makerOf(maker.publicKey);
  assert.equal(m.bond, 2n * SOL);
  assert.equal(m.endpoint, 'https://maker.example/api');
  assert.equal(m.active, true);
  const ok2 = await send(c, [P.ixRegisterMaker(pid, maker2.publicKey, 3n * SOL, makerParams({ directions: 1, endpoint: 'https://m2.example' }))], [maker2]);
  assert.ok(ok2.ok, ok2.err);
});

test('update_maker: only the authority', async () => {
  expectErr(await send(c, [new TransactionInstruction({ ...P.ixUpdateMaker(pid, maker.publicKey, 0n, makerParams(), true), keys: P.ixUpdateMaker(pid, maker.publicKey, 0n, makerParams(), true).keys.map((k, i) => i === 0 ? { pubkey: rando.publicKey, isSigner: true, isWritable: true } : k) })], [rando]), 'Unauthorized');
  const ok = await send(c, [P.ixUpdateMaker(pid, maker.publicKey, SOL, makerParams({ spreadBps: 80 }), true)], [maker]);
  assert.ok(ok.ok, ok.err);
  const m = await makerOf(maker.publicKey);
  assert.equal(m.bond, 3n * SOL);
  assert.equal(m.spreadBps, 80);
});

// ------------------------------------------------------------------ lock validation
test('lock: rejects bad parameters', async () => {
  const cases: [string, Partial<P.LockParams>, string][] = [
    ['below maker min', { amount: 1000n }, 'AmountOutOfRange'],
    ['above maker max', { amount: 6n * SOL }, 'AmountOutOfRange'],
    ['zero xmr', { xmrAmount: 0n }, 'BadParam'],
    ['bad direction', { direction: 3 }, 'BadParam'],
    ['t0 too long', { t0Secs: 3601 }, 'BadParam'],
    ['t0 zero', { t0Secs: 0 }, 'BadParam'],
    ['window zero', { windowSecs: 0 }, 'BadParam'],
    ['claimer is not the maker (SOL->XMR)', { claimer: rando.publicKey }, 'BadParam'],
    ['watchtower == claimer', { watchtowers: [maker.publicKey] }, 'BadParam'],
  ];
  for (const [label, o, want] of cases) {
    const s = buildSwap();
    Object.assign(s.lock, o);
    const r = await lockSwap(s);
    assert.equal(r.err, want, label);
  }
});

test('lock: rejects identity, torsion, duplicate and off-curve points', async () => {
  const torsion8 = K.fromHex('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a'); // order-8 point
  const good = K.randomHalf().spendPub;
  const withTorsion = K.pointAdd(good, torsion8);
  const identity = new Uint8Array(32); identity[0] = 1;
  const offCurve = new Uint8Array(32).fill(0); offCurve[0] = 2; // y=2 is not on the curve
  assert.equal(K.isGoodPoint(withTorsion), false);
  const variants: [string, Partial<P.LockParams>][] = [
    ['identity claim', { claimPoint: identity }],
    ['identity refund', { refundPoint: identity }],
    ['torsioned claim', { claimPoint: withTorsion }],
    ['torsioned refund', { refundPoint: withTorsion }],
    ['small-order view', { viewPub: torsion8 }],
    ['off-curve refund', { refundPoint: offCurve }],
  ];
  for (const [label, o] of variants) {
    const s = buildSwap();
    Object.assign(s.lock, o);
    assert.equal((await lockSwap(s)).err, 'BadPoint', label);
  }
  const s = buildSwap();
  s.lock.refundPoint = s.lock.claimPoint;
  assert.equal((await lockSwap(s)).err, 'BadPoint', 'claim == refund');
});

// BUG-1 (docs/FORMAL-VERIFICATION.md): the on-chain point check compares against the canonical
// identity bytes only, and the curve syscalls decode non-canonical encodings, so these three
// encodings of the identity were accepted as swap keys. Fixed on branch formal-fix.
test('lock: rejects non-canonical encodings of the identity (BUG-1)', async () => {
  const negZero = new Uint8Array(32); negZero[0] = 1; negZero[31] = 0x80; // (x = -0, y = 1)
  const yP1 = new Uint8Array(32).fill(0xff); yP1[0] = 0xee; yP1[31] = 0x7f; // y = p + 1
  const yP1Neg = new Uint8Array(32).fill(0xff); yP1Neg[0] = 0xee; // y = p + 1, sign bit set
  const results: string[] = [];
  for (const [label, enc] of [['x=-0', negZero], ['y=p+1', yP1], ['y=p+1,-x', yP1Neg]] as const) {
    for (const field of ['claimPoint', 'refundPoint', 'viewPub'] as const) {
      const s = buildSwap({ t0: 600, window: 600 });
      (s.lock as any)[field] = enc;
      const r = await lockSwap(s);
      results.push(`${field} ${label}: ${r.ok ? 'ACCEPTED' : r.err}`);
      if (r.ok) {
        // Clean up: abort releases the counters; refund works unless the refund point is the bad one.
        assert.ok((await send(c, [P.ixAbort(pid, s.locker.publicKey, s.escrow, s.makerAuth.publicKey)], [s.locker])).ok);
        if (field !== 'refundPoint') assert.ok((await send(c, [refundIx(s, rando.publicKey)], [rando])).ok);
        else expectErr(await send(c, [refundIx(s, rando.publicKey)], [rando]), 'WrongSecret'); // no s has s*G == these bytes
      }
    }
  }
  assert.deepEqual(results.filter((x) => x.includes('ACCEPTED')), [], results.join('\n'));
});

test('lock: direction checks and caps', async () => {
  // maker2 only supports SOL->XMR
  const s = buildSwap({ direction: 2, makerAuth: maker2 });
  assert.equal((await lockSwap(s)).err, 'DirectionUnsupported');
  // XMR->SOL must be locked by the maker itself
  const s2 = buildSwap({ direction: 2 });
  const forged = { ...s2.lock };
  const r = await send(c, [P.ixLock(pid, rando.publicKey, forged)], [rando]);
  assert.equal(r.err, 'BadParam');
  // escrow PDA must match the locker + swap id
  const s3 = buildSwap();
  const ix = P.ixLock(pid, user.publicKey, s3.lock);
  ix.keys[1].pubkey = P.pda.escrow(pid, user.publicKey, K.newSwapId());
  assert.equal((await send(c, [ix], [user])).err, 'BadPda');
  // global per-swap cap
  await send(c, [P.ixUpdateConfig(pid, admin.publicKey, params({ maxSwap: SOL, maxOpenTvl: 40n * SOL }), false, admin.publicKey)], [admin]);
  assert.equal((await lockSwap(buildSwap({ amount: 2n * SOL }))).err, 'CapExceeded');
  // open TVL cap
  const cfg = await configOf();
  await send(c, [P.ixUpdateConfig(pid, admin.publicKey, params({ maxSwap: SOL, maxOpenTvl: cfg.openTvl + SOL }), false, admin.publicKey)], [admin]);
  const a = buildSwap({ amount: SOL, t0: 1, window: 1 });
  assert.ok((await lockSwap(a)).ok);
  assert.equal((await lockSwap(buildSwap({ amount: SOL / 10n }))).err, 'CapExceeded');
  // pause blocks new locks only
  await send(c, [P.ixUpdateConfig(pid, admin.publicKey, params(), true, admin.publicKey)], [admin]);
  assert.equal((await lockSwap(buildSwap())).err, 'Paused');
  await waitChainTime(c, Number((await escrowOf(a.escrow))!.t1));
  const rr = await send(c, [refundIx(a, rando.publicKey)], [rando]); // exits still work while paused
  assert.ok(rr.ok, rr.err);
  await send(c, [P.ixUpdateConfig(pid, admin.publicKey, params(), false, admin.publicKey)], [admin]);
});

test('lock: a pre-funded escrow address cannot block the lock', async () => {
  const s = buildSwap();
  assert.ok((await send(c, [transferIx(rando.publicKey, s.escrow, 1_000_000)], [rando])).ok);
  const r = await lockSwap(s);
  assert.ok(r.ok, r.err);
  const e = await escrowOf(s.escrow);
  assert.equal(e!.state, P.ST.LOCKED);
});

test('lock: SOL->XMR needs the maker consent signature, exact terms, unexpired, right before lock', async () => {
  const s = buildSwap();
  const lockIx = () => P.ixLock(pid, user.publicKey, s.lock);
  expectErr(await send(c, [lockIx()], [user]), 'NoConsent');
  expectErr(await send(c, [consentIx(s, rando), lockIx()], [user]), 'NoConsent');
  const other = { ...s.lock, amount: s.lock.amount + 1n };
  expectErr(await send(c, [consentIx(s, maker, P.consentDigest(pid, user.publicKey, other)), lockIx()], [user]), 'NoConsent');
  expectErr(await send(c, [consentIx(s), transferIx(user.publicKey, rando.publicKey, 1), lockIx()], [user]), 'NoConsent');
  const late = buildSwap();
  late.lock.consentExpiry = (await chainTime(c)) - 1;
  expectErr(await send(c, [consentIx(late), P.ixLock(pid, user.publicKey, late.lock)], [user]), 'NoConsent');
  // a consent for one escrow cannot be replayed on another swap id
  const s2 = buildSwap();
  expectErr(await send(c, [consentIx(s), P.ixLock(pid, user.publicKey, { ...s.lock, swapId: s2.swapId })], [user]), 'NoConsent');
  const ok = await send(c, [consentIx(s), lockIx()], [user]);
  assert.ok(ok.ok, ok.err);
  assert.ok((await send(c, [P.ixAbort(pid, user.publicKey, s.escrow, maker.publicKey)], [user])).ok);
  assert.ok((await send(c, [refundIx(s, rando.publicKey)], [rando])).ok);
});

test('expire: anyone releases an unclaimed swap after t1; refund later still pays the locker', async () => {
  const s = buildSwap({ t0: 1, window: 1 });
  assert.ok((await lockSwap(s)).ok);
  const m0 = await makerOf(maker.publicKey);
  const c0 = await configOf();
  expectErr(await send(c, [P.ixExpire(pid, rando.publicKey, s.escrow, maker.publicKey)], [rando]), 'TooEarly');
  await waitChainTime(c, Number((await escrowOf(s.escrow))!.t1));
  assert.ok((await send(c, [P.ixExpire(pid, rando.publicKey, s.escrow, maker.publicKey)], [rando])).ok);
  const m1 = await makerOf(maker.publicKey);
  assert.equal(m1.openSwaps, m0.openSwaps - 1);
  assert.equal(m1.expired, m0.expired + 1n);
  assert.equal((await configOf()).openTvl, c0.openTvl - s.amount);
  expectErr(await send(c, [P.ixExpire(pid, rando.publicKey, s.escrow, maker.publicKey)], [rando]), 'BadState');
  const ub = await bal(user.publicKey);
  assert.ok((await send(c, [refundIx(s, rando.publicKey)], [rando])).ok);
  assert.equal((await bal(user.publicKey)) - ub, s.amount);
  assert.equal((await makerOf(maker.publicKey)).expired, m1.expired, 'no double count');
});

test('stats: watchtower abort, locker cancel and maker decline are counted apart', async () => {
  const m0 = await makerOf(maker.publicKey);
  const a = buildSwap({ t0: 600 }), b = buildSwap({ t0: 600 }), d = buildSwap({ t0: 600 });
  for (const x of [a, b, d]) assert.ok((await lockSwap(x)).ok);
  assert.ok((await send(c, [P.ixAbort(pid, wt.publicKey, a.escrow, maker.publicKey)], [wt])).ok);
  assert.ok((await send(c, [P.ixAbort(pid, user.publicKey, b.escrow, maker.publicKey)], [user])).ok);
  assert.ok((await send(c, [P.ixAbort(pid, maker.publicKey, d.escrow, maker.publicKey)], [maker])).ok);
  const m1 = await makerOf(maker.publicKey);
  assert.equal(m1.aborted, m0.aborted + 1n);
  assert.equal(m1.cancelled, m0.cancelled + 1n);
  assert.equal(m1.declined, m0.declined + 1n);
  assert.equal(m1.openSwaps, m0.openSwaps, 'aborts release the open counters');
  for (const x of [a, b, d]) assert.ok((await send(c, [refundIx(x, rando.publicKey)], [rando])).ok);
});

// ------------------------------------------------------------------ happy path SOL -> XMR
test('SOL->XMR: lock, ready, claim (fee to vault, secret on chain), close', async () => {
  const s = buildSwap({ t0: 600, window: 600 });
  const userBefore = await bal(user.publicKey);
  const r = await lockSwap(s);
  assert.ok(r.ok, r.err);
  const e = (await escrowOf(s.escrow))!;
  assert.equal(e.state, P.ST.LOCKED);
  assert.equal(e.amount, s.amount);
  assert.equal(e.feeBps, 50);
  assert.ok(e.locker.equals(user.publicKey));
  assert.ok(userBefore - (await bal(user.publicKey)) >= s.amount);
  const m0 = await makerOf(maker.publicKey);
  assert.equal(m0.openSwaps >= 1, true);

  // claim before t0 without ready
  expectErr(await send(c, [claimIx(s)], [maker]), 'TooEarly');
  // ready: only the locker
  expectErr(await send(c, [P.ixReady(pid, rando.publicKey, s.escrow)], [rando]), 'Unauthorized');
  expectErr(await send(c, [P.ixReady(pid, maker.publicKey, s.escrow)], [maker]), 'Unauthorized');
  assert.ok((await send(c, [P.ixReady(pid, user.publicKey, s.escrow)], [user])).ok);
  expectErr(await send(c, [P.ixReady(pid, user.publicKey, s.escrow)], [user]), 'BadState');
  // locker/watchtower can no longer abort after ready
  expectErr(await send(c, [P.ixAbort(pid, wt.publicKey, s.escrow, s.makerAuth.publicKey)], [wt]), 'BadState');
  expectErr(await send(c, [P.ixAbort(pid, user.publicKey, s.escrow, s.makerAuth.publicKey)], [user]), 'BadState');

  // wrong secret, malleable alias, wrong signer, refund secret
  expectErr(await send(c, [claimIx(s, K.randomScalar())], [maker]), 'WrongSecret');
  const alias = K.bigToLe32(K.leToBig(s.claimHalf.spend) + K.L);
  expectErr(await send(c, [claimIx(s, alias)], [maker]), 'NonCanonicalScalar');
  expectErr(await send(c, [claimIx(s, s.claimHalf.spend, rando.publicKey)], [rando]), 'Unauthorized');
  expectErr(await send(c, [claimIx(s, s.refundHalf.spend)], [maker]), 'WrongSecret');
  // wrong maker account (maker2's) for this escrow
  const bad = claimIx(s); bad.keys[2].pubkey = P.pda.maker(pid, maker2.publicKey);
  expectErr(await send(c, [bad], [maker]), 'BadAccount');
  // fake fee vault
  const bad2 = claimIx(s); bad2.keys[4].pubkey = rando.publicKey;
  expectErr(await send(c, [bad2], [maker]), 'BadPda');
  // refund is closed while claimable
  expectErr(await send(c, [refundIx(s, rando.publicKey)], [rando]), 'TooEarly');

  const vault = P.pda.feeVault(pid);
  const [mb, vb, cfg0] = [await bal(maker.publicKey), await bal(vault), await configOf()];
  const cl = await send(c, [claimIx(s)], [maker], rando); // fee paid by someone else, so maker delta is exact
  assert.ok(cl.ok, cl.err);
  cus.claim = cl.cu!;
  const fee = (s.amount * 50n) / 10_000n;
  assert.equal((await bal(maker.publicKey)) - mb, s.amount - fee);
  assert.equal((await bal(vault)) - vb, fee);
  const e2 = (await escrowOf(s.escrow))!;
  assert.equal(e2.state, P.ST.CLAIMED);
  assert.deepEqual(Buffer.from(e2.secret), Buffer.from(s.claimHalf.spend));
  // The user can now rebuild the full Monero spend key.
  const full = K.scalarAdd(e2.secret, s.refundHalf.spend);
  assert.deepEqual(Buffer.from(K.pub(full)), Buffer.from(K.pointAdd(s.claimHalf.spendPub, s.refundHalf.spendPub)));
  const cfg1 = await configOf();
  assert.equal(cfg1.totalSwaps, cfg0.totalSwaps + 1n);
  assert.equal(cfg1.totalFees - cfg0.totalFees, fee);
  assert.equal(cfg0.openTvl - cfg1.openTvl, s.amount);
  const m1 = await makerOf(maker.publicKey);
  assert.equal(m1.completed, m0.completed + 1n);

  // terminal: no second claim, no refund, no abort
  expectErr(await send(c, [claimIx(s)], [maker]), 'BadState');
  expectErr(await send(c, [refundIx(s, rando.publicKey)], [rando]), 'BadState');
  expectErr(await send(c, [P.ixAbort(pid, maker.publicKey, s.escrow, s.makerAuth.publicKey)], [maker]), 'BadState');

  // close: only the locker; rent back
  expectErr(await send(c, [P.ixClose(pid, rando.publicKey, s.escrow)], [rando]), 'Unauthorized');
  const ub = await bal(user.publicKey);
  assert.ok((await send(c, [P.ixClose(pid, user.publicKey, s.escrow)], [user], rando)).ok);
  assert.ok((await bal(user.publicKey)) > ub);
  assert.equal(await escrowOf(s.escrow), null);
});

test('SOL->XMR: without ready, the maker claims after t0 only with an on-chain payment proof (v1.5)', async () => {
  const s = buildSwap({ t0: 2, window: 60 });
  assert.ok((await lockSwap(s)).ok);
  expectErr(await send(c, [claimIx(s)], [maker]), 'TooEarly');
  await waitChainTime(c, Number((await escrowOf(s.escrow))!.t0));
  // locker and watchtower lose abort power at t0
  expectErr(await send(c, [P.ixAbort(pid, wt.publicKey, s.escrow, s.makerAuth.publicKey)], [wt]), 'TooLate');
  expectErr(await send(c, [P.ixAbort(pid, user.publicKey, s.escrow, s.makerAuth.publicKey)], [user]), 'TooLate');
  // no bare claim at t0: the maker's word is not enough
  assert.equal((await send(c, [claimIx(s)], [maker])).ok, false);
  const notMine = P.ixClaim(pid, maker.publicKey, s.escrow, s.makerAuth.publicKey, s.claimHalf.spend, rando.publicKey);
  expectErr(await send(c, [notMine], [maker]), 'BadAccount');
  await kit.prove(s.escrow);
  const r = await send(c, [claimIx(s)], [maker]);
  assert.ok(r.ok, r.err);
  cus.claim_with_proof = r.cu!;
});

// ------------------------------------------------------------------ abort / refund
test('abort: watchtower cancels before t0, gasless refund pays only the locker', async () => {
  const s = buildSwap({ t0: 600, window: 600 });
  assert.ok((await lockSwap(s)).ok);
  expectErr(await send(c, [P.ixAbort(pid, rando.publicKey, s.escrow, s.makerAuth.publicKey)], [rando]), 'Unauthorized');
  const m0 = await makerOf(maker.publicKey);
  // refund impossible before abort/t1
  expectErr(await send(c, [refundIx(s, rando.publicKey)], [rando]), 'TooEarly');
  const ab = await send(c, [P.ixAbort(pid, wt.publicKey, s.escrow, s.makerAuth.publicKey)], [wt]);
  assert.ok(ab.ok, ab.err);
  const e = (await escrowOf(s.escrow))!;
  assert.equal(e.state, P.ST.ABORTED);
  assert.deepEqual(Buffer.from(e.secret), Buffer.alloc(32), 'abort reveals nothing');
  // claim can no longer race the refund
  assert.ok((await send(c, [P.ixReady(pid, user.publicKey, s.escrow)], [user])).ok === false);
  expectErr(await send(c, [claimIx(s)], [maker]), 'BadState');
  expectErr(await send(c, [P.ixAbort(pid, wt.publicKey, s.escrow, s.makerAuth.publicKey)], [wt]), 'BadState');
  // wrong secret / claim secret / wrong locker account
  expectErr(await send(c, [refundIx(s, rando.publicKey, K.randomScalar())], [rando]), 'WrongSecret');
  expectErr(await send(c, [refundIx(s, rando.publicKey, s.claimHalf.spend)], [rando]), 'WrongSecret');
  const steal = refundIx(s, rando.publicKey); steal.keys[2].pubkey = rando.publicKey;
  expectErr(await send(c, [steal], [rando]), 'BadAccount');
  // relayer (rando) pays the fee; user gets exactly the amount
  const ub = await bal(user.publicKey);
  const rf = await send(c, [refundIx(s, rando.publicKey)], [rando]);
  assert.ok(rf.ok, rf.err);
  cus.refund = rf.cu!;
  assert.equal((await bal(user.publicKey)) - ub, s.amount);
  const e2 = (await escrowOf(s.escrow))!;
  assert.equal(e2.state, P.ST.REFUNDED);
  assert.deepEqual(Buffer.from(e2.secret), Buffer.from(s.refundHalf.spend), 'refund reveals the locker half for the maker');
  assert.equal((await makerOf(maker.publicKey)).aborted, m0.aborted + 1n);
  expectErr(await send(c, [refundIx(s, rando.publicKey)], [rando]), 'BadState');
});

test('abort: the locker can cancel itself before t0; second watchtower slot works', async () => {
  const s = buildSwap({ t0: 600, window: 600 });
  assert.ok((await lockSwap(s)).ok);
  assert.ok((await send(c, [P.ixAbort(pid, user.publicKey, s.escrow, s.makerAuth.publicKey)], [user])).ok);
  const wt2 = Keypair.generate();
  const s2 = buildSwap({ t0: 600, window: 600, watchtowers: [wt.publicKey, wt2.publicKey] });
  assert.ok((await lockSwap(s2)).ok);
  assert.ok((await send(c, [P.ixAbort(pid, wt2.publicKey, s2.escrow, s2.makerAuth.publicKey)], [rando, wt2], rando)).ok);
  for (const x of [s, s2]) assert.ok((await send(c, [refundIx(x, rando.publicKey)], [rando])).ok);
});

test('abort: the claimer may give up any time before t1, even after ready', async () => {
  const s = buildSwap({ t0: 600, window: 600 });
  assert.ok((await lockSwap(s)).ok);
  assert.ok((await send(c, [P.ixReady(pid, user.publicKey, s.escrow)], [user])).ok);
  assert.ok((await send(c, [P.ixAbort(pid, maker.publicKey, s.escrow, s.makerAuth.publicKey)], [maker])).ok);
  assert.ok((await send(c, [refundIx(s, user.publicKey)], [user])).ok);
});

test('expiry: after t1 only refund; maker marked expired', async () => {
  const s = buildSwap({ t0: 1, window: 2 });
  assert.ok((await lockSwap(s)).ok);
  const e = (await escrowOf(s.escrow))!;
  await waitChainTime(c, Number(e.t1));
  expectErr(await send(c, [claimIx(s)], [maker]), 'TooLate');
  expectErr(await send(c, [P.ixAbort(pid, maker.publicKey, s.escrow, s.makerAuth.publicKey)], [maker]), 'TooLate');
  const m0 = await makerOf(maker.publicKey);
  assert.ok((await send(c, [refundIx(s, rando.publicKey)], [rando])).ok);
  assert.equal((await makerOf(maker.publicKey)).expired, m0.expired + 1n);
});

test('race: claim and refund fired together at t1 never both pay', async () => {
  const swaps: Swap[] = [];
  for (let i = 0; i < 6; i++) swaps.push(buildSwap({ t0: 1, window: 3 + (i % 3) }));
  for (const s of swaps) { assert.ok((await lockSwap(s)).ok); await kit.prove(s.escrow); }
  const results: { claim: boolean; refund: boolean }[] = [];
  await Promise.all(swaps.map(async (s, i) => {
    const e = (await escrowOf(s.escrow))!;
    // aim at the boundary: half start just before t1, half exactly at t1; fire both until one settles
    while ((await chainTime(c)) < Number(e.t1) - (i % 2 === 0 ? 1 : 0)) await sleep(150);
    let claim = false, refund = false;
    for (let k = 0; k < 12 && !claim && !refund; k++) {
      const [cr, rr] = await Promise.all([send(c, [claimIx(s)], [maker]), send(c, [refundIx(s, rando.publicKey)], [rando])]);
      claim ||= cr.ok; refund ||= rr.ok;
      if (!cr.ok) assert.ok(['TooLate', 'BadState'].includes(cr.err!), cr.err);
      if (!rr.ok) assert.ok(['TooEarly', 'BadState'].includes(rr.err!), rr.err);
    }
    results.push({ claim, refund });
    const fin = (await escrowOf(s.escrow))!;
    assert.ok(claim !== refund, 'exactly one settles');
    assert.equal(fin.state, claim ? P.ST.CLAIMED : P.ST.REFUNDED);
    // escrow keeps only its rent
    const rent = BigInt(await c.getMinimumBalanceForRentExemption(P.ESCROW_LEN));
    assert.equal(await bal(s.escrow), rent);
  }));
  console.log('race outcomes', results.map((r) => (r.claim ? 'claim' : 'refund')).join(','));
});

test('race: in [t0,t1) claim wins and refund is rejected', async () => {
  const s = buildSwap({ t0: 1, window: 30 });
  assert.ok((await lockSwap(s)).ok);
  await kit.prove(s.escrow);
  await waitChainTime(c, Number((await escrowOf(s.escrow))!.t0));
  const [cr, rr] = await Promise.all([send(c, [claimIx(s)], [maker]), send(c, [refundIx(s, rando.publicKey)], [rando])]);
  assert.ok(cr.ok, cr.err);
  assert.equal(rr.ok, false);
});

// ------------------------------------------------------------------ XMR -> SOL
test('XMR->SOL: maker locks SOL, user claims to a fresh wallet (relayer pays gas)', async () => {
  const fresh = Keypair.generate(); // zero-SOL wallet
  const s = buildSwap({ direction: 2, user: fresh, t0: 600, window: 600 });
  const r = await lockSwap(s);
  assert.ok(r.ok, r.err);
  const e = (await escrowOf(s.escrow))!;
  assert.ok(e.locker.equals(maker.publicKey) && e.claimer.equals(fresh.publicKey));
  // maker (locker) confirms the user's XMR, then the user claims
  assert.ok((await send(c, [P.ixReady(pid, maker.publicKey, s.escrow)], [maker])).ok);
  const cl = await send(c, [claimIx(s)], [rando, fresh], rando);
  assert.ok(cl.ok, cl.err);
  const fee = (s.amount * 50n) / 10_000n;
  assert.equal(await bal(fresh.publicKey), s.amount - fee);
  const e2 = (await escrowOf(s.escrow))!;
  assert.deepEqual(Buffer.from(e2.secret), Buffer.from(s.claimHalf.spend));
});

test('XMR->SOL: user never sends XMR, maker aborts and refunds itself', async () => {
  const fresh = Keypair.generate();
  const s = buildSwap({ direction: 2, user: fresh, t0: 600, window: 600, watchtowers: [] });
  assert.ok((await lockSwap(s)).ok);
  assert.ok((await send(c, [P.ixAbort(pid, maker.publicKey, s.escrow, s.makerAuth.publicKey)], [maker])).ok);
  const mb = await bal(maker.publicKey);
  assert.ok((await send(c, [refundIx(s, rando.publicKey)], [rando])).ok);
  assert.equal((await bal(maker.publicKey)) - mb, s.amount);
});

// ------------------------------------------------------------------ $HALFKEY maker bond (stake)
test('stake: maker bonding >= holder_min $HALFKEY pays the lower fee; unstake has a delay', async () => {
  const ta = Keypair.generate();
  const rent = await c.getMinimumBalanceForRentExemption(165);
  const mk = await send(c, [
    SystemProgram.createAccount({ fromPubkey: admin.publicKey, newAccountPubkey: ta.publicKey, lamports: rent, space: 165, programId: TOKEN }),
    new TransactionInstruction({ programId: TOKEN, keys: [{ pubkey: ta.publicKey, isSigner: false, isWritable: true }, { pubkey: mint.publicKey, isSigner: false, isWritable: false }], data: Buffer.concat([Buffer.from([18]), maker.publicKey.toBuffer()]) }),
  ], [admin, ta]);
  assert.ok(mk.ok, mk.err);
  const d = Buffer.alloc(9); d[0] = 7; d.writeBigUInt64LE(5000n, 1);
  assert.ok((await send(c, [new TransactionInstruction({ programId: TOKEN, keys: [{ pubkey: mint.publicKey, isSigner: false, isWritable: true }, { pubkey: ta.publicKey, isSigner: false, isWritable: true }, { pubkey: admin.publicKey, isSigner: true, isWritable: false }], data: d })], [admin])).ok);
  const tokBal = async (k: PublicKey) => (await c.getAccountInfo(k, 'confirmed'))!.data.readBigUInt64LE(64);

  // wrong mint / someone else staking for the maker
  const wrongMint = P.ixStake(pid, maker.publicKey, mint.publicKey, ta.publicKey, 10n); wrongMint.keys[2].pubkey = rando.publicKey;
  expectErr(await send(c, [wrongMint], [maker]), 'BadAccount');
  const wrongVault = P.ixStake(pid, maker.publicKey, mint.publicKey, ta.publicKey, 10n); wrongVault.keys[4].pubkey = P.ata(rando.publicKey, mint.publicKey);
  expectErr(await send(c, [wrongVault], [maker]), 'BadPda');

  assert.ok((await send(c, [P.ixStake(pid, maker.publicKey, mint.publicKey, ta.publicKey, 999n)], [maker])).ok);
  assert.equal((await makerOf(maker.publicKey)).staked, 999n);
  const below = buildSwap({ t0: 600 });
  assert.ok((await lockSwap(below)).ok);
  assert.equal((await escrowOf(below.escrow))!.feeBps, 50, 'below threshold: full fee');

  assert.ok((await send(c, [P.ixStake(pid, maker.publicKey, mint.publicKey, ta.publicKey, 1n)], [maker])).ok);
  assert.equal(await tokBal(P.stakeVault(pid, maker.publicKey, mint.publicKey)), 1000n);
  const at = buildSwap({ t0: 600 });
  assert.equal((await lockSwap(at)).err, 'NoConsent', 'consent at the full fee no longer matches');
  at.lock.feeBps = 25;
  assert.ok((await lockSwap(at)).ok);
  assert.equal((await escrowOf(at.escrow))!.feeBps, 25, 'bonded maker: discounted fee');
  const other = buildSwap({ makerAuth: maker2, t0: 600 });
  assert.ok((await lockSwap(other)).ok);
  assert.equal((await escrowOf(other.escrow))!.feeBps, 50, 'another maker without a bond pays full fee');

  // unstake: discount stops at the request; tokens come back only after the delay
  expectErr(await send(c, [P.ixUnstake(pid, maker.publicKey, mint.publicKey, ta.publicKey)], [maker]), 'BondLocked');
  assert.ok((await send(c, [P.ixUnstakeRequest(pid, maker.publicKey)], [maker])).ok);
  const after = buildSwap({ t0: 600 });
  after.lock.feeBps = 25;
  assert.equal((await lockSwap(after)).err, 'NoConsent', 'no discount while unstaking');
  after.lock.feeBps = 50;
  assert.ok((await lockSwap(after)).ok);
  expectErr(await send(c, [P.ixStake(pid, maker.publicKey, mint.publicKey, ta.publicKey, 1n)], [maker]), 'BadState');
  expectErr(await send(c, [P.ixUnstake(pid, maker.publicKey, mint.publicKey, ta.publicKey)], [maker]), 'BondLocked');
  expectErr(await send(c, [P.ixUnstakeRequest(pid, rando.publicKey)], [rando]), 'BadAccount');
  await waitChainTime(c, Number((await makerOf(maker.publicKey)).stakeUnlockAt));
  assert.ok((await send(c, [P.ixUnstake(pid, maker.publicKey, mint.publicKey, ta.publicKey)], [maker])).ok);
  assert.equal(await tokBal(ta.publicKey), 5000n, 'all tokens back');
  const m = await makerOf(maker.publicKey);
  assert.equal(m.staked, 0n);
  assert.equal(m.stakeUnlockAt, 0n);
  for (const x of [below, at, other, after]) {
    assert.ok((await send(c, [P.ixAbort(pid, x.claimer.publicKey, x.escrow, x.makerAuth.publicKey)], [x.claimer])).ok);
    assert.ok((await send(c, [refundIx(x, rando.publicKey)], [rando])).ok);
  }
});

test('sweep_fees: only to the configured recipient', async () => {
  expectErr(await send(c, [P.ixSweepFees(pid, rando.publicKey, rando.publicKey)], [rando]), 'BadAccount');
  const vault = P.pda.feeVault(pid);
  const vb = await bal(vault);
  const fb = await bal(feeRecipient.publicKey);
  const r = await send(c, [P.ixSweepFees(pid, rando.publicKey, feeRecipient.publicKey)], [rando]);
  assert.ok(r.ok, r.err);
  const rent = BigInt(await c.getMinimumBalanceForRentExemption(0));
  assert.equal((await bal(feeRecipient.publicKey)) - fb, vb - rent);
  assert.equal(await bal(vault), rent);
});

test('maker exit: bond locked while swaps are open and during unbonding', async () => {
  const s = buildSwap({ makerAuth: maker2, t0: 600, window: 600 });
  assert.ok((await lockSwap(s)).ok);
  expectErr(await send(c, [P.ixWithdrawMaker(pid, maker2.publicKey)], [maker2]), 'OpenSwaps');
  assert.ok((await send(c, [P.ixRequestUnbond(pid, maker2.publicKey)], [maker2])).ok);
  // inactive maker takes no new swaps
  assert.equal((await lockSwap(buildSwap({ makerAuth: maker2 }))).err, 'MakerInactive');
  // the swap is aborted but the locker never refunds: it must not pin the bond
  assert.ok((await send(c, [P.ixAbort(pid, maker2.publicKey, s.escrow, s.makerAuth.publicKey)], [maker2])).ok);
  expectErr(await send(c, [P.ixWithdrawMaker(pid, maker2.publicKey)], [maker2]), 'BondLocked');
  await waitChainTime(c, Number((await makerOf(maker2.publicKey)).withdrawAfter));
  const mb = await bal(maker2.publicKey);
  const w = await send(c, [P.ixWithdrawMaker(pid, maker2.publicKey)], [maker2], rando);
  assert.ok(w.ok, w.err);
  assert.ok((await bal(maker2.publicKey)) - mb >= 3n * SOL);
  assert.equal(await c.getAccountInfo(P.pda.maker(pid, maker2.publicKey)), null);
  // the abandoned refund still works with the maker account gone
  const ub = await bal(user.publicKey);
  const rf = await send(c, [refundIx(s, rando.publicKey)], [rando]);
  assert.ok(rf.ok, rf.err);
  assert.equal((await bal(user.publicKey)) - ub, s.amount);
});

test('account spoofing: fake config / escrow owned by another program are rejected', async () => {
  // A system-owned account in the config slot
  const s = buildSwap();
  const ix = P.ixLock(pid, user.publicKey, s.lock);
  ix.keys[3].pubkey = rando.publicKey;
  ix.keys[3].isWritable = true;
  assert.equal((await send(c, [ix], [user, rando])).err, 'BadAccount');
  // the maker account in the escrow slot (program-owned, wrong discriminator)
  const ab = P.ixAbort(pid, maker.publicKey, P.pda.maker(pid, maker.publicKey), maker.publicKey);
  assert.equal((await send(c, [ab], [maker])).err, 'BadAccount');
});

test('compute units', () => {
  console.log('CU', JSON.stringify(cus));
  assert.ok(cus.claim < 60_000 && cus.lock < 120_000, JSON.stringify(cus));
});
