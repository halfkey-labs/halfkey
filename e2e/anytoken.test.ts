// Any coin <-> XMR on a local validator, through the SDK's route path end to end (run e2e/validator.sh first).
// Jupiter is mocked: its /swap/v2/build answer is replayed from a fake DEX built with the stock SPL token
// program (a "pool" that took the user as delegate on its wSOL and coin accounts), so every instruction is
// real and only the user signs. The route goes through J.buildRoute -> routeInstructions -> composeSell ->
// the HALFKEY lock -> the maker's claim, and the in-between state is found from chain with findUnlocked.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { Keypair, PublicKey, SystemProgram, TransactionInstruction, VersionedTransaction, LAMPORTS_PER_SOL } from '@solana/web3.js';
import { ed25519 } from '@noble/curves/ed25519';
import * as P from '../sdk/program.ts';
import * as K from '../sdk/keys.ts';
import * as J from '../sdk/jupiter.ts';
import { conn, send, newFunded, loadKeypair, fund, PROGRAM_ID as pid, sleep, chainTime } from './harness.ts';

const c = conn();
const SOL = BigInt(LAMPORTS_PER_SOL);
const TOKEN = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
const ATA = new PublicKey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');
const WSOL = new PublicKey(J.WSOL);
const FAKE = { swapProgram: TOKEN.toBase58(), allowPrograms: [TOKEN.toBase58()] }; // the fake DEX is plain SPL token instructions

let admin: Keypair, maker: Keypair, user: Keypair, pool: Keypair, wt: Keypair, coin: Keypair;

const ata = (owner: PublicKey, mint: PublicKey) => PublicKey.findProgramAddressSync([owner.toBuffer(), TOKEN.toBuffer(), mint.toBuffer()], ATA)[0];
const meta = (pubkey: PublicKey, isSigner = false, isWritable = true) => ({ pubkey, isSigner, isWritable });
const u64 = (tag: number, n: bigint) => { const d = Buffer.alloc(9); d[0] = tag; d.writeBigUInt64LE(n, 1); return d; };
const createAta = (payer: PublicKey, owner: PublicKey, mint: PublicKey) => new TransactionInstruction({ programId: ATA, keys: [meta(payer, true), meta(ata(owner, mint)), meta(owner, false, false), meta(mint, false, false), meta(SystemProgram.programId, false, false), meta(TOKEN, false, false)], data: Buffer.from([1]) });
const tTransfer = (src: PublicKey, dst: PublicKey, owner: PublicKey, n: bigint) => new TransactionInstruction({ programId: TOKEN, keys: [meta(src), meta(dst), meta(owner, true, false)], data: u64(3, n) });
const tApprove = (src: PublicKey, delegate: PublicKey, owner: PublicKey, n: bigint) => new TransactionInstruction({ programId: TOKEN, keys: [meta(src), meta(delegate, false, false), meta(owner, true, false)], data: u64(4, n) });
const tSync = (a: PublicKey) => new TransactionInstruction({ programId: TOKEN, keys: [meta(a)], data: Buffer.from([17]) });
const tClose = (a: PublicKey, dst: PublicKey, owner: PublicKey) => new TransactionInstruction({ programId: TOKEN, keys: [meta(a), meta(dst), meta(owner, true, false)], data: Buffer.from([9]) });
const raw = (ix: TransactionInstruction): J.RawIx => ({ programId: ix.programId.toBase58(), accounts: ix.keys.map((k) => ({ pubkey: k.pubkey.toBase58(), isSigner: k.isSigner, isWritable: k.isWritable })), data: ix.data.toString('base64') });

async function bal(k: PublicKey) { return BigInt(await c.getBalance(k, 'confirmed')); }
async function tok(k: PublicKey) { const a = await c.getAccountInfo(k, 'confirmed'); return a ? a.data.readBigUInt64LE(64) : 0n; }
async function escrowOf(a: PublicKey) { const x = await c.getAccountInfo(a, 'confirmed'); return x ? P.decodeEscrow(x.data, a) : null; }

/** What Jupiter's /swap/v2/build would answer, for the fake DEX: COIN -> SOL at a fixed price (sell), or SOL -> COIN (buy). */
function fakeBuild(side: 'sell' | 'buy', amountIn: bigint, out: bigint, taker: PublicKey, slippageBps = 100) {
  const userCoin = ata(taker, coin.publicKey), userWsol = ata(taker, WSOL), poolCoin = ata(pool.publicKey, coin.publicKey), poolWsol = ata(pool.publicKey, WSOL);
  const minOut = (out * BigInt(10_000 - slippageBps)) / 10_000n;
  const setup = side === 'sell'
    ? [createAta(taker, taker, WSOL), tTransfer(userCoin, poolCoin, taker, amountIn)]
    : [createAta(taker, taker, WSOL), SystemProgram.transfer({ fromPubkey: taker, toPubkey: userWsol, lamports: amountIn }), tSync(userWsol), createAta(taker, taker, coin.publicKey), tTransfer(userWsol, poolWsol, taker, amountIn)];
  // the pool delivers as the user's delegate (approved in before())
  const swap = side === 'sell' ? tTransfer(poolWsol, userWsol, taker, out) : tTransfer(poolCoin, userCoin, taker, out);
  return {
    inputMint: side === 'sell' ? coin.publicKey.toBase58() : J.WSOL, outputMint: side === 'sell' ? J.WSOL : coin.publicKey.toBase58(),
    inAmount: String(amountIn), outAmount: String(out), otherAmountThreshold: String(minOut), swapMode: 'ExactIn', slippageBps,
    priceImpactPct: '0.004', routePlan: [{ percent: 100, bps: 10000, swapInfo: { label: 'FakeDex' } }],
    computeBudgetInstructions: [raw(new TransactionInstruction({ programId: new PublicKey('ComputeBudget111111111111111111111111111111'), keys: [], data: u64(3, 20_000n) }))],
    setupInstructions: setup.map(raw), swapInstruction: raw(swap), cleanupInstruction: raw(tClose(userWsol, taker, taker)), otherInstructions: [],
    addressesByLookupTableAddress: {}, transactionVersion: 0,
  };
}
const fetchOf = (body: unknown) => (async () => new Response(JSON.stringify(body), { status: 200 })) as unknown as typeof fetch;

/** The maker's consent + lock for `lamports` (what taker.prepareSolToXmr returns after the handshake). */
function makerLock(locker: PublicKey, lamports: bigint, o: { t0?: number; consentExpiry?: number } = {}) {
  const swapId = K.newSwapId(), claimHalf = K.randomHalf(), refundHalf = K.randomHalf();
  const shared = K.sharedWallet(claimHalf.spendPub, refundHalf.spendPub, refundHalf.view, 'stagenet');
  const lock: P.LockParams = {
    swapId, claimer: maker.publicKey, direction: 1, amount: lamports, xmrAmount: 4_100_000_000n,
    claimPoint: claimHalf.spendPub, refundPoint: refundHalf.spendPub, viewPub: shared.viewPub, quoteHash: new Uint8Array(32).fill(5),
    t0Secs: o.t0 ?? 120, windowSecs: 600, watchtowers: [wt.publicKey], makerAuthority: maker.publicKey,
    consentExpiry: o.consentExpiry ?? Math.floor(Date.now() / 1000) + 90, feeBps: 50,
  };
  const d = P.consentDigest(pid, locker, lock);
  return { swapId, claimHalf, lock, escrow: P.pda.escrow(pid, locker, swapId), ixs: [P.ixConsent(maker.publicKey, d, ed25519.sign(d, maker.secretKey.slice(0, 32))), P.ixLock(pid, locker, lock)] };
}

async function sendV0(tx: VersionedTransaction, signer: Keypair) {
  tx.sign([signer]);
  const sig = await c.sendRawTransaction(tx.serialize(), { skipPreflight: true });
  const { lastValidBlockHeight } = await c.getLatestBlockhash('confirmed');
  await c.confirmTransaction({ signature: sig, blockhash: tx.message.recentBlockhash, lastValidBlockHeight }, 'confirmed');
  const t = await c.getTransaction(sig, { commitment: 'confirmed', maxSupportedTransactionVersion: 0 });
  return { sig, ok: !t?.meta?.err, err: t?.meta?.err, fee: BigInt(t?.meta?.fee ?? 0), logs: t?.meta?.logMessages ?? [] };
}

/** v1.5: a SOL->XMR claim needs the user's `ready` or an on-chain payment proof; the maker can no
 * longer claim at t0 on its own word (the proof path has its own suite, e2e/zk.test.ts). Here the
 * user's browser has checked the XMR lock and signs `ready` (before t0), then the maker claims. */
async function claimAfterReady(m: ReturnType<typeof makerLock>, locker = user) {
  assert.equal((await send(c, [P.ixClaim(pid, maker.publicKey, m.escrow, maker.publicKey, m.claimHalf.spend)], [maker])).ok, false, 'no claim before ready');
  const rd = await send(c, [P.ixReady(pid, locker.publicKey, m.escrow)], [locker]);
  assert.ok(rd.ok, rd.err);
  const r = await send(c, [P.ixClaim(pid, maker.publicKey, m.escrow, maker.publicKey, m.claimHalf.spend)], [maker]);
  assert.ok(r.ok, r.err);
  assert.equal((await escrowOf(m.escrow))!.state, P.ST.CLAIMED);
}

before(async () => {
  admin = loadKeypair('.run/keys/admin.json');
  await fund(c, admin.publicKey, 50);
  [maker, user, pool, wt] = await Promise.all([20, 5, 40, 1].map((s) => newFunded(c, s)));
  // config + a registered maker (fee 0.5%)
  const hk = Keypair.generate();
  coin = Keypair.generate();
  const mintRent = await c.getMinimumBalanceForRentExemption(82);
  for (const m of [hk, coin]) {
    const r = await send(c, [
      SystemProgram.createAccount({ fromPubkey: admin.publicKey, newAccountPubkey: m.publicKey, lamports: mintRent, space: 82, programId: TOKEN }),
      new TransactionInstruction({ programId: TOKEN, keys: [meta(m.publicKey)], data: Buffer.concat([Buffer.from([20, 6]), admin.publicKey.toBuffer(), Buffer.from([0])]) }),
    ], [admin, m]);
    assert.ok(r.ok, r.err);
  }
  // (a validator another suite already configured keeps its config)
  const cfgOk = (await c.getAccountInfo(P.pda.config(pid))) ? { ok: true, err: '' } : await send(c, [P.ixInitConfig(pid, admin.publicKey, {
    feeRecipient: admin.publicKey, halfkeyMint: hk.publicKey, feeBps: 50, holderFeeBps: 25, holderMin: 1000n, minBond: 2n * SOL, maxSwap: 5n * SOL,
    maxOpenTvl: 40n * SOL, minT0: 1, maxT0: 3600, minWindow: 1, maxWindow: 7200, unbondSecs: 12,
  })], [admin]);
  assert.ok(cfgOk.ok, cfgOk.err);
  assert.ok((await send(c, [P.ixRegisterMaker(pid, maker.publicKey, 2n * SOL, { min: SOL / 1000n, max: 5n * SOL, directions: 3, spreadBps: 100, endpoint: 'https://maker.example' })], [maker])).ok);
  // fake DEX: the pool holds 30 wSOL and 1e12 COIN and takes the user as delegate on both; the user holds 1e9 COIN
  const poolWsol = ata(pool.publicKey, WSOL), poolCoin = ata(pool.publicKey, coin.publicKey), userCoin = ata(user.publicKey, coin.publicKey);
  const mintTo = (dst: PublicKey, n: bigint) => new TransactionInstruction({ programId: TOKEN, keys: [meta(coin.publicKey), meta(dst), meta(admin.publicKey, true, false)], data: u64(7, n) });
  let r = await send(c, [createAta(admin.publicKey, pool.publicKey, WSOL), SystemProgram.transfer({ fromPubkey: pool.publicKey, toPubkey: poolWsol, lamports: 30n * SOL }), tSync(poolWsol),
    createAta(admin.publicKey, pool.publicKey, coin.publicKey), createAta(admin.publicKey, user.publicKey, coin.publicKey)], [admin, pool]);
  assert.ok(r.ok, r.err);
  r = await send(c, [mintTo(poolCoin, 1_000_000_000_000n), mintTo(userCoin, 1_000_000_000n), tApprove(poolWsol, user.publicKey, pool.publicKey, 30n * SOL), tApprove(poolCoin, user.publicKey, pool.publicKey, 1_000_000_000_000n)], [admin, pool]);
  assert.ok(r.ok, r.err);
});

test('sell any coin, ONE transaction: route -> consent + lock in the same signature -> maker claims', async () => {
  const amountIn = 120_000_000n, out = 400_000_000n; // 120 COIN -> 0.4 SOL
  const route = await J.buildRoute({ inputMint: coin.publicKey.toBase58(), outputMint: J.WSOL, amount: amountIn, taker: user.publicKey.toBase58() }, { fetch: fetchOf(fakeBuild('sell', amountIn, out, user.publicKey)) });
  assert.equal(route.minOut, 396_000_000n);
  const sw = J.routeInstructions(route, user.publicKey, FAKE);
  const m = makerLock(user.publicKey, route.minOut);
  const { blockhash } = await c.getLatestBlockhash('confirmed');
  const comp = J.composeSell({ user: user.publicKey, blockhash, route, swap: sw, alts: await J.loadAlts(c, route), lockIxs: m.ixs, lockLamports: route.minOut, memo: J.soldMemo({ swapId: m.swapId, lamports: route.minOut }) });
  assert.equal(comp.mode, 'one');
  // the pre-signing simulation: the route pays this wallet, so the SOL change stays within the lock + rent + fees
  await J.simulateCheck(c, comp.txs[0], user.publicKey, { minLamportsDelta: J.sellMinDelta(comp, route, route.minOut) });
  // the same route claiming more than it pays (minimum above what the pool delivers) is caught before signing
  await assert.rejects(J.simulateCheck(c, comp.txs[0], user.publicKey, { minLamportsDelta: J.sellMinDelta(comp, { ...route, minOut: route.minOut + 10_000_000n }, route.minOut) }), /would not pay/);
  const [sol0, coin0] = [await bal(user.publicKey), await tok(ata(user.publicKey, coin.publicKey))];
  const r = await sendV0(comp.txs[0], user);
  assert.ok(r.ok, JSON.stringify(r.err) + r.logs.slice(-4).join('\n'));
  const e = (await escrowOf(m.escrow))!;
  assert.equal(e.state, P.ST.LOCKED);
  assert.equal(e.amount, route.minOut);
  assert.equal(coin0 - (await tok(ata(user.publicKey, coin.publicKey))), amountIn);
  // the wallet keeps the unused guard (out - lock) and pays the record rent + the network fee
  assert.equal((await bal(user.publicKey)) - sol0, out - route.minOut - J.ESCROW_RENT - r.fee);
  assert.equal(r.fee, comp.feeLamports);
  assert.equal(await c.getAccountInfo(J.wsolAccount(user.publicKey)), null, 'temporary wSOL account closed');
  assert.deepEqual(await J.findUnlocked(c, pid, user.publicKey), []);
  await claimAfterReady(m);
});

test('sell, TWO transactions, the lock fails: the SOL is found from chain, resumed with a fresh lock, claimed', async () => {
  const amountIn = 60_000_000n, out = 200_000_000n;
  const route = await J.buildRoute({ inputMint: coin.publicKey.toBase58(), outputMint: J.WSOL, amount: amountIn, taker: user.publicKey.toBase58() }, { fetch: fetchOf(fakeBuild('sell', amountIn, out, user.publicKey)) });
  const sw = J.routeInstructions(route, user.publicKey, FAKE);
  // the maker's consent has already expired by the time the lock lands: the lock fails, the swap does not
  const m = makerLock(user.publicKey, route.minOut, { consentExpiry: (await chainTime(c)) - 120 }); // chain clock: a long-running test validator lags wall time
  const { blockhash } = await c.getLatestBlockhash('confirmed');
  const comp = J.composeSell({ user: user.publicKey, blockhash, route, swap: sw, alts: [], lockIxs: m.ixs, lockLamports: route.minOut, memo: J.soldMemo({ swapId: m.swapId, lamports: route.minOut }), force: 'two' });
  assert.equal(comp.mode, 'two');
  const sol0 = await bal(user.publicKey);
  const r1 = await sendV0(comp.txs[0], user);
  assert.ok(r1.ok, JSON.stringify(r1.err));
  const r2 = await sendV0(comp.txs[1], user);
  assert.equal(r2.ok, false, 'lock must fail (expired consent)');
  assert.equal(await escrowOf(m.escrow), null);
  assert.ok((await bal(user.publicKey)) - sol0 > route.minOut - 100_000n, 'the SOL from the sale is in the wallet');
  // any device: the swap's memo names the swap id and the SOL it guaranteed
  await sleep(500);
  const pend = await J.findUnlocked(c, pid, user.publicKey);
  assert.equal(pend.length, 1);
  assert.equal(pend[0].swapId, K.toHex(m.swapId));
  assert.equal(pend[0].lamports, route.minOut);
  assert.equal(pend[0].sig, r1.sig);
  assert.equal(pend[0].kind, 'swap');
  // a stranger's memos can neither invent a sale for this wallet nor mark this one as locked
  const stranger = await newFunded(c, 1);
  const spoof = await send(c, [SystemProgram.transfer({ fromPubkey: stranger.publicKey, toPubkey: user.publicKey, lamports: 1n }),
    J.memoIx(J.soldMemo({ swapId: new Uint8Array(32).fill(7), lamports: 50n * SOL, kind: 'pay', link: 'evil' })), J.memoIx(J.lockMemo(pend[0].swapId))], [stranger]);
  assert.ok(spoof.ok, spoof.err);
  assert.deepEqual((await J.findUnlocked(c, pid, user.publicKey)).map((x) => x.swapId), [pend[0].swapId]);
  // resume: a fresh quote/consent, a plain SOL lock carrying the "lock" memo for the original id
  const m2 = makerLock(user.publicKey, pend[0].lamports);
  const rr = await send(c, [J.memoIx(J.lockMemo(pend[0].swapId)), ...m2.ixs], [user]);
  assert.ok(rr.ok, rr.err);
  assert.equal((await escrowOf(m2.escrow))!.amount, route.minOut);
  assert.deepEqual(await J.findUnlocked(c, pid, user.publicKey), []);
  await claimAfterReady(m2);
});

test('sell, TWO transactions that both land: nothing pending, even after the escrow is settled and closed', async () => {
  const amountIn = 30_000_000n, out = 100_000_000n;
  const route = await J.buildRoute({ inputMint: coin.publicKey.toBase58(), outputMint: J.WSOL, amount: amountIn, taker: user.publicKey.toBase58() }, { fetch: fetchOf(fakeBuild('sell', amountIn, out, user.publicKey)) });
  const m = makerLock(user.publicKey, route.minOut);
  const { blockhash } = await c.getLatestBlockhash('confirmed');
  const comp = J.composeSell({ user: user.publicKey, blockhash, route, swap: J.routeInstructions(route, user.publicKey, FAKE), alts: [], lockIxs: m.ixs, lockLamports: route.minOut, memo: J.soldMemo({ swapId: m.swapId, lamports: route.minOut }), force: 'two' });
  for (const t of comp.txs) assert.ok((await sendV0(t, user)).ok);
  assert.deepEqual(await J.findUnlocked(c, pid, user.publicKey), []);
  await claimAfterReady(m);
  assert.ok((await send(c, [P.ixClose(pid, user.publicKey, m.escrow)], [user])).ok);
  assert.equal(await escrowOf(m.escrow), null);
  assert.deepEqual(await J.findUnlocked(c, pid, user.publicKey), [], 'a closed escrow has history: still resolved');
});

test('XMR -> coin: the maker locks SOL, the user claims it, then the optional Jupiter buy spends the claim only', async () => {
  // maker locks 0.5 SOL for the user (XMR -> SOL); the user's XMR arrived, maker says ready, user claims
  const swapId = K.newSwapId(), claimHalf = K.randomHalf(), refundHalf = K.randomHalf();
  const shared = K.sharedWallet(claimHalf.spendPub, refundHalf.spendPub, refundHalf.view, 'stagenet');
  const lock: P.LockParams = {
    swapId, claimer: user.publicKey, direction: 2, amount: SOL / 2n, xmrAmount: 1n, claimPoint: claimHalf.spendPub, refundPoint: refundHalf.spendPub,
    viewPub: shared.viewPub, quoteHash: new Uint8Array(32), t0Secs: 600, windowSecs: 600, watchtowers: [wt.publicKey], makerAuthority: maker.publicKey, consentExpiry: 0, feeBps: 50,
  };
  const escrow = P.pda.escrow(pid, maker.publicKey, swapId);
  assert.ok((await send(c, [P.ixLock(pid, maker.publicKey, lock)], [maker])).ok);
  assert.ok((await send(c, [P.ixReady(pid, maker.publicKey, escrow)], [maker])).ok);
  const before = await bal(user.publicKey);
  assert.ok((await send(c, [P.ixClaim(pid, user.publicKey, escrow, maker.publicKey, claimHalf.spend)], [user], wt)).ok); // relayer pays the fee
  const received = (await bal(user.publicKey)) - before;
  assert.equal(received, SOL / 2n - (SOL / 2n) * 50n / 10_000n);
  // the buy: what the claim paid, never the wallet's fee reserve
  const spend = J.buyAmount(received, await bal(user.publicKey));
  assert.equal(spend, received);
  const coinOut = 1_234_000n;
  const route = await J.buildRoute({ inputMint: J.WSOL, outputMint: coin.publicKey.toBase58(), amount: spend, taker: user.publicKey.toBase58() }, { fetch: fetchOf(fakeBuild('buy', spend, coinOut, user.publicKey)) });
  const { blockhash } = await c.getLatestBlockhash('confirmed');
  const comp = J.composeBuy({ user: user.publicKey, blockhash, swap: J.routeInstructions(route, user.publicKey, FAKE), alts: [] });
  await J.simulateCheck(c, comp.txs[0], user.publicKey, { tokenAccount: J.buyOutAccount(user.publicKey, coin.publicKey.toBase58()), minTokenDelta: route.minOut });
  // a route that pays the coin to someone else is refused before anything is built
  const evil = fakeBuild('buy', spend, coinOut, user.publicKey);
  evil.swapInstruction = raw(tTransfer(ata(pool.publicKey, coin.publicKey), ata(pool.publicKey, coin.publicKey), user.publicKey, coinOut));
  const evilRoute = await J.buildRoute({ inputMint: J.WSOL, outputMint: coin.publicKey.toBase58(), amount: spend, taker: user.publicKey.toBase58() }, { fetch: fetchOf(evil) });
  assert.throws(() => J.routeInstructions(evilRoute, user.publicKey, FAKE), /your own account/);
  const [s0, c0] = [await bal(user.publicKey), await tok(ata(user.publicKey, coin.publicKey))];
  const r = await sendV0(comp.txs[0], user);
  assert.ok(r.ok, JSON.stringify(r.err) + r.logs.slice(-4).join('\n'));
  assert.equal((await tok(ata(user.publicKey, coin.publicKey))) - c0, coinOut);
  assert.equal(s0 - (await bal(user.publicKey)), spend + r.fee);
  assert.equal(await c.getAccountInfo(J.wsolAccount(user.publicKey)), null);
});

test('a stranger cannot hide a sold-but-unlocked XMR sale: a transfer to the escrow address (0 lamports, or enough to create it) changes nothing', async () => {
  const amountIn = 20_000_000n, out = 70_000_000n;
  const route = await J.buildRoute({ inputMint: coin.publicKey.toBase58(), outputMint: J.WSOL, amount: amountIn, taker: user.publicKey.toBase58() }, { fetch: fetchOf(fakeBuild('sell', amountIn, out, user.publicKey)) });
  const m = makerLock(user.publicKey, route.minOut);
  const { blockhash } = await c.getLatestBlockhash('confirmed');
  const comp = J.composeSell({ user: user.publicKey, blockhash, route, swap: J.routeInstructions(route, user.publicKey, FAKE), alts: [], lockIxs: m.ixs, lockLamports: route.minOut, memo: J.soldMemo({ swapId: m.swapId, lamports: route.minOut }), force: 'two' });
  assert.ok((await sendV0(comp.txs[0], user)).ok); // sold; the lock is never sent
  const stranger = await newFunded(c, 1);
  assert.ok((await send(c, [SystemProgram.transfer({ fromPubkey: stranger.publicKey, toPubkey: m.escrow, lamports: 0 })], [stranger])).ok);
  assert.ok((await send(c, [SystemProgram.transfer({ fromPubkey: stranger.publicKey, toPubkey: m.escrow, lamports: 1_000_000 })], [stranger])).ok);
  assert.ok(await c.getAccountInfo(m.escrow, 'confirmed'), 'a system account now sits at the escrow address');
  assert.equal(await J.escrowEverLocked(c, m.escrow, user.publicKey, pid), false);
  await sleep(500);
  const pend = await J.findUnlocked(c, pid, user.publicKey);
  assert.deepEqual(pend.map((p) => p.swapId), [K.toHex(m.swapId)], 'still offered back');
  // resume as the page does: a fresh lock carrying the "lock" memo
  const m2 = makerLock(user.publicKey, pend[0].lamports);
  const rr = await send(c, [J.memoIx(J.lockMemo(pend[0].swapId)), ...m2.ixs], [user]);
  assert.ok(rr.ok, rr.err);
  assert.equal(J.isOwnLock(await c.getAccountInfo(m2.escrow, 'confirmed'), pid, user.publicKey, 'swap'), true);
  assert.deepEqual(await J.findUnlocked(c, pid, user.publicKey), []);
  await claimAfterReady(m2);
});
