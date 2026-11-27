// Any coin <-> XMR / ZEC: Jupiter route parsing, instruction checks, transaction shape, the all-in quote and
// the in-between state. No network: real /swap/v2/build answers are replayed from fixtures/.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { AddressLookupTableAccount, Keypair, PublicKey, TransactionInstruction } from '@solana/web3.js';
import { ed25519 } from '@noble/curves/ed25519';
import * as J from './jupiter.ts';
import * as P from './program.ts';
import * as K from './keys.ts';
import * as H from './htlc.ts';
import * as ZS from './zecswap.ts';

const fx = (f: string) => JSON.parse(fs.readFileSync(new URL(`./fixtures/${f}`, import.meta.url), 'utf8'));
const SELL = fx('jup-sell-bonk.json'), BUY = fx('jup-buy-bonk.json');
const TAKER = new PublicKey(fx('taker.json').taker);
const BONK = 'DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263';
const pid = Keypair.generate().publicKey;
const N_PAD = 10;

function res(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers });
}
const fetchOf = (fn: (url: string) => Response) => (async (u: any) => fn(String(u))) as typeof fetch;
const sellRoute = (over: Record<string, unknown> = {}) =>
  J.parseRoute({ ...SELL, ...over }, { inputMint: BONK, outputMint: J.WSOL, amount: BigInt(SELL.inAmount), taker: TAKER.toBase58(), slippageBps: 100 }, 1);

function altsOf(d: any): AddressLookupTableAccount[] {
  return Object.entries(d.addressesByLookupTableAddress as Record<string, string[]>).map(([k, xs]) => new AddressLookupTableAccount({
    key: new PublicKey(k), state: { deactivationSlot: BigInt('18446744073709551615'), lastExtendedSlot: 0, lastExtendedSlotStartIndex: 0, authority: undefined, addresses: xs.map((x) => new PublicKey(x)) },
  }));
}

/** The real consent + lock for `lamports`, signed by a throwaway maker (as taker.prepareSolToXmr returns them). */
function lockIxs(user: PublicKey, lamports: bigint) {
  const maker = Keypair.generate(), h = K.randomHalf(), m = K.randomHalf();
  const lock: P.LockParams = {
    swapId: K.newSwapId(), claimer: maker.publicKey, direction: 1, amount: lamports, xmrAmount: 4_100_000_000n,
    claimPoint: m.spendPub, refundPoint: h.spendPub, viewPub: h.viewPub, quoteHash: new Uint8Array(32).fill(3), t0Secs: 3000, windowSecs: 7200,
    watchtowers: [Keypair.generate().publicKey, Keypair.generate().publicKey], makerAuthority: maker.publicKey, consentExpiry: 1, feeBps: 50,
  };
  const d = P.consentDigest(pid, user, lock);
  return { swapId: lock.swapId, ixs: [P.ixConsent(maker.publicKey, d, ed25519.sign(d, maker.secretKey.slice(0, 32))), P.ixLock(pid, user, lock)] };
}

// ---------------------------------------------------------------- Jupiter answers
test('buildRoute: asks /swap/v2/build ExactIn with the guard, parses a real answer', async () => {
  let asked = '';
  const r = await J.buildRoute({ inputMint: BONK, outputMint: J.WSOL, amount: BigInt(SELL.inAmount), taker: TAKER.toBase58() },
    { fetch: fetchOf((u) => { asked = u; return res(200, SELL); }), now: () => 42 });
  const u = new URL(asked);
  assert.equal(u.origin + u.pathname, 'https://api.jup.ag/swap/v2/build');
  assert.equal(u.searchParams.get('slippageBps'), '100');
  assert.equal(u.searchParams.get('maxAccounts'), '20');
  assert.equal(u.searchParams.get('taker'), TAKER.toBase58());
  assert.equal(r.inAmount, 120_000_000_000n);
  assert.equal(r.outAmount, 38_990_000n);
  assert.equal(r.minOut, 38_600_100n);
  assert.equal(r.fetchedAt, 42);
  assert.deepEqual(r.labels, ['Scorch']);
  assert.ok(Math.abs(r.priceImpact - 0.00084) < 1e-5);
});

test('buildRoute: refuses answers that are not what was asked', () => {
  assert.throws(() => sellRoute({ outputMint: J.USDC }), /different coins/);
  assert.throws(() => sellRoute({ swapMode: 'ExactOut' }), /swap mode/);
  assert.throws(() => sellRoute({ inAmount: '1' }), /different amount/);
  assert.throws(() => sellRoute({ slippageBps: 300 }), /slippage/);
  assert.throws(() => sellRoute({ otherAmountThreshold: '38990001' }), /above its quote/);
  // a minimum far under the quote (an invitation to sandwich the swap) is refused
  assert.throws(() => sellRoute({ otherAmountThreshold: '30000000' }), /below the slippage guard/);
  assert.throws(() => sellRoute({ outAmount: '0', otherAmountThreshold: '0' }), J.NoRoute);
  assert.throws(() => sellRoute({ swapInstruction: null }), J.NoRoute);
  // unreadable impact counts as 100% (refused), never as 0
  assert.equal(sellRoute({ priceImpactPct: 'n/a' }).priceImpact, 1);
});

test('429: a JupiterBusy with the retry time from x-ratelimit-reset; no route; unreachable', async () => {
  const now = () => 1_793_795_000_000;
  await assert.rejects(J.buildRoute({ inputMint: BONK, outputMint: J.WSOL, amount: 1n, taker: TAKER.toBase58() },
    { now, fetch: fetchOf(() => res(429, 'Too Many Requests', { 'x-ratelimit-reset': '1793795004' })) }),
  (e: any) => e instanceof J.JupiterBusy && e.retryAt === 1_793_795_004_000);
  await assert.rejects(J.searchTokens('bonk', { now, fetch: fetchOf(() => res(429, '')) }), (e: any) => e instanceof J.JupiterBusy && e.retryAt === now() + 2000);
  await assert.rejects(J.buildRoute({ inputMint: BONK, outputMint: J.WSOL, amount: 1n, taker: TAKER.toBase58() },
    { fetch: fetchOf(() => res(400, '{"error":"Could not find any route","errorCode":"COULD_NOT_FIND_ANY_ROUTE"}')) }), J.NoRoute);
  await assert.rejects(J.buildRoute({ inputMint: BONK, outputMint: J.WSOL, amount: 1n, taker: TAKER.toBase58() },
    { fetch: (async () => { throw new TypeError('fetch failed'); }) as any }), /Could not reach Jupiter/);
  await assert.rejects(J.buildRoute({ inputMint: J.WSOL, outputMint: J.WSOL, amount: 1n, taker: TAKER.toBase58() }), /different coins/);
});

test('price impact: warn above 3%, refuse above 10%', () => {
  assert.equal(J.impactLevel({ priceImpact: 0.0008 }), 'ok');
  assert.equal(J.impactLevel({ priceImpact: 0.03 }), 'ok');
  assert.equal(J.impactLevel({ priceImpact: 0.031 }), 'warn');
  assert.equal(J.impactLevel({ priceImpact: 0.10 }), 'warn');
  assert.equal(J.impactLevel({ priceImpact: 0.1001 }), 'refuse');
});

test('tokens: search normalises verified/unverified, puts a pasted CA first, drops junk', async () => {
  const xs = [
    { id: 'BonK1YhkXEGLZzwtcvRTip3gAL9nCeQD7ppZBLXhtTs', symbol: 'bonkSOL', name: 'bonkSOL', decimals: 9, isVerified: true, tags: ['lst'] },
    { id: BONK, symbol: 'Bonk', name: 'Bonk', decimals: 5, tags: ['verified', 'meme'], icon: 'https://arweave.net/x', usdPrice: 3e-6, liquidity: 6e6 },
    { id: 'hqYtLoxviwcsGd1QPAg8vxWbDgfJCYmo6K3jFUGs8i3', symbol: 'BONKAI', name: 'x', decimals: 6, tags: ['unknown'], icon: 'javascript:alert(1)' },
    { id: 'not a key', symbol: 'BAD', decimals: 6 }, { id: BONK.slice(0, 40), decimals: 99 },
  ];
  const out = await J.searchTokens(BONK, { fetch: fetchOf(() => res(200, xs)) });
  assert.equal(out.length, 3);
  assert.equal(out[0].mint, BONK);
  assert.equal(out[0].verified, true);
  assert.equal(out[0].usd, 3e-6);
  assert.equal(out[1].verified, true);
  assert.equal(out[2].verified, false);
  assert.equal(out[2].icon, undefined, 'only https icons');
  assert.deepEqual(await J.searchTokens('  '), []);
});

// ---------------------------------------------------------------- instruction checks
test('routeInstructions: real sell and buy routes pass; compute budget dropped, price read', () => {
  const s = J.routeInstructions(sellRoute(), TAKER);
  assert.equal(s.ixs.length, 3); // create wSOL account, swap, close wSOL
  assert.equal(s.cuPrice, 10_000);
  assert.ok(s.ixs.every((ix) => !ix.programId.equals(new PublicKey('ComputeBudget111111111111111111111111111111'))));
  const buy = J.parseRoute(BUY, { inputMint: J.WSOL, outputMint: BONK, amount: 100_000_000n, taker: TAKER.toBase58(), slippageBps: 100 }, 1);
  const b = J.routeInstructions(buy, TAKER);
  assert.equal(b.ixs.length, 6); // wSOL account, wrap transfer, syncNative, BONK account, swap, close wSOL
});

test('routeInstructions: refuses other signers, other programs, SOL or tokens moved elsewhere', () => {
  const other = Keypair.generate().publicKey.toBase58();
  const mut = (f: (d: any) => void) => { const d = structuredClone(BUY); f(d); return J.parseRoute(d, { inputMint: J.WSOL, outputMint: BONK, amount: 100_000_000n, taker: TAKER.toBase58(), slippageBps: 100 }, 1); };
  assert.throws(() => J.routeInstructions(sellRoute(), Keypair.generate().publicKey), /different wallet/);
  assert.throws(() => J.routeInstructions(mut((d) => { d.swapInstruction.accounts[1] = { pubkey: other, isSigner: true, isWritable: true }; }), TAKER), /unexpected signer/);
  assert.throws(() => J.routeInstructions(mut((d) => { d.swapInstruction.programId = other; }), TAKER), /unexpected swap program/);
  assert.throws(() => J.routeInstructions(mut((d) => { d.setupInstructions[1].accounts[1].pubkey = other; }), TAKER), /moves SOL/);
  assert.throws(() => J.routeInstructions(mut((d) => { d.otherInstructions = [{ programId: other, accounts: [], data: '' }]; }), TAKER), /unexpected program/);
  // a token transfer (3) or a close of the wSOL account to someone else
  assert.throws(() => J.routeInstructions(mut((d) => { d.setupInstructions[2].data = Buffer.from([3, 1, 0, 0, 0, 0, 0, 0, 0]).toString('base64'); }), TAKER), /token instruction/);
  assert.throws(() => J.routeInstructions(mut((d) => { d.cleanupInstruction.accounts[1].pubkey = other; }), TAKER), /token instruction/);
  assert.throws(() => J.routeInstructions(mut((d) => { d.setupInstructions[3].accounts[2].pubkey = other; }), TAKER), /someone else/);
  assert.throws(() => J.routeInstructions(mut((d) => { d.computeBudgetInstructions = [{ programId: other, accounts: [], data: 'AxAnAAAAAAAA' }]; }), TAKER), /compute budget/);
  // the swap pays into someone else's coin account
  assert.throws(() => J.routeInstructions(mut((d) => { for (const a of d.swapInstruction.accounts) if (a.pubkey === d.setupInstructions[3].accounts[1].pubkey) a.pubkey = other; }), TAKER), /your own account/);
  assert.throws(() => J.routeInstructions(J.parseRoute({ ...SELL, swapInstruction: { ...SELL.swapInstruction, accounts: SELL.swapInstruction.accounts.map((a: any) => (a.pubkey === SELL.setupInstructions[0].accounts[1].pubkey ? { ...a, pubkey: other } : a)) } },
    { inputMint: BONK, outputMint: J.WSOL, amount: BigInt(SELL.inAmount), taker: TAKER.toBase58(), slippageBps: 100 }, 1), TAKER), /your own account/);
  // priority price is clamped
  assert.equal(J.routeInstructions(mut((d) => { d.computeBudgetInstructions[0].data = Buffer.from([3, ...new Uint8Array(new BigUint64Array([10n ** 12n]).buffer)]).toString('base64'); }), TAKER).cuPrice, J.CU_PRICE.max);
});

test('loadAlts: tables come from our RPC and must match what Jupiter listed', async () => {
  const r = sellRoute();
  const alts = altsOf(SELL);
  const conn = (xs: (AddressLookupTableAccount | null)[]) => ({ getAddressLookupTable: async (k: PublicKey) => ({ context: { slot: 1 }, value: xs.find((a) => a?.key.equals(k)) ?? null }) });
  assert.equal((await J.loadAlts(conn(alts) as any, r)).length, alts.length);
  await assert.rejects(J.loadAlts(conn([]) as any, r), /missing/);
  const bad = alts.map((a) => new AddressLookupTableAccount({ key: a.key, state: { ...a.state, addresses: [Keypair.generate().publicKey, ...a.state.addresses.slice(1)] } }));
  await assert.rejects(J.loadAlts(conn(bad) as any, r), /does not match/);
});

// ---------------------------------------------------------------- transaction shape
test('composeSell: a real BONK route + consent + lock fit ONE transaction', () => {
  const r = sellRoute(), sw = J.routeInstructions(r, TAKER);
  const { ixs } = lockIxs(TAKER, r.minOut);
  const c = J.composeSell({ user: TAKER, blockhash: '11111111111111111111111111111111', route: r, swap: sw, alts: altsOf(SELL), lockIxs: ixs, lockLamports: r.minOut, memo: 'x' });
  assert.equal(c.mode, 'one');
  assert.equal(c.txs.length, 1);
  const tx = c.txs[0];
  assert.ok(tx.serialize().length <= 1232);
  const keys = tx.message.getAccountKeys({ addressLookupTableAccounts: altsOf(SELL) });
  const progs = tx.message.compiledInstructions.map((ix) => keys.get(ix.programIdIndex)!.toBase58());
  // consent sits right before the lock (the program checks the previous instruction)
  assert.equal(progs.at(-1), pid.toBase58());
  assert.equal(progs.at(-2), 'Ed25519SigVerify111111111111111111111111111');
  assert.equal(progs.filter((p) => p === J.MEMO_PROGRAM).length, 0);
  assert.equal(c.feeLamports, 2n * 5_000n + 6_000n); // wallet + consent signatures, 600k CU at 10k micro-lamports
});

test('composeSell: two transactions when forced or too big; the swap carries the memo; never lock more than the minimum', () => {
  const r = sellRoute(), sw = J.routeInstructions(r, TAKER);
  const { ixs, swapId } = lockIxs(TAKER, r.minOut);
  const memo = J.soldMemo({ swapId, lamports: r.minOut });
  const c = J.composeSell({ user: TAKER, blockhash: '11111111111111111111111111111111', route: r, swap: sw, alts: altsOf(SELL), lockIxs: ixs, lockLamports: r.minOut, memo, force: 'two' });
  assert.equal(c.mode, 'two');
  const [t1, t2] = c.txs;
  const k1 = t1.message.getAccountKeys({ addressLookupTableAccounts: altsOf(SELL) });
  const memoIx = t1.message.compiledInstructions.find((ix) => k1.get(ix.programIdIndex)!.toBase58() === J.MEMO_PROGRAM)!;
  assert.equal(Buffer.from(memoIx.data).toString(), memo);
  assert.equal(t2.message.compiledInstructions.length, 4); // budget x2, consent, lock
  assert.equal(t1.message.recentBlockhash, t2.message.recentBlockhash);
  // too big for one: pad the route with many unique accounts (no lookup tables)
  const big = { ...sw, ixs: [...sw.ixs, new TransactionInstruction({ programId: new PublicKey(J.JUP_PROGRAM), keys: Array.from({ length: N_PAD }, () => ({ pubkey: Keypair.generate().publicKey, isSigner: false, isWritable: false })), data: Buffer.alloc(8) })] };
  assert.equal(J.composeSell({ user: TAKER, blockhash: '11111111111111111111111111111111', route: r, swap: big, alts: altsOf(SELL), lockIxs: ixs, lockLamports: r.minOut, memo }).mode, 'two');
  assert.throws(() => J.composeSell({ user: TAKER, blockhash: '11111111111111111111111111111111', route: r, swap: sw, alts: [], lockIxs: ixs, lockLamports: r.minOut + 1n, memo }), /larger than the route guarantees/);
});

test('composeBuy + buyAmount: the claimed SOL, never the fee reserve', () => {
  const buy = J.parseRoute(BUY, { inputMint: J.WSOL, outputMint: BONK, amount: 100_000_000n, taker: TAKER.toBase58(), slippageBps: 100 }, 1);
  const c = J.composeBuy({ user: TAKER, blockhash: '11111111111111111111111111111111', swap: J.routeInstructions(buy, TAKER), alts: altsOf(BUY) });
  assert.equal(c.txs.length, 1);
  assert.equal(J.buyAmount(995_000_000n, 1_000_000_000n), 995_000_000n);        // claim 1 SOL - 0.5% fee
  assert.equal(J.buyAmount(995_000_000n, 997_000_000n), 992_000_000n);          // wallet had less: keep 0.005
  assert.equal(J.buyAmount(995_000_000n, 4_000_000n), 0n);
});

// ---------------------------------------------------------------- the all-in quote
test('sellQuote: 1.2M BONK -> XMR, every fee itemised', () => {
  // 120,000,000,000 base units = 1,200,000 BONK (5 decimals); real route numbers from the fixture
  const r = sellRoute();
  const q = J.sellQuote({
    route: r, lockLamports: r.minOut, piconero: 4_100_000_000n, spreadBps: 120, feeBps: 50,
    prices: { coinUsd: 3.0e-6, solUsd: 93, xmrUsd: 870 }, coinDecimals: 5,
  });
  assert.equal(q.payAmount, 120_000_000_000n);
  assert.equal(q.lockLamports, 38_600_100n);
  assert.equal(q.changeLamports, 389_900n);   // route out - lock: the unused slippage guard, back as SOL
  assert.equal(q.priceImpactBps, 8);
  assert.equal(q.costBps, 8 + 120 + 50);
  assert.equal(q.slippageBps, 100);
  assert.equal(q.depositLamports, 4_008_960n);
  assert.equal(q.feeLamports, J.estimateSellFee('one'));
  assert.equal(q.solNeeded, q.feeLamports + 4_008_960n + 890_880n);
  assert.ok(Math.abs(q.usd!.pay - 3.6) < 1e-9);
  assert.ok(Math.abs(q.usd!.get - 3.567) < 1e-9);
  assert.throws(() => J.sellQuote({ route: r, lockLamports: r.minOut + 1n, piconero: 1n, spreadBps: 0, feeBps: 50 }), /more SOL than the route guarantees/);
  assert.equal(J.estimateSellFee('two'), 15_000n + 22_500n + 6_000n);
});

// ---------------------------------------------------------------- the in-between state
test('memos: round trip, as getSignaturesForAddress returns them', () => {
  const id = new Uint8Array(32).fill(0xab);
  const m = J.soldMemo({ swapId: id, lamports: 386_001n });
  assert.equal(m, `halfkey:any:v1:sold:${'ab'.repeat(32)}:386001:swap`);
  assert.deepEqual(J.parseMemos(`[${m.length}] ${m}`), [{ t: 'sold', swapId: 'ab'.repeat(32), lamports: 386_001n, kind: 'swap', link: undefined }]);
  const p = J.soldMemo({ swapId: id, lamports: 5n, kind: 'pay', link: 'Alice<x>' });
  assert.ok(p.endsWith(':pay:alicex'), p); // link names are lowercase; junk dropped
  const both = `[10] hello; [${p.length}] ${p}; [80] ${J.lockMemo(id)}`;
  assert.deepEqual(J.parseMemos(both).map((x) => x.t), ['sold', 'lock']);
  assert.deepEqual(J.parseMemos(null), []);
  assert.deepEqual(J.parseMemos('halfkey:any:v1:sold:zz'), []);
});

/** An escrow account as the chain returns it: a real lock (program-owned, the kind's size + discriminator, the locker) unless overridden. */
function lockAcc(kind: J.SoldKind, o: { locker?: PublicKey; owner?: PublicKey; disc?: number } = {}) {
  const d = Buffer.alloc(kind === 'zec' ? H.HTLC_LEN : P.ESCROW_LEN);
  d[0] = o.disc ?? (kind === 'zec' ? H.DISC_HTLC : 0xe5);
  (o.locker ?? USER).toBuffer().copy(d, 40);
  return { owner: o.owner ?? pid, data: d, lamports: 1, executable: false };
}
/**
 * `escrows`: accounts at escrow addresses. `history`: escrow addresses whose history holds a failed tx
 * and a successful one; by default that one is the wallet's own HALFKEY lock, `strangers` makes it a
 * stranger's transfer (or the wallet's own tx that does not call HALFKEY).
 */
function fakeChain(rows: { sig: string; memo?: string | null; err?: unknown; blockTime?: number; payer?: PublicKey; gain?: bigint }[], escrows: Map<string, unknown> = new Map(), history: Set<string> = new Set(), strangers: Map<string, 'stranger' | 'not-halfkey'> = new Map()) {
  const SYS = new PublicKey('11111111111111111111111111111111'), other = Keypair.generate().publicKey;
  const progTx = (signer: PublicKey, prog: PublicKey) => ({ transaction: { message: { staticAccountKeys: [signer, prog], header: { numRequiredSignatures: 1 }, compiledInstructions: [{ programIdIndex: 1, accountKeyIndexes: [], data: new Uint8Array() }] } }, meta: { err: null, preBalances: [0, 0], postBalances: [0, 0], fee: 5000 } });
  return {
    getTransaction: async (sig: string) => {
      if (sig === 'h') return progTx(USER, pid);
      if (sig === 'h-stranger') return progTx(other, SYS);
      if (sig === 'h-not-halfkey') return progTx(USER, SYS);
      const r = rows.find((x) => x.sig === sig);
      if (!r) return null;
      return { transaction: { message: { staticAccountKeys: [r.payer ?? USER], header: { numRequiredSignatures: 1 }, compiledInstructions: [] } }, meta: { err: r.err ?? null, preBalances: [1_000_000_000], postBalances: [1_000_000_000 + Number(r.gain ?? 10n ** 9n) - 5000], fee: 5000 } };
    },
    getSignaturesForAddress: async (a: PublicKey) => (a.equals(USER) ? rows.map((r) => ({ signature: r.sig, slot: 1, err: r.err ?? null, memo: r.memo ?? null, blockTime: r.blockTime ?? 1000 }))
      : history.has(a.toBase58()) ? [{ signature: 'f', slot: 2, err: { x: 1 }, memo: null, blockTime: 1101 }, { signature: strangers.has(a.toBase58()) ? `h-${strangers.get(a.toBase58())}` : 'h', slot: 1, err: null, memo: null, blockTime: 1100 }]
      // every other escrow: only the failed lock of a two-transaction sell names it
      : [{ signature: 'failed-lock', slot: 1, err: { InstructionError: [2, 'x'] }, memo: null, blockTime: 1 }]),
    getMultipleAccountsInfo: async (ks: PublicKey[]) => ks.map((k) => (escrows.get(k.toBase58()) ?? null)),
  } as any;
}
const USER = Keypair.generate().publicKey;

test('findUnlocked: sold but never locked shows up on any device; resumed, locked, closed, failed and old do not', async () => {
  const ids = [1, 2, 3, 4, 5, 6].map((n) => new Uint8Array(32).fill(n));
  const esc = (id: Uint8Array) => P.pda.escrow(pid, USER, id).toBase58();
  const rows = [
    { sig: 's1', memo: `[1] ${J.soldMemo({ swapId: ids[0], lamports: 100n })}`, blockTime: 1000 },                // open
    { sig: 's2', memo: `[1] ${J.soldMemo({ swapId: ids[1], lamports: 200n, kind: 'pay', link: 'bob' })}`, blockTime: 1100 }, // open (pay)
    { sig: 's3', memo: `[1] ${J.soldMemo({ swapId: ids[2], lamports: 300n })}` },                                // lock landed
    { sig: 's4', memo: `[1] ${J.soldMemo({ swapId: ids[3], lamports: 400n })}` },                                // resumed elsewhere
    { sig: 'r4', memo: `[1] ${J.lockMemo(ids[3])}` },
    { sig: 's5', memo: `[1] ${J.soldMemo({ swapId: ids[4], lamports: 500n })}`, err: { InstructionError: [2, 'x'] } }, // swap failed
    { sig: 's6', memo: `[1] ${J.soldMemo({ swapId: ids[5], lamports: 600n })}`, blockTime: 1 },                  // too old
    { sig: 'n', memo: null },
  ];
  const closed = new Uint8Array(32).fill(9);
  rows.push({ sig: 's9', memo: `[1] ${J.soldMemo({ swapId: closed, lamports: 900n })}`, blockTime: 1000 }); // locked, settled, closed
  const out = await J.findUnlocked(fakeChain(rows, new Map([[esc(ids[2]), lockAcc('swap')]]), new Set([esc(closed)])), pid, USER, { nowSecs: 1200, maxAgeSecs: 1000 });
  assert.deepEqual(out.map((x) => x.sig), ['s2', 's1']);
  assert.equal(out[0].kind, 'pay');
  assert.equal(out[0].link, 'bob');
  assert.equal(out[1].lamports, 100n);
  assert.equal(out[1].escrow, esc(ids[0]));
  assert.deepEqual(await J.findUnlocked(fakeChain([{ sig: 'x' }]), pid, USER), []);
});

test('findUnlocked: a stranger\'s memo neither invents a sale nor hides one; the amount is capped by what the sale paid', async () => {
  const other = Keypair.generate().publicKey;
  const real = new Uint8Array(32).fill(1), fake = new Uint8Array(32).fill(2);
  const rows = [
    { sig: 'real', memo: `[1] ${J.soldMemo({ swapId: real, lamports: 50n * 10n ** 9n })}`, gain: 386_000_000n },            // memo claims 50 SOL, the sale paid 0.386
    { sig: 'spoof-sold', memo: `[1] ${J.soldMemo({ swapId: fake, lamports: 50n * 10n ** 9n, kind: 'pay', link: 'evil' })}`, payer: other },
    { sig: 'spoof-lock', memo: `[1] ${J.lockMemo(real)}`, payer: other },
    { sig: 'dust', memo: `[1] ${J.soldMemo({ swapId: new Uint8Array(32).fill(3), lamports: 5n })}`, gain: -1n },              // the wallet signed, but gained nothing
  ];
  const out = await J.findUnlocked(fakeChain(rows), pid, USER, { nowSecs: 1200 });
  assert.deepEqual(out.map((x) => x.sig), ['real']);
  assert.equal(out[0].lamports, 386_000_000n);
});

test('localSellState: the recorded two-transaction sell, from chain status', () => {
  assert.equal(J.localSellState({ swapStatus: 'unknown', escrowSeen: false, ageSecs: 10 }), 'sending');
  assert.equal(J.localSellState({ swapStatus: 'unknown', escrowSeen: false, ageSecs: 400 }), 'failed');
  assert.equal(J.localSellState({ swapStatus: 'failed', escrowSeen: false, ageSecs: 10 }), 'failed');
  assert.equal(J.localSellState({ swapStatus: 'success', escrowSeen: false, ageSecs: 10 }), 'unlocked');
  assert.equal(J.localSellState({ swapStatus: 'success', escrowSeen: true, ageSecs: 10 }), 'locked');
  assert.equal(J.localSellState({ swapStatus: 'unknown', escrowSeen: true, ageSecs: 999 }), 'locked');
  // the lock was sent but is not confirmed: never offer "lock now" while it can still land
  assert.equal(J.localSellState({ swapStatus: 'success', escrowSeen: false, ageSecs: 10, lockStatus: 'unknown', lockCanLand: true }), 'locking');
  assert.equal(J.localSellState({ swapStatus: 'success', escrowSeen: false, ageSecs: 400, lockStatus: 'unknown', lockCanLand: false }), 'unlocked');
  assert.equal(J.localSellState({ swapStatus: 'success', escrowSeen: false, ageSecs: 10, lockStatus: 'failed' }), 'unlocked');
  assert.equal(J.localSellState({ swapStatus: 'success', escrowSeen: false, ageSecs: 10, lockStatus: 'success' }), 'locked');
});

// ---------------------------------------------------------------- the ZEC pair (HTLC kind)
/** The real [consent, htlc_lock] for `lamports` (as zecswap.solToZecLockIxs returns them after verifySolToZecOffer). */
function htlcLockIxs(user: PublicKey, lamports: bigint) {
  const maker = Keypair.generate();
  const lock: H.HtlcLockParams = {
    swapId: K.newSwapId(), claimer: maker.publicKey, direction: H.DIR_SOL_TO_ZEC, amount: lamports, zecAmount: 150_000_000n,
    hashlock: new Uint8Array(32).fill(7), quoteHash: new Uint8Array(32).fill(3), t1Secs: 3600, consentExpiry: 1, makerAuthority: maker.publicKey, feeBps: 50,
  };
  const d = H.htlcConsentDigest(pid, user, lock);
  return { swapId: lock.swapId, lock, ixs: ZS.solToZecLockIxs(pid, user, lock, Buffer.from(ed25519.sign(d, maker.secretKey.slice(0, 32))).toString('hex')) };
}

test('ZEC pair: a real BONK route + consent + htlc_lock fit ONE transaction; the consent sits right before the lock', () => {
  const r = sellRoute(), sw = J.routeInstructions(r, TAKER);
  const { ixs } = htlcLockIxs(TAKER, r.minOut);
  const c = J.composeSell({ user: TAKER, blockhash: '11111111111111111111111111111111', route: r, swap: sw, alts: altsOf(SELL), lockIxs: ixs, lockLamports: r.minOut, memo: 'x' });
  assert.equal(c.mode, 'one');
  const keys = c.txs[0].message.getAccountKeys({ addressLookupTableAccounts: altsOf(SELL) });
  const cix = c.txs[0].message.compiledInstructions;
  assert.equal(keys.get(cix.at(-1)!.programIdIndex)!.toBase58(), pid.toBase58());
  assert.equal(cix.at(-1)!.data[0], H.IX.HTLC_LOCK);
  assert.equal(keys.get(cix.at(-2)!.programIdIndex)!.toBase58(), 'Ed25519SigVerify111111111111111111111111111');
  assert.equal(c.feeLamports, J.estimateSellFee('one', J.routeCuPrice(r)));
  // the pre-sign bound uses the HTLC record's rent, which is smaller than the XMR record's
  assert.equal(J.sellMinDelta(c, r, r.minOut, J.HTLC_RENT) - J.sellMinDelta(c, r, r.minOut), J.ESCROW_RENT - J.HTLC_RENT);
  assert.equal(J.HTLC_RENT, BigInt((280 + 128) * 6960));
  assert.equal(J.ESCROW_RENT, BigInt((448 + 128) * 6960));
});

test('ZEC pair: two transactions carry a "zec" sold memo; never lock more than the minimum', () => {
  const r = sellRoute(), sw = J.routeInstructions(r, TAKER);
  const { ixs, swapId } = htlcLockIxs(TAKER, r.minOut);
  const memo = J.soldMemo({ swapId, lamports: r.minOut, kind: 'zec' });
  assert.ok(memo.endsWith(`:${r.minOut}:zec`), memo);
  const c = J.composeSell({ user: TAKER, blockhash: '11111111111111111111111111111111', route: r, swap: sw, alts: altsOf(SELL), lockIxs: ixs, lockLamports: r.minOut, memo, force: 'two' });
  assert.equal(c.mode, 'two');
  const k1 = c.txs[0].message.getAccountKeys({ addressLookupTableAccounts: altsOf(SELL) });
  const m = c.txs[0].message.compiledInstructions.find((ix) => k1.get(ix.programIdIndex)!.toBase58() === J.MEMO_PROGRAM)!;
  assert.equal(Buffer.from(m.data).toString(), memo);
  assert.equal(c.txs[1].message.compiledInstructions.length, 4); // budget x2, consent, htlc_lock
  assert.throws(() => J.composeSell({ user: TAKER, blockhash: '11111111111111111111111111111111', route: r, swap: sw, alts: [], lockIxs: htlcLockIxs(TAKER, r.minOut + 1n).ixs, lockLamports: r.minOut + 1n, memo }), /larger than the route guarantees/);
});

test('ZEC pair memos: round trip; a pay link is never attached to a zec sale; old parsers ignore it', () => {
  const id = new Uint8Array(32).fill(0xcd);
  const m = J.soldMemo({ swapId: id, lamports: 77n, kind: 'zec', link: 'bob' });
  assert.equal(m, `halfkey:any:v1:sold:${'cd'.repeat(32)}:77:zec`);
  assert.deepEqual(J.parseMemos(`[${m.length}] ${m}; [80] ${J.lockMemo(id)}`), [{ t: 'sold', swapId: 'cd'.repeat(32), lamports: 77n, kind: 'zec', link: undefined }, { t: 'lock', swapId: 'cd'.repeat(32) }]);
  // the pre-ZEC parser (kinds swap|pay) skips it rather than reading it as an XMR sale
  const old = [...m.matchAll(/halfkey:any:v1:(sold|lock):([0-9a-f]{64})(?::(\d{1,20}):(swap|pay)(?::([a-z0-9_-]{1,32}))?)?/g)];
  assert.equal(old.length, 1);
  assert.equal(old[0][3], undefined);
});

test('findUnlocked, ZEC pair: looks for the HTLC escrow (seed "htlc"), not the XMR one; locked, closed, resumed and spoofed do not show', async () => {
  const ids = [1, 2, 3, 4, 5].map((n) => new Uint8Array(32).fill(0x40 + n));
  const hesc = (id: Uint8Array) => H.htlcPda(pid, USER, id).toBase58();
  const xesc = (id: Uint8Array) => P.pda.escrow(pid, USER, id).toBase58();
  const other = Keypair.generate().publicKey;
  const rows = [
    { sig: 'z1', memo: `[1] ${J.soldMemo({ swapId: ids[0], lamports: 100n, kind: 'zec' })}`, blockTime: 1000 }, // open
    { sig: 'z2', memo: `[1] ${J.soldMemo({ swapId: ids[1], lamports: 200n, kind: 'zec' })}`, blockTime: 1001 }, // HTLC locked
    { sig: 'z3', memo: `[1] ${J.soldMemo({ swapId: ids[2], lamports: 300n, kind: 'zec' })}`, blockTime: 1002 }, // HTLC settled + closed
    { sig: 'z4', memo: `[1] ${J.soldMemo({ swapId: ids[3], lamports: 400n, kind: 'zec' })}`, blockTime: 1003 }, // resumed (lock memo)
    { sig: 'r4', memo: `[1] ${J.lockMemo(ids[3])}` },
    { sig: 'z5', memo: `[1] ${J.soldMemo({ swapId: ids[4], lamports: 500n, kind: 'zec' })}`, blockTime: 1004 }, // only an XMR escrow with this id exists: still open
    { sig: 'spoof', memo: `[1] ${J.lockMemo(ids[0])}`, payer: other },                                     // a stranger cannot mark z1 locked
  ];
  const out = await J.findUnlocked(fakeChain(rows, new Map([[hesc(ids[1]), lockAcc('zec')], [xesc(ids[4]), lockAcc('swap')]]), new Set([hesc(ids[2])])), pid, USER, { nowSecs: 1200 });
  assert.deepEqual(out.map((x) => x.sig), ['z5', 'z1']);
  assert.equal(out[1].kind, 'zec');
  assert.equal(out[1].escrow, hesc(ids[0]));
  assert.equal(J.soldEscrow(pid, USER, ids[0], 'zec').toBase58(), hesc(ids[0]));
  assert.equal(J.soldEscrow(pid, USER, ids[0], 'swap').toBase58(), xesc(ids[0]));
});

test('coinFor: the coin amount that covers the lock again after the price moved', () => {
  assert.equal(J.coinFor({ inAmount: 1000n, minOut: 500n }, 400n), 1000n);            // still covered: unchanged
  const n = J.coinFor({ inAmount: 1_000_000n, minOut: 480n }, 500n);                  // fell 4%: sell ~4.2% more + 0.5%
  assert.equal(n, 1_046_875n);
  assert.ok((n * 480n) / 1_000_000n >= 500n);
  assert.equal(J.coinFor({ inAmount: 3n, minOut: 7n }, 8n, 0), 4n);                    // rounds up
  assert.throws(() => J.coinFor({ inAmount: 1n, minOut: 0n }, 1n), /empty/);
});

test('sellQuote, ZEC pair: zatoshis, the ZEC price and the HTLC record rent', () => {
  const r = sellRoute();
  const q = J.sellQuote({
    route: r, lockLamports: r.minOut, piconero: 1_500_000n, spreadBps: 120, feeBps: 50, outDecimals: 8, rent: J.HTLC_RENT,
    prices: { coinUsd: 3.0e-6, solUsd: 93, xmrUsd: 240 }, coinDecimals: 5,
  });
  assert.equal(q.depositLamports, J.HTLC_RENT);
  assert.equal(q.solNeeded, q.feeLamports + J.HTLC_RENT + 890_880n);
  assert.ok(Math.abs(q.usd!.get - 3.6) < 1e-9); // 0.015 ZEC at $240
  assert.equal(q.costBps, 8 + 120 + 50);
});

// ---------------------------------------------------------------- review fixes: what counts as locked
test('isOwnLock: only a program-owned escrow of the right kind, size and discriminator, locked by this wallet', () => {
  const other = Keypair.generate().publicKey;
  for (const k of ['swap', 'pay', 'zec'] as const) {
    assert.equal(J.isOwnLock(lockAcc(k), pid, USER, k), true, k);
    assert.equal(J.isOwnLock(lockAcc(k, { owner: new PublicKey('11111111111111111111111111111111') }), pid, USER, k), false, `${k}: a stranger's transfer makes a system account`);
    assert.equal(J.isOwnLock(lockAcc(k, { locker: other }), pid, USER, k), false, `${k}: someone else's lock`);
    assert.equal(J.isOwnLock(lockAcc(k, { disc: 0 }), pid, USER, k), false, `${k}: wrong discriminator`);
    assert.equal(J.isOwnLock({ owner: pid, data: Buffer.alloc(0) }, pid, USER, k), false, `${k}: empty data`);
  }
  assert.equal(J.isOwnLock(lockAcc('swap'), pid, USER, 'zec'), false, 'an XMR escrow is not an HTLC lock');
  assert.equal(J.isOwnLock(lockAcc('zec'), pid, USER, 'swap'), false, 'an HTLC is not an XMR lock');
  assert.equal(J.isOwnLock(null, pid, USER, 'zec'), false);
});

test('findUnlocked: a stranger cannot make an open sale read as locked (funded address, transfer in its history, the wallet\'s non-HALFKEY tx)', async () => {
  const ids = [1, 2, 3, 4].map((n) => new Uint8Array(32).fill(0x60 + n));
  const hesc = (id: Uint8Array) => H.htlcPda(pid, USER, id).toBase58();
  const xesc = (id: Uint8Array) => P.pda.escrow(pid, USER, id).toBase58();
  const rows = [
    { sig: 'a', memo: `[1] ${J.soldMemo({ swapId: ids[0], lamports: 10n, kind: 'zec' })}`, blockTime: 1000 },
    { sig: 'b', memo: `[1] ${J.soldMemo({ swapId: ids[1], lamports: 20n, kind: 'zec' })}`, blockTime: 1001 },
    { sig: 'c', memo: `[1] ${J.soldMemo({ swapId: ids[2], lamports: 30n })}`, blockTime: 1002 },
    { sig: 'd', memo: `[1] ${J.soldMemo({ swapId: ids[3], lamports: 40n })}`, blockTime: 1003 },
  ];
  const sys = new PublicKey('11111111111111111111111111111111');
  const chain = fakeChain(rows,
    new Map<string, unknown>([[hesc(ids[0]), lockAcc('zec', { owner: sys })], [xesc(ids[2]), lockAcc('swap', { owner: sys })]]), // lamports sent to the address
    new Set([hesc(ids[1]), xesc(ids[3])]), new Map([[hesc(ids[1]), 'stranger'], [xesc(ids[3]), 'not-halfkey']]));
  assert.deepEqual((await J.findUnlocked(chain, pid, USER, { nowSecs: 1200 })).map((x) => x.sig), ['d', 'c', 'b', 'a']);
  assert.equal(await J.escrowEverLocked(chain, new PublicKey(hesc(ids[1])), USER, pid), false);
  // the wallet's own HALFKEY lock in the history does count (closed after settlement)
  assert.equal(await J.escrowEverLocked(fakeChain([], new Map(), new Set([hesc(ids[1])])), new PublicKey(hesc(ids[1])), USER, pid), true);
});

test('saleOnChain: own "sold" / "lock" memos for one swap id; a stranger\'s count for nothing', async () => {
  const id = new Uint8Array(32).fill(0x71), hex = '71'.repeat(32), other = Keypair.generate().publicKey;
  const sold = { sig: 's', memo: `[1] ${J.soldMemo({ swapId: id, lamports: 5n, kind: 'zec' })}` };
  const lock = { sig: 'l', memo: `[1] ${J.lockMemo(id)}` };
  assert.deepEqual(await J.saleOnChain(fakeChain([sold]), USER, hex), { sold: true, lockMemo: false });
  assert.deepEqual(await J.saleOnChain(fakeChain([sold, lock]), USER, hex), { sold: true, lockMemo: true });
  assert.deepEqual(await J.saleOnChain(fakeChain([{ ...sold, payer: other }, { ...lock, payer: other }]), USER, hex), { sold: false, lockMemo: false });
  assert.deepEqual(await J.saleOnChain(fakeChain([{ ...sold, err: { x: 1 } }]), USER, hex), { sold: false, lockMemo: false });
  assert.deepEqual(await J.saleOnChain(fakeChain([sold]), USER, 'ab'.repeat(32)), { sold: false, lockMemo: false });
});

test('topUp: the price-fell top-up is capped at 1.25x the quoted amount', () => {
  assert.deepEqual(J.topUp(1_000_000n, 1_116_667n), { ok: true, extraBps: 1167 });
  assert.deepEqual(J.topUp(1_000_000n, 1_250_000n), { ok: true, extraBps: 2500 });
  assert.equal(J.topUp(1_000_000n, 1_250_001n).ok, false);
  assert.deepEqual(J.topUp(1_000_000n, 900_000n), { ok: true, extraBps: 0 });
  assert.equal(J.MAX_TOPUP_BPS, 12_500);
});

// ---------------------------------------------------------------- history read in full (spam cannot push it out)
/** A chain whose histories honour limit/before (newest first), as an RPC does. */
function pagedChain(hist: Map<string, { signature: string; err: unknown; memo: string | null; blockTime: number }[]>, txs: Map<string, unknown>) {
  return {
    getSignaturesForAddress: async (a: PublicKey, o?: { limit?: number; before?: string }) => {
      const all = hist.get(a.toBase58()) ?? [];
      const start = o?.before ? all.findIndex((x) => x.signature === o.before) + 1 : 0;
      return all.slice(start, start + (o?.limit ?? 1000)).map((x) => ({ ...x, slot: 1 }));
    },
    getTransaction: async (sig: string) => txs.get(sig) ?? null,
    getMultipleAccountsInfo: async (ks: PublicKey[]) => ks.map(() => null),
  } as any;
}
const dust = (n: number, t0: number, tag = 'dust') => Array.from({ length: n }, (_, i) => ({ signature: `${tag}${i}`, err: null, memo: null, blockTime: t0 + n - i }));
const walletTx = (payer: PublicKey, gain = 10n ** 8n) => ({ transaction: { message: { staticAccountKeys: [payer], header: { numRequiredSignatures: 1 }, compiledInstructions: [] } }, meta: { err: null, preBalances: [10 ** 9], postBalances: [10 ** 9 + Number(gain) - 5000], fee: 5000 } });
const programTx = (signer: PublicKey, prog: PublicKey) => ({ transaction: { message: { staticAccountKeys: [signer, prog], header: { numRequiredSignatures: 1 }, compiledInstructions: [{ programIdIndex: 1, accountKeyIndexes: [], data: new Uint8Array() }] } }, meta: { err: null, preBalances: [0, 0], postBalances: [0, 0], fee: 5000 } });

test('saleOnChain: 2,500 dust transactions after the sale do not hide it; a cap hit before the sale is "unknown", never "not sold"', async () => {
  const id = new Uint8Array(32).fill(0x81), hex = '81'.repeat(32);
  const memo = `[1] ${J.soldMemo({ swapId: id, lamports: 5n, kind: 'zec' })}`;
  const hist = new Map([[USER.toBase58(), [...dust(2500, 2000), { signature: 'sold', err: null, memo, blockTime: 1500 }, ...dust(50, 100, 'old')]]]);
  const chain = pagedChain(hist, new Map([['sold', walletTx(USER)]]));
  assert.deepEqual(await J.saleOnChain(chain, USER, hex, { since: 1400 }), { sold: true, lockMemo: false });
  await assert.rejects(J.saleOnChain(chain, USER, hex, { since: 1400, maxPages: 2 }), J.HistoryUnknown);
  // the whole window back to the swap's start was read and holds no sale: a real "not sold"
  assert.deepEqual(await J.saleOnChain(pagedChain(new Map([[USER.toBase58(), dust(2500, 2000)]]), new Map()), USER, hex, { since: 2000 + J.HISTORY.skewSecs }), { sold: false, lockMemo: false });
});

test('escrowEverLocked: a settled + closed escrow stays locked after 30 stranger transfers; caps answer null (unknown)', async () => {
  const escrow = Keypair.generate().publicKey, stranger = Keypair.generate().publicKey, sys = new PublicKey('11111111111111111111111111111111');
  const hist = [...dust(30, 3000, 's'), { signature: 'close', err: null, memo: null, blockTime: 2500 }, { signature: 'lock', err: null, memo: null, blockTime: 2000 }];
  const txs = new Map<string, unknown>([['close', programTx(USER, pid)], ['lock', programTx(USER, pid)], ...hist.slice(0, 30).map((x) => [x.signature, programTx(stranger, sys)] as [string, unknown])]);
  const chain = pagedChain(new Map([[escrow.toBase58(), hist]]), txs);
  assert.equal(await J.escrowEverLocked(chain, escrow, USER, pid, { since: 1990 }), true);
  // the read stops at the page cap before reaching the lock: unknown, not "never locked"
  assert.equal(await J.escrowEverLocked(chain, escrow, USER, pid, { since: 1990, pageSize: 10, maxPages: 1 }), null);
  // strangers dusted the address BEFORE the lock (oldest first): too many to check is unknown
  const early = [{ signature: 'lock', err: null, memo: null, blockTime: 2100 }, ...dust(30, 2000, 'e')];
  const chain2 = pagedChain(new Map([[escrow.toBase58(), early]]), new Map<string, unknown>([['lock', programTx(USER, pid)], ...early.slice(1).map((x) => [x.signature, programTx(stranger, sys)] as [string, unknown])]));
  assert.equal(await J.escrowEverLocked(chain2, escrow, USER, pid, { since: 1990, maxTxReads: 5 }), null);
  assert.equal(await J.escrowEverLocked(chain2, escrow, USER, pid, { since: 1990 }), true);
  // only stranger transfers, whole history read: never locked
  assert.equal(await J.escrowEverLocked(pagedChain(new Map([[escrow.toBase58(), dust(30, 3000, 's')]]), new Map(hist.slice(0, 30).map((x) => [x.signature, programTx(stranger, sys)] as [string, unknown]))), escrow, USER, pid, { since: 1990 }), false);
});

test('findUnlocked: 300 dust transactions after a sale do not push it out of view; an escrow whose history is unknown is not offered', async () => {
  const id = new Uint8Array(32).fill(0x91);
  const memo = `[1] ${J.soldMemo({ swapId: id, lamports: 5n, kind: 'zec' })}`;
  const esc = H.htlcPda(pid, USER, id).toBase58();
  const hist = new Map([[USER.toBase58(), [...dust(300, 2000), { signature: 'sold', err: null, memo, blockTime: 1500 }]]]);
  const out = await J.findUnlocked(pagedChain(hist, new Map([['sold', walletTx(USER)]])), pid, USER, { nowSecs: 3000 });
  assert.deepEqual(out.map((x) => x.sig), ['sold']);
  // the escrow address holds more stranger transactions than can be checked: unknown, so not "lock it now"
  hist.set(esc, dust(3000, 1600, 'x'));
  assert.deepEqual(await J.findUnlocked(pagedChain(hist, new Map([['sold', walletTx(USER)]])), pid, USER, { nowSecs: 3000, maxPages: 2 }), []);
});
