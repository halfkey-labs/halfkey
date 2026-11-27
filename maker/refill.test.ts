// Unit tests: auto-refill (maker/refill.ts) against a mock exchanger and mock wallets. No network, no funds.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Refiller, type Exchanger, type ExQuote, type ExState, type RefillWallets, type Leg, type RefillConfig } from './refill.ts';
import { Journal } from './lib.ts';

const XMR = 1_000_000_000_000n, SOL = 1_000_000_000n;
const PX = 0.5; // XMR per SOL

function mockExchanger(o: { slipBps?: number; tradeSlipBps?: number; quoteErr?: boolean; memo?: boolean } = {}) {
  const trades = new Map<string, { state: ExState; out: bigint }>();
  const ex: Exchanger & { trades: typeof trades; created: number } = {
    name: 'mock', trades, created: 0,
    async quote(from, to, amountIn): Promise<ExQuote> {
      if (o.quoteErr) throw new Error('api down');
      const mid = from === 'SOL' ? (amountIn * BigInt(PX * 1e6) * XMR) / (SOL * 1_000_000n) : (amountIn * SOL * 1_000_000n) / (XMR * BigInt(PX * 1e6));
      return { amountOut: (mid * BigInt(10_000 - (o.slipBps ?? 80))) / 10_000n, fixed: true, provider: 'p1', min: 1n, max: 10n ** 20n };
    },
    async create(a) {
      ex.created++;
      const id = `T${ex.created}`;
      const out = (a.quote.amountOut * BigInt(10_000 - (o.tradeSlipBps ?? 0))) / 10_000n;
      trades.set(id, { state: 'waiting', out });
      return { id, depositAddress: `dep-${id}`, depositMemo: o.memo ? 'tag' : undefined, amountIn: a.amountIn, amountOut: out, fixed: true, provider: 'p1' };
    },
    async status(id) { const t = trades.get(id)!; return { state: t.state, payoutTxid: t.state === 'finished' ? `payout-${id}` : undefined, amountOut: t.out }; },
  };
  return ex;
}

function mockWallets(start: { coin: bigint; sol: bigint }, o: { payThrowsBefore?: boolean; payThrowsAfter?: boolean; paidKnown?: boolean | null } = {}) {
  const st = { ...start, sent: [] as { leg: Leg; to: string; amount: bigint; txid: string }[], inbox: new Map<string, bigint>(), midAt: Date.now(), n: 0 };
  const w: RefillWallets & { st: typeof st; deliver(ref: string, amt: bigint): void } = {
    st,
    async balances() { return { coin: st.coin, sol: st.sol }; },
    mid() { return { coinPerSol: PX, at: st.midAt }; },
    async receiveAddress(leg, id) { return { address: `${leg}-addr-${id}`, ref: `ref-${id}` }; },
    async refundAddress(leg) { return `refund-${leg}`; },
    async pay(leg, to, amount, onTxid) {
      if (o.payThrowsBefore) throw new Error('wallet locked');
      const txid = `tx${++st.n}`;
      onTxid(txid);
      if (o.payThrowsAfter) throw new Error('rpc timeout');
      st.sent.push({ leg, to, amount, txid });
      if (leg === 'coin') st.sol -= amount; else st.coin -= amount;
      return txid;
    },
    async paid() { return o.paidKnown ?? null; },
    async received(_leg, ref) { const a = st.inbox.get(ref) ?? 0n; return { seen: a, spendable: a, txids: a ? [`in-${ref}`] : [] }; },
    deliver(ref, amt) { st.inbox.set(ref, (st.inbox.get(ref) ?? 0n) + amt); },
  };
  return w;
}

function setup(cfg: RefillConfig = {}, w = mockWallets({ coin: 2n * XMR, sol: 96n * SOL }), ex = mockExchanger(), dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refill-'))) {
  let now = Date.now();
  const alerts: string[] = [];
  const mk = () => new Refiller({
    cfg: { enabled: true, route: 'mock', ...cfg }, target: 0.5, coin: 'XMR', coinDecimals: 12, exchanger: ex, wallets: w, defaultDir: dir,
    now: () => now, alert: async (t) => { alerts.push(t); },
  });
  const r = mk();
  return { r, w, ex, dir, alerts, mk, advance: (ms: number) => { now += ms; w.st.midAt = now; } };
}

test('nothing happens while both sides are above the trigger, or when disabled', async () => {
  const { r, w, ex } = setup({}, mockWallets({ coin: 20n * XMR, sol: 60n * SOL }));
  await r.tick();
  assert.equal(ex.created, 0);
  assert.equal(w.st.sent.length, 0);
  const off = setup({ enabled: false });
  await off.r.tick();
  assert.equal(off.ex.created, 0);
});

test('XMR low: buys XMR with surplus SOL in a capped chunk, journals the receipt, follows it into the wallet', async () => {
  // 2 XMR (= 4 SOL) vs 96 SOL: XMR at 8% of its target
  const { r, w, ex, advance } = setup({ chunkSol: 5 });
  await r.tick();
  assert.equal(ex.created, 1);
  assert.equal(w.st.sent.length, 1);
  assert.equal(w.st.sent[0].leg, 'coin');
  assert.equal(w.st.sent[0].amount, 5n * SOL, 'capped at chunkSol');
  assert.equal(w.st.sent[0].to, 'dep-T1');
  const a = r.active()!;
  assert.equal(a.stage, 'paid');
  assert.ok(r.incoming('coin') > 0n, 'the skew counts XMR on its way');
  assert.equal(r.incoming('sol'), 0n);
  // exchanger finishes, coins land in our own address
  advance(20 * 60_000);
  w.deliver(a.receiveRef!, BigInt(a.tradeOut!) / 2n); // half visible in the wallet: no double count
  const before = r.incoming('coin');
  await r.tick();
  assert.equal(r.incoming('coin'), before - BigInt(a.tradeOut!) / 2n);
  ex.trades.get('T1')!.state = 'finished';
  w.deliver(a.receiveRef!, BigInt(a.tradeOut!) - BigInt(a.tradeOut!) / 2n);
  await r.tick();
  assert.equal(r.active(), undefined);
  const done = r.refills.get(a.id)!;
  assert.equal(done.stage, 'done');
  assert.equal(done.payoutTxid, 'payout-T1');
  assert.deepEqual(done.receivedTxids, [`in-${a.receiveRef}`]);
  assert.ok(done.costBps! > 0 && done.costBps! < 150);
  assert.equal(r.incoming('coin'), 0n);
  // receipt on disk: planned -> created -> paying -> paid -> delivered -> received, with tx ids
  const kinds = Journal.read(r.journalFile).map((x) => x.kind);
  assert.deepEqual(kinds, ['planned', 'created', 'paying', 'paid', 'delivered', 'received']);
  const rec = Journal.read(r.journalFile);
  assert.equal(rec[1].exchangeId, 'T1');
  assert.equal(rec[3].txid, 'tx1');
});

test('SOL low: the reverse leg buys SOL with XMR', async () => {
  const { r, w } = setup({}, mockWallets({ coin: 48n * XMR, sol: 3n * SOL }));
  await r.tick();
  assert.equal(w.st.sent.length, 1);
  assert.equal(w.st.sent[0].leg, 'sol');
  assert.equal(w.st.sent[0].amount, 2_500_000_000_000n, 'chunkSol 5 worth of XMR = 2.5 XMR');
  const only = setup({ directions: 'coin' }, mockWallets({ coin: 48n * XMR, sol: 3n * SOL }));
  await only.r.tick();
  assert.equal(only.w.st.sent.length, 0, 'directions: coin never sells XMR');
});

test('a quote worse than the max slippage vs mid is skipped; nothing is created or sent', async () => {
  const { r, w, ex } = setup({ maxSlippageBps: 100 }, undefined, mockExchanger({ slipBps: 300 }));
  await r.tick();
  assert.equal(ex.created, 0);
  assert.equal(w.st.sent.length, 0);
  assert.equal(Journal.read(r.journalFile)[0].kind, 'skipped');
});

test('a trade worse than its quote, or one that needs a memo, is rejected before paying', async () => {
  const a = setup({ maxSlippageBps: 150 }, undefined, mockExchanger({ slipBps: 80, tradeSlipBps: 200 }));
  await a.r.tick();
  assert.equal(a.w.st.sent.length, 0);
  assert.match([...a.r.refills.values()][0].why!, /below mid/);
  const b = setup({}, undefined, mockExchanger({ memo: true }));
  await b.r.tick();
  assert.equal(b.w.st.sent.length, 0);
  assert.match([...b.r.refills.values()][0].why!, /memo/);
});

test('no fresh mid price: no refill', async () => {
  const { r, w, ex } = setup();
  w.st.midAt = Date.now() - 3600_000;
  await r.tick();
  assert.equal(ex.created, 0);
});

test('per-refill cap, cooldown and the rolling daily cap', async () => {
  const { r, w, ex, advance } = setup({ chunkSol: 4, dailyCapSol: 10, cooldownMins: 30 });
  for (let i = 0; i < 6; i++) {
    await r.tick();
    const a = r.active();
    if (a) { ex.trades.get(a.exchangeId!)!.state = 'finished'; w.deliver(a.receiveRef!, BigInt(a.tradeOut!)); await r.tick(); }
    advance(5 * 60_000); // inside the cooldown: no new refill
    await r.tick();
    advance(30 * 60_000);
  }
  const amounts = w.st.sent.map((s) => Number(s.amount) / 1e9);
  assert.deepEqual(amounts, [4, 4, 2], 'chunks of 4, then what is left of the 10 SOL day');
  assert.ok(r.spentToday() <= 10 + 1e-9);
  advance(24 * 3600_000);
  await r.tick();
  assert.equal(w.st.sent.length, 4, 'the cap rolls after 24 h');
});

test('exchanger fails after we paid: alert, pause, and never send again until the operator resumes', async () => {
  const { r, w, ex, alerts, advance } = setup();
  await r.tick();
  ex.trades.get('T1')!.state = 'failed';
  await r.tick();
  assert.ok(r.paused());
  assert.equal(alerts.length, 1);
  assert.match(alerts[0], /PAUSED.*failed/);
  for (let i = 0; i < 5; i++) { advance(60 * 60_000); await r.tick(); }
  assert.equal(w.st.sent.length, 1, 'no retry loop');
  fs.unlinkSync(r.pauseFile);
  await r.tick();
  assert.equal(w.st.sent.length, 2, 'resumes once the pause file is gone');
});

test('not delivered in time: pause, keep watching, record a late delivery', async () => {
  const { r, w, ex, alerts, advance } = setup({ deliverMins: 60 });
  await r.tick();
  const a = r.active()!;
  advance(61 * 60_000);
  await r.tick();
  assert.ok(r.paused());
  assert.match(alerts[0], /not delivered 60 min/);
  advance(60 * 60_000);
  await r.tick();
  assert.equal(alerts.length, 1, 'one alert, not one per tick');
  ex.trades.get('T1')!.state = 'finished';
  w.deliver(a.receiveRef!, BigInt(a.tradeOut!));
  await r.tick();
  assert.equal(r.refills.get(a.id)!.stage, 'done', 'late delivery still lands in the receipt');
  assert.equal(w.st.sent.length, 1, 'still paused for new refills');
});

test('operator resumes while a refill is stuck: it stops being followed and refills continue', async () => {
  const { r, w, advance } = setup({ deliverMins: 30 });
  await r.tick();
  const a = r.active()!;
  advance(31 * 60_000);
  await r.tick();
  assert.ok(r.paused());
  fs.unlinkSync(r.pauseFile);
  await r.tick();
  assert.equal(r.refills.get(a.id)!.stage, 'failed');
  assert.equal(w.st.sent.length, 2);
});

test('crash between journaling our tx id and confirming: restart pauses, never re-sends', async () => {
  const w = mockWallets({ coin: 2n * XMR, sol: 96n * SOL }, { payThrowsAfter: true });
  const { r, alerts } = setup({}, w);
  await r.tick();
  assert.ok(r.paused(), 'an error after signing pauses at once');
  assert.match(alerts[0], /funds may have left/);
  assert.equal(w.st.sent.length, 0);
  // simulated torn journal: planned/created/paying with no paid, then restart
  const torn = () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refill-'));
    const j = new Journal(path.join(dir, 'refill.jsonl'));
    j.append({ kind: 'planned', id: 'x1', refill: { id: 'x1', leg: 'coin', from: 'SOL', to: 'XMR', amountIn: '5000000000', solValue: 5, quoteOut: '1', midOut: '1', slippageBps: 50, route: 'mock', stage: 'planned', t: Date.now() } });
    j.append({ kind: 'created', id: 'x1', exchangeId: 'T9', depositAddress: 'dep', tradeOut: '1', receiveRef: 'r', receiveAddress: 'a' });
    j.append({ kind: 'paying', id: 'x1', txid: 'txZ' });
    return dir;
  };
  const w2 = mockWallets({ coin: 2n * XMR, sol: 96n * SOL }, { paidKnown: null });
  const again = setup({}, w2, mockExchanger(), torn());
  await again.r.tick();
  assert.ok(again.r.paused());
  assert.match(again.alerts[0], /nothing was re-sent/);
  assert.equal(w2.st.sent.length, 0);
  // same journal, but the tx is on chain: it continues as paid
  const w3 = mockWallets({ coin: 2n * XMR, sol: 96n * SOL }, { paidKnown: true });
  const ok = setup({}, w3, mockExchanger(), torn());
  await ok.r.tick();
  assert.equal(ok.r.paused(), null);
  assert.equal(ok.r.refills.get('x1')!.stage, 'paid');
});

test('failures before any funds move: cooldown, then pause after three in a row', async () => {
  const { r, w, alerts, advance } = setup({ cooldownMins: 1 }, mockWallets({ coin: 2n * XMR, sol: 96n * SOL }, { payThrowsBefore: true }));
  for (let i = 0; i < 3; i++) { await r.tick(); advance(2 * 60_000); }
  assert.ok(r.paused());
  assert.match(alerts[0], /no funds were sent/);
  assert.equal(w.st.sent.length, 0);
  const q = setup({ cooldownMins: 1 }, undefined, mockExchanger({ quoteErr: true }));
  for (let i = 0; i < 3; i++) { await q.r.tick(); q.advance(2 * 60_000); }
  assert.ok(q.r.paused());
});
