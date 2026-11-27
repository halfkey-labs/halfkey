// The maker's price rule: a repro of "the price API fails and the daemon keeps quoting the frozen price".
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pickRate, PriceFeed, DEFAULT_LIMITS, PYTH_IDS, readKraken } from './price.ts';

const now = 1_800_000_000_000;
const leg = (usd: number, ageSecs = 5, confBps = 10) => ({ usd, atMs: now - ageSecs * 1000, confBps });
const gleg = (usd: number, ageSecs = 5) => ({ usd, atMs: now - ageSecs * 1000 });
const pick = (pyth: any, kraken: any, coingecko: any) => pickRate({ sources: { pyth, kraken, coingecko }, base: 'SOL', quote: 'XMR', nowMs: now });
const pair = (s: number, x: number, age?: number, conf?: number) => ({ SOL: leg(s, age, conf), XMR: leg(x, age, conf) });

test('first usable source sets the price; rate is XMR per SOL', () => {
  const s = pick(pair(93, 630), pair(93.1, 630), { SOL: gleg(93.1), XMR: gleg(629) });
  assert.ok(s.ok); assert.equal(s.source, 'pyth'); assert.ok(Math.abs(s.rate - 93 / 630) < 1e-9);
  const k = pick(undefined, pair(93, 630), { SOL: gleg(93.1), XMR: gleg(629) });
  assert.ok(k.ok); assert.equal(k.source, 'kraken');
});
test('a stale or wide primary falls through to the next source', () => {
  for (const pyth of [{ SOL: leg(93, DEFAULT_LIMITS.maxAgeSecs + 1), XMR: leg(630) }, { SOL: leg(93), XMR: leg(630, 5, DEFAULT_LIMITS.maxConfBps + 1) }, {}]) {
    const s = pick(pyth, pair(93, 630), undefined);
    assert.ok(s.ok); assert.equal(s.source, 'kraken');
  }
  const g = pick(undefined, undefined, { SOL: gleg(93), XMR: gleg(630) });
  assert.ok(g.ok); assert.equal(g.source, 'coingecko');
});
test('every source stale or empty: no price, whatever the last value was', () => {
  const s = pick(pair(93, 630, 3600), pair(93, 630, 3600), { SOL: gleg(93, 3600), XMR: gleg(630, 3600) });
  assert.equal(s.ok, false);
  assert.equal(pick({}, {}, {}).ok, false);
  assert.equal(pick(undefined, undefined, undefined).ok, false);
});
test('sources that disagree stop quoting', () => {
  const s = pick(undefined, pair(93, 630), { SOL: gleg(93), XMR: gleg(600) });
  assert.equal(s.ok, false);
  assert.match((s as any).reason, /disagree/);
});
test('a stale source does not veto a good price', () => {
  const s = pick(undefined, pair(93, 630), { SOL: gleg(50, 3600), XMR: gleg(600, 3600) });
  assert.ok(s.ok); assert.equal(s.source, 'kraken');
});
test('zero and nonsense prices never pass', () => {
  assert.equal(pick(undefined, pair(0, 630), undefined).ok, false);
  assert.equal(pick(undefined, pair(NaN, 630), undefined).ok, false);
  assert.equal(pick(undefined, undefined, { SOL: gleg(93), XMR: gleg(0) }).ok, false);
});

function fakeFetch(behave: { pyth?: 'ok' | 'fail' | '401'; kraken?: 'ok' | 'fail' | '429' | 'api-error'; gecko?: 'ok' | 'fail' | '429'; publish?: () => number }) {
  return (async (url: string) => {
    if (String(url).includes('hermes')) {
      if (behave.pyth === 'fail') throw new Error('network');
      if (behave.pyth === '401') return new Response('unauthorized', { status: 401 });
      const t = Math.floor((behave.publish?.() ?? now) / 1000);
      return Response.json({ parsed: [
        { id: PYTH_IDS.SOL, price: { price: '9300000000', conf: '1000000', expo: -8, publish_time: t } },
        { id: PYTH_IDS.XMR, price: { price: '63000000000', conf: '3000000', expo: -8, publish_time: t } },
      ] });
    }
    if (String(url).includes('kraken')) {
      if (behave.kraken === 'fail') throw new Error('network');
      if (behave.kraken === '429') return new Response('slow down', { status: 429 });
      if (behave.kraken === 'api-error') return Response.json({ error: ['EService:Unavailable'] });
      return Response.json({ error: [], result: { SOLUSD: { a: ['93.01'], b: ['92.99'] }, XXMRZUSD: { a: ['630.10'], b: ['629.90'] } } });
    }
    if (behave.gecko === 'fail') throw new Error('network');
    if (behave.gecko === '429') return new Response('{"status":{"error_code":429}}', { status: 429 });
    return Response.json({ solana: { usd: 93 }, monero: { usd: 630 } });
  }) as unknown as typeof fetch;
}

test('Kraken names are mapped (XXMRZUSD), the mid and the bid/ask band are read', async () => {
  const legs = await readKraken(['SOL', 'XMR'], now, fakeFetch({ kraken: 'ok' }));
  assert.equal(legs.SOL!.usd, 93); assert.equal(legs.XMR!.usd, 630);
  assert.ok(legs.XMR!.confBps! < 4);
});
test('a feed that starts failing goes from ok to refused once values age out (the frozen-price repro)', async () => {
  let t = now;
  const behave: any = { kraken: 'ok', gecko: 'ok' };
  const feed = new PriceFeed({ base: 'SOL', quote: 'XMR', fetchImpl: fakeFetch(behave), now: () => t, geckoEveryMs: 0 });
  await feed.refresh();
  const a = feed.state();
  assert.ok(a.ok); assert.equal(a.source, 'kraken');
  behave.kraken = 'fail'; behave.gecko = '429';
  t += 30_000; await feed.refresh();
  assert.ok(feed.state().ok, '30 s of errors: still inside the age limit');
  assert.match(feed.lastError, /kraken.*coingecko/);
  t += 200_000; await feed.refresh();
  assert.equal(feed.state().ok, false, 'never quotes on the frozen price');
});
test('a 429 or an API error body is an error, not an empty price', async () => {
  for (const kraken of ['429', 'api-error'] as const) {
    const feed = new PriceFeed({ base: 'SOL', quote: 'XMR', fetchImpl: fakeFetch({ kraken, gecko: '429' }), now: () => now, geckoEveryMs: 0 });
    await feed.refresh();
    assert.equal(feed.state().ok, false);
    assert.match(feed.lastError, /kraken/);
  }
});
test('one source alone: refused without an earlier cross-check, and outside a band of the last checked rate', async () => {
  let t = now, xmr = 630;
  const behave: any = { gecko: 'ok' };
  const f = (async (u: string) => {
    if (String(u).includes('kraken')) return Response.json({ error: [], result: { SOLUSD: { a: ['93.01'], b: ['92.99'] }, XXMRZUSD: { a: [String(xmr + 0.1)], b: [String(xmr - 0.1)] } } });
    if (behave.gecko === '429') return new Response('', { status: 429 });
    return Response.json({ solana: { usd: 93 }, monero: { usd: 630 } });
  }) as unknown as typeof fetch;
  const lone = new PriceFeed({ base: 'SOL', quote: 'XMR', fetchImpl: f, now: () => t, geckoEveryMs: 0 });
  behave.gecko = '429';
  await lone.refresh();
  assert.equal(lone.state().ok, false, 'never cross-checked yet');
  behave.gecko = 'ok';
  await lone.refresh();
  assert.ok(lone.state().ok);
  behave.gecko = '429';
  t += 200_000; xmr = 640;
  await lone.refresh();
  assert.ok(lone.state().ok, 'a small move, source alone');
  xmr = 500;
  await lone.refresh();
  const s = lone.state();
  assert.equal(s.ok, false);
  assert.match((s as any).reason, /moved/);
});
test('Pyth is read only with a key, and a 401 falls through without stopping the others', async () => {
  const noKey = new PriceFeed({ base: 'SOL', quote: 'XMR', fetchImpl: fakeFetch({ pyth: '401', kraken: 'ok', gecko: 'ok' }), now: () => now, geckoEveryMs: 0 });
  await noKey.refresh();
  assert.equal(noKey.lastError, '');
  const key = new PriceFeed({ base: 'SOL', quote: 'XMR', pythApiKey: 'k', fetchImpl: fakeFetch({ pyth: '401', kraken: 'ok', gecko: 'ok' }), now: () => now, geckoEveryMs: 0 });
  await key.refresh();
  assert.match(key.lastError, /pyth HTTP 401/);
  const s = key.state(); assert.ok(s.ok); assert.equal(s.source, 'kraken');
  const good = new PriceFeed({ base: 'SOL', quote: 'XMR', pythApiKey: 'k', fetchImpl: fakeFetch({ pyth: 'ok', kraken: 'ok', gecko: 'ok', publish: () => now }), now: () => now, geckoEveryMs: 0 });
  await good.refresh();
  const g = good.state(); assert.ok(g.ok); assert.equal(g.source, 'pyth');
});
