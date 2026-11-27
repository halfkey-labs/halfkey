// Unit tests: the Trocador route (maker/exchangers.ts) against a mocked HTTP API. No network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Trocador, toDec, fromDec, makeExchanger } from './exchangers.ts';

test('decimal <-> base units, exact', () => {
  assert.equal(toDec(1_500_000_000n, 9), '1.5');
  assert.equal(toDec(1n, 12), '0.000000000001');
  assert.equal(toDec(3n * 10n ** 12n, 12), '3');
  assert.equal(fromDec('0.751234567891234', 12), 751_234_567_891n, 'extra digits are truncated');
  assert.equal(fromDec(2.5, 9), 2_500_000_000n);
  assert.throws(() => fromDec('1e5', 9));
  assert.throws(() => fromDec('-1', 9));
});

function api(routes: Record<string, (q: URLSearchParams) => unknown>) {
  const calls: { path: string; q: URLSearchParams; key: string | null }[] = [];
  const f = (async (u: URL, init: RequestInit) => {
    const key = new Headers(init.headers).get('API-Key');
    calls.push({ path: u.pathname, q: u.searchParams, key });
    const h = routes[u.pathname];
    const body = h ? h(u.searchParams) : { error: 'not found' };
    return new Response(JSON.stringify(body), { status: h ? 200 : 404 });
  }) as unknown as typeof fetch;
  return { f, calls };
}

test('trocador: quote keeps only rating-A providers and takes the best; create and status map cleanly', async () => {
  const { f, calls } = api({
    '/new_rate': () => ({ trade_id: 'TR1', quotes: { quotes: [
      { provider: 'Holdy', amount_to: '0.80', kycrating: 'C', logpolicy: 'A', fixed: 'False' },
      { provider: 'Fine', amount_to: '0.75', kycrating: 'A', logpolicy: 'A', fixed: 'True' },
      { provider: 'Ok', amount_to: '0.74', kycrating: 'A', logpolicy: 'B', fixed: 'False' },
    ] } }),
    '/new_trade': (q) => ({ trade_id: q.get('id'), address_provider: 'So1DepositAddr', address_provider_memo: '0', amount_from: q.get('amount_from'), amount_to: '0.75', provider: q.get('provider'), fixed: 'True' }),
    '/trade': () => [{ status: 'finished', ticker_to: 'xmr', amount_to: '0.7499', details: { hashout: 'abc123' } }],
  });
  const t = new Trocador({ apiKey: 'k', fetch: f });
  const q = await t.quote('SOL', 'XMR', 5n * 10n ** 9n);
  assert.equal(q.provider, 'Fine', 'the better-paying provider with KYC rating C is filtered out');
  assert.equal(q.amountOut, 750_000_000_000n);
  assert.equal(q.fixed, true);
  assert.equal(calls[0].key, 'k');
  assert.equal(calls[0].q.get('amount_from'), '5');
  assert.equal(calls[0].q.get('min_kycrating'), 'A');
  const tr = await t.create({ from: 'SOL', to: 'XMR', amountIn: 5n * 10n ** 9n, payout: '4xmrAddr', refund: 'SoLrefund', quote: q });
  assert.equal(tr.depositAddress, 'So1DepositAddr');
  assert.equal(tr.depositMemo, undefined, 'memo "0" = none');
  assert.equal(tr.amountIn, 5n * 10n ** 9n);
  assert.equal(calls[1].q.get('address'), '4xmrAddr');
  assert.equal(calls[1].q.get('refund'), 'SoLrefund');
  assert.equal(calls[1].q.get('provider'), 'Fine');
  const st = await t.status(tr.id);
  assert.deepEqual([st.state, st.payoutTxid, st.amountOut], ['finished', 'abc123', 749_900_000_000n]);
});

test('trocador: no deposit address ("0"), API errors and unknown statuses are handled, never guessed', async () => {
  const { f } = api({
    '/new_rate': () => ({ trade_id: 'TR2', quotes: { quotes: [{ provider: 'P', amount_to: '1', kycrating: 'A', logpolicy: 'A', fixed: 'False' }] } }),
    '/new_trade': () => ({ trade_id: 'TR2', address_provider: '0' }),
    '/trade': () => [{ status: 'halted' }],
  });
  const t = new Trocador({ apiKey: 'k', fetch: f });
  const q = await t.quote('XMR', 'SOL', 10n ** 12n);
  await assert.rejects(t.create({ from: 'XMR', to: 'SOL', amountIn: 10n ** 12n, payout: 'So1', refund: '4x', quote: q }), /no deposit address/);
  assert.equal((await t.status('TR2')).state, 'hold', 'halted = a hold: pause and alert');
  const bad = new Trocador({ apiKey: 'k', fetch: api({ '/new_rate': () => ({ error: 'Missing API key' }) }).f });
  await assert.rejects(bad.quote('SOL', 'XMR', 1n), /Missing API key/);
  const none = new Trocador({ apiKey: 'k', fetch: api({ '/new_rate': () => ({ trade_id: 'x', quotes: { quotes: [{ provider: 'D', amount_to: '1', kycrating: 'D', logpolicy: 'A' }] } }) }).f });
  await assert.rejects(none.quote('SOL', 'XMR', 1n), /rating limits/);
  assert.throws(() => makeExchanger('nope', 'k'), /unknown refill route/);
  assert.throws(() => makeExchanger('trocador', ''), /no API key/);
});
