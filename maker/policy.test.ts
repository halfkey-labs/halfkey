// Unit tests: XMR->SOL deposit timing (one rule for maker and client) and the maker's admission caps.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as T from '../sdk/taker.ts';
import { admitX2S, DEFAULT_X2S_LIMITS, admitS2X, xmrPromised, clientIp, RateWindow, walked, WALK_REFUSE_SECS, ipKey, noShowRefusal, NO_SHOW_REFUSE_SECS } from './policy.ts';

test('deposit deadline: shown deadline + 10 confirmations land before the maker aborts, with margin', () => {
  for (const terms of [T.DEFAULT_DEPOSIT_TERMS, { depositMarginSecs: 600, depositWindowSecs: 900 }, { depositMarginSecs: 900, depositWindowSecs: 3600 }]) {
    for (const t0Secs of [T.minXmrToSolT0(terms), 3000, 4800, 7200]) {
      const created = 1_800_000_000, t0 = created + t0Secs;
      const by = T.depositDeadline(created, t0, terms);
      const { noShowAt, unconfirmedAt } = T.makerAbortTimes(created, t0, terms);
      assert.ok(by + T.CONFIRM_BUDGET_SECS <= unconfirmedAt, 'a deposit sent at the deadline has the full confirmation budget');
      assert.ok(by + T.NO_SHOW_GRACE_SECS <= noShowAt, 'the maker never calls a no-show before the shown deadline + grace');
      assert.ok(by - created >= 10 * 60 || t0Secs < T.minXmrToSolT0(terms), 'at least 10 minutes to send at the minimum t0');
      assert.ok(T.CONFIRM_BUDGET_SECS >= 10 * 120 * 1.5, 'budget covers 10 blocks with 50% variance');
    }
  }
  // the old rule (t0 - 25 min) left only ~10 min against a t0 - 15 min abort: no longer possible
  const created = 0, t0 = 3000;
  assert.ok(T.depositDeadline(created, t0) <= t0 - 900 - 1800);
});

test('admission: per-wallet, per-IP and total unfunded caps; funded swaps do not count', () => {
  const L = { perWallet: 1, perIp: 2, unfundedLamports: 3_000_000_000n, perIpLamports: 3_000_000_000n };
  const req = (taker: string, ip: string, sol = 1n) => ({ taker, ip, lamports: sol * 1_000_000_000n });
  assert.equal(admitX2S([], req('A', '1.1.1.1'), L), null);
  const open = [{ taker: 'A', ip: '1.1.1.1', lamports: 1_000_000_000n, funded: false }];
  assert.match(admitX2S(open, req('A', '2.2.2.2'), L)!, /this wallet/);
  assert.equal(admitX2S(open, req('B', '1.1.1.1'), L), null);
  const two = [...open, { taker: 'B', ip: '1.1.1.1', lamports: 1_000_000_000n, funded: false }];
  assert.match(admitX2S(two, req('C', '1.1.1.1'), L)!, /this address/);
  assert.equal(admitX2S(two, req('C', '3.3.3.3'), L), null);
  assert.match(admitX2S(two, req('C', '3.3.3.3', 2n), L)!, /too much SOL/, 'many wallets and IPs still hit the budget');
  // once a deposit is seen the swap no longer counts
  assert.equal(admitX2S(two.map((o) => ({ ...o, funded: true })), req('A', '1.1.1.1', 3n), L), null);
  assert.ok(DEFAULT_X2S_LIMITS.perWallet >= 1);
});

test('a handshake with no lock on chain reserves no XMR (the 0-SOL inventory grief)', () => {
  const swaps = [
    { direction: 1, xmrAmount: '500000000000' },                                   // POST /v1/swap only: costs the sender nothing
    { direction: 1, xmrAmount: '400000000000', verified: true },                    // lock on chain, XMR not sent yet
    { direction: 1, xmrAmount: '300000000000', verified: true, xmrRelayed: true },  // XMR sent
    { direction: 1, xmrAmount: '200000000000', verified: true, done: 'claimed' },
    { direction: 2, xmrAmount: '100000000000', verified: true },
  ];
  assert.equal(xmrPromised(swaps), 400000000000n);
});
test('handshake caps: per wallet and per client IP', () => {
  const L = { perWallet: 2, perIp: 3 };
  assert.equal(admitS2X([], { taker: 'A', ip: '1.1.1.1' }, L), null);
  const open = [{ taker: 'A', ip: '1.1.1.1' }, { taker: 'A', ip: '2.2.2.2' }];
  assert.match(admitS2X(open, { taker: 'A', ip: '3.3.3.3' }, L)!, /this wallet/);
  assert.equal(admitS2X(open, { taker: 'B', ip: '1.1.1.1' }, L), null);
  const fromIp = [{ taker: 'A', ip: '1.1.1.1' }, { taker: 'B', ip: '1.1.1.1' }, { taker: 'C', ip: '1.1.1.1' }];
  assert.match(admitS2X(fromIp, { taker: 'D', ip: '1.1.1.1' }, L)!, /this address/);
  assert.equal(admitS2X(fromIp, { taker: 'D' }, L), null);
});
test('client IP: a spoofed X-Forwarded-For does not move a Cloudflare client to a new bucket', () => {
  const socket = { remoteAddress: '127.0.0.1' };
  const viaCf = { headers: { 'cf-connecting-ip': '9.9.9.9', 'x-forwarded-for': '1.2.3.4, 9.9.9.9' }, socket };
  assert.equal(clientIp(viaCf, true), '9.9.9.9');
  assert.equal(clientIp(viaCf, false), '127.0.0.1', 'headers are ignored unless trusted');
  assert.equal(clientIp({ headers: { 'x-forwarded-for': '1.2.3.4, 8.8.8.8' }, socket }, true), '8.8.8.8', 'the proxy-added entry, not the client-sent one');
  assert.equal(clientIp({ headers: {}, socket }, true), '127.0.0.1');
});
test('rate window: real traffic passes, a flood stops, the window resets', () => {
  let t = 0;
  const w = new RateWindow(3, 1000, () => t);
  assert.ok(w.take('a') && w.take('a') && w.take('a'));
  assert.equal(w.take('a'), false);
  assert.ok(w.take('b'), 'other clients are not affected');
  t = 1000;
  assert.ok(w.take('a'));
  w.sweep();
});
test('a wallet that cancelled after the maker paid is refused for a day, nobody else', () => {
  const swaps = [{ taker: 'A', walkedAt: 1000 }, { taker: 'B' }];
  assert.equal(walked(swaps, 'A', 1000 + WALK_REFUSE_SECS - 1), true);
  assert.equal(walked(swaps, 'A', 1000 + WALK_REFUSE_SECS), false);
  assert.equal(walked(swaps, 'B', 1001), false);
  assert.equal(walked(swaps, 'C', 1001), false);
});
test('IPv6 counts by the /64; IPv4 and mapped IPv4 unchanged', () => {
  assert.equal(ipKey('2001:db8:1:2:aaaa::1'), '2001:db8:1:2::/64');
  assert.equal(ipKey('2001:db8:1:2:bbbb:cccc:dddd:eeee'), '2001:db8:1:2::/64');
  assert.equal(ipKey('2001:DB8:0001:2::9'), '2001:db8:1:2::/64');
  assert.equal(ipKey('fe80::1'), 'fe80:0:0:0::/64');
  assert.equal(ipKey('1.2.3.4'), '1.2.3.4');
  assert.equal(ipKey('::ffff:1.2.3.4'), '1.2.3.4');
  const socket = { remoteAddress: '127.0.0.1' };
  assert.equal(clientIp({ headers: { 'cf-connecting-ip': '2001:db8:1:2:aaaa::1' }, socket }, true), clientIp({ headers: { 'cf-connecting-ip': '2001:db8:1:2:ffff::2' }, socket }, true));
});
test('open handshakes have a ceiling for everyone', () => {
  const open = Array.from({ length: 3 }, (_, i) => ({ taker: `T${i}`, ip: `9.9.9.${i}` }));
  assert.match(admitS2X(open, { taker: 'N', ip: '1.1.1.1' }, { perWallet: 5, perIp: 5, total: 3 })!, /busy/);
  assert.equal(admitS2X(open, { taker: 'N', ip: '1.1.1.1' }, { perWallet: 5, perIp: 5, total: 4 }), null);
});
test('XMR->SOL: one address cannot use the whole budget; a lone big swap still fits', () => {
  const L = { perWallet: 1, perIp: 3, unfundedLamports: 10n };
  const open = [{ taker: 'A', ip: '1.1.1.1', lamports: 4n, funded: false }];
  assert.match(admitX2S(open, { taker: 'B', ip: '1.1.1.1', lamports: 2n }, L)!, /from this address/);
  assert.equal(admitX2S(open, { taker: 'C', ip: '2.2.2.2', lamports: 2n }, L), null);
  assert.equal(admitX2S([], { taker: 'D', ip: '3.3.3.3', lamports: 8n }, L), null, 'a single swap larger than the share');
});
test('XMR->SOL: a seen deposit does not lift the caps for good', () => {
  const L = { perWallet: 1, perIp: 3, unfundedLamports: 100n };
  const funded = (n: number, taker: string, ip: string) => Array.from({ length: n }, () => ({ taker, ip, lamports: 1n, funded: true }));
  assert.match(admitX2S(funded(2, 'A', '1.1.1.1'), { taker: 'A', ip: '9.9.9.9', lamports: 1n }, L)!, /already has/);
  assert.match(admitX2S(funded(6, 'B', '1.1.1.1'), { taker: 'C', ip: '1.1.1.1', lamports: 1n }, L)!, /from this address/);
  assert.equal(admitX2S(funded(1, 'A', '1.1.1.1'), { taker: 'A', ip: '1.1.1.1', lamports: 1n }, L), null);
});
test('XMR->SOL: a total ceiling, funded swaps included', () => {
  const L = { perWallet: 1, perIp: 3, unfundedLamports: 10n };
  const big = [{ taker: 'A', ip: '1', lamports: 15n, funded: true }];
  assert.match(admitX2S(big, { taker: 'B', ip: '2', lamports: 6n }, L)!, /too much SOL open/);
  assert.equal(admitX2S(big, { taker: 'B', ip: '2', lamports: 5n }, L), null);
});
test('no-show: the wallet at once, an address after a second, both for an hour', () => {
  const now = 10_000;
  const s = [{ taker: 'A', ip: '1.1.1.1', noShowAt: now - 10 }];
  assert.match(noShowRefusal(s, { taker: 'A', ip: '9.9.9.9' }, now)!, /wallet/);
  assert.equal(noShowRefusal(s, { taker: 'B', ip: '1.1.1.1' }, now), null, 'one no-show on a shared address');
  const two = [...s, { taker: 'C', ip: '1.1.1.1', noShowAt: now - 20 }];
  assert.match(noShowRefusal(two, { taker: 'B', ip: '1.1.1.1' }, now)!, /address/);
  assert.equal(noShowRefusal(two, { taker: 'B', ip: '1.1.1.1' }, now + NO_SHOW_REFUSE_SECS), null);
});
