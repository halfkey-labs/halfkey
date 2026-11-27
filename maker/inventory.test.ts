// Unit tests: inventory skew (maker/inventory.ts).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { skew, pressure, skewConfig, ratios, DEFAULT_SKEW } from './inventory.ts';

const BASE = 150;

test('on target: the flat spread both ways', () => {
  const inv = { coin: 50, sol: 50 };
  for (const side of ['giveCoin', 'takeCoin'] as const) {
    const r = skew(undefined, BASE, inv, side);
    assert.equal(r.spreadBps, BASE);
    assert.equal(r.widenBps, 0);
    assert.equal(r.improveBps, 0);
    assert.equal(r.stop, undefined);
  }
  // inside the dead band (each side within 10% of target): still flat
  assert.equal(skew(undefined, BASE, { coin: 46, sol: 54 }, 'giveCoin').spreadBps, BASE);
});

test('coin running low: giving it away widens, taking it in tightens', () => {
  let lastGive = BASE, lastTake = BASE;
  for (const coin of [45, 40, 30, 20, 12]) {
    const inv = { coin, sol: 100 - coin };
    const g = skew(undefined, BASE, inv, 'giveCoin'), t = skew(undefined, BASE, inv, 'takeCoin');
    assert.ok(g.spreadBps >= lastGive, `give widens monotonically (coin ${coin})`);
    assert.ok(t.spreadBps <= lastTake, `take tightens monotonically (coin ${coin})`);
    assert.ok(g.spreadBps <= BASE + DEFAULT_SKEW.maxWidenBps, 'widening is capped');
    assert.ok(t.spreadBps >= BASE - DEFAULT_SKEW.maxImproveBps, 'improvement is capped');
    lastGive = g.spreadBps; lastTake = t.spreadBps;
  }
  assert.ok(lastGive > BASE + 100 && lastTake < BASE - 50, 'meaningful pull near the floor');
});

test('mirror: SOL running low widens takeCoin and tightens giveCoin', () => {
  const a = skew(undefined, BASE, { coin: 20, sol: 80 }, 'giveCoin');
  const b = skew(undefined, BASE, { coin: 80, sol: 20 }, 'takeCoin');
  assert.equal(a.spreadBps, b.spreadBps, 'symmetric at a 50/50 target');
  const c = skew(undefined, BASE, { coin: 20, sol: 80 }, 'takeCoin');
  const d = skew(undefined, BASE, { coin: 80, sol: 20 }, 'giveCoin');
  assert.equal(c.spreadBps, d.spreadBps);
});

test('never better than mid, whatever the caps', () => {
  for (const base of [0, 20, 80, 150]) {
    const r = skew({ maxImproveBps: 500 }, base, { coin: 5, sol: 95 }, 'takeCoin');
    assert.ok(r.spreadBps >= 0, `spread ${r.spreadBps} >= 0 at base ${base}`);
    assert.ok(r.improveBps <= base, 'improvement never exceeds the base spread');
  }
  assert.equal(skew(undefined, 0, { coin: 10, sol: 90 }, 'takeCoin').spreadBps, 0);
});

test('the widening cap holds at and past the floor', () => {
  const r = skew(undefined, BASE, { coin: 0.5, sol: 99.5 }, 'giveCoin');
  assert.equal(r.widenBps, DEFAULT_SKEW.maxWidenBps);
  assert.equal(r.spreadBps, BASE + 150);
  const big = skew({ maxWidenBps: 99_999 }, BASE, { coin: 0.5, sol: 99.5 }, 'giveCoin');
  assert.ok(big.widenBps <= 1000, 'config cannot set an absurd cap');
});

test('floor: stop quoting the draining direction instead of failing later', () => {
  // 50 total value, coin target 25; floor 0.1 = 2.5 of coin
  const inv = { coin: 4, sol: 46 };
  assert.equal(skew(undefined, BASE, inv, 'giveCoin', { coin: 1, sol: 1 }).stop, undefined);
  assert.equal(skew(undefined, BASE, inv, 'giveCoin', { coin: 2, sol: 2 }).stop, 'coin', 'a trade that would cross the floor is not quoted');
  assert.equal(skew(undefined, BASE, inv, 'takeCoin', { coin: 2, sol: 2 }).stop, undefined, 'the refilling direction stays open');
  assert.equal(skew(undefined, BASE, { coin: 46, sol: 4 }, 'takeCoin', { coin: 2, sol: 2 }).stop, 'sol');
  assert.equal(skew(undefined, BASE, { coin: 10, sol: 0 }, 'takeCoin', { coin: 1, sol: 1 }).stop, 'sol', 'cannot pay out SOL it does not have');
  assert.equal(skew(undefined, BASE, { coin: 0, sol: 0 }, 'giveCoin').stop, 'coin');
});

test('trade size is priced at its midpoint: a big drain costs more than a small one', () => {
  const inv = { coin: 40, sol: 60 };
  const small = skew(undefined, BASE, inv, 'giveCoin', { coin: 0.1, sol: 0.1 });
  const big = skew(undefined, BASE, inv, 'giveCoin', { coin: 20, sol: 20 });
  assert.ok(big.spreadBps > small.spreadBps);
});

test('disabled and odd inputs fall back to the flat spread', () => {
  assert.equal(skew({ enabled: false }, BASE, { coin: 1, sol: 99 }, 'giveCoin').spreadBps, BASE);
  assert.equal(skew(undefined, BASE, { coin: NaN, sol: 1 }, 'giveCoin').spreadBps, BASE);
  const c = skewConfig({ target: 7, floor: -1, deadband: 3 });
  assert.equal(c.target, 0.95);
  assert.equal(c.floor, 0);
  assert.ok(c.deadband <= 0.9);
});

test('curve: 0 in the band, 1 at the floor, smooth and monotone in between', () => {
  const c = skewConfig();
  assert.equal(pressure(1, c), 0);
  assert.equal(pressure(0.95, c), 0);
  assert.equal(pressure(0.1, c), 1);
  assert.equal(pressure(0, c), 1);
  let prev = 0;
  for (let r = 0.9; r >= 0.1; r -= 0.05) { const p = pressure(r, c); assert.ok(p >= prev && p <= 1); prev = p; }
  assert.ok(Math.abs(pressure(0.5, c) - 0.5) < 1e-9, 'halfway between band and floor = half pressure');
});

test('a non-50/50 target', () => {
  const r = ratios({ coin: 30, sol: 70 }, 0.3);
  assert.ok(Math.abs(r.coin - 1) < 1e-9 && Math.abs(r.sol - 1) < 1e-9);
  assert.equal(skew({ target: 0.3 }, BASE, { coin: 30, sol: 70 }, 'giveCoin').spreadBps, BASE);
  assert.ok(skew({ target: 0.3 }, BASE, { coin: 10, sol: 90 }, 'giveCoin').spreadBps > BASE);
});
