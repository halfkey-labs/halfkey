import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { checkMainnet, checkZecDesk, type CheckableConfig, type CheckableZec } from './launch-checks.ts';
import { pickPriority } from './lib.ts';

const good: CheckableConfig = {
  cluster: 'mainnet-beta', moneroNet: 'mainnet', livePrice: true, minConf: 10, endpoint: 'https://maker.halfkey.xyz',
  trustProxy: true, programId: 'HALFKEY11111111111111111111111111111111111', claimMarginSecs: 900, t0Secs: 3300, windowSecs: 7200, depositMarginSecs: 900, x2sLimits: {},
  x2sT0Secs: 21_600, x2sWindowSecs: 3600,
  refundTowers: { minAcks: 3, towers: [
    { url: 'https://node.halfkey.xyz/rt', pubkey: 'Tower1111111111111111111111111111111111111' },
    { url: 'https://t2.example.org/rt', pubkey: 'Tower2222222222222222222222222222222222222' },
    { url: 'https://t3.example.org/rt', pubkey: 'Tower3333333333333333333333333333333333333' },
  ] },
};
test('a complete mainnet config passes; test clusters are not touched', () => {
  assert.deepEqual(checkMainnet(good), []);
  assert.deepEqual(checkMainnet({ cluster: 'devnet', moneroNet: 'stagenet', livePrice: false, minConf: 2, endpoint: 'http://127.0.0.1:7801', programId: 'x' }), []);
});
test('each missing mainnet setting stops the daemon', () => {
  for (const [patch, why] of [
    [{ livePrice: false }, /livePrice/], [{ minConf: 2 }, /minConf/], [{ endpoint: 'https://maker.example.com' }, /endpoint/], [{ endpoint: 'http://1.2.3.4' }, /endpoint/],
    [{ trustProxy: false }, /trustProxy/], [{ attesters: ['https://a1'] }, /attesters/], [{ moneroNet: 'stagenet' }, /both real/], [{ programId: '<HALFKEY program id>' }, /placeholder/],
    [{ x2sLimits: undefined }, /x2sLimits/], [{ x2sT0Secs: 3000 }, /too short for XMR->SOL/],
    [{ refundTowers: undefined }, /refundTowers/], [{ refundTowers: { ...good.refundTowers!, minAcks: 1 } }, /minAcks/],
    [{ refundTowers: { ...good.refundTowers!, towers: good.refundTowers!.towers.slice(0, 2) } }, /three/],
    [{ refundTowers: { ...good.refundTowers!, towers: [good.refundTowers!.towers[0], good.refundTowers!.towers[0], good.refundTowers!.towers[2]] } }, /distinct/],
    [{ refundTowers: { ...good.refundTowers!, towers: [{ ...good.refundTowers!.towers[0], url: 'http://node.halfkey.xyz/rt' }, ...good.refundTowers!.towers.slice(1)] } }, /https/],
    [{ x2sT0Secs: 13 * 3600 }, /x2sT0Secs/], [{ x2sWindowSecs: 600 }, /x2sWindowSecs/], [{ claimMarginSecs: undefined }, /claimMarginSecs/], [{ windowSecs: 100 }, /windowSecs/], [{ sanctionsFile: '/nonexistent/list.json' }, /sanctions/], [{ refill: { enabled: true } }, /refill/],
  ] as [Partial<CheckableConfig>, RegExp][]) {
    const errs = checkMainnet({ ...good, ...patch });
    assert.ok(errs.some((e) => why.test(e)), `${JSON.stringify(patch)}: ${errs.join('; ')}`);
  }
});
test('priority price: p75 + 20%, clamped, floor when the read is empty', () => {
  assert.equal(pickPriority([], {}), 20_000);
  assert.equal(pickPriority([0, 0, 0], {}), 20_000);
  assert.equal(pickPriority(Array(100).fill(100_000), {}), 120_000);
  assert.equal(pickPriority([10_000_000], {}), 2_000_000);
  assert.equal(pickPriority([1], { minMicroLamports: 5 }), 5);
});

test('v1.5 is explicitly switchable with three HTTPS attesters; ready-only stays the fallback', () => {
  const proof = { ...good, claimMode: 'payment-proof' as const, attesters: ['https://a1.halfkey.xyz', 'https://a2.halfkey.xyz', 'https://a3.halfkey.xyz'] };
  assert.deepEqual(checkMainnet(proof), []);
  assert.ok(checkMainnet({ ...proof, attesters: proof.attesters.slice(0, 2) }).some((s) => /three distinct/.test(s)));
  assert.ok(checkMainnet({ ...proof, attesters: Array(3).fill(proof.attesters[0]) }).some((s) => /three distinct/.test(s)));
  assert.ok(checkMainnet({ ...proof, attesters: ['http://a1', ...proof.attesters.slice(1)] }).some((s) => /HTTPS/.test(s)));
  assert.ok(checkMainnet({ ...proof, claimMode: 'ready-only' }).some((s) => /ready-only/.test(s)));
});

const seedDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hk-zc-'));
process.on('exit', () => fs.rmSync(seedDir, { recursive: true, force: true }));
const seed = path.join(seedDir, 'seed.hex'); fs.writeFileSync(seed, '00'.repeat(32), { mode: 0o600 });
const zgood: CheckableZec = {
  cluster: 'mainnet-beta', programId: good.programId, trustProxy: true,
  zec: { zecNet: 'mainnet', zebraRpc: 'https://zebra.halfkey.fun', zebraAuth: 'a:b', seedFile: seed, minConf: 60, marginSecs: 7200, claimMarginSecs: 900 },
};
test('ZEC desk: a complete mainnet config passes; test networks are not touched', () => {
  assert.deepEqual(checkZecDesk(zgood), []);
  assert.deepEqual(checkZecDesk({ programId: 'x', zec: { zecNet: 'regtest', zebraRpc: 'http://127.0.0.1:1', seedFile: '/nope', minConf: 1, marginSecs: 1, claimMarginSecs: 1 } }), []);
});
test('ZEC desk: each missing mainnet setting stops it', () => {
  const open = path.join(seedDir, 'open.hex'); fs.writeFileSync(open, '00'.repeat(32)); fs.chmodSync(open, 0o644);
  for (const [patch, zpatch, why] of [
    [{}, { livePrice: false }, /livePrice/], [{}, { minConf: 2 }, /minConf/], [{}, { marginSecs: 60 }, /marginSecs/], [{}, { claimMarginSecs: 1 }, /claimMarginSecs/], [{}, { speed: 1 }, /speed/],
    [{}, { zebraRpc: 'http://1.2.3.4:8232' }, /zebraRpc/], [{}, { zebraAuth: undefined }, /zebraAuth/], [{}, { seedFile: '/nonexistent/seed' }, /seedFile/], [{}, { seedFile: open }, /seedFile/],
    [{ cluster: 'devnet' }, {}, /both real/], [{ cluster: undefined }, {}, /both real/], [{ trustProxy: false }, {}, /trustProxy/], [{ programId: '<HALFKEY program id>' }, {}, /placeholder/],
    [{ sanctionsFile: '/nonexistent/list.json' }, {}, /sanctions/], [{ pythApiKeyFile: '/nonexistent/key' }, {}, /pythApiKeyFile/],
  ] as [Partial<CheckableZec>, Record<string, unknown>, RegExp][]) {
    const errs = checkZecDesk({ ...zgood, ...patch, zec: { ...zgood.zec, ...zpatch } });
    assert.ok(errs.some((e) => why.test(e)), `${JSON.stringify([patch, zpatch])}: ${errs.join('; ')}`);
  }
  assert.ok(checkZecDesk({ ...zgood, cluster: 'mainnet-beta', zec: { ...zgood.zec, zecNet: 'testnet' } }).some((e) => /both real/.test(e)));
});
test('the full daemon runs the ZEC checks when it has a ZEC desk', () => {
  const errs = checkMainnet({ ...good, zec: { ...zgood.zec, livePrice: false } });
  assert.ok(errs.some((e) => /livePrice/.test(e)), errs.join('; '));
});
