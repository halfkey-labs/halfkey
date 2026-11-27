import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Screen, parseOfac, loadList } from './sanctions.ts';

test('the pinned list loads, has both chains, and matches exactly', () => {
  const s = new Screen(loadList());
  const list = loadList();
  assert.ok(list.addresses.SOL.length >= 1, 'SOL list');
  assert.ok(list.addresses.ETH.length >= 1, 'ETH list');
  const one = list.addresses.SOL[0];
  assert.equal(s.sol(one), true);
  assert.equal(s.sol(` ${one} `), true);
  assert.equal(s.sol(one.toLowerCase()), false, 'base58 is case-sensitive');
  assert.equal(s.sol('11111111111111111111111111111111'), false);
  const e = list.addresses.ETH[0];
  assert.equal(s.evmAddr(e.toUpperCase().replace('0X', '0x')), true, 'EVM ignores case');
  assert.ok(s.ageDays(Date.parse(list.date) + 86_400_000) > 0.9);
});
test('OFAC parsing reads remarks and the overflow file, including an entry split across files', () => {
  const sdn = '36,"BAD GUY","entity","SDN","","","","","","","","Digital Currency Address - SOL 42RLPACwZPx3vYYmxSueqsogfynBDqXK298EDsNoyoHi; Digital Currency Address - ETH 0x8589427373D6D84E98730D7795D8f6f8731FDA16; Digital Cur"\n';
  const comments = '36,"rency Address - SOL 6wjqWWra8ombzaw6VHrG5xpQ972jCYF6bbHiFCbWmr4U"\n';
  const p = parseOfac(sdn, comments);
  assert.deepEqual(p.SOL, ['42RLPACwZPx3vYYmxSueqsogfynBDqXK298EDsNoyoHi', '6wjqWWra8ombzaw6VHrG5xpQ972jCYF6bbHiFCbWmr4U']);
  assert.deepEqual(p.ETH, ['0x8589427373D6D84E98730D7795D8f6f8731FDA16']);
});
