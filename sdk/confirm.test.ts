import { test } from 'node:test';
import assert from 'node:assert/strict';
import { waitForTx, TxFailed, TxExpired, TxTimeout } from './confirm.ts';

const fast = { sleep: async () => {} };
const seq = <T>(xs: (T | Error)[]) => { let i = 0; return async () => { const x = xs[Math.min(i++, xs.length - 1)]; if (x instanceof Error) throw x; return x; }; };

test('confirmed returns; an on-chain error throws', async () => {
  await waitForTx('s', 100, { ...fast, status: seq([null, { err: null, confirmationStatus: 'processed' }, { err: null, confirmationStatus: 'confirmed' }]), height: async () => 50 });
  await assert.rejects(waitForTx('s', 100, { ...fast, status: async () => ({ err: { InstructionError: [0, 'x'] } }), height: async () => 50 }), TxFailed);
});
test('a read that fails is never counted as empty, however long it goes on (a landed lock must not read as lost)', async () => {
  let t = 0;
  await assert.rejects(waitForTx('s', 100, { sleep: async () => { t += 1000; }, now: () => t, status: async () => { throw new Error('502'); }, height: async () => 999 }, { timeoutMs: 20_000 }), TxTimeout);
});
test('gone only after several clean empty reads past the blockhash life + margin; one is not enough', async () => {
  await waitForTx('s', 100, { ...fast, status: seq([null, null, { err: null, confirmationStatus: 'confirmed' }]), height: async () => 200 });
  await assert.rejects(waitForTx('s', 100, { ...fast, status: async () => null, height: async () => 200 }), TxExpired);
  let t = 0;
  await assert.rejects(waitForTx('s', 100, { sleep: async () => { t += 1000; }, now: () => t, status: async () => null, height: async () => 105 }, { timeoutMs: 10_000 }), TxTimeout, 'still inside the margin: not gone');
  // a failed height read neither counts nor resets
  await assert.rejects(waitForTx('s', 100, { ...fast, status: async () => null, height: seq([200, 200, new Error('x'), 200, 200, 200]) }), TxExpired);
});
