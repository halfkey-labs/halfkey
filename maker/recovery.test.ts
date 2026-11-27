// Getting the XMR back when an escrow was refunded and closed in one transaction. The history search,
// offline, with a real encoded refund instruction: the two reviews' failures (IX not exported, a zero secret
// wedging the scan) both happen here without a validator.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Keypair, PublicKey } from '@solana/web3.js';
import bs58 from 'bs58';
import * as P from '../sdk/program.ts';
import * as K from '../sdk/keys.ts';
import { pickSettlement, scanEscrowHistory, Journal } from './lib.ts';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const pid = Keypair.generate().publicKey, escrow = Keypair.generate().publicKey, who = Keypair.generate().publicKey;
const taker = K.randomHalf(), mySpend = K.randomScalar();
const pick = pickSettlement(taker.spendPub, mySpend);
const refund = (s: Uint8Array) => P.ixRefund(pid, who, escrow, who, who, s).data;
const claim = (s: Uint8Array) => P.ixClaim(pid, who, escrow, who, s).data;

test('the refund instruction is recognised by its real encoding, and hands back the taker\'s half', () => {
  const got = pick(refund(taker.spend));
  assert.equal(got?.kind, 'refund');
  assert.equal(K.toHex(got!.secret), K.toHex(taker.spend));
  assert.equal(pick(claim(mySpend))?.kind, 'claim');
});
test('anything else is passed over: another key, a claim by someone else, other lengths', () => {
  assert.equal(pick(refund(K.randomScalar())), null);
  assert.equal(pick(claim(K.randomScalar())), null);
  assert.equal(pick(new Uint8Array(32)), null);
  assert.equal(pick(refund(new Uint8Array(32))), null, 'a zero secret (a pay refund) must not throw');
});

function conn(pages: { sig: string; ixs?: Uint8Array[]; inner?: Uint8Array[]; err?: boolean }[][]) {
  const keys = [pid];
  const all = pages.flat();
  let page = 0;
  return {
    getSignaturesForAddress: async () => (pages[page++] ?? []).map((x) => ({ signature: x.sig, err: x.err ? {} : null })),
    getTransaction: async (sig: string) => {
      const x = all.find((y) => y.sig === sig)!;
      return {
        meta: { loadedAddresses: undefined, innerInstructions: x.inner ? [{ index: 0, instructions: x.inner.map((d) => ({ programIdIndex: 0, data: bs58.encode(d), accounts: [] })) }] : [] },
        transaction: { message: { getAccountKeys: () => ({ get: (i: number) => keys[i] }), compiledInstructions: (x.ixs ?? []).map((d) => ({ programIdIndex: 0, data: d, accountKeyIndexes: [] })) } },
      };
    },
  } as any;
}

test('history: found among junk, including instructions that would make a naive check throw, and inside a CPI', async () => {
  const c = conn([[{ sig: 'j1', ixs: [new Uint8Array(33).fill(10)] }, { sig: 'z', ixs: [refund(new Uint8Array(32))] }, { sig: 'bad', ixs: [refund(taker.spend)], err: true }, { sig: 'cpi', inner: [refund(taker.spend)] }]]);
  const r = await scanEscrowHistory(c, pid, escrow, pick);
  assert.equal(r.found?.kind, 'refund');
});
test('a padded history is searched across calls, never given up on', async () => {
  const junk = Array.from({ length: 40 }, (_, i) => ({ sig: `j${i}`, ixs: [new Uint8Array(3)] }));
  const c = conn([junk, [{ sig: 'real', ixs: [refund(taker.spend)] }]]);
  const a = await scanEscrowHistory(c, pid, escrow, pick);
  assert.equal(a.found, null); assert.equal(a.done, false); assert.equal(a.cursor, 'j39');
  const b = await scanEscrowHistory(c, pid, escrow, pick, a.cursor);
  assert.equal(b.found?.kind, 'refund');
});
test('a transaction that can\'t be read is an error, not "not there"', async () => {
  const c = { getSignaturesForAddress: async () => [{ signature: 's', err: null }], getTransaction: async () => null } as any;
  await assert.rejects(scanEscrowHistory(c, pid, escrow, pick), /not readable/);
});
test('the journal loads line by line, including a torn last line', () => {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'hk-j-')), 'j.jsonl');
  const j = new Journal(f);
  for (let i = 0; i < 500; i++) j.append({ kind: 'x', i, pad: 'é'.repeat(300) });
  fs.appendFileSync(f, '{"kind":"to');
  const rows = Journal.read(f);
  assert.equal(rows.length, 500);
  assert.equal(rows[499].i, 499);
  assert.equal(rows[0].pad, 'é'.repeat(300));
});
