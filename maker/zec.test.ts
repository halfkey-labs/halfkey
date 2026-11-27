// Unit tests for the maker's ZEC desk (maker/zec.ts) against a mocked zebrad and Solana connection.
// The real-chain run is e2e/zec-swap.ts (zebrad regtest + local validator).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Keypair, PublicKey, SYSVAR_CLOCK_PUBKEY, Transaction } from '@solana/web3.js';
import * as J from '../sdk/jupiter.ts';
import { setPriority } from './lib.ts';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes, bytesToHex } from '@noble/hashes/utils';
import * as Z from '../sdk/zec.ts';
import * as S from '../sdk/zecswap.ts';
import * as H from '../sdk/htlc.ts';
import http from 'node:http';
import { ed25519 } from '@noble/curves/ed25519';
import { ZecDesk, ZecWallet, zecHttp, HttpError, type ZecConfig, type DeskDeps } from './zec.ts';
import { Screen } from './sanctions.ts';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hk-zec-'));
process.on('exit', () => fs.rmSync(tmp, { recursive: true, force: true }));

/** A tiny zebrad: one funded address, NU7 from height 1, accepts any well-formed tx and indexes its outputs. */
function fakeZebra(tip0 = 1000) {
  const st = { tip: tip0, utxos: new Map<string, { address: string; script: string; value: bigint; height: number }>(), sent: [] as string[], txs: new Map<string, any>() };
  const call: Z.Rpc = async (m, p: any[] = []) => {
    switch (m) {
      case 'getblockchaininfo': return { blocks: st.tip, upgrades: { '77190ad9': { name: 'NU7', activationheight: 1, status: 'active' } } };
      case 'getaddressutxos': {
        const want = new Set(p[0].addresses);
        return [...st.utxos.entries()].filter(([, u]) => want.has(u.address)).map(([k, u]) => ({ address: u.address, txid: k.split(':')[0], outputIndex: Number(k.split(':')[1]), script: u.script, satoshis: Number(u.value), height: u.height }));
      }
      case 'sendrawtransaction': {
        st.sent.push(p[0]);
        const tx = Z.parseTx(Z.unhex(p[0]));
        const id = Z.txid(tx);
        tx.vout.forEach((o, i) => st.utxos.set(`${id}:${i}`, { address: '', script: Z.hex(o.script), value: o.value, height: 0 }));
        st.txs.set(id, { txid: id, confirmations: 0, vout: tx.vout.map((o) => ({ valueZat: Number(o.value), scriptPubKey: { hex: Z.hex(o.script) } })) });
        return id;
      }
      case 'getrawtransaction': { const t = st.txs.get(p[0]); if (!t) throw new Error('no tx'); return t; }
      case 'gettxout': return st.utxos.has(`${p[0]}:${p[1]}`) ? { value: 1 } : null;
      default: throw new Error(`unmocked ${m}`);
    }
  };
  return { st, call };
}

/** A SOL->ZEC request as the page sends it: the taker's wallet signs it (a real ZEC lock follows). */
const ask4 = (q: { quote: S.ZecQuote; sig: string }, swapId: string, claimPub: string, who: Keypair, extra: Record<string, unknown> = {}) => ({
  ...q, swapId, taker: who.publicKey.toBase58(), claimPub, takerSig: bytesToHex(ed25519.sign(S.offerRequestMessage(q.quote, swapId, claimPub), who.secretKey.slice(0, 32))), ...extra,
});

/** A ZEC->SOL request as the page sends it. */
const ask8 = (q: { quote: S.ZecQuote; sig: string }, swapId: string, keys: { hashlock: Uint8Array; refundPub: Uint8Array }, who: Keypair = Keypair.generate(), extra: Record<string, unknown> = {}) => {
  const hashlock = Z.hex(keys.hashlock), refundPub = Z.hex(keys.refundPub);
  return { ...q, swapId, taker: who.publicKey.toBase58(), hashlock, refundPub, takerSig: bytesToHex(ed25519.sign(S.offerRequestMessage(q.quote, swapId, S.zecToSolKeys(hashlock, refundPub)), who.secretKey.slice(0, 32))), ...extra };
};

function desk(o: Partial<ZecConfig> = {}, bal = 100n * 1_000_000_000n, deps: Partial<DeskDeps> = {}, connExtra: Record<string, unknown> = {}) {
  const seedFile = path.join(tmp, `seed-${Math.random()}`);
  fs.writeFileSync(seedFile, bytesToHex(randomBytes(32)));
  const me = Keypair.generate();
  const pid = Keypair.generate().publicKey;
  const cfg: ZecConfig = { zebraRpc: 'http://127.0.0.1:1', zecNet: 'regtest', seedFile, journal: path.join(tmp, `j-${Math.random()}.jsonl`), directions: 12, zatPerSol: 7_000_000, spreadBps: 100, t1Secs: 3600, minConf: 60, marginSecs: 7200, consentSecs: 3600, payWindowSecs: 1800, claimMarginSecs: 900, ...o };
  const maker = { active: true, directions: 15, min: 10_000_000n, max: 5_000_000_000n } as any;
  const conn = { getBalance: async () => Number(bal), ...connExtra } as any;
  const d = new ZecDesk({ cfg, conn, me, pid, feeBps: () => 50, maker: () => maker, ...deps });
  return { d, me, pid, cfg };
}

test('quotes: spread in the maker\'s favour both ways, range and direction enforced, signed', async () => {
  const { d, me } = desk();
  const z = fakeZebra();
  (d as any).call = z.call;
  await d.init().catch(() => {}); // journal/wallet setup; the fake has no ups for d.call before init
  d.ups = await Z.upgradesFromNode(z.call);
  const a = d.quote(4, 1_000_000_000n), b = d.quote(8, 1_000_000_000n);
  assert.equal(a.quote.zats, String(Math.floor(7_000_000 * 0.99)));
  assert.equal(b.quote.zats, String(Math.floor(7_000_000 * 1.01)));
  assert.ok(S.verifyZecQuote(a.quote, a.sig, me.publicKey.toBytes()));
  assert.throws(() => d.quote(1, 1_000_000_000n), /direction/);
  assert.throws(() => d.quote(4, 1n), /amount outside/);
  assert.throws(() => d.quote(4, 6_000_000_000n), /amount outside/);
});

test('inventory skew: low ZEC widens SOL->ZEC and tightens ZEC->SOL; below the floor SOL->ZEC pauses', async () => {
  const { d } = desk();
  const z = fakeZebra();
  (d as any).call = z.call;
  await d.init().catch(() => {});
  d.ups = await Z.upgradesFromNode(z.call);
  const flat4 = Math.floor(7_000_000 * 0.99), flat8 = Math.floor(7_000_000 * 1.01);
  d.inv = { coin: 50, sol: 50, at: Date.now() };
  assert.equal(d.quote(4, 1_000_000_000n).quote.zats, String(flat4), 'on target: flat');
  d.inv = { coin: 15, sol: 85, at: Date.now() };
  const give = Number(d.quote(4, 1_000_000_000n).quote.zats), take = Number(d.quote(8, 1_000_000_000n).quote.zats);
  assert.ok(give < flat4, 'SOL->ZEC pays less ZEC while ZEC is low');
  assert.ok(give >= Math.floor(7_000_000 * (1 - 0.025)), 'widening capped at +1.5%');
  assert.ok(take < flat8 && take >= 7_000_000, 'ZEC->SOL asks less ZEC, never better than mid');
  d.inv = { coin: 4, sol: 96, at: Date.now() };
  assert.throws(() => d.quote(4, 1_000_000_000n), /low on ZEC/);
  assert.ok(d.quote(8, 1_000_000_000n), 'the refilling direction stays open');
  d.inv = { coin: 96, sol: 4, at: Date.now() };
  assert.throws(() => d.quote(8, 1_000_000_000n), /low on SOL/);
  const off = desk({ skew: { enabled: false } }).d;
  (off as any).call = z.call; off.ups = d.ups; off.inv = { coin: 4, sol: 96, at: Date.now() };
  assert.equal(off.quote(4, 1_000_000_000n).quote.zats, String(flat4), 'skew off: flat');
});

test('SOL->ZEC start: checks the request, funds the HTLC, and the offer passes the taker checks', async () => {
  const { d, me, pid } = desk({ minConf: 3 });
  const z = fakeZebra();
  (d as any).call = z.call;
  d.ups = await Z.upgradesFromNode(z.call);
  d.wallet = new ZecWallet(z.call, d.key('hot'), 'regtest');
  z.st.utxos.set(`${'a'.repeat(64)}:0`, { address: d.wallet.address, script: Z.hex(d.wallet.script), value: 50n * Z.ZAT, height: 10 });
  await (d as any).tip();
  const takerKp = Keypair.generate(), taker = takerKp.publicKey;
  const keys = S.zecKeys(randomBytes(64), randomBytes(32));
  const swapId = bytesToHex(randomBytes(32));
  const { quote, sig } = d.quote(4, 500_000_000n);
  await assert.rejects(d.start({ quote, sig: '00'.repeat(64), swapId, taker: taker.toBase58(), claimPub: Z.hex(keys.claimPub) }), /not my quote/);
  await assert.rejects(d.start(ask4({ quote, sig }, swapId, '02' + '00'.repeat(32), takerKp)), /claimPub/);
  const offer = await d.start(ask4({ quote, sig }, swapId, Z.hex(keys.claimPub), takerKp)) as S.SolToZecOffer;
  await assert.rejects(d.start(ask4({ quote, sig }, bytesToHex(randomBytes(32)), Z.hex(keys.claimPub), takerKp)), /already used/);
  // The funding pays exactly the quoted zats to the HTLC, plus change, and is signed correctly.
  assert.equal(z.st.sent.length, 1);
  const lock = S.verifySolToZecOffer(offer, { pid, taker, swapId: Buffer.from(swapId, 'hex'), quote, quoteSig: sig, claimPub: keys.claimPub, zecNet: 'regtest', now: Math.floor(Date.now() / 1000) });
  assert.equal(lock.amount, 500_000_000n);
  const salt = d.swaps.get(swapId)!.salt!;
  assert.match(salt, /^[0-9a-f]{32}$/);
  assert.deepEqual(lock.hashlock, sha256(d.preimage(swapId, salt)));
  // The maker's refund height satisfies the taker's own safety check at the consent deadline.
  const nowS = Math.floor(Date.now() / 1000);
  const blocksByExpiry = Math.ceil((offer.consentExpiry - nowS) / 25 / 0.75);
  assert.equal(S.lockHeightSafe(d.ups, 1000 + blocksByExpiry, offer.consentExpiry, offer.lockHeight, offer.consentExpiry + offer.t1Secs, d.policy), null);
  // Journal replay restores the swap.
  const again = new ZecDesk({ ...(d as any).d });
  (again as any).call = z.call;
  await again.init();
  assert.equal(again.swaps.get(swapId)?.phase, 'funded');
  assert.equal(again.swaps.get(swapId)?.fundTxid, offer.fundTxid);
  // The funding output is the HTLC, with the quoted amount; every input signature verifies.
  const tx = Z.parseTx(Z.unhex(z.st.sent[0]));
  assert.deepEqual(tx.vout[0], { value: 7_000_000n * 99n / 200n, script: Z.p2sh(Z.unhex(offer.redeem)) });
  const f = await Z.checkFunding(z.call, offer.fundTxid, 0, Z.unhex(offer.redeem));
  assert.equal(f.value, BigInt(quote.zats));
  for (let i = 0; i < tx.vin.length; i++) {
    const sigLen = tx.vin[i].scriptSig[0];
    const sigB = tx.vin[i].scriptSig.slice(1, 1 + sigLen);
    assert.ok(Z.verifySig(Z.sighash(tx, i, [{ value: 50n * Z.ZAT, script: d.wallet.script }]), sigB, d.wallet.pub));
  }
});

test('SOL->ZEC: no inventory = a clean refusal, the swap is closed in the journal', async () => {
  const { d } = desk();
  const z = fakeZebra();
  (d as any).call = z.call;
  d.ups = await Z.upgradesFromNode(z.call);
  d.wallet = new ZecWallet(z.call, d.key('hot'), 'regtest');
  const { quote, sig } = d.quote(4, 500_000_000n);
  const swapId = bytesToHex(randomBytes(32));
  await assert.rejects(d.start(ask4({ quote, sig }, swapId, Z.hex(S.zecKeys(randomBytes(64), randomBytes(32)).claimPub), Keypair.generate())), /inventory/);
  assert.equal(d.swaps.get(swapId)?.phase, 'done');
});

test('ZEC->SOL start: our claim key, the user\'s hashlock and refund key; SOL inventory checked', async () => {
  const { d, pid, me } = desk();
  const z = fakeZebra();
  (d as any).call = z.call;
  d.ups = await Z.upgradesFromNode(z.call);
  await (d as any).tip();
  const swapId = bytesToHex(randomBytes(32));
  const keys = S.zecKeys(randomBytes(64), Buffer.from(swapId, 'hex'));
  const { quote, sig } = d.quote(8, 500_000_000n);
  await assert.rejects(d.start({ quote, sig, swapId, taker: Keypair.generate().publicKey.toBase58(), hashlock: '00'.repeat(32), refundPub: Z.hex(keys.refundPub) }), /hashlock/);
  const offer = await d.start(ask8({ quote, sig }, swapId, keys)) as S.ZecToSolOffer;
  const t = S.verifyZecToSolOffer(offer, { pid, swapId: Buffer.from(swapId, 'hex'), quote, quoteSig: sig, keys, zecNet: 'regtest', now: 0, tip: 1000, ups: d.ups, policy: S.MAINNET_POLICY });
  assert.deepEqual(t.claimPub, Z.pubOf(d.key('claim', swapId, d.swaps.get(swapId)!.salt)));
  assert.equal(offer.escrow, H.htlcPda(pid, me.publicKey, Buffer.from(swapId, 'hex')).toBase58());
  // The deposit window, confirmations and t1 all fit before the refund height (maker side check at lock time).
  const lockAt = Math.floor(Date.now() / 1000) + 1800 + 60 * 25;
  assert.equal(S.lockHeightSafe(d.ups, 1000 + Math.ceil((1800 + 60 * 25) / 25 / 0.75), lockAt, offer.lockHeight, lockAt + 3600, d.policy), null);
  const poor = desk({}, 1n);
  (poor.d as any).call = z.call; poor.d.ups = d.ups;
  const q2 = poor.d.quote(8, 500_000_000n);
  await assert.rejects(poor.d.start(ask8(q2, bytesToHex(randomBytes(32)), keys)), /SOL inventory/);
});

test('upgrade window: quotes refused when an upgrade activates before the refund height would', async () => {
  const { d } = desk();
  const z = fakeZebra(3_543_300);
  (d as any).call = z.call;
  d.ups = Z.MAINNET_UPGRADES;
  await (d as any).tip();
  assert.throws(() => d.quote(4, 500_000_000n), /NU7/);
});

test('wallet: picks inputs, pays change, signs every input (ZIP 244), refuses when short', async () => {
  const z = fakeZebra();
  const w = new ZecWallet(z.call, Z.privFrom(new TextEncoder().encode('w')), 'regtest');
  z.st.utxos.set(`${'b'.repeat(64)}:1`, { address: w.address, script: Z.hex(w.script), value: 3n * Z.ZAT, height: 5 });
  z.st.utxos.set(`${'c'.repeat(64)}:0`, { address: w.address, script: Z.hex(w.script), value: 2n * Z.ZAT, height: 6 });
  const dest = Z.p2sh(new Uint8Array(10));
  await assert.rejects(w.pay([{ value: 6n * Z.ZAT, script: dest }], Z.BRANCH.NU7), /not enough/);
  const { txid, tx } = await w.pay([{ value: 4n * Z.ZAT, script: dest }], Z.BRANCH.NU7);
  assert.equal(txid, Z.txid(Z.parseTx(Z.unhex(z.st.sent.at(-1)!))));
  assert.equal(tx.vin.length, 2);
  const fee = 5n * Z.ZAT - 4n * Z.ZAT - tx.vout[1].value;
  assert.equal(fee, Z.zip317Fee(tx)); // change = inputs - payment - ZIP 317 fee
  assert.deepEqual(tx.vout[1].script, w.script);
  // Inputs are reserved until they leave the UTXO set: a second payment cannot reuse them.
  await assert.rejects(w.pay([{ value: 1n * Z.ZAT, script: dest }], Z.BRANCH.NU7), /not enough/);
});

test('review fix: two concurrent requests with one swap id fund one HTLC; a reused id or hashlock is refused', async () => {
  const { d } = desk({ minConf: 3 });
  const z = fakeZebra();
  (d as any).call = z.call;
  d.ups = await Z.upgradesFromNode(z.call);
  d.wallet = new ZecWallet(z.call, d.key('hot'), 'regtest');
  for (const k of ['a', 'b', 'c']) z.st.utxos.set(`${k.repeat(64)}:0`, { address: d.wallet.address, script: Z.hex(d.wallet.script), value: 50n * Z.ZAT, height: 10 });
  const keys = S.zecKeys(randomBytes(64), randomBytes(32));
  const swapId = bytesToHex(randomBytes(32));
  const req = (q: ReturnType<typeof d.quote>, who: Keypair) => d.start(ask4(q, swapId, Z.hex(keys.claimPub), who), '1.2.3.4');
  const r = await Promise.allSettled([req(d.quote(4, 500_000_000n), Keypair.generate()), req(d.quote(4, 500_000_000n), Keypair.generate())]);
  assert.equal(r.filter((x) => x.status === 'fulfilled').length, 1);
  assert.match(String((r.find((x) => x.status === 'rejected') as PromiseRejectedResult).reason), /swap id already used/);
  assert.equal(z.st.sent.length, 1);
  // Same id again after the journal is reloaded: refused.
  const again = new ZecDesk({ ...(d as any).d });
  (again as any).call = z.call; await again.init();
  await assert.rejects(again.start(ask4(again.quote(4, 500_000_000n), swapId, Z.hex(keys.claimPub), Keypair.generate())), /already used/);
  // ZEC->SOL: a hashlock already used is refused.
  const h = S.zecKeys(randomBytes(64), randomBytes(32));
  await again.start(ask8(again.quote(8, 500_000_000n), bytesToHex(randomBytes(32)), h));
  await assert.rejects(again.start({ ...again.quote(8, 500_000_000n), swapId: bytesToHex(randomBytes(32)), taker: Keypair.generate().publicKey.toBase58(), hashlock: Z.hex(h.hashlock), refundPub: Z.hex(h.refundPub) }), /hashlock already used/);
});

test('review fix: SOL->ZEC admission caps (per taker, per IP, total unlocked ZEC) and the taker\'s SOL balance', async () => {
  const mk = (bal: bigint) => {
    const x = desk({ minConf: 3, s2zLimits: { perTaker: 1, perIp: 2, unlockedZats: String(8_000_000n), perIpZats: String(8_000_000n) } }, bal);
    return x;
  };
  const { d } = mk(100n * 1_000_000_000n);
  const z = fakeZebra();
  (d as any).call = z.call;
  d.ups = await Z.upgradesFromNode(z.call);
  d.wallet = new ZecWallet(z.call, d.key('hot'), 'regtest');
  for (const k of 'abcdef') z.st.utxos.set(`${k.repeat(64)}:0`, { address: d.wallet.address, script: Z.hex(d.wallet.script), value: 50n * Z.ZAT, height: 10 });
  const keys = S.zecKeys(randomBytes(64), randomBytes(32));
  const go = (who: Keypair, ip: string) => d.start(ask4(d.quote(4, 500_000_000n), bytesToHex(randomBytes(32)), Z.hex(keys.claimPub), who), ip);
  const t1 = Keypair.generate();
  await go(t1, 'ip1');
  await assert.rejects(go(t1, 'ip2'), /already have an offer/);
  await go(Keypair.generate(), 'ip1');
  await assert.rejects(go(Keypair.generate(), 'ip1'), /too many open offers/);
  await assert.rejects(go(Keypair.generate(), 'ip3'), /busy/); // 3 x 3.465M > 8M unlocked budget
  const poor = mk(1n);
  (poor.d as any).call = z.call; poor.d.ups = d.ups; poor.d.wallet = d.wallet;
  await assert.rejects(poor.d.start(ask4(poor.d.quote(4, 500_000_000n), bytesToHex(randomBytes(32)), Z.hex(keys.claimPub), Keypair.generate())), /does not hold the SOL/);
});

test('review fix: an RPC error is never read as "spent"', async () => {
  const z = fakeZebra();
  const redeem = Z.htlcScript({ hashlock: sha256(new Uint8Array(32)), claimPub: Z.pubOf(Z.privFrom(new Uint8Array([1]))), refundPub: Z.pubOf(Z.privFrom(new Uint8Array([2]))), lockHeight: 500 });
  const w = new ZecWallet(z.call, Z.privFrom(new TextEncoder().encode('f')), 'regtest');
  z.st.utxos.set(`${'d'.repeat(64)}:0`, { address: w.address, script: Z.hex(w.script), value: 5n * Z.ZAT, height: 1 });
  const { txid } = await w.pay([{ value: Z.ZAT, script: Z.p2sh(redeem) }], Z.BRANCH.NU7);
  assert.equal((await Z.checkFunding(z.call, txid, 0, redeem)).spent, false);
  const flaky: Z.Rpc = async (m, p) => { if (m === 'gettxout') throw new Error('zebrad busy'); return z.call(m, p); };
  await assert.rejects(Z.checkFunding(flaky, txid, 0, redeem), /busy/);
  z.st.utxos.delete(`${txid}:0`);
  assert.equal((await Z.checkFunding(z.call, txid, 0, redeem)).spent, true);
  // A coinbase-funded HTLC is refused (its transparent outputs could never be claimed transparently).
  z.st.txs.set('e'.repeat(64), { vin: [{ coinbase: '00' }], vout: [{ valueZat: 1e8, scriptPubKey: { hex: Z.hex(Z.p2sh(redeem)) } }], confirmations: 200 });
  await assert.rejects(Z.checkFunding(z.call, 'e'.repeat(64), 0, redeem), /coinbase/);
});

// ------------------------------------------------------------------ the same bar as the XMR maker
/** A desk wired to the fake zebrad, with a funded hot wallet. */
async function ready(o: Partial<ZecConfig> = {}, bal = 100n * 1_000_000_000n, deps: Partial<DeskDeps> = {}, connExtra: Record<string, unknown> = {}) {
  const x = desk({ minConf: 3, ...o }, bal, deps, connExtra);
  const z = fakeZebra();
  (x.d as any).call = z.call;
  x.d.ups = await Z.upgradesFromNode(z.call);
  x.d.wallet = new ZecWallet(z.call, x.d.key('hot'), 'regtest');
  for (const k of 'abcdef') z.st.utxos.set(`${k.repeat(64)}:0`, { address: x.d.wallet.address, script: Z.hex(x.d.wallet.script), value: 50n * Z.ZAT, height: 10 });
  await (x.d as any).tip();
  return { ...x, z };
}
const fakeFeed = (rate: number) => {
  const f = { st: { ok: true, rate, source: 'kraken', atMs: Date.now() } as any, reads: 0, lastError: '', async refresh() { this.reads++; }, state() { return this.st; } };
  return f;
};
const claimPub = () => Z.hex(S.zecKeys(randomBytes(64), randomBytes(32)).claimPub);
const newId = () => bytesToHex(randomBytes(32));
const code = (n: number) => (e: unknown) => e instanceof HttpError && e.code === n;

test('live price: the rate comes from the feed, not the config; no fresh price = no quote and no swap (503)', async () => {
  const feed = fakeFeed(0.1); // 0.1 ZEC per SOL
  const { d, z } = await ready({ livePrice: true, zatPerSol: 7_000_000 }, undefined, { feed });
  assert.equal(d.quote(4, 1_000_000_000n).quote.zats, String(Math.floor(10_000_000 * 0.99)), 'priced at the feed');
  const q = d.quote(4, 500_000_000n);
  feed.st = { ok: false, reason: 'kraken and coingecko disagree' };
  assert.throws(() => d.quote(4, 1_000_000_000n), code(503));
  assert.throws(() => d.quote(8, 1_000_000_000n), code(503));
  assert.equal(d.info().priceLive, false);
  await assert.rejects(d.start(ask4(q, newId(), claimPub(), Keypair.generate())), code(503));
  assert.equal(z.st.sent.length, 0, 'an earlier quote does not fund an HTLC on a dead price');
  feed.st = { ok: true, rate: 500_000, source: 'kraken', atMs: Date.now() }; // a broken source
  assert.throws(() => d.quote(4, 1_000_000_000n), code(503));
  feed.st = { ok: true, rate: 0.2, source: 'kraken', atMs: Date.now() };
  d.setPrice(1);
  assert.equal(d.quote(4, 1_000_000_000n).quote.zats, String(Math.floor(20_000_000 * 0.99)), 'setPrice never overrides a live feed');
  assert.equal(d.info().priceLive, true);
});

test('live price: on by default on mainnet, and nothing is quoted before the first read', async () => {
  const seedFile = path.join(tmp, 'seed-main'); fs.writeFileSync(seedFile, bytesToHex(randomBytes(32)));
  const { d } = desk({ zecNet: 'mainnet', seedFile });
  assert.throws(() => d.quote(4, 1_000_000_000n), code(503));
});

test('screening: a listed wallet gets no quote honoured, either direction, and nothing is spent', async () => {
  const listed = Keypair.generate();
  const screen = new Screen({ date: '2026-11-01', addresses: { SOL: [listed.publicKey.toBase58()] } });
  const { d, z } = await ready({}, undefined, { screen });
  const keys = S.zecKeys(randomBytes(64), randomBytes(32));
  await assert.rejects(d.start(ask4(d.quote(4, 500_000_000n), newId(), claimPub(), listed)), /cannot take this swap/);
  await assert.rejects(d.start({ ...d.quote(8, 500_000_000n), swapId: newId(), taker: listed.publicKey.toBase58(), hashlock: Z.hex(keys.hashlock), refundPub: Z.hex(keys.refundPub) }), /cannot take this swap/);
  assert.equal(z.st.sent.length, 0);
  assert.equal(d.swaps.size, 0);
  await d.start(ask4(d.quote(4, 500_000_000n), newId(), claimPub(), Keypair.generate()));
  assert.equal(z.st.sent.length, 1, 'anyone else goes through');
});

test('handshake: a request that names a rich wallet without its signature locks no ZEC', async () => {
  const { d, z } = await ready();
  const whale = Keypair.generate(), griefer = Keypair.generate(), pub = claimPub();
  const q = d.quote(4, 500_000_000n), id = newId();
  await assert.rejects(d.start({ ...q, swapId: id, taker: whale.publicKey.toBase58(), claimPub: pub }), /wallet signature/);
  await assert.rejects(d.start(ask4(q, id, pub, griefer, { taker: whale.publicKey.toBase58() })), /wallet signature/);
  await assert.rejects(d.start(ask4(q, id, claimPub(), whale, { claimPub: pub })), /wallet signature/, 'the signature covers the claim key');
  assert.equal(z.st.sent.length, 0);
  assert.equal(d.swaps.size, 0);
  await d.start(ask4(q, id, pub, whale));
  assert.equal(z.st.sent.length, 1, 'the refused requests did not burn the quote');
});

test('handshake: a wallet that left an offer unlocked is refused for an hour; an address after two; others are not', async () => {
  const now = () => Math.floor(Date.now() / 1000);
  const clock = Buffer.alloc(40); clock.writeBigInt64LE(BigInt(now()), 32);
  const conn = { getAccountInfo: async (k: PublicKey) => (k.equals(SYSVAR_CLOCK_PUBKEY) ? { data: clock } : null) };
  const { d } = await ready({ consentSecs: 1, s2zLimits: { perTaker: 1, perIp: 5, unlockedZats: String(100n * Z.ZAT) } }, undefined, {}, conn);
  const w1 = Keypair.generate(), w2 = Keypair.generate();
  for (const w of [w1, w2]) {
    const id = newId();
    await d.start(ask4(d.quote(4, 500_000_000n), id, claimPub(), w), 'ip1');
    d.swaps.get(id)!.consentExpiry = now() - 200; // the consent ran out long ago
    for (let i = 0; i < 3; i++) await (d as any).step(d.swaps.get(id));
    assert.equal(d.swaps.get(id)!.phase, 'refunding-zec');
    assert.ok(d.swaps.get(id)!.noShowAt);
  }
  await assert.rejects(d.start(ask4(d.quote(4, 500_000_000n), newId(), claimPub(), w1), 'ip9'), /unpaid/);
  await assert.rejects(d.start(ask4(d.quote(4, 500_000_000n), newId(), claimPub(), Keypair.generate()), 'ip1'), /unpaid/);
  await d.start(ask4(d.quote(4, 500_000_000n), newId(), claimPub(), Keypair.generate()), 'ip2');
  // survives a restart: the journal keeps it
  const again = new ZecDesk({ ...(d as any).d });
  (again as any).call = (d as any).call; await again.init();
  await assert.rejects(again.start(ask4(again.quote(4, 500_000_000n), newId(), claimPub(), w1), 'ip9'), /unpaid/);
});

test('handshake: one address cannot take the whole unlocked-ZEC budget', async () => {
  const { d } = await ready({ s2zLimits: { perTaker: 1, perIp: 9, unlockedZats: String(8_000_000n) } });
  await d.start(ask4(d.quote(4, 500_000_000n), newId(), claimPub(), Keypair.generate()), 'ip1');
  await assert.rejects(d.start(ask4(d.quote(4, 500_000_000n), newId(), claimPub(), Keypair.generate()), 'ip1'), /too many open offers/);
  await d.start(ask4(d.quote(4, 500_000_000n), newId(), claimPub(), Keypair.generate()), 'ip2');
});

test('handshake: a ZEC->SOL offer past its deposit window stops counting against the offer caps', async () => {
  const { d } = await ready({ offerLimits: { total: 1, perIp: 1 } });
  const offer = async (ip: string) => {
    const keys = S.zecKeys(randomBytes(64), randomBytes(32)), id = newId();
    await d.start(ask8(d.quote(8, 500_000_000n), id, keys), ip);
    return id;
  };
  const a = await offer('ip1');
  await assert.rejects(offer('ip2'), /busy/);
  d.swaps.get(a)!.payBy = Math.floor(Date.now() / 1000) - 1;
  await offer('ip2');
});

test('coin payer: needs enough of the coin, worth the lock, plus fee SOL; a failed read is not "does not hold"', async () => {
  const mint = Keypair.generate().publicKey.toBase58();
  const tokenData = (amt: bigint) => { const b = Buffer.alloc(165); b.writeBigUInt64LE(amt, 64); return b; };
  let tokens: any = async () => ({ value: [{ account: { data: tokenData(600n) } }] });
  let value: any = async () => 500_000_000n;
  const { d, z } = await ready({}, 3_000_000n, { coinValue: (...a: [string, bigint, string]) => value(...a) }, { getTokenAccountsByOwner: (...a: unknown[]) => tokens(...a) });
  const go = (coinAmount = '500') => d.start(ask4(d.quote(4, 500_000_000n), newId(), claimPub(), Keypair.generate(), { coinMint: mint, coinAmount }));
  await assert.rejects(d.start(ask4(d.quote(4, 500_000_000n), newId(), claimPub(), Keypair.generate())), /does not hold the SOL/, 'no coin named: the SOL itself is needed');
  tokens = async () => { throw new Error('429 from the RPC'); };
  await assert.rejects(go(), code(503));
  tokens = async () => ({ value: [{ account: { data: tokenData(1n) } }] });
  await assert.rejects(go(), /does not hold that much/, 'one raw unit of the coin is not enough');
  tokens = async () => ({ value: [{ account: { data: tokenData(300n) } }, { account: { data: tokenData(300n) } }] });
  value = async () => 1000n;
  await assert.rejects(go(), /does not cover this swap/, 'a worthless coin locks no ZEC');
  value = async () => { throw new J.NoRoute(); };
  await assert.rejects(go(), /no route/);
  value = async () => { throw new J.JupiterBusy(0); };
  await assert.rejects(go(), code(503), 'a busy Jupiter is not a worthless coin');
  assert.equal(z.st.sent.length, 0);
  await assert.rejects(go('0'), /coinAmount/);
  value = async (m: string, amt: bigint) => { assert.equal(m, mint); assert.equal(amt, 500n); return 460_000_000n; }; // 92%: moved a little since the quote
  await go();
  assert.equal(z.st.sent.length, 1);
  const broke = await ready({}, 1000n, { coinValue: async () => 500_000_000n }, { getTokenAccountsByOwner: async () => ({ value: [{ account: { data: tokenData(500n) } }] }) });
  await assert.rejects(broke.d.start(ask4(broke.d.quote(4, 500_000_000n), newId(), claimPub(), Keypair.generate(), { coinMint: mint, coinAmount: '500' })), /network fees/);
});

test('quote: refused up front when the inventory for it is not there; a failed read does not read as empty', async () => {
  const { d, z } = await ready({ skew: { enabled: false } });
  const q = (dir: number, lam = 500_000_000n) => d.handle('GET', new URL(`http://x/v1/zec/quote?direction=${dir}&lamports=${lam}`), async () => ({}), '');
  await q(4);
  z.st.utxos.clear();
  await assert.rejects(q(4), /not enough ZEC inventory/);
  const real = (d as any).call;
  (d.wallet as any).call = async (m: string, p: any[]) => { if (m === 'getaddressutxos') throw new Error('zebrad busy'); return real(m, p); };
  await q(4);
  const poor = await ready({ skew: { enabled: false } }, 1n);
  await assert.rejects(poor.d.handle('GET', new URL('http://x/v1/zec/quote?direction=8&lamports=500000000'), async () => ({}), ''), /not enough SOL inventory/);
});

test('rate limits: per client address on quotes, swaps and other posts; another address is not affected', async () => {
  const { d } = await ready({ skew: { enabled: false }, rateLimits: { quotePerMin: 2, swapPerMin: 1, postPerMin: 1 } });
  const quote = (ip: string) => d.handle('GET', new URL('http://x/v1/zec/quote?direction=8&lamports=500000000'), async () => ({}), ip);
  await quote('ip1'); await quote('ip1');
  await assert.rejects(quote('ip1'), code(429));
  await quote('ip2');
  const swap = (ip: string) => d.handle('POST', new URL('http://x/v1/zec/swap'), async () => ({}), ip);
  await assert.rejects(swap('ip1'), code(400));
  await assert.rejects(swap('ip1'), code(429));
  await assert.rejects(swap('ip2'), code(400));
  const funded = (ip: string) => d.handle('POST', new URL('http://x/v1/zec/funded'), async () => ({ swapId: 'none' }), ip);
  await assert.rejects(funded('ip1'), code(404));
  await assert.rejects(funded('ip1'), code(429));
});

test('standalone desk: the client address comes through a trusted proxy; it answers /v1/info', async () => {
  const { d, me, pid } = await ready({ skew: { enabled: false }, rateLimits: { quotePerMin: 1 } });
  const srv = http.createServer(zecHttp(d, { trustProxy: true }));
  await new Promise<void>((ok) => srv.listen(0, '127.0.0.1', ok));
  try {
    const base = `http://127.0.0.1:${(srv.address() as any).port}`;
    const ask = (ip: string) => fetch(`${base}/v1/zec/quote?direction=8&lamports=500000000`, { headers: { 'cf-connecting-ip': ip } }).then((r) => r.status);
    assert.equal(await ask('9.9.9.1'), 200);
    assert.equal(await ask('9.9.9.1'), 429);
    assert.equal(await ask('9.9.9.2'), 200, 'behind one tunnel, clients stay separate');
    const info = await fetch(`${base}/v1/info`).then((r) => r.json()) as any;
    assert.equal(info.maker, me.publicKey.toBase58());
    assert.equal(info.programId, pid.toBase58());
    assert.equal(info.online, true);
    assert.equal(info.priceLive, true);
    assert.equal((await fetch(`${base}/nope`)).status, 404);
  } finally { srv.close(); }
});

// ------------------------------------------------------------------ independent review
const clockConn = (extra: Record<string, unknown> = {}) => {
  const clock = () => { const b = Buffer.alloc(40); b.writeBigInt64LE(BigInt(Math.floor(Date.now() / 1000)), 32); return b; };
  return { getAccountInfo: async (k: PublicKey) => (k.equals(SYSVAR_CLOCK_PUBKEY) ? { data: clock() } : null), ...extra };
};
const nowS = () => Math.floor(Date.now() / 1000);

test('budget: the ZEC of an offer nobody locked counts until it is refunded, not until the consent runs out', async () => {
  const { d } = await ready({ s2zLimits: { perTaker: 1, perIp: 9, unlockedZats: String(4_000_000n), perIpZats: String(4_000_000n) } }, undefined, {}, clockConn());
  const id = newId();
  await d.start(ask4(d.quote(4, 500_000_000n), id, claimPub(), Keypair.generate()), 'ip1');
  d.swaps.get(id)!.consentExpiry = nowS() - 200;
  for (let i = 0; i < 3; i++) await (d as any).step(d.swaps.get(id));
  assert.equal(d.swaps.get(id)!.phase, 'refunding-zec');
  // 3.465M of the 4M is still sitting in the HTLC
  await assert.rejects(d.start(ask4(d.quote(4, 500_000_000n), newId(), claimPub(), Keypair.generate()), 'ip2'), /busy/);
  (d as any).record(id, 'done', { why: 'zec-refunded' });
  await d.start(ask4(d.quote(4, 500_000_000n), newId(), claimPub(), Keypair.generate()), 'ip2');
});

test('funding: an error after the send leaves the swap open; the funding is found on chain and refunded; only "nothing sent" closes it', async () => {
  const { d, z } = await ready({}, undefined, {}, clockConn());
  const real = z.call;
  let accepted = '';
  (d.wallet as any).call = async (m: string, p: any[]) => { if (m !== 'sendrawtransaction') return real(m, p); accepted = await real(m, p); throw new Error('fetch failed'); };
  const id = newId();
  await assert.rejects(d.start(ask4(d.quote(4, 500_000_000n), id, claimPub(), Keypair.generate())), code(503));
  assert.ok(accepted, 'the node took it');
  const s = d.swaps.get(id)!;
  assert.equal(s.phase, 'funded');
  assert.equal(s.fundTxid, undefined);
  // the inputs of that send are not spent again
  (d.wallet as any).call = real;
  assert.equal((await d.wallet.utxos()).length, 5);
  // a chain that can't be read says nothing, even past the give-up time
  (d as any).tipCache = { at: Date.now(), tip: s.lockHeight + 500 };
  (d as any).call = async (m: string, p: any[]) => { if (m === 'getaddressutxos') throw new Error('zebrad busy'); return real(m, p); };
  await assert.rejects((d as any).step(s), /busy/);
  assert.equal(s.phase, 'funded');
  // the output is on chain: found, and it refunds with no no-show against a user who never got the offer
  (d as any).call = real;
  (d as any).tipCache = { at: Date.now(), tip: 1000 };
  z.st.utxos.get(`${accepted}:0`)!.address = Z.htlcAddress('regtest', Z.unhex(s.redeem));
  await (d as any).step(s);
  assert.equal(s.fundTxid, accepted);
  s.consentExpiry = nowS() - 200;
  for (let i = 0; i < 3; i++) await (d as any).step(s);
  assert.equal(s.phase, 'refunding-zec');
  assert.equal(s.noShowAt, undefined);
  // nothing at the address and the time is up: closed
  const other = await ready({}, undefined, {}, clockConn());
  (other.d.wallet as any).call = async (m: string, p: any[]) => { if (m === 'sendrawtransaction') throw new Error('rejected'); return other.z.call(m, p); };
  const id2 = newId();
  await assert.rejects(other.d.start(ask4(other.d.quote(4, 500_000_000n), id2, claimPub(), Keypair.generate())), code(503));
  // hours later and still unmined: it could mine yet, so the search goes on
  other.d.swaps.get(id2)!.createdAt = nowS() - 20_000;
  await (other.d as any).step(other.d.swaps.get(id2));
  assert.equal(other.d.swaps.get(id2)!.phase, 'funded');
  // past its lock height: closed
  (other.d as any).tipCache = { at: Date.now(), tip: other.d.swaps.get(id2)!.lockHeight + 101 };
  await (other.d as any).step(other.d.swaps.get(id2));
  assert.equal(other.d.swaps.get(id2)!.phase, 'done');
});

test('ZEC->SOL offers: a request needs the wallet signature, and one wallet holds at most two', async () => {
  const { d } = await ready({ offerLimits: { total: 50, perIp: 50 } });
  const keys = () => S.zecKeys(randomBytes(64), randomBytes(32));
  const w = Keypair.generate(), k = keys();
  const q = d.quote(8, 500_000_000n), id = newId();
  await assert.rejects(d.start({ ...q, swapId: id, taker: w.publicKey.toBase58(), hashlock: Z.hex(k.hashlock), refundPub: Z.hex(k.refundPub) }), /wallet signature/);
  await assert.rejects(d.start(ask8(q, id, k, Keypair.generate(), { taker: w.publicKey.toBase58() })), /wallet signature/);
  await assert.rejects(d.start(ask8(q, id, k, w, { refundPub: Z.hex(keys().refundPub) })), /wallet signature/, 'the signature covers the keys');
  assert.equal(d.swaps.size, 0);
  await d.start(ask8(q, id, k, w));
  await d.start(ask8(d.quote(8, 500_000_000n), newId(), keys(), w));
  await assert.rejects(d.start(ask8(d.quote(8, 500_000_000n), newId(), keys(), w)), /already has offers/);
  await d.start(ask8(d.quote(8, 500_000_000n), newId(), keys()));
});

test('a deposit after the window: locked only at a price still good for the maker; no fresh price = wait', async () => {
  const sends: string[] = [];
  const conn = clockConn({
    getLatestBlockhash: async () => ({ blockhash: Keypair.generate().publicKey.toBase58(), lastValidBlockHeight: 1 }),
    sendRawTransaction: async () => { sends.push('x'); return 'sig'; }, getSignatureStatuses: async () => ({ value: [{ err: null, confirmationStatus: 'confirmed' }] }), getBlockHeight: async () => 1, getSignatureStatuses: async () => ({ value: [{ err: null, confirmationStatus: 'confirmed' }] }),
  });
  const feed = fakeFeed(0.07);
  const mk = await ready({ livePrice: true, minConf: 3, skew: { enabled: false } }, undefined, { feed }, conn);
  const { d, z } = mk;
  const paid = async () => {
    const id = newId(), k = S.zecKeys(randomBytes(64), randomBytes(32));
    await d.start(ask8(d.quote(8, 500_000_000n), id, k));
    const s = d.swaps.get(id)!;
    const txid = randomBytes(32).reduce((a, b) => a + b.toString(16).padStart(2, '0'), '');
    z.st.txs.set(txid, { txid, confirmations: 3, vout: [{ valueZat: Number(s.zats), scriptPubKey: { hex: Z.hex(Z.p2sh(Z.unhex(s.redeem))) } }] });
    z.st.utxos.set(`${txid}:0`, { address: Z.htlcAddress('regtest', Z.unhex(s.redeem)), script: '', value: BigInt(s.zats), height: 999 });
    s.payBy = nowS() - 600; // three blocks ago was well past it
    return s;
  };
  (d as any).policy.minConf = 3;
  const a = await paid();
  feed.st = { ok: false, reason: 'stale' };
  await (d as any).step(a);
  assert.equal(a.phase, 'offered', 'waits for a price');
  assert.equal(sends.length, 0);
  feed.st = { ok: true, rate: 0.2, source: 'kraken', atMs: Date.now() }; // ZEC got much cheaper against SOL: the old quote now loses
  await (d as any).step(a);
  assert.equal(a.phase, 'done');
  assert.match(a.why!, /price moved/);
  assert.equal(sends.length, 0);
  feed.st = { ok: true, rate: 0.07, source: 'kraken', atMs: Date.now() };
  const b = await paid();
  await (d as any).step(b);
  assert.equal(b.phase, 'sol-locked');
  assert.equal(sends.length, 1);
  // paid inside the window: the signed quote stands whatever the price did since
  const c = await paid();
  c.payBy = nowS() + 60;
  feed.st = { ok: true, rate: 0.2, source: 'kraken', atMs: Date.now() };
  await (d as any).step(c);
  assert.equal(c.phase, 'sol-locked');
});

test('sendClaim carries the shared priority fee', async () => {
  let wire: Buffer | null = null;
  const conn = { getLatestBlockhash: async () => ({ blockhash: Keypair.generate().publicKey.toBase58(), lastValidBlockHeight: 1 }), sendRawTransaction: async (w: Buffer) => { wire = w; return 'sig'; }, getSignatureStatuses: async () => ({ value: [{ err: null, confirmationStatus: 'confirmed' }] }), getBlockHeight: async () => 1 };
  const { d, me, pid } = desk({}, undefined, {}, conn);
  setPriority(conn as any, { auto: false, microLamports: 77_000 });
  try {
    await (d as any).sendClaim({ swapId: 'ab'.repeat(32), salt: '' }, { address: Keypair.generate().publicKey, maker: me.publicKey });
    const tx = Transaction.from(wire!);
    const budget = tx.instructions.filter((i) => i.programId.toBase58() === 'ComputeBudget111111111111111111111111111111');
    assert.ok(budget.some((i) => i.data[0] === 3 && Number(i.data.readBigUInt64LE(1)) === 77_000), 'setComputeUnitPrice');
    assert.equal(tx.instructions.at(-1)!.programId.toBase58(), pid.toBase58());
  } finally { setPriority(conn as any, { auto: false, microLamports: 0 }); }
});

test('status gives another device what it needs: redeem, lock height and the signed quote; recovery trusts none of it', async () => {
  const { d, me } = await ready();
  const root = randomBytes(64), idB = randomBytes(32), id = bytesToHex(idB), keys = S.zecKeys(root, idB);
  const q = d.quote(8, 500_000_000n);
  const offer = await d.start(ask8(q, id, keys)) as S.ZecToSolOffer;
  const st = d.status(id);
  assert.equal(st.redeem, offer.redeem);
  assert.equal(st.lockHeight, offer.lockHeight);
  assert.deepEqual(st.quote, q.quote);
  const h = { direction: 8, maker: me.publicKey, hashlock: keys.hashlock, quoteHash: S.zecQuoteHash(q.quote), address: new PublicKey(offer.escrow) } as any;
  const got = S.recoverZecToSol(h, st, keys, 'regtest');
  assert.equal(got.offer.htlcAddress, offer.htlcAddress);
  assert.equal(got.offer.lockHeight, offer.lockHeight);
  const stranger = S.zecKeys(randomBytes(64), idB);
  assert.throws(() => S.recoverZecToSol(h, st, stranger, 'regtest'), /did not start/);
  assert.throws(() => S.recoverZecToSol(h, st, { hashlock: keys.hashlock, refundPub: stranger.refundPub }, 'regtest'), /does not refund to this wallet/);
  assert.throws(() => S.recoverZecToSol(h, { ...st, lockHeight: st.lockHeight! + 1 }, keys, 'regtest'), /refund block/);
  assert.throws(() => S.recoverZecToSol(h, { ...st, sig: '00'.repeat(64) }, keys, 'regtest'), /quote/);
  assert.throws(() => S.recoverZecToSol({ ...h, quoteHash: new Uint8Array(32) }, st, keys, 'regtest'), /not this swap/);
  assert.throws(() => S.recoverZecToSol(h, { ...st, redeem: undefined }, keys, 'regtest'), /no record/);
});

test('htlcOutputs: lists what sits at the address; a failed read throws, it is not "none"', async () => {
  const z = fakeZebra();
  const redeem = Z.htlcScript({ hashlock: sha256(new Uint8Array(32)), claimPub: Z.pubOf(Z.privFrom(new Uint8Array([1]))), refundPub: Z.pubOf(Z.privFrom(new Uint8Array([2]))), lockHeight: 500 });
  z.st.utxos.set(`${'a'.repeat(64)}:1`, { address: Z.htlcAddress('regtest', redeem), script: '', value: 7n, height: 3 });
  assert.deepEqual(await Z.htlcOutputs(z.call, 'regtest', redeem), [{ txid: 'a'.repeat(64), vout: 1, value: 7n, height: 3 }]);
  await assert.rejects(Z.htlcOutputs(async () => { throw new Error('zebrad busy'); }, 'regtest', redeem), /busy/);
});

// ------------------------------------------------------------------ a full offer table
const offerIn = async (d: ZecDesk, ip: string, who = Keypair.generate()) => {
  const id = newId(), k = S.zecKeys(randomBytes(64), randomBytes(32));
  await d.start(ask8(d.quote(8, 500_000_000n), id, k, who), ip);
  return { id, k, s: d.swaps.get(id)!, who };
};
const aged = (d: ZecDesk, id: string, secs = 120) => { const s = d.swaps.get(id)!; s.createdAt = nowS() - secs; return s; };

test('full table: griefers\' unpaid offers give way to the next person, oldest first; funded and young ones stay', async () => {
  const { d, z } = await ready({ offerLimits: { total: 3, perIp: 9, perTaker: 9 } }, undefined, {}, clockConn());
  const a = await offerIn(d, 'g1'), b = await offerIn(d, 'g2'), c = await offerIn(d, 'g3');
  // scanned and unpaid, but nothing is old enough yet: still refused, a griefer can't churn it instantly
  aged(d, a.id, 5); aged(d, b.id, 5); aged(d, c.id, 5);
  await assert.rejects(offerIn(d, 'real'), /busy/);
  aged(d, a.id, 300); aged(d, b.id, 200); aged(d, c.id, 100);
  // a has a real, full deposit: never evicted
  const redeem = Z.unhex(a.s.redeem), txid = 'e'.repeat(64);
  z.st.txs.set(txid, { txid, confirmations: 1, vout: [{ valueZat: Number(a.s.zats), scriptPubKey: { hex: Z.hex(Z.p2sh(redeem)) } }] });
  z.st.utxos.set(`${txid}:0`, { address: Z.htlcAddress('regtest', redeem), script: '', value: BigInt(a.s.zats), height: 999 });
  await (d as any).step(a.s);
  assert.equal(a.s.depositSeen, true);
  const real = await offerIn(d, 'real');
  assert.ok(real.s, 'a full table did not refuse the next person');
  assert.equal(a.s.evictedAt, undefined, 'funded: stays');
  assert.ok(b.s.evictedAt, 'the oldest unpaid one gave way');
  assert.equal(c.s.evictedAt, undefined);
  // an evicted offer holds no place: the next one takes c's, and then only the paid and the young are left
  await offerIn(d, 'next');
  assert.ok(c.s.evictedAt);
  await assert.rejects(offerIn(d, 'last'), /busy/);
  // survives a restart
  const again = new ZecDesk({ ...(d as any).d });
  (again as any).call = z.call; await again.init();
  assert.ok(again.swaps.get(b.id)!.evictedAt);
});

test('full table: a failed scan is not "no deposit", and a made-up hint does not make an offer unevictable', async () => {
  const { d, z } = await ready({ offerLimits: { total: 1, perIp: 9, perTaker: 9 } }, undefined, {}, clockConn());
  const a = await offerIn(d, 'g1');
  a.s.createdAt = nowS() - 300;
  const real = (d as any).call;
  (d as any).call = async (m: string, p: any[]) => { if (m === 'getaddressutxos') throw new Error('zebrad busy'); return real(m, p); };
  await assert.rejects(offerIn(d, 'real'), /busy/, 'unknown is not evictable');
  (d as any).call = real;
  d.funded({ swapId: a.id, txid: 'f'.repeat(64), vout: 0 }); // anyone can post this
  await offerIn(d, 'real');
  assert.equal(a.s.depositSeen, undefined);
  assert.ok(a.s.evictedAt);
  assert.equal(z.st.sent.length, 0);
});

test('evicted and then paid: the deposit is found, the swap goes on at its quote; evicted offers take turns on the tick', async () => {
  const conn = clockConn({
    getLatestBlockhash: async () => ({ blockhash: Keypair.generate().publicKey.toBase58(), lastValidBlockHeight: 1 }), getBlockHeight: async () => 1,
    sendRawTransaction: async () => { sends.push(1); return 'sig'; }, getSignatureStatuses: async () => ({ value: [{ err: null, confirmationStatus: 'confirmed' }] }),
  });
  const sends: number[] = [];
  const { d, z } = await ready({ offerLimits: { total: 50, perIp: 50, perTaker: 50 }, skew: { enabled: false } }, undefined, {}, conn);
  const offers = [];
  for (let i = 0; i < 25; i++) offers.push(await offerIn(d, 'g'));
  for (const o of offers) (d as any).record(o.id, 'evicted', { at: nowS() });
  const steps = new Map<string, number>(), step = (d as any).step.bind(d);
  (d as any).step = async (s: any) => { steps.set(s.swapId, (steps.get(s.swapId) ?? 0) + 1); return step(s); };
  await d.tick();
  assert.equal(steps.size, 10, 'one tick scans only a batch');
  await d.tick(); await d.tick();
  assert.equal(steps.size, 25, 'and in turn reaches all of them');
  const o = offers[7];
  const redeem = Z.unhex(o.s.redeem), txid = 'd'.repeat(64);
  z.st.txs.set(txid, { txid, confirmations: 60, vout: [{ valueZat: Number(o.s.zats), scriptPubKey: { hex: Z.hex(Z.p2sh(redeem)) } }] });
  z.st.utxos.set(`${txid}:0`, { address: Z.htlcAddress('regtest', redeem), script: '', value: BigInt(o.s.zats), height: 999 });
  for (let i = 0; i < 3 && o.s.phase === 'offered'; i++) await d.tick();
  assert.equal(o.s.evictedAt, undefined);
  assert.equal(o.s.phase, 'sol-locked');
  assert.equal(sends.length, 1);
});

test('evicted to the end and then paid: the maker never locks or touches it, and the user\'s refund needs nothing from the maker', async () => {
  const { d, z } = await ready({ offerLimits: { total: 50, perIp: 50, perTaker: 50 } }, undefined, {}, clockConn());
  const root = randomBytes(64), idB = randomBytes(32), id = bytesToHex(idB), keys = S.zecKeys(root, idB);
  const offer = await d.start(ask8(d.quote(8, 500_000_000n), id, keys)) as S.ZecToSolOffer;
  (d as any).record(id, 'done', { why: 'evicted from a full table; no deposit seen' });
  const redeem = Z.unhex(offer.redeem), txid = 'c'.repeat(64);
  z.st.txs.set(txid, { txid, confirmations: 60, vout: [{ valueZat: 3_000_000, scriptPubKey: { hex: Z.hex(Z.p2sh(redeem)) } }] });
  z.st.utxos.set(`${txid}:0`, { address: Z.htlcAddress('regtest', redeem), script: '', value: 3_000_000n, height: 999 });
  await d.tick();
  assert.equal(z.st.sent.length, 0);
  assert.equal(d.status(id).phase, 'done');
  // from the page's own data: the script and the wallet's key
  const p = Z.presign({ kind: 'refund', branch: Z.BRANCH.NU7, txid, vout: 0, value: 3_000_000n, redeem, outScript: Z.p2pkh(keys.refundPub), priv: keys.refundPriv });
  Z.verifyPresigned(p);
  const fin = Z.finalize(p);
  assert.equal(Z.parseTx(Z.unhex(fin.raw)).lockTime, offer.lockHeight);
});

// ------------------------------------------------------------------ another device, before the SOL lock
const listUrl = (wallet: string, at: number, nonce: string, sig: string) => new URL(`http://x/v1/zec/swaps?wallet=${wallet}&at=${at}&nonce=${nonce}&sig=${sig}`);
const signList = (maker: PublicKey, who: Keypair, at = nowS(), nonce = bytesToHex(randomBytes(16))) => ({ at, nonce, sig: bytesToHex(ed25519.sign(S.listSwapsMessage(maker.toBase58(), who.publicKey.toBase58(), at, nonce), who.secretKey.slice(0, 32))) });

test('my swaps at this maker: only with the wallet\'s signature, once, in time, for this maker; only its own; no secrets', async () => {
  const { d, me } = await ready({}, undefined, {}, clockConn());
  const alice = Keypair.generate(), bob = Keypair.generate();
  const ask = (w: string, r: { at: number; nonce: string; sig: string }) => d.handle('GET', listUrl(w, r.at, r.nonce, r.sig), async () => ({}), '') as Promise<{ swaps: S.ZecResumeItem[] }>;
  const a8 = S.zecKeys(randomBytes(64), randomBytes(32)), id8 = newId(), id4 = newId(), pub = claimPub();
  await d.start(ask8(d.quote(8, 500_000_000n), id8, a8, alice));
  await d.start(ask4(d.quote(4, 500_000_000n), id4, pub, alice));
  await offerIn(d, 'x', bob);
  const a = alice.publicKey.toBase58();
  const good = signList(me.publicKey, alice);
  const { swaps } = await ask(a, good);
  assert.deepEqual(swaps.map((x) => x.swapId).sort(), [id8, id4].sort(), 'its own, both directions');
  await assert.rejects(ask(a, good), /already used/, 'replay');
  await assert.rejects(ask(bob.publicKey.toBase58(), good), /wallet signature/, 'someone else\'s signature reads nothing');
  await assert.rejects(ask(a, signList(me.publicKey, bob)), /wallet signature/, 'a signature by another wallet');
  await assert.rejects(ask(a, signList(Keypair.generate().publicKey, alice)), /wallet signature/, 'signed for another maker: no replay across desks');
  await assert.rejects(ask(a, signList(me.publicKey, alice, nowS() - 500)), /out of date/);
  await assert.rejects(ask(a, signList(me.publicKey, alice, nowS() + 500)), /out of date/);
  await assert.rejects(ask(a, { ...signList(me.publicKey, alice), at: nowS() - 1 }), /wallet signature/, 'the time is signed');
  // replay across a restart: used nonces live in memory, so a request signed before the start is refused
  const older = signList(me.publicKey, alice, nowS() - 2);
  const restarted = new ZecDesk({ ...(d as any).d });
  (restarted as any).call = (d as any).call; await restarted.init();
  await assert.rejects(restarted.handle('GET', listUrl(a, older.at, older.nonce, older.sig), async () => ({}), ''), /out of date/);
  const fresh = signList(me.publicKey, alice, nowS() + 1);
  assert.equal((await restarted.handle('GET', listUrl(a, fresh.at, fresh.nonce, fresh.sig), async () => ({}), '') as { swaps: unknown[] }).swaps.length, 2, 'a new request works');
  // no secret of the maker's, no client address, nothing internal
  const text = JSON.stringify(swaps), s4 = d.swaps.get(id4)!;
  assert.ok(!text.includes(s4.salt!), 'salt');
  assert.ok(!text.includes(bytesToHex(d.preimage(id4, s4.salt!))), 'preimage');
  for (const k of ['salt', 'ip', 'x', 'preimage', 'depositHints', 'quoteNonce', 'lastError', 'why']) assert.ok(!(new RegExp(`"${k}"`)).test(text), k);
  // what it gives is enough: the offers pass the taker's own checks
  const i4 = swaps.find((x) => x.swapId === id4)!;
  const lock = S.verifySolToZecOffer(i4.offer as S.SolToZecOffer, { pid: (d as any).d.pid, taker: alice.publicKey, swapId: Buffer.from(id4, 'hex'), quote: i4.quote, quoteSig: i4.sig, claimPub: Z.unhex(pub), zecNet: 'regtest', now: nowS() });
  assert.ok(ed25519.verify(Z.unhex((i4.offer as S.SolToZecOffer).consentSig), H.htlcConsentDigest((d as any).d.pid, alice.publicKey, lock), me.publicKey.toBytes()));
});

test('a listed ZEC->SOL swap is checked against the wallet\'s keys; a closed or locked-out one is not listed', async () => {
  const { d, me, pid } = await ready({}, undefined, {}, clockConn());
  const alice = Keypair.generate(), root = randomBytes(64), idB = randomBytes(32), id = bytesToHex(idB), keys = S.zecKeys(root, idB);
  await d.start(ask8(d.quote(8, 500_000_000n), id, keys, alice));
  const a = alice.publicKey.toBase58();
  const list = async () => { const r = signList(me.publicKey, alice); return (await d.handle('GET', listUrl(a, r.at, r.nonce, r.sig), async () => ({}), '') as { swaps: S.ZecResumeItem[] }).swaps; };
  const [item] = await list();
  const x = { pid, maker: me.publicKey, keys, net: 'regtest' as Z.ZecNet };
  assert.equal(S.checkResumedZecToSol(item, x).lockHeight, d.swaps.get(id)!.lockHeight);
  const other = S.zecKeys(randomBytes(64), idB);
  assert.throws(() => S.checkResumedZecToSol(item, { ...x, keys: other }), /did not start/);
  assert.throws(() => S.checkResumedZecToSol(item, { ...x, keys: { hashlock: keys.hashlock, refundPub: other.refundPub } }), /does not refund/);
  assert.throws(() => S.checkResumedZecToSol(item, { ...x, maker: Keypair.generate().publicKey }), /quote/);
  assert.throws(() => S.checkResumedZecToSol({ ...item, sig: '00'.repeat(64) }, x), /quote/);
  assert.throws(() => S.checkResumedZecToSol({ ...item, offer: { ...item.offer, escrow: Keypair.generate().publicKey.toBase58() } }, x), /escrow/);
  assert.throws(() => S.checkResumedZecToSol({ ...item, offer: { ...item.offer, lockHeight: 1 } as S.ZecToSolOffer }, x), /refund block/);
  // the swap completed: nothing left for this wallet to do with it
  (d as any).record(id, 'zec-claimed', { txid: 'ab'.repeat(32), x: 'cd'.repeat(32) });
  (d as any).record(id, 'done', { why: 'completed' });
  assert.deepEqual(await list(), []);
});

// ------------------------------------------------------------------ closed offers keep their script
const payAddress = (z: ReturnType<typeof fakeZebra>, s: { redeem: string; zats: string }, txid: string, value = BigInt(s.zats), confirmations = 60) => {
  const redeem = Z.unhex(s.redeem);
  z.st.txs.set(txid, { txid, confirmations, vout: [{ valueZat: Number(value), scriptPubKey: { hex: Z.hex(Z.p2sh(redeem)) } }] });
  z.st.utxos.set(`${txid}:0`, { address: Z.htlcAddress('regtest', redeem), script: '', value, height: 999 });
};
const listOf = async (d: ZecDesk, me: Keypair, who: Keypair) => { const r = signList(me.publicKey, who); return (await d.handle('GET', listUrl(who.publicKey.toBase58(), r.at, r.nonce, r.sig), async () => ({}), '') as { swaps: S.ZecResumeItem[] }).swaps; };

test('a closed offer stays on the wallet\'s list with its script, so a refund does not depend on the first browser', async () => {
  const { d, z, me } = await ready({ skew: { enabled: false } }, undefined, {}, clockConn());
  const who = Keypair.generate(), root = randomBytes(64), idB = randomBytes(32), id = bytesToHex(idB), keys = S.zecKeys(root, idB);
  await d.start(ask8(d.quote(8, 500_000_000n), id, keys, who));
  const s = d.swaps.get(id)!;
  s.payBy = nowS() - 4000;
  await (d as any).step(s);
  assert.equal(s.phase, 'done');
  const [item] = await listOf(d, me, who);
  assert.equal(item.swapId, id);
  assert.equal(item.closed, true);
  // another device, the first browser gone: script from the list, key from the wallet, money at the address
  const o = S.checkResumedZecToSol(item, { pid: (d as any).d.pid, maker: me.publicKey, keys, net: 'regtest' });
  const txid = '1'.repeat(64);
  payAddress(z, s, txid);
  const p = Z.presign({ kind: 'refund', branch: Z.BRANCH.NU7, txid, vout: 0, value: BigInt(s.zats), redeem: Z.unhex(o.redeem), outScript: Z.p2pkh(keys.refundPub), priv: keys.refundPriv });
  Z.verifyPresigned(p);
  assert.equal(Z.parseTx(Z.unhex(Z.finalize(p).raw)).lockTime, o.lockHeight);
});

test('a deposit declined for being late is on the list and is marked paid, in all three closing paths', async () => {
  const feed = fakeFeed(0.07);
  const { d, z, me } = await ready({ livePrice: true, minConf: 3, skew: { enabled: false } }, undefined, { feed }, clockConn());
  const who = Keypair.generate();
  const a = await offerIn(d, 'x', who);
  a.s.payBy = nowS() - 600;
  payAddress(z, a.s, '2'.repeat(64), BigInt(a.s.zats), 3);
  feed.st = { ok: true, rate: 0.2, source: 'kraken', atMs: Date.now() };
  await (d as any).step(a.s);
  assert.equal(a.s.phase, 'done');
  assert.equal(a.s.paid, true);
  feed.st = { ok: true, rate: 0.07, source: 'kraken', atMs: Date.now() };
  const b = await offerIn(d, 'x', who);
  b.s.payBy = nowS() - 4000;
  payAddress(z, b.s, '3'.repeat(64), BigInt(b.s.zats), 3); // its block came minutes ago, after the offer closed
  await (d as any).step(b.s);
  assert.equal(b.s.phase, 'done');
  assert.equal(b.s.paid, true, 'past the window with money there: not "no deposit"');
  assert.equal((await listOf(d, me, who)).filter((i) => i.closed).length, 2);
  const c = await offerIn(d, 'x', who);
  c.s.lockHeight = 1001; // too close to lock SOL against
  payAddress(z, c.s, '7'.repeat(64), BigInt(c.s.zats), 3);
  await (d as any).step(c.s);
  assert.equal(c.s.phase, 'done');
  assert.equal(c.s.paid, true);
});

test('closing an offer past its window needs a scan that answered', async () => {
  const { d } = await ready({}, undefined, {}, clockConn());
  const a = await offerIn(d, 'x');
  a.s.payBy = nowS() - 4000;
  const real = (d as any).call;
  (d as any).call = async (m: string, p: any[]) => { if (m === 'getaddressutxos') throw new Error('zebrad busy'); return real(m, p); };
  await assert.rejects((d as any).step(a.s), /busy/);
  assert.equal(a.s.phase, 'offered');
  (d as any).call = real;
  await (d as any).step(a.s);
  assert.equal(a.s.phase, 'done');
  assert.equal(a.s.why, 'no deposit');
});

test('eviction scans right then: a payment found keeps the offer, with no earlier scan to go on', async () => {
  const { d, z } = await ready({ offerLimits: { total: 1, perIp: 9, perTaker: 9 } }, undefined, {}, clockConn());
  const a = await offerIn(d, 'g1');
  a.s.createdAt = nowS() - 300;
  payAddress(z, a.s, '4'.repeat(64), BigInt(a.s.zats), 1);
  await assert.rejects(offerIn(d, 'real'), /busy/);
  assert.equal(a.s.evictedAt, undefined);
  assert.equal(a.s.depositSeen, true);
});

test('past the evicted ceiling: closes only on a scan that answered; a payment found brings the offer back', async () => {
  const { d, z } = await ready({ maxEvictedOffers: 1, offerLimits: { total: 50, perIp: 50, perTaker: 50 } }, undefined, {}, clockConn());
  const paid = await offerIn(d, 'g'), unpaid = await offerIn(d, 'g'), newest = await offerIn(d, 'g');
  paid.s.createdAt = nowS() - 30; unpaid.s.createdAt = nowS() - 20; newest.s.createdAt = nowS() - 10;
  for (const o of [paid, unpaid, newest]) (d as any).record(o.id, 'evicted', { at: nowS() });
  payAddress(z, paid.s, '5'.repeat(64));
  const real = (d as any).call;
  (d as any).call = async (m: string, p: any[]) => { if (m === 'getaddressutxos') throw new Error('zebrad busy'); return real(m, p); };
  await (d as any).closeExcessEvicted();
  assert.deepEqual([paid.s.phase, unpaid.s.phase], ['offered', 'offered'], 'no answer closes nothing');
  (d as any).call = real;
  await (d as any).closeExcessEvicted();
  assert.equal(paid.s.phase, 'offered');
  assert.equal(paid.s.evictedAt, undefined, 'paid: back on every tick');
  assert.equal(unpaid.s.phase, 'done');
  assert.equal(newest.s.phase, 'offered');
});

test('journal: closed unpaid offers are forgotten a day after their refund height, after a scan; paid and live ones stay; the file shrinks and reloads', async () => {
  const { d, z, cfg } = await ready({ skew: { enabled: false } }, undefined, {}, clockConn());
  const flood = [];
  for (let i = 0; i < 40; i++) { const o = await offerIn(d, `ip${i}`); (d as any).record(o.id, 'done', { why: 'no deposit' }); flood.push(o); }
  const recent = await offerIn(d, 'a');
  const paidLate = await offerIn(d, 'b'), live = await offerIn(d, 'c');
  (d as any).record(paidLate.id, 'done', { why: 'no deposit' });
  payAddress(z, paidLate.s, '6'.repeat(64), 60_000n); // arrives after closing: found by the last scan
  (d as any).record(recent.id, 'done', { why: 'no deposit' });
  const size0 = fs.statSync(cfg.journal).size;
  // before the time: nothing goes
  await d.pruneJournal();
  assert.equal(d.swaps.size, 43);
  // a scan that fails forgets nothing
  z.st.tip = flood[0].s.lockHeight + 10_000;
  (d as any).tipCache = { at: Date.now(), tip: z.st.tip };
  (d as any).pruneAt = 0;
  const real = (d as any).call;
  (d as any).call = async (m: string, p: any[]) => { if (m === 'getaddressutxos') throw new Error('zebrad busy'); return real(m, p); };
  await d.pruneJournal();
  assert.equal(d.swaps.size, 43);
  (d as any).call = real;
  (d as any).pruneAt = 0;
  await d.pruneJournal();
  assert.equal(d.swaps.has(live.id), true);
  assert.equal(d.swaps.get(paidLate.id)!.paid, true, 'money at the address: kept for good');
  assert.equal(d.swaps.has(flood[0].id), false);
  assert.equal(d.swaps.size, 2);
  // paid and since refunded: nothing at the address any more, and it still stays
  z.st.utxos.delete(`${'6'.repeat(64)}:0`);
  (d as any).pruneAt = 0;
  await d.pruneJournal();
  assert.equal(d.swaps.has(paidLate.id), true);
  d.compactJournal();
  assert.ok(fs.statSync(cfg.journal).size < size0 / 5, 'the file shrank');
  // still writable, and a restart sees exactly what is left
  (d as any).record(live.id, 'deposit-hint', { txid: 'a'.repeat(64), vout: 0 });
  const again = new ZecDesk({ ...(d as any).d });
  (again as any).call = z.call; await again.init();
  assert.deepEqual([...again.swaps.keys()].sort(), [live.id, paidLate.id].sort());
  assert.equal(again.swaps.get(paidLate.id)!.paid, true);
  assert.equal(again.swaps.get(live.id)!.depositHints?.length, 1);
  assert.ok(!fs.existsSync(`${cfg.journal}.compact`));
});

test('journal: the desk\'s own tick forgets old offers and rewrites the file, with no one calling it', async () => {
  const { d, z, cfg } = await ready({ skew: { enabled: false } }, undefined, {}, clockConn());
  const flood = [];
  for (let i = 0; i < 10; i++) { const o = await offerIn(d, `ip${i}`); (d as any).record(o.id, 'done', { why: 'no deposit' }); flood.push(o); }
  const size0 = fs.statSync(cfg.journal).size;
  z.st.tip = flood[0].s.lockHeight + 10_000;
  (d as any).tipCache = { at: Date.now(), tip: z.st.tip };
  (d as any).compactAt = 0;
  await d.tick();
  assert.equal(d.swaps.size, 0);
  assert.ok(fs.statSync(cfg.journal).size < size0 / 5);
});

// ------------------------------------------------------------------ fifth review
test('one empty read of the lock is not a no-show: it takes several in a row, and nothing at "confirmed" either', async () => {
  const { d } = await ready({}, undefined, {}, clockConn());
  const w = Keypair.generate(), id = newId();
  await d.start(ask4(d.quote(4, 500_000_000n), id, claimPub(), w), 'ip1');
  const s = d.swaps.get(id)!;
  s.consentExpiry = nowS() - 200;
  await (d as any).step(s);
  assert.equal(s.phase, 'funded', 'one read');
  await (d as any).step(s);
  assert.equal(s.phase, 'funded', 'two reads');
  // it shows up at "confirmed", not yet final: the count starts again
  s.noLockReads = 2;
  (d as any).loadHtlc = async (_a: string, c: string) => (c === 'confirmed' ? ({ state: 1 } as any) : null);
  await (d as any).step(s);
  assert.equal(s.noLockReads, 0);
  assert.equal(s.phase, 'funded');
  (d as any).loadHtlc = async () => null;
  for (let i = 0; i < 2; i++) await (d as any).step(s);
  assert.equal(s.phase, 'funded');
  await (d as any).step(s);
  assert.equal(s.phase, 'refunding-zec');
  assert.ok(s.noShowAt);
});

test('an unknown funding send does not hold the user\'s own caps against them, but its ZEC counts against the budget', async () => {
  const { d, z } = await ready({ s2zLimits: { perTaker: 1, perIp: 1, unlockedZats: String(4_000_000n), perIpZats: String(4_000_000n) } }, undefined, {}, clockConn());
  const real = z.call, w = Keypair.generate();
  (d.wallet as any).call = async (m: string, p: any[]) => { if (m === 'sendrawtransaction') { await real(m, p); throw new Error('fetch failed'); } return real(m, p); };
  await assert.rejects(d.start(ask4(d.quote(4, 500_000_000n), newId(), claimPub(), w), 'ip1'), code(503));
  (d.wallet as any).call = real;
  // the same wallet and address may try again: it is the budget that says no, with 3.465M of 4M possibly out
  await assert.rejects(d.start(ask4(d.quote(4, 500_000_000n), newId(), claimPub(), w), 'ip1'), /busy/);
});

test('an outage is not the user\'s lateness: an on-time payer found hours later still gets its lock; a truly late one is told what happens', async () => {
  const sends: number[] = [];
  const conn = clockConn({
    getLatestBlockhash: async () => ({ blockhash: Keypair.generate().publicKey.toBase58(), lastValidBlockHeight: 1 }), getBlockHeight: async () => 1,
    sendRawTransaction: async () => { sends.push(1); return 'sig'; }, getSignatureStatuses: async () => ({ value: [{ err: null, confirmationStatus: 'confirmed' }] }),
  });
  const { d, z } = await ready({ skew: { enabled: false } }, undefined, {}, conn);
  const a = await offerIn(d, 'x');
  a.s.payBy = nowS() - 4000; // past the closing time now
  payAddress(z, a.s, 'a1'.repeat(32), BigInt(a.s.zats), 200); // 200 blocks ago = 5000 s, before that window ended
  await (d as any).step(a.s);
  assert.equal(a.s.phase, 'sol-locked');
  assert.equal(sends.length, 1);
  const b = await offerIn(d, 'x');
  b.s.payBy = nowS() - 4000;
  payAddress(z, b.s, 'b1'.repeat(32), BigInt(b.s.zats), 3);
  await (d as any).step(b.s);
  assert.equal(b.s.phase, 'done');
  assert.match(b.s.why!, /no SOL will be locked/);
  assert.equal(sends.length, 1);
});

test('SOL is reserved for an offer with a full deposit, never for an unpaid one', async () => {
  const lam = 500_000_000n;
  const { d, z } = await ready({ skew: { enabled: false } }, lam + 50_000_000n + 100n, {}, clockConn());
  const q = () => d.handle('GET', new URL(`http://x/v1/zec/quote?direction=8&lamports=${lam}`), async () => ({}), '');
  const a = await offerIn(d, 'x'), b = await offerIn(d, 'y'); // unpaid: reserve nothing, so a flood can't make real users read "not enough SOL"
  await q();
  payAddress(z, a.s, 'c1'.repeat(32), BigInt(a.s.zats), 1);
  await (d as any).step(a.s);
  assert.equal(a.s.depositSeen, true);
  assert.equal(a.s.phase, 'offered', 'waiting for confirmations');
  await assert.rejects(q(), /not enough SOL/);
  const k = S.zecKeys(randomBytes(64), randomBytes(32));
  const held = d.quote(8, lam);
  await assert.rejects(d.start(ask8(held, newId(), k)), /SOL inventory/);
  void b;
});

test('a pruned swap id stays used until the journal is compacted, so a reused id is never erased with the old records (review 11-08)', async () => {
  const { d, z } = await ready({ skew: { enabled: false } }, undefined, {}, clockConn());
  const attacker = Keypair.generate();
  const old = await offerIn(d, 'ipA', attacker);
  (d as any).record(old.id, 'done', { why: 'no deposit' });
  z.st.tip = old.s.lockHeight + 10_000;
  (d as any).tipCache = { at: Date.now(), tip: z.st.tip };
  (d as any).pruneAt = 0;
  (d as any).compactAt = Date.now(); // no compaction inside this prune pass
  await d.pruneJournal();
  assert.equal(d.swaps.has(old.id), false, 'pruned');
  await assert.rejects(d.start(ask4(d.quote(4, 500_000_000n), old.id, claimPub(), attacker), 'ipB'), /already used/, 'refused before compaction');
  d.compactJournal();
  // after compaction the id may be used again, and the new swap survives a restart
  const off: any = await d.start(ask4(d.quote(4, 500_000_000n), old.id, claimPub(), attacker), 'ipB');
  assert.ok(off.fundTxid);
  d.compactJournal();
  const again = new ZecDesk({ ...(d as any).d });
  (again as any).call = z.call; await again.init();
  assert.equal(again.swaps.has(old.id), true, 'the funded swap is still on disk');
  assert.equal(again.swaps.get(old.id)!.direction, 4);
});

test('the desk re-reads network upgrades while it runs: one scheduled after start pauses quotes (review 11-08)', async () => {
  const { d, z } = await ready({ skew: { enabled: false } }, undefined, {}, clockConn());
  assert.equal(d.upgradeNear(), null);
  // a new upgrade gets scheduled just ahead of the tip after the desk started
  const orig = z.call;
  (d as any).call = async (m: string, p: any[] = []) => {
    if (m === 'getblockchaininfo') {
      const r = await orig(m, p);
      return { ...r, upgrades: { ...r.upgrades, 'deadbeef': { name: 'NU8', activationheight: z.st.tip + 50, status: 'pending' } } };
    }
    return orig(m, p);
  };
  (d as any).upsAt = 0;
  await d.tick();
  assert.match(String(d.upgradeNear()), /NU8/);
});
