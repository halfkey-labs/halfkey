// The ZEC watchtower against a mocked zebrad and Solana connection. Real-chain run: e2e/zec-swap.ts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Keypair, PublicKey, Transaction, TransactionInstruction } from '@solana/web3.js';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes, bytesToHex } from '@noble/hashes/utils';
import * as Z from '../sdk/zec.ts';
import * as H from '../sdk/htlc.ts';
import { ZecTower } from './zec.ts';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hk-zt-'));
process.on('exit', () => fs.rmSync(tmp, { recursive: true, force: true }));
const TIP = 1000;
const pid = Keypair.generate().publicKey;

function tower(o: Record<string, unknown> = {}, conn: any = { getAccountInfo: async () => null }) {
  const t = new ZecTower({ zebraRpc: 'http://127.0.0.1:1', zecNet: 'regtest', db: path.join(tmp, `db-${Math.random()}.json`), ...o } as any, conn, pid, Keypair.generate());
  const txs = new Map<string, any>();
  (t as any).call = async (m: string, p: any[] = []) => {
    if (m === 'getblockchaininfo') return { blocks: TIP, upgrades: { '77190ad9': { name: 'NU7', activationheight: 1, status: 'active' } } };
    if (m === 'getrawtransaction') { const x = txs.get(p[0]); if (!x) throw new Error('no tx'); return x; }
    if (m === 'gettxout') return { value: 1 };
    throw new Error(`unmocked ${m}`);
  };
  return { t, txs };
}
/** A funded HTLC and the user's pre-signed refund for it. */
function refund(txs: Map<string, any>, lockHeight = TIP + 100) {
  const priv = Z.privFrom(randomBytes(32)), redeem = Z.htlcScript({ hashlock: sha256(randomBytes(32)), claimPub: Z.pubOf(Z.privFrom(randomBytes(32))), refundPub: Z.pubOf(priv), lockHeight });
  const txid = bytesToHex(randomBytes(32));
  txs.set(txid, { txid, confirmations: 3, vout: [{ valueZat: 1_000_000, scriptPubKey: { hex: Z.hex(Z.p2sh(redeem)) } }] });
  return Z.presign({ kind: 'refund', branch: Z.BRANCH.NU7, txid, vout: 0, value: 1_000_000n, redeem, outScript: Z.p2pkh(Z.pubOf(priv)), priv });
}
const esc = () => Keypair.generate().publicKey.toBase58();

test('a spend whose lock height is too far off is refused: it would hold its slot for that long', async () => {
  const { t, txs } = tower();
  const blocksIn7d = Z.heightAfter(await Z.upgradesFromNode((t as any).call), TIP, 7 * 86_400);
  await t.register({ escrow: esc(), presigned: refund(txs, blocksIn7d) });
  await assert.rejects(t.register({ escrow: esc(), presigned: refund(txs, blocksIn7d + 1) }), /too far away/);
  assert.equal(t.open, 1);
});

test('open registrations per client address are capped; another address is not affected; a finished one frees its place', async () => {
  const { t, txs } = tower({ maxPerIp: 2 });
  await t.register({ escrow: esc(), presigned: refund(txs) }, 'ip1');
  await t.register({ escrow: esc(), presigned: refund(txs) }, 'ip1');
  await assert.rejects(t.register({ escrow: esc(), presigned: refund(txs) }, 'ip1'), /too many open registrations/);
  await t.register({ escrow: esc(), presigned: refund(txs) }, 'ip2');
  [...(t as any).watches.values()].find((w: any) => w.ip === 'ip1').outcome = 'refunded';
  await t.register({ escrow: esc(), presigned: refund(txs) }, 'ip1');
  // survives a restart: the address is in the database
  const again = new ZecTower((t as any).cfg, (t as any).conn, pid, Keypair.generate());
  (again as any).call = (t as any).call;
  await assert.rejects(again.register({ escrow: esc(), presigned: refund(txs) }, 'ip1'), /too many open registrations/);
});

test('the preimage is found behind hundreds of padding transactions, also in a failed claim; an unreadable page is not "not there"', async () => {
  const signer = Keypair.generate(), escrow = Keypair.generate().publicKey, x = randomBytes(32), hb = Keypair.generate().publicKey.toBase58();
  const msg = (ix: TransactionInstruction) => { const tx = new Transaction({ feePayer: signer.publicKey, recentBlockhash: hb }).add(ix); return tx.compileMessage(); };
  const pad = msg(new TransactionInstruction({ programId: pid, keys: [], data: Buffer.from([1, 2, 3]) }));
  const claim = msg(H.ixHtlcClaim(pid, signer.publicKey, escrow, signer.publicKey, x));
  const sigs = [...Array.from({ length: 350 }, (_, i) => ({ signature: `pad${i}`, err: null })), { signature: 'claim', err: { InstructionError: [0, 'x'] } }, { signature: 'older', err: null }];
  let broken = false;
  const conn = {
    getAccountInfo: async () => null,
    getSignaturesForAddress: async (_: PublicKey, o: { limit: number; before?: string }) => { const from = o.before ? sigs.findIndex((s) => s.signature === o.before) + 1 : 0; return sigs.slice(from, from + o.limit); },
    getTransaction: async (s: string) => { if (broken) return null; return { transaction: { message: s === 'claim' ? claim : pad }, meta: { innerInstructions: [] } }; },
  };
  const { t } = tower({}, conn);
  const w = { escrow: escrow.toBase58(), hashlock: Z.hex(sha256(x)) } as any;
  broken = true;
  await assert.rejects((t as any).preimageFromHistory(w), /not readable/);
  broken = false;
  let got: Uint8Array | null = null;
  for (let i = 0; i < 3 && !got; i++) got = await (t as any).preimageFromHistory(w); // pages on from where it stopped
  assert.deepEqual(got, x);
});

test('a broadcast is rebroadcast until it is deep: 3 confirmations (about a minute at 25 s blocks) is not final', async () => {
  const { t, txs } = tower();
  const p = refund(txs, TIP - 1); // refund height reached
  const escrow = esc();
  await t.register({ escrow, presigned: p });
  const real = (t as any).call, sent: string[] = [];
  let conf = 3;
  (t as any).call = async (m: string, a: any[] = []) => {
    if (m === 'sendrawtransaction') { sent.push(a[0]); return 'x'; }
    if (m === 'getrawtransaction' && !txs.has(a[0])) return { confirmations: conf };
    return real(m, a);
  };
  const w = [...(t as any).watches.values()][0];
  await t.tick();
  assert.ok(w.broadcast);
  assert.equal(sent.length, 1);
  await t.tick();
  assert.equal(w.outcome, undefined, 'still watching at 3');
  assert.equal(sent.length, 2, 'and sending again while the output shows unspent');
  conf = 59;
  await t.tick();
  assert.equal(w.outcome, undefined);
  conf = 60;
  await t.tick();
  assert.equal(w.outcome, 'refunded');
});

// ---------------------------------------------------------------- script copies
import { ed25519 } from '@noble/curves/ed25519';
import * as ZS from '../sdk/zecswap.ts';

const makerKp = Keypair.generate();
/** A real request: the maker's quote, the wallet's signature, a script that refunds to that wallet. */
function copyOf(who: Keypair, lockHeight = TIP + 100) {
  const swapId = bytesToHex(randomBytes(32)), idB = Buffer.from(swapId, 'hex'), keys = ZS.zecKeys(randomBytes(64), idB);
  const hashlock = Z.hex(keys.hashlock), refundPub = Z.hex(keys.refundPub);
  const quote: ZS.ZecQuote = { v: 1, kind: 'zec', maker: makerKp.publicKey.toBase58(), direction: 8, lamports: '500000000', zats: '3000000', feeBps: 50, expiresAt: Math.floor(Date.now() / 1000) + 60, nonce: bytesToHex(randomBytes(16)), zecNet: 'regtest' };
  const redeem = Z.htlcScript({ hashlock: keys.hashlock, claimPub: Z.pubOf(Z.privFrom(randomBytes(32))), refundPub: keys.refundPub, lockHeight });
  const offer: ZS.ZecToSolOffer = { direction: 8, escrow: H.htlcPda(pid, makerKp.publicKey, idB).toBase58(), redeem: Z.hex(redeem), htlcAddress: Z.htlcAddress('regtest', redeem), lockHeight, payBy: 1 };
  const takerSig = bytesToHex(ed25519.sign(ZS.offerRequestMessage(quote, swapId, ZS.zecToSolKeys(hashlock, refundPub)), who.secretKey.slice(0, 32)));
  return { wallet: who.publicKey.toBase58(), takerSig, swapId, hashlock, refundPub, quote, sig: ZS.signZecQuote(quote, makerKp.secretKey.slice(0, 32)), offer } as ZS.ZecScriptCopy;
}
const towerKey = (t: ZecTower) => ((t as any).me as Keypair).publicKey.toBase58();
const listReq = (t: ZecTower, who: Keypair, at = Math.floor(Date.now() / 1000), nonce = bytesToHex(randomBytes(16)), tower = towerKey(t)) =>
  new URLSearchParams({ wallet: who.publicKey.toBase58(), at: String(at), nonce, sig: bytesToHex(ed25519.sign(ZS.listCopiesMessage(tower, who.publicKey.toBase58(), at, nonce), who.secretKey.slice(0, 32))) });

test('a script copy: only with the wallet\'s signature and its own script; on disk; read back only by that wallet', async () => {
  const { t } = tower();
  const alice = Keypair.generate(), bob = Keypair.generate(), c = copyOf(alice);
  await assert.rejects(t.saveCopy({ ...c, wallet: bob.publicKey.toBase58() }), /wallet signature/, 'planted under another wallet');
  await assert.rejects(t.saveCopy({ ...c, takerSig: '00'.repeat(64) }), /wallet signature/);
  const other = copyOf(alice);
  await assert.rejects(t.saveCopy({ ...c, offer: other.offer }), /did not start|refund|escrow/, 'another swap\'s script');
  await assert.rejects(t.saveCopy({ ...c, sig: '00'.repeat(64) }), /quote/);
  assert.equal(t.listCopies(listReq(t, alice)).swaps.length, 0);
  await t.saveCopy(c, 'ip1');
  assert.deepEqual(await t.saveCopy(c, 'ip1'), { ok: true, known: true });
  const [it] = t.listCopies(listReq(t, alice)).swaps;
  assert.equal(it.swapId, c.swapId);
  assert.equal(JSON.stringify(it).includes('ip1'), false, 'the address stays here');
  // enough for the wallet to rebuild and refund, on another device
  assert.equal(ZS.checkResumedZecToSol(it, { pid, maker: makerKp.publicKey, keys: { hashlock: Z.unhex(c.hashlock), refundPub: Z.unhex(c.refundPub) }, net: 'regtest' }).redeem, c.offer.redeem);
  assert.equal(t.listCopies(listReq(t, bob)).swaps.length, 0);
  // a restart keeps it
  const again = new ZecTower((t as any).cfg, (t as any).conn, pid, (t as any).me);
  (again as any).call = (t as any).call;
  (again as any).bootAt -= 10;
  assert.equal(again.listCopies(listReq(again, alice)).swaps.length, 1);
});

test('reading copies: this wallet, this watchtower, in time, once, and not across a restart', async () => {
  const { t } = tower();
  const alice = Keypair.generate(), bob = Keypair.generate();
  await t.saveCopy(copyOf(alice));
  const good = listReq(t, alice);
  assert.equal(t.listCopies(good).swaps.length, 1);
  assert.throws(() => t.listCopies(good), /already used/);
  const forged = listReq(t, bob); forged.set('wallet', alice.publicKey.toBase58());
  assert.throws(() => t.listCopies(forged), /wallet signature/);
  assert.throws(() => t.listCopies(listReq(t, alice, undefined, undefined, Keypair.generate().publicKey.toBase58())), /wallet signature/, 'signed for another watchtower');
  assert.throws(() => t.listCopies(listReq(t, alice, Math.floor(Date.now() / 1000) - 500)), /out of date/);
  assert.throws(() => t.listCopies(listReq(t, alice, Math.floor(Date.now() / 1000) + 500)), /out of date/, 'signed for the future');
  const before = listReq(t, alice, Math.floor(Date.now() / 1000) - 2);
  const again = new ZecTower((t as any).cfg, (t as any).conn, pid, (t as any).me);
  (again as any).call = (t as any).call;
  assert.throws(() => again.listCopies(before), /out of date/);
});

test('a full store drops its oldest and never refuses: a wallet, an address or a flood costs its own first', async () => {
  const { t } = tower({ maxCopiesPerWallet: 2, maxCopiesPerIp: 3, maxCopies: 5 });
  const a = Keypair.generate();
  const c1 = copyOf(a), c2 = copyOf(a), c3 = copyOf(a);
  await t.saveCopy(c1); await new Promise((r) => setTimeout(r, 1100));
  await t.saveCopy(c2); await t.saveCopy(c3);
  assert.deepEqual(t.listCopies(listReq(t, a)).swaps.map((x) => x.swapId).sort(), [c2.swapId, c3.swapId].sort(), 'the wallet\'s oldest went');
  const real = Keypair.generate(), mine = copyOf(real);
  await t.saveCopy(mine, 'real');
  await new Promise((r) => setTimeout(r, 1100));
  for (let i = 0; i < 6; i++) await t.saveCopy(copyOf(Keypair.generate()), 'flood');
  assert.equal(t.listCopies(listReq(t, real)).swaps.length, 1, 'a flood from one address only displaces its own');
  await assert.rejects(t.saveCopy(copyOf(a, TIP + 10_000_000)), /too far away/);
});

test('a copy goes 7 days past its refund height, and the file is rewritten without it', async () => {
  const { t, txs } = tower();
  const a = Keypair.generate(), c = copyOf(a);
  await t.saveCopy(c);
  const file = `${(t as any).cfg.db}.copies`, size0 = fs.statSync(file).size;
  void txs;
  await t.tick();
  assert.equal(t.listCopies(listReq(t, a)).swaps.length, 1, 'not yet');
  const real = (t as any).call;
  (t as any).call = async (m: string, p: any[] = []) => { const r = await real(m, p); return m === 'getblockchaininfo' ? { ...r, blocks: TIP + 100_000 } : r; };
  await t.tick();
  assert.equal(t.listCopies(listReq(t, a)).swaps.length, 0);
  assert.ok(fs.statSync(file).size < size0, 'the file shrank');
  const again = new ZecTower((t as any).cfg, (t as any).conn, pid, (t as any).me);
  (again as any).call = real; (again as any).bootAt -= 10;
  assert.equal(again.listCopies(listReq(again, a)).swaps.length, 0);
});
