// HALFKEY watchtower: view keys only, abort power only.
//
// Users register a SOL->XMR escrow that lists this watchtower's pubkey, plus the shared view key.
// Before t0 the watchtower must see the maker's XMR lock (exact amount, unlock_time 0,
// >= minConf confirmations, amount proven against the commitment). If it cannot by
// t0 - abortMargin, it calls `abort`. The program gives a watchtower no other power: it can never
// claim, never refund, never move funds. Worst case it griefs an honest swap (the user refunds,
// the maker recovers its XMR from the refund secret).
//
// Pay links / cashout vaults (escrow flag PAY): the payer cannot cancel and is often offline, so the
// watchtower is its only protection; and a refund reveals nothing (the XMR key is the recipient's),
// so an abort after the maker's XMR lock strands that XMR. So for these escrows:
//  * the watchtower finds them itself (every escrow listing its key) and derives the view key from
//    the public link, so nobody has to register them (a keeper or payer who "forgets" cannot blind it);
//  * a lock counts as delivered from 1 confirmation (not minConf) with the right amount, no time lock,
//    in a block no older than the escrow; it is re-checked every poll until minConf (then latched), so
//    a dropped or double-spent lock is caught, but only two clean negatives in a row clear it and an
//    error keeps the last verdict (an abort after delivery would strand the maker's XMR);
//  * registrations never replace earlier ones, and pay escrows always use the link-derived view key,
//    so nobody who learns an escrow address early can blind the watchtower with a junk key;
//  * makers push their lock tx here (POST /v1/hint) as well as reporting it on their own endpoint.
//
//   node watchtower/watchtower.ts watchtower/config.json
import fs from 'node:fs';
import http from 'node:http';
import { Connection, PublicKey, Transaction, ComputeBudgetProgram } from '@solana/web3.js';
import * as P from '../sdk/program.ts';
import * as K from '../sdk/keys.ts';
import { verifyLock, daemon } from '../sdk/xmrverify.ts';
import * as Pay from '../sdk/pay.ts';
import { primaryEndpoint } from '../sdk/discovery.ts';
import { ed25519 } from '@noble/curves/ed25519';
import { utf8ToBytes } from '@noble/hashes/utils';

/** What a maker signs to push a lock hint (only the escrow's maker can). */
export const hintBytes = (escrow: string, txHash: string) => utf8ToBytes(`halfkey-hint-v1:${escrow}:${txHash}`);
import { chainNow, sendIxs, setPriority, loadKeypair, log, describeErr } from '../maker/lib.ts';
import { clientIp, RateWindow } from '../maker/policy.ts';
import { waitForTx } from '../sdk/confirm.ts';
import * as Htlc from '../sdk/htlc.ts';
import { ZecTower, type ZecTowerConfig } from './zec.ts';

interface Config { rpcUrl: string; programId: string; keypair: string; port: number; daemonUri: string; minConf: number; abortMarginSecs: number; pollMs: number; db: string; zec?: ZecTowerConfig; trustProxy?: boolean; priority?: { auto?: boolean; microLamports?: number; minMicroLamports?: number; maxMicroLamports?: number } }
const cfg: Config = JSON.parse(fs.readFileSync(process.argv[2] ?? 'watchtower/config.json', 'utf8'));
// Unsigned endpoints: a registration is free, and each open one costs RPC reads until it expires.
const unsigned = new RateWindow(30, 60_000);
setInterval(() => unsigned.sweep(), 60_000).unref();
const MAX_PRELOCK = 300; // registrations whose escrow has not appeared (15 min each)
const MAX_PRELOCK_PER_IP = 10;
const prelockIp = new Map<string, string>(); // memory only, for that cap
setInterval(() => { if (prelockIp.size > 2000) prelockIp.clear(); }, 60_000).unref();
const pid = new PublicKey(cfg.programId);
const me = loadKeypair(cfg.keypair);
const conn = new Connection(cfg.rpcUrl, 'confirmed');
if (cfg.priority) setPriority(conn, cfg.priority); // mainnet: `"priority": {}` (auto, clamped) so aborts land on a busy chain
const zec = cfg.zec ? new ZecTower(cfg.zec, conn, pid, me) : null;

interface Watch {
  escrow: string; viewSecret: string; registeredAt?: number; validated?: boolean; safe?: boolean; lastCheck?: string; outcome?: string; pay?: boolean;
  /** Every view key anyone registered for this address (a later registration never replaces an earlier one). */
  candidates?: string[];
  /** Lock tx hashes pushed by makers (kept, each tried; a junk one cannot displace a good one). */
  hints?: string[];
  /** Consecutive polls with a clean negative result (pay escrows clear `safe` only after 2). */
  negStreak?: number;
  /** Full minConf reached: delivered for good. */
  latched?: boolean;
  /** The right amount to the shared address was seen (any confirmations, unlocked): the maker delivered. */
  delivered?: boolean;
}
const watches = new Map<string, Watch>();
if (fs.existsSync(cfg.db)) for (const w of JSON.parse(fs.readFileSync(cfg.db, 'utf8')) as Watch[]) watches.set(w.escrow, w);
const save = () => { fs.writeFileSync(cfg.db + '.tmp', JSON.stringify([...watches.values()]), { mode: 0o600 }); fs.renameSync(cfg.db + '.tmp', cfg.db); };

async function loadEscrow(addr: string) {
  const a = await conn.getAccountInfo(new PublicKey(addr), 'confirmed');
  return a && a.owner.equals(pid) && a.data.length === P.ESCROW_LEN ? P.decodeEscrow(a.data, new PublicKey(addr)) : null;
}

/**
 * Registration happens BEFORE the user locks (the client refuses to lock without an ack), so the
 * escrow may not exist yet. It is validated (listed watchtower, matching view key, SOL->XMR) as
 * soon as it appears; an escrow that never appears is dropped after 15 minutes.
 */
async function register(b: any, ip = '') {
  const escrow = new PublicKey(String(b.escrow)).toBase58();
  const view = K.fromHex(String(b.viewSecret));
  if (!K.isCanonical(view) || K.leToBig(view) === 0n) throw new Error('bad view key');
  const e = await loadEscrow(escrow);
  if (e) validate(e, view);
  const prev = watches.get(escrow);
  if (prev && prev.outcome && /^(invalid|never-locked)/.test(prev.outcome)) { prev.outcome = undefined; prev.validated = false; } // re-check with the new candidate
  if (!prev && !e) {
    const waiting = [...watches.values()].filter((w) => !w.validated && !w.outcome);
    if (waiting.length >= MAX_PRELOCK) throw new Error('too many registrations waiting for a lock; try again in a few minutes');
    if (ip && waiting.filter((w) => prelockIp.get(w.escrow) === ip).length >= MAX_PRELOCK_PER_IP) throw new Error('too many registrations from this address; lock those first');
  }
  if (prev) {
    // Never replace: whoever learned the address first (a maker, a keeper) must not be able to
    // swap in a junk key and blind us. Keep every candidate; validation picks the right one.
    prev.candidates = [...new Set([...(prev.candidates ?? [prev.viewSecret]), K.toHex(view)])].slice(0, 8);
    save();
    return { ok: true };
  }
  watches.set(escrow, { escrow, viewSecret: K.toHex(view), candidates: [K.toHex(view)], registeredAt: Date.now(), validated: !!e });
  if (ip) prelockIp.set(escrow, ip);
  save();
  log(`watching ${escrow.slice(0, 8)}${e ? ` until t0=${e.t0}` : ' (pre-lock)'}`);
  return { ok: true };
}

function validate(e: P.EscrowAccount, view: Uint8Array) {
  if (e.direction !== 1) throw new Error('only SOL->XMR swaps are watched');
  if (!e.watchtowers.some((w) => w.equals(me.publicKey))) throw new Error('this watchtower is not listed in the escrow');
  if (!K.equalBytes(K.pub(view), e.viewPub)) throw new Error('view key does not match the escrow');
}

/** Pay escrows listing this watchtower, found on chain; their view key is public-derivable. */
async function discover() {
  const now = await chainNow(conn);
  for (const off of [P.OFF_ESCROW_WT0, P.OFF_ESCROW_WT1]) {
    const xs = await conn.getProgramAccounts(pid, { commitment: 'confirmed', filters: [{ dataSize: P.ESCROW_LEN }, { memcmp: { offset: off, bytes: me.publicKey.toBase58() } }] });
    for (const x of xs) {
      const a = x.pubkey.toBase58();
      const prev = watches.get(a);
      if (prev && !prev.outcome?.startsWith('invalid')) continue;
      const e = P.decodeEscrow(x.account.data, x.pubkey);
      if (!(e.flags & P.F.PAY) || e.state !== P.ST.LOCKED || now >= Number(e.t0)) continue;
      const la = await conn.getAccountInfo(e.link, 'confirmed');
      if (!la) continue;
      const k = Pay.payKeys(P.decodeLink(la.data, e.link).master, x.pubkey.toBytes(), e.quoteHash);
      if (!K.equalBytes(k.viewPub, e.viewPub) || !K.equalBytes(k.spendPub, e.refundPoint)) continue;
      watches.set(a, { escrow: a, viewSecret: K.toHex(k.view), registeredAt: Date.now(), validated: true, pay: true });
      log(`found pay escrow ${a.slice(0, 8)} on chain, t0=${e.t0}`);
    }
  }
}

/** The pay escrow's view key, derived from its link (null for non-pay escrows). */
async function payView(e: P.EscrowAccount): Promise<string | null> {
  if (!(e.flags & P.F.PAY)) return null;
  const la = await conn.getAccountInfo(e.link, 'confirmed');
  if (!la) throw new Error('link missing');
  const k = Pay.payKeys(P.decodeLink(la.data, e.link).master, e.address!.toBytes(), e.quoteHash);
  if (!K.equalBytes(k.viewPub, e.viewPub) || !K.equalBytes(k.spendPub, e.refundPoint)) throw new Error('escrow keys do not derive from its link');
  return K.toHex(k.view);
}

/** The lock block was mined no earlier than an hour before the escrow existed (block timestamp). */
async function lockIsFresh(e: P.EscrowAccount, height: number): Promise<boolean> {
  const r = await daemon(cfg.daemonUri, 'json_rpc', { jsonrpc: '2.0', id: 0, method: 'get_block_header_by_height', params: { height } });
  return Number(r.result.block_header.timestamp) >= Number(e.createdAt) - 3600;
}

async function makerHint(e: P.EscrowAccount): Promise<string | undefined> {
  const m = await conn.getAccountInfo(P.pda.maker(pid, e.maker));
  if (!m) return undefined;
  const ep = primaryEndpoint(P.decodeMaker(m.data).endpoint); // registry field: 'url|url|px=..|ts=..'
  try {
    const r = await fetch(`${ep}/v1/swap/${e.address!.toBase58()}`, { signal: AbortSignal.timeout(8000) });
    if (!r.ok) return undefined;
    const j = await r.json() as any;
    return typeof j.xmrLockTx === 'string' ? j.xmrLockTx : undefined;
  } catch { return undefined; }
}

async function check(w: Watch) {
  const e = await loadEscrow(w.escrow);
  if (!e) {
    if (!w.validated && Date.now() - (w.registeredAt ?? 0) < 15 * 60_000) return; // not locked yet
    w.outcome = w.validated ? 'closed' : 'never-locked'; return;
  }
  if (!w.validated) {
    // Pay escrows: the view key is derived from the public link, whatever was registered.
    const derived = await payView(e).catch(() => null);
    const cands = derived ? [derived] : (w.candidates ?? [w.viewSecret]);
    let err: unknown = null;
    for (const v of cands) {
      try { validate(e, K.fromHex(v)); w.viewSecret = v; w.validated = true; w.pay = !!derived; break; } catch (x) { err = x; }
    }
    if (!w.validated) { w.outcome = `invalid: ${(err as Error)?.message}`; return; }
    log(`${w.escrow.slice(0, 8)} lock seen, t0=${e.t0}`);
  }
  if (e.state !== P.ST.LOCKED) { w.outcome = P.ST_NAME[e.state]; return; } // ready = user vouched; terminal = done
  const now = await chainNow(conn);
  if (now >= Number(e.t0)) { w.outcome = 'past-t0'; return; }
  const isPay = (e.flags & P.F.PAY) !== 0;
  if (!w.latched && (!w.safe || isPay)) {
    // Normal escrows: fail closed (any error leaves the swap unsafe; the abort branch still runs).
    // Pay escrows are re-checked every poll until full minConf, because a pool tx can vanish; but
    // an abort there strands a delivered maker's XMR, so `safe` is cleared only after 2 polls in a
    // row with a clean negative answer, and an error keeps the last verdict.
    let verdict: 'ok' | 'neg' | 'err' = 'neg';
    try {
      const hints = [...new Set([await makerHint(e).catch(() => undefined), ...(w.hints ?? [])].filter((x): x is string => !!x))];
      if (!hints.length) w.lastCheck = 'no lock reported by maker';
      let errored: unknown = null;
      for (const hint of hints) {
        try {
        const v = await verifyLock({ daemonUri: cfg.daemonUri, txHash: hint, spendPub: K.pointAdd(e.claimPoint, e.refundPoint), viewSecret: K.fromHex(w.viewSecret), minAmount: e.xmrAmount, minConf: isPay ? 1 : cfg.minConf });
        const fresh = !isPay || v.height === undefined || v.inPool || !v.ok || (await lockIsFresh(e, v.height));
        w.lastCheck = v.ok && !fresh ? 'lock tx is older than the escrow' : v.ok ? `ok ${v.confirmations} conf` : v.reason;
        if (fresh && (v.ok || /^confirmations /.test(v.reason ?? ''))) w.delivered = true;
        if (v.ok && fresh) {
          verdict = 'ok';
          if (!w.safe) log(`${w.escrow.slice(0, 8)} XMR lock verified (${v.confirmations} conf, ${K.fmtXmr(v.amount!)} XMR)`);
          if ((v.confirmations ?? 0) >= cfg.minConf) w.latched = true;
          break;
        }
        } catch (err) { errored = err; } // one bad hint or node error must not skip the others
      }
      if (verdict !== 'ok' && errored) throw errored;
    } catch (err) { verdict = 'err'; w.lastCheck = `verify error: ${describeErr(err)}`; }
    if (verdict === 'ok') { w.safe = true; w.negStreak = 0; }
    else if (!isPay) { /* normal escrows never had safe set unless verified */ }
    else if (verdict === 'neg') { w.negStreak = (w.negStreak ?? 0) + 1; if (w.negStreak >= 2) w.safe = false; }
  }
  // A stay-to-confirm (READY_ONLY) escrow can never be paid out without the user's own ready, so an abort there only
  // protects against a maker that never delivered. Once the right XMR is seen at the shared address (still
  // confirming), aborting would only throw away a delivered swap: the user finishes it, or refunds after t1.
  const readyOnly = (e.flags & P.F.READY_ONLY) !== 0;
  if (!w.safe && !(readyOnly && w.delivered) && now >= Number(e.t0) - cfg.abortMarginSecs) {
    const sig = await sendIxs(conn, me, [P.ixAbort(pid, me.publicKey, e.address!, e.maker)]);
    w.outcome = `aborted ${sig}`;
    log(`${w.escrow.slice(0, 8)} ABORT: ${w.lastCheck} -> ${sig}`);
  }
}

/**
 * Neutral gas relay for XMR->SOL claims (fresh wallets with 0 SOL). The watchtower is never a
 * party to the swap. Strict: one claim instruction for an open XMR->SOL escrow, bounded compute
 * budget and fee, and the watchtower key appears nowhere but as fee payer.
 */
const MAX_RELAY_FEE = 30_000; // lamports
async function relayClaim(b: any) {
  const tx = Transaction.from(Buffer.from(String(b.tx), 'base64'));
  if (!tx.feePayer?.equals(me.publicKey)) throw new Error('fee payer must be this relayer');
  if (tx.nonceInfo) throw new Error('durable nonces are not relayed');
  let claims = 0;
  for (const ix of tx.instructions) {
    if (ix.programId.equals(ComputeBudgetProgram.programId)) {
      const d = Buffer.from(ix.data);
      if (d[0] === 2 && d.length === 5 && d.readUInt32LE(1) <= 60_000) continue;          // SetComputeUnitLimit
      if (d[0] === 3 && d.length === 9 && d.readBigUInt64LE(1) <= 20_000n) continue;     // SetComputeUnitPrice (micro-lamports)
      throw new Error('compute budget out of bounds');
    }
    const isHtlc = ix.programId.equals(pid) && ix.data[0] === Htlc.IX.HTLC_CLAIM && ix.data.length === 33;
    if (!isHtlc && (!ix.programId.equals(pid) || ix.data[0] !== 9 || ix.data.length !== 33)) throw new Error('only a single claim is relayed');
    claims++;
    if (ix.keys.some((k) => k.pubkey.equals(me.publicKey))) throw new Error('relayer key used in the claim');
    if (isHtlc) {
      // ZEC -> SOL into a fresh wallet: an open HTLC escrow for this claimer, before its deadline.
      const a = await conn.getAccountInfo(ix.keys[1].pubkey, 'confirmed');
      if (!a || !a.owner.equals(pid) || a.data.length !== Htlc.HTLC_LEN) throw new Error('not an HTLC escrow');
      const h = Htlc.decodeHtlc(a.data);
      if (h.direction !== Htlc.DIR_ZEC_TO_SOL || !h.claimer.equals(ix.keys[0].pubkey) || h.state !== P.ST.LOCKED) throw new Error('not an open ZEC->SOL escrow for this claimer');
      if ((await chainNow(conn)) >= Number(h.t1)) throw new Error('escrow not claimable now');
      continue;
    }
    const e = await loadEscrow(ix.keys[1].pubkey.toBase58());
    if (!e || e.direction !== 2 || !e.claimer.equals(ix.keys[0].pubkey)) throw new Error('not an open XMR->SOL escrow for this claimer');
    const now = await chainNow(conn);
    if (!(e.state === P.ST.READY || (e.state === P.ST.LOCKED && now >= Number(e.t0))) || now >= Number(e.t1)) throw new Error('escrow not claimable now');
  }
  if (claims !== 1) throw new Error('exactly one claim');
  const fee = (await conn.getFeeForMessage(tx.compileMessage(), 'confirmed')).value;
  if (fee === null || fee > MAX_RELAY_FEE) throw new Error('fee above the relay cap');
  tx.partialSign(me);
  if (!tx.verifySignatures()) throw new Error('missing claimer signature');
  const sig = await conn.sendRawTransaction(tx.serialize());
  const lastValid = await conn.getBlockHeight('confirmed').then((h) => h + 150);
  await waitForTx(sig, lastValid, { status: async (x) => (await conn.getSignatureStatuses([x], { searchTransactionHistory: true })).value[0], height: () => conn.getBlockHeight('confirmed') });
  log(`relayed claim ${ix0(tx)} ${sig.slice(0, 12)}`);
  return { sig };
}
const ix0 = (tx: Transaction) => tx.instructions.find((i) => i.programId.equals(pid))!.keys[1].pubkey.toBase58().slice(0, 8);

if (zec) setInterval(() => { zec.tick().catch((err) => log('zec tick', describeErr(err))); }, cfg.pollMs);
let lastDiscover = 0, tickN = 0;
setInterval(async () => {
  // Listing pay escrows is the expensive read: once a minute is enough for their window.
  if (Date.now() - lastDiscover >= 60_000) { lastDiscover = Date.now(); await discover().catch((err) => log('discover', describeErr(err))); }
  tickN++;
  for (const w of watches.values()) {
    if (w.outcome) continue;
    if (!w.validated && tickN % 4 !== 0) continue; // not locked yet: no need to read every tick
    try { await check(w); } catch (err) { w.lastCheck = describeErr(err); }
  }
  save();
}, cfg.pollMs);

http.createServer(async (req, res) => {
  res.setHeader('access-control-allow-origin', '*');
  res.setHeader('access-control-allow-headers', 'content-type');
  if (req.method === 'OPTIONS') { res.writeHead(204).end(); return; }
  try {
    let out: unknown;
    if (req.method === 'POST' && !unsigned.take(clientIp(req, cfg.trustProxy))) { res.writeHead(429, { 'content-type': 'application/json' }).end('{"error":"too many requests; slow down a little"}'); return; }
    if (req.method === 'GET' && req.url === '/v1/info') out = { pubkey: me.publicKey.toBase58(), watching: [...watches.values()].filter((w) => !w.outcome).length + (zec?.open ?? 0), powers: zec ? ['abort', 'zec-broadcast', 'htlc-refund-relay'] : ['abort'] };
    else if (req.method === 'POST' && req.url === '/v1/zec/watch') {
      if (!zec) throw new Error('no ZEC support here');
      // A shielded spend carries its v6 transaction (~9.2 kB, ~18.5 kB as hex).
      let s = ''; for await (const c of req) { s += c; if (s.length > 48_000) throw new Error('too large'); }
      out = await zec.register(JSON.parse(s), clientIp(req, cfg.trustProxy));
    }
    else if (req.method === 'POST' && req.url === '/v1/zec/script') {
      if (!zec) throw new Error('no ZEC support here');
      let s = ''; for await (const c of req) { s += c; if (s.length > 8000) throw new Error('too large'); }
      out = await zec.saveCopy(JSON.parse(s), clientIp(req, cfg.trustProxy));
    }
    else if (req.method === 'GET' && (req.url ?? '').startsWith('/v1/zec/scripts?')) {
      if (!zec) throw new Error('no ZEC support here');
      if (!unsigned.take(clientIp(req, cfg.trustProxy))) { res.writeHead(429, { 'content-type': 'application/json' }).end('{"error":"too many requests; slow down a little"}'); return; }
      out = zec.listCopies(new URL(req.url!, 'http://x').searchParams);
    }
    else if (req.method === 'POST' && req.url === '/v1/hint') {
      // A maker pushing its lock tx for an escrow we watch: only a hint, verified like any other.
      let s = ''; for await (const c of req) { s += c; if (s.length > 1024) throw new Error('too large'); }
      const b = JSON.parse(s);
      const w = watches.get(new PublicKey(String(b.escrow)).toBase58());
      if (!w || !/^[0-9a-f]{64}$/.test(String(b.txHash))) throw new Error('unknown escrow or bad tx hash');
      // Only the escrow's maker may push hints (signed), and the first few are kept for good.
      const e = await loadEscrow(w.escrow);
      if (!e || !ed25519.verify(K.fromHex(String(b.sig)), hintBytes(w.escrow, String(b.txHash)), e.maker.toBytes())) throw new Error('hint not signed by this escrow\'s maker');
      if (!(w.hints ?? []).includes(String(b.txHash)) && (w.hints ?? []).length < 4) w.hints = [...(w.hints ?? []), String(b.txHash)];
      out = { ok: true };
    } else if (req.method === 'POST' && req.url === '/v1/watch') {
      let s = ''; for await (const c of req) { s += c; if (s.length > 4096) throw new Error('too large'); }
      out = await register(JSON.parse(s), clientIp(req, cfg.trustProxy));
    } else if (req.method === 'POST' && req.url === '/v1/relay/claim') {
      let s = ''; for await (const c of req) { s += c; if (s.length > 8192) throw new Error('too large'); }
      out = await relayClaim(JSON.parse(s));
    } else { res.writeHead(404).end(); return; }
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(out));
  } catch (e) {
    res.writeHead(400, { 'content-type': 'application/json' }).end(JSON.stringify({ error: String((e as Error).message ?? e) }));
  }
}).listen(cfg.port, '127.0.0.1', () => log(`watchtower ${me.publicKey.toBase58()} on :${cfg.port}, watching ${watches.size}`));
