// HALFKEY watchtower, ZEC leg: holds users' PRE-SIGNED Zcash spends and broadcasts them at the
// right moment. It can only ever pay the user:
//  * SOL -> ZEC: the user's HTLC claim, signed before the preimage existed (ZIP 244 does not commit
//    to the scriptSig). When the maker claims the SOL, x is public in the escrow; the watchtower
//    inserts it and broadcasts. The outputs are covered by the user's signature, so it cannot
//    redirect anything. It also relays the permissionless Solana refund after t1 (pays the locker).
//  * ZEC -> SOL: the user's HTLC refund (valid from the lock height). Broadcast once the height is
//    reached if the output is still unspent (the maker did not claim it).
// Shielded spends (v2, sdk/zecshield.ts) are held the same way: the user's claim or refund pays one
// Ironwood note the watchtower cannot read; it checks the template, the signature and the Halo2
// proof once (WASM) at registration, then only splices the scriptSig (pure JS) when it broadcasts.
// Registrations never replace earlier ones (nobody can swap a good claim for a junk one).
import fs from 'node:fs';
import { Connection, Keypair, PublicKey } from '@solana/web3.js';
import * as Z from '../sdk/zec.ts';
import * as H from '../sdk/htlc.ts';
import * as SH from '../sdk/zecshield.ts';
import { loadZecWasm } from '../sdk/zecwasm-node.ts';
import { sha256 } from '@noble/hashes/sha256';
import { Journal, chainNow, sendIxs, describeErr, log, scanEscrowHistory } from '../maker/lib.ts';
import * as ZS from '../sdk/zecswap.ts';

export interface ZecTowerConfig { zebraRpc: string; zebraAuth?: string; zecNet: Z.ZecNet; db: string; maxWatches?: number; maxPerIp?: number; maxLockWaitSecs?: number; maxCopies?: number; maxCopiesPerWallet?: number; maxCopiesPerIp?: number }

interface ZWatch {
  escrow: string;
  presigned: SH.AnyPresigned;
  hashlock: string;
  lockHeight: number;
  registeredAt: number;
  ip?: string;
  /** Where the search for the preimage in the escrow's history got to (padding can push it back many pages). */
  histCursor?: string;
  broadcast?: string;
  outcome?: string;
  lastCheck?: string;
  solRefund?: string;
  /** The escrow was seen on Solana at least once. */
  seen?: boolean;
  /** Consecutive "spent" observations (a terminal outcome needs several). */
  spentStreak?: number;
  checks?: number;
}
/** Per HTLC output: at most this many registrations (junk entries need real ZEC outputs each). */
const MAX_PER_OUTPOINT = 4;
/**
 * Our broadcast counts as final at this many confirmations; until then it is rebroadcast if it drops out.
 * The same depth takers and makers ask of a deposit: at 25 s blocks a few confirmations are about a minute, and a reorg can go far deeper.
 */
const FINAL_CONF = 60;
/** A registered escrow that never appeared on chain gives up its slot after this long. */
const UNBOUND_SECS = 900;
/** Failed shielded verifications per HTLC output before it is refused outright (proof checks cost CPU). */
const MAX_FAILS_PER_OUTPOINT = 8;
/** Open watches per client address: an entry costs a check on every tick. Far above what real users behind one address hold. */
const MAX_PER_IP = 200;
/** A spend whose lock height is further off than this is refused: it would hold its slot for that long (takers accept 24 h). */
const MAX_LOCK_WAIT_SECS = 7 * 86_400;
/** Script copies kept. A full store, wallet or address drops its oldest instead of refusing: a flood costs the flooder's own copies first, and starting a swap never fails on it. */
const MAX_COPIES = 20_000;
const MAX_COPIES_PER_WALLET = 8;
const MAX_COPIES_PER_IP = 200;
/** A copy stays this long past its refund height: a user may come back late. */
const COPY_AFTER_REFUND_SECS = 7 * 86_400;
/** A copy handed over this long after its quote ran out is not a swap being started. */
const COPY_QUOTE_GRACE_SECS = 600;
/** A signed list request is good this long either way (seconds), and once. */
const LIST_WINDOW_SECS = 120;
/** History pages read per check. */
const HISTORY_PAGES = 5;

export class ZecTower {
  readonly call: Z.Rpc;
  private watches = new Map<string, ZWatch>();
  /** Shielded verdicts by sha256(raw) (failures too), and failure counts per outpoint. */
  private verdicts = new Map<string, string>();
  private fails = new Map<string, number>();
  private cfg: ZecTowerConfig;
  private conn: Connection;
  private pid: PublicKey;
  private me: Keypair;
  constructor(cfg: ZecTowerConfig, conn: Connection, pid: PublicKey, me: Keypair) {
    this.cfg = cfg; this.conn = conn; this.pid = pid; this.me = me;
    this.call = Z.rpc(cfg.zebraRpc, cfg.zebraAuth);
    if (fs.existsSync(cfg.db)) for (const w of JSON.parse(fs.readFileSync(cfg.db, 'utf8')) as ZWatch[]) this.watches.set(`${w.escrow}:${w.presigned.kind}:${w.presigned.txid}:${w.presigned.vout}`, w);
  }
  private save() {
    fs.writeFileSync(this.cfg.db + '.tmp', JSON.stringify([...this.watches.values()]), { mode: 0o600 });
    fs.renameSync(this.cfg.db + '.tmp', this.cfg.db);
  }
  // ---------------------------------------------------------------- script copies
  private copies = new Map<string, { item: ZS.ZecResumeItem; wallet: string; ip: string }>();
  private copyLog: Journal | null = null;
  private copyDirty = false;
  private compactAt = 0;
  private listNonces = new Map<string, number>();
  /** Used list nonces are in memory only, so a request signed before this process began is refused. */
  private bootAt = Math.floor(Date.now() / 1000);
  private copyJournal() {
    if (this.copyLog) return this.copyLog;
    const file = `${this.cfg.db}.copies`;
    for (const r of Journal.read(file)) { if (r.gone) this.copies.delete(r.swapId); else this.copies.set(r.swapId, { item: r.item, wallet: r.wallet, ip: r.ip }); }
    return (this.copyLog = new Journal(file));
  }
  private dropCopy(swapId: string) { this.copies.delete(swapId); this.copyDirty = true; this.copyJournal().append({ swapId, gone: true }); }
  /**
   * POST /v1/zec/script. Counts only with the wallet's own signature for this swap, the maker's quote, and a script that
   * really is that wallet's, so nobody can plant a copy under someone else's wallet. Written to disk before it is acknowledged.
   */
  async saveCopy(b: ZS.ZecScriptCopy, ip = '') {
    const log0 = this.copyJournal(), id = String(b?.swapId), t = Math.floor(Date.now() / 1000);
    if (!/^[0-9a-f]{64}$/.test(id)) throw new Error('swapId');
    let wallet: PublicKey, maker: PublicKey;
    try { wallet = new PublicKey(String(b.wallet)); maker = new PublicKey(String(b.quote?.maker)); } catch { throw new Error('bad copy'); }
    const q = b.quote, keysField = ZS.zecToSolKeys(String(b.hashlock), String(b.refundPub));
    if (!ZS.verifyOfferRequest(q, id, keysField, String(b.takerSig), wallet.toBytes())) throw new Error('this copy needs the wallet signature for this swap');
    if (q.expiresAt < t - COPY_QUOTE_GRACE_SECS) throw new Error('that quote is too old');
    const item: ZS.ZecResumeItem = { swapId: id, direction: 8, createdAt: t, quote: q, sig: String(b.sig), offer: b.offer };
    ZS.checkResumedZecToSol(item, { pid: this.pid, maker, keys: { hashlock: Z.unhex(String(b.hashlock)), refundPub: Z.unhex(String(b.refundPub)) }, net: this.cfg.zecNet }); // throws
    if (this.copies.has(id)) return { ok: true, known: true };
    const tip = Number((await this.call('getblockchaininfo')).blocks);
    if (b.offer.lockHeight > Z.heightAfter(await Z.upgradesFromNode(this.call), tip, this.cfg.maxLockWaitSecs ?? MAX_LOCK_WAIT_SECS)) throw new Error('that swap\'s lock height is too far away');
    const oldestOf = (f: (c: { wallet: string; ip: string }) => boolean, max: number) => { const m = [...this.copies.entries()].filter(([, c]) => f(c)); if (m.length >= max) this.dropCopy(m.sort((x, y) => x[1].item.createdAt - y[1].item.createdAt)[0][0]); };
    oldestOf((c) => c.wallet === wallet.toBase58(), this.cfg.maxCopiesPerWallet ?? MAX_COPIES_PER_WALLET);
    if (ip) oldestOf((c) => c.ip === ip, this.cfg.maxCopiesPerIp ?? MAX_COPIES_PER_IP);
    oldestOf(() => true, this.cfg.maxCopies ?? MAX_COPIES);
    log0.append({ swapId: id, item, wallet: wallet.toBase58(), ip });
    this.copies.set(id, { item, wallet: wallet.toBase58(), ip });
    return { ok: true };
  }
  /** GET /v1/zec/scripts: the signer's own copies. Same rules as the desk's list: this watchtower, this wallet, in time, once. */
  listCopies(q: URLSearchParams): { swaps: ZS.ZecResumeItem[] } {
    this.copyJournal();
    const wallet = q.get('wallet') ?? '', at = Number(q.get('at')), nonce = q.get('nonce') ?? '', sig = q.get('sig') ?? '', t = Math.floor(Date.now() / 1000);
    if (!Number.isInteger(at) || Math.abs(t - at) > LIST_WINDOW_SECS) throw new Error('that request is out of date; try again');
    if (!/^[0-9a-f]{32}$/.test(nonce)) throw new Error('nonce');
    if (!ZS.verifyListCopies(this.me.publicKey.toBase58(), wallet, at, nonce, sig)) throw new Error('this request needs your wallet signature');
    if (at < this.bootAt) throw new Error('that request is out of date; try again');
    for (const [k, exp] of this.listNonces) if (exp < t) this.listNonces.delete(k);
    const used = `${wallet}:${nonce}`;
    if (this.listNonces.has(used)) throw new Error('that request was already used; try again');
    this.listNonces.set(used, t + 2 * LIST_WINDOW_SECS + 1);
    return { swaps: [...this.copies.values()].filter((c) => c.wallet === wallet).map((c) => c.item).sort((x, y) => y.createdAt - x.createdAt) };
  }
  /** Copies past their time go, and the file is rewritten without what has gone, at most hourly. */
  private async pruneCopies(tip: number) {
    this.copyJournal();
    if (this.copies.size) {
      const ups = await Z.upgradesFromNode(this.call);
      for (const [id, c] of this.copies) if (tip > Z.heightAfter(ups, (c.item.offer as ZS.ZecToSolOffer).lockHeight, COPY_AFTER_REFUND_SECS)) this.dropCopy(id);
    }
    if (this.copyDirty && Date.now() - this.compactAt >= 3_600_000) {
      this.copyLog!.compact((r) => !r.gone && this.copies.has(r.swapId));
      this.copyDirty = false; this.compactAt = Date.now();
    }
  }

  get open() { return [...this.watches.values()].filter((w) => !w.outcome).length; }

  /**
   * POST /v1/zec/watch {escrow, presigned}. The spend must verify (template, key, signature) and
   * its HTLC output must exist, unspent, with the signed value: every entry is backed by real ZEC
   * locked on chain, so junk registrations cost the registrant.
   */
  async register(b: any, ip = '') {
    const escrow = new PublicKey(String(b?.escrow)).toBase58();
    const p = b?.presigned as SH.AnyPresigned;
    if (typeof p?.redeem !== 'string' || p.redeem.length > 400) throw new Error('bad presigned');
    let t: Z.HtlcTerms;
    const shielded = SH.isShielded(p);
    if (shielded) {
      // Cheap checks first (template, signature); the Halo2 proof only after the funding lookup.
      t = SH.verifyShieldedPresigned(await loadZecWasm(), p);
    } else {
      t = Z.verifyPresigned(p);
      if (BigInt(p.outValue) <= 0n || p.outScript.length > 200) throw new Error('bad presigned');
    }
    const key = `${escrow}:${p.kind}:${p.txid}:${p.vout}`;
    if (this.watches.has(key)) return { ok: true, known: true };
    const claimedEscrow = await this.escrowState(escrow);
    if (claimedEscrow && !this.bound(claimedEscrow, Z.hex(t.hashlock), p.kind)) throw new Error('this spend does not belong to that escrow');
    await this.freeSlots(p);
    if ([...this.watches.values()].filter((w) => !w.outcome && w.presigned.txid === p.txid && w.presigned.vout === p.vout).length >= MAX_PER_OUTPOINT) throw new Error('too many registrations for this output');
    if (this.open >= (this.cfg.maxWatches ?? 10_000)) throw new Error('watchtower full');
    if (ip && [...this.watches.values()].filter((w) => !w.outcome && w.ip === ip).length >= (this.cfg.maxPerIp ?? MAX_PER_IP)) throw new Error('too many open registrations from this address');
    const zt = Number((await this.call('getblockchaininfo')).blocks);
    if (t.lockHeight > Z.heightAfter(await Z.upgradesFromNode(this.call), zt, this.cfg.maxLockWaitSecs ?? MAX_LOCK_WAIT_SECS)) throw new Error('that spend\'s lock height is too far away');
    const op = `${p.txid}:${p.vout}`;
    if ((this.fails.get(op) ?? 0) >= MAX_FAILS_PER_OUTPOINT) throw new Error('too many bad registrations for this output');
    const f = await Z.checkFunding(this.call, p.txid, p.vout, Z.unhex(p.redeem));
    if (f.spent || f.value !== BigInt(p.value)) throw new Error('no such unspent HTLC output');
    if (shielded) await this.checkShielded(p as SH.ShieldedPresigned, t, op);
    this.watches.set(key, { escrow, presigned: p, hashlock: Z.hex(t.hashlock), lockHeight: t.lockHeight, registeredAt: Date.now(), ip: ip || undefined });
    this.save();
    log(`zec watch ${SH.isShielded(p) ? 'shielded ' : ''}${p.kind} ${escrow.slice(0, 8)} (${Z.hex(t.hashlock).slice(0, 8)})`);
    return { ok: true };
  }

  /** The escrow as it is on chain: null = no account (yet), or not an HTLC of this program. Errors throw: unknown is not "absent". */
  private async escrowState(escrow: string): Promise<H.HtlcAccount | null> {
    const a = await this.conn.getAccountInfo(new PublicKey(escrow), 'confirmed');
    if (!a || !a.owner.equals(this.pid) || a.data.length !== H.HTLC_LEN) return null;
    return H.decodeHtlc(a.data, new PublicKey(escrow));
  }
  private bound(h: H.HtlcAccount, hashlock: string, kind: 'claim' | 'refund') {
    return Z.hex(h.hashlock) === hashlock && h.direction === (kind === 'claim' ? H.DIR_SOL_TO_ZEC : H.DIR_ZEC_TO_SOL);
  }
  /**
   * Whoever holds a pre-signed spend could register it under made-up escrow addresses and use up an
   * output's slots, so the real registration is refused. A slot only counts while its escrow can still
   * be real: an entry whose escrow exists with another hashlock, or never appeared within
   * UNBOUND_SECS, gives its slot back. (Registration comes before the SOL lock, so a fresh entry can't be judged.)
   */
  private async freeSlots(p: SH.AnyPresigned) {
    const same = [...this.watches.values()].filter((w) => !w.outcome && w.presigned.txid === p.txid && w.presigned.vout === p.vout);
    if (same.length < MAX_PER_OUTPOINT) return;
    for (const w of same) {
      const h = await this.escrowState(w.escrow);
      if (h ? !this.bound(h, w.hashlock, w.presigned.kind) : !w.seen && Date.now() - w.registeredAt > UNBOUND_SECS * 1000) w.outcome = 'escrow-mismatch';
    }
  }

  /**
   * The expensive part, once per distinct transaction: the branch must hold until the spend can be
   * mined (no upgrade before the lock height plus a buffer), the anchor must be a real final root
   * on our own node, and the Halo2 proof and bundle signatures must verify. Every check is backed
   * by a real unspent HTLC output; verdicts (failures included) are cached by sha256(raw).
   */
  private async checkShielded(p: SH.ShieldedPresigned, t: Z.HtlcTerms, op: string) {
    const key = Z.hex(sha256(Z.unhex(p.raw)));
    const cached = this.verdicts.get(key);
    if (cached === 'ok') return;
    if (cached) throw new Error(cached);
    try {
      const ups = await Z.upgradesFromNode(this.call);
      const tip = Number((await this.call('getblockchaininfo')).blocks);
      if (Z.upgradeAt(ups, tip + 1).branch !== p.branch) throw new Error('signed for another branch');
      const up = Z.upgradeBetween(ups, tip, Z.heightAfter(ups, t.lockHeight, 6 * 3600));
      if (up) throw new Error(`network upgrade ${up.name} before the spend can be mined`);
      const w = await loadZecWasm();
      // 90, not 100: the client anchors at its tip - 100 on testnet (720 on mainnet); a tower node a
      // few blocks behind the site's must not refuse a fresh refund for being too recent.
      await SH.checkAnchor(w, this.call, p, this.cfg.zecNet === 'regtest' ? 1 : 90);
      SH.verifyShieldedPresigned(w, p, { verifyProof: true });
      this.verdicts.set(key, 'ok');
    } catch (e) {
      const m = String((e as Error).message ?? e);
      // Node errors and tip-dependent checks (anchor depth, branch, upgrade window) are not
      // verdicts: they can pass later. Everything else is remembered and counted.
      if (!/fetch|ECONN|timeout|-28|-32|anchor too recent|another branch|network upgrade/i.test(m)) { this.verdicts.set(key, m); this.fails.set(op, (this.fails.get(op) ?? 0) + 1); }
      throw e;
    }
    if (this.verdicts.size > 50_000) this.verdicts.clear();
  }

  private async send(w: ZWatch, raw: string, txid: string) {
    try { await this.call('sendrawtransaction', [raw]); } catch (e) {
      const m = String((e as Error).message);
      if (!/already|known|duplicate|exists/i.test(m)) throw e; // already in the mempool or a block: fine
    }
    w.broadcast = txid;
  }

  async tick() {
    let tip = 0;
    try { tip = Number((await this.call('getblockchaininfo')).blocks); } catch (e) { log('zec tower tip', describeErr(e)); return; }
    await this.pruneCopies(tip).catch((e) => log('zec copies', describeErr(e)));
    for (const w of this.watches.values()) {
      if (w.outcome) continue;
      try { await this.check(w, tip); w.lastCheck = undefined; } catch (e) { w.lastCheck = describeErr(e); }
    }
    this.save();
  }

  private async check(w: ZWatch, tip: number) {
    const p = w.presigned;
    w.checks = (w.checks ?? 0) + 1;
    // RPC errors throw here (kept as lastCheck); only the node's explicit "gone" counts as spent.
    const f = await Z.checkFunding(this.call, p.txid, p.vout, Z.unhex(p.redeem));
    w.spentStreak = f.spent ? (w.spentStreak ?? 0) + 1 : 0;
    if (w.broadcast) {
      const conf = await this.call('getrawtransaction', [w.broadcast, 1]).then((r: any) => Number(r.confirmations ?? 0), () => -1);
      if (conf >= FINAL_CONF) { w.outcome = p.kind === 'claim' ? 'claimed' : 'refunded'; log(`zec ${w.outcome} for ${w.escrow.slice(0, 8)}: ${w.broadcast}`); return; }
      if (conf < 0 && (w.spentStreak ?? 0) >= 10) { w.outcome = 'spent-elsewhere'; return; } // ours is gone and so is the output
    } else if ((w.spentStreak ?? 0) >= 3) { w.outcome = 'spent-elsewhere'; return; }
    if (p.kind === 'refund') {
      if (tip >= w.lockHeight && !f.spent) {
        const fin = SH.finalizeAny(p);
        await this.send(w, fin.raw, fin.txid);
      }
      return;
    }
    // claim: wait for the preimage on Solana.
    const a = await this.conn.getAccountInfo(new PublicKey(w.escrow), 'confirmed');
    if (!a || !a.owner.equals(this.pid) || a.data.length !== H.HTLC_LEN) {
      // Closed after the claim (rent reclaimed): the preimage is still in the claim transaction.
      if (w.seen || w.checks % 10 === 1) {
        const x = await this.preimageFromHistory(w);
        if (x && !f.spent) { const fin = SH.finalizeAny(p, x); await this.send(w, fin.raw, fin.txid); return; }
      }
      if (!w.seen && tip > w.lockHeight) w.outcome = 'expired-never-locked';
      return;
    }
    w.seen = true;
    const h = H.decodeHtlc(a.data, new PublicKey(w.escrow));
    if (Z.hex(h.hashlock) !== w.hashlock || h.direction !== H.DIR_SOL_TO_ZEC) { w.outcome = 'escrow-mismatch'; return; }
    if (h.state === 4) {
      const x = H.revealedPreimage(h);
      if (x && !f.spent) {
        const fin = SH.finalizeAny(p, x);
        await this.send(w, fin.raw, fin.txid);
      }
      return;
    }
    if (h.state === 3 || h.state === 5) {
      if (h.state === 5) w.outcome = 'sol-refunded';
      if (h.state === 3) await this.relayRefund(w, h);
      return;
    }
    if (h.state === 1 && (await chainNow(this.conn)) >= Number(h.t1)) await this.relayRefund(w, h);
  }

  /** x from an htlc_claim instruction in the escrow's history (successful or not: x is x). */
  private async preimageFromHistory(w: ZWatch): Promise<Uint8Array | null> {
    const hl = Z.hex(Z.unhex(w.hashlock));
    const pick = (d: Uint8Array) => {
      if (d.length !== 33 || d[0] !== H.IX.HTLC_CLAIM) return null;
      const x = Uint8Array.from(d.slice(1));
      return Z.hex(sha256(x)) === hl ? x : null;
    };
    // Anyone can pad an escrow's history. Page on from where the last check stopped; a page that can't be read throws (kept as lastCheck).
    for (let i = 0; i < HISTORY_PAGES; i++) {
      const r = await scanEscrowHistory(this.conn, this.pid, new PublicKey(w.escrow), pick, w.histCursor, 40, true);
      if (r.found) return r.found;
      w.histCursor = r.done ? undefined : r.cursor;
      if (r.done) break;
    }
    return null;
  }

  /** The permissionless HTLC refund: pays only the locker (the user), reveals nothing. */
  private async relayRefund(w: ZWatch, h: H.HtlcAccount) {
    if (w.solRefund) return;
    w.solRefund = await sendIxs(this.conn, this.me, [H.ixHtlcRefund(this.pid, this.me.publicKey, h.address!, h.locker, h.maker)]);
    log(`relayed HTLC refund ${w.escrow.slice(0, 8)} ${w.solRefund.slice(0, 12)}`);
  }
}
