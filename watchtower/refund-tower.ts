// HALFKEY refund tower (XMR->SOL). Holds one share of a maker's key half per swap; never a whole half.
//
// The maker deals 2-of-3 shares after it locks SOL (sdk/refundtowers.ts). This tower accepts a share only
// when the escrow is on chain, locked by a maker it serves, in ready-only mode, and the request is signed
// by that maker; it checks the share against the commitments and signs an ack the page checks before it
// shows a deposit address. It releases the share only when a claim is impossible, read at finalized from
// two independent RPCs that agree (sdk/refundtowers.ts releaseDecision). Then it rebuilds the half with a
// peer's released share and submits the permissionless `refund`: the SOL goes back to the maker, the half
// lands on chain, and the user sweeps its XMR back. A claimed swap's share is destroyed.
//
// Keys: one Solana key per tower. It signs acks and pays refund fees (keep dust on it). It can't move swap
// funds: a refund pays only the escrow's locker.
//
//   node watchtower/refund-tower.ts /etc/halfkey/refund-tower.json
import fs from 'node:fs';
import http from 'node:http';
import { Connection, Keypair, PublicKey, SYSVAR_CLOCK_PUBKEY } from '@solana/web3.js';
import * as P from '../sdk/program.ts';
import * as K from '../sdk/keys.ts';
import * as R from '../sdk/refundtowers.ts';

export interface Reader {
  /** The escrow (or its absence) and the clock, from one finalized snapshot. */
  read(escrow: PublicKey, commitment: 'confirmed' | 'finalized'): Promise<R.ChainRead>;
}
const withTimeout = <T>(p: Promise<T>, ms: number) => Promise.race([p, new Promise<never>((_, rej) => setTimeout(() => rej(new Error('timeout')), ms).unref?.())]);
export function rpcReader(conn: Connection, pid: PublicKey, timeoutMs = 10_000): Reader {
  return {
    async read(escrow, commitment) {
      try {
        const [a, c] = await withTimeout(conn.getMultipleAccountsInfo([escrow, SYSVAR_CLOCK_PUBKEY], commitment), timeoutMs);
        if (!c) return { kind: 'error' };
        const clock = Number(Buffer.from(c.data).readBigInt64LE(32)); // Clock.unix_timestamp
        if (!a) return { kind: 'missing', clock };
        if (!a.owner.equals(pid)) return { kind: 'missing', clock };
        return { kind: 'escrow', e: P.decodeEscrow(a.data, escrow), clock };
      } catch {
        return { kind: 'error' };
      }
    },
  };
}

export interface Rec {
  escrow: string; index: number; share: string; c1: string; refundPoint: string; createdAt: string; t1: string;
  locker: string; claimer: string; amount: string; ack: R.Ack; at: number;
  /** For a page that finds the escrow closed: what it needs to rebuild its own half and the address. */
  swapId?: string; claimPoint?: string; viewPub?: string; xmrAmount?: string;
  /** Released because the refund (and the half) was found in the escrow's history after it closed. */
  fromHistory?: boolean; settledAt?: number; historyCheckedAt?: number; historyCursor?: string;
  /** A claim became impossible (latched: survives the escrow being closed later). */
  releasable?: boolean;
  /** Claimed: the share was destroyed. */
  claimed?: boolean;
  goneSince?: number; refundSig?: string; refundError?: string; lastDecision?: string;
}

export interface TowerOpts {
  pid: PublicKey; index: number; key: Keypair; makers: string[]; readers: Reader[];
  /** Other towers' base URLs (their GET /share/<escrow>), for rebuilding the half. */
  peers: string[];
  /**
   * A closed escrow's history, a few pages per call from `cursor`: a successful refund (its secret matches the refund
   * point) or a claim (its secret matches the claim point). `done` = read to the start with neither.
   */
  findSettlement?: (escrow: PublicKey, refundPoint: Uint8Array, claimPoint: Uint8Array | null, cursor?: string) => Promise<{ kind: 'refund'; secret: Uint8Array } | { kind: 'claim' } | { kind: 'none'; cursor?: string; done: boolean }>;
  /** Sends the refund; returns the signature. */
  submitRefund: (e: P.EscrowAccount, secret: Uint8Array) => Promise<string>;
  load: () => Rec[]; save: (recs: Rec[]) => void;
  now: () => number;
  fetchJson?: (url: string) => Promise<any>;
  /** Furthest t1 accepted, seconds from now (default 2 days). */
  maxHoldSecs?: number;
  maxRecords?: number;
  log?: (...a: unknown[]) => void;
}

export class TowerError extends Error { status: number; constructor(status: number, msg: string) { super(msg); this.status = status; } }

export class RefundTower {
  recs = new Map<string, Rec>();
  o: TowerOpts;
  constructor(o: TowerOpts) {
    this.o = o;
    if (o.readers.length < 2) throw new Error('a refund tower needs two independent RPC readers');
    if (!(o.index >= 1 && o.index <= R.N_TOWERS)) throw new Error('tower index must be 1..3');
    for (const r of o.load()) this.recs.set(r.escrow, r);
  }
  private log(...a: unknown[]) { (this.o.log ?? console.log)(...a); }
  private persist() { this.o.save([...this.recs.values()]); }

  private inflight = new Map<string, Promise<unknown>>();
  /** POST /deal: store one share and return the ack. Idempotent for the same share. One deal per escrow at a time. */
  async deal(b: any): Promise<R.Ack> {
    const k = String(b?.escrow ?? '');
    while (this.inflight.has(k)) await this.inflight.get(k)!.catch(() => {});
    const p = this.dealOne(b);
    this.inflight.set(k, p);
    try { return await p; } finally { this.inflight.delete(k); }
  }

  private async dealOne(b: any): Promise<R.Ack> {
    const req: R.DealReq = { escrow: String(b?.escrow ?? ''), index: Number(b?.index), share: String(b?.share ?? ''), c1: String(b?.c1 ?? ''), sig: String(b?.sig ?? '') };
    if (req.index !== this.o.index) throw new TowerError(400, `this is tower ${this.o.index}`);
    let escrowPk: PublicKey;
    try { escrowPk = new PublicKey(req.escrow); } catch { throw new TowerError(400, 'bad escrow'); }
    if (!/^[0-9a-f]{64}$/.test(req.share) || !/^[0-9a-f]{64}$/.test(req.c1) || !/^[0-9a-f]{128}$/.test(req.sig)) throw new TowerError(400, 'bad fields');
    req.maker = b?.maker === undefined ? undefined : String(b.maker); req.auth = b?.auth === undefined ? undefined : String(b.auth);
    // Before any chain read: only a maker on our list gets past here.
    if (!R.verifyDealAuth(req, this.o.makers)) throw new TowerError(401, 'not signed by a maker this tower serves');
    const prev = this.recs.get(req.escrow);
    if (prev && prev.share === req.share && prev.c1 === req.c1 && !prev.claimed) return prev.ack;
    if (this.recs.size >= (this.o.maxRecords ?? 20_000)) throw new TowerError(503, 'tower full');
    // Confirmed is enough to accept: the maker deals right after its lock lands. Release reads finalized. A provider
    // that hasn't seen the lock yet is asked again through the other one.
    let r = await this.o.readers[0].read(escrowPk, 'confirmed');
    if (r.kind !== 'escrow') r = await this.o.readers[1].read(escrowPk, 'confirmed');
    if (r.kind !== 'escrow') throw new TowerError(r.kind === 'error' ? 503 : 404, r.kind === 'error' ? 'chain read failed' : 'escrow not found');
    const e = r.e;
    if (prev) {
      // A swap id reused after the old escrow closed: replace the old record only if it is settled and for another escrow.
      const settled = prev.claimed || !!prev.refundSig || prev.releasable;
      if (!(settled && prev.createdAt !== e.createdAt.toString())) throw new TowerError(409, 'this escrow already has a share here');
    }
    if (e.direction !== 2) throw new TowerError(400, 'not an XMR->SOL escrow');
    if (e.state !== P.ST.LOCKED) throw new TowerError(400, 'escrow is not open');
    if (!(e.flags & P.F.PROOF)) throw new TowerError(400, 'escrow is not ready-only');
    if (!this.o.makers.includes(e.locker.toBase58())) throw new TowerError(403, 'maker not served by this tower');
    const now = this.o.now();
    if (Number(e.t1) - now > (this.o.maxHoldSecs ?? 172_800)) throw new TowerError(400, 't1 too far out');
    if (Number(e.t1) <= now) throw new TowerError(400, 'past t1');
    const c1 = K.fromHex(req.c1);
    const t = R.termsOf(this.o.pid, escrowPk, e, c1);
    if (!R.verifyDeal(req, t, this.o.key.publicKey)) throw new TowerError(403, 'not signed by the escrow\'s maker');
    const sh: R.Share = { i: this.o.index, s: K.fromHex(req.share) };
    if (!R.verifyShare(sh, { c0: e.refundPoint, c1 })) throw new TowerError(400, 'share does not match the commitments');
    const ack = R.signAck(t, this.o.index, this.o.key);
    this.recs.set(req.escrow, {
      escrow: req.escrow, index: this.o.index, share: req.share, c1: req.c1, refundPoint: K.toHex(e.refundPoint), createdAt: e.createdAt.toString(),
      t1: e.t1.toString(), locker: e.locker.toBase58(), claimer: e.claimer.toBase58(), amount: e.amount.toString(), ack, at: now,
      swapId: K.toHex(e.swapId), claimPoint: K.toHex(e.claimPoint), viewPub: K.toHex(e.viewPub), xmrAmount: e.xmrAmount.toString(),
    });
    this.persist();
    this.log(`deal ${req.escrow.slice(0, 8)} accepted, t1 ${e.t1}`);
    return ack;
  }

  ack(escrow: string): R.Ack {
    const r = this.recs.get(escrow);
    if (!r || r.claimed) throw new TowerError(404, 'no share for this escrow');
    return r.ack;
  }

  /** GET /share: only once a claim is impossible. */
  share(escrow: string): { index: number; share: string; c1: string; refundPoint: string; claimPoint?: string; viewPub?: string; swapId?: string; createdAt: string; t1: string; claimer: string; xmrAmount?: string } {
    const r = this.recs.get(escrow);
    if (!r) throw new TowerError(404, 'no share for this escrow');
    if (r.claimed) throw new TowerError(410, 'claimed: share destroyed');
    if (!r.releasable) throw new TowerError(403, 'not released: the swap can still be claimed');
    return { index: r.index, share: r.share, c1: r.c1, refundPoint: r.refundPoint, claimPoint: r.claimPoint, viewPub: r.viewPub, swapId: r.swapId, createdAt: r.createdAt, t1: r.t1, claimer: r.claimer, xmrAmount: r.xmrAmount };
  }

  /** One pass over open records, a few at a time; one slow or failing record never holds up the others. */
  async tick(): Promise<void> {
    const now = this.o.now();
    let dirty = this.prune(now);
    const open = [...this.recs.values()].filter((r) => !r.claimed && !r.refundSig);
    for (let i = 0; i < open.length; i += 8) {
      const res = await Promise.allSettled(open.slice(i, i + 8).map((r) => this.step(r, now)));
      if (res.some((x) => x.status === 'fulfilled' && x.value)) dirty = true;
    }
    if (dirty) this.persist();
  }

  /** Settled records go: claimed after a day, refunded after 180 days (a page finding the escrow closed still fetches the pieces). */
  private prune(now: number): boolean {
    let n = 0;
    for (const [k, r] of this.recs) {
      const keep = r.claimed ? 86_400 : r.refundSig ? 180 * 86_400 : Infinity;
      if (now - (r.settledAt ?? now) > keep) { this.recs.delete(k); n++; }
    }
    return n > 0;
  }

  private async step(r: Rec, now: number): Promise<boolean> {
    const pk = new PublicKey(r.escrow);
    let dirty = false;
    if (!r.releasable) {
      // Read every pass, before t1 too: an aborted swap releases at once.
      const reads = await Promise.all(this.o.readers.map((x) => x.read(pk, 'finalized')));
      const held: R.Held = { createdAt: BigInt(r.createdAt), refundPoint: K.fromHex(r.refundPoint), t1: BigInt(r.t1) };
      const d = R.releaseDecision(reads, held);
      if (d !== r.lastDecision) { r.lastDecision = d; dirty = true; }
      if (d === 'claimed') {
        r.share = ''.padEnd(64, '0'); r.claimed = true; r.settledAt = now;
        this.log(`escrow ${r.escrow.slice(0, 8)} claimed: share destroyed`);
        return true;
      }
      if (d === 'gone') {
        if (!r.goneSince) { r.goneSince = now; dirty = true; }
        // Closed before we saw it settle. A refund in the history made the half public: release. A claim there: destroy.
        // Neither found yet: keep reading, a few pages a pass; read to the start, look again in an hour.
        if (this.o.findSettlement && (r.historyCursor || r.historyCheckedAt === undefined || now - r.historyCheckedAt >= 3600)) {
          dirty = true;
          const f = await withTimeout(this.o.findSettlement(pk, K.fromHex(r.refundPoint), r.claimPoint ? K.fromHex(r.claimPoint) : null, r.historyCursor), 120_000).catch(() => null);
          if (f?.kind === 'refund' && K.equalBytes(K.pub(f.secret), K.fromHex(r.refundPoint))) {
            r.releasable = true; r.fromHistory = true; r.refundSig = 'refunded-then-closed'; r.settledAt = now; r.historyCursor = undefined;
            this.log(`escrow ${r.escrow.slice(0, 8)} closed after a refund: share released`);
          } else if (f?.kind === 'claim') {
            r.share = ''.padEnd(64, '0'); r.claimed = true; r.settledAt = now; r.historyCursor = undefined;
            this.log(`escrow ${r.escrow.slice(0, 8)} closed after a claim: share destroyed`);
          } else if (f?.kind === 'none') {
            r.historyCursor = f.done ? undefined : f.cursor;
            if (f.done) r.historyCheckedAt = now;
          }
        }
        return dirty;
      }
      if (d !== 'release') return dirty;
      r.releasable = true; dirty = true;
      this.log(`escrow ${r.escrow.slice(0, 8)} can no longer be claimed: share released`);
    }
    // Released: put the half on chain unless the refund already happened.
    const read = await this.o.readers[0].read(pk, 'confirmed');
    if (read.kind === 'missing') { r.refundSig = 'closed-after-release'; r.settledAt = now; return true; } // refunded and closed by someone
    if (read.kind !== 'escrow' || read.e.createdAt.toString() !== r.createdAt) return dirty; // read failed, or another escrow now
    if (read.e.state === P.ST.REFUNDED) { r.refundSig = 'already-refunded'; r.settledAt = now; return true; }
    try {
      const secret = await this.rebuild(r);
      r.refundSig = await withTimeout(this.o.submitRefund(read.e, secret), 90_000);
      r.refundError = undefined; r.settledAt = now;
      this.log(`escrow ${r.escrow.slice(0, 8)} refunded ${r.refundSig.slice(0, 12)}`);
    } catch (err) {
      r.refundError = String((err as Error)?.message ?? err).slice(0, 200);
    }
    return true;
  }

  /** Our share plus one peer's released share. */
  async rebuild(r: Rec): Promise<Uint8Array> {
    const mine: R.Share = { i: r.index, s: K.fromHex(r.share) };
    const c: R.Commitments = { c0: K.fromHex(r.refundPoint), c1: K.fromHex(r.c1) };
    const fetchJson = this.o.fetchJson ?? (async (u: string) => { const x = await fetch(u, { signal: AbortSignal.timeout(8000) }); if (!x.ok) throw new Error(String(x.status)); return x.json(); });
    for (const p of this.o.peers) {
      try {
        const j = await fetchJson(`${p.replace(/\/+$/, '')}/share/${r.escrow}`);
        const sh: R.Share = { i: Number(j.index), s: K.fromHex(String(j.share)) };
        if (sh.i === mine.i || String(j.c1) !== r.c1 || !R.verifyShare(sh, c)) continue;
        return R.combine([mine, sh], c.c0);
      } catch { /* next peer */ }
    }
    throw new Error('no peer share released yet');
  }
}

// ---------------------------------------------------------------- service
interface Config {
  programId: string; index: number; keypair: string; port: number; db: string; makers: string[];
  /** Two different providers: release needs both to agree. */
  rpcUrls: string[]; peers: string[]; pollMs?: number; trustProxy?: boolean;
  priority?: { auto?: boolean; microLamports?: number; minMicroLamports?: number; maxMicroLamports?: number };
}

async function main() {
  const { sendIxs, setPriority, loadKeypair, log, describeErr, scanEscrowHistory } = await import('../maker/lib.ts');
  const { ipKey } = await import('../maker/policy.ts');
  const cfg: Config = JSON.parse(fs.readFileSync(process.argv[2] ?? 'watchtower/refund-tower.json', 'utf8'));
  if (!Array.isArray(cfg.rpcUrls) || cfg.rpcUrls.length < 2 || new Set(cfg.rpcUrls).size < 2) throw new Error('rpcUrls: two different RPC providers are required');
  if (!cfg.makers?.length) throw new Error('makers: list the maker authorities this tower serves');
  const pid = new PublicKey(cfg.programId);
  const key = loadKeypair(cfg.keypair);
  const conns = cfg.rpcUrls.map((u) => new Connection(u, 'confirmed'));
  if (cfg.priority) setPriority(conns[0], cfg.priority);
  const tower = new RefundTower({
    pid, index: cfg.index, key, makers: cfg.makers, peers: cfg.peers ?? [], readers: conns.map((c) => rpcReader(c, pid)), now: () => Math.floor(Date.now() / 1000),
    // A missing or unreadable store stops the service: starting empty would orphan every piece we hold.
    load: () => { if (!fs.existsSync(cfg.db)) throw new Error(`db ${cfg.db} is missing: restore it, or create it with [] on a new tower`); return JSON.parse(fs.readFileSync(cfg.db, 'utf8')); },
    findSettlement: async (escrow, refundPoint, claimPoint, cursor) => {
      const pick = (d: Uint8Array) => {
        if (d.length !== 33) return null;
        const x = d.slice(1);
        if (!K.isCanonical(x) || K.leToBig(x) === 0n) return null;
        if (d[0] === P.IX.REFUND && K.equalBytes(K.pub(x), refundPoint)) return { kind: 'refund' as const, secret: x };
        if (d[0] === P.IX.CLAIM && claimPoint && K.equalBytes(K.pub(x), claimPoint)) return { kind: 'claim' as const };
        return null;
      };
      for (let page = 0; page < 5; page++) {
        const r = await scanEscrowHistory(conns[1], pid, escrow, pick, cursor);
        if (r.found) return r.found;
        if (r.done) return { kind: 'none' as const, done: true };
        cursor = r.cursor;
      }
      return { kind: 'none' as const, cursor, done: false };
    },
    save: (recs) => { fs.writeFileSync(cfg.db + '.tmp', JSON.stringify(recs), { mode: 0o600 }); fs.renameSync(cfg.db + '.tmp', cfg.db); },
    submitRefund: (e, secret) => sendIxs(conns[0], key, [P.ixRefund(pid, key.publicKey, e.address!, e.locker, e.maker, secret)]),
    log,
  });
  // Counted per client address only for requests that fail the maker signature, so nobody can spend the maker's budget.
  // Behind Caddy, the last X-Forwarded-For entry is the address Caddy saw; client-set headers are ignored.
  const fails = new Map<string, { n: number; at: number }>();
  const failed = (ip: string) => { const t = Date.now(), h = fails.get(ip); if (!h || t - h.at > 60_000) fails.set(ip, { n: 1, at: t }); else h.n++; };
  const blocked = (ip: string) => { const h = fails.get(ip); return !!h && Date.now() - h.at <= 60_000 && h.n >= 30; };
  const ipOf = (req: http.IncomingMessage) => {
    const xff = String(req.headers['x-forwarded-for'] ?? '').split(',').map((x) => x.trim()).filter(Boolean);
    return ipKey(cfg.trustProxy && xff.length ? xff[xff.length - 1] : req.socket.remoteAddress ?? '');
  };
  setInterval(() => { const t = Date.now(); for (const [k, h] of fails) if (t - h.at > 60_000) fails.delete(k); }, 60_000).unref();
  let ticking = false;
  setInterval(() => { if (ticking) return; ticking = true; tower.tick().catch((e) => log('tick', describeErr(e))).finally(() => { ticking = false; }); }, cfg.pollMs ?? 20_000);
  http.createServer(async (req, res) => {
    const send = (code: number, body: unknown) => res.writeHead(code, { 'content-type': 'application/json', 'access-control-allow-origin': '*', 'cache-control': 'no-store' }).end(JSON.stringify(body));
    try {
      const url = new URL(req.url ?? '/', 'http://x');
      const m = url.pathname.match(/^\/(ack|share)\/([1-9A-HJ-NP-Za-km-z]{32,44})$/);
      if (req.method === 'GET' && url.pathname === '/health') return send(200, { tower: key.publicKey.toBase58(), index: cfg.index, held: tower.recs.size });
      if (req.method === 'GET' && m) return send(200, m[1] === 'ack' ? tower.ack(m[2]) : tower.share(m[2]));
      if (req.method === 'POST' && url.pathname === '/deal') {
        const ip = ipOf(req);
        if (blocked(ip)) return send(429, { error: 'too many failed requests' });
        let s = '';
        for await (const ch of req) { s += ch; if (s.length > 4096) return send(413, { error: 'too large' }); }
        try { return send(200, await tower.deal(JSON.parse(s))); }
        catch (err) { if (!(err instanceof TowerError) || err.status === 401 || err.status === 400) failed(ip); throw err; }
      }
      send(404, { error: 'not found' });
    } catch (err) {
      send(err instanceof TowerError ? err.status : 400, { error: err instanceof TowerError ? err.message : 'bad request' });
    }
  }).listen(cfg.port, '127.0.0.1', () => log(`refund tower ${cfg.index} ${key.publicKey.toBase58()} on 127.0.0.1:${cfg.port}`));
}

if (import.meta.main) main().catch((e) => { console.error(e); process.exit(1); });
