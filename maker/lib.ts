// Maker daemon building blocks: crash-safe journal, monero-wallet-rpc client, Solana helpers.
import fs from 'node:fs';
import path from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import { Connection, Keypair, PublicKey, Transaction, TransactionInstruction, ComputeBudgetProgram, SYSVAR_CLOCK_PUBKEY } from '@solana/web3.js';
import bs58 from 'bs58';
import { errName, IX } from '../sdk/program.ts';
import * as K from '../sdk/keys.ts';
import { waitForTx } from '../sdk/confirm.ts';

// ---------------------------------------------------------------- journal
/**
 * Append-only JSONL, fsync'd before any externally visible action (HTTP reply, XMR relay,
 * claim). Replaying it plus the chain state reconstructs every swap after a crash.
 */
export class Journal {
  fd: number;
  file: string;
  constructor(file: string) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    this.file = file;
    this.fd = fs.openSync(file, 'a', 0o600);
  }
  append(rec: Record<string, unknown>) {
    const line = JSON.stringify({ t: Date.now(), ...rec }, (_k, v) => (typeof v === 'bigint' ? v.toString() : v)) + '\n';
    fs.writeSync(this.fd, line);
    fs.fsyncSync(this.fd);
  }
  /**
   * Rewrite without the records `keep` refuses. Atomic: a crash at any point leaves the old file or the new
   * one whole, and a failure leaves the old one in use and throws.
   */
  compact(keep: (rec: Record<string, any>) => boolean) {
    const tmp = `${this.file}.compact`;
    const out = fs.openSync(tmp, 'w', 0o600);
    try {
      for (const r of Journal.read(this.file)) if (keep(r)) fs.writeSync(out, JSON.stringify(r) + '\n');
      fs.fsyncSync(out);
    } catch (e) { fs.closeSync(out); fs.rmSync(tmp, { force: true }); throw e; }
    fs.closeSync(out);
    fs.renameSync(tmp, this.file);
    const dir = fs.openSync(path.dirname(this.file), 'r');
    try { fs.fsyncSync(dir); } catch { /* not every filesystem syncs a directory */ } finally { fs.closeSync(dir); }
    fs.closeSync(this.fd);
    this.fd = fs.openSync(this.file, 'a', 0o600);
  }
  /** Line by line: a journal larger than the biggest string node can hold must still load (it holds the swap secrets). */
  static read(file: string): Record<string, any>[] {
    if (!fs.existsSync(file)) return [];
    const out: Record<string, any>[] = [];
    const push = (line: string) => {
      if (!line.trim()) return;
      try { out.push(JSON.parse(line)); } catch { /* torn last line after a crash: ignore */ }
    };
    const fd = fs.openSync(file, 'r'), buf = Buffer.alloc(1 << 20);
    const dec = new StringDecoder('utf8');
    let rest = '';
    try {
      for (let n = fs.readSync(fd, buf); n > 0; n = fs.readSync(fd, buf)) {
        const parts = (rest + dec.write(buf.subarray(0, n))).split('\n');
        rest = parts.pop() ?? '';
        for (const line of parts) push(line);
      }
      push(rest + dec.end());
    } finally { fs.closeSync(fd); }
    return out;
  }
}

// ---------------------------------------------------------------- monero-wallet-rpc
const WALLET_TIMEOUT_MS = 300_000;
export class WalletRpc {
  url: string;
  private chain: Promise<unknown> = Promise.resolve();
  constructor(url: string) { this.url = url; }
  async call<T = any>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    // A hung wallet-rpc must not hold the exclusive chain forever; the state machine retries the step.
    const r = await fetch(`${this.url}/json_rpc`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 0, method, params }), signal: AbortSignal.timeout(WALLET_TIMEOUT_MS) });
    const j = await r.json() as any;
    if (j.error) throw new Error(`wallet-rpc ${method}: ${j.error.message}`);
    return j.result as T;
  }
  /** Serialize multi-call sequences (one open wallet per wallet-rpc process). */
  exclusive<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.chain.then(fn, fn);
    this.chain = run.catch(() => {});
    return run;
  }
}

export async function daemonHeight(daemonUri: string): Promise<number> {
  const { daemon } = await import('../sdk/xmrverify.ts');
  return (await daemon(daemonUri, 'json_rpc', { jsonrpc: '2.0', id: 0, method: 'get_info' })).result.height;
}

// ---------------------------------------------------------------- solana
export async function chainNow(c: Connection, commitment: 'confirmed' | 'finalized' = 'confirmed'): Promise<number> {
  const a = await c.getAccountInfo(SYSVAR_CLOCK_PUBKEY, commitment);
  return Number(a!.data.readBigInt64LE(32));
}

// ---------------------------------------------------------------- priority fee
// Without a priority fee a transaction often does not land on a busy mainnet, and a claim that does
// not land before t1 is a loss. Off on test clusters (setPriority is called from the daemons).
export interface PriorityOpts { auto?: boolean; microLamports?: number; minMicroLamports?: number; maxMicroLamports?: number }
let priority: PriorityOpts | null = null;
let priorityConn: Connection | null = null;
let priorityCache: { price: number; at: number } | null = null;
export function setPriority(c: Connection, o: PriorityOpts = {}) { priorityConn = c; priority = o; priorityCache = null; }
/** p75 of recent fees, clamped; a failed read uses the floor rather than none at all. */
export function pickPriority(recent: number[], o: PriorityOpts): number {
  const min = o.minMicroLamports ?? 20_000, max = o.maxMicroLamports ?? 2_000_000;
  const xs = recent.filter((x) => x > 0).sort((a, b) => a - b);
  const p75 = xs.length ? xs[Math.floor(xs.length * 0.75)] : 0;
  return Math.max(min, Math.min(max, Math.ceil(p75 * 1.2)));
}
export async function priorityPrice(): Promise<number> {
  if (!priority) return 0;
  if (priority.auto === false) return priority.microLamports ?? 0;
  if (priorityCache && Date.now() - priorityCache.at < 20_000) return priorityCache.price;
  let price: number;
  try { price = pickPriority((await priorityConn!.getRecentPrioritizationFees()).map((f) => f.prioritizationFee), priority); }
  catch { price = pickPriority([], priority); }
  priorityCache = { price, at: Date.now() };
  return price;
}

const MAX_TX_BYTES = 1232;
export async function sendIxs(c: Connection, payer: Keypair, ixs: TransactionInstruction[], extra: Keypair[] = []) {
  const price = await priorityPrice();
  const { blockhash, lastValidBlockHeight } = await c.getLatestBlockhash('confirmed');
  const limitIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 });
  const priceIx = price ? [ComputeBudgetProgram.setComputeUnitPrice({ microLamports: price })] : [];
  // A payment proof can sit at the size limit: the budget instructions go first when it doesn't fit (a proof that
  // never lands means no claim). 200k CU is the default limit anyway.
  let tx: Transaction | null = null, wire: Buffer | null = null;
  for (const budget of [[limitIx, ...priceIx], priceIx.length ? [limitIx] : null, []]) {
    if (!budget) continue;
    const t = new Transaction().add(...budget, ...ixs);
    t.feePayer = payer.publicKey;
    t.recentBlockhash = blockhash;
    try {
      t.sign(payer, ...extra);
      const w = t.serialize();
      if (w.length <= MAX_TX_BYTES) { tx = t; wire = w; break; }
    } catch { /* too large: the next shape is smaller */ }
  }
  if (!tx || !wire) throw new Error('transaction too large');
  const sig = await c.sendRawTransaction(wire, { skipPreflight: false, preflightCommitment: 'confirmed' });
  await waitForTx(sig, lastValidBlockHeight, {
    status: async (x) => (await c.getSignatureStatuses([x], { searchTransactionHistory: true })).value[0],
    height: () => c.getBlockHeight('confirmed'),
  }, { timeoutMs: 120_000, intervalMs: 800 });
  return sig;
}

/**
 * A settled escrow can be closed in the same transaction as its refund, and the account is then gone:
 * the secret lives only in history. Scans newest first, a page at a time, from `cursor`, so a padded
 * history costs whoever padded it rather than stopping the search. Instructions run through another program
 * count too. `pick` returns a value for the instruction it wants.
 */
export async function scanEscrowHistory<T>(c: Connection, pid: PublicKey, escrow: PublicKey, pick: (data: Uint8Array) => T | null, cursor?: string, pageSize = 40, includeFailed = false): Promise<{ found: T | null; cursor?: string; done: boolean }> {
  // Anyone can put junk instructions in a transaction naming this escrow: one that makes `pick` throw must not end the search.
  const tryPick = (d: Uint8Array) => { try { return pick(d); } catch { return null; } };
  const sigs = await c.getSignaturesForAddress(escrow, { limit: pageSize, before: cursor }, 'confirmed');
  for (const s of sigs) {
    if (s.err && !includeFailed) continue;
    const t = await c.getTransaction(s.signature, { commitment: 'confirmed', maxSupportedTransactionVersion: 0 });
    if (!t) throw new Error(`transaction ${s.signature} not readable yet`); // a failed read is not "not there"
    const keys = t.transaction.message.getAccountKeys({ accountKeysFromLookups: t.meta?.loadedAddresses ?? undefined });
    const isUs = (i: number) => keys.get(i)?.equals(pid) ?? false;
    for (const ix of t.transaction.message.compiledInstructions) {
      if (!isUs(ix.programIdIndex)) continue;
      const got = tryPick(ix.data instanceof Uint8Array ? ix.data : bs58.decode(ix.data as unknown as string));
      if (got !== null) return { found: got, done: true };
    }
    for (const inner of t.meta?.innerInstructions ?? []) for (const ix of inner.instructions) {
      if (!isUs(ix.programIdIndex)) continue;
      const got = tryPick(bs58.decode(ix.data));
      if (got !== null) return { found: got, done: true };
    }
  }
  return { found: null, cursor: sigs.length ? sigs[sigs.length - 1].signature : cursor, done: sigs.length < pageSize };
}

/** Which instruction settled an escrow we hold half of: the refund that hands us the taker's half, or our own claim. */
export function pickSettlement(refundPoint: Uint8Array, mySpend: Uint8Array) {
  return (d: Uint8Array): { kind: 'refund' | 'claim'; secret: Uint8Array } | null => {
    if (d.length !== 33) return null;
    const x = d.slice(1);
    if (d[0] === IX.REFUND && K.isCanonical(x) && K.leToBig(x) !== 0n && K.equalBytes(K.pub(x), refundPoint)) return { kind: 'refund', secret: x };
    if (d[0] === IX.CLAIM && K.equalBytes(x, mySpend)) return { kind: 'claim', secret: x };
    return null;
  };
}

export function describeErr(e: unknown) {
  return errName(e);
}

export function loadKeypair(file: string) {
  return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(file, 'utf8'))));
}

export const log = (...a: unknown[]) => console.log(new Date().toISOString().slice(11, 19), ...a);

export { PublicKey };
