// View-key verification of a Monero transaction output, with no wallet and no sync.
// Given a tx hash (a hint from the maker; untrusted), the shared spend pub and the shared view
// secret, find the output paying the shared address, decode its amount, and PROVE the amount
// against the on-chain Pedersen commitment (a maker cannot fake ecdhInfo). Also checks
// unlock_time and confirmations. Used by watchtowers and by the user's browser before `ready`.
import { ed25519 } from '@noble/curves/ed25519';
import { keccak_256 } from '@noble/hashes/sha3';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils';
import * as K from './keys.ts';

const Point = ed25519.ExtendedPoint;
// Monero's second generator H (rctTypes.h), compressed.
const H = Point.fromHex('8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94');

const hs = (b: Uint8Array) => K.leToBig(keccak_256(b)) % K.L;

function varint(n: number): Uint8Array {
  const out: number[] = [];
  while (n >= 0x80) { out.push((n & 0x7f) | 0x80); n >>>= 7; }
  out.push(n);
  return Uint8Array.from(out);
}

/** Tx public keys from tx_extra: main (tag 0x01) and additional (tag 0x04). */
export function txPubKeys(extra: number[]): { main: Uint8Array[]; additional: Uint8Array[] } {
  const main: Uint8Array[] = [], additional: Uint8Array[] = [];
  let i = 0;
  while (i < extra.length) {
    const tag = extra[i++];
    if (tag === 0x01) { main.push(Uint8Array.from(extra.slice(i, i + 32))); i += 32; }
    else if (tag === 0x04) {
      let n = 0, shift = 0, b: number;
      do { b = extra[i++]; n |= (b & 0x7f) << shift; shift += 7; } while (b & 0x80);
      for (let k = 0; k < n; k++) { additional.push(Uint8Array.from(extra.slice(i, i + 32))); i += 32; }
    } else if (tag === 0x02) { const len = extra[i++]; i += len; } // nonce
    else if (tag === 0x00) { while (i < extra.length && extra[i] === 0) i++; } // padding
    else break; // unknown field: stop parsing (keys found so far are still valid)
  }
  return { main, additional };
}

export interface OwnedOutput { index: number; amount: bigint; outKey: string }

/** Scan one decoded tx (daemon `as_json`) for outputs to (spendPub, viewSecret). */
export function scanTx(tx: any, spendPub: Uint8Array, viewSecret: Uint8Array): OwnedOutput[] {
  const v = K.leToBig(viewSecret);
  const B = Point.fromHex(spendPub);
  const { main, additional } = txPubKeys(tx.extra);
  const found: OwnedOutput[] = [];
  const vout = tx.vout as any[];
  for (let i = 0; i < vout.length; i++) {
    const tgt = vout[i].target;
    const outKey: string = tgt.tagged_key?.key ?? tgt.key;
    if (!outKey) continue;
    const seen = new Set<string>();
    const cands = [...main, ...(additional[i] ? [additional[i]] : [])].filter((R) => { const h = K.toHex(R); if (seen.has(h)) return false; seen.add(h); return true; });
    for (const R of cands) {
      let D;
      try { D = Point.fromHex(R).multiply(v).multiply(8n); } catch { continue; }
      const Db = D.toRawBytes();
      const s = hs(concatBytes(Db, varint(i)));
      const P = Point.BASE.multiply(s === 0n ? K.L : s).add(B);
      if (K.toHex(P.toRawBytes()) !== outKey) continue;
      // amount: ecdh xor keccak("amount" || s)
      const sb = K.bigToLe32(s);
      const mask = keccak_256(concatBytes(utf8ToBytes('amount'), sb));
      const enc = K.fromHex(tx.rct_signatures.ecdhInfo[i].amount);
      const a = new Uint8Array(8);
      for (let k = 0; k < 8; k++) a[k] = enc[k] ^ mask[k];
      const amount = K.leToBig(a);
      // commitment: C = y*G + a*H with y = Hs("commitment_mask" || s)
      const y = hs(concatBytes(utf8ToBytes('commitment_mask'), sb));
      let C = Point.BASE.multiply(y === 0n ? K.L : y);
      if (amount > 0n) C = C.add(H.multiply(amount));
      if (K.toHex(C.toRawBytes()) !== tx.rct_signatures.outPk[i]) continue; // forged amount
      found.push({ index: i, amount, outKey });
      break; // each output counts once, whatever tx_extra repeats
    }
  }
  return found;
}

export interface LockCheck {
  ok: boolean;
  reason?: string;
  amount?: bigint;
  confirmations?: number;
  unlockTime?: number;
  inPool?: boolean;
  height?: number;
}

/**
 * monerod RPC with failover. `uris` may be a comma-separated list; nodes are tried in order and
 * the last one that answered is preferred next time. A single dead public node must never make
 * a watchtower abort an honest swap.
 */
const preferred = new Map<string, string>();
export async function daemon(uris: string, path: string, body: unknown): Promise<any> {
  const list = uris.split(',').map((x) => x.trim().replace(/\/+$/, '')).filter(Boolean);
  const first = preferred.get(uris);
  const order = first ? [first, ...list.filter((x) => x !== first)] : list;
  let last: unknown;
  for (const u of order) {
    try {
      const r = await fetch(`${u}/${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(15_000) });
      if (!r.ok) throw new Error(`monerod ${path} ${r.status}`);
      const j = await r.json();
      preferred.set(uris, u);
      return j;
    } catch (e) { last = e; }
  }
  throw new Error(`all monerod nodes failed (${path}): ${String((last as Error)?.message ?? last)}`);
}

/** First node in the list that answers get_info (for monero-ts / wallet-rpc, which take one URI). */
export async function pickDaemon(uris: string): Promise<string> {
  await daemon(uris, 'json_rpc', { jsonrpc: '2.0', id: 0, method: 'get_info' });
  return preferred.get(uris)!;
}

/**
 * The same check against two independent nodes; both must agree (a single lying monerod can
 * serve a fabricated tx with valid commitments). Used before the user signs `ready`.
 */
export async function verifyLockCrossChecked(a: Parameters<typeof verifyLock>[0]): Promise<LockCheck> {
  const list = a.daemonUri.split(',').map((x) => x.trim()).filter(Boolean);
  if (list.length < 2) return { ok: false, reason: 'need two independent monerod nodes to release early' };
  const results: LockCheck[] = [];
  for (const u of list) {
    try { results.push(await verifyLock({ ...a, daemonUri: u })); } catch { continue; }
    if (results.length === 2) break;
  }
  if (results.length < 2) return { ok: false, reason: 'fewer than two nodes reachable' };
  const [x, y] = results;
  if (x.ok && y.ok && x.height === y.height && x.amount === y.amount) return { ...x, confirmations: Math.min(x.confirmations!, y.confirmations!) };
  return { ok: false, reason: `nodes disagree or not ready: ${x.reason ?? 'ok'} / ${y.reason ?? 'ok'}` };
}

/** Verify that `txHash` pays >= minAmount to the shared address, spendable, with >= minConf. */
export async function verifyLock(a: {
  daemonUri: string; txHash: string; spendPub: Uint8Array; viewSecret: Uint8Array; minAmount: bigint; minConf: number;
}): Promise<LockCheck> {
  if (!/^[0-9a-f]{64}$/.test(a.txHash)) return { ok: false, reason: 'bad tx hash' };
  const res = await daemon(a.daemonUri, 'get_transactions', { txs_hashes: [a.txHash], decode_as_json: true });
  const t = res.txs?.[0];
  if (!t) return { ok: false, reason: 'tx not found' };
  const tx = JSON.parse(t.as_json);
  const outs = scanTx(tx, a.spendPub, a.viewSecret);
  if (!outs.length) return { ok: false, reason: 'tx does not pay the shared address' };
  const amount = outs.reduce((s, o) => s + o.amount, 0n);
  const unlockTime = Number(tx.unlock_time ?? 0);
  if (unlockTime !== 0) return { ok: false, reason: 'time-locked output (unlock_time != 0)', amount, unlockTime };
  if (amount < a.minAmount) return { ok: false, reason: `amount ${amount} < ${a.minAmount}`, amount };
  const inPool = !!t.in_pool;
  let confirmations = 0;
  if (!inPool) {
    const info = await daemon(a.daemonUri, 'json_rpc', { jsonrpc: '2.0', id: 0, method: 'get_info' });
    confirmations = Math.max(0, info.result.height - t.block_height);
  }
  const ok = confirmations >= a.minConf;
  return { ok, reason: ok ? undefined : `confirmations ${confirmations}/${a.minConf}`, amount, confirmations, unlockTime, inPool, height: t.block_height };
}
