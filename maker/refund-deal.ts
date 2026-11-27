// XMR->SOL: right after the SOL lock lands, deal the swap's key half 2-of-3 to the refund towers
// (sdk/refundtowers.ts) and collect their acks. The page shows a deposit address only with enough acks,
// so a swap the towers can't cover never takes a deposit; the daemon aborts it instead.
import { Keypair, PublicKey } from '@solana/web3.js';
import * as K from '../sdk/keys.ts';
import * as P from '../sdk/program.ts';
import * as R from '../sdk/refundtowers.ts';

export interface TowerRef { url: string; pubkey: string }
export interface RefundTowersConfig { towers: TowerRef[]; minAcks: number }

export async function postJson(url: string, body: unknown, ms = 8000): Promise<any> {
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(ms) });
  const t = await r.text();
  if (!r.ok) throw new Error(`${r.status} ${t.slice(0, 120)}`);
  return JSON.parse(t);
}

export async function dealToTowers(a: {
  pid: PublicKey; escrow: PublicKey; e: P.EscrowAccount; makerSpend: Uint8Array; maker: Keypair; towers: TowerRef[]; minAcks: number;
  post?: (url: string, body: R.DealReq) => Promise<any>;
  /** Waits between tries (a tower's provider may not have seen the lock yet). Default 0, 1.5 s, 4 s. */
  backoffMs?: number[];
}): Promise<{ c1: string; acks: R.Ack[] }> {
  if (a.towers.length !== R.N_TOWERS) throw new Error('refund towers: list exactly three');
  if (!K.equalBytes(K.pub(a.makerSpend), a.e.refundPoint)) throw new Error('our half does not match the escrow\'s refund point');
  const post = a.post ?? ((u, b) => postJson(u, b));
  const d = R.deal(a.makerSpend);
  const t = R.termsOf(a.pid, a.escrow, a.e, d.c.c1);
  const listed = a.towers.map((x) => ({ pubkey: new PublicKey(x.pubkey) }));
  const answers = await Promise.all(a.towers.map(async (tw, n) => {
    const req = R.signDeal(t, d.shares[n], listed[n].pubkey, a.maker.secretKey.slice(0, 32));
    for (const wait of a.backoffMs ?? [0, 1500, 4000]) {
      if (wait) await new Promise((r) => setTimeout(r, wait));
      try { return (await post(`${tw.url.replace(/\/+$/, '')}/deal`, req)) as R.Ack; } catch { /* next try */ }
    }
    return null;
  }));
  // Keep only acks that verify on their own and are on our polynomial; the page applies the same count (checkAcks).
  const c1hex = K.toHex(d.c.c1);
  const acks = answers.filter((x): x is R.Ack => !!x && x.c1 === c1hex && R.verifyAck(x, listed, a.pid, a.escrow, a.e));
  const all = R.checkAcks(acks, listed, a.pid, a.escrow, a.e, a.minAcks);
  if (!all.ok) throw new Error(`refund towers: ${acks.length} of ${a.minAcks} acked`);
  return { c1: K.toHex(d.c.c1), acks };
}
