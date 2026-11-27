// Waiting for a sent Solana transaction, by polling. One rule for the browser and the daemons: only a read that
// worked and came back empty says anything, and a send is gone only after several of those past its
// blockhash's life. Polling, not a websocket: the site's RPC route has none, and one missed notification
// must never read as failed.
export interface ConfirmDeps {
  status(sig: string): Promise<{ err: unknown; confirmationStatus?: string | null } | null>;
  height(): Promise<number>;
  sleep?(ms: number): Promise<void>;
  now?(): number;
}
export class TxFailed extends Error { constructor(sig: string, err: unknown) { super(`transaction ${sig} failed: ${JSON.stringify(err)}`); } }
export class TxExpired extends Error {}
export class TxTimeout extends Error {}

export async function waitForTx(sig: string, lastValidBlockHeight: number, d: ConfirmDeps, o: { timeoutMs?: number; intervalMs?: number; goneReads?: number } = {}): Promise<void> {
  const clock = d.now ?? Date.now, sleep = d.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
  const until = clock() + (o.timeoutMs ?? 180_000);
  let gone = 0;
  for (;;) {
    let st: Awaited<ReturnType<ConfirmDeps['status']>> = null, readOk = true;
    try { st = await d.status(sig); } catch { readOk = false; }
    if (st?.err) throw new TxFailed(sig, st.err);
    if (st && (st.confirmationStatus === 'confirmed' || st.confirmationStatus === 'finalized')) return;
    if (readOk && !st) {
      const h = await d.height().catch(() => 0);
      if (h > lastValidBlockHeight + 10) gone++; else if (h > 0) gone = 0;
      if (gone >= (o.goneReads ?? 5)) throw new TxExpired(`transaction ${sig} did not land before it expired`);
    }
    if (clock() > until) throw new TxTimeout(`transaction ${sig} is taking long to confirm`);
    await sleep(o.intervalMs ?? 1500);
  }
}
