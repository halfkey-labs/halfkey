// Collect: sweep the shared 2-of-2 output to the user's own Monero address, in-process
// (browser WASM or Node) with monero-ts (MIT). The full spend key never leaves this process.
import * as K from './keys.ts';

export interface CollectArgs {
  spendKey: Uint8Array;           // s = s_maker + s_user (fullSpendKey)
  viewKey: Uint8Array;            // user-derived shared view key
  net: K.MoneroNet;
  daemonUri: string;              // monerod RPC (our proxy or a public node)
  restoreHeight: number;
  destination: string;            // user's Monero address
  expectPiconero?: bigint;        // sanity: the swap amount
  onProgress?: (msg: string, pct?: number) => void;
  /** Optional wallet cache from an earlier view-only prewarm (skips the hash-chain download). */
  cacheData?: Uint8Array;
}

export interface CollectResult { txHashes: string[]; sweptPiconero: bigint; feePiconero: bigint; address: string }

let mtsPromise: Promise<any> | null = null;
let workerUrl: string | undefined;
/** Browser: where monero.worker.js is served (the site root; set by the web client). */
export function setMoneroWorkerUrl(url: string) { workerUrl = url; }
export function loadMoneroTs(): Promise<any> {
  mtsPromise ??= import('monero-ts').then((m: any) => {
    const mts = m.default ?? m;
    // Load the wallet worker from the site root (works on nested routes like /pay/<name> and under
    // an IPFS/Arweave path gateway too).
    if (typeof document !== 'undefined') mts.LibraryUtils?.setWorkerDistPath?.(workerUrl ?? new URL('monero.worker.js', document.baseURI).href);
    return mts;
  });
  return mtsPromise;
}

const NET: Record<K.MoneroNet, number> = { mainnet: 0, testnet: 1, stagenet: 2 };

export async function sharedWalletInfo(spendKey: Uint8Array, viewKey: Uint8Array, net: K.MoneroNet) {
  return { address: K.moneroAddress(K.pub(spendKey), K.pub(viewKey), net) };
}

/** Sweep everything unlocked in the shared wallet to `destination`. */
export async function collect(a: CollectArgs): Promise<CollectResult> {
  K.parseMoneroAddress(a.destination, a.net); // throws on a wrong-network or malformed address
  const mts = await loadMoneroTs();
  const address = K.moneroAddress(K.pub(a.spendKey), K.pub(a.viewKey), a.net);
  const p = a.onProgress ?? (() => {});
  p('Opening the shared wallet');
  const wallet = await mts.createWalletFull({
    networkType: NET[a.net],
    primaryAddress: address,
    privateViewKey: K.toHex(a.viewKey),
    privateSpendKey: K.toHex(a.spendKey),
    restoreHeight: a.restoreHeight,
    server: { uri: a.daemonUri },
    proxyToWorker: typeof window !== 'undefined',
  });
  try {
    let lastPct = -1;
    await wallet.sync(new (class extends mts.MoneroWalletListener {
      async onSyncProgress(_h: number, _s: number, _e: number, pct: number) {
        const v = Math.floor(pct * 100);
        if (v !== lastPct) { lastPct = v; p('Scanning Monero blocks', pct); }
      }
    })());
    const unlocked = BigInt((await wallet.getUnlockedBalance()).toString());
    const total = BigInt((await wallet.getBalance()).toString());
    if (unlocked === 0n) {
      throw new Error(total > 0n ? 'XMR found but not yet spendable (needs 10 confirmations). Try again in a few minutes.' : 'No XMR found in the shared wallet yet.');
    }
    if (a.expectPiconero !== undefined && unlocked < a.expectPiconero) {
      p(`Note: found ${K.fmtXmr(unlocked)} XMR, expected ${K.fmtXmr(a.expectPiconero)}`);
    }
    p('Building the sweep transaction');
    const txs = await wallet.sweepUnlocked({ address: a.destination, relay: true });
    let fee = 0n, swept = 0n;
    const hashes: string[] = [];
    for (const tx of txs) {
      hashes.push(tx.getHash());
      fee += BigInt(tx.getFee().toString());
      const amt = tx.getOutgoingAmount?.();
      if (amt !== undefined) swept += BigInt(amt.toString());
    }
    p('Sent');
    return { txHashes: hashes, sweptPiconero: swept, feePiconero: fee, address };
  } finally {
    await wallet.close(false);
  }
}

/** Keys for "open in Cake / Feather": restore-from-keys fields. */
export function exportKeys(spendKey: Uint8Array, viewKey: Uint8Array, net: K.MoneroNet, restoreHeight: number) {
  return {
    address: K.moneroAddress(K.pub(spendKey), K.pub(viewKey), net),
    spendKey: K.toHex(spendKey),
    viewKey: K.toHex(viewKey),
    restoreHeight,
  };
}
