// Runtime config (/config.json), the Solana connection, and on-chain reads shared by every page.
import { waitForTx, TxExpired, TxTimeout } from '../../../sdk/confirm.ts';
import { Connection, PublicKey } from '@solana/web3.js';
import * as P from '../../../sdk/program.ts';
import * as T from '../../../sdk/taker.ts';
import type { MoneroNet } from '../../../sdk/keys.ts';
import * as D from '../../../sdk/discovery.ts';

export interface Cfg {
  cluster: string;
  features?: { zecRoute?: boolean; hypeRoute?: boolean; payLinks?: boolean; otc?: boolean; paymentProofs?: boolean };
  attesters?: string[];
  notifications?: { endpoint: string; vapidPublicKey: string; verifyRpcUrls: string[]; email?: boolean };
  rpcUrl: string;
  programId: string;
  moneroNet: MoneroNet;
  monerodUrl: string;
  /** Two or more independent monerod URLs for the cross-checked lock verification before 'Release now'. */
  monerodVerify?: string[];
  /** Daemon for the in-browser wallet (collect). Empty = this origin (the worker proxies monerod paths at the root). */
  walletDaemonUrl?: string;
  watchtowers: { url: string; pubkey: string }[];
  /** XMR->SOL refund towers, in order (tower n acks index n), and how many acks a deposit address needs. */
  refundTowers?: { minAcks: number; towers: { url: string; pubkey: string }[] };
  makers: { url: string }[] | string[];
  explorers: { solTx: string; solAccount: string; xmrTx: string; zecTx?: string };
  /** ZEC swaps (hash-locked): the transparent network, its JSON-RPC (zebrad, via the worker's /api/zebra by default). */
  zecNet?: 'mainnet' | 'testnet' | 'regtest';
  zecRpcUrl?: string;
  /** Test networks only: relax the ZEC policy (never applied on mainnet). */
  zecPolicy?: Record<string, number>;
  holderThresholdLabel?: string;
  tokenCa?: string;
  xHandle?: string;
  repoUrl?: string;
  policy?: Partial<T.Policy>;
  /** Launch from Monero: ENTER's launch flow, `{say}` = the prefilled prompt (url-encoded), `{wallet}` = the fresh wallet. */
  enterUrl?: string;
  enterSay?: string;
  /** Cashout: the HALFKEY keeper's key (default keeper for new vaults; empty = anyone may trigger). */
  keeper?: string;
  /** Cashout: default vault timelock in seconds (never below the program minimum). */
  vaultDelaySecs?: number;
  /** Static build (IPFS/Arweave): no worker routes; config.json sits next to the pages. */
  static?: boolean;
  /** Extra Solana RPCs tried in order when the first one fails. */
  rpcFallbacks?: string[];
  /** Maker authorities to read directly when the RPC refuses getProgramAccounts. */
  makerAuthorities?: string[];
  /** Jupiter API base (default https://api.jup.ag, keyless 0.5 req/s per visitor) and an optional key. */
  jupiterApi?: string;
  jupiterKey?: string;
}

/** User overrides (settings dialog or ?rpc= / ?monerod=), kept in this browser only. */
export const overrides = {
  get(k: 'rpc' | 'monerod'): string { try { return localStorage.getItem('hk:' + k) || ''; } catch { return ''; } },
  set(k: 'rpc' | 'monerod', v: string) { try { v ? localStorage.setItem('hk:' + k, v) : localStorage.removeItem('hk:' + k); } catch { /* storage blocked */ } },
};

export let cfg: Cfg;
export let conn: Connection;
export let pid: PublicKey;

export async function loadEnv() {
  // Relative to the bundle (assets/ sits next to config.json), not to the page: works at the worker
  // origin, on nested routes like /pay/<name>, and under an IPFS/Arweave path gateway alike.
  const r = await fetch(new URL('../config.json', import.meta.url), { cache: 'no-store' });
  cfg = await r.json();
  const qs = new URLSearchParams(location.search);
  for (const k of ['rpc', 'monerod'] as const) { const v = qs.get(k); if (v && /^https?:\/\//.test(v)) overrides.set(k, v); }
  if (overrides.get('rpc')) cfg.rpcUrl = overrides.get('rpc');
  if (overrides.get('monerod')) { cfg.monerodUrl = overrides.get('monerod'); cfg.walletDaemonUrl = overrides.get('monerod'); cfg.monerodVerify = [overrides.get('monerod'), ...(cfg.monerodVerify ?? []).filter((u) => /^https?:/.test(u))]; }
  // a rate-limited public RPC answers 429: fail fast to the empty state instead of retrying in a loop
  // '/api/solana' on the production worker (the paid RPC stays server-side), a full URL elsewhere
  conn = new Connection(new URL(cfg.rpcUrl, location.origin).href, { commitment: 'confirmed', disableRetryOnRateLimit: true });
  pid = new PublicKey(cfg.programId);
  return cfg;
}

export const isMainnet = () => cfg.cluster === 'mainnet-beta';

/** Wait for a sent transaction, by polling (sdk/confirm.ts). */
export async function confirmSent(sig: string, lastValidBlockHeight: number, timeoutMs = 180_000): Promise<void> {
  try {
    await waitForTx(sig, lastValidBlockHeight, {
      status: async (x) => (await conn.getSignatureStatuses([x], { searchTransactionHistory: true })).value[0],
      height: () => conn.getBlockHeight('confirmed'),
    }, { timeoutMs });
  } catch (e) {
    if (e instanceof TxExpired) throw new Error('This transaction did not land before it expired. Nothing was sent; try again.');
    if (e instanceof TxTimeout) throw new Error('This transaction is taking long to confirm. Check your wallet history before trying again.');
    throw e;
  }
}
/** Link to a page: '/makers' at the worker origin, 'makers.html' in the static build. */
export const pageHref = (p: '' | 'swaps' | 'makers' | 'stats' | 'docs' | 'otc' | 'pay' | 'cashout' | 'launch', hash = '') => (cfg?.static ? (p ? `${p}.html` : './') : `/${p}`) + hash;
export const netLabel = () => (isMainnet() ? 'Mainnet' : 'Testnet');

/** MAINNET_POLICY always; a test cluster may relax it from config (never on mainnet). */
export function policy(): T.Policy {
  if (isMainnet() || !cfg.policy) return T.MAINNET_POLICY;
  return { ...T.MAINNET_POLICY, ...cfg.policy };
}

const abs = (u: string) => new URL(u, location.origin).href.replace(/\/+$/, '');
/** Static build with no Monero node set: say so instead of calling a worker route that does not exist. */
const needNode = (u?: string) => { if (cfg.static && !(u && /^https?:\/\//.test(u))) throw new Error('No Monero node is set for this build. Add one under Network settings (an https node with CORS).'); return u; };
export const daemonUri = () => abs(needNode(cfg.static ? cfg.monerodUrl : undefined) || cfg.monerodUrl || '/api/monerod');
/** wallet2 drops URL paths, so the wallet daemon is an origin (ours by default). */
export const walletDaemon = () => abs(needNode(cfg.static ? cfg.walletDaemonUrl || cfg.monerodUrl : undefined) || cfg.walletDaemonUrl || location.origin);
/** Comma-separated independent nodes for verifyLockCrossChecked. */
export const verifyDaemons = () => { const xs = (cfg.monerodVerify ?? []).filter((u) => !cfg.static || /^https?:\/\//.test(u)); if (cfg.static && !xs.length) needNode(); return xs.map(abs).join(','); };
export const towers = () => (cfg.watchtowers || []).map((w) => ({ url: w.url, pubkey: new PublicKey(w.pubkey) }));
/** Watchtowers answering /v1/info with the pubkey config lists for them. */
export const towersOnline = () => cached('towers', 20_000, async () => {
  const r = await Promise.all(towers().map(async (t) => {
    try { const i = await withTimeout(T.watchtowerApi.info(t.url), 5000); return i.pubkey === t.pubkey.toBase58() ? t : null; } catch { return null; }
  }));
  return r.filter((x): x is { url: string; pubkey: PublicKey } => !!x);
});

export const explorer = {
  solTx: (sig: string) => cfg.explorers.solTx.replace('{sig}', sig),
  solAcct: (a: string) => cfg.explorers.solAccount.replace('{address}', a),
  xmrTx: (h: string) => cfg.explorers.xmrTx.replace('{hash}', h),
  zecTx: (h: string) => (cfg.explorers.zecTx || '').replace('{txid}', h),
};

/** The ZEC JSON-RPC endpoint (worker proxy by default; a static build needs an https node with CORS). */
export const zecRpcUri = () => {
  const u = cfg.zecRpcUrl || (cfg.static ? '' : '/api/zebra');
  if (!u || (cfg.static && !/^https?:\/\//.test(u))) throw new Error('No ZEC node is set for this build.');
  return abs(u);
};

// ---------------------------------------------------------------- small TTL cache
const memo = new Map<string, { at: number; p: Promise<any> }>();
function cached<T>(key: string, ttlMs: number, fn: () => Promise<T>): Promise<T> {
  const hit = memo.get(key);
  if (hit && Date.now() - hit.at < ttlMs) return hit.p;
  const p = fn();
  memo.set(key, { at: Date.now(), p });
  p.catch(() => memo.delete(key));
  return p;
}
export const bust = (key?: string) => (key ? memo.delete(key) : memo.clear());

// ---------------------------------------------------------------- chain reads
/** Is the program deployed on this network? true/false only from an answered read (a failed read throws, never "absent"). */
export const programLive = () => cached('program', 60_000, async () => !!(await conn.getAccountInfo(pid)));
/** Lists before launch: an answered "no program here" means nothing to list; any other failure still throws. */
async function ifLive<T>(fn: () => Promise<T[]>): Promise<T[]> { return (await programLive()) ? fn() : []; }

export const chainConfig = () => cached('config', 15_000, async () => {
  const a = await conn.getAccountInfo(P.pda.config(pid));
  if (!a || !a.owner.equals(pid)) return null;
  try { return P.decodeConfig(a.data); } catch { return null; }
});

export const feeVaultLamports = () => cached('vault', 15_000, async () => {
  try { return BigInt(await conn.getBalance(P.pda.feeVault(pid))); } catch { return 0n; }
});

/** The registry, read straight from chain (no HALFKEY server). Falls back to the RPCs and maker list in config. */
export const listMakers = () => cached('makers', 20_000, () => ifLive(async () => {
  const known = (cfg.makerAuthorities ?? []).map((a) => new PublicKey(a));
  let last: unknown;
  for (const c of [conn, ...(cfg.rpcFallbacks ?? []).map((u) => new Connection(u, 'confirmed'))]) {
    try {
      const { makers } = await D.fetchMakers(c, pid, known);
      return makers.sort((a, b) => Number(b.completed - a.completed) || Number(b.bond - a.bond));
    } catch (e) { last = e; }
  }
  throw last;
}));

/** The endpoint that last answered for this maker, else its primary published endpoint. */
const resolvedEp = new Map<string, string>();
export const makerUrl = (m: P.MakerAccount) => resolvedEp.get(m.authority.toBase58()) ?? D.primaryEndpoint(m.endpoint);
export const postedRate = (m: P.MakerAccount) => { const f = D.parseEndpointField(m.endpoint); return f.px ? { px: f.px, ts: f.ts } : null; };

export const listEscrows = () => cached('escrows', 15_000, () => ifLive(async () => {
  const xs = await conn.getProgramAccounts(pid, { filters: [{ dataSize: P.ESCROW_LEN }] });
  const out: P.EscrowAccount[] = [];
  for (const x of xs) { try { out.push(P.decodeEscrow(x.account.data, x.pubkey)); } catch { /* skip */ } }
  return out.sort((a, b) => Number(b.createdAt - a.createdAt));
}));

/** ZEC swaps (the hash-locked kind): their own accounts, newest first. */
export const listHtlcs = () => cached('htlcs', 15_000, () => ifLive(async () => {
  const H = await import('../../../sdk/htlc.ts');
  const xs = await conn.getProgramAccounts(pid, { filters: [{ dataSize: H.HTLC_LEN }] });
  const out: import('../../../sdk/htlc.ts').HtlcAccount[] = [];
  for (const x of xs) { try { out.push(H.decodeHtlc(x.account.data, x.pubkey)); } catch { /* skip */ } }
  return out.sort((a, b) => Number(b.createdAt - a.createdAt));
}));

export async function getEscrow(addr: PublicKey, commitment: 'confirmed' | 'finalized' = 'confirmed') {
  const a = await conn.getAccountInfo(addr, commitment);
  if (!a || !a.owner.equals(pid)) return null;
  return P.decodeEscrow(a.data, addr);
}

export async function makerByAuthority(auth: PublicKey) {
  return cached('maker:' + auth.toBase58(), 30_000, async () => {
    const a = await conn.getAccountInfo(P.pda.maker(pid, auth));
    return a ? P.decodeMaker(a.data, P.pda.maker(pid, auth)) : null;
  });
}

/** Cluster clock (unix seconds) from the Clock sysvar. */
export async function chainNow(): Promise<number> {
  return cached('clock', 4_000, async () => {
    const a = await conn.getAccountInfo(new PublicKey('SysvarC1ock11111111111111111111111111111111'), 'confirmed');
    return a ? Number(a.data.readBigInt64LE(32)) : Math.floor(Date.now() / 1000);
  });
}

const liveInfo = new Map<string, unknown>();
/**
 * The spread a maker quotes right now for one direction (1 = SOL->XMR, 2 = XMR->SOL): its live
 * `spreadNow` from /v1/info after inventory balancing; null = that direction is paused; the
 * registered spread when the maker doesn't publish spreadNow (older makers) or hasn't answered.
 */
export function spreadFor(m: P.MakerAccount, dir: 1 | 2): number | null {
  const i = liveInfo.get(m.authority.toBase58()) as { spreadNow?: Record<string, number | null> } | undefined;
  const v = i?.spreadNow?.[String(dir)];
  if (v === null) return null;
  return typeof v === 'number' && Number.isFinite(v) ? v : m.spreadBps;
}

/** The maker's own word on its price feed (/v1/info `priceLive`): false = no live price, it refuses quotes. Undefined = unknown or an older maker. */
export function makerPriceLive(m: P.MakerAccount): boolean | undefined {
  const v = (liveInfo.get(m.authority.toBase58()) as { priceLive?: unknown } | undefined)?.priceLive;
  return typeof v === 'boolean' ? v : undefined;
}
/** The maker's indicative XMR per SOL from its last /v1/info, if it answered. */
export function makerXmrPerSol(m: P.MakerAccount): number | null {
  const v = (liveInfo.get(m.authority.toBase58()) as { xmrPerSol?: unknown } | undefined)?.xmrPerSol;
  return typeof v === 'number' && v > 0 && Number.isFinite(v) ? v : null;
}

/** Maker online = active in the registry AND answering /v1/info for this program and cluster. */
export function probeMaker(m: P.MakerAccount) {
  return cached('probe:' + m.authority.toBase58(), 30_000, async () => {
    if (!m.active || !m.endpoint) return null;
    // Every endpoint the maker published, in order; the first that answers for this program and
    // this maker identity wins. The browser talks to the maker directly (makers send CORS *).
    const r = await D.probeEndpoints(m, pid, { timeoutMs: 5000 });
    if (!r || !r.info.online) return null;
    resolvedEp.set(m.authority.toBase58(), r.endpoint);
    liveInfo.set(m.authority.toBase58(), r.info);
    return r.info;
  });
}

export function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise((res, rej) => {
    const t = setTimeout(() => rej(new Error('timed out')), ms);
    p.then((v) => { clearTimeout(t); res(v); }, (e) => { clearTimeout(t); rej(e); });
  });
}

// ---------------------------------------------------------------- market (worker: prices + Monero tip)
export interface Market { sol: number | null; xmr: number | null; zec?: number | null; xmrPerSol: number | null; tip: { height: number; lastBlockAt: number } | null }
export const market = () => cached<Market>('market', 20_000, async () => {
  if (!cfg.static) {
    try { const r = await fetch('/api/market', { cache: 'no-store' }); if (r.ok) return await r.json(); } catch { /* static fallback below */ }
  }
  return directMarket();
});

/** No worker: prices from a CORS-enabled public API, the Monero tip from the configured monerod. */
async function directMarket(): Promise<Market> {
  const [p, tip] = await Promise.all([
    fetch('https://api.coingecko.com/api/v3/simple/price?ids=solana,monero,zcash&vs_currencies=usd', { signal: AbortSignal.timeout(6000) })
      .then((r) => r.json()).then((d) => ({ sol: d?.solana?.usd ?? null, xmr: d?.monero?.usd ?? null, zec: d?.zcash?.usd ?? null })).catch(() => ({ sol: null, xmr: null, zec: null })),
    fetch(`${daemonUri()}/json_rpc`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: '0', method: 'get_last_block_header' }), signal: AbortSignal.timeout(8000) })
      .then((r) => r.json()).then((d) => { const h = d?.result?.block_header; return h ? { height: h.height + 1, lastBlockAt: h.timestamp } : null; }).catch(() => null),
  ]);
  return { ...p, xmrPerSol: p.sol && p.xmr ? p.sol / p.xmr : null, tip };
}

/** Completion rate as the makers page defines it; null when the maker has no settled swaps yet. */
export function completion(m: P.MakerAccount): number | null {
  const den = m.completed + m.aborted + m.declined + m.expired;
  return den === 0n ? null : Number(m.completed) / Number(den);
}

/** The Monero sweep module (code-split), with its wallet worker loaded from the site root. */
export async function loadCollect() {
  const m = await import('../../../sdk/collect.ts');
  m.setMoneroWorkerUrl(new URL('../monero.worker.js', import.meta.url).href);
  return m;
}
