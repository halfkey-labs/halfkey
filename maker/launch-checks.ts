// What a mainnet maker must have before it may start. Loud, and it stops the daemon: a missing
// setting on mainnet is a money problem, not a warning. Test clusters are unaffected.
import fs from 'node:fs';
import { LIST_FILE, loadList } from './sanctions.ts';
import { MAINNET_POLICY } from '../sdk/zecswap.ts';
import { minXmrToSolT0 } from '../sdk/taker.ts';

export interface CheckableConfig {
  cluster: string; moneroNet: string; livePrice: boolean; minConf: number; endpoint: string;
  trustProxy?: boolean; attesters?: string[]; sanctionsFile?: string; pythApiKeyFile?: string; claimMarginSecs?: number; t0Secs?: number; windowSecs?: number; depositMarginSecs?: number; depositWindowSecs?: number; x2sLimits?: object;
  programId: string; bind?: string; refill?: { enabled?: boolean; apiKeyFile?: string };
  claimMode?: 'ready-only' | 'payment-proof';
  zec?: ZecCheck;
  x2sT0Secs?: number; x2sWindowSecs?: number;
  refundTowers?: { minAcks: number; towers: { url: string; pubkey: string }[] };
}
export interface ZecCheck { zecNet: string; zebraRpc: string; zebraAuth?: string; seedFile: string; minConf: number; marginSecs: number; claimMarginSecs: number; speed?: number; livePrice?: boolean; pythApiKeyFile?: string; sanctionsFile?: string }
export interface CheckableZec { cluster?: string; programId: string; bind?: string; trustProxy?: boolean; sanctionsFile?: string; pythApiKeyFile?: string; zec: ZecCheck }

function sanctionsErrors(file?: string): string[] {
  try {
    const list = loadList(file ?? LIST_FILE);
    if (!list.addresses.SOL?.length) return ['sanctions list has no SOL addresses'];
    const age = (Date.now() - Date.parse(list.date)) / 86_400_000;
    return age <= 30 ? [] : [`sanctions list is ${age.toFixed(0)} days old: run node maker/sanctions.ts --refresh`];
  } catch (e) { return [`sanctions list: ${(e as Error).message}`]; }
}

/** The ZEC desk, alone (maker/zec-daemon.ts) or inside the full daemon. The desk locks real ZEC on request, so the same stop applies. */
export function checkZecDesk(cfg: CheckableZec): string[] {
  const z = cfg.zec, errs: string[] = [];
  const main = cfg.cluster === 'mainnet-beta', real = z.zecNet === 'mainnet';
  if (main !== real) errs.push(`cluster ${cfg.cluster} with ZEC ${z.zecNet}: both real or both test`);
  if (!real) return errs;
  if (z.livePrice === false) errs.push('zec.livePrice must not be false on mainnet: the fixed zatPerSol is for test networks');
  const p = MAINNET_POLICY;
  if (z.minConf < p.minConf) errs.push(`zec.minConf ${z.minConf} is below ${p.minConf}: takers refuse the lock`);
  if (z.marginSecs < p.marginSecs) errs.push(`zec.marginSecs ${z.marginSecs} is below ${p.marginSecs}: takers refuse the refund height`);
  if (z.claimMarginSecs < p.claimMarginSecs) errs.push(`zec.claimMarginSecs ${z.claimMarginSecs} is below ${p.claimMarginSecs}`);
  if ((z.speed ?? 0.75) > p.speed) errs.push(`zec.speed ${z.speed} is above ${p.speed}: refund heights would come too soon`);
  const local = /^http:\/\/(127\.0\.0\.1|localhost|\[::1\])(:|\/|$)/.test(z.zebraRpc);
  if (!local && !/^https:\/\//.test(z.zebraRpc)) errs.push(`zec.zebraRpc ${z.zebraRpc.replace(/\/\/[^@/]*@/, '//')} must be https unless it is on this machine`);
  if (!local && !z.zebraAuth) errs.push('zec.zebraAuth is empty for a remote node');
  try {
    if (fs.statSync(z.seedFile).mode & 0o077) errs.push(`zec.seedFile ${z.seedFile} is readable by other users: chmod 600`);
  } catch { errs.push(`zec.seedFile ${z.seedFile} is missing`); }
  if (!cfg.trustProxy && (cfg.bind ?? '127.0.0.1') === '127.0.0.1') errs.push('trustProxy must be true when the ZEC desk sits behind a local tunnel or proxy');
  if (/[<>]/.test(cfg.programId)) errs.push('programId is still the placeholder');
  errs.push(...sanctionsErrors(z.sanctionsFile ?? cfg.sanctionsFile));
  const key = z.pythApiKeyFile ?? cfg.pythApiKeyFile;
  if (key && !fs.existsSync(key)) errs.push(`pythApiKeyFile ${key} is missing`);
  return errs;
}

export function checkMainnet(cfg: CheckableConfig): string[] {
  const errs: string[] = cfg.zec ? checkZecDesk({ ...cfg, zec: cfg.zec }) : [];
  const main = cfg.cluster === 'mainnet-beta';
  if (main !== (cfg.moneroNet === 'mainnet')) errs.push(`cluster ${cfg.cluster} with Monero ${cfg.moneroNet}: both real or both test`);
  if (!main) return errs;
  if (!cfg.livePrice) errs.push('livePrice must be true on mainnet: the fixed fallback rate is for test clusters');
  if (cfg.minConf < 10) errs.push(`minConf ${cfg.minConf} is below 10`);
  // Otherwise every XMR->SOL request is refused at the handshake (after the quote has already succeeded).
  const margin = Number(cfg.depositMarginSecs ?? 900);
  const x2sT0 = Number(cfg.x2sT0Secs ?? cfg.t0Secs), x2sWin = Number(cfg.x2sWindowSecs ?? cfg.windowSecs);
  const minT0 = minXmrToSolT0({ depositMarginSecs: margin, depositWindowSecs: Number(cfg.depositWindowSecs ?? 900) });
  if (x2sT0 < minT0) errs.push(`x2sT0Secs ${x2sT0} is too short for XMR->SOL with depositMarginSecs ${margin}: at least ${minT0}`);
  // The user's XMR can wait until t1 before it comes back: keep that bounded (pages refuse more than 12 h).
  if (x2sT0 + x2sWin > 12 * 3600) errs.push(`x2sT0Secs + x2sWindowSecs ${x2sT0 + x2sWin} is above 12 h: pages refuse the swap`);
  if (!(x2sWin > Number(cfg.claimMarginSecs ?? 0) + 900)) errs.push(`x2sWindowSecs ${x2sWin} leaves the user under 15 minutes to claim after the margin`);
  // XMR->SOL is ready-only: without refund towers a paying user whose maker went dark could not get its XMR back.
  const rt = cfg.refundTowers;
  if (!rt) errs.push('refundTowers is not set: XMR->SOL needs three refund towers');
  else {
    if (rt.towers?.length !== 3) errs.push('refundTowers: list exactly three towers');
    if (!(rt.minAcks >= 2 && rt.minAcks <= 3)) errs.push(`refundTowers.minAcks ${rt.minAcks} must be 2 or 3`);
    if (new Set((rt.towers ?? []).map((t) => t.pubkey)).size !== (rt.towers ?? []).length) errs.push('refundTowers: the three towers must be distinct keys');
    for (const t of rt.towers ?? []) if (!/^https:\/\//.test(t.url) || /[<>]/.test(t.url + t.pubkey)) errs.push(`refundTowers: ${t.url} must be a real https URL with a real key`);
  }
  // A late claim that fails leaks the secret: this margin must be there, and real.
  if (!(Number(cfg.claimMarginSecs) >= 300)) errs.push(`claimMarginSecs ${cfg.claimMarginSecs} must be at least 300`);
  if (!(Number(cfg.t0Secs) > 0) || !(Number(cfg.windowSecs) > Number(cfg.claimMarginSecs))) errs.push('t0Secs and windowSecs must be set, with windowSecs above claimMarginSecs');
  if (!/^https:\/\//.test(cfg.endpoint) || /example|localhost|127\.0\.0\.1/.test(cfg.endpoint)) errs.push(`endpoint ${cfg.endpoint} is not a public https URL`);
  // Behind a tunnel every client shares one address unless the proxy header is trusted: the per-IP caps would then lock out real users.
  if (!cfg.trustProxy && (cfg.bind ?? '127.0.0.1') === '127.0.0.1') errs.push('trustProxy must be true when the maker sits behind a local tunnel or proxy');
  if (!cfg.x2sLimits) errs.push('x2sLimits is not set: the default XMR->SOL budget is 5 SOL, set one below your SOL inventory');
  if (cfg.claimMode !== undefined && cfg.claimMode !== 'ready-only' && cfg.claimMode !== 'payment-proof') errs.push('claimMode must be ready-only or payment-proof');
  if (cfg.claimMode === 'payment-proof') {
    if (cfg.attesters?.length !== 3 || new Set(cfg.attesters).size !== 3) errs.push('payment-proof requires three distinct attesters URLs');
    for (const u of cfg.attesters ?? []) if (!/^https:\/\//.test(u) || /[<>]/.test(u)) errs.push('attesters must be real HTTPS URLs');
  } else if (cfg.attesters?.length) errs.push('attesters must be empty in ready-only fallback mode');
  if (/[<>]/.test(cfg.programId)) errs.push('programId is still the placeholder');
  errs.push(...sanctionsErrors(cfg.sanctionsFile));
  if (cfg.pythApiKeyFile && !fs.existsSync(cfg.pythApiKeyFile)) errs.push(`pythApiKeyFile ${cfg.pythApiKeyFile} is missing`);
  if (cfg.refill?.enabled && (!cfg.refill.apiKeyFile || !fs.existsSync(cfg.refill.apiKeyFile))) errs.push('refill is on but its API key file is missing');
  return [...new Set(errs)];
}
