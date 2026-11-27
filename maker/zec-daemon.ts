// HALFKEY maker, ZEC leg only (no Monero): quotes, HTLC funding, the per-swap state machine and
// the /v1/zec/* API. The full daemon (maker/daemon.ts) mounts the same desk when its config has
// a `zec` section; this entry point is for ZEC-only makers and the regtest runner.
//
//   node maker/zec-daemon.ts maker/zec-config.json
import fs from 'node:fs';
import http from 'node:http';
import { Connection, PublicKey } from '@solana/web3.js';
import * as P from '../sdk/program.ts';
import { ZecDesk, zecHttp, type ZecConfig } from './zec.ts';
import { describeErr, loadKeypair, log } from './lib.ts';
import { checkZecDesk } from './launch-checks.ts';
import { Screen, loadList } from './sanctions.ts';

interface Config { rpcUrl: string; programId: string; keypair: string; port: number; bind?: string; pollMs: number; cluster?: string; trustProxy?: boolean; sanctionsFile?: string; pythApiKeyFile?: string; zec: ZecConfig }
const cfg: Config = JSON.parse(fs.readFileSync(process.argv[2] ?? 'maker/zec-config.json', 'utf8'));
for (const err of checkZecDesk(cfg)) { console.error(`config: ${err}`); process.exitCode = 1; }
if (process.exitCode) process.exit(1);
const pid = new PublicKey(cfg.programId);
const me = loadKeypair(cfg.keypair);
const conn = new Connection(cfg.rpcUrl, 'confirmed');

let makerAcct: P.MakerAccount | null = null;
let feeBpsNow = 0;
async function refreshChain() {
  const [m, c] = await Promise.all([conn.getAccountInfo(P.pda.maker(pid, me.publicKey)), conn.getAccountInfo(P.pda.config(pid))]);
  makerAcct = m ? P.decodeMaker(m.data) : null;
  const ca = c ? P.decodeConfig(c.data) : null;
  feeBpsNow = ca && makerAcct && !ca.halfkeyMint.equals(PublicKey.default) && makerAcct.staked >= ca.holderMin && makerAcct.stakeUnlockAt === 0n ? ca.holderFeeBps : (ca?.feeBps ?? 0);
}

const sanctionsFile = cfg.zec.sanctionsFile ?? cfg.sanctionsFile;
const screen = new Screen(loadList(sanctionsFile));
setInterval(() => { // the list is a file the refresh tool rewrites: reload it, and say when it gets old
  try { screen.set(loadList(sanctionsFile)); } catch (e) { log(`!! sanctions list unreadable, keeping the last one: ${describeErr(e)}`); }
  if (screen.ageDays() > 14) log(`!! sanctions list is ${screen.ageDays().toFixed(0)} days old: run node maker/sanctions.ts --refresh`);
}, 3_600_000).unref();
const desk = new ZecDesk({ cfg: { ...cfg.zec, pythApiKeyFile: cfg.zec.pythApiKeyFile ?? cfg.pythApiKeyFile }, conn, me, pid, feeBps: () => feeBpsNow, maker: () => makerAcct, screen });
await refreshChain();
await desk.init();
let ticking = false;
setInterval(async () => {
  if (ticking) return;
  ticking = true;
  try { await refreshChain(); await desk.tick(); } catch (e) { log('zec tick', describeErr(e)); } finally { ticking = false; }
}, cfg.pollMs);

const server = http.createServer(zecHttp(desk, { trustProxy: cfg.trustProxy }));
server.listen(cfg.port, cfg.bind ?? '127.0.0.1', () => log(`zec maker ${me.publicKey.toBase58()} on :${cfg.port}`));
process.on('SIGTERM', () => { server.close(); process.exit(0); });
