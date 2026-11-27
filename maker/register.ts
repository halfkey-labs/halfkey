// Register / update / unbond a maker in the on-chain registry.
//   node maker/register.ts <config.json> register --bond 2 --min 0.05 --max 5 --dirs 3 --spread 120
//   node maker/register.ts <config.json> update   --min 0.05 --max 5 --dirs 3 --spread 120 [--add-bond 1] [--pause]
//   node maker/register.ts <config.json> upgrade | unbond | withdraw | show
// The registry endpoint field holds `endpoint` plus any `endpoints` from the config, '|'-separated
// (clients try them in order; see sdk/discovery.ts).
import fs from 'node:fs';
import { Connection, PublicKey, LAMPORTS_PER_SOL } from '@solana/web3.js';
import * as P from '../sdk/program.ts';
import { sendIxs, loadKeypair } from './lib.ts';
import { formatEndpointField } from '../sdk/discovery.ts';

const [cfgPath, cmd, ...rest] = process.argv.slice(2);
const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
const opt = (k: string, d?: string) => { const i = rest.indexOf(`--${k}`); return i >= 0 ? rest[i + 1] : d; };
const sol = (v: string) => BigInt(Math.round(Number(v) * LAMPORTS_PER_SOL));
const pid = new PublicKey(cfg.programId);
const me = loadKeypair(cfg.keypair);
const conn = new Connection(cfg.rpcUrl, 'confirmed');
const params = (): P.MakerParams => ({ min: sol(opt('min', '0.05')!), max: sol(opt('max', '5')!), directions: Number(opt('dirs', '3')), spreadBps: Number(opt('spread', String(cfg.spreadBps))), endpoint: formatEndpointField({ endpoints: [cfg.endpoint, ...(cfg.endpoints ?? [])] }) });

// The upgrade belongs to registering: a flagged lock (every XMR->SOL lock) needs the maker extension, and refuses without it.
if (cmd === 'register') console.log(await sendIxs(conn, me, [P.ixRegisterMaker(pid, me.publicKey, sol(opt('bond', '2')!), params()), P.ixUpgradeMaker(pid, me.publicKey, 0n, 0n)]));
else if (cmd === 'upgrade') console.log(await sendIxs(conn, me, [P.ixUpgradeMaker(pid, me.publicKey, 0n, 0n)]));
else if (cmd === 'update') console.log(await sendIxs(conn, me, [P.ixUpdateMaker(pid, me.publicKey, sol(opt('add-bond', '0')!), params(), !rest.includes('--pause'))]));
else if (cmd === 'unbond') console.log(await sendIxs(conn, me, [P.ixRequestUnbond(pid, me.publicKey)]));
else if (cmd === 'withdraw') console.log(await sendIxs(conn, me, [P.ixWithdrawMaker(pid, me.publicKey)]));
else if (cmd === 'show') {
  const a = await conn.getAccountInfo(P.pda.maker(pid, me.publicKey));
  console.log(a ? P.decodeMaker(a.data) : 'not registered');
} else { console.error('usage: register | update | upgrade | unbond | withdraw | show'); process.exit(1); }
