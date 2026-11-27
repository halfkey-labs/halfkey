// Bring up an E2E environment on a cluster (localnet by default): program config, two makers in
// the registry (an honest one and a fault-injected one that never locks XMR), a watchtower, users.
// Writes runtime configs to .run/ (gitignored). Keys are throwaway test keys generated here.
//
//   node e2e/bootstrap.ts [rpcUrl] [cluster]
import fs from 'node:fs';
import path from 'node:path';
import { Keypair, LAMPORTS_PER_SOL, PublicKey, SystemProgram, TransactionInstruction } from '@solana/web3.js';
import * as P from '../sdk/program.ts';
import { conn, send, fund, loadKeypair, ROOT, PROGRAM_ID as pid } from './harness.ts';

import { STAGENET_NODES } from './nodes.ts';
const rpcUrl = process.argv[2] ?? 'http://127.0.0.1:8899';
const cluster = process.argv[3] ?? 'localnet';
const c = conn(rpcUrl);
const SOL = BigInt(LAMPORTS_PER_SOL);
const keyDir = path.join(ROOT, '.run/keys');

function key(name: string): Keypair {
  const f = path.join(keyDir, `${name}.json`);
  if (!fs.existsSync(f)) fs.writeFileSync(f, JSON.stringify([...Keypair.generate().secretKey]), { mode: 0o600 });
  return loadKeypair(`.run/keys/${name}.json`);
}

const admin = loadKeypair('.run/keys/admin.json');
const names = ['maker1', 'maker2', 'tower1', 'user1', 'user2', 'user3', 'fees'];
const k = Object.fromEntries(names.map((n) => [n, key(n)])) as Record<string, Keypair>;

if (cluster === 'localnet') {
  for (const [n, sol] of [['admin', 20], ['maker1', 30], ['maker2', 10], ['tower1', 2], ['user1', 10], ['user2', 10], ['user3', 1], ['fees', 1]] as const) {
    await fund(c, (n === 'admin' ? admin : k[n]).publicKey, sol);
  }
}

// $HALFKEY test mint (6 decimals) on test clusters, so the maker bond path runs end to end.
const TOKEN = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
const mintKp = key('halfkey-mint');
if (!(await c.getAccountInfo(mintKp.publicKey))) {
  const rent = await c.getMinimumBalanceForRentExemption(82);
  const r = await send(c, [
    SystemProgram.createAccount({ fromPubkey: admin.publicKey, newAccountPubkey: mintKp.publicKey, lamports: rent, space: 82, programId: TOKEN }),
    new TransactionInstruction({ programId: TOKEN, keys: [{ pubkey: mintKp.publicKey, isSigner: false, isWritable: true }], data: Buffer.concat([Buffer.from([20, 6]), admin.publicKey.toBuffer(), Buffer.from([0])]) }),
  ], [admin, mintKp]);
  console.log('test $HALFKEY mint', mintKp.publicKey.toBase58(), r.ok ? 'ok' : r.err);
}
const params: P.ConfigParams = {
  feeRecipient: k.fees.publicKey, halfkeyMint: mintKp.publicKey, feeBps: 50, holderFeeBps: 25, holderMin: 1_000_000n,
  minBond: 2n * SOL, maxSwap: 5n * SOL, maxOpenTvl: 50n * SOL, minT0: 60, maxT0: 3600, minWindow: 60, maxWindow: 7200, unbondSecs: 60,
};
if (!(await c.getAccountInfo(P.pda.config(pid)))) {
  const r = await send(c, [P.ixInitConfig(pid, admin.publicKey, params)], [admin]);
  console.log('init_config', r.ok ? r.sig : r.err);
}

const makers = [
  { kp: k.maker1, port: 7801, t0: 3600, window: 1800, fault: '' }, // t0 >= T.minXmrToSolT0 (margin 600): 3000
  { kp: k.maker2, port: 7802, t0: 420, window: 600, fault: 'no-xmr-lock' },
];
for (const m of makers) {
  if (!(await c.getAccountInfo(P.pda.maker(pid, m.kp.publicKey)))) {
    const r = await send(c, [P.ixRegisterMaker(pid, m.kp.publicKey, 2n * SOL, {
      min: SOL / 100n, max: 2n * SOL, directions: 3, spreadBps: 100, endpoint: `http://127.0.0.1:${m.port}`,
    })], [m.kp]);
    console.log('register maker', m.kp.publicKey.toBase58(), r.ok ? r.sig : r.err);
  }
}

// maker1 bonds 2 $HALFKEY (threshold 1) -> pays the 0.25% holder fee.
{
  const ataAddr = P.ata(k.maker1.publicKey, mintKp.publicKey);
  if (!(await c.getAccountInfo(ataAddr))) {
    const ATA = P.ATA_PROGRAM;
    const create = new TransactionInstruction({ programId: ATA, data: Buffer.from([1]), keys: [
      { pubkey: admin.publicKey, isSigner: true, isWritable: true }, { pubkey: ataAddr, isSigner: false, isWritable: true },
      { pubkey: k.maker1.publicKey, isSigner: false, isWritable: false }, { pubkey: mintKp.publicKey, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }, { pubkey: TOKEN, isSigner: false, isWritable: false }] });
    const d = Buffer.alloc(9); d[0] = 7; d.writeBigUInt64LE(5_000_000n, 1);
    const mintTo = new TransactionInstruction({ programId: TOKEN, data: d, keys: [
      { pubkey: mintKp.publicKey, isSigner: false, isWritable: true }, { pubkey: ataAddr, isSigner: false, isWritable: true }, { pubkey: admin.publicKey, isSigner: true, isWritable: false }] });
    console.log('maker1 $HALFKEY', (await send(c, [create, mintTo], [admin])).ok);
    const st = await send(c, [P.ixStake(pid, k.maker1.publicKey, mintKp.publicKey, ataAddr, 2_000_000n)], [k.maker1]);
    console.log('maker1 bonds 2 $HALFKEY', st.ok ? st.sig : st.err);
  }
}

const run = (f: string) => path.join(ROOT, '.run', f);
for (const [i, m] of makers.entries()) {
  fs.writeFileSync(run(`maker${i + 1}.json`), JSON.stringify({
    rpcUrl, cluster, programId: pid.toBase58(), keypair: `.run/keys/maker${i + 1}.json`, endpoint: `http://127.0.0.1:${m.port}`, port: m.port,
    moneroNet: 'stagenet', daemonUri: STAGENET_NODES, walletRpc: 'http://127.0.0.1:38190', swapWalletRpc: 'http://127.0.0.1:38191',
    journal: `.run/maker${i + 1}/journal.jsonl`, spreadBps: 100, fallbackXmrPerSol: 0.17, livePrice: true,
    t0Secs: m.t0, windowSecs: m.window, minConf: 10, lockDeadlineSecs: 600, claimMarginSecs: 300, depositMarginSecs: 600, pollMs: 4000,
  }, null, 2));
}
fs.writeFileSync(run('tower1.json'), JSON.stringify({
  rpcUrl, programId: pid.toBase58(), keypair: '.run/keys/tower1.json', port: 7901, daemonUri: STAGENET_NODES,
  minConf: 10, abortMarginSecs: 120, pollMs: 5000, db: '.run/tower1-db.json',
}, null, 2));
console.log(JSON.stringify({ programId: pid.toBase58(), rpcUrl, maker1: k.maker1.publicKey.toBase58(), maker2: k.maker2.publicKey.toBase58(), tower1: k.tower1.publicKey.toBase58() }, null, 1));
