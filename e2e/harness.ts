// Shared Solana test helpers (local validator / devnet).
import fs from 'node:fs';
import path from 'node:path';
import {
  Connection, Keypair, PublicKey, Transaction, TransactionInstruction, ComputeBudgetProgram,
  SYSVAR_CLOCK_PUBKEY, LAMPORTS_PER_SOL, SystemProgram,
} from '@solana/web3.js';
import { errName } from '../sdk/program.ts';

export const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');

export function loadKeypair(p: string): Keypair {
  return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(path.resolve(ROOT, p), 'utf8'))));
}

export const PROGRAM_ID = new PublicKey(
  process.env.HALFKEY_PROGRAM_ID ?? loadKeypair('target/deploy/halfkey-keypair.json').publicKey.toBase58(),
);

export function conn(url = process.env.RPC_URL ?? 'http://127.0.0.1:8899') {
  return new Connection(url, 'confirmed');
}

export interface SendResult { ok: boolean; sig?: string; err?: string; cu?: number; logs?: string[] }

export async function send(c: Connection, ixs: TransactionInstruction[], signers: Keypair[], feePayer?: Keypair): Promise<SendResult> {
  const tx = new Transaction();
  tx.add(ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }));
  for (const i of ixs) tx.add(i);
  const payer = feePayer ?? signers[0];
  tx.feePayer = payer.publicKey;
  const { blockhash, lastValidBlockHeight } = await c.getLatestBlockhash('confirmed');
  tx.recentBlockhash = blockhash;
  const all = [payer, ...signers.filter((s) => !s.publicKey.equals(payer.publicKey))];
  tx.sign(...all);
  let sig: string;
  try {
    sig = await c.sendRawTransaction(tx.serialize(), { skipPreflight: true });
  } catch (e) {
    return { ok: false, err: errName(e) };
  }
  await c.confirmTransaction({ signature: sig, blockhash, lastValidBlockHeight }, 'confirmed');
  for (let i = 0; i < 20; i++) {
    const t = await c.getTransaction(sig, { commitment: 'confirmed', maxSupportedTransactionVersion: 0 });
    if (t) {
      const logs = t.meta?.logMessages ?? [];
      if (t.meta?.err) return { ok: false, sig, err: errName({ message: JSON.stringify(t.meta.err), logs }), cu: t.meta?.computeUnitsConsumed, logs };
      return { ok: true, sig, cu: t.meta?.computeUnitsConsumed, logs };
    }
    await sleep(250);
  }
  return { ok: false, sig, err: 'tx not found' };
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function chainTime(c: Connection): Promise<number> {
  const a = await c.getAccountInfo(SYSVAR_CLOCK_PUBKEY, 'processed');
  if (!a) throw new Error('no clock');
  return Number(a.data.readBigInt64LE(32));
}

/** Wait until the bank clock is >= t (unix seconds). */
export async function waitChainTime(c: Connection, t: number) {
  for (;;) {
    if ((await chainTime(c)) >= t) return;
    await sleep(300);
  }
}

export async function fund(c: Connection, to: PublicKey, sol = 10) {
  const sig = await c.requestAirdrop(to, sol * LAMPORTS_PER_SOL);
  const bh = await c.getLatestBlockhash();
  await c.confirmTransaction({ signature: sig, ...bh }, 'confirmed');
}

export async function newFunded(c: Connection, sol = 10) {
  const k = Keypair.generate();
  await fund(c, k.publicKey, sol);
  return k;
}

export function transferIx(from: PublicKey, to: PublicKey, lamports: number | bigint) {
  return SystemProgram.transfer({ fromPubkey: from, toPubkey: to, lamports: BigInt(lamports) });
}
