// HALFKEY v1.5: build the transactions that put a Monero payment proof on chain for an escrow.
// Used by the maker (SOL->XMR: it proves its own lock with the wallet's OutProof) and by the
// user's client (XMR->SOL: it proves its deposit with an InProof from the shared view key).
//   1. the tx and its block from a monerod; wait for the committee's minimum confirmations;
//   2. check the proof off chain with the program's rules (sdk/xmrproof.ts buildProve);
//   3. if the block is not attested under the current committee yet: ask the attesters to sign
//      the header (same message for all), keep `threshold` valid signatures, attest_header;
//   4. prove_lock. Anyone may send either transaction; the program re-checks everything.
import { Connection, PublicKey, TransactionInstruction } from '@solana/web3.js';
import * as K from './keys.ts';
import * as P from './program.ts';
import * as X from './xmrproof.ts';
import * as V from './v15.ts';
import { ed25519 } from '@noble/curves/ed25519';

export interface AttesterSig { height: number; blockId: string; confirmations: number; net: number; pubkey: string; signature: string }

/** Keep attestations that verify over exactly (net, height, blockId, conf) by a committee key, one per key. */
export function pickAttestations(list: AttesterSig[], want: { net: number; height: number; blockId: Uint8Array; conf: number; keys: PublicKey[]; threshold: number }): V.Attestation[] {
  const msg = V.headerMessage(want.net, want.height, want.blockId, want.conf);
  const keys = new Set(want.keys.map((k) => K.toHex(k.toBytes())));
  const out: V.Attestation[] = [];
  const seen = new Set<string>();
  for (const a of list) {
    if (out.length >= want.threshold) break;
    if (!a || a.net !== want.net || a.height !== want.height || a.blockId !== K.toHex(want.blockId) || a.confirmations !== want.conf) continue;
    if (!keys.has(a.pubkey) || seen.has(a.pubkey)) continue;
    try {
      if (!ed25519.verify(K.fromHex(a.signature), msg, K.fromHex(a.pubkey))) continue;
    } catch { continue; }
    seen.add(a.pubkey);
    out.push({ pubkey: K.fromHex(a.pubkey), signature: K.fromHex(a.signature) });
  }
  return out;
}

export type ProvePlan =
  | { status: 'pending'; why: string; confirmations?: number }
  | { status: 'ready'; attestIxs: TransactionInstruction[] | null; proveIx: TransactionInstruction; proofPda: PublicKey; args: X.ProveArgs };

/**
 * Plan the proof of `txid` for escrow `escrow` (decoded `e`). `sig` is the TXPROOF_V2 signature
 * (from `X.decodeProofString(wallet get_tx_proof)`, or `X.genTxProof` with the view key).
 */
export async function planProve(o: {
  conn: Connection; pid: PublicKey; payer: PublicKey; escrow: PublicKey; e: P.EscrowAccount;
  txid: string; kind: number; sig: X.ProofSig; daemon: string; attesters: string[]; fetchImpl?: typeof fetch;
}): Promise<ProvePlan> {
  const f = o.fetchImpl ?? fetch;
  if (!P.allowsPaymentProof(o.e)) throw new Error('not a proof-gated escrow, or this swap is ready-only');
  const attAcc = await o.conn.getAccountInfo(V.pdaV15.attesters(o.pid), 'confirmed');
  if (!attAcc) throw new Error('no attester committee on this program');
  const att = V.decodeAttesters(attAcc.data);
  const tx = await X.fetchTx(o.daemon, o.txid);
  if (tx.inPool) return { status: 'pending', why: 'in the mempool' };
  const block = await X.fetchBlock(o.daemon, tx.height);
  const conf = (block.depth ?? 0) + 1;
  if (conf < att.minConf) return { status: 'pending', why: `${conf}/${att.minConf} confirmations`, confirmations: conf };
  const args = X.buildProve({
    kind: o.kind, sig: o.sig, unprunable: tx.unprunable, prunableHash: tx.prunableHash, block,
    escrow: o.escrow.toBytes(), spendPub: K.pointAdd(o.e.claimPoint, o.e.refundPoint), viewPub: o.e.viewPub, minAmount: o.e.xmrAmount,
  });
  const proofPda = V.pdaV15.proof(o.pid, o.escrow, o.e);
  const proveIx = V.ixProveLock(o.pid, o.payer, o.escrow, o.e, att.epoch, args);
  if (await o.conn.getAccountInfo(V.pdaV15.header(o.pid, att.epoch, args.blockId), 'confirmed')) return { status: 'ready', attestIxs: null, proveIx, proofPda, args };
  const answers = await Promise.allSettled(o.attesters.map(async (u) => {
    const r = await f(`${u.replace(/\/$/, '')}/v1/attest?height=${tx.height}&conf=${att.minConf}`, { signal: AbortSignal.timeout(20_000) });
    return (await r.json()) as AttesterSig;
  }));
  const sigs = pickAttestations(answers.flatMap((a) => (a.status === 'fulfilled' ? [a.value] : [])), {
    net: att.net, height: tx.height, blockId: args.blockId, conf: att.minConf, keys: att.keys, threshold: att.threshold,
  });
  if (sigs.length < att.threshold) return { status: 'pending', why: `${sigs.length}/${att.threshold} attesters signed block ${tx.height}` };
  const attestIxs = V.ixsAttestHeader(o.pid, o.payer, att.epoch, att.net, tx.height, args.blockId, att.minConf, sigs);
  return { status: 'ready', attestIxs, proveIx, proofPda, args };
}
