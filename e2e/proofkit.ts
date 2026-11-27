// Test helper (local validator): a 2-of-3 attester committee and Monero payment proofs for any
// escrow, so tests can exercise the v1.5 claim rule (every SOL->XMR claim without `ready` needs
// an on-chain payment proof). The Monero side is e2e/zkvec.ts: a real stagenet tx re-keyed to
// the escrow's shared key.
import assert from 'node:assert/strict';
import { Connection, Keypair, PublicKey } from '@solana/web3.js';
import { ed25519 } from '@noble/curves/ed25519';
import * as P from '../sdk/program.ts';
import * as K from '../sdk/keys.ts';
import * as V from '../sdk/v15.ts';
import { makeVector } from './zkvec.ts';
import { send } from './harness.ts';

export class ProofKit {
  c: Connection; pid: PublicKey; admin: Keypair; payer: Keypair;
  att = [Keypair.generate(), Keypair.generate(), Keypair.generate()];
  epoch = 0n;
  /** escrow -> its proof record, once proven. */
  proofs = new Map<string, PublicKey>();
  constructor(c: Connection, pid: PublicKey, admin: Keypair, payer: Keypair) { this.c = c; this.pid = pid; this.admin = admin; this.payer = payer; }

  async init() {
    const r = await send(this.c, [V.ixSetAttesters(this.pid, this.admin.publicKey, V.MONERO_NET.stagenet, 2, 10, this.att.map((k) => k.publicKey))], [this.admin]);
    assert.ok(r.ok, `set_attesters: ${r.err}`);
    this.epoch = V.decodeAttesters((await this.c.getAccountInfo(V.pdaV15.attesters(this.pid), 'confirmed'))!.data).epoch;
  }

  /** Pay the escrow's shared key at least its amount (Monero side), attest the block, prove_lock. */
  async prove(escrow: PublicKey, amount?: bigint): Promise<PublicKey> {
    if (!this.epoch) await this.init();
    const e = P.decodeEscrow((await this.c.getAccountInfo(escrow, 'confirmed'))!.data, escrow);
    const v = makeVector({ spendPub: K.pointAdd(e.claimPoint, e.refundPoint), viewPub: e.viewPub, escrow: escrow.toBytes(), amount: amount ?? e.xmrAmount });
    const msg = V.headerMessage(V.MONERO_NET.stagenet, v.height, v.args.blockId, 10);
    const sigs = this.att.slice(0, 2).map((k) => ({ pubkey: k.publicKey.toBytes(), signature: ed25519.sign(msg, k.secretKey.slice(0, 32)) }));
    const a = await send(this.c, V.ixsAttestHeader(this.pid, this.payer.publicKey, this.epoch, V.MONERO_NET.stagenet, v.height, v.args.blockId, 10, sigs), [this.payer]);
    assert.ok(a.ok, `attest_header: ${a.err}`);
    const p = await send(this.c, [V.ixProveLock(this.pid, this.payer.publicKey, escrow, e, this.epoch, v.args)], [this.payer]);
    if (!p.ok) { console.error('PROVE FAIL', escrow.toBase58(), 'created', e.createdAt, 'epoch', this.epoch, 'logs', (p.logs||[]).filter(l=>/invalid|seeds|Program log|Error/.test(l)).slice(-8)); }
    assert.ok(p.ok, `prove_lock: ${p.err}`);
    const pda = V.pdaV15.proof(this.pid, escrow, e);
    this.proofs.set(escrow.toBase58(), pda);
    return pda;
  }
}
