// The maker's own wallets as auto-refill sees them (maker/refill.ts): the main Monero wallet
// (monero-wallet-rpc, account 0) and the maker's Solana keypair. Refills receive XMR on a fresh
// subaddress of account 0 per refill, so each delivery is matched to its refill and is inventory
// as soon as it unlocks (10 confirmations). SOL arrives at the maker's own address and is matched
// by plain incoming transfers paid by someone else after we paid the exchanger.
import { Connection, Keypair, PublicKey, SystemProgram, Transaction, ComputeBudgetProgram } from '@solana/web3.js';
import bs58 from 'bs58';
import { waitForTx } from '../sdk/confirm.ts';
import type { WalletRpc } from './lib.ts';
import type { Leg, RefillWallets } from './refill.ts';

const SOL_KEEP = 100_000_000n; // never refill out of the last 0.1 SOL (fees for claims, refunds, locks)
const XMR_UNLOCK = 10;

export function xmrRefillWallets(a: {
  main: WalletRpc; conn: Connection; me: Keypair;
  /** XMR promised to open swaps that is still in the wallet (piconero). */
  reserved: () => bigint;
  mid: () => { coinPerSol: number; at: number };
}): RefillWallets {
  const { main, conn, me } = a;
  return {
    async balances() {
      const [b, lam] = await Promise.all([main.call('get_balance', { account_index: 0 }), conn.getBalance(me.publicKey)]);
      const coin = BigInt(b.unlocked_balance) - a.reserved(), sol = BigInt(lam) - SOL_KEEP;
      return { coin: coin > 0n ? coin : 0n, sol: sol > 0n ? sol : 0n };
    },
    mid: a.mid,
    async receiveAddress(leg: Leg, id: string) {
      if (leg === 'sol') return { address: me.publicKey.toBase58(), ref: 'sol' };
      const r = await main.call('create_address', { account_index: 0, label: `halfkey-refill ${id}` });
      return { address: r.address as string, ref: String(r.address_index) };
    },
    async refundAddress(leg: Leg) {
      // the refund goes back in the coin we paid with
      if (leg === 'coin') return me.publicKey.toBase58();
      return (await main.call('get_address', { account_index: 0 })).address as string;
    },
    async pay(leg: Leg, to: string, amount: bigint, onTxid: (txid: string) => void) {
      if (leg === 'coin') {
        // pay SOL
        const tx = new Transaction().add(ComputeBudgetProgram.setComputeUnitLimit({ units: 10_000 }), SystemProgram.transfer({ fromPubkey: me.publicKey, toPubkey: new PublicKey(to), lamports: amount }));
        tx.feePayer = me.publicKey;
        const { blockhash, lastValidBlockHeight } = await conn.getLatestBlockhash('confirmed');
        tx.recentBlockhash = blockhash;
        tx.sign(me);
        const sig = bs58.encode(tx.signature!);
        onTxid(sig); // journaled before it can reach the network
        await conn.sendRawTransaction(tx.serialize(), { skipPreflight: false, preflightCommitment: 'confirmed' });
        await waitForTx(sig, lastValidBlockHeight, {
          status: async (x) => (await conn.getSignatureStatuses([x], { searchTransactionHistory: true })).value[0],
          height: () => conn.getBlockHeight('confirmed'),
        }, { timeoutMs: 120_000, intervalMs: 800 });
        return sig;
      }
      // pay XMR: build without relaying, journal the hash, then relay
      return main.exclusive(async () => {
        const r = await main.call('transfer', { destinations: [{ amount: Number(amount), address: to }], account_index: 0, priority: 0, do_not_relay: true, get_tx_metadata: true, get_tx_key: true });
        onTxid(r.tx_hash);
        await main.call('relay_tx', { hex: r.tx_metadata });
        return r.tx_hash as string;
      });
    },
    async paid(leg: Leg, txid: string) {
      try {
        if (leg === 'coin') {
          const s = await conn.getSignatureStatus(txid, { searchTransactionHistory: true });
          return s.value ? !s.value.err : null;
        }
        const t = await main.call('get_transfer_by_txid', { txid, account_index: 0 });
        return t?.transfer ? true : null;
      } catch { return null; }
    },
    async received(leg: Leg, ref: string, sinceMs: number) {
      if (leg === 'coin') {
        const t = await main.call('get_transfers', { in: true, pool: true, account_index: 0, subaddr_indices: [Number(ref)] });
        let seen = 0n, spendable = 0n;
        const txids: string[] = [];
        for (const x of t.in ?? []) { seen += BigInt(x.amount); txids.push(x.txid); if (x.confirmations >= XMR_UNLOCK && !x.locked) spendable += BigInt(x.amount); }
        for (const x of t.pool ?? []) { seen += BigInt(x.amount); txids.push(x.txid); }
        return { seen, spendable, txids };
      }
      // SOL: plain system transfers to us, paid by someone else, after we paid the exchanger
      const sigs = (await conn.getSignaturesForAddress(me.publicKey, { limit: 50 }, 'confirmed')).filter((s) => !s.err && (s.blockTime ?? 0) * 1000 >= sinceMs - 60_000);
      let seen = 0n;
      const txids: string[] = [];
      for (const s of sigs.slice(0, 25)) {
        const tx = await conn.getParsedTransaction(s.signature, { commitment: 'confirmed', maxSupportedTransactionVersion: 0 });
        if (!tx?.meta) continue;
        const keys = tx.transaction.message.accountKeys;
        if (keys[0]?.pubkey.equals(me.publicKey)) continue; // our own tx
        const plain = tx.transaction.message.instructions.every((ix: any) => (ix.program === 'system' && ix.parsed?.type === 'transfer') || ix.programId?.equals?.(ComputeBudgetProgram.programId));
        if (!plain) continue;
        const i = keys.findIndex((k) => k.pubkey.equals(me.publicKey));
        const delta = BigInt(tx.meta.postBalances[i]) - BigInt(tx.meta.preBalances[i]);
        if (i >= 0 && delta > 0n) { seen += delta; txids.push(s.signature); }
      }
      return { seen, spendable: seen, txids };
    },
  };
}
