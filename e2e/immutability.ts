// Proves on a local validator what "upgrade authority = None" means at the RUNTIME level (not just
// the CLI's own checks): upgrade-loader Close, SetAuthority, Upgrade and Extend all fail, and the
// ProgramData lamports stay where they are. Usage (after `solana program deploy` + `--final` of a
// throwaway copy, see docs/NO-OFF-SWITCH.md):
//   RPC_URL=http://127.0.0.1:8869 node e2e/immutability.ts <finalized program id> <payer keypair.json> <buffer>
// where <buffer> is a real `solana program write-buffer` of new code with the payer as its authority.
import { PublicKey, TransactionInstruction, SystemProgram, Keypair, SYSVAR_RENT_PUBKEY, SYSVAR_CLOCK_PUBKEY } from '@solana/web3.js';
import { conn, send, loadKeypair } from './harness.ts';

const LOADER = new PublicKey('BPFLoaderUpgradeab1e11111111111111111111111');
const c = conn();
const program = new PublicKey(process.argv[2]);
const payer = loadKeypair(process.argv[3]);
const programData = PublicKey.findProgramAddressSync([program.toBytes()], LOADER)[0];
const u32 = (n: number, extra: number[] = []) => Buffer.from([n, 0, 0, 0, ...extra]);
const m = (pubkey: PublicKey, isWritable: boolean, isSigner = false) => ({ pubkey, isWritable, isSigner });
const pdBefore = await c.getAccountInfo(programData, 'confirmed');
const header = pdBefore!.data.subarray(0, 45);
console.log(`ProgramData ${programData.toBase58()}: ${pdBefore!.data.length} bytes (45 header + ${pdBefore!.data.length - 45} ELF), ${pdBefore!.lamports} lamports, authority option byte = ${header[12]} (0 = None)`);
const buffer = { publicKey: new PublicKey(process.argv[4]) };
const attempts: [string, TransactionInstruction[], Keypair[]][] = [
  ['Close (reclaim the rent)', [new TransactionInstruction({ programId: LOADER, keys: [m(programData, true), m(payer.publicKey, true), m(payer.publicKey, false, true), m(program, true)], data: u32(5) })], [payer]],
  ['SetAuthority (take control back)', [new TransactionInstruction({ programId: LOADER, keys: [m(programData, true), m(payer.publicKey, false, true), m(payer.publicKey, false)], data: u32(4) })], [payer]],
  ['Upgrade (new code)', [new TransactionInstruction({ programId: LOADER, keys: [m(programData, true), m(program, true), m(buffer.publicKey, true), m(payer.publicKey, true), m(SYSVAR_RENT_PUBKEY, false), m(SYSVAR_CLOCK_PUBKEY, false), m(payer.publicKey, false, true)], data: u32(3) })], [payer]],
  ['ExtendProgramChecked (grow it, as authority)', [new TransactionInstruction({ programId: LOADER, keys: [m(programData, true), m(program, true), m(payer.publicKey, false, true), m(SystemProgram.programId, false), m(payer.publicKey, true, true)], data: u32(9, [0, 4, 0, 0]) })], [payer]],
  ['ExtendProgram (grow it)', [new TransactionInstruction({ programId: LOADER, keys: [m(programData, true), m(program, true), m(SystemProgram.programId, false), m(payer.publicKey, true, true)], data: u32(6, [0, 4, 0, 0]) })], [payer]],
];
let allFailed = true;
for (const [name, ixs, signers] of attempts) {
  const r = await send(c, ixs, signers);
  const why = (r.logs ?? []).find((l) => /failed|Error|immutable|authority/i.test(l)) ?? r.err;
  console.log(`${r.ok ? 'SUCCEEDED (!)' : 'rejected'}  ${name}: ${why}`);
  if (r.ok) allFailed = false;
}
const pdAfter = await c.getAccountInfo(programData, 'confirmed');
console.log(`ProgramData after: ${pdAfter!.lamports} lamports (${pdAfter!.lamports === pdBefore!.lamports ? 'unchanged' : 'CHANGED'})`);
if (!allFailed || pdAfter!.lamports !== pdBefore!.lamports) process.exit(1);
