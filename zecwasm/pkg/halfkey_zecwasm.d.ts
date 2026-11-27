/* tslint:disable */
/* eslint-disable */
/**
 * Build the Halo2 proving key now (the slow first step), returns milliseconds taken.
 */
export function prepareProver(): number;
/**
 * Build + prove + shielded-sign a v6 spend of one P2SH output into one Ironwood note.
 */
export function buildShieldedSpend(req: string): string;
/**
 * Parse a finished (or template) spend: txid, inputs, Ironwood summary, input-0 sighash, proof check.
 */
export function inspectSpend(req: string): string;
/**
 * The Orchard-family (Ironwood) receiver of a unified address, hex.
 */
export function uaReceiver(ua: string, net: string): string;
/**
 * {tSecp, tEd} for a secret t (32 bytes little-endian hex, t < 2^252).
 */
export function adaptorPoints(t: string): string;
/**
 * {tSecp, tEd, proof}: the cross-curve DLEQ that both points share t (~1-3 s).
 */
export function dleqProve(t: string): string;
export function dleqVerify(t_secp: string, t_ed: string, proof: string): boolean;
/**
 * Adaptor signature (162 bytes hex) by `sk` (32-byte big-endian hex) on `msg` (32 bytes), encrypted to T_secp.
 */
export function adaptorSign(sk: string, t_secp: string, msg: string): string;
export function adaptorVerify(pk: string, t_secp: string, msg: string, enc: string): boolean;
/**
 * Decrypt with t: the 64-byte r||s ECDSA signature (low-S), hex.
 */
export function adaptorDecrypt(t: string, enc: string): string;
export function adaptorRecover(t_secp: string, sig64: string, enc: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly adaptorDecrypt: (a: number, b: number, c: number, d: number) => [number, number, number, number];
  readonly adaptorPoints: (a: number, b: number) => [number, number, number, number];
  readonly adaptorRecover: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly adaptorSign: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly adaptorVerify: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
  readonly buildShieldedSpend: (a: number, b: number) => [number, number, number, number];
  readonly dleqProve: (a: number, b: number) => [number, number, number, number];
  readonly dleqVerify: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
  readonly inspectSpend: (a: number, b: number) => [number, number, number, number];
  readonly uaReceiver: (a: number, b: number, c: number, d: number) => [number, number, number, number];
  readonly prepareProver: () => number;
  readonly rustsecp256k1_v0_14_default_error_callback_fn: (a: number, b: number) => void;
  readonly rustsecp256k1_v0_14_default_illegal_callback_fn: (a: number, b: number) => void;
  readonly rustsecp256k1_v0_14_context_destroy: (a: number) => void;
  readonly rustsecp256k1_v0_14_context_create: (a: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_export_2: WebAssembly.Table;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
