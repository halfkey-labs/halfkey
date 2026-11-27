/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const adaptorDecrypt: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const adaptorPoints: (a: number, b: number) => [number, number, number, number];
export const adaptorRecover: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
export const adaptorSign: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
export const adaptorVerify: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
export const buildShieldedSpend: (a: number, b: number) => [number, number, number, number];
export const dleqProve: (a: number, b: number) => [number, number, number, number];
export const dleqVerify: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
export const inspectSpend: (a: number, b: number) => [number, number, number, number];
export const uaReceiver: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const prepareProver: () => number;
export const rustsecp256k1_v0_14_default_error_callback_fn: (a: number, b: number) => void;
export const rustsecp256k1_v0_14_default_illegal_callback_fn: (a: number, b: number) => void;
export const rustsecp256k1_v0_14_context_destroy: (a: number) => void;
export const rustsecp256k1_v0_14_context_create: (a: number) => number;
export const __wbindgen_exn_store: (a: number) => void;
export const __externref_table_alloc: () => number;
export const __wbindgen_export_2: WebAssembly.Table;
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
export const __externref_table_dealloc: (a: number) => void;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __wbindgen_start: () => void;
