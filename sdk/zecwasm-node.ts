// Node loader for the zecwasm module (watchtower, maker, regtest runners). The browser loads the
// same build from /zec/ in a Web Worker (web/src/client/zecprove.worker.ts).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ZecWasm } from './zecshield.ts';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const cache = new Map<string, Promise<any>>();
/** `testkit` adds the seed-wallet and trial-decryption helpers (regtest runner only). */
export function loadZecWasm(opts: { testkit?: boolean } = {}): Promise<ZecWasm & Record<string, any>> {
  const dir = path.join(HERE, '..', 'zecwasm', opts.testkit ? 'pkg-testkit' : 'pkg');
  let p = cache.get(dir);
  if (!p) {
    p = (async () => {
      const m = await import(path.join(dir, 'halfkey_zecwasm.js'));
      m.initSync({ module: fs.readFileSync(path.join(dir, 'halfkey_zecwasm_bg.wasm')) });
      return m;
    })();
    cache.set(dir, p);
  }
  return p;
}
