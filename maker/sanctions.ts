// Wallet screening for the maker: decline wallets on the OFAC SDN list before any quote is honoured.
// The list lives in sanctions-list.json (refresh with `node maker/sanctions.ts --refresh`), read
// from the official OFAC files and cross-checked with 0xB10C's nightly extract. OFAC itself says its
// address listings are not exhaustive, so this catches listed wallets only.
//
// Missing or empty list on mainnet is loud: the daemon refuses to start (daemon.ts checkMainnet).
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

export interface SanctionsList { date: string; addresses: Record<string, string[]> }
export const LIST_FILE = fileURLToPath(new URL('./sanctions-list.json', import.meta.url));

export function loadList(file = LIST_FILE): SanctionsList {
  const j = JSON.parse(fs.readFileSync(file, 'utf8')) as SanctionsList;
  if (!j.addresses || typeof j.date !== 'string') throw new Error('bad sanctions list file');
  return j;
}

export class Screen {
  private solana = new Set<string>();
  private evm = new Set<string>();
  date = '';
  constructor(list: SanctionsList) { this.set(list); }
  set(list: SanctionsList) {
    this.solana = new Set(list.addresses.SOL ?? []);
    this.evm = new Set((list.addresses.ETH ?? []).map((a) => a.toLowerCase()));
    this.date = list.date;
  }
  /** Exact match: base58 is case-sensitive, EVM addresses are not. */
  sol(address: string) { return this.solana.has(String(address).trim()); }
  evmAddr(address: string) { return this.evm.has(String(address).trim().toLowerCase()); }
  count() { return this.solana.size + this.evm.size; }
  ageDays(nowMs = Date.now()) { return (nowMs - Date.parse(this.date)) / 86_400_000; }
}

/** Every "Digital Currency Address - <TICKER> <addr>" in the OFAC remarks, including the overflow file. */
export function parseOfac(sdnCsv: string, commentsCsv = ''): Record<string, string[]> {
  const out: Record<string, Set<string>> = {};
  // Remarks can split an entry across a CSV row boundary in the overflow file, so read each entity's text whole.
  const byEnt = new Map<string, string>();
  const rows = (text: string) => {
    const res: string[][] = []; let row: string[] = [], f = '', q = false;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (q) { if (c === '"') { if (text[i + 1] === '"') { f += '"'; i++; } else q = false; } else f += c; }
      else if (c === '"') q = true;
      else if (c === ',') { row.push(f); f = ''; }
      else if (c === '\n' || c === '\r') { if (f || row.length) { row.push(f); res.push(row); row = []; f = ''; } }
      else f += c;
    }
    if (f || row.length) { row.push(f); res.push(row); }
    return res;
  };
  for (const r of rows(sdnCsv)) if (r.length >= 12 && /^\d+$/.test(r[0])) byEnt.set(r[0], (byEnt.get(r[0]) ?? '') + ' ' + r[11]);
  for (const r of rows(commentsCsv)) if (r.length >= 2 && /^\d+$/.test(r[0])) byEnt.set(r[0], (byEnt.get(r[0]) ?? '') + r[1]);
  for (const remarks of byEnt.values()) {
    for (const m of remarks.matchAll(/Digital Currency Address - ([A-Z0-9]+)\s+([0-9A-Za-z]{20,})/g)) (out[m[1]] ??= new Set()).add(m[2]);
  }
  return Object.fromEntries(Object.entries(out).map(([k, v]) => [k, [...v].sort()]));
}

async function refresh() {
  const OFAC = 'https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/';
  const B10C = 'https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_';
  const get = async (url: string) => {
    const r = await fetch(url, { signal: AbortSignal.timeout(180_000), headers: { 'user-agent': 'halfkey-maker-sanctions/1.0' } });
    if (!r.ok) throw new Error(`${url} -> HTTP ${r.status}`);
    return new TextDecoder('latin1').decode(await r.arrayBuffer());
  };
  const [sdn, comments] = await Promise.all([get(`${OFAC}SDN.CSV`), get(`${OFAC}SDN_COMMENTS.CSV`)]);
  const parsed = parseOfac(sdn, comments);
  const keep = ['SOL', 'ETH', 'XMR', 'ZEC'];
  const addresses = Object.fromEntries(keep.map((k) => [k, parsed[k] ?? []]));
  for (const k of ['SOL', 'ETH']) {
    if (!addresses[k].length) throw new Error(`refusing to write an empty ${k} list`);
    try {
      const other = (JSON.parse(await get(`${B10C}${k}.json`)) as string[]).map((a) => a.toLowerCase()).sort();
      const mine = addresses[k].map((a) => a.toLowerCase()).sort();
      const onlyO = other.filter((a) => !mine.includes(a)), onlyM = mine.filter((a) => !other.includes(a));
      console.log(`${k}: OFAC ${mine.length}, 0xB10C ${other.length}${onlyO.length || onlyM.length ? `, differ: only 0xB10C ${JSON.stringify(onlyO)}, only OFAC ${JSON.stringify(onlyM)}` : ', identical'}`);
    } catch (e) { console.log(`${k}: cross-check unavailable (${(e as Error).message})`); }
  }
  fs.writeFileSync(LIST_FILE, JSON.stringify({ date: new Date().toISOString().slice(0, 10), addresses }, null, 1) + '\n');
  console.log(`wrote ${LIST_FILE}: ${keep.map((k) => `${k} ${addresses[k].length}`).join(', ')}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url) && process.argv.includes('--refresh')) await refresh();
