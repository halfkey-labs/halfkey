// Maker discovery without any HALFKEY server: read the on-chain registry directly, take the maker's
// published endpoints from its registry entry, talk to the maker directly, fall back gracefully.
//
// Registry `endpoint` field (<= 128 bytes of printable ASCII without spaces, enforced by the program;
// written only by the maker authority's own transaction, so everything in it is authenticated by
// the chain):
//   "<url>[|<url>...][|px=<xmr per SOL>][|ts=<unix seconds>]"
// '|'-separated tokens. Every http(s) URL is an endpoint, tried in order (first = primary, so a
// plain single URL keeps working everywhere). `px`/`ts` are an optional indicative rate the maker
// posted on chain: the client shows it when no endpoint answers. Firm quotes and the handshake
// (consent signature, key exchange) always need a live endpoint.
import { Connection, PublicKey } from '@solana/web3.js';
import * as P from './program.ts';
import type { MakerInfo } from './taker.ts';

export const MAX_ENDPOINT_BYTES = 128;

export interface EndpointField { endpoints: string[]; px?: number; ts?: number }

export function parseEndpointField(raw: string): EndpointField {
  const out: EndpointField = { endpoints: [] };
  for (const tok of (raw || '').trim().split(/[|\s]+/)) {
    if (!tok) continue;
    if (/^https?:\/\//i.test(tok)) {
      try { const u = new URL(tok); if (!out.endpoints.includes(u.href.replace(/\/+$/, ''))) out.endpoints.push(u.href.replace(/\/+$/, '')); } catch { /* skip */ }
    } else if (tok.startsWith('px=')) {
      const v = Number(tok.slice(3)); if (Number.isFinite(v) && v > 0) out.px = v;
    } else if (tok.startsWith('ts=')) {
      const v = Number(tok.slice(3)); if (Number.isInteger(v) && v > 0) out.ts = v;
    }
  }
  out.endpoints = out.endpoints.slice(0, 4);
  return out;
}

export function formatEndpointField(f: EndpointField): string {
  const toks = [...f.endpoints];
  if (f.px !== undefined) toks.push(`px=${Number(f.px.toPrecision(6))}`);
  if (f.ts !== undefined) toks.push(`ts=${Math.floor(f.ts)}`);
  const s = toks.join('|');
  if (new TextEncoder().encode(s).length > MAX_ENDPOINT_BYTES) throw new Error(`endpoint field is over ${MAX_ENDPOINT_BYTES} bytes`);
  for (const e of f.endpoints) if (!/^https?:\/\/[\x21-\x7e]+$/i.test(e) || e.includes('|')) throw new Error(`bad endpoint ${e}`);
  return s;
}

/** Primary endpoint (what older clients read as the whole field). */
export const primaryEndpoint = (raw: string) => parseEndpointField(raw).endpoints[0] ?? '';

/**
 * All makers. getProgramAccounts first (one call); some public RPCs refuse it, so fall back to
 * fetching known maker PDAs (from config) with getMultipleAccountsInfo.
 */
export async function fetchMakers(conn: Connection, pid: PublicKey, knownAuthorities: PublicKey[] = []): Promise<{ makers: P.MakerAccount[]; via: 'registry' | 'known-list' }> {
  try {
    // Both layouts: phase-1 makers (MAKER_LEN) and makers with the platform extension (MAKER_LEN_V2).
    const xs = (await Promise.all(P.MAKER_SIZES.map((n) => conn.getProgramAccounts(pid, { filters: [{ dataSize: n }] })))).flat();
    const makers: P.MakerAccount[] = [];
    for (const x of xs) { try { makers.push(P.decodeMaker(x.account.data, x.pubkey)); } catch { /* not a maker */ } }
    return { makers, via: 'registry' };
  } catch (e) {
    if (!knownAuthorities.length) throw e;
    const pdas = knownAuthorities.map((a) => P.pda.maker(pid, a));
    const infos = await conn.getMultipleAccountsInfo(pdas);
    const makers: P.MakerAccount[] = [];
    infos.forEach((a, i) => { if (a && a.owner.equals(pid)) { try { makers.push(P.decodeMaker(a.data, pdas[i])); } catch { /* skip */ } } });
    return { makers, via: 'known-list' };
  }
}

/**
 * Try each published endpoint until one answers /v1/info for THIS program, cluster and maker
 * authority (an endpoint that claims another identity is skipped, not trusted).
 */
export async function probeEndpoints(m: P.MakerAccount, pid: PublicKey, opts: { timeoutMs?: number; fetchFn?: typeof fetch } = {}): Promise<{ endpoint: string; info: MakerInfo } | null> {
  const f = opts.fetchFn ?? fetch;
  for (const ep of parseEndpointField(m.endpoint).endpoints) {
    try {
      const r = await f(`${ep}/v1/info`, { signal: AbortSignal.timeout(opts.timeoutMs ?? 5000) });
      if (!r.ok) continue;
      const info = await r.json() as MakerInfo;
      if (info.programId !== pid.toBase58() || info.maker !== m.authority.toBase58()) continue;
      return { endpoint: ep, info };
    } catch { /* next endpoint */ }
  }
  return null;
}
