// HALFKEY v1.5 attester: signs "Monero block <height> has id <id> and <n> confirmations" for the
// on-chain payment proofs (program/src/zkproof.rs attest_header). It holds no swap data and no
// view keys. A threshold of compromised signers can certify a fabricated block, so opted-in
// proof claims rely on the committee's honesty; they are not a Monero light-client proof.
//
// Fail-closed rule: sign only if at least two independent monerods return the SAME block id at
// that height and each reports at least `minConf` confirmations; the confirmations signed are the
// smallest any node reported.
//
//   node watchtower/attester.ts attester.json
//   { "keypair": "/secure/attester.json", "nodes": ["http://a:18081", "http://b:18081"], "net": "mainnet",
//     "minConf": 10, "port": 7951 }
// GET /v1/attest?height=N[&conf=C] -> { height, blockId, confirmations, net, pubkey, signature } (hex)
import fs from 'node:fs';
import http from 'node:http';
import { ed25519 } from '@noble/curves/ed25519';
import * as K from '../sdk/keys.ts';
import { headerMessage, MONERO_NET } from '../sdk/v15.ts';
import { clientIp, RateWindow } from '../maker/policy.ts';

export interface AttestConfig { nodes: string[]; net: keyof typeof MONERO_NET; minConf: number; secret: Uint8Array; fetchImpl?: typeof fetch }
export interface Attestation { height: number; blockId: string; confirmations: number; net: number; pubkey: string; signature: string }

async function rpc(f: typeof fetch, uri: string, method: string, params: unknown) {
  const r = await f(`${uri.replace(/\/$/, '')}/json_rpc`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: '0', method, params }), signal: AbortSignal.timeout(15_000) });
  const j: any = await r.json();
  if (j.error) throw new Error(`${method}: ${j.error.message}`);
  return j.result;
}

/** One node's view of a height: block id and confirmations (tip - height + 1). */
export async function nodeView(f: typeof fetch, uri: string, height: number) {
  const h = await rpc(f, uri, 'get_block_header_by_height', { height });
  const count = Number((await rpc(f, uri, 'get_block_count', {})).count);
  const id = String(h.block_header.hash);
  if (!/^[0-9a-f]{64}$/.test(id)) throw new Error('bad block id');
  if (h.block_header.orphan_status) throw new Error('orphaned block');
  if (h.block_header.height !== undefined && h.block_header.height !== height) throw new Error('wrong block height');
  if (!Number.isSafeInteger(count) || count <= height) throw new Error('invalid block count');
  return { id, confirmations: count - height };
}

/**
 * `conf` (optional): sign exactly this many confirmations (callers collecting a threshold need
 * every signature over the same message), only if every node reports at least that many.
 */
export async function attestHeight(cfg: AttestConfig, height: number, conf?: number): Promise<Attestation> {
  if (!Number.isSafeInteger(height) || height < 1) throw new Error('bad height');
  const nodes = [...new Set(cfg.nodes.map((n) => new URL(n).href.replace(/\/$/, '')))];
  if (nodes.length < 2) throw new Error('need 2 distinct node URLs');
  const f = cfg.fetchImpl ?? fetch;
  const views = (await Promise.allSettled(nodes.map((n) => nodeView(f, n, height)))).flatMap((r) => (r.status === 'fulfilled' ? [r.value] : []));
  if (views.length < 2) throw new Error(`need 2 nodes to agree, ${views.length} answered`);
  if (!views.every((v) => v.id === views[0].id)) throw new Error('nodes disagree on the block at this height');
  const seen = Math.min(...views.map((v) => v.confirmations));
  const confirmations = conf ?? seen;
  if (!Number.isSafeInteger(confirmations) || confirmations > seen) throw new Error(`only ${seen} confirmations`);
  if (confirmations < cfg.minConf) throw new Error(`only ${confirmations} confirmations`);
  const net = MONERO_NET[cfg.net];
  const msg = headerMessage(net, height, K.fromHex(views[0].id), confirmations);
  return { height, blockId: views[0].id, confirmations, net, pubkey: K.toHex(ed25519.getPublicKey(cfg.secret)), signature: K.toHex(ed25519.sign(msg, cfg.secret)) };
}

/** Client side: check an attestation before using it (the program re-checks everything). */
export function checkAttestation(a: Attestation, want: { net: number; height: number; blockId: string; keys: string[] }): boolean {
  if (a.net !== want.net || a.height !== want.height || a.blockId !== want.blockId || !want.keys.includes(a.pubkey)) return false;
  try {
    return ed25519.verify(K.fromHex(a.signature), headerMessage(a.net, a.height, K.fromHex(a.blockId), a.confirmations), K.fromHex(a.pubkey));
  } catch { return false; }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const c = JSON.parse(fs.readFileSync(process.argv[2] ?? 'watchtower/attester.json', 'utf8'));
  const secret = Uint8Array.from(JSON.parse(fs.readFileSync(c.keypair, 'utf8'))).slice(0, 32);
  const cfg: AttestConfig = { nodes: c.nodes, net: c.net, minConf: Math.max(10, c.minConf ?? 10), secret };
  // Recheck the nodes for every response: a pinned confirmation count does not make a block
  // permanent. An indefinite signature cache would keep serving an orphan after a reorg.
  const rate = new RateWindow(c.perIpPerMin ?? 60, 60_000);
  setInterval(() => { rate.sweep(); }, 60_000).unref();
  http.createServer(async (req, res) => {
    const u = new URL(req.url ?? '/', 'http://x');
    res.setHeader('content-type', 'application/json');
    res.setHeader('access-control-allow-origin', '*');
    if (u.pathname !== '/v1/attest') { res.statusCode = 404; res.end('{}'); return; }
    if (!rate.take(clientIp(req, c.trustProxy))) { res.statusCode = 429; res.end('{"error":"too many requests"}'); return; }
    try {
      const conf = u.searchParams.get('conf');
      const a = await attestHeight(cfg, Number(u.searchParams.get('height')), conf === null ? undefined : Number(conf));
      res.end(JSON.stringify(a));
    } catch (e) {
      res.statusCode = 409;
      res.end(JSON.stringify({ error: String((e as Error).message) }));
    }
  }).listen(c.port ?? 7951, '127.0.0.1');
  console.log(`attester ${K.toHex(ed25519.getPublicKey(secret))} on :${c.port ?? 7951} (${cfg.nodes.length} nodes, min ${cfg.minConf} conf)`);
}
