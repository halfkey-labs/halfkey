// Offline tests for server-free maker discovery: the registry endpoint field format and the
// endpoint fallback / identity checks.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Keypair } from '@solana/web3.js';
import * as D from './discovery.ts';
import type * as P from './program.ts';

test('endpoint field: single URL stays a single URL (back-compat), multi + posted rate round trip', () => {
  assert.deepEqual(D.parseEndpointField('https://maker.example'), { endpoints: ['https://maker.example'] });
  assert.equal(D.primaryEndpoint('https://maker.example/api/'), 'https://maker.example/api');
  const s = D.formatEndpointField({ endpoints: ['https://a.example', 'http://xyz.onion'], px: 0.171234567, ts: 1_800_000_000 });
  assert.equal(s, 'https://a.example|http://xyz.onion|px=0.171235|ts=1800000000');
  assert.ok(new TextEncoder().encode(s).length <= D.MAX_ENDPOINT_BYTES);
  assert.deepEqual(D.parseEndpointField(s), { endpoints: ['https://a.example', 'http://xyz.onion'], px: 0.171235, ts: 1_800_000_000 });
  // junk tokens ignored, duplicates dropped, at most 4 endpoints
  assert.deepEqual(D.parseEndpointField(' junk https://a.example  https://a.example/ px=-1 ts=x ').endpoints, ['https://a.example']);
  assert.equal(D.parseEndpointField('https://1.x https://2.x https://3.x https://4.x https://5.x').endpoints.length, 4);
  assert.throws(() => D.formatEndpointField({ endpoints: ['https://' + 'a'.repeat(130) + '.example'] }), /128 bytes/);
  assert.throws(() => D.formatEndpointField({ endpoints: ['ftp://a.example'] }), /bad endpoint/);
});

test('probeEndpoints: skips dead and impostor endpoints, returns the first that answers for this maker', async () => {
  const pid = Keypair.generate().publicKey, auth = Keypair.generate().publicKey, other = Keypair.generate().publicKey;
  const m = { authority: auth, endpoint: 'https://dead.example https://impostor.example https://good.example https://late.example' } as P.MakerAccount;
  const seen: string[] = [];
  const fetchFn = (async (url: string) => {
    seen.push(url);
    if (url.startsWith('https://dead')) throw new Error('ECONNREFUSED');
    const maker = url.startsWith('https://impostor') ? other.toBase58() : auth.toBase58();
    return new Response(JSON.stringify({ v: 1, maker, programId: pid.toBase58(), online: true }));
  }) as unknown as typeof fetch;
  const r = await D.probeEndpoints(m, pid, { fetchFn });
  assert.equal(r?.endpoint, 'https://good.example');
  assert.deepEqual(seen, ['https://dead.example/v1/info', 'https://impostor.example/v1/info', 'https://good.example/v1/info']);
  const none = await D.probeEndpoints({ ...m, endpoint: 'https://dead.example' }, pid, { fetchFn });
  assert.equal(none, null);
  // wrong program id is skipped too
  const wrongPid = await D.probeEndpoints({ ...m, endpoint: 'https://good.example' }, Keypair.generate().publicKey, { fetchFn });
  assert.equal(wrongPid, null);
});
