// A credential's egress in workerd, as on Cloudflare: its requests leave
// through a binding, here a service binding to the Worker itself in place of
// a VPC Service's, which local workerd cannot run. The binding is handed the
// URL and init the proxy made, and what it answers goes back to the app as
// an upstream's: a redirect kept on the proxy, an upload streamed, never
// held whole. A binding the Worker lacks fails the configuration. And a
// workload's body that declares its Content-Digest streams out of workerd to
// an upstream on this machine, which gets it whole only if it is that digest.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { unstable_dev, type Unstable_DevWorker } from 'wrangler';

import { contentDigest } from '@coffre/client/dpop';

const HANDLE = `coffre_use_${'h'.repeat(43)}`;
const NAME = 'coffre-egress-workers-test';

let dir: string;
let worker: Unstable_DevWorker;
/** The upstream on this machine: each request it got whole, and how much it got of each it did not. */
let upstream: Server;
const whole: { headers: IncomingHttpHeaders; length: number; sha256: string }[] = [];
const broken: number[] = [];

before(async () => {
  upstream = createServer((request, response) => {
    const hash = createHash('sha256');
    let length = 0;
    request.on('data', (chunk: Buffer) => (hash.update(chunk), (length += chunk.length)));
    request.on('close', () => void (request.complete || broken.push(length)));
    request.on('end', () => {
      whole.push({ headers: request.headers, length, sha256: hash.digest('hex') });
      response.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}');
    });
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  dir = mkdtempSync(join(tmpdir(), 'coffre-egress-worker-'));
  writeFileSync(
    join(dir, 'wrangler.json'),
    JSON.stringify({
      name: NAME,
      compatibility_date: '2026-08-06',
      compatibility_flags: ['nodejs_compat'],
      services: [{ binding: 'EGRESS', service: NAME }],
      vars: { UPSTREAM: `http://127.0.0.1:${(upstream.address() as AddressInfo).port}/v3` },
    }),
  );
  // Bundled from the packages' sources, as the tests read them.
  process.env.WRANGLER_BUILD_CONDITIONS = 'coffre:source,workerd,worker,browser';
  worker = await unstable_dev(fileURLToPath(new URL('./workers/egress-worker.ts', import.meta.url)), {
    config: join(dir, 'wrangler.json'),
    local: true, ip: '127.0.0.1', port: 0, inspectorPort: 0, persist: false, logLevel: 'error',
    experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
  });
}, { timeout: 120_000 });

after(async () => {
  await worker?.stop();
  rmSync(dir, { recursive: true, force: true });
  upstream.closeAllConnections();
  upstream.close();
});

test('a request leaves through the binding with the real key, and its redirect stays on the proxy', { timeout: 30_000 }, async () => {
  const sent = await worker.fetch('/use/schumann/companies?q=acme', { method: 'POST', headers: { 'x-api-key': HANDLE, 'content-type': 'application/json' }, body: '{"siren":"123"}' });
  assert.equal(sent.status, 200);
  assert.deepEqual(await sent.json(), { url: 'https://dev.api.europ.schuman.io/companies?q=acme', method: 'POST', key: true, signed: false, contentLength: '15', length: 15 });
  // The binding answers the 3xx as it is, not followed: the proxy makes it its own URL for it.
  const moved = await worker.fetch('/use/schumann/moved', { headers: { 'x-api-key': HANDLE }, redirect: 'manual' });
  assert.equal(moved.status, 302);
  assert.equal(moved.headers.get('location'), 'https://secrets.acme.example/use/market/dev/schumann/companies?page=2');
});

test('an AWS-signed upload past the 16 MiB a body is held to streams through the binding, signed again with the real key', { timeout: 60_000 }, async () => {
  const size = 24 * 1024 * 1024;
  const put = await worker.fetch('/use/s3/bucket/object', {
    method: 'PUT',
    headers: {
      authorization: `AWS4-HMAC-SHA256 Credential=${HANDLE}/20261020/eu-west-3/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=${'0'.repeat(64)}`,
      'x-amz-content-sha256': 'UNSIGNED-PAYLOAD',
      'x-amz-date': '20261020T000000Z',
      'content-length': String(size),
    },
    body: new Uint8Array(size),
  });
  assert.equal(put.status, 200);
  assert.deepEqual(await put.json(), { url: 'https://s3.eu-west-3.amazonaws.com/bucket/object', method: 'PUT', key: false, signed: true, contentLength: String(size), length: size });
});

test('a binding the Worker lacks, undefined in its env, fails the configuration', { timeout: 30_000 }, async () => {
  const missing = await worker.fetch('/use/schumann/companies?missing', { headers: { 'x-api-key': HANDLE } });
  assert.equal(missing.status, 500);
  assert.match(await missing.text(), /schumann's egress is undefined, as a Worker's binding is when wrangler\.jsonc lacks it/);
});

test("a workload's 55 MB document that declares its Content-Digest streams out of workerd whole, with its length; other bytes never arrive whole", { timeout: 120_000 }, async () => {
  const body = randomBytes(55_000_000);
  const sha256 = createHash('sha256').update(body).digest('hex');
  // Straight to workerd, as Cloudflare's edge hands a Worker a request, with its content-length: `worker.fetch` sends any body chunked.
  const send = (bytes: Uint8Array<ArrayBuffer>) =>
    fetch(`http://${worker.address}:${worker.port}/use/yousign/documents`, {
      method: 'POST',
      headers: { authorization: `DPoP coffre_wl_${'t'.repeat(43)}`, dpop: 'checked on Node', 'content-type': 'application/pdf', 'content-digest': contentDigest(sha256), 'x-dropped': 'not signed' },
      body: bytes,
    });
  const sent = await send(body);
  assert.equal(sent.status, 200, await sent.text());
  assert.deepEqual([whole.at(-1)!.length, whole.at(-1)!.sha256], [body.length, sha256]);
  assert.equal(whole.at(-1)!.headers['content-length'], String(body.length), 'the length goes with it (FixedLengthStream)');
  assert.equal(whole.at(-1)!.headers['content-digest'], contentDigest(sha256));
  assert.equal(whole.at(-1)!.headers['x-dropped'], undefined);
  assert.equal(whole.at(-1)!.headers.authorization, 'Bearer sk_schumann_real_0123456789abcdef');
  // The same length, one bit else: refused once all of it has passed, and the upstream, cut off before its last byte, has none of it whole.
  const tampered = Buffer.from(body);
  tampered[body.length >> 1]! ^= 1;
  const refused = await send(tampered);
  assert.deepEqual([refused.status, ((await refused.json()) as { message: string }).message], [400, 'the body is not what its Content-Digest says']);
  for (let waited = 0; broken.length === 0 && waited < 5000; waited += 10) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(whole.length, 1);
  assert.equal(broken.length, 1);
  assert.ok(broken[0]! < body.length, `the upstream got ${broken[0]} bytes of ${body.length}`);
});
