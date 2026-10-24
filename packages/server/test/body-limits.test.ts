// Every request body is read with a byte cap and abandoned past it, so an
// oversize or endless body never buffers and never reaches JSON.parse: the
// unauthenticated device-login endpoints (W155 red-team: a 20 MB body was
// buffered and parsed before validation), the whole authenticated API, and
// the bulk writes' key counts.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { createClient, type CoffreClient } from '@coffre/client';
import { github, signin } from '@coffre/core/identity';

import { coffreRoute } from '../src/app.ts';
import { readJson, readLimitedJson, readLimitedText } from '../src/http.ts';
import { resolveConfig } from '../src/config.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let runtime: CoffreRuntime;
let root: CoffreClient;

before(async () => { db = await openTestDatabase(); });
after(async () => { await db.close(); });

beforeEach(async () => {
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  const config = resolveConfig({
    publicUrl: ORIGIN,
    vault: deps.vault,
    auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })] }),
    auditChainKey: deps.chainKey.toString('base64'),
  });
  runtime = createRuntime(config, deps.db, deps.vault, { json: async () => ({}) });
  deps.signin = runtime.signin!;
  root = clientFor(deps, ROOT);
});

test('readJson abandons an oversize body instead of buffering and parsing it', async () => {
  const big = 'a'.repeat(200 * 1024);
  const request = new Request('https://x/', { method: 'POST', body: JSON.stringify({ v: big }) });
  await assert.rejects(readJson(request, 4 * 1024), /larger than 4096 bytes/);
  // readLimitedText stops reading past the cap too.
  await assert.rejects(readLimitedText(new Request('https://x/', { method: 'POST', body: big }), 1024), /larger than 1024 bytes/);
  // Within the cap, it still parses, and still refuses a __proto__ key.
  assert.deepEqual(await readJson(new Request('https://x/', { method: 'POST', body: '{"a":1}' }), 4 * 1024), { a: 1 });
  await assert.rejects(readJson(new Request('https://x/', { method: 'POST', body: '{"__proto__":1}' }), 4 * 1024), /__proto__/);
});

test('a body is abandoned soon after the cap, not drained to the end', async () => {
  let pulled = 0;
  const endless = new ReadableStream<Uint8Array>({
    pull(controller) {
      pulled += 1;
      controller.enqueue(new Uint8Array(1024).fill(0x61));
    },
  });
  await assert.rejects(readLimitedText(new Request('https://x/', { method: 'POST', body: endless, duplex: 'half' } as RequestInit), 4 * 1024), /larger than 4096 bytes/);
  assert.ok(pulled <= 8, `the stream was abandoned soon after the cap, not drained (pulled ${pulled} chunks)`);
});

test('both unauthenticated device-login endpoints refuse an oversize body', async () => {
  for (const path of ['/api/auth/device', '/api/auth/device/token']) {
    const body = JSON.stringify({ client_label: 'x', device_code: 'a'.repeat(32 * 1024) });
    const response = await coffreRoute(
      new Request(`${ORIGIN}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body }),
      runtime,
      '203.0.113.7',
    );
    assert.equal(response!.status, 400, path);
    assert.match(JSON.stringify(await response!.json()), /larger than 4096 bytes/);
  }
});

test('readLimitedJson refuses a top-level __proto__ key, as readJson does', async () => {
  await assert.rejects(readLimitedJson(new Request('https://x/', { method: 'POST', body: '{"__proto__":1}' }), 1024), /__proto__/);
});

test('an object body names at most MAX_BODY_KEYS entries, refused before validation', async () => {
  await root.projects.create('market');
  await root.environments.create('market/dev');
  const is400 = (error: unknown) => { assert.equal((error as { status: number }).status, 400); return true; };
  // A bulk write over the cap.
  await assert.rejects(root.secrets.set('market/dev', Object.fromEntries(Array.from({ length: 1001 }, (_, i) => [`K${i}`, 'v']))), is400);
  // A dismissal map over the cap, the same guard.
  await assert.rejects(root.environments.dismiss('market/dev', Object.fromEntries(Array.from({ length: 1001 }, (_, i) => [`K${i}`, true as const]))), is400);
  // A write at the cap is accepted.
  await root.secrets.set('market/dev', Object.fromEntries(Array.from({ length: 1000 }, (_, i) => [`K${i}`, 'v'])));
  assert.equal((await root.secrets.list('market/dev')).keys.length, 1000);
});
