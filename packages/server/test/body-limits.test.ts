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
import { readJson, readLimitedText } from '../src/http.ts';
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

test('the unauthenticated device-login endpoint refuses an oversize body', async () => {
  const body = JSON.stringify({ device_code: 'a'.repeat(32 * 1024) });
  const response = await coffreRoute(
    new Request(`${ORIGIN}/api/auth/device/token`, { method: 'POST', headers: { 'content-type': 'application/json' }, body }),
    runtime,
    '203.0.113.7',
  );
  assert.equal(response!.status, 400);
  assert.match(JSON.stringify(await response!.json()), /larger than 4096 bytes/);
});

test('a bulk secret write names at most MAX_BULK_KEYS keys', async () => {
  await root.projects.create('market');
  await root.environments.create('market/dev');
  const tooMany = Object.fromEntries(Array.from({ length: 1001 }, (_, i) => [`K${i}`, 'v']));
  await assert.rejects(root.secrets.set('market/dev', tooMany), (error: unknown) => {
    const { status } = error as { status: number };
    assert.equal(status, 400);
    return true;
  });
  // A write at the cap is accepted.
  const ok = Object.fromEntries(Array.from({ length: 1000 }, (_, i) => [`K${i}`, 'v']));
  await root.secrets.set('market/dev', ok);
  assert.equal((await root.secrets.list('market/dev')).keys.length, 1000);
});
