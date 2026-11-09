// coffre on Node before its database opens (`createCoffre`): the pools are
// sized from what the database lets in, read as the process starts, so until
// it answers, health answers without it, and every other request meets the
// outage as it would later (W364, review r1), until a request or a readiness
// probe finds it back (review r2).
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';

import type { VaultEntry } from '@coffre/core/vault';

import { createCoffre, github, signin } from '../src/node.ts';
import { TEST_RUNTIME_DATABASE_URL } from './db/connections.ts';
import { postgresOnly } from './db/engine.ts';
import { closedPort, proxy } from './db/proxy.ts';

const ORIGIN = 'https://secrets.acme.example';
/** A vault none of these requests reaches. */
const vault: VaultEntry = { call: async () => assert.fail('the vault was called') };

const UNOPENED = /has not opened yet/;

test("a database that cannot be reached at start: /livez answers 200, /readyz and the API 503, and none waits for it", async () => {
  const node = createCoffre({
    publicUrl: ORIGIN,
    database: `postgres://coffre_runtime:none@127.0.0.1:${await closedPort()}/coffre`,
    vault,
    auth: signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })] }),
    auditChainKey: randomBytes(32).toString('base64'),
  });
  const ask = async (path: string, method = 'GET') => {
    const request = new Request(`${ORIGIN}${path}`, { method });
    return node.request(request).coffre.route(request);
  };
  const live = await ask('/livez');
  assert.equal(live.status, 200);
  assert.deepEqual(await live.json(), { ok: true });
  assert.equal((await ask('/livez', 'HEAD')).status, 200);
  const ready = await ask('/readyz');
  assert.equal(ready.status, 503);
  assert.equal(((await ready.json()) as { error: string }).error, 'unavailable');
  // Any other request tries the database again, and answers as an outage does.
  const api = await ask('/api/me');
  assert.equal(api.status, 503);
  assert.equal(((await api.json()) as { error: string }).error, 'unavailable');
});

test('a database down at start and back later: readiness probes alone open it, with no other request', postgresOnly('a database to come back to'), async () => {
  const port = await closedPort();
  const url = new URL(TEST_RUNTIME_DATABASE_URL);
  url.host = `127.0.0.1:${port}`;
  const node = createCoffre({
    publicUrl: ORIGIN,
    database: url.href,
    vault: { call: async () => Promise.reject(new Error('no vault here')) },
    auth: signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })] }),
    auditChainKey: randomBytes(32).toString('base64'),
  });
  const readyz = async () => {
    const request = new Request(`${ORIGIN}/readyz`);
    const response = await node.request(request).coffre.route(request);
    return { status: response.status, body: (await response.json()) as { message?: string } };
  };
  const down = await readyz();
  assert.equal(down.status, 503);
  assert.match(down.body.message ?? '', UNOPENED);
  // The first attempt, at start, has failed on the closed port by now: what opens it after is a probe's.
  await new Promise((resolve) => setTimeout(resolve, 500));
  const back = await proxy(port, TEST_RUNTIME_DATABASE_URL);
  try {
    // The first probe after it is back starts the attempt and answers at once; a later one finds it open.
    let answer = await readyz();
    for (let tries = 0; UNOPENED.test(answer.body.message ?? '') && tries < 100; tries += 1) {
      await new Promise((resolve) => setTimeout(resolve, 50));
      answer = await readyz();
    }
    assert.doesNotMatch(answer.body.message ?? '', UNOPENED, 'readiness probes alone never opened the database');
  } finally {
    await back.close();
  }
});
