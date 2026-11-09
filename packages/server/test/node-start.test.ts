// coffre on Node before its database opens (`createCoffre`): the pools are
// sized from what the database lets in, read as the process starts, so until
// it answers, health answers without it, and every other request meets the
// outage as it would later (W364, review r1).
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:net';
import { test } from 'node:test';

import type { VaultEntry } from '@coffre/core/vault';

import { createCoffre, github, signin } from '../src/node.ts';

const ORIGIN = 'https://secrets.acme.example';
/** A vault none of these requests reaches. */
const vault: VaultEntry = { call: async () => assert.fail('the vault was called') };

/** A port nothing listens on: one the system gave, closed again. */
async function closedPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as { port: number };
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

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
