// A use by ids the vault refuses before its principal's lock writes nothing in the vault's log (DecideBeforeLock; review
// r2 of D153): the app logs the request, whoever asked for it (`withRefusals`, review r3), a fork's copy and a dry run's
// compare as a reveal does: one entry each, at the use's place and key, with its purpose and the vault's reason. 0.15's
// log alone, where a request's values are uses; on both engines.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { createClient, type CoffreClient } from '@coffre/client';
import { eq } from 'drizzle-orm';

import { coffreRoute } from '../src/app.ts';
import { clientFor, LOG, usesLogged } from './api-fixture.ts';
import { db, deps, entries, ORIGIN, ROOT, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { secrets } from './db/tables.ts';

const skip = LOG === '0.15' ? false : "0.14's reads go through the vault's unwrap, which logs its own refusals";

useMcp(async () => {
  const root = clientFor(deps, ROOT);
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { API_KEY: 'sk_live_0123456789abcdef' });
});

/** The API as whoever `token` is, over coffre's own routes. */
function bearer(token: string): CoffreClient {
  return createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${token}` }), transport: (request) => coffreRoute(request, runtime, '203.0.113.7').then((response) => response!) });
}

/** API_KEY's row, its seal replaced around the log: whoever opens it is refused, and its key is in nobody's set yet. */
const forge = () => db.owner.update(secrets).set({ seal: randomBytes(16) }).where(eq(secrets.key, 'API_KEY'));
const refusals = async () => (await entries('secret.read')).filter((entry) => entry.decision === 'deny');

for (const [what, ask, purpose] of [
  ["a whole environment's read", (owner: CoffreClient) => owner.secrets.reveal('market/dev'), 'run'],
  ["a fork's copy", (owner: CoffreClient) => owner.environments.create('market/copy', { from: 'dev' }), 'copy'],
  ["a dry run's compare", (owner: CoffreClient) => owner.secrets.dryRun('market/dev', { API_KEY: 'sk_live_other_0123456789' }), 'compare'],
] as const) {
  test(`${what} the vault refuses before its principal's lock is logged by the app, once, as the use was and why (review r3 of D153)`, { skip }, async () => {
    const owner = bearer(await sessionFor(ROOT));
    await forge();
    const [denied, logged] = [(await refusals()).length, (await usesLogged(db.owner)).length];
    await assert.rejects(ask(owner), (error: { status?: number }) => error.status === 403);
    const added = (await refusals()).slice(denied);
    assert.equal(added.length, 1, 'one entry of the request');
    assert.deepEqual([added[0]!.actor, added[0]!.metadata.reason, added[0]!.metadata.purpose], [`user:${ROOT}`, 'tampered', purpose]);
    assert.ok(added[0]!.secretId !== null && added[0]!.environmentId !== null, 'at the use\'s place and key');
    assert.equal((await usesLogged(db.owner)).length, logged, "nothing in the vault's log: refused before anything was written");
  });
}

// A read of one key at a fork, inheriting a reference its parent holds: the vault's one call by name (T165), its refusal
// answered as the one `no`, and logged where the key is held, at the holder's place and key (review r5 of D153), as a
// use by ids would be, with the named request's path and key.
test("a fork's read of a reference its parent holds, refused before its principal's lock, is logged at the holder's place and key (review r5 of D153)", { skip }, async () => {
  const root = clientFor(deps, ROOT);
  await root.environments.create('market/holder');
  await root.secrets.set('market/holder', { LINK: { ref: 'market/dev/API_KEY' } });
  await root.environments.create('market/fork', { from: 'holder', inherit: true });
  const [link] = await db.owner.select({ id: secrets.id, environmentId: secrets.environmentId }).from(secrets).where(eq(secrets.key, 'LINK'));
  await db.owner.update(secrets).set({ seal: randomBytes(16) }).where(eq(secrets.key, 'LINK'));
  const owner = bearer(await sessionFor(ROOT));
  const [denied, logged] = [(await refusals()).length, (await usesLogged(db.owner)).length];
  await assert.rejects(owner.secrets.reveal('market/fork/LINK'), (error: { status?: number; code?: string }) => error.status === 404 && error.code === 'not_available');
  const added = (await refusals()).slice(denied);
  assert.equal(added.length, 1, 'one entry of the request');
  assert.deepEqual(
    [added[0]!.environmentId, added[0]!.secretId, added[0]!.metadata.reason, added[0]!.metadata.key],
    [link!.environmentId, link!.id, 'tampered', 'LINK'],
  );
  assert.equal((await usesLogged(db.owner)).length, logged, "nothing in the vault's log: refused before anything was written");
});
