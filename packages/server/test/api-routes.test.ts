import test, { after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { asc, eq } from 'drizzle-orm';

import { auditLog } from './db/tables.ts';
import { serveApi } from '../src/api/router.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, testDeps } from './api-fixture.ts';

const ROOT = 'admin@acme.example';
const DEV = 'dev@acme.example';
const LEAD = 'lead@acme.example';

const db = await openTestDatabase();
const deps = testDeps(db.runtime, [ROOT]);
const root = clientFor(deps, ROOT);
const dev = clientFor(deps, DEV);
const lead = clientFor(deps, LEAD);

/** A request the client would never send, straight to the router. */
async function raw(method: string, path: string, body?: unknown): Promise<Response> {
  const request = new Request(`https://coffre.test/api${path}`, {
    method,
    headers: body === undefined ? {} : { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return serveApi(request, await contextFor(deps, ROOT));
}

/** The log's actions, the app's and the vault's. */
async function actions(): Promise<string[]> {
  const rows = await db.owner
    .select({ action: auditLog.action, decision: auditLog.decision })
    .from(auditLog)
    .orderBy(asc(auditLog.seq));
  return rows.map((row) => `${row.decision} ${row.action}`);
}

async function grantsAt(member: string, place: string) {
  const { members } = await root.members.list(place);
  return members.find((entry) => entry.member === member)?.grants ?? [];
}

after(() => db.close());

beforeEach(async () => {
  await resetDatabase(db.owner);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/dev', { name: 'Dev' });
  await root.environments.create('market/prod', { name: 'Prod' });
  await root.members.add(`user:${DEV}`);
  await root.members.add(`user:${LEAD}`);
});

// --- merge patches ------------------------------------------------------------

test('a secrets patch writes the keys it names, archives the nulls, and leaves the rest alone', async () => {
  await root.secrets.set('market/prod', { A: '1', B: '2', C: '3' });
  const { keys } = await root.secrets.set('market/prod', { A: null, B: '2b', D: '4' });
  assert.deepEqual(keys, { A: { archived: true }, B: { version: 2 }, D: { version: 1 } });

  const listed = await root.secrets.list('market/prod');
  const byKey = Object.fromEntries(listed.keys.map((entry) => [entry.key, entry]));
  assert.equal(byKey.A.archived, true);
  assert.equal(byKey.B.version, 2);
  assert.equal(byKey.C.version, 1);
  assert.equal(byKey.C.archived, false);
  assert.deepEqual(Object.keys((await root.secrets.reveal('market/prod')).values).sort(), ['B', 'C', 'D']);
});

test('a null needs secret.archive, and a refused patch writes none of its keys', async () => {
  await root.secrets.set('market/prod', { A: '1', B: '2' });
  await root.access.set(`user:${DEV}`, { 'market/prod': 'developer' });

  await assert.rejects(dev.secrets.set('market/prod', { B: 'changed', A: null }), { status: 403 });
  const { values } = await root.secrets.reveal('market/prod');
  assert.deepEqual({ ...values }, { A: '1', B: '2' });
  assert.ok((await actions()).includes('deny secret.write'));

  // Writing alone is within the role.
  assert.deepEqual((await dev.secrets.set('market/prod', { B: 'changed' })).keys, { B: { version: 2 } });
});

test('a place patch changes only the fields it names', async () => {
  await root.projects.update('market', { name: 'Marketplace' });
  await root.projects.update('market', { archived: true });
  const [project] = (await root.projects.list()).projects;
  assert.equal(project.slug, 'market');
  assert.equal(project.name, 'Marketplace');
  assert.notEqual(project.archivedAt, null);

  await root.projects.update('market', { archived: false });
  assert.equal((await root.projects.list()).projects[0].name, 'Marketplace');
});

test('a patch with a field the route does not know is refused', async () => {
  const response = await raw('PATCH', '/projects/market', { name: 'M', owner: 'someone' });
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, 'bad_request');
});

// --- declarative access -------------------------------------------------------

test('access says what someone should hold; sending it again changes nothing', async () => {
  const member = `user:${DEV}`;
  const wanted = { market: 'viewer', 'market/prod': 'developer' } as const;
  assert.deepEqual((await root.access.set(member, wanted)).changes, {
    market: 'created',
    'market/prod': 'created',
  });
  const logged = (await actions()).length;

  assert.deepEqual((await root.access.set(member, wanted)).changes, {
    market: 'unchanged',
    'market/prod': 'unchanged',
  });
  assert.equal((await actions()).length, logged, 'an unchanged grant is not logged');

  // A place left out is left alone; null revokes.
  assert.deepEqual((await root.access.set(member, { market: null })).changes, { market: 'revoked' });
  assert.deepEqual(
    (await grantsAt(member, 'market')).map((grant) => `${grant.environment}:${grant.role}`),
    ['prod:developer'],
  );
});

test('access applies all of its places or none', async () => {
  await assert.rejects(
    root.access.set(`user:${DEV}`, { market: 'viewer', 'market/nowhere': 'viewer' }),
    { status: 404 },
  );
  assert.deepEqual(await grantsAt(`user:${DEV}`, 'market'), []);

  await assert.rejects(
    root.access.set(`user:${DEV}`, { 'market/dev': 'viewer', 'market/prod': 'owner' }),
    { status: 409 },
  );
  assert.deepEqual(await grantsAt(`user:${DEV}`, 'market'), []);
});

test('managing access needs grant.manage on each place named', async () => {
  await root.projects.create('billing', { name: 'Billing' });
  await root.access.set(`user:${LEAD}`, { market: 'access-manager' });

  assert.deepEqual((await lead.access.set(`user:${DEV}`, { market: 'viewer' })).changes, { market: 'created' });
  await assert.rejects(lead.access.set(`user:${DEV}`, { market: null, billing: 'viewer' }), { status: 403 });
  assert.equal((await grantsAt(`user:${DEV}`, 'market')).length, 1, 'the refused patch revoked nothing');
});

// --- one role per place -------------------------------------------------------

test('someone holds at most one role per place; a new role replaces the old', async () => {
  const member = `user:${DEV}`;
  await root.access.set(member, { 'market/prod': 'viewer' });
  assert.deepEqual((await root.access.set(member, { 'market/prod': 'developer' })).changes, {
    'market/prod': 'updated',
  });

  const held = await grantsAt(member, 'market/prod');
  assert.deepEqual(held.map((grant) => grant.role), ['developer']);
  // The vault's: the viewer grant, then the developer one in its place.
  assert.deepEqual((await actions()).filter((action) => action.includes('access.')).slice(-2), [
    'allow access.grant',
    'allow access.grant',
  ]);

  // A project grant and an environment grant are two places, not two roles at one.
  await root.access.set(member, { market: 'viewer' });
  assert.equal((await grantsAt(member, 'market')).length, 2);
});

test('an access patch names each place once', async () => {
  const response = await raw('PATCH', `/access/${encodeURIComponent(`user:${DEV}`)}`, {
    'market/prod': 'viewer',
    'market/prod/': 'developer',
  });
  assert.equal(response.status, 400);
  assert.deepEqual(await grantsAt(`user:${DEV}`, 'market'), []);
});

// --- reveal only by POST ------------------------------------------------------

test('values leave only through POST /reveals, and each one is logged', async () => {
  await root.secrets.set('market/prod', { DATABASE_URL: 'postgres://secret-value' });

  const reveals = await raw('GET', '/reveals?path=market/prod');
  assert.equal(reveals.status, 405);
  assert.equal(reveals.headers.get('allow'), 'POST');

  for (const path of ['/secrets/market/prod', '/secrets/market/prod/DATABASE_URL/versions', '/audit']) {
    const response = await raw('GET', path);
    assert.equal(response.status, 200, path);
    assert.doesNotMatch(await response.text(), /secret-value/, path);
  }

  const before = (await actions()).filter((action) => action === 'allow secret.read').length;
  const revealed = await root.secrets.reveal('market/prod/DATABASE_URL');
  assert.deepEqual({ ...revealed.values }, { DATABASE_URL: 'postgres://secret-value' });
  const logged = await db.owner
    .select({ operationId: auditLog.operationId })
    .from(auditLog)
    .where(eq(auditLog.action, 'secret.read'));
  assert.equal(logged.length, before + 1);
  assert.equal(logged.at(-1)?.operationId, revealed.operationId);
});

test('a reveal names an environment or a secret, nothing wider', async () => {
  await assert.rejects(root.secrets.reveal('market'), { status: 400 });
  await assert.rejects(root.secrets.reveal('market/prod/A/B'), { status: 400 });
});

// --- path depth ---------------------------------------------------------------

test('each segment is one level: …/prod/versions is a secret named versions', async () => {
  await root.secrets.set('market/prod', { versions: 'v1' });
  await root.secrets.set('market/prod', { versions: 'v2' });

  // Four levels name the secret; its history is one level further down.
  const history = await root.secrets.history('market/prod/versions');
  assert.deepEqual(history.versions.map((version) => version.version), [2, 1]);

  await root.secrets.rename('market/prod/versions', 'RENAMED');
  assert.deepEqual((await root.secrets.list('market/prod')).keys.map((entry) => entry.key), ['RENAMED']);

  // `/secrets/market/prod/versions` is a secret's address: there is no GET on it.
  const response = await raw('GET', '/secrets/market/prod/versions');
  assert.equal(response.status, 405);
  assert.equal(response.headers.get('allow'), 'PATCH');
});

test('removed sync routes cannot be called', async () => {
  for (const [method, path] of [
    ['GET', '/syncs/providers'], ['GET', '/syncs/market/prod'],
    ['POST', '/syncs/market/prod'], ['PATCH', '/syncs/by-id/00000000-0000-4000-8000-000000000001'],
    ['DELETE', '/syncs/by-id/00000000-0000-4000-8000-000000000001'], ['POST', '/syncs/by-id/00000000-0000-4000-8000-000000000001/runs'],
  ]) assert.equal((await raw(method, path)).status, 404);
  assert.equal((await raw('PATCH', '/access/sync:00000000-0000-4000-8000-000000000001', { 'market/prod': 'viewer' })).status, 400);
});

test('unknown places are 404 and are not logged', async () => {
  const logged = (await actions()).length;
  await assert.rejects(root.secrets.list('market/nowhere'), { status: 404 });
  await assert.rejects(root.secrets.history('market/prod/NOPE'), { status: 404 });
  await assert.rejects(root.secrets.list('nowhere/prod'), { status: 404 });
  assert.equal((await actions()).length, logged);
});

test('every error has the same shape', async () => {
  for (const [method, path, status] of [
    ['GET', '/nothing/here', 404],
    ['DELETE', '/me', 405],
    ['GET', '/secrets/Not A Slug/prod', 400],
  ] as const) {
    const response = await raw(method, path);
    assert.equal(response.status, status, path);
    const body = await response.json();
    assert.deepEqual(Object.keys(body).sort(), ['error', 'message'], path);
  }
});
