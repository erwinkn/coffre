// A workload's key-bound session reads no value but a plain one or one its
// binding lists in `reads`, by environment and key ID, where the value is
// held: everything else it uses through coffre (docs/design/workload-access.md,
// section 6.1, `NoLaundering`). Its reads leave the rest out, naming them;
// a reference, a fork or a dry run cannot move or test one either. The
// vault decides the same (packages/vault/test/use-only.test.ts). Until the
// exchange makes them, a workload's caller is built here as it will.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { createClient, type CoffreClient } from '@coffre/client';
import { scopeWithReads } from '@coffre/core/access';
import { and, eq } from 'drizzle-orm';

import { reveal, type PickKeys } from '../src/api/secrets.ts';
import { serveApi } from '../src/api/router.ts';
import { parsePath } from '../src/api/paths.ts';
import type { ApiContext } from '../src/api/context.ts';
import { auditLog, environments, projects, secrets } from './db/tables.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';

const ROOT = 'admin@acme.example';
const API = 'api';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let root: CoffreClient;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  root = clientFor(deps, ROOT);
  await root.projects.create('market');
  for (const path of ['market/prod', 'market/dev']) await root.environments.create(path);
  await root.secrets.set('market/prod', {
    TWILIO_SID: { value: 'AC0123', plain: true },
    STRIPE_SECRET_KEY: 'sk_live_0123',
    STRIPE_WEBHOOK_SECRET: 'whsec_0123',
    DATABASE_URL: { value: 'postgres://prod', sensitivity: 'sensitive' },
  });
  await root.members.add(`token:${API}`);
  await root.access.set(`token:${API}`, { market: 'maintainer' });
});

/** An environment's ID, and a key's there, by path. */
async function ids(path: string): Promise<{ environmentId: string; secretId?: string }> {
  const [project, environment, key] = path.split('/');
  const [row] = await db.owner.select({ id: environments.id }).from(environments).innerJoin(projects, eq(projects.id, environments.projectId))
    .where(and(eq(projects.slug, project!), eq(environments.slug, environment!)));
  if (key === undefined) return { environmentId: row!.id };
  const [secret] = await db.owner.select({ id: secrets.id }).from(secrets).where(and(eq(secrets.environmentId, row!.id), eq(secrets.key, key)));
  return { environmentId: row!.id, secretId: secret!.id };
}

/**
 * `reads` as a binding stores them, by ID: each environment's path with the
 * keys it lists by path, or `'*'`. The IDs are those the keys have now.
 */
async function byId(reads: Record<string, readonly string[] | '*'>): Promise<{ reads: Record<string, { keys: readonly string[] | '*' }>; projectOf: Map<string, string> }> {
  const [market] = await db.owner.select({ id: projects.id }).from(projects).where(eq(projects.slug, 'market'));
  const listed: Record<string, { keys: readonly string[] | '*' }> = {};
  const projectOf = new Map<string, string>();
  for (const [environment, keys] of Object.entries(reads)) {
    const { environmentId } = await ids(environment);
    projectOf.set(environmentId, market!.id);
    listed[environmentId] = { keys: keys === '*' ? '*' : await Promise.all(keys.map(async (key) => (await ids(`${environment}/${key}`)).secretId!)) };
  }
  return { reads: listed, projectOf };
}

/** The handler context of api's workload session, its binding's `reads` materialized onto its scope as the exchange will. */
async function workload(listed: Awaited<ReturnType<typeof byId>>): Promise<ApiContext> {
  const ctx = await contextFor(deps, API, 'service');
  return { ...ctx, caller: { ...ctx.caller, kind: 'workload', credentialScope: scopeWithReads(ctx.caller.credentialScope!, listed.reads, listed.projectOf) } };
}

/** The API as api's workload session sees it. */
function client(listed: Awaited<ReturnType<typeof byId>>): CoffreClient {
  return createClient({ url: 'https://coffre.test', transport: async (request) => serveApi(request, await workload(listed)) });
}

/** What a call answered, or its refusal's status and reason. */
async function outcome<T>(call: Promise<T>): Promise<T | string> {
  try {
    return await call;
  } catch (error) {
    const { status, reason } = error as { status: number; reason?: string };
    return `${status} ${reason ?? ''}`.trim();
  }
}

test('a workload reads plain values and the keys its binding lists; the rest it uses, left out and named', async () => {
  const api = client(await byId({ 'market/prod': ['STRIPE_WEBHOOK_SECRET', 'DATABASE_URL'] }));
  const read = await api.secrets.reveal('market/prod');
  assert.deepEqual(read.values, { DATABASE_URL: 'postgres://prod', STRIPE_WEBHOOK_SECRET: 'whsec_0123', TWILIO_SID: 'AC0123' });
  assert.deepEqual([read.sensitive, read.useOnly], [[], ['STRIPE_SECRET_KEY']]);
  assert.equal(await outcome(api.secrets.reveal('market/prod/STRIPE_SECRET_KEY')), '403 use_only');
  assert.deepEqual((await api.secrets.reveal('market/prod/STRIPE_WEBHOOK_SECRET')).values, { STRIPE_WEBHOOK_SECRET: 'whsec_0123' });

  // Listing nothing, it reads the plain values alone.
  const none = client(await byId({}));
  const bare = await none.secrets.reveal('market/prod');
  assert.deepEqual([bare.values, bare.useOnly], [{ TWILIO_SID: 'AC0123' }, ['DATABASE_URL', 'STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET']]);
  // `'*'` is every key of the place.
  assert.deepEqual(Object.keys((await client(await byId({ 'market/prod': '*' })).secrets.reveal('market/prod')).values).sort(), ['DATABASE_URL', 'STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET', 'TWILIO_SID']);

  // The single read refused is logged, naming the key.
  const [entry] = await db.owner.select({ metadata: auditLog.metadata }).from(auditLog)
    .where(and(eq(auditLog.author, 'app'), eq(auditLog.action, 'secret.read'), eq(auditLog.decision, 'deny')));
  assert.deepEqual(JSON.parse(entry!.metadata), { reason: 'use_only', keys: ['STRIPE_SECRET_KEY'] });
});

test('renaming a key onto a listed name leaves it unreadable: reads list IDs, not names', async () => {
  const api = client(await byId({ 'market/prod': ['STRIPE_WEBHOOK_SECRET'] }));
  await root.secrets.rename('market/prod/STRIPE_WEBHOOK_SECRET', 'STRIPE_WEBHOOK_OLD');
  await root.secrets.rename('market/prod/STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET');
  assert.equal(await outcome(api.secrets.reveal('market/prod/STRIPE_WEBHOOK_SECRET')), '403 use_only');
  assert.deepEqual((await api.secrets.reveal('market/prod/STRIPE_WEBHOOK_OLD')).values, { STRIPE_WEBHOOK_OLD: 'whsec_0123' });
  assert.deepEqual((await api.secrets.reveal('market/prod')).useOnly, ['DATABASE_URL', 'STRIPE_WEBHOOK_SECRET']);
});

test('a reference is read where its value is held: "*" where it lives reads nothing of its source', async () => {
  await root.secrets.set('market/dev', { S: { ref: 'market/prod/STRIPE_SECRET_KEY' }, T: { ref: 'market/prod/TWILIO_SID' } });
  const api = client(await byId({ 'market/dev': '*' }));
  const read = await api.secrets.reveal('market/dev');
  assert.deepEqual([read.values, read.useOnly], [{ T: 'AC0123' }, ['S']]);
  assert.equal(await outcome(api.secrets.reveal('market/dev/S')), '403 use_only');
  assert.deepEqual((await client(await byId({ 'market/dev': '*', 'market/prod': ['STRIPE_SECRET_KEY'] })).secrets.reveal('market/dev/S')).values, { S: 'sk_live_0123' });
});

test('a workload makes no reference to a value it only uses', async () => {
  // "*" at market/dev: a reference there to an unlisted source would hand it the source's value.
  const api = client(await byId({ 'market/dev': '*', 'market/prod': ['STRIPE_WEBHOOK_SECRET'] }));
  assert.equal(await outcome(api.secrets.set('market/dev', { S: { ref: 'market/prod/STRIPE_SECRET_KEY' } })), '403 use_only');
  assert.equal(await outcome(api.secrets.set('market/dev', { D: { ref: 'market/prod/DATABASE_URL' } })), '403 use_only');
  // A plain source is no secret, and a listed one it reads anyway.
  await api.secrets.set('market/dev', { T: { ref: 'market/prod/TWILIO_SID' }, W: { ref: 'market/prod/STRIPE_WEBHOOK_SECRET' } });
  assert.deepEqual((await api.secrets.reveal('market/dev')).values, { T: 'AC0123', W: 'whsec_0123' });
  assert.deepEqual((await root.secrets.list('market/dev')).keys.map((key) => key.key), ['T', 'W']);
});

test('a workload forks only what it reads: a copy would move what it only uses', async () => {
  const api = client(await byId({ 'market/prod': ['STRIPE_WEBHOOK_SECRET'] }));
  assert.equal(await outcome(api.environments.create('market/pr-1', { from: 'prod' })), '403 use_only');
  assert.equal(await outcome(api.environments.create('market/pr-1', { from: 'prod', references: true })), '403 use_only');
  // Nothing was made.
  assert.equal((await db.owner.select().from(environments).where(eq(environments.slug, 'pr-1'))).length, 0);
  // Inheriting copies nothing: its keys are read at their parent, as listed there.
  const inherits = await api.environments.create('market/pr-2', { from: 'prod', inherit: true });
  assert.equal(inherits.forked?.inherits, true);
  const listedAtFork = client(await byId({ 'market/pr-2': '*', 'market/prod': ['STRIPE_WEBHOOK_SECRET'] }));
  assert.deepEqual((await listedAtFork.secrets.reveal('market/pr-2')).useOnly, ['DATABASE_URL', 'STRIPE_SECRET_KEY']);
  // Listing every value it holds, it forks.
  const all = client(await byId({ 'market/prod': '*' }));
  const forked = await all.environments.create('market/pr-3', { from: 'prod' });
  assert.equal(forked.forked?.keys, 4);
});

test("a dry run never tells a workload whether its guess at a value it only uses is right", async () => {
  const api = client(await byId({ 'market/prod': ['STRIPE_WEBHOOK_SECRET'] }));
  const guessed = await api.secrets.dryRun('market/prod', { STRIPE_SECRET_KEY: 'sk_live_0123', STRIPE_WEBHOOK_SECRET: 'whsec_0123', TWILIO_SID: { value: 'AC0123', plain: true } });
  assert.deepEqual(guessed.keys, { STRIPE_SECRET_KEY: 'changed', STRIPE_WEBHOOK_SECRET: 'unchanged', TWILIO_SID: 'unchanged' });
});

test("the proxy uses what a workload only uses, and its plan hands back only what it reads", async () => {
  const ctx = await workload(await byId({ 'market/prod': ['STRIPE_WEBHOOK_SECRET'] }));
  const path = parsePath('market/prod', [2]);
  const used = await reveal(ctx, path, { purpose: 'use', keys: ['STRIPE_SECRET_KEY'], logged: {} });
  assert.deepEqual(used.values, { STRIPE_SECRET_KEY: 'sk_live_0123' });
  let offered: Parameters<PickKeys>[1] = [];
  const plan = await reveal(ctx, path, {
    purpose: 'expose',
    logged: {},
    keys: (_, rows) => {
      offered = rows;
      return rows.filter((row) => row.plain || (row.reads && !row.sensitive)).map((row) => row.key);
    },
  });
  assert.deepEqual(offered.map((row) => [row.key, row.reads]), [['DATABASE_URL', false], ['STRIPE_SECRET_KEY', false], ['STRIPE_WEBHOOK_SECRET', true], ['TWILIO_SID', true]]);
  assert.deepEqual(plan.values, { STRIPE_WEBHOOK_SECRET: 'whsec_0123', TWILIO_SID: 'AC0123' });
  // Asked by name to expose one it only uses, the read is refused whole.
  await assert.rejects(reveal(ctx, path, { purpose: 'expose', keys: ['STRIPE_SECRET_KEY'], logged: {} }), { reason: 'use_only' });
});
