import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { asc, eq } from 'drizzle-orm';

import { auditLog, secrets, syncs } from './db/tables.ts';
import {
  resolveSyncProviders,
  SyncConfigError,
  SyncProviderError,
  type SyncPlan,
  type SyncProvider,
} from '../src/sync/index.ts';
import { planSync, SyncRunner } from '../src/api/syncs.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';
import { actorParts } from '../src/db/audit.ts';

const ROOT = 'admin@acme.example';
const DEV = 'dev@acme.example';
const LEAD = 'lead@acme.example';
const CREDENTIAL = 'ops/sync/DEST_TOKEN';

// --- a destination that lives in memory ---------------------------------------

type FakeConfig = { target: string };

class FakeDestination {
  values = new Map<string, string>();
  tokens: string[] = [];
  applied: SyncPlan[] = [];
  failKeys = new Set<string>();
  outage: SyncProviderError | null = null;

  provider: SyncProvider<FakeConfig> = {
    id: 'fake',
    label: 'Fake',
    brand: 'other',
    fields: [{ type: 'text', name: 'target', label: 'Target', placeholder: 'app' }],
    credential: { placeholder: 'ops/sync/DEST_TOKEN', hint: 'Any token will do.' },
    parseConfig: (input) => {
      const target = (input as { target?: unknown } | null)?.target;
      if (typeof target !== 'string' || target === '') throw new SyncConfigError('Fake: target is required');
      return { target };
    },
    describe: (config) => `fake:${config.target}`,
    checkKey: (key) =>
      key.startsWith('RESERVED_') ? { ok: false, reason: 'names starting with RESERVED_ are taken' } : { ok: true },
    listKeys: async (ctx) => {
      this.tokens.push(ctx.token);
      if (this.outage) throw this.outage;
      return [...this.values.keys()];
    },
    apply: async (ctx, _config, plan) => {
      this.tokens.push(ctx.token);
      this.applied.push(plan);
      const result = { upserted: [] as string[], deleted: [] as string[], failed: [] as { key: string; operation: 'upsert' | 'delete'; message: string }[] };
      for (const { key, value } of plan.upsert) {
        if (this.failKeys.has(key)) {
          result.failed.push({ key, operation: 'upsert', message: 'value is too large' });
          continue;
        }
        this.values.set(key, value);
        result.upserted.push(key);
      }
      for (const key of plan.delete) {
        this.values.delete(key);
        result.deleted.push(key);
      }
      return result;
    },
  };
}

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let runner: SyncRunner;
let destination: FakeDestination;
let root: ReturnType<typeof clientFor>;
let developer: ReturnType<typeof clientFor>;
let maintainer: ReturnType<typeof clientFor>;
const background: Promise<unknown>[] = [];

/** Let every run the API started in the background finish. */
async function settle() {
  while (background.length > 0) await Promise.all(background.splice(0));
}

before(async () => {
  db = await openTestDatabase();
  deps = testDeps(db.runtime, [ROOT], { waitUntil: (promise) => void background.push(promise) });
  root = clientFor(deps, ROOT);
  developer = clientFor(deps, DEV);
  maintainer = clientFor(deps, LEAD);
});

after(async () => {
  await settle();
  await resetDatabase(db.owner);
  await db.close();
});

beforeEach(async () => {
  await settle();
  destination = new FakeDestination();
  // Each test gets a destination of its own, so a runner of its own that offers it.
  runner = new SyncRunner({ ...deps, providers: resolveSyncProviders([destination.provider]) });
  deps.syncs = runner;
  await resetDatabase(db.owner);
  await root.members.add(`user:${DEV}`);
  await root.members.add(`user:${LEAD}`);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/prod', { name: 'Production' });
  await root.projects.create('ops', { name: 'Ops' });
  await root.environments.create('ops/sync', { name: 'Sync credentials' });
  await root.access.set(`user:${DEV}`, { market: 'developer' });
  await root.access.set(`user:${LEAD}`, { market: 'maintainer' });
  await root.secrets.set('ops/sync', { DEST_TOKEN: 'token-v1' });
  await root.secrets.set('market/prod', { API_KEY: 'api-1', DB_URL: 'postgres://db' });
  await settle();
});

async function createSync(client = root) {
  const view = await client.syncs.add('market/prod', {
    provider: 'fake',
    config: { target: 'app' },
    credential: CREDENTIAL,
  });
  await settle();
  return view;
}

async function auditActions(action: string) {
  const rows = await db.owner
    .select({
      actor: auditLog.actor,
      decision: auditLog.decision,
      environmentId: auditLog.environmentId,
      secretId: auditLog.secretId,
      metadata: auditLog.metadata,
    })
    .from(auditLog)
    .where(eq(auditLog.action, action))
    .orderBy(asc(auditLog.seq));
  return rows.map(({ actor, ...row }) => ({
    ...actorParts(actor),
    ...row,
    metadata: JSON.parse(row.metadata) as Record<string, unknown>,
  }));
}

async function view(id: string) {
  const listed = await root.syncs.list('market/prod');
  const found = listed.syncs.find((sync) => sync.id === id);
  assert.ok(found, 'sync is listed');
  return found;
}

// --- planning -----------------------------------------------------------------

test('the plan compares versions, so only what changed is pushed', () => {
  const ok = () => ({ ok: true as const });
  const plan = planSync({
    desired: [
      { key: 'API_KEY', secretId: 's1', versionId: 'v7' },
      { key: 'DB_URL', secretId: 's2', versionId: 'v3' },
      { key: 'NEW_FLAG', secretId: 's3', versionId: 'v1' },
    ],
    recorded: [
      { key: 'API_KEY', versionId: 'v6' },
      { key: 'DB_URL', versionId: 'v3' },
      { key: 'OLD_KEY', versionId: 'v2' },
    ],
    checkKey: ok,
  });
  assert.deepEqual(plan.upsert.map((entry) => entry.key), ['API_KEY', 'NEW_FLAG']);
  assert.deepEqual(plan.delete, ['OLD_KEY']);
  assert.equal(plan.inSync, 1);
});

test('with the destination’s key list, missing keys are pushed again and gone ones forgotten', () => {
  const plan = planSync({
    desired: [{ key: 'DB_URL', secretId: 's2', versionId: 'v3' }],
    recorded: [
      { key: 'DB_URL', versionId: 'v3' },
      { key: 'OLD_KEY', versionId: 'v2' },
    ],
    remote: new Set(),
    checkKey: () => ({ ok: true }),
  });
  assert.deepEqual(plan.upsert.map((entry) => entry.key), ['DB_URL']);
  assert.deepEqual(plan.delete, []);
  assert.deepEqual(plan.forget, ['OLD_KEY']);
});

test('keys the destination cannot hold are skipped with its reason', () => {
  const plan = planSync({
    desired: [{ key: 'github_token', secretId: 's', versionId: 'v' }],
    recorded: [],
    checkKey: () => ({ ok: false, reason: 'upper case only' }),
  });
  assert.deepEqual(plan.upsert, []);
  assert.deepEqual(plan.skipped, [{ key: 'github_token', reason: 'upper case only' }]);
});

// --- creating -----------------------------------------------------------------

test('creating a sync pushes the environment with the credential, and never the credential itself', async () => {
  await root.secrets.set('market/prod', { RESERVED_NAME: 'x' });
  await settle();
  const created = await createSync();

  assert.deepEqual(Object.fromEntries(destination.values), { API_KEY: 'api-1', DB_URL: 'postgres://db' });
  assert.ok(destination.tokens.every((token) => token === 'token-v1'));

  const listed = await view(created.id);
  assert.equal(listed.destination, 'fake:app');
  assert.equal(listed.credential, CREDENTIAL);
  assert.equal(listed.lastStatus, 'ok');
  assert.equal(listed.running, false);
  assert.equal(listed.synced, 2);
  assert.equal(listed.pending, 0);
  assert.deepEqual(listed.skipped, [{ key: 'RESERVED_NAME', reason: 'names starting with RESERVED_ are taken' }]);
});

test('each pushed value is audited, and opening the credential is filed under the credential', async () => {
  const created = await createSync();

  const pushes = await auditActions('sync.push');
  assert.deepEqual(pushes.map((row) => row.metadata.key).sort(), ['API_KEY', 'DB_URL']);
  assert.ok(pushes.every((row) => row.actorType === 'system' && row.actorId === `sync:${created.id}`));
  assert.ok(pushes.every((row) => row.metadata.destination === 'fake:app' && row.metadata.trigger === 'create'));

  const [run] = await auditActions('sync.run');
  const [credential] = await db.owner
    .select({ id: secrets.id, environmentId: secrets.environmentId })
    .from(secrets)
    .where(eq(secrets.key, 'DEST_TOKEN'));
  assert.equal(run.secretId, credential.id);
  assert.equal(run.environmentId, credential.environmentId);
  assert.equal(run.metadata.source, 'market/prod');

  const [creation] = await auditActions('sync.create');
  assert.equal(creation.actorId, ROOT);
  assert.equal(creation.metadata.credential, CREDENTIAL);
});

test('creating a sync needs environment.manage and secret.read, and a refusal is logged', async () => {
  await assert.rejects(createSync(developer), { status: 403 });
  const [denied] = await auditActions('sync.create');
  assert.equal(denied.decision, 'deny');
  assert.equal(denied.metadata.reason, 'missing_environment_manage');
  assert.equal(destination.applied.length, 0);
});

test('a credential the creator cannot read is refused like one that does not exist', async () => {
  // The maintainer manages market but has no grant on ops.
  await assert.rejects(createSync(maintainer), {
    status: 400,
    message: `${CREDENTIAL} is not a secret you can read`,
  });
  await assert.rejects(
    root.syncs.add('market/prod', { provider: 'fake', config: { target: 'app' }, credential: 'ops/sync/NOPE' }),
    { status: 400, message: 'ops/sync/NOPE is not a secret you can read' },
  );
});

test('a member sees where this instance can sync to, and what each asks for', async () => {
  assert.deepEqual(await developer.syncs.providers(), {
    providers: [
      {
        id: 'fake',
        label: 'Fake',
        brand: 'other',
        fields: [{ type: 'text', name: 'target', label: 'Target', placeholder: 'app' }],
        credential: { placeholder: 'ops/sync/DEST_TOKEN', hint: 'Any token will do.' },
      },
    ],
  });
});

test('unknown providers and bad configs are refused with a message for the caller', async () => {
  // github-actions is built in, but this deployment does not list it.
  for (const provider of ['dropbox', 'github-actions', 'toString']) {
    await assert.rejects(
      root.syncs.add('market/prod', { provider, config: {}, credential: CREDENTIAL }),
      { status: 400, message: `"${provider}" is not a sync provider this instance offers` },
    );
  }
  await assert.rejects(
    root.syncs.add('market/prod', { provider: 'fake', config: {}, credential: CREDENTIAL }),
    { status: 400, message: /Fake: target is required/ },
  );
  await assert.rejects(
    root.syncs.add('market/prod', { provider: 'fake', config: { target: 'x' }, credential: 'DEST_TOKEN' }),
    { status: 400, message: /project\/environment\/KEY/ },
  );
});

test('one destination cannot be fed by two syncs', async () => {
  await createSync();
  await root.environments.create('market/staging', { name: 'Staging' });
  await assert.rejects(
    root.syncs.add('market/staging', { provider: 'fake', config: { target: 'app' }, credential: CREDENTIAL }),
    { status: 409, message: 'fake:app is already synced from market/prod' },
  );
});

// --- keeping up -----------------------------------------------------------------

test('a write pushes only the key that changed', async () => {
  await createSync();
  destination.applied = [];

  await developer.secrets.set('market/prod', { API_KEY: 'api-2' });
  await settle();

  assert.equal(destination.values.get('API_KEY'), 'api-2');
  assert.deepEqual(destination.applied, [{ upsert: [{ key: 'API_KEY', value: 'api-2' }], delete: [] }]);
});

test('archiving and renaming remove what coffre pushed, and nothing else', async () => {
  destination.values.set('SET_BY_HAND', 'keep me');
  await createSync();

  await root.secrets.set('market/prod', { DB_URL: null });
  await root.secrets.rename('market/prod/API_KEY', 'PUBLIC_API_KEY');
  await settle();

  assert.deepEqual(Object.fromEntries(destination.values), { SET_BY_HAND: 'keep me', PUBLIC_API_KEY: 'api-1' });
  const removals = await auditActions('sync.remove');
  assert.deepEqual(removals.map((row) => row.metadata.key).sort(), ['API_KEY', 'DB_URL']);
});

test('a key deleted at the destination is pushed again by the hourly check', async () => {
  const created = await createSync();
  destination.values.delete('DB_URL');

  assert.deepEqual(await runner.reconcile(), { ran: 0 }, 'nothing is due yet');
  await db.owner.update(syncs).set({ lastRunAt: new Date(Date.now() - 2 * 60 * 60_000) });
  assert.deepEqual(await runner.reconcile(), { ran: 1 });

  assert.equal(destination.values.get('DB_URL'), 'postgres://db');
  const pushes = await auditActions('sync.push');
  assert.equal(pushes.at(-1)?.metadata.trigger, 'scheduled');
  assert.equal((await view(created.id)).lastStatus, 'ok');
});

test('the scheduler picks up changes a run missed', async () => {
  const created = await createSync();
  // A write whose after-change run never happened, e.g. the Worker was stopped.
  await db.owner.update(syncs).set({ pausedAt: new Date() }).where(eq(syncs.id, created.id));
  await root.secrets.set('market/prod', { API_KEY: 'api-3' });
  await settle();
  await db.owner.update(syncs).set({ pausedAt: null }).where(eq(syncs.id, created.id));
  assert.equal((await view(created.id)).pending, 1);

  assert.deepEqual(await runner.reconcile(), { ran: 1 });
  assert.equal(destination.values.get('API_KEY'), 'api-3');
});

// --- failing well ---------------------------------------------------------------

test('a key the destination refuses leaves the run partial and the rest pushed', async () => {
  destination.failKeys.add('DB_URL');
  const created = await createSync();

  const listed = await view(created.id);
  assert.equal(listed.lastStatus, 'partial');
  assert.equal(listed.lastError, 'DB_URL: value is too large');
  assert.equal(listed.synced, 1);
  assert.equal(listed.pending, 1);
  assert.deepEqual([...destination.values.keys()], ['API_KEY']);

  // Retried, but not every five minutes.
  assert.deepEqual(await runner.reconcile(), { ran: 0 });
});

test('a destination that is down fails the run with its message and frees the lease', async () => {
  destination.outage = new SyncProviderError('Fake rejected the token (401)', 'unauthorized', 401);
  const created = await createSync();

  const listed = await view(created.id);
  assert.equal(listed.lastStatus, 'failed');
  assert.equal(listed.lastError, 'Fake rejected the token (401)');
  assert.equal(listed.running, false);
  assert.equal(listed.pending, 2);
  assert.equal(destination.applied.length, 0);
  assert.equal((await auditActions('sync.push')).length, 0, 'no value left, so none is logged');
});

test('an archived credential stops the sync with a sentence saying so', async () => {
  const created = await createSync();
  await root.secrets.set('ops/sync', { DEST_TOKEN: null });

  const { outcome } = await root.syncs.run(created.id);
  assert.equal(outcome.status, 'failed');
  assert.equal(
    outcome.status === 'failed' ? outcome.error : null,
    'ops/sync/DEST_TOKEN is archived; restore it or point this sync at another secret',
  );
});

test('a sync whose provider the deployment stopped listing still lists, and says why it cannot run', async () => {
  const created = await createSync();
  deps.syncs = new SyncRunner({ ...deps, providers: [] });

  const listed = await view(created.id);
  assert.deepEqual(
    [listed.provider, listed.providerLabel, listed.brand, listed.offered],
    ['fake', 'fake', 'other', false],
  );
  const { outcome } = await root.syncs.run(created.id);
  assert.equal(
    outcome.status === 'failed' ? outcome.error : null,
    'This deployment no longer offers the sync provider "fake". Remove this sync, or ask whoever runs coffre to list the provider again.',
  );
});

test('rotating the credential is writing a new version of it', async () => {
  const created = await createSync();
  await root.secrets.set('ops/sync', { DEST_TOKEN: 'token-v2' });
  destination.tokens = [];

  await root.syncs.run(created.id);
  assert.ok(destination.tokens.length > 0);
  assert.ok(destination.tokens.every((token) => token === 'token-v2'));
});

test('a sync already running is left alone', async () => {
  const created = await createSync();
  await db.owner.update(syncs).set({ leaseUntil: new Date(Date.now() + 60_000) }).where(eq(syncs.id, created.id));
  destination.applied = [];

  const { outcome, sync } = await root.syncs.run(created.id);
  assert.deepEqual(outcome, { status: 'busy' });
  assert.equal(sync.running, true);
  assert.equal(destination.applied.length, 0);
});

// --- managing -------------------------------------------------------------------

test('a paused sync holds changes back and pushes them when resumed', async () => {
  const created = await createSync();
  await maintainer.syncs.update(created.id, { paused: true });
  await root.secrets.set('market/prod', { API_KEY: 'api-paused' });
  await settle();
  assert.equal(destination.values.get('API_KEY'), 'api-1');

  const resumed = await maintainer.syncs.update(created.id, { paused: false });
  assert.equal(resumed.paused, false);
  await settle();
  assert.equal(destination.values.get('API_KEY'), 'api-paused');
});

test('archiving a sync stops it and leaves the destination as it was', async () => {
  const created = await createSync();
  await maintainer.syncs.remove(created.id);

  await root.secrets.set('market/prod', { API_KEY: 'api-after' });
  await settle();
  assert.deepEqual(Object.fromEntries(destination.values), { API_KEY: 'api-1', DB_URL: 'postgres://db' });
  assert.deepEqual((await root.syncs.list('market/prod')).syncs, []);
});

test('a sync reads as sync:<id>, and revoking its grant stops it', async () => {
  const created = await createSync();
  const principal = `sync:${created.id}`;
  assert.deepEqual(
    (await deps.vault.access(principal)).grants.map(({ role }) => role),
    ['viewer', 'viewer'],
    'its source and its credential',
  );

  await root.access.set(principal, { 'market/prod': null });
  await root.secrets.set('market/prod', { API_KEY: 'api-after' });
  await settle();
  assert.equal(destination.values.get('API_KEY'), 'api-1');
  const { outcome } = await root.syncs.run(created.id);
  assert.equal(outcome.status === 'failed' ? outcome.error : null, 'the vault refused: the sync no longer has read access to its source');
  // Refused twice: the run the write started, and the one asked for by hand.
  const denials = (await auditActions('sync.run')).filter((row) => row.decision === 'deny');
  assert.deepEqual(denials.map((row) => [row.actorId, row.metadata.reason]), [
    [principal, 'vault_no_grant'],
    [ROOT, 'vault_no_grant'],
  ]);

  // Archiving it removes the principal altogether.
  await maintainer.syncs.remove(created.id);
  assert.equal((await deps.vault.access(principal)).status, 'removed');
});

test('developers may run a sync but not pause or remove it', async () => {
  const created = await createSync();
  const { outcome } = await developer.syncs.run(created.id);
  assert.equal(outcome.status, 'ok');

  await assert.rejects(developer.syncs.update(created.id, { paused: true }), { status: 403 });
  await assert.rejects(developer.syncs.remove(created.id), { status: 403 });

  assert.equal((await developer.syncs.list('market/prod')).canManage, false);
  assert.equal((await maintainer.syncs.list('market/prod')).canManage, true);
});

test('people with no access to the environment cannot see its syncs', async () => {
  await createSync();
  await assert.rejects(clientFor(deps, 'stranger@acme.example').syncs.list('market/prod'), { status: 403 });
});

test('revoking the source grant stops a delete-only run before using its credential', async () => {
  const created = await createSync();
  assert.deepEqual(Object.fromEntries(destination.values), { API_KEY: 'api-1', DB_URL: 'postgres://db' });
  await root.syncs.update(created.id, { paused: true });
  await root.secrets.set('market/prod', { API_KEY: null, DB_URL: null });
  await settle();
  await root.access.set(`sync:${created.id}`, { 'market/prod': null });
  destination.tokens = [];
  destination.applied = [];
  await root.syncs.update(created.id, { paused: false });
  await settle();
  assert.equal((await view(created.id)).lastStatus, 'failed');
  assert.deepEqual(Object.fromEntries(destination.values), { API_KEY: 'api-1', DB_URL: 'postgres://db' });
  assert.deepEqual(destination.tokens, []);
  assert.deepEqual(destination.applied, []);
  // Restoring the grant lets the same pending deletions complete.
  await root.access.set(`sync:${created.id}`, { 'market/prod': 'viewer' });
  const { outcome } = await root.syncs.run(created.id);
  assert.equal(outcome.status, 'ok');
  assert.deepEqual(outcome.status === 'ok' ? outcome.deleted.sort() : [], ['API_KEY', 'DB_URL']);
  assert.equal(destination.values.size, 0);
});

for (const parent of ['environment', 'project']) {
  test(`a credential in an archived ${parent} is not used by a sync`, async () => {
    const created = await createSync();
    assert.equal((await view(created.id)).lastStatus, 'ok');
    if (parent === 'environment') await root.environments.update('ops/sync', { archived: true });
    else await root.projects.update('ops', { archived: true });
    destination.tokens = [];
    await assert.rejects(root.secrets.reveal(CREDENTIAL), { status: 404 });
    const { outcome } = await root.syncs.run(created.id);
    assert.equal(outcome.status, 'failed');
    assert.equal(outcome.status === 'failed' ? outcome.error : null,
      'ops/sync/DEST_TOKEN is archived; restore it or point this sync at another secret');
    assert.deepEqual(destination.tokens, []);
  });
}

test('a sync is committed and paused before its vault grant, then enabled', async (t) => {
  const setAccess = deps.vault.setAccess;
  t.mock.method(deps.vault, 'setAccess', async (input: Parameters<typeof setAccess>[0]) => {
    const [row] = await db.owner.select().from(syncs);
    assert.ok(row, 'the sync is committed before its principal is granted access');
    assert.notEqual(row.pausedAt, null);
    assert.deepEqual(await runner.runSettled(row.id, 'scheduled', { actorType: 'system', actorId: 'test' }), { status: 'busy' });
    assert.equal(destination.applied.length, 0);
    return setAccess(input);
  });
  const created = await createSync();
  const [row] = await db.owner.select().from(syncs).where(eq(syncs.id, created.id));
  assert.equal(row.pausedAt, null);
  assert.equal(destination.values.get('API_KEY'), 'api-1');
});

test('a failed sync grant leaves a paused sync that cannot push', async (t) => {
  t.mock.method(deps.vault, 'setAccess', async () => { throw new Error('vault unavailable'); });
  await assert.rejects(createSync(), { status: 500 });
  const [row] = await db.owner.select().from(syncs);
  assert.ok(row);
  assert.notEqual(row.pausedAt, null);
  assert.deepEqual(await runner.runSettled(row.id, 'scheduled', { actorType: 'system', actorId: 'test' }), { status: 'busy' });
  assert.deepEqual(destination.applied, []);
});

test('archiving stops scheduling before vault removal and a failed removal can be retried', async (t) => {
  const created = await createSync();
  const remove = deps.vault.remove;
  let fail = true;
  t.mock.method(deps.vault, 'remove', async (input: Parameters<typeof remove>[0]) => {
    const [row] = await db.owner.select().from(syncs).where(eq(syncs.id, created.id));
    assert.notEqual(row.archivedAt, null);
    assert.deepEqual(await runner.runSettled(row.id, 'scheduled', { actorType: 'system', actorId: 'test' }), { status: 'busy' });
    if (fail) { fail = false; throw new Error('vault unavailable'); }
    return remove(input);
  });
  await assert.rejects(root.syncs.remove(created.id), { status: 500 });
  await root.syncs.remove(created.id);
  assert.equal((await deps.vault.access(`sync:${created.id}`)).status, 'removed');
});

for (const release of ['credential', 'values'] as const) {
  test(`a failed app audit after releasing sync ${release} prevents the provider push`, async (t) => {
    const created = await createSync();
    destination.values.clear();
    destination.applied = [];
    destination.tokens = [];
    const [credential] = await db.owner.select({ versionId: secrets.currentVersionId }).from(secrets).where(eq(secrets.key, 'DEST_TOKEN'));
    let failCommit = false;
    const unwrap = deps.vault.unwrap;
    t.mock.method(deps.vault, 'unwrap', async (input: Parameters<typeof unwrap>[0]) => {
      const result = await unwrap(input);
      const opensCredential = input.items.some(({ secretVersionId }) => secretVersionId === credential.versionId);
      if (opensCredential === (release === 'credential')) failCommit = true;
      return result;
    });
    const transaction = db.runtime.transaction.bind(db.runtime);
    t.mock.method(db.runtime, 'transaction', ((work, options) => transaction(async (tx) => {
      const result = await work(tx);
      if (failCommit) {
        failCommit = false;
        throw new Error('audit commit failed');
      }
      return result;
    }, options)) as typeof db.runtime.transaction);
    const { outcome } = await root.syncs.run(created.id);
    assert.equal(outcome.status, 'failed');
    assert.deepEqual(destination.applied, []);
    assert.equal(destination.values.size, 0);
    if (release === 'credential') assert.deepEqual(destination.tokens, []);
  });
}
