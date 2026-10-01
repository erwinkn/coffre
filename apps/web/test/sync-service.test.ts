import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';

import { LocalKekProvider } from '../../../packages/core/src/kek/local.ts';
import { KekRegistry } from '../../../packages/core/src/kek/registry.ts';
import {
  TEST_OWNER_DATABASE_URL,
  TEST_RUNTIME_DATABASE_URL,
} from '../../../packages/db/test/connections.ts';
import {
  SyncConfigError,
  SyncProviderError,
  type SyncPlan,
  type SyncProvider,
  type SyncProviderKind,
} from '../../../packages/sync/src/index.ts';
import { AdminService } from '../src/server/services/admin.ts';
import { AccessDenied, SecretsService } from '../src/server/services/secrets.ts';
import { planSync, SyncService } from '../src/server/services/sync.ts';
import { requestContext } from './service-fixture.ts';

const CHAIN_KEY = randomBytes(32);
const ROOT = 'admin@acme.example';
const root = requestContext(ROOT);
const developer = requestContext('dev@acme.example');
const maintainer = requestContext('lead@acme.example');
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
    kind: 'fake' as SyncProviderKind,
    label: 'Fake',
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

let pool: pg.Pool;
let runtimePool: pg.Pool;
let destination: FakeDestination;
let admin: AdminService;
let secrets: SecretsService;
let syncs: SyncService;
const background: Promise<unknown>[] = [];

function waitUntil(promise: Promise<unknown>) {
  background.push(promise);
}

/** Let every run the services started in the background finish. */
async function settle() {
  while (background.length > 0) await Promise.all(background.splice(0));
}

async function cleanSyncTables() {
  await pool.query('DELETE FROM sync_keys');
  await pool.query('DELETE FROM syncs');
}

before(() => {
  pool = new pg.Pool({ connectionString: TEST_OWNER_DATABASE_URL });
  runtimePool = new pg.Pool({ connectionString: TEST_RUNTIME_DATABASE_URL });
  const keks = new KekRegistry(LocalKekProvider.generate('test-kek-1'));
  const deps = { pool: runtimePool, keks, auditChainKey: CHAIN_KEY, rootAdmins: [ROOT] };
  admin = new AdminService({ pool: runtimePool, auditChainKey: CHAIN_KEY, rootAdmins: [ROOT] });
  syncs = new SyncService({
    ...deps,
    waitUntil,
    resolveProvider: (kind) => (kind === 'fake' ? (destination.provider as SyncProvider<unknown>) : null),
  });
  secrets = new SecretsService({
    ...deps,
    onChange: (environmentId) => waitUntil(syncs.runForEnvironment(environmentId)),
  });
});

after(async () => {
  await settle();
  // Other suites delete secrets and projects, which these rows would block.
  await cleanSyncTables();
  await runtimePool.end();
  await pool.end();
});

beforeEach(async () => {
  await settle();
  destination = new FakeDestination();
  await cleanSyncTables();
  await pool.query('DELETE FROM audit_log');
  await pool.query(
    "UPDATE audit_chain_head SET next_seq = 0, head_hash = decode(repeat('00', 32), 'hex')",
  );
  await pool.query('UPDATE secrets SET current_version_id = NULL');
  await pool.query('DELETE FROM secret_versions');
  await pool.query('DELETE FROM secrets');
  await pool.query('DELETE FROM grants');
  await pool.query('DELETE FROM principals');
  await pool.query('DELETE FROM environments');
  await pool.query('DELETE FROM projects');
  await pool.query(
    `INSERT INTO principals (principal_type, principal_id, instance_role, created_by, active)
     VALUES ('user', $1, 'user', $3, true), ('user', $2, 'user', $3, true)`,
    [developer.principal.id, maintainer.principal.id, ROOT],
  );
  await admin.createProject(root, 'market', 'Market');
  await admin.createEnvironment(root, 'market', 'prod', 'Production');
  await admin.createProject(root, 'ops', 'Ops');
  await admin.createEnvironment(root, 'ops', 'sync', 'Sync credentials');
  await admin.createGrant(root, 'market', {
    principalType: 'user',
    principalId: developer.principal.id,
    role: 'developer',
  });
  await admin.createGrant(root, 'market', {
    principalType: 'user',
    principalId: maintainer.principal.id,
    role: 'maintainer',
  });
  await secrets.writeSecret(root, 'ops', 'sync', 'DEST_TOKEN', 'token-v1');
  await secrets.writeSecret(root, 'market', 'prod', 'API_KEY', 'api-1');
  await secrets.writeSecret(root, 'market', 'prod', 'DB_URL', 'postgres://db');
  await settle();
});

async function createSync(ctx = root) {
  const view = await syncs.create(ctx, 'market', 'prod', {
    provider: 'fake',
    config: { target: 'app' },
    credential: CREDENTIAL,
  });
  await settle();
  return view;
}

async function auditActions(action: string) {
  const rows = await pool.query<{
    actor_type: string;
    actor_id: string;
    environment_id: string | null;
    secret_id: string | null;
    metadata: Record<string, unknown>;
  }>(
    `SELECT actor_type, actor_id, environment_id, secret_id, metadata::jsonb AS metadata
       FROM audit_log WHERE action = $1 ORDER BY seq`,
    [action],
  );
  return rows.rows;
}

async function view(id: string) {
  const listed = await syncs.list(root, 'market', 'prod');
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
  await secrets.writeSecret(root, 'market', 'prod', 'RESERVED_NAME', 'x');
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
  assert.ok(pushes.every((row) => row.actor_type === 'system' && row.actor_id === `sync:${created.id}`));
  assert.ok(pushes.every((row) => row.metadata.destination === 'fake:app' && row.metadata.trigger === 'create'));

  const [run] = await auditActions('sync.run');
  const credential = await pool.query<{ id: string; environment_id: string }>(
    "SELECT id, environment_id FROM secrets WHERE key = 'DEST_TOKEN'",
  );
  assert.equal(run.secret_id, credential.rows[0].id);
  assert.equal(run.environment_id, credential.rows[0].environment_id);
  assert.equal(run.metadata.source, 'market/prod');

  const [creation] = await auditActions('sync.create');
  assert.equal(creation.actor_id, ROOT);
  assert.equal(creation.metadata.credential, CREDENTIAL);
});

test('creating a sync needs environment.manage and secret.read, and a refusal is logged', async () => {
  await assert.rejects(createSync(developer), AccessDenied);
  const [denied] = await pool.query<{ decision: string; metadata: { reason: string } }>(
    "SELECT decision, metadata::jsonb AS metadata FROM audit_log WHERE action = 'sync.create'",
  ).then((result) => result.rows);
  assert.equal(denied.decision, 'deny');
  assert.equal(denied.metadata.reason, 'missing_environment_manage');
  assert.equal(destination.applied.length, 0);
});

test('a credential the creator cannot read is refused like one that does not exist', async () => {
  // The maintainer manages market but has no grant on ops.
  await assert.rejects(createSync(maintainer), (error: Error & { statusCode?: number }) => {
    assert.equal(error.statusCode, 400);
    assert.equal(error.message, `${CREDENTIAL} is not a secret you can read`);
    return true;
  });
  await assert.rejects(
    syncs.create(root, 'market', 'prod', { provider: 'fake', config: { target: 'app' }, credential: 'ops/sync/NOPE' }),
    /ops\/sync\/NOPE is not a secret you can read/,
  );
});

test('unknown destinations and bad configs are refused with a message for the caller', async () => {
  await assert.rejects(
    syncs.create(root, 'market', 'prod', { provider: 'dropbox', config: {}, credential: CREDENTIAL }),
    (error: Error & { statusCode?: number; expose?: boolean }) =>
      error.statusCode === 400 && error.expose === true && /dropbox/.test(error.message),
  );
  await assert.rejects(
    syncs.create(root, 'market', 'prod', { provider: 'fake', config: {}, credential: CREDENTIAL }),
    /Fake: target is required/,
  );
  await assert.rejects(
    syncs.create(root, 'market', 'prod', { provider: 'fake', config: { target: 'x' }, credential: 'DEST_TOKEN' }),
    /project\/environment\/KEY/,
  );
});

test('one destination cannot be fed by two syncs', async () => {
  await createSync();
  await admin.createEnvironment(root, 'market', 'staging', 'Staging');
  await assert.rejects(
    syncs.create(root, 'market', 'staging', { provider: 'fake', config: { target: 'app' }, credential: CREDENTIAL }),
    (error: Error & { statusCode?: number }) =>
      error.statusCode === 409 && error.message === 'fake:app is already synced from market/prod',
  );
});

// --- keeping up -----------------------------------------------------------------

test('a write pushes only the key that changed', async () => {
  await createSync();
  destination.applied = [];

  await secrets.writeSecret(developer, 'market', 'prod', 'API_KEY', 'api-2');
  await settle();

  assert.equal(destination.values.get('API_KEY'), 'api-2');
  assert.deepEqual(destination.applied, [{ upsert: [{ key: 'API_KEY', value: 'api-2' }], delete: [] }]);
});

test('archiving and renaming remove what coffre pushed, and nothing else', async () => {
  destination.values.set('SET_BY_HAND', 'keep me');
  await createSync();

  await secrets.setSecretArchived(root, 'market', 'prod', 'DB_URL', true);
  await secrets.renameSecret(root, 'market', 'prod', 'API_KEY', 'PUBLIC_API_KEY');
  await settle();

  assert.deepEqual(Object.fromEntries(destination.values), { SET_BY_HAND: 'keep me', PUBLIC_API_KEY: 'api-1' });
  const removals = await auditActions('sync.remove');
  assert.deepEqual(removals.map((row) => row.metadata.key).sort(), ['API_KEY', 'DB_URL']);
});

test('a key deleted at the destination is pushed again by the hourly check', async () => {
  const created = await createSync();
  destination.values.delete('DB_URL');

  assert.deepEqual(await syncs.reconcile(), { ran: 0 }, 'nothing is due yet');
  await pool.query("UPDATE syncs SET last_run_at = now() - interval '2 hours'");
  assert.deepEqual(await syncs.reconcile(), { ran: 1 });

  assert.equal(destination.values.get('DB_URL'), 'postgres://db');
  const pushes = await auditActions('sync.push');
  assert.equal(pushes.at(-1)?.metadata.trigger, 'scheduled');
  assert.equal((await view(created.id)).lastStatus, 'ok');
});

test('the scheduler picks up changes a run missed', async () => {
  const created = await createSync();
  // A write whose after-change run never happened, e.g. the Worker was stopped.
  await pool.query("UPDATE syncs SET paused_at = now() WHERE id = $1", [created.id]);
  await secrets.writeSecret(root, 'market', 'prod', 'API_KEY', 'api-3');
  await settle();
  await pool.query('UPDATE syncs SET paused_at = NULL WHERE id = $1', [created.id]);
  assert.equal((await view(created.id)).pending, 1);

  assert.deepEqual(await syncs.reconcile(), { ran: 1 });
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
  assert.deepEqual(await syncs.reconcile(), { ran: 0 });
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
  await secrets.setSecretArchived(root, 'ops', 'sync', 'DEST_TOKEN', true);

  const { outcome } = await syncs.runNow(root, created.id);
  assert.equal(outcome.status, 'failed');
  assert.equal(
    outcome.status === 'failed' ? outcome.error : null,
    'ops/sync/DEST_TOKEN is archived; restore it or point this sync at another secret',
  );
});

test('rotating the credential is writing a new version of it', async () => {
  const created = await createSync();
  await secrets.writeSecret(root, 'ops', 'sync', 'DEST_TOKEN', 'token-v2');
  destination.tokens = [];

  await syncs.runNow(root, created.id);
  assert.ok(destination.tokens.length > 0);
  assert.ok(destination.tokens.every((token) => token === 'token-v2'));
});

test('a sync already running is left alone', async () => {
  const created = await createSync();
  await pool.query("UPDATE syncs SET lease_until = now() + interval '1 minute' WHERE id = $1", [created.id]);
  destination.applied = [];

  const { outcome, sync } = await syncs.runNow(root, created.id);
  assert.deepEqual(outcome, { status: 'busy' });
  assert.equal(sync.running, true);
  assert.equal(destination.applied.length, 0);
});

// --- managing -------------------------------------------------------------------

test('a paused sync holds changes back and pushes them when resumed', async () => {
  const created = await createSync();
  await syncs.setPaused(maintainer, created.id, true);
  await secrets.writeSecret(root, 'market', 'prod', 'API_KEY', 'api-paused');
  await settle();
  assert.equal(destination.values.get('API_KEY'), 'api-1');

  const resumed = await syncs.setPaused(maintainer, created.id, false);
  assert.equal(resumed.paused, false);
  await settle();
  assert.equal(destination.values.get('API_KEY'), 'api-paused');
});

test('archiving a sync stops it and leaves the destination as it was', async () => {
  const created = await createSync();
  await syncs.archive(maintainer, created.id);

  await secrets.writeSecret(root, 'market', 'prod', 'API_KEY', 'api-after');
  await settle();
  assert.deepEqual(Object.fromEntries(destination.values), { API_KEY: 'api-1', DB_URL: 'postgres://db' });
  assert.deepEqual((await syncs.list(root, 'market', 'prod')).syncs, []);
});

test('developers may run a sync but not pause or remove it', async () => {
  const created = await createSync();
  const { outcome } = await syncs.runNow(developer, created.id);
  assert.equal(outcome.status, 'ok');

  await assert.rejects(syncs.setPaused(developer, created.id, true), AccessDenied);
  await assert.rejects(syncs.archive(developer, created.id), AccessDenied);

  const listed = await syncs.list(developer, 'market', 'prod');
  assert.equal(listed.canManage, false);
  assert.equal((await syncs.list(maintainer, 'market', 'prod')).canManage, true);
});

test('people with no access to the environment cannot see its syncs', async () => {
  await createSync();
  await assert.rejects(syncs.list(requestContext('stranger@acme.example'), 'market', 'prod'), AccessDenied);
});
