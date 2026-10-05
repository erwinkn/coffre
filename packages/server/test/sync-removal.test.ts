import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { getTableColumns, sql, type AnyColumn, type SQL } from 'drizzle-orm';
import pg from 'pg';
import { createDatabase, tablesOf, type Database } from '@coffre/db';
import { openDatabase } from '@coffre/db/connect';
import { migrateDatabase, migrationsFolder } from '@coffre/db/migrate';
import { localVault } from '@coffre/vault/node';

import { clientFor, type TestVault } from './api-fixture.ts';
import { auditReadiness, writeAuditHeartbeat } from '../src/heartbeat.ts';
import { TEST_ENGINE, withLogUnlocked } from './db/engine.ts';
import { TEST_OWNER_DATABASE_URL, TEST_RUNTIME_DATABASE_URL, TEST_VAULT_DATABASE_URL } from './db/connections.ts';
import { testPostgresPool } from './db/postgres-pool.ts';

const ROOT = 'admin@acme.example';
const SYNC = 'sync:00000000-0000-4000-8000-000000000003';

/** An actual 0.1.10 log, before sync removal, including its sealed active grant
 * and checkpoint. Never re-sign this fixture with the new code to make it pass.
 * Its fake KEK is 32 bytes of 17; its app chain seed is 32 bytes of 23.
 */
async function history(db: Database) {
  const data = JSON.parse(await readFile(new URL('./fixtures/legacy-sync.json', import.meta.url), 'utf8'), (_, value) => {
    if (value?.type === 'bytes') return Buffer.from(value.hex, 'hex');
    if (value?.type === 'bigint') return BigInt(value.value);
    return value;
  });
  const tables = tablesOf(db);
  await withLogUnlocked(db, async (tx) => {
    for (const name of ['projects', 'environments', 'vaultMembers', 'vaultGrants', 'auditLog', 'auditChainHead'] as const) {
      const table = tables[name];
      const columns = getTableColumns(table) as Record<string, AnyColumn>;
      if (name === 'auditChainHead') await tx.delete(table);
      // The fixture's columns only: the tables are the baseline's, before later migrations added any.
      for (const row of data[name] as Record<string, unknown>[]) {
        const keys = Object.keys(row);
        const values = keys.map((key) => {
          const value = row[key] !== null && columns[key].dataType === 'date' ? new Date(row[key] as string) : row[key];
          return sql.param(value, columns[key]);
        });
        const insert = sql`INSERT INTO ${table} (${sql.join(keys.map((key) => sql.identifier(columns[key].name)), sql`, `)}) VALUES (${sql.join(values, sql`, `)})`;
        if (TEST_ENGINE === 'postgres') await tx.execute(insert);
        else await (tx as unknown as { run(query: SQL): Promise<unknown> }).run(insert);
      }
    }
  });
}

test('the upgrade refuses populated syncs atomically, then preserves the old log and denies legacy sync access', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'coffre-upgrade-'));
  const name = `coffre_upgrade_${randomBytes(8).toString('hex')}`;
  const adminUrl = new URL(TEST_OWNER_DATABASE_URL);
  adminUrl.pathname = '/postgres';
  // DROP DATABASE can wait for a cluster-wide checkpoint. On the shared
  // host one flushed 16,279 files in 15s; this is DDL, not a per-test query.
  const admin = TEST_ENGINE === 'postgres' ? new pg.Client({
    connectionString: adminUrl.href,
    connectionTimeoutMillis: 5_000,
    query_timeout: 60_000,
    statement_timeout: 60_000,
  }) : null;
  const url = TEST_ENGINE === 'postgres' ? new URL(TEST_OWNER_DATABASE_URL) : null;
  if (url) url.pathname = `/${name}`;
  let opened: Awaited<ReturnType<typeof openDatabase>> | null = null;
  const pools: pg.Pool[] = [];
  const databaseUrl = url?.href ?? `file:${directory}/upgrade.db`;
  // A teardown failure must not hide which upgrade assertion failed.
  t.after(async () => {
    try {
      await Promise.all(pools.map((pool) => pool.end()));
      await opened?.close();
      // Every connection belongs to this test and has been closed. Never
      // terminate a client to hide unfinished work during teardown.
      if (admin) await admin.query(`DROP DATABASE IF EXISTS "${name}"`);
    } finally {
      await admin?.end();
      await rm(directory, { recursive: true, force: true });
    }
  });
  if (admin) {
    await admin.connect();
    await admin.query(`CREATE DATABASE "${name}"`);
  }
  opened = await openDatabase(databaseUrl);
  const db = opened.db;
  const execute = (statement: SQL) => TEST_ENGINE === 'postgres' ? db.execute(statement) :
    (db as unknown as { run(query: SQL): Promise<unknown> }).run(statement);
  const baseline = await readFile(`${migrationsFolder(TEST_ENGINE)}/0000_baseline.sql`, 'utf8');
  const journal = JSON.parse(await readFile(`${migrationsFolder(TEST_ENGINE)}/meta/_journal.json`, 'utf8'));
  const hash = createHash('sha256').update(baseline).digest('hex');
  if (TEST_ENGINE === 'postgres') {
    const pool = testPostgresPool(databaseUrl);
    try {
      await pool.query('CREATE SCHEMA drizzle; CREATE TABLE drizzle.__drizzle_migrations (id serial PRIMARY KEY, hash text NOT NULL, created_at bigint)');
      await pool.query(baseline);
      await pool.query('INSERT INTO drizzle.__drizzle_migrations (hash, created_at) VALUES ($1, $2)', [hash, journal.entries[0].when]);
    } finally { await pool.end(); }
  } else {
    for (const statement of baseline.split('--> statement-breakpoint')) if (statement.trim()) await execute(sql.raw(statement));
    await execute(sql`CREATE TABLE __drizzle_migrations (id INTEGER PRIMARY KEY AUTOINCREMENT, hash text NOT NULL, created_at numeric)`);
    await execute(sql`INSERT INTO __drizzle_migrations (hash, created_at) VALUES (${hash}, ${journal.entries[0].when})`);
  }
  await history(db);
  const fakeCredential = '00000000-0000-4000-8000-000000000004';
  // A configured destination must not be silently discarded, and its
  // referenced secret must survive upgrade.
  await db.insert(tablesOf(db).secrets).values({ id: fakeCredential, projectId: '00000000-0000-4000-8000-000000000001', environmentId: '00000000-0000-4000-8000-000000000002', key: 'OLD_TOKEN' });
  await execute(sql`INSERT INTO syncs (id, project_id, environment_id, provider, config, credential_secret_id, created_by) VALUES ('00000000-0000-4000-8000-000000000003', '00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002', 'github-actions', '{}', ${fakeCredential}, ${ROOT})`);
  await execute(sql`INSERT INTO sync_keys (sync_id, key) VALUES ('00000000-0000-4000-8000-000000000003', 'VALUE')`);
  const runtimeDatabase = (connection: string) => {
    if (TEST_ENGINE !== 'postgres') return db;
    const scoped = new URL(connection);
    scoped.pathname = `/${name}`;
    const pool = testPostgresPool(scoped.href);
    pools.push(pool);
    return createDatabase(pool);
  };
  const appDb = runtimeDatabase(TEST_RUNTIME_DATABASE_URL);
  const vaultDb = runtimeDatabase(TEST_VAULT_DATABASE_URL);
  const kek = Buffer.alloc(32, 17);
  const vault = await localVault({ database: vaultDb, kek: { id: 'legacy', key: kek.toString('base64') }, rootAdmins: [ROOT] });
  const chainKey = Buffer.alloc(32, 23);
  const deps = { db: appDb, vault: vault as unknown as TestVault, chainKey };
  const root = clientFor(deps, ROOT);
  // Workers Builds does not migrate. The new app and vault must operate on
  // 0000 using their restricted logins, even while sync tables still exist.
  assert.equal((await root.audit.verify()).ok, true);
  await root.secrets.set('market/prod', { OLD_TOKEN: 'preserved credential' });
  assert.deepEqual((await root.secrets.reveal('market/prod/OLD_TOKEN')).values, { OLD_TOKEN: 'preserved credential' });
  // Before 0005, nothing is filed and nothing can be: lists work, and moving waits for the migration.
  assert.deepEqual((await root.secrets.list('market/prod')).keys.map((key) => key.folder), [null]);
  assert.ok((await root.projects.list()).projects.every((project) => project.folder === null));
  await assert.rejects(root.secrets.update('market/prod/OLD_TOKEN', { folder: 'tokens' }), { status: 503 });
  // Nor a reference: it waits for 0006, and nothing is one until then.
  await assert.rejects(root.secrets.set('market/prod', { LINKED: { ref: 'market/prod/OLD_TOKEN' } }), { status: 503 });
  assert.deepEqual((await root.references.list('market')).references, []);
  assert.ok((await root.secrets.list('market/prod')).keys.every((key) => key.reference === null));
  // Missing keys list without 0007, and dismissing them waits for it.
  assert.deepEqual((await root.environments.missing('market/prod')).dismissed, []);
  await assert.rejects(root.environments.dismiss('market/prod', { ANYTHING: true }), { status: 503 });
  assert.equal(await writeAuditHeartbeat(appDb, chainKey, vault, { warn: () => {} }), true);
  assert.equal((await auditReadiness(appDb, vault)).ok, true, '0000 is ready: deploy before migrating');
  assert.equal((await vault.access(SYNC)).status, 'unknown');
  // Grants on every project need a column of a later migration: refused, in words, until it runs.
  await root.members.add('user:ada@acme.example');
  await assert.rejects(root.access.set('user:ada@acme.example', { '*': 'viewer' }), { status: 503, message: /coffre migrate/ });
  const early = await vault.setAccess({
    actor: `user:${ROOT}`, principal: 'user:ada@acme.example', changes: [{ projectId: null, environmentId: null, role: 'viewer', expiresAt: null }],
  });
  assert.match(!early.ok ? early.refusal.message : '', /coffre migrate/, 'the vault refuses it too');
  const original = await db.select().from(tablesOf(db).auditLog).orderBy(tablesOf(db).auditLog.seq);
  await assert.rejects(migrateDatabase(databaseUrl), /syncs.*(?:removed|cleared)/);
  assert.deepEqual(await db.select().from(tablesOf(db).auditLog).orderBy(tablesOf(db).auditLog.seq), original);
  // A second attempt must still meet the old tables, not a partial upgrade;
  // even archived destinations must be checked before dropping them.
  await execute(sql`UPDATE syncs SET archived_at = CURRENT_TIMESTAMP`);
  await assert.rejects(migrateDatabase(databaseUrl), /syncs.*(?:removed|cleared)/);
  await execute(sql`DELETE FROM sync_keys`);
  await execute(sql`DELETE FROM syncs`);
  await migrateDatabase(databaseUrl);
  await migrateDatabase(databaseUrl);
  for (const table of ['syncs', 'sync_keys']) await assert.rejects(execute(sql.raw(`SELECT * FROM ${table}`)));
  assert.deepEqual(await db.select().from(tablesOf(db).auditLog).orderBy(tablesOf(db).auditLog.seq), original);
  assert.equal((await db.select().from(tablesOf(db).secrets)).length, 1);
  assert.equal((await root.audit.verify()).ok, true);
  assert.equal((await auditReadiness(appDb, vault)).ok, true, '0001 remains ready after migrating');
  assert.deepEqual((await root.secrets.reveal('market/prod/OLD_TOKEN')).values, { OLD_TOKEN: 'preserved credential' });
  await root.secrets.update('market/prod/OLD_TOKEN', { folder: 'tokens' });
  assert.deepEqual((await root.secrets.list('market/prod')).keys.map((key) => key.folder), ['tokens']);
  assert.deepEqual((await vault.access(SYNC)).grants, []);
  assert.equal((await vault.access(SYNC)).status, 'unknown');
  assert.equal((await vault.setAccess({ actor: `user:${ROOT}`, principal: SYNC, changes: [{ projectId: '00000000-0000-4000-8000-000000000001', environmentId: null, role: 'viewer', expiresAt: null }] })).ok, false);
  assert.equal((await vault.admit({ actor: `user:${ROOT}`, principal: SYNC })).ok, false);
  await root.secrets.set('market/prod', { VALUE: 'still private' });
  const versions = await db.select().from(tablesOf(db).secretVersions);
  const version = versions.find((version) => version.secretId !== fakeCredential)!;
  const denied = await vault.unwrap({ principal: SYNC, purpose: 'run', items: [{ secretVersionId: version.id }] });
  assert.equal(denied.ok, false, 'even an old sealed sync grant cannot release a value');
  assert.equal((await root.audit.verify()).ok, true);
  const actions = (await root.audit.list({ detail: '1' })).entries.map((entry) => entry.action);
  for (const action of ['sync.create', 'sync.push', 'sync.remove', 'sync.run', 'sync.update', 'sync.delete', 'sync.list']) assert.ok(actions.includes(action));
});
