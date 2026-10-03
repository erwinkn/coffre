import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { getTableColumns, sql, type SQL } from 'drizzle-orm';
import pg from 'pg';
import { tablesOf, type Database } from '@coffre/db';
import { openDatabase } from '@coffre/db/connect';
import { migrateDatabase, migrationsFolder } from '@coffre/db/migrate';
import { localVault } from '@coffre/vault/node';

import { clientFor, type TestVault } from './api-fixture.ts';
import { TEST_ENGINE, withLogUnlocked } from './db/engine.ts';
import { TEST_OWNER_DATABASE_URL } from './db/connections.ts';
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
      const columns = getTableColumns(table) as Record<string, { dataType: string }>;
      const rows = data[name].map((row: Record<string, unknown>) => Object.fromEntries(Object.entries(row).map(([key, value]) =>
        [key, value !== null && columns[key]?.dataType === 'date' ? new Date(value as string) : value],
      )));
      if (name === 'auditChainHead') await tx.delete(table);
      await tx.insert(table).values(rows);
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
  const databaseUrl = url?.href ?? `file:${directory}/upgrade.db`;
  // A teardown failure must not hide which upgrade assertion failed.
  t.after(async () => {
    try {
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
  const original = await db.select().from(tablesOf(db).auditLog).orderBy(tablesOf(db).auditLog.seq);
  const fakeCredential = '00000000-0000-4000-8000-000000000004';
  // A configured destination must not be silently discarded, and its
  // referenced secret must survive upgrade.
  await db.insert(tablesOf(db).secrets).values({ id: fakeCredential, projectId: '00000000-0000-4000-8000-000000000001', environmentId: '00000000-0000-4000-8000-000000000002', key: 'OLD_TOKEN' });
  await execute(sql`INSERT INTO syncs (id, project_id, environment_id, provider, config, credential_secret_id, created_by) VALUES ('00000000-0000-4000-8000-000000000003', '00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002', 'github-actions', '{}', ${fakeCredential}, ${ROOT})`);
  await execute(sql`INSERT INTO sync_keys (sync_id, key) VALUES ('00000000-0000-4000-8000-000000000003', 'VALUE')`);
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
  const kek = Buffer.alloc(32, 17);
  const vault = await localVault({ database: db, kek: { id: 'legacy', key: kek.toString('base64') }, rootAdmins: [ROOT] });
  const deps = { db, vault: vault as unknown as TestVault, chainKey: Buffer.alloc(32, 23) };
  const root = clientFor(deps, ROOT);
  assert.equal((await root.audit.verify()).ok, true);
  assert.deepEqual((await vault.access(SYNC)).grants, []);
  assert.equal((await vault.access(SYNC)).status, 'unknown');
  assert.equal((await vault.setAccess({ actor: `user:${ROOT}`, principal: SYNC, changes: [{ projectId: '00000000-0000-4000-8000-000000000001', environmentId: null, role: 'viewer', expiresAt: null }] })).ok, false);
  assert.equal((await vault.admit({ actor: `user:${ROOT}`, principal: SYNC })).ok, false);
  await root.secrets.set('market/prod', { VALUE: 'still private' });
  const [version] = await db.select().from(tablesOf(db).secretVersions);
  const denied = await vault.unwrap({ principal: SYNC, purpose: 'run', items: [{ secretVersionId: version.id }] });
  assert.equal(denied.ok, false, 'even an old sealed sync grant cannot release a value');
  assert.equal((await root.audit.verify()).ok, true);
  const actions = (await root.audit.list({ detail: '1' })).entries.map((entry) => entry.action);
  for (const action of ['sync.create', 'sync.push', 'sync.remove', 'sync.run', 'sync.update', 'sync.delete', 'sync.list']) assert.ok(actions.includes(action));
});
