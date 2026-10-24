import test from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sql } from 'drizzle-orm';
import { migrate } from 'drizzle-orm/libsql/migrator';

import { openDatabase } from '../src/connect.ts';
import { migrateDatabase, migrationsFolder } from '../src/migrate.ts';

/**
 * 0015_workload_access widens two checks on `credentials`, which SQLite
 * does by rebuilding the table: a database of the release before, with its
 * credentials of every kind, keeps every row and index, and takes the new
 * kind only as its checks say.
 */

const TAG = '0015_workload_access';
const hash = (byte: number) => Buffer.alloc(32, byte);

type Db = Awaited<ReturnType<typeof openDatabase>>['db'];
const all = (db: Db, text: string) => (db as unknown as { all(query: ReturnType<typeof sql.raw>): Promise<Record<string, unknown>[]> }).all(sql.raw(text));
const run = (db: Db, text: string) => (db as unknown as { run(query: ReturnType<typeof sql.raw>): Promise<unknown> }).run(sql.raw(text));

/** A statement the database refuses, by the constraint its cause names: drizzle wraps the driver's error. */
const refused = (attempt: Promise<unknown>, constraint: RegExp) =>
  assert.rejects(attempt, (error: Error) => constraint.test(String((error as { cause?: unknown }).cause ?? error)));

/** A copy of the SQLite migrations up to the one before this one. */
function before(dir: string): string {
  const folder = join(dir, 'migrations');
  cpSync(migrationsFolder('sqlite'), folder, { recursive: true });
  const journal = JSON.parse(readFileSync(join(folder, 'meta/_journal.json'), 'utf8')) as { entries: { tag: string }[] };
  const at = journal.entries.findIndex((entry) => entry.tag === TAG);
  assert.ok(at > 0, `${TAG} is in the journal`);
  writeFileSync(join(folder, 'meta/_journal.json'), JSON.stringify({ ...journal, entries: journal.entries.slice(0, at) }));
  rmSync(join(folder, `${TAG}.sql`));
  return folder;
}

const ROWS = `
  INSERT INTO vault_members (principal, status, owner, generation, created_at, created_by, status_changed_at, status_changed_by, access_seq, mac)
    VALUES ('user:ada@acme.example', 'active', 1, 1, 1, 'setup', 1, 'setup', 1, X'${hash(1).toString('hex')}'),
           ('token:deploy', 'active', 0, 1, 1, 'setup', 1, 'setup', 2, X'${hash(2).toString('hex')}');
  INSERT INTO credentials (id, kind, auth_mac, token_hash, token_hint, generation, principal, scope, places, label, created_at, created_by, expires_at, last_used_at, last_used_ip, revoked_at, revoked_by)
    VALUES ('11111111-1111-4111-8111-111111111111', 'cli', X'${hash(3).toString('hex')}', X'${hash(4).toString('hex')}', 'coffre_cli_…abcd', 1, 'user:ada@acme.example', NULL, NULL, 'laptop', 10, 'device', 20, 15, '192.0.2.1', NULL, NULL),
           ('22222222-2222-4222-8222-222222222222', 'service', X'${hash(5).toString('hex')}', X'${hash(6).toString('hex')}', 'coffre_svc_…efgh', 1, 'token:deploy', '[]', NULL, NULL, 11, 'user:ada@acme.example', 21, NULL, NULL, 12, 'user:ada@acme.example'),
           ('33333333-3333-4333-8333-333333333333', 'handle', X'${hash(7).toString('hex')}', X'${hash(8).toString('hex')}', 'coffre_use_…ijkl', 1, 'user:ada@acme.example', '[]', '[]', 'run', 12, 'user:ada@acme.example', 22, NULL, NULL, NULL, NULL);
`;

test(`${TAG} keeps every credential and index on SQLite, and takes a workload's session only bound to a key`, async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-0015-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const url = `file:${join(dir, 'coffre.db')}`;

  const { db, close } = await openDatabase(url);
  try {
    await migrate(db as never, { migrationsFolder: before(dir) });
    const columns = (await all(db, 'PRAGMA table_info(credentials)')).map((column) => column.name as string);
    assert.ok(!columns.includes('jkt'), 'the release before has no jkt');
    for (const statement of ROWS.split(';').map((text) => text.trim()).filter(Boolean)) await run(db, statement);
  } catch (error) {
    await close();
    throw error;
  }
  const rowsBefore = await all(db, 'SELECT * FROM credentials ORDER BY id');
  const indexesBefore = await all(db, "SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'credentials' ORDER BY name");
  await close();

  await migrateDatabase(url);

  const after = await openDatabase(url);
  try {
    const rows = await all(after.db, 'SELECT * FROM credentials ORDER BY id');
    const added = ['jkt', 'not_after', 'ancestors', 'constraints', 'enrollment_id', 'approved_at', 'approved_by'];
    assert.deepEqual(rows.map((row) => Object.fromEntries(Object.entries(row).filter(([name]) => !added.includes(name)))), rowsBefore);
    for (const row of rows) for (const name of added) assert.equal(row[name], null, `${row.id as string}.${name}`);

    const indexes = await all(after.db, "SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'credentials' ORDER BY name");
    assert.deepEqual(indexes.filter((index) => index.name !== 'credentials_enrollment_roots_idx'), indexesBefore);
    assert.ok(indexes.some((index) => index.name === 'credentials_enrollment_roots_idx'));
    assert.deepEqual(await all(after.db, 'PRAGMA foreign_key_check'), []);
    assert.deepEqual(await all(after.db, 'PRAGMA integrity_check'), [{ integrity_check: 'ok' }]);
    for (const name of ['audit_log_freeze_idx', 'audit_log_supersede_idx', 'enrollments_binding_idx']) {
      assert.equal((await all(after.db, `SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = '${name}'`)).length, 1, name);
    }
    // The freeze index serves the per-request lookup, by its expression.
    const plan = await all(after.db, "EXPLAIN QUERY PLAN SELECT seq FROM audit_log WHERE json_extract(metadata, '$.target') = 'instance' AND author = 'app' AND action IN ('workload.freeze', 'workload.unfreeze') AND decision = 'allow' ORDER BY seq DESC LIMIT 1");
    assert.match(JSON.stringify(plan), /audit_log_freeze_idx/);

    // The release before's own insert, which names none of the new columns, still goes in.
    await run(after.db, `INSERT INTO credentials (id, kind, auth_mac, token_hash, token_hint, generation, principal, created_by, expires_at)
      VALUES ('44444444-4444-4444-8444-444444444444', 'personal', X'${hash(9).toString('hex')}', X'${hash(10).toString('hex')}', 'coffre_pat_…mnop', 1, 'user:ada@acme.example', 'user:ada@acme.example', 30)`);
    const workload = (id: string, principal: string, jkt: string | null) =>
      run(after.db, `INSERT INTO credentials (id, kind, auth_mac, token_hash, token_hint, generation, principal, created_by, expires_at, jkt)
        VALUES ('${id}', 'workload', X'${hash(11).toString('hex')}', X'${Buffer.from(id.replace(/-/g, '').padEnd(64, '0'), 'hex').toString('hex')}', 'coffre_wl_…qrst', 1, '${principal}', 'binding:x', 40, ${jkt === null ? 'NULL' : `'${jkt}'`})`);
    await refused(workload('55555555-5555-4555-8555-555555555555', 'token:deploy', null), /credentials_workload_jkt_check/);
    await refused(workload('66666666-6666-4666-8666-666666666666', 'user:ada@acme.example', 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs'), /credentials_kind_matches_principal/);
    await workload('77777777-7777-4777-8777-777777777777', 'token:deploy', 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
    // A session's code exists.
    await refused(
      run(after.db, `UPDATE credentials SET enrollment_id = '88888888-8888-4888-8888-888888888888' WHERE id = '77777777-7777-4777-8777-777777777777'`),
      /FOREIGN KEY constraint failed/,
    );
  } finally {
    await after.close();
  }
});
