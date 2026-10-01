import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { migrate } from '../src/schema.ts';
import { nodeSqlite } from '../src/sqlite-node.ts';

function scratch(t: test.TestContext): string {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-vault-sqlite-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return join(dir, 'vault.db');
}

function mode(file: string): string {
  return (statSync(file).mode & 0o777).toString(8);
}

test('a new store is 0600, its -wal and -shm too, in WAL with full syncs', (t) => {
  const path = scratch(t);
  const db = nodeSqlite(path);
  t.after(() => db.close());
  migrate(db);
  db.transaction(() => db.run(`INSERT INTO checkpoints VALUES (1, 'h', 0, 'v', 0, 'k', 's')`));
  assert.deepEqual([path, `${path}-wal`, `${path}-shm`].map(mode), ['600', '600', '600']);
  assert.equal(db.get<{ journal_mode: string }>('PRAGMA journal_mode')?.journal_mode, 'wal');
  assert.equal(db.get<{ synchronous: number }>('PRAGMA synchronous')?.synchronous, 2);
});

test('a store others may write is refused; one they may read is closed to them', (t) => {
  const path = scratch(t);
  writeFileSync(path, '');
  chmodSync(path, 0o664);
  assert.throws(() => nodeSqlite(path), /writable by other users \(mode 664\)/);

  const warn = t.mock.method(console, 'warn', () => undefined);
  chmodSync(path, 0o644);
  nodeSqlite(path).close();
  assert.equal(mode(path), '600');
  assert.match(String(warn.mock.calls[0].arguments[0]), /readable by other users \(mode 644\)/);
});

test('a transaction commits, rolls back whatever it wrote when it throws, and does not nest', (t) => {
  const db = nodeSqlite(scratch(t));
  t.after(() => db.close());
  db.run('CREATE TABLE t (n INTEGER) STRICT');
  const count = () => db.get<{ n: number }>('SELECT count(*) AS n FROM t')!.n;

  assert.equal(db.transaction(() => (db.run('INSERT INTO t VALUES (1)'), 'done')), 'done');
  assert.throws(
    () =>
      db.transaction(() => {
        db.run('INSERT INTO t VALUES (2)');
        throw new Error('no');
      }),
    /no/,
  );
  assert.equal(count(), 1);
  assert.throws(() => db.transaction(() => db.transaction(() => db.run('INSERT INTO t VALUES (3)'))), /do not nest/);
  assert.equal(count(), 1);
  assert.deepEqual([...db.iterate<{ n: number }>('SELECT n FROM t')].map((row) => row.n), [1]);
});

test('migrating is idempotent, and a store from a newer vault is refused', (t) => {
  const path = scratch(t);
  const tables = (db: ReturnType<typeof nodeSqlite>) =>
    db.all<{ name: string }>(`SELECT name FROM sqlite_schema WHERE type IN ('table', 'trigger') ORDER BY name`).map((row) => row.name);

  const first = nodeSqlite(path);
  migrate(first);
  const created = tables(first);
  assert.deepEqual(created, [
    'checkpoints',
    'checkpoints_no_delete',
    'checkpoints_no_update',
    'grants',
    'log',
    'log_no_delete',
    'log_no_update',
    'migrations',
    'principals',
  ]);
  first.close();

  const again = nodeSqlite(path);
  t.after(() => again.close());
  migrate(again);
  migrate(again);
  assert.deepEqual(tables(again), created);
  assert.deepEqual(again.all('SELECT version FROM migrations').map((row) => ({ ...(row as object) })), [{ version: 1 }]);

  again.run('INSERT INTO migrations (version) VALUES (2)');
  assert.throws(() => migrate(again), /at version 2; this vault knows 1/);
});
