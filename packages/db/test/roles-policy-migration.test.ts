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
 * 0040_roles_policy copies `log_config`'s policy row into the typed `policy` table, on a database the release
 * before wrote. That release writes the value canonical, its keys sorted (`bulk` before `kind`), and SQLite's
 * `json()` keeps a value's key order: the copy holds the value to its shape, whatever the order, and leaves out
 * anything else, a writer's row or one under no seal, so that no row stands for it (review r1 of #544).
 */

const TAG = '0040_roles_policy';
const SEAL = Buffer.alloc(16, 7);

type Db = Awaited<ReturnType<typeof openDatabase>>['db'];
const all = (db: Db, text: string) => (db as unknown as { all(query: ReturnType<typeof sql.raw>): Promise<Record<string, unknown>[]> }).all(sql.raw(text));
const run = (db: Db, text: string) => (db as unknown as { run(query: ReturnType<typeof sql.raw>): Promise<unknown> }).run(sql.raw(text));

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

/** The `policy` rows a database holds once migrated from one whose `log_config` policy row is this. */
async function migrated(t: test.TestContext, value: string, seal: Buffer | null): Promise<Record<string, unknown>[]> {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-0040-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const url = `file:${join(dir, 'coffre.db')}`;
  const { db, close } = await openDatabase(url);
  try {
    await migrate(db as never, { migrationsFolder: before(dir) });
    await run(db, `INSERT INTO log_config (name, value, seal) VALUES ('policy', '${value}', ${seal === null ? 'NULL' : `X'${seal.toString('hex')}'`})`);
  } finally {
    await close();
  }
  await migrateDatabase(url);
  const after = await openDatabase(url);
  try {
    return await all(after.db, 'SELECT name, bulk_count, bulk_window_ms, hex(seal) AS seal FROM policy');
  } finally {
    await after.close();
  }
}

const copied = (count: number, windowMs: number) => [{ name: 'instance', bulk_count: count, bulk_window_ms: windowMs, seal: SEAL.toString('hex').toUpperCase() }];

test(`${TAG} copies the policy the release before wrote, its keys sorted, into the typed row on SQLite`, async (t) => {
  // Exactly what 0.15.0's vault writes: `canonical(after)`, keys sorted.
  assert.deepEqual(await migrated(t, '{"bulk":{"count":1000,"windowMs":900000},"kind":"policy"}', SEAL), copied(1000, 900_000));
});

test(`${TAG} copies a policy whatever its keys' order on SQLite`, async (t) => {
  assert.deepEqual(await migrated(t, '{"kind":"policy","bulk":{"windowMs":60000,"count":5}}', SEAL), copied(5, 60_000));
});

test(`${TAG} leaves out a policy row that is not one of the vault's, or under no seal, on SQLite`, async (t) => {
  const refused = {
    'no seal': ['{"bulk":{"count":1000,"windowMs":900000},"kind":"policy"}', null],
    'a key more': ['{"bulk":{"count":1000,"windowMs":900000},"kind":"policy","x":1}', SEAL],
    'a bulk key more': ['{"bulk":{"count":1000,"windowMs":900000,"x":1},"kind":"policy"}', SEAL],
    'no kind': ['{"bulk":{"count":1000,"windowMs":900000}}', SEAL],
    'another kind': ['{"bulk":{"count":1000,"windowMs":900000},"kind":"roles"}', SEAL],
    'a count not whole': ['{"bulk":{"count":1000.5,"windowMs":900000},"kind":"policy"}', SEAL],
    'a count of none': ['{"bulk":{"count":0,"windowMs":900000},"kind":"policy"}', SEAL],
    'a window over a day': ['{"bulk":{"count":1000,"windowMs":86400001},"kind":"policy"}', SEAL],
    'a count as text': ['{"bulk":{"count":"1000","windowMs":900000},"kind":"policy"}', SEAL],
    'not an object': ['[1000,900000]', SEAL],
  } satisfies Record<string, [string, Buffer | null]>;
  for (const [name, [value, seal]] of Object.entries(refused)) {
    assert.deepEqual(await migrated(t, value, seal), [], name);
  }
});
