// What a migration waits for (docs/design/limits.md D2): the advisory lock, as long as another migrator's run
// takes; a table, no longer than a use could stand to wait behind it, tried again a stated number of times, then
// refused loudly, rather than queue every use of that table behind it for minutes.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { migrate } from 'drizzle-orm/postgres-js/migrator';

import { HOT_LOCK_TIMEOUT_MS } from '@coffre/core/vault';

import { createDatabase } from '../src/database.ts';
import {
  LockWaitsExhausted,
  migrateDatabase,
  MIGRATION_LOCK_ATTEMPTS,
  MIGRATION_LOCK_PAUSE_MS,
  MIGRATION_LOCK_WAIT_MS,
  migrationsFolder,
} from '../src/migrate.ts';
import { postgresClient, postgresSession, quoteIdentifier, type PostgresClient } from '../src/postgres.ts';

const BASE = `postgresql://coffre_owner:local-dev-only@127.0.0.1:${process.env.COFFRE_POSTGRES_PORT ?? '55432'}/${process.env.COFFRE_TEST_DATABASE ?? 'coffre_test'}`;
const NAME = `${new URL(BASE).pathname.slice(1)}_locks_${randomBytes(4).toString('hex')}`;
const url = Object.assign(new URL(BASE), { pathname: `/${NAME}` }).toString();
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * The newest migration that adds a column to a table an earlier one made, and the table: ALTER TABLE … ADD COLUMN
 * takes ACCESS EXCLUSIVE, which waits for any session holding the table, a reader's ACCESS SHARE included.
 */
function pendingAlter(): { tag: string; table: string; journal: { entries: { tag: string }[] } } {
  const folder = migrationsFolder();
  const journal = JSON.parse(readFileSync(join(folder, 'meta/_journal.json'), 'utf8')) as { entries: { tag: string }[] };
  for (const { tag } of [...journal.entries].reverse()) {
    const table = /ALTER TABLE "(\w+)" ADD COLUMN/.exec(readFileSync(join(folder, `${tag}.sql`), 'utf8'))?.[1];
    if (table !== undefined) return { tag, table, journal };
  }
  throw new Error('no migration adds a column to a table');
}

const { tag: TAG, table: TABLE, journal: JOURNAL } = pendingAlter();
const AT = JOURNAL.entries.findIndex((entry) => entry.tag === TAG);
const dirs: string[] = [];

before(async () => {
  // The tree before TAG: it and every migration after it are left to migrateDatabase.
  const dir = mkdtempSync(join(tmpdir(), 'coffre-locks-'));
  dirs.push(dir);
  const folder = join(dir, 'migrations');
  cpSync(migrationsFolder(), folder, { recursive: true });
  writeFileSync(join(folder, 'meta/_journal.json'), JSON.stringify({ ...JOURNAL, entries: JOURNAL.entries.slice(0, AT) }));
  for (const { tag } of JOURNAL.entries.slice(AT)) rmSync(join(folder, `${tag}.sql`));
  assert.equal(readdirSync(folder).filter((file) => file.endsWith('.sql')).length, AT);

  const admin = postgresClient(BASE, { max: 1 });
  try {
    await admin.unsafe(`CREATE DATABASE ${quoteIdentifier(NAME)}`);
  } finally {
    await admin.end();
  }
  const session = postgresSession(url);
  try {
    await migrate(createDatabase(session) as unknown as Parameters<typeof migrate>[0], { migrationsFolder: folder });
    const [found] = await session.unsafe<{ relation: string | null }[]>(`SELECT to_regclass('public.${TABLE}')::text AS relation`);
    assert.equal(found?.relation, TABLE, `${TABLE} is there before ${TAG}`);
  } finally {
    await session.end();
  }
});

after(async () => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
  const admin = postgresClient(BASE, { max: 1 });
  try {
    await admin.unsafe(`DROP DATABASE IF EXISTS ${quoteIdentifier(NAME)} WITH (FORCE)`);
  } finally {
    await admin.end();
  }
});

/** A session holding TABLE as a long read does, ACCESS SHARE, until `release()`. */
async function holdTable(): Promise<{ pid: number; release: () => Promise<void> }> {
  const holder = postgresSession(url, { application_name: 'coffre-locks-holder' });
  await holder.unsafe('BEGIN');
  await holder.unsafe(`LOCK TABLE ${quoteIdentifier(TABLE)} IN ACCESS SHARE MODE`);
  const [row] = await holder.unsafe<{ pid: number }[]>('SELECT pg_backend_pid() AS pid');
  return {
    pid: row!.pid,
    release: async () => {
      await holder.unsafe('COMMIT');
      await holder.end();
    },
  };
}

/** How many of the migrator's sessions wait for a lock of `kind` in the test's database. */
async function waiting(observer: PostgresClient, kind: 'relation' | 'advisory'): Promise<number> {
  const [row] = await observer.unsafe<{ n: number }[]>(
    `SELECT count(*)::int AS n FROM pg_locks l JOIN pg_stat_activity a USING (pid)
      WHERE NOT l.granted AND l.locktype = $1 AND a.application_name = 'coffre-migrations' AND a.datname = $2`,
    [kind, NAME],
  );
  return row!.n;
}

/** How long a migrator's statement waiting for a lock of `kind` in the test's database has waited, in ms, or 0. */
async function waitedFor(observer: PostgresClient, kind: 'advisory' | 'object'): Promise<number> {
  const [row] = await observer.unsafe<{ ms: number }[]>(
    `SELECT coalesce(max(extract(epoch FROM clock_timestamp() - a.query_start) * 1000), 0)::int AS ms
       FROM pg_locks l JOIN pg_stat_activity a USING (pid)
      WHERE NOT l.granted AND l.locktype = $1 AND a.application_name = 'coffre-migrations' AND a.datname = $2`,
    [kind, NAME],
  );
  return row!.ms;
}

async function until(check: () => Promise<boolean>, what: string, within = 10_000): Promise<void> {
  const deadline = Date.now() + within;
  while (!(await check())) {
    if (Date.now() > deadline) throw new Error(`timed out waiting until ${what}`);
    await sleep(10);
  }
}

async function ledger(observer: PostgresClient): Promise<number> {
  const [row] = await observer.unsafe<{ n: number }[]>('SELECT count(*)::int AS n FROM drizzle.__drizzle_migrations');
  return row!.n;
}

test('the waits are what their comments say: a statement waits half what a use may, tried a handful of times', () => {
  assert.ok(MIGRATION_LOCK_WAIT_MS < HOT_LOCK_TIMEOUT_MS, 'a migration statement leaves the queue before a use behind it is refused');
  assert.equal(MIGRATION_LOCK_WAIT_MS, HOT_LOCK_TIMEOUT_MS / 2);
  assert.ok(MIGRATION_LOCK_ATTEMPTS > 1);
});

test(`a table held past every try fails the migration loudly within seconds, naming who held it, and a use of the table behind it waits less than its own lock_timeout (${TAG}, ${TABLE})`, async () => {
  const observer = postgresClient(url, { max: 1 });
  const holder = await holdTable();
  // A use's session: the hot login's lock_timeout, reading TABLE again and again while the migration waits.
  const reader = postgresSession(url, { application_name: 'coffre-locks-reader' });
  let run: Promise<unknown> | undefined;
  try {
    const before = await ledger(observer);
    await reader.unsafe(`SET lock_timeout = '${HOT_LOCK_TIMEOUT_MS}ms'`);
    // Every try waits its wait, with a pause between: well under the advisory lock's 5 minutes.
    const least = MIGRATION_LOCK_ATTEMPTS * MIGRATION_LOCK_WAIT_MS + (MIGRATION_LOCK_ATTEMPTS - 1) * MIGRATION_LOCK_PAUSE_MS;
    const most = least + 15_000;
    const started = Date.now();
    let settled = false;
    run = migrateDatabase(url).finally(() => (settled = true));
    run.catch(() => {});

    await until(async () => (await waiting(observer, 'relation')) > 0, `the migration waits for ${TABLE}`);
    const reads: number[] = [];
    while (!settled) {
      if (Date.now() - started > most) assert.fail(`the migration was still trying after ${most} ms`);
      const at = Date.now();
      await reader.unsafe(`SELECT count(*) FROM ${quoteIdentifier(TABLE)}`);
      reads.push(Date.now() - at);
      await sleep(25);
    }

    const error = await run.then(() => assert.fail('the migration ran with its table held'), (thrown: unknown) => thrown);
    const took = Date.now() - started;
    assert.ok(error instanceof LockWaitsExhausted, `refused as LockWaitsExhausted, not ${String(error)}`);
    assert.equal(error.attempts, MIGRATION_LOCK_ATTEMPTS);
    assert.match(error.message, new RegExp(`waited for a lock ${MIGRATION_LOCK_ATTEMPTS} times, ${MIGRATION_LOCK_WAIT_MS} ms each`));
    assert.match(error.message, new RegExp(`pid ${holder.pid} \\(coffre_owner, coffre-locks-holder\\) on public\\.${TABLE}\\b`));
    assert.match(error.message, /ALTER TABLE/, 'the statement that waited');
    assert.deepEqual(error.holders?.find((found) => found.pid === holder.pid)?.tables, [`public.${TABLE}`]);
    assert.ok(took >= least, `gave up after ${took} ms, before its ${least} ms of tries`);
    assert.equal(await ledger(observer), before, 'nothing applied');

    // Each read queued behind the migration's wait at most, and none was refused: it ran within the use's own wait.
    const slowest = Math.max(...reads);
    assert.ok(slowest >= MIGRATION_LOCK_WAIT_MS / 2, `a read queued behind the migration's wait (slowest ${slowest} ms of ${reads.length})`);
    assert.ok(slowest < MIGRATION_LOCK_WAIT_MS + 250, `a read waited ${slowest} ms behind the migration`);
  } finally {
    // The table released, a migration still trying ends before the next test.
    await holder.release();
    await run?.catch(() => {});
    await reader.end();
    await observer.end();
  }
});

test('a table released between tries lets the next try apply the migrations, while a second migrator waits for the first on the advisory lock past a use\'s wait', async () => {
  const observer = postgresClient(url, { max: 1 });
  const holder = await holdTable();
  let released = false;
  const runs: Promise<unknown>[] = [];
  try {
    const first = migrateDatabase(url);
    runs.push(first);
    first.catch(() => {});
    await until(async () => (await waiting(observer, 'relation')) > 0, 'the first try waits for the table');

    const secondStarted = Date.now();
    const second = migrateDatabase(url).then(() => Date.now() - secondStarted);
    second.catch(() => {});
    runs.push(second);
    // The first migrator tries again, the table still held, until the second has waited past a use's wait.
    await until(async () => (await waitedFor(observer, 'advisory')) > HOT_LOCK_TIMEOUT_MS, "the second migrator waits past a use's wait");

    // Then release the table in a pause between tries, before the next.
    await until(async () => (await waiting(observer, 'relation')) === 0, 'a try gives up');
    await holder.release();
    released = true;

    await first;
    const waited = await second;
    assert.equal(await ledger(observer), JOURNAL.entries.length, 'every migration applied');
    assert.ok(waited > HOT_LOCK_TIMEOUT_MS, `the second migrator waited ${waited} ms for the first, past any table's wait, and did not fail`);
  } finally {
    if (!released) await holder.release();
    await Promise.allSettled(runs);
    await observer.end();
  }
});

test("reasserting the privileges waits for another database's migrator changing the same role, as for the migration lock, rather than fail in a use's wait", async () => {
  // The roles are the server's: another database's run granting coffre_backup holds the role's lock to its commit.
  const other = postgresSession(BASE, { application_name: 'coffre-locks-other-database' });
  const observer = postgresClient(url, { max: 1 });
  let run: Promise<unknown> | undefined;
  let rolledBack = false;
  try {
    await other.unsafe('BEGIN');
    await other.unsafe('GRANT coffre_backup TO coffre_backup_login WITH ADMIN FALSE, INHERIT TRUE, SET FALSE');
    run = migrateDatabase(url, { backupLogin: 'coffre_backup_login' });
    run.catch(() => {});
    // One statement waits past a use's wait, and a migration statement's, never tried again in between.
    await until(async () => (await waitedFor(observer, 'object')) > 3 * MIGRATION_LOCK_WAIT_MS, 'the grant has waited past three of a migration statement\'s waits');
    await other.unsafe('ROLLBACK');
    rolledBack = true;
    await run;
  } finally {
    if (!rolledBack) await other.unsafe('ROLLBACK').catch(() => {});
    await other.end();
    await run?.catch(() => {});
    await observer.end();
  }
});
