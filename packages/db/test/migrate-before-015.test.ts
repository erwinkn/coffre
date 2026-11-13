// 0.16 upgrades only from a 0.15.0 that cut its log over: a database a release before 0.15.0 left is
// refused before anything changes, through `migrateDatabase` as through `coffre migrate`.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { migrate } from 'drizzle-orm/postgres-js/migrator';

import { createDatabase } from '../src/database.ts';
import { migrateDatabase, migrationsFolder } from '../src/migrate.ts';
import { postgresClient, postgresSession, quoteIdentifier } from '../src/postgres.ts';

const BASE = `postgresql://coffre_owner:local-dev-only@127.0.0.1:${process.env.COFFRE_POSTGRES_PORT ?? '55432'}/${process.env.COFFRE_TEST_DATABASE ?? 'coffre_test'}`;

test("a database on 0.14.5's schema is refused, its ledger as it was", async (t) => {
  const name = `${new URL(BASE).pathname.slice(1)}_before015_${randomBytes(4).toString('hex')}`;
  const url = Object.assign(new URL(BASE), { pathname: `/${name}` }).toString();
  const admin = postgresClient(BASE, { max: 1 });
  await admin.unsafe(`CREATE DATABASE ${quoteIdentifier(name)}`);
  const dir = mkdtempSync(join(tmpdir(), 'coffre-before-015-'));
  t.after(async () => {
    await admin.unsafe(`DROP DATABASE IF EXISTS ${quoteIdentifier(name)} WITH (FORCE)`);
    await admin.end();
    rmSync(dir, { recursive: true, force: true });
  });

  // The migrations before 0.15's first, 0022_log_015: 0.14.5's.
  const folder = join(dir, 'migrations');
  cpSync(migrationsFolder(), folder, { recursive: true });
  const journal = JSON.parse(readFileSync(join(folder, 'meta/_journal.json'), 'utf8')) as { entries: { tag: string }[] };
  const at = journal.entries.findIndex((entry) => entry.tag === '0022_log_015');
  assert.ok(at > 0);
  writeFileSync(join(folder, 'meta/_journal.json'), JSON.stringify({ ...journal, entries: journal.entries.slice(0, at) }));
  for (const { tag } of journal.entries.slice(at)) rmSync(join(folder, `${tag}.sql`));
  const session = postgresSession(url);
  try {
    await migrate(createDatabase(session) as unknown as Parameters<typeof migrate>[0], { migrationsFolder: folder });
  } finally {
    await session.end();
  }

  await assert.rejects(migrateDatabase(url), /the database was made by a coffre before 0\.15\.0, which this version does not upgrade from: upgrade it to 0\.15\.0 and start it once/);
  const observer = postgresClient(url, { max: 1 });
  try {
    const [row] = await observer.unsafe<{ n: number }[]>('SELECT count(*)::int AS n FROM drizzle.__drizzle_migrations');
    assert.equal(row!.n, at, 'nothing applied');
  } finally {
    await observer.end();
  }
});
