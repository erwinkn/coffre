import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { drizzle } from 'drizzle-orm/node-postgres';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import pg from 'pg';

const MIGRATIONS_FOLDER = fileURLToPath(new URL('../migrations', import.meta.url));
const MIGRATIONS_TABLE = 'drizzle.__drizzle_migrations';
const MIGRATION_LOCK_KEY = '7165058122361679213';

interface JournalEntry {
  idx: number;
  when: number;
  tag: string;
}

interface ExpectedMigration {
  createdAt: string;
  hash: string;
  tag: string;
}

interface AppliedMigration {
  created_at: string;
  hash: string;
}

function databaseUrl(): string {
  const value = process.env.DATABASE_URL?.trim();
  if (!value) {
    throw new Error('DATABASE_URL is required');
  }
  return value;
}

async function expectedMigrations(): Promise<ExpectedMigration[]> {
  const journalPath = new URL('../migrations/meta/_journal.json', import.meta.url);
  const journal = JSON.parse(await readFile(journalPath, 'utf8')) as { entries?: JournalEntry[] };
  if (!Array.isArray(journal.entries)) {
    throw new Error('invalid Drizzle migration journal');
  }

  const expected = await Promise.all(
    journal.entries.map(async (entry, position) => {
      if (
        entry.idx !== position
        || !Number.isSafeInteger(entry.when)
        || typeof entry.tag !== 'string'
        || !/^[a-zA-Z0-9_-]+$/.test(entry.tag)
      ) {
        throw new Error(`invalid Drizzle migration journal entry at index ${position}`);
      }
      const sqlText = await readFile(
        new URL(`../migrations/${entry.tag}.sql`, import.meta.url),
        'utf8',
      );
      return {
        createdAt: String(entry.when),
        hash: createHash('sha256').update(sqlText).digest('hex'),
        tag: entry.tag,
      };
    }),
  );

  for (let index = 1; index < expected.length; index += 1) {
    if (BigInt(expected[index - 1].createdAt) >= BigInt(expected[index].createdAt)) {
      throw new Error('Drizzle migration journal timestamps must be strictly increasing');
    }
  }
  return expected;
}

async function appliedMigrations(client: pg.PoolClient): Promise<AppliedMigration[] | null> {
  const relation = await client.query<{ relation: string | null }>(
    "SELECT to_regclass('drizzle.__drizzle_migrations')::text AS relation",
  );
  if (!relation.rows[0]?.relation) {
    return null;
  }

  const result = await client.query<AppliedMigration>(
    `SELECT hash, created_at::text
       FROM ${MIGRATIONS_TABLE}
      ORDER BY created_at, id`,
  );
  return result.rows;
}

function verifyHistory(
  expected: ExpectedMigration[],
  applied: AppliedMigration[] | null,
  requireComplete: boolean,
): void {
  const rows = applied ?? [];
  if (rows.length > expected.length) {
    throw new Error('database contains migrations that are absent from this image');
  }
  if (requireComplete && rows.length !== expected.length) {
    throw new Error(`migration history is incomplete: expected ${expected.length}, found ${rows.length}`);
  }

  rows.forEach((row, index) => {
    const local = expected[index];
    if (row.created_at !== local.createdAt || row.hash !== local.hash) {
      throw new Error(
        `migration history diverged at ${local.tag}; applied migrations must never be edited`,
      );
    }
  });
}

async function main(): Promise<void> {
  const expected = await expectedMigrations();
  const pool = new pg.Pool({
    application_name: 'coffre-migrations',
    connectionString: databaseUrl(),
    max: 1,
  });
  const client = await pool.connect();
  let locked = false;

  try {
    await client.query("SET lock_timeout = '5min'");
    await client.query('SELECT pg_advisory_lock($1::bigint)', [MIGRATION_LOCK_KEY]);
    locked = true;

    verifyHistory(expected, await appliedMigrations(client), false);
    await migrate(drizzle(client), { migrationsFolder: MIGRATIONS_FOLDER });
    verifyHistory(expected, await appliedMigrations(client), true);
    console.log('database schema is up to date');
  } finally {
    try {
      if (locked) {
        await client.query('SELECT pg_advisory_unlock($1::bigint)', [MIGRATION_LOCK_KEY]);
      }
    } finally {
      client.release();
      await pool.end();
    }
  }
}

await main();
