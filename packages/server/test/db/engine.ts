import { createDatabase, tablesOf, type Database, type Queryable } from '@coffre/db';
import { openDatabase } from '@coffre/db/connect';
import type { Engine } from '@coffre/db/dialect';
import { forgetLogHeads } from '@coffre/db/log';
import { sql, type SQL } from 'drizzle-orm';

import { TEST_OWNER_DATABASE_URL, TEST_RUNTIME_DATABASE_URL, TEST_VAULT_DATABASE_URL } from './connections.ts';
import { guardTransactions } from '../transaction-guard.ts';
import { drainBackgroundTasks } from '../background-tasks.ts';
import { testPostgresPool } from './postgres-pool.ts';

/**
 * Which database the integration suite runs on: `COFFRE_TEST_ENGINE` is
 * postgres (the default) or sqlite. scripts/test-suite.sh prepares it,
 * and for SQLite hands its URL over in `COFFRE_TEST_DATABASE_URL`.
 */
export const TEST_ENGINE = testEngine(process.env.COFFRE_TEST_ENGINE ?? 'postgres');

function testEngine(name: string): Engine {
  if (name === 'postgres' || name === 'sqlite') return name;
  throw new Error(`COFFRE_TEST_ENGINE must be postgres or sqlite, not ${name}`);
}

/**
 * The integration database twice: as its owner, to reset and inspect, and
 * as the app. On Postgres the app is the restricted runtime role. SQLite
 * has no logins, but opens two clients all the same, as two servers would.
 */
export async function openTestDatabase(): Promise<{ owner: Database; runtime: Database; close: () => Promise<void> }> {
  if (TEST_ENGINE === 'postgres') {
    const ownerPool = testPostgresPool(TEST_OWNER_DATABASE_URL);
    const runtimePool = testPostgresPool(TEST_RUNTIME_DATABASE_URL);
    return {
      owner: guardTransactions(createDatabase(ownerPool)),
      runtime: guardTransactions(createDatabase(runtimePool)),
      close: async () => {
        await drainBackgroundTasks();
        await Promise.all([ownerPool.end(), runtimePool.end()]);
      },
    };
  }
  const url = process.env.COFFRE_TEST_DATABASE_URL;
  if (!url) throw new Error(`COFFRE_TEST_DATABASE_URL is required on ${TEST_ENGINE}; see scripts/setup-test-database.sh`);
  const [owner, runtime] = await Promise.all([openDatabase(url), openDatabase(url)]);
  return {
    owner: guardTransactions(owner.db),
    runtime: guardTransactions(runtime.db),
    close: async () => {
      await drainBackgroundTasks();
      await Promise.all([owner.close(), runtime.close()]);
    },
  };
}

let vaultDatabase: Promise<Database> | null = null;

/**
 * The integration database as the vault: on Postgres, the vault's own
 * login; on SQLite, the same file. Opened once, on first use, and left to
 * the end of the process: its pool lets the process exit when idle.
 */
export function openVaultDatabase(): Promise<Database> {
  vaultDatabase ??= (async () => {
    if (TEST_ENGINE === 'postgres') {
      return createDatabase(testPostgresPool(TEST_VAULT_DATABASE_URL, true));
    }
    const url = process.env.COFFRE_TEST_DATABASE_URL;
    if (!url) throw new Error(`COFFRE_TEST_DATABASE_URL is required on ${TEST_ENGINE}; see scripts/setup-test-database.sh`);
    return (await openDatabase(url)).db;
  })();
  return vaultDatabase;
}

/** Test options that run a test on Postgres only, saying why it cannot run elsewhere. */
export function postgresOnly(reason: string): { skip: string | false } {
  return { skip: TEST_ENGINE === 'postgres' ? false : `Postgres only: ${reason}` };
}

/**
 * `work`, as the owner, with the audit log's append-only triggers lifted:
 * what a test does to empty the log between cases, or to play someone who
 * rewrites it.
 */
export function withLogUnlocked<T>(owner: Database, work: (db: Queryable) => Promise<T>): Promise<T> {
  return withTriggersLifted(owner, 'audit_log', work);
}

/**
 * `work`, as the owner, with a table's own triggers lifted: the log's, or
 * `secret_versions`', which lets a version only be erased. Postgres disables
 * them for one transaction; SQLite has no such switch, so they are dropped
 * and made again.
 */
export async function withTriggersLifted<T>(owner: Database, table: 'audit_log' | 'secret_versions', work: (db: Queryable) => Promise<T>): Promise<T> {
  if (TEST_ENGINE === 'postgres') {
    return owner.transaction(async (tx) => {
      await tx.execute(sql.raw(`ALTER TABLE ${table} DISABLE TRIGGER USER`));
      const result = await work(tx);
      await tx.execute(sql.raw(`ALTER TABLE ${table} ENABLE TRIGGER USER`));
      return result;
    });
  }
  const sqlite = owner as unknown as { all<Row>(query: SQL): Promise<Row[]>; run(query: SQL): Promise<unknown> };
  const triggers = await sqlite.all<{ name: string; sql: string }>(
    sql`SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ${table}`,
  );
  for (const trigger of triggers) await sqlite.run(sql.raw(`DROP TRIGGER ${trigger.name}`));
  try {
    return await work(owner);
  } finally {
    for (const trigger of triggers) await sqlite.run(sql.raw(trigger.sql));
  }
}

/**
 * Empty the audit log and rewind its head, and forget the heads this process
 * found in it, which would otherwise refuse the next append as a rollback.
 */
export async function emptyLog(owner: Database): Promise<void> {
  const { auditLog, auditChainHead } = tablesOf(owner);
  // SQLite checks a RESTRICT foreign key row by row, so entries that point
  // at others let go of them first.
  await withLogUnlocked(owner, async (db) => {
    await db.update(auditLog).set({ relatedSeq: null });
    await db.delete(auditLog);
  });
  await owner.update(auditChainHead).set({ nextSeq: 0n, headHash: Buffer.alloc(32) });
  forgetLogHeads();
}
