import { createDatabase, type Database, type Queryable } from '@coffre/db';
import { forgetLogHeads } from '@coffre/db/log';
import { sql } from 'drizzle-orm';

import { TEST_OWNER_DATABASE_URL, TEST_RUNTIME_DATABASE_URL, TEST_VAULT_DATABASE_URL } from './connections.ts';
import { guardTransactions } from '../transaction-guard.ts';
import { drainBackgroundTasks } from '../background-tasks.ts';
import { testPostgresPool } from './postgres-pool.ts';
import { auditChainHead, vaultReleases } from '@coffre/db/schema';

/**
 * The integration database twice: as its owner, to reset and inspect, and
 * as the app. The app is the restricted runtime role.
 */
export async function openTestDatabase(): Promise<{ owner: Database; runtime: Database; close: () => Promise<void> }> {
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

let vaultDatabase: Promise<Database> | null = null;
let vaultPool: { end(): Promise<void> } | null = null;

/** Ends `openVaultDatabase`'s pool, for a process whose pools keep their connections (`keepTestConnections`). */
export async function closeVaultDatabase(): Promise<void> {
  const pool = vaultPool;
  [vaultDatabase, vaultPool] = [null, null];
  await pool?.end();
}

/**
 * The integration database as the vault: the vault's own login. Opened
 * once, on first use, and left to the end of the process: its pool lets
 * the process exit when idle.
 */
export function openVaultDatabase(): Promise<Database> {
  vaultDatabase ??= (async () => {
    const pool = testPostgresPool(TEST_VAULT_DATABASE_URL, true);
    vaultPool = pool;
    return createDatabase(pool);
  })();
  return vaultDatabase;
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
 * `secret_versions`', which lets a version only be erased. Disabled for one
 * transaction.
 */
export async function withTriggersLifted<T>(owner: Database, table: 'audit_log' | 'secret_versions' | 'log_changes', work: (db: Queryable) => Promise<T>): Promise<T> {
  return owner.transaction(async (tx) => {
    await tx.execute(sql.raw(`ALTER TABLE ${table} DISABLE TRIGGER USER`));
    const result = await work(tx);
    await tx.execute(sql.raw(`ALTER TABLE ${table} ENABLE TRIGGER USER`));
    return result;
  });
}

/**
 * Empty the audit log and rewind its head, and forget the heads this process
 * found in it, which would otherwise refuse the next append as a rollback.
 */
export async function emptyLog(owner: Database): Promise<void> {
  // Deleting checks every row against `related_seq`, which no index serves: a log of thousands takes longer than a
  // statement may. References name entries, and are gone by now.
  await withLogUnlocked(owner, async (db) => void (await db.execute(sql`TRUNCATE audit_log, secret_references`)));
  await owner.update(auditChainHead).set({ nextSeq: 0n, headHash: Buffer.alloc(32) });
  // Kept from the log, and gone with it.
  await owner.delete(vaultReleases);
  forgetLogHeads();
}
