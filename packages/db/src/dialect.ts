import { sql } from 'drizzle-orm';
import { bigint, integer, pgSchema, text, type PgTable } from 'drizzle-orm/pg-core';

import type { Transaction } from './database.ts';
import { auditChainHead, syncKeys } from './schema.ts';

/**
 * Everything that is written differently on Postgres, MySQL and SQLite, and
 * nothing else. The rest of coffre's queries are builder code that reads the
 * same on all three, so moving to another database means another copy of
 * this file, not an audit of the whole server.
 *
 *                     Postgres                MySQL                  SQLite
 *   lock a row        SELECT … FOR UPDATE     SELECT … FOR UPDATE    one writer at a time
 *   insert if absent  ON CONFLICT DO NOTHING  INSERT IGNORE          ON CONFLICT DO NOTHING
 *   upsert            ON CONFLICT DO UPDATE   ON DUPLICATE KEY       ON CONFLICT DO UPDATE
 *   duplicate key     SQLSTATE 23505          errno 1062             SQLITE_CONSTRAINT_UNIQUE
 */

/** A second name for a table, to join it twice. Each dialect's core exports its own. */
export { alias } from 'drizzle-orm/pg-core';

/** Lock the rows a select reads until the transaction ends. */
export function forUpdate<Query extends { for: (strength: 'update') => unknown }>(
  query: Query,
): ReturnType<Query['for']> {
  return query.for('update') as ReturnType<Query['for']>;
}

/**
 * Lock the audit chain head and read the database clock in one statement.
 * Every appender queues here, which is what keeps the chain a chain. The
 * clock is the database's, not an application server's, so entries from
 * several servers still order by time (CDR 2024/1774 Art 12(2)(f)).
 */
export async function lockAuditHead(
  tx: Transaction,
): Promise<{ nextSeq: bigint; headHash: Buffer; now: string } | null> {
  const [head] = await forUpdate(
    tx
      .select({
        nextSeq: auditChainHead.nextSeq,
        headHash: auditChainHead.headHash,
        now: sql<string>`CURRENT_TIMESTAMP`,
      })
      .from(auditChainHead)
      .limit(1),
  );
  return head ?? null;
}

/**
 * Insert a row unless one with the same unique key exists. Two writers
 * adding the same secret both end up writing versions of one secret; two
 * first sign-ins of a root admin both find one principal.
 */
export async function insertIfAbsent<Table extends PgTable>(
  tx: Transaction,
  table: Table,
  row: Table['$inferInsert'],
): Promise<void> {
  await tx.insert(table).values(row).onConflictDoNothing();
}

/** Record that a sync pushed a key at a version, or pushed it again. */
export async function upsertSyncKey(
  tx: Transaction,
  row: { syncId: string; key: string; secretVersionId: string; pushedAt: Date },
): Promise<void> {
  await tx
    .insert(syncKeys)
    .values({ ...row, removedAt: null })
    .onConflictDoUpdate({
      target: [syncKeys.syncId, syncKeys.key],
      set: { secretVersionId: row.secretVersionId, pushedAt: row.pushedAt, removedAt: null },
    });
}

/** Whether an insert or update failed on a unique constraint. */
export function isUniqueViolation(error: unknown): boolean {
  for (let cause = error; typeof cause === 'object' && cause !== null; ) {
    if ((cause as { code?: unknown }).code === '23505') return true;
    cause = (cause as { cause?: unknown }).cause;
  }
  return false;
}

/**
 * The migrator's own ledger, read by readiness to tell a database that is
 * up but not yet migrated from one that is ready. Drizzle keeps it in a
 * `drizzle` schema on Postgres, and in a plain table elsewhere.
 */
export const migrations = pgSchema('drizzle').table('__drizzle_migrations', {
  id: integer().primaryKey(),
  hash: text().notNull(),
  createdAt: bigint('created_at', { mode: 'number' }),
});
