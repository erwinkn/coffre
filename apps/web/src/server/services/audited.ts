import type { Database, DatabaseClient } from '../database.ts';

import { appendAudit, type AuditEntry } from '../../../../../packages/db/src/audit.ts';
import { AuditedFailure } from './secrets.ts';

/**
 * The services' one transaction shape: do the work and append its audit
 * entries in the same transaction, so neither commits without the other.
 *
 * A refusal is thrown as an AuditedFailure. Whatever the attempt touched is
 * rolled back, and the refusal's own entry is then committed on its own:
 * "who was turned away" is half of what an audit log is for.
 */
export async function runAudited<T>(
  pool: Database,
  chainKey: Buffer,
  fn: (tx: DatabaseClient) => Promise<{ result: T; entries: AuditEntry[] }>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    let outcome: { result: T; entries: AuditEntry[] };
    try {
      outcome = await fn(client);
    } catch (error) {
      if (error instanceof AuditedFailure) {
        await client.query('ROLLBACK');
        await client.query('BEGIN');
        await appendAudit(client, chainKey, [error.entry]);
        await client.query('COMMIT');
        throw error.cause;
      }
      throw error;
    }

    if (outcome.entries.length > 0) {
      await appendAudit(client, chainKey, outcome.entries);
    }
    await client.query('COMMIT');
    return outcome.result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    await client.release();
  }
}

export async function advisoryLock(tx: DatabaseClient, key: string): Promise<void> {
  await tx.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [key]);
}
