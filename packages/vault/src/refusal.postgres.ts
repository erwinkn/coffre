import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import type { RefusalRow } from './refusal.ts';

/** `log_refusal` on Postgres (the migration of PR 6): one statement, its own transaction, under the fence shared. Its number. */
export async function callRefusal(db: Queryable, row: RefusalRow): Promise<bigint> {
  const [written] = await rowsOf<{ n: string }>(db, sql`SELECT CAST(log_refusal(
    ${String(row.at)}::bigint, ${row.requestId}::text, ${row.actor}::text, ${row.payload}::text, ${row.mac}::bytea
  ) AS text) AS n`);
  return BigInt(written!.n);
}
