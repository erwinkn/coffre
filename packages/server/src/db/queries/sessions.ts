import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

/**
 * A workload's session as the app routes its request (docs/design/0.16.md,
 * "What the app reads of a workload, and decides nothing on"): its id, its
 * service, whose gate takes its proofs, and the thumbprint of the key it is
 * bound to, which must have signed the proof. The row as stored, its MAC
 * unchecked: it finds a gate and turns away another key's proof before the
 * vault is asked, and decides nothing the vault does not decide again on
 * its own read.
 */
export type RoutedSession = { id: string; principal: string; jkt: string };

/** The session whose token hashes to `tokenHash`, one row by the token's unique index; null for no workload's session with a key. */
export async function routedSession(db: Queryable, tokenHash: Buffer): Promise<RoutedSession | null> {
  const [row] = await rowsOf<RoutedSession>(db, sql`
    SELECT id, principal, jkt FROM credentials
    WHERE token_hash = ${tokenHash} AND kind = 'workload' AND jkt IS NOT NULL
  `);
  return row ?? null;
}
