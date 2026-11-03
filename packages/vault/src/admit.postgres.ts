import { createHash } from 'node:crypto';

import { later, type Queryable, type Transaction } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

/** What the add's read is asked: the token's hash, the member it adds, its role's scope's projects by slug, and the Worker's clock. */
export type AdmitCall = { at: number; tokenHash: Buffer; principal: string; scope: readonly string[] };

/** What it answers: the Worker's clock too far ahead (nothing read), or the read, its digest and the app's rows. */
export type AdmitRead =
  | { state: 'ahead' }
  | { state: 'read'; inputs: string; digest: string; app: string };

/** `admit_read` on Postgres (migration 0062): one statement, its own transaction, no lock. */
export async function callAdmit(db: Queryable, call: AdmitCall): Promise<AdmitRead> {
  const [row] = await rowsOf<{ read: string }>(db, sql`SELECT admit_read(
    ${String(call.at)}::bigint, ${call.tokenHash}::bytea, ${call.principal}::text, ${sql.param([...call.scope])}::text[]
  )::text AS read`);
  const answer = JSON.parse(row!.read) as { state: string; inputs?: string; digest?: string; app?: string };
  if (answer.state === 'ahead') return { state: 'ahead' };
  if (answer.state !== 'read' || answer.inputs === undefined || answer.digest === undefined || answer.app === undefined) {
    throw new Error(`admit_read answered ${answer.state}, which no add reads`);
  }
  // The digest is of the bytes the decision parses: Postgres's, checked here over the text as it came.
  const digest = createHash('sha256').update(answer.inputs, 'utf8').digest('hex');
  if (digest !== answer.digest) throw new Error("admit_read's read does not hash to the digest it answered with: its text was changed on the way");
  return { state: 'read', inputs: answer.inputs, digest, app: answer.app };
}

/**
 * The add's hold (`admit_hold`): the issue lock and the fence, then the read again, `coffre_moved` (CF001) unless it
 * reads as decided. Left to `later`, so that it goes with the add's writes and their COMMIT, under one Sync, ahead of
 * them: what it fails with fails the transaction, and nothing is written.
 */
export function holdAdmit(tx: Transaction, hold: { tokenHash: Buffer; principal: string; scope: readonly string[]; digest: Buffer }): void {
  later(tx, sql`SELECT admit_hold(${hold.tokenHash}::bytea, ${hold.principal}::text, ${sql.param([...hold.scope])}::text[], ${hold.digest}::bytea)`);
}
