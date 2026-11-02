import { createHash } from 'node:crypto';

import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

/** What the vault's statement is asked: the token's hash, the place by its slugs, the keys by name, and the Worker's clock. */
export type WriteCall = { at: number; tokenHash: Buffer; project: string; environment: string; keys: readonly string[] };

/** What it answers: the Worker's clock too far ahead (nothing read), or the read, its digest, the app's rows and the request's number. */
export type WriteRead =
  | { state: 'ahead' }
  | { state: 'read'; number: bigint; inputs: string; digest: string; app: string };

/** `write_request` on Postgres: one statement, its own transaction. */
export async function callWrite(db: Queryable, call: WriteCall): Promise<WriteRead> {
  const [row] = await rowsOf<{ write: string }>(db, sql`SELECT write_request(
    ${String(call.at)}::bigint, ${call.tokenHash}::bytea, ${call.project}::text, ${call.environment}::text, ${sql.param([...call.keys])}::text[]
  )::text AS write`);
  const answer = JSON.parse(row!.write) as { state: string; number?: string; inputs?: string; digest?: string; app?: string };
  if (answer.state === 'ahead') return { state: 'ahead' };
  if (answer.state !== 'read' || answer.number === undefined || answer.inputs === undefined || answer.digest === undefined || answer.app === undefined) {
    throw new Error(`write_request answered ${answer.state}, which no write reads`);
  }
  // The digest is of the bytes the decision parses: Postgres's, checked here over the text as it came.
  const digest = createHash('sha256').update(answer.inputs, 'utf8').digest('hex');
  if (digest !== answer.digest) throw new Error("write_request's read does not hash to the digest it answered with: its text was changed on the way");
  return { state: 'read', number: BigInt(answer.number), inputs: answer.inputs, digest, app: answer.app };
}
