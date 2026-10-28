import { randomUUID } from 'node:crypto';

import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import type { Answer, RevokeCall, SignInCall } from './credentials.ts';

/** `sign_in` (migration 0034): one statement, its own transaction, its answer one JSON value. */
export async function signInOnPostgres(db: Queryable, c: SignInCall): Promise<Answer> {
  const k = c.credential;
  const [row] = await rowsOf<{ answer: string }>(db, sql`/* writes */ SELECT sign_in(
    ${c.requestId}::text, ${String(c.at)}::bigint, ${c.actor}::text, ${c.payload}::text, ${c.mac}::bytea, ${c.seal}::bytea,
    ${c.binding.id}::uuid, ${c.principal}::text, ${c.binding.generation}::integer, ${c.binding.scope}::text, ${c.binding.policy}::text,
    ${c.spent}::bytea, ${c.validUntil === null ? null : String(c.validUntil)}::bigint, ${c.frozen}::boolean, ${c.rate}::integer, ${String(c.window)}::bigint, ${String(c.longest)}::bigint,
    ${k.id}::uuid, ${k.kind}::text, ${k.authMacBytes}::bytea, ${k.tokenHashBytes}::bytea, ${k.tokenHint}::text, ${k.label}::text, ${k.createdBy}::text,
    ${k.scope}::text, ${k.places}::text, ${String(k.expiresAt)}::bigint, ${k.notAfter === null ? null : String(k.notAfter)}::bigint, ${k.jkt}::text
  )::text AS answer`);
  return JSON.parse(row!.answer) as Answer;
}

/** `revoke_credential` (migration 0034): one statement, its own transaction, its answer one JSON value. */
export async function revokeOnPostgres(db: Queryable, c: RevokeCall): Promise<Answer> {
  const [row] = await rowsOf<{ answer: string }>(db, sql`/* writes */ SELECT revoke_credential(
    ${c.change?.requestId ?? randomUUID()}::text, ${String(c.at)}::bigint, ${c.actor}::text, ${c.change?.payload ?? null}::text, ${c.change?.mac ?? null}::bytea,
    ${c.change?.sealFrom ?? null}::bytea, ${c.change?.seal ?? null}::bytea,
    ${c.ref.id}::uuid, ${c.macFrom}::bytea, ${c.mac}::bytea, ${String(c.revokedAt)}::bigint, ${c.revokedBy}::text
  )::text AS answer`);
  return JSON.parse(row!.answer) as Answer;
}
