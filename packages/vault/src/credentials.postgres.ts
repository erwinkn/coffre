import { MAX_BINDINGS } from '@coffre/core/identity';
import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import type { Answer, BindingsCall, IssueCall, RevokeCall, SignInCall } from './credentials.ts';

/** `sign_in` (migration 0037): one statement, its own transaction, its answer one JSON value. */
export async function signInOnPostgres(db: Queryable, c: SignInCall): Promise<Answer> {
  const k = c.credential;
  const [row] = await rowsOf<{ answer: string }>(db, sql`/* writes */ SELECT sign_in(
    ${c.requestId}::text, ${String(c.at)}::bigint, ${c.actor}::text, ${c.payload}::text, ${c.mac}::bytea, ${c.seal}::bytea,
    ${c.binding.id}::uuid, ${c.principal}::text, ${c.binding.generation}::integer, ${c.binding.profile}::text, ${c.binding.scope}::text, ${c.binding.policy}::text,
    ${c.binding.issuer}::text, ${c.binding.jwksUri}::text, ${c.binding.claims}::text, ${c.bindingSeal}::bytea,
    ${c.spent}::bytea, ${c.validUntil === null ? null : String(c.validUntil)}::bigint, ${c.frozen}::boolean, ${c.rate}::integer, ${String(c.window)}::bigint, ${String(c.longest)}::bigint,
    ${k.id}::uuid, ${k.kind}::text, ${k.authMacBytes}::bytea, ${k.tokenHashBytes}::bytea, ${k.tokenHint}::text, ${k.label}::text, ${k.createdBy}::text,
    ${k.scope}::text, ${k.places}::text, ${String(k.expiresAt)}::bigint, ${k.notAfter === null ? null : String(k.notAfter)}::bigint, ${k.jkt}::text, ${c.appKey}::text
  )::text AS answer`);
  return JSON.parse(row!.answer) as Answer;
}

/** `revoke_credential` (migration 0034): one statement, its own transaction, its answer one JSON value. */
export async function revokeOnPostgres(db: Queryable, c: RevokeCall): Promise<Answer> {
  const { change, policy } = c;
  const guarded = policy?.protected ?? [];
  const [row] = await rowsOf<{ answer: string }>(db, sql`/* writes */ SELECT revoke_credential(
    ${change.requestId}::text, ${String(change.at)}::bigint, ${change.actor}::text, ${change.payload}::text, ${change.mac}::bytea,
    ${change.sealFrom}::bytea, ${change.seal}::bytea,
    ${c.ref.id}::uuid, ${c.macFrom}::bytea, ${c.mac}::bytea, ${String(c.revokedAt)}::bigint, ${c.revokedBy}::text,
    ${policy !== null}::boolean, ${policy?.seq ?? null}::bigint,
    ${sql.param(guarded.map(({ environmentId }) => environmentId))}::uuid[], ${sql.param(guarded.map(({ slug }) => slug))}::text[]
  )::text AS answer`);
  return JSON.parse(row!.answer) as Answer;
}

/** `issue_token` (migration 0036): one statement, its own transaction, its answer one JSON value. */
export async function issueOnPostgres(db: Queryable, c: IssueCall): Promise<Answer> {
  const { change, input, read } = c;
  const k = input.credential;
  const guarded = read.slugs;
  const [row] = await rowsOf<{ answer: string }>(db, sql`/* writes */ SELECT issue_token(
    ${change.requestId}::text, ${String(change.at)}::bigint, ${change.actor}::text, ${change.payload}::text, ${change.mac}::bytea, ${change.seal}::bytea,
    ${input.principal}::text, ${input.generation}::integer, ${read.principal.accessSeq.toString()}::bigint, ${read.actor.generation}::integer, ${read.actor.accessSeq.toString()}::bigint,
    ${input.via}::uuid, ${read.via?.seal ?? null}::bytea, ${read.via?.columns.expiresAt == null ? null : String(read.via.columns.expiresAt)}::bigint,
    ${input.policy.seq}::bigint, ${sql.param(guarded.map(({ environmentId }) => environmentId))}::uuid[], ${sql.param(guarded.map(({ slug }) => slug))}::text[], ${input.appKey}::text,
    ${k.id}::uuid, ${k.kind}::text, ${c.authMac}::bytea, ${c.tokenHash}::bytea, ${k.tokenHint}::text, ${k.label}::text, ${k.createdBy}::text,
    ${k.scope}::text, ${k.places}::text, ${String(k.expiresAt)}::bigint
  )::text AS answer`);
  return JSON.parse(row!.answer) as Answer;
}

/** `change_bindings` (migration 0037): one statement, its own transaction, its answer one JSON value. */
export async function bindingsOnPostgres(db: Queryable, c: BindingsCall): Promise<Answer> {
  const m = c.make;
  const r = m?.read ?? null;
  const b = m?.row ?? null;
  const array = <T>(values: T[]) => sql.param(values);
  const [row] = await rowsOf<{ answer: string }>(db, sql`/* writes */ SELECT change_bindings(
    ${String(c.at)}::bigint, ${c.actor}::text,
    ${m !== null}::boolean, ${c.principal}::text, ${b?.generation ?? null}::integer, ${r?.principal.accessSeq.toString() ?? null}::bigint,
    ${r?.actor.generation ?? null}::integer, ${r?.actor.accessSeq.toString() ?? null}::bigint,
    ${m?.via ?? null}::uuid, ${r?.via?.seal ?? null}::bytea, ${r?.via?.columns.expiresAt == null ? null : String(r.via.columns.expiresAt)}::bigint,
    ${c.policy.seq}::bigint, ${array(c.policy.slugs.map(({ environmentId }) => environmentId))}::uuid[], ${array(c.policy.slugs.map(({ slug }) => slug))}::text[], ${c.appKey}::text,
    ${MAX_BINDINGS}::integer, ${b?.id ?? null}::uuid, ${m?.authMac ?? null}::bytea, ${b?.profile ?? null}::text, ${b?.issuer ?? null}::text, ${b?.jwksUri ?? null}::text, ${b?.jwks ?? null}::text,
    ${b?.claims ?? null}::text, ${b?.scope ?? null}::text, ${b?.policy ?? null}::text, ${b?.label ?? null}::text, ${b?.createdBy ?? null}::text,
    ${b === null ? null : String(b.createdAt)}::bigint, ${m?.seal ?? null}::bytea,
    ${array(c.ends.map((e) => e.id))}::uuid[], ${array(c.ends.map((e) => e.macFrom))}::bytea[], ${array(c.ends.map((e) => e.sealFrom))}::bytea[],
    ${array(c.ends.map((e) => e.authMac))}::bytea[], ${array(c.ends.map((e) => e.seal))}::bytea[],
    ${array(c.credentials.map((x) => x.id))}::uuid[], ${array(c.credentials.map((x) => x.binding))}::uuid[], ${array(c.credentials.map((x) => x.macFrom))}::bytea[],
    ${array(c.credentials.map((x) => x.sealFrom))}::bytea[], ${array(c.credentials.map((x) => x.authMac))}::bytea[], ${array(c.credentials.map((x) => x.seal))}::bytea[],
    ${String(c.revokedAt)}::bigint, ${c.revokedBy}::text,
    ${array(c.changes.map((x) => x.requestId))}::text[], ${array(c.changes.map((x) => x.object))}::uuid[], ${array(c.changes.map((x) => x.payload))}::text[],
    ${array(c.changes.map((x) => x.seal))}::bytea[], ${array(c.changes.map((x) => x.mac))}::bytea[]
  )::text AS answer`);
  return JSON.parse(row!.answer) as Answer;
}
