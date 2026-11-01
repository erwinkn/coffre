import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { GATE_ROLES } from './decide.ts';
import type { UseCall, UseRow } from './use.ts';

/**
 * A use on Postgres: one call of `use_credential` (0024's, as 0050 has it), one
 * statement and one round trip, its own transaction. It answers its row as
 * one JSON value (0024 says why), read back here as `UseRow`.
 */
export async function callUse(db: Queryable, call: UseCall): Promise<UseRow> {
  const known = call.known;
  const [row] = await rowsOf<{ use: string }>(db, sql`SELECT use_credential(
    ${call.credential}::uuid, ${call.secretId}::uuid, ${call.requestId}::bigint, ${String(call.at)}::bigint, ${call.purpose}::smallint, ${call.place}::uuid,
    ${call.mac}::bytea, ${String(call.deadline)}::bigint,
    ${call.cover?.number ?? null}::bigint, ${call.cover === undefined ? null : String(call.cover.at)}::bigint, ${call.cover?.requestId ?? null}::bigint,
    ${known?.newest ?? null}::bigint, ${known?.newestMac ?? null}::bytea,
    ${known?.cap.count ?? null}::integer, ${known === undefined ? null : String(known.cap.windowMs)}::bigint,
    ${call.names?.tokenHash ?? null}::bytea, ${call.names?.project ?? null}::text, ${call.names?.environment ?? null}::text, ${call.names?.key ?? null}::text,
    ${call.decided === true}::boolean,
    ${call.names?.handle === true}::boolean,
    ${call.names === undefined ? null : sql.param([...call.names.unless])}::text[],
    ${call.names?.accepts.signin ?? null}::boolean,
    ${call.names === undefined ? null : sql.param([...call.names.accepts.issuers])}::text[],
    ${call.names === undefined ? null : GATE_ROLES}::jsonb,
    ${call.way}::smallint, ${call.principal}::text,
    ${call.names?.forks === true}::boolean
  )::text AS use`);
  return rowOf(row!.use);
}

/**
 * A batch of uses by ids on Postgres (T167, B2): one call of `use_batch` (0048), one statement and one round trip, its
 * own transaction, each key's use `use_credential`'s, in order. `lock`: the principal whose lock the batch takes
 * exclusive before its first key (StrongestFirst), its keys decided. It answers a JSON array of `use_credential`'s rows.
 */
export async function callBatch(db: Queryable, calls: readonly UseCall[], lock: string | null): Promise<UseRow[]> {
  const [first] = calls;
  if (first === undefined) throw new Error('a batch of uses names a key at least');
  if (calls.some((call) => call.names !== undefined || call.credential !== first.credential || call.at !== first.at || call.purpose !== first.purpose
    || call.deadline !== first.deadline || call.way !== first.way || call.principal !== first.principal)) {
    throw new Error("a batch's uses are one request's, by ids: one way in, time, purpose and deadline");
  }
  const list = <T>(of: (call: UseCall) => T) => sql.param(calls.map(of));
  const [row] = await rowsOf<{ uses: string }>(db, sql`SELECT use_batch(
    ${first.credential}::uuid, ${list((call) => call.secretId)}::uuid[], ${list((call) => call.requestId)}::bigint[], ${String(first.at)}::bigint, ${first.purpose}::smallint,
    ${list((call) => call.place)}::uuid[], ${list((call) => call.mac)}::bytea[], ${String(first.deadline)}::bigint,
    ${list((call) => call.cover?.number ?? null)}::bigint[], ${list((call) => (call.cover === undefined ? null : String(call.cover.at)))}::bigint[], ${list((call) => call.cover?.requestId ?? null)}::bigint[],
    ${list((call) => call.known?.newest ?? null)}::bigint[], ${list((call) => call.known?.newestMac ?? null)}::bytea[],
    ${list((call) => call.known?.cap.count ?? null)}::integer[], ${list((call) => (call.known === undefined ? null : String(call.known.cap.windowMs)))}::bigint[],
    ${list((call) => call.decided === true)}::boolean[],
    ${first.way}::smallint, ${first.principal}::text, ${lock}::text
  )::text AS uses`);
  return rowsOfBatch(row!.uses);
}

/** `use_batch`'s JSON array, each element as `rowOf` reads one, the array read again exactly if any needs it. */
export function rowsOfBatch(text: string): UseRow[] {
  let rows = JSON.parse(text) as Record<string, unknown>[];
  if (!Array.isArray(rows)) throw new Error('use_batch answered no array');
  if (rows.some(inexact)) rows = exactly(text) as Record<string, unknown>[];
  return rows.map(rowFrom);
}

/** The row's bigints: as text, exactly. */
const WHOLE = ['number', 'covered', 'newest', 'inputs', 'c_expires', 'm_old', 'm_access', 'cap_window'] as const;
/** Its bytes, which JSON carries as `\x` and hex. */
const BYTES = [
  'newest_mac', 'c_token_hash', 'c_seal', 'c_last', 'm_seal', 'm_last', 'r_seal', 'r_last', 'p_seal', 'p_last', 's_seal', 's_last', 'x_seal', 'x_last',
  'v_ciphertext', 'v_iv', 'v_auth_tag', 'v_wrapped_dek', ...['e1', 'e2', 'e3', 'e4'].flatMap((slot) => [`${slot}_seal`, `${slot}_last`]),
] as const;

/**
 * `use_credential`'s JSON as `UseRow`. A JSON number past 2^53 would lose
 * digits in `JSON.parse`: none of the row's is (entry numbers, times in
 * ms), but one that were is read again with each number's own text, rather
 * than misread (a reviver on every value costs 30 µs a use: measured).
 */
export function rowOf(text: string): UseRow {
  const row = JSON.parse(text) as Record<string, unknown>;
  return rowFrom(inexact(row) ? exactly(text) as Record<string, unknown> : row);
}

const unsafe = (value: unknown) => typeof value === 'number' && !Number.isSafeInteger(value);

/** Whether a row as `JSON.parse` read it has a whole number it could not read exactly. */
function inexact(row: Record<string, unknown>): boolean {
  return WHOLE.some((name) => unsafe(row[name])) || ((row.g_expires as unknown[] | null)?.some(unsafe) ?? false);
}

/** JSON read with each number past 2^53 as its own text. */
function exactly(text: string): unknown {
  return JSON.parse(text, (_key, value: unknown, context?: { source?: string }) => {
    if (!unsafe(value)) return value;
    // A runtime without JSON.parse's source text: never a number misread.
    if (context?.source === undefined) throw new Error('use_credential answered a whole number past 2^53, which this runtime cannot read exactly');
    return context.source;
  });
}

/** A row read, its whole numbers as text and its bytes as bytes. */
function rowFrom(row: Record<string, unknown>): UseRow {
  for (const name of WHOLE) if (row[name] != null) row[name] = String(row[name]);
  if (Array.isArray(row.g_expires)) row.g_expires = row.g_expires.map((value) => (value == null ? null : String(value)));
  for (const name of BYTES) {
    const value = row[name];
    if (typeof value === 'string') row[name] = Buffer.from(value.slice(2), 'hex');
  }
  return row as UseRow;
}
