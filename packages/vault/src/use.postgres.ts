import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import type { UseCall, UseRow } from './use.ts';

/**
 * A use on Postgres: one call of `use_credential` (0024's, as 0029 has it), one
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
    ${known?.cap.count ?? null}::integer, ${known === undefined ? null : String(known.cap.windowMs)}::bigint
  )::text AS use`);
  return rowOf(row!.use);
}

/** The row's bigints: as text, exactly. */
const WHOLE = ['number', 'covered', 'newest', 'inputs', 'c_expires', 'm_old', 'm_access', 'cap_window'] as const;
/** Its bytes, which JSON carries as `\x` and hex. */
const BYTES = [
  'newest_mac', 'c_seal', 'c_last', 'm_seal', 'm_last', 'r_seal', 'r_last', 'p_seal', 'p_last', 's_seal', 's_last', 'x_seal', 'x_last',
  'v_ciphertext', 'v_iv', 'v_auth_tag', 'v_wrapped_dek', ...['e1', 'e2', 'e3', 'e4'].flatMap((slot) => [`${slot}_seal`, `${slot}_last`]),
] as const;

/**
 * `use_credential`'s JSON as `UseRow`. A JSON number past 2^53 would lose
 * digits in `JSON.parse`: none of the row's is (entry numbers, times in
 * ms), but one that were is read again with each number's own text, rather
 * than misread (a reviver on every value costs 30 µs a use: measured).
 */
export function rowOf(text: string): UseRow {
  let row = JSON.parse(text) as Record<string, unknown>;
  const unsafe = (value: unknown) => typeof value === 'number' && !Number.isSafeInteger(value);
  if (WHOLE.some((name) => unsafe(row[name])) || (row.g_expires as unknown[] | null)?.some(unsafe)) {
    row = JSON.parse(text, (_key, value: unknown, context?: { source?: string }) => {
      if (!unsafe(value)) return value;
      // A runtime without JSON.parse's source text: never a number misread.
      if (context?.source === undefined) throw new Error('use_credential answered a whole number past 2^53, which this runtime cannot read exactly');
      return context.source;
    }) as Record<string, unknown>;
  }
  for (const name of WHOLE) if (row[name] != null) row[name] = String(row[name]);
  if (Array.isArray(row.g_expires)) row.g_expires = row.g_expires.map((value) => (value == null ? null : String(value)));
  for (const name of BYTES) {
    const value = row[name];
    if (typeof value === 'string') row[name] = Buffer.from(value.slice(2), 'hex');
  }
  return row as UseRow;
}
