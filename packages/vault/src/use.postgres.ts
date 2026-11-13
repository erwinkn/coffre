import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { GATE_ROLES } from './decide.ts';
import { exactly, unsafe } from './exact.ts';
import type { ChangeColumns, EditorRow, NamedAhead, NamedBatchCall, NamedBatchRows, ResolvedRow, RouteCall, RouteLevelRow, RouteNamedRows, RouteRows, UseCall, UseRow } from './use.ts';

/**
 * A use on Postgres: one call of `use_credential` (0024's, as 0053 has it), one
 * statement and one round trip, its own transaction. It answers its row as
 * one JSON value (0024 says why), read back here as `UseRow`.
 */
export async function callUse(db: Queryable, call: UseCall): Promise<UseRow> {
  return rowOf(await useText(db, call));
}

/**
 * A route's named call on Postgres (0071): one call of `use_credential`, a handle's that names its route and no
 * key, one statement and one round trip. It answers the key's row and what it read of the route beside it, none where
 * it read none (`RouteNamedRows`).
 */
export async function callRouteNamed(db: Queryable, call: UseCall): Promise<RouteNamedRows> {
  if (call.names === undefined || call.names.key !== null || call.route == null) throw new Error("a route's named call is a handle's, naming its route and no key");
  const text = await useText(db, call);
  type Read = { row: Record<string, unknown>; route: (Omit<RouteNamedRows['route'] & object, 'levels' | 'editor'> & { levels: Record<string, unknown>[] | null; editor: Record<string, unknown> | null }) | null };
  let read = JSON.parse(text) as Read;
  if (inexact(read.row)) read = exactly(text) as Read;
  const route = read.route;
  return {
    row: rowFrom(read.row),
    route: route === null ? null : {
      place: String(route.place), project: String(route.project), levels: (route.levels ?? []).map(levelFrom), editor: editorFrom(route.editor),
      keys: route.keys ?? [], made: route.made === true, keyed: route.keyed === true,
    },
  };
}

/** `use_credential`'s answer to a call, as its text. */
async function useText(db: Queryable, call: UseCall): Promise<string> {
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
    ${call.names?.forks === true}::boolean,
    ${call.route ?? null}::text,
    p_passkeys => ${call.names?.accepts.passkeys ?? null}::text
  )::text AS use`);
  return row!.use;
}

/**
 * A batch of uses by ids on Postgres: one call of `use_batch` (0048), one statement and one round trip, its
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

/**
 * A request's several keys by name on Postgres: one call of `use_named_batch` (0055), one statement
 * and one round trip, its own transaction: the gate's named call with no key, then, for one who stands there, each key,
 * the keys `calls` name or, `calls` null, every key the place holds, at most `limit`: a key by its ids when its call has
 * them (a use by ids, which the statement makes only when they are its name's now, its value sealed), else by its name
 * alone. It answers the gate's row, the names it listed, each key's row, whether each was by ids, and their app rows.
 */
export async function callNamedBatch(db: Queryable, gate: UseCall, calls: readonly NamedBatchCall[] | null, limit: number): Promise<NamedBatchRows> {
  const names = gate.names;
  if (names === undefined || gate.credential !== null || names.key !== null) throw new Error("a named batch's gate reads by its names alone, with no key");
  const [first] = calls ?? [];
  if (calls !== null && (first === undefined || calls.length > limit || calls.some(({ key, call }) => key === '' || call.at !== gate.at || call.purpose !== gate.purpose || call.deadline !== gate.deadline
    || call.way !== first.call.way || call.principal !== first.call.principal || (call.names === undefined ? call.credential === null : call.names.key !== key || call.credential !== null)))) {
    throw new Error("a named batch's keys are one request's, each by its name alone or by its ids, at most its limit");
  }
  const list = <T>(of: (call: UseCall) => T) => (calls === null ? null : sql.param(calls.map(({ call }) => of(call))));
  const [row] = await rowsOf<{ uses: string }>(db, sql`SELECT use_named_batch(
    ${names.tokenHash}::bytea, ${names.project}::text, ${names.environment}::text, ${names.handle}::boolean, ${sql.param([...names.unless])}::text[],
    ${names.accepts.signin}::boolean, ${sql.param([...names.accepts.issuers])}::text[], ${GATE_ROLES}::jsonb,
    ${String(gate.at)}::bigint, ${gate.purpose}::smallint, ${String(gate.deadline)}::bigint, ${gate.mac}::bytea,
    ${calls === null ? null : sql.param(calls.map(({ key }) => key))}::text[], ${list((call) => call.credential)}::uuid[], ${list((call) => call.secretId)}::uuid[], ${list((call) => call.place)}::uuid[],
    ${list((call) => call.requestId)}::bigint[], ${list((call) => call.mac)}::bytea[],
    ${list((call) => call.cover?.number ?? null)}::bigint[], ${list((call) => (call.cover === undefined ? null : String(call.cover.at)))}::bigint[], ${list((call) => call.cover?.requestId ?? null)}::bigint[],
    ${list((call) => call.known?.newest ?? null)}::bigint[], ${list((call) => call.known?.newestMac ?? null)}::bytea[],
    ${list((call) => call.known?.cap.count ?? null)}::integer[], ${list((call) => (call.known === undefined ? null : String(call.known.cap.windowMs)))}::bigint[],
    ${first?.call.way ?? 0}::smallint, ${first?.call.principal ?? null}::text,
    ${limit}::integer, ${names.accepts.passkeys}::text
  )::text AS uses`);
  type Read = { gate: Record<string, unknown>; keys: string[] | null; rows: (Record<string, unknown> | null)[]; by_ids: boolean[]; aheads: (NamedAhead | null)[] };
  let read = JSON.parse(row!.uses) as Read;
  // Read again exactly if any row has a whole number `JSON.parse` could not read (`rowOf` says why).
  if (inexact(read.gate) || read.rows.some((one) => one !== null && inexact(one))) read = exactly(row!.uses) as Read;
  return { gate: rowFrom(read.gate), keys: read.keys, rows: read.rows.map((one) => (one === null ? null : rowFrom(one))), byIds: read.by_ids, aheads: read.aheads };
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

/** Whether a row as `JSON.parse` read it has a whole number it could not read exactly. */
function inexact(row: Record<string, unknown>): boolean {
  return WHOLE.some((name) => unsafe(row[name])) || ((row.g_expires as unknown[] | null)?.some(unsafe) ?? false);
}

/** A row read, its whole numbers as text and its bytes as bytes. */
function rowFrom(row: Record<string, unknown>): UseRow {
  for (const name of WHOLE) if (row[name] != null) row[name] = String(row[name]);
  if (Array.isArray(row.g_expires)) row.g_expires = row.g_expires.map((value) => (value == null ? null : String(value)));
  for (const name of BYTES) {
    const value = row[name];
    if (typeof value === 'string') row[name] = Buffer.from(value.slice(2), 'hex');
  }
  // Each newest change's MAC, last of its columns (0059). Its time, a JSON number, is a time in ms: one a writer
  // put past 2^53 reads inexactly, and its MAC then does not hold, which refuses the input, as any edit does.
  const changes = row.changes as Record<string, unknown> | null | undefined;
  if (changes != null) for (const [input, columns] of Object.entries(changes)) changes[input] = changeFrom(columns);
  return row as UseRow;
}

/** A newest change's MAC'd columns as `use_credential` and `use_route` answer them, its MAC as bytes; null for none. */
function changeFrom(columns: unknown): ChangeColumns | null {
  if (!Array.isArray(columns) || typeof columns[4] !== 'string') return null;
  return [columns[0], columns[1], columns[2], columns[3], Buffer.from(columns[4].slice(2), 'hex')] as ChangeColumns;
}

/**
 * A route use on Postgres: one call of `use_route` (0058), one statement and one round trip, its own
 * transaction: the gate, the route's levels, its editor and its keys, read; each key's use by ids when the call has
 * them and they are the names' now. It answers one JSON object (`RouteRows`). A handle's gate holds its credential to
 * `accepts`, the passkey policy included (0073, `p_passkeys`), as any named call's.
 */
export async function callRoute(db: Queryable, call: RouteCall): Promise<RouteRows> {
  const keys = call.keys;
  const list = <T>(of: (one: UseCall | null) => T) => (keys === null ? null : sql.param(keys.map(of)));
  const [row] = await rowsOf<{ route: string }>(db, sql`SELECT use_route(
    ${call.tokenHash}::bytea, ${call.project}::text, ${call.environment}::text, ${call.named}::text, ${call.stable}::text, ${call.reading}::smallint,
    ${call.accepts?.signin ?? null}::boolean, ${call.accepts === null ? null : sql.param([...call.accepts.issuers])}::text[], ${call.tokenHash === null ? null : GATE_ROLES}::jsonb,
    ${call.credential}::uuid, ${call.tokenHash === null ? call.way : null}::smallint, ${call.principal}::text, ${call.place}::uuid,
    ${String(call.at)}::bigint, ${call.purpose}::smallint, ${String(call.deadline)}::bigint, ${call.mac}::bytea,
    ${list((one) => one?.secretId ?? null)}::uuid[], ${list((one) => one?.place ?? null)}::uuid[],
    ${list((one) => (one === null || one.requestId === '' ? null : one.requestId))}::bigint[], ${list((one) => (one === null || one.requestId === '' ? null : one.mac))}::bytea[],
    ${list((one) => one?.cover?.number ?? null)}::bigint[], ${list((one) => (one?.cover === undefined ? null : String(one.cover.at)))}::bigint[], ${list((one) => one?.cover?.requestId ?? null)}::bigint[],
    ${list((one) => one?.decided === true)}::boolean[],
    ${call.offset}::integer, ${call.limit}::integer, ${call.lock}::text, ${call.use}::boolean, ${call.light}::boolean,
    p_passkeys => ${call.accepts?.passkeys ?? null}::text
  )::text AS route`);
  type Read = Omit<RouteRows, 'gate' | 'rows' | 'levels' | 'editor' | 'madeFor'> & {
    gate: Record<string, unknown>; rows: (Record<string, unknown> | null)[] | null; levels: Record<string, unknown>[] | null; editor: Record<string, unknown> | null; made_for: string[] | null;
  };
  let read = JSON.parse(row!.route) as Read;
  if (inexact(read.gate) || (read.rows ?? []).some((one) => one !== null && inexact(one))) read = exactly(row!.route) as Read;
  return {
    gate: rowFrom(read.gate), reading: read.reading, route: read.route ?? null, madeFor: read.made_for ?? null, stood: read.stood === true, place: read.place ?? null,
    project: read.project ?? null, personal: read.personal === true, cut: read.cut === true,
    levels: (read.levels ?? []).map(levelFrom),
    editor: editorFrom(read.editor ?? null),
    keys: read.keys ?? [], resolved: (read.resolved ?? []) as ResolvedRow[], made: read.made === true,
    rows: (read.rows ?? []).map((one) => (one === null ? null : rowFrom(one))),
  };
}

/** A JSON value's bytes, which JSON carries as `\x` and hex; null for none. */
const bytesOf = (value: unknown) => (typeof value === 'string' ? Buffer.from(value.slice(2), 'hex') : null);

/** One level of a route's place as `use_route` and a route's named call answer it. */
function levelFrom(level: Record<string, unknown>): RouteLevelRow {
  return {
    environment: String(level.environment), row: level.row === true, item: level.item ?? null, digests: bytesOf(level.digests), seal: bytesOf(level.seal),
    newest: bytesOf(level.newest), number: level.number == null ? null : String(level.number), change: changeFrom(level.change),
    env: level.env == null ? null : (() => {
      const env = level.env as Record<string, unknown>;
      return {
        project: String(env.project), slug: String(env.slug), owner: env.owner == null ? null : String(env.owner), parent: env.parent == null ? null : String(env.parent),
        protected: env.protected == null ? null : env.protected === true, archived: env.archived === true, project_archived: env.project_archived === true,
        seal: bytesOf(env.seal), last: bytesOf(env.last), change: changeFrom(env.change),
      };
    })(),
  };
}

/** A route's editor's principal as `use_route` and a route's named call answer it. */
function editorFrom(editor: Record<string, unknown> | null): EditorRow | null {
  return editor === null ? null : {
    ...(editor as Omit<EditorRow, 'seal' | 'last' | 'change'>), seal: bytesOf(editor.seal), last: bytesOf(editor.last), change: changeFrom(editor.change),
    generation: editor.generation == null ? null : Number(editor.generation),
  };
}
