import { USE_WAYS, useOfCode, type UseWay } from '@coffre/core/vault';
import type { Queryable } from '@coffre/db';
import * as dialect from '@coffre/db/dialect';
import { logObject } from '@coffre/db/log';
import { sql, type SQL } from 'drizzle-orm';

import type { ChangePoint, RecordedChange } from './queries.ts';

// 0.15's uses as the audit pages list them (T166; docs/design/0.15-plan.md,
// "As built: T166"). With 0.15's log a read (a reveal, a run, the proxy's
// use, a read through a reference) writes no 0.14 `secret.read` entry: its
// use is the record, a slim row (R53) that names its way in, its key and the
// fork it was read in, and no account, place or version. These reads find
// them, by the indexes of migration 0049, and say what each row leaves out,
// from the rows and the log as they are.

/** How far a use's time may stand from its way in's life, its reference's, or its key's, as the database's clock dates those: a use's `at` is the app's clock, held to the database's within a minute ahead (`ahead`) and its 3 s deadline behind. */
const SLACK_MS = 5 * 60_000;

/** A use as a page reads it: the row, and the account its way in acts as, as the way in's row says. */
export type ListedUse = {
  number: bigint;
  at: number;
  /** The use's own id, which names no request of the app's: random, unique within its millisecond. */
  requestId: string;
  credential: string;
  secret: string;
  purpose: number;
  place: string | null;
  mac: Buffer;
  /** Whose way in: its credential's, connection's or binding's account; behind Access, null, as the row names the person only by their object (`accountsBehindAccess`). */
  principal: string | null;
  /** Through MCP, the app, as its connection's row names it. */
  client: { id: string; name: string } | null;
  /** The key it names, where it is held (a reference's holder), and the fork it was read in. */
  home: { projectId: string; environmentId: string; key: string; project: string; environment: string } | null;
  fork: { id: string; slug: string } | null;
};

/**
 * Places a list of uses is held to: any of these projects, environments or
 * keys, and none of the environments `except` names (a protected one the
 * caller's role leaves out). A use is in a place by its key, where that is
 * held; by the fork it was read in; or, through a reference, by its source.
 */
export type UsePlaces = { projectIds: readonly string[]; environmentIds: readonly string[]; secretIds: readonly string[]; except: readonly string[] };

export type UseFilter = {
  /** The members whose uses: through any of their credentials, MCP apps or bindings, or behind Access. */
  actors?: readonly string[];
  /** Each must hold: a page's path, and the places its caller reads. */
  places?: readonly UsePlaces[];
  before?: ChangePoint;
  limit: number;
};

/**
 * The newest uses `filter` asks for, newest first by when they were asked,
 * then by number, as 0.15's records are listed, below `before`: up to
 * `limit`, and whether there are more.
 *
 * On Postgres, each index read newest first and no further than a page,
 * through the functions of migration 0049, which hold the plan to the index
 * (R48): every use, by `log_uses_request_idx`; a place's, for each key it
 * holds (`log_uses_of`, by `log_uses_secret_idx`), each reference whose
 * source it holds (the holder's, over the reference's life), and each fork
 * of it (`log_uses_in`, by `log_uses_place_idx`); a member's, for each of
 * their ways in (`log_uses_by`, by `log_uses_credential_idx`), over its life,
 * and at a place, those of the place. A member's credentials are walked by
 * their end, newest first, `WALKED` at a time, and the walk stops once the
 * page's oldest use is newer than the next one's end: a CI service's page
 * reads its newest runs' credentials, not every run it ever had. One
 * statement for most pages, one per stretch of a member's credentials for
 * the rest. What a page costs grows with the keys of its place, not with
 * the uses: each key's probe reads each day it may have been used in, since
 * it was made, until the page is full, so a quiet key costs its days.
 * SQLite, which serves tests and development, filters the uses in order.
 */
export async function usesPage(db: Queryable, filter: UseFilter): Promise<UsesPage> {
  const engine = dialect.engineOf(db);
  const take = filter.limit + 1;
  const actors = filter.actors?.filter((actor) => actor.startsWith('user:') || actor.startsWith('token:'));
  if (actors?.length === 0) return { rows: [], more: false, floor: null };
  const places = filter.places ?? [];
  if (places.some(empty)) return { rows: [], more: false, floor: null };
  // Below `before`, as a pair the indexes compare: a time alone is above every use asked at it.
  const point = { at: filter.before?.at ?? MAX, number: filter.before?.number ?? MAX };
  if (engine === 'postgres' && actors !== undefined) return byMembers(db, actors, places, point, filter.limit);
  let found: SQL;
  if (engine === 'sqlite') {
    found = sql`SELECT u.at, u.number FROM log_uses u
      WHERE (u.at, u.number) < (${point.at}, ${point.number}) AND ${actors === undefined ? sql`TRUE` : byWays(engine, actors)}
        AND ${sql.join([sql`TRUE`, ...places.map((p) => inPlaces(engine, p))], sql` AND `)}
      ORDER BY u.at DESC, u.number DESC LIMIT ${take}`;
  } else if (places.length > 0) {
    found = placesFound(places, point, take);
  } else {
    found = sql`SELECT u.at, u.number FROM log_uses u WHERE (u.at, u.number) < (${bigint(point.at)}, ${bigint(point.number)}) ORDER BY u.at DESC, u.number DESC LIMIT ${take}`;
  }
  return pageOf(await dialect.rowsOf<UseRow>(db, listed(engine, found)), filter.limit);
}

/** Above every use: the start of a page with no `before`, and below a time alone, above every use asked at it. */
const MAX = 9_223_372_036_854_775_807n;

/** A number as Postgres's bigint, which a parameter alone would not say. */
const bigint = (value: number | bigint) => sql`CAST(${String(value)} AS bigint)`;

/** A use as `listed` reads it. */
type UseRow = {
  number: string | number | bigint; at: string | number; request_id: string | number | bigint; credential: string; secret: string; purpose: number | string;
  place: string | null; mac: Uint8Array; principal: string | null; client_id: string | null; client_name: string | null;
  project_id: string | null; environment_id: string | null; key: string | null; project: string | null; environment: string | null; fork: string | null;
};

/**
 * The uses `found` names by `(at, number)`, newest first, each with whose
 * and where, as the rows say: by primary keys, a probe each (on Postgres,
 * lateral, so that no plan reads a table whole to join a page of rows).
 */
function listed(engine: dialect.Engine, found: SQL): SQL {
  const way = (name: (typeof USE_WAYS)[number]) => sql.raw(`${USE_WAYS.indexOf(name) * 512}`);
  if (engine === 'sqlite') {
    return sql`
      SELECT c.number, c.at, c.request_id, c.credential, c.secret, c.purpose, c.place, c.mac,
        CASE WHEN c.purpose < ${way('connection')} THEN cr.principal WHEN c.purpose < ${way('binding')} THEN k.principal WHEN c.purpose < ${way('access')} THEN b.principal END AS principal,
        k.client_id, k.client_name, s.project_id, s.environment_id, s.key, p.slug AS project, e.slug AS environment, f.slug AS fork
      FROM (${found}) t
      JOIN log_uses c ON c.at = t.at AND c.number = t.number
      LEFT JOIN credentials cr ON cr.id = c.credential AND c.purpose < ${way('connection')}
      LEFT JOIN mcp_connections k ON k.id = c.credential AND c.purpose >= ${way('connection')} AND c.purpose < ${way('binding')}
      LEFT JOIN service_bindings b ON b.id = c.credential AND c.purpose >= ${way('binding')} AND c.purpose < ${way('access')}
      LEFT JOIN secrets s ON s.id = c.secret
      LEFT JOIN projects p ON p.id = s.project_id
      LEFT JOIN environments e ON e.id = s.environment_id
      LEFT JOIN environments f ON f.id = c.place
      ORDER BY c.at DESC, c.number DESC`;
  }
  return sql`
    SELECT c.number, c.at, c.request_id, CAST(c.credential AS text) AS credential, CAST(c.secret AS text) AS secret, c.purpose, CAST(c.place AS text) AS place, c.mac,
      w.principal, w.client_id, w.client_name, CAST(h.project_id AS text) AS project_id, CAST(h.environment_id AS text) AS environment_id, h.key, h.project, h.environment, f.slug AS fork
    FROM (${found}) t
    CROSS JOIN LATERAL (SELECT * FROM log_uses x WHERE x.at = t.at AND x.number = t.number LIMIT 1) c
    LEFT JOIN LATERAL (
      SELECT cr.principal, NULL AS client_id, NULL AS client_name FROM credentials cr WHERE cr.id = c.credential AND c.purpose < ${way('connection')}
      UNION ALL SELECT k.principal, k.client_id, k.client_name FROM mcp_connections k WHERE k.id = c.credential AND c.purpose >= ${way('connection')} AND c.purpose < ${way('binding')}
      UNION ALL SELECT b.principal, NULL, NULL FROM service_bindings b WHERE b.id = c.credential AND c.purpose >= ${way('binding')} AND c.purpose < ${way('access')}) w ON TRUE
    LEFT JOIN LATERAL (SELECT s.project_id, s.environment_id, s.key, p.slug AS project, e.slug AS environment
      FROM secrets s JOIN projects p ON p.id = s.project_id JOIN environments e ON e.id = s.environment_id WHERE s.id = c.secret) h ON TRUE
    LEFT JOIN LATERAL (SELECT slug FROM environments WHERE id = c.place) f ON TRUE
    ORDER BY c.at DESC, c.number DESC`;
}

/**
 * A page of uses: up to its limit, and whether there are more. `floor`, for
 * a page that stopped early (`byMembers` at some places): nothing below it
 * was looked at, so the list goes on below it, though the page holds fewer
 * than it asked.
 */
export type UsesPage = { rows: ListedUse[]; more: boolean; floor: ChangePoint | null };

/** Rows as `listed` read them, up to `limit`, and whether there were more. */
function pageOf(rows: readonly UseRow[], limit: number): UsesPage {
  return {
    floor: null,
    rows: rows.slice(0, limit).map((row): ListedUse => ({
      number: BigInt(row.number),
      at: Number(row.at),
      requestId: String(row.request_id),
      credential: row.credential,
      secret: row.secret,
      purpose: Number(row.purpose),
      place: row.place,
      mac: Buffer.from(row.mac),
      principal: row.principal,
      client: row.client_id === null || row.client_name === null ? null : { id: row.client_id, name: row.client_name },
      home: row.project_id === null || row.environment_id === null || row.key === null || row.project === null || row.environment === null
        ? null
        : { projectId: row.project_id, environmentId: row.environment_id, key: row.key, project: row.project, environment: row.environment },
      fork: row.place === null || row.fork === null ? null : { id: row.place, slug: row.fork },
    })),
    more: rows.length > limit,
  };
}

/** A uuid column as text, for a page whose rows come from Postgres and SQLite alike. */
function text(engine: dialect.Engine, column: string): string {
  return engine === 'postgres' ? `CAST(${column} AS text)` : column;
}

/** Whether a list of places holds nothing: no project, environment or key to be in. */
function empty(places: UsePlaces): boolean {
  return places.projectIds.length === 0 && places.environmentIds.length === 0 && places.secretIds.length === 0;
}

/** `values` as a list for `IN (…)`; never empty, as a place list always names one. */
function list(values: readonly string[], cast: boolean): SQL {
  return sql.join(values.map((value) => (cast ? sql`CAST(${value} AS uuid)` : sql`${value}`)), sql`, `);
}

/** Whether any of `values` matches `column`, false for none. */
function anyOf(engine: dialect.Engine, column: string, values: readonly string[]): SQL {
  return values.length === 0 ? sql`FALSE` : sql`${sql.raw(column)} IN (${list(values, engine === 'postgres')})`;
}

/** None of `values` is `column`'s, true for none; a null column is none of them. */
function noneOf(engine: dialect.Engine, column: string, values: readonly string[]): SQL {
  return values.length === 0 ? sql`TRUE` : sql`(${sql.raw(column)} IS NULL OR ${sql.raw(column)} NOT IN (${list(values, engine === 'postgres')}))`;
}

/** A key, by alias, in `places`: its project, environment or itself named, its environment not left out. */
function keyIn(engine: dialect.Engine, alias: string, places: UsePlaces): SQL {
  return sql`(${anyOf(engine, `${alias}.project_id`, places.projectIds)} OR ${anyOf(engine, `${alias}.environment_id`, places.environmentIds)} OR ${anyOf(engine, `${alias}.id`, places.secretIds)})
    AND ${noneOf(engine, `${alias}.environment_id`, places.except)}`;
}

/** A fork, by alias, in `places`: itself or its project named, not left out. */
function forkIn(engine: dialect.Engine, alias: string, places: UsePlaces): SQL {
  return sql`(${anyOf(engine, `${alias}.id`, places.environmentIds)} OR ${anyOf(engine, `${alias}.project_id`, places.projectIds)}) AND ${noneOf(engine, `${alias}.id`, places.except)}`;
}

/** A reference, by alias, whose source is in `places`, neither its source's environment nor its holder's left out. */
function sourceIn(engine: dialect.Engine, alias: string, places: UsePlaces): SQL {
  return sql`(${anyOf(engine, `${alias}.source_project_id`, places.projectIds)} OR ${anyOf(engine, `${alias}.source_environment_id`, places.environmentIds)} OR ${anyOf(engine, `${alias}.source_secret_id`, places.secretIds)})
    AND ${noneOf(engine, `${alias}.source_environment_id`, places.except)} AND ${noneOf(engine, `${alias}.environment_id`, places.except)}`;
}

/** A time column of the database's in ms since the epoch, as a use's `at` counts. */
function millis(engine: dialect.Engine, column: string): string {
  return engine === 'postgres' ? `CAST(extract(epoch FROM ${column}) * 1000 AS bigint)` : column;
}

/** Whether a use `u` was read through reference `r`: within its life, as the database's clock dates it, give or take the slack. */
function during(engine: dialect.Engine, alias: string): SQL {
  return sql.raw(`u.at >= ${millis(engine, `${alias}.created_at`)} - ${SLACK_MS} AND (${alias}.ended_at IS NULL OR u.at <= ${millis(engine, `${alias}.ended_at`)} + ${SLACK_MS})`);
}

/**
 * Whether a use `u` is in `places` (`UsePlaces`): its key's place, the fork
 * it was read in, or the source of the reference it was read through; and
 * none of those left out.
 */
function inPlaces(engine: dialect.Engine, places: UsePlaces): SQL {
  return sql`(
      EXISTS (SELECT 1 FROM secrets s WHERE s.id = u.secret AND ${keyIn(engine, 's', places)})
      OR (u.place IS NOT NULL AND EXISTS (SELECT 1 FROM environments f WHERE f.id = u.place AND ${forkIn(engine, 'f', places)}))
      OR EXISTS (SELECT 1 FROM secret_references r WHERE r.secret_id = u.secret AND ${sourceIn(engine, 'r', places)} AND ${during(engine, 'r')}))
    AND ${left(engine, places.except)}`;
}

/** Whether a use `u` names nothing left out: its key's environment, its fork, its reference's source's. */
function left(engine: dialect.Engine, except: readonly string[]): SQL {
  if (except.length === 0) return sql`TRUE`;
  return sql`NOT EXISTS (SELECT 1 FROM secrets s WHERE s.id = u.secret AND ${anyOf(engine, 's.environment_id', except)})
    AND ${noneOf(engine, 'u.place', except)}
    AND NOT EXISTS (SELECT 1 FROM secret_references r WHERE r.secret_id = u.secret AND ${anyOf(engine, 'r.source_environment_id', except)} AND ${during(engine, 'r')})`;
}

/** Uses by ways in: a member's credentials, MCP apps and bindings, and their object behind Access. SQLite's form. */
function byWays(engine: dialect.Engine, actors: readonly string[]): SQL {
  const members = sql.join(actors.map((actor) => sql`${actor}`), sql`, `);
  return sql`(u.credential IN (SELECT id FROM credentials WHERE principal IN (${members}))
    OR u.credential IN (SELECT id FROM mcp_connections WHERE principal IN (${members}))
    OR u.credential IN (SELECT id FROM service_bindings WHERE principal IN (${members}))
    OR u.credential IN (${list(actors.map(accessObject), engine === 'postgres')}))`;
}

/** A person's or service's object behind Cloudflare Access, which a use through it names as its way in (T147). */
export function accessObject(member: string): string {
  return logObject('principal', member);
}

/** How many of a member's credentials one statement of their walk reads (`byMembers`). */
const WALKED = 32;

/** How many of one way in's uses a member's page at some places reads past those it keeps (`byMembers`). */
export const SCANNED = 1000;

/**
 * A member's uses, on Postgres (`usesPage`): their credentials walked by
 * their end, newest first, `WALKED` at a time, each read newest first over
 * its life (`log_uses_by`), with their MCP apps, bindings and their object
 * behind Access in the first stretch. A stretch holds every use newer than
 * the next credential's end, give or take the slack: once the page's
 * oldest is newer than that, no later credential has one to give it.
 *
 * At some places, each way in's index is read newest first and kept by
 * what it includes, the key and the fork (`log_uses_by_at`), no further
 * than `SCANNED` entries: a member who reads mostly elsewhere would
 * otherwise have every such read of theirs read for a page (review r1). A
 * way in that ran out first says where (`floor`): the page holds what is
 * above the highest such point, which may be fewer than it asks, and the
 * next goes on below it.
 */
async function byMembers(
  db: Queryable, actors: readonly string[], places: readonly UsePlaces[], point: { at: number | bigint; number: number | bigint }, limit: number,
): Promise<UsesPage> {
  const take = limit + 1;
  const members = sql.join(actors.map((actor) => sql`${actor}`), sql`, `);
  const sets = places.length === 0 ? null : placeSets(places);
  const made = (alias: string) => sql.raw(`${millis('postgres', `${alias}.created_at`)} - ${SLACK_MS}`);
  const ended = (alias: string) => sql.raw(`${millis('postgres', `${alias}.expires_at`)} + ${SLACK_MS}`);
  const always = bigint(MAX);
  // None made after the page's start: none of theirs is below it.
  const before = point.at === MAX ? sql`TRUE` : sql`c.created_at <= to_timestamp(${(Number(point.at) + SLACK_MS) / 1000})`;
  const read = sets === null
    ? sql`SELECT f.at, f.number, true AS hit FROM ways w CROSS JOIN LATERAL log_uses_by(w.id, w.lo, w.hi, ${bigint(point.at)}, ${bigint(point.number)}, ${take}) f`
    : sql`SELECT f.at, f.number, f.hit FROM ways w CROSS JOIN sets p CROSS JOIN LATERAL log_uses_by_at(w.id, w.lo, w.hi, ${bigint(point.at)}, ${bigint(point.number)}, ${take}, ${SCANNED},
        p.keys, p.forks, p.held, p.held_from, p.held_to, p.left_keys, p.left_envs, p.left_held, p.left_from, p.left_to) f`;
  let rows: UseRow[] = [];
  let floor: { at: number; number: bigint } | null = null;
  for (let after: { expires: string; id: string } | null = null, first = true; ; first = false) {
    const below = after === null ? sql`TRUE` : sql`(c.expires_at, c.id) < (CAST(${after.expires} AS timestamptz), CAST(${after.id} AS uuid))`;
    const credentials = sql.join(actors.map((actor) => sql`(SELECT c.id, c.created_at, c.expires_at FROM credentials c
      WHERE c.principal = ${actor} AND ${below} AND ${before} ORDER BY c.expires_at DESC, c.id DESC LIMIT ${WALKED + 1})`), sql` UNION ALL `);
    const others = sql`
      UNION ALL SELECT k.id, ${made('k')}, ${ended('k')} FROM mcp_connections k WHERE k.principal IN (${members})
      UNION ALL SELECT b.id, ${made('b')}, ${always} FROM service_bindings b WHERE b.principal IN (${members})
      UNION ALL ${sql.join(actors.map((actor) => sql`SELECT CAST(${accessObject(actor)} AS uuid), ${bigint(-MAX)}, ${always}`), sql` UNION ALL `)}`;
    const stretch = await dialect.rowsOf<UseRow & { next: string | number | null; last_expires: string | null; last_id: string | null; floor_at: string | number | null; floor_number: string | number | null }>(db, sql`
      WITH walked AS MATERIALIZED (
        SELECT c.id, ${made('c')} AS lo, ${ended('c')} AS hi, CAST(c.expires_at AS text) AS expires, row_number() OVER (ORDER BY c.expires_at DESC, c.id DESC) AS i
          FROM (${credentials}) c ORDER BY c.expires_at DESC, c.id DESC LIMIT ${WALKED + 1}),
      ways AS (SELECT id, lo, hi FROM walked WHERE i <= ${WALKED} ${first ? others : sql``}),
      ${sets === null ? sql`` : sql`sets AS MATERIALIZED (${sets}),`}
      found AS MATERIALIZED (${read})
      SELECT m.*, r.* FROM (SELECT (SELECT hi FROM walked WHERE i = ${WALKED + 1}) AS next, (SELECT expires FROM walked WHERE i = ${WALKED}) AS last_expires,
          (SELECT CAST(id AS text) FROM walked WHERE i = ${WALKED}) AS last_id,
          (SELECT f.at FROM found f WHERE NOT f.hit ORDER BY f.at DESC, f.number DESC LIMIT 1) AS floor_at,
          (SELECT f.number FROM found f WHERE NOT f.hit ORDER BY f.at DESC, f.number DESC LIMIT 1) AS floor_number) m
        LEFT JOIN LATERAL (${listed('postgres', sql`SELECT f.at, f.number FROM found f WHERE f.hit ORDER BY f.at DESC, f.number DESC LIMIT ${take}`)}) r ON TRUE`);
    const [meta] = stretch;
    // A way in that ran out of what it reads before its page: nothing of its below this was looked at.
    if (meta?.floor_at != null && meta.floor_number != null) {
      const point = { at: Number(meta.floor_at), number: BigInt(meta.floor_number) };
      if (floor === null || point.at > floor.at || (point.at === floor.at && point.number > floor.number)) floor = point;
    }
    rows = [...rows, ...stretch.filter((row) => row.number !== null)].sort(newestFirst).slice(0, take);
    // The next credential could hold a use newer than the page's oldest, and than where a way in ran out: walk on, from
    // the last one read.
    const next = meta?.next ?? null;
    const full = rows.length === take && Number(rows[take - 1]!.at) > Number(next);
    if (next === null || meta!.last_expires === null || meta!.last_id === null || full || (floor !== null && Number(next) < floor.at)) break;
    after = { expires: meta!.last_expires, id: meta!.last_id };
  }
  if (floor === null) return pageOf(rows, limit);
  const kept = rows.filter((row) => Number(row.at) > floor!.at || (Number(row.at) === floor!.at && BigInt(row.number) >= floor!.number));
  return { ...pageOf(kept.slice(0, limit), limit), more: true, floor: kept.length > limit ? null : floor };
}

/** Uses newest first, by `(at, number)`. */
function newestFirst(a: UseRow, b: UseRow): number {
  const [at, bt] = [Number(a.at), Number(b.at)];
  if (at !== bt) return bt - at;
  const [an, bn] = [BigInt(a.number), BigInt(b.number)];
  return an === bn ? 0 : bn > an ? 1 : -1;
}

/**
 * What a member's uses at `places` are kept by, on Postgres, as
 * `log_uses_by_at` takes them, each read once (`sets`): the keys the places
 * hold; the forks of them; each reference whose source they hold, its
 * holder over its life; then what is left out: the keys of the
 * environments left out, those environments, and the references whose
 * source is in one. Without `kept`, only what is left out (`placesFound`).
 */
function placeSets(places: readonly UsePlaces[], kept = true): SQL {
  const engine = 'postgres';
  const all = (parts: SQL[]) => sql.join(parts, sql` AND `);
  const except = exceptOf(places);
  const held = (where: SQL) => sql`SELECT coalesce(array_agg(r.secret_id), '{}') AS ids,
      coalesce(array_agg(${sql.raw(millis(engine, 'r.created_at'))} - ${SLACK_MS}), '{}') AS froms,
      coalesce(array_agg(coalesce(${sql.raw(millis(engine, 'r.ended_at'))} + ${SLACK_MS}, ${bigint(MAX)})), '{}') AS tos
    FROM secret_references r WHERE ${where}`;
  const none = sql`CAST('{}' AS uuid[])`;
  return sql`SELECT
      ${kept ? sql`(SELECT coalesce(array_agg(s.id), '{}') FROM secrets s WHERE ${all(places.map((p) => keyIn(engine, 's', p)))})` : none} AS keys,
      ${kept ? sql`(SELECT coalesce(array_agg(f.id), '{}') FROM environments f WHERE ${all(places.map((p) => forkIn(engine, 'f', p)))})` : none} AS forks,
      h.ids AS held, h.froms AS held_from, h.tos AS held_to,
      (SELECT coalesce(array_agg(s.id), '{}') FROM secrets s WHERE s.environment_id = ANY (${except})) AS left_keys,
      ${except} AS left_envs,
      x.ids AS left_held, x.froms AS left_from, x.tos AS left_to
    FROM (${held(kept ? all(places.map((p) => sourceIn(engine, 'r', p))) : sql`FALSE`)}) h, (${held(sql`r.source_environment_id = ANY (${except})`)}) x`;
}

/** Every environment `places` leaves out, as Postgres's array. */
function exceptOf(places: readonly UsePlaces[]): SQL {
  const except = [...new Set(places.flatMap((p) => p.except))];
  return except.length === 0 ? sql`'{}'::uuid[]` : sql`ARRAY[${list(except, true)}]`;
}

/**
 * The newest uses in `places`, on Postgres, by `(at, number)`: each key the
 * first place names (where it is held), each reference whose source it
 * names (its holder's, over the reference's life), each fork it names, each
 * held to the other places too, newest first by its own index
 * (`log_uses_of`, `log_uses_in`), then the newest of them all. What is left
 * out comes as arrays, read once (`placeSets`). A use in one place by one
 * of its own places and in another by a different one (its key's holder
 * named by a path, its source by the places the caller reads) is not
 * listed: none of 0.14's pages asks for it.
 */
function placesFound(places: readonly UsePlaces[], point: { at: number | bigint; number: number | bigint }, take: number): SQL {
  const engine = 'postgres';
  const all = (parts: SQL[]) => sql.join(parts, sql` AND `);
  const [at, number] = [bigint(point.at), bigint(point.number)];
  const left = sql`p.left_held, p.left_from, p.left_to`;
  return sql`
    WITH sets AS MATERIALIZED (${placeSets(places, false)})
    SELECT DISTINCT f.at, f.number FROM (
      SELECT f.at, f.number FROM sets p, secrets s
        CROSS JOIN LATERAL log_uses_of(s.id, ${sql.raw(millis(engine, 's.created_at'))} - ${SLACK_MS}, ${bigint(MAX)}, ${at}, ${number}, ${take}, p.left_envs, ${left}) f
       WHERE ${all(places.map((pl) => keyIn(engine, 's', pl)))}
      UNION ALL
      SELECT f.at, f.number FROM sets p, secret_references r
        CROSS JOIN LATERAL log_uses_of(r.secret_id, ${sql.raw(millis(engine, 'r.created_at'))} - ${SLACK_MS},
          coalesce(${sql.raw(millis(engine, 'r.ended_at'))} + ${SLACK_MS}, ${bigint(MAX)}), ${at}, ${number}, ${take}, p.left_envs, ${left}) f
       WHERE ${all(places.map((pl) => sourceIn(engine, 'r', pl)))}
      UNION ALL
      SELECT f.at, f.number FROM sets p, environments e CROSS JOIN LATERAL log_uses_in(e.id, ${at}, ${number}, ${take}, p.left_keys, ${left}) f
       WHERE ${all(places.map((pl) => forkIn(engine, 'e', pl)))}
    ) f ORDER BY f.at DESC, f.number DESC LIMIT ${take}`;
}

/** What a use read, from its key's object as the log sealed it before the use (`useDetails`). */
export type UseDetail = {
  /** The version it read: its key's, or, through a reference, its source's; null where the log says none. */
  version: number | null;
  /** Through a reference: the reference, its source and where that is, as the log sealed the holder then. */
  reference: { id: string; createdSeq: number | null; createdBy: string | null; createdAt: string | null } | null;
  source: { secretId: string; projectId: string; environmentId: string; key: string; project: string; environment: string } | null;
  /** The changes all of that was read from, each with what its MAC covers: a page has the vault vouch for them too. */
  backing: RecordedChange[];
};

/**
 * What each use read, by its number: its key's object, the newest change
 * the log numbers before the use, which every use reads under (the number
 * orders them, R50): its version, or the reference it read through, and
 * then the source's object before the use, and that one's version. One
 * probe of `log_changes_object_idx` per use and key, in one statement, and
 * one more for the reads through references, if any.
 */
export async function useDetails(db: Queryable, uses: readonly Pick<ListedUse, 'number' | 'secret'>[]): Promise<Map<bigint, UseDetail>> {
  const held = await objectsBefore(db, uses);
  const throughs = uses.flatMap(({ number }) => {
    const source = held.get(number)?.source;
    return source == null ? [] : [{ number, secret: source }];
  });
  const sources = await objectsBefore(db, throughs);
  return new Map(uses.map(({ number }): [bigint, UseDetail] => {
    const object = held.get(number);
    const backing = [object?.change, sources.get(number)?.change].filter((change): change is RecordedChange => change != null);
    if (object?.source == null) return [number, { version: object?.versionNumber ?? null, reference: null, source: null, backing }];
    return [number, { version: sources.get(number)?.versionNumber ?? null, reference: object.reference, source: object.sourcePlace, backing }];
  }));
}

/** A key's object as the log sealed it before a use: its version's number; a reference's source, its row and its source's place. */
type Sealed = {
  versionNumber: number | null;
  source: string | null;
  reference: UseDetail['reference'];
  sourcePlace: UseDetail['source'];
  /** The change it was read from. */
  change: RecordedChange | null;
};

/**
 * Each key's object before each use (`useDetails`), by the use's number:
 * its newest change below it, a write's (`secret.write`) or the cutover's
 * (`genesis`), whose fields name its version, or its reference and source,
 * each read by its primary key. A deletion, or a payload of another shape,
 * which only a database writer could leave on a key's object, names none.
 * The change comes back whole, for the vault to vouch for: a payload a
 * writer edited would otherwise name another version or source unseen.
 * One statement, of one index probe each.
 */
async function objectsBefore(db: Queryable, wanted: readonly { number: bigint; secret: string }[]): Promise<Map<bigint, Sealed>> {
  if (wanted.length === 0) return new Map();
  const engine = dialect.engineOf(db);
  const postgres = engine === 'postgres';
  const asked = sql.join(
    wanted.map(({ number, secret }, i) => {
      const object = postgres ? sql`CAST(${logObject('secret', secret)} AS uuid)` : sql`${logObject('secret', secret)}`;
      return i === 0 ? sql`SELECT ${object} AS object, CAST(${number} AS bigint) AS n` : sql`SELECT ${object}, CAST(${number} AS bigint)`;
    }),
    sql` UNION ALL `,
  );
  const rows = await dialect.rowsOf<{
    n: string | number | bigint; c_number: string | number | bigint | null; c_at: string | number | null; c_request: string | null; c_object: string | null;
    c_actor: string | null; payload: string | null; c_seal: Uint8Array | null; c_mac: Uint8Array | null;
    version: string | number | null; source: string | null; reference: string | null;
    created_seq: string | number | bigint | null; created_by: string | null; created_at: string | number | null;
    key: string | null; project_id: string | null; environment_id: string | null; project: string | null; environment: string | null;
  }>(db, sql`
    SELECT x.n, x.c_number, x.c_at, x.c_request, x.c_object, x.c_actor, x.payload, x.c_seal, x.c_mac, v.version, ${sql.raw(text(engine, 's.id'))} AS source, ${sql.raw(text(engine, 'r.id'))} AS reference,
           r.created_seq, r.created_by, ${sql.raw(millis(engine, 'r.created_at'))} AS created_at,
           s.key, ${sql.raw(text(engine, 's.project_id'))} AS project_id, ${sql.raw(text(engine, 's.environment_id'))} AS environment_id, p.slug AS project, e.slug AS environment
      FROM (SELECT a.n, c.number AS c_number, c.at AS c_at, c.request_id AS c_request, ${sql.raw(text(engine, 'c.object'))} AS c_object, c.actor AS c_actor,
                   c.payload, c.seal AS c_seal, c.mac AS c_mac
              FROM (${asked}) a
              LEFT JOIN log_changes c ON c.number = (SELECT max(b.number) FROM log_changes b WHERE b.object = a.object AND b.number < a.n)) x
      LEFT JOIN secret_versions v ON v.id = ${named(engine, 'x', 'version')}
      LEFT JOIN secret_references r ON r.id = ${named(engine, 'x', 'reference')}
      LEFT JOIN secrets s ON s.id = ${named(engine, 'x', 'source')}
      LEFT JOIN projects p ON p.id = s.project_id
      LEFT JOIN environments e ON e.id = s.environment_id`);
  return new Map(rows.map((row): [bigint, Sealed] => [BigInt(row.n), {
    versionNumber: row.version === null ? null : Number(row.version),
    source: row.source,
    reference: row.reference === null ? null : {
      id: row.reference,
      createdSeq: row.created_seq === null ? null : Number(row.created_seq),
      createdBy: row.created_by,
      createdAt: row.created_at === null ? null : new Date(Number(row.created_at)).toISOString(),
    },
    change: row.c_number === null ? null : {
      number: BigInt(row.c_number), at: Number(row.c_at), requestId: row.c_request!, object: row.c_object!, actor: row.c_actor!, payload: row.payload!,
      seal: row.c_seal === null ? null : Buffer.from(row.c_seal), mac: Buffer.from(row.c_mac!),
    },
    sourcePlace: row.source === null || row.key === null || row.project_id === null || row.environment_id === null || row.project === null || row.environment === null
      ? null
      : { secretId: row.source, key: row.key, projectId: row.project_id, environmentId: row.environment_id, project: row.project, environment: row.environment },
  }]));
}

/**
 * Every state of these keys' objects while a member read them, for an
 * offboarding report (`memberActivity`): for each `(secret, first, last)`,
 * the object as the log sealed it at the first use and every change after
 * it below the last, each its version, or, a reference's, its source; and
 * for each such source, its own versions over the same stretch. What they
 * may have read, never less than what they did: a key written between two
 * of their reads counts the version they did not see too, and a reference
 * repointed between them each source (review r1). One statement, and one
 * more for the sources, if any. Like 0.14's report, it reads every change
 * of those keys in that stretch.
 */
export async function statesDuring(
  db: Queryable, read: readonly { secret: string; first: bigint; last: bigint }[],
): Promise<{ secretId: string; version: number }[][]> {
  const held = await changesDuring(db, read);
  const sources = read.flatMap((one, i) => [...new Set(held[i]!.flatMap((state) => (state.source === null ? [] : [state.source])))]
    .map((source) => ({ i, secret: source, first: one.first, last: one.last })));
  const through = await changesDuring(db, sources);
  const seen = read.map((one, i) => held[i]!.flatMap((state) => (state.version === null ? [] : [{ secretId: one.secret, version: state.version }])));
  sources.forEach(({ i, secret }, j) => seen[i]!.push(...through[j]!.flatMap((state) => (state.version === null ? [] : [{ secretId: secret, version: state.version }]))));
  return seen;
}

/** Each key's object's changes over a stretch (`statesDuring`): the one in force at `first`, and each after it below `last`. */
async function changesDuring(
  db: Queryable, wanted: readonly { secret: string; first: bigint; last: bigint }[],
): Promise<{ version: number | null; source: string | null }[][]> {
  if (wanted.length === 0) return [];
  const engine = dialect.engineOf(db);
  const asked = sql.join(wanted.map(({ secret, first, last }, i) => {
    const object = engine === 'postgres' ? sql`CAST(${logObject('secret', secret)} AS uuid)` : sql`${logObject('secret', secret)}`;
    return i === 0
      ? sql`SELECT ${i} AS i, ${object} AS object, CAST(${first} AS bigint) AS first, CAST(${last} AS bigint) AS last`
      : sql`SELECT ${i}, ${object}, CAST(${first} AS bigint), CAST(${last} AS bigint)`;
  }), sql` UNION ALL `);
  const rows = await dialect.rowsOf<{ i: number | string; version: number | string | null; source: string | null }>(db, sql`
    SELECT a.i, v.version, ${sql.raw(text(engine, 's.id'))} AS source
      FROM (${asked}) a
      JOIN log_changes x ON x.object = a.object AND x.number < a.last
        AND x.number >= coalesce((SELECT max(b.number) FROM log_changes b WHERE b.object = a.object AND b.number < a.first), 0)
      LEFT JOIN secret_versions v ON v.id = ${named(engine, 'x', 'version')}
      LEFT JOIN secrets s ON s.id = ${named(engine, 'x', 'source')}`);
  const states = wanted.map((): { version: number | null; source: string | null }[] => []);
  for (const row of rows) states[Number(row.i)]!.push({ version: row.version === null ? null : Number(row.version), source: row.source });
  return states;
}

/** A field of the key's object a change's payload (`<alias>.payload`) holds, as text: a write's own, or the cutover's object's. */
function field(engine: dialect.Engine, alias: string, name: string): SQL {
  return sql.raw(engine === 'postgres'
    ? `(CASE (${alias}.payload::jsonb ->> 'op') WHEN 'secret.write' THEN (${alias}.payload::jsonb ->> '${name}') WHEN 'genesis' THEN (${alias}.payload::jsonb -> 'value' ->> '${name}') END)`
    : `(CASE json_extract(${alias}.payload, '$.op') WHEN 'secret.write' THEN json_extract(${alias}.payload, '$.${name}') WHEN 'genesis' THEN json_extract(${alias}.payload, '$.value.${name}') END)`);
}

/** An id the object names (`field`), to read by primary key; none for one that is no uuid (a reference's empty version). */
function named(engine: dialect.Engine, alias: string, name: string): SQL {
  const value = field(engine, alias, name);
  return engine === 'postgres' ? sql`CAST(CASE WHEN ${value} ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN ${value} END AS uuid)` : value;
}

/** Whose way in a use's code names (`USE_WAYS`); and its purpose, null for a code no release writes. */
export function useParts(code: number): { purpose: string | null; keepsSensitive: boolean; way: 'credential' | UseWay } {
  const parts = useOfCode(code);
  return parts === null ? { purpose: null, keepsSensitive: false, way: 'credential' } : { purpose: parts.purpose, keepsSensitive: parts.keepsSensitive, way: parts.way ?? 'credential' };
}

/**
 * The members behind Cloudflare Access whom these uses name, by their
 * object (`accessObject`): every member's, read from `vault_members`,
 * hashed, and matched. Only a page with a use through Access reads it.
 */
export async function accountsBehindAccess(db: Queryable, objects: readonly string[]): Promise<Map<string, string>> {
  if (objects.length === 0) return new Map();
  const wanted = new Set(objects);
  const rows = await dialect.rowsOf<{ principal: string }>(db, sql`SELECT principal FROM vault_members`);
  return new Map(rows.map(({ principal }) => [accessObject(principal), principal] as const).filter(([object]) => wanted.has(object)));
}

/**
 * What these members read under 0.15's log, by key: the first and last of
 * their uses of it, by number, and when the last was. What an offboarding
 * report weighs (`memberActivity`); a read through a reference counts for
 * the reference's key here, its caller looks through it. Every use of
 * theirs is read, as 0.14's report reads every entry of theirs.
 */
export async function usesBy(db: Queryable, actors: readonly string[]): Promise<{ actor: string; secret: string; first: bigint; last: bigint; at: number }[]> {
  const members = actors.filter((actor) => actor.startsWith('user:') || actor.startsWith('token:'));
  if (members.length === 0) return [];
  const engine = dialect.engineOf(db);
  const list = sql.join(members.map((member) => sql`${member}`), sql`, `);
  const access = sql.join(members.map((member) => sql`SELECT ${engine === 'postgres' ? sql`CAST(${accessObject(member)} AS uuid)` : sql`${accessObject(member)}`} AS id, ${member} AS principal`), sql` UNION ALL `);
  const rows = await dialect.rowsOf<{ actor: string; secret: string; first: string | number | bigint; last: string | number | bigint; at: string | number }>(db, sql`
    SELECT w.principal AS actor, ${sql.raw(text(engine, 'u.secret'))} AS secret, min(u.number) AS first, max(u.number) AS last, max(u.at) AS at
      FROM (SELECT id, principal FROM credentials WHERE principal IN (${list})
            UNION ALL SELECT id, principal FROM mcp_connections WHERE principal IN (${list})
            UNION ALL SELECT id, principal FROM service_bindings WHERE principal IN (${list})
            UNION ALL ${access}) w
      JOIN log_uses u ON u.credential = w.id
     GROUP BY w.principal, u.secret`);
  return rows.map((row) => ({ actor: row.actor, secret: row.secret, first: BigInt(row.first), last: BigInt(row.last), at: Number(row.at) }));
}
