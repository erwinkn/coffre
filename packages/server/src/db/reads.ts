import type { Queryable } from '@coffre/db';
import * as dialect from '@coffre/db/dialect';
import { sql, type SQL } from 'drizzle-orm';

import type { ChangePoint } from './queries.ts';

// 0.15's reads as the audit pages list them (T166; docs/design/0.15-plan.md,
// "As built: T166"; formal/Reads.tla). Each use a signed pair seals, the
// vault's projector writes once, from the sealed objects at its number, under
// a MAC of the vault's that covers its number too (`log_reads`): whose read it
// was, its key's place, the fork it was read in, through a reference its
// source then, the version read. These reads list them on the whole log and
// by member (no page of a place lists them in 0.15: D160), a page at a time,
// each from an index read newest first and no further than a page.

/** A read as a page lists it: the projector's row, and the names of what it names, as the rows say them now. */
export type ListedRead = {
  number: bigint;
  at: number;
  credential: string;
  purpose: number;
  principal: string;
  secret: string;
  environment: string;
  project: string;
  place: string | null;
  source: string | null;
  sourceEnvironment: string | null;
  sourceProject: string | null;
  version: string | null;
  mac: Buffer;
  /** The key's name and where it is, by slugs; through a reference, the source's; the fork's slug. */
  key: string | null;
  projectSlug: string | null;
  environmentSlug: string | null;
  sourceKey: string | null;
  sourceProjectSlug: string | null;
  sourceEnvironmentSlug: string | null;
  forkSlug: string | null;
  /** The number of the version read, as `secret_versions` says it. */
  versionNumber: number | null;
  /** Through MCP, the app, as its connection's row names it. */
  client: { id: string; name: string } | null;
};

/**
 * Places a list of reads is held to: any of these projects, environments or
 * keys, and none of the environments `except` names (a protected one the
 * caller's role leaves out). A read is at its key's environment, at the fork
 * it was read in, and through a reference at its source's.
 */
export type ReadFilter = {
  /** The members whose reads, as the log names them: `user:ada@acme.example`, `token:ci`. */
  actors?: readonly string[];
  before?: ChangePoint;
  limit: number;
};

/** Above every read: a page's start without `before`, and, below a time alone, above every read at it. */
const MAX = 9_223_372_036_854_775_807n;

const bigint = (value: number | bigint) => sql`CAST(${String(value)} AS bigint)`;

/**
 * The newest reads `filter` asks for, newest first by `(at, number)`, as
 * 0.15's records are listed, below `before`: up to `limit`, and whether there
 * are more. Every read, by the projection's own index; a member's, by
 * `log_reads_principal_idx`, through a function that holds its plan to it
 * (migration 0049). However many reads the log holds, a page reads as many
 * index entries as it shows. No page of a place lists reads in 0.15 (D160).
 */
export async function readsPage(db: Queryable, filter: ReadFilter): Promise<{ rows: ListedRead[]; more: boolean }> {
  const engine = dialect.engineOf(db);
  const take = filter.limit + 1;
  const found = pageSql(engine, filter, take);
  if (found === null) return { rows: [], more: false };
  const rows = await dialect.rowsOf<Row>(db, listed(engine, found));
  return { rows: rows.slice(0, filter.limit).map(read), more: rows.length > filter.limit };
}

/** The `(at, number)` of the page's reads, newest first, `take` at most; null for a filter of no member. */
function pageSql(engine: dialect.Engine, filter: ReadFilter, take: number): SQL | null {
  const actors = filter.actors?.filter((actor) => actor.startsWith('user:') || actor.startsWith('token:'));
  if (actors?.length === 0) return null;
  const [at, number] = [bigint(filter.before?.at ?? MAX), bigint(filter.before?.number ?? MAX)];
  const streams = actors === undefined
    ? [sql`SELECT r.at, r.number FROM log_reads r WHERE (r.at, r.number) < (${at}, ${number}) ORDER BY r.at DESC, r.number DESC LIMIT ${take}`]
    : actors.map((actor) => (engine === 'postgres'
      ? sql`SELECT * FROM log_reads_by(${actor}, ${at}, ${number}, ${take})`
      : sql`SELECT at, number FROM log_reads WHERE principal = ${actor} AND (at, number) < (${at}, ${number}) ORDER BY at DESC, number DESC LIMIT ${take}`));
  return sql`SELECT DISTINCT f.at, f.number FROM (${sql.join(streams.map((each) => sql`SELECT * FROM (${each}) s`), sql` UNION ALL `)}) f ORDER BY f.at DESC, f.number DESC LIMIT ${take}`;
}

type Row = {
  number: string | number | bigint; at: string | number; credential: string; purpose: number | string; principal: string; secret: string; environment: string; project: string;
  place: string | null; source: string | null; source_environment: string | null; source_project: string | null; version: string | null; mac: Uint8Array;
  key: string | null; project_slug: string | null; environment_slug: string | null; source_key: string | null; source_project_slug: string | null; source_environment_slug: string | null;
  fork_slug: string | null; version_number: number | string | null; client_id: string | null; client_name: string | null;
};

/** The reads `found` names, newest first, each with the names of what it names: lookups by primary key, a probe each. */
function listed(engine: dialect.Engine, found: SQL): SQL {
  const text = (column: string) => sql.raw(engine === 'postgres' ? `CAST(${column} AS text)` : column);
  // Each a probe of its row's key, `LIMIT 1` so that Postgres keeps it one: pulled up into a join, the planner may read a
  // table whole once its estimates grow (review r3: secrets read whole, 911 pages a page, then 2,139).
  const join = (alias: string, select: SQL) => (engine === 'postgres' ? sql`LEFT JOIN LATERAL (${select} LIMIT 1) ${sql.raw(alias)} ON TRUE` : sql`LEFT JOIN (${select}) ${sql.raw(alias)}`);
  if (engine === 'postgres') {
    return sql`
      SELECT c.number, c.at, ${text('c.credential')} AS credential, c.purpose, c.principal, ${text('c.secret')} AS secret, ${text('c.environment')} AS environment,
        ${text('c.project')} AS project, ${text('c.place')} AS place, ${text('c.source')} AS source, ${text('c.source_environment')} AS source_environment,
        ${text('c.source_project')} AS source_project, ${text('c.version')} AS version, c.mac,
        k.key, k.project_slug, k.environment_slug, s.key AS source_key, s.project_slug AS source_project_slug, s.environment_slug AS source_environment_slug,
        f.slug AS fork_slug, v.version AS version_number, m.client_id, m.client_name
      FROM (${found}) t
      CROSS JOIN LATERAL (SELECT * FROM log_reads x WHERE x.at = t.at AND x.number = t.number LIMIT 1) c
      ${join('k', sql`SELECT s.key, p.slug AS project_slug, e.slug AS environment_slug FROM secrets s JOIN projects p ON p.id = s.project_id JOIN environments e ON e.id = s.environment_id WHERE s.id = c.secret`)}
      ${join('s', sql`SELECT s.key, p.slug AS project_slug, e.slug AS environment_slug FROM secrets s JOIN projects p ON p.id = s.project_id JOIN environments e ON e.id = s.environment_id WHERE s.id = c.source`)}
      ${join('f', sql`SELECT slug FROM environments WHERE id = c.place`)}
      ${join('v', sql`SELECT version FROM secret_versions WHERE id = c.version`)}
      ${join('m', sql`SELECT client_id, client_name FROM mcp_connections WHERE id = c.credential AND c.purpose >= 512 AND c.purpose < 1024`)}
      ORDER BY c.at DESC, c.number DESC`;
  }
  void join;
  return sql`
    SELECT c.number, c.at, c.credential, c.purpose, c.principal, c.secret, c.environment, c.project, c.place, c.source, c.source_environment, c.source_project, c.version, c.mac,
      ks.key, kp.slug AS project_slug, ke.slug AS environment_slug, ss.key AS source_key, sp.slug AS source_project_slug, se.slug AS source_environment_slug,
      f.slug AS fork_slug, v.version AS version_number, m.client_id, m.client_name
    FROM (${found}) t
    JOIN log_reads c ON c.at = t.at AND c.number = t.number
    LEFT JOIN secrets ks ON ks.id = c.secret LEFT JOIN projects kp ON kp.id = ks.project_id LEFT JOIN environments ke ON ke.id = ks.environment_id
    LEFT JOIN secrets ss ON ss.id = c.source LEFT JOIN projects sp ON sp.id = ss.project_id LEFT JOIN environments se ON se.id = ss.environment_id
    LEFT JOIN environments f ON f.id = c.place
    LEFT JOIN secret_versions v ON v.id = c.version
    LEFT JOIN mcp_connections m ON m.id = c.credential AND c.purpose >= 512 AND c.purpose < 1024
    ORDER BY c.at DESC, c.number DESC`;
}

function read(row: Row): ListedRead {
  return {
    number: BigInt(row.number), at: Number(row.at), credential: row.credential, purpose: Number(row.purpose), principal: row.principal, secret: row.secret,
    environment: row.environment, project: row.project, place: row.place, source: row.source, sourceEnvironment: row.source_environment, sourceProject: row.source_project,
    version: row.version, mac: Buffer.from(row.mac), key: row.key, projectSlug: row.project_slug, environmentSlug: row.environment_slug, sourceKey: row.source_key,
    sourceProjectSlug: row.source_project_slug, sourceEnvironmentSlug: row.source_environment_slug, forkSlug: row.fork_slug,
    versionNumber: row.version_number === null ? null : Number(row.version_number),
    client: row.client_id === null || row.client_name === null ? null : { id: row.client_id, name: row.client_name },
  };
}

/**
 * How far the reads are listed (`log_reads_cursor`), against the newest pair
 * signed: every read at or below `through` is projected, and `at` is the
 * signed time they are listed through, `pair` and `mac` the cursor's own;
 * `sealed`, the newest pair's number, and `sealedAt`, its time. One statement.
 */
/** How far the reads are listed, as a page or a report reads it: the cursor, and the newest signed pair; `missing`, no cursor. */
export type ReadsStanding = { through: bigint; pair: bigint; at: number; mac: Buffer | null; sealed: bigint | null; sealedAt: number | null; missing: boolean };

/**
 * The standing's columns, one row whatever the cursor: its migration's one
 * row gone (only a database writer leaves it so) reads as `missing`, which
 * the pages show unvouched, never as a fresh start (review r6). Joined into
 * a page's or a report's statement, the two are one snapshot.
 */
function standingSql(): SQL {
  return sql`SELECT c.through AS s_through, c.pair AS s_pair, c.at AS s_at, c.mac AS s_mac, k.upto AS s_sealed, k.at AS s_sealed_at, c.only_row AS s_row
    FROM (SELECT 1 AS one) o LEFT JOIN log_reads_cursor c ON c.only_row
    LEFT JOIN (SELECT upto, at FROM log_checkpoints ORDER BY upto DESC LIMIT 1) k ON TRUE`;
}

type StandingRow = {
  s_through: string | number | null; s_pair: string | number | null; s_at: string | number | null; s_mac: Uint8Array | null;
  s_sealed: string | number | null; s_sealed_at: string | number | null; s_row: unknown;
};

function standingOf(row: StandingRow | undefined): ReadsStanding {
  const sealed = row?.s_sealed == null ? null : BigInt(row.s_sealed);
  const sealedAt = row?.s_sealed_at == null ? null : Number(row.s_sealed_at);
  if (row === undefined || row.s_row === null || row.s_through === null) return { through: 0n, pair: 0n, at: 0, mac: null, sealed, sealedAt, missing: true };
  return {
    through: BigInt(row.s_through), pair: BigInt(row.s_pair!), at: Number(row.s_at), mac: row.s_mac === null ? null : Buffer.from(row.s_mac), sealed, sealedAt, missing: false,
  };
}

export async function readsStanding(db: Queryable): Promise<ReadsStanding> {
  const [row] = await dialect.rowsOf<StandingRow>(db, standingSql());
  return standingOf(row);
}

/**
 * A page of reads (`readsPage`) and how far they are listed, in one
 * statement, so in one snapshot: read apart, a projector's write between the
 * two would have the cursor vouch for reads the page did not list (review
 * r6).
 */
export async function readsPageStanding(db: Queryable, filter: ReadFilter): Promise<{ rows: ListedRead[]; more: boolean; standing: ReadsStanding }> {
  const engine = dialect.engineOf(db);
  const take = filter.limit + 1;
  const found = pageSql(engine, filter, take);
  const rows = await dialect.rowsOf<Row & StandingRow>(db, found === null
    ? standingSql()
    : sql`SELECT st.*, p.* FROM (${standingSql()}) st LEFT JOIN (${listed(engine, found)}) p ON TRUE ORDER BY p.at DESC, p.number DESC`);
  const listedRows = rows.filter((row) => row.number !== null && row.number !== undefined);
  return { rows: listedRows.slice(0, filter.limit).map(read), more: listedRows.length > filter.limit, standing: standingOf(rows[0]) };
}

/**
 * What these members read under 0.15's log, by key and version: each key
 * they read, or through a reference each source, every version they read of
 * it, and when last, from their days that hold any (`log_read_days`): never
 * a probe of each day the log holds. What an offboarding report weighs
 * (`memberActivity`). Like 0.14's report, it reads every read of theirs.
 */
function readsBySql(db: Queryable, members: readonly string[]): SQL {
  const engine = dialect.engineOf(db);
  const text = (column: string) => sql.raw(engine === 'postgres' ? `CAST(${column} AS text)` : column);
  const named = sql.join(members.map((member) => sql`${member}`), sql`, `);
  // On Postgres each of the member's days reads its own partition, a day at a time: `OFFSET 0` keeps the lateral a loop
  // over the days, whose bounds prune the partitions as it runs; flattened into a join, the planner may read every
  // day's partition first (review r8: 80 buffers, then 322 with 100 newer days of others' reads). SQLite has no
  // partitions to read.
  const reads = engine === 'postgres'
    ? sql`log_read_days d CROSS JOIN LATERAL (
        SELECT r.principal, r.source, r.secret, r.version, r.at FROM log_reads r
         WHERE r.principal = d.principal AND r.at >= CAST(d.day AS bigint) * 86400000 AND r.at < (CAST(d.day AS bigint) + 1) * 86400000 OFFSET 0) r`
    : sql`log_read_days d JOIN log_reads r ON r.principal = d.principal AND r.at >= d.day * 86400000 AND r.at < (d.day + 1) * 86400000`;
  return sql`
    SELECT r.principal AS actor, ${text('coalesce(r.source, r.secret)')} AS secret, v.version, max(r.at) AS read_at
      FROM ${reads}
      JOIN secret_versions v ON v.id = r.version
     WHERE d.principal IN (${named})
     GROUP BY r.principal, coalesce(r.source, r.secret), v.version`;
}

const membersOf = (actors: readonly string[]) => actors.filter((actor) => actor.startsWith('user:') || actor.startsWith('token:'));
type ByRow = { actor: string | null; secret: string | null; version: number | string | null; read_at: string | number | null };
const byRows = (rows: readonly ByRow[]) => rows.filter((row) => row.actor !== null).map((row) => ({ actor: row.actor!, secret: row.secret!, version: Number(row.version), at: Number(row.read_at) }));

export async function readsBy(db: Queryable, actors: readonly string[]): Promise<{ actor: string; secret: string; version: number; at: number }[]> {
  const members = membersOf(actors);
  if (members.length === 0) return [];
  return byRows(await dialect.rowsOf<ByRow>(db, readsBySql(db, members)));
}

/**
 * `readsBy` and `readsStanding` in one statement, so in one snapshot: an
 * offboarding report's reads, and how far they are listed as it read them.
 * Read apart, a projector's write between the two would have the report
 * name none and say none wait (review r5).
 */
export async function readsByStanding(db: Queryable, actors: readonly string[]): Promise<{ reads: Awaited<ReturnType<typeof readsBy>>; standing: ReadsStanding }> {
  const members = membersOf(actors);
  const rows = await dialect.rowsOf<StandingRow & ByRow>(db, members.length === 0
    ? standingSql()
    : sql`SELECT st.*, g.* FROM (${standingSql()}) st LEFT JOIN (${readsBySql(db, members)}) g ON TRUE`);
  return { reads: byRows(rows.map((row) => ({ actor: row.actor ?? null, secret: row.secret ?? null, version: row.version ?? null, read_at: row.read_at ?? null }))), standing: standingOf(rows[0]) };
}
