import type { Queryable } from '@coffre/db';
import * as dialect from '@coffre/db/dialect';
import { sql, type SQL } from 'drizzle-orm';

import type { ChangePoint } from './queries.ts';

// 0.15's reads as the audit pages list them (T166; docs/design/0.15-plan.md,
// "As built: T166"; formal/Reads.tla). Each use a signed pair seals, the
// vault's projector writes once, from the sealed objects at its number, under
// a MAC of the vault's that covers its number too (`log_reads`): whose read it
// was, its key's place, the fork it was read in, through a reference its
// source then, the version read; and a row for each place it is at, with the
// place it is at besides (`log_read_places`). These reads list them, a page at
// a time, each from an index read newest first and no further than a page.

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
export type ReadPlaces = { projectIds: readonly string[]; environmentIds: readonly string[]; secretIds: readonly string[]; except: readonly string[] };

export type ReadFilter = {
  /** The members whose reads, as the log names them: `user:ada@acme.example`, `token:ci`. */
  actors?: readonly string[];
  /** Each must hold: a page's path, and the places its caller reads. */
  places?: readonly ReadPlaces[];
  before?: ChangePoint;
  limit: number;
};

/** Above every read: a page's start without `before`, and, below a time alone, above every read at it. */
const MAX = 9_223_372_036_854_775_807n;

const bigint = (value: number | bigint) => sql`CAST(${String(value)} AS bigint)`;

/**
 * The newest reads `filter` asks for, newest first by `(at, number)`, as
 * 0.15's records are listed, below `before`: up to `limit`, and whether there
 * are more.
 *
 * Every read, by the projection's own index; a member's, by
 * `log_reads_principal_idx`; at some places, from the places they name and
 * the sets of places a read there is at (`log_read_partners`), each set the
 * caller may see whole (`sets`), by `log_read_places`' indexes, the
 * member's or the key's where a page asks for one. On Postgres each through
 * a function that holds its plan to its index (migration 0049). However many
 * reads the log holds, a page reads as many index entries as it shows, for
 * each set it reads, and none of a set it may not see: a quiet place costs
 * a probe of each day it may hold a read, never a read. Two statements: the
 * sets, then the page.
 */
export async function readsPage(db: Queryable, filter: ReadFilter): Promise<{ rows: ListedRead[]; more: boolean }> {
  const engine = dialect.engineOf(db);
  const take = filter.limit + 1;
  const actors = filter.actors?.filter((actor) => actor.startsWith('user:') || actor.startsWith('token:'));
  if (actors?.length === 0) return { rows: [], more: false };
  const places = filter.places ?? [];
  if (places.some(empty)) return { rows: [], more: false };
  const point = { at: filter.before?.at ?? MAX, number: filter.before?.number ?? MAX };
  const streams: SQL[] = [];
  if (places.length === 0) {
    if (actors === undefined) {
      streams.push(sql`SELECT r.at, r.number FROM log_reads r WHERE (r.at, r.number) < (${bigint(point.at)}, ${bigint(point.number)}) ORDER BY r.at DESC, r.number DESC LIMIT ${take}`);
    } else {
      for (const actor of actors) streams.push(stream(engine, 'by', { principal: actor }, point, take));
    }
  } else {
    const { sets, keys } = await setsOf(db, places);
    for (const { environment, partners } of sets) {
      for (const principal of actors ?? [null]) {
        for (const secret of keys ?? [null]) {
          const kind = principal === null ? (secret === null ? 'in' : 'of') : secret === null ? 'byIn' : 'byOf';
          streams.push(stream(engine, kind, { principal, secret, environment, partners }, point, take));
        }
      }
    }
  }
  if (streams.length === 0) return { rows: [], more: false };
  const found = sql`SELECT DISTINCT f.at, f.number FROM (${sql.join(streams.map((each) => sql`SELECT * FROM (${each}) s`), sql` UNION ALL `)}) f ORDER BY f.at DESC, f.number DESC LIMIT ${take}`;
  const rows = await dialect.rowsOf<Row>(db, listed(engine, found));
  // Each read where its own columns, which its MAC covers, place it: the place rows only find it (fail closed).
  return { rows: rows.slice(0, filter.limit).map(read).filter((row) => places.every((list) => within(row, list))), more: rows.length > filter.limit };
}

/**
 * Whether a read is at one of `list`'s places and at none it leaves out, by
 * its own columns: its key's environment and project, the fork it was read
 * in, its source's environment and project; for a list of keys, the key it
 * names or its source.
 */
function within(row: ListedRead, list: ReadPlaces): boolean {
  const at: [string, string][] = [[row.environment, row.project]];
  if (row.place !== null) at.push([row.place, row.project]);
  if (row.sourceEnvironment !== null) at.push([row.sourceEnvironment, row.sourceProject ?? row.project]);
  if (at.some(([environment]) => list.except.includes(environment))) return false;
  if (list.secretIds.length > 0) return list.secretIds.includes(row.secret) || (row.source !== null && list.secretIds.includes(row.source));
  return at.some(([environment, project]) => list.environmentIds.includes(environment) || list.projectIds.includes(project));
}

/** One index's stream of `(at, number)`, newest first, below `point`, at most `take` reads: on Postgres its function, on SQLite its read. */
function stream(
  engine: dialect.Engine, kind: 'by' | 'in' | 'of' | 'byIn' | 'byOf',
  on: { principal?: string | null; secret?: string | null; environment?: string; partners?: readonly string[] },
  point: { at: number | bigint; number: number | bigint }, take: number,
): SQL {
  const [at, number] = [bigint(point.at), bigint(point.number)];
  if (engine === 'postgres') {
    const id = (value: string | null | undefined) => sql`CAST(${value} AS uuid)`;
    const set = sql`CAST(${`{${(on.partners ?? []).join(',')}}`} AS uuid[])`;
    switch (kind) {
      case 'by': return sql`SELECT * FROM log_reads_by(${on.principal}, ${at}, ${number}, ${take})`;
      case 'in': return sql`SELECT * FROM log_reads_in(${id(on.environment)}, ${set}, ${at}, ${number}, ${take})`;
      case 'of': return sql`SELECT * FROM log_reads_of(${id(on.secret)}, ${id(on.environment)}, ${set}, ${at}, ${number}, ${take})`;
      case 'byIn': return sql`SELECT * FROM log_reads_by_in(${on.principal}, ${id(on.environment)}, ${set}, ${at}, ${number}, ${take})`;
      case 'byOf': return sql`SELECT * FROM log_reads_by_of(${on.principal}, ${id(on.secret)}, ${id(on.environment)}, ${set}, ${at}, ${number}, ${take})`;
    }
  }
  const below = sql`(at, number) < (${at}, ${number})`;
  if (kind === 'by') return sql`SELECT at, number FROM log_reads WHERE principal = ${on.principal} AND ${below} ORDER BY at DESC, number DESC LIMIT ${take}`;
  const conditions = [
    sql`environment = ${on.environment}`, sql`partners = ${JSON.stringify(on.partners ?? [])}`, below,
    ...(on.principal == null ? [] : [sql`principal = ${on.principal}`]),
    ...(on.secret == null ? [] : [sql`secret = ${on.secret}`]),
  ];
  // A read through a reference within one environment is at it under two keys: once.
  return sql`SELECT DISTINCT at, number FROM log_read_places WHERE ${sql.join(conditions, sql` AND `)} ORDER BY at DESC, number DESC LIMIT ${take}`;
}

/** Whether a list of places holds nothing: no project, environment or key to be in. */
function empty(places: ReadPlaces): boolean {
  return places.projectIds.length === 0 && places.environmentIds.length === 0 && places.secretIds.length === 0;
}

/**
 * The sets of places a page at `places` reads: each place one of them
 * names (a key's environment, and its forks', for a key) with the places a
 * read there is at besides, as `log_read_partners` lists them, kept where
 * the set holds a place each list names, and none left out, so that every
 * read a set stands for is one the caller may see, and the page reads no
 * read it may not. The keys a page of keys names. One statement.
 */
async function setsOf(db: Queryable, places: readonly ReadPlaces[]): Promise<{ sets: { environment: string; partners: string[] }[]; keys: string[] | null }> {
  const engine = dialect.engineOf(db);
  const postgres = engine === 'postgres';
  const text = (column: string) => sql.raw(postgres ? `CAST(${column} AS text)` : column);
  const keys = [...new Set(places.flatMap((p) => p.secretIds))];
  // The pages ask for at most one list of keys: a path's.
  const keyed = places.find((p) => p.secretIds.length > 0);
  const ids = (values: readonly string[]) => (values.length === 0 ? sql`NULL` : sql.join(values.map((value) => (postgres ? sql`CAST(${value} AS uuid)` : sql`${value}`)), sql`, `));
  const named = [...new Set(places.flatMap((p) => p.environmentIds))];
  const projects = [...new Set(places.flatMap((p) => p.projectIds))];
  // Where the places' reads are: the environments named, those of the projects named, and a key's own and its forks'.
  // With each set, the projects of the places in it that are among those: a place outside them is in no list.
  const rows = await dialect.rowsOf<{ environment: string; partners: string | string[]; projects: string | null }>(db, sql`
    WITH RECURSIVE named(id) AS (
      SELECT e.id FROM environments e WHERE e.id IN (${ids(named)}) OR e.project_id IN (${ids(projects)})
        OR e.id IN (SELECT s.environment_id FROM secrets s WHERE s.id IN (${ids(keys)}))
      UNION SELECT e.id FROM environments e JOIN named n ON e.parent_id = n.id WHERE ${keyed === undefined ? sql`FALSE` : sql`TRUE`}
    ), places AS (
      SELECT e.id, e.project_id FROM environments e JOIN named n ON n.id = e.id
    )
    SELECT ${text('p.environment')} AS environment, ${sql.raw(postgres ? 'CAST(to_json(p.partners) AS text)' : 'p.partners')} AS partners,
      ${postgres
        ? sql`(SELECT string_agg(CAST(q.id AS text) || ':' || CAST(q.project_id AS text), ',') FROM places q WHERE q.id = p.environment OR q.id = ANY(p.partners))`
        : sql`(SELECT group_concat(q.id || ':' || q.project_id, ',') FROM places q WHERE q.id = p.environment OR q.id IN (SELECT value FROM json_each(p.partners)))`} AS projects
      FROM log_read_partners p JOIN named n ON n.id = p.environment`);
  const except = new Set(places.flatMap((p) => p.except));
  const sets = rows.flatMap((row) => {
    const partners = Array.isArray(row.partners) ? row.partners : (JSON.parse(row.partners) as string[]);
    const projectOf = new Map((row.projects ?? '').split(',').filter((pair) => pair !== '').map((pair) => pair.split(':') as [string, string]));
    const at = [row.environment, ...partners];
    if (at.some((place) => except.has(place))) return [];
    const holds = (list: ReadPlaces) => list.secretIds.length > 0
      || at.some((place) => list.environmentIds.includes(place) || (projectOf.has(place) && list.projectIds.includes(projectOf.get(place)!)));
    return places.every(holds) ? [{ environment: row.environment, partners }] : [];
  });
  return { sets, keys: keyed === undefined ? null : [...keyed.secretIds] };
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
export async function readsStanding(db: Queryable): Promise<{ through: bigint; pair: bigint; at: number; mac: Buffer | null; sealed: bigint | null; sealedAt: number | null }> {
  const [row] = await dialect.rowsOf<{ through: string | number; pair: string | number; at: string | number; mac: Uint8Array | null; sealed: string | number | null; sealed_at: string | number | null }>(db, sql`
    SELECT c.through, c.pair, c.at, c.mac, k.upto AS sealed, k.at AS sealed_at FROM log_reads_cursor c
      LEFT JOIN (SELECT upto, at FROM log_checkpoints ORDER BY upto DESC LIMIT 1) k ON TRUE WHERE c.only_row`);
  if (row === undefined) return { through: 0n, pair: 0n, at: 0, mac: null, sealed: null, sealedAt: null };
  return {
    through: BigInt(row.through), pair: BigInt(row.pair), at: Number(row.at), mac: row.mac === null ? null : Buffer.from(row.mac),
    sealed: row.sealed === null ? null : BigInt(row.sealed), sealedAt: row.sealed_at === null ? null : Number(row.sealed_at),
  };
}

/**
 * What these members read under 0.15's log, by key and version: each key
 * they read, or through a reference each source, every version they read of
 * it, and when last. What an offboarding report weighs (`memberActivity`).
 * Like 0.14's report, it reads every read of theirs.
 */
export async function readsBy(db: Queryable, actors: readonly string[]): Promise<{ actor: string; secret: string; version: number; at: number }[]> {
  const members = actors.filter((actor) => actor.startsWith('user:') || actor.startsWith('token:'));
  if (members.length === 0) return [];
  const engine = dialect.engineOf(db);
  const text = (column: string) => sql.raw(engine === 'postgres' ? `CAST(${column} AS text)` : column);
  const rows = await dialect.rowsOf<{ actor: string; secret: string; version: number | string; at: string | number }>(db, sql`
    SELECT r.principal AS actor, ${text('coalesce(r.source, r.secret)')} AS secret, v.version, max(r.at) AS at
      FROM log_reads r JOIN secret_versions v ON v.id = r.version
     WHERE r.principal IN (${sql.join(members.map((member) => sql`${member}`), sql`, `)})
     GROUP BY r.principal, coalesce(r.source, r.secret), v.version`);
  return rows.map((row) => ({ actor: row.actor, secret: row.secret, version: Number(row.version), at: Number(row.at) }));
}

/**
 * `readsBy` and `readsStanding` in one statement, so in one snapshot: an
 * offboarding report's reads, and how far they are listed as it read them.
 * Read apart, a projector's write between the two would have the report
 * name none and say none wait (review r5).
 */
export async function readsByStanding(db: Queryable, actors: readonly string[]): Promise<{ reads: Awaited<ReturnType<typeof readsBy>>; standing: Awaited<ReturnType<typeof readsStanding>> }> {
  const members = actors.filter((actor) => actor.startsWith('user:') || actor.startsWith('token:'));
  const engine = dialect.engineOf(db);
  const text = (column: string) => sql.raw(engine === 'postgres' ? `CAST(${column} AS text)` : column);
  const reads = members.length === 0 ? sql`SELECT NULL AS actor, NULL AS secret, NULL AS version, NULL AS read_at WHERE FALSE` : sql`
    SELECT r.principal AS actor, ${text('coalesce(r.source, r.secret)')} AS secret, v.version, max(r.at) AS read_at
      FROM log_reads r JOIN secret_versions v ON v.id = r.version
     WHERE r.principal IN (${sql.join(members.map((member) => sql`${member}`), sql`, `)})
     GROUP BY r.principal, coalesce(r.source, r.secret), v.version`;
  const rows = await dialect.rowsOf<{
    through: string | number; pair: string | number; at: string | number; mac: Uint8Array | null; sealed: string | number | null; sealed_at: string | number | null;
    actor: string | null; secret: string | null; version: number | string | null; read_at: string | number | null;
  }>(db, sql`
    SELECT s.through, s.pair, s.at, s.mac, s.sealed, s.sealed_at, g.actor, g.secret, g.version, g.read_at FROM (
      SELECT c.through, c.pair, c.at, c.mac, k.upto AS sealed, k.at AS sealed_at FROM log_reads_cursor c
        LEFT JOIN (SELECT upto, at FROM log_checkpoints ORDER BY upto DESC LIMIT 1) k ON TRUE WHERE c.only_row
    ) s LEFT JOIN (${reads}) g ON TRUE`);
  const [first] = rows;
  const standing = first === undefined
    ? { through: 0n, pair: 0n, at: 0, mac: null, sealed: null, sealedAt: null }
    : {
        through: BigInt(first.through), pair: BigInt(first.pair), at: Number(first.at), mac: first.mac === null ? null : Buffer.from(first.mac),
        sealed: first.sealed === null ? null : BigInt(first.sealed), sealedAt: first.sealed_at === null ? null : Number(first.sealed_at),
      };
  return {
    reads: rows.filter((row) => row.actor !== null).map((row) => ({ actor: row.actor!, secret: row.secret!, version: Number(row.version), at: Number(row.read_at) })),
    standing,
  };
}
