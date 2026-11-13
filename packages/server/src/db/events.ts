import type { Queryable } from '@coffre/db';
import * as dialect from '@coffre/db/dialect';
import { BATCH_BYTES, changesOf, logObject } from '@coffre/db/log';
import { sql, type SQL } from 'drizzle-orm';

// The audit pages and the offboarding report, read from the projection (docs/design/state-rows.md,
// section 2): `audit_events`, one row per entry of any log, `audit_event_places`, a row for each place an entry is
// at, `audit_member_keys`, the newest time each member read or wrote each version, and `audit_cursor`, how far the
// vault's projector has listed. The projector is their only writer, and every row is under its MAC.
//
// A page reads one stream, newest first by `(at, number, log)`, the projection's primary key: a place's, from
// `audit_event_places`; a member's, from `audit_events_actor_idx`; everyone's, from the primary key or
// `audit_events_shown_idx`. Every other filter (a member at a place, `decision`, what a reader of some places reads)
// is a condition on the rows it reads. A page stops reading where it fills, and reads no more than `WINDOW` rows past
// those it shows: it then holds what it found, and `next` goes on below the last row it read. So a page reads as many
// rows however long the log is.

/** A point in the projection, newest first: an entry, by its time, its number and its log. */
export type Position = { at: number; number: bigint; log: number };

/** Above every entry: a page with no `before`. */
const TOP: Position = { at: Number.MAX_SAFE_INTEGER, number: 9_223_372_036_854_775_807n, log: 32_767 };

/**
 * The most rows of its stream a page reads past those it shows: twice the
 * largest page the route serves (500), so that a page whose stream half
 * matches its filters still fills. A page whose filters match less reads no
 * further, shows what it found and goes on from `next`.
 */
export const WINDOW = 1_000;

/**
 * The most places a page reads each on its own index: each reads up to a
 * window of its own, so a reader of more reads everyone's stream instead,
 * held to their places, one window in all. A page of theirs may then come
 * back short where their places are a small part of the log, and goes on
 * from `next`.
 */
export const PLACES_APART = 8;

/** The stream a page reads: everyone's, shown entries alone or all; some members'; or the entries at some places. */
export type Stream = { all: true; shownOnly: boolean } | { actors: readonly string[] } | { places: readonly string[] };

/**
 * A page of the projection. `match` holds the rows of the stream to the
 * page's other filters; `detail` takes the entries a page leaves out unless
 * asked (`shown` false), which `counted` counts by action instead.
 */
export type EventsFilter = {
  stream: Stream;
  match: {
    allowed?: boolean;
    actors?: readonly string[];
    /** At one of these places, and at none of `except`: what a reader of some places reads. */
    within?: readonly string[];
    except?: readonly string[];
  };
  detail: boolean;
  counted: boolean;
  before?: Position;
  limit: number;
};

/** An entry as the projector wrote it, with the names of the places, key and version it names, as their rows say now. */
export type EventRow = {
  at: number;
  number: bigint;
  log: number;
  author: 'app' | 'vault';
  action: string;
  shown: boolean;
  allowed: boolean;
  code: string | null;
  actor: string;
  subject: string | null;
  credential: string | null;
  project: string | null;
  environment: string | null;
  secret: string | null;
  version: string | null;
  places: string[];
  requestId: string | null;
  operationId: string | null;
  related: bigint | null;
  sourceIp: string | null;
  detail: string;
  mac: Buffer;
  projectSlug: string | null;
  environmentSlug: string | null;
  key: string | null;
  versionNumber: number | null;
  recipe: string | null;
};

/**
 * How far the projector has listed (`audit_cursor`), against the newest pair
 * signed: every entry of the chains numbered at or below `through` is
 * listed, and `at` is the signed time of the newest pair whose entries are
 * all listed; `old*`, how far the frozen `audit_log` is. `sealed`, the newest pair's number,
 * and `sealedAt`, its time. `missing`: the cursor's one row is gone, which
 * only a database writer does.
 */
export type CursorStanding = {
  through: bigint;
  pair: bigint;
  at: number;
  oldFloor: bigint;
  oldFrom: bigint;
  oldTop: bigint;
  oldHash: Buffer;
  mac: Buffer | null;
  sealed: bigint | null;
  sealedAt: number | null;
  missing: boolean;
};

/**
 * A page: the entries it shows, newest first; the detail entries it passed
 * over, by action, when counted; and where the next page starts, null when
 * it read to the end. Its stretch runs from `before` down to the last row
 * it read, so pages tile the log: each entry is shown, or counted, on one.
 */
export type EventsPage = { rows: EventRow[]; hidden: Map<string, number>; next: Position | null; standing: CursorStanding };

const big = (value: number | bigint) => sql`CAST(${String(value)} AS bigint)`;
const uuids = (ids: readonly string[]) => sql`CAST(${sql.param([...ids])} AS uuid[])`;
const texts = (values: readonly string[]) => sql`CAST(${sql.param([...values])} AS text[])`;

/**
 * The stream's rows below `before`, newest first, `take` at most: each one's
 * place in the projection's order and its row whole (`e`). Each of a
 * stream's keys (a member, a place) is read on its own index, and, for a
 * place, each row it names by the projection's primary key as it comes; one
 * key's rows come in their index's order, so that the page stops reading
 * where it fills; several keys' are merged, each entry once.
 */
function streamSql(stream: Stream, before: Position, take: number): SQL {
  const below = (alias: string) => sql`(${sql.raw(alias)}.at, ${sql.raw(alias)}.number, ${sql.raw(alias)}.log) < (${big(before.at)}, ${big(before.number)}, CAST(${before.log} AS smallint))`;
  const order = (alias: string) => sql`ORDER BY ${sql.raw(alias)}.at DESC, ${sql.raw(alias)}.number DESC, ${sql.raw(alias)}.log DESC LIMIT ${take}`;
  if ('all' in stream) return sql`SELECT e.at, e.number, e.log, e FROM audit_events e WHERE ${stream.shownOnly ? sql`e.shown AND ` : sql``}${below('e')} ${order('e')}`;
  const [keys, list] = 'actors' in stream ? [stream.actors, texts] : [stream.places, uuids];
  // Each key's points from its index alone, newest first; then each point's entry by the primary key, as it comes.
  const points = (key: SQL) => ('actors' in stream
    ? sql`SELECT x.at, x.number, x.log FROM audit_events x WHERE x.actor = ${key} AND ${below('x')} ${order('x')}`
    : sql`SELECT x.at, x.number, x.log FROM audit_event_places x WHERE x.place = ${key} AND ${below('x')} ${order('x')}`);
  const merged = keys.length === 1
    ? points('actors' in stream ? sql`${keys[0]!}` : sql`CAST(${keys[0]!} AS uuid)`)
    : sql`SELECT DISTINCT p.at, p.number, p.log FROM unnest(${list(keys)}) AS k(key) CROSS JOIN LATERAL (${points(sql`k.key`)}) p`;
  // An entry gone from under its point (only a database writer leaves one so) comes as a point with no row: never taken.
  return sql`SELECT m.at, m.number, m.log, (SELECT e FROM audit_events e WHERE e.at = m.at AND e.number = m.number AND e.log = m.log) AS e
    FROM (${merged}) m ORDER BY m.at DESC, m.number DESC, m.log DESC LIMIT ${take}`;
}

/** The page's other filters, on a row `w` of the stream, whose entry is `w.e`. */
function matchSql(match: EventsFilter['match']): SQL {
  const conditions = [
    match.allowed === undefined ? null : sql`(w.e).allowed = ${match.allowed}`,
    match.actors === undefined ? null : sql`(w.e).actor = ANY(${texts(match.actors)})`,
    match.within === undefined ? null : sql`(w.e).places && ${uuids(match.within)}`,
    match.except === undefined || match.except.length === 0 ? null : sql`NOT ((w.e).places && ${uuids(match.except)})`,
  ].filter((condition) => condition !== null);
  return conditions.length === 0 ? sql`true` : sql.join(conditions, sql` AND `);
}

/**
 * The cursor and the newest pair, one row whatever the cursor: its one row
 * gone reads as `missing`, which the pages show unvouched, never as a fresh
 * start. Joined into a page's or a report's statement, the two are one
 * snapshot: read apart, a batch of the projector between them would have
 * the cursor vouch for entries the page did not list.
 */
function standingSql(): SQL {
  return sql`SELECT c.through AS s_through, c.pair AS s_pair, c.at AS s_at, c.old_floor AS s_old_floor, c.old_from AS s_old_from,
      c.old_top AS s_old_top, c.old_hash AS s_old_hash, c.mac AS s_mac, c.only_row AS s_row,
      k.upto AS s_sealed, k.at AS s_sealed_at
    FROM (SELECT 1 AS one) o LEFT JOIN audit_cursor c ON c.only_row
    LEFT JOIN (SELECT upto, at FROM log_checkpoints ORDER BY upto DESC LIMIT 1) k ON TRUE`;
}

type StandingRow = {
  s_through: string | number | null; s_pair: string | number | null; s_at: string | number | null; s_old_floor: string | number | null;
  s_old_from: string | number | null; s_old_top: string | number | null; s_old_hash: Uint8Array | null; s_mac: Uint8Array | null;
  s_row: unknown; s_sealed: string | number | null; s_sealed_at: string | number | null;
};

function standingOf(row: StandingRow | undefined): CursorStanding {
  const sealed = row?.s_sealed == null ? null : BigInt(row.s_sealed);
  const sealedAt = row?.s_sealed_at == null ? null : Number(row.s_sealed_at);
  if (row === undefined || row.s_row === null || row.s_through === null) {
    return { through: 0n, pair: 0n, at: 0, oldFloor: 0n, oldFrom: 0n, oldTop: 0n, oldHash: Buffer.alloc(32), mac: null, sealed, sealedAt, missing: true };
  }
  return {
    through: BigInt(row.s_through), pair: BigInt(row.s_pair!), at: Number(row.s_at), oldFloor: BigInt(row.s_old_floor!), oldFrom: BigInt(row.s_old_from!),
    oldTop: BigInt(row.s_old_top!), oldHash: Buffer.from(row.s_old_hash!), mac: row.s_mac === null ? null : Buffer.from(row.s_mac),
    sealed, sealedAt, missing: false,
  };
}

type PageRow = StandingRow & {
  held: string | number | null;
  at: string | number | null; number: string | number | null; log: number | string | null; taken: boolean | null; kept: boolean | null; passed: boolean | null; action: string | null;
  author: string | null; allowed: boolean | null; code: string | null; actor: string | null; subject: string | null;
  credential: string | null; project: string | null; environment: string | null; secret: string | null; version: string | null; places: string[] | null;
  request_id: string | null; operation_id: string | null; related: string | number | null; source_ip: string | null; detail: string | null; mac: Uint8Array | null;
  shown: boolean | null; project_slug: string | null; environment_slug: string | null; key: string | null; version_number: number | string | null;
  recipe: string | null;
};

/**
 * A page of the projection (`EventsFilter`) and how far it is listed, in one
 * statement, so as of one moment. The stream's rows, newest first, each
 * held to the page's filters, up to the `limit`-th it takes, the last
 * whose details fit in `BATCH_BYTES` with those before it (the first is
 * taken whatever its size), or `WINDOW` past the page: the page's stretch. Of it, the rows taken, whole, with the
 * names of what they name, each by its primary key; the rest light, for
 * what a page hides (when counted) and where the next one starts.
 */
export async function eventsPage(db: Queryable, asked: EventsFilter): Promise<EventsPage> {
  const filter = 'places' in asked.stream && asked.stream.places.length > PLACES_APART
    ? { ...asked, stream: { all: true as const, shownOnly: !asked.detail && !asked.counted }, match: { ...asked.match, within: asked.match.within ?? asked.stream.places } }
    : asked;
  const window = filter.limit + WINDOW;
  const match = matchSql(filter.match);
  const [taken, passed] = filter.detail ? [match, sql`false`] : [sql`(${match}) AND (w.e).shown`, sql`(${match}) AND NOT (w.e).shown`];
  const order = (t: string) => sql.raw(`ORDER BY ${t}.at DESC, ${t}.number DESC, ${t}.log DESC`);
  // `b`, the rows taken before each: the stretch is every row while fewer than `limit` were taken before it, so the
  // scan stops at the `limit`-th taken (a run condition) wherever the stream comes in its order. A row not taken comes
  // back light, for where the page stops and what it hides; one taken whole, with the names of what it names, each
  // by its primary key. `held`, the bytes of the details taken up to each: the first taken row past `BATCH_BYTES`
  // comes back light too, not kept, and the page stops above it. `held` is a level below `b`: Postgres stops a scan
  // on the run condition of the topmost window alone (a lower one only stops computing, and reads on), and its
  // frame ends at the current row, so it reads no further ahead than `b` asks.
  const page = sql`
    SELECT c.at, c.number, c.log, c.held, c.taken, c.taken AND (c.b = 0 OR c.held <= ${BATCH_BYTES}) AS kept, c.passed, (c.e).action, (c.e).author, (c.e).shown, (c.e).allowed, (c.e).code, (c.e).actor,
      (c.e).subject, CAST((c.e).credential AS text) AS credential, CAST((c.e).project AS text) AS project,
      CAST((c.e).environment AS text) AS environment, CAST((c.e).secret AS text) AS secret, CAST((c.e).version AS text) AS version,
      CASE WHEN c.taken AND (c.b = 0 OR c.held <= ${BATCH_BYTES}) THEN CAST((c.e).places AS text[]) END AS places, (c.e).request_id, CAST((c.e).operation_id AS text) AS operation_id,
      (c.e).related, (c.e).source_ip, CASE WHEN c.taken AND (c.b = 0 OR c.held <= ${BATCH_BYTES}) THEN (c.e).detail END AS detail,
      CASE WHEN c.taken THEN (c.e).mac END AS mac,
      p.slug AS project_slug, v.slug AS environment_slug, s.key, sv.version AS version_number, sv.recipe
    FROM (
      SELECT u.*, count(*) FILTER (WHERE u.taken) OVER (${order('u')} ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) AS b FROM (
        SELECT t.*, sum(octet_length((t.e).detail)) FILTER (WHERE t.taken) OVER (${order('t')} ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS held
          FROM (SELECT w.*, ${taken} AS taken, ${passed} AS passed FROM (${streamSql(filter.stream, filter.before ?? TOP, window)}) w) t
      ) u
    ) c
    LEFT JOIN projects p ON c.taken AND p.id = (c.e).project
    LEFT JOIN environments v ON c.taken AND v.id = (c.e).environment
    LEFT JOIN secrets s ON c.taken AND s.id = (c.e).secret
    LEFT JOIN secret_versions sv ON c.taken AND sv.id = (c.e).version
    WHERE c.b < ${filter.limit} AND (c.b = 0 OR c.held - CASE WHEN c.taken THEN octet_length((c.e).detail) ELSE 0 END <= ${BATCH_BYTES})`;
  const rows = await dialect.rowsOf<PageRow>(db, sql`SELECT st.*, g.* FROM (${standingSql()}) st LEFT JOIN (${page}) g ON TRUE
    ORDER BY g.at DESC, g.number DESC, g.log DESC`);
  const position = (row: PageRow): Position => ({ at: Number(row.at), number: BigInt(row.number!), log: Number(row.log) });
  // A row taken but not kept is the first past `BATCH_BYTES`: the stretch ends above it.
  const listed = rows.filter((row) => row.at !== null);
  const cut = listed.findIndex((row) => row.taken === true && row.kept !== true);
  const read = cut === -1 ? listed : listed.slice(0, cut);
  const shown = read.filter((row) => row.taken === true);
  const hidden = new Map<string, number>();
  if (filter.counted) for (const row of read) if (row.passed === true) hidden.set(row.action!, (hidden.get(row.action!) ?? 0) + 1);
  // The stretch read: to the `limit`-th row taken, or as far as the stream went, a whole window at most. The next page
  // starts below its last row, unless the stream ended inside it. Past `BATCH_BYTES` already at the last row (a first
  // row taken that large, kept whatever its size), every row below it was left out for its bytes, not for the stream
  // ending: the next page starts below it.
  const bottom = read.at(-1);
  const full = bottom !== undefined && Number(bottom.held ?? 0) > BATCH_BYTES;
  const end = cut === -1 && !full && shown.length < filter.limit && read.length < window;
  return { rows: shown.map(eventOf), hidden, next: end || bottom === undefined ? null : position(bottom), standing: standingOf(rows[0]) };
}

function eventOf(row: PageRow): EventRow {
  return {
    at: Number(row.at), number: BigInt(row.number!), log: Number(row.log), author: row.author as 'app' | 'vault', action: row.action!, shown: row.shown!,
    allowed: row.allowed!, code: row.code, actor: row.actor!, subject: row.subject, credential: row.credential, project: row.project,
    environment: row.environment, secret: row.secret, version: row.version, places: row.places ?? [], requestId: row.request_id,
    operationId: row.operation_id, related: row.related === null ? null : BigInt(row.related), sourceIp: row.source_ip, detail: row.detail!,
    mac: Buffer.from(row.mac!), projectSlug: row.project_slug, environmentSlug: row.environment_slug, key: row.key,
    versionNumber: row.version_number === null ? null : Number(row.version_number), recipe: row.recipe,
  };
}

/** The names a page's reads show that their rows hold by id alone: a holder's path, a fork's slug, an MCP app's. */
export type PageNames = { paths: Map<string, string>; slugs: Map<string, string>; clients: Map<string, { id: string; name: string }> };

/**
 * The names of these keys (`project/environment/KEY`), environments and MCP connections, as their rows say them now,
 * each by its primary key: one statement for a page, none for a page that names none.
 */
export async function namesOf(db: Queryable, asked: { secrets: readonly string[]; environments: readonly string[]; connections: readonly string[] }): Promise<PageNames> {
  const names: PageNames = { paths: new Map(), slugs: new Map(), clients: new Map() };
  if (asked.secrets.length + asked.environments.length + asked.connections.length === 0) return names;
  const rows = await dialect.rowsOf<{ kind: string; id: string; name: string | null; extra: string | null }>(db, sql`
    SELECT 'secret' AS kind, CAST(s.id AS text) AS id, p.slug || '/' || e.slug || '/' || s.key AS name, NULL AS extra
      FROM secrets s JOIN projects p ON p.id = s.project_id JOIN environments e ON e.id = s.environment_id WHERE s.id = ANY(${uuids(asked.secrets)})
    UNION ALL SELECT 'environment', CAST(e.id AS text), e.slug, NULL FROM environments e WHERE e.id = ANY(${uuids(asked.environments)})
    UNION ALL SELECT 'connection', CAST(m.id AS text), m.client_name, m.client_id FROM mcp_connections m WHERE m.id = ANY(${uuids(asked.connections)})`);
  for (const row of rows) {
    if (row.name === null) continue;
    if (row.kind === 'secret') names.paths.set(row.id, row.name);
    else if (row.kind === 'environment') names.slugs.set(row.id, row.name);
    else if (row.extra !== null) names.clients.set(row.id, { id: row.extra, name: row.name });
  }
  return names;
}

/** A live key a member read or wrote, by member, and whether its current value is one they saw. */
export type MemberKey = {
  principal: string;
  secret: string;
  project: string;
  environment: string;
  key: string;
  version: number;
  /** They saw its current value: they read or wrote its current version, or a version of the same ciphertext a restore brought back. */
  exposed: boolean;
  /** Of what they saw of the current value: whether they wrote it, and when they last read or wrote it. */
  wrote: boolean;
  at: number | null;
};

/**
 * What these members read or wrote that is still a live key (`audit_member_keys`), each key once: whether its current
 * value is one they saw, held to the version they saw by its ciphertext, `(iv, auth_tag)`, which a restore keeps (it
 * wraps the same value again); then, in the same statement, so as of one moment, how far the projection is listed and
 * each member's newest change, which is their removal for one removed (one seek of `log_changes_object_idx` each). Its
 * reads are as many as the keys they saw, however long the log.
 */
export async function memberKeys(
  db: Queryable, principals: readonly string[],
): Promise<{ keys: MemberKey[]; standing: CursorStanding; newest: Map<string, bigint>; readsFrom: number | null }> {
  const keys = sql`
    SELECT k.principal, CAST(s.id AS text) AS secret, p.slug AS project, v.slug AS environment, s.key, s.current_version AS version,
      bool_or(x.same) AS exposed, coalesce(bool_or(k.wrote) FILTER (WHERE x.same), false) AS wrote, max(k.at) FILTER (WHERE x.same) AS seen_at,
      NULL AS changed, NULL AS number
    FROM audit_member_keys k
    JOIN secrets s ON s.id = k.secret AND s.archived_at IS NULL AND s.current_version > 0
    JOIN environments v ON v.id = s.environment_id AND v.archived_at IS NULL
    JOIN projects p ON p.id = s.project_id AND p.archived_at IS NULL
    JOIN secret_versions now ON now.id = s.current_version_id
    JOIN secret_versions seen ON seen.id = k.version
    CROSS JOIN LATERAL (SELECT seen.id = now.id OR (seen.iv = now.iv AND seen.auth_tag = now.auth_tag) AS same) x
    WHERE k.principal = ANY(${texts(principals)})
    GROUP BY k.principal, s.id, p.slug, v.slug, s.key, s.current_version`;
  // One statement of one shape however many members: each one's newest change by their object, from two arrays.
  const mine = changesOf('c', sql`m.object`);
  const changed = sql`
    SELECT m.principal, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, m.principal AS changed,
      (SELECT c.number FROM log_changes c WHERE ${mine.where} ORDER BY ${mine.order} LIMIT 1) AS number
    FROM unnest(${texts(principals)}, ${uuids(principals.map((principal) => logObject('principal', principal)))}) AS m(principal, object)`;
  type Row = StandingRow & {
    retained: string | null; principal: string | null; secret: string | null; project: string | null; environment: string | null; key: string | null; version: number | string | null;
    exposed: boolean | null; wrote: boolean | null; seen_at: string | number | null; changed: string | null; number: string | number | null;
  };
  // The newest retention change, which names the day it dropped (the vault's, sealed in the chain; vault/log-entry.ts):
  // one seek of `log_changes_object_idx`.
  const retention = changesOf('c', RETENTION_OBJECT);
  const retained = sql`(SELECT c.payload FROM log_changes c WHERE ${retention.where} ORDER BY ${retention.order} LIMIT 1) AS retained`;
  const rows = await dialect.rowsOf<Row>(db, principals.length === 0
    ? sql`SELECT st.*, ${retained} FROM (${standingSql()}) st`
    : sql`SELECT st.*, ${retained}, g.* FROM (${standingSql()}) st LEFT JOIN (${keys} UNION ALL ${changed}) g ON TRUE`);
  const newest = new Map<string, bigint>();
  const found: MemberKey[] = [];
  for (const row of rows) {
    if (row.changed != null) {
      if (row.number != null) newest.set(row.changed, BigInt(row.number));
    } else if (row.secret != null) {
      found.push({
        principal: row.principal!, secret: row.secret, project: row.project!, environment: row.environment!, key: row.key!, version: Number(row.version),
        exposed: row.exposed === true, wrote: row.wrote === true, at: row.seen_at === null ? null : Number(row.seen_at),
      });
    }
  }
  return { keys: found, standing: standingOf(rows[0]), newest, readsFrom: keptFrom(rows[0]?.retained ?? null) };
}

/** The log's own object for retention's changes (vault/log-entry.ts, `RETENTION_OBJECT`). */
const RETENTION_OBJECT = logObject('log', 'retention');

/**
 * Where a retention change's drop leaves the reads kept: the start of the day after the one it dropped, ms; null for
 * none. Only retention writes its object (`retentionPayload`: `{"op":"retention","day":"YYYY-MM-DD",…}`), so another
 * payload there is a fault, and the report fails rather than say retention dropped nothing.
 */
function keptFrom(payload: string | null): number | null {
  if (payload === null) return null;
  let parsed: { op?: unknown; day?: unknown } | null = null;
  try {
    parsed = JSON.parse(payload) as { op?: unknown; day?: unknown };
  } catch {}
  const day = parsed?.op === 'retention' && typeof parsed.day === 'string' && /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(parsed.day) ? parsed.day : null;
  const start = day === null ? NaN : Date.parse(`${day}T00:00:00Z`);
  if (Number.isNaN(start)) throw new Error('the newest retention change names no day it dropped: the log was written around the vault');
  return start + 86_400_000;
}
