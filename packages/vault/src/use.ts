import type { Peeked } from '@coffre/core/vault';
import { allows, readsSensitive, useOnly, withinCredential, type Place } from '@coffre/core/access';
import { open } from '@coffre/core/envelope';
import { KekUnavailableError } from '@coffre/core/kek';
import { isUnavailable, rowsOf } from '@coffre/db/dialect';
import type { BindingPolicy, Constraints } from '@coffre/core/identity';
import { bindings, credentials, dismissedKeys, environments, grants, identities, policy, principals, projects, roles, secrets, secretVersions } from '@coffre/db/schema';
import { sql, type SQL } from 'drizzle-orm';

import { callerOf, ID, live, touch, type Caller, type CallerRead, type Workloads } from './caller.ts';
import { bounded, keep, MOST, type Refusal, type Running } from './change.ts';
import { pending } from './entry.ts';
import { fromWire, sealedBy, type Row, type Sealed, type Wire } from './rows.ts';
import { contextOf, natureOf } from './value.ts';

/**
 * A use: anything that opens a value (docs/design/0.16.md, "A use"). A
 * reveal, `coffre run`, an export, a proxied request, a signature.
 *
 * 1. One read: the caller's rows, the environment and its parents, the keys
 *    asked for and what they refer to, each one's current version. A row
 *    whose MAC is not the vault's is not a row.
 * 2. The decision, one function of those rows.
 * 3. The values, opened.
 * 4. One write, for the keys this credential was not logged reading in the
 *    last minute: who has seen which key, the log entry, and the bulk cap,
 *    which refuses it all.
 *
 * It takes no lock and waits on no change: its write touches `exposures`
 * and the log's pending entries, which no change writes and which point at
 * no other table. Within the vault's short memory a repeat is no database
 * call at all: the rows are remembered from when they were read, and
 * decided on again as of now.
 *
 * While the database cannot be reached, a proxied use, and no other, is
 * answered from the rows it was last answered from, for as long as the
 * deployment says (`outageSeconds`, never unless set): `use`, below.
 */

export type Ask = {
  /** The SHA-256 of the token the caller presented. */
  token: Buffer;
  /** The place, by its slugs. */
  project: string;
  environment: string;
  /** The caller's personal config of that environment, `@me`, where they have one. */
  mine: boolean;
  /** The keys asked for, by name, 1,000 at most: null is every key the environment has. */
  keys: readonly string[] | null;
  /** `use`: the value is used for the caller, by the credential proxy, and never handed back. Any other, `reveal` or `run`, hands it back. */
  purpose: string;
  /** The upstream credential the values are used for, by its name in the deployment's configuration: a freeze names it, and a narrowed session's limits. Null for none. */
  upstream: string | null;
  /** The thumbprint of the key that signed the request's proof, which the app held to the request: a workload's session is its key's alone. Null with no proof. */
  proof: string | null;
  /** The app's request, for the log, and the address it came from, which a workload's binding may name. */
  request: string | null;
  ip: string | null;
};

/** One key's value, or why this caller is not given it. `secret` is where the value is held: a reference's source. */
export type Value = { key: string; secret: string; version: number; sensitive: boolean; value: Buffer } | { key: string; refused: string };

export type Answer = {
  principal: string;
  credential: string;
  values: Value[];
  /** For a workload's session, what only the app can hold its request to: an unsigned upload its binding must allow, a narrowed session's methods and paths. */
  workload: { binding: string; profile: string; policy: BindingPolicy; constraints: Constraints | null } | null;
};

/** What a use needs of the vault as it runs, past a change's. */
export type Serving = Running & {
  /** The bulk cap: how many distinct keys one principal is given within the window. */
  cap: { count: number; windowMs: number };
  workloads: Workloads;
  memory: Memory;
};

/** What a read finds, by table. */
const READ = { credential: credentials, principal: principals, identity: identities, grant: grants, role: roles, binding: bindings, ancestor: credentials, policy, project: projects, environment: environments, secret: secrets, dismissed: dismissedKeys, version: secretVersions };
type Seen = { [K in keyof typeof READ]: Row<(typeof READ)[K]>[] };

/**
 * Rows as one read found them, when, and the values opened from them since.
 * `used`: a proxied use was answered from them, and logged, so an outage may
 * be answered from them too.
 */
export type Read = { at: number; seen: Seen; opened: Map<string, Buffer>; used?: boolean };

/**
 * What one isolate remembers between calls. Never across a change of what it
 * read: `reads`, a use's rows, and `callers`, the rows of who a request is,
 * for `seconds` (2 by default, 0 for never), counted from the read, not the
 * answer; `logged`, what it wrote a log entry for in the last minute;
 * `touched`, the credentials whose last use it moved on.
 *
 * For an outage of the database (`use`): `outageSeconds`, how long the rows
 * a proxied use was answered from are kept past `seconds`, to answer it
 * while the database cannot be reached (0 for never); `downAt`, when it last
 * could not be; `unlogged`, by ask, the uses answered since then that were
 * due a log entry, which the next entry written for that ask says.
 */
export type Memory = {
  seconds: number;
  reads: Map<string, Read>;
  callers: Map<string, CallerRead>;
  logged: Map<string, { at: number }>;
  touched: Map<string, { at: number }>;
  outageSeconds: number;
  downAt: number;
  unlogged: Map<string, { at: number; uses: number }>;
};

export const memoryOf = (seconds: number, outageSeconds = 0): Memory => ({ seconds, reads: new Map(), callers: new Map(), logged: new Map(), touched: new Map(), outageSeconds, downAt: -Infinity, unlogged: new Map() });

/** A credential given the same version of a key for the same purpose within the last minute writes no second log entry, wherever it asked. */
const LOGGED_MS = 60_000;
/** Parents an environment may have above it, as in 0.14. */
const MAX_PARENTS = 3;
const shapeOfAsk = (ask: Ask) => JSON.stringify([ask.token.toString('hex'), ask.project, ask.environment, ask.mine, ask.keys]);

/** How long a read's rows are kept, in milliseconds: the memory's length, or an outage's for those a proxied use was answered from. */
const keptMs = (memory: Memory, read: Read) => Math.max(memory.seconds, read.used === true ? memory.outageSeconds : 0) * 1000;

/** The rows this ask read within the vault's memory, if any. */
export function recall(vault: Serving, ask: Ask): Read | undefined {
  const { memory } = vault;
  const read = memory.reads.get(shapeOfAsk(ask));
  const now = vault.now();
  // Fresh only between its read and the memory's length after it: a clock set back makes nothing fresher.
  if (read === undefined || (now >= read.at && now < read.at + memory.seconds * 1000)) return read;
  // Stale: its rows and the values opened from them go now, not when the next read happens to push them out. But for
  // those kept for an outage, which answer nothing while the database does (`use`).
  if (!(now >= read.at && now < read.at + keptMs(memory, read))) memory.reads.delete(shapeOfAsk(ask));
  return undefined;
}


/** A use's one read. */
export async function read(vault: Serving, ask: Ask): Promise<Read> {
  if (ask.token.length !== 32 || (ask.keys?.length ?? 0) > 1000) throw new Error('a use names a token by its SHA-256, and 1,000 keys at most');
  const at = vault.now();
  const keyed = (key: SQL) => (ask.keys === null ? sql`true` : sql`${key} = ANY(${sql.param(ask.keys)}::text[])`);
  // The database's clock is read with the rows so that no pooler answers from a cache: Hyperdrive caches no
  // statement that reads it. Its caching is off in every deployment besides (docs/deploy.md); this holds if one forgets.
  const found = await rowsOf<{ part: keyof Seen; row: Wire }>(vault.db, sql`
    WITH RECURSIVE
      c AS (SELECT * FROM credentials WHERE token_hash = decode(${ask.token.toString('hex')}, 'hex')),
      p AS (SELECT * FROM projects WHERE slug = ${ask.project}),
      base AS (SELECT e.* FROM environments e, p WHERE e.project_id = p.id AND e.slug = ${ask.environment}),
      mine AS (SELECT e.* FROM environments e, base, c WHERE ${ask.mine} AND e.parent_id = base.id AND e.owner = c.principal AND strpos(e.slug, '~') = 0),
      -- UNION, not UNION ALL: a loop someone wrote around the vault ends where it closes.
      chain AS (SELECT * FROM base UNION SELECT * FROM mine UNION SELECT e.* FROM environments e JOIN chain ON e.id = chain.parent_id),
      -- By the project too: the index on secrets leads with it, and an environment's parents are its project's.
      keyed AS (SELECT s.* FROM secrets s WHERE s.project_id = (SELECT id FROM p) AND s.environment_id IN (SELECT id FROM chain) AND ${keyed(sql`s.key`)}),
      held AS (SELECT * FROM keyed UNION SELECT s.* FROM secrets s WHERE s.id IN (SELECT source_id FROM keyed))
    SELECT part, row, clock_timestamp() AS read_at FROM (
    SELECT 'credential' AS part, to_jsonb(c) AS row FROM c
    UNION ALL SELECT 'principal', to_jsonb(t) FROM principals t, c WHERE t.id = c.principal
    UNION ALL SELECT 'identity', to_jsonb(t) FROM identities t, c WHERE t.id = c.identity_id
    UNION ALL SELECT 'grant', to_jsonb(t) FROM grants t, c WHERE t.principal = c.principal
    UNION ALL SELECT 'role', to_jsonb(t) FROM roles t
    -- What a trust binding issued names it, and a narrowed session the sessions above it: each by its id, and only for a row that has them.
    -- Read before its MAC is checked, so only what is shaped like ids is cast: a row someone else wrote is no row, not an error.
    UNION ALL SELECT 'binding', to_jsonb(t) FROM bindings t, c WHERE t.id = CASE WHEN c.created_by ~ '^binding:${ID}$' THEN substr(c.created_by, 9)::uuid END
    -- An array the statement works out once, so each id is one lookup by the key.
    UNION ALL SELECT 'ancestor', to_jsonb(t) FROM credentials t WHERE t.id = ANY(ARRAY(SELECT above.id::uuid FROM c, jsonb_array_elements_text(CASE WHEN c.kind = 'workload' AND c.ancestors ~ '^[[]("${ID}"(,"${ID}")*)?[]]$' THEN c.ancestors::jsonb END) AS above(id)))
    UNION ALL SELECT 'policy', to_jsonb(t) FROM policy t, c WHERE c.kind = 'workload'
    UNION ALL SELECT 'project', to_jsonb(t) FROM projects t WHERE t.id IN (SELECT project_id FROM held UNION ALL SELECT id FROM p)
    UNION ALL SELECT 'environment', to_jsonb(t) FROM environments t WHERE t.id IN (SELECT environment_id FROM held UNION ALL SELECT id FROM chain)
    UNION ALL SELECT 'secret', to_jsonb(t) FROM held t
    UNION ALL SELECT 'dismissed', to_jsonb(t) FROM dismissed_keys t WHERE t.environment_id IN (SELECT id FROM chain) AND t.restored_at IS NULL AND ${keyed(sql`t.key`)}
    UNION ALL SELECT 'version', to_jsonb(t) FROM secret_versions t JOIN held ON t.secret_id = held.id AND t.version = held.current_version) parts`);
  const seen = Object.fromEntries(Object.keys(READ).map((part) => [part, []])) as unknown as Seen;
  for (const { part, row: wire } of found) {
    const table = READ[part];
    const row = fromWire(table, wire);
    // A version carries no MAC: its encryption names what it is.
    if (!('mac' in table) || sealedBy(vault.keys, table as Sealed, row as Row<Sealed>) !== undefined) (seen[part] as object[]).push(row);
  }
  return { at, seen, opened: new Map() };
}

/** A key the caller is given: the secret that holds its value, the one asked for when that is a reference to it, and the version. */
type Given = { key: string; held: Row<typeof secrets>; asked: Row<typeof secrets>; version: Row<typeof secretVersions>; owner: string | null };
type Decided = { caller: Caller; project: Row<typeof projects>; environment: Row<typeof environments>; items: (Given | { key: string; refused: string })[] };

/**
 * The same answer whether the place does not exist, is archived, or is one
 * the caller holds nothing in: none says which.
 */
const NO_ACCESS: Refusal = { refused: 'no_access' };

/**
 * A use's decision, from the rows read and the time, and nothing else.
 * Refused as a whole for who asks or where; key by key past that, so that
 * a `coffre run` is told which keys it is not given, and why.
 */
export function decide(seen: Seen, ask: Ask, workloads: Workloads, at: number): Decided | Refusal {
  const caller = callerOf({ credential: seen.credential, principal: seen.principal, identity: seen.identity, grants: seen.grant, roles: seen.role, environments: seen.environment, binding: seen.binding, ancestors: seen.ancestor, policy: seen.policy }, ask, workloads, at);
  if (caller === null) return { refused: 'unauthenticated' };
  const handed = ask.purpose !== 'use';
  const { workload } = caller;
  // A session that stands and is stopped is told why, before anything about the place: lifting it restores service.
  if (workload?.stop != null) return { refused: workload.stop };
  // A narrowed session uses values, within the places and credentials it was narrowed to, and is handed none.
  const within = (list: readonly string[] | undefined, name: string | null) => list === undefined || (name !== null && list.includes(name));
  if (workload?.narrowed === true && (handed || !within(workload.constraints?.places, `${ask.project}/${ask.environment}${ask.mine ? '@me' : ''}`) || !within(workload.constraints?.credentials, ask.upstream))) return { refused: 'narrowed' };
  const permission = handed ? 'secret.read' : 'secret.use';
  const environment = new Map(seen.environment.map((row) => [row.id, row]));
  const place = (row: Row<typeof environments>): Place => ({ projectId: row.projectId, environmentId: row.id, environmentSlug: row.slug });
  /**
   * Whether the caller reads, or uses, the keys an environment holds: by
   * what they hold there; or, in a personal config, as its owner alone,
   * while they read or use the environment it is a config of, within their
   * credential's scope (docs/design/forking.md, section 4).
   */
  const may = (row: Row<typeof environments>): boolean => {
    if (row.owner === null) return allows(caller.holds, permission, place(row));
    const parent = row.parentId === null ? undefined : environment.get(row.parentId);
    if (row.owner !== caller.principal || parent === undefined || !live(parent)) return false;
    const there = place(parent);
    return (allows(caller.holds, 'secret.use', there) || allows(caller.holds, 'secret.read', there)) && withinCredential(caller.holds, 'secret.use', there);
  };

  const project = seen.project.find((row) => row.slug === ask.project && live(row));
  const base = project && seen.environment.find((row) => row.projectId === project.id && row.slug === ask.environment && live(row));
  if (project === undefined || base === undefined) return NO_ACCESS;
  // `@me` with no config of one's own is the environment itself.
  const first = (ask.mine ? seen.environment.find((row) => row.parentId === base.id && row.owner === caller.principal && live(row)) : undefined) ?? base;
  if (!may(first)) return NO_ACCESS;
  // An upstream credential frozen in this environment is used by nobody, until an Owner of the project lifts it.
  if (ask.upstream !== null && base.frozenCredentials.includes(ask.upstream)) return { refused: 'frozen' };

  // The environment, then what it inherits from, nearest first: a key is the nearest one's.
  const layers = [first];
  for (let last = first; last.parentId !== null; layers.push(last)) {
    const parent = environment.get(last.parentId);
    if (parent === undefined || !live(parent) || parent.projectId !== project.id || layers.length > MAX_PARENTS + (first === base ? 0 : 1)) return { refused: 'broken_chain' };
    last = parent;
  }

  // By id, and the live ones by where they are: a batch is a thousand keys, decided again at every use from memory.
  const secret = new Map(seen.secret.map((row) => [row.id, row]));
  const keyed = new Map(seen.secret.filter((row) => row.archivedAt === null).map((row) => [`${row.environmentId} ${row.key}`, row]));
  const versions = new Map(seen.version.map((row) => [`${row.secretId} ${row.version}`, row]));
  const dismissed = new Set(seen.dismissed.filter((row) => row.restoredAt === null).map((row) => `${row.environmentId} ${row.key}`));
  const given = (key: string, asked: Row<typeof secrets>, layer: Row<typeof environments>): Decided['items'][number] => {
    // An inherited key is read where it is: the fork's reader reads its parent too, or is not given it.
    if (!may(layer)) return { key, refused: 'parent_unreadable' };
    let held = asked;
    if (asked.sourceId !== null) {
      // A reference takes its value and nature from its source, and its permissions from where it lives. Never through
      // another reference, nor into or out of a personal config, whose values are their owner's alone.
      const source = secret.get(asked.sourceId);
      const where = source && environment.get(source.environmentId);
      const whose = source && seen.project.find((row) => row.id === source.projectId);
      if (source === undefined || source.archivedAt !== null || source.sourceId !== null || layer.owner !== null) return { key, refused: 'unreadable' };
      if (where === undefined || !live(where) || where.owner !== null || whose === undefined || !live(whose)) return { key, refused: 'unreadable' };
      held = source;
    }
    if (held.currentVersion === null) return { key, refused: held === asked ? 'no_value' : 'unreadable' };
    const version = versions.get(`${held.id} ${held.currentVersion}`);
    // A version labelled other than its secret's row says is no value of it: it may open as its label says, but is not given.
    if (version === undefined || natureOf(version) !== held.nature) return { key, refused: 'unreadable' };
    // A workload is handed only what its credential lists where the value is held, and a person no sensitive value, ever;
    // a service account one, on a credential an Owner of the value's project issued.
    // A plain value is no secret, use-only to nobody: and it opens as plain, or not at all (`answer`).
    if (handed && version.plaintext === null && useOnly(caller.holds, { projectId: held.projectId, environmentId: held.environmentId, secretId: held.id })) return { key, refused: 'use_only' };
    if (handed && version.sensitive && caller.holds.service !== true) return { key, refused: 'sensitive' };
    if (handed && version.sensitive && !readsSensitive(caller.holds, held.projectId)) return { key, refused: 'not_owner_issued' };
    // A value held in a personal config is read there alone: a reference's source is in none.
    return { key, held, asked, version, owner: asked === held ? layer.owner : null };
  };
  const resolve = (key: string): Decided['items'][number] => {
    for (const layer of layers) {
      const asked = keyed.get(`${layer.id} ${key}`);
      if (asked !== undefined) return given(key, asked, layer);
      // A fork that dismissed a key has none, whatever its parents hold.
      if (dismissed.has(`${layer.id} ${key}`)) break;
    }
    return { key, refused: 'unknown_key' };
  };
  const every = () => [...new Set(seen.secret.filter((row) => row.archivedAt === null && layers.some((layer) => layer.id === row.environmentId)).map((row) => row.key))].sort();
  const items = ask.keys === null ? every().map(resolve).filter((item) => !('refused' in item) || item.refused !== 'unknown_key') : ask.keys.map(resolve);
  return { caller, project, environment: first, items };
}

/**
 * A use's answer from rows read: the decision as of now, the values, and
 * the one write. A refusal writes nothing, the log included. `down`, the
 * database cannot be reached (`use`): the same decision and values, and no
 * write; a use that was due a log entry is counted instead (`unlogged`).
 */
export async function answer(vault: Serving, ask: Ask, found: Read, down = false): Promise<Answer | Refusal> {
  const at = vault.now();
  const { memory } = vault;
  const shape = shapeOfAsk(ask);
  const decided = decide(found.seen, ask, vault.workloads, at);
  if ('refused' in decided) {
    // Not remembered: the next use reads again, and is given what has changed since.
    memory.reads.delete(shape);
    return decided;
  }
  const { caller, project, environment } = decided;

  const values: Value[] = [];
  const read: Given[] = [];
  for (const item of decided.items) {
    if ('refused' in item) {
      values.push(item);
      continue;
    }
    const { held, version } = item;
    let value = found.opened.get(version.id);
    try {
      // As its rows say it is: a version relabelled, plain or not sensitive, to be handed to someone else, does not open.
      value ??= await open(version, contextOf(held, version, item.owner), vault.keks);
    } catch (error) {
      // A key service that cannot answer is an outage. Anything else is a row that is not what it says: moved, relabelled, erased.
      if (error instanceof KekUnavailableError) throw error;
      values.push({ key: item.key, refused: 'unreadable' });
      continue;
    }
    found.opened.set(version.id, value);
    // A copy: the caller may wipe what it is given, and the memory answers the next use from its own.
    values.push({ key: item.key, secret: held.id, version: version.version, sensitive: version.sensitive, value: Buffer.from(value) });
    read.push(item);
  }

  // What this credential has not been logged reading in the last minute.
  const mark = ({ held, version }: Given) => `${caller.credential.id} ${ask.purpose} ${held.id} ${version.version}`;
  const fresh = read.filter((item) => (memory.logged.get(mark(item))?.at ?? -Infinity) + LOGGED_MS <= at);
  const { workload } = caller;
  const answered: Answer = { principal: caller.principal, credential: caller.credential.id, values, workload: workload && { binding: workload.binding.id, profile: workload.binding.profile, policy: workload.policy, constraints: workload.constraints } };
  if (down) {
    // Nowhere to write it: counted from the first one, for the entry the next use writes once the database answers.
    const missed = memory.unlogged.get(shape);
    if (fresh.length > 0) keep(memory.unlogged, shape, { at: missed?.at ?? at, uses: (missed?.uses ?? 0) + 1 }, -Infinity);
    return answered;
  }
  if (fresh.length > 0) {
    const ids = [...new Set(fresh.map((item) => item.held.id))];
    // Dated now, as its write is sent, not when the use was decided: opening its values, through a key service, takes as long as it takes.
    const written = vault.now();
    const unlogged = memory.unlogged.get(shape);
    const entry = pending(vault.keys[0]!, {
      kept: false,
      action: 'secret.read',
      actor: caller.principal,
      credential: caller.credential.id,
      request: ask.request,
      ip: ask.ip,
      objects: [...new Set([`project:${project.id}`, `environment:${environment.id}`, `principal:${caller.principal}`, `credential:${caller.credential.id}`, ...fresh.flatMap((item) => [`secret:${item.held.id}`, `secret:${item.asked.id}`])])],
      // After an outage, the uses of this ask that no entry says: since when, and how many (`use`).
      detail: { purpose: ask.purpose, ...(ask.upstream === null ? {} : { credential: ask.upstream }), ...(unlogged === undefined ? {} : { unlogged: { since: new Date(unlogged.at).toISOString(), uses: unlogged.uses } }), keys: fresh.map(({ key, held, asked, version }) => ({ key, secret: held.id, version: version.version, ...(asked === held ? {} : { through: asked.id }) })) },
    }, written, []);
    const time = sql`${new Date(written).toISOString()}::timestamptz`;
    const since = sql`${new Date(written - vault.cap.windowMs).toISOString()}::timestamptz`;
    // The cap counts the keys this principal was given in the window, these among them. Uses side by side each count
    // without the other's, so it can be overshot by what is in flight (D217). The rows are written in one order,
    // `ORDER BY id`, by every use: two that write the same ones wait in line, never on each other.
    const [{ ok }] = await bounded<{ ok: boolean }>(vault.db, sql`
      WITH ids AS (SELECT id FROM unnest(${sql.param(ids)}::uuid[]) AS id),
        cap AS (SELECT (SELECT count(*) FROM exposures WHERE principal = ${caller.principal} AND seen_at > ${since} AND secret_id NOT IN (SELECT id FROM ids)) + ${ids.length} <= ${vault.cap.count} AS ok),
        seen AS (INSERT INTO exposures (principal, secret_id, seen_at) SELECT ${caller.principal}, id, ${time} FROM ids, cap WHERE cap.ok ORDER BY id ON CONFLICT (principal, secret_id) DO UPDATE SET seen_at = greatest(exposures.seen_at, excluded.seen_at)),
        entry AS (INSERT INTO log_pending (kept, body, mac) SELECT ${entry.kept}, ${entry.body}, decode(${entry.mac.toString('hex')}, 'hex') FROM cap WHERE cap.ok)
      SELECT ok FROM cap`) as [{ ok: boolean }];
    if (!ok) return { refused: 'bulk_limit' };
    vault.wake(entry.hash);
    if (unlogged !== undefined) memory.unlogged.delete(shape);
    // Remembered by the entry's own date: the minute a use is logged once in starts there.
    for (const item of fresh) memory.logged.set(mark(item), { at: written });
    keep(memory.logged, mark(fresh[0]!), { at: written }, at - LOGGED_MS);
  }

  await touch(vault, caller.credential, ask.ip, at);
  // Answered and logged as a proxied use: what an outage may be answered from.
  if (ask.purpose === 'use') found.used = true;
  remember(memory, ask, found, at);
  return answered;
}

/**
 * A read's rows kept for as long as they may answer (`keptMs`), unless a
 * newer read of the same is there already: a slow use does not put its
 * older rows back over it. What has outlasted its own length goes, and past
 * `MOST` reads the ones that came first.
 */
function remember(memory: Memory, ask: Ask, found: Read, at: number): void {
  const shape = shapeOfAsk(ask);
  if (keptMs(memory, found) === 0 || (memory.reads.get(shape)?.at ?? -Infinity) > found.at) return;
  memory.reads.delete(shape);
  memory.reads.set(shape, found);
  for (const [old, read] of memory.reads) if (read.at + keptMs(memory, read) <= at || memory.reads.size > MOST) memory.reads.delete(old);
}

/**
 * What a use would be given, as of now, without it: each key's secret and
 * version, or why it is refused, as `answer` would say (docs/design/0.16.md,
 * "Pages"). It opens nothing and writes nothing: no log entry, no exposure,
 * no credential's last use. Its rows are remembered as a use's are, so a
 * reveal just after reads nothing again. A value whose row says it is
 * there but does not open is the one thing it cannot tell: the use refuses
 * it `unreadable`.
 */
export async function peek(vault: Serving, ask: Ask): Promise<Peeked | Refusal> {
  const found = recall(vault, ask) ?? (await read(vault, ask));
  const at = vault.now();
  const decided = decide(found.seen, ask, vault.workloads, at);
  if ('refused' in decided) {
    vault.memory.reads.delete(shapeOfAsk(ask));
    return decided;
  }
  remember(vault.memory, ask, found, at);
  const items = decided.items.map((item) => ('refused' in item ? item : { key: item.key, secret: item.held.id, version: item.version.version }));
  return { principal: decided.caller.principal, credential: decided.caller.credential.id, items };
}

/**
 * A use: from memory while it is fresh, else one read.
 *
 * While the database cannot be reached (`isUnavailable`: no connection, or
 * a statement that gave up waiting), a proxied use is answered all the
 * same, where the deployment set `outageSeconds`: from the rows this ask
 * was last answered from as a proxied use, for that long after they were
 * read. So it is given what it was given before, and nothing else: the same
 * credential, keys and versions, never handed back. The decision is made
 * again as of now, so a credential that expires in the outage stops. What
 * it cannot see is a change the rows do not hold: one made after they were
 * read, in the memory's length before the outage, or made through another
 * instance that still reaches the database. Any other use fails with the
 * database, as does every change.
 *
 * The failure is remembered for the memory's length (`downAt`): the uses in
 * it are answered at once, and the first one after asks the database again.
 */
export async function use(vault: Serving, ask: Ask): Promise<Answer | Refusal> {
  const { memory } = vault;
  let found = recall(vault, ask);
  // After `recall`, what is kept is fresh, or kept for an outage alone.
  const kept = memory.reads.get(shapeOfAsk(ask));
  const spare = memory.outageSeconds > 0 && ask.purpose === 'use' && kept?.used === true ? kept : undefined;
  const now = vault.now();
  if (spare !== undefined && now >= memory.downAt && now < memory.downAt + memory.seconds * 1000) return answer(vault, ask, spare, true);
  try {
    if (found === undefined) {
      found = await read(vault, ask);
      memory.downAt = -Infinity;
    }
    return await answer(vault, ask, found);
  } catch (error) {
    if (spare === undefined || !isUnavailable(error)) throw error;
    memory.downAt = vault.now();
    // The rows just read, when it is the write that failed: the newest there are.
    return answer(vault, ask, found ?? spare, true);
  }
}
