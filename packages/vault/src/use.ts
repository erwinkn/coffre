import { allows, readsSensitive, useOnly, withinCredential, type Place } from '@coffre/core/access';
import { open, ownerKey } from '@coffre/core/envelope';
import { KekUnavailableError, type KekRegistry } from '@coffre/core/kek';
import { rowsOf } from '@coffre/db/dialect';
import { credentials, dismissedKeys, environments, grants, identities, principals, projects, roles, secrets, secretVersions } from '@coffre/db/schema';
import { sql, type SQL } from 'drizzle-orm';

import { callerOf, type Caller } from './caller.ts';
import type { Refusal, Running } from './change.ts';
import { pending } from './entry.ts';
import { fromWire, sealedBy, type Row, type Sealed, type Wire } from './rows.ts';

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
 * It takes no lock. Within the vault's short memory a repeat is no database
 * call at all: the rows are remembered from when they were read, and
 * decided on again as of now.
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
  /** The app's request, for the log. */
  request: string | null;
  ip: string | null;
};

/** One key's value, or why this caller is not given it. `secret` is where the value is held: a reference's source. */
export type Value = { key: string; secret: string; version: number; sensitive: boolean; value: Buffer } | { key: string; refused: string };

export type Answer = { principal: string; credential: string; values: Value[] };

/** What a use needs of the vault as it runs, past a change's. */
export type Serving = Running & {
  keks: KekRegistry;
  /** The bulk cap: how many distinct keys one principal is given within the window. */
  cap: { count: number; windowMs: number };
  memory: Memory;
};

/** What a read finds, by table. */
const READ = { credential: credentials, principal: principals, identity: identities, grant: grants, role: roles, project: projects, environment: environments, secret: secrets, dismissed: dismissedKeys, version: secretVersions };
type Seen = { [K in keyof typeof READ]: Row<(typeof READ)[K]>[] };

/** Rows as one read found them, when, and the values opened from them since. */
export type Read = { at: number; seen: Seen; opened: Map<string, Buffer> };

/**
 * What one isolate remembers between uses. Never across a change of what it
 * read: `reads` for `seconds` (2 by default, 0 for never), counted from the
 * read, not the answer; `logged`, what it wrote a log entry for in the last
 * minute; `touched`, the credentials whose last use it moved on.
 */
export type Memory = { seconds: number; reads: Map<string, Read>; logged: Map<string, { at: number }>; touched: Map<string, { at: number }> };

export const memoryOf = (seconds: number): Memory => ({ seconds, reads: new Map(), logged: new Map(), touched: new Map() });

/** A read of the same credential, place and keys within the last minute writes no second log entry. */
const LOGGED_MS = 60_000;
/** A credential's last use is moved on at most this often. */
const TOUCHED_MS = 5 * 60_000;
/** Parents an environment may have above it, as in 0.14. */
const MAX_PARENTS = 3;
/** The most a memory's map holds, whatever the rate: past it, the oldest go. */
const MOST = 1000;

/** Remember `value`, and forget what is older than `since`: a map keeps its entries in the order they came. */
function keep<V extends { at: number }>(map: Map<string, V>, key: string, value: V, since: number): void {
  map.delete(key);
  map.set(key, value);
  for (const [old, { at }] of map) {
    if (at >= since && map.size <= MOST) break;
    map.delete(old);
  }
}

const shapeOfAsk = (ask: Ask) => JSON.stringify([ask.token.toString('hex'), ask.project, ask.environment, ask.mine, ask.keys]);

/** The rows this ask read within the vault's memory, if any. */
export function recall(vault: Serving, ask: Ask): Read | undefined {
  const read = vault.memory.reads.get(shapeOfAsk(ask));
  return read !== undefined && vault.now() < read.at + vault.memory.seconds * 1000 ? read : undefined;
}

/** A use's one read. */
export async function read(vault: Serving, ask: Ask): Promise<Read> {
  if (ask.token.length !== 32 || (ask.keys?.length ?? 0) > 1000) throw new Error('a use names a token by its SHA-256, and 1,000 keys at most');
  const at = vault.now();
  const keyed = (key: SQL) => (ask.keys === null ? sql`true` : sql`${key} = ANY(${sql.param(ask.keys)}::text[])`);
  const found = await rowsOf<{ part: keyof Seen; row: Wire }>(vault.db, sql`
    WITH RECURSIVE
      c AS (SELECT * FROM credentials WHERE token_hash = decode(${ask.token.toString('hex')}, 'hex')),
      p AS (SELECT * FROM projects WHERE slug = ${ask.project}),
      base AS (SELECT e.* FROM environments e, p WHERE e.project_id = p.id AND e.slug = ${ask.environment}),
      mine AS (SELECT e.* FROM environments e, base, c WHERE ${ask.mine} AND e.parent_id = base.id AND e.owner = c.principal AND strpos(e.slug, '~') = 0),
      -- UNION, not UNION ALL: a loop someone wrote around the vault ends where it closes.
      chain AS (SELECT * FROM base UNION SELECT * FROM mine UNION SELECT e.* FROM environments e JOIN chain ON e.id = chain.parent_id),
      keyed AS (SELECT s.* FROM secrets s WHERE s.environment_id IN (SELECT id FROM chain) AND ${keyed(sql`s.key`)}),
      held AS (SELECT * FROM keyed UNION SELECT s.* FROM secrets s WHERE s.id IN (SELECT source_id FROM keyed))
    SELECT 'credential' AS part, to_jsonb(c) AS row FROM c
    UNION ALL SELECT 'principal', to_jsonb(t) FROM principals t, c WHERE t.id = c.principal
    UNION ALL SELECT 'identity', to_jsonb(t) FROM identities t, c WHERE t.id = c.identity_id
    UNION ALL SELECT 'grant', to_jsonb(t) FROM grants t, c WHERE t.principal = c.principal
    UNION ALL SELECT 'role', to_jsonb(t) FROM roles t
    UNION ALL SELECT 'project', to_jsonb(t) FROM projects t WHERE t.id IN (SELECT project_id FROM held UNION ALL SELECT id FROM p)
    UNION ALL SELECT 'environment', to_jsonb(t) FROM environments t WHERE t.id IN (SELECT environment_id FROM held UNION ALL SELECT id FROM chain)
    UNION ALL SELECT 'secret', to_jsonb(t) FROM held t
    UNION ALL SELECT 'dismissed', to_jsonb(t) FROM dismissed_keys t WHERE t.environment_id IN (SELECT id FROM chain) AND t.restored_at IS NULL AND ${keyed(sql`t.key`)}
    UNION ALL SELECT 'version', to_jsonb(t) FROM secret_versions t JOIN held ON t.secret_id = held.id AND t.version = held.current_version`);
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

/** A place that is there: not archived, and not the tombstone a deletion leaves. */
const live = (row: { slug: string; archivedAt: Date | null }) => row.archivedAt === null && !row.slug.includes('~');

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
export function decide(seen: Seen, ask: Ask, at: number): Decided | Refusal {
  const caller = callerOf({ credential: seen.credential, principal: seen.principal, identity: seen.identity, grants: seen.grant, roles: seen.role, environments: seen.environment }, at);
  if (caller === null) return { refused: 'unauthenticated' };
  const handed = ask.purpose !== 'use';
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

  // The environment, then what it inherits from, nearest first: a key is the nearest one's.
  const layers = [first];
  for (let last = first; last.parentId !== null; layers.push(last)) {
    const parent = environment.get(last.parentId);
    if (parent === undefined || !live(parent) || parent.projectId !== project.id || layers.length > MAX_PARENTS + (first === base ? 0 : 1)) return { refused: 'broken_chain' };
    last = parent;
  }

  const given = (key: string, asked: Row<typeof secrets>, layer: Row<typeof environments>): Decided['items'][number] => {
    // An inherited key is read where it is: the fork's reader reads its parent too, or is not given it.
    if (!may(layer)) return { key, refused: 'parent_unreadable' };
    let held = asked;
    if (asked.sourceId !== null) {
      // A reference takes its value and nature from its source, and its permissions from where it lives. Never through
      // another reference, nor into or out of a personal config, whose values are their owner's alone.
      const source = seen.secret.find((row) => row.id === asked.sourceId);
      const where = source && environment.get(source.environmentId);
      const whose = source && seen.project.find((row) => row.id === source.projectId);
      if (source === undefined || source.archivedAt !== null || source.sourceId !== null || layer.owner !== null) return { key, refused: 'unreadable' };
      if (where === undefined || !live(where) || where.owner !== null || whose === undefined || !live(whose)) return { key, refused: 'unreadable' };
      held = source;
    }
    if (held.currentVersion === null) return { key, refused: held === asked ? 'no_value' : 'unreadable' };
    const version = seen.version.find((row) => row.secretId === held.id && row.version === held.currentVersion);
    if (version === undefined) return { key, refused: 'unreadable' };
    // A workload is handed only what its credential lists where the value is held, and a person no sensitive value, ever;
    // a service account one, on a credential an Owner of the value's project issued.
    if (handed && useOnly(caller.holds, { projectId: held.projectId, environmentId: held.environmentId, secretId: held.id })) return { key, refused: 'use_only' };
    if (handed && version.sensitive && caller.holds.service !== true) return { key, refused: 'sensitive' };
    if (handed && version.sensitive && !readsSensitive(caller.holds, held.projectId)) return { key, refused: 'not_owner_issued' };
    return { key, held, asked, version, owner: environment.get(held.environmentId)?.owner ?? null };
  };
  const inLayer = (layer: Row<typeof environments>, key: string) => seen.secret.find((row) => row.environmentId === layer.id && row.key === key && row.archivedAt === null);
  const resolve = (key: string): Decided['items'][number] => {
    for (const layer of layers) {
      const asked = inLayer(layer, key);
      if (asked !== undefined) return given(key, asked, layer);
      // A fork that dismissed a key has none, whatever its parents hold.
      if (seen.dismissed.some((row) => row.environmentId === layer.id && row.key === key)) break;
    }
    return { key, refused: 'unknown_key' };
  };
  const every = () => [...new Set(seen.secret.filter((row) => row.archivedAt === null && layers.some((layer) => layer.id === row.environmentId)).map((row) => row.key))].sort();
  const items = ask.keys === null ? every().map(resolve).filter((item) => !('refused' in item) || item.refused !== 'unknown_key') : ask.keys.map(resolve);
  return { caller, project, environment: first, items };
}

/**
 * A use's answer from rows read: the decision as of now, the values, and
 * the one write. A refusal writes nothing, the log included.
 */
export async function answer(vault: Serving, ask: Ask, found: Read): Promise<Answer | Refusal> {
  const at = vault.now();
  const { memory } = vault;
  const decided = decide(found.seen, ask, at);
  if ('refused' in decided) {
    // Not remembered: the next use reads again, and is given what has changed since.
    memory.reads.delete(shapeOfAsk(ask));
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
      const nature = version.sensitive ? { sensitive: true as const } : version.plaintext !== null ? { plain: true as const } : {};
      value ??= await open(version, { projectId: held.projectId, environmentId: held.environmentId, secretId: held.id, version: version.version, ...(item.owner === null ? {} : { owner: ownerKey(item.owner) }), ...nature }, vault.keks);
    } catch (error) {
      // A key service that cannot answer is an outage. Anything else is a row that is not what it says: moved, relabelled, erased.
      if (error instanceof KekUnavailableError) throw error;
      values.push({ key: item.key, refused: 'unreadable' });
      continue;
    }
    found.opened.set(version.id, value);
    values.push({ key: item.key, secret: held.id, version: version.version, sensitive: version.sensitive, value });
    read.push(item);
  }

  // What this credential has not been logged reading in the last minute, in one order for every use: two that write the same rows lock them in the same order.
  const mark = ({ held, version }: Given) => `${caller.credential.id} ${ask.purpose} ${held.id} ${version.version}`;
  const fresh = read.filter((item) => (memory.logged.get(mark(item))?.at ?? -Infinity) + LOGGED_MS <= at).sort((a, b) => (a.held.id < b.held.id ? -1 : 1));
  if (fresh.length > 0) {
    const ids = [...new Set(fresh.map((item) => item.held.id))];
    const entry = pending(vault.keys[0]!, {
      kept: false,
      action: 'secret.read',
      actor: caller.principal,
      credential: caller.credential.id,
      request: ask.request,
      ip: ask.ip,
      objects: [...new Set([`project:${project.id}`, `environment:${environment.id}`, `principal:${caller.principal}`, `credential:${caller.credential.id}`, ...fresh.flatMap((item) => [`secret:${item.held.id}`, `secret:${item.asked.id}`])])],
      detail: { purpose: ask.purpose, keys: fresh.map(({ key, held, asked, version }) => ({ key, secret: held.id, version: version.version, ...(asked === held ? {} : { through: asked.id }) })) },
    }, at, []);
    const time = sql`${new Date(at).toISOString()}::timestamptz`;
    const since = sql`${new Date(at - vault.cap.windowMs).toISOString()}::timestamptz`;
    // The cap counts the keys this principal was given in the window, these among them. Uses side by side each count
    // without the other's, so it can be overshot by what is in flight (D217).
    const [{ ok }] = await rowsOf<{ ok: boolean }>(vault.db, sql`
      WITH ids AS (SELECT id FROM unnest(${sql.param(ids)}::uuid[]) AS id),
        cap AS (SELECT (SELECT count(*) FROM exposures WHERE principal = ${caller.principal} AND seen_at > ${since} AND secret_id NOT IN (SELECT id FROM ids)) + ${ids.length} <= ${vault.cap.count} AS ok),
        seen AS (INSERT INTO exposures (principal, secret_id, seen_at) SELECT ${caller.principal}, id, ${time} FROM ids, cap WHERE cap.ok ORDER BY id ON CONFLICT (principal, secret_id) DO UPDATE SET seen_at = excluded.seen_at),
        entry AS (INSERT INTO log_pending (kept, body, mac) SELECT ${entry.kept}, ${entry.body}, decode(${entry.mac.toString('hex')}, 'hex') FROM cap WHERE cap.ok)
      SELECT ok FROM cap`) as [{ ok: boolean }];
    if (!ok) return { refused: 'bulk_limit' };
    vault.wake(entry.hash);
    for (const item of fresh) keep(memory.logged, mark(item), { at }, at - LOGGED_MS);
  }

  // When the credential was last used: its row's own statement, since it shares one with nothing a change may lock.
  const { id, lastUsedAt } = caller.credential;
  if (Math.max(lastUsedAt?.getTime() ?? -Infinity, memory.touched.get(id)?.at ?? -Infinity) + TOUCHED_MS <= at) {
    await vault.db.execute(sql`UPDATE credentials SET last_used_at = ${new Date(at).toISOString()}::timestamptz, last_used_ip = ${ask.ip} WHERE id = ${id}`);
    keep(memory.touched, id, { at }, at - TOUCHED_MS);
  }
  if (memory.seconds > 0) keep(memory.reads, shapeOfAsk(ask), found, at - memory.seconds * 1000);
  return { principal: caller.principal, credential: id, values };
}

/** A use: from memory while it is fresh, else one read. */
export async function use(vault: Serving, ask: Ask): Promise<Answer | Refusal> {
  return answer(vault, ask, recall(vault, ask) ?? (await read(vault, ask)));
}
