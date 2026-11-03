
import { personalOf } from '@coffre/core/schemas';
import { ACCESS_ACTIONS } from '@coffre/core/vault';
import type { Database, Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql, type SQL } from 'drizzle-orm';

import { periodOf, refreshMs, USE_AHEAD_MS, USE_DEADLINE_MS } from './bulk.ts';
import { namedStanding } from './decide.ts';
import { noEdits, objectKey, type Kind, type RolesInput } from './inputs.ts';
import { purposeOf, WAYS } from './log-replay.ts';
import { configObject, credentialObject, environmentObject, memberStanding, principalObject } from './objects.ts';
import type { ChangeColumns, Cover, EditorRow, NamedAhead, NamedBatchCall, NamedBatchRows, ResolvedRow, RouteCall, RouteLevelRow, RouteRows, UseCall, UseRow } from './use.ts';

/**
 * `use_credential` (0024's, as 0046 has it) on SQLite, for tests and local development
 * (docs/design/0.15-plan.md, "Postgres serves; SQLite is for tests"): the
 * same reads and writes, the same row, in one transaction. SQLite runs one
 * writer at a time (`BEGIN IMMEDIATE`, @coffre/db/connect), so the fence and
 * the principal's lock are implicit, and no number is taken out of order.
 * It has no sequence: an entry's number is one past the log's highest.
 */
export async function callUse(db: Queryable, call: UseCall): Promise<UseRow> {
  return (db as Database).transaction((tx) => useOnce(tx, call, direct(tx)));
}

/**
 * `use_batch` (0048) on SQLite: each key's use as `callUse` makes it, in order, in one transaction. Its one writer at a
 * time makes the principal's lock, the batch's `lock`, implicit too.
 *
 * Each key is decided as `useOnce` decides it, on rows read for all the keys at once (`Batched`): what every key reads
 * alike once, each key's own rows in a few statements of all their ids, and the principal's cap rows once, counted in
 * memory as the keys before it enter them. Its entries and cap rows are written together, last. A thousand keys are
 * then some 30 statements where they were 30,000 (W281), and none counts the cap's set again.
 */
export async function callBatch(db: Queryable, calls: readonly UseCall[], _lock: string | null): Promise<UseRow[]> {
  return (db as Database).transaction(async (tx) => {
    const batched = await Batched.read(tx, calls);
    const rows: UseRow[] = [];
    for (const call of calls) rows.push(await useOnce(tx, call, batched));
    await batched.write();
    // Past the deadline once written, as each key's use is past it at its end: the whole batch rolls back.
    if (rows.some((row) => row.state === null) && Date.now() > calls[0]!.deadline) throw Object.assign(new Error('past its deadline'), { code: '57014' });
    return rows;
  });
}

/**
 * `use_named_batch` (0055) on SQLite: in one transaction, the gate's named call with no key, then, for one who stands
 * there, its chain whole, each key as Postgres's makes it: the keys `calls` name, or, `calls` null, every key the place
 * holds (`listed`), at most `limit`; a key with a sealed value of its own by the ids its call has when they are its
 * name's now (a use by ids, on rows read for them all as `callBatch` reads them), or else by none, left to the vault's
 * batch by ids; any other key by its name alone.
 */
export async function callNamedBatch(db: Queryable, gate: UseCall, calls: readonly NamedBatchCall[] | null, limit: number): Promise<NamedBatchRows> {
  if (gate.names === undefined || gate.credential !== null || gate.names.key !== null) throw new Error("a named batch's gate reads by its names alone, with no key");
  return (db as Database).transaction(async (tx) => {
    const rows = direct(tx);
    const opened = await useOnce(tx, gate, rows);
    const none = { gate: opened, keys: null, rows: [], byIds: [], aheads: [] };
    if (opened.state !== 'moved' || opened.n_standing !== true || opened.n_cut !== false) return none;
    const place = opened.n_place!;
    const [at] = await rowsOf<{ project_id: string; parent_id: string | null }>(tx, sql`SELECT project_id, parent_id FROM environments WHERE id = ${place}`);
    const { layers, cut } = at === undefined ? { layers: [], cut: true } : await chainOf(tx, place, at.parent_id);
    // Cut: no names listed, as for a refused gate, never the empty list of a place that holds no key.
    if (cut) return none;
    const names = calls === null ? await listed(tx, at!.project_id, layers) : calls.map(({ key }) => key);
    const asked = names.slice(0, limit);
    // Each key's name first, then: a sealed key of its own, by the ids its call has when they are the name's now, on
    // rows read for all those keys at once (`Batched`, as `callBatch` reads them), or, without them, no call, left to
    // the vault's batch by ids (its row null); any other key by its name alone, which writes nothing.
    const found: (Awaited<ReturnType<typeof resolved>>)[] = [];
    for (const key of asked) found.push(await resolved(tx, at!.project_id, layers, key));
    const byIds = asked.map((_, i) => {
      const held = found[i]!;
      const call = calls?.[i]?.call;
      return held !== null && held.sealed && call !== undefined && call.names === undefined && call.credential === opened.n_credential
        && call.secretId === held.id && call.place === (held.holder === place ? null : place);
    });
    const used = calls === null ? [] : calls.filter((_, i) => byIds[i]).map(({ call }) => call);
    const batched = used.length === 0 ? null : await Batched.read(tx, used);
    const out: (UseRow | null)[] = [];
    const aheads: (NamedAhead | null)[] = [];
    for (const [i, key] of asked.entries()) {
      const held = found[i]!;
      if (byIds[i]) out.push(await useOnce(tx, calls![i]!.call, batched!));
      else if (held?.sealed === true) out.push(null);
      else out.push(await useOnce(tx, { ...gate, names: { ...gate.names!, key } }, rows));
      aheads.push(held?.sealed !== true ? null : {
        id: held.id, sensitive: held.sensitive, secret: null, version: null, held: held.holder === place ? null : { environmentId: held.holder, slug: held.slug },
      });
    }
    await batched?.write();
    // Past the deadline once written, as `callBatch`'s: the whole statement rolls back.
    if (out.some((row, i) => byIds[i] && row!.state === null) && Date.now() > gate.deadline) throw Object.assign(new Error('past its deadline'), { code: '57014' });
    return { gate: opened, keys: calls === null ? names : null, rows: out, byIds, aheads };
  });
}

/**
 * `use_route` (0058) on SQLite: in one transaction, as Postgres's makes it: the reading, the gate (a handle's named call
 * with no key, or a workload's quiet use of no key at its place), the place's chain, each level's proxy row through the
 * first that holds the route's item, the item's editor's principal, the item's keys resolved by name, and, when the
 * call's ids are the names' now at its reading, each key's use by them (a call with no request id only checked).
 */
export async function callRoute(db: Queryable, call: RouteCall): Promise<RouteRows> {
  return (db as Database).transaction(async (tx) => {
    const one = async <T>(query: SQL): Promise<T | undefined> => (await rowsOf<T>(tx, query))[0];
    const handle = call.tokenHash !== null;
    let madeFor: string[] | null = null;
    let made = false;
    if (handle && call.named !== null) {
      const credential = await one<{ places: string | null }>(sql`SELECT places FROM credentials WHERE token_hash = ${call.tokenHash}`);
      const mine = call.environment!.endsWith('@me');
      const candidate = await one<{ id: string }>(sql`SELECT e.id FROM projects q JOIN environments e ON e.project_id = q.id AND e.slug = ${mine ? call.environment!.slice(0, -3) : call.environment}
        WHERE q.slug = ${call.project} AND q.slug NOT LIKE '%~%' AND e.slug NOT LIKE '%~%'`);
      const places = placesOf(credential?.places ?? null);
      made = candidate !== undefined && places.some((place) => place.environmentId === candidate.id && place.personal === mine);
      madeFor = [];
      for (const place of places) {
        const path = await one<{ path: string }>(sql`SELECT q.slug || '/' || e.slug AS path FROM environments e JOIN projects q ON q.id = e.project_id
          WHERE e.id = ${place.environmentId} AND e.slug NOT LIKE '%~%' AND q.slug NOT LIKE '%~%'`);
        if (path !== undefined) madeFor.push(`${path.path}${place.personal ? '@me' : ''}`);
      }
    }
    const reading: 1 | 2 = call.use ? (handle && call.named !== null && (made || call.stable === null) ? 1 : 2) : call.project !== null ? 1 : 2;
    const route = reading === 1 ? call.named : call.stable;
    const rows = direct(tx);
    const base = { requestId: '0', at: call.at, purpose: call.purpose, mac: call.mac, deadline: call.deadline };
    const gate = handle
      ? await useOnce(tx, {
        ...base, credential: null, secretId: null, place: null, way: 0, principal: null,
        names: {
          tokenHash: call.tokenHash!, project: reading === 1 ? call.project : null, environment: reading === 1 ? call.environment : null, key: null, handle: reading === 2,
          unless: reading === 2 && call.project !== null ? [`${call.project}/${call.environment}`] : [], accepts: call.accepts!, forks: true,
        },
      }, rows)
      : await useOnce(tx, { ...base, credential: call.credential, secretId: null, place: call.place, way: call.way, principal: call.principal, route: route ?? 'every' }, rows);
    const none = { reading, route, madeFor, place: null, project: null, personal: false, cut: false, levels: [], editor: null, keys: [], resolved: [], made: false, rows: [] };
    if (handle ? gate.state !== 'moved' || gate.n_standing !== true || gate.n_cut !== false : gate.state !== null) return { ...none, gate, stood: false };
    const place = handle ? gate.n_place! : call.place!;
    const credential = handle ? gate.n_credential! : call.credential!;
    const at = await one<{ project_id: string; parent_id: string | null; owner: string | null }>(sql`SELECT project_id, parent_id, owner FROM environments WHERE id = ${place}`);
    if (at?.owner != null || (handle && reading === 1 && call.environment!.endsWith('@me'))) return { ...none, gate, stood: true, place, personal: true };
    const { layers, cut } = at === undefined ? { layers: [], cut: true } : await chainOf(tx, place, at.parent_id);
    if (cut) return { ...none, gate, stood: true, place, cut: true };
    const levels: RouteLevelRow[] = [];
    let serving: Record<string, unknown> | null = null;
    let inputs = 0n;
    // Each level's definitions through the first that serves the route (every level's, for every item), and every
    // level's environment, which the keys resolve through whatever level serves (review r2).
    for (const layer of layers) {
      const looking = serving === null;
      const row = looking ? await one<{ items: string; digests: Buffer; seal: Buffer }>(sql`SELECT items, digests, seal FROM proxy_definitions WHERE environment_id = ${layer}`) : undefined;
      // By the column, not the text it is read as, which the alias would sort by.
      const newest = looking ? await one<Changed>(sql`SELECT ${CHANGED} FROM log_changes c
        WHERE c.object = ${objectKey({ kind: 'proxy', id: layer })} ORDER BY c.number DESC LIMIT 1`) : undefined;
      if (newest !== undefined && BigInt(newest.number) > inputs) inputs = BigInt(newest.number);
      let items: unknown;
      try {
        items = row === undefined ? null : JSON.parse(row.items);
      } catch {
        items = null;
      }
      const record = items !== null && typeof items === 'object' && !Array.isArray(items) ? items as Record<string, unknown> : null;
      const item = route === null ? items : record !== null && Object.hasOwn(record, route) ? record[route] ?? null : null;
      // The level's environment, row, seal and newest change, which the vault checks the chain by, link by link.
      const env = await one<EnvironmentRow & { parent_id: string | null }>(sql`SELECT ${ENVIRONMENT} FROM environments e LEFT JOIN projects p ON p.id = e.project_id WHERE e.id = ${layer}`);
      const envNewest = await one<Changed>(sql`SELECT ${CHANGED} FROM log_changes c
        WHERE c.object = ${objectKey({ kind: 'environment', id: layer })} ORDER BY c.number DESC LIMIT 1`);
      if (envNewest !== undefined && BigInt(envNewest.number) > inputs) inputs = BigInt(envNewest.number);
      levels.push({
        environment: layer, row: row !== undefined, item, digests: row === undefined ? null : Buffer.from(row.digests), seal: row === undefined ? null : Buffer.from(row.seal),
        newest: newest?.seal == null ? null : Buffer.from(newest.seal), number: newest?.number ?? null, change: columnsOf(newest) ?? null,
        env: env === undefined ? null : {
          project: env.project_id, slug: env.slug, owner: env.owner, parent: env.parent_id, protected: env.protected === null ? null : Boolean(env.protected),
          archived: Boolean(env.archived), project_archived: Boolean(env.project_archived), seal: env.seal == null ? null : Buffer.from(env.seal),
          last: envNewest?.seal == null ? null : Buffer.from(envNewest.seal), change: columnsOf(envNewest) ?? null,
        },
      });
      if (looking && route !== null && item !== null) serving = typeof item === 'object' && !Array.isArray(item) ? item as Record<string, unknown> : {};
    }
    if (serving === null) return { ...none, gate, stood: true, place, project: at!.project_id, levels };
    let editor: EditorRow | null = null;
    if (typeof serving.savedBy === 'string') {
      const principal = serving.savedBy;
      const member = await one<{ status: string; owner: number; role: string | null; scope: string | null; generation: number; seal: Buffer | null }>(sql`SELECT status, owner, role, scope, generation, seal
        FROM vault_members WHERE principal = ${principal}`);
      const grants = member === undefined ? [] : await rowsOf<{ project_id: string | null; environment_id: string | null; environment_slug: string | null; role: string; expires_at: number | null }>(tx, sql`SELECT
        coalesce(g.project_id, e.project_id) AS project_id, g.environment_id, g.environment_slug, g.role, g.expires_at
        FROM vault_grants g LEFT JOIN environments e ON e.id = g.environment_id WHERE g.principal = ${principal}`);
      const last = await one<Changed>(sql`SELECT ${CHANGED} FROM log_changes c
        WHERE c.object = ${objectKey({ kind: 'principal', id: principal })} ORDER BY c.number DESC LIMIT 1`);
      const access = await one<{ seq: string }>(sql`SELECT CAST(a.seq AS TEXT) AS seq FROM audit_log a WHERE a.author = 'vault' AND a.subject_principal = ${principal}
        AND a.decision = 'allow' AND a.action IN (${sql.join(ACCESS_ACTIONS.map((action) => sql`${action}`), sql`, `)}) ORDER BY a.seq DESC LIMIT 1`);
      if (last !== undefined && BigInt(last.number) > inputs) inputs = BigInt(last.number);
      const listOf = <T>(of: (grant: (typeof grants)[number]) => T) => (member === undefined || grants.length === 0 ? null : grants.map(of));
      editor = {
        principal, status: member?.status ?? null, owner: member === undefined ? null : Boolean(member.owner), role: member?.role ?? null, scope: member?.scope ?? null,
        generation: member?.generation ?? null, seal: member?.seal == null ? null : Buffer.from(member.seal),
        g_project: listOf((grant) => grant.project_id), g_environment: listOf((grant) => grant.environment_id), g_slug: listOf((grant) => grant.environment_slug),
        g_role: listOf((grant) => grant.role), g_expires: listOf((grant) => (grant.expires_at === null ? null : String(grant.expires_at))),
        last: last?.seal == null ? null : Buffer.from(last.seal), number: last?.number ?? null, old: last === undefined ? null : oldOf(last.payload), access: access?.seq ?? null,
        change: columnsOf(last) ?? null,
      };
    }
    const keys = Array.isArray(serving.keys) ? serving.keys.map(String) : [];
    const found: (Awaited<ReturnType<typeof resolved>>)[] = [];
    for (const key of keys) found.push(await resolved(tx, at!.project_id, layers, key));
    const resolvedRows: ResolvedRow[] = found.map((held) => ({
      id: held?.id ?? null, sensitive: held === null ? null : held.sensitive, secret: null, version: null,
      held: held === null || held.holder === place ? null : { environmentId: held.holder, slug: held.slug },
    }));
    const chunk = Math.max(0, Math.min(keys.length - call.offset, call.limit));
    const asked = call.keys;
    const right = call.use && asked !== null && asked.length === chunk && chunk > 0 && call.reading === reading && call.credential === credential
      && asked.every((one, k) => {
        const held = found[call.offset + k] ?? null;
        return one !== null && one.secretId === (held?.id ?? null) && one.place === (held === null || held.holder !== place ? place : null);
      });
    const out: (UseRow | null)[] = [];
    if (right) {
      // A cover rides only past every change of the route's own inputs, which `useOnce` does not read.
      const calls: UseCall[] = asked.map((one) => {
        const { cover, ...rest } = one!;
        return { ...rest, credential, route, ...(cover === undefined || BigInt(cover.number) <= inputs ? {} : { cover }) };
      });
      const made = calls.filter((one) => one.requestId !== '');
      const batched = made.length === 0 ? null : await Batched.read(tx, made);
      // Each its call as the batch read it: a cover is found by the call it was read for.
      for (const one of calls) out.push(one.requestId === '' ? null : await useOnce(tx, one, batched!));
      await batched?.write();
      if (out.some((row) => row !== null && row.state === null) && Date.now() > call.deadline) throw Object.assign(new Error('past its deadline'), { code: '57014' });
    }
    return { gate, reading, route, madeFor, stood: true, place, project: at!.project_id, personal: false, cut: false, levels, editor, keys, resolved: resolvedRows, made: right, rows: out };
  });
}

/** A credential's `places`, read without throwing: each place's environment and whether it is a personal config. */
function placesOf(places: string | null): { environmentId: string; personal: boolean }[] {
  let parsed: unknown;
  try {
    parsed = places === null ? null : JSON.parse(places);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  return parsed.flatMap((place: unknown) => {
    if (typeof place !== 'object' || place === null || Array.isArray(place)) return [];
    const { environmentId, personal } = place as { environmentId?: unknown; personal?: unknown };
    return typeof environmentId === 'string' ? [{ environmentId, personal: personal === true }] : [];
  });
}

/**
 * The key `key` names through `layers` (0051): the nearest layer that holds it live, or but the last that removed it;
 * none, removed or held nowhere. With where it is held, and whether its value is a sealed one of its own.
 */
async function resolved(tx: Queryable, project: string, layers: readonly string[], key: string): Promise<{ id: string; holder: string; slug: string; sealed: boolean; sensitive: boolean } | null> {
  for (const [depth, layer] of layers.entries()) {
    const [held] = await rowsOf<{ id: string; slug: string; sealed: number; sensitive: number | null }>(tx, sql`SELECT s.id, e.slug,
        (v.id IS NOT NULL AND v.plaintext IS NULL) AS sealed, v.sensitive
      FROM secrets s JOIN environments e ON e.id = s.environment_id LEFT JOIN secret_versions v ON v.id = s.current_version_id
      WHERE s.project_id = ${project} AND s.environment_id = ${layer} AND s.key = ${key} AND s.archived_at IS NULL LIMIT 1`);
    if (held !== undefined) return { id: held.id, holder: layer, slug: held.slug, sealed: Boolean(held.sealed), sensitive: Boolean(held.sensitive) };
    if (depth < layers.length - 1) {
      const [removed] = await rowsOf<{ one: number }>(tx, sql`SELECT 1 AS one FROM dismissed_keys WHERE environment_id = ${layer} AND key = ${key} AND restored_at IS NULL LIMIT 1`);
      if (removed !== undefined) return null;
    }
  }
  return null;
}

/**
 * What `place` inherits from, nearest first (0051's chain): the place, then each parent; a parent archived, deleted (its
 * slug a tombstone) or not there, or a chain that loops or runs past 3, cuts it.
 */
async function chainOf(tx: Queryable, place: string, parentId: string | null): Promise<{ layers: string[]; cut: boolean }> {
  const layers = [place];
  const seen = new Set(layers);
  for (let next: string | null = parentId, depth = 1; next !== null; depth += 1) {
    const parent: { id: string; parent_id: string | null; slug: string; archived: number } | undefined = depth > 3 || seen.has(next) ? undefined
      : (await rowsOf<{ id: string; parent_id: string | null; slug: string; archived: number }>(tx, sql`SELECT id, parent_id, slug, archived_at IS NOT NULL AS archived FROM environments WHERE id = ${next}`))[0];
    if (parent === undefined || Boolean(parent.archived) || parent.slug.includes('~')) return { layers, cut: true };
    seen.add(parent.id);
    layers.push(parent.id);
    next = parent.parent_id;
  }
  return { layers, cut: false };
}

/**
 * Every key the place holds through `layers`, its chain whole, as `resolveValues` lists them (0055): a key held live in a
 * layer is the place's unless a nearer layer but the last removed it. Sorted by name.
 */
async function listed(tx: Queryable, project: string, layers: readonly string[]): Promise<string[]> {
  const depth = new Map(layers.map((id, i) => [id, i]));
  const live = new Map<string, number>();
  for (const one of await rowsOf<{ key: string; environment_id: string }>(tx, sql`SELECT key, environment_id FROM secrets
    WHERE project_id = ${project} AND environment_id IN (${sql.join(layers.map((id) => sql`${id}`), sql`, `)}) AND archived_at IS NULL`)) {
    const at = depth.get(one.environment_id)!;
    live.set(one.key, Math.min(live.get(one.key) ?? at, at));
  }
  const removed = new Map<string, number>();
  const nearer = layers.slice(0, -1);
  if (nearer.length > 0) {
    for (const one of await rowsOf<{ key: string; environment_id: string }>(tx, sql`SELECT key, environment_id FROM dismissed_keys
      WHERE environment_id IN (${sql.join(nearer.map((id) => sql`${id}`), sql`, `)}) AND restored_at IS NULL`)) {
      const at = depth.get(one.environment_id)!;
      removed.set(one.key, Math.min(removed.get(one.key) ?? at, at));
    }
  }
  return [...live].filter(([key, at]) => !removed.has(key) || at <= removed.get(key)!).map(([key]) => key).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

/**
 * An input's newest change: its number as text (SQLite's integers are 64 bits, a JavaScript number's exact ones 53), its
 * seal, and what its MAC covers besides its object, with the MAC, which the vault checks (T190, `ChangeColumns`).
 */
type Changed = { number: string; at: number; request_id: string; actor: string; payload: string; seal: Buffer | null; mac: Buffer };

/** The columns of a newest change the vault checks its MAC over, as `use_credential` answers them; none for no change. */
const columnsOf = (change: Changed | undefined): ChangeColumns | undefined =>
  change === undefined ? undefined : [Number(change.at), change.request_id, change.actor, change.payload, Buffer.from(change.mac)];

type SecretRow = { id: string; project_id: string; environment_id: string; current_version_id: string | null; seal: Buffer | null; key: string };
type ReferenceRow = { source_secret_id: string | null; id: string | null };
type VersionRow = {
  envelope_version: number; ciphertext: Buffer; iv: Buffer; auth_tag: Buffer; wrapped_dek: Buffer; kek_provider: string; kek_id: string; kek_version: string; sensitive: number; plaintext: string | null;
};
type EnvironmentRow = { project_id: string; slug: string; owner: string | null; parent_id: string | null; protected: number | null; archived: number; project_archived: number; seal: Buffer | null };

// The columns a key's rows are read with, alone (`useOnce`) or a batch's at once (`Batched`): the same rows either way.
const SECRET = sql.raw('id, project_id, environment_id, current_version_id, seal, key');
const REFERENCE = sql.raw('CASE WHEN ended_at IS NULL THEN source_secret_id END AS source_secret_id, CASE WHEN ended_at IS NULL THEN id END AS id');
const VERSION = sql.raw('envelope_version, ciphertext, iv, auth_tag, wrapped_dek, kek_provider, kek_id, kek_version, sensitive, plaintext');
/** A newest change's columns, `Changed`: its number as text. */
const CHANGED = sql.raw('CAST(c.number AS TEXT) AS number, c.at, c.request_id, c.actor, c.payload, c.seal, c.mac');
const ENVIRONMENT = sql.raw('e.project_id, e.slug, e.owner, e.parent_id, e.protected, e.archived_at IS NOT NULL AS archived, p.archived_at IS NOT NULL AS project_archived, e.seal');

/**
 * What a use reads and writes beside the named call's own reads: `read`, a row no use writes, by a key naming what the
 * query reads; the principal's cap rows; its entry, numbered; and its key's cap row entered or moved on.
 */
type Rows = {
  read<T>(key: string, load: () => Promise<T>): Promise<T>;
  /**
   * The principal's row for `secret`. `since`: the bound `others` counts from, before which a row decides nothing (it
   * is in no set, is never fresh and holds no cover), so that a batch may read none from before it.
   */
  bulk(principal: string, secret: string, since: number): Promise<{ last: number } | undefined>;
  /** How many of the principal's keys but `secret` count since `since`, up to `count`. */
  others(principal: string, secret: string | null, since: number, count: number): Promise<number>;
  /** Whether the entry the call's cover names is its request's: the same key, way in, purpose and place. */
  cover(call: UseCall & { cover: Cover }): Promise<boolean>;
  /** The use's entry, written; its number. */
  use(call: UseCall): Promise<bigint>;
  enter(principal: string, secret: string | null, period: number): Promise<void>;
};

/** A lone use's: each read and write a statement, made as it is asked. */
function direct(tx: Queryable): Rows {
  const one = async <T>(query: SQL): Promise<T | undefined> => (await rowsOf<T>(tx, query))[0];
  return {
    read: (_key, load) => load(),
    bulk: (principal, secret) => one<{ last: number }>(sql`SELECT last FROM log_bulk WHERE principal = ${principal} AND secret = ${secret}`),
    others: async (principal, secret, since, count) => Number((await one<{ n: number }>(sql`SELECT count(*) AS n FROM (
      SELECT 1 FROM log_bulk WHERE principal = ${principal} AND secret <> ${secret} AND last > ${since} LIMIT ${count})`))!.n),
    cover: async ({ cover, ...call }) => (await one(sql`SELECT 1 FROM log_uses WHERE at = ${cover.at} AND request_id = ${BigInt(cover.requestId)} AND number = ${BigInt(cover.number)}
      AND credential = ${call.credential} AND secret = ${call.secretId} AND purpose = ${call.purpose} AND place IS ${call.place} AND route IS ${call.route ?? null}`)) !== undefined,
    use: async (call) => {
      const next = BigInt((await one<{ n: string }>(NEXT))!.n);
      await insertUses(tx, [{ number: next, call }]);
      return next;
    },
    enter: async (principal, secret, period) => {
      await rowsOf(tx, sql`INSERT INTO log_bulk (principal, secret, last) VALUES (${principal}, ${secret}, ${period})
        ON CONFLICT (principal, secret) DO UPDATE SET last = max(last, excluded.last)`);
    },
  };
}

/** The next entry's number: one past the log's highest. */
const NEXT = sql`SELECT CAST(max(coalesce((SELECT max(number) FROM log_changes), 0), coalesce((SELECT max(number) FROM log_uses), 0)) + 1 AS TEXT) AS n`;

async function insertUses(tx: Queryable, uses: readonly { number: bigint; call: UseCall }[]): Promise<void> {
  for (let start = 0; start < uses.length; start += CHUNK) {
    const values = uses.slice(start, start + CHUNK).map(({ number, call }) =>
      sql`(${number}, ${call.at}, ${BigInt(call.requestId)}, ${call.credential}, ${call.secretId}, ${call.purpose}, ${call.mac}, ${call.place}, ${call.route ?? null})`);
    try {
      await rowsOf(tx, sql`INSERT INTO log_uses (number, at, request_id, credential, secret, purpose, mac, place, route) VALUES ${sql.join(values, sql`, `)}`);
    } catch (error) {
      // The unique (at, request_id), as Postgres says it.
      if (/UNIQUE constraint failed: log_uses/.test(`${String(error)} ${String((error as { cause?: unknown }).cause)}`)) throw Object.assign(new Error('a replayed use'), { code: '23505' });
      throw error;
    }
  }
}

/** Rows or ids a statement lists at most: 4,000 parameters at most, well under SQLite's bound of 32,766. */
const CHUNK = 500;

/** A principal's cap rows in a batch: each key's `last`, every one since `since`; those it entered; how many count since each bound asked. */
type Bulk = { since: number; rows: Map<string, number>; entered: Set<string>; above: Map<number, number> };

/**
 * A batch's rows (`callBatch`): every key's own rows read up front, a statement for all the keys' ids at a time, and
 * any other read once for the batch, by its key; a key whose row was not read up front (a personal config's parent, a
 * reference's source's source) reads it as alone, once. No use writes what these read but its entry and its cap row:
 * the entries are numbered on from the log's highest, and the principal's cap rows are kept here as each key enters
 * or moves on, counted in memory; both are written once every key is decided (`write`).
 */
class Batched implements Rows {
  readonly #tx: Queryable;
  readonly #read = new Map<string, Promise<unknown>>();
  /** Per principal, the cap rows read (`#bulkOf`) and those the batch's keys entered. */
  readonly #bulk = new Map<string, Bulk>();
  readonly #uses: { number: bigint; call: UseCall }[] = [];
  /** The same, by number. */
  readonly #numbered = new Map<string, UseCall>();
  /** The calls whose cover names an entry the log held when the batch began. */
  readonly #covered = new Set<UseCall>();
  #next: bigint | undefined;

  private constructor(tx: Queryable) {
    this.#tx = tx;
  }

  /** The batch's keys' rows, each kind read for all their ids at once: secrets, their references and sources, versions, places, newest changes, covers. */
  static async read(tx: Queryable, calls: readonly UseCall[]): Promise<Batched> {
    const batch = new Batched(tx);
    const ids = (list: Iterable<string | null | undefined>) => [...new Set([...list].filter((id): id is string => typeof id === 'string'))];
    const secrets = new Map<string, SecretRow>();
    const readSecrets = async (wanted: string[]) => {
      for (const row of await batch.#in<SecretRow>(wanted, (list) => sql`SELECT ${SECRET} FROM secrets WHERE id IN (${list}) AND archived_at IS NULL`)) secrets.set(row.id, row);
      for (const id of wanted) batch.#set(`secret\n${id}`, secrets.get(id));
      // The newest reference row of each, which a key without a version of its own reads.
      const held = wanted.filter((id) => secrets.get(id)?.current_version_id === null);
      const references = new Map<string, ReferenceRow>();
      for (const { of, ...row } of await batch.#in<ReferenceRow & { of: string }>(held, (list) => sql`SELECT r.secret_id AS of, ${REFERENCE} FROM secret_references r
          WHERE r.secret_id IN (${list}) AND r.created_seq = (SELECT max(created_seq) FROM secret_references WHERE secret_id = r.secret_id)`)) references.set(of, row);
      for (const id of held) batch.#set(`reference\n${id}`, references.get(id));
      return [...references.values()].map((row) => row.source_secret_id);
    };
    const asked = new Set(ids(calls.map((call) => call.secretId)));
    const sources = ids(await readSecrets([...asked]));
    await readSecrets(sources.filter((id) => !secrets.has(id) && !asked.has(id)));
    const versions = ids([...secrets.values()].map((row) => row.current_version_id));
    const rows = await batch.#in<VersionRow & { of: string }>(versions, (list) => sql`SELECT id AS of, ${VERSION} FROM secret_versions WHERE id IN (${list})`);
    batch.#all('version', versions, rows);
    const places = ids([...calls.map((call) => call.place), ...[...secrets.values()].map((row) => row.environment_id)]);
    batch.#all('environment', places, await batch.#in<EnvironmentRow & { of: string }>(places, (list) => sql`SELECT e.id AS of, ${ENVIRONMENT}
        FROM environments e LEFT JOIN projects p ON p.id = e.project_id WHERE e.id IN (${list})`));
    const objects = [...ids([...asked, ...sources]).map((id) => objectKey({ kind: 'secret', id })), ...places.map((id) => objectKey({ kind: 'environment', id }))];
    batch.#all('newest', objects, await batch.#in<Changed & { of: string }>(objects, (list) => sql`SELECT c.object AS of, ${CHANGED}
        FROM log_changes c WHERE c.object IN (${list}) AND c.number = (SELECT max(number) FROM log_changes WHERE object = c.object)`));
    const covered = calls.filter((call) => call.cover !== undefined);
    for (let start = 0; start < covered.length; start += CHUNK) {
      const some = covered.slice(start, start + CHUNK);
      const values = some.map(({ cover, ...call }, k) => sql`(${k}, ${cover!.at}, ${BigInt(cover!.requestId)}, ${BigInt(cover!.number)}, ${call.credential}, ${call.secretId}, ${call.purpose}, ${call.place}, ${call.route ?? null})`);
      const found = new Set((await rowsOf<{ k: number }>(tx, sql`WITH v (k, at, request_id, number, credential, secret, purpose, place, route) AS (VALUES ${sql.join(values, sql`, `)})
        SELECT v.k FROM v JOIN log_uses u ON u.at = v.at AND u.request_id = v.request_id AND u.number = v.number AND u.credential = v.credential
          AND u.secret = v.secret AND u.purpose = v.purpose AND u.place IS v.place AND u.route IS v.route`)).map((row) => Number(row.k)));
      for (const [k, call] of some.entries()) if (found.has(k)) batch.#covered.add(call);
    }
    return batch;
  }

  read<T>(key: string, load: () => Promise<T>): Promise<T> {
    if (!this.#read.has(key)) this.#read.set(key, load());
    return this.#read.get(key) as Promise<T>;
  }

  async bulk(principal: string, secret: string, since: number): Promise<{ last: number } | undefined> {
    const last = (await this.#bulkOf(principal, since)).rows.get(secret);
    return last === undefined ? undefined : { last };
  }

  async others(principal: string, secret: string | null, since: number, count: number): Promise<number> {
    // As SQL counts them: `secret <> NULL` holds for no row, and a negative LIMIT is none.
    if (secret === null) return 0;
    const bulk = await this.#bulkOf(principal, since);
    let above = bulk.above.get(since);
    if (above === undefined) {
      above = 0;
      for (const last of bulk.rows.values()) if (last > since) above += 1;
      bulk.above.set(since, above);
    }
    const n = above - ((bulk.rows.get(secret) ?? -Infinity) > since ? 1 : 0);
    return count < 0 ? n : Math.min(n, count);
  }

  async cover(call: UseCall & { cover: Cover }): Promise<boolean> {
    if (this.#covered.has(call)) return true;
    // Or an entry of the batch's own, made before it, as alone the use would find it written (SQL's `=` holds for no null).
    const { cover } = call;
    const made = this.#numbered.get(String(BigInt(cover.number)));
    return made !== undefined && made.at === cover.at && BigInt(made.requestId) === BigInt(cover.requestId)
      && call.credential !== null && made.credential === call.credential && call.secretId !== null && made.secretId === call.secretId
      && made.purpose === call.purpose && made.place === call.place && (made.route ?? null) === (call.route ?? null);
  }

  async use(call: UseCall): Promise<bigint> {
    this.#next ??= BigInt((await rowsOf<{ n: string }>(this.#tx, NEXT))[0]!.n);
    const number = this.#next++;
    this.#uses.push({ number, call });
    this.#numbered.set(String(number), call);
    return number;
  }

  async enter(principal: string, secret: string | null, period: number): Promise<void> {
    // A use with no key has no row to enter: its entry, queued before, fails to write first (its key NOT NULL), as alone.
    if (secret === null) return;
    // A key enters once its row was read (`bulk`).
    const bulk = this.#bulk.get(principal);
    if (bulk === undefined) throw new Error('a cap row entered unread');
    const old = bulk.rows.get(secret) ?? -Infinity;
    const last = Math.max(old, period);
    bulk.rows.set(secret, last);
    bulk.entered.add(secret);
    // Each count kept moves with it.
    for (const [since, n] of bulk.above) if (old <= since && last > since) bulk.above.set(since, n + 1);
  }

  /** The batch's entries and cap rows, each as a lone use writes it: a statement for many at a time. */
  async write(): Promise<void> {
    await insertUses(this.#tx, this.#uses);
    for (const [principal, { rows, entered }] of this.#bulk) {
      const all = [...entered];
      for (let start = 0; start < all.length; start += CHUNK) {
        const values = all.slice(start, start + CHUNK).map((secret) => sql`(${principal}, ${secret}, ${rows.get(secret)!})`);
        await rowsOf(this.#tx, sql`INSERT INTO log_bulk (principal, secret, last) VALUES ${sql.join(values, sql`, `)}
          ON CONFLICT (principal, secret) DO UPDATE SET last = max(last, excluded.last)`);
      }
    }
  }

  /** The principal's cap rows since `since`, read once, and again from further back should a key count from there. */
  async #bulkOf(principal: string, since: number): Promise<Bulk> {
    const known = this.#bulk.get(principal);
    if (known !== undefined && known.since <= since) return known;
    const bulk: Bulk = known ?? { since, rows: new Map(), entered: new Set(), above: new Map() };
    const read = await rowsOf<{ secret: string; last: number }>(this.#tx, sql`SELECT secret, last FROM log_bulk WHERE principal = ${principal} AND last > ${since}`);
    // A row the batch entered keeps the greater `last`, as its write will.
    for (const row of read) bulk.rows.set(row.secret, Math.max(bulk.rows.get(row.secret) ?? -Infinity, Number(row.last)));
    bulk.since = since;
    bulk.above.clear();
    this.#bulk.set(principal, bulk);
    return bulk;
  }

  #set(key: string, value: unknown): void {
    this.#read.set(key, Promise.resolve(value));
  }

  /** Each of `ids`' row, keyed `<kind>\n<id>`, by the `of` column it was read with; none for an id with no row. */
  #all<T extends { of: string }>(kind: string, ids: readonly string[], rows: readonly T[]): void {
    const by = new Map(rows.map(({ of, ...row }) => [of, row]));
    for (const id of ids) this.#set(`${kind}\n${id}`, by.get(id));
  }

  /** A query over `ids`, `CHUNK` of them a statement. */
  async #in<T>(ids: readonly string[], query: (list: SQL) => SQL): Promise<T[]> {
    const rows: T[] = [];
    for (let start = 0; start < ids.length; start += CHUNK) {
      rows.push(...await rowsOf<T>(this.#tx, query(sql.join(ids.slice(start, start + CHUNK).map((id) => sql`${id}`), sql`, `))));
    }
    return rows;
  }
}

async function useOnce(tx: Queryable, call: UseCall, rows: Rows): Promise<UseRow> {
  const one = async <T>(query: SQL): Promise<T | undefined> => (await rowsOf<T>(tx, query))[0];
  const once = <T>(key: string, query: SQL) => rows.read(key, () => one<T>(query));
  const now = Date.now();
  const nothing = (state: string): UseRow => ({ state } as UseRow);
  if (call.deadline > call.at + USE_DEADLINE_MS) return nothing('late');
  if (call.at > now + 60_000) return nothing('ahead');
  // A named call's credential first, held to what the app's config accepts (0045, reviews r6 and r7 of D153): one the
  // app would refuse is answered as a token no credential has, before the place, the key or anything else is read.
  const names = call.names;
  const credential = names === undefined ? undefined : await one<{ id: string; places: string | null; principal: string; kind: string; provider: string | null; issuer_hash: string | null }>(sql`SELECT
    c.id, c.places, c.principal, c.kind, x.provider, x.issuer_hash FROM credentials c LEFT JOIN identities x ON x.id = c.identity_id WHERE c.token_hash = ${names.tokenHash}`);
  if (names !== undefined && (credential === undefined || !names.accepts.signin
    || (credential.kind === 'browser' && !names.accepts.issuers.includes(`${credential.provider}:${credential.issuer_hash}`)))) return nothing('unknown');
  const newestOf = (kind: Kind, id: string | null) =>
    id === null ? Promise.resolve(undefined) : once<Changed>(`newest\n${objectKey({ kind, id })}`, sql`SELECT ${CHANGED} FROM log_changes c WHERE c.object = ${objectKey({ kind, id })} ORDER BY c.number DESC LIMIT 1`);
  const n = await once<{ number: string; mac: Buffer }>('head', sql`SELECT CAST(c.number AS TEXT) AS number, c.mac FROM log_changes c ORDER BY c.number DESC LIMIT 1`);
  const known = call.known;
  let cached = n !== undefined && known !== undefined && n.number === known.newest && Buffer.from(n.mac).equals(known.newestMac);
  const floor = await once<{ at_floor: number; retired: string }>('floor', sql`SELECT at_floor, retired FROM log_fence WHERE only_row`);
  // A MAC that names a key the log moved on from (T168), first, as the Postgres function has it.
  if (floor !== undefined && (JSON.parse(floor.retired) as string[]).includes(call.mac.subarray(0, 4).toString('hex'))) return nothing('superseded');
  if (floor === undefined || call.at < floor.at_floor || Date.now() > call.deadline) return nothing('late');
  const policy = await newestOf('policy', 'instance');
  const logged = policy === undefined ? {} : (JSON.parse(policy.payload) as { value?: { bulk?: { count?: number; windowMs?: number } } }).value?.bulk ?? {};
  const cap = cached ? known!.cap : { count: logged.count, windowMs: logged.windowMs };
  if (typeof cap.count !== 'number' || typeof cap.windowMs !== 'number') return nothing('unconfigured');
  const limit = { count: cap.count, windowMs: cap.windowMs };

  // A named call reads what its names name, as 0045 has it (D153): the credential of its token's hash, the place of its
  // slugs or a handle's one place, as `use_resolve` reads it, and the key of its name there. Every row it reads is one
  // of those; the ids the vault passed only let it write, when they are those (`right`).
  let read: { credential: string | null; secretId: string | null; place: string | null } = { credential: call.credential, secretId: call.secretId, place: call.place };
  let resolved: { state: 'nowhere' | null; right: boolean; place: string | null; project: string | null; environment: string | null; cut: boolean } | null = null;
  let stands: boolean | null = null;
  if (names !== undefined && credential !== undefined) {
    type Place = { id: string; project_id: string; project_slug: string; slug: string; parent_id: string | null; live: number };
    // A fork's place too, with forks served (0051, T165); never a personal config's by its own slug.
    const placed = sql`SELECT e.id, e.project_id, p.slug AS project_slug, e.slug, e.parent_id,
      e.archived_at IS NULL AND p.archived_at IS NULL AND e.owner IS NULL AND (e.parent_id IS NULL OR ${names.forks ? 1 : 0}) AS live
      FROM environments e JOIN projects p ON p.id = e.project_id WHERE e.slug NOT LIKE '%~%' AND p.slug NOT LIKE '%~%'`;
    const bound = names.handle ? boundOf(credential.places) : null;
    // `dev@me` (0051): dev, then the caller's personal config of it, the place; dev itself while they have none.
    const mine = names.forks && !names.handle && names.environment !== null ? personalOf(names.environment) : null;
    let place = names.handle
      ? (bound === null ? undefined : await one<Place>(sql`${placed} AND e.id = ${bound}`))
      : await one<Place>(sql`${placed} AND p.slug = ${names.project} AND e.slug = ${mine ?? names.environment}`);
    if (mine !== null && place !== undefined && Boolean(place.live)) {
      const config = await one<{ id: string; archived: number }>(sql`SELECT id, archived_at IS NOT NULL AS archived FROM environments
        WHERE parent_id = ${place.id} AND owner = ${credential.principal} AND instr(slug, '~') = 0`);
      if (config !== undefined) {
        place = { ...place, id: config.id, parent_id: place.id, live: config.archived ? 0 : 1 };
      }
    }
    // A handle's place the stable URL does not mean, by the slugs read here: the app's, as a place that is none.
    const state = place === undefined || !place.live || (names.handle && names.unless.includes(`${place.project_slug}/${place.slug}`)) ? 'nowhere' : null;
    // The caller's standing there first, from rows no key decides (0045's `use_stands`, W268): the key only for one who
    // stands. At a personal config, weighed with dev (0051's `use_stands_personal`).
    stands = state === null && place !== undefined && await standsAt(tx, credential.id, place.id, call);
    // What the place inherits from, nearest first, for one who stands (0051): a parent archived, deleted, not there, or a
    // chain that loops or runs past 3 cuts it, and the place reads nothing.
    const { layers, cut } = place === undefined ? { layers: [], cut: false }
      : stands && names.forks && place.parent_id !== null ? await chainOf(tx, place.id, place.parent_id) : { layers: [place.id], cut: false };
    // The key, in the nearest layer that settles it: holds it live, or (but the last) removed it.
    let key: { id: string; environment_id: string } | undefined;
    if (stands && !cut && names.key !== null) {
      for (const [depth, layer] of layers.entries()) {
        key = await one<{ id: string; environment_id: string }>(sql`SELECT id, environment_id FROM secrets
          WHERE project_id = ${place!.project_id} AND environment_id = ${layer} AND key = ${names.key} AND archived_at IS NULL LIMIT 1`);
        if (key !== undefined) break;
        if (depth < layers.length - 1 && await one(sql`SELECT 1 AS removed FROM dismissed_keys WHERE environment_id = ${layer} AND key = ${names.key} AND restored_at IS NULL`) !== undefined) break;
      }
    }
    // Held at the place, by its id; inherited, by its id through the place; none, through the place.
    read = { credential: credential.id, secretId: key?.id ?? null, place: key === undefined || key.environment_id !== place?.id ? place?.id ?? null : null };
    // No standing, or a chain cut: on the place alone, whatever seals the isolate passed (0045's `probe`).
    if (!stands || cut) cached = false;
    resolved = {
      state,
      right: read.credential === call.credential && read.secretId === call.secretId && read.place === call.place,
      place: place?.id ?? null, project: place?.project_slug ?? null, environment: mine !== null ? names.environment : place?.slug ?? null, cut,
    };
  }

  // The way in (0046, T147): a credential's row, an MCP connection's or a Cloudflare binding's, each read as the
  // credential's columns, a binding's whole row beside; behind Access, the person alone.
  const way = WAYS[call.way];
  type WayRow = { principal: string; kind: string | null; scope: string | null; revoked_at: number | null; expires_at: number | null; not_after: number | null; seal: Buffer | null; generation: number | null; token_hash: Buffer | null };
  const c: WayRow | undefined = way === 'access'
    ? { principal: call.principal!, kind: null, scope: null, revoked_at: null, expires_at: null, not_after: null, seal: null, generation: null, token_hash: null }
    : way === 'connection'
      ? await once<WayRow>(`way\n${way}\n${read.credential}`, sql`SELECT principal, NULL AS kind, NULL AS scope, revoked_at, expires_at, NULL AS not_after, seal, generation, NULL AS token_hash FROM mcp_connections WHERE id = ${read.credential}`)
      : way === 'binding'
        ? await once<WayRow>(`way\n${way}\n${read.credential}`, sql`SELECT principal, NULL AS kind, scope, revoked_at, NULL AS expires_at, NULL AS not_after, seal, generation, NULL AS token_hash FROM service_bindings WHERE id = ${read.credential}`)
        : await once<WayRow>(`way\n${way}\n${read.credential}`, sql`SELECT principal, kind, scope, revoked_at, expires_at, not_after, seal, generation, token_hash FROM credentials WHERE id = ${read.credential}`);
  const wRow = way !== 'binding' || c === undefined ? null : (await once<Record<string, unknown>>(`binding\n${read.credential}`, sql`SELECT principal, generation, profile, issuer, origin, jwks_uri, claims, scope, policy, revoked_at FROM service_bindings WHERE id = ${read.credential}`)) ?? null;
  const m = c === undefined ? undefined : await once<{ status: string; owner: number; role: string | null; scope: string | null; seal: Buffer | null; generation: number }>(
    `member\n${c.principal}`, sql`SELECT status, owner, role, scope, seal, generation FROM vault_members WHERE principal = ${c.principal}`);
  const grants = m === undefined ? [] : await rows.read(`grants\n${c!.principal}`, () => rowsOf<{ project_id: string | null; environment_id: string | null; environment_slug: string | null; role: string; expires_at: number | null }>(tx,
    sql`SELECT coalesce(g.project_id, ge.project_id) AS project_id, g.environment_id, g.environment_slug, g.role, g.expires_at
          FROM vault_grants g LEFT JOIN environments ge ON ge.id = g.environment_id WHERE g.principal = ${c!.principal}`));
  const config = await rows.read('config', () => rowsOf<{ name: string; value: string; seal: Buffer | null }>(tx, sql`SELECT name, value, seal FROM log_config`));
  const roles = config.find((row) => row.name === 'roles');
  const policyRow = config.find((row) => row.name === 'policy');
  const secretOf = (id: string | null) => id === null
    ? Promise.resolve(undefined)
    : once<SecretRow>(`secret\n${id}`, sql`SELECT ${SECRET} FROM secrets WHERE id = ${id} AND archived_at IS NULL`);
  // Its newest reference row's source and id, unless that row has ended.
  const referenceOf = async (secret: SecretRow | undefined) => secret === undefined || secret.current_version_id !== null
    ? undefined
    : once<ReferenceRow>(`reference\n${secret.id}`, sql`SELECT ${REFERENCE} FROM secret_references WHERE secret_id = ${secret.id} ORDER BY created_seq DESC LIMIT 1`);
  const s = await secretOf(read.secretId);
  const sReference = await referenceOf(s);
  const sSource = sReference?.source_secret_id ?? null;
  const x = sSource === null ? undefined : await secretOf(sSource);
  const xReference = await referenceOf(x);
  const xSource = xReference?.source_secret_id ?? null;
  const versionId = sSource === null ? s?.current_version_id ?? null : x?.current_version_id ?? null;
  const v = versionId === null ? undefined : await once<VersionRow>(`version\n${versionId}`, sql`SELECT ${VERSION} FROM secret_versions WHERE id = ${versionId}`);
  // Its own archival and its project's, apart.
  const environmentOf = (id: string | null) => id === null
    ? Promise.resolve(undefined)
    : once<EnvironmentRow>(`environment\n${id}`, sql`SELECT ${ENVIRONMENT} FROM environments e LEFT JOIN projects p ON p.id = e.project_id WHERE e.id = ${id}`);
  // As 0024 names them: the place read through, the key's own, its value's elsewhere, a personal config's parent.
  const ids: (string | null)[] = [
    read.place !== null && read.place !== s?.environment_id ? read.place : null,
    s?.environment_id ?? null,
    x !== undefined && x.environment_id !== s?.environment_id ? x.environment_id : null,
  ];
  const e = [await environmentOf(ids[0]!), await environmentOf(ids[1]!), await environmentOf(ids[2]!)];
  // A named call's key the place does not hold: the place's own row, a personal config's parent weighed (0051).
  const own = s === undefined && names !== undefined ? e[0] : sSource === null || (x !== undefined && ids[2] === null) ? e[1] : e[2];
  ids.push(own?.owner != null ? own.parent_id : null);
  e.push(await environmentOf(ids[3]!));
  // What the names name, if not a live place; ids the vault passed that are not the names' (`moved`), nothing written;
  // a place it reads archived, the key's or a reference's source's, which the vault refuses by name (0045's `archived`).
  let namedState: 'unknown' | 'nowhere' | 'moved' | 'archived' | null = null;
  if (resolved !== null) {
    namedState = resolved.state ?? (!resolved.right ? 'moved'
      : resolved.cut || e.slice(0, 3).some((row) => row !== undefined && (Boolean(row.archived) || Boolean(row.project_archived))) ? 'archived' : null);
    if (namedState !== null) cached = false;
  }
  // Named, or a route use's (T186, 0058's `v_quiet`): a key the place does not hold, and a plain value, decided, never
  // used, so neither an entry nor a cap's row (0044). A use by ids logs its request whatever it finds.
  const quiet = names !== undefined || call.route != null;
  const uses = namedState === null && (!quiet || (s !== undefined && (v === undefined || v.plaintext === null)));

  const last = (kind: Kind, id: string | null) => (cached ? Promise.resolve(undefined) : newestOf(kind, id));
  const [lc, lm, lr, ls, lx, ...le] = await Promise.all([
    last(way === 'access' ? 'credential' : way, way === 'access' ? null : read.credential), last('principal', c?.principal ?? null), last('roles', 'instance'), last('secret', read.secretId), last('secret', sSource),
    ...ids.map((id) => last('environment', id)),
  ]);
  const numbers = [lc, lm, lr, cached ? undefined : policy, ls, lx, ...le].flatMap((change) => (change === undefined ? [] : [BigInt(change.number)]));
  const inputs = numbers.length === 0 ? null : numbers.reduce((a, b) => (b > a ? b : a));
  const access = c === undefined ? undefined : await once<{ seq: string }>(`access\n${c.principal}`, sql`SELECT CAST(a.seq AS TEXT) AS seq FROM audit_log a WHERE a.author = 'vault' AND a.subject_principal = ${c.principal}
    AND a.decision = 'allow' AND a.action IN (${sql.join(ACCESS_ACTIONS.map((action) => sql`${action}`), sql`, `)}) ORDER BY a.seq DESC LIMIT 1`);

  // The cap's rule (bulk.ts, as 0022 and 0024 write it): the key's row, and the others only for a key not in the set.
  const refresh = refreshMs(limit);
  const period = periodOf(call.at, refresh);
  const since = call.at - limit.windowMs - refresh - USE_DEADLINE_MS - USE_AHEAD_MS;
  const b = c === undefined || read.secretId === null ? undefined : await rows.bulk(c.principal, read.secretId, since);
  const inSet = b !== undefined && b.last > call.at - limit.windowMs - refresh;
  const stale = b === undefined || b.last < period;
  const others = c === undefined || inSet ? 0 : await rows.others(c.principal, read.secretId, since, limit.count);
  const cover = call.cover;
  const covered = cover !== undefined && b !== undefined && b.last >= period && (cached || BigInt(cover.number) > (inputs ?? 0n))
    && await rows.cover(call as UseCall & { cover: Cover });
  // A use whose key would take its principal's lock, to enter the cap's set or move on in it, named or by ids, takes it
  // only in the call the vault makes once it has decided the use (0045, T158, D153): else `decide`, nothing written, its
  // rows for the vault to decide on. SQLite's one writer at a time makes the lock implicit; the call is the same, so
  // that both engines answer alike.
  const decide = c !== undefined && uses && stale && call.decided !== true;
  let number: string | null = null;
  if (!covered && uses && !decide) number = String(await rows.use(call));
  if (c !== undefined && uses && !decide && !covered && stale && (inSet || others < limit.count)) await rows.enter(c.principal, call.secretId, period);
  // Past its deadline by the end, the call rolls back and writes nothing (DeadlineChecked), as Postgres's does.
  if (!decide && namedState === null && Date.now() > call.deadline) throw Object.assign(new Error('past its deadline'), { code: '57014' });
  const blob = (value: Buffer | Uint8Array | null | undefined) => (value == null ? null : Buffer.from(value));
  const slot = (i: number) => {
    const row = e[i];
    const at = `e${i + 1}`;
    return {
      [`${at}_id`]: ids[i] ?? null, [`${at}_project`]: row?.project_id ?? null, [`${at}_slug`]: row?.slug ?? null, [`${at}_owner`]: row?.owner ?? null,
      [`${at}_parent`]: row?.parent_id ?? null, [`${at}_protected`]: row?.protected == null ? null : Boolean(row.protected),
      [`${at}_archived`]: row === undefined ? null : Boolean(row.archived), [`${at}_project_archived`]: row === undefined ? null : Boolean(row.project_archived),
      [`${at}_seal`]: blob(row?.seal), [`${at}_last`]: blob(le[i]?.seal),
    };
  };
  const expires = c === undefined || c.expires_at === null ? null : Math.min(c.expires_at, c.not_after ?? Infinity);
  return {
    state: namedState ?? (decide ? 'decide' : null), number, covered: covered ? cover!.number : null, newest: n === undefined ? null : n.number, newest_mac: blob(n?.mac), inputs: cached || inputs === null ? null : String(inputs),
    probed: !cached,
    c_principal: c?.principal ?? null, c_kind: c?.kind ?? null, c_scope: c?.scope ?? null, c_revoked: c === undefined ? null : c.revoked_at !== null,
    c_expires: expires === null ? null : String(expires), c_seal: blob(c?.seal), c_last: blob(lc?.seal),
    m_status: m?.status ?? null, m_owner: m === undefined ? null : Boolean(m.owner), m_role: m?.role ?? null, m_scope: m?.scope ?? null, m_seal: blob(m?.seal), m_last: blob(lm?.seal),
    m_old: lm === undefined ? null : oldOf(lm.payload), m_access: access === undefined ? null : access.seq,
    c_generation: c?.generation ?? null, m_generation: m?.generation ?? null,
    g_project: m === undefined ? null : grants.map((g) => g.project_id), g_environment: m === undefined ? null : grants.map((g) => g.environment_id),
    g_slug: m === undefined ? null : grants.map((g) => g.environment_slug), g_role: m === undefined ? null : grants.map((g) => g.role),
    g_expires: m === undefined ? null : grants.map((g) => (g.expires_at === null ? null : String(g.expires_at))),
    r_value: roles?.value ?? null, r_seal: blob(roles?.seal), r_last: blob(lr?.seal),
    p_value: policyRow?.value ?? null, p_seal: blob(policyRow?.seal), p_last: cached ? null : blob(policy?.seal), cap_count: limit.count, cap_window: String(limit.windowMs),
    s_project: s?.project_id ?? null, s_environment: s?.environment_id ?? null, s_version: s?.current_version_id ?? null, s_source: sSource,
    s_reference: sSource === null ? null : sReference?.id ?? null, s_seal: blob(s?.seal), s_last: blob(ls?.seal),
    x_project: x?.project_id ?? null, x_environment: x?.environment_id ?? null, x_version: x?.current_version_id ?? null, x_source: xSource,
    x_reference: xSource === null ? null : xReference?.id ?? null, x_seal: blob(x?.seal), x_last: blob(lx?.seal),
    v_envelope: v?.envelope_version ?? null, v_ciphertext: blob(v?.ciphertext), v_iv: blob(v?.iv), v_auth_tag: blob(v?.auth_tag), v_wrapped_dek: blob(v?.wrapped_dek),
    v_kek_provider: v?.kek_provider ?? null, v_kek_id: v?.kek_id ?? null, v_kek_version: v?.kek_version ?? null,
    v_sensitive: v === undefined ? null : Boolean(v.sensitive), v_plain: v === undefined ? null : v.plaintext !== null, v_plaintext: v?.plaintext ?? null,
    ...slot(0), ...slot(1), ...slot(2), ...slot(3),
    in_set: inSet, others,
    // SQLite's app reads its own rows, as it always has (`app_read` is Postgres's).
    c_token_hash: blob(c?.token_hash), app: null,
    n_credential: resolved === null ? null : read.credential, n_secret: resolved === null ? null : read.secretId, n_place: resolved?.place ?? null,
    n_project: resolved?.project ?? null, n_environment: resolved?.environment ?? null, n_standing: stands, n_cut: resolved === null ? null : resolved.cut,
    w_row: wRow,
    changes: cached ? null : {
      c: columnsOf(lc), m: columnsOf(lm), r: columnsOf(lr), p: columnsOf(policy), s: columnsOf(ls), x: columnsOf(lx),
      e1: columnsOf(le[0]), e2: columnsOf(le[1]), e3: columnsOf(le[2]), e4: columnsOf(le[3]),
    },
  } as UseRow;
}

/**
 * Whether a named call's caller stands at `place` for its purpose, as 0045's `use_stands` decides it before the key
 * is read (W268): the vault's own rule on the rows as read (`namedStanding`), whose seals the vault checks after.
 */
async function standsAt(tx: Queryable, credentialId: string, place: string, call: UseCall): Promise<boolean> {
  const one = async <T>(query: SQL): Promise<T | undefined> => (await rowsOf<T>(tx, query))[0];
  const c = await one<{ principal: string; kind: string; scope: string | null; revoked_at: number | null; expires_at: number; not_after: number | null; generation: number }>(
    sql`SELECT principal, kind, scope, revoked_at, expires_at, not_after, generation FROM credentials WHERE id = ${credentialId}`);
  const e = await one<{ project_id: string; slug: string; owner: string | null; parent_id: string | null; protected: number | null; archived: number; project_archived: number }>(
    sql`SELECT e.project_id, e.slug, e.owner, e.parent_id, e.protected, e.archived_at IS NOT NULL AS archived, p.archived_at IS NOT NULL AS project_archived
          FROM environments e LEFT JOIN projects p ON p.id = e.project_id WHERE e.id = ${place}`);
  if (c === undefined || e === undefined) return false;
  const m = await one<{ status: string; owner: number; role: string | null; scope: string | null; generation: number }>(
    sql`SELECT status, owner, role, scope, generation FROM vault_members WHERE principal = ${c.principal}`);
  const grants = m === undefined ? [] : await rowsOf<{ project_id: string | null; environment_id: string | null; environment_slug: string | null; role: string; expires_at: number | null }>(tx,
    sql`SELECT coalesce(g.project_id, ge.project_id) AS project_id, g.environment_id, g.environment_slug, g.role, g.expires_at
          FROM vault_grants g LEFT JOIN environments ge ON ge.id = g.environment_id WHERE g.principal = ${c.principal}`);
  const roles = await one<{ value: string }>(sql`SELECT value FROM log_config WHERE name = 'roles'`);
  const credential = credentialObject({
    id: credentialId, principal: c.principal, kind: c.kind, scope: c.scope, revoked: c.revoked_at !== null,
    expiresAt: Math.min(c.expires_at, c.not_after ?? Infinity), generation: c.generation,
  });
  const principal = m === undefined ? null : principalObject({ principal: c.principal, status: m.status, generation: m.generation, ...memberStanding({ owner: Boolean(m.owner), role: m.role, scope: m.scope }) },
    grants.map((g) => ({ projectId: g.project_id, environmentId: g.environment_id, environmentSlug: g.environment_slug, role: g.role, expiresAt: g.expires_at })));
  const environment = environmentObject({
    id: place, projectId: e.project_id, slug: e.slug, owner: e.owner, parentId: e.parent_id, protected: e.protected === null ? null : Boolean(e.protected),
    archived: Boolean(e.archived), projectArchived: Boolean(e.project_archived),
  });
  // A personal config is weighed with its parent, as the vault's rule weighs it (0051's `use_stands_personal`).
  const parent = e.owner === null || e.parent_id === null ? undefined : await one<{ id: string; project_id: string; slug: string; owner: string | null; parent_id: string | null; protected: number | null; archived: number; project_archived: number }>(
    sql`SELECT e.id, e.project_id, e.slug, e.owner, e.parent_id, e.protected, e.archived_at IS NOT NULL AS archived, p.archived_at IS NOT NULL AS project_archived
          FROM environments e LEFT JOIN projects p ON p.id = e.project_id WHERE e.id = ${e.parent_id}`);
  const parents = parent === undefined ? [] : [environmentObject({
    id: parent.id, projectId: parent.project_id, slug: parent.slug, owner: parent.owner, parentId: parent.parent_id, protected: parent.protected === null ? null : Boolean(parent.protected),
    archived: Boolean(parent.archived), projectArchived: Boolean(parent.project_archived),
  })];
  const request = { at: call.at, purpose: purposeOf(call.purpose)!.purpose };
  return namedStanding(principal, credential, roles === undefined ? noEdits() : configObject(roles.value) as RolesInput, environment, request, parents) === null;
}

/**
 * A handle's one place, as 0045 reads it from its credential's `places`: none for several, a personal config, or
 * anything that is no list of one place, read before the credential is checked, so without throwing.
 */
function boundOf(places: string | null): string | null {
  let parsed: unknown;
  try {
    parsed = places === null ? null : JSON.parse(places);
  } catch {
    return null;
  }
  if (!Array.isArray(parsed) || parsed.length !== 1) return null;
  const [place] = parsed as unknown[];
  if (typeof place !== 'object' || place === null || Array.isArray(place)) return null;
  const { environmentId, personal } = place as { environmentId?: unknown; personal?: unknown };
  if (personal !== undefined && personal !== null && personal !== false) return null;
  return typeof environmentId === 'string' && UUID.test(environmentId) ? environmentId : null;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function oldOf(payload: string): string | null {
  const old = (JSON.parse(payload) as { old?: unknown }).old;
  return old === undefined || old === null ? null : String(old);
}
