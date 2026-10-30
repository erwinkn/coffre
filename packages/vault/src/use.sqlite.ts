
import { ACCESS_ACTIONS } from '@coffre/core/vault';
import type { Database, Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql, type SQL } from 'drizzle-orm';

import { periodOf, refreshMs, USE_AHEAD_MS, USE_DEADLINE_MS } from './bulk.ts';
import { namedStanding } from './decide.ts';
import { noEdits, objectKey, type Kind, type RolesInput } from './inputs.ts';
import { purposeOf, WAYS } from './log-replay.ts';
import { configObject, credentialObject, environmentObject, memberStanding, principalObject } from './objects.ts';
import type { Resolved, UseCall, UseRow } from './use.ts';

/**
 * `use_credential` (0024's, as 0046 has it) on SQLite, for tests and local development
 * (docs/design/0.15-plan.md, "Postgres serves; SQLite is for tests"): the
 * same reads and writes, the same row, in one transaction. SQLite runs one
 * writer at a time (`BEGIN IMMEDIATE`, @coffre/db/connect), so the fence and
 * the principal's lock are implicit, and no number is taken out of order.
 * It has no sequence: an entry's number is one past the log's highest.
 */
export async function callUse(db: Queryable, call: UseCall): Promise<UseRow> {
  return (db as Database).transaction((tx) => useOnce(tx, call));
}

/**
 * `use_batch` (0048) on SQLite: each key's use as `callUse` makes it, in order, in one transaction. Its one writer at a
 * time makes the principal's lock, the batch's `lock`, implicit too.
 */
export async function callBatch(db: Queryable, calls: readonly UseCall[], _lock: string | null): Promise<UseRow[]> {
  return (db as Database).transaction(async (tx) => {
    const rows: UseRow[] = [];
    for (const call of calls) rows.push(await useOnce(tx, call));
    return rows;
  });
}

/** A change's number as text: SQLite's integers are 64 bits, a JavaScript number's exact ones 53. */
type Changed = { number: string; mac: Buffer; seal: Buffer | null; payload: string };

async function useOnce(tx: Queryable, call: UseCall): Promise<UseRow> {
  const one = async <T>(query: SQL): Promise<T | undefined> => (await rowsOf<T>(tx, query))[0];
  const now = Date.now();
  const nothing = (state: string): UseRow => ({ state } as UseRow);
  if (call.deadline > call.at + USE_DEADLINE_MS) return nothing('late');
  if (call.at > now + 60_000) return nothing('ahead');
  // A named call's credential first, held to what the app's config accepts (0045, reviews r6 and r7 of D153): one the
  // app would refuse is answered as a token no credential has, before the place, the key or anything else is read.
  const names = call.names;
  const credential = names === undefined ? undefined : await one<{ id: string; places: string | null; kind: string; provider: string | null; issuer_hash: string | null }>(sql`SELECT
    c.id, c.places, c.kind, x.provider, x.issuer_hash FROM credentials c LEFT JOIN identities x ON x.id = c.identity_id WHERE c.token_hash = ${names.tokenHash}`);
  if (names !== undefined && (credential === undefined || !names.accepts.signin
    || (credential.kind === 'browser' && !names.accepts.issuers.includes(`${credential.provider}:${credential.issuer_hash}`)))) return nothing('unknown');
  const newestOf = (kind: Kind, id: string | null) =>
    id === null ? Promise.resolve(undefined) : one<Changed>(sql`SELECT CAST(c.number AS TEXT) AS number, c.seal, c.payload FROM log_changes c WHERE c.object = ${objectKey({ kind, id })} ORDER BY c.number DESC LIMIT 1`);
  const n = await one<{ number: string; mac: Buffer }>(sql`SELECT CAST(c.number AS TEXT) AS number, c.mac FROM log_changes c ORDER BY c.number DESC LIMIT 1`);
  const known = call.known;
  let cached = n !== undefined && known !== undefined && n.number === known.newest && Buffer.from(n.mac).equals(known.newestMac);
  const floor = await one<{ at_floor: number; retired: string }>(sql`SELECT at_floor, retired FROM log_fence WHERE only_row`);
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
  let resolved: { state: 'nowhere' | null; right: boolean; place: string | null; project: string | null; environment: string | null } | null = null;
  let stands: boolean | null = null;
  if (names !== undefined && credential !== undefined) {
    type Place = { id: string; project_id: string; project_slug: string; slug: string; live: number };
    const placed = sql`SELECT e.id, e.project_id, p.slug AS project_slug, e.slug,
      e.archived_at IS NULL AND p.archived_at IS NULL AND e.parent_id IS NULL AND e.owner IS NULL AS live
      FROM environments e JOIN projects p ON p.id = e.project_id WHERE e.slug NOT LIKE '%~%' AND p.slug NOT LIKE '%~%'`;
    const bound = names.handle ? boundOf(credential.places) : null;
    const place = names.handle
      ? (bound === null ? undefined : await one<Place>(sql`${placed} AND e.id = ${bound}`))
      : await one<Place>(sql`${placed} AND p.slug = ${names.project} AND e.slug = ${names.environment}`);
    // A handle's place the stable URL does not mean, by the slugs read here: the app's, as a place that is none.
    const state = place === undefined || !place.live || (names.handle && names.unless.includes(`${place.project_slug}/${place.slug}`)) ? 'nowhere' : null;
    // The caller's standing there first, from rows no key decides (0045's `use_stands`, W268): the key only for one who stands.
    stands = state === null && place !== undefined && await standsAt(tx, credential.id, place.id, call);
    const key = !stands || names.key === null ? undefined : await one<{ id: string }>(sql`SELECT id FROM secrets
      WHERE project_id = ${place!.project_id} AND environment_id = ${place!.id} AND key = ${names.key} AND archived_at IS NULL LIMIT 1`);
    read = { credential: credential.id, secretId: key?.id ?? null, place: key === undefined ? place?.id ?? null : null };
    // No standing: on the place alone, whatever seals the isolate passed (0045's `probe`).
    if (!stands) cached = false;
    resolved = {
      state,
      right: read.credential === call.credential && read.secretId === call.secretId && read.place === call.place,
      place: place?.id ?? null, project: place?.project_slug ?? null, environment: place?.slug ?? null,
    };
  }

  // The way in (0046, T147): a credential's row, an MCP connection's or a Cloudflare binding's, each read as the
  // credential's columns, a binding's whole row beside; behind Access, the person alone.
  const way = WAYS[call.way];
  type WayRow = { principal: string; kind: string | null; scope: string | null; revoked_at: number | null; expires_at: number | null; not_after: number | null; seal: Buffer | null; generation: number | null; token_hash: Buffer | null };
  const c: WayRow | undefined = way === 'access'
    ? { principal: call.principal!, kind: null, scope: null, revoked_at: null, expires_at: null, not_after: null, seal: null, generation: null, token_hash: null }
    : way === 'connection'
      ? await one<WayRow>(sql`SELECT principal, NULL AS kind, NULL AS scope, revoked_at, expires_at, NULL AS not_after, seal, generation, NULL AS token_hash FROM mcp_connections WHERE id = ${read.credential}`)
      : way === 'binding'
        ? await one<WayRow>(sql`SELECT principal, NULL AS kind, scope, revoked_at, NULL AS expires_at, NULL AS not_after, seal, generation, NULL AS token_hash FROM service_bindings WHERE id = ${read.credential}`)
        : await one<WayRow>(sql`SELECT principal, kind, scope, revoked_at, expires_at, not_after, seal, generation, token_hash FROM credentials WHERE id = ${read.credential}`);
  const wRow = way !== 'binding' || c === undefined ? null : (await one<Record<string, unknown>>(sql`SELECT principal, generation, profile, issuer, origin, jwks_uri, claims, scope, policy, revoked_at FROM service_bindings WHERE id = ${read.credential}`)) ?? null;
  const m = c === undefined ? undefined : await one<{ status: string; owner: number; role: string | null; scope: string | null; seal: Buffer | null; generation: number }>(
    sql`SELECT status, owner, role, scope, seal, generation FROM vault_members WHERE principal = ${c.principal}`);
  const grants = m === undefined ? [] : await rowsOf<{ project_id: string | null; environment_id: string | null; environment_slug: string | null; role: string; expires_at: number | null }>(tx,
    sql`SELECT coalesce(g.project_id, ge.project_id) AS project_id, g.environment_id, g.environment_slug, g.role, g.expires_at
          FROM vault_grants g LEFT JOIN environments ge ON ge.id = g.environment_id WHERE g.principal = ${c!.principal}`);
  const config = await rowsOf<{ name: string; value: string; seal: Buffer | null }>(tx, sql`SELECT name, value, seal FROM log_config`);
  const roles = config.find((row) => row.name === 'roles');
  const policyRow = config.find((row) => row.name === 'policy');
  type SecretRow = { id: string; project_id: string; environment_id: string; current_version_id: string | null; seal: Buffer | null; key: string };
  const secretOf = (id: string | null) => id === null
    ? Promise.resolve(undefined)
    : one<SecretRow>(sql`SELECT id, project_id, environment_id, current_version_id, seal, key FROM secrets WHERE id = ${id} AND archived_at IS NULL`);
  // Its newest reference row's source and id, unless that row has ended.
  const referenceOf = async (secret: SecretRow | undefined) => secret === undefined || secret.current_version_id !== null
    ? undefined
    : one<{ source_secret_id: string | null; id: string | null }>(sql`SELECT CASE WHEN ended_at IS NULL THEN source_secret_id END AS source_secret_id,
        CASE WHEN ended_at IS NULL THEN id END AS id FROM secret_references WHERE secret_id = ${secret.id} ORDER BY created_seq DESC LIMIT 1`);
  const s = await secretOf(read.secretId);
  const sReference = await referenceOf(s);
  const sSource = sReference?.source_secret_id ?? null;
  const x = sSource === null ? undefined : await secretOf(sSource);
  const xReference = await referenceOf(x);
  const xSource = xReference?.source_secret_id ?? null;
  const versionId = sSource === null ? s?.current_version_id ?? null : x?.current_version_id ?? null;
  const v = versionId === null ? undefined : await one<{
    envelope_version: number; ciphertext: Buffer; iv: Buffer; auth_tag: Buffer; wrapped_dek: Buffer; kek_provider: string; kek_id: string; kek_version: string; sensitive: number; plaintext: string | null;
  }>(sql`SELECT envelope_version, ciphertext, iv, auth_tag, wrapped_dek, kek_provider, kek_id, kek_version, sensitive, plaintext FROM secret_versions WHERE id = ${versionId}`);
  type EnvironmentRow = { project_id: string; slug: string; owner: string | null; parent_id: string | null; protected: number | null; archived: number; project_archived: number; seal: Buffer | null };
  // Its own archival and its project's, apart.
  const environmentOf = (id: string | null) => id === null
    ? Promise.resolve(undefined)
    : one<EnvironmentRow>(sql`SELECT e.project_id, e.slug, e.owner, e.parent_id, e.protected, e.archived_at IS NOT NULL AS archived, p.archived_at IS NOT NULL AS project_archived, e.seal
        FROM environments e LEFT JOIN projects p ON p.id = e.project_id WHERE e.id = ${id}`);
  // As 0024 names them: the place read through, the key's own, its value's elsewhere, a personal config's parent.
  const ids: (string | null)[] = [
    read.place !== null && read.place !== s?.environment_id ? read.place : null,
    s?.environment_id ?? null,
    x !== undefined && x.environment_id !== s?.environment_id ? x.environment_id : null,
  ];
  const e = [await environmentOf(ids[0]!), await environmentOf(ids[1]!), await environmentOf(ids[2]!)];
  const own = sSource === null || (x !== undefined && ids[2] === null) ? e[1] : e[2];
  ids.push(own?.owner != null ? own.parent_id : null);
  e.push(await environmentOf(ids[3]!));
  // What the names name, if not a live place; ids the vault passed that are not the names' (`moved`), nothing written;
  // a place it reads archived, the key's or a reference's source's, which the vault refuses by name (0045's `archived`).
  let namedState: 'unknown' | 'nowhere' | 'moved' | 'archived' | null = null;
  if (resolved !== null) {
    namedState = resolved.state ?? (!resolved.right ? 'moved'
      : e.slice(0, 3).some((row) => row !== undefined && (Boolean(row.archived) || Boolean(row.project_archived))) ? 'archived' : null);
    if (namedState !== null) cached = false;
  }
  // Named, a key the place does not hold, and a plain value: decided, never used, so neither an entry nor a cap's row
  // (0044). A use by ids logs its request whatever it finds, as before.
  const uses = namedState === null && (names === undefined || (s !== undefined && (v === undefined || v.plaintext === null)));

  const last = (kind: Kind, id: string | null) => (cached ? Promise.resolve(undefined) : newestOf(kind, id));
  const [lc, lm, lr, ls, lx, ...le] = await Promise.all([
    last(way === 'access' ? 'credential' : way, way === 'access' ? null : read.credential), last('principal', c?.principal ?? null), last('roles', 'instance'), last('secret', read.secretId), last('secret', sSource),
    ...ids.map((id) => last('environment', id)),
  ]);
  const numbers = [lc, lm, lr, cached ? undefined : policy, ls, lx, ...le].flatMap((change) => (change === undefined ? [] : [BigInt(change.number)]));
  const inputs = numbers.length === 0 ? null : numbers.reduce((a, b) => (b > a ? b : a));
  const access = c === undefined ? undefined : await one<{ seq: string }>(sql`SELECT CAST(a.seq AS TEXT) AS seq FROM audit_log a WHERE a.author = 'vault' AND a.subject_principal = ${c.principal}
    AND a.decision = 'allow' AND a.action IN (${sql.join(ACCESS_ACTIONS.map((action) => sql`${action}`), sql`, `)}) ORDER BY a.seq DESC LIMIT 1`);

  // The cap's rule (bulk.ts, as 0022 and 0024 write it): the key's row, and the others only for a key not in the set.
  const refresh = refreshMs(limit);
  const period = periodOf(call.at, refresh);
  const b = c === undefined || read.secretId === null ? undefined : await one<{ last: number }>(sql`SELECT last FROM log_bulk WHERE principal = ${c.principal} AND secret = ${read.secretId}`);
  const inSet = b !== undefined && b.last > call.at - limit.windowMs - refresh;
  const stale = b === undefined || b.last < period;
  const others = c === undefined || inSet ? 0 : Number((await one<{ n: number }>(sql`SELECT count(*) AS n FROM (
    SELECT 1 FROM log_bulk WHERE principal = ${c.principal} AND secret <> ${read.secretId} AND last > ${call.at - limit.windowMs - refresh - USE_DEADLINE_MS - USE_AHEAD_MS} LIMIT ${limit.count})`))!.n);
  const cover = call.cover;
  const covered = cover !== undefined && b !== undefined && b.last >= period && (cached || BigInt(cover.number) > (inputs ?? 0n))
    && (await one(sql`SELECT 1 FROM log_uses WHERE at = ${cover.at} AND request_id = ${BigInt(cover.requestId)} AND number = ${BigInt(cover.number)}
      AND credential = ${call.credential} AND secret = ${call.secretId} AND purpose = ${call.purpose} AND place IS ${call.place}`)) !== undefined;
  // A use whose key would take its principal's lock, to enter the cap's set or move on in it, named or by ids, takes it
  // only in the call the vault makes once it has decided the use (0045, T158, D153): else `decide`, nothing written, its
  // rows for the vault to decide on. SQLite's one writer at a time makes the lock implicit; the call is the same, so
  // that both engines answer alike.
  const decide = c !== undefined && uses && stale && call.decided !== true;
  let number: string | null = null;
  if (!covered && uses && !decide) {
    const next = BigInt((await one<{ n: string }>(sql`SELECT CAST(max(coalesce((SELECT max(number) FROM log_changes), 0), coalesce((SELECT max(number) FROM log_uses), 0)) + 1 AS TEXT) AS n`))!.n);
    try {
      await rowsOf(tx, sql`INSERT INTO log_uses (number, at, request_id, credential, secret, purpose, mac, place)
        VALUES (${next}, ${call.at}, ${BigInt(call.requestId)}, ${call.credential}, ${call.secretId}, ${call.purpose}, ${call.mac}, ${call.place})`);
    } catch (error) {
      // The unique (at, request_id), as Postgres says it.
      if (/UNIQUE constraint failed: log_uses/.test(`${String(error)} ${String((error as { cause?: unknown }).cause)}`)) throw Object.assign(new Error('a replayed use'), { code: '23505' });
      throw error;
    }
    number = String(next);
  }
  if (c !== undefined && uses && !decide && !covered && stale && (inSet || others < limit.count)) {
    await rowsOf(tx, sql`INSERT INTO log_bulk (principal, secret, last) VALUES (${c.principal}, ${call.secretId}, ${period})
      ON CONFLICT (principal, secret) DO UPDATE SET last = max(last, excluded.last)`);
  }
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
    n_project: resolved?.project ?? null, n_environment: resolved?.environment ?? null, n_standing: stands,
    w_row: wRow,
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
  const request = { at: call.at, purpose: purposeOf(call.purpose)!.purpose };
  return namedStanding(principal, credential, roles === undefined ? noEdits() : configObject(roles.value) as RolesInput, environment, request) === null;
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
