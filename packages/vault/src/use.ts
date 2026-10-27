import { ownerKey, type SecretContext } from '@coffre/core/envelope';
import { KekBadClaimError, KekUnavailableError, type KekRegistry } from '@coffre/core/kek';
import type { UseBusy, UseInput, UseOutcome, UsedValue } from '@coffre/core/vault';
import type { Queryable } from '@coffre/db';
import { engineOf } from '@coffre/db/dialect';

import { USE_DEADLINE_MS } from './bulk.ts';
import type { BulkLimit } from './config.ts';
import { checkSeals, decideChecked, type Read, type UseCode, type UseRequest, type UseView } from './decide.ts';
import type { EnvironmentInput, Input, InputGrant, PolicyInput, RolesInput, SealKeys } from './inputs.ts';
import { entryMac } from './log-entry.ts';
import { configObject, credentialObject, environmentObject, memberStanding, principalObject, secretObject } from './objects.ts';
import { PURPOSES, purposeCode } from './log-replay.ts';
import { callUse as callPostgres } from './use.postgres.ts';
import { callUse as callSqlite } from './use.sqlite.ts';

/**
 * 0.15's use (docs/design/0.15-plan.md, PR 5; hot-path-one.md, "A use";
 * formal/HotPathOne.tla): one call, `use_credential`, then the decision on
 * what it read, then the key, opened only once the call has returned,
 * which is once its entry has committed (ReleaseAfterCommit). The log
 * records the request; the outcome is `decideChecked`'s on what the
 * statement read, which the replay of the log recomputes (R53).
 *
 * Around the call, what is per isolate (each a settled value, never work in
 * flight: vault.ts, `PreparedVault`):
 * - **admission:** at most `limit` calls in flight; the next is refused at
 *   once, `overloaded`, holding no connection (R44);
 * - **the deadline:** at most 3 s from the request's time (R53, R54). The
 *   call is raced against it and answered `late` when it loses; Postgres
 *   holds it too (DeadlineChecked), and a value whose call returns after
 *   it never leaves (WorkerHonoursDeadline);
 * - **the seal cache:** each key's inputs' newest seals and the cap, as of
 *   the log's newest change (its number and MAC), which the next call
 *   names so that its statement probes nothing while that change is still
 *   the newest (CacheChecked, CacheSameChange);
 * - **covers:** a repeat of an allowed use rides its entry, writing none,
 *   while no input changed since and the key's bulk row is fresh.
 */

export type { UseInput, UseOutcome, UsedValue };

/** A use's request id (`newUseRequestId`, core's: the app makes them too). */
export { newUseRequestId as newRequestId } from '@coffre/core/vault';

/** What the vault holds per isolate for its uses (`UseCache`): only settled values. */
export type CachedSeals = {
  /** The log's newest change when these were read: its number and MAC. */
  newest: string;
  newestMac: Buffer;
  /** The cap its policy's newest change said then (CapSealed). */
  cap: BulkLimit;
  /** The newest change of any input then: a cover after it holds. */
  inputs: string | null;
  /** Which objects each seal is of, as the rows named them: a row that names others now reads nothing from here. */
  ids: string;
  last: Lasts;
};

/** Each input's newest change's seal, and the 0.14 entry the principal's accounts for. */
type Lasts = {
  c: Buffer | null; m: Buffer | null; mOld: string | null; r: Buffer | null; p: Buffer | null; s: Buffer | null; x: Buffer | null;
  e1: Buffer | null; e2: Buffer | null; e3: Buffer | null; e4: Buffer | null;
};

export type Cover = { number: string; at: number; requestId: string; until: number };

/** The settings of an isolate's uses: how many calls in flight at once, and how long a cover holds. */
export type UseLimits = { inFlight: number; coverMs: number };

/**
 * How many uses an isolate has in flight at most, unless set: a pool of
 * `connections` serves that many at once, and a call past it would only
 * queue for a connection, holding its deadline. T112 measures the number
 * for Workers; here it is the pool's.
 */
export function useLimits(connections: number, set: Partial<UseLimits> = {}): UseLimits {
  return { inFlight: set.inFlight ?? Math.max(1, connections), coverMs: set.coverMs ?? 60_000 };
}

/** An isolate's admission count, seal cache and covers. Bounded: past `max` entries, a map starts over. */
export class UseCache {
  inFlight = 0;
  readonly seals = new Map<string, CachedSeals>();
  readonly covers = new Map<string, Cover>();
  readonly limits: UseLimits;
  readonly max: number;

  constructor(limits: UseLimits, max = 10_000) {
    this.limits = limits;
    this.max = max;
  }

  keep<T>(map: Map<string, T>, key: string, value: T): void {
    if (map.size >= this.max && !map.has(key)) map.clear();
    map.set(key, value);
  }
}

/** One call of `use_credential` as the vault makes it: the request, its MAC, a cover and the cache, if any. */
export type UseCall = {
  credential: string; secretId: string; requestId: string; at: number; purpose: number; place: string | null; mac: Buffer; deadline: number;
  cover?: Cover;
  known?: Pick<CachedSeals, 'newest' | 'newestMac' | 'cap'>;
};

/** What `use_credential` answers (schema 0024's `use_row`), as node-postgres reads it; the SQLite twin answers the same. */
export type UseRow = {
  state: string | null; number: string | null; covered: string | null; newest: string | null; newest_mac: Buffer | null; inputs: string | null; probed: boolean;
  c_principal: string | null; c_kind: string | null; c_scope: string | null; c_revoked: boolean | null; c_expires: string | null; c_seal: Buffer | null; c_last: Buffer | null;
  m_status: string | null; m_owner: boolean | null; m_role: string | null; m_scope: string | null; m_seal: Buffer | null; m_last: Buffer | null; m_old: string | null; m_access: string | null;
  g_project: (string | null)[] | null; g_environment: (string | null)[] | null; g_slug: (string | null)[] | null; g_role: string[] | null; g_expires: (string | null)[] | null;
  r_value: string | null; r_seal: Buffer | null; r_last: Buffer | null;
  p_value: string | null; p_seal: Buffer | null; p_last: Buffer | null; cap_count: number | null; cap_window: string | null;
  s_project: string | null; s_environment: string | null; s_version: string | null; s_source: string | null; s_seal: Buffer | null; s_last: Buffer | null;
  x_project: string | null; x_environment: string | null; x_version: string | null; x_source: string | null; x_seal: Buffer | null; x_last: Buffer | null;
  v_envelope: number | null; v_ciphertext: Buffer | null; v_iv: Buffer | null; v_auth_tag: Buffer | null; v_wrapped_dek: Buffer | null;
  v_kek_provider: string | null; v_kek_id: string | null; v_kek_version: string | null; v_sensitive: boolean | null; v_plain: boolean | null;
  in_set: boolean | null; others: number | null;
} & Slot<'e1'> & Slot<'e2'> & Slot<'e3'> & Slot<'e4'>;

type Slot<N extends string> = {
  [K in `${N}_id` | `${N}_project` | `${N}_slug` | `${N}_owner` | `${N}_parent`]: string | null;
} & { [K in `${N}_protected` | `${N}_archived`]: boolean | null } & { [K in `${N}_seal` | `${N}_last`]: Buffer | null };

const SLOTS = ['e1', 'e2', 'e3', 'e4'] as const;

/**
 * What a use needs of its vault: its database, the keys it checks seals
 * with, the log's MAC key (`logMacKey`, the change path's and the
 * checkpointer's: one key, the tree under the MAC, KindInMac), its key
 * registry, and its isolate's cache.
 */
export type UsePath = { db: Queryable; sealKeys: SealKeys; macKey: Buffer; keks: KekRegistry; cache: UseCache };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const REQUEST_ID = /^(0|[1-9][0-9]{0,18})$/;

/** Why a use's input is not one: a bug of the app's, which fails the call. */
function checkInput(input: UseInput): void {
  if (!UUID.test(input.credential) || !UUID.test(input.secretId) || (input.place !== null && !UUID.test(input.place))) {
    throw new Error('a use names its credential, its key and its place, if any, by lowercase UUID');
  }
  if (!REQUEST_ID.test(input.requestId) || BigInt(input.requestId) >= 2n ** 63n) throw new Error('a use request id is a whole number below 2^63, as text');
  if (!Number.isSafeInteger(input.at) || !Number.isSafeInteger(input.deadline)) throw new Error("a use's time and deadline are whole ms since the epoch");
  if (input.keepsSensitive !== undefined && typeof input.keepsSensitive !== 'boolean') throw new Error('keepsSensitive is true, false or absent');
  if (!(PURPOSES as readonly string[]).includes(input.purpose)) throw new Error(`no purpose ${String(input.purpose)}`);
}

/** Busy answers: nothing was decided, ask again shortly. */
const busy = (why: UseBusy, retryAfter = 1): Extract<UseOutcome, { busy: UseBusy }> => ({ ok: false, busy: why, retryAfter });

/** One use, end to end (the module's comment says how). */
export async function use(path: UsePath, input: UseInput): Promise<UseOutcome> {
  checkInput(input);
  const { cache } = path;
  // A deadline the database would refuse (deadline_max) is refused here at no cost; one already past, too.
  if (input.deadline > input.at + USE_DEADLINE_MS || Date.now() >= input.deadline) return busy('late');
  if (cache.inFlight >= cache.limits.inFlight) return busy('overloaded');
  const request: UseRequest = {
    credential: input.credential, secretId: input.secretId, place: input.place, purpose: input.purpose,
    keepsSensitive: input.keepsSensitive === true, at: input.at,
  };
  const purpose = purposeCode(request);
  const key = `${input.credential}\n${input.secretId}\n${input.place ?? ''}`;
  const known = cache.seals.get(key);
  // A cover is of the same request but its id and time: the same credential, key, place and purpose.
  const coverKey = `${key}\n${purpose}`;
  const held = cache.covers.get(coverKey);
  // A cover a change this isolate knows of came after is no cover; one it cannot judge, the statement judges.
  const cover = held !== undefined && input.at < held.until && input.at >= held.at && (known?.inputs == null || BigInt(held.number) > BigInt(known.inputs)) ? held : undefined;
  const call: UseCall = {
    credential: input.credential, secretId: input.secretId, requestId: input.requestId, at: input.at, purpose, place: input.place,
    mac: entryMac(path.macKey, { tree: 'uses', row: { at: input.at, requestId: BigInt(input.requestId), credential: input.credential, secret: input.secretId, purpose, place: input.place } }),
    deadline: input.deadline,
    ...(cover === undefined ? {} : { cover }),
    ...(known === undefined ? {} : { known }),
  };
  const answered = await raced(path, call);
  if ('busy' in answered) return answered;
  const row = answered;
  if (row.state === 'late' || row.state === 'ahead' || row.state === 'unconfigured') return busy(row.state, row.state === 'unconfigured' ? 5 : 1);
  if (row.state !== null) throw new Error(`use_credential answered ${row.state}, which never leaves it`);
  const view = viewOf(row, request, row.probed ? undefined : known);
  if (row.probed && row.newest !== null) {
    cache.keep(cache.seals, key, {
      newest: row.newest, newestMac: row.newest_mac!, inputs: row.inputs, ids: view.ids,
      cap: { count: Number(row.cap_count), windowMs: Number(row.cap_window) }, last: lastsOf(row),
    });
  }
  // A row that names other objects than the cache's seals are of: `stale`, and the next use probes.
  if (view.view === null) cache.seals.delete(key);
  const code = view.view === null ? 'stale' : decided(path.sealKeys, view.view, request, view.accounted);
  if (row.covered !== null && code !== null) {
    // Refused on a cover (its credential's end, say): the request is logged as an entry of its own.
    cache.covers.delete(coverKey);
    return use(path, input);
  }
  if (code !== null) {
    cache.covers.delete(coverKey);
    return { ok: false, code, number: row.number };
  }
  const v = view.view!;
  if (row.covered === null) {
    const expires = v.credential.row!.expiresAt ?? Infinity;
    cache.keep(cache.covers, coverKey, { number: row.number!, at: input.at, requestId: input.requestId, until: Math.min(input.at + cache.limits.coverMs, expires) });
  }
  const opened = await open(path, v, row, input.deadline);
  if (opened === 'late') return busy('late');
  if (opened === 'bad_claim') return { ok: false, code: 'bad_claim', number: row.covered ?? row.number };
  return { ok: true, number: row.covered ?? row.number!, covered: row.covered !== null, value: opened };
}

/**
 * The call, raced against the deadline (WorkerHonoursDeadline): lost, the
 * use is answered `late`, and the call's row, if it ever comes, is
 * dropped. It counts against admission until it settles, holding its
 * connection until then.
 */
async function raced(path: UsePath, call: UseCall): Promise<UseRow | Extract<UseOutcome, { busy: UseBusy }>> {
  const { cache } = path;
  cache.inFlight += 1;
  const running = (engineOf(path.db) === 'postgres' ? callPostgres : callSqlite)(path.db, call).finally(() => {
    cache.inFlight -= 1;
  });
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<'late'>((resolve) => {
    timer = setTimeout(() => resolve('late'), Math.max(0, call.deadline - Date.now()));
  });
  try {
    const first = await Promise.race([running, deadline]);
    if (first === 'late') {
      running.catch(() => {});
      return busy('late');
    }
    return first;
  } catch (error) {
    // node-postgres's code, on the error drizzle wraps it in.
    const code = (error as { code?: string }).code ?? (error as { cause?: { code?: string } }).cause?.code;
    // A replay of a call that wrote: its entry stands, and its value never left. Not decided again.
    if (code === '23505') return busy('replayed');
    // Past its deadline by Postgres's clock, or a lock not had within the hot login's lock_timeout: nothing written.
    if (code === '57014' || code === '55P03') return busy('late');
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function lastsOf(row: UseRow): Lasts {
  return {
    c: row.c_last, m: row.m_last, mOld: row.m_old, r: row.r_last, p: row.p_last, s: row.s_last, x: row.x_last,
    e1: row.e1_last, e2: row.e2_last, e3: row.e3_last, e4: row.e4_last,
  };
}

/**
 * What the statement read, as PR 3's `UseView` (decide.ts): each input's
 * object, made from its row's columns (objects.ts), its seal, and its
 * newest change's, probed or the cache's. Null, the use `stale`, when the
 * rows name other objects than the cache's seals are of. `accounted`: the
 * principal's newest 0.14 access entry is one the new log accounts for
 * (UsesSeeOldWrites).
 */
export function viewOf(row: UseRow, request: UseRequest, known?: CachedSeals): { view: UseView | null; ids: string; accounted: boolean } {
  const last = known?.last ?? lastsOf(row);
  const read = <T extends Input>(object: T | null, seal: Buffer | null, newest: Buffer | null): Read<T> => ({ row: object, seal, newest });
  const credential = read(row.c_principal === null ? null : credentialObject({
    id: request.credential, principal: row.c_principal, kind: row.c_kind!, scope: row.c_scope, revoked: row.c_revoked === true,
    expiresAt: row.c_expires === null ? null : Number(row.c_expires),
  }), row.c_seal, last.c);
  const principal = row.c_principal === null ? null : read(row.m_status === null ? null : principalObject({
    principal: row.c_principal, status: row.m_status, ...memberStanding({ owner: row.m_owner === true, role: row.m_role, scope: row.m_scope }),
  }, grantsOf(row)), row.m_seal, last.m);
  const version = row.v_wrapped_dek === null ? null : {
    sensitive: row.v_sensitive === true, plain: row.v_plain === true, kekProvider: row.v_kek_provider!, kekId: row.v_kek_id!, kekVersion: row.v_kek_version!,
    wrappedDek: row.v_wrapped_dek.toString('base64'),
  };
  const secret = read(row.s_environment === null ? null : secretObject({
    id: request.secretId, projectId: row.s_project!, environmentId: row.s_environment, source: row.s_source,
    version: row.s_source === null && version !== null ? { id: row.s_version!, ...version } : null,
  }), row.s_seal, last.s);
  const source = row.s_source === null ? null : read(row.x_environment === null ? null : secretObject({
    id: row.s_source, projectId: row.x_project!, environmentId: row.x_environment, source: row.x_source,
    version: row.x_source === null && version !== null ? { id: row.x_version!, ...version } : null,
  }), row.x_seal, last.x);
  const environments = new Map<string, Read<EnvironmentInput>>();
  for (const slot of SLOTS) {
    const id = row[`${slot}_id`];
    if (id === null || environments.has(id)) continue;
    const project = row[`${slot}_project`];
    environments.set(id, read(project === null ? null : environmentObject({
      id, projectId: project, slug: row[`${slot}_slug`]!, owner: row[`${slot}_owner`], parentId: row[`${slot}_parent`],
      protected: row[`${slot}_protected`], archived: row[`${slot}_archived`] === true,
    }), row[`${slot}_seal`], last[slot]));
  }
  const view: UseView = {
    credential,
    principal,
    roles: read(row.r_value === null ? null : configObject(row.r_value) as RolesInput, row.r_seal, last.r),
    policy: read(row.p_value === null ? null : configObject(row.p_value) as PolicyInput, row.p_seal, last.p),
    secret,
    source,
    environments,
    bulk: credential.row === null ? null : { inSet: row.in_set === true, others: Number(row.others ?? 0) },
  };
  const ids = [request.credential, row.c_principal, request.secretId, row.s_source, ...SLOTS.map((slot) => row[`${slot}_id`])].join('\n');
  // UsesSeeOldWrites: 0.14's newest access entry about the principal, at or below the one its newest change accounts for.
  const old = last.mOld;
  const accounted = row.m_access === null || (old !== null && BigInt(row.m_access) <= BigInt(old));
  return { view: known !== undefined && known.ids !== ids ? null : view, ids, accounted };
}

function grantsOf(row: UseRow): InputGrant[] {
  return (row.g_role ?? []).map((role, i) => ({
    projectId: row.g_project![i] ?? null,
    environmentId: row.g_environment![i] ?? null,
    environmentSlug: row.g_slug![i] ?? null,
    role,
    expiresAt: row.g_expires![i] == null ? null : Number(row.g_expires![i]),
  }));
}

/**
 * PR 3's decision, with the principal `stale` too while 0.14 holds an
 * access entry about it that the new log does not account for
 * (Migration015.tla, UsesSeeOldWrites): a seal the principal's row passes
 * could still be one a late 0.14 revoke moved past. Checked with the
 * seals, before any row (StaleFirst).
 */
function decided(keys: SealKeys, view: UseView, request: UseRequest, accounted: boolean): UseCode | null {
  const checked = checkSeals(keys, view, request);
  const principal = checked.principal === null || accounted ? checked.principal : { ...checked.principal, current: false };
  return decideChecked({ ...checked, principal }, request);
}

/**
 * The value's data key, opened as its version's context binds it: its ids,
 * a personal config's owner, whether it is sensitive. Within the use's
 * deadline, which the key operation is bound by too: past it, nothing
 * leaves (`late`). A key that does not open as this value's is a claim the
 * rows do not bear out (`bad_claim`).
 */
async function open(path: UsePath, view: UseView, row: UseRow, deadline: number): Promise<UsedValue | 'late' | 'bad_claim'> {
  const secret = view.secret.row!;
  const value = secret.source === null ? secret : view.source!.row!;
  const owner = view.environments.get(value.environmentId)?.row?.owner ?? null;
  const context: SecretContext = {
    projectId: value.projectId, environmentId: value.environmentId, secretId: value.id,
    ...(owner === null ? {} : { owner: ownerKey(owner) }),
    ...(value.nature === 'sensitive' ? { sensitive: true as const } : {}),
  };
  const left = deadline - Date.now();
  if (left <= 0) return 'late';
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), left);
  let dek: Buffer;
  try {
    const wrapped = value.key!;
    dek = await path.keks.unwrap({ ...wrapped, bytes: Buffer.from(wrapped.bytes, 'base64') }, context, { deadline, signal: controller.signal });
  } catch (error) {
    if (error instanceof KekBadClaimError) return 'bad_claim';
    if (error instanceof KekUnavailableError && controller.signal.aborted) return 'late';
    throw error;
  } finally {
    clearTimeout(timer);
  }
  try {
    // Opened after its deadline: it never leaves.
    if (Date.now() >= deadline) return 'late';
    return {
      key: dek.toString('base64'),
      versionId: value.version,
      context,
      envelope: { version: row.v_envelope!, ciphertext: row.v_ciphertext!.toString('base64'), iv: row.v_iv!.toString('base64'), authTag: row.v_auth_tag!.toString('base64') },
    };
  } finally {
    dek.fill(0);
  }
}
