import { ownerKey, type SecretContext } from '@coffre/core/envelope';
import { KekBadClaimError, KekUnavailableError, type KekRegistry } from '@coffre/core/kek';
import { newUseRequestId, type Access, type NamedUseInput, type NamedUseOutcome, type UseBusy, type UseInput, type UseOutcome, type UsedValue } from '@coffre/core/vault';
import type { Queryable } from '@coffre/db';
import { engineOf } from '@coffre/db/dialect';

import { USE_DEADLINE_MS } from './bulk.ts';
import type { BulkLimit } from './config.ts';
import { checkSeals, decideChecked, readerOf, type CheckedView, type Read, type UseCode, type UseRequest, type UseView } from './decide.ts';
import type { EnvironmentInput, Input, InputGrant, PolicyInput, RolesInput, SealKeys } from './inputs.ts';
import { entryMac } from './log-entry.ts';
import { configObject, credentialObject, environmentObject, memberStanding, principalObject, secretObject } from './objects.ts';
import { PURPOSES, purposeCode } from './log-replay.ts';
import { callResolve as resolvePostgres, callUse as callPostgres } from './use.postgres.ts';
import { callResolve as resolveSqlite, callUse as callSqlite } from './use.sqlite.ts';

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

/** How long the standing a late named use asks after may take: a call that waits for no lock (`useNamed`). */
const STANDING_MS = 1_000;

/**
 * The settings of an isolate's uses: how many calls in flight at once, how long a cover holds, and how many requests'
 * names it maps to ids (`UseCache.names`; 0 maps none, each request then reads its ids: the bench's worst case).
 */
export type UseLimits = { inFlight: number; coverMs: number; names: number };

/**
 * How many uses an isolate has in flight at most, unless set: a pool of
 * `connections` serves that many at once, and a call past it would only
 * queue for a connection, holding its deadline. T112 measures the number
 * for Workers; here it is the pool's.
 */
export function useLimits(connections: number, set: Partial<UseLimits> = {}): UseLimits {
  return { inFlight: set.inFlight ?? Math.max(1, connections), coverMs: set.coverMs ?? 60_000, names: set.names ?? 10_000 };
}

/** An isolate's admission count, seal cache and covers. Bounded: past `max` entries, a map starts over. */
export class UseCache {
  inFlight = 0;
  readonly seals = new Map<string, CachedSeals>();
  readonly covers = new Map<string, Cover>();
  /**
   * What a request names, by its token's hash and place, mapped to ids (`useNamed`): ids only, never an answer, and
   * no key's (`keyIds`). The least recently used goes first past `limits.names` (`named`, `name`).
   */
  readonly names = new Map<string, Resolved>();
  /**
   * Each key's id by its environment and name, whoever asks (`keyed`, `key`): bounded on its own, so that names asked
   * and dropped leave none behind (review r3 of #412).
   */
  readonly keyIds = new Map<string, string>();
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

  /** The ids `key` names, if mapped, made the most recently used. */
  named(key: string): Resolved | undefined {
    return recall(this.names, key);
  }

  /** Maps `key` to its ids, the least recently used dropped past the cap. */
  name(key: string, ids: Resolved): void {
    remember(this.names, key, ids, this.limits.names);
  }

  /** The id of the key named `key` in `environment`, if mapped, made the most recently used. */
  keyed(environment: string, key: string): string | undefined {
    return recall(this.keyIds, `${environment}\n${key}`);
  }

  /** Maps a key's name in `environment` to its id, the least recently used dropped past the cap. */
  key(environment: string, key: string, id: string): void {
    remember(this.keyIds, `${environment}\n${key}`, id, this.limits.names);
  }

  /** Forgets the key named `key` in `environment`. */
  unkey(environment: string, key: string): void {
    this.keyIds.delete(`${environment}\n${key}`);
  }
}

/** A Map as an LRU: `key`'s value, moved to the end, the most recent; a Map iterates in the order of insertion. */
function recall<T>(map: Map<string, T>, key: string): T | undefined {
  const found = map.get(key);
  if (found !== undefined) {
    map.delete(key);
    map.set(key, found);
  }
  return found;
}

/** `key` mapped to `value`, the most recent, the least recent dropped past `cap` (0: none kept). */
function remember<T>(map: Map<string, T>, key: string, value: T, cap: number): void {
  map.delete(key);
  if (cap <= 0) return;
  if (map.size >= cap) map.delete(map.keys().next().value!);
  map.set(key, value);
}

/** One call of `use_credential` as the vault makes it: the request, its MAC, a cover and the cache, if any; `names`, what the request named. */
export type UseCall = {
  credential: string; secretId: string | null; requestId: string; at: number; purpose: number; place: string | null; mac: Buffer; deadline: number;
  cover?: Cover;
  known?: Pick<CachedSeals, 'newest' | 'newestMac' | 'cap'>;
  names?: Names;
};

/** What a request named, which the statement holds its rows to (`moved`), and answers the app's rows for (0044). */
export type Names = { tokenHash: Buffer; project: string | null; environment: string | null; key: string | null };

/**
 * The ids of what a request names, as `use_resolve` read them: its credential, its place, and each key it named
 * there. `shared`: a fork or a personal config, which the app reads as ever. Kept per token and place without its keys,
 * which `UseCache.keyIds` keeps by environment and name, each map's least recently used dropped past `UseLimits.names`:
 * about 250 and 120 bytes an entry, some 4 MB with both full at 10,000.
 */
export type Resolved = {
  credential: string | null; project: string | null; environment: string | null;
  /** The place's slugs as read, which a use with no place named is held to (`moved`) and the request told. */
  slugs: { project: string; environment: string } | null;
  shared: boolean; keys: Map<string, string>;
};

/** What `use_credential` answers (schema 0024's `use_row`), as node-postgres reads it; the SQLite twin answers the same. */
export type UseRow = {
  state: string | null; number: string | null; covered: string | null; newest: string | null; newest_mac: Buffer | null; inputs: string | null; probed: boolean;
  c_principal: string | null; c_kind: string | null; c_scope: string | null; c_revoked: boolean | null; c_expires: string | null; c_seal: Buffer | null; c_last: Buffer | null;
  m_status: string | null; m_owner: boolean | null; m_role: string | null; m_scope: string | null; m_seal: Buffer | null; m_last: Buffer | null; m_old: string | null; m_access: string | null;
  c_generation: number | null; m_generation: number | null;
  g_project: (string | null)[] | null; g_environment: (string | null)[] | null; g_slug: (string | null)[] | null; g_role: string[] | null; g_expires: (string | null)[] | null;
  r_value: string | null; r_seal: Buffer | null; r_last: Buffer | null;
  p_value: string | null; p_seal: Buffer | null; p_last: Buffer | null; cap_count: number | null; cap_window: string | null;
  s_project: string | null; s_environment: string | null; s_version: string | null; s_source: string | null; s_reference: string | null; s_seal: Buffer | null; s_last: Buffer | null;
  x_project: string | null; x_environment: string | null; x_version: string | null; x_source: string | null; x_reference: string | null; x_seal: Buffer | null; x_last: Buffer | null;
  v_envelope: number | null; v_ciphertext: Buffer | null; v_iv: Buffer | null; v_auth_tag: Buffer | null; v_wrapped_dek: Buffer | null;
  v_kek_provider: string | null; v_kek_id: string | null; v_kek_version: string | null; v_sensitive: boolean | null; v_plain: boolean | null; v_plaintext: string | null;
  in_set: boolean | null; others: number | null;
  /** The credential's token hash, and the rows the app checks, when the call named them (0044). */
  c_token_hash: Buffer | null; app: unknown;
} & Slot<'e1'> & Slot<'e2'> & Slot<'e3'> & Slot<'e4'>;

type Slot<N extends string> = {
  [K in `${N}_id` | `${N}_project` | `${N}_slug` | `${N}_owner` | `${N}_parent`]: string | null;
} & { [K in `${N}_protected` | `${N}_archived` | `${N}_project_archived`]: boolean | null } & { [K in `${N}_seal` | `${N}_last`]: Buffer | null };

const SLOTS = ['e1', 'e2', 'e3', 'e4'] as const;

/**
 * What a use needs of its vault: its database, the keys it checks seals
 * with, the log's MAC key (`logMacKey`, the change path's and the
 * checkpointer's: one key, the tree under the MAC, KindInMac), its key
 * registry, and its isolate's cache.
 */
export type UsePath = {
  db: Queryable;
  sealKeys: SealKeys;
  macKey: Buffer;
  keks: KekRegistry;
  cache: UseCache;
  /** What a call waits for first, within its admission (`inFlight`): an isolate's first, the log's cutover (vault.ts, `#cutOverYet`). */
  ready?: () => Promise<void>;
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const REQUEST_ID = /^(0|[1-9][0-9]{0,18})$/;

/** Why a use's input is not one: a bug of the app's, which fails the call. */
function checkInput(input: Pick<UseInput, 'requestId' | 'at' | 'deadline' | 'keepsSensitive' | 'purpose'>): void {
  if (!REQUEST_ID.test(input.requestId) || BigInt(input.requestId) >= 2n ** 63n) throw new Error('a use request id is a whole number below 2^63, as text');
  if (!Number.isSafeInteger(input.at) || !Number.isSafeInteger(input.deadline)) throw new Error("a use's time and deadline are whole ms since the epoch");
  if (input.keepsSensitive !== undefined && typeof input.keepsSensitive !== 'boolean') throw new Error('keepsSensitive is true, false or absent');
  if (!(PURPOSES as readonly string[]).includes(input.purpose)) throw new Error(`no purpose ${String(input.purpose)}`);
}

function checkIds(input: { credential: string; secretId: string | null; place: string | null }): void {
  if (!UUID.test(input.credential) || (input.secretId !== null && !UUID.test(input.secretId)) || (input.place !== null && !UUID.test(input.place))) {
    throw new Error('a use names its credential, its key and its place, if any, by lowercase UUID');
  }
}

/** Busy answers: nothing was decided, ask again shortly. */
const busy = (why: UseBusy, retryAfter = 1): Extract<UseOutcome, { busy: UseBusy }> => ({ ok: false, busy: why, retryAfter });

/** One use, end to end (the module's comment says how). */
export async function use(path: UsePath, input: UseInput): Promise<UseOutcome> {
  checkInput(input);
  checkIds(input);
  const used = await useOnce(path, input);
  if ('moved' in used || 'unnamed' in used) throw new Error('use_credential answered a named state to a use that named nothing');
  // A plain value is the app's to hand back on a use by ids, as 0.14's vault never decides one: only a named use hands one back.
  if ('plain' in used.outcome) return { ok: false, code: 'bad_claim', number: null };
  return used.outcome;
}

/**
 * A use's answer inside the vault: its outcome, its row, the view it decided on, if it got that far; or `moved`; or
 * `unnamed`, a place it reads archived, which the app answers itself.
 */
type Used = { moved: true } | { unnamed: true } | { outcome: UseOutcome | { ok: true; plain: string; versionId: string }; row: UseRow | null; checked: CheckedView | null; request: UseRequest };

/**
 * One call of `use_credential`, by ids, and the decision on its row. `secretId` null with `place`: a key the place
 * does not hold, decided on the caller's standing there (Probing.tla, MissingByStanding); a plain value, decided as
 * any and handed back as its text, which its object's digest binds (PlainByStanding). Neither leaves an entry, nor a
 * cover. `names`: what the request named, which the statement holds its rows to, answering `moved` if they are no
 * longer those, having written nothing.
 */
async function useOnce(
  path: UsePath,
  input: Pick<UseInput, 'credential' | 'place' | 'purpose' | 'keepsSensitive' | 'requestId' | 'at' | 'deadline'> & { secretId: string | null },
  names?: Names,
  /** Within the place in admission a call of the same request held: not refused for want of one. */
  reserved = false,
): Promise<Used> {
  const { cache } = path;
  const request: UseRequest = {
    credential: input.credential, secretId: input.secretId ?? '', place: input.place, purpose: input.purpose,
    keepsSensitive: input.keepsSensitive === true, at: input.at,
  };
  // A deadline the database would refuse (deadline_max) is refused here at no cost; one already past, too.
  if (input.deadline > input.at + USE_DEADLINE_MS || Date.now() >= input.deadline) return { outcome: busy('late'), row: null, checked: null, request };
  if (!reserved && cache.inFlight >= cache.limits.inFlight) return { outcome: busy('overloaded'), row: null, checked: null, request };
  const purpose = purposeCode(request);
  const key = `${input.credential}\n${input.secretId ?? ''}\n${input.place ?? ''}`;
  const known = cache.seals.get(key);
  // A cover is of the same request but its id and time: the same credential, key, place and purpose.
  const coverKey = `${key}\n${purpose}`;
  const held = input.secretId === null ? undefined : cache.covers.get(coverKey);
  // A cover a change this isolate knows of came after is no cover; one it cannot judge, the statement judges.
  const cover = held !== undefined && input.at < held.until && input.at >= held.at && (known?.inputs == null || BigInt(held.number) > BigInt(known.inputs)) ? held : undefined;
  const call: UseCall = {
    credential: input.credential, secretId: input.secretId, requestId: input.requestId, at: input.at, purpose, place: input.place,
    mac: entryMac(path.macKey, { tree: 'uses', row: { at: input.at, requestId: BigInt(input.requestId), credential: input.credential, secret: input.secretId ?? '', purpose, place: input.place } }),
    deadline: input.deadline,
    ...(cover === undefined ? {} : { cover }),
    ...(known === undefined ? {} : { known }),
    ...(names === undefined ? {} : { names }),
  };
  const answered = await raced(path, call);
  if ('busy' in answered) return { outcome: answered, row: null, checked: null, request };
  const row = answered;
  if (row.state === 'moved') return { moved: true };
  if (row.state === 'unnamed') return { unnamed: true };
  if (row.state === 'late' || row.state === 'ahead' || row.state === 'unconfigured') return { outcome: busy(row.state, row.state === 'unconfigured' ? 5 : 1), row, checked: null, request };
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
  const checked = view.view === null ? null : checkedOf(path.sealKeys, view.view, request, view.accounted);
  const code = checked === null ? 'stale' : decideChecked(checked, request);
  if (row.covered !== null && code !== null) {
    // Refused on a cover (its credential's end, say): the request is logged as an entry of its own.
    cache.covers.delete(coverKey);
    return useOnce(path, input, names);
  }
  if (code !== null) {
    cache.covers.delete(coverKey);
    return { outcome: { ok: false, code, number: row.number }, row, checked, request };
  }
  const v = view.view!;
  const secret = v.secret.row!;
  const value = secret.source === null ? secret : v.source!.row!;
  // A plain value, decided: its text, which its object's digest binds; no entry, no cover (it counts toward nothing).
  if (value.key === null) return { outcome: { ok: true, plain: row.v_plaintext!, versionId: value.version }, row, checked, request };
  if (row.covered === null) {
    const expires = v.credential.row!.expiresAt ?? Infinity;
    cache.keep(cache.covers, coverKey, { number: row.number!, at: input.at, requestId: input.requestId, until: Math.min(input.at + cache.limits.coverMs, expires) });
  }
  const opened = await open(path, v, row, input.deadline);
  if (opened === 'late') return { outcome: busy('late'), row, checked, request };
  if (opened === 'bad_claim') return { outcome: { ok: false, code: 'bad_claim', number: row.covered ?? row.number }, row, checked, request };
  return { outcome: { ok: true, number: row.covered ?? row.number!, covered: row.covered !== null, value: opened }, row, checked, request };
}

/**
 * A use as the request names it (T145, PR B; formal/Probing.tla, Credentials.tla Revoking015Caller): the ids of
 * what it names from this isolate's map, or one read of them on a miss (`use_resolve`), then one use by them, which
 * holds its rows to the names (`moved`) and answers the rows the app checks. A map out of date (`moved`, or a key the
 * place no longer holds by the id kept) is dropped and read again, once: that attempt wrote nothing and released
 * nothing. One admission for the whole call, checked before anything is read, so that a busy answer never hangs on
 * whether a key is held.
 */
export async function useNamed(path: UsePath, input: NamedUseInput): Promise<NamedUseOutcome> {
  checkInput(input);
  if ((input.key !== null && (typeof input.key !== 'string' || input.key === '')) || typeof input.tokenHash !== 'string') throw new Error('a named use names its token, by hash, and its key, if any');
  const { cache } = path;
  const tokenHash = Buffer.from(input.tokenHash, 'base64');
  const answered = (outcome: UseOutcome) => ({ served: true as const, secretId: null, outcome, app: null, standing: null, place: input.place });
  if (input.deadline > input.at + USE_DEADLINE_MS || Date.now() >= input.deadline) return answered(busy('late'));
  if (cache.inFlight >= cache.limits.inFlight) return answered(busy('overloaded'));
  const at = `${input.tokenHash}\n${input.place?.project ?? ''}\n${input.place?.environment ?? ''}`;
  for (let attempt = 0; ; attempt += 1) {
    let found = cache.named(at);
    let keyed = found?.environment == null || input.key === null ? undefined : cache.keyed(found.environment, input.key);
    // A key the map holds no id for is read again: one made since is found, one never made costs the read.
    const fresh = found === undefined || (input.key !== null && keyed === undefined);
    if (fresh) {
      const read = await resolved(path, tokenHash, input.place, input.key === null ? [] : [input.key], input.deadline);
      if (read === 'late') return answered(busy('late'));
      found = read;
      keyed = input.key === null ? undefined : read.keys.get(input.key);
      if (read.credential !== null && !read.shared) {
        cache.name(at, { ...read, keys: new Map() });
        if (read.environment !== null) for (const [name, id] of read.keys) cache.key(read.environment, name, id);
      }
    }
    // An unknown token: refused as one, whatever it names (`credential`, as a use of an ended one).
    if (found!.credential === null) return answered({ ok: false, code: 'credential', number: null });
    // A fork, a personal config, a handle of several environments or none: the app reads those as ever.
    if (found!.shared || found!.environment === null || found!.slugs === null) return { served: false };
    const ids = found!;
    // The handle's own place, which the request does not mean: the app routes it as ever.
    const slugs = input.place ?? ids.slugs!;
    if (input.place === null && (input.unless ?? []).some((other) => other.project === slugs.project && other.environment === slugs.environment)) return { served: false };
    const secretId = input.key === null ? null : keyed ?? null;
    // Held to the slugs it is at, named or the handle's as read: renamed since, `moved`, and read again.
    const names: Names = { tokenHash, project: slugs.project, environment: slugs.environment, key: input.key };
    const used = await useOnce(path, {
      credential: ids.credential!, secretId, place: secretId === null ? ids.environment : null,
      purpose: input.purpose, keepsSensitive: input.keepsSensitive, requestId: input.requestId, at: input.at, deadline: input.deadline,
    }, names);
    // A place it reads archived: the app answers it, as it did before any use by name.
    if ('unnamed' in used) return { served: false };
    // Out of date: dropped and read again, once. A key gone by the id kept may have been made again under its name.
    const stale = 'moved' in used || (!fresh && secretId !== null && !used.outcome.ok && 'code' in used.outcome && used.outcome.code === 'missing');
    if (stale && attempt === 0) {
      cache.names.delete(at);
      if (input.key !== null) cache.unkey(ids.environment!, input.key);
      continue;
    }
    if ('moved' in used) return answered(busy('late'));
    // Late: a use of a key held may have waited for its principal's lock, for the cap's row of a key it has not used in
    // the window, which a key never made never does; whatever the key, its history is the caller's to shape. So the
    // caller's standing at the place decides first, in a call that takes no lock and reads no key: refused there, the
    // request is refused as for any key; otherwise it stays busy (Probing.tla, ConfirmStandingOnLate; review r2 of #412).
    // It runs within the place the use held in admission, once the use's call has let it go, never refused for want of
    // one: else the late use's own call, still running, would leave it none (ConfirmReserved; review r3 of #412).
    if (secretId !== null && !used.outcome.ok && 'busy' in used.outcome && used.outcome.busy === 'late') {
      await leftBehind.get(used.outcome);
      const now = Date.now();
      const stood = await useOnce(path, {
        credential: ids.credential!, secretId: null, place: ids.environment, purpose: input.purpose, keepsSensitive: input.keepsSensitive,
        requestId: newUseRequestId(), at: now, deadline: now + STANDING_MS,
      }, { ...names, key: null }, true);
      if ('outcome' in stood && stood.checked !== null && !stood.outcome.ok && 'code' in stood.outcome && stood.outcome.code !== 'missing') {
        return {
          served: true, secretId, outcome: stood.outcome, app: stood.row?.app == null ? null : JSON.stringify(stood.row.app),
          standing: standingOf(stood.checked, stood.request), place: slugs,
        };
      }
    }
    return {
      served: true,
      secretId,
      outcome: used.outcome,
      app: used.row?.app == null ? null : JSON.stringify(used.row.app),
      standing: used.checked === null ? null : standingOf(used.checked, used.request),
      place: slugs,
    };
  }
}

/** One read of the ids a request names (`use_resolve`), within its deadline, as a call admitted as a use is. */
async function resolved(path: UsePath, tokenHash: Buffer, place: NamedUseInput['place'], keys: readonly string[], deadline: number): Promise<Resolved | 'late'> {
  const { cache } = path;
  cache.inFlight += 1;
  // Counted until the read settles, not until its deadline: one left behind still holds its connection (review r1).
  const read = (engineOf(path.db) === 'postgres' ? resolvePostgres : resolveSqlite)(path.db, { tokenHash, place, keys }).finally(() => {
    cache.inFlight -= 1;
  });
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<'late'>((resolve) => {
    timer = setTimeout(() => resolve('late'), Math.max(0, deadline - Date.now()));
  });
  try {
    const first = await Promise.race([read, late]);
    if (first === 'late') read.catch(() => {});
    return first;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * What the use decided the caller holds, as `access` answers it, from the sealed rows it read (`readerOf`): their
 * standing, role, scope and live grants, and the policy as far as the environments it weighed, which is all the app
 * then checks (the place it reads). Null where the decision did not reach them.
 */
function standingOf(checked: CheckedView, request: UseRequest): Access | null {
  const credential = checked.credential.row;
  if (credential === null || checked.principal === null) return null;
  // Only from rows the vault's seals bear out, each its object's newest: one put back or written around the log (a
  // grant restored by a writer) is no standing, and the app asks the vault as before (review r1).
  const inputs = [checked.credential, checked.principal, checked.roles, checked.policy, ...checked.environments.values()];
  if (inputs.some((input) => !input.valid || !input.current)) return null;
  const rows = [...checked.environments.values()].flatMap((read) => (read.row === null ? [] : [read.row]));
  const reader = readerOf(checked.principal.row, credential, checked.roles.row ?? { kind: 'roles', roles: {}, instanceRoles: {} }, rows, request.at);
  const principal = checked.principal.row;
  const live = reader.live;
  return {
    principal: credential.principal,
    status: reader.status,
    generation: principal?.generation ?? 0,
    role: live.role,
    scope: live.scope,
    grants: reader.status !== 'active' || principal === null
      ? []
      : principal.grants.filter((grant) => grant.expiresAt === null || grant.expiresAt > request.at).map(({ projectId, environmentId, role, expiresAt }) => ({ projectId, environmentId, role, expiresAt })),
    since: null,
    by: null,
    ...(live.policy === undefined ? {} : { policy: live.policy }),
  } as Access;
}

/**
 * The call, raced against the deadline (WorkerHonoursDeadline): lost, the
 * use is answered `late`, and the call's row, if it ever comes, is
 * dropped. It counts against admission until it settles, holding its
 * connection until then.
 */
/** A `late` answer's call, left behind at its deadline, settled: what a use that asks again within its place waits for. */
const leftBehind = new WeakMap<object, Promise<void>>();

async function raced(path: UsePath, call: UseCall): Promise<UseRow | Extract<UseOutcome, { busy: UseBusy }>> {
  const { cache } = path;
  cache.inFlight += 1;
  const running = (async () => {
    await path.ready?.();
    return (engineOf(path.db) === 'postgres' ? callPostgres : callSqlite)(path.db, call);
  })().finally(() => {
    cache.inFlight -= 1;
  });
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<'late'>((resolve) => {
    timer = setTimeout(() => resolve('late'), Math.max(0, call.deadline - Date.now()));
  });
  try {
    const first = await Promise.race([running, deadline]);
    if (first === 'late') {
      const late = busy('late');
      // Its call left behind, which still holds its place in admission until it settles.
      leftBehind.set(late, running.then(() => undefined, () => undefined));
      return late;
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
    expiresAt: row.c_expires === null ? null : Number(row.c_expires), generation: row.c_generation!,
  }), row.c_seal, last.c);
  const principal = row.c_principal === null ? null : read(row.m_status === null ? null : principalObject({
    principal: row.c_principal, status: row.m_status, generation: row.m_generation!, ...memberStanding({ owner: row.m_owner === true, role: row.m_role, scope: row.m_scope }),
  }, grantsOf(row)), row.m_seal, last.m);
  // A plain value's text, which its object's digest binds.
  const version = row.v_wrapped_dek === null ? null : {
    sensitive: row.v_sensitive === true, plaintext: row.v_plaintext,
    kekProvider: row.v_kek_provider!, kekId: row.v_kek_id!, kekVersion: row.v_kek_version!, wrappedDek: row.v_wrapped_dek.toString('base64'),
  };
  const secret = read(row.s_environment === null ? null : secretObject({
    id: request.secretId, projectId: row.s_project!, environmentId: row.s_environment, source: row.s_source, reference: row.s_reference,
    version: row.s_source === null && version !== null ? { id: row.s_version!, ...version } : null,
  }), row.s_seal, last.s);
  const source = row.s_source === null ? null : read(row.x_environment === null ? null : secretObject({
    id: row.s_source, projectId: row.x_project!, environmentId: row.x_environment, source: row.x_source, reference: row.x_reference,
    version: row.x_source === null && version !== null ? { id: row.x_version!, ...version } : null,
  }), row.x_seal, last.x);
  const environments = new Map<string, Read<EnvironmentInput>>();
  for (const slot of SLOTS) {
    const id = row[`${slot}_id`];
    if (id === null || environments.has(id)) continue;
    const project = row[`${slot}_project`];
    environments.set(id, read(project === null ? null : environmentObject({
      id, projectId: project, slug: row[`${slot}_slug`]!, owner: row[`${slot}_owner`], parentId: row[`${slot}_parent`],
      protected: row[`${slot}_protected`], archived: row[`${slot}_archived`] === true, projectArchived: row[`${slot}_project_archived`] === true,
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
 * The view checked as PR 3's decision takes it, with the principal `stale`
 * too while 0.14 holds an access entry about it that the new log does not
 * account for (Migration015.tla, UsesSeeOldWrites): a seal the principal's
 * row passes could still be one a late 0.14 revoke moved past. Checked with
 * the seals, before any row (StaleFirst).
 */
function checkedOf(keys: SealKeys, view: UseView, request: UseRequest, accounted: boolean): CheckedView {
  const checked = checkSeals(keys, view, request);
  const principal = checked.principal === null || accounted ? checked.principal : { ...checked.principal, current: false };
  return { ...checked, principal };
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
