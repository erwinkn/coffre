import { NOTHING } from '@coffre/core/access';
import { ownerKey, type SecretContext } from '@coffre/core/envelope';
import { KekBadClaimError, KekUnavailableError, type KekRegistry } from '@coffre/core/kek';
import { type Access, type CredentialAcceptance, type NamedKey, type NamedManyInput, type NamedManyOutcome, type NamedUseInput, type NamedUseOutcome, type NamedValue, newUseRequestId, type UseBusy, type UseInput, type UseManyInput, type UseManyOutcome, type UseOutcome, type UsedValue } from '@coffre/core/vault';
import type { Queryable } from '@coffre/db';
import { engineOf } from '@coffre/db/dialect';

import { USE_DEADLINE_MS } from './bulk.ts';
import type { BulkLimit } from './config.ts';
import { checkSeals, credentialEnded, decideChecked, readerOf, standingRefusal, useEnvironments, type CheckedView, type Read, type UseCode, type UseRequest, type UseView, type Way, type WayInput } from './decide.ts';
import { noEdits, objectKey, sealedOnce, type EnvironmentInput, type Input, type InputGrant, type PolicyInput, type RolesInput, type SealKeys, type sealed } from './inputs.ts';
import { entryMac, MAC_BYTES, TAG_BYTES, type LogMacKey } from './log-entry.ts';
import { bindingObject, configObject, connectionObject, credentialObject, environmentObject, memberStanding, principalObject, secretObject } from './objects.ts';
import { PURPOSES, purposeCode, WAYS } from './log-replay.ts';
import { callBatch as batchPostgres, callNamedBatch as namedPostgres, callUse as callPostgres } from './use.postgres.ts';
import { callBatch as batchSqlite, callNamedBatch as namedSqlite, callUse as callSqlite } from './use.sqlite.ts';

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
 *   once, `overloaded`, holding no connection (R44). A call's place is
 *   given back when it settles; on Workers, where a call may never settle,
 *   at the latest `HELD_PAST_DEADLINE_MS` past its deadline (`UseCache`);
 * - **the deadline:** at most 3 s from the request's time (R53, R54). The
 *   call is raced against it and answered `late` when it loses; Postgres
 *   holds it too (DeadlineChecked), and a value whose call returns after
 *   it never leaves (WorkerHonoursDeadline);
 * - **the seal cache:** each key's inputs' newest seals and the cap, as of
 *   the log's newest change (its number and MAC), which the next call
 *   names so that its statement probes nothing while that change is still
 *   the newest (CacheChecked, CacheSameChange);
 * - **covers:** a repeat of an allowed use rides its entry, writing none,
 *   while no input changed since and the key's bulk row is fresh;
 * - **no decision** for a use to take its principal's lock on (T158, D153):
 *   a named use that would take it makes a call that locks and writes
 *   nothing, decides the use on its rows (`decide`), and only then makes it,
 *   in a second call (DecideBeforeLock, DecideEachLock).
 */

export type { NamedManyInput, NamedManyOutcome, UseInput, UseManyInput, UseManyOutcome, UseOutcome, UsedValue };

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
  /** Which object each seal is of, as the rows named them: an input whose row names another now reads nothing from here. */
  ids: Identities;
  last: Lasts;
};

/** Which object each input's row is of (the credential, its principal, the key, its source, each place): the seals' keys. */
type Identities = Record<'c' | 'm' | 's' | 'x' | (typeof SLOTS)[number], string | null>;

/** Each input's newest change's seal, and the 0.14 entry the principal's accounts for. */
type Lasts = {
  c: Buffer | null; m: Buffer | null; mOld: string | null; r: Buffer | null; p: Buffer | null; s: Buffer | null; x: Buffer | null;
  e1: Buffer | null; e2: Buffer | null; e3: Buffer | null; e4: Buffer | null;
};

export type Cover = { number: string; at: number; requestId: string; until: number };

/**
 * The settings of an isolate's uses: how many calls in flight at once, how long a cover holds, and how many requests'
 * names it maps to ids (`UseCache.names`; 0 maps none, each request then reads its ids: the bench's worst case).
 */
export type UseLimits = {
  inFlight: number; coverMs: number; names: number;
  /**
   * The most keys a statement of a batch makes uses of (`useMany`): each statement holds the fence for its keys' uses,
   * about 0.4 ms a key, and a change or the checkpointer's barrier waits behind it, every use queued behind that (R44).
   * A batch of more is made in statements of this many, in turn (review r2 of #433): 100 hold the fence about 40 ms.
   */
  batch: number;
};

/**
 * How many uses an isolate has in flight at most, unless set: a pool of
 * `connections` serves that many at once, and a call past it would only
 * queue for a connection, holding its deadline. T112 measures the number
 * for Workers; here it is the pool's.
 */
export function useLimits(connections: number, set: Partial<UseLimits> = {}): UseLimits {
  return { inFlight: set.inFlight ?? Math.max(1, connections), coverMs: set.coverMs ?? 60_000, names: set.names ?? 10_000, batch: Math.max(1, set.batch ?? 100) };
}

/**
 * How long past its deadline a call keeps its place at most where places lapse (`UseCache`, Workers): the hot login's
 * `statement_timeout` (`coffre setup`'s HOT_SETTINGS, `migrate`). On Workers a call's connection is its own, closed
 * at its deadline at the latest (cloudflare.ts, `HyperdrivePool.end`), or with its request if that ends first: what
 * the call asked and Hyperdrive had not sent goes with it, and what reached Postgres by then Postgres ends within its
 * `statement_timeout`. So by this long past the deadline nothing of the call's holds a connection, whether its
 * promise ever settles or not, which on Workers it may never do: its I/O is gone with its request (AGENTS.md, "What
 * an isolate keeps"). Counted until it settled, each such call kept its place until the isolate was recycled (T170).
 */
export const HELD_PAST_DEADLINE_MS = 2_000;

/**
 * An isolate's admission, seal cache and covers. Bounded: past `max` entries, a map starts over.
 *
 * A call holds its place in admission until it settles. With `callsEndWithRequest` (Workers), at most until `HELD_PAST_DEADLINE_MS`
 * past its deadline, settled or not; without (Node), until it settles, as it always does there, its I/O never torn
 * down under it: a call stuck queued for the hot pool or reading past its deadline (`oldWrite`) holds the pool too,
 * and counts until it lets go, so that no call abandoned piles more on the pool (review r1 of #438).
 */
export class UseCache {
  /** Each call admitted and not settled, by when its place lapses (`admit`): a time, never work in flight. */
  readonly #admitted = new Set<{ until: number }>();
  readonly #lapses: boolean;
  readonly seals = new Map<string, CachedSeals>();
  readonly covers = new Map<string, Cover>();
  /**
   * What a request names, by its token's hash and place, mapped to ids (`useNamed`): ids only, never an answer, and
   * no key's (`keyIds`). The least recently used goes first past `limits.names` (`named`, `name`). They only let a
   * named use's first call make the use: what it reads, it reads by the request's names (D153).
   */
  readonly names = new Map<string, Resolved>();
  /**
   * Each key's id by its environment and name, whoever asks (`keyed`, `key`), or null for a name the environment held
   * no key of when read: bounded on its own, so that names asked and dropped leave none behind (review r3 of #412).
   */
  readonly keyIds = new Map<string, KeyId | null>();
  readonly limits: UseLimits;
  readonly max: number;

  constructor(limits: UseLimits, { max = 10_000, callsEndWithRequest = false }: { max?: number; callsEndWithRequest?: boolean } = {}) {
    this.limits = limits;
    this.max = max;
    this.#lapses = callsEndWithRequest;
  }

  /** How many calls hold a place now: admitted, not settled, and not lapsed. */
  get inFlight(): number {
    const now = Date.now();
    for (const slot of this.#admitted) if (slot.until <= now) this.#admitted.delete(slot);
    return this.#admitted.size;
  }

  /** Whether the next call is refused, `overloaded`. */
  full(): boolean {
    return this.inFlight >= this.limits.inFlight;
  }

  /** A place for a call due by `deadline`, given back once it settles (what this answers), unless it lapsed first. */
  admit(deadline: number): () => void {
    const slot = { until: this.#lapses ? deadline + HELD_PAST_DEADLINE_MS : Infinity };
    this.#admitted.add(slot);
    return () => this.#admitted.delete(slot);
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

  /** The id of the key named `key` in `environment`, or null for none, if mapped, made the most recently used. */
  keyed(environment: string, key: string): KeyId | null | undefined {
    return recall(this.keyIds, `${environment}\n${key}`);
  }

  /** Maps a key's name in `environment` to its id, or null for none, the least recently used dropped past the cap. */
  key(environment: string, key: string, id: KeyId | null): void {
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

/**
 * One call of `use_credential` as the vault makes it: the request, its MAC, a cover and the cache, if any; `names`,
 * what the request named, which a named call reads by. Its credential none: the isolate's map holds no ids for the
 * names, and the call makes no use, only reads them (D153).
 */
export type UseCall = {
  credential: string | null; secretId: string | null; requestId: string; at: number; purpose: number; place: string | null; mac: Buffer; deadline: number;
  /** Its way in (`WAYS`'s index: a credential, 0), and behind Access the person, `credential` their object's key (T147). */
  way: number; principal: string | null;
  cover?: Cover;
  known?: Pick<CachedSeals, 'newest' | 'newestMac' | 'cap'>;
  names?: Names;
  /** The call a named use makes once the vault has decided the use on the rows of one that answered `decide` or `moved`. */
  decided?: true;
};

/**
 * What a request named, which a named call reads by (0045, D153), and answers the app's rows for (0044). `handle`: it
 * named no place, and means its handle's own.
 */
/**
 * What a named call names (0045): its token's hash, its place by slugs, or the handle's own (`handle`), and its key.
 * `unless`, a handle's: the places, `project/environment`, its request does not mean, which the call judges against the
 * slugs it reads (never the map's), answering them as none, the app's.
 */
export type Names = {
  tokenHash: Buffer; project: string | null; environment: string | null; key: string | null; handle: boolean; unless: readonly string[];
  /** What the app's config accepts of a credential (`NamedUseInput.accepts`), which the call holds the token's to first. */
  accepts: CredentialAcceptance;
  /** Whether the app reads a fork's and `dev@me`'s answer by name (`NamedUseInput.forks`, T165): else the call serves neither. */
  forks: boolean;
};

/**
 * The ids of what a request names, as a named call read them: its credential and its place, and the place's slugs.
 * Kept per token and place without its keys, which `UseCache.keyIds` keeps by environment and name, each map's least
 * recently used dropped past `UseLimits.names`: about 200 and 120 bytes an entry, some 3 MB with both full at 10,000.
 */
export type Resolved = { credential: string; environment: string; slugs: { project: string; environment: string } };

/**
 * A key's id as its place's name reads it (`UseCache.keyIds`): held there, or, `through`, one a fork or a personal
 * config inherits, which a use reads through the place (T165).
 */
export type KeyId = { id: string; through: boolean };

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
  /** What a named call's names name now: its credential, key and place, by id, and the place's slugs (0045, D153). */
  n_credential: string | null; n_secret: string | null; n_place: string | null; n_project: string | null; n_environment: string | null;
  /**
   * Whether a named call found its caller standing at the place, for its purpose, and so read its key (`use_stands`,
   * W268): false, it read no key and answered on the place alone, as for a key the place does not hold.
   */
  n_standing: boolean | null;
  /**
   * Whether a named call found its place's chain cut (a parent archived, deleted or not there, or a chain that loops or
   * runs past 3; 0051, T165): the place reads nothing, and the call read no key, answered on the place alone.
   */
  n_cut: boolean | null;
  /** A Cloudflare binding's row, which a use through it read whole, its object (T147): as `to_json` writes it. */
  w_row: Record<string, unknown> | null;
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
  macKey: LogMacKey;
  keks: KekRegistry;
  cache: UseCache;
  /**
   * What a call waits for first, within its admission: an isolate's first, the log's cutover (vault.ts, `#cutOverYet`).
   * Within it, as on Workers it reads on the call's one connection; however long it waits, its place lapses as any does.
   */
  ready?: () => Promise<void>;
  /**
   * Whether `principal`'s newest 0.14 access entry that carries the vault's
   * MAC, at or below `through`, is past `old`, the newest its newest change
   * accounts for (null: none): asked only when the statement's probe, which
   * reads any entry in the vault's name, found one past it, `through`
   * (UsesSeeOldWrites). An entry forged there is passed over (vault.ts,
   * `#oldWrite`), which writes nothing. Never past `through`: the use's
   * statement committed before this reads, and an entry since is no input it
   * decided on. Absent, the probe's answer stands. `starts`, before each
   * statement it sends: it throws once the use has lost its race, whose
   * answer has gone, so that the reads stop there (`raced`).
   */
  oldWrite?: (principal: string, old: bigint | null, through: bigint, starts: () => void) => Promise<boolean>;
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

function checkIds(input: { credential: string; secretId: string | null; place: string | null; way?: unknown }): void {
  if (input.way !== undefined && !(WAYS as readonly unknown[]).includes(input.way)) throw new Error(`no way in ${String(input.way)}`);
  // Behind Access, the account: a `user:` or a `token:`, as `vault_members` holds them.
  const named = input.way === 'access' ? /^(user|token):[^\s]{1,320}$/.test(input.credential) : UUID.test(input.credential);
  if (!named || (input.secretId !== null && !UUID.test(input.secretId)) || (input.place !== null && !UUID.test(input.place))) {
    throw new Error('a use names its way in, its key and its place, if any, by lowercase UUID; behind Access, its account');
  }
}

/**
 * A use's way in as its entry names it (T147): a credential's, a connection's or a binding's id; behind Access, the
 * person's object's key, and the person beside it, which the call reads their row by.
 */
function wayOf(input: Pick<UseInput, 'credential' | 'way'>): { credential: string; way: Way; principal: string | null } {
  const way = input.way ?? 'credential';
  return way === 'access'
    ? { credential: objectKey({ kind: 'principal', id: input.credential }), way, principal: input.credential }
    : { credential: input.credential, way, principal: null };
}

/** Busy answers: nothing was decided, ask again shortly. */
const busy = (why: UseBusy, retryAfter = 1): Extract<UseOutcome, { busy: UseBusy }> => ({ ok: false, busy: why, retryAfter });

/** One use, end to end (the module's comment says how). */
export async function use(path: UsePath, input: UseInput): Promise<UseOutcome> {
  checkInput(input);
  checkIds(input);
  const asked = { ...input, ...wayOf(input) };
  let used = await useOnce(path, asked);
  // Its key would take its principal's lock: decided first, as a named use is, and made by a second call once allowed;
  // refused, nothing written, which the app logs (`number` null; review r2 of D153, DecideBeforeLock).
  if ('again' in used) used = await useOnce(path, asked, undefined, true);
  if (!('outcome' in used)) throw new Error('use_credential answered a named state to a use that named nothing');
  // A plain value is the app's to hand back on a use by ids, as 0.14's vault never decides one: `decideChecked` refuses
  // it, `bad_claim`, live and replayed alike; only a named use hands one back.
  if ('plain' in used.outcome) throw new Error('a use by ids was handed a plain value');
  return used.outcome;
}

/**
 * A request's several keys, one call (T167, B2; formal/Batching.tla; migration 0048, `use_batch`): each key's use made
 * as `use` makes it, by ids, in the request's order, in one statement (of at most `limits.batch` keys: more are made
 * in statements of that many, in turn), and decided on what it read (`settle`), under one admission and one deadline. Then, only once every key is allowed on those rows (AllDecidedFirst), one more call
 * for the keys that would take the principal's lock, which answered `decide` having written and locked nothing: it
 * takes the lock exclusive before its first key (StrongestFirst), and each key is decided again on what it reads then.
 * Values leave only once every key is allowed, all opened then (AnswerWhole); otherwise the first key in the request's
 * order not allowed is the answer, refused or busy, and no key is opened.
 *
 *   a CI run's `coffre export` of 30 keys    1 call, 30 entries (2, its keys entering its cap's set)   the 30 values
 *   the same, a reference among them ended   1 call, the other keys' entries                           that key's refusal
 *
 * A refusal on a cover, which a lone use by ids makes again as an entry of its own, is answered as it is (its `number`
 * null, the app logs it): the batch is refused, and makes no other call.
 */
export async function useMany(path: UsePath, input: UseManyInput): Promise<UseManyOutcome> {
  const { items, ...asked } = input;
  if (!Array.isArray(items) || items.length === 0) throw new Error('a batch of uses names a key at least');
  for (const item of items) {
    checkInput({ ...asked, requestId: item.requestId });
    checkIds({ credential: asked.credential, secretId: item.secretId, place: item.place, way: asked.way });
  }
  if (new Set(items.map((item) => item.requestId)).size !== items.length) throw new Error("a batch's uses each have a request id of their own");
  const way = wayOf(asked);
  const each: Asked[] = items.map((item) => ({ ...asked, ...way, secretId: item.secretId, place: item.place, requestId: item.requestId }));
  const made = await byIds(path, input, each, sealedOnce());
  if ('busy' in made) return made;
  if ('index' in made) return refusedAt(made.index, made.used);
  // Every key allowed: each opened, within the deadline.
  const opened = await Promise.all(made.allowed.map((one) => opening(path, one, input.deadline)));
  const values: Extract<UseManyOutcome, { ok: true }>['values'] = [];
  for (const [index, one] of opened.entries()) {
    const outcome = 'outcome' in one ? one.outcome : null;
    if (outcome === null || !outcome.ok || !('value' in outcome)) return refusedAt(index, one);
    values.push({ number: outcome.number, covered: outcome.covered, value: outcome.value });
  }
  return { ok: true, values };
}

/**
 * A batch's uses by ids (T167; formal/Batching.tla), `useMany`'s rounds: each key's use made as `use` makes it, by ids,
 * in order, in one statement (of at most `limits.batch` keys: more in statements of that many, in turn), and decided on
 * what it read (`settle`), under one admission and one deadline; then, only once every key is allowed on those rows
 * (AllDecidedFirst), one more call for the keys that would take the principal's lock, which answered `decide` having
 * written and locked nothing: it takes the lock exclusive before its first key (StrongestFirst), and each key is decided
 * again on what it reads then. Every key allowed, its key yet to open; or the first key in order not allowed; or busy.
 */
async function byIds(
  path: UsePath, input: Pick<UseInput, 'at' | 'deadline'>, each: readonly Asked[], seals: typeof sealed,
): Promise<{ allowed: Allowed[] } | { index: number; used: Used | Allowed | Uncovered } | Extract<UseOutcome, { busy: UseBusy }>> {
  const settled: (Used | Allowed | Uncovered | undefined)[] = [];
  let pending = each.map((_, index) => index);
  for (let round = 1; pending.length > 0; round++) {
    const decided = round > 1;
    if (round > 2) throw new Error('use_batch answered `decide` to a call of keys it was decided for');
    if (input.deadline > input.at + USE_DEADLINE_MS || Date.now() >= input.deadline) return busy('late');
    if (path.cache.full()) return busy('overloaded');
    const made = pending.map((index) => ready(path, each[index]!, requestOf(each[index]!, undefined), undefined, decided, seals));
    // Round 2's keys, each decided on round 1's rows, take their principal's lock: exclusive, first. Rows that name two
    // principals for one credential were written around the log: no lock first, and Postgres ends a wait cycle (40P01).
    const principals = new Set(decided ? pending.map((index) => (settled[index] as Extract<Used, { again: Ids }>).row.c_principal) : []);
    const lock = principals.size === 1 ? [...principals][0] ?? null : null;
    const answered = await raced(path, input.deadline, (sends) => inStatements(path, made.map((one) => one.call), lock, sends), async (rows, starts) => {
      if (rows.length !== made.length) throw new Error(`use_batch answered ${rows.length} rows for ${made.length} keys`);
      const forgedOf = forgedOnce(path, starts);
      const out: { row: UseRow; forged: boolean }[] = [];
      for (const [i, row] of rows.entries()) out.push({ row, forged: await forgedOf(row, row.probed ? undefined : made[i]!.known) });
      return out;
    });
    if ('busy' in answered) return answered;
    for (const [i, index] of pending.entries()) settled[index] = settle(path, each[index]!, undefined, decided, made[i]!, answered[i]!.row, answered[i]!.forged);
    // The first key not allowed, in the request's order, answers for the batch, and no other call is made.
    const first = settled.findIndex((one) => one !== undefined && !('again' in one) && !('allowed' in one));
    if (first >= 0) return { index: first, used: settled[first]! };
    pending = settled.flatMap((one, index) => (one !== undefined && 'again' in one ? [index] : []));
  }
  return { allowed: settled as Allowed[] };
}

/**
 * Whether each row's principal has an access entry forged past what its newest change accounts for (`forgedPast`): one
 * check a principal and entry, as every key's row of a batch reads the same, in turn on the call's connection; none
 * once the race is lost (T177).
 */
function forgedOnce(path: UsePath, starts: () => void): (row: UseRow, known: CachedSeals | undefined) => Promise<boolean> {
  const forged = new Map<string, Promise<boolean>>();
  return async (row, known) => {
    const at = `${row.c_principal}\n${row.m_access}\n${(known?.last ?? lastsOf(row)).mOld}`;
    if (!forged.has(at)) forged.set(at, forgedPast(path, row, starts, known));
    return forged.get(at)!;
  };
}

/** A batch's answer for the key at `index` that was not allowed. */
function refusedAt(index: number, used: Used | Allowed | Uncovered): Extract<UseManyOutcome, { ok: false }> {
  if (!('outcome' in used)) throw new Error('a use by ids answered a named state');
  const { outcome } = used;
  if ('busy' in outcome) return outcome;
  if (outcome.ok) throw new Error('a use allowed is no refusal');
  if (!('code' in outcome)) throw new Error('a use by ids was handed a plain value');
  return { ok: false, index, code: outcome.code, number: outcome.number };
}

/**
 * A round's calls, `limits.batch` keys a statement, in turn, under the round's one admission and deadline: each its own
 * transaction and fence span, a locked round's each taking the principal's lock exclusive before its first key.
 */
async function inStatements(path: UsePath, calls: readonly UseCall[], lock: string | null, sends: () => void): Promise<UseRow[]> {
  const rows: UseRow[] = [];
  const size = path.cache.limits.batch;
  for (let start = 0; start < calls.length; start += size) {
    // Past the deadline, the round is answered `late` (`raced`): no statement more is sent, and the call lets go of its
    // admission and connection with the one in flight (review r3 of #433). As Postgres's own past-deadline refusal.
    if (start > 0) sends();
    rows.push(...await batchOf(path.db)(path.db, calls.slice(start, start + size), lock));
  }
  return rows;
}

/** The engine's `use_batch`. */
function batchOf(db: Queryable): (db: Queryable, calls: readonly UseCall[], lock: string | null) => Promise<UseRow[]> {
  return engineOf(db) === 'postgres' ? batchPostgres : batchSqlite;
}

/** A use's request as the vault makes it: by its ids, and its way in's (`wayOf`). */
type Ids = { credential: string; secretId: string | null; place: string | null; way?: Way; principal?: string | null };

/**
 * A use's answer inside the vault: its outcome, its row, the view it decided on, if it got that far. A named one may
 * also answer, having written and locked nothing: `unknown`, a token no credential has; `nowhere`, a place that is
 * none, archived, a fork's or a personal config's, which the app answers itself, decided on the place alone; or, named
 * or by ids, `again`, the use the vault allowed on the rows the call read, to be made by their ids, decided (D153).
 */
type Used =
  | { unknown: true } | { nowhere: true } | { again: Ids; row: UseRow }
  | { outcome: UseOutcome | { ok: true; plain: string; versionId: string }; row: UseRow | null; checked: CheckedView | null; request: UseRequest };

/**
 * One call of `use_credential`, and the decision on its row. `secretId` null with `place`: a key the place does not
 * hold, decided on the caller's standing there (Probing.tla, MissingByStanding); a plain value, decided as any and
 * handed back as its text, which its object's digest binds (PlainByStanding). Neither leaves an entry, nor a cover.
 *
 * `names`: what the request named, which the statement reads by (0045, D153); its ids, the isolate's map's, only let it
 * make the use. A named call whose ids are not the names' answers `moved`, and one whose key would take its principal's
 * lock with no use of it kept answers `decide`, each having written and locked nothing: the vault decides the use on
 * the rows the names read, key and all, and refuses it there, whatever the reason, as for a key never made; only a use
 * it allows is made, in a second call (DecideBeforeLock). A named call whose caller stands nowhere there, for what
 * they ask, reads no key at all (`use_stands`, W268; StandingFirst): its row is a key the place does not hold, which
 * the vault refuses on that standing.
 */
async function useOnce(path: UsePath, input: Asked, names?: Names, decided = false): Promise<Used> {
  const request = requestOf(input, names);
  // A deadline the database would refuse (deadline_max) is refused here at no cost; one already past, too.
  if (input.deadline > input.at + USE_DEADLINE_MS || Date.now() >= input.deadline) return { outcome: busy('late'), row: null, checked: null, request };
  if (path.cache.full()) return { outcome: busy('overloaded'), row: null, checked: null, request };
  const made = ready(path, input, request, names, decided);
  // The statement, then, within the same admission and deadline, the MAC check of an access entry its probe found that
  // the new log does not account for (`oldWrite`), never past that entry: one forged in the vault's name is passed over.
  const answered = await raced(path, input.deadline, () => callOf(path.db)(path.db, made.call), async (row, starts) => ({ row, forged: await forgedPast(path, row, starts, row.probed ? undefined : made.known) }));
  if ('busy' in answered) return { outcome: answered, row: null, checked: null, request };
  const used = settle(path, input, names, decided, made, answered.row, answered.forged);
  // Refused on a cover, by ids: the request is logged as an entry of its own.
  if ('uncovered' in used) return useOnce(path, input);
  return 'allowed' in used ? opening(path, used, input.deadline) : used;
}

/** What a use asks the vault, by ids: the request's, or a named call's ids as its isolate's map holds them (none: null). */
type Asked = Pick<UseInput, 'place' | 'purpose' | 'keepsSensitive' | 'requestId' | 'at' | 'deadline'> & {
  credential: string | null; secretId: string | null; way?: Way; principal?: string | null;
};

/** The request a use decides, as the log's replay reads it back. */
function requestOf(input: Asked, names: Names | undefined): UseRequest {
  const way = input.way ?? 'credential';
  return {
    credential: input.credential ?? '', ...(way === 'credential' ? {} : { way }), secretId: input.secretId ?? '', place: input.place, purpose: input.purpose,
    keepsSensitive: input.keepsSensitive === true, at: input.at, ...(names === undefined ? {} : { plain: true as const }),
  };
}

/** A use's call made ready, with what deciding on its row takes: its cache's keys, and the seals the call passed. */
type Ready = { call: UseCall; request: UseRequest; key: string; coverKey: string; known: CachedSeals | undefined; seals?: typeof sealed };

/** A use's call, its cover and its cached seals as the isolate holds them (`useOnce`, before the statement). */
function ready(path: UsePath, input: Asked, request: UseRequest, names: Names | undefined, decided: boolean, seals?: typeof sealed): Ready {
  const { cache } = path;
  const way = input.way ?? 'credential';
  const purpose = purposeCode(request);
  const key = `${input.credential ?? ''}\n${input.secretId ?? ''}\n${input.place ?? ''}`;
  // The seals a probe of these ids read, for the cached form: a use by ids only. A named call always probes, so that
  // its work is the same whatever the key and whatever this isolate kept of earlier uses (D153; review r12).
  const known = input.credential === null || names !== undefined ? undefined : cache.seals.get(key);
  // A cover is of the same request but its id and time: the same credential, key, place and purpose.
  const coverKey = `${key}\n${purpose}`;
  const held = input.secretId === null ? undefined : cache.covers.get(coverKey);
  // A cover a change this isolate knows of came after is no cover; one it cannot judge, the statement judges.
  const cover = held !== undefined && input.at < held.until && input.at >= held.at && (known?.inputs == null || BigInt(held.number) > BigInt(known.inputs)) ? held : undefined;
  const call: UseCall = {
    credential: input.credential, secretId: input.secretId, requestId: input.requestId, at: input.at, purpose, place: input.place,
    way: WAYS.indexOf(way), principal: input.principal ?? null,
    // No ids, no use: a call that only reads by names writes nothing, whatever its MAC (0045, `v_right`). Its key's tag
    // all the same, so that every MAC the statement takes names the key the isolate holds (D162; T168 refuses by it).
    mac: input.credential === null
      ? Buffer.concat([path.macKey.tag, Buffer.alloc(MAC_BYTES - TAG_BYTES)])
      : entryMac(path.macKey, { tree: 'uses', row: { at: input.at, requestId: BigInt(input.requestId), credential: input.credential, secret: input.secretId ?? '', purpose, place: input.place } }),
    deadline: input.deadline,
    ...(cover === undefined ? {} : { cover }),
    ...(known === undefined ? {} : { known }),
    ...(names === undefined ? {} : { names }),
    ...(decided ? { decided: true as const } : {}),
  };
  return { call, request, key, coverKey, known, ...(seals === undefined ? {} : { seals }) };
}

/** A use by ids refused on its cover, nothing written of it: made again as an entry of its own, or answered as it is (a batch's). */
type Uncovered = { uncovered: true; outcome: Extract<UseOutcome, { code: UseCode }> };

/**
 * The decision on a call's row (`useOnce`, after the statement): a use allowed with its key yet to open (`Allowed`), or
 * refused on its cover by ids (`Uncovered`), or any other answer.
 */
function settle(path: UsePath, input: Asked, names: Names | undefined, decided: boolean, made: Ready, row: UseRow, forged: boolean, plainAtOnce = false): Used | Allowed | Uncovered {
  const { cache } = path;
  const { request, key, coverKey, known } = made;
  const way = input.way ?? 'credential';
  if (row.state === 'late' || row.state === 'ahead' || row.state === 'unconfigured' || row.state === 'superseded') {
    return { outcome: busy(row.state, row.state === 'unconfigured' ? 5 : 1), row, checked: null, request };
  }
  if (names !== undefined && row.state === 'unknown') return { unknown: true };
  if (names !== undefined && row.state === 'nowhere') return { nowhere: true };
  if (row.state !== null && !((names !== undefined && (row.state === 'moved' || row.state === 'archived')) || (row.state === 'decide' && !decided))) {
    throw new Error(`use_credential answered ${row.state}, which never leaves it`);
  }
  if (row.state !== null) {
    // The rows the call read, by the names' ids or the use's own (D153): the use decided on them, key and all but the
    // cap, which a use the vault allows weighs under its principal's lock. Refused, as for a key never made, whatever
    // the reason, nothing written; a key that reads an archived place (a reference's source's) too, by name (review r4);
    // allowed, made by those ids, in a second call. A moved call read every seal anew (0045), so the map's never judge
    // the names' rows.
    const ids: Ids = names === undefined
      ? { credential: input.credential!, secretId: input.secretId, place: input.place, way, principal: input.principal ?? null }
      : { credential: row.n_credential!, secretId: row.n_secret, place: row.n_secret === null || inherited(row) ? row.n_place : null, way, principal: null };
    const named: UseRequest = { ...request, credential: ids.credential, secretId: ids.secretId ?? '', place: ids.place };
    const view = viewOf(row, named, row.probed ? undefined : known);
    if (view.changed) cache.seals.delete(key);
    const checked = checkedOf(path.sealKeys, view.view, named, view.accounted || forged, made.seals);
    const code = decidedOn(checked, named, row) ?? (names !== undefined && readsArchived(row) ? 'archived' : null);
    if (code !== null) return { outcome: { ok: false, code, number: null }, row, checked, request: named };
    // A named batch's plain value, decided on these rows: its text, which its object's digest binds, at once, as a lone
    // named use's second call would hand it back; no use is made of it, no entry, no cover (`plainAtOnce`). A batch's
    // second round is by ids, which makes no plain value's use (`bad_claim`).
    const read = view.view.secret.row;
    const value = read == null ? null : read.source === null ? read : view.view.source?.row ?? null;
    if (plainAtOnce && value != null && value.key === null) {
      if (Date.now() >= input.deadline) return { outcome: busy('late'), row, checked, request: named };
      return { outcome: { ok: true, plain: row.v_plaintext!, versionId: value.version }, row, checked, request: named };
    }
    return { again: ids, row };
  }
  const view = viewOf(row, request, row.probed ? undefined : known);
  // An input whose row names another object than the cache's seal is of: `stale`, and the next use probes.
  if (view.changed) cache.seals.delete(key);
  const checked = checkedOf(path.sealKeys, view.view, request, view.accounted || forged, made.seals);
  const code = decidedOn(checked, request, row);
  // The seals a probe read, kept for the next use's cached form: by ids alone. A named call never runs the cached form
  // (above), which an earlier use's seals would choose for a key held and never for one not (Fable's review, r12).
  if (row.probed && row.newest !== null && !view.changed && names === undefined) {
    cache.keep(cache.seals, key, {
      newest: row.newest, newestMac: row.newest_mac!, inputs: row.inputs, ids: view.ids,
      cap: { count: Number(row.cap_count), windowMs: Number(row.cap_window) }, last: lastsOf(row),
    });
  }
  if (row.covered !== null && code !== null) {
    // Refused on a cover (its credential's end, say): by ids, the request is logged as an entry of its own. By name, it
    // is answered as it is, in its one call, as a key the place does not hold is, and the app's entry records it: a
    // second call would tell a key held from one never made (T158; Probing.tla, CoveredRefusalAnswered).
    cache.covers.delete(coverKey);
    if (names === undefined) return { uncovered: true, outcome: { ok: false, code, number: null } };
  }
  if (code !== null) {
    cache.covers.delete(coverKey);
    return { outcome: { ok: false, code, number: row.number }, row, checked, request };
  }
  const v = view.view;
  const secret = v.secret.row!;
  const value = secret.source === null ? secret : v.source!.row!;
  // A plain value, decided: its text, which its object's digest binds; no entry, no cover (it counts toward nothing).
  // Past its deadline, it never leaves, as a value whose key opened late (`open`).
  if (value.key === null) {
    if (Date.now() >= input.deadline) return { outcome: busy('late'), row, checked, request };
    return { outcome: { ok: true, plain: row.v_plaintext!, versionId: value.version }, row, checked, request };
  }
  if (row.covered === null) {
    const expires = checked.credential.row!.expiresAt ?? Infinity;
    cache.keep(cache.covers, coverKey, { number: row.number!, at: input.at, requestId: input.requestId, until: Math.min(input.at + cache.limits.coverMs, expires) });
  }
  return { allowed: { view: v, number: row.covered ?? row.number!, covered: row.covered !== null }, row, checked, request };
}

/** A use allowed, its key yet to open: what `settle` answers of a sealed value, which its caller opens (`opening`). */
type Allowed = { allowed: { view: UseView; number: string; covered: boolean }; row: UseRow; checked: CheckedView; request: UseRequest };

/** A use's answer once its key is opened: the value, or `late` past its deadline, or `bad_claim` for a key not this value's. */
async function opening(path: UsePath, { allowed: { view, number, covered }, row, checked, request }: Allowed, deadline: number): Promise<Used> {
  const opened = await open(path, view, row, deadline);
  if (opened === 'late') return { outcome: busy('late'), row, checked, request };
  if (opened === 'bad_claim') return { outcome: { ok: false, code: 'bad_claim', number }, row, checked, request };
  return { outcome: { ok: true, number, covered, value: opened }, row, checked, request };
}

/**
 * `decideChecked` on what a call read. A named call that found its caller standing nowhere read no key (`n_standing`,
 * W268): refused as for a key the place does not hold, which the vault's rule refuses too, on the caller's standing
 * (`standingRefusal`). Where that rule finds them standing, a row changed around the log between the gate's statement
 * and the one that read the rest, each with its own snapshot (the fence holds back changes, not such writes): `stale`,
 * which is what happened, never an answer of its own.
 */
function decidedOn(checked: CheckedView, request: UseRequest, row: UseRow): UseCode | null {
  if (request.plain === true && row.n_standing === false && standingRefusal(checked, request) === null) return 'stale';
  // A place whose chain is cut reads nothing, as the app's read refuses it whole (0051, T165; Probing.tla, CutByPlace):
  // the call read no key, and the caller, standing there, is refused on the place, `archived`, as for every key.
  if (request.plain === true && row.n_cut === true) return standingRefusal(checked, request) ?? 'archived';
  return decideChecked(checked, request);
}

/** Whether a named call's key is one its place inherits (a fork's or a personal config's, T165): used through the place. */
function inherited(row: UseRow): boolean {
  return row.n_secret !== null && row.s_environment !== null && row.s_environment !== row.n_place;
}

/** Whether a call read its key through an archived place: the place, the key's own, or a reference's source's (0045). */
function readsArchived(row: UseRow): boolean {
  return (['e1', 'e2', 'e3'] as const).some((slot) => row[`${slot}_archived`] === true || row[`${slot}_project_archived`] === true);
}

/** The ids and slugs a named call read, which the isolate's map keeps for the request's names. */
function mapped(row: UseRow): Resolved | null {
  if (row.n_credential === null || row.n_place === null || row.n_project === null || row.n_environment === null) return null;
  return { credential: row.n_credential, environment: row.n_place, slugs: { project: row.n_project, environment: row.n_environment } };
}

/**
 * A use as the request names it (T145, PR B; D153; formal/Probing.tla, Credentials.tla Revoking015Caller): one call,
 * which reads what the request names by its names, whatever this isolate's map holds; the ids the map holds, if any,
 * let it make the use in that call, as by ids. A use the vault refuses, whatever the reason, is refused in that one
 * call, whatever the map held (Probing.tla, ResolveByName, NoIsFixed); one it allows on rows the map had no ids for
 * is made by the ids the call read, in a second, and the map keeps them. One admission, checked before anything is
 * read, so that a busy answer never hangs on whether a key is held. The request's route is the credential's and its
 * account's alone (`routeOf`, Probing.tla, OneRoute): the key and the map decide the use, never how the app answers it.
 */
export async function useNamed(path: UsePath, input: NamedUseInput): Promise<NamedUseOutcome> {
  checkInput(input);
  if ((input.key !== null && (typeof input.key !== 'string' || input.key === '')) || typeof input.tokenHash !== 'string') throw new Error('a named use names its token, by hash, and its key, if any');
  const accepts = acceptsOf(input);
  const { cache } = path;
  const tokenHash = Buffer.from(input.tokenHash, 'base64');
  const busyFor = (outcome: Extract<UseOutcome, { busy: UseBusy }>) => ({ served: true as const, route: 'busy' as const, outcome });
  if (input.deadline > input.at + USE_DEADLINE_MS || Date.now() >= input.deadline) return busyFor(busy('late'));
  if (cache.full()) return busyFor(busy('overloaded'));
  const at = `${input.tokenHash}\n${input.place?.project ?? ''}\n${input.place?.environment ?? ''}`;
  const found = cache.named(at);
  const keyed = found === undefined || input.key === null ? undefined : cache.keyed(found.environment, input.key);
  // The ids the map holds, if it holds them all; else none, and the first call only reads.
  const held: Ids | null = found === undefined || (input.key !== null && keyed === undefined) ? null
    : { credential: found.credential, secretId: keyed?.id ?? null, place: keyed == null || keyed.through ? found.environment : null };
  const names: Names = {
    tokenHash, project: input.place?.project ?? null, environment: input.place?.environment ?? null, key: input.key, handle: input.place === null,
    // The places a stable URL does not mean, judged by the call against the slugs it reads, never the map's.
    unless: input.place !== null ? [] : (input.unless ?? []).map((other) => `${other.project}/${other.environment}`),
    accepts,
    forks: input.forks === true,
  };
  const asked = { purpose: input.purpose, keepsSensitive: input.keepsSensitive, requestId: input.requestId, at: input.at, deadline: input.deadline };
  let used = await useOnce(path, { ...asked, ...(held ?? { credential: null, secretId: null, place: null }) }, names);
  if ('again' in used) {
    // Allowed on the rows its names read: the map keeps their ids, and the use is made by them, decided.
    keep(cache, at, input.key, used.row);
    used = await useOnce(path, { ...asked, ...used.again }, names, true);
    // Out of date again, between its two calls: nothing decided, ask again.
    if ('again' in used) return busyFor(busy('late'));
  }
  if ('unknown' in used) {
    cache.names.delete(at);
    // An unknown token: the credential's own check answers it, whatever it names.
    return { served: true, route: 'credential', outcome: { ok: false, code: 'credential', number: null } };
  }
  // A place the vault serves not by name (none, archived, a fork's, a personal config's, one the URL does not mean):
  // decided on the place, never the key.
  if ('nowhere' in used) return { served: false };
  if ('busy' in used.outcome) return busyFor(used.outcome);
  const row = used.row!;
  const checked = used.checked!;
  keep(cache, at, input.key, row);
  if (routeOf(checked, input.at) === 'credential') {
    const outcome = used.outcome.ok ? null : used.outcome;
    // The credential's seals bear out, ended or not, before any use is allowed (`decideChecked`, the credential first).
    if (outcome === null || !('code' in outcome)) throw new Error('a use was allowed on a credential its seals do not bear out');
    return { served: true, route: 'credential', outcome };
  }
  return {
    served: true,
    route: 'name',
    secretId: used.request.secretId === '' ? null : used.request.secretId,
    outcome: used.outcome,
    app: row.app == null ? null : JSON.stringify(row.app),
    standing: standingOf(checked, used.request),
    place: input.place ?? mapped(row)?.slugs ?? null,
    at: placeOf(checked, row),
  };
}

/**
 * A request's several keys as it names them (T165, B2's PR 2; formal/ProbingMany.tla; migration 0055,
 * `use_named_batch`): one call, whose first statement decides the caller's standing at the place first, from rows no key
 * decides (GateBeforeKeys), and reads nothing of any key without it: no standing, a chain cut, and the request is the
 * place's refusal, whatever the keys are or were. For one who stands, the same statement reads each key as a lone
 * named use reads it (`useNamed`), the request's names, or every key the place holds, which it lists itself: with the
 * ids this isolate maps it to, if any, a key whose row of the cap's is fresh is used at once; otherwise the call writes
 * and locks nothing. The vault decides every key on those rows (DecideAllFirst); then, only once it allowed every one,
 * makes the rest as `useMany` makes a batch by ids, and opens them all. All or nothing: every value, or the first key
 * refused, or busy.
 *
 * A read that leaves out a sensitive value, naming it (`leavesSensitive`: a person's), passes no ids in its first
 * statement, which then writes nothing (LeaveFirst): the vault leaves every sensitive key out, unused, on its rows.
 *
 *   Ada's `coffre export market/dev`, 9 keys            1 call: 2 statements (3, a key entering her cap's set)
 *   the same, her grant revoked                         1 call, 1 statement: 403, no key listed, whatever dev holds
 *   the proxy's two keys of a credential, mapped        1 call, 1 statement, both values
 */
export async function useNamedMany(path: UsePath, input: NamedManyInput): Promise<NamedManyOutcome> {
  checkInput({ ...input, requestId: '0' });
  const keys = input.keys === null ? null : [...input.keys];
  if (keys !== null && (keys.length === 0 || keys.some((key) => typeof key !== 'string' || key === '') || new Set(keys).size !== keys.length)) {
    throw new Error("a named batch names each of its keys once, or none, for every key the place holds");
  }
  if (typeof input.tokenHash !== 'string') throw new Error('a named batch names its token, by hash');
  const accepts = acceptsOf(input);
  const { cache } = path;
  const busyFor = (outcome: Extract<UseOutcome, { busy: UseBusy }>) => ({ served: true as const, route: 'busy' as const, outcome });
  if (input.deadline > input.at + USE_DEADLINE_MS || Date.now() >= input.deadline) return busyFor(busy('late'));
  if (cache.full()) return busyFor(busy('overloaded'));
  const tokenHash = Buffer.from(input.tokenHash, 'base64');
  const at = `${input.tokenHash}\n${input.place?.project ?? ''}\n${input.place?.environment ?? ''}`;
  const found = cache.named(at);
  const leaves = input.leavesSensitive === true;
  const names = (key: string | null): Names => ({
    tokenHash, project: input.place?.project ?? null, environment: input.place?.environment ?? null, key, handle: input.place === null,
    unless: input.place !== null ? [] : (input.unless ?? []).map((other) => `${other.project}/${other.environment}`),
    accepts, forks: true,
  });
  const asked = { purpose: input.purpose, keepsSensitive: input.keepsSensitive, at: input.at, deadline: input.deadline };
  const none = { credential: null, secretId: null, place: null };
  // A key's ids, as this isolate maps them, for its use in the first statement: none for a read that leaves keys out.
  const mappedIds = (key: string): Pick<Ids, 'credential' | 'secretId' | 'place'> | null => {
    if (found === undefined || leaves) return null;
    const keyed = cache.keyed(found.environment, key);
    return keyed === undefined ? null : { credential: found.credential, secretId: keyed?.id ?? null, place: keyed === null || keyed.through ? found.environment : null };
  };
  const seals = sealedOnce();
  const gateAsked: Asked = { ...asked, ...none, requestId: newUseRequestId() };
  const gate = ready(path, gateAsked, requestOf(gateAsked, names(null)), names(null), false, seals);
  // Each key's use as asked, and its call: by the ids the isolate maps it to, which the statement takes only when they
  // are its name's now and its value is sealed, as a use by ids is made (the cached form, its cover); else by its name.
  const keyAsked = new Map<string, Asked>();
  const keyReady = new Map<string, { made: Ready; byIds: boolean }>();
  const callFor = (key: string): NamedBatchCall => {
    const ids = mappedIds(key);
    const one: Asked = { ...asked, ...(ids ?? none), requestId: keyAsked.get(key)?.requestId ?? newUseRequestId() };
    keyAsked.set(key, one);
    const byIds = ids !== null && ids.secretId !== null;
    const made = byIds ? ready(path, one, requestOf(one, undefined), undefined, false, seals) : readyFor(path, { ...one, ...none }, names(key), seals);
    keyReady.set(key, { made, byIds });
    return { key, call: made.call };
  };
  const limit = cache.limits.batch;
  const answered = await raced(path, input.deadline, async (sends) => {
    // The first statement: the gate, then the request's first keys, or the place's, listed.
    const first = keys === null ? null : keys.slice(0, limit).map(callFor);
    const read = await namedBatchOf(path.db)(path.db, gate.call, first, limit);
    const listed = keys ?? read.keys ?? [];
    const rows = [...read.rows];
    const byIds = [...read.byIds];
    const aheads = [...read.aheads];
    // A place of more keys than a statement reads: the rest by their names, in statements of that many, each its gate.
    for (let start = rows.length; read.rows.length > 0 && start < listed.length; start += limit) {
      sends();
      const more = await namedBatchOf(path.db)(path.db, gate.call, listed.slice(start, start + limit).map(callFor), limit);
      if (more.rows.length === 0) return { gate: more.gate, listed: [], rows: [], byIds: [], aheads: [] };
      rows.push(...more.rows);
      byIds.push(...more.byIds);
      aheads.push(...more.aheads);
    }
    return { gate: read.gate, listed: read.rows.length === 0 ? [] : listed, rows, byIds, aheads };
  }, async (read, starts) => {
    const forgedOf = forgedOnce(path, starts);
    const gateForged = await forgedOf(read.gate, undefined);
    const forged: boolean[] = [];
    for (const [i, row] of read.rows.entries()) {
      // A use by ids judged on the seals its call passed, as `byIds`' are; a named call's, on every seal it read.
      const known = read.byIds[i] === true && !row.probed ? keyReady.get(read.listed[i]!)?.made.known : undefined;
      forged.push(await forgedOf(row, known));
    }
    return { ...read, gateForged, forged };
  });
  if ('busy' in answered) return busyFor(answered);
  // The gate's row: the caller, the place and its chain, decided on rows no key decides.
  const opened = settle(path, gateAsked, names(null), false, gate, answered.gate, answered.gateForged);
  if ('unknown' in opened) {
    cache.names.delete(at);
    return { served: true, route: 'credential', outcome: { ok: false, code: 'credential', number: null } };
  }
  if ('nowhere' in opened) return { served: false };
  if ('again' in opened || 'allowed' in opened || 'uncovered' in opened) throw new Error('a named batch\'s gate made a use');
  if ('busy' in opened.outcome) return busyFor(opened.outcome);
  const gateRow = answered.gate;
  const checked = opened.checked!;
  keep(cache, at, null, gateRow);
  if (routeOf(checked, input.at) === 'credential') {
    const outcome = opened.outcome.ok ? null : opened.outcome;
    if (outcome === null || !('code' in outcome)) throw new Error('a use was allowed on a credential its seals do not bear out');
    return { served: true, route: 'credential', outcome };
  }
  // Standing there and its chain whole, as a key the place does not hold answers to one who may act there: `missing`.
  const gateCode = opened.outcome.ok ? null : 'code' in opened.outcome ? opened.outcome.code : null;
  const stands = gateRow.n_standing === true && gateRow.n_cut === false && gateCode === 'missing';
  const named = {
    served: true as const, route: 'name' as const, standing: standingOf(checked, opened.request),
    app: gateRow.app == null ? null : JSON.stringify(gateRow.app),
    place: input.place ?? mapped(gateRow)?.slugs ?? null, at: placeOf(checked, gateRow),
  };
  if (!stands || answered.rows.length !== answered.listed.length) {
    return { ...named, stands: false, keys: [], outcome: { ok: false, index: null, code: gateCode ?? 'stale', number: null } };
  }
  // Each key, decided on the rows its named call read, every one before any other call (DecideAllFirst).
  const out: NamedKey[] = [];
  const decided: ({ none: true } | { plain: string; versionId: string } | { again: Ids; asked: Asked } | { allowed: Allowed } | { refused: Used | Allowed | Uncovered })[] = [];
  for (const [i, key] of answered.listed.entries()) {
    const row = answered.rows[i]!;
    if (answered.byIds[i] === true) {
      // By its ids: a key with a sealed value of its own, its name's now, decided as a batch by ids decides its first round.
      const { made } = keyReady.get(key)!;
      const one = keyAsked.get(key)!;
      const rows = answered.aheads[i] ?? null;
      out.push({
        key, secretId: one.secretId, held: rows?.held ?? null, left: false,
        app: rows === null || gateRow.app == null ? null : JSON.stringify({ ...(gateRow.app as Record<string, unknown>), secrets: [{ secret: rows.secret, version: rows.version }] }),
      });
      const used = settle(path, one, undefined, false, made, row, answered.forged[i]!);
      if ('allowed' in used) decided.push({ allowed: used });
      else if ('again' in used) decided.push({ again: used.again, asked: one });
      else if ('uncovered' in used) decided.push({ refused: used });
      else if ('unknown' in used || 'nowhere' in used) throw new Error('a use by ids answered a named state');
      else if ('busy' in used.outcome) return { ...named, stands: true, keys: out, outcome: used.outcome };
      else decided.push({ refused: used });
      continue;
    }
    const one = keyAsked.get(key) ?? { ...asked, ...none, requestId: newUseRequestId() };
    keep(cache, at, key, row);
    const held = inherited(row) ? { environmentId: row.s_environment!, slug: row.e2_slug! } : null;
    // Left out by the read, its value sensitive: decided by no rule, used by nothing, its call having written nothing.
    const left = leaves && row.state === 'moved' && row.n_secret !== null && row.v_sensitive === true;
    out.push({ key, secretId: row.n_secret, held, app: row.app == null ? null : JSON.stringify(row.app), left });
    if (left) {
      decided.push({ none: true });
      continue;
    }
    // By its name alone: the call it was made by, or, its ids passed but not its name's now, the named call the
    // statement made in their place, as this request asks it.
    const named1 = { ...one, ...none };
    const sent = keyReady.get(key);
    const used = settle(path, named1, names(key), false, sent !== undefined && !sent.byIds ? sent.made : readyFor(path, named1, names(key), seals), row, answered.forged[i]!, true);
    if ('allowed' in used) decided.push({ allowed: used });
    else if ('again' in used) decided.push({ again: used.again, asked: one });
    else if ('unknown' in used || 'nowhere' in used || 'uncovered' in used) decided.push({ refused: { outcome: { ok: false, code: 'stale', number: null }, row, checked: null, request: requestOf(one, names(key)) } });
    else if ('busy' in used.outcome) return { ...named, stands: true, keys: out, outcome: used.outcome };
    else if (used.outcome.ok) decided.push('plain' in used.outcome ? { plain: used.outcome.plain, versionId: used.outcome.versionId } : { refused: used });
    // A key the place does not hold, to one who stands there: none, which the request leaves out. One held with neither a
    // value nor a reference, written around coffre (its seal does not hold), reads as no value, as the app's read reads
    // it (`Hollow`): left out too, nothing served. A reference ended is refused, as the app refuses it.
    else if ('code' in used.outcome && used.outcome.code === 'missing' && row.n_secret === null) decided.push({ none: true });
    else if ('code' in used.outcome && (used.outcome.code === 'tampered' || used.outcome.code === 'stale') && hollow(row)) decided.push({ none: true });
    else decided.push({ refused: used });
  }
  const refusedFirst = decided.findIndex((one) => 'refused' in one);
  if (refusedFirst >= 0) return { ...named, stands: true, keys: out, outcome: refusal(refusedFirst, (decided[refusedFirst] as { refused: Used | Allowed | Uncovered }).refused) };
  // Every key allowed: the rest made by the ids its row read, as a batch by ids makes them, decided again.
  const again = decided.flatMap((one, index) => ('again' in one ? [{ index, asked: { ...one.asked, ...one.again } }] : []));
  const values: (NamedValue | null)[] = decided.map((one) => ('plain' in one ? { plain: one.plain, versionId: one.versionId } : null));
  const allowed = new Map<number, Allowed>(decided.flatMap((one, index) => ('allowed' in one ? [[index, one.allowed] as const] : [])));
  if (again.length > 0) {
    const made = await byIds(path, input, again.map((one) => one.asked), seals);
    if ('busy' in made) return { ...named, stands: true, keys: out, outcome: made };
    if ('index' in made) return { ...named, stands: true, keys: out, outcome: refusal(again[made.index]!.index, made.used) };
    for (const [i, one] of made.allowed.entries()) allowed.set(again[i]!.index, one);
  }
  const indices = [...allowed.keys()].sort((a, b) => a - b);
  const opened2 = await Promise.all(indices.map((index) => opening(path, allowed.get(index)!, input.deadline)));
  for (const [i, one] of opened2.entries()) {
    const outcome = 'outcome' in one ? one.outcome : null;
    if (outcome === null || !outcome.ok || !('value' in outcome)) return { ...named, stands: true, keys: out, outcome: refusal(indices[i]!, one) };
    values[indices[i]!] = { number: outcome.number, covered: outcome.covered, value: outcome.value };
  }
  return { ...named, stands: true, keys: out, outcome: { ok: true, values } };
}

/** Whether a key's row reads neither a value of its own nor a reference: a key held with nothing to read. */
function hollow(row: UseRow): boolean {
  return row.n_secret !== null && row.s_environment !== null && row.s_version === null && row.s_source === null;
}

/** A named batch's answer for its key at `index`, not allowed: refused, or busy. */
function refusal(index: number, used: Used | Allowed | Uncovered): Extract<NamedManyOutcome, { route: 'name' }>['outcome'] {
  if (!('outcome' in used)) throw new Error('a refused key answered a named state');
  const { outcome } = used;
  if ('busy' in outcome) return outcome;
  if (outcome.ok) throw new Error('a use allowed is no refusal');
  return { ok: false, index, code: outcome.code, number: outcome.number };
}

/** A key's named call made ready, its request as the vault decides it. */
function readyFor(path: UsePath, asked: Asked, names: Names, seals: typeof sealed): Ready {
  return ready(path, asked, requestOf(asked, names), names, false, seals);
}

/** What the app's config accepts of a credential, as a named call carries it, checked. */
function acceptsOf(input: { accepts: CredentialAcceptance }): CredentialAcceptance {
  const { accepts } = input;
  if (typeof accepts?.signin !== 'boolean' || !Array.isArray(accepts.issuers) || accepts.issuers.some((issuer) => typeof issuer !== 'string')) {
    throw new Error('a named use says what credentials the app accepts: whether it signs in, and its providers\' issuers');
  }
  return { signin: accepts.signin, issuers: [...accepts.issuers] };
}

/** The engine's `use_named_batch`. */
function namedBatchOf(db: Queryable): (db: Queryable, gate: UseCall, calls: readonly NamedBatchCall[] | null, limit: number) => Promise<NamedBatchRows> {
  return engineOf(db) === 'postgres' ? namedPostgres : namedSqlite;
}

/** A named batch's key: its name, and its call, by its name alone or by the ids the isolate maps it to. */
export type NamedBatchCall = { key: string; call: UseCall };

/** The app's rows of a key a named batch used by its ids: its row and its version's, as `to_json` writes them, and where it is held, inherited. */
export type NamedAhead = { secret: unknown; version: unknown; held: { environmentId: string; slug: string } | null };

/**
 * What `use_named_batch` answers: the gate's row, the names it listed (none named), each key's row, in order, whether
 * each was its use by ids, and, for those, the app's rows of it.
 */
export type NamedBatchRows = { gate: UseRow; keys: string[] | null; rows: UseRow[]; byIds: boolean[]; aheads: (NamedAhead | null)[] };

/**
 * The ids and slugs a named call read, kept in the isolate's map for the request's names and its key: never a key it
 * did not read, its caller standing nowhere there (W268), which would map the name to none for whoever asks next.
 */
function keep(cache: UseCache, at: string, key: string | null, row: UseRow): void {
  const read = mapped(row);
  if (read === null) return;
  cache.name(at, read);
  if (key !== null && row.n_standing !== false && row.n_cut !== true) cache.key(read.environment, key, row.n_secret === null ? null : { id: row.n_secret, through: inherited(row) });
}

/**
 * Where a named call's refusal is logged, by the ids of its row as the call read it: the key's own place when it read a
 * key (a key a fork or a personal config inherits, where it is held: as a use by ids logs it, review r5 of D153; T165),
 * else the place its names named. None for a row its seals do not bear out (T159).
 */
function placeOf(checked: CheckedView, row: UseRow): { projectId: string; environmentId: string } | null {
  const id = inherited(row) ? row.s_environment : row.n_place;
  const read = id === null ? undefined : checked.environments.get(id);
  const place = read !== undefined && read.valid && read.current ? read.row : null;
  return place === null ? null : { projectId: place.projectId, environmentId: place.id };
}

/** What a named request's route hangs on: its credential and its account, as the use read and checked them. */
type CallerSeals = Pick<CheckedView, 'credential' | 'principal'>;

/**
 * How the app answers a named request (D153, review r2): `name`, on the vault's decision, every refusal of the key
 * alike; or `credential`, by the credential's own check (401, a token of 0.10's sealed first). On the credential and
 * its account alone, as their seals bear them out, and whether the credential has ended: never the roles, a place, the
 * key's rows or the isolate's map, which it cannot see, so that no key, however it is held, and no state of the map,
 * moves a request from one path to the other (formal/Probing.tla, OneRoute).
 */
export function routeOf(caller: CallerSeals, at: number): 'name' | 'credential' {
  const { credential, principal } = caller;
  if (credential.row === null || !credential.valid || !credential.current) return 'credential';
  if (principal === null || !principal.valid || !principal.current) return 'credential';
  return credentialEnded(credential.row, principal.row, at) ? 'credential' : 'name';
}

/**
 * What the use decided the caller holds, as `access` answers it, from the sealed rows it read (`readerOf`): their
 * standing, role, scope and live grants, and the policy as far as the environments it weighed, which is all the app
 * then checks (the place it reads). Its credential and account bear out, as its route says. Roles, the policy or the
 * place where the key is held or sought not as their seals say (put back, or written around the log): the use was
 * refused on them (`decideChecked`, the seals first), and the caller holds nothing, so that nothing the app checks
 * after reads those rows. Never the key's own rows, which a refusal of it alone says (D153).
 */
function standingOf(checked: CheckedView, request: UseRequest): Access {
  const credential = checked.credential.row!;
  const principal = checked.principal!.row;
  // Every place the use weighed (where its key is sought or held, read through, its value's, a personal config's parent):
  // one a writer changed refused the use, and tells the app nothing either (T159, Fable on #431).
  const weighed = useEnvironments(checked, request).flatMap((id) => {
    const read = checked.environments.get(id);
    return read === undefined ? [] : [read];
  });
  const sealed = [checked.roles, checked.policy, ...weighed].every((input) => input.valid && input.current);
  // Only the rows their seals bear out: another a writer changed protects or names nothing the app is told (T159).
  const rows = [...checked.environments.values()].flatMap((read) => (read.row === null || !read.valid || !read.current ? [] : [read.row]));
  const reader = sealed
    ? readerOf(principal, credential, checked.roles.row ?? noEdits(), rows, request.at)
    : { status: readerOf(principal, credential, noEdits(), [], request.at).status, live: NOTHING };
  const live = reader.live;
  return {
    principal: credential.principal,
    status: reader.status,
    generation: principal?.generation ?? 0,
    role: live.role,
    scope: live.scope,
    grants: !sealed || reader.status !== 'active' || principal === null
      ? []
      : principal.grants.filter((grant) => grant.expiresAt === null || grant.expiresAt > request.at).map(({ projectId, environmentId, role, expiresAt }) => ({ projectId, environmentId, role, expiresAt })),
    since: null,
    by: null,
    ...(live.policy === undefined ? {} : { policy: live.policy }),
  } as Access;
}

/**
 * The call, then `then` on its row (or a batch's rows), raced against the
 * deadline (WorkerHonoursDeadline): lost, the use is answered `late`, and
 * the call's row, if it ever comes, is dropped. Both hold one place in
 * admission, as they hold the call's connection: what the vault reads
 * after the statement (`oldWrite`) is within the same place and deadline.
 * Past the deadline, or the race lost, the call starts nothing more, neither the statement
 * after `ready` (nor a batch's next, `sends`) nor, the race lost, the reads after it: its
 * answer has gone. `then` is handed `starts` for those, which it calls before each (a batch's
 * `oldWrite` for one key, then another's, T177). One it had started may still reach Postgres
 * (on Node, its bytes leave on the next turn of the loop), which refuses it past the deadline,
 * and its row is dropped. A round of a batch is one call, its statements made in turn within it.
 */
async function raced<R, T>(path: UsePath, deadline: number, call: (sends: () => void) => Promise<R>, then: (row: R, starts: () => void) => Promise<T>): Promise<T | Extract<UseOutcome, { busy: UseBusy }>> {
  const release = path.cache.admit(deadline);
  // Whether the race is lost: once it is, `then` starts nothing. The timer alone says so, never the clock, so that a
  // statement that answered first is decided on, its entry written (Fable's review of #438).
  let lost = false;
  // Before each statement: none past the deadline, nor once the race is lost. Both, as they disagree: a timer can fire
  // a ms or two before `Date.now()` reaches the deadline (Node measures it from the loop's cached time), and a call
  // answered `late` would still send its statement and write its use.
  const sends = () => {
    if (lost || Date.now() >= deadline) throw Object.assign(new Error('a use past its deadline sends nothing more'), { code: '57014' });
  };
  // Before each read after the statement: none once the race is lost. The timer alone, as above: a statement that
  // answered first is decided on, whatever the clock says by then.
  const starts = () => {
    if (lost) throw Object.assign(new Error('a use that lost its race starts nothing more'), { code: '57014' });
  };
  const running = (async () => {
    await path.ready?.();
    sends();
    const row = await call(sends);
    starts();
    return then(row, starts);
  })().finally(release);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<'late'>((resolve) => {
    timer = setTimeout(() => {
      lost = true;
      resolve('late');
    }, Math.max(0, deadline - Date.now()));
  });
  try {
    const first = await Promise.race([running, late]);
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
    // Past its deadline by Postgres's clock, or a lock not had within the hot login's lock_timeout: nothing written. A
    // batch that waited on another for the principal's lock, which Postgres ended (40P01), the same: it never does when
    // each takes the lock exclusive first (`use_batch`, StrongestFirst), unless rows written around the log name two
    // principals for one credential.
    if (code === '57014' || code === '55P03' || code === '40P01') return busy('late');
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

/** The engine's `use_credential`. */
function callOf(db: Queryable): (db: Queryable, call: UseCall) => Promise<UseRow> {
  return engineOf(db) === 'postgres' ? callPostgres : callSqlite;
}

/**
 * Whether the access entry the statement's probe found past what the
 * principal's newest change accounts for (`viewOf`'s `accounted` false) is
 * one forged in the vault's name, as is every one past it up to the probe's:
 * then it is passed over, as Migration015.tla's UsesSeeOldWrites reads only
 * authentic writes, and the use is decided as its replay decides it.
 */
async function forgedPast(path: UsePath, row: UseRow, starts: () => void, known?: CachedSeals): Promise<boolean> {
  // A row that answers a state (`moved`, `unknown`, `unconfigured`) may name none of these: nothing to check.
  if (path.oldWrite === undefined || row.m_access == null || row.c_principal == null) return false;
  const old = (known?.last ?? lastsOf(row)).mOld ?? null;
  if (old !== null && BigInt(row.m_access) <= BigInt(old)) return false;
  // The race lost, no read: whatever `oldWrite` does with `starts`, it is not asked.
  starts();
  return !(await path.oldWrite(row.c_principal, old === null ? null : BigInt(old), BigInt(row.m_access), starts));
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
 * newest change's, probed or the cache's. An input whose row names another
 * object than the cache's seal is of (a reference's source repointed, a
 * credential's principal, written around the log) has no newest seal the
 * vault knows: it is not current, and decides `stale` (review r2 of D153).
 * Each input alone: the credential's and its account's judgement never
 * hangs on the key's rows, which a request's route needs (`routeOf`).
 * `changed`: some input's did, and the next use probes. `accounted`: the
 * principal's newest 0.14 access entry is one the new log accounts for
 * (UsesSeeOldWrites).
 */
export function viewOf(row: UseRow, request: UseRequest, known?: CachedSeals): { view: UseView; ids: Identities; changed: boolean; accounted: boolean } {
  const ids: Identities = {
    c: request.credential, m: row.c_principal, s: request.secretId, x: row.s_source,
    e1: row.e1_id, e2: row.e2_id, e3: row.e3_id, e4: row.e4_id,
  };
  const moved = (Object.keys(ids) as (keyof Identities)[]).filter((input) => known !== undefined && known.ids[input] !== ids[input]);
  const cached = known?.last ?? lastsOf(row);
  // No seal is equal to none: an input moved is current to nothing.
  const last = (input: keyof Identities): Buffer | null => (moved.includes(input) ? UNKNOWN : cached[input]);
  const read = <T extends Input>(object: T | null, seal: Buffer | null, newest: Buffer | null): Read<T> => ({ row: object, seal, newest });
  const credential: Read<WayInput> = read(wayObject(row, request), row.c_seal, last('c'));
  const principal = row.c_principal === null ? null : read(row.m_status === null ? null : principalObject({
    principal: row.c_principal, status: row.m_status, generation: row.m_generation!, ...memberStanding({ owner: row.m_owner === true, role: row.m_role, scope: row.m_scope }),
  }, grantsOf(row)), row.m_seal, last('m'));
  // A plain value's text, which its object's digest binds.
  const version = row.v_wrapped_dek === null ? null : {
    sensitive: row.v_sensitive === true, plaintext: row.v_plaintext,
    kekProvider: row.v_kek_provider!, kekId: row.v_kek_id!, kekVersion: row.v_kek_version!, wrappedDek: row.v_wrapped_dek.toString('base64'),
  };
  const secret = read(row.s_environment === null ? null : secretObject({
    id: request.secretId, projectId: row.s_project!, environmentId: row.s_environment, source: row.s_source, reference: row.s_reference,
    version: row.s_source === null && version !== null ? { id: row.s_version!, ...version } : null,
  }), row.s_seal, last('s'));
  const source = row.s_source === null ? null : read(row.x_environment === null ? null : secretObject({
    id: row.s_source, projectId: row.x_project!, environmentId: row.x_environment, source: row.x_source, reference: row.x_reference,
    version: row.x_source === null && version !== null ? { id: row.x_version!, ...version } : null,
  }), row.x_seal, last('x'));
  const environments = new Map<string, Read<EnvironmentInput>>();
  for (const slot of SLOTS) {
    const id = row[`${slot}_id`];
    if (id === null || environments.has(id)) continue;
    const project = row[`${slot}_project`];
    environments.set(id, read(project === null ? null : environmentObject({
      id, projectId: project, slug: row[`${slot}_slug`]!, owner: row[`${slot}_owner`], parentId: row[`${slot}_parent`],
      protected: row[`${slot}_protected`], archived: row[`${slot}_archived`] === true, projectArchived: row[`${slot}_project_archived`] === true,
    }), row[`${slot}_seal`], last(slot)));
  }
  const view: UseView = {
    credential,
    principal,
    roles: read(row.r_value === null ? null : configObject(row.r_value) as RolesInput, row.r_seal, cached.r),
    policy: read(row.p_value === null ? null : configObject(row.p_value) as PolicyInput, row.p_seal, cached.p),
    secret,
    source,
    environments,
    // Behind Access, the account is the way in: its cap is read with it.
    bulk: (request.way === 'access' ? principal?.row ?? null : credential.row) === null ? null : { inSet: row.in_set === true, others: Number(row.others ?? 0) },
  };
  // UsesSeeOldWrites: 0.14's newest access entry about the principal, at or below the one its newest change accounts for.
  const old = cached.mOld;
  const accounted = row.m_access === null || (old !== null && BigInt(row.m_access) <= BigInt(old));
  return { view, ids, changed: moved.length > 0, accounted };
}

const UNKNOWN = Buffer.alloc(0);

/**
 * The way in's object, from its row's columns as the call read them (T147): a credential's or a connection's, its
 * columns; a binding's, its whole row (`w_row`); behind Access none, the account's row being all of it.
 */
function wayObject(row: UseRow, request: UseRequest): WayInput | null {
  if (row.c_principal === null) return null;
  const expiresAt = row.c_expires === null ? null : Number(row.c_expires);
  switch (request.way ?? 'credential') {
    case 'credential':
      return credentialObject({ id: request.credential, principal: row.c_principal, kind: row.c_kind!, scope: row.c_scope, revoked: row.c_revoked === true, expiresAt, generation: row.c_generation! });
    case 'connection':
      return connectionObject({ id: request.credential, principal: row.c_principal, generation: row.c_generation!, expiresAt: expiresAt!, revoked: row.c_revoked === true });
    case 'binding': {
      const b = row.w_row;
      if (b === null) return null;
      const text = (value: unknown) => (value == null ? null : String(value));
      return bindingObject({
        id: request.credential, principal: String(b.principal), generation: Number(b.generation), profile: String(b.profile), issuer: String(b.issuer),
        // A sealed binding names the instance it was made on (0040): one with none bears out no seal.
        origin: text(b.origin) ?? '', jwksUri: String(b.jwks_uri), claims: String(b.claims), scope: text(b.scope), policy: text(b.policy), revoked: b.revoked_at != null,
      });
    }
    case 'access':
      return null;
  }
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
function checkedOf(keys: SealKeys, view: UseView, request: UseRequest, accounted: boolean, seals?: typeof sealed): CheckedView {
  const checked = checkSeals(keys, view, request, seals);
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
