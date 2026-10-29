import { MAX_KEYS, verifyWorkloadToken, WorkloadTokenRefused, type JSONWebKeySet } from '../identity/workload-token.ts';

import { FETCH_DEADLINE_MS, FetchRefused, type WorkloadTransport } from './transport.ts';

/**
 * Issuers' keys, as this isolate (or process) last fetched them. Settled
 * values only: a key set and when it came, or when a fetch last failed,
 * never a fetch under way. Two first exchanges in one isolate each fetch,
 * rather than one waiting on the other's request, which Cloudflare cancels
 * as hung once the first ends (AGENTS.md, "What an isolate keeps").
 */
type Entry = { keys: JSONWebKeySet | null; fetchedAt: number; failedAt: number | null };

/** A key set is used for ten minutes, then fetched again. */
export const KEYS_FRESH_MS = 10 * 60 * 1000;
/** After a failed fetch, or a key the set lacks, this long before that URL is fetched again. */
export const KEYS_COOLDOWN_MS = 60 * 1000;
/**
 * At most this many key sets, and `MAX_KEYS` keys in each. A set in its
 * minute's wait is never the one evicted, and a URL not among them is
 * fetched only while there is room for it, counting the first fetches under
 * way (`room`): cycling tokens through more URLs than the cache holds, one
 * after another or all at once, buys at most this many fetches a minute
 * (reviews r1, r2).
 */
export const MAX_KEY_SETS = 64;

const entries = new Map<string, Entry>();

/**
 * The first fetches under way of URLs the cache does not hold, by when each
 * began: a time, never the fetch, so no call waits on another's. One that a
 * cancelled request never finished stops counting after `STARTED_MS`.
 */
const started = new Map<string, number>();
const STARTED_MS = 2 * FETCH_DEADLINE_MS;

/** The issuer could not be asked for its keys, or will not be for a while. Not a verdict on the token. */
export class IssuerUnavailable extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'IssuerUnavailable';
  }
}

/** Forget every key set: for tests, which play several issuers in one process. */
export function forgetKeys(): void {
  entries.clear();
  started.clear();
}

/** How many key sets this isolate holds: for tests, of the bound. */
export function keySetsHeld(): number {
  return entries.size;
}

async function fetchKeys(transport: WorkloadTransport, url: string, now: number): Promise<JSONWebKeySet> {
  try {
    const document = await transport.json(new URL(url));
    const keys = (document as { keys?: unknown } | null)?.keys;
    if (!Array.isArray(keys) || keys.length === 0) throw new FetchRefused(new URL(url), 'holds no keys');
    if (keys.length > MAX_KEYS) throw new FetchRefused(new URL(url), `holds more than ${MAX_KEYS} keys`);
    const set = { keys: keys.filter((key) => typeof key === 'object' && key !== null && (key as { use?: unknown }).use !== 'enc') } as JSONWebKeySet;
    remember(url, { keys: set, fetchedAt: now, failedAt: null }, now);
    return set;
  } catch (error) {
    remember(url, { keys: entries.get(url)?.keys ?? null, fetchedAt: entries.get(url)?.fetchedAt ?? 0, failedAt: now }, now);
    throw new IssuerUnavailable(`the issuer's keys could not be fetched: ${(error as Error).message}`, { cause: error });
  }
}

function remember(url: string, entry: Entry, now: number): void {
  entries.delete(url);
  entries.set(url, entry);
  // The oldest go first, but for those waiting their minute: their wait outlives no eviction. Should every other be
  // waiting (`room` counted one that has begun waiting since), the oldest of them: the bound holds whatever the timing.
  while (entries.size > MAX_KEY_SETS) {
    let victim: string | undefined;
    for (const [held, kept] of entries) {
      if (held === url) continue;
      victim ??= held;
      if (!cooling(kept, now)) {
        victim = held;
        break;
      }
    }
    entries.delete(victim!);
  }
}

/**
 * Whether a URL the cache does not hold may be fetched: while the sets
 * held and the first fetches under way of others leave a place, or as many
 * sets as those fetches would take are not waiting their minute, to be
 * evicted for them.
 */
function room(url: string, now: number): boolean {
  let under = 0;
  for (const [other, at] of started) {
    if (now - at >= STARTED_MS || at > now) started.delete(other);
    else if (other !== url) under += 1;
  }
  if (entries.size + under < MAX_KEY_SETS) return true;
  let evictable = 0;
  for (const entry of entries.values()) if (!cooling(entry, now)) evictable += 1;
  return evictable > under;
}

function cooling(entry: Entry | undefined, now: number): boolean {
  return entry?.failedAt != null && now - entry.failedAt < KEYS_COOLDOWN_MS;
}

/** The token's key is not in a set fetched just now: the issuer's, or no one's. */
const KEY_ABSENT = "the token's key is not among the issuer's, which were fetched a moment ago; try again in a minute";

/**
 * Verify a token under the keys at `url`: the cached set while fresh, else
 * fetched. At most one fetch an exchange: a key missing from a set this
 * call fetched is not there, and a key missing from an older set is fetched
 * for once, in case the issuer rotated. Either way the URL then waits a
 * minute before the next fetch, and until then, or while the issuer cannot
 * be reached, `IssuerUnavailable`. Fresh cached keys work all the while.
 */
export async function verifyWithKeys(
  transport: WorkloadTransport,
  url: string,
  token: string,
  expected: { issuer: string; audience: string; now: Date; maxAge?: null },
): ReturnType<typeof verifyWorkloadToken> {
  const now = expected.now.getTime();
  let entry = entries.get(url);
  let keys = entry?.keys != null && now - entry.fetchedAt < KEYS_FRESH_MS ? entry.keys : null;
  const fetched = keys === null;
  if (keys === null) {
    if (cooling(entry, now) || (entry === undefined && !room(url, now))) throw new IssuerUnavailable("the issuer's keys could not be fetched a moment ago; try again in a minute");
    if (entry === undefined) started.set(url, now);
    try {
      keys = await fetchKeys(transport, url, now);
    } finally {
      if (entry === undefined) started.delete(url);
    }
  }
  try {
    return await verifyWorkloadToken(token, keys, expected);
  } catch (error) {
    if (!absentKey(error)) throw error;
    entry = entries.get(url);
    if (fetched || cooling(entry, now)) {
      if (fetched) remember(url, { ...(entry ?? { keys, fetchedAt: now }), failedAt: now }, now);
      throw new IssuerUnavailable(KEY_ABSENT);
    }
    // The issuer may have rotated: fetch once, and wait a minute before the next.
    remember(url, { ...(entry ?? { keys: null, fetchedAt: 0 }), failedAt: now }, now);
    const fresh = await fetchKeys(transport, url, now);
    remember(url, { keys: fresh, fetchedAt: now, failedAt: now }, now);
    try {
      return await verifyWorkloadToken(token, fresh, expected);
    } catch (refetched) {
      if (absentKey(refetched)) throw new IssuerUnavailable(KEY_ABSENT);
      throw refetched;
    }
  }
}

function absentKey(error: unknown): boolean {
  return error instanceof WorkloadTokenRefused && error.reason === 'unknown_key';
}
