import { MAX_KEYS, verifyWorkloadToken, WorkloadTokenRefused, type JSONWebKeySet } from '@coffre/core/identity';

import { FetchRefused, type WorkloadTransport } from './transport.ts';

/**
 * Issuers' keys, as this isolate (or process) last fetched them. Settled
 * values only: a key set and when it came, when a fetch last failed (none
 * since the last that worked), and when a token last named a key the set
 * lacked; never a fetch under way. Two first exchanges in one isolate each
 * fetch, rather than one waiting on the other's request, which Cloudflare
 * cancels as hung once the first ends (AGENTS.md, "What an isolate keeps").
 */
type Entry = { keys: JSONWebKeySet | null; fetchedAt: number; failedAt: number | null; missedAt: number | null };

/** A key set is used for ten minutes, then fetched again. */
export const KEYS_FRESH_MS = 10 * 60 * 1000;
/**
 * How old a set may be and still verify when it cannot be fetched again: the
 * issuer unreachable, or its URL cooling down after a failed fetch (T258).
 *
 * What it risks is a key the issuer withdrew, which verifies until coffre
 * holds a set without it: for `KEYS_FRESH_MS` at most while the issuer
 * answers, as before, and for this long while it does not. A rotation
 * withdraws the old key only once the tokens it signed have expired, or the
 * issuer would break its own tokens at every verifier: 5 minutes after the
 * switch for GitHub's ID tokens (`exp` is `iat` + 300 s), an hour for
 * Kubernetes' projected service account tokens (`expirationSeconds`'
 * default; its key rotation keeps the old public key in
 * `--service-account-key-file` until they expire). A key that new tokens
 * name is fetched for at once, stale or not (OpenID Connect Core, 10.1.1).
 * So the bound only weighs an emergency withdrawal, a key leaked, against
 * an issuer that cannot serve its keys at the same time.
 *
 * An hour from the fetch: as long as a Kubernetes key stays valid after a
 * planned switch, and the age coffre already accepts for a token no issuer
 * can be asked about (`MAX_TOKEN_AGE_SECONDS`, uploaded keys); and far past
 * a blip of the endpoint (T258: one 10 s timeout in three probes). An issuer
 * unreachable for longer is down, not flaky, and its runs fail with it.
 */
export const KEYS_STALE_MS = 60 * 60 * 1000;
/**
 * After a failed fetch, or a key the set lacks, this long before that URL is
 * fetched again, while a set still verifies meanwhile: the fetch an exchange
 * would wait on, up to `FETCH_DEADLINE_MS`, is made once a minute at most.
 * After a key the set lacks, at most until the set is due anyway.
 */
export const KEYS_COOLDOWN_MS = 60 * 1000;
/**
 * The same with no set to verify with, a cold isolate's or one past
 * `KEYS_STALE_MS`: every exchange fails meanwhile, so the wait is short
 * enough for the CLI to ask again within it. Its `Retry-After` is what is
 * left of this (`IssuerUnavailable.retryAfter`), and the CLI waits at least
 * that when it is 10 s or less (`unavailableWait` in `packages/cli/src/main.ts`,
 * as since 0.14.3), then again: the cooldown starts as the fetch fails,
 * when the 503 is sent, so each retry comes after the URL may be fetched
 * again, 5 to 7.5 s after the answer before it, and two of them reach past
 * a blip like T258's. It still spares an unreachable issuer: an isolate
 * starts no fetch of its keys within 5 s of one that failed, nor beside one
 * that follows a failure, whatever anonymous requests ask of it.
 */
export const KEYS_COLD_COOLDOWN_MS = 5_000;
/** At most this many key sets, and `MAX_KEYS` keys in each. */
export const MAX_KEY_SETS = 64;

const entries = new Map<string, Entry>();

/** The issuer could not be asked for its keys, or will not be for a while. Not a verdict on the token. */
export class IssuerUnavailable extends Error {
  /** When the URL may be fetched again, in whole seconds from now, at least 1: the 503's `Retry-After`. */
  readonly retryAfter: number;
  constructor(message: string, retryAfter: number, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'IssuerUnavailable';
    this.retryAfter = retryAfter;
  }
}

/** Forget every key set: for tests, which play several issuers in one process. */
export function forgetKeys(): void {
  entries.clear();
}

/**
 * Fetch the set at `url` and keep it, or keep that the fetch failed. Times
 * are read when the fetch settles, not when the exchange began: a fetch that
 * ran out its `FETCH_DEADLINE_MS` starts its cooldown, and its `Retry-After`,
 * as it fails. A failure while a set is kept says so once, never with a
 * token's contents: that set verifies until the URL may be fetched again,
 * and the exchanges meanwhile keep quiet. A failure after another exchange
 * fetched the set, since this fetch began, is no failure: that set is as
 * new as this one would have been, and is this fetch's answer.
 */
async function fetchKeys(transport: WorkloadTransport, url: string): Promise<JSONWebKeySet> {
  const began = Date.now();
  try {
    const document = await transport.json(new URL(url));
    const keys = (document as { keys?: unknown } | null)?.keys;
    if (!Array.isArray(keys) || keys.length === 0) throw new FetchRefused(new URL(url), 'holds no keys');
    if (keys.length > MAX_KEYS) throw new FetchRefused(new URL(url), `holds more than ${MAX_KEYS} keys`);
    const set = { keys: keys.filter((key) => typeof key === 'object' && key !== null && (key as { use?: unknown }).use !== 'enc') } as JSONWebKeySet;
    remember(url, { keys: set, fetchedAt: Date.now(), failedAt: null, missedAt: null });
    return set;
  } catch (error) {
    const now = Date.now();
    // The entry as it is now: another exchange may have fetched meanwhile.
    const latest = entries.get(url);
    if (latest?.keys != null && latest.fetchedAt >= began) return latest.keys;
    const entry = { ...(latest ?? { keys: null, fetchedAt: 0, missedAt: null }), failedAt: now };
    remember(url, entry);
    const message = `the issuer's keys could not be fetched: ${(error as Error).message}`;
    if (kept(entry, now) !== null) console.warn(`verifying with the issuer's keys fetched ${Math.round((now - entry.fetchedAt) / 60_000)} min ago: ${message}`);
    throw unavailable(message, entry, now, error);
  }
}

function remember(url: string, entry: Entry): void {
  entries.delete(url);
  entries.set(url, entry);
  // The oldest go first.
  while (entries.size > MAX_KEY_SETS) entries.delete(entries.keys().next().value!);
}

/** The set kept for `url`, if it may still verify when it cannot be fetched again. */
function kept(entry: Entry | undefined, now: number): JSONWebKeySet | null {
  return entry?.keys != null && now - entry.fetchedAt < KEYS_STALE_MS ? entry.keys : null;
}

/**
 * How long before `url` is fetched again, in ms: none once its cooldown has
 * run out. After a failed fetch, the long cooldown while a set is kept, the
 * short one from when none is, which may come first: a set an hour old at
 * 10:00, its fetch failed at 09:59:59, may be fetched again at 10:00:04, not
 * 10:00:59. After a key the set lacked, the long one, or until the set is
 * due, which a missed key never delays: a set fetched at 09:00, a key missed
 * at 09:09:30, is fetched again at 09:10.
 */
function cooldownLeft(entry: Entry | undefined, now: number): number {
  let next = 0;
  if (entry?.failedAt != null) {
    const staleAt = entry.keys === null ? 0 : entry.fetchedAt + KEYS_STALE_MS;
    next = Math.min(entry.failedAt + KEYS_COOLDOWN_MS, Math.max(staleAt, entry.failedAt + KEYS_COLD_COOLDOWN_MS));
  }
  if (entry?.missedAt != null) next = Math.max(next, Math.min(entry.missedAt + KEYS_COOLDOWN_MS, entry.fetchedAt + KEYS_FRESH_MS));
  return Math.max(0, next - now);
}

function unavailable(message: string, entry: Entry | undefined, now: number, cause?: unknown): IssuerUnavailable {
  return new IssuerUnavailable(message, Math.max(1, Math.ceil(cooldownLeft(entry, now) / 1000)), { cause });
}

/** The token's key is not in a set fetched just now: the issuer's, or no one's. */
const KEY_ABSENT = "the token's key is not among the issuer's, which were fetched a moment ago";

/**
 * Verify a token under the keys at `url`: the cached set while fresh, else
 * fetched. At most one fetch an exchange: a key missing from a set this
 * call fetched is not there, and a key missing from an older set is fetched
 * for once, in case the issuer rotated. Either way the URL then waits a
 * minute before the next fetch, and until then `IssuerUnavailable`.
 *
 * When the set cannot be fetched again, the issuer unreachable or its URL
 * cooling down after a failed fetch, the set kept stands in while it is
 * younger than `KEYS_STALE_MS`, and a token whose key it lacks is
 * `IssuerUnavailable` (whether the issuer rotated cannot be asked). With no
 * such set, `IssuerUnavailable`, until a fetch may be made again
 * (`KEYS_COLD_COOLDOWN_MS`).
 */
export async function verifyWithKeys(
  transport: WorkloadTransport,
  url: string,
  token: string,
  expected: { issuer: string; audience: string; now: Date; maxAge?: null },
): ReturnType<typeof verifyWorkloadToken> {
  // The cache's clock, read again after each fetch; `expected.now` is the token's.
  const now = Date.now();
  let entry = entries.get(url);
  let keys = entry?.keys != null && now - entry.fetchedAt < KEYS_FRESH_MS ? entry.keys : null;
  let fetched = false;
  // Why the set kept stands in for one that could not be fetched, when it does.
  let standing: IssuerUnavailable | null = null;
  if (keys === null) {
    if (cooldownLeft(entry, now) > 0) {
      standing = unavailable("the issuer's keys could not be fetched a moment ago", entry, now);
      keys = kept(entry, now);
      if (keys === null) throw standing;
    } else {
      // A fetch after a failed one counts as failed until it settles, so that
      // the exchanges meanwhile use the set kept, or are answered at once,
      // rather than each fetch too: one attempt in flight per cooldown. Only
      // after a failure, which was said: due after a key missed, or simply
      // due, the exchanges meanwhile each fetch, as a cold isolate's do.
      if (entry?.failedAt != null) remember(url, { ...entry, failedAt: now });
      try {
        keys = await fetchKeys(transport, url);
        fetched = true;
      } catch (error) {
        // The set kept as it is now, not as it was before the fetch: one another exchange fetched meanwhile, without a key this one's held, wins.
        keys = kept(entries.get(url), Date.now());
        if (keys === null) throw error;
        standing = error as IssuerUnavailable;
      }
    }
  }
  try {
    return await verifyWorkloadToken(token, keys, expected);
  } catch (error) {
    if (!absentKey(error)) throw error;
    // Whether the issuer rotated cannot be asked: as unavailable as the fetch that failed.
    if (standing !== null) throw standing;
    const at = Date.now();
    entry = entries.get(url);
    if (fetched || cooldownLeft(entry, at) > 0) {
      if (fetched) remember(url, { ...(entry ?? { keys, fetchedAt: at, failedAt: null }), missedAt: at });
      throw unavailable(KEY_ABSENT, entries.get(url), at);
    }
    // The issuer may have rotated: fetch once, and wait a minute before the next.
    remember(url, { ...(entry ?? { keys: null, fetchedAt: 0, failedAt: null }), missedAt: at });
    const fresh = await fetchKeys(transport, url);
    const after = Date.now();
    remember(url, { keys: fresh, fetchedAt: after, failedAt: null, missedAt: after });
    try {
      return await verifyWorkloadToken(token, fresh, expected);
    } catch (refetched) {
      if (absentKey(refetched)) throw unavailable(KEY_ABSENT, entries.get(url), Date.now());
      throw refetched;
    }
  }
}

function absentKey(error: unknown): boolean {
  return error instanceof WorkloadTokenRefused && error.reason === 'unknown_key';
}
