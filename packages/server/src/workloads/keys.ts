import { MAX_KEYS, verifyWorkloadToken, WorkloadTokenRefused, type JSONWebKeySet } from '@coffre/core/identity';

import { FetchRefused, type WorkloadTransport } from './transport.ts';

/**
 * Issuers' keys, as this isolate (or process) last fetched them. Settled
 * values only: a key set and when it came, or when to fetch it again, never
 * a fetch under way. Two first exchanges in one isolate each fetch, rather
 * than one waiting on the other's request, which Cloudflare cancels as hung
 * once the first ends (AGENTS.md, "What an isolate keeps").
 */
type Entry = {
  /** The set last fetched, and when. */
  keys: JSONWebKeySet | null;
  fetchedAt: number;
  /** Until when `keys` stand in for a set the issuer cannot be asked for now (`keptFor`). */
  keptUntil: number;
  /** No fetch of the URL before `until`; until then a token no kept key verifies is told `why`. */
  quiet: { until: number; why: string } | null;
};

/** A key set is used for ten minutes, then fetched again. */
export const KEYS_FRESH_MS = 10 * 60 * 1000;
/**
 * The longest a set stands in, from its fetch, while the issuer cannot be
 * reached: an hour, or less if its `Cache-Control` says so (`keptFor`).
 * GitHub's says `max-age=3600, must-revalidate`: kept no longer than it
 * allows any cache to.
 */
export const KEYS_KEPT_MS = 60 * 60 * 1000;
/** After a key the set lacks, or an issuer that answered anything but its keys, this long before that URL is fetched again. */
export const KEYS_COOLDOWN_MS = 60 * 1000;
/** After an issuer that did not answer, twice: a blip passes in seconds, and the CLI asks again after it (its `Retry-After`). */
export const KEYS_UNREACHED_MS = 10 * 1000;
/** At most this many key sets, and `MAX_KEYS` keys in each. */
export const MAX_KEY_SETS = 64;

const entries = new Map<string, Entry>();

/**
 * The issuer could not be asked for its keys, or will not be for a while.
 * Not a verdict on the token. `retryAfter`, in seconds: when the URL is
 * fetched again. `transient`: the issuer did not answer, where a moment
 * later it may (`FetchRefused`).
 */
export class IssuerUnavailable extends Error {
  readonly retryAfter: number;
  readonly transient: boolean;
  constructor(why: string, retryAfter: number, options?: { cause?: unknown; transient?: boolean }) {
    super(`${why}; try again in ${retryAfter} s`, options);
    this.name = 'IssuerUnavailable';
    this.retryAfter = retryAfter;
    this.transient = options?.transient ?? false;
  }
}

/** Forget every key set: for tests, which play several issuers in one process. */
export function forgetKeys(): void {
  entries.clear();
}

/**
 * How long a set may stand in, from its fetch, by its answer's
 * `Cache-Control`: its `max-age`, up to `KEYS_KEPT_MS`; `KEYS_KEPT_MS`
 * when it says none. Never less than `KEYS_FRESH_MS`, which is coffre's own
 * refresh and keeps a set that long whatever the issuer says, as before.
 *
 *   public, max-age=3600, must-revalidate     an hour (GitHub's)
 *   max-age=300                               ten minutes: no stand-in past fresh
 *   no-store, or no-cache                     ten minutes
 *   (none)                                    an hour
 */
export function keptFor(cacheControl: string | null): number {
  if (cacheControl === null) return KEYS_KEPT_MS;
  if (/(^|,)\s*no-(store|cache)\s*(=|,|$)/i.test(cacheControl)) return KEYS_FRESH_MS;
  const maxAge = /(^|,)\s*max-age\s*=\s*"?(\d+)"?\s*(,|$)/i.exec(cacheControl);
  if (maxAge === null) return KEYS_KEPT_MS;
  return Math.max(KEYS_FRESH_MS, Math.min(KEYS_KEPT_MS, Number(maxAge[2]) * 1000));
}

/**
 * The keys at `url`, fetched now, and kept. When the issuer did not answer
 * and `retry`, asked once more at once, on a connection of its own: a
 * request lost on its way, or one host of many stuck, rarely is twice.
 * Failing, that URL waits `KEYS_UNREACHED_MS` before the next fetch, or
 * `KEYS_COOLDOWN_MS` after an answer that was not its keys, which also ends
 * the stand-in of the set kept: an issuer that answers anything but keys is
 * not one whose old keys outlive their ten minutes.
 */
async function fetchKeys(transport: WorkloadTransport, url: string, issuer: string, now: number, retry: boolean): Promise<JSONWebKeySet> {
  const started = performance.now();
  for (let attempt = 1; ; attempt++) {
    let cacheControl: string | null = null;
    try {
      const document = await transport.json(new URL(url), (value) => (cacheControl = value));
      const keys = (document as { keys?: unknown } | null)?.keys;
      if (!Array.isArray(keys) || keys.length === 0) throw new FetchRefused(new URL(url), 'holds no keys');
      if (keys.length > MAX_KEYS) throw new FetchRefused(new URL(url), `holds more than ${MAX_KEYS} keys`);
      const set = { keys: keys.filter((key) => typeof key === 'object' && key !== null && (key as { use?: unknown }).use !== 'enc') } as JSONWebKeySet;
      remember(url, { keys: set, fetchedAt: now, keptUntil: now + keptFor(cacheControl), quiet: null });
      return set;
    } catch (error) {
      const transient = error instanceof FetchRefused && error.transient;
      if (transient && retry && attempt === 1) continue;
      // From when it failed: two attempts at the deadline take ten seconds.
      const at = now + Math.round(performance.now() - started);
      const pause = transient ? KEYS_UNREACHED_MS : KEYS_COOLDOWN_MS;
      const why =
        `coffre could not fetch the signing keys of the issuer ${issuer} (${(error as Error).message}): ` +
        'its own request to the issuer failed, not the token or the job that sent it';
      // One line a failed fetch, which the quiet after it spaces out.
      console.error({ event: 'workload_keys_unfetched', url, attempts: attempt, transient, error: (error as Error).message }, "coffre could not fetch an issuer's signing keys");
      const entry = entries.get(url);
      const kept = entry?.keys == null ? 0 : transient ? entry.keptUntil : Math.min(entry.keptUntil, entry.fetchedAt + KEYS_FRESH_MS);
      remember(url, { keys: entry?.keys ?? null, fetchedAt: entry?.fetchedAt ?? 0, keptUntil: kept, quiet: { until: at + pause, why } });
      throw new IssuerUnavailable(why, pause / 1000, { cause: error, transient });
    }
  }
}

function remember(url: string, entry: Entry): void {
  entries.delete(url);
  entries.set(url, entry);
  // The oldest go first.
  while (entries.size > MAX_KEY_SETS) entries.delete(entries.keys().next().value!);
}

/** The URL's quiet, still on at `now`, or null. */
function quiet(url: string, now: number): { until: number; why: string } | null {
  const pause = entries.get(url)?.quiet ?? null;
  return pause !== null && now < pause.until ? pause : null;
}

/** `IssuerUnavailable` for a quiet: its reason, and the seconds it has left. */
function quieted(pause: { until: number; why: string }, now: number): IssuerUnavailable {
  return new IssuerUnavailable(pause.why, Math.max(1, Math.ceil((pause.until - now) / 1000)));
}

/** Why a token is refused whose key a set lacks that coffre fetched a moment ago. */
function absentWhy(url: string, issuer: string): string {
  return `the token's key is not among the signing keys ${issuer} publishes, which coffre fetched from ${url} a moment ago`;
}

/** No fetch of `url` for `KEYS_COOLDOWN_MS` from `now`, for `why`: what a token no kept key verifies is told until then. */
function pauseFor(url: string, now: number, why: string): { until: number; why: string } {
  const pause = { until: now + KEYS_COOLDOWN_MS, why };
  remember(url, { ...(entries.get(url) ?? { keys: null, fetchedAt: 0, keptUntil: 0 }), quiet: pause });
  return pause;
}

/**
 * Verify a token under the keys at `url`: the cached set while fresh, else
 * fetched. A fetch that finds the issuer unreachable leaves the set fetched
 * last standing in, until `keptFor` ends it; a key that set lacks is
 * `IssuerUnavailable`, never verified, as is any token once no set stands.
 *
 * At most one fetch an exchange, asked twice when the issuer did not answer
 * and no set stands in: a key missing from a set this call fetched is not
 * there, and a key missing from a fresh set is fetched for once, in case
 * the issuer rotated. Either way the URL then waits a minute before the
 * next fetch (an unreachable issuer, `KEYS_UNREACHED_MS`), and until then a
 * token its kept keys cannot verify is `IssuerUnavailable`. Kept keys work
 * all the while.
 *
 *   fresh set has the kid                       verified, no fetch
 *   stale set; GitHub answers                   fetched, verified under the new set
 *   stale set, 40 min old; GitHub times out     verified under the old set, after one attempt
 *   stale set, 70 min old; GitHub times out     two attempts, then 503, Retry-After 10
 *   cold isolate; GitHub times out, then 200    two attempts, verified
 *   fresh set lacks the kid                     one fetch; 503, Retry-After 60, if the new set lacks it too
 */
export async function verifyWithKeys(
  transport: WorkloadTransport,
  url: string,
  token: string,
  expected: { issuer: string; audience: string; now: Date; maxAge?: null },
): ReturnType<typeof verifyWorkloadToken> {
  const now = expected.now.getTime();
  const entry = entries.get(url);
  const fresh = entry?.keys != null && now - entry.fetchedAt < KEYS_FRESH_MS;
  // Why the set verifying is one kept past fresh, if it is: the token is told that, should the set lack its key.
  let standIn: IssuerUnavailable | null = null;
  let fetched = false;
  let keys: JSONWebKeySet;
  if (fresh) {
    keys = entry.keys!;
  } else {
    const kept = entry?.keys != null && now < entry.keptUntil ? entry.keys : null;
    const pause = quiet(url, now);
    if (pause !== null) {
      standIn = quieted(pause, now);
      if (kept === null) throw standIn;
      keys = kept;
    } else {
      try {
        keys = await fetchKeys(transport, url, expected.issuer, now, kept === null);
        fetched = true;
      } catch (error) {
        if (!(error instanceof IssuerUnavailable && error.transient) || kept === null) throw error;
        standIn = error;
        keys = kept;
      }
    }
  }
  try {
    return await verifyWorkloadToken(token, keys, expected);
  } catch (error) {
    if (!absentKey(error)) throw error;
    if (fetched) throw quieted(pauseFor(url, now, absentWhy(url, expected.issuer)), now);
    if (standIn !== null) throw standIn;
    const pause = quiet(url, now);
    if (pause !== null) throw quieted(pause, now);
  }
  // The issuer may have rotated: fetch once, and wait a minute before the next, whatever it finds. Paused first, so that
  // a token naming another unknown key meanwhile fetches nothing.
  pauseFor(url, now, absentWhy(url, expected.issuer));
  const rotated = await fetchKeys(transport, url, expected.issuer, now, true);
  const pause = pauseFor(url, now, absentWhy(url, expected.issuer));
  try {
    return await verifyWorkloadToken(token, rotated, expected);
  } catch (error) {
    if (absentKey(error)) throw quieted(pause, now);
    throw error;
  }
}

function absentKey(error: unknown): boolean {
  return error instanceof WorkloadTokenRefused && error.reason === 'unknown_key';
}
