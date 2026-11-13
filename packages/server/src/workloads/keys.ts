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
  /** The last fetch's failure, until the URL may be fetched again; a success clears it. */
  failed: Failure | null;
  /** No fetch for a key the set lacks before then: the minute after one (`KEYS_COOLDOWN_MS`). Only that path sets or reads it. */
  kidUntil: number;
};

/**
 * A fetch that failed: no fetch of the URL before `until`. `message`, the
 * transport's, says what it met; the 503 names each token's own issuer,
 * since bindings to several issuers may share one URL. `standIn` when the
 * issuer did not answer: then, and only then, a set past fresh verifies
 * meanwhile, up to `keptUntil`.
 */
type Failure = { until: number; message: string; standIn: boolean };

/**
 * The time the cache goes by: the caller's `now` (tests set it), moved on by
 * what this call has spent since, its fetches included. A fetch that takes
 * five seconds dates what it finds five seconds later.
 */
type Clock = () => number;

/** A key set is used for ten minutes, then fetched again. */
export const KEYS_FRESH_MS = 10 * 60 * 1000;
/**
 * The longest a set stands in, from its fetch, while the issuer cannot be
 * reached: an hour, or less if its `Cache-Control` says so (`keptFor`).
 * GitHub's says `max-age=3600, must-revalidate`, with no `Age`: kept no
 * longer than it allows any cache to. `max-age` counts from coffre's fetch;
 * an `Age` the answer gives is not subtracted.
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
 * `Cache-Control` (RFC 9111, section 5.2): its `max-age`, up to
 * `KEYS_KEPT_MS`; `KEYS_KEPT_MS` when it says none. Never less than
 * `KEYS_FRESH_MS`, which is coffre's own refresh and keeps a set that long
 * whatever the issuer says. A header it cannot read, or a
 * `max-age` given twice or not as a number, keeps nothing past fresh.
 *
 *   public, max-age=3600, must-revalidate     an hour (GitHub's)
 *   max-age=300                               ten minutes: no stand-in past fresh
 *   no-store, or no-cache                     ten minutes
 *   x-note="a, max-age=3600", max-age=600     ten minutes: the quoted one is a note's
 *   max-age=600, max-age=3600                 ten minutes
 *   (none)                                    an hour
 */
export function keptFor(cacheControl: string | null): number {
  if (cacheControl === null) return KEYS_KEPT_MS;
  const said = directives(cacheControl);
  if (said === null || said.some(([name]) => name === 'no-store' || name === 'no-cache')) return KEYS_FRESH_MS;
  const maxAges = said.filter(([name]) => name === 'max-age');
  if (maxAges.length === 0) return KEYS_KEPT_MS;
  const seconds = maxAges[0][1];
  if (maxAges.length > 1 || seconds === null || !/^\d+$/.test(seconds)) return KEYS_FRESH_MS;
  return Math.max(KEYS_FRESH_MS, Math.min(KEYS_KEPT_MS, Number(seconds) * 1000));
}

const TOKEN = "[!#$%&'*+.^_`|~0-9A-Za-z-]+";
/** One element of a `Cache-Control` list: a name, and a value, a token or a quoted string; then a comma, or the end. */
const DIRECTIVE = new RegExp(`[ \\t]*(?:(${TOKEN})[ \\t]*(?:=[ \\t]*(?:"((?:[^"\\\\]|\\\\.)*)"|(${TOKEN})))?[ \\t]*)?(?:,|$)`, 'y');

/** The directives of a `Cache-Control` header, names lowercased, quoted values unescaped; null for one that is not a list of them. */
function directives(header: string): Array<[name: string, value: string | null]> | null {
  const found: Array<[string, string | null]> = [];
  DIRECTIVE.lastIndex = 0;
  while (DIRECTIVE.lastIndex < header.length) {
    const at = DIRECTIVE.lastIndex;
    const match = DIRECTIVE.exec(header);
    if (match === null || DIRECTIVE.lastIndex === at) return null;
    if (match[1] !== undefined) found.push([match[1].toLowerCase(), match[2]?.replace(/\\(.)/g, '$1') ?? match[3] ?? null]);
  }
  return found;
}

/**
 * The keys at `url`, fetched now, and kept. When the issuer did not answer
 * and `retry`, asked once more at once (on Node, on a connection of its
 * own): a request lost on its way, or one host of many stuck, rarely is
 * twice. Not after a 429, which asks for time, nor once another call's
 * failure has stopped fetches of the URL meanwhile. Failing, that URL waits
 * `KEYS_UNREACHED_MS` before the next fetch, or `KEYS_COOLDOWN_MS` after an
 * answer that was not its keys, which also ends the stand-in of the set
 * kept: an issuer that answers anything but keys is not one whose old keys
 * outlive their ten minutes.
 *
 * A fetch that fails after another call fetched the URL meanwhile takes
 * that call's set instead, as new as its own would have been, and asks no
 * more: say a stale set, A's fetch hanging, B's answered, then A's timing
 * out: A verifies under B's set.
 *
 * Another call's failure may stand meanwhile too. It stays, so that every
 * `Retry-After` it was told stays true, unless it was a timeout's and this
 * one a definite answer, which ends the stand-in; the 503 says the failure
 * that stands, and its time left. `kid`, for a fetch for a key the set
 * lacked, is the end of the minute this call paused such fetches for: a
 * failure lifts it, since the issuer said nothing of that key, and the
 * failure alone then holds the next one back. A minute another call set
 * since stays.
 */
async function fetchKeys(
  transport: WorkloadTransport,
  url: string,
  issuer: string,
  clock: Clock,
  { retry, kid }: { retry: boolean; kid: number | null },
): Promise<JSONWebKeySet> {
  const before = entries.get(url)?.keys ?? null;
  for (let attempt = 1; ; attempt++) {
    let cacheControl: string | null = null;
    try {
      const document = await transport.json(new URL(url), (value) => (cacheControl = value));
      const keys = (document as { keys?: unknown } | null)?.keys;
      if (!Array.isArray(keys) || keys.length === 0) throw new FetchRefused(new URL(url), 'holds no keys');
      if (keys.length > MAX_KEYS) throw new FetchRefused(new URL(url), `holds more than ${MAX_KEYS} keys`);
      const set = { keys: keys.filter((key) => typeof key === 'object' && key !== null && (key as { use?: unknown }).use !== 'enc') } as JSONWebKeySet;
      const at = clock();
      remember(url, { keys: set, fetchedAt: at, keptUntil: at + keptFor(cacheControl), failed: null, kidUntil: entries.get(url)?.kidUntil ?? 0 });
      return set;
    } catch (error) {
      const transient = error instanceof FetchRefused && error.transient;
      const at = clock();
      const entry = entries.get(url);
      const meanwhile = entry?.keys != null && entry.keys !== before;
      const standing = failure(url, at);
      const retrying = transient && retry && attempt === 1 && !meanwhile && standing === null && (error as FetchRefused).status !== 429;
      // One line a failed fetch, the one a retry then answers included; the quiet after the last spaces them out.
      console.error({ event: 'workload_keys_unfetched', url, attempt, transient, retrying, error: (error as Error).message }, "coffre could not fetch an issuer's signing keys");
      if (retrying) continue;
      const keptUntil = entry?.keys == null ? 0 : transient ? entry.keptUntil : Math.min(entry.keptUntil, entry.fetchedAt + KEYS_FRESH_MS);
      const base = { keys: entry?.keys ?? null, fetchedAt: entry?.fetchedAt ?? 0, kidUntil: entry?.kidUntil ?? 0, keptUntil };
      // Fresh for minutes, a set fetched meanwhile needs no failure on; a definite answer still ends its stand-in.
      if (meanwhile) {
        remember(url, { ...base, failed: entry.failed });
        return entry.keys!;
      }
      const own: Failure = { until: at + (transient ? KEYS_UNREACHED_MS : KEYS_COOLDOWN_MS), message: (error as Error).message, standIn: transient };
      const failed = standing !== null && !(standing.standIn && !own.standIn) ? standing : own;
      remember(url, { ...base, failed, kidUntil: kid !== null && base.kidUntil === kid ? 0 : base.kidUntil });
      throw unavailable(url, issuer, at, { kid: false, cause: error });
    }
  }
}

function remember(url: string, entry: Entry): void {
  entries.delete(url);
  entries.set(url, entry);
  // The oldest go first.
  while (entries.size > MAX_KEY_SETS) entries.delete(entries.keys().next().value!);
}

/** The URL's failure, if it still stops fetches at `at`, or null. */
function failure(url: string, at: number): Failure | null {
  const failed = entries.get(url)?.failed ?? null;
  return failed !== null && at < failed.until ? failed : null;
}

/** The URL's set, if it may still stand in at `at`, or null. */
function kept(url: string, at: number): JSONWebKeySet | null {
  const entry = entries.get(url);
  return entry?.keys != null && at < entry.keptUntil ? entry.keys : null;
}

/**
 * The 503 for a token of `issuer` no usable key verifies at `at`: why, and
 * the seconds until `url` is fetched again for it. With `kid`, for a key
 * the set lacks, whose fetch also waits out the minute after the last one.
 */
function unavailable(url: string, issuer: string, at: number, { kid, cause }: { kid: boolean; cause?: unknown }): IssuerUnavailable {
  const entry = entries.get(url);
  const failed = failure(url, at);
  const until = Math.max(failed?.until ?? 0, kid ? (entry?.kidUntil ?? 0) : 0);
  const why =
    failed !== null
      ? `coffre could not fetch the signing keys of the issuer ${issuer} (${failed.message}): ` +
        'its own request to the issuer failed, not the token or the job that sent it'
      : `the token's key is not among the signing keys ${issuer} publishes, which coffre fetched from ${url} a moment ago`;
  return new IssuerUnavailable(why, Math.max(1, Math.ceil((until - at) / 1000)), { cause, transient: failed?.standIn ?? false });
}

/** No fetch of `url` for a key its set lacks for `KEYS_COOLDOWN_MS` from `at`, which ends when it returns. */
function pauseKids(url: string, at: number): number {
  const kidUntil = at + KEYS_COOLDOWN_MS;
  remember(url, { ...(entries.get(url) ?? { keys: null, fetchedAt: 0, keptUntil: 0, failed: null }), kidUntil });
  return kidUntil;
}

/**
 * Verify a token under the keys at `url`: the cached set while fresh, else
 * fetched. A fetch that finds the issuer unreachable leaves the set fetched
 * last standing in, until `keptFor` ends it; a key that set lacks is
 * `IssuerUnavailable`, never verified, as is any token once no set stands.
 * Whether a set stands in is asked of the entry as it is once the fetch has
 * failed, at the time it failed: another call's definite answer meanwhile,
 * or the end of `keptFor` reached during the fetch, ends it.
 *
 * At most one fetch an exchange, asked twice when the issuer did not answer
 * and no set stands in: a key missing from a set this call fetched is not
 * there, and a key missing from a fresh set is fetched for once, in case
 * the issuer rotated. Either way the URL then waits a minute before the
 * next fetch (an unreachable issuer, `KEYS_UNREACHED_MS`), and until then a
 * token its kept keys cannot verify is `IssuerUnavailable`. Fresh keys work
 * all the while, and kept ones while the issuer is unreachable.
 *
 *   fresh set has the kid                       verified, no fetch
 *   stale set; GitHub answers                   fetched, verified under the new set
 *   stale set, 40 min old; GitHub times out     verified under the old set, after one attempt
 *   stale set, 70 min old; GitHub times out     two attempts, then 503, Retry-After 10
 *   cold isolate; GitHub times out, then 200    two attempts, verified
 *   fresh set lacks the kid                     one fetch; 503, Retry-After 60, if the new set lacks it too
 *   stale set, during another's kid refetch     fetched, as any stale set; the minute stays on
 *   stale set; A times out after B was answered  A verified under B's set, no second attempt
 *   cold; A fails at 10 s, B at 13 s            B told 7 s, what is left of A's pause, which stands
 */
export async function verifyWithKeys(
  transport: WorkloadTransport,
  url: string,
  token: string,
  expected: { issuer: string; audience: string; now: Date; maxAge?: null },
): ReturnType<typeof verifyWorkloadToken> {
  const now = expected.now.getTime();
  const started = performance.now();
  const clock: Clock = () => now + Math.round(performance.now() - started);
  const entry = entries.get(url);
  const fresh = entry?.keys != null && now - entry.fetchedAt < KEYS_FRESH_MS;
  // Why the set verifying is one kept past fresh, if it is: the token is told that, should the set lack its key.
  let standIn: IssuerUnavailable | null = null;
  let fetched = false;
  let keys: JSONWebKeySet;
  if (fresh) {
    keys = entry.keys!;
  } else if (failure(url, now) !== null) {
    // The minute after a key the set lacked holds back no refresh of a stale set: a token whose key the old set has is
    // not held up a minute, past the CLI's patience.
    standIn = unavailable(url, expected.issuer, now, { kid: false });
    const set = standIn.transient ? kept(url, now) : null;
    if (set === null) throw standIn;
    keys = set;
  } else {
    try {
      keys = await fetchKeys(transport, url, expected.issuer, clock, { retry: kept(url, now) === null, kid: null });
      fetched = true;
    } catch (error) {
      const set = error instanceof IssuerUnavailable && error.transient ? kept(url, clock()) : null;
      if (set === null) throw error;
      standIn = error as IssuerUnavailable;
      keys = set;
    }
  }
  try {
    return await verifyWorkloadToken(token, keys, expected);
  } catch (error) {
    if (!absentKey(error)) throw error;
    if (standIn !== null) throw standIn;
    if (fetched) {
      pauseKids(url, clock());
      throw unavailable(url, expected.issuer, clock(), { kid: true });
    }
    // Other calls may have evicted the entry meanwhile (64 other URLs): then nothing pauses this one.
    if (failure(url, clock()) !== null || clock() < (entries.get(url)?.kidUntil ?? 0)) throw unavailable(url, expected.issuer, clock(), { kid: true });
  }
  // The issuer may have rotated: fetch once, and wait a minute before the next, whatever it finds. Paused first, so that
  // a token naming another unknown key meanwhile fetches nothing.
  const paused = pauseKids(url, clock());
  const rotated = await fetchKeys(transport, url, expected.issuer, clock, { retry: true, kid: paused });
  try {
    return await verifyWorkloadToken(token, rotated, expected);
  } catch (error) {
    if (absentKey(error)) throw unavailable(url, expected.issuer, clock(), { kid: true });
    throw error;
  }
}

function absentKey(error: unknown): boolean {
  return error instanceof WorkloadTokenRefused && error.reason === 'unknown_key';
}
