import { MAX_KEYS, verifyWorkloadToken, WorkloadTokenRefused, type JSONWebKeySet } from '../identity/workload-token.ts';

import { FETCH_DEADLINE_MS, FetchRefused, type WorkloadTransport } from './transport.ts';

/**
 * Issuers' keys, as this isolate (or process) last fetched them, and when
 * each URL was last asked. Settled values only: key sets and times, never a
 * fetch under way. Two first exchanges in one isolate each fetch, rather
 * than one waiting on the other's request, which Cloudflare cancels as hung
 * once the first ends (AGENTS.md, "What an isolate keeps").
 */
type Held = { keys: JSONWebKeySet; fetchedAt: number };

/** A key set is used for ten minutes, then fetched again. */
export const KEYS_FRESH_MS = 10 * 60 * 1000;
/** A URL is asked at most twice in this long: for its keys, and once more for a key they lack, whatever the answers. */
export const KEYS_COOLDOWN_MS = 60 * 1000;
/** At most this many key sets held, `MAX_KEYS` keys in each, and as many URLs asked a minute. */
export const MAX_KEY_SETS = 64;

/** The key sets, the least recently fetched first: evicting one changes no wait, which `asked` keeps. */
const held = new Map<string, Held>();

/**
 * Each URL asked in the last minute: when its first fetch began, how many
 * of its first fetches are under way, and whether it was asked again for a
 * key its set lacks (`again`), or need not be (its set, just fetched, lacked
 * it already). A URL not in it is fetched only while fewer than
 * `MAX_KEY_SETS` are, and is counted when its fetch begins, before any
 * wait, so neither tokens cycled through more URLs than it holds nor
 * fetches finishing late buy more than two fetches a URL a minute and
 * `MAX_KEY_SETS` URLs in all (reviews r1 to r3); evicting a key set changes
 * no wait. The one exception: first calls at once for a URL whose keys are
 * not held fresh each fetch, for `FIRST_MS` at most, so that none waits on
 * another.
 */
const asked = new Map<string, { at: number; flying: number; again: boolean }>();
const FIRST_MS = 2 * FETCH_DEADLINE_MS;

/** The issuer could not be asked for its keys, or will not be for a while. Not a verdict on the token. */
export class IssuerUnavailable extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'IssuerUnavailable';
  }
}

/** Forget every key set and wait: for tests, which play several issuers in one process. */
export function forgetKeys(): void {
  held.clear();
  asked.clear();
}

/** How many key sets this isolate holds, and URLs it waits on: for tests, of the bound. */
export function keySetsHeld(): { sets: number; asked: number } {
  return { sets: held.size, asked: asked.size };
}

/**
 * Whether `url` may be fetched now, counted as asked if so: for keys not
 * held fresh (`first`), once a minute but for first calls at once; for a
 * key a fresh set lacks, once a minute more.
 */
function admit(url: string, now: number, first: boolean): boolean {
  for (const [other, ask] of asked) if (now - ask.at >= KEYS_COOLDOWN_MS || ask.at > now) asked.delete(other);
  const ask = asked.get(url);
  if (ask === undefined) {
    if (asked.size >= MAX_KEY_SETS) return false;
    asked.set(url, { at: now, flying: 1, again: !first });
    return true;
  }
  if (first ? ask.flying === 0 || now - ask.at >= FIRST_MS : ask.again) return false;
  if (first) ask.flying += 1;
  else ask.again = true;
  return true;
}

/** A first fetch ended; `lacking`: its set lacked the token's key, so a minute passes before it is looked for again. */
function landed(url: string, first: boolean, lacking: boolean): void {
  const ask = asked.get(url);
  if (ask === undefined) return;
  if (first && ask.flying > 0) ask.flying -= 1;
  if (lacking) ask.again = true;
}

async function fetchKeys(transport: WorkloadTransport, url: string, now: number): Promise<JSONWebKeySet> {
  try {
    const document = await transport.json(new URL(url));
    const keys = (document as { keys?: unknown } | null)?.keys;
    if (!Array.isArray(keys) || keys.length === 0) throw new FetchRefused(new URL(url), 'holds no keys');
    if (keys.length > MAX_KEYS) throw new FetchRefused(new URL(url), `holds more than ${MAX_KEYS} keys`);
    const set = { keys: keys.filter((key) => typeof key === 'object' && key !== null && (key as { use?: unknown }).use !== 'enc') } as JSONWebKeySet;
    held.delete(url);
    held.set(url, { keys: set, fetchedAt: now });
    while (held.size > MAX_KEY_SETS) held.delete(held.keys().next().value!);
    return set;
  } catch (error) {
    throw new IssuerUnavailable(`the issuer's keys could not be fetched: ${(error as Error).message}`, { cause: error });
  }
}

/** The token's key is not in a set fetched just now: the issuer's, or no one's. */
const KEY_ABSENT = "the token's key is not among the issuer's, which were fetched a moment ago; try again in a minute";
const WAITING = "the issuer's keys were asked for a moment ago; try again in a minute";

/**
 * Verify a token under the keys at `url`: the held set while fresh; else
 * the keys fetched, once a minute at most, and for a key a fresh set lacks
 * (the issuer may have rotated), once a minute more (`admit`). A key
 * missing from a set just fetched is not there. Until the URL may be asked again, or while the issuer cannot
 * be reached, `IssuerUnavailable`; fresh held keys work all the while.
 */
export async function verifyWithKeys(
  transport: WorkloadTransport,
  url: string,
  token: string,
  expected: { issuer: string; audience: string; now: Date; maxAge?: null },
): ReturnType<typeof verifyWorkloadToken> {
  const now = expected.now.getTime();
  const kept = held.get(url);
  const fresh = kept !== undefined && now - kept.fetchedAt < KEYS_FRESH_MS ? kept.keys : null;
  if (fresh !== null) {
    try {
      return await verifyWorkloadToken(token, fresh, expected);
    } catch (error) {
      if (!absentKey(error)) throw error;
    }
  }
  const first = fresh === null;
  if (!admit(url, now, first)) throw new IssuerUnavailable(first ? WAITING : KEY_ABSENT);
  let lacking = false;
  try {
    const keys = await fetchKeys(transport, url, now);
    try {
      return await verifyWorkloadToken(token, keys, expected);
    } catch (error) {
      if (!absentKey(error)) throw error;
      lacking = true;
      throw new IssuerUnavailable(KEY_ABSENT);
    }
  } finally {
    landed(url, first, lacking);
  }
}

function absentKey(error: unknown): boolean {
  return error instanceof WorkloadTokenRefused && error.reason === 'unknown_key';
}
