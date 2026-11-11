import test, { beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as signWith, type KeyObject } from 'node:crypto';

import { forgetKeys, IssuerUnavailable, keptFor, KEYS_COOLDOWN_MS, KEYS_FRESH_MS, KEYS_KEPT_MS, KEYS_UNREACHED_MS, verifyWithKeys } from '../src/workloads/keys.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';

const ISSUER = 'https://token.actions.githubusercontent.com';
const KEYS = `${ISSUER}/.well-known/jwks`;
const AUDIENCE = 'https://secrets.acme.example';
const T0 = Date.now();

type Key = { kid: string; privateKey: KeyObject; jwk: Record<string, unknown> };

function key(kid: string): Key {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return { kid, privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' } };
}

const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

/** A token signed by `by`, issued just before `at` ms past T0, valid half an hour. */
function token(by: Key, at = 0): string {
  const seconds = Math.floor((T0 + at) / 1000);
  const input = `${part({ alg: 'RS256', kid: by.kid, typ: 'JWT' })}.${part({ iss: ISSUER, aud: AUDIENCE, sub: 'repo:acme/api', iat: seconds - 10, exp: seconds + 1800 })}`;
  return `${input}.${signWith('sha256', Buffer.from(input), by.privateKey).toString('base64url')}`;
}

const [known, rotated, unknown] = [key('known'), key('rotated'), key('unknown')];
/**
 * What the issuer publishes, with its `Cache-Control`, and how many times it
 * was asked. Its next `timeouts` fetches time out, as GitHub's did on
 * 2026-11-11; while `answering` is set, it answers that status instead.
 */
let published: Key[];
let cacheControl: string | null;
let timeouts: number;
let answering: number | null;
let fetches: number;
/**
 * The milliseconds calls have spent, as the cache reads them
 * (`performance.now`): none, but as a test spends them, so that the times
 * the cache dates are the ones the tests name.
 */
let spent = 0;
mock.method(performance, 'now', () => spent);
/** How the next fetches answer, one each, before the issuer's own: to hold one while others go on. */
let scripted: Array<(url: URL) => Promise<void>>;
const transport: WorkloadTransport = {
  json: async (url, seen) => {
    fetches++;
    await scripted.shift()?.(url);
    if (timeouts > 0) {
      timeouts--;
      throw FetchRefused.unreached(url, new DOMException('The operation was aborted due to timeout', 'TimeoutError'));
    }
    if (answering !== null) throw FetchRefused.answered(url, answering);
    if (url.href !== KEYS) throw FetchRefused.answered(url, 404);
    seen?.(cacheControl);
    return { keys: published.map((each) => each.jwk) };
  },
};

beforeEach(() => {
  forgetKeys();
  published = [known];
  cacheControl = 'public, max-age=3600, must-revalidate';
  timeouts = 0;
  answering = null;
  fetches = 0;
  scripted = [];
  spent = 0;
});

const timedOut = (url: URL) => FetchRefused.unreached(url, new DOMException('The operation was aborted due to timeout', 'TimeoutError'));

/** Once the issuer has been asked `count` times in all. */
async function started(count: number): Promise<void> {
  while (fetches < count) await new Promise((resolve) => setImmediate(resolve));
}

/** A fetch held until `release`, and then answered as `then` says, or as the issuer would. */
function held(then?: (url: URL) => never): { answer: (url: URL) => Promise<void>; release: () => void } {
  let release!: () => void;
  const released = new Promise<void>((resolve) => (release = resolve));
  return {
    answer: async (url) => {
      await released;
      then?.(url);
    },
    release,
  };
}

/** Verify at `at` ms past T0 a token issued then: whom it came from, or why not, with the fetches it cost. */
async function verify(by: Key, at = 0): Promise<{ outcome: string; fetches: number }> {
  const before = fetches;
  const outcome = await attempt(by, at).then(
    (claims) => `verified ${String(claims.sub)}`,
    (error: unknown) => (error instanceof IssuerUnavailable ? `unavailable ${error.retryAfter}` : `refused ${(error as Error).message}`),
  );
  return { outcome, fetches: fetches - before };
}

function attempt(by: Key, at = 0) {
  return verifyWithKeys(transport, KEYS, token(by, at), { issuer: ISSUER, audience: AUDIENCE, now: new Date(T0 + at) });
}

const VERIFIED = 'verified repo:acme/api';

test('cold: one fetch, and a key it lacks is unavailable without a second; during the cooldown no fetch, and known keys still verify', async () => {
  assert.deepEqual(await verify(unknown), { outcome: 'unavailable 60', fetches: 1 });
  assert.deepEqual(await verify(unknown, 1500), { outcome: 'unavailable 59', fetches: 0 });
  assert.deepEqual(await verify(known, 2000), { outcome: VERIFIED, fetches: 0 });
  // After the cooldown, a key still missing from a set that is fresh is looked for once more.
  assert.deepEqual(await verify(unknown, KEYS_COOLDOWN_MS + 1), { outcome: 'unavailable 60', fetches: 1 });
});

test('expired: one fetch, as cold', async () => {
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  assert.deepEqual(await verify(unknown, KEYS_FRESH_MS + 1), { outcome: 'unavailable 60', fetches: 1 });
  assert.deepEqual(await verify(known, KEYS_FRESH_MS + 2), { outcome: VERIFIED, fetches: 0 });
});

test('warm: a key the cached set lacks is fetched for once, in case the issuer rotated, and is unavailable if it did not', async () => {
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  published = [known, rotated];
  assert.deepEqual(await verify(rotated, 1000), { outcome: VERIFIED, fetches: 1 });
  // Within the minute, nothing more is fetched for a key no one has.
  assert.deepEqual(await verify(unknown, 2500), { outcome: 'unavailable 59', fetches: 0 });
  // A minute on, a key the issuer still lacks: one fetch, and unavailable, not refused.
  assert.deepEqual(await verify(unknown, KEYS_COOLDOWN_MS + 3000), { outcome: 'unavailable 60', fetches: 1 });
});

test('concurrent cold: each fetches once, never twice, and neither waits on the other', async () => {
  const unknowns = await Promise.all([verify(unknown), verify(unknown)]);
  assert.deepEqual(unknowns.map((each) => each.outcome), ['unavailable 60', 'unavailable 60']);
  assert.equal(fetches, 2);
  forgetKeys();
  fetches = 0;
  const knowns = await Promise.all([verify(known), verify(known)]);
  assert.deepEqual(knowns.map((each) => each.outcome), [VERIFIED, VERIFIED]);
  assert.equal(fetches, 2);
});

test("a set past fresh stands in while the issuer does not answer, as long as its Cache-Control allows; a key it lacks is never taken", async () => {
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  // Ten minutes on, GitHub times out: one attempt, and the set fetched then verifies.
  timeouts = Infinity;
  assert.deepEqual(await verify(known, KEYS_FRESH_MS + 1), { outcome: VERIFIED, fetches: 1 });
  // A key it lacks is not taken: 503, to ask again when the URL is fetched again, ten seconds on.
  assert.deepEqual(await verify(unknown, KEYS_FRESH_MS + 2), { outcome: `unavailable ${KEYS_UNREACHED_MS / 1000}`, fetches: 0 });
  // Meanwhile, nothing is fetched, and the kept set still verifies; then it is tried again.
  assert.deepEqual(await verify(known, KEYS_FRESH_MS + 3), { outcome: VERIFIED, fetches: 0 });
  assert.deepEqual(await verify(known, KEYS_FRESH_MS + KEYS_UNREACHED_MS + 1000), { outcome: VERIFIED, fetches: 1 });
  // An hour past its fetch, GitHub's max-age, the set stands in no more: two attempts, then 503.
  assert.deepEqual(await verify(known, KEYS_KEPT_MS), { outcome: `unavailable ${KEYS_UNREACHED_MS / 1000}`, fetches: 2 });
  assert.deepEqual(await verify(known, KEYS_KEPT_MS + 1500), { outcome: `unavailable ${KEYS_UNREACHED_MS / 1000 - 1}`, fetches: 0 });
  // GitHub back: fetched, and verified under the set it publishes now.
  timeouts = 0;
  assert.deepEqual(await verify(known, KEYS_KEPT_MS + KEYS_UNREACHED_MS + 1000), { outcome: VERIFIED, fetches: 1 });
});

test('a set whose Cache-Control says less than ten minutes, or forbids keeping it, stands in for nothing past fresh', async () => {
  for (const said of ['max-age=300', 'no-store', 'private, no-cache']) {
    forgetKeys();
    cacheControl = said;
    timeouts = 0;
    assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 }, said);
    timeouts = Infinity;
    assert.deepEqual(await verify(known, KEYS_FRESH_MS), { outcome: `unavailable ${KEYS_UNREACHED_MS / 1000}`, fetches: 2 }, said);
  }
  assert.deepEqual(
    [null, 'public, max-age=3600, must-revalidate', 'max-age=86400', 'max-age="1200"', 'max-age=0', 's-maxage=60', 'no-cache="set-cookie"'].map(keptFor),
    [KEYS_KEPT_MS, KEYS_KEPT_MS, KEYS_KEPT_MS, 1_200_000, KEYS_FRESH_MS, KEYS_KEPT_MS, KEYS_FRESH_MS],
  );
});

test("Cache-Control is read as a list of directives, a quoted argument's commas and words its own; what it cannot read keeps nothing past fresh (review r1 of #565)", () => {
  const cases: Array<[string, number]> = [
    ['x-note="example, max-age=3600", max-age=600', KEYS_FRESH_MS],
    ['x-note="example, max-age=600", max-age=1800', 1_800_000],
    ['x-note="say \\"no-store\\"", MAX-AGE=1800', 1_800_000],
    [', public ,, max-age=1800 ,', 1_800_000],
    ['max-age=1800, max-age=3600', KEYS_FRESH_MS],
    ['max-age=abc', KEYS_FRESH_MS],
    ['max-age', KEYS_FRESH_MS],
    ['max-age=1800, x="unclosed', KEYS_FRESH_MS],
    ['max-age=1800 public', KEYS_FRESH_MS],
  ];
  assert.deepEqual(cases.map(([said]) => keptFor(said)), cases.map(([, ms]) => ms));
});

test("a set past fresh does not stand in during another call's fetch for a key it lacked, which is no failure (review r1 of #565, F1)", async () => {
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  // A second before the set goes stale, a key it lacks is fetched for, slowly.
  const refetch = held();
  scripted = [refetch.answer];
  const lacked = verify(unknown, KEYS_FRESH_MS - 1000);
  await started(2);
  // Stale now, and no fetch for the minute: the old set is not taken, though the issuer has not failed.
  assert.deepEqual(await verify(known, KEYS_FRESH_MS + 1000), { outcome: 'unavailable 58', fetches: 0 });
  refetch.release();
  assert.deepEqual(await lacked, { outcome: 'unavailable 60', fetches: 1 });
  assert.deepEqual(await verify(known, KEYS_FRESH_MS + 1500), { outcome: VERIFIED, fetches: 0 });
});

test("a set stands in after a timeout only as the entry is once it failed: another call's definite answer, or the end of its hour, ends it (review r1 of #565, F2)", async () => {
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  // Stale: A's fetch hangs, B's is answered 404, then A's times out.
  const hung = held((url) => {
    throw timedOut(url);
  });
  scripted = [hung.answer];
  const a = verify(known, KEYS_FRESH_MS + 1);
  await started(2);
  answering = 404;
  assert.deepEqual(await verify(known, KEYS_FRESH_MS + 1), { outcome: `unavailable ${KEYS_COOLDOWN_MS / 1000}`, fetches: 1 });
  answering = null;
  hung.release();
  // A takes no old key, and leaves B's minute as it was (its fetches counted with B's).
  assert.deepEqual(await a, { outcome: `unavailable ${KEYS_COOLDOWN_MS / 1000}`, fetches: 2 });
  assert.deepEqual(await verify(known, KEYS_FRESH_MS + 4502), { outcome: 'unavailable 56', fetches: 0 });

  // A fetch begun just before the hour ends, that times out just after it.
  forgetKeys();
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  scripted = [
    async (url) => {
      spent += 200;
      throw timedOut(url);
    },
  ];
  assert.deepEqual(await verify(known, KEYS_KEPT_MS - 50), { outcome: `unavailable ${KEYS_UNREACHED_MS / 1000}`, fetches: 1 });
});

test('cold, a fetch that times out is asked again once, at once; failing twice, a 503 that names the issuer and says coffre failed', async () => {
  timeouts = 1;
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 2 });
  forgetKeys();
  fetches = 0;
  timeouts = 2;
  await assert.rejects(attempt(known), (error: unknown) => {
    assert.ok(error instanceof IssuerUnavailable);
    assert.equal(error.retryAfter, KEYS_UNREACHED_MS / 1000);
    assert.equal(
      error.message,
      `coffre could not fetch the signing keys of the issuer ${ISSUER} (${KEYS}: timed out after 5 s): its own request to the issuer failed, ` +
        'not the token or the job that sent it; try again in 10 s',
    );
    return true;
  });
  assert.equal(fetches, 2);
  // Within the ten seconds, nothing is fetched, and the 503 says what is left of them.
  const quiet = (await attempt(known, 4500).then(() => assert.fail('verified while quiet'), (error: unknown) => error)) as IssuerUnavailable;
  assert.deepEqual([fetches, quiet.retryAfter, quiet.message.startsWith(`coffre could not fetch the signing keys of the issuer ${ISSUER}`)], [2, 6, true]);
  assert.deepEqual(await verify(known, KEYS_UNREACHED_MS + 1000), { outcome: VERIFIED, fetches: 1 });
});

test('each failed fetch logs, the one a retry then answers included (review r2 of #565)', async (t) => {
  const logged: unknown[] = [];
  t.mock.method(console, 'error', (line: { event?: string }) => logged.push(line));
  timeouts = 1;
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 2 });
  assert.deepEqual(
    logged.map((line) => {
      const { event, attempt, transient, retrying } = line as Record<string, unknown>;
      return { event, attempt, transient, retrying };
    }),
    [{ event: 'workload_keys_unfetched', attempt: 1, transient: true, retrying: true }],
  );
});

test('a key the fresh set lacks is fetched for with a retry, and a timeout leaves the set as it was', async () => {
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  published = [known, rotated];
  timeouts = 1;
  assert.deepEqual(await verify(rotated, 1000), { outcome: VERIFIED, fetches: 2 });
  // Twice out of reach on the next unknown key, after the minute: 503 for it, and the fresh set still verifies.
  timeouts = 2;
  assert.deepEqual(await verify(unknown, KEYS_COOLDOWN_MS + 2000), { outcome: `unavailable ${KEYS_UNREACHED_MS / 1000}`, fetches: 2 });
  assert.deepEqual(await verify(rotated, KEYS_COOLDOWN_MS + 3000), { outcome: VERIFIED, fetches: 0 });
});

test('an issuer that answers, but not with keys, is not asked again at once, and ends the stand-in of the set it published before', async () => {
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  answering = 404;
  assert.deepEqual(await verify(known, KEYS_FRESH_MS + 1), { outcome: `unavailable ${KEYS_COOLDOWN_MS / 1000}`, fetches: 1 });
  assert.deepEqual(await verify(known, KEYS_FRESH_MS + 2), { outcome: `unavailable ${KEYS_COOLDOWN_MS / 1000}`, fetches: 0 });
  // A 503 is a moment's: the set stands in again, as for a timeout.
  forgetKeys();
  answering = null;
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  answering = 503;
  assert.deepEqual(await verify(known, KEYS_FRESH_MS + 1), { outcome: VERIFIED, fetches: 1 });
});
