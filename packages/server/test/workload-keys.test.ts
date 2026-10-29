import test, { beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as signWith, type KeyObject } from 'node:crypto';

import { forgetKeys, IssuerUnavailable, KEYS_COOLDOWN_MS, KEYS_FRESH_MS, keySetsHeld, MAX_KEY_SETS, verifyWithKeys } from '../src/workloads/keys.ts';
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

/** A token signed by `by`, valid from just before T0 to half an hour after. */
function token(by: Key): string {
  const seconds = Math.floor(T0 / 1000);
  const input = `${part({ alg: 'RS256', kid: by.kid, typ: 'JWT' })}.${part({ iss: ISSUER, aud: AUDIENCE, sub: 'repo:acme/api', iat: seconds - 10, exp: seconds + 1800 })}`;
  return `${input}.${signWith('sha256', Buffer.from(input), by.privateKey).toString('base64url')}`;
}

const [known, rotated, unknown] = [key('known'), key('rotated'), key('unknown')];
/** What the issuer publishes, and how many times it was asked. */
let published: Key[];
let fetches: number;
const transport: WorkloadTransport = {
  json: async (url) => {
    fetches++;
    if (url.href !== KEYS) throw FetchRefused.answered(url, 404);
    return { keys: published.map((each) => each.jwk) };
  },
};

beforeEach(() => {
  forgetKeys();
  published = [known];
  fetches = 0;
});

/** Verify at `at` ms past T0: whom the token came from, or why not, with the fetches it cost. */
async function verify(by: Key, at = 0): Promise<{ outcome: string; fetches: number }> {
  const before = fetches;
  const outcome = await verifyWithKeys(transport, KEYS, token(by), { issuer: ISSUER, audience: AUDIENCE, now: new Date(T0 + at) }).then(
    (claims) => `verified ${String(claims.sub)}`,
    (error: unknown) => (error instanceof IssuerUnavailable ? 'unavailable' : `refused ${(error as Error).message}`),
  );
  return { outcome, fetches: fetches - before };
}

const VERIFIED = 'verified repo:acme/api';

test('cold: one fetch, and a key it lacks is unavailable without a second; during the cooldown no fetch, and known keys still verify', async () => {
  assert.deepEqual(await verify(unknown), { outcome: 'unavailable', fetches: 1 });
  assert.deepEqual(await verify(unknown, 1000), { outcome: 'unavailable', fetches: 0 });
  assert.deepEqual(await verify(known, 2000), { outcome: VERIFIED, fetches: 0 });
  // After the cooldown, a key still missing from a set that is fresh is looked for once more.
  assert.deepEqual(await verify(unknown, KEYS_COOLDOWN_MS + 1), { outcome: 'unavailable', fetches: 1 });
});

test('expired: one fetch, as cold', async () => {
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  assert.deepEqual(await verify(unknown, KEYS_FRESH_MS + 1), { outcome: 'unavailable', fetches: 1 });
  assert.deepEqual(await verify(known, KEYS_FRESH_MS + 2), { outcome: VERIFIED, fetches: 0 });
});

test('warm: a key the cached set lacks is fetched for once, in case the issuer rotated, and is unavailable if it did not', async () => {
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  published = [known, rotated];
  assert.deepEqual(await verify(rotated, 1000), { outcome: VERIFIED, fetches: 1 });
  // Within the minute, nothing more is fetched for a key no one has.
  assert.deepEqual(await verify(unknown, 2000), { outcome: 'unavailable', fetches: 0 });
  // A minute on, a key the issuer still lacks: one fetch, and unavailable, not refused.
  assert.deepEqual(await verify(unknown, KEYS_COOLDOWN_MS + 3000), { outcome: 'unavailable', fetches: 1 });
});

test('concurrent cold: each fetches once, never twice, and neither waits on the other', async () => {
  const unknowns = await Promise.all([verify(unknown), verify(unknown)]);
  assert.deepEqual(unknowns.map((each) => each.outcome), ['unavailable', 'unavailable']);
  assert.equal(fetches, 2);
  forgetKeys();
  fetches = 0;
  const knowns = await Promise.all([verify(known), verify(known)]);
  assert.deepEqual(knowns.map((each) => each.outcome), [VERIFIED, VERIFIED]);
  assert.equal(fetches, 2);
});

test('tokens cycled through more key URLs than the cache holds cost each at most one fetch a minute: a URL waits its minute whether or not its keys are still held, and none is fetched while 64 wait', async () => {
  let asked = 0;
  const many: WorkloadTransport = {
    json: async () => {
      asked++;
      return { keys: [known.jwk] };
    },
  };
  const urls = Array.from({ length: MAX_KEY_SETS + 6 }, (_, n) => `https://issuer-${n}.example/keys`);
  const cycle = async (at: number) => {
    for (const url of urls) {
      await assert.rejects(verifyWithKeys(many, url, token(unknown), { issuer: ISSUER, audience: AUDIENCE, now: new Date(T0 + at) }), IssuerUnavailable);
    }
  };
  await cycle(0);
  assert.equal(asked, MAX_KEY_SETS, 'one fetch for each URL the cache can hold; the rest wait');
  await cycle(1_000);
  await cycle(2_000);
  assert.equal(asked, MAX_KEY_SETS, 'none again within the minute, however often they come round');
  // The keys each holds still verify the issuer's own tokens meanwhile.
  assert.equal(await verifyWithKeys(many, urls[0]!, token(known), { issuer: ISSUER, audience: AUDIENCE, now: new Date(T0 + 3_000) }).then((claims) => claims.sub), 'repo:acme/api');
  await cycle(KEYS_COOLDOWN_MS + 3_000);
  assert.ok(asked <= 2 * MAX_KEY_SETS, `a minute on, at most one each again: ${asked}`);
});

test('first fetches of more key URLs than the cache holds, all at once and finishing late, take no more places than it has: the rest wait, and the cooldowns stand', async () => {
  let asked = 0;
  let release!: () => void;
  const gate = new Promise<void>((resolve) => (release = resolve));
  const late: WorkloadTransport = {
    json: async () => {
      asked++;
      await gate;
      return { keys: [known.jwk] };
    },
  };
  const urls = Array.from({ length: MAX_KEY_SETS + 6 }, (_, n) => `https://issuer-${n}.example/keys`);
  const all = (at: number) => urls.map((url) => verifyWithKeys(late, url, token(unknown), { issuer: ISSUER, audience: AUDIENCE, now: new Date(T0 + at) }));
  const first = all(0);
  release();
  const settled = await Promise.allSettled(first);
  assert.ok(settled.every((outcome) => outcome.status === 'rejected' && outcome.reason instanceof IssuerUnavailable));
  assert.equal(asked, MAX_KEY_SETS, 'as many fetches as places; the rest were refused before asking');
  assert.deepEqual(keySetsHeld(), { sets: MAX_KEY_SETS, asked: MAX_KEY_SETS });
  await Promise.allSettled(all(1_000));
  assert.equal(asked, MAX_KEY_SETS, 'each waits its minute: none fetched again');
  assert.deepEqual(keySetsHeld(), { sets: MAX_KEY_SETS, asked: MAX_KEY_SETS });
});

test("a fetch finishing late, beside warm sets whose keys tokens keep missing, costs no URL a third fetch in its minute, and holds the bounds (review r3)", async () => {
  let asked = 0;
  let release: (() => void) | null = null;
  const many: WorkloadTransport = {
    json: async (url) => {
      asked++;
      if (url.href === LATE) await new Promise<void>((resolve) => (release = resolve));
      return { keys: [known.jwk] };
    },
  };
  const LATE = 'https://late.example/keys';
  const urls = Array.from({ length: MAX_KEY_SETS }, (_, n) => `https://issuer-${n}.example/keys`);
  const at = (url: string, by: Key, ms: number) => verifyWithKeys(many, url, token(by), { issuer: ISSUER, audience: AUDIENCE, now: new Date(T0 + ms) });
  // 64 sets held, their minute over.
  for (const url of urls) await at(url, known, 0);
  const warm = KEYS_COOLDOWN_MS + 1_000;
  asked = 0;
  // A cold URL's fetch begins, and finishes only once every held set has been asked again for a key it lacks.
  const late = at(LATE, known, warm);
  const missed = await Promise.allSettled(urls.map((url) => at(url, unknown, warm)));
  assert.ok(missed.every((outcome) => outcome.status === 'rejected' && outcome.reason instanceof IssuerUnavailable));
  release!();
  await late;
  assert.equal(asked, MAX_KEY_SETS, 'the late one, and one for each held set but the one no place was left for');
  assert.deepEqual(keySetsHeld(), { sets: MAX_KEY_SETS, asked: MAX_KEY_SETS });
  // The set it pushed out is asked for again at once: it waits its minute, held or not.
  await Promise.allSettled(urls.map((url) => at(url, unknown, warm + 1_000)));
  assert.equal(asked, MAX_KEY_SETS, 'none fetched twice in the minute');
});

test("a call that names an earlier time than one before it, having waited, erases no wait: the cache's clock never goes back (review r4)", async () => {
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  // A minute on, a key it lacks, looked for once: its wait begins then.
  assert.deepEqual(await verify(unknown, KEYS_COOLDOWN_MS + 2000), { outcome: 'unavailable', fetches: 1 });
  // Calls that took their time a second before that and reach the cache only now: the wait stands.
  for (let i = 0; i < 5; i += 1) assert.deepEqual(await verify(unknown, KEYS_COOLDOWN_MS + 1000), { outcome: 'unavailable', fetches: 0 });
  assert.deepEqual(await verify(known, KEYS_COOLDOWN_MS + 1000), { outcome: VERIFIED, fetches: 0 });
});

test('a refresh that failed just before its set expired leaves no first fetch counted as under way: the calls after it wait their minute (review r4)', async () => {
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  published = [];
  // A minute and more on, a key the set lacks: looked for, and the issuer answers nothing usable.
  assert.deepEqual(await verify(unknown, KEYS_FRESH_MS - 1000), { outcome: 'unavailable', fetches: 1 });
  // The set expires; each call after asks nothing until the minute is over.
  for (let i = 0; i < 5; i += 1) assert.deepEqual(await verify(known, KEYS_FRESH_MS + 1 + i), { outcome: 'unavailable', fetches: 0 });
});

test("a URL's minute runs from its latest fetch: a refetch at 59 s puts off the next fetch to a minute after it (review r5)", async () => {
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  // At 59 s, a key the set lacks: looked for once, and the minute starts over.
  assert.deepEqual(await verify(unknown, 59_000), { outcome: 'unavailable', fetches: 1 });
  // At 60.001 s, a minute on from the first fetch but not from the refetch: nothing fetched.
  assert.deepEqual(await verify(unknown, KEYS_COOLDOWN_MS + 1), { outcome: 'unavailable', fetches: 0 });
  assert.deepEqual(await verify(known, KEYS_COOLDOWN_MS + 1), { outcome: VERIFIED, fetches: 0 });
  assert.deepEqual(await verify(unknown, 59_000 + KEYS_COOLDOWN_MS - 1), { outcome: 'unavailable', fetches: 0 });
  // A minute after the refetch, the key is looked for again.
  assert.deepEqual(await verify(unknown, 59_000 + KEYS_COOLDOWN_MS), { outcome: 'unavailable', fetches: 1 });
});

test('64 URLs asked again at 59 s keep their places: a 65th waits a minute from those refetches, not from the first fetches (review r5)', async () => {
  let asked = 0;
  const many: WorkloadTransport = {
    json: async () => {
      asked++;
      return { keys: [known.jwk] };
    },
  };
  const urls = Array.from({ length: MAX_KEY_SETS }, (_, n) => `https://issuer-${n}.example/keys`);
  const extra = 'https://issuer-extra.example/keys';
  const at = (url: string, by: Key, ms: number) => verifyWithKeys(many, url, token(by), { issuer: ISSUER, audience: AUDIENCE, now: new Date(T0 + ms) });
  for (const url of urls) await at(url, known, 0);
  for (const url of urls) await assert.rejects(at(url, unknown, 59_000), IssuerUnavailable);
  assert.equal(asked, 2 * MAX_KEY_SETS, 'each fetched for its keys, then for the key they lack');
  await assert.rejects(at(extra, known, KEYS_COOLDOWN_MS + 1), IssuerUnavailable);
  await assert.rejects(at(extra, known, 59_000 + KEYS_COOLDOWN_MS - 1), IssuerUnavailable);
  assert.equal(asked, 2 * MAX_KEY_SETS, 'no 65th URL within a minute of the last fetches');
  assert.deepEqual(keySetsHeld(), { sets: MAX_KEY_SETS, asked: MAX_KEY_SETS });
  assert.equal(await at(extra, known, 59_000 + KEYS_COOLDOWN_MS).then((claims) => claims.sub), 'repo:acme/api');
  assert.equal(asked, 2 * MAX_KEY_SETS + 1);
});
