import test, { afterEach, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as signWith, type KeyObject } from 'node:crypto';

import { forgetKeys, IssuerUnavailable, KEYS_COLD_COOLDOWN_MS, KEYS_COOLDOWN_MS, KEYS_FRESH_MS, KEYS_STALE_MS, verifyWithKeys } from '../src/workloads/keys.ts';
import { FETCH_DEADLINE_MS, FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';

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

/** A token signed by `by`, valid from just before `at` ms past T0 to half an hour after. */
function token(by: Key, at = 0): string {
  const seconds = Math.floor((T0 + at) / 1000);
  const input = `${part({ alg: 'RS256', kid: by.kid, typ: 'JWT' })}.${part({ iss: ISSUER, aud: AUDIENCE, sub: 'repo:acme/api', iat: seconds - 10, exp: seconds + 1800 })}`;
  return `${input}.${signWith('sha256', Buffer.from(input), by.privateKey).toString('base64url')}`;
}

const [known, rotated, unknown] = [key('known'), key('rotated'), key('unknown')];
/**
 * What the issuer publishes, how many times it was asked, whether it answers,
 * whether it answers only once its deadline has run out (the clock moved on),
 * and a fetch held until the test lets it go on, to answer or fail as the rest says.
 */
let published: Key[];
let fetches: number;
let down: boolean;
let slow: boolean;
let held: Promise<void> | null;
const transport: WorkloadTransport = {
  json: async (url) => {
    fetches++;
    if (held !== null) {
      const until = held;
      held = null;
      await until;
    }
    if (slow) mock.timers.setTime(Date.now() + FETCH_DEADLINE_MS);
    if (down) throw new FetchRefused(url, 'could not be fetched');
    if (url.href !== KEYS) throw FetchRefused.answered(url, 404);
    return { keys: published.map((each) => each.jwk) };
  },
};

// The cache reads its own clock, `Date.now()`, which the test drives: `verify` sets it.
beforeEach(() => {
  mock.timers.enable({ apis: ['Date'], now: T0 });
  forgetKeys();
  published = [known];
  fetches = 0;
  down = false;
  slow = false;
  held = null;
});

afterEach(() => mock.timers.reset());

/** Verify at `at` ms past T0: whom the token came from, or why not (with its `Retry-After`, if unavailable), with the fetches it cost. */
async function verify(by: Key, at = 0): Promise<{ outcome: string; fetches: number }> {
  const before = fetches;
  mock.timers.setTime(T0 + at);
  const outcome = await verifyWithKeys(transport, KEYS, token(by, at), { issuer: ISSUER, audience: AUDIENCE, now: new Date(T0 + at) }).then(
    (claims) => `verified ${String(claims.sub)}`,
    (error: unknown) => (error instanceof IssuerUnavailable ? `unavailable ${error.retryAfter}` : `refused ${(error as Error).message}`),
  );
  return { outcome, fetches: fetches - before };
}

const VERIFIED = 'verified repo:acme/api';

test('cold: one fetch, and a key it lacks is unavailable without a second; during the cooldown no fetch, and known keys still verify', async () => {
  assert.deepEqual(await verify(unknown), { outcome: 'unavailable 60', fetches: 1 });
  assert.deepEqual(await verify(unknown, 1000), { outcome: 'unavailable 59', fetches: 0 });
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
  assert.deepEqual(await verify(unknown, 2000), { outcome: 'unavailable 59', fetches: 0 });
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

// T258: a set past its ten minutes stands in for one that cannot be fetched, for an hour from its fetch.

/** Each warning the cache gives, while `fn` runs. */
async function warnings(fn: () => Promise<void>): Promise<string[]> {
  const warn = mock.method(console, 'warn', () => {});
  try {
    await fn();
    return warn.mock.calls.map((call) => String(call.arguments[0]));
  } finally {
    warn.mock.restore();
  }
}

const MIN = 60 * 1000;

test('fresh: a set fetched within ten minutes verifies with no fetch, the issuer down or not', async () => {
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  down = true;
  assert.deepEqual(await verify(known, KEYS_FRESH_MS - 1), { outcome: VERIFIED, fetches: 0 });
});

test('stale: a failed fetch verifies with the set kept, says so once, and the cooldown that follows fetches nothing', async () => {
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  down = true;
  const said = await warnings(async () => {
    assert.deepEqual(await verify(known, KEYS_FRESH_MS + MIN), { outcome: VERIFIED, fetches: 1 });
    // The minute after: no fetch, the same set, and nothing said again.
    assert.deepEqual(await verify(known, KEYS_FRESH_MS + MIN + 1000), { outcome: VERIFIED, fetches: 0 });
    assert.deepEqual(await verify(known, KEYS_FRESH_MS + MIN + KEYS_COOLDOWN_MS - 1), { outcome: VERIFIED, fetches: 0 });
  });
  assert.equal(said.length, 1);
  assert.match(said[0]!, /^verifying with the issuer's keys fetched 11 min ago: the issuer's keys could not be fetched: https:\/\/token\.actions\.githubusercontent\.com\/\.well-known\/jwks: could not be fetched$/);
  assert.doesNotMatch(said[0]!, /eyJ/);
  // Past the cooldown, fetched again; the issuer back, its set is fresh again and nothing is said.
  down = false;
  published = [rotated];
  const quiet = await warnings(async () => {
    assert.deepEqual(await verify(rotated, KEYS_FRESH_MS + MIN + KEYS_COOLDOWN_MS), { outcome: VERIFIED, fetches: 1 });
  });
  assert.deepEqual(quiet, []);
});

test('stale: a key the set kept lacks, while its issuer cannot be reached, is unavailable for the cooldown, with one fetch', async () => {
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  down = true;
  await warnings(async () => {
    assert.deepEqual(await verify(rotated, KEYS_FRESH_MS + MIN), { outcome: `unavailable ${KEYS_COOLDOWN_MS / 1000}`, fetches: 1 });
    assert.deepEqual(await verify(rotated, KEYS_FRESH_MS + MIN + 20_000), { outcome: `unavailable ${KEYS_COOLDOWN_MS / 1000 - 20}`, fetches: 0 });
    // A key it holds verifies all the while.
    assert.deepEqual(await verify(known, KEYS_FRESH_MS + MIN + 30_000), { outcome: VERIFIED, fetches: 0 });
  });
});

test('stale: a key the set kept lacks, its issuer answering, is fetched for once, then unavailable as before', async () => {
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  assert.deepEqual(await verify(unknown, KEYS_FRESH_MS + MIN), { outcome: `unavailable ${KEYS_COOLDOWN_MS / 1000}`, fetches: 1 });
  assert.deepEqual(await verify(unknown, KEYS_FRESH_MS + MIN + 1000), { outcome: `unavailable ${KEYS_COOLDOWN_MS / 1000 - 1}`, fetches: 0 });
  // A key the issuer rotated in, once the minute is over: the set it fetched has it.
  published = [known, rotated];
  assert.deepEqual(await verify(rotated, KEYS_FRESH_MS + MIN + KEYS_COOLDOWN_MS), { outcome: VERIFIED, fetches: 1 });
});

test('stale past the bound: an hour from its fetch, the set kept no longer stands in, and the cooldown is the short one', async () => {
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  down = true;
  await warnings(async () => {
    assert.deepEqual(await verify(known, KEYS_STALE_MS - 1), { outcome: VERIFIED, fetches: 1 });
    // A moment on, the set is an hour old: unavailable, with no fetch, until the short cooldown is over.
    assert.deepEqual(await verify(known, KEYS_STALE_MS), { outcome: `unavailable ${KEYS_COLD_COOLDOWN_MS / 1000}`, fetches: 0 });
    assert.deepEqual(await verify(known, KEYS_STALE_MS - 1 + KEYS_COLD_COOLDOWN_MS), { outcome: `unavailable ${KEYS_COLD_COOLDOWN_MS / 1000}`, fetches: 1 });
  });
});

test('stale, a moment before the bound: the Retry-After is when a fetch may be made, the short cooldown once the set goes stale', async () => {
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  down = true;
  await warnings(async () => {
    // A key the set lacks, a second before the hour: the set goes stale within the long cooldown, and the short one then decides.
    assert.deepEqual(await verify(rotated, KEYS_STALE_MS - 1000), { outcome: `unavailable ${KEYS_COLD_COOLDOWN_MS / 1000}`, fetches: 1 });
    assert.deepEqual(await verify(known, KEYS_STALE_MS - 1000 + 500), { outcome: VERIFIED, fetches: 0 });
    assert.deepEqual(await verify(rotated, KEYS_STALE_MS + 2000), { outcome: `unavailable ${KEYS_COLD_COOLDOWN_MS / 1000 - 3}`, fetches: 0 });
    // As it said: a fetch then.
    down = false;
    published = [known, rotated];
    assert.deepEqual(await verify(rotated, KEYS_STALE_MS - 1000 + KEYS_COLD_COOLDOWN_MS), { outcome: VERIFIED, fetches: 1 });
  });
});

test('cold, the issuer unreachable: unavailable, asking to come back as soon as a fetch may be made again, which the CLI waits for', async () => {
  down = true;
  const said = await warnings(async () => {
    assert.deepEqual(await verify(known), { outcome: `unavailable ${KEYS_COLD_COOLDOWN_MS / 1000}`, fetches: 1 });
    assert.deepEqual(await verify(known, 1500), { outcome: `unavailable ${Math.ceil((KEYS_COLD_COOLDOWN_MS - 1500) / 1000)}`, fetches: 0 });
    // The CLI waits at most 15 s before it asks again, and takes a Retry-After up to 10 s as asked (`unavailableWait`).
    assert.ok(KEYS_COLD_COOLDOWN_MS <= 10_000);
    assert.deepEqual(await verify(known, KEYS_COLD_COOLDOWN_MS), { outcome: `unavailable ${KEYS_COLD_COOLDOWN_MS / 1000}`, fetches: 1 });
    down = false;
    assert.deepEqual(await verify(known, 2 * KEYS_COLD_COOLDOWN_MS), { outcome: VERIFIED, fetches: 1 });
  });
  // Nothing kept stood in: nothing to say.
  assert.deepEqual(said, []);
});

test('cold, the fetch running out its deadline: the cooldown, and its Retry-After, start as it fails', async () => {
  [down, slow] = [true, true];
  assert.deepEqual(await verify(known), { outcome: `unavailable ${KEYS_COLD_COOLDOWN_MS / 1000}`, fetches: 1 });
  assert.deepEqual(await verify(known, FETCH_DEADLINE_MS + 1000), { outcome: `unavailable ${KEYS_COLD_COOLDOWN_MS / 1000 - 1}`, fetches: 0 });
  [down, slow] = [false, false];
  assert.deepEqual(await verify(known, FETCH_DEADLINE_MS + KEYS_COLD_COOLDOWN_MS), { outcome: VERIFIED, fetches: 1 });
});

test('stale, raced: a fetch failing after another exchange fetched a set without the key stands in with that set, not the older one', async () => {
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  // The issuer withdrew `known`. One exchange's fetch hangs; another's gets the new set meanwhile.
  published = [rotated];
  let fail!: () => void;
  held = new Promise((resolve) => (fail = resolve));
  await warnings(async () => {
    const hung = verify(known, KEYS_FRESH_MS + MIN);
    assert.deepEqual(await verify(rotated, KEYS_FRESH_MS + MIN), { outcome: VERIFIED, fetches: 1 });
    fail();
    assert.equal((await hung).outcome, `unavailable ${KEYS_COOLDOWN_MS / 1000}`);
  });
});

test('fresh, a key it lacks fetched for in vain: said once, and the set verifies on, past its ten minutes, through the cooldown', async () => {
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  down = true;
  const said = await warnings(async () => {
    assert.deepEqual(await verify(unknown, KEYS_FRESH_MS - 1000), { outcome: `unavailable ${KEYS_COOLDOWN_MS / 1000}`, fetches: 1 });
    assert.deepEqual(await verify(known, KEYS_FRESH_MS + 1000), { outcome: VERIFIED, fetches: 0 });
  });
  assert.equal(said.length, 1);
  assert.match(said[0]!, /^verifying with the issuer's keys fetched 10 min ago: the issuer's keys could not be fetched: /);
});

test('cold, a fetch after a failed one under way: the exchanges meanwhile fetch nothing beside it and are answered at once', async () => {
  down = true;
  assert.deepEqual(await verify(known), { outcome: `unavailable ${KEYS_COLD_COOLDOWN_MS / 1000}`, fetches: 1 });
  let fail!: () => void;
  held = new Promise((resolve) => (fail = resolve));
  const probe = verify(known, KEYS_COLD_COOLDOWN_MS);
  assert.deepEqual(await verify(known, KEYS_COLD_COOLDOWN_MS + 1000), { outcome: `unavailable ${KEYS_COLD_COOLDOWN_MS / 1000 - 1}`, fetches: 0 });
  fail();
  assert.equal((await probe).outcome, `unavailable ${KEYS_COLD_COOLDOWN_MS / 1000}`);
});

test('stale, a fetch after a failed one under way: the exchanges meanwhile verify with the set kept, fetching nothing, and its failure is said once', async () => {
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  down = true;
  const said = await warnings(async () => {
    assert.deepEqual(await verify(known, KEYS_FRESH_MS), { outcome: VERIFIED, fetches: 1 });
    let fail!: () => void;
    held = new Promise((resolve) => (fail = resolve));
    const probe = verify(known, KEYS_FRESH_MS + KEYS_COOLDOWN_MS);
    assert.deepEqual(await verify(known, KEYS_FRESH_MS + KEYS_COOLDOWN_MS + 1000), { outcome: VERIFIED, fetches: 0 });
    fail();
    assert.equal((await probe).outcome, VERIFIED);
  });
  // The failure before, and the probe's: none for the exchange beside it.
  assert.equal(said.length, 2);
});

test('a key missed, its minute over, leaves nothing behind: at ten minutes the exchanges beside the refresh fetch for themselves, never verify with the set past its ten minutes', async () => {
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  published = [known, rotated];
  assert.deepEqual(await verify(rotated, 1000), { outcome: VERIFIED, fetches: 1 });
  // The issuer withdraws `known`, and the set kept, fetched a second in, is due at ten minutes.
  published = [rotated];
  const said = await warnings(async () => {
    let answer!: () => void;
    held = new Promise((resolve) => (answer = resolve));
    const refresh = verify(known, 1000 + KEYS_FRESH_MS);
    assert.deepEqual(await verify(known, 2000 + KEYS_FRESH_MS), { outcome: `unavailable ${KEYS_COOLDOWN_MS / 1000}`, fetches: 1 });
    answer();
    assert.equal((await refresh).outcome, `unavailable ${KEYS_COOLDOWN_MS / 1000}`);
  });
  assert.deepEqual(said, []);
});

test('a key missed, its fetch never settling (cancelled): the set is still fetched when it is due, not used past its ten minutes', async () => {
  assert.deepEqual(await verify(known), { outcome: VERIFIED, fetches: 1 });
  held = new Promise(() => {});
  void verify(unknown, KEYS_FRESH_MS - 1000);
  // Its fetch comes once the token's signature has been checked against the set it lacks a key of.
  while (held !== null) await new Promise((resolve) => setImmediate(resolve));
  published = [rotated];
  assert.deepEqual(await verify(known, KEYS_FRESH_MS + 1000), { outcome: `unavailable ${KEYS_COOLDOWN_MS / 1000}`, fetches: 1 });
});
