import test, { beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as signWith, type KeyObject } from 'node:crypto';

import { forgetKeys, IssuerUnavailable, KEYS_COOLDOWN_MS, KEYS_FRESH_MS, verifyWithKeys } from '../src/workloads/keys.ts';
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
    if (url.href !== KEYS) throw new FetchRefused(url, 'answered 404');
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
