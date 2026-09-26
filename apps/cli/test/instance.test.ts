import test from 'node:test';
import assert from 'node:assert/strict';

import {
  credentialHeaders,
  emptyStore,
  instanceOrigin,
  parseStore,
  resolveTarget,
  withSession,
  withoutSession,
  type Store,
} from '../src/instance.ts';

const OURS = 'https://coffre.example.com';
const THEIRS = 'https://coffre.equisafe.dev';
const NOW = new Date('2026-09-26T12:00:00Z');

function storeWith(): Store {
  let store = withSession(emptyStore(), THEIRS, {
    mode: 'cloudflare',
    obtainedAt: '2026-09-01T00:00:00Z',
  });
  store = withSession(store, OURS, {
    mode: 'signin',
    token: 'coffre_cli_ours',
    expiresAt: '2026-10-26T12:00:00Z',
    obtainedAt: '2026-09-26T00:00:00Z',
  });
  return store;
}

// --- addresses ----------------------------------------------------------------

test('an address is normalised to its origin, HTTPS by default', () => {
  assert.equal(instanceOrigin('coffre.example.com'), OURS);
  assert.equal(instanceOrigin('https://coffre.example.com/'), OURS);
  assert.equal(instanceOrigin('  HTTPS://Coffre.Example.com  '), OURS);
  assert.equal(instanceOrigin('127.0.0.1:3051'), 'http://127.0.0.1:3051');
  assert.equal(instanceOrigin('localhost:3000'), 'http://localhost:3000');
});

test('credentials never travel over plain HTTP off this machine', () => {
  assert.throws(() => instanceOrigin('http://coffre.example.com'), /plain HTTP/);
  assert.throws(() => instanceOrigin('http://coffre.example.com', 'cloudflare'), /plain HTTP/);
  assert.equal(instanceOrigin('http://127.0.0.1:3051'), 'http://127.0.0.1:3051');
  assert.equal(instanceOrigin('http://localhost:3000'), 'http://localhost:3000');
  assert.equal(instanceOrigin('http://[::1]:3000'), 'http://[::1]:3000');
  // The dev IdP flow is local by construction.
  assert.equal(instanceOrigin('http://devbox:3000', 'dev'), 'http://devbox:3000');
});

test('addresses with a path, query, or embedded password are refused', () => {
  assert.throws(() => instanceOrigin('https://coffre.example.com/api'), /without a path/);
  assert.throws(() => instanceOrigin('https://coffre.example.com/?x=1'), /without a path/);
  assert.throws(() => instanceOrigin('https://user:pw@coffre.example.com'), /user name or password/);
  assert.throws(() => instanceOrigin('ftp://coffre.example.com'), /not a coffre address/);
  assert.throws(() => instanceOrigin('not a url at all'), /not a coffre address/);
});

// --- the credentials file -----------------------------------------------------

test('the single-token file older CLIs wrote reads as signed out, not as a session', () => {
  assert.deepEqual(parseStore('{"token":"eyJ…","obtainedAt":"2026-01-01"}'), emptyStore());
  assert.deepEqual(parseStore('not json'), emptyStore());
  assert.deepEqual(parseStore('null'), emptyStore());
});

test('unknown modes and a dangling current are dropped on read', () => {
  const store = parseStore(
    JSON.stringify({
      version: 2,
      current: 'https://gone.example.com',
      instances: {
        [OURS]: { mode: 'signin', token: 't', obtainedAt: 'x' },
        'https://odd.example.com': { mode: 'kerberos', obtainedAt: 'x' },
      },
    }),
  );
  assert.deepEqual(Object.keys(store.instances), [OURS]);
  assert.equal(store.current, null);
});

test('signing out of the current instance falls back to another one', () => {
  const store = withoutSession(storeWith(), OURS);
  assert.equal(store.current, THEIRS);
  assert.deepEqual(Object.keys(store.instances), [THEIRS]);
  assert.equal(withoutSession(store, THEIRS).current, null);
});

// --- resolution ---------------------------------------------------------------

test('with no environment, the current instance and its session are used', () => {
  assert.deepEqual(resolveTarget({}, storeWith(), NOW), {
    origin: OURS,
    mode: 'signin',
    credential: { kind: 'token', token: 'coffre_cli_ours' },
  });
});

test('COFFRE_API_URL picks another saved instance, with that instance’s mode', () => {
  assert.deepEqual(resolveTarget({ COFFRE_API_URL: 'coffre.equisafe.dev' }, storeWith(), NOW), {
    origin: THEIRS,
    mode: 'cloudflare',
    credential: { kind: 'cloudflared' },
  });
});

test('a service token in COFFRE_TOKEN works with nothing saved, as in CI', () => {
  assert.deepEqual(
    resolveTarget({ COFFRE_API_URL: OURS, COFFRE_TOKEN: 'coffre_svc_ci' }, emptyStore(), NOW),
    { origin: OURS, mode: 'signin', credential: { kind: 'token', token: 'coffre_svc_ci' } },
  );
});

test('a Cloudflare Access service token implies Cloudflare mode', () => {
  const target = resolveTarget(
    {
      COFFRE_API_URL: THEIRS,
      COFFRE_ACCESS_CLIENT_ID: 'id.access',
      COFFRE_ACCESS_CLIENT_SECRET: 'shh',
    },
    emptyStore(),
    NOW,
  );
  assert.deepEqual(target, {
    origin: THEIRS,
    mode: 'cloudflare',
    credential: { kind: 'access-service-token', clientId: 'id.access', clientSecret: 'shh' },
  });
  assert.throws(
    () => resolveTarget({ COFFRE_API_URL: THEIRS, COFFRE_ACCESS_CLIENT_ID: 'id' }, emptyStore(), NOW),
    /COFFRE_ACCESS_CLIENT_SECRET is not/,
  );
});

test('an instance with no saved session asks for a login there', () => {
  assert.throws(
    () => resolveTarget({ COFFRE_API_URL: 'https://other.example.com' }, storeWith(), NOW),
    /not signed in to https:\/\/other\.example\.com: run `coffre login https:\/\/other\.example\.com`/,
  );
  assert.throws(() => resolveTarget({}, emptyStore(), NOW), /coffre login <url>/);
});

test('a saved token is not sent to the same origin under a different mode', () => {
  assert.throws(
    () => resolveTarget({ COFFRE_AUTH_MODE: 'dev' }, storeWith(), NOW),
    /not signed in to https:\/\/coffre\.example\.com/,
  );
  assert.throws(() => resolveTarget({ COFFRE_AUTH_MODE: 'saml' }, storeWith(), NOW), /must be one of/);
});

test('an expired session is refused locally with the date it ended', () => {
  assert.throws(
    () => resolveTarget({}, storeWith(), new Date('2026-11-01T00:00:00Z')),
    /ended on 2026-10-26: run `coffre login https:\/\/coffre\.example\.com`/,
  );
});

// --- headers ------------------------------------------------------------------

test('each mode carries its credential the way its gatekeeper expects', () => {
  assert.deepEqual(credentialHeaders('signin', { kind: 'token', token: 't' }), {
    authorization: 'Bearer t',
  });
  assert.deepEqual(credentialHeaders('cloudflare', { kind: 'token', token: 't' }), {
    'cf-access-token': 't',
  });
  assert.deepEqual(credentialHeaders('cloudflare', { kind: 'cloudflared' }, 'from-cloudflared'), {
    'cf-access-token': 'from-cloudflared',
  });
  assert.deepEqual(
    credentialHeaders('cloudflare', { kind: 'access-service-token', clientId: 'i', clientSecret: 's' }),
    { 'cf-access-client-id': 'i', 'cf-access-client-secret': 's' },
  );
  assert.deepEqual(credentialHeaders('dev', { kind: 'token', token: 't' }), {
    'cf-access-jwt-assertion': 't',
  });
});
