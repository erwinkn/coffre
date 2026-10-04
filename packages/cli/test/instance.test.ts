import test from 'node:test';
import assert from 'node:assert/strict';

import {
  credentialHeaders,
  emptyStore,
  instanceOrigin,
  isJsonContentType,
  loginMode,
  parseStore,
  resolveTarget,
  withSession,
  withoutSession,
  type Store,
} from '../src/instance.ts';

const OURS = 'https://coffre.example.com';
const THEIRS = 'https://coffre.acme.example';
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
  assert.equal(instanceOrigin('http://127.0.0.1:3051'), 'http://127.0.0.1:3051');
  assert.equal(instanceOrigin('http://localhost:3000'), 'http://localhost:3000');
  assert.equal(instanceOrigin('http://[::1]:3000'), 'http://[::1]:3000');
  assert.throws(() => instanceOrigin('http://devbox:3000'), /plain HTTP/);
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

test('unknown modes, like the dev mode older CLIs saved, and a dangling current are dropped on read', () => {
  const store = parseStore(
    JSON.stringify({
      version: 2,
      current: 'https://gone.example.com',
      instances: {
        [OURS]: { mode: 'signin', token: 't', obtainedAt: 'x' },
        'https://odd.example.com': { mode: 'kerberos', obtainedAt: 'x' },
        'http://127.0.0.1:3000': { mode: 'dev', token: 't', obtainedAt: 'x' },
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

test('with no session flags, the current instance and its session are used', () => {
  assert.deepEqual(resolveTarget({}, storeWith(), NOW), {
    origin: OURS,
    mode: 'signin',
    credential: { kind: 'token', token: 'coffre_cli_ours' },
  });
});

test('--url picks another saved instance, with that instance’s mode', () => {
  assert.deepEqual(resolveTarget({ url: 'coffre.acme.example' }, storeWith(), NOW), {
    origin: THEIRS,
    mode: 'cloudflare',
    credential: { kind: 'cloudflared' },
  });
});

test('a service token in --token-file works with nothing saved, as in CI', () => {
  assert.deepEqual(
    resolveTarget({ url: OURS, token: 'coffre_svc_ci' }, emptyStore(), NOW),
    { origin: OURS, mode: 'signin', credential: { kind: 'token', token: 'coffre_svc_ci' } },
  );
});

test('a Cloudflare Access service token implies Cloudflare mode', () => {
  const target = resolveTarget(
    {
      url: THEIRS,
      accessClientId: 'id.access',
      accessClientSecret: 'shh',
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
    () => resolveTarget({ url: THEIRS, accessClientId: 'id' }, emptyStore(), NOW),
    /--access-client-id needs its secret: --access-client-secret-file/,
  );
  // Even where a session is saved for coffre's own sign-in: the flag says which.
  assert.equal(resolveTarget({ url: OURS, accessClientId: 'id', accessClientSecret: 'shh' }, storeWith(), NOW).credential.kind, 'access-service-token');
  assert.throws(
    () => resolveTarget({ url: OURS, accessClientId: 'id', accessClientSecret: 'shh', authMode: 'signin' }, storeWith(), NOW),
    /--access-client-id is a Cloudflare Access service token, and --auth-mode signin/,
  );
  assert.throws(() => resolveTarget({ url: THEIRS, accessClientSecret: 'shh' }, emptyStore(), NOW), /--access-client-secret-file goes with --access-client-id/);
});

test('an instance with no saved session asks for a login there', () => {
  assert.throws(
    () => resolveTarget({ url: 'https://other.example.com' }, storeWith(), NOW),
    /not signed in to https:\/\/other\.example\.com: run `coffre login https:\/\/other\.example\.com`/,
  );
  assert.throws(() => resolveTarget({}, emptyStore(), NOW), /coffre login <url>/);
});

test('a saved token is not sent to the same origin under a different mode', () => {
  assert.throws(
    () => resolveTarget({ authMode: 'cloudflare' }, storeWith(), NOW),
    /not signed in to https:\/\/coffre\.example\.com/,
  );
  assert.throws(() => resolveTarget({ authMode: 'dev' }, storeWith(), NOW), /--auth-mode must be one of signin, cloudflare/);
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
});

// --- login ----------------------------------------------------------------------

test('login signs in the way GET /api/auth says, or the way Access turns it away', () => {
  const signin = { signin: { title: 'coffre', note: null, providers: [] }, access: null };
  assert.equal(loginMode(OURS, 200, signin), 'signin');
  assert.equal(loginMode(THEIRS, 200, { signin: null, access: { assertion: false } }), 'cloudflare');
  assert.equal(loginMode(THEIRS, 302, undefined), 'cloudflare');
  assert.throws(() => loginMode(THEIRS, 403, undefined), /coffre --auth-mode cloudflare login https:\/\/coffre\.acme\.example/);
  assert.throws(() => loginMode(OURS, 404, undefined), /does not look like coffre: GET \/api\/auth answered 404/);
  assert.throws(() => loginMode(OURS, 200, { hello: 'world' }), /does not look like coffre/);
});

test('JSON is recognised by its media type, parameters or not', () => {
  assert.equal(isJsonContentType('application/json'), true);
  assert.equal(isJsonContentType('application/problem+json; charset=utf-8'), true);
  assert.equal(isJsonContentType('text/html; charset=utf-8'), false);
  assert.equal(isJsonContentType(null), false);
});
