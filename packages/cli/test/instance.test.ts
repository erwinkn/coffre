import test from 'node:test';
import assert from 'node:assert/strict';

import {
  choose,
  credentialHeaders,
  emptyPins,
  emptyStore,
  instanceOrigin,
  isJsonContentType,
  loginMode,
  parsePins,
  parseStore,
  pinFor,
  resolveTarget,
  within,
  withPin,
  withoutPins,
  withSession,
  withoutSession,
  type Pins,
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

test('a file in another shape reads as signed out, not as a session', () => {
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
  assert.deepEqual(resolveTarget({}, storeWith(), null, NOW), {
    origin: OURS,
    mode: 'signin',
    by: 'person',
    credential: { kind: 'token', token: 'coffre_cli_ours' },
  });
});

test('--url picks another saved instance, with that instance’s mode', () => {
  assert.deepEqual(resolveTarget({ url: 'coffre.acme.example' }, storeWith(), null, NOW), {
    origin: THEIRS,
    mode: 'cloudflare',
    by: 'person',
    credential: { kind: 'cloudflared' },
  });
});

test('a CI run signs in with `coffre login`, and its session is used as a person’s is', () => {
  const token = withSession(emptyStore(), OURS, { mode: 'signin', kind: 'token', token: 'coffre_svc_ci', expiresAt: null, obtainedAt: '2026-09-26T00:00:00Z' });
  assert.deepEqual(resolveTarget({}, token, null, NOW), { origin: OURS, mode: 'signin', by: 'token', credential: { kind: 'token', token: 'coffre_svc_ci' } });
  const access = withSession(emptyStore(), THEIRS, { mode: 'cloudflare', kind: 'access', clientId: 'id.access', clientSecret: 'shh', obtainedAt: '2026-09-26T00:00:00Z' });
  assert.deepEqual(resolveTarget({}, access, null, NOW), {
    origin: THEIRS,
    mode: 'cloudflare',
    by: 'access',
    credential: { kind: 'access-service-token', clientId: 'id.access', clientSecret: 'shh' },
  });
  // A run's credential lasts five minutes, and says how to get another.
  const run = withSession(emptyStore(), OURS, {
    mode: 'signin',
    kind: 'run',
    token: 'coffre_svc_run',
    principal: { type: 'service', id: 'token:api-deploy' },
    expiresAt: '2026-09-26T12:05:00Z',
    obtainedAt: '2026-09-26T12:00:00Z',
  });
  assert.equal(resolveTarget({}, run, null, NOW).by, 'run');
  assert.throws(
    () => resolveTarget({}, run, null, new Date('2026-09-26T12:06:00Z')),
    /lasted until 12:05:00: sign in again, `coffre login https:\/\/coffre\.example\.com --service token:api-deploy`/,
  );
  // An unknown kind, from a later CLI say, is no session at all.
  assert.deepEqual(parseStore(JSON.stringify({ version: 2, current: OURS, instances: { [OURS]: { mode: 'signin', kind: 'robot', token: 't' } } })), emptyStore());
});

test('an instance with no saved session asks for a login there', () => {
  assert.throws(
    () => resolveTarget({ url: 'https://other.example.com' }, storeWith(), null, NOW),
    /not signed in to https:\/\/other\.example\.com: run `coffre login https:\/\/other\.example\.com`/,
  );
  assert.throws(() => resolveTarget({}, emptyStore(), null, NOW), /coffre login <url>/);
});

test('a saved token is not sent to the same origin under a different mode', () => {
  assert.throws(
    () => resolveTarget({ authMode: 'cloudflare' }, storeWith(), null, NOW),
    /not signed in to https:\/\/coffre\.example\.com/,
  );
  assert.throws(() => resolveTarget({ authMode: 'dev' }, storeWith(), null, NOW), /--auth-mode must be one of signin, cloudflare/);
});

test('an expired session is refused locally with the date it ended', () => {
  assert.throws(
    () => resolveTarget({}, storeWith(), null, new Date('2026-11-01T00:00:00Z')),
    /ended on 2026-10-26: run `coffre login https:\/\/coffre\.example\.com`/,
  );
});

// --- pinned directories -------------------------------------------------------

function pinned(): Pins {
  let pins = withPin(emptyPins(), '/home/ada/Code/acme', THEIRS);
  pins = withPin(pins, '/home/ada/Code/acme/side', OURS);
  return pins;
}

test('a directory uses its nearest pinned parent, and a sibling sharing a prefix is not below it', () => {
  const pins = pinned();
  assert.deepEqual(pinFor(pins, '/home/ada/Code/acme'), { directory: '/home/ada/Code/acme', origin: THEIRS });
  assert.deepEqual(pinFor(pins, '/home/ada/Code/acme/web/src'), { directory: '/home/ada/Code/acme', origin: THEIRS });
  assert.deepEqual(pinFor(pins, '/home/ada/Code/acme/side/x'), { directory: '/home/ada/Code/acme/side', origin: OURS });
  assert.equal(pinFor(pins, '/home/ada/Code/acme-old'), null);
  assert.equal(pinFor(pins, '/home/ada/Code'), null);
  assert.ok(within('/home/ada', '/'));
  assert.ok(within('/home/ada/..x', '/home/ada'), 'a directory whose name starts with two dots is still below');
});

test('a login pins its directory only where the pin that applies says otherwise', () => {
  const pins = pinned();
  assert.equal(withPin(pins, '/home/ada/Code/acme/web', THEIRS), pins, 'a pin below one to the same instance is redundant');
  assert.deepEqual(withPin(pins, '/home/ada/Code/acme/web', OURS).directories['/home/ada/Code/acme/web'], OURS);
  assert.deepEqual(withPin(pins, '/home/ada/Code/acme', OURS).directories['/home/ada/Code/acme'], OURS, 'a directory is pinned again in place');
});

test('signing out unpins every directory pinned to that instance', () => {
  const { pins, unpinned } = withoutPins(withPin(pinned(), '/srv/other', THEIRS), THEIRS);
  assert.deepEqual(unpinned, ['/home/ada/Code/acme', '/srv/other']);
  assert.deepEqual(pins.directories, { '/home/ada/Code/acme/side': OURS });
});

test('the pins file is read whole or not at all: one this CLI cannot read is an error, never no pins', () => {
  assert.deepEqual(parsePins(JSON.stringify({ version: 1, directories: { '/home/ada/Code/acme': 'coffre.acme.example' } })).directories, {
    '/home/ada/Code/acme': THEIRS,
  });
  assert.throws(() => parsePins('not json'), /not JSON/);
  assert.throws(() => parsePins(JSON.stringify({ version: 2, directories: {} })), /does not know its shape/);
  assert.throws(() => parsePins(JSON.stringify({ version: 1, directories: { 'Code/acme': THEIRS } })), /pins "Code\/acme"/);
  assert.throws(() => parsePins(JSON.stringify({ version: 1, directories: { '/a': 'http://devbox:3000' } })), /plain HTTP/);
});

test('--url, then the pin that applies, then the default', () => {
  const pin = { directory: '/home/ada/Code/acme', origin: THEIRS };
  assert.deepEqual(choose({ url: 'coffre.example.com' }, storeWith(), pin), { origin: OURS, by: 'url' });
  assert.deepEqual(choose({}, storeWith(), pin), { origin: THEIRS, by: 'pin', directory: '/home/ada/Code/acme' });
  assert.deepEqual(choose({}, storeWith(), null), { origin: OURS, by: 'default' });
  assert.equal(resolveTarget({}, storeWith(), pin, NOW).origin, THEIRS);
  // A CI run's ID token goes where the directory is pinned too, as it went to the default.
  assert.equal(resolveTarget({ service: 'deploy' }, emptyStore(), pin, NOW).origin, THEIRS);
});

test('a directory pinned to an instance with no session asks for a login there, and never uses the default', () => {
  const pin = { directory: '/home/ada/Code/gone', origin: 'https://gone.example.com' };
  assert.throws(
    () => resolveTarget({}, storeWith(), pin, NOW),
    /^Error: not signed in to https:\/\/gone\.example\.com: run `coffre login https:\/\/gone\.example\.com`$/,
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
