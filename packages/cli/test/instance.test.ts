import test from 'node:test';
import assert from 'node:assert/strict';

import {
  choose,
  credentialHeaders,
  emptyPins,
  emptyStore,
  instanceOrigin,
  isJsonContentType,
  localFor,
  loginMode,
  parsePins,
  parseRepoFile,
  parseStore,
  pinFor,
  resolveTarget,
  signInError,
  SIGN_IN_HINT,
  within,
  withPin,
  withoutPins,
  withSession,
  withoutSession,
  type AuthMode,
  type Local,
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
    /not signed in: run `coffre login https:\/\/other\.example\.com`/,
  );
  assert.throws(() => resolveTarget({}, emptyStore(), null, NOW), /coffre login <url>/);
});

test('every message that sends someone to `coffre login` has the one-line agent hint under it', () => {
  assert.equal(SIGN_IN_HINT, 'agents: run the command in the background and provide the link it prints to the user');
  assert.equal(signInError('not signed in: run `coffre login https://coffre.example.com`', 'signin'), `not signed in: run \`coffre login https://coffre.example.com\`\n${SIGN_IN_HINT}`);
  // An instance not yet signed in to gets the same hint; Cloudflare Access signs in with cloudflared and gets none.
  assert.equal(signInError('x'), `x\n${SIGN_IN_HINT}`);
  assert.equal(signInError('x', 'cloudflare'), 'x');

  const sentTo = (call: () => unknown, line: string, mode?: AuthMode) =>
    assert.throws(call, (error: Error) => {
      assert.equal(error.message.split('\n')[0], line, 'the first line is the one grep finds');
      assert.equal(error.message, signInError(line, mode));
      return true;
    });
  sentTo(() => resolveTarget({}, emptyStore(), null, NOW), 'not signed in anywhere yet: run `coffre login <url>`');
  sentTo(() => choose({}, emptyStore(), null), 'not signed in anywhere yet: run `coffre login <url>`');
  sentTo(() => resolveTarget({ url: 'https://other.example.com' }, storeWith(), null, NOW), 'not signed in: run `coffre login https://other.example.com`');
  // Named a sign-in instance by --auth-mode: known.
  sentTo(() => resolveTarget({ url: 'https://other.example.com', authMode: 'signin' }, storeWith(), null, NOW), 'not signed in: run `coffre login https://other.example.com`', 'signin');
  sentTo(
    () => resolveTarget({}, storeWith(), null, new Date('2026-11-01T00:00:00Z')),
    `your session on ${OURS} ended on 2026-10-26: run \`coffre login ${OURS}\``,
    'signin',
  );
  // A person's session with no token left in it; a bearer token's or a CI run's is signed in again another way.
  const tokenless = (kind?: 'token' | 'run') => withSession(emptyStore(), OURS, { mode: 'signin', ...(kind === undefined ? {} : { kind }), obtainedAt: '2026-09-26T00:00:00Z' });
  sentTo(() => resolveTarget({}, tokenless(), null, NOW), `not signed in: run \`coffre login ${OURS}\``, 'signin');
  for (const kind of ['token', 'run'] as const) {
    assert.throws(() => resolveTarget({}, tokenless(kind), null, NOW), (error: Error) => !error.message.includes('\n'));
  }
  // Cloudflare Access signs in with cloudflared, not a code: no hint.
  assert.throws(() => resolveTarget({ authMode: 'cloudflare' }, storeWith(), null, NOW), (error: Error) => !error.message.includes('\n'));
  assert.throws(() => choose({ authMode: 'cloudflare' }, emptyStore(), null), (error: Error) => !error.message.includes('\n'));
  sentTo(() => choose({ authMode: 'signin' }, emptyStore(), null), 'not signed in anywhere yet: run `coffre login <url>`', 'signin');
  // A mode that is none is the command's to refuse, not the hint's.
  sentTo(() => choose({ authMode: 'dev' }, emptyStore(), null), 'not signed in anywhere yet: run `coffre login <url>`');
});

test('a saved token is not sent to the same origin under a different mode', () => {
  assert.throws(
    () => resolveTarget({ authMode: 'cloudflare' }, storeWith(), null, NOW),
    /not signed in: run `coffre login https:\/\/coffre\.example\.com`/,
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

test('a directory is pinned, or pinned again in place', () => {
  const pins = pinned();
  assert.deepEqual(withPin(pins, '/home/ada/Code/acme/web', OURS).directories['/home/ada/Code/acme/web'], OURS);
  assert.deepEqual(withPin(pins, '/home/ada/Code/acme', OURS).directories['/home/ada/Code/acme'], OURS);
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
  assert.throws(() => parsePins(JSON.stringify({ version: 1, directories: [] })), /does not know its shape/);
  assert.throws(() => parsePins(JSON.stringify({ version: 1, directories: { 'Code/acme': THEIRS } })), /pins "Code\/acme"/);
  assert.throws(() => parsePins(JSON.stringify({ version: 1, directories: { '/a': 'http://devbox:3000' } })), /plain HTTP/);
});

// --- coffre.json -------------------------------------------------------------

test("a repository's coffre.json names an origin, and nothing else", () => {
  assert.equal(parseRepoFile('{ "url": "https://coffre.acme.example" }\n'), THEIRS);
  assert.equal(parseRepoFile('{"url":"http://127.0.0.1:3000"}'), 'http://127.0.0.1:3000', 'this machine, over HTTP, as login takes it');
  assert.throws(() => parseRepoFile('{'), /^Error: it is not JSON$/);
  for (const text of ['[]', '"https://coffre.acme.example"', 'null', '{}', '{"url":3}']) {
    assert.throws(() => parseRepoFile(text), /^Error: expected \{ "url": "https:\/\/…" \}$/, text);
  }
  assert.throws(() => parseRepoFile(JSON.stringify({ url: THEIRS, token: 'coffre_cli_x' })), /^Error: it holds only "url", never a credential or anything else: not "token"$/);
  assert.throws(() => parseRepoFile(JSON.stringify({ url: 'http://coffre.acme.example' })), /plain HTTP; use https:\/\/coffre\.acme\.example/);
  assert.throws(() => parseRepoFile(JSON.stringify({ url: 'https://coffre.acme.example/api' })), /must be an origin/);
  assert.throws(() => parseRepoFile(JSON.stringify({ url: 'https://ada@coffre.acme.example' })), /user name or password/);
  for (const url of ['https://coffre.acme.example/', 'coffre.acme.example', 'HTTPS://Coffre.Acme.Example']) {
    assert.throws(() => parseRepoFile(JSON.stringify({ url })), /^Error: "url" is an origin, written as one: "https:\/\/coffre\.acme\.example", not /, url);
  }
});

test('walking up from a directory, the nearest pin or coffre.json names the instance, a pin first in the same directory', () => {
  const files: Record<string, string> = {
    '/home/ada/Code/acme/coffre.json': JSON.stringify({ url: OURS }),
    '/home/ada/Code/acme/web/coffre.json': JSON.stringify({ url: OURS }),
    '/home/ada/Code/coffre.json': JSON.stringify({ url: 'https://code.example' }),
    '/home/ada/coffre.json': JSON.stringify({ url: 'https://home.example' }),
    '/home/coffre.json': JSON.stringify({ url: 'https://above.example' }),
    '/coffre.json': JSON.stringify({ url: 'https://root.example' }),
    '/srv/repo/coffre.json': JSON.stringify({ url: THEIRS }),
    '/srv/broken/coffre.json': JSON.stringify({ url: THEIRS, token: 'x' }),
    '/home/ada/Code/acme/side/coffre.json': '{',
  };
  const read: string[] = [];
  const at = (directory: string): Local | null => localFor(pinned(), directory, '/home/ada', (path) => (read.push(path), files[path] ?? null));
  assert.deepEqual(at('/home/ada/Code/acme'), { origin: THEIRS, by: 'pin', directory: '/home/ada/Code/acme' }, 'a pin in the same directory');
  assert.deepEqual(at('/home/ada/Code/acme/lib'), { origin: THEIRS, by: 'pin', directory: '/home/ada/Code/acme' });
  assert.deepEqual(at('/home/ada/Code/acme/web/src'), { origin: OURS, by: 'file', directory: '/home/ada/Code/acme/web' }, 'a file below the pin');
  assert.deepEqual(at('/home/ada/Code/other'), { origin: 'https://code.example', by: 'file', directory: '/home/ada/Code' }, 'a file above');
  assert.deepEqual(at('/srv/repo/app'), { origin: THEIRS, by: 'file', directory: '/srv/repo' }, 'outside your home, too');
  // Your home and above it, and the root, are no repository's.
  assert.equal(at('/home/ada'), null);
  assert.equal(at('/home'), null);
  assert.equal(at('/srv'), null);
  read.length = 0;
  at('/home/ada/Code/acme/side/x');
  assert.deepEqual(read, ['/home/ada/Code/acme/side/x/coffre.json'], 'a pin nearer than a broken file: the file is not read');
  // The nearest file, unusable, is an error: never the file or the pin above it.
  assert.throws(() => at('/srv/broken/app'), /^Error: cannot use \/srv\/broken\/coffre\.json: it holds only "url"/);
  assert.throws(() => localFor(emptyPins(), '/home/ada/Code/acme/side', '/home/ada', (path) => files[path] ?? null), /^Error: cannot use \/home\/ada\/Code\/acme\/side\/coffre\.json: it is not JSON$/);
});

test('a coffre.json names the instance, and the session sent there is its own: with none, the error says where the URL came from', () => {
  const file: Local = { origin: THEIRS, by: 'file', directory: '/home/ada/Code/acme' };
  assert.deepEqual(choose({}, storeWith(), file), file);
  assert.deepEqual(choose({ url: OURS }, storeWith(), file), { origin: OURS, by: 'url' }, '--url first');
  assert.deepEqual(resolveTarget({}, storeWith(), file, NOW).credential, { kind: 'cloudflared' });
  assert.throws(
    () => resolveTarget({}, emptyStore(), file, NOW),
    /^Error: not signed in: run `coffre login https:\/\/coffre\.acme\.example` \(named by \/home\/ada\/Code\/acme\/coffre\.json\)\n/,
  );
  // A CI run's ID token is asked for that origin alone, which no other instance takes: it needs no --url.
  assert.deepEqual(resolveTarget({ service: 'deploy' }, emptyStore(), file, NOW), {
    origin: THEIRS, mode: 'signin', by: 'service', credential: { kind: 'workload', service: 'token:deploy' },
  });
});

test('--url, then the pin that applies, then the default', () => {
  const pin: Local = { directory: '/home/ada/Code/acme', origin: THEIRS, by: 'pin' };
  assert.deepEqual(choose({ url: 'coffre.example.com' }, storeWith(), pin), { origin: OURS, by: 'url' });
  assert.deepEqual(choose({}, storeWith(), pin), { origin: THEIRS, by: 'pin', directory: '/home/ada/Code/acme' });
  assert.deepEqual(choose({}, storeWith(), null), { origin: OURS, by: 'default' });
  assert.equal(resolveTarget({}, storeWith(), pin, NOW).origin, THEIRS);
  // A CI run's ID token goes where the directory is pinned too, as it went to the default.
  assert.equal(resolveTarget({ service: 'deploy' }, emptyStore(), pin, NOW).origin, THEIRS);
});

test('a saved default or pin over plain HTTP is refused as a typed one is, a CI run’s ID token too', () => {
  const insecure = 'http://secrets.acme.example';
  const store = withSession(emptyStore(), insecure, { mode: 'signin', token: 'coffre_cli_x', obtainedAt: '2026-09-26T00:00:00Z' });
  assert.equal(store.current, insecure);
  for (const flags of [{}, { service: 'deploy' }]) {
    assert.throws(() => resolveTarget(flags, store, null, NOW), /refusing to send credentials over plain HTTP/);
    assert.throws(() => resolveTarget(flags, storeWith(), { directory: '/home/ada/Code/acme', origin: insecure, by: 'pin' }, NOW), /plain HTTP/);
  }
});

test('a directory pinned to an instance with no session asks for a login there, and never uses the default', () => {
  const pin: Local = { directory: '/home/ada/Code/gone', origin: 'https://gone.example.com', by: 'pin' };
  assert.throws(
    () => resolveTarget({}, storeWith(), pin, NOW),
    /^Error: not signed in: run `coffre login https:\/\/gone\.example\.com`\n/,
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
