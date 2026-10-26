import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { execFile, spawn } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, mkdirSync, writeFileSync, statSync, rmSync, readFileSync, realpathSync, symlinkSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { parseStore, signInError } from '../src/instance.ts';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));
const token = `coffre_cli_${'a'.repeat(43)}`;

for (const linked of [false, true]) {
  test(`login ${linked ? 'refuses a linked credentials file' : 'tightens existing credentials and directory permissions'}`, async (t) => {
    const home = mkdtempSync(join(tmpdir(), 'coffre-login-'));
    t.after(() => rmSync(home, { recursive: true, force: true }));
    const directory = join(home, '.coffre');
    const file = join(directory, 'credentials.json');
    const contents = '{"version":2,"current":null,"instances":{}}';
    mkdirSync(directory);
    chmodSync(directory, 0o755);
    if (linked) {
      writeFileSync(join(home, 'linked.json'), contents);
      symlinkSync(join(home, 'linked.json'), file);
    } else {
      writeFileSync(file, contents);
      chmodSync(file, 0o644);
    }
    const server = createServer((req, res) => {
      const body = req.url === '/api/auth' ? { signin: { providers: [] }, access: null }
        : req.url === '/api/auth/device' ? {
          device_code: 'device', user_code: 'BCDF-GHJK', verification_uri_complete: 'http://127.0.0.1/approve',
          interval: 1, expires_in: 60,
        }
        : req.url === '/api/auth/device/token' ? { access_token: token, expires_at: '2099-01-01T00:00:00Z' }
        : { principal: { type: 'user', id: 'admin@acme.example' }, registered: true, features: { mcp: null, workloads: true }, environments: [] };
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(body));
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    t.after(() => new Promise<void>((resolve) => { server.close(() => resolve()); server.closeAllConnections(); }));
    const address = server.address();
    assert.ok(address !== null && typeof address !== 'string');
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('COFFRE_')));
    const login = promisify(execFile)(process.execPath, [
      '--conditions=coffre:source', main, 'login', `http://127.0.0.1:${address.port}`, '--no-browser',
    ], { env: { ...env, HOME: home } });
    if (linked) {
      await assert.rejects(login, (error: Error & { stderr?: string }) => {
        assert.match(error.stderr ?? '', /cannot secure credentials.*symbolic link/);
        return true;
      });
      assert.equal(readFileSync(join(home, 'linked.json'), 'utf8'), contents);
    } else {
      const { stderr } = await login;
      assert.match(stderr, /Waiting for you to approve it; the code expires in 1 minute…/);
      assert.equal(JSON.parse(readFileSync(file, 'utf8')).instances[`http://127.0.0.1:${address.port}`].token, token);
      assert.equal(statSync(file).mode & 0o777, 0o600);
      assert.equal(statSync(directory).mode & 0o777, 0o700);
    }
  });
}

/**
 * A coffre that knows one credential of each kind a CI run signs in with,
 * and signs a person in by a device login approved at once, and keeps every
 * request. It plays GitHub's runner too, at /runner: an ID token for its
 * own origin alone. Its first `unavailable` exchanges answer 503
 * `unavailable`, each with its reason, or none; so do its first
 * `meUnavailable` answers at /api/me.
 */
async function ciInstance(t: test.TestContext, { unavailable = [] as (string | null)[], meUnavailable = 0 } = {}) {
  const seen: { method: string; url: string; headers: Record<string, string | string[] | undefined>; body: string }[] = [];
  let origin = '';
  const server = createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += String(chunk);
    seen.push({ method: req.method!, url: req.url!, headers: req.headers, body });
    const send = (status: number, value: unknown) => res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(value));
    if (req.url === '/api/auth') return send(200, { signin: { providers: [] }, access: null });
    if (req.url === '/api/auth/device') return send(200, { device_code: 'device', user_code: 'BCDF-GHJK', verification_uri_complete: `${origin}/approve`, interval: 1, expires_in: 60 });
    if (req.url === '/api/auth/device/token') return send(200, { access_token: 'coffre_cli_ada', expires_at: '2099-01-01T00:00:00Z' });
    if (req.url?.startsWith('/runner?')) {
      return new URL(req.url, origin).searchParams.get('audience') === origin ? send(200, { value: 'id.token.ok' }) : send(400, {});
    }
    if (req.url === '/api/auth/oidc') {
      const reason = unavailable.shift();
      if (reason !== undefined) {
        return send(503, { error: 'unavailable', message: 'coffre cannot reach what it depends on right now; try again in a moment', ...(reason === null ? {} : { reason }) });
      }
      const { token } = JSON.parse(body) as { token: string };
      return token === 'id.token.ok' ? send(200, { token: 'coffre_svc_run', expiresAt: '2099-01-01T00:05:00.000Z' }) : send(401, { error: 'unauthenticated', reason: 'no_match', message: 'no' });
    }
    const known =
      req.headers.authorization === 'Bearer coffre_svc_ci' ||
      req.headers.authorization === 'Bearer coffre_cli_ada' ||
      req.headers.authorization === 'Bearer coffre_svc_run' ||
      (req.headers['cf-access-client-id'] === 'id.access' && req.headers['cf-access-client-secret'] === 'shh');
    if (req.url === '/api/me' && meUnavailable > 0) {
      meUnavailable -= 1;
      return send(503, { error: 'unavailable', message: 'coffre cannot check who you are right now' });
    }
    if (req.url === '/api/me' && req.headers.authorization === 'Bearer coffre_cli_busy') return send(500, { error: 'internal', message: 'something went wrong' });
    if (req.url === '/api/me' && known) return send(200, { principal: { type: 'service', id: 'deploy' }, registered: true, features: { mcp: null, workloads: true }, environments: [] });
    if (req.method === 'PATCH' && req.url === '/api/secrets/app/prod' && known) return send(200, { operationId: 'op', keys: { KEY: { version: 1 } } });
    send(401, { error: 'unauthenticated', message: 'that credential is unknown, expired or revoked' });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise<void>((resolve) => { server.close(() => resolve()); server.closeAllConnections(); }));
  const address = server.address();
  assert.ok(address !== null && typeof address !== 'string');
  origin = `http://127.0.0.1:${address.port}`;
  return { origin, seen };
}

/**
 * The CLI, `input` on its stdin: not spawnSync, which would stop the server in this process from answering it.
 * `gone`, it runs in `cwd` removed once it started, as another shell might; `more`, with those variables too.
 */
async function cli(home: string, args: string[], input: string, cwd?: string, gone = false, more: Record<string, string> = {}): Promise<{ status: number | null; stdout: string; stderr: string }> {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('COFFRE_') && !key.startsWith('ACTIONS_ID_TOKEN_')));
  const removed = `import { rmSync } from 'node:fs'; process.cwd(); rmSync(process.cwd(), { recursive: true }); process.argv.splice(1, 0, ${JSON.stringify(main)}); await import(${JSON.stringify(pathToFileURL(main).href)});`;
  const node = gone ? ['--conditions=coffre:source', '--input-type=module', '-e', removed, '--'] : ['--conditions=coffre:source', main];
  const child = spawn(process.execPath, [...node, ...args], { cwd, env: { ...env, HOME: home, ...more }, stdio: ['pipe', 'pipe', 'pipe'] });
  let [stdout, stderr] = ['', ''];
  child.stdout.setEncoding('utf8').on('data', (chunk: string) => (stdout += chunk));
  child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
  child.stdin.on('error', () => {});
  child.stdin.end(input);
  const [status] = (await once(child, 'close')) as [number | null];
  return { status, stdout, stderr };
}

test('a CI run the instance cannot sign in yet asks again, with a fresh ID token, twice at most', async (t) => {
  const home = mkdtempSync(join(tmpdir(), 'coffre-login-busy-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const signIns = (seen: { url: string }[]) => seen.map(({ url }) => url.split('?')[0]).filter((url) => url === '/runner' || url === '/api/auth/oidc');

  // The issuer's keys out of reach for a moment, as its database: asked again.
  const busy = await ciInstance(t, { unavailable: ['issuer_unavailable'] });
  const runner = { ACTIONS_ID_TOKEN_REQUEST_URL: `${busy.origin}/runner`, ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'bearer' };
  const signed = await cli(home, ['--url', busy.origin, '--service', 'deploy', '--verbose', 'whoami'], '', undefined, false, runner);
  assert.equal(signed.status, 0, signed.stderr);
  assert.match(signed.stdout, /^service:deploy \(service account\)/);
  assert.deepEqual(signIns(busy.seen), ['/runner', '/api/auth/oidc', '/runner', '/api/auth/oidc']);
  assert.deepEqual(signed.stderr.replace(/ in \d+(\.\d)? m?s/g, ' in t').split('\n').slice(0, 5), [
    'coffre: GET /runner: 200 in t',
    'coffre: POST /api/auth/oidc: 503 in t',
    'coffre: the instance could not answer POST /api/auth/oidc: asking again in t',
    'coffre: GET /runner: 200 in t',
    'coffre: POST /api/auth/oidc: 200 in t',
  ]);

  // Signed in, then unable for a moment to say who as: login asks who again, and keeps the session.
  const unsure = await ciInstance(t, { meUnavailable: 1 });
  const kept = await cli(home, ['login', unsure.origin, '--service', 'deploy', '--id-token'], 'id.token.ok\n');
  assert.equal(kept.status, 0, kept.stderr);
  assert.match(kept.stdout, new RegExp(`^Signed in to ${unsure.origin} as deploy\\n`));
  assert.deepEqual(unsure.seen.map(({ url }) => url), ['/api/auth/oidc', '/api/me', '/api/me']);

  // Three times unable, it fails as it did; a 503 an operator must fix, at once. Login asks again the same way.
  for (const [unavailable, exchanges] of [[[null, 'busy', null], 3], [['wrong_kek'], 1]] as const) {
    const down = await ciInstance(t, { unavailable: [...unavailable] });
    const login = await cli(home, ['login', down.origin, '--service', 'deploy', '--id-token'], 'id.token.ok\n');
    assert.equal(login.status, 1);
    assert.match(login.stderr, new RegExp(`would not sign this run in as token:deploy${unavailable[0] === null ? '' : ' \\(wrong_kek\\)'}: coffre cannot reach what it depends on right now`));
    assert.equal(signIns(down.seen).length, exchanges, unavailable.join(' '));
  }
});

test('a CI run signs in with what login asks it for, piped in, and later commands use that session', async (t) => {
  const { origin, seen } = await ciInstance(t);
  for (const [args, input, saved] of [
    [['--token'], 'coffre_svc_ci\n', { mode: 'signin', kind: 'token', token: 'coffre_svc_ci' }],
    [['--access-client-id', 'id.access', '--auth-mode', 'cloudflare'], 'shh\n', { mode: 'cloudflare', kind: 'access', clientId: 'id.access', clientSecret: 'shh' }],
    [['--service', 'deploy', '--id-token'], 'id.token.ok\n', { mode: 'signin', kind: 'run', token: 'coffre_svc_run', expiresAt: '2099-01-01T00:05:00.000Z' }],
  ] as const) {
    const home = mkdtempSync(join(tmpdir(), 'coffre-login-ci-'));
    t.after(() => rmSync(home, { recursive: true, force: true }));
    const login = await cli(home, ['login', origin, ...args.filter((arg) => arg !== '--auth-mode' && arg !== 'cloudflare')], input);
    assert.equal(login.status, 0, login.stderr);
    assert.match(login.stdout, new RegExp(`^Signed in to ${origin} as deploy\\n`));
    assert.ok(!login.stdout.includes(input.trim()) && !login.stderr.includes(input.trim()), 'the secret was shown');
    const store = JSON.parse(readFileSync(join(home, '.coffre', 'credentials.json'), 'utf8'));
    assert.equal(store.current, origin);
    const { principal, obtainedAt, expiresAt = null, ...kept } = store.instances[origin];
    assert.deepEqual(principal, { type: 'service', id: 'deploy' });
    assert.ok(typeof obtainedAt === 'string');
    assert.deepEqual({ ...kept, expiresAt }, { expiresAt: null, ...saved });
    assert.equal(statSync(join(home, '.coffre', 'credentials.json')).mode & 0o777, 0o600);
    // The next command, signed in as the run.
    const whoami = await cli(home, ['whoami'], '');
    assert.equal(whoami.status, 0, whoami.stderr);
    assert.match(whoami.stdout, /^service:deploy \(service account\) on .*, via (a bearer token|an Access service token|the run's ID token)/);
    assert.match(whoami.stdout, /\n {2}MCP clients: off\n {2}CI sign-in by ID token: on\n/, 'whoami says what the deployment turns on');
    // Signing out forgets it here, and revokes nothing: the token is the service's.
    const before = seen.length;
    const logout = await cli(home, ['logout'], '');
    assert.equal(logout.status, 0, logout.stderr);
    assert.ok(!seen.slice(before).some(({ url }) => url === '/api/auth/logout'), 'logout sent the service credential to be revoked');
    assert.equal(JSON.parse(readFileSync(join(home, '.coffre', 'credentials.json'), 'utf8')).instances[origin], undefined);
  }
  // A person's session is not replaced unseen, and left valid on the server.
  const person = mkdtempSync(join(tmpdir(), 'coffre-login-ci-'));
  t.after(() => rmSync(person, { recursive: true, force: true }));
  mkdirSync(join(person, '.coffre'), { mode: 0o700 });
  const ada = { mode: 'signin', token: 'coffre_cli_ada', principal: { type: 'user', id: 'ada@acme.example' }, expiresAt: '2099-01-01T00:00:00Z', obtainedAt: '2026-10-01T00:00:00Z' };
  writeFileSync(join(person, '.coffre', 'credentials.json'), JSON.stringify({ version: 2, current: origin, instances: { [origin]: ada } }), { mode: 0o600 });
  const replacing = await cli(person, ['login', origin, '--token'], 'coffre_svc_ci\n');
  assert.equal(replacing.status, 1);
  assert.equal(replacing.stderr, `coffre: signed in to ${origin} as ada@acme.example: \`coffre logout ${origin}\` first, or sign the run in from a home of its own\n`);
  assert.deepEqual(JSON.parse(readFileSync(join(person, '.coffre', 'credentials.json'), 'utf8')).instances[origin], ada);

  // A token the instance does not know: said, and nothing saved.
  const home = mkdtempSync(join(tmpdir(), 'coffre-login-ci-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const refused = await cli(home, ['login', origin, '--token'], 'coffre_svc_unknown\n');
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /does not know/);
  assert.equal(existsSync(join(home, '.coffre', 'credentials.json')), false);
});

test('set takes a piped value as it is, less exactly one final line break', async (t) => {
  const { origin, seen } = await ciInstance(t);
  const home = mkdtempSync(join(tmpdir(), 'coffre-set-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  assert.equal((await cli(home, ['login', origin, '--token'], 'coffre_svc_ci\n')).status, 0);
  for (const [piped, value] of [['  spaced  \n', '  spaced  '], ['l1\nl2\n\n', 'l1\nl2\n'], ['no break', 'no break']]) {
    const set = await cli(home, ['set', 'app/prod/KEY'], piped!);
    assert.equal(set.status, 0, set.stderr);
    assert.deepEqual(JSON.parse(seen.at(-1)!.body), { KEY: value });
  }
});

test('a login pins the directory it ran in: there and below, commands use that instance', async (t) => {
  const a = await ciInstance(t);
  const b = await ciInstance(t);
  const home = realpathSync(mkdtempSync(join(tmpdir(), 'coffre-pins-')));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  for (const directory of ['code/a/nested', 'code/b', 'code/gone']) mkdirSync(join(home, directory), { recursive: true });
  symlinkSync(join(home, 'code/b'), join(home, 'linked'));
  const at = (directory: string, args: string[], input = '') => cli(home, args, input, join(home, directory));

  const first = await at('code/a', ['login', a.origin, '--token'], 'coffre_svc_ci\n');
  assert.equal(first.status, 0, first.stderr);
  assert.match(first.stdout, new RegExp(`\nPinned ~/code/a to it: coffre uses ${a.origin} there and in every directory below\n$`));
  // A directory reached through a link is pinned by its real path.
  const second = await at('linked', ['login', b.origin, '--token'], 'coffre_svc_ci\n');
  assert.equal(second.status, 0, second.stderr);
  assert.match(second.stdout, /\nPinned ~\/code\/b to it/);
  const pinsFile = join(home, '.coffre', 'directories.json');
  assert.deepEqual(JSON.parse(readFileSync(pinsFile, 'utf8')), {
    version: 1,
    directories: { [join(home, 'code/a')]: a.origin, [join(home, 'code/b')]: b.origin },
  });
  assert.equal(statSync(pinsFile).mode & 0o777, 0o600);
  // Your home is no project: a login there sets the default only.
  const again = await at('.', ['login', b.origin, '--token'], 'coffre_svc_ci\n');
  assert.equal(again.status, 0, again.stderr);
  assert.doesNotMatch(again.stdout, /[Pp]inned/);
  assert.equal(Object.keys(JSON.parse(readFileSync(pinsFile, 'utf8')).directories).length, 2);

  const whoami = async (directory: string, flags: string[] = []) => {
    const run = await at(directory, [...flags, 'whoami']);
    assert.equal(run.status, 0, run.stderr);
    return run.stdout.split('\n')[0];
  };
  assert.equal(await whoami('code/a/nested'), `service:deploy (service account) on ${a.origin} (pinned at ~/code/a), via a bearer token, from coffre login --token`);
  assert.equal(await whoami('linked'), `service:deploy (service account) on ${b.origin} (pinned at ~/code/b), via a bearer token, from coffre login --token`);
  assert.equal(await whoami('.'), `service:deploy (service account) on ${b.origin} (the default), via a bearer token, from coffre login --token`);
  assert.equal(await whoami('code/a', ['--url', b.origin]), `service:deploy (service account) on ${b.origin}, via a bearer token, from coffre login --token`);
  const before = { a: a.seen.length, b: b.seen.length };
  const set = await at('code/a/nested', ['set', 'app/prod/KEY'], 'value');
  assert.equal(set.status, 0, set.stderr);
  assert.equal(a.seen.length, before.a + 1);
  assert.equal(b.seen.length, before.b);

  const use = await at('code/a', ['use']);
  assert.equal(use.status, 0, use.stderr);
  assert.equal(
    use.stdout,
    `* ${a.origin.padEnd(36)} ${'deploy'.padEnd(24)} pinned at ~/code/a\n` +
      `  ${b.origin.padEnd(36)} ${'deploy'.padEnd(24)} the default, pinned at ~/code/b\n`,
  );

  // Older CLIs read the sessions as before: the file keeps the shape they know.
  const credentials = readFileSync(join(home, '.coffre', 'credentials.json'), 'utf8');
  assert.deepEqual(Object.keys(JSON.parse(credentials)), ['version', 'current', 'instances']);
  assert.deepEqual(Object.keys(parseStore(credentials).instances).sort(), [a.origin, b.origin].sort());

  // A pin to an instance with no session says so, and sends nothing to the default.
  const gone = 'https://gone.example.com';
  const pins = JSON.parse(readFileSync(pinsFile, 'utf8'));
  writeFileSync(pinsFile, JSON.stringify({ ...pins, directories: { ...pins.directories, [join(home, 'code/gone')]: gone } }));
  const quiet = b.seen.length;
  const refused = await at('code/gone', ['whoami']);
  assert.equal(refused.status, 1);
  assert.equal(refused.stderr, `coffre: ${signInError(`not signed in: run \`coffre login ${gone}\``)}\n`);
  assert.equal(b.seen.length, quiet);
  const dropped = await at('code/gone', ['logout']);
  assert.equal(dropped.stdout, `Not signed in to ${gone}\n  Unpinned ~/code/gone\n`);

  // Signing out, from below a pinned directory, signs out of its instance and unpins it.
  const logout = await at('code/a/nested', ['logout']);
  assert.equal(logout.status, 0, logout.stderr);
  assert.equal(logout.stdout, `Signed out of ${a.origin}\n  Unpinned ~/code/a\n  The bearer token is forgotten here, and works elsewhere until it is revoked.\n`);
  assert.deepEqual(JSON.parse(readFileSync(pinsFile, 'utf8')).directories, { [join(home, 'code/b')]: b.origin });
  assert.equal(await whoami('code/a'), `service:deploy (service account) on ${b.origin} (the default), via a bearer token, from coffre login --token`);

  // A corrupt pins file stops every command that would read it, rather than send it to the default.
  writeFileSync(pinsFile, '{');
  const corrupt = await at('code/b', ['whoami']);
  assert.equal(corrupt.status, 1);
  assert.match(corrupt.stderr, /cannot read the pinned directories in .*directories\.json: it is not JSON\. Name the instance with --url/);
  assert.equal((await at('code/b', ['--url', b.origin, 'whoami'])).status, 0);
});

test("a person's login keeps the session the instance still knows, and only pins", async (t) => {
  const { origin, seen } = await ciInstance(t);
  const home = realpathSync(mkdtempSync(join(tmpdir(), 'coffre-pins-')));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  mkdirSync(join(home, 'code'));
  mkdirSync(join(home, '.coffre'), { mode: 0o700 });
  const ada = { mode: 'signin', token: 'coffre_cli_ada', principal: { type: 'user', id: 'ada@acme.example' }, expiresAt: '2099-01-01T00:00:00Z', obtainedAt: '2026-10-01T00:00:00Z' };
  writeFileSync(join(home, '.coffre', 'credentials.json'), JSON.stringify({ version: 2, current: null, instances: { [origin]: ada } }), { mode: 0o600 });
  const login = await cli(home, ['login', origin, '--no-browser'], '', join(home, 'code'));
  assert.equal(login.status, 0, login.stderr);
  assert.match(login.stdout, new RegExp(`^Signed in to ${origin} as deploy already, until 2099-01-01: \`coffre logout\` first for a new session\n`));
  assert.match(login.stdout, /\nPinned ~\/code to it/);
  assert.ok(!seen.some(({ url }) => url.startsWith('/api/auth')), 'a new sign-in was started');
  const store = JSON.parse(readFileSync(join(home, '.coffre', 'credentials.json'), 'utf8'));
  assert.equal(store.current, origin);
  assert.deepEqual(store.instances[origin], ada);
  const again = await cli(home, ['login', origin], '', join(home, 'code'));
  assert.match(again.stdout, /\n~\/code is pinned to it already\n$/);

  // One the instance no longer knows starts a sign-in.
  writeFileSync(join(home, '.coffre', 'credentials.json'), JSON.stringify({ version: 2, current: origin, instances: { [origin]: { ...ada, token: 'coffre_cli_gone' } } }), { mode: 0o600 });
  await cli(home, ['login', origin, '--no-browser'], '', join(home, 'code'));
  assert.ok(seen.some(({ url }) => url === '/api/auth'), 'no new sign-in was started');
});

/** A home with `code/a` pinned to `a`, `b` the default, and what each instance has been asked. */
async function pinnedHome(t: test.TestContext) {
  const a = await ciInstance(t);
  const b = await ciInstance(t);
  const home = realpathSync(mkdtempSync(join(tmpdir(), 'coffre-pins-')));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  for (const directory of ['code/a', 'elsewhere']) mkdirSync(join(home, directory), { recursive: true });
  const at = (directory: string, args: string[], input = '') => cli(home, args, input, join(home, directory));
  assert.equal((await at('code/a', ['login', a.origin, '--token'], 'coffre_svc_ci\n')).status, 0);
  assert.equal((await at('.', ['login', b.origin, '--token'], 'coffre_svc_ci\n')).status, 0);
  const asked = { a: a.seen.length, b: b.seen.length };
  return {
    b: b.origin,
    home,
    at,
    pinsFile: join(home, '.coffre', 'directories.json'),
    /** The requests sent since, to each. */
    since: () => ({ a: a.seen.length - asked.a, b: b.seen.length - asked.b }),
    refused: async (directory: string, error: RegExp) => {
      const run = await at(directory, ['whoami']);
      assert.equal(run.status, 1, run.stdout);
      assert.match(run.stderr, error);
    },
  };
}

test('pins are read from the file the CLI wrote, not through a link, dangling or not', async (t) => {
  const { b, home, at, pinsFile, since, refused } = await pinnedHome(t);
  const elsewhere = join(home, 'elsewhere', 'pins.json');
  writeFileSync(elsewhere, readFileSync(pinsFile));
  rmSync(pinsFile);
  symlinkSync(elsewhere, pinsFile);
  await refused('code/a', /cannot read the pinned directories in .*directories\.json: it is reached through a symbolic link\. Name the instance with --url/);
  rmSync(elsewhere);
  await refused('code/a', /it is reached through a symbolic link/);
  assert.deepEqual(since(), { a: 0, b: 0 });
  assert.equal((await at('code/a', ['--url', b, 'whoami'])).status, 0);
});

test('a pins file whose directories are a list, not a record, stops a command', async (t) => {
  const { pinsFile, since, refused } = await pinnedHome(t);
  writeFileSync(pinsFile, JSON.stringify({ version: 1, directories: [] }));
  await refused('code/a', /cannot read the pinned directories .*: this CLI does not know its shape/);
  assert.deepEqual(since(), { a: 0, b: 0 });
});

test('a command run in a directory removed since stops, unless --url names the instance', async (t) => {
  const { b, home, since } = await pinnedHome(t);
  mkdirSync(join(home, 'code/a/gone'));
  const gone = await cli(home, ['whoami'], '', join(home, 'code/a/gone'), true);
  assert.equal(gone.status, 1, gone.stdout);
  assert.match(gone.stderr, /^coffre: cannot tell which directory this is: .*\. Name the instance with --url\n$/);
  assert.deepEqual(since(), { a: 0, b: 0 });
  const named = await cli(home, ['--url', b, 'whoami'], '', join(home, 'elsewhere'), true);
  assert.equal(named.status, 0, named.stderr);
  assert.deepEqual(since(), { a: 0, b: 1 });
});

/** A home with a person's session saved, by `token`, for the instance. */
async function savedHome(t: test.TestContext, token: string) {
  const { origin, seen } = await ciInstance(t);
  const home = realpathSync(mkdtempSync(join(tmpdir(), 'coffre-pins-')));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  mkdirSync(join(home, 'code'));
  mkdirSync(join(home, '.coffre'), { mode: 0o700 });
  const credentials = join(home, '.coffre', 'credentials.json');
  const saved = JSON.stringify({ version: 2, current: origin, instances: { [origin]: { mode: 'signin', token, expiresAt: '2099-01-01T00:00:00Z', obtainedAt: '2026-10-01T00:00:00Z' } } });
  writeFileSync(credentials, saved, { mode: 0o600 });
  return { origin, seen, home, credentials, saved };
}

test("a person's login replaces the saved session only when the instance says it does not know it", async (t) => {
  // The instance answers GET /api/me for this one with a 500.
  const { origin, seen, home, credentials, saved } = await savedHome(t, 'coffre_cli_busy');
  const busy = await cli(home, ['login', origin, '--no-browser'], '', join(home, 'code'));
  assert.equal(busy.status, 1, busy.stdout);
  assert.equal(busy.stderr, `coffre: could not check the session saved for ${origin}, which is kept: something went wrong. Retry, or \`coffre logout ${origin}\` first for a new one\n`);
  assert.equal(readFileSync(credentials, 'utf8'), saved);
  assert.ok(!seen.some(({ url }) => url.startsWith('/api/auth')), 'a new sign-in was started');
  assert.ok(!existsSync(join(home, '.coffre', 'directories.json')));
});

test('login refuses an --auth-mode it does not know before asking the instance anything', async (t) => {
  const { origin, seen, home } = await savedHome(t, 'coffre_cli_ada');
  const typo = await cli(home, ['--auth-mode', 'signon', 'login', origin, '--no-browser'], '', join(home, 'code'));
  assert.equal(typo.status, 1, typo.stdout);
  assert.equal(typo.stderr, 'coffre: --auth-mode must be one of signin, cloudflare, not "signon"\n');
  assert.equal(seen.length, 0);
  assert.ok(!existsSync(join(home, '.coffre', 'directories.json')));
});

test("a repository's coffre.json names its instance for a fresh clone, which signs in there, and a pin still comes first", async (t) => {
  const a = await ciInstance(t);
  const b = await ciInstance(t);
  const home = realpathSync(mkdtempSync(join(tmpdir(), 'coffre-repo-')));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  for (const directory of ['code/acme/src', 'code/bad', 'code/linked', 'code/other']) mkdirSync(join(home, directory), { recursive: true });
  writeFileSync(join(home, 'code/acme/coffre.json'), `${JSON.stringify({ url: a.origin }, null, 2)}\n`);
  symlinkSync(join(home, 'code/acme/src'), join(home, 'through'));
  const at = (directory: string, args: string[], input = '', env: Record<string, string> = {}) => cli(home, args, input, join(home, directory), false, env);
  const first = async (directory: string, args: string[]) => {
    const run = await at(directory, args);
    assert.equal(run.status, 0, run.stderr);
    return run.stdout.split('\n')[0];
  };

  // Not signed in yet: the error says where the URL came from, and nothing is sent.
  const fresh = await at('code/acme/src', ['whoami']);
  assert.equal(fresh.status, 1);
  assert.equal(fresh.stderr, `coffre: ${signInError(`not signed in: run \`coffre login ${a.origin}\` (named by ${join(home, 'code/acme/coffre.json')})`)}\n`);
  assert.equal(a.seen.length, 0);
  assert.equal((await at('code/acme', ['use'])).stdout, `* ${a.origin.padEnd(36)} ${'not signed in'.padEnd(24)} named by ~/code/acme/coffre.json\n`);

  // A secret goes only where you name it, not where a clone says.
  for (const [args, input] of [[['--token'], 'coffre_svc_ci\n'], [['--access-client-id', 'id.access'], 'shh\n'], [['--service', 'deploy', '--id-token'], 'id.token.ok\n']] as const) {
    const handed = await at('code/acme/src', ['login', ...args], input);
    assert.equal(handed.status, 1);
    assert.match(handed.stderr, new RegExp(`^coffre: ~/code/acme/coffre\\.json names ${a.origin}, and a secret goes only where you name it: \`coffre login ${a.origin} ${args[0]}`));
  }
  assert.equal(a.seen.length, 0);

  // A login with no URL signs in where the file says, says so first, and pins nothing.
  const login = await at('code/acme/src', ['login', '--no-browser']);
  assert.equal(login.status, 0, login.stderr);
  assert.match(login.stderr, new RegExp(`^Signing in to ${a.origin}, which ~/code/acme/coffre\\.json names\n`));
  assert.match(login.stdout, /\n~\/code\/acme\/coffre\.json names it already\n$/);
  assert.equal(existsSync(join(home, '.coffre', 'directories.json')), false);
  assert.equal(JSON.parse(readFileSync(join(home, '.coffre', 'credentials.json'), 'utf8')).instances[a.origin].token, 'coffre_cli_ada');
  assert.equal(await first('code/acme/src', ['whoami']), `service:deploy (service account) on ${a.origin} (named by ~/code/acme/coffre.json), via coffre sign-in`);
  // By its real path, through a link.
  assert.equal(await first('through', ['whoami']), `service:deploy (service account) on ${a.origin} (named by ~/code/acme/coffre.json), via coffre sign-in`);

  // A CI run's ID token, asked for that origin, needs no --url either.
  const runner = { ACTIONS_ID_TOKEN_REQUEST_URL: `${a.origin}/runner`, ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'bearer' };
  const ci = await at('code/acme', ['--service', 'deploy', 'whoami'], '', runner);
  assert.equal(ci.status, 0, ci.stderr);
  assert.match(ci.stdout, new RegExp(`^service:deploy \\(service account\\) on ${a.origin} \\(named by ~/code/acme/coffre\\.json\\), via the run's ID token, as --service\n`));

  // Your own pin comes first, in the same directory; signing out of it hands the directory back to the file.
  assert.equal((await at('.', ['login', b.origin, '--token'], 'coffre_svc_ci\n')).status, 0);
  const pin = await at('code/acme', ['login', b.origin, '--token'], 'coffre_svc_ci\n');
  assert.equal(pin.status, 0, pin.stderr);
  assert.match(pin.stdout, /\nPinned ~\/code\/acme to it/);
  assert.equal(await first('code/acme/src', ['whoami']), `service:deploy (service account) on ${b.origin} (pinned at ~/code/acme), via a bearer token, from coffre login --token`);
  assert.equal(await first('code/acme', ['--url', a.origin, 'whoami']), `service:deploy (service account) on ${a.origin}, via coffre sign-in`);
  assert.match((await at('code/acme', ['logout', b.origin])).stdout, /\n {2}Unpinned ~\/code\/acme\n/);
  assert.equal(await first('code/acme/src', ['whoami']), `service:deploy (service account) on ${a.origin} (named by ~/code/acme/coffre.json), via coffre sign-in`);

  // Switching the default says when the file here names another instance.
  assert.equal((await at('.', ['login', b.origin, '--token'], 'coffre_svc_ci\n')).status, 0);
  assert.equal((await at('code/acme', ['use', a.origin])).stdout, `Now using ${a.origin} by default\n`);
  assert.equal(
    (await at('code/acme', ['use', b.origin])).stdout,
    `Now using ${b.origin} by default\n  but not here: ~/code/acme/coffre.json names ${a.origin}, and \`coffre login ${b.origin}\` pins this directory to it\n`,
  );

  // A file that cannot be used stops every command below it, but --url, rather than send one elsewhere.
  for (const [contents, why] of [
    [JSON.stringify({ url: a.origin, token: 'coffre_cli_ada' }), 'it holds only "url", never a credential or anything else: not "token"'],
    [JSON.stringify({ url: `${a.origin}/` }), `"url" is an origin, written as one: "${a.origin}", not "${a.origin}/"`],
    ['{', 'it is not JSON'],
  ]) {
    writeFileSync(join(home, 'code/bad/coffre.json'), contents);
    const bad = await at('code/bad', ['whoami']);
    assert.equal(bad.status, 1);
    assert.equal(bad.stderr, `coffre: cannot use ${join(home, 'code/bad/coffre.json')}: ${why}\n`);
  }
  assert.equal((await at('code/bad', ['--url', b.origin, 'whoami'])).status, 0);
  // A linked one too: a coffre.json is the repository's own file.
  symlinkSync(join(home, 'code/acme/coffre.json'), join(home, 'code/linked/coffre.json'));
  const linked = await at('code/linked', ['whoami']);
  assert.equal(linked.status, 1);
  assert.equal(linked.stderr, `coffre: cannot use ${join(home, 'code/linked/coffre.json')}: it is a symbolic link, and a coffre.json is a file of the repository's own\n`);
  // Your home is no repository: a coffre.json there names nothing.
  writeFileSync(join(home, 'coffre.json'), JSON.stringify({ url: a.origin }));
  assert.equal(await first('code/other', ['whoami']), `service:deploy (service account) on ${b.origin} (the default), via a bearer token, from coffre login --token`);
});
