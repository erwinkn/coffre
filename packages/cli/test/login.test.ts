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
import { parseStore } from '../src/instance.ts';

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
      await login;
      assert.equal(JSON.parse(readFileSync(file, 'utf8')).instances[`http://127.0.0.1:${address.port}`].token, token);
      assert.equal(statSync(file).mode & 0o777, 0o600);
      assert.equal(statSync(directory).mode & 0o777, 0o700);
    }
  });
}

/** A coffre that knows one credential of each kind a CI run signs in with, and keeps every request. */
async function ciInstance(t: test.TestContext) {
  const seen: { method: string; url: string; headers: Record<string, string | string[] | undefined>; body: string }[] = [];
  const server = createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += String(chunk);
    seen.push({ method: req.method!, url: req.url!, headers: req.headers, body });
    const send = (status: number, value: unknown) => res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(value));
    if (req.url === '/api/auth/oidc') {
      const { token } = JSON.parse(body) as { token: string };
      return token === 'id.token.ok' ? send(200, { token: 'coffre_svc_run', expiresAt: '2099-01-01T00:05:00.000Z' }) : send(401, { error: 'unauthenticated', reason: 'no_match', message: 'no' });
    }
    const known =
      req.headers.authorization === 'Bearer coffre_svc_ci' ||
      req.headers.authorization === 'Bearer coffre_cli_ada' ||
      req.headers.authorization === 'Bearer coffre_svc_run' ||
      (req.headers['cf-access-client-id'] === 'id.access' && req.headers['cf-access-client-secret'] === 'shh');
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
  return { origin: `http://127.0.0.1:${address.port}`, seen };
}

/**
 * The CLI, `input` on its stdin: not spawnSync, which would stop the server in this process from answering it.
 * `gone`, it runs in `cwd` removed once it started, as another shell might.
 */
async function cli(home: string, args: string[], input: string, cwd?: string, gone = false): Promise<{ status: number | null; stdout: string; stderr: string }> {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('COFFRE_')));
  const removed = `import { rmSync } from 'node:fs'; process.cwd(); rmSync(process.cwd(), { recursive: true }); process.argv.splice(1, 0, ${JSON.stringify(main)}); await import(${JSON.stringify(pathToFileURL(main).href)});`;
  const node = gone ? ['--conditions=coffre:source', '--input-type=module', '-e', removed, '--'] : ['--conditions=coffre:source', main];
  const child = spawn(process.execPath, [...node, ...args], { cwd, env: { ...env, HOME: home }, stdio: ['pipe', 'pipe', 'pipe'] });
  let [stdout, stderr] = ['', ''];
  child.stdout.setEncoding('utf8').on('data', (chunk: string) => (stdout += chunk));
  child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
  child.stdin.on('error', () => {});
  child.stdin.end(input);
  const [status] = (await once(child, 'close')) as [number | null];
  return { status, stdout, stderr };
}

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
  assert.equal(refused.stderr, `coffre: not signed in to ${gone}: run \`coffre login ${gone}\`\n`);
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
