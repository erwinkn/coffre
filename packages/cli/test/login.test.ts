import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { execFile, spawn } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, mkdirSync, writeFileSync, statSync, rmSync, readFileSync, symlinkSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

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
        : { principal: { type: 'user', id: 'admin@acme.example' }, registered: true, environments: [] };
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
      req.headers.authorization === 'Bearer coffre_svc_run' ||
      (req.headers['cf-access-client-id'] === 'id.access' && req.headers['cf-access-client-secret'] === 'shh');
    if (req.url === '/api/me' && known) return send(200, { principal: { type: 'service', id: 'deploy' }, registered: true, environments: [] });
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

/** The CLI, `input` on its stdin: not spawnSync, which would stop the server in this process from answering it. */
async function cli(home: string, args: string[], input: string): Promise<{ status: number | null; stdout: string; stderr: string }> {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('COFFRE_')));
  const child = spawn(process.execPath, ['--conditions=coffre:source', main, ...args], { env: { ...env, HOME: home }, stdio: ['pipe', 'pipe', 'pipe'] });
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
    assert.match(whoami.stdout, /^deploy \(service\) on .*, via (a service token|an Access service token|the run's ID token)/);
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
