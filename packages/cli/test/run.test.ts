import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { clash, environmentPaths } from '../src/environments.ts';
import { signedInWithToken } from './fakes.ts';

const TOKEN = `coffre_cli_${'s'.repeat(43)}`;

test('environments are named as <project>/<environment>, each once', () => {
  assert.deepEqual(environmentPaths(['deploy/prod', 'auth/prod']), ['deploy/prod', 'auth/prod']);
  assert.throws(() => environmentPaths([]), /name an environment/);
  assert.throws(() => environmentPaths(['deploy/prod/KEY']), /expected <project>\/<environment>, not "deploy\/prod\/KEY"/);
  assert.throws(() => environmentPaths(['deploy/prod', 'deploy/prod']), /deploy\/prod is named twice/);
});

test('a clash names each key and both environments that define it, by the pair', () => {
  assert.equal(clash([['deploy/prod', ['A', 'B']], ['auth/prod', ['C']]]), null);
  assert.equal(
    clash([['deploy/prod', ['A', 'TOKEN', 'URL']], ['auth/prod', ['URL', 'TOKEN']], ['www/prod', ['A']]]),
    'deploy/prod and auth/prod both define TOKEN and URL; deploy/prod and www/prod both define A',
  );
});

type Listed = { key: string; version: number | null; archived?: boolean; reference?: { state: string } };
type Environment = { values: Record<string, string>; listed?: Listed[]; refused?: number };

/** A coffre holding these environments, which keeps every request it is sent. */
async function instance(t: test.TestContext, environments: Record<string, Environment>) {
  const home = mkdtempSync(join(tmpdir(), 'coffre-run-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const requests: string[] = [];
  const server = createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += String(chunk);
    assert.equal(req.headers.authorization, `Bearer ${TOKEN}`);
    const send = (status: number, value: unknown) => res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(value));
    const listing = /^\/api\/secrets\/([^/]+)\/([^/]+)$/.exec(req.url ?? '');
    const path = listing === null ? (JSON.parse(body || '{}') as { path?: string }).path : `${listing[1]}/${listing[2]}`;
    requests.push(`${listing === null ? 'reveal' : 'list'} ${path}`);
    const environment = path === undefined ? undefined : environments[path];
    if (environment === undefined) return send(404, { error: 'not_found', message: 'unknown project or environment' });
    if (environment.refused !== undefined) return send(environment.refused, { error: 'forbidden', message: 'you do not have permission to do that' });
    if (listing !== null) {
      const keys = environment.listed ?? Object.keys(environment.values).map((key) => ({ key, version: 1 }));
      return send(200, { permissions: ['secret.read'], keys: keys.map((key) => ({ archived: false, reference: null, folder: null, updatedAt: null, updatedBy: null, ...key })) });
    }
    send(200, { operationId: 'op', values: environment.values });
  });
  t.after(() => new Promise<void>((resolve) => (server.close(() => resolve()), server.closeAllConnections())));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  signedInWithToken(home, `http://127.0.0.1:${address.port}`, TOKEN);

  return {
    requests,
    async coffre(args: string[]) {
      const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('COFFRE_') && key !== 'GITHUB_ENV'));
      Object.assign(env, { COFFRE_STATE_DIR: home, HOME: home });
      const child = spawn(process.execPath, ['--conditions=coffre:source', new URL('../src/main.ts', import.meta.url).pathname, ...args], { env, stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000 });
      let stdout = '';
      let stderr = '';
      child.stdout.setEncoding('utf8').on('data', (data: string) => (stdout += data));
      child.stderr.setEncoding('utf8').on('data', (data: string) => (stderr += data));
      const [code] = await once(child, 'close');
      return { code, stdout, stderr };
    },
  };
}

/** A command that prints the variables named, as run hands them to it. */
const printing = (...keys: string[]) => [process.execPath, '-e', `process.stdout.write(JSON.stringify(Object.fromEntries(${JSON.stringify(keys)}.map((k) => [k, process.env[k] ?? null]))))`];

test('run of several environments injects their union, each read once, after each is listed', async (t) => {
  const coffre = await instance(t, {
    'deploy/prod': { values: { CLOUDFLARE_API_TOKEN: 'cf-secret', DATABASE_URL: 'postgres://x' } },
    'auth/prod': { values: { GITHUB_CLIENT_SECRET: 'gh-secret' } },
  });
  const run = await coffre.coffre(['run', 'deploy/prod', 'auth/prod', '--', ...printing('CLOUDFLARE_API_TOKEN', 'DATABASE_URL', 'GITHUB_CLIENT_SECRET')]);
  assert.equal(run.code, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout), { CLOUDFLARE_API_TOKEN: 'cf-secret', DATABASE_URL: 'postgres://x', GITHUB_CLIENT_SECRET: 'gh-secret' });
  assert.deepEqual(coffre.requests, ['list deploy/prod', 'list auth/prod', 'reveal deploy/prod', 'reveal auth/prod']);
});

test('run of one environment reads it as it always did, without listing it first', async (t) => {
  const coffre = await instance(t, { 'deploy/prod': { values: { TOKEN: 'one' } } });
  const run = await coffre.coffre(['run', 'deploy/prod', '--', ...printing('TOKEN')]);
  assert.equal(run.code, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout), { TOKEN: 'one' });
  assert.deepEqual(coffre.requests, ['reveal deploy/prod']);
});

test('a key two environments define stops run before any value is read, naming it and both, not its values', async (t) => {
  const coffre = await instance(t, {
    'deploy/prod': { values: { API_URL: 'deploy-url-value', TOKEN: 'deploy-token-value', ONLY_HERE: 'x' } },
    'auth/prod': { values: { API_URL: 'auth-url-value', TOKEN: 'auth-token-value' } },
  });
  const run = await coffre.coffre(['run', 'deploy/prod', 'auth/prod', '--', ...printing('API_URL')]);
  assert.equal(run.code, 1);
  assert.equal(run.stdout, '', 'the command ran');
  assert.equal(run.stderr, 'coffre: deploy/prod and auth/prod both define API_URL and TOKEN: a key comes from one environment only. Nothing was read\n');
  assert.deepEqual(coffre.requests, ['list deploy/prod', 'list auth/prod']);
});

test('archived keys and keys without a value clash with nothing, as run reads neither', async (t) => {
  const coffre = await instance(t, {
    'deploy/prod': { values: { TOKEN: 'deploy' }, listed: [{ key: 'TOKEN', version: 1 }, { key: 'OLD', version: 3, archived: true }, { key: 'EMPTY', version: null }] },
    'auth/prod': { values: { OLD: 'auth', EMPTY: 'auth' } },
  });
  const run = await coffre.coffre(['run', 'deploy/prod', 'auth/prod', '--', ...printing('TOKEN', 'OLD', 'EMPTY')]);
  assert.equal(run.code, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout), { TOKEN: 'deploy', OLD: 'auth', EMPTY: 'auth' });
});

test('an environment refused, unknown or holding a reference that cannot be read stops run before any value is read', async (t) => {
  const cases: [Record<string, Environment>, string][] = [
    [{ 'auth/prod': { values: {}, refused: 403 } }, 'coffre: auth/prod: you do not have permission to do that. Nothing was read\n'],
    [{}, 'coffre: auth/prod: unknown project or environment. Nothing was read\n'],
    [
      { 'auth/prod': { values: {}, listed: [{ key: 'SHARED', version: null, reference: { state: 'source_archived' } }] } },
      'coffre: auth/prod/SHARED is a reference that cannot be read (source archived): `coffre references auth/prod` says more. Nothing was read\n',
    ],
  ];
  for (const [auth, said] of cases) {
    const coffre = await instance(t, { 'deploy/prod': { values: { TOKEN: 'deploy-token-value' } }, ...auth });
    const run = await coffre.coffre(['run', 'deploy/prod', 'auth/prod', '--', ...printing('TOKEN')]);
    assert.equal(run.code, 1);
    assert.equal(run.stdout, '', 'the command ran');
    assert.equal(run.stderr, said);
    assert.deepEqual(coffre.requests, ['list deploy/prod', 'list auth/prod'], 'a value was read');
  }
});

test('a key that came to clash between listing and reading still stops run, its values unused', async (t) => {
  const coffre = await instance(t, {
    'deploy/prod': { values: { TOKEN: 'deploy-token-value' } },
    'auth/prod': { values: { TOKEN: 'auth-token-value' }, listed: [] },
  });
  const run = await coffre.coffre(['run', 'deploy/prod', 'auth/prod', '--', ...printing('TOKEN')]);
  assert.equal(run.code, 1);
  assert.equal(run.stdout, '', 'the command ran');
  assert.equal(run.stderr, 'coffre: deploy/prod and auth/prod both define TOKEN, as read just now. No value was used, and the reads are in the audit log\n');
});

test('run and export refuse an environment named twice, or a secret in place of one, before any request', async (t) => {
  const coffre = await instance(t, {});
  for (const args of [['run', 'deploy/prod', 'deploy/prod', '--', 'true'], ['export', 'deploy/prod/TOKEN']]) {
    const run = await coffre.coffre(args);
    assert.equal(run.code, 2);
    assert.match(run.stderr, /^coffre: (deploy\/prod is named twice|expected <project>\/<environment>, not "deploy\/prod\/TOKEN")\n/);
  }
  assert.deepEqual(coffre.requests, []);
});

test('export of several environments prints their union, and refuses a clash as run does', async (t) => {
  const coffre = await instance(t, {
    'deploy/prod': { values: { B: 'deploy', A: 'deploy' } },
    'auth/prod': { values: { C: 'auth' } },
    'www/prod': { values: { A: 'www-value' } },
  });
  const union = await coffre.coffre(['export', 'deploy/prod', 'auth/prod', '--format', 'json']);
  assert.equal(union.code, 0, union.stderr);
  assert.equal(union.stdout, `${JSON.stringify({ A: 'deploy', B: 'deploy', C: 'auth' }, null, 2)}\n`);
  const clashing = await coffre.coffre(['export', '--format', 'dotenv', 'deploy/prod', 'www/prod']);
  assert.equal(clashing.code, 1);
  assert.equal(clashing.stdout, '');
  assert.equal(clashing.stderr, 'coffre: deploy/prod and www/prod both define A: a key comes from one environment only. Nothing was read\n');
});
