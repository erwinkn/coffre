// `coffre serve` and `coffre --service <name> run`, key-bound, against the
// fake coffre (workload-fake.ts), which checks every proof as the server
// does: what the app sends the local listener reaches coffre signed and as
// sent, a tunnel's upgrade is signed, and the session ends with the process.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { request } from 'node:http';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import pg from 'pg';

import { fakeCoffre, fakePostgres } from './workload-fake.ts';

const MAIN = new URL('../src/main.ts', import.meta.url).pathname;
const CODE = `coffre_enr_${'k'.repeat(43)}`;

function cli(t: test.TestContext, args: string[], stdin = CODE): { child: ChildProcess; stderr: () => string; stdout: () => string } {
  const home = mkdtempSync(join(tmpdir(), 'coffre-serve-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const env = { ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('COFFRE_') && !key.startsWith('ACTIONS_'))), COFFRE_STATE_DIR: home, HOME: home };
  // From the package, whose dependencies a run's command imports.
  const child = spawn(process.execPath, ['--conditions=coffre:source', MAIN, ...args], { env, cwd: new URL('..', import.meta.url).pathname, stdio: ['pipe', 'pipe', 'pipe'] });
  t.after(() => child.kill('SIGKILL'));
  child.stdin!.end(stdin);
  let [stdout, stderr] = ['', ''];
  child.stdout!.setEncoding('utf8').on('data', (data: string) => (stdout += data));
  child.stderr!.setEncoding('utf8').on('data', (data: string) => (stderr += data));
  return { child, stderr: () => stderr, stdout: () => stdout };
}

/** Waits until the process has said `pattern` on stderr, and gives the match. */
async function said(run: ReturnType<typeof cli>, pattern: RegExp): Promise<RegExpMatchArray> {
  for (let i = 0; i < 200; i++) {
    const match = pattern.exec(run.stderr());
    if (match !== null) return match;
    if (run.child.exitCode !== null) break;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert.fail(`never said ${pattern}: ${run.stderr()}`);
}

test("coffre serve forwards the app's requests signed, as sent, carries a tunnel, and logs out on SIGTERM", async (t) => {
  const database = await fakePostgres();
  t.after(() => database.close());
  const coffre = await fakeCoffre({ database });
  t.after(() => coffre.close());
  const run = cli(t, ['serve', '--url', coffre.url, '--service', 'api-prod', '--proof', 'enrollment', '--listen', '127.0.0.1:0', '--tunnel', 'db=127.0.0.1:0']);
  const [, listener] = await said(run, /(http:\/\/127\.0\.0\.1:\d+)\/use\/<credential>/);
  const [, databaseUrl] = await said(run, /db on (postgres:\/\/\S+)/);

  const response = await fetch(`${listener}/use/openai/chat/completions?stream=false`, {
    method: 'POST',
    headers: { authorization: 'Bearer coffre', 'content-type': 'application/json', 'openai-organization': 'org-1' },
    body: JSON.stringify({ model: 'gpt-x' }),
  });
  assert.equal(response.status, 200);
  const sent = coffre.forwarded.at(-1)!;
  assert.equal(sent.path, '/use/openai/chat/completions');
  assert.equal(sent.query, 'stream=false');
  assert.equal(sent.body, '{"model":"gpt-x"}');
  // What the app set, and what Node's fetch added for it: never the app's stand-in key, nor the transport's.
  assert.equal(sent.headers['content-type'], 'application/json');
  assert.equal(sent.headers['openai-organization'], 'org-1');
  assert.equal(sent.headers.authorization, undefined);
  assert.equal(sent.headers.host, undefined);
  assert.equal((await fetch(`${listener}/api/me`)).status, 404);

  // No password: the sidecar's boundary is the pod.
  assert.match(databaseUrl!, /^postgres:\/\/app@127\.0\.0\.1:\d+\/app\?sslmode=disable$/);
  const client = new pg.Client({ connectionString: databaseUrl });
  await client.connect();
  assert.deepEqual((await client.query('select three')).rows, [{ value: 'select three' }]);
  await client.end();

  run.child.kill('SIGTERM');
  const [code] = await once(run.child, 'exit');
  assert.equal(code, 0, run.stderr());
  assert.equal(coffre.log.at(-1), 'POST /api/auth/logout 200');
  assert.ok(coffre.log.includes('GET /use/db upgrade'), coffre.log.join('\n'));
});

test('coffre serve on a Unix socket: only its owner may connect', async (t) => {
  const coffre = await fakeCoffre();
  t.after(() => coffre.close());
  const dir = mkdtempSync(join(tmpdir(), 'coffre-sock-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const socketPath = join(dir, 'api.sock');
  const run = cli(t, ['--url', coffre.url, 'serve', '--service', 'api-prod', '--proof', 'enrollment', '--listen', `unix:${socketPath}`]);
  await said(run, /unix:.*\/use\/<credential>/);
  assert.equal(statSync(socketPath).mode & 0o777, 0o600);
  const status = await new Promise<number>((resolve, reject) => {
    request({ socketPath, path: '/use/openai/models', headers: { accept: 'application/json' } }, (res) => (res.resume(), resolve(res.statusCode!))).on('error', reject).end();
  });
  assert.equal(status, 200);
  assert.deepEqual(coffre.forwarded.at(-1)!.headers, { accept: 'application/json' });
});

test('coffre serve refuses a proof it does not know, and an address it cannot read', async (t) => {
  const bad = cli(t, ['serve', '--url', 'http://127.0.0.1:1', '--service', 'api-prod', '--proof', 'carrier-pigeon']);
  await once(bad.child, 'exit');
  assert.match(bad.stderr(), /--proof carrier-pigeon: a proof is one of kubernetes/);
  const where = cli(t, ['serve', '--url', 'http://127.0.0.1:1', '--service', 'api-prod', '--proof', 'aws', '--listen', 'nowhere']);
  await once(where.child, 'exit');
  assert.match(where.stderr(), /--listen nowhere: an address is <host>:<port>/);
});

test("a service's run, key-bound: the values it may read, its credentials and databases through local listeners, and what it no longer holds, said", async (t) => {
  const database = await fakePostgres();
  t.after(() => database.close());
  let url = '';
  const coffre = await fakeCoffre({
    database,
    get plan() {
      return {
        environment: 'market/prod',
        values: { TWILIO_SID: 'AC012' },
        credentials: ['openai'],
        tunnels: { db: { key: 'DATABASE_URL', url: `${url.replace(/^http/, 'ws')}/use/market/prod/db` } },
        left: ['STRIPE_SECRET_KEY'],
      };
    },
  });
  url = coffre.url;
  t.after(() => coffre.close());
  const app = `
    const { credential } = await import('@coffre/client/credential');
    const pg = (await import('pg')).default;
    const models = await credential('openai').fetch('/models', { headers: { accept: 'application/json' } });
    const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
    await client.connect();
    const { rows } = await client.query('select four');
    await client.end();
    console.log(JSON.stringify({ sid: process.env.TWILIO_SID, credentials: JSON.parse(process.env.COFFRE_CREDENTIALS), models: models.status, rows }));
  `;
  const run = cli(t, ['--url', coffre.url, '--service', 'api-prod', 'run', '--proof', 'enrollment', '--', process.execPath, '--conditions=coffre:source', '--input-type=module', '-e', app]);
  const [code] = await once(run.child, 'exit');
  assert.equal(code, 0, run.stderr());
  const printed = JSON.parse(run.stdout()) as { sid: string; credentials: Record<string, string>; models: number; rows: unknown };
  assert.equal(printed.sid, 'AC012');
  assert.match(printed.credentials.openai!, /^http:\/\/127\.0\.0\.1:\d+\/use\/market\/prod\/openai$/);
  assert.equal(printed.models, 200);
  assert.deepEqual(printed.rows, [{ value: 'select four' }]);
  assert.match(run.stderr(), /market\/prod: STRIPE_SECRET_KEY is used through coffre now; list it in the binding's reads if this job must hold it/);
  // What the app's fetch sent, signed; the handle header `credential()` sends empty is coffre's own, and goes nowhere.
  const sent = coffre.forwarded.find((each) => each.path === '/use/market/prod/openai/models')!;
  assert.equal(sent.headers.accept, 'application/json');
  assert.ok(!('x-coffre-handle' in sent.headers) && !('authorization' in sent.headers), JSON.stringify(sent.headers));
  assert.deepEqual(coffre.log, [
    'POST /api/auth/workload 200',
    'GET /use/market/prod 200',
    'GET /use/market/prod/openai/models 200',
    'GET /use/market/prod/db upgrade',
    'POST /api/auth/logout 200',
  ]);
});

test("a service's run falls back to the bearer exchange where the instance has no key-bound sessions yet", async (t) => {
  const coffre = await fakeCoffre({ exchange: () => ({ status: 501, body: { error: 'not_implemented' } }) });
  t.after(() => coffre.close());
  const run = cli(t, ['--url', coffre.url, '--service', 'api-prod', 'run', '--proof', 'enrollment', 'market/prod', '--', process.execPath, '-e', '']);
  const [code] = await once(run.child, 'exit');
  // The bearer path's exchange trades the run's ID token, which a job outside GitHub Actions lacks.
  assert.equal(code, 1);
  assert.deepEqual(coffre.log, ['POST /api/auth/workload 501']);
  assert.match(run.stderr(), /--service signs in with the run's ID token, and there is none/);
});
