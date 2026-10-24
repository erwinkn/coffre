// `coffre serve` and `coffre --service <name> run`, key-bound, against the
// fake coffre (workload-fake.ts), which checks every proof as the server
// does: what the app sends the local listener reaches coffre signed and as
// sent, a tunnel's upgrade is signed, and the session ends with the process.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { request } from 'node:http';
import { connect as connectTcp } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
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
  assert.ok(coffre.log.includes('GET /use/market/prod/db upgrade'), coffre.log.join('\n'));
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

test('coffre serve sends no proof to an instance outside TLS, and survives a request with no URL; --place picks the environment of its tunnels', async (t) => {
  const plain = cli(t, ['serve', '--url', 'http://192.0.2.1:7300', '--service', 'api-prod', '--proof', 'enrollment']);
  const [code] = await once(plain.child, 'exit');
  assert.equal(code, 1);
  assert.match(plain.stderr(), /not a coffre address|https/);

  const database = await fakePostgres();
  t.after(() => database.close());
  const coffre = await fakeCoffre({ database, places: ['market/prod', 'market/staging'] });
  t.after(() => coffre.close());
  const run = cli(t, ['serve', '--url', coffre.url, '--service', 'api-prod', '--proof', 'enrollment', '--place', 'market/staging', '--listen', '127.0.0.1:0', '--tunnel', 'db=127.0.0.1:0']);
  const [, listener] = await said(run, /(http:\/\/127\.0\.0\.1:\d+)\/use\/<credential>/);
  const [, databaseUrl] = await said(run, /db on (postgres:\/\/\S+)/);
  // A request target no URL parser takes: answered 400, and the sidecar goes on.
  const raw = connectTcp(Number(new URL(listener!).port), '127.0.0.1');
  raw.end('GET http://[ HTTP/1.1\r\nhost: x\r\n\r\n');
  let answer = '';
  for await (const chunk of raw) answer += String(chunk);
  assert.match(answer, /^HTTP\/1\.1 400/);
  assert.equal((await fetch(`${listener}/use/market/staging/openai/models`)).status, 200);
  const client = new pg.Client({ connectionString: databaseUrl });
  await client.connect();
  assert.deepEqual((await client.query('select five')).rows, [{ value: 'select five' }]);
  await client.end();
  assert.ok(coffre.log.includes('GET /use/market/staging/db upgrade'), coffre.log.join('\n'));
});

test("a service's run refuses a plan whose tunnels name no key for their URL", async (t) => {
  const coffre = await fakeCoffre({ plan: { environment: 'market/prod', values: {}, credentials: [], tunnels: ['db'] } });
  t.after(() => coffre.close());
  const run = cli(t, ['--url', coffre.url, '--service', 'api-prod', 'run', '--proof', 'enrollment', '--', process.execPath, '-e', '']);
  const [code] = await once(run.child, 'exit');
  assert.equal(code, 1);
  assert.match(run.stderr(), /names its tunnels without the key each URL goes in/);
  assert.equal(coffre.log.at(-1), 'POST /api/auth/logout 200');
});

test('through the sidecar: a redirect within coffre comes back to it, a SigV4 upload streams past the buffered limit, and a refused upgrade gives the next one its nonce', async (t) => {
  const database = await fakePostgres();
  t.after(() => database.close());
  let url = '';
  const coffre = await fakeCoffre({
    database,
    sigv4: ['s3'],
    upstream: (sent) =>
      sent.path === '/use/openai/start' ? { status: 302, headers: { location: `${url}/use/openai/next?x=1` } } : { status: 200, body: { path: sent.path, size: sent.body.length } },
  });
  url = coffre.url;
  t.after(() => coffre.close());
  const run = cli(t, ['serve', '--url', coffre.url, '--service', 'api-prod', '--proof', 'enrollment', '--listen', '127.0.0.1:0', '--tunnel', 'db=127.0.0.1:0']);
  const [, listener] = await said(run, /(http:\/\/127\.0\.0\.1:\d+)\/use\/<credential>/);
  const [, databaseUrl] = await said(run, /db on (postgres:\/\/\S+)/);

  const followed = await fetch(`${listener}/use/openai/start`);
  assert.deepEqual(await followed.json(), { path: '/use/openai/next', size: 0 });

  const size = 17 * 1024 * 1024;
  const upload = await fetch(`${listener}/use/s3/bucket/big`, { method: 'PUT', headers: { 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' }, body: new Uint8Array(size) });
  assert.deepEqual(await upload.json(), { path: '/use/s3/bucket/big', size });
  // With the length it says, which coffre streams it by: without one, coffre would read it whole, and refuse it past 16 MiB.
  assert.equal(coffre.forwarded.at(-1)!.length, String(size));

  // The gate restarts: the next upgrade is refused for its nonce, and the one after it signs with the nonce that refusal gave.
  coffre.gate.restart();
  await assert.rejects(new pg.Client({ connectionString: databaseUrl }).connect());
  const client = new pg.Client({ connectionString: databaseUrl });
  await client.connect();
  assert.deepEqual((await client.query('select six')).rows, [{ value: 'select six' }]);
  await client.end();
  assert.deepEqual(coffre.log.filter((line) => line.startsWith('GET /use/market/prod/db')), ['GET /use/market/prod/db use_dpop_nonce', 'GET /use/market/prod/db upgrade']);
});

/** The most the process has held in memory so far, in bytes (Linux's VmHWM); null where /proc does not say. */
function peak(pid: number): number | null {
  try {
    return Number(/VmHWM:\s+(\d+) kB/.exec(readFileSync(`/proc/${pid}/status`, 'utf8'))![1]) * 1024;
  } catch {
    return null;
  }
}

test('through the sidecar, a 55 MB document is held once, in memory, hashed as it comes, and streamed to coffre with its Content-Digest; sent again from the chunks for a fresh nonce', { timeout: 120_000 }, async (t) => {
  const coffre = await fakeCoffre({ upstream: (sent) => ({ status: 200, body: { size: Number(sent.length), sha256: sent.sha256 } }) });
  t.after(() => coffre.close());
  const run = cli(t, ['serve', '--url', coffre.url, '--service', 'api-prod', '--proof', 'enrollment', '--listen', '127.0.0.1:0']);
  const [, listener] = await said(run, /(http:\/\/127\.0\.0\.1:\d+)\/use\/<credential>/);
  const boundary = '----coffre5f1c';
  const body = Buffer.concat([
    Buffer.from(`--${boundary}\r\ncontent-disposition: form-data; name="file"; filename="contract.pdf"\r\ncontent-type: application/pdf\r\n\r\n`),
    randomBytes(55_000_000),
    Buffer.from(`\r\n--${boundary}\r\ncontent-disposition: form-data; name="nature"\r\n\r\nsignable_document\r\n--${boundary}--\r\n`),
  ]);
  const sha256 = createHash('sha256').update(body).digest();
  const before = peak(run.child.pid!);
  const sent = await fetch(`${listener}/use/yousign/v3/signature_requests/sr-1/documents`, { method: 'POST', headers: { 'content-type': `multipart/form-data; boundary=${boundary}` }, body });
  assert.deepEqual(await sent.json(), { size: body.length, sha256: sha256.toString('hex') });
  const forwarded = coffre.forwarded.at(-1)!;
  assert.equal(forwarded.headers['content-digest'], `sha-256=:${sha256.toString('base64')}:`);
  assert.equal(forwarded.headers['content-type'], `multipart/form-data; boundary=${boundary}`);
  assert.equal(forwarded.length, String(body.length));
  // One copy of the body, and some room (70 MB here): one buffer of it handed to the SDK, which reads it whole, grew by 430 MB.
  const after = peak(run.child.pid!);
  if (before !== null && after !== null) assert.ok(after - before < 1.5 * body.length, `the sidecar grew by ${after - before} bytes for a body of ${body.length}`);

  // An app's own digest of another algorithm stays, beside the sidecar's, which the body streams by; a sha-256 that is none is refused here.
  const sha512 = `sha-512=:${createHash('sha512').update('a receipt').digest('base64')}:`;
  const own = await fetch(`${listener}/use/yousign/v3/receipts`, { method: 'POST', headers: { 'content-digest': sha512 }, body: 'a receipt' });
  assert.equal(own.status, 200, await own.text());
  assert.equal(coffre.forwarded.at(-1)!.headers['content-digest'], `${sha512}, sha-256=:${createHash('sha256').update('a receipt').digest('base64')}:`);
  const malformed = await fetch(`${listener}/use/yousign/v3/receipts`, { method: 'POST', headers: { 'content-digest': 'sha-256=:bm90IGEgZGlnZXN0:' }, body: 'a receipt' });
  assert.equal(malformed.status, 400);
  assert.match(((await malformed.json()) as { message: string }).message, /Content-Digest declares a body's SHA-256 once/);

  // An empty POST declares the empty body's digest, and streams as any other.
  const empty = await fetch(`${listener}/use/yousign/v3/ping`, { method: 'POST' });
  assert.deepEqual(await empty.json(), { size: 0, sha256: createHash('sha256').digest('hex') });

  // The gate restarts: the stream, refused for its nonce, goes again from the chunks the sidecar holds, signed with the new one.
  coffre.gate.restart();
  const again = await fetch(`${listener}/use/yousign/v3/documents`, { method: 'POST', body: 'a small document' });
  assert.equal(again.status, 200, await again.text());
  assert.deepEqual(coffre.log.filter((line) => line.startsWith('POST /use/yousign/v3/documents')), ['POST /use/yousign/v3/documents use_dpop_nonce', 'POST /use/yousign/v3/documents 200']);

  // Past 95 MiB, refused by the sidecar itself, before a byte goes to coffre.
  const forwards = coffre.forwarded.length;
  const huge = await fetch(`${listener}/use/yousign/v3/documents`, { method: 'POST', body: new Uint8Array(95 * 1024 * 1024 + 1) });
  assert.equal(huge.status, 413);
  assert.match(((await huge.json()) as { message: string }).message, /at most 95 MiB/);
  assert.equal(coffre.forwarded.length, forwards);
});

test("a service's run refuses a credential two of its environments name, and a run stopped before its command starts logs out first", async (t) => {
  const coffre = await fakeCoffre({ places: ['market/prod', 'market/staging'], plan: (place) => ({ environment: place, values: {}, credentials: ['openai'], tunnels: {} }) });
  t.after(() => coffre.close());
  const both = cli(t, ['--url', coffre.url, '--service', 'api-prod', 'run', '--proof', 'enrollment', '--', process.execPath, '-e', '']);
  const [code] = await once(both.child, 'exit');
  assert.equal(code, 1);
  assert.match(both.stderr(), /both define openai: a credential comes from one environment only/);

  const slow = await fakeCoffre({ planDelayMs: 10_000 });
  t.after(() => slow.close());
  const run = cli(t, ['--url', slow.url, '--service', 'api-prod', 'run', '--proof', 'enrollment', '--', process.execPath, '-e', '']);
  // Stopped while its plan is being asked for: the session exists, the command does not yet.
  for (let i = 0; i < 200 && !slow.log.some((line) => line.endsWith(' waiting')); i++) await new Promise((resolve) => setTimeout(resolve, 50));
  run.child.kill('SIGTERM');
  const [exit, signal] = await once(run.child, 'exit');
  assert.deepEqual([exit, signal], [null, 'SIGTERM']);
  assert.ok(slow.log.includes('POST /api/auth/logout 200'), slow.log.join('\n'));
});
