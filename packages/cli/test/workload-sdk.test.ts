// `@coffre/client/workload` against a fake coffre that speaks the design's
// wire format and checks every proof with core's `verifyProof`
// (workload-fake.ts): the exchange and what it waits out, renewal, a fresh
// proof before `notAfter`, the nonce, every request signed as the server
// recomputes it, OpenAI's SDK and postgres.js through it, and a key that
// never leaves memory.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import OpenAI from 'openai';
import { WebSocket } from 'ws';

import { generateProofKey } from '@coffre/client/dpop';
import { CoffreError, enrollment, fromCoffre, kubernetes, oidc, workload, type Workload } from '@coffre/client/workload';
import { connect } from '@coffre/client/workload/postgres';
import { postgresClient } from '@coffre/db/connect';

import { fakeCoffre, fakePostgres, type FakeOptions } from './workload-fake.ts';

const quiet = () => undefined;
// Teardown closes each session after its fake coffre is gone, so a logout cannot be confirmed: close() says so, and it is not the test's point.

async function signedIn(t: test.TestContext, options: FakeOptions = {}, proof = oidc(() => 'id-token')) {
  const coffre = await fakeCoffre(options);
  t.after(() => coffre.close());
  const session = await workload({ url: coffre.url, service: 'api-prod', proof, log: quiet });
  t.after(() => session.close().catch(() => undefined));
  return { coffre, session };
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** postgres.js through the tunnel `db`: coffre logs in to the database, so the URL names no password, and its host is never dialled. */
const throughTunnel = (session: Workload, options: { max?: number; WebSocket?: typeof WebSocket } = {}) =>
  postgresClient('postgres://app@tunnel/app', { max: options.max ?? 1, socket: () => connect(session, 'db', options.WebSocket === undefined ? {} : { WebSocket: options.WebSocket }) });

test('a request is signed whole and forwarded as the app made it: only the headers the app set, the query and the body', async (t) => {
  const { coffre, session } = await signedIn(t);
  const response = await session.fetch(`${session.url('stripe')}/v1/charges?expand[]=balance_transaction&a=%2F`, {
    method: 'POST',
    headers: { 'Idempotency-Key': '5f1c', 'Stripe-Account': 'acct_1', authorization: 'Bearer coffre' },
    body: new URLSearchParams({ amount: '2000', currency: 'eur' }),
  });
  assert.equal(response.status, 200);
  const [sent] = coffre.forwarded;
  assert.equal(sent!.method, 'POST');
  assert.equal(sent!.path, '/use/stripe/v1/charges');
  assert.equal(sent!.query, 'expand[]=balance_transaction&a=%2F');
  // The content-type fetch adds for a form is the app's, and signed, as is the body's digest; fetch's own transport headers, and the app's stand-in key, are not.
  const digest = `sha-256=:${createHash('sha256').update('amount=2000&currency=eur').digest('base64')}:`;
  assert.deepEqual(sent!.headers, { 'content-digest': digest, 'content-type': 'application/x-www-form-urlencoded;charset=UTF-8', 'idempotency-key': '5f1c', 'stripe-account': 'acct_1' });
  assert.equal(sent!.body, 'amount=2000&currency=eur');
  // The credential's own fetch, the same; and a Request object, its body read once.
  await session.credential('stripe').fetch('v1/balance', { headers: { accept: 'application/json' } });
  await session.fetch(new Request(`${session.url('openai')}/files`, { method: 'PUT', body: new Uint8Array([0, 1, 2, 255]) }));
  assert.equal(coffre.forwarded[1]!.path, '/use/stripe/v1/balance');
  assert.deepEqual(coffre.forwarded[1]!.headers, { accept: 'application/json' }, 'no body, no digest');
  assert.equal(coffre.forwarded[2]!.body, Buffer.from([0, 1, 2, 255]).toString());
});

test('a request elsewhere passes through untouched: no session, no proof', async (t) => {
  const { session } = await signedIn(t);
  const seen: Record<string, string | string[] | undefined>[] = [];
  const other = createServer((req, res) => {
    seen.push(req.headers);
    res.end('ok');
  }).listen(0, '127.0.0.1');
  t.after(() => other.close());
  await once(other, 'listening');
  assert.equal(await (await session.fetch(`http://127.0.0.1:${(other.address() as { port: number }).port}/use/x`, { headers: { authorization: 'Bearer mine' } })).text(), 'ok');
  assert.equal(seen[0]!.authorization, 'Bearer mine');
  assert.equal(seen[0]!.dpop, undefined);
});

test('a streamed upload to an AWS-signed credential is bound by its declared digest; an unsigned one says so', async (t) => {
  const { coffre, session } = await signedIn(t, { sigv4: ['s3'] });
  const bytes = new TextEncoder().encode('object bytes');
  const digest = Buffer.from(await crypto.subtle.digest('SHA-256', bytes)).toString('hex');
  const stream = () => new ReadableStream({ start: (controller) => (controller.enqueue(bytes), controller.close()) });
  for (const declared of [digest, 'UNSIGNED-PAYLOAD']) {
    const response = await session.fetch(`${session.url('s3')}/bucket/key`, { method: 'PUT', headers: { 'x-amz-content-sha256': declared }, body: stream(), duplex: 'half' } as RequestInit);
    assert.equal(response.status, 200, await response.text());
  }
  // A request with no body signs the empty body's digest, whatever it declares.
  assert.equal((await session.fetch(`${session.url('s3')}/bucket/key`, { headers: { 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' } })).status, 200);
  // A Request object's stream streams too.
  const request = new Request(`${session.url('s3')}/bucket/other`, { method: 'PUT', headers: { 'x-amz-content-sha256': digest }, body: stream(), duplex: 'half' } as RequestInit);
  assert.equal((await session.fetch(request)).status, 200);
  assert.deepEqual(coffre.forwarded.map((sent) => sent.body), ['object bytes', 'object bytes', '', 'object bytes']);
});

test("a body read whole declares its own SHA-256; a stream that declares it streams, held to it; an app's own digest of another algorithm stays as it is", async (t) => {
  const { coffre, session } = await signedIn(t);
  const bytes = new TextEncoder().encode('%PDF-1.7 a signature document');
  const declared = `sha-256=:${createHash('sha256').update(bytes).digest('base64')}:`;
  const stream = (body = bytes) => new ReadableStream({ start: (controller) => (controller.enqueue(body), controller.close()) });
  const upload = (headers: Record<string, string>, body: BodyInit) => session.fetch(`${session.url('yousign')}/v3/documents`, { method: 'POST', headers, body, duplex: 'half' } as RequestInit);
  assert.equal((await upload({}, bytes)).status, 200);
  assert.equal(coffre.forwarded.at(-1)!.headers['content-digest'], declared);
  // Declared by whoever holds the bytes (`coffre serve`): its stream is never read here, and coffre holds the bytes to it.
  const response = await upload({ 'content-digest': declared, 'content-length': String(bytes.length) }, stream());
  assert.equal(response.status, 200, await response.text());
  assert.equal(coffre.forwarded.at(-1)!.body, '%PDF-1.7 a signature document');
  const tampered = await upload({ 'content-digest': declared, 'content-length': String(bytes.length) }, stream(new TextEncoder().encode('%PDF-1.7 another document!!!!')));
  assert.equal(tampered.status, 400);
  assert.equal(coffre.forwarded.length, 2);
  // An app's own sha-512 declares nothing to coffre: it goes on as the app set it, signed, and the body is read whole.
  const sha512 = `sha-512=:${createHash('sha512').update(bytes).digest('base64')}:`;
  assert.equal((await upload({ 'content-digest': sha512 }, stream())).status, 200);
  assert.equal(coffre.forwarded.at(-1)!.headers['content-digest'], sha512);
  // A sha-256 member that is no SHA-256 binds nothing, and is sent nowhere.
  await assert.rejects(upload({ 'content-digest': 'sha-256=:bm90IGEgZGlnZXN0:' }, bytes), /Content-Digest declares a body's SHA-256 once/);
  assert.equal(coffre.forwarded.length, 3);
});

test('a nonce the gate no longer knows is refused once, and the request sent again with the new one; the newest is always used', async (t) => {
  const { coffre, session } = await signedIn(t);
  // Each answer carries the gate's current nonce: two rotations later, the SDK still holds a nonce the gate takes.
  coffre.gate.rotate();
  await session.fetch(session.url('openai'));
  coffre.gate.rotate();
  await session.fetch(session.url('openai'));
  assert.ok(!coffre.log.some((line) => line.endsWith('use_dpop_nonce')), coffre.log.join('\n'));
  // A restarted gate knows no nonce: one refusal, then the same request, body and all.
  coffre.gate.restart();
  const response = await session.fetch(session.url('openai'), { method: 'POST', body: 'again' });
  assert.equal(response.status, 200);
  assert.deepEqual(coffre.log.slice(-2), ['POST /use/openai use_dpop_nonce', 'POST /use/openai 200']);
  assert.equal(coffre.forwarded.at(-1)!.body, 'again');
});

/**
 * Time, mocked, moved on by `ms`; then the I/O that set off, on real time, until `done` holds. A count of the event
 * loop's turns is no bound: a loaded runner takes more of them for a request on loopback and its proof's signature.
 */
async function advance(t: test.TestContext, ms: number, done: () => boolean) {
  t.mock.timers.tick(ms);
  const until = performance.now() + 10_000;
  while (!done() && performance.now() < until) await new Promise((resolve) => setImmediate(resolve));
}

/**
 * How many times the SDK has set a timer `ms` on: a session's renewal or its next proof, set once the answer that
 * brought the session is read. coffre's log says it answered; this says the SDK is done with the answer, so that the
 * next tick finds the timer set, and a close the session. Time must be mocked first.
 */
function armed(t: test.TestContext, ms: number): () => number {
  const set = t.mock.method(globalThis, 'setTimeout');
  return () => set.mock.calls.filter((call) => call.arguments[1] === ms).length;
}

const count = (log: string[], line: string) => log.filter((each) => each === line).length;

test('a session renews at half-life, and outlives its first expiry', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: Date.now() });
  // Each renewal set half an hour on: once signed in, then once each renewal.
  const renewals = armed(t, 1800_000);
  const { coffre, session } = await signedIn(t);
  for (let i = 1; i <= 3; i++) await advance(t, 1800_000, () => renewals() === 1 + i);
  assert.equal(count(coffre.log, 'POST /api/auth/workload/renew 200'), 3, coffre.log.join('\n'));
  // Two hours on, past the first hour's expiry: the same session.
  assert.equal((await session.fetch(session.url('openai'))).status, 200);
  assert.equal(count(coffre.log, 'POST /api/auth/workload 200'), 1);
});

test('an enrollment session renews every 30 seconds, its expiry its liveness', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: Date.now() });
  const renewals = armed(t, 30_000);
  const { coffre } = await signedIn(t, { lifetimeMs: 90_000 }, enrollment(`coffre_enr_${'c'.repeat(43)}`));
  for (let i = 1; i <= 4; i++) await advance(t, 30_000, () => renewals() === 1 + i);
  assert.equal(count(coffre.log, 'POST /api/auth/workload/renew 200'), 4, coffre.log.join('\n'));
  assert.equal(count(coffre.log, 'POST /api/auth/workload 200'), 1);
});

test('before its hard end, a session is proved again with the same key, and requests go on', async (t) => {
  const jkts: string[] = [];
  const { coffre, session } = await signedIn(t, { notAfterMs: 1500, exchange: (_proof, jkt) => (jkts.push(jkt), null) });
  await sleep(2000);
  assert.ok(jkts.length >= 2, coffre.log.join('\n'));
  assert.equal(new Set(jkts).size, 1);
  assert.equal((await session.fetch(session.url('openai'))).status, 200);
});

test('a session coffre stops renewing (revoked, frozen) is lost, and a new one proved', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: Date.now() });
  let refused = false;
  const { coffre, session } = await signedIn(t, { renew: () => (refused ? null : ((refused = true), { status: 401, body: { error: 'unauthorized', reason: 'revoked' } })) });
  await advance(t, 1800_000, () => count(coffre.log, 'POST /api/auth/workload 200') === 2);
  assert.equal((await session.fetch(session.url('openai'))).status, 200);
  assert.deepEqual(coffre.log, ['POST /api/auth/workload 200', 'POST /api/auth/workload/renew 401', 'POST /api/auth/workload 200', 'GET /use/openai 200']);
});

test('a superseded code is final: requests say why, and no exchange is tried again', async (t) => {
  const { coffre, session } = await signedIn(
    t,
    {
      lifetimeMs: 1000,
      renew: () => ({ status: 401, body: { error: 'unauthorized', reason: 'superseded' } }),
      exchange: (_proof, _jkt, attempt) => (attempt === 1 ? null : { status: 401, body: { error: 'unauthorized', reason: 'superseded', message: 'a newer deploy promoted its code' } }),
    },
    enrollment(`coffre_enr_${'s'.repeat(43)}`),
  );
  // An enrollment renews every 30 s, so its expiry, a second here, finds the session gone first.
  await sleep(1500);
  await assert.rejects(session.fetch(session.url('openai')), (error) => error instanceof CoffreError && error.reason === 'superseded');
  const tried = coffre.log.filter((line) => line.startsWith('POST /api/auth/workload ')).length;
  await assert.rejects(session.fetch(session.url('openai')), (error) => error instanceof CoffreError && error.reason === 'superseded');
  assert.equal(coffre.log.filter((line) => line.startsWith('POST /api/auth/workload ')).length, tried);
});

test('a full enrollment code is waited out, by its Retry-After', async (t) => {
  const said: string[] = [];
  const coffre = await fakeCoffre({ exchange: (_proof, _jkt, attempt) => (attempt < 3 ? { status: 429, body: { error: 'too_many', reason: 'full' }, headers: { 'retry-after': '1' } } : null) });
  t.after(() => coffre.close());
  const started = Date.now();
  const session = await workload({ url: coffre.url, service: 'api-prod', proof: enrollment(`coffre_enr_${'f'.repeat(43)}`), log: (line) => said.push(line) });
  t.after(() => session.close().catch(() => undefined));
  assert.ok(Date.now() - started >= 2000);
  assert.equal(said.length, 1);
  assert.match(said[0]!, /holds all the sessions it admits/);
});

test('a session awaiting approval is asked for again every 5 seconds, with the same key', async (t) => {
  const jkts: string[] = [];
  const coffre = await fakeCoffre({ exchange: (_proof, jkt, attempt) => (jkts.push(jkt), attempt < 2 ? { status: 202, body: { pending: 's1', approve: 'https://coffre/approve/s1' } } : null) });
  t.after(() => coffre.close());
  const said: string[] = [];
  const session = await workload({ url: coffre.url, service: 'api-prod', proof: enrollment(`coffre_enr_${'p'.repeat(43)}`), log: (line) => said.push(line) });
  t.after(() => session.close().catch(() => undefined));
  assert.equal(new Set(jkts).size, 1);
  assert.match(said[0]!, /waits for a person to approve it, at https:\/\/coffre\/approve\/s1/);
});

test('a restarted process finds its projected token spent (replayed) and waits for the kubelet to write the next', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-k8s-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'token');
  writeFileSync(file, 'spent-token\n');
  const sent: unknown[] = [];
  const coffre = await fakeCoffre({ exchange: (proof) => (sent.push(proof.oidc), proof.oidc === 'spent-token' ? { status: 401, body: { error: 'unauthorized', reason: 'replayed' } } : null) });
  t.after(() => coffre.close());
  setTimeout(() => writeFileSync(file, 'next-token\n'), 1500);
  const said: string[] = [];
  const session = await workload({ url: coffre.url, service: 'api-prod', proof: kubernetes(file), log: (line) => said.push(line) });
  t.after(() => session.close().catch(() => undefined));
  assert.equal(said.length, 1);
  assert.match(said[0]!, /is already used; waiting for the next one/);
  assert.deepEqual(sent, ['spent-token', 'next-token']);
  assert.equal(coffre.log.filter((line) => line.startsWith('POST /api/auth/workload ')).join(','), 'POST /api/auth/workload 401,POST /api/auth/workload 200');
});

test('a long-running process waits for the kubelet to write the next token before it proves again, and never sends a spent one', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-k8s-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'token');
  writeFileSync(file, 'token-1\n');
  const sent: unknown[] = [];
  const seen = new Set<unknown>();
  // A projected token is spent once used, as the server's replay check has it.
  const coffre = await fakeCoffre({
    // The session re-proves at 90% of its 2 seconds; the kubelet's next comes a second later.
    notAfterMs: 2000,
    lifetimeMs: 60_000,
    exchange: (proof) => {
      sent.push(proof.oidc);
      if (seen.has(proof.oidc)) return { status: 401, body: { error: 'unauthorized', reason: 'replayed' } };
      seen.add(proof.oidc);
      return null;
    },
  });
  t.after(() => coffre.close());
  const said: string[] = [];
  const session = await workload({ url: coffre.url, service: 'api-prod', proof: kubernetes(file), log: (line) => said.push(line) });
  t.after(() => session.close().catch(() => undefined));
  await sleep(3000);
  assert.deepEqual(sent, ['token-1'], 'it waits, and sends nothing, while the file holds the token it sent');
  assert.equal(said.length, 1);
  assert.match(said[0]!, /is already used; waiting for the next one/);
  writeFileSync(file, 'token-2\n');
  await sleep(2500);
  assert.deepEqual(sent.slice(0, 2), ['token-1', 'token-2']);
  assert.equal(coffre.log.filter((line) => /^POST \/api\/auth\/workload \d+$/.test(line)).slice(0, 2).join(','), 'POST /api/auth/workload 200,POST /api/auth/workload 200');
  assert.ok(!coffre.log.some((line) => line === 'POST /api/auth/workload 401'), 'no replayed answer was ever needed');
});

test("a refused exchange rejects workload() with coffre's reason", async (t) => {
  const coffre = await fakeCoffre({ exchange: () => ({ status: 401, body: { error: 'unauthorized', reason: 'no_binding', message: 'no binding takes this proof' } }) });
  t.after(() => coffre.close());
  await assert.rejects(workload({ url: coffre.url, service: 'api-prod', proof: oidc('t'), log: quiet }), (error) => error instanceof CoffreError && error.reason === 'no_binding' && /no binding takes this proof/.test(error.message));
});

test("the key is made non-extractable, and never leaves: exportKey rejects", async (t) => {
  const made: CryptoKeyPair[] = [];
  const generate = crypto.subtle.generateKey.bind(crypto.subtle);
  t.mock.method(crypto.subtle, 'generateKey', async (...args: Parameters<typeof generate>) => {
    const pair = (await generate(...args)) as CryptoKeyPair;
    made.push(pair);
    return pair;
  });
  await signedIn(t);
  t.mock.restoreAll();
  assert.equal(made.length, 1);
  assert.equal(made[0]!.privateKey.extractable, false);
  await assert.rejects(crypto.subtle.exportKey('jwk', made[0]!.privateKey));
  await assert.rejects(crypto.subtle.exportKey('pkcs8', made[0]!.privateKey));
});

test('nothing is written to disk or the environment, and SIGTERM logs every session out, then ends the process', async (t) => {
  const coffre = await fakeCoffre();
  t.after(() => coffre.close());
  const code = `coffre_enr_${'e'.repeat(43)}`;
  const script = `
    import { workload, enrollment, oidc } from '@coffre/client/workload';
    const before = JSON.stringify(process.env);
    const coffre = await workload({ url: ${JSON.stringify(coffre.url)}, service: 'api-prod', proof: enrollment(process.env.COFFRE_ENROLL) });
    // A second session: SIGTERM still ends the process once both have logged out.
    await workload({ url: ${JSON.stringify(coffre.url)}, service: 'batch', proof: oidc('t') });
    await (await coffre.fetch(coffre.url('openai') + '/models')).text();
    const after = JSON.parse(before);
    delete after.COFFRE_ENROLL;
    if (JSON.stringify(process.env) !== JSON.stringify(after)) throw new Error('the environment changed beyond the code removed');
    process.kill(process.pid, 'SIGTERM');
    setTimeout(() => {}, 10_000);
  `;
  const home = mkdtempSync(join(tmpdir(), 'coffre-sdk-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  // Node's permission model: any write to the file system throws.
  const child = spawn(process.execPath, ['--conditions=coffre:source', '--permission', '--allow-fs-read=*', '--input-type=module', '-e', script], {
    env: { PATH: process.env.PATH, HOME: home, TMPDIR: home, COFFRE_ENROLL: code },
    cwd: new URL('.', import.meta.url).pathname,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = '';
  child.stderr.setEncoding('utf8').on('data', (data: string) => (stderr += data));
  const [exit, signal] = (await once(child, 'exit')) as [number | null, string | null];
  assert.equal(signal, 'SIGTERM', stderr);
  assert.equal(exit, null);
  assert.deepEqual(readdirSync(home), []);
  assert.deepEqual(coffre.log, ['POST /api/auth/workload 200', 'POST /api/auth/workload 200', 'GET /use/openai/models 200', 'POST /api/auth/logout 200', 'POST /api/auth/logout 200']);
});

test("OpenAI's SDK, given coffre's fetch and URL, holds no key: coffre gets its request as it made it", async (t) => {
  const { coffre, session } = await signedIn(t, {
    upstream: () => ({ status: 200, body: { id: 'chatcmpl-1', object: 'chat.completion', created: 0, model: 'gpt-x', choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: 'bonjour' } }] } }),
  });
  const openai = new OpenAI({ apiKey: 'coffre', baseURL: session.url('openai'), fetch: session.fetch, maxRetries: 0 });
  const completion = await openai.chat.completions.create({ model: 'gpt-x', messages: [{ role: 'user', content: 'hello' }] });
  assert.equal(completion.choices[0]!.message.content, 'bonjour');
  const [sent] = coffre.forwarded;
  assert.equal(sent!.path, '/use/openai/chat/completions');
  assert.deepEqual(JSON.parse(sent!.body), { model: 'gpt-x', messages: [{ role: 'user', content: 'hello' }] });
  assert.equal(sent!.headers['content-type'], 'application/json');
  assert.equal(sent!.headers.authorization, undefined);
});

for (const paced of [true, false]) {
  test(`postgres.js through the tunnel, its bytes ${paced ? 'paced by credit, as on Workers' : 'unpaced, as on Node'}, a result larger than the window included`, async (t) => {
    const database = await fakePostgres();
    t.after(() => database.close());
    const { coffre, session } = await signedIn(t, { database, paced });
    const pool = throughTunnel(session, { max: 10, WebSocket });
    assert.deepEqual([...await pool.unsafe('select one')], [{ value: 'select one' }]);
    const big = await pool.unsafe<{ value: string }[]>('select 3000 1000');
    assert.equal(big.length, 3000);
    assert.equal(big[2999]!.value.length, 1000);
    // A query larger than the window goes in frames, each within the credit left.
    const query = `select ${'q'.repeat(3 * 1024 * 1024)}`;
    assert.equal((await pool.unsafe<{ value: string }[]>(query))[0]!.value.length, query.length);
    assert.ok(coffre.log.includes('GET /use/market/prod/db upgrade'), coffre.log.join('\n'));
    await pool.end();
  });
}

test("the runtime's own WebSocket carries the tunnel where it has one", async (t) => {
  const database = await fakePostgres();
  t.after(() => database.close());
  const { session } = await signedIn(t, { database });
  const client = throughTunnel(session);
  assert.deepEqual([...await client.unsafe('select two')], [{ value: 'select two' }]);
  await client.end();
});

test('sign, verify, presign and mint go to the environment, and read returns only what the session may read', async (t) => {
  const { coffre, session } = await signedIn(t, {
    plan: { environment: 'market/prod', values: { TWILIO_SID: 'AC012' }, credentials: ['stripe'], tunnels: {} },
    upstream: (sent) => {
      const asked = JSON.parse(sent.body) as Record<string, unknown>;
      if ('sign' in asked) return { status: 200, body: { signature: 'c2ln' } };
      if ('verify' in asked) return { status: 200, body: { valid: true } };
      if ('presign' in asked) return { status: 200, body: { url: 'https://s3/x?X-Amz-Signature=1', expiresAt: '2026-10-24T03:00:00Z' } };
      return { status: 200, body: { accessKeyId: 'ASIA1', secretAccessKey: 's', sessionToken: 't', expiresAt: new Date(Date.now() + 900_000).toISOString() } };
    },
  });
  assert.equal(await session.credential('dfns-key').sign('challenge'), 'c2ln');
  assert.equal(await session.credential('stripe-webhook').verify(new Uint8Array([1, 2]), 't=1,v1=ab'), true);
  assert.equal((await session.credential('s3').presign('/bucket/key', { expiresIn: 60 })).url, 'https://s3/x?X-Amz-Signature=1');
  const provider = fromCoffre(session, 'aws');
  assert.equal((await provider()).accessKeyId, 'ASIA1');
  await provider();
  assert.deepEqual(coffre.forwarded.map((sent) => [sent.path, JSON.parse(sent.body)]), [
    ['/use/market/prod', { sign: { credential: 'dfns-key', message: Buffer.from('challenge').toString('base64url') } }],
    ['/use/market/prod', { verify: { credential: 'stripe-webhook', message: 'AQI', signature: 't=1,v1=ab' } }],
    ['/use/market/prod', { presign: { credential: 's3', path: '/bucket/key', expiresIn: 60 } }],
    // A minted child is kept until a minute before it expires.
    ['/use/market/prod', { mint: { credential: 'aws' } }],
  ]);
  assert.equal(await session.read('TWILIO_SID'), 'AC012');
  await assert.rejects(session.read('STRIPE_SECRET_KEY'), (error) => error instanceof CoffreError && error.reason === 'use_only');
});

test('with several environments, URLs name the one chosen', async (t) => {
  const coffre = await fakeCoffre({ places: ['market/prod', 'market/staging'] });
  t.after(() => coffre.close());
  const unnamed = await workload({ url: coffre.url, service: 'api-prod', proof: oidc('t'), log: quiet });
  t.after(() => unnamed.close().catch(() => undefined));
  assert.throws(() => unnamed.url('openai'), /name the one to use/);
  const named = await workload({ url: coffre.url, service: 'api-prod', proof: oidc('t'), place: 'market/staging', log: quiet });
  t.after(() => named.close().catch(() => undefined));
  assert.equal(named.url('openai'), `${coffre.url}/use/market/staging/openai`);
  await assert.rejects(workload({ url: coffre.url, service: 'api-prod', proof: oidc('t'), place: 'market/dev', log: quiet }), /not market\/dev/);
});

test('a narrowed session signs with its own key, and ends with its parent', async (t) => {
  const { coffre, session } = await signedIn(t);
  const child: Workload = await session.narrow({ credentials: ['stripe'], paths: ['/v1/refunds'], expiresIn: 600, label: 'refund-agent' });
  assert.equal((await child.fetch(`${child.url('stripe')}/v1/refunds`, { method: 'POST' })).status, 200);
  const [parentSession, childSession] = [...coffre.sessions.values()];
  assert.notEqual(parentSession!.jkt, childSession!.jkt);
  assert.equal(coffre.forwarded.at(-1)!.session, childSession!.id);
  await session.close();
  assert.equal((await child.fetch(`${child.url('stripe')}/v1/refunds`, { method: 'POST' })).status, 401);
  // A key made elsewhere: the child's token, for the process that holds the key.
  const { jwk } = await generateProofKey();
  const handed = await (await signedIn(t)).session.narrow({ key: jwk, credentials: ['stripe'] });
  assert.match(handed.token, /^coffre_wl_/);
});

test('closing after a new proof ends every session it proved, and their children', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: Date.now() });
  // Each session's next proof, set at 90% of the way to its 24-hour end: once signed in, then once the new proof is read.
  const day = 24 * 3_600_000;
  const proofs = armed(t, day - day / 10);
  const { coffre, session } = await signedIn(t, { lifetimeMs: 48 * 3_600_000 });
  const child = await session.narrow({ credentials: ['stripe'] });
  // At 90% of the way to its 24-hour end, the parent proves again: the child's root is the old session, alive until then.
  await advance(t, 22 * 3_600_000, () => proofs() === 2);
  assert.equal(count(coffre.log, 'POST /api/auth/workload 200'), 2, coffre.log.join('\n'));
  await session.close();
  assert.ok([...coffre.sessions.values()].filter((each) => each.parent === undefined).every((each) => each.revoked));
  assert.equal((await child.fetch(child.url('stripe'))).status, 401);
});

test("a child's logout survives a restarted gate, and ends the grandchild", async (t) => {
  const { coffre, session } = await signedIn(t);
  const child = await session.narrow({ credentials: ['stripe'] });
  const grandchild = await child.narrow({ credentials: ['stripe'] });
  coffre.gate.restart();
  await child.close();
  assert.deepEqual(coffre.log.slice(-2), ['POST /api/auth/logout use_dpop_nonce', 'POST /api/auth/logout 200']);
  assert.equal((await grandchild.fetch(grandchild.url('stripe'))).status, 401);
});

test('a redirect is followed hop by hop: signed afresh within coffre, and without the session anywhere else', async (t) => {
  const seen: Record<string, string | string[] | undefined>[] = [];
  const other = createServer((req, res) => (seen.push(req.headers), res.end('elsewhere'))).listen(0, '127.0.0.1');
  t.after(() => other.close());
  await once(other, 'listening');
  const elsewhere = `http://127.0.0.1:${(other.address() as { port: number }).port}/landing`;
  const { coffre, session } = await signedIn(t, {
    upstream: (sent) =>
      sent.path === '/use/openai/start' ? { status: 307, headers: { location: '/use/openai/next' } }
        : sent.path === '/use/openai/next' ? { status: 303, headers: { location: elsewhere } }
          : { status: 200, body: sent },
  });
  const response = await session.fetch(`${session.url('openai')}/start`, { method: 'POST', body: 'payload', headers: { 'x-app': '1', authorization: 'Bearer mine', cookie: 'a=1' } });
  assert.equal(await response.text(), 'elsewhere');
  assert.deepEqual(coffre.forwarded.map((sent) => [sent.method, sent.path, sent.body]), [['POST', '/use/openai/start', 'payload'], ['POST', '/use/openai/next', 'payload']]);
  assert.equal(seen[0]!['x-app'], '1');
  // As fetch does, credentials the app set go to no other origin; nor does the session's.
  assert.equal(seen[0]!.authorization, undefined);
  assert.equal(seen[0]!.cookie, undefined);
  assert.equal(seen[0]!.dpop, undefined);
  // Asked not to follow, the redirect is the answer.
  assert.equal((await session.fetch(`${session.url('openai')}/start`, { method: 'POST', redirect: 'manual' })).status, 307);
});

test('close() stops an exchange waiting for approval, and a logout that never answers is given up after 3 seconds', async (t) => {
  let refused = false;
  const { coffre, session } = await signedIn(t, {
    lifetimeMs: 1000,
    renew: () => (refused ? null : ((refused = true), { status: 401, body: { error: 'unauthorized', reason: 'revoked' } })),
    exchange: (_proof, _jkt, attempt) => (attempt === 1 ? null : { status: 202, body: { pending: 's2' } }),
  });
  await sleep(1200);
  const asked = coffre.log.filter((line) => line.startsWith('POST /api/auth/workload ')).length;
  assert.ok(asked >= 2, coffre.log.join('\n'));
  const started = Date.now();
  await session.close();
  assert.ok(Date.now() - started < 1000, 'no session to log out: the pending one was never given');
  await sleep(5500);
  assert.equal(coffre.log.filter((line) => line.startsWith('POST /api/auth/workload ')).length, asked);

  const silent = await fakeCoffre({ stallLogout: true });
  t.after(() => silent.close());
  const stalled = await workload({ url: silent.url, service: 'api-prod', proof: oidc('t'), log: quiet });
  const closing = Date.now();
  await assert.rejects(stalled.close());
  assert.ok(Date.now() - closing < 4000);
});

test('workload() talks to coffre over https, or http on this machine only', async () => {
  await assert.rejects(workload({ url: 'http://192.0.2.1:7300', service: 'api-prod', proof: oidc('t'), log: quiet, fetch: () => assert.fail('nothing is sent') }), /over https/);
});

test("a proof goes to coffre's exchange alone: a redirect there is refused, and its target gets nothing", async (t) => {
  const seen: string[] = [];
  const other = createServer((req, res) => (seen.push(req.url!), res.end())).listen(0, '127.0.0.1');
  t.after(() => other.close());
  await once(other, 'listening');
  const coffre = await fakeCoffre({ exchange: () => ({ status: 307, headers: { location: `http://127.0.0.1:${(other.address() as { port: number }).port}/steal` } }) });
  t.after(() => coffre.close());
  await assert.rejects(workload({ url: coffre.url, service: 'api-prod', proof: enrollment(`coffre_enr_${'r'.repeat(43)}`), log: quiet }));
  assert.deepEqual(seen, []);
});

test('a logout coffre keeps asking a fresh nonce for has not ended the session: close() says so', async (t) => {
  const { session } = await signedIn(t, { nonceLogout: true });
  await assert.rejects(session.close(), /did not end the session/);
});

test("narrow's body is signed with its proof: a copy of the request carrying another key is refused", async (t) => {
  const coffre = await fakeCoffre();
  t.after(() => coffre.close());
  const seen: { url: string; headers: Headers; body: string }[] = [];
  const session = await workload({
    url: coffre.url,
    service: 'api-prod',
    proof: oidc('t'),
    log: quiet,
    fetch: async (input, init) => {
      if (String(input).endsWith('/narrow')) seen.push({ url: String(input), headers: new Headers(init?.headers), body: String(init?.body) });
      return fetch(input, init);
    },
  });
  t.after(() => session.close().catch(() => undefined));
  await session.narrow({ credentials: ['stripe'] });
  const [asked] = seen;
  const { jwk } = await generateProofKey();
  const forged = JSON.stringify({ ...JSON.parse(asked!.body), key: jwk, constraints: {} });
  const replayed = await fetch(asked!.url, { method: 'POST', headers: asked!.headers, body: forged });
  assert.equal(replayed.status, 401);
  assert.equal(((await replayed.json()) as { reason: string }).reason, 'req');
});

test("a tunnel refused before it opened makes the next one ask for the gate's newest nonce", async (t) => {
  const database = await fakePostgres();
  t.after(() => database.close());
  const { coffre, session } = await signedIn(t, { database });
  coffre.gate.restart();
  const refused = throughTunnel(session);
  await assert.rejects(refused.unsafe('select 1'));
  await refused.end();
  const client = throughTunnel(session);
  assert.deepEqual([...await client.unsafe('select seven')], [{ value: 'select seven' }]);
  await client.end();
  // The refused one, perhaps twice (undici's WebSocket tries its handshake again), then a renewal for the newest nonce, then the upgrade.
  assert.deepEqual(coffre.log.slice(-3), ['POST /api/auth/workload/renew use_dpop_nonce', 'POST /api/auth/workload/renew 200', 'GET /use/market/prod/db upgrade']);
});

test("a credential's fetch reaches its own upstream only: a path that climbs out to another credential is refused", async (t) => {
  const { coffre, session } = await signedIn(t);
  const s3 = session.credential('s3');
  for (const path of ['/../stripe/v1/charges', '/a/../../stripe/v1/charges', '/%2e%2e/stripe/v1/charges', '..']) {
    await assert.rejects(s3.fetch(path, { method: 'POST' }), /leaves s3's URL/, path);
  }
  assert.equal(coffre.forwarded.length, 0);
  // Within it, dot segments are the path's own business.
  assert.equal((await s3.fetch('/bucket/a/../b')).status, 200);
  assert.equal(coffre.forwarded[0]!.path, '/use/s3/bucket/b');
});

test('a proof given once, found spent when proving again, is final: no retry storm, and it says so once', async (t) => {
  const said: string[] = [];
  const coffre = await fakeCoffre({ notAfterMs: 1000, exchange: (_proof, _jkt, attempt) => (attempt === 1 ? null : { status: 401, body: { error: 'unauthorized', reason: 'replayed' } }) });
  t.after(() => coffre.close());
  const session = await workload({ url: coffre.url, service: 'api-prod', proof: oidc('id-token'), log: (line) => said.push(line) });
  t.after(() => session.close().catch(() => undefined));
  await sleep(3000);
  assert.equal(coffre.log.filter((line) => line.startsWith('POST /api/auth/workload ')).length, 2, coffre.log.join('\n'));
  assert.equal(said.filter((line) => /was spent, and it gives no fresh one/.test(line)).length, 1);
});

test("a session proved again waits at least the Retry-After coffre answers, not its own backoff", async (t) => {
  // No spread: its backoff its least, coffre's 4 s exactly.
  t.mock.method(Math, 'random', () => 0);
  const busy = { status: 503, body: { error: 'unavailable', message: 'coffre cannot reach what it depends on right now' }, headers: { 'retry-after': '4' } };
  // When coffre was asked for each exchange.
  const asked: number[] = [];
  const coffre = await fakeCoffre({ notAfterMs: 1000, exchange: (_proof, _jkt, attempt) => (asked.push(Date.now()), attempt === 2 || attempt === 3 ? busy : null) });
  t.after(() => coffre.close());
  const session = await workload({ url: coffre.url, service: 'api-prod', proof: oidc('id-token'), log: () => undefined });
  t.after(() => session.close().catch(() => undefined));
  // Proved again at 90% of its second, refused; lost at its end, proved again at once, refused: then asked again 4 s on,
  // where its own backoff said 1.5 to 2.5 s. Measured between the two asks, which a loaded machine makes late alike.
  for (let waited = 0; asked.length < 4 && waited < 15_000; waited += 100) await sleep(100);
  assert.ok(asked.length >= 4, coffre.log.join('\n'));
  assert.ok(asked[3]! - asked[2]! >= 4000, `asked again ${asked[3]! - asked[2]!} ms after the refusal`);
});
