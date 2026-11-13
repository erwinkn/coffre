// Every request body is read with a byte cap and abandoned past it, 413, so
// an oversize or endless body never buffers and never reaches JSON.parse:
// before sign-in, the device-login endpoints (where a 20 MB body would be
// buffered and parsed before validation) and every other, to
// `SIGN_IN_BODY_BYTES`; the authenticated API, to `API_BODY_BYTES`; and its
// values counted before it is parsed (`MAX_BODY_NODES`), then validated to
// their first issue.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { createClient, type CoffreClient } from '@coffre/client';
import { github, signin } from '@coffre/core/identity';

import { parsePath, trimSlashes } from '../src/api/paths.ts';
import { coffreRoute } from '../src/app.ts';
import { z } from 'zod';

import { API_BODY_BYTES, check, countValues, MAX_BODY_NODES, readJson, readLimitedJson, readLimitedText, SIGN_IN_BODY_BYTES } from '../src/http.ts';
import { resolveConfig } from '../src/config.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let runtime: CoffreRuntime;
let root: CoffreClient;

before(async () => { db = await openTestDatabase(); });
after(async () => { await db.close(); });

beforeEach(async () => {
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  const config = resolveConfig({
    publicUrl: ORIGIN,
    vault: deps.vault,
    auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })] }),
    auditChainKey: deps.chainKey.toString('base64'),
  });
  runtime = createRuntime(config, deps.db, deps.vault, { json: async () => ({}) });
  deps.signin = runtime.signin!;
  root = clientFor(deps, ROOT);
});

test('readJson abandons an oversize body instead of buffering and parsing it, a 413', async () => {
  const big = 'a'.repeat(200 * 1024);
  const request = new Request('https://x/', { method: 'POST', body: JSON.stringify({ v: big }) });
  await assert.rejects(readJson(request, 4 * 1024), (error: unknown) => {
    assert.deepEqual([(error as { code: string }).code, (error as { status: number }).status], ['too_large', 413]);
    assert.match((error as Error).message, /larger than 4096 bytes/);
    return true;
  });
  // readLimitedText stops reading past the cap too.
  await assert.rejects(readLimitedText(new Request('https://x/', { method: 'POST', body: big }), 1024), /larger than 1024 bytes/);
  // Within the cap, it still parses, and still refuses a __proto__ key, nested too.
  assert.deepEqual(await readJson(new Request('https://x/', { method: 'POST', body: '{"a":1}' }), 4 * 1024), { a: 1 });
  await assert.rejects(readJson(new Request('https://x/', { method: 'POST', body: '{"__proto__":1}' }), 4 * 1024), /__proto__/);
  await assert.rejects(readJson(new Request('https://x/', { method: 'POST', body: '{"a":{"b":{"__proto__":1}}}' }), 4 * 1024), /__proto__/);
});

test('readJson refuses a body with too many values, nested array or record alike, before it is parsed', async () => {
  const over = new RegExp(`more than ${MAX_BODY_NODES} values`);
  const bigArray = `{"paths":[${Array.from({ length: MAX_BODY_NODES }, () => '0').join(',')}]}`;
  await assert.rejects(readJson(new Request('https://x/', { method: 'POST', body: bigArray }), API_BODY_BYTES), over);
  const bigRecord = `{${Array.from({ length: MAX_BODY_NODES }, (_, i) => `"K${i}":0`).join(',')}}`;
  await assert.rejects(readJson(new Request('https://x/', { method: 'POST', body: bigRecord }), API_BODY_BYTES), over);
  // As deep as it is wide: each level a value.
  const deep = `${'['.repeat(MAX_BODY_NODES + 1)}${']'.repeat(MAX_BODY_NODES + 1)}`;
  await assert.rejects(readJson(new Request('https://x/', { method: 'POST', body: deep }), API_BODY_BYTES), over);
  // One under the count passes; so does a small nested array.
  const most = `{${Array.from({ length: MAX_BODY_NODES - 1 }, (_, i) => `"K${i}":0`).join(',')}}`;
  assert.equal(Object.keys((await readJson(new Request('https://x/', { method: 'POST', body: most }), API_BODY_BYTES)) as object).length, MAX_BODY_NODES - 1);
  assert.ok(await readJson(new Request('https://x/', { method: 'POST', body: '{"paths":[1,2,3]}' }), 4 * 1024));
  // A mebibyte of tiny entries is refused by the count, which makes none of them: JSON.parse is never called.
  const parse = JSON.parse;
  let parsed = 0;
  JSON.parse = ((...args: Parameters<typeof JSON.parse>) => ((parsed += 1), parse(...args))) as typeof JSON.parse;
  try {
    const tiny = `[${'0,'.repeat(API_BODY_BYTES / 2 - 2)}0]`;
    await assert.rejects(readJson(new Request('https://x/', { method: 'POST', body: tiny }), API_BODY_BYTES), over);
  } finally {
    JSON.parse = parse;
  }
  assert.equal(parsed, 0);
});

test('the count is the one JSON.parse would make: the root, each element and each entry, strings read whole', () => {
  const tree = (value: unknown): number =>
    1 + (value !== null && typeof value === 'object' ? (Array.isArray(value) ? value : Object.values(value)).reduce<number>((sum, child) => sum + tree(child), 0) : 0);
  for (const text of [
    '1', '"a"', 'null', '[]', '{}', ' [ ] ', '[1,2,3]', '{"a":[1,2]}', '[[],[[]],{}]', '{"a":{"b":{"c":null}}}',
    '{"k,[{":"v]}","q":"\\\"","r":["\u005b",1.5e3,true,false]}', '\n{\t"a" :\r\n [ 1 , { } ] }',
  ]) {
    const value: unknown = JSON.parse(text);
    assert.equal(countValues(text), tree(value), text);
  }
  // It stops once past its cap.
  assert.equal(countValues('[1,2,3,4,5,6]', 3), 4);
});

test('a path of a long run of slashes is read in a pass: trimmed at either end, refused for its empty parts', () => {
  assert.equal(trimSlashes('//market/dev/'), 'market/dev');
  assert.equal(trimSlashes('///'), '');
  assert.deepEqual(parsePath('/market/dev/KEY/'), { project: 'market', environment: 'dev', key: 'KEY' });
  // 50,000 slashes inside, as long as a body lets a path be: once seconds of a regular expression's retries.
  // The least CPU of five reads, the read's own: the first also compiles it, and the process's CPU counts V8's
  // threads (packages/core/test/linear-inputs.test.ts). A regular expression's retries cost as much in every read.
  const slashes = `x${'/'.repeat(50_000)}y`;
  let least = Infinity;
  for (let i = 0; i < 5; i++) {
    const started = process.cpuUsage();
    assert.throws(() => parsePath(slashes), /name a project/);
    const spent = process.cpuUsage(started);
    least = Math.min(least, (spent.user + spent.system) / 1000);
  }
  assert.ok(least < 20, `took ${least} ms`);
});

test('validation answers the first issue alone, as safeParse would name it, however many entries fail', () => {
  const schema = z.record(z.string().regex(/^K/), z.union([z.string(), z.object({ value: z.string() }).strict()]));
  const failing = Object.fromEntries(Array.from({ length: 500 }, (_, i) => [`K${i}`, i]));
  const ours = check(schema, failing);
  const zods = schema.safeParse(failing);
  assert.equal(ours.success, false);
  assert.equal(zods.success, false);
  assert.equal(ours.error!.issues.length, 1);
  // The issue an answer names, its path and its message; a union's branches inside it keep a message no one reads.
  const named = ({ code, path, message }: z.core.$ZodIssue) => ({ code, path, message });
  assert.deepEqual(named(ours.error!.issues[0]!), named(zods.error!.issues[0]!));
  assert.deepEqual(named(ours.error!.issues[0]!), { code: 'invalid_union', path: ['K0'], message: 'Invalid input' });
  // And what passes, passes as zod parses it.
  assert.deepEqual(check(schema, { K1: 'a', K2: { value: 'b' } }), schema.safeParse({ K1: 'a', K2: { value: 'b' } }));
});

test('a body is abandoned soon after the cap, not drained to the end', async () => {
  let pulled = 0;
  const endless = new ReadableStream<Uint8Array>({
    pull(controller) {
      pulled += 1;
      controller.enqueue(new Uint8Array(1024).fill(0x61));
    },
  });
  await assert.rejects(readLimitedText(new Request('https://x/', { method: 'POST', body: endless, duplex: 'half' } as RequestInit), 4 * 1024), /larger than 4096 bytes/);
  assert.ok(pulled <= 8, `the stream was abandoned soon after the cap, not drained (pulled ${pulled} chunks)`);
});

test('both unauthenticated device-login endpoints refuse a body past the bound of every body before sign-in, 413', async () => {
  assert.equal(SIGN_IN_BODY_BYTES, 128 * 1024);
  const post = (path: string, body: string) => coffreRoute(
    new Request(`${ORIGIN}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body }),
    runtime,
    '203.0.113.7',
  );
  for (const path of ['/api/auth/device', '/api/auth/device/token']) {
    const over = JSON.stringify({ client_label: 'x', device_code: 'a'.repeat(SIGN_IN_BODY_BYTES) });
    const response = await post(path, over);
    assert.equal(response!.status, 413, path);
    assert.deepEqual(await response!.json(), { error: 'too_large', message: `the body is larger than ${SIGN_IN_BODY_BYTES} bytes` });
  }
  // At the bound, read: a device login started with a label as long as the body lets it be.
  const at = JSON.stringify({ client_label: 'x'.repeat(SIGN_IN_BODY_BYTES - 20) });
  assert.equal(at.length <= SIGN_IN_BODY_BYTES, true);
  assert.equal((await post('/api/auth/device', at))!.status, 200);
});

test('the API refuses a body past its bound, 413, as a client reads any refusal: its status, code and message', async () => {
  await root.projects.create('market');
  await root.environments.create('market/dev');
  const value = 'v'.repeat(60 * 1024);
  const keys = Object.fromEntries(Array.from({ length: Math.ceil(API_BODY_BYTES / value.length) + 1 }, (_, i) => [`K${i}`, value]));
  await assert.rejects(root.secrets.set('market/dev', keys), (error: unknown) => {
    assert.deepEqual([(error as { status: number }).status, (error as { code: string }).code], [413, 'too_large']);
    assert.equal((error as Error).message, `the body is larger than ${API_BODY_BYTES} bytes`);
    return true;
  });
});

test('readLimitedJson refuses a top-level __proto__ key, as readJson does', async () => {
  await assert.rejects(readLimitedJson(new Request('https://x/', { method: 'POST', body: '{"__proto__":1}' }), 1024), /__proto__/);
});

test('a write names as many keys as its body holds values, and a refusal names its first bad entry', async () => {
  await root.projects.create('market');
  await root.environments.create('market/dev');
  const is400 = (pattern: RegExp) => (error: unknown) => {
    assert.equal((error as { status: number }).status, 400);
    assert.match((error as Error).message, pattern);
    return true;
  };
  // Past the count, refused before it is parsed: the keys and the root.
  await assert.rejects(root.secrets.set('market/dev', Object.fromEntries(Array.from({ length: MAX_BODY_NODES }, (_, i) => [`K${i}`, 'v']))), is400(/more than \d+ values/));
  // Within it, every entry bad: the first is the one named.
  await assert.rejects(root.environments.dismiss('market/dev', Object.fromEntries(Array.from({ length: 1000 }, (_, i) => [`K${i}`, 0 as unknown as true]))), is400(/^K0: /));
  // A write may name more keys than the 1000-key bulk-read cap returns.
  await root.secrets.set('market/dev', Object.fromEntries(Array.from({ length: 1001 }, (_, i) => [`K${i}`, 'v'])));
  assert.equal((await root.secrets.list('market/dev')).keys.length, 1001);
});
