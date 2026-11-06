// Every request body is read with a byte cap and abandoned past it, so an
// oversize or endless body never buffers and never reaches JSON.parse: the
// unauthenticated device-login endpoints (W155 red-team: a 20 MB body was
// buffered and parsed before validation) and the whole authenticated API,
// one bound for both (`API_BODY_BYTES`); and its values counted before it is
// parsed (`MAX_BODY_NODES`), then validated to their first issue.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { createClient, type CoffreClient } from '@coffre/client';
import { github, signin } from '@coffre/core/identity';

import { parsePath, trimSlashes } from '../src/api/paths.ts';
import { coffreRoute } from '../src/app.ts';
import { z } from 'zod';

import { API_BODY_BYTES, check, countValues, MAX_BODY_NODES, readJson, readLimitedForm, readLimitedJson, readLimitedText } from '../src/http.ts';
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

test('readJson abandons an oversize body instead of buffering and parsing it', async () => {
  const big = 'a'.repeat(200 * 1024);
  const request = new Request('https://x/', { method: 'POST', body: JSON.stringify({ v: big }) });
  await assert.rejects(readJson(request, 4 * 1024), /larger than 4096 bytes/);
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

test('a form reads as URLSearchParams reads it, its fields counted first, in one pass however long a field', async () => {
  const request = (body: string | Uint8Array<ArrayBuffer>) => new Request('https://x/', { method: 'POST', body });
  let seed = 11;
  const random = () => ((seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31);
  // Raw characters past ASCII or escapes of them, not both: where they meet in one name or value, a broken escape
  // beside a raw one, Node's URLSearchParams reads otherwise than the standard, which this reads as written (below).
  const pieces = ['a', 'b=', '=', '&', '&&', '+', '%', '%2', '%20', '%2B', '%e2%82%ac', '%E2%82', '%zz', ' ', '%26', '%3D'];
  for (const text of ['é=€', 'a=€+é', '€%20=%26']) assert.deepEqual([...(await readLimitedForm(request(text), API_BODY_BYTES))], [...new URLSearchParams(text)], text);
  // The standard: UTF-8 of the text, its escapes decoded, then UTF-8 read again, a broken sequence one U+FFFD.
  assert.deepEqual([...(await readLimitedForm(request('a=€%E2%82a'), API_BODY_BYTES))], [['a', '€\uFFFDa']]);
  for (let i = 0; i < 4000; i++) {
    const text = Array.from({ length: Math.floor(random() * 12) }, () => pieces[Math.floor(random() * pieces.length)]).join('');
    assert.deepEqual([...(await readLimitedForm(request(text), API_BODY_BYTES))], [...new URLSearchParams(text)], JSON.stringify(text));
  }
  await assert.rejects(readLimitedForm(request(new Uint8Array([0x61, 0x3d, 0xff])), API_BODY_BYTES), /not UTF-8/);
  await assert.rejects(readLimitedForm(request(Array.from({ length: MAX_BODY_NODES + 1 }, () => 'x').join('&')), API_BODY_BYTES), /more than \d+ fields/);
  // One field of a mebibyte of `+`, which URLSearchParams takes 50 ms to read: a pass over its bytes.
  const plus = `x=${'+'.repeat(API_BODY_BYTES - 2)}`;
  const started = process.cpuUsage();
  const read = await readLimitedForm(request(plus), API_BODY_BYTES);
  const spent = process.cpuUsage(started);
  assert.equal(read.get('x'), ' '.repeat(API_BODY_BYTES - 2));
  assert.ok((spent.user + spent.system) / 1000 < 20, `took ${(spent.user + spent.system) / 1000} ms`);
});

test('a path of a long run of slashes is read in a pass: trimmed at either end, refused for its empty parts', () => {
  assert.equal(trimSlashes('//market/dev/'), 'market/dev');
  assert.equal(trimSlashes('///'), '');
  assert.deepEqual(parsePath('/market/dev/KEY/'), { project: 'market', environment: 'dev', key: 'KEY' });
  // 50,000 slashes inside, as long as a body lets a path be: once seconds of a regular expression's retries.
  const started = process.cpuUsage();
  assert.throws(() => parsePath(`x${'/'.repeat(50_000)}y`), /name a project/);
  const spent = process.cpuUsage(started);
  assert.ok((spent.user + spent.system) / 1000 < 20, `took ${(spent.user + spent.system) / 1000} ms`);
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

test('both unauthenticated device-login endpoints refuse an oversize body, to the one bound every body has', async () => {
  for (const path of ['/api/auth/device', '/api/auth/device/token']) {
    const body = JSON.stringify({ client_label: 'x', device_code: 'a'.repeat(API_BODY_BYTES) });
    const response = await coffreRoute(
      new Request(`${ORIGIN}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body }),
      runtime,
      '203.0.113.7',
    );
    assert.equal(response!.status, 400, path);
    assert.match(JSON.stringify(await response!.json()), new RegExp(`larger than ${API_BODY_BYTES} bytes`));
  }
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
