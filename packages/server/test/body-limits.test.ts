// Every request body is read with a byte cap and abandoned past it, so an
// oversize or endless body never buffers and never reaches JSON.parse: the
// device login's two endpoints, which anyone may call (W155's red team sent
// one 20 MB), and the whole API, which reads the body before the vault is
// asked who is calling (docs/design/0.16.md: the size limit is public). A
// parsed body is then walked once, under a cap on its values, refusing
// `__proto__` at any depth.
import { after, test } from 'node:test';
import assert from 'node:assert/strict';

import { readJson, readLimitedJson, readLimitedText } from '../src/http.ts';
import { openApp } from './app-fixture.ts';

const app = await openApp();
after(() => app.close());

const post = (body: BodyInit, more: RequestInit = {}) => new Request('https://x/', { method: 'POST', body, ...more } as RequestInit);

/** A body that never ends, 1 KiB a pull, or `chunk` bytes: how many times it was pulled, and whether it was cancelled. */
function endless(chunk = 1024) {
  const seen = { pulled: 0, cancelled: false };
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      seen.pulled += 1;
      controller.enqueue(new Uint8Array(chunk).fill(0x61));
    },
    cancel: () => void (seen.cancelled = true),
  });
  return { body, seen };
}

test('readJson abandons an oversize body instead of buffering and parsing it, and refuses __proto__ at any depth', async () => {
  await assert.rejects(readJson(post(JSON.stringify({ v: 'a'.repeat(200 * 1024) })), 4 * 1024), { code: 'bad_request', message: 'the body is larger than 4096 bytes' });
  await assert.rejects(readLimitedText(post('a'.repeat(200 * 1024)), 1024), { code: 'bad_request', message: 'the body is larger than 1024 bytes' });
  // At the cap exactly, it is read.
  assert.equal(await readLimitedText(post('a'.repeat(1024)), 1024), 'a'.repeat(1024));
  assert.deepEqual(await readJson(post('{"a":1}'), 4 * 1024), { a: 1 });
  for (const body of ['{"__proto__":1}', '{"a":{"b":{"__proto__":1}}}', '[{"a":[{"__proto__":{}}]}]']) {
    await assert.rejects(readJson(post(body), 4 * 1024), { code: 'bad_request', message: '__proto__ cannot be used as a key' }, body);
  }
  await assert.rejects(readLimitedJson(post('{"__proto__":1}'), 1024), { message: '__proto__ cannot be used as a key' });
  // A name that only looks like it is any other key.
  assert.deepEqual(await readJson(post('{"__proto__x":1,"constructor":2}'), 4 * 1024), { __proto__x: 1, constructor: 2 });
});

test('readJson refuses a body of more than 20,000 values, nested array or record alike, and an empty body is its fallback', async () => {
  const bigArray = `{"paths":[${Array.from({ length: 30000 }, () => '0').join(',')}]}`;
  await assert.rejects(readJson(post(bigArray), 4 * 1024 * 1024), { message: 'the body holds more than 20000 values' });
  const bigRecord = `{${Array.from({ length: 30000 }, (_, i) => `"K${i}":0`).join(',')}}`;
  await assert.rejects(readJson(post(bigRecord), 4 * 1024 * 1024), { message: 'the body holds more than 20000 values' });
  // Counted over the whole tree: 100 arrays of 200 are 20,101 values with the arrays and the root.
  const nested = JSON.stringify(Array.from({ length: 100 }, () => Array.from({ length: 200 }, () => 0)));
  await assert.rejects(readJson(post(nested), 4 * 1024 * 1024), { message: 'the body holds more than 20000 values' });
  const under = JSON.stringify(Array.from({ length: 19999 }, () => 0));
  assert.equal(((await readJson(post(under), 4 * 1024 * 1024)) as unknown[]).length, 19999);
  assert.deepEqual(await readJson(post(''), 1024, {}), {});
  await assert.rejects(readJson(post(''), 1024), { message: 'the body is not JSON' });
});

test('a body is UTF-8, its byte-order mark read once: two are no JSON', async () => {
  assert.deepEqual(await readJson(post('﻿{"a":1}'), 1024), { a: 1 });
  await assert.rejects(readJson(post('﻿﻿{"a":1}'), 1024), { code: 'bad_request', message: 'the body is not JSON' });
  await assert.rejects(readLimitedText(post(new Uint8Array([0x7b, 0xff, 0x7d])), 1024), { code: 'bad_request', message: 'the body is not UTF-8' });
});

test('a body is abandoned soon after the cap, its stream cancelled, not drained to the end', async () => {
  const { body, seen } = endless();
  await assert.rejects(readLimitedText(post(body, { duplex: 'half' } as RequestInit), 4 * 1024), { message: 'the body is larger than 4096 bytes' });
  assert.ok(seen.pulled <= 8, `the stream was abandoned soon after the cap, not drained (pulled ${seen.pulled} chunks)`);
  assert.equal(seen.cancelled, true);
});

test("both device-login endpoints, which anyone may call, refuse a body over 4 KiB, and ask nothing of the vault", async () => {
  for (const path of ['/api/auth/device', '/api/auth/device/token']) {
    app.calls.length = 0;
    const body = JSON.stringify({ client_label: 'x', device_code: 'a'.repeat(32 * 1024) });
    const response = await app.request(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body });
    assert.deepEqual([response.status, await response.json(), app.calls], [400, { error: 'bad_request', message: 'the body is larger than 4096 bytes' }, []], path);
    // An endless one, too: cancelled, not read to the end.
    const { body: stream, seen } = endless(64 * 1024);
    const streamed = await app.request(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: stream, duplex: 'half' } as RequestInit);
    assert.deepEqual([streamed.status, seen.cancelled, app.calls], [400, true, []], path);
  }
  // Under the cap, the poll is read and asked of the vault.
  app.calls.length = 0;
  await app.request('/api/auth/device/token', { method: 'POST', body: JSON.stringify({ device_code: 'a'.repeat(43) }) });
  assert.deepEqual(app.calls, ['change']);
});

test("the API reads a body under its 1 MiB cap before the vault is asked who is calling: an endless one is refused at once and cancelled", async () => {
  app.calls.length = 0;
  const { body, seen } = endless(64 * 1024);
  const answered = await Promise.race([
    app.request('/api/reveals', { method: 'POST', headers: { authorization: 'Bearer nobody', 'content-type': 'application/json' }, body, duplex: 'half' } as RequestInit),
    new Promise<null>((resolve) => setTimeout(() => resolve(null), 5000)),
  ]);
  assert.ok(answered !== null, 'the body was read to the end');
  assert.deepEqual([answered.status, ((await answered.json()) as { message: string }).message], [400, 'the body is larger than 1048576 bytes']);
  assert.ok(seen.cancelled, 'the body was not cancelled');
  assert.ok(seen.pulled <= 20, `pulled ${seen.pulled} chunks`);
  assert.deepEqual(app.calls, []);
});
