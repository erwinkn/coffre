import test from 'node:test';
import assert from 'node:assert/strict';

import { timed, took } from '../src/timings.ts';

test('each request is said once answered: its method, path, status and time, never its query, headers or body', async () => {
  const said: string[] = [];
  const answered = timed(async () => Response.json({ value: 'fake-secret' }, { status: 201 }), (line) => said.push(line));
  await answered(new Request('https://secrets.acme.example/api/reveals?token=fake-query', {
    method: 'POST', headers: { authorization: 'Bearer coffre_svc_fake' }, body: JSON.stringify({ path: 'ci/prod' }),
  }));
  await answered('https://secrets.acme.example/api/secrets/ci/prod?keys=A');
  assert.equal(said.length, 2);
  assert.match(said[0]!, /^POST \/api\/reveals: 201 in \d+ ms$/);
  assert.match(said[1]!, /^GET \/api\/secrets\/ci\/prod: 201 in \d+ ms$/);
  assert.doesNotMatch(said.join('\n'), /fake|token|Bearer/);
});

test("a request that fails is said with how long it waited and the network's code, never the error's words, and fails as it did", async () => {
  const said: string[] = [];
  const say = (line: string) => void said.push(line);
  const refused = timed(async () => {
    throw new TypeError('fetch failed', { cause: Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:1'), { code: 'ECONNREFUSED' }) });
  }, say, "GitHub's ID token");
  await assert.rejects(refused('https://pipelines.actions.githubusercontent.com/abc?audience=x'), /fetch failed/);
  // An invalid header's error quotes it: a credential with a stray newline would be in the log.
  const invalid = timed(async () => {
    throw new TypeError('Headers.append: "Bearer coffre_svc_fake\n" is an invalid header value.');
  }, say);
  await assert.rejects(invalid('https://secrets.acme.example/api/me'), /invalid header value/);
  assert.deepEqual(said.map((line) => line.replace(/\d+ ms/, 'n ms')), ["GitHub's ID token: failed after n ms (ECONNREFUSED)", 'GET /api/me: failed after n ms (TypeError)']);
});

test("a credential proxy's path is said as far as its credential: the rest is the app's", async () => {
  const said: string[] = [];
  const proxied = timed(async () => new Response(null, { status: 204 }), (line) => void said.push(line));
  await proxied('https://secrets.acme.example/use/telegram/botcoffre_use_fake/sendMessage', { method: 'POST' });
  await proxied('https://secrets.acme.example/use');
  await proxied('https://secrets.acme.example/use/stripe');
  assert.deepEqual(said.map((line) => line.replace(/ in .*/, '')), ['POST /use/telegram/…: 204', 'GET /use: 204', 'GET /use/stripe: 204']);
});

test('a duration reads in milliseconds under a second, in tenths of seconds above', () => {
  assert.equal(took(245.4), '245 ms');
  assert.equal(took(15_826), '15.8 s');
  assert.equal(took(1000), '1.0 s');
});
