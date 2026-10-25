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

test('a request that fails is said with how long it waited, and fails as it did', async () => {
  const said: string[] = [];
  const down = timed(async () => {
    throw new TypeError('fetch failed');
  }, (line) => said.push(line), "GitHub's ID token");
  await assert.rejects(down('https://pipelines.actions.githubusercontent.com/abc?audience=x'), /fetch failed/);
  assert.match(said[0]!, /^GitHub's ID token: failed after \d+ ms \(fetch failed\)$/);
});

test('a duration reads in milliseconds under a second, in tenths of seconds above', () => {
  assert.equal(took(245.4), '245 ms');
  assert.equal(took(15_826), '15.8 s');
  assert.equal(took(1000), '1.0 s');
});
