import test from 'node:test';
import assert from 'node:assert/strict';

import { passkeyAnswer } from '../src/lib/passkey-answer.ts';

const json = (body: unknown, status: number) => Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }));

test('a passkey step: what to ask, or the session it ended in', async () => {
  assert.deepEqual(await passkeyAnswer(json({ purpose: 'signin' }, 200)), { kind: 'ok', value: { purpose: 'signin' } });
  assert.deepEqual(await passkeyAnswer(json({ next: '/projects' }, 200)), { kind: 'ok', value: { next: '/projects' } });
});

test("the server's refusals end the step, with their code", async () => {
  // GET with nothing waiting, and the POST's refusals (auth-routes.ts, `PASSKEY_REFUSED`).
  assert.deepEqual(await passkeyAnswer(json({ error: 'state_mismatch', message: 'expired' }, 404)), { kind: 'refused', code: 'state_mismatch' });
  assert.deepEqual(await passkeyAnswer(json({ error: 'passkey_failed' }, 401)), { kind: 'refused', code: 'passkey_failed' });
  assert.deepEqual(await passkeyAnswer(json({ error: 'tampered' }, 400)), { kind: 'refused', code: 'tampered' });
  assert.deepEqual(await passkeyAnswer(Promise.resolve(new Response('<html>', { status: 403 }))), { kind: 'refused', code: undefined });
});

test('no answer to go by keeps the step: the sign-in still waits (Sol r4, #500)', async () => {
  const unavailable = { kind: 'unavailable' };
  assert.deepEqual(await passkeyAnswer(json({ error: 'unavailable' }, 503)), unavailable);
  assert.deepEqual(await passkeyAnswer(json({ error: 'migrating' }, 503)), unavailable);
  assert.deepEqual(await passkeyAnswer(json({ error: 'internal_error' }, 500)), unavailable);
  assert.deepEqual(await passkeyAnswer(Promise.resolve(new Response('Bad Gateway', { status: 502 }))), unavailable);
  assert.deepEqual(await passkeyAnswer(json({ error: 'too_many_requests' }, 429)), unavailable);
  assert.deepEqual(await passkeyAnswer(Promise.resolve(new Response('', { status: 408 }))), unavailable);
  assert.deepEqual(await passkeyAnswer(Promise.reject(new TypeError('Failed to fetch'))), unavailable);
  assert.deepEqual(await passkeyAnswer(Promise.resolve(new Response('not json', { status: 200 }))), unavailable);
});

test("a change that came between every try asks again, the sign-in kept (Sol r6, #500)", async () => {
  // `ObjectMoved` once `retrying`'s tries are spent: the pending sign-in's cookie stands, and the same answer may pass.
  assert.deepEqual(await passkeyAnswer(json({ error: 'conflict', message: 'try again', reason: 'changed' }, 409)), { kind: 'unavailable' });
  // Any other conflict is the server's refusal.
  assert.deepEqual(await passkeyAnswer(json({ error: 'conflict', message: 'taken' }, 409)), { kind: 'refused', code: 'conflict' });
});
