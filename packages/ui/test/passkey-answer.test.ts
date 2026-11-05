import test from 'node:test';
import assert from 'node:assert/strict';

import { passkeyAnswer, sendPasskey } from '../src/lib/passkey-answer.ts';

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

test("a 409 or 401 whose body did not arrive whole is no refusal read: the step is kept (review r7 of #500)", async () => {
  const cut = (status: number) => Promise.resolve(new Response('{"error":"conflict","reason":', { status }));
  assert.deepEqual(await passkeyAnswer(cut(409)), { kind: 'unavailable' });
  assert.deepEqual(await passkeyAnswer(cut(401)), { kind: 'unavailable' });
  // A status none of whose refusals keeps the step ends it, read or not.
  assert.deepEqual(await passkeyAnswer(cut(400)), { kind: 'refused', code: undefined });
});

test("an answer coffre did not answer is sent again, the same, never asked of the authenticator again: a second create() could replace the passkey the first one added (review r7 of #500)", async () => {
  let asked = 0;
  const ask = async () => `{"response":"passkey ${++asked}"}`;
  const sent: string[] = [];
  const answers = [
    () => Promise.reject(new TypeError('Failed to fetch')),
    () => json({ error: 'unavailable' }, 503),
    () => json({ error: 'passkey_exists' }, 400),
    () => json({ error: 'passkey_failed' }, 401),
    () => json({ next: '/projects' }, 200),
  ];
  const send = (body: string) => {
    sent.push(body);
    return answers[sent.length - 1]!();
  };

  // Lost on the way, then a 503: the same passkey both times, the authenticator asked once.
  const page = { body: null };
  assert.deepEqual(await sendPasskey(page, ask, send), { kind: 'unavailable' });
  assert.deepEqual(await sendPasskey(page, ask, send), { kind: 'unavailable' });
  // The first had committed: the server ends the step, and the key on the device is the one it holds.
  assert.deepEqual(await sendPasskey(page, ask, send), { kind: 'refused', code: 'passkey_exists' });
  assert.equal(asked, 1);
  assert.deepEqual(sent, Array(3).fill('{"response":"passkey 1"}'));

  // A refusal that keeps the step drops the answer it refused: the next press asks for another.
  const again = { body: null };
  assert.deepEqual(await sendPasskey(again, ask, send), { kind: 'refused', code: 'passkey_failed' });
  assert.deepEqual(await sendPasskey(again, ask, send), { kind: 'ok', value: { next: '/projects' } });
  assert.equal(asked, 3);
});

test("a press the authenticator did not answer, cancelled or timed out, is forgotten: the next asks again, and sends nothing before", async () => {
  let asked = 0;
  const sent: string[] = [];
  const unsent = { body: null };
  const send = (body: string) => {
    sent.push(body);
    return json({ next: '/projects' }, 200);
  };
  await assert.rejects(sendPasskey(unsent, () => Promise.reject(new DOMException('cancelled', 'NotAllowedError')), send), { name: 'NotAllowedError' });
  assert.deepEqual(unsent, { body: null });
  assert.deepEqual(await sendPasskey(unsent, async () => `{"response":"passkey ${++asked}"}`, send), { kind: 'ok', value: { next: '/projects' } });
  assert.deepEqual(sent, ['{"response":"passkey 1"}']);
});
