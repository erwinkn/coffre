import test from 'node:test';
import assert from 'node:assert/strict';

import { authenticatorError, deadlineOf, lapsed, passkeyAnswer, readClock, sendPasskey, withinDeadline, type Clock } from '../src/lib/passkey-answer.ts';

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
  assert.equal(unsent.body, null);
  assert.deepEqual(await sendPasskey(unsent, async () => `{"response":"passkey ${++asked}"}`, send), { kind: 'ok', value: { next: '/projects' } });
  assert.deepEqual(sent, ['{"response":"passkey 1"}']);
});

test("a new passkey's options are asked of the authenticator once: refused after a lost answer, the next press asks coffre for new options, never create() again (review r13 of #500)", async () => {
  let asked = 0;
  const ask = async () => `{"response":"passkey ${++asked}"}`;
  const sent: string[] = [];
  // Tab A's POST commits, its answer lost; tab B's sign-in replaces the pending cookie, and A's answer, sent again,
  // fails B's challenge.
  const answers = [() => Promise.reject(new TypeError('Failed to fetch')), () => json({ error: 'passkey_failed' }, 401)];
  const send = (body: string) => {
    sent.push(body);
    return answers[sent.length - 1]!();
  };
  const page = { body: null, asked: false };
  assert.deepEqual(await sendPasskey(page, ask, send, { once: true }), { kind: 'unavailable' });
  assert.deepEqual(await sendPasskey(page, ask, send, { once: true }), { kind: 'refused', code: 'passkey_failed' });
  // A second create() would name the handle coffre now holds: the press asks nothing and sends nothing.
  assert.deepEqual(await sendPasskey(page, ask, send, { once: true }), { kind: 'stale' });
  assert.equal(asked, 1);
  assert.equal(sent.length, 2);
  // New options, a new step: one create() of their own.
  const fresh = { body: null, asked: false };
  answers.push(() => json({ next: '/projects' }, 200));
  assert.deepEqual(await sendPasskey(fresh, ask, send, { once: true }), { kind: 'ok', value: { next: '/projects' } });
  assert.equal(asked, 2);
});

test("a press after the step's five minutes asks the authenticator nothing, by either clock; before them, the authenticator is given what is left (review r14 of #500)", async () => {
  const FIVE_MINUTES = 5 * 60_000;
  let wall = 1_000_000;
  let elapsed = 50;
  const clock: Clock = { wall: () => wall, elapsed: () => elapsed };
  const lefts: number[] = [];
  const ask = async (left: number) => {
    lefts.push(left);
    return `{"response":"passkey ${lefts.length}"}`;
  };
  const sent: string[] = [];
  const send = (body: string) => {
    sent.push(body);
    return json({ next: '/projects' }, 200);
  };
  // The GET was sent at (wall, elapsed); the server answered with its five minutes.
  const step = () => ({ body: null, asked: false, ends: deadlineOf(readClock(clock), FIVE_MINUTES) });

  // Pressed a minute later: the authenticator has four minutes, not the five the GET said.
  const early = step();
  wall += 60_000;
  elapsed += 60_000;
  assert.deepEqual(await sendPasskey(early, ask, send, { once: true, clock }), { kind: 'ok', value: { next: '/projects' } });
  assert.deepEqual(lefts, [4 * 60_000]);

  // Left open past five minutes, by both clocks: nothing asked, nothing sent.
  const late = step();
  wall += FIVE_MINUTES + 1;
  elapsed += FIVE_MINUTES + 1;
  assert.deepEqual(await sendPasskey(late, ask, send, { once: true, clock }), { kind: 'expired' });

  // The wall clock set back an hour while the page sat open: the elapsed clock still ends the step.
  const setBack = step();
  wall -= 60 * 60_000;
  elapsed += FIVE_MINUTES;
  assert.deepEqual(await sendPasskey(setBack, ask, send, { clock }), { kind: 'expired' });

  // Elapsed time that stood still while the machine slept: the wall clock ends it.
  const slept = step();
  wall += FIVE_MINUTES;
  assert.deepEqual(await sendPasskey(slept, ask, send, { clock }), { kind: 'expired' });

  assert.equal(lefts.length, 1);
  assert.equal(sent.length, 1);
});

test("an answer coffre did not answer is still sent again past the deadline: the server, not the page, says the step ended", async () => {
  let wall = 0;
  const clock: Clock = { wall: () => wall, elapsed: () => wall };
  let asked = 0;
  const answers = [() => Promise.reject(new TypeError('Failed to fetch')), () => json({ error: 'state_mismatch' }, 404)];
  const sent: string[] = [];
  const send = (body: string) => {
    sent.push(body);
    return answers[sent.length - 1]!();
  };
  const page = { body: null, asked: false, ends: deadlineOf(readClock(clock), 60_000) };
  assert.deepEqual(await sendPasskey(page, async () => `{"response":"passkey ${++asked}"}`, send, { once: true, clock }), { kind: 'unavailable' });
  wall += 120_000;
  // Its first POST may have committed: the same answer again lets the server end the step, `passkey_exists` or this.
  assert.deepEqual(await sendPasskey(page, async () => `{"response":"passkey ${++asked}"}`, send, { once: true, clock }), { kind: 'refused', code: 'state_mismatch' });
  assert.equal(asked, 1);
  assert.deepEqual(sent, ['{"response":"passkey 1"}', '{"response":"passkey 1"}']);
});

test("an RP ID the browser refuses names the setting to fix (Sol r15, #500)", () => {
  // Chromium refuses `co.uk` for https://coffre.acme.co.uk with a SecurityError: a public suffix, which coffre's
  // startup check leaves to the browser's list.
  const said = authenticatorError(new DOMException('The relying party ID is not a registrable domain suffix of, nor equal to the current domain.', 'SecurityError'), 'co.uk');
  assert.match(said, /no passkey for co\.uk/);
  assert.match(said, /passkeys\.rpId/);
  assert.match(authenticatorError(new DOMException('cancelled', 'NotAllowedError'), 'acme.co.uk'), /No passkey answered/);
  assert.match(authenticatorError(new DOMException('held', 'InvalidStateError'), 'acme.co.uk'), /already holds a passkey/);
  assert.match(authenticatorError(new TypeError('no WebAuthn'), 'acme.co.uk'), /could not use a passkey/);
});

test("the page ends the authenticator's call at the step's deadline, whatever the browser makes of the timeout: Chromium stretches one under three minutes (review r2 of #539)", async () => {
  // A browser that waits until it is aborted, as Chromium does with `timeout: 1000` and a person still choosing.
  const waits = (signal: AbortSignal) =>
    new Promise<string>((_, reject) => signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError'))));
  // Held to a second of its own, so a call never ended fails rather than hangs.
  let guard: ReturnType<typeof setTimeout> | undefined;
  const never = new Promise<never>((_, reject) => {
    guard = setTimeout(() => reject(new Error('the call was never ended')), 1000);
  });
  await assert.rejects(Promise.race([withinDeadline(20, waits), never]), { name: 'TimeoutError' });
  clearTimeout(guard);
  // An answer that came first is kept; a refusal that came first is the browser's own.
  assert.equal(await withinDeadline(1000, async () => 'answer'), 'answer');
  await assert.rejects(withinDeadline(1000, async () => Promise.reject(new DOMException('cancelled', 'NotAllowedError'))), { name: 'NotAllowedError' });
  assert.match(authenticatorError(lapsed(), 'acme.example'), /lapsed/);

  // Ended so, a press is `expired`: nothing sent, and the page asks coffre for new options.
  const sent: string[] = [];
  const unsent = { body: null, asked: false };
  const answer = await sendPasskey(unsent, () => withinDeadline(5, waits), (body) => {
    sent.push(body);
    return json({}, 200);
  }, { once: true });
  assert.deepEqual(answer, { kind: 'expired' });
  assert.deepEqual(sent, []);
  assert.equal(unsent.asked, false);
});
