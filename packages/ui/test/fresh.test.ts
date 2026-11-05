import test from 'node:test';
import assert from 'node:assert/strict';

import { askFresh, CALLER_HEADER, freshTransport, onFreshAsk, type FreshAsk } from '../src/lib/fresh.ts';

const ADA = 'user:0190c5a4-6e4f-7a10-8b2c-3d4e5f607182';

const refusal = (reason?: string, caller: string | null = ADA) =>
  new Response(JSON.stringify({ error: 'fresh_check_required', message: 'this takes a fresh touch of your passkey', ...(reason === undefined ? {} : { reason }), ...(caller === null ? {} : { caller }) }), { status: 403 });

/** The API as the server answers it: each request's body recorded, answered in turn. */
function server(answers: (() => Response)[]) {
  const bodies: string[] = [];
  const callers: (string | null)[] = [];
  return {
    bodies,
    callers,
    send: async (request: Request) => {
      callers.push(request.headers.get(CALLER_HEADER));
      bodies.push(await request.text());
      return answers.shift()!();
    },
  };
}

const act = () => new Request('https://secrets.acme.example/api/access/user:bob@acme.example', { method: 'PATCH', body: JSON.stringify({ role: 'owner' }) });

test('an act refused for a fresh check is sent again, the same, once the person confirmed', async () => {
  const api = server([() => refusal(), () => new Response('{"changes":{}}', { status: 200 })]);
  const asked: boolean[] = [];
  const answered = await freshTransport(api.send, async (add) => (asked.push(add), true))(act());
  assert.equal(answered.status, 200);
  assert.deepEqual(asked, [false], 'asked once, to confirm, not to add a passkey');
  assert.deepEqual(api.bodies, ['{"role":"owner"}', '{"role":"owner"}'], 'the same act, its body whole');
  assert.deepEqual(api.callers, [null, ADA], 'sent again saying who sent it first, which the server holds it to');
});

test('a refusal that names no caller is the answer: the act is never sent again unbound to its person', async () => {
  const api = server([() => refusal(undefined, null)]);
  let asked = 0;
  const answered = await freshTransport(api.send, async () => (asked++, true))(act());
  assert.equal(answered.status, 403);
  assert.deepEqual([asked, api.bodies.length], [0, 1]);
});

test('an act the person did not confirm gets its refusal, sent once; one of a person with no passkey asks to add one', async () => {
  const api = server([() => refusal('add_passkey')]);
  const asked: boolean[] = [];
  const answered = await freshTransport(api.send, async (add) => (asked.push(add), false))(act());
  assert.equal(answered.status, 403);
  assert.equal(((await answered.json()) as { reason: string }).reason, 'add_passkey', 'the page reads the refusal whole');
  assert.deepEqual(asked, [true]);
  assert.equal(api.bodies.length, 1, 'not sent again');
});

test('any other answer, another 403 included, is the answer, nothing asked; and a refusal sent again stays the answer', async () => {
  for (const answer of [
    () => new Response(JSON.stringify({ error: 'forbidden', message: 'no' }), { status: 403 }),
    () => new Response('not json', { status: 403 }),
    () => new Response('{}', { status: 200 }),
  ]) {
    const api = server([answer]);
    let asked = 0;
    const answered = await freshTransport(api.send, async () => (asked++, true))(act());
    assert.equal(asked, 0);
    assert.equal(api.bodies.length, 1);
    assert.equal(answered.status, answer().status);
  }
  // Confirmed, and refused again (the window closed between, or the touch went to another tab): one try, no loop.
  const api = server([() => refusal(), () => refusal()]);
  let asked = 0;
  const answered = await freshTransport(api.send, async () => (asked++, true))(act());
  assert.equal(answered.status, 403);
  assert.deepEqual([asked, api.bodies.length], [1, 2]);
});

test('with no dialog to ask, the refusal is the answer', async () => {
  const api = server([() => refusal()]);
  const answered = await freshTransport(api.send)(act());
  assert.equal(answered.status, 403);
  assert.equal(api.bodies.length, 1);
});

test('acts refused together share one ask, and one answer; the dialog hears each ask and its end', async () => {
  const heard: (FreshAsk | null)[] = [];
  const stop = onFreshAsk((ask) => heard.push(ask));
  const api = server([() => refusal(), () => refusal(), () => new Response('{}'), () => new Response('{}')]);
  const send = freshTransport(api.send);
  const both = Promise.all([send(act()), send(act())]);
  // Both refused, then asked: one ask, which the dialog answers.
  while (heard.filter((ask) => ask !== null).length === 0) await new Promise((resolve) => setTimeout(resolve, 1));
  await new Promise((resolve) => setTimeout(resolve, 5));
  assert.equal(heard.filter((ask) => ask !== null).length, 1, 'one ask for both');
  heard.find((ask) => ask !== null)!.settle(true);
  const answers = await both;
  assert.deepEqual(answers.map((answer) => answer.status), [200, 200], 'both sent again');
  assert.equal(heard.at(-1), null, 'the dialog closes');
  // The next refusal asks again; the old ask, settled late (the dialog's close after its touch), settles nothing of it.
  const old = heard.find((ask) => ask !== null)!;
  const next = askFresh(false);
  const asked = heard.at(-1)!;
  assert.notEqual(asked, null);
  assert.notEqual(asked, old);
  old.settle(false);
  assert.equal(heard.at(-1), asked, 'still asked');
  asked.settle(true);
  assert.equal(await next, true);
  stop();
});
