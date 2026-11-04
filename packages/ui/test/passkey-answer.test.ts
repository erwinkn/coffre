import test from 'node:test';
import assert from 'node:assert/strict';

import { lifetime, memoryKeeper, passkeyAnswer, sendPasskey, storedKeeper, type KeptStorage } from '../src/lib/passkey-answer.ts';

const MINUTES_5 = 5 * 60 * 1000;
/** A step whose GET left and came back at 0, with five minutes left of it. */
const FIVE_MINUTES = lifetime(0, 0, MINUTES_5);

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
  const page = memoryKeeper(FIVE_MINUTES, () => 0);
  assert.deepEqual(await sendPasskey(page, ask, send), { kind: 'unavailable' });
  assert.deepEqual(await sendPasskey(page, ask, send), { kind: 'unavailable' });
  // The first had committed: the server ends the step, and the key on the device is the one it holds.
  assert.deepEqual(await sendPasskey(page, ask, send), { kind: 'refused', code: 'passkey_exists' });
  assert.equal(asked, 1);
  assert.deepEqual(sent, Array(3).fill('{"response":"passkey 1"}'));

  // A refusal that keeps the step drops the answer it refused: the next press asks for another.
  const again = memoryKeeper(FIVE_MINUTES, () => 0);
  assert.deepEqual(await sendPasskey(again, ask, send), { kind: 'refused', code: 'passkey_failed' });
  assert.deepEqual(await sendPasskey(again, ask, send), { kind: 'ok', value: { next: '/projects' } });
  assert.equal(asked, 3);
});

/** `localStorage` as one browser profile holds it, shared by its tabs. */
function storage(): KeptStorage & { entries: Map<string, string> } {
  const entries = new Map<string, string>();
  return {
    entries,
    get length() {
      return entries.size;
    },
    key: (i) => [...entries.keys()][i] ?? null,
    getItem: (key) => entries.get(key) ?? null,
    setItem: (key, value) => void entries.set(key, String(value)),
    removeItem: (key) => void entries.delete(key),
  };
}

test("two tabs, or a reload, of one enrollment make one passkey: an unanswered one is sent again from any of them, an answered one ends the others, and none asks while another's create() is open (review r8 of #500)", async () => {
  const shared = storage();
  let now = 0;
  const clock = () => now;
  const tab = () => storedKeeper(shared, 'challenge-1', FIVE_MINUTES, clock);
  let asked = 0;
  const ask = async () => `{"response":"passkey ${++asked}"}`;
  const sent: string[] = [];
  const replies: (() => Promise<Response>)[] = [];
  const send = (body: string) => {
    sent.push(body);
    return replies.shift()!();
  };

  // Tab 1's answer is lost on the way; tab 2, and tab 1 reloaded, send that same passkey.
  const one = tab();
  const two = tab();
  replies.push(() => Promise.reject(new TypeError('Failed to fetch')), () => json({ error: 'unavailable' }, 503), () => json({ next: '/projects' }, 200));
  assert.deepEqual(await sendPasskey(one, ask, send), { kind: 'unavailable' });
  assert.deepEqual(await sendPasskey(two, ask, send), { kind: 'unavailable' });
  assert.deepEqual(await sendPasskey(tab(), ask, send), { kind: 'ok', value: { next: '/projects' } });
  assert.equal(asked, 1);
  assert.deepEqual(sent, Array(3).fill('{"response":"passkey 1"}'));
  // Answered: the other tabs' presses end their page, and send nothing.
  assert.deepEqual(await sendPasskey(one, ask, send), { kind: 'refused', code: 'state_mismatch' });
  assert.deepEqual(await sendPasskey(two, ask, send), { kind: 'refused', code: 'state_mismatch' });
  assert.equal(sent.length, 3);

  // Another step: tab 1's create() is open, so tab 2 asks for nothing.
  let made!: (body: string) => void;
  const open = new Promise<string>((resolve) => (made = resolve));
  const first = storedKeeper(shared, 'challenge-2', FIVE_MINUTES, clock);
  replies.push(() => json({ next: '/projects' }, 200));
  const pressed = sendPasskey(first, () => open, send);
  assert.deepEqual(await sendPasskey(storedKeeper(shared, 'challenge-2', FIVE_MINUTES, clock), ask, send), { kind: 'elsewhere' });
  made('{"response":"tab 1"}');
  assert.deepEqual(await pressed, { kind: 'ok', value: { next: '/projects' } });
  assert.equal(asked, 1);

  // A create() cancelled forgets the press: no passkey was made, and the next one asks.
  const cancelled = storedKeeper(shared, 'challenge-3', FIVE_MINUTES, clock);
  await assert.rejects(sendPasskey(cancelled, () => Promise.reject(new DOMException('cancelled', 'NotAllowedError')), send), { name: 'NotAllowedError' });
  replies.push(() => json({ next: '/projects' }, 200));
  assert.deepEqual(await sendPasskey(storedKeeper(shared, 'challenge-3', FIVE_MINUTES, clock), ask, send), { kind: 'ok', value: { next: '/projects' } });
  assert.equal(asked, 2);

  // A tab closed mid-create() leaves `asking`, which lapses with the step; the next keeper made removes every lapsed
  // entry.
  storedKeeper(shared, 'challenge-4', FIVE_MINUTES, clock).write({ kind: 'asking' });
  assert.deepEqual(await sendPasskey(storedKeeper(shared, 'challenge-4', FIVE_MINUTES, clock), ask, send), { kind: 'elsewhere' });
  now += MINUTES_5;
  storedKeeper(shared, 'challenge-5', FIVE_MINUTES, clock);
  assert.deepEqual([...shared.entries.keys()], []);
});

test('a browser that keeps no storage, or refuses it, keeps the step in the page, as review r7 did', async () => {
  const refusing: KeptStorage = {
    length: 1,
    key: () => {
      throw new DOMException('denied', 'SecurityError');
    },
    getItem: () => {
      throw new DOMException('denied', 'SecurityError');
    },
    setItem: () => {
      throw new DOMException('full', 'QuotaExceededError');
    },
    removeItem: () => {},
  };
  for (const kept of [storedKeeper(null, 'c', FIVE_MINUTES, () => 0), storedKeeper(refusing, 'c', FIVE_MINUTES, () => 0)]) {
    let asked = 0;
    const replies = [json({ error: 'unavailable' }, 503), json({ next: '/' }, 200)];
    assert.deepEqual(await sendPasskey(kept, async () => `${++asked}`, () => replies.shift()!), { kind: 'unavailable' });
    assert.deepEqual(await sendPasskey(kept, async () => `${++asked}`, () => replies.shift()!), { kind: 'ok', value: { next: '/' } });
    assert.equal(asked, 1);
  }
});

test("a storage that reads but will not write leaves the step to the page's memory: the answer the write lost is sent again, never asked for again (review r9 of #500)", async () => {
  // Full from the start (`QuotaExceededError` on every write), or from the second write on, `asking` already stored.
  for (const failFrom of [1, 2]) {
    const shared = storage();
    let writes = 0;
    const full: KeptStorage = {
      ...shared,
      get length() {
        return shared.length;
      },
      setItem: (key, value) => {
        if (++writes >= failFrom) throw new DOMException('full', 'QuotaExceededError');
        shared.setItem(key, value);
      },
    };
    const page = storedKeeper(full, 'c', FIVE_MINUTES, () => 0);
    let asked = 0;
    const replies = [json({ error: 'unavailable' }, 503), json({ error: 'passkey_exists' }, 400)];
    const sent: string[] = [];
    const send = (body: string) => (sent.push(body), replies.shift()!);
    // The enrollment committed, its answer lost: Try again sends the same passkey, which ends the step.
    assert.deepEqual(await sendPasskey(page, async () => `passkey ${++asked}`, send), { kind: 'unavailable' });
    assert.deepEqual(await sendPasskey(page, async () => `passkey ${++asked}`, send), { kind: 'refused', code: 'passkey_exists' });
    assert.equal(asked, 1);
    assert.deepEqual(sent, ['passkey 1', 'passkey 1']);
    // What the storage held stays: another tab finds this step `asking`, and asks for nothing.
    if (failFrom === 2) assert.deepEqual(await sendPasskey(storedKeeper(shared, 'c', FIVE_MINUTES, () => 0), async () => `passkey ${++asked}`, send), { kind: 'elsewhere' });
    assert.equal(asked, 1);
  }
});

test("a page left open past its step's lifetime asks the authenticator for nothing, whatever the storage forgot: a create() then could replace the passkey another tab added (review r9 of #500)", async () => {
  const shared = storage();
  let now = 0;
  const clock = () => now;
  let asked = 0;
  const ask = async () => `passkey ${++asked}`;
  const send = () => json({ next: '/projects' }, 200);

  // Tab A's GET took 10 ms there and back; tab B's left 5 ms later and took 10 ms too. Both are told five minutes left.
  const a = storedKeeper(shared, 'challenge', lifetime(0, 10, MINUTES_5), clock);
  const b = storedKeeper(shared, 'challenge', lifetime(5, 15, MINUTES_5), clock);
  assert.deepEqual(await sendPasskey(a, ask, send), { kind: 'ok', value: { next: '/projects' } });
  // Past A's `ends`, before B's: B may still ask, and A's entry, kept to A's `endedBy`, says the step was answered.
  now = MINUTES_5 + 2;
  assert.deepEqual(await sendPasskey(b, ask, send), { kind: 'refused', code: 'state_mismatch' });
  // Past every `endedBy` the entry is gone, as is the step: B, a page restored from the back-forward cache, a tab of
  // another sign-in's making, ends without asking.
  now = MINUTES_5 + 60_000;
  storedKeeper(shared, 'another', lifetime(now, now, MINUTES_5), clock);
  assert.deepEqual([...shared.entries.keys()].filter((key) => key.endsWith('.challenge')), []);
  assert.deepEqual(await sendPasskey(b, ask, send), { kind: 'refused', code: 'state_mismatch' });
  assert.deepEqual(await sendPasskey(storedKeeper(shared, 'challenge', lifetime(5, 15, MINUTES_5), clock), ask, send), { kind: 'refused', code: 'state_mismatch' });
  // A touch's page alike.
  assert.deepEqual(await sendPasskey(memoryKeeper(lifetime(5, 15, MINUTES_5), clock), ask, send), { kind: 'refused', code: 'state_mismatch' });
  assert.equal(asked, 1);
});
