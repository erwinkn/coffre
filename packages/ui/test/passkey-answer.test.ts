import test from 'node:test';
import assert from 'node:assert/strict';

import { lifetime, memoryKeeper, passkeyAnswer, sendPasskey, storedKeeper, type KeptStorage } from '../src/lib/passkey-answer.ts';

const MINUTES_5 = 5 * 60 * 1000;
/** A moment at which both of the browser's clocks read `ms`. */
const at = (ms: number) => ({ wall: ms, elapsed: ms });
/** A step whose GET left and came back at 0, with five minutes left of it. */
const FIVE_MINUTES = lifetime(at(0), at(0), MINUTES_5);

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
  const page = memoryKeeper(FIVE_MINUTES, () => at(0));
  assert.deepEqual(await sendPasskey(page, ask, send), { kind: 'unavailable' });
  assert.deepEqual(await sendPasskey(page, ask, send), { kind: 'unavailable' });
  // The first had committed: the server ends the step, and the key on the device is the one it holds.
  assert.deepEqual(await sendPasskey(page, ask, send), { kind: 'refused', code: 'passkey_exists' });
  assert.equal(asked, 1);
  assert.deepEqual(sent, Array(3).fill('{"response":"passkey 1"}'));

  // A refusal that keeps the step drops the answer it refused: the next press asks for another.
  const again = memoryKeeper(FIVE_MINUTES, () => at(0));
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
  const clock = () => at(now);
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

  // A tab closed mid-create() leaves `asking`, which lapses with the step; the next keeper made, another step's,
  // removes every lapsed entry.
  storedKeeper(shared, 'challenge-4', FIVE_MINUTES, clock).write({ kind: 'asking' });
  assert.deepEqual(await sendPasskey(storedKeeper(shared, 'challenge-4', FIVE_MINUTES, clock), ask, send), { kind: 'elsewhere' });
  now += MINUTES_5;
  storedKeeper(shared, 'challenge-5', lifetime(at(now), at(now), MINUTES_5), clock);
  assert.deepEqual([...shared.entries.keys()], ['coffre.passkey.challenge-5']);
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
  for (const kept of [storedKeeper(null, 'c', FIVE_MINUTES, () => at(0)), storedKeeper(refusing, 'c', FIVE_MINUTES, () => at(0))]) {
    let asked = 0;
    const replies = [json({ error: 'unavailable' }, 503), json({ next: '/' }, 200)];
    assert.deepEqual(await sendPasskey(kept, async () => `${++asked}`, () => replies.shift()!), { kind: 'unavailable' });
    assert.deepEqual(await sendPasskey(kept, async () => `${++asked}`, () => replies.shift()!), { kind: 'ok', value: { next: '/' } });
    assert.equal(asked, 1);
  }
});

test("a storage that reads but will not write leaves the step to the page's memory: the answer the write lost is sent again, never asked for again (review r9 of #500)", async () => {
  // Full from the start (`QuotaExceededError` on every write, the keeper's first, which pushes the entry's `until`,
  // included), from the press's first, or from its second, `asking` already stored.
  for (const failFrom of [1, 2, 3]) {
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
    const page = storedKeeper(full, 'c', FIVE_MINUTES, () => at(0));
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
    if (failFrom === 3) assert.deepEqual(await sendPasskey(storedKeeper(shared, 'c', FIVE_MINUTES, () => at(0)), async () => `passkey ${++asked}`, send), { kind: 'elsewhere' });
    assert.equal(asked, 1);
  }
});

test("a page left open past its step's lifetime asks the authenticator for nothing, whatever the storage forgot: a create() then could replace the passkey another tab added (review r9 of #500)", async () => {
  const shared = storage();
  let now = 0;
  const clock = () => at(now);
  let asked = 0;
  const ask = async () => `passkey ${++asked}`;
  const send = () => json({ next: '/projects' }, 200);

  // Tab A's GET took 10 ms there and back; tab B's left 5 ms later and took 10 ms too. Both are told five minutes left.
  const a = storedKeeper(shared, 'challenge', lifetime(at(0), at(10), MINUTES_5), clock);
  const b = storedKeeper(shared, 'challenge', lifetime(at(5), at(15), MINUTES_5), clock);
  assert.deepEqual(await sendPasskey(a, ask, send), { kind: 'ok', value: { next: '/projects' } });
  // Past A's `ends`, before B's: B may still ask, and the entry, kept to B's `endedBy`, says the step was answered.
  now = MINUTES_5 + 2;
  assert.deepEqual(await sendPasskey(b, ask, send), { kind: 'refused', code: 'state_mismatch' });
  // Past every `endedBy` the entry is gone, as is the step: B, a page restored from the back-forward cache, a tab of
  // another sign-in's making, ends without asking.
  now = MINUTES_5 + 60_000;
  storedKeeper(shared, 'another', lifetime(at(now), at(now), MINUTES_5), clock);
  assert.deepEqual([...shared.entries.keys()].filter((key) => key.endsWith('.challenge')), []);
  assert.deepEqual(await sendPasskey(b, ask, send), { kind: 'refused', code: 'state_mismatch' });
  assert.deepEqual(await sendPasskey(storedKeeper(shared, 'challenge', lifetime(at(5), at(15), MINUTES_5), clock), ask, send), { kind: 'refused', code: 'state_mismatch' });
  // A touch's page alike.
  assert.deepEqual(await sendPasskey(memoryKeeper(lifetime(at(5), at(15), MINUTES_5), clock), ask, send), { kind: 'refused', code: 'state_mismatch' });
  assert.equal(asked, 1);
});

test("a clock corrected between two tabs' GETs neither drops the entry before the later tab's step ends nor keeps a step past either clock (review r10 of #500)", async () => {
  const shared = storage();
  // Real time, in ms since tab A's GET; the wall clock, moved 60 s ahead at 10 s; each tab's elapsed clock, its own.
  let real = 0;
  let correction = 0;
  const wall = () => real + correction;
  const tabA = () => ({ wall: wall(), elapsed: 1_000 + real });
  const tabB = () => ({ wall: wall(), elapsed: real - 10_000 });
  let asked = 0;
  const ask = async () => `passkey ${++asked}`;
  const replies = [() => Promise.reject(new TypeError('Failed to fetch')), () => json({ error: 'passkey_exists' }, 400)];
  const sent: string[] = [];
  const send = (body: string) => (sent.push(body), replies.shift()!());

  // A's GET at 0, five minutes left: its wall clock says the step ends at 300 s.
  const a = storedKeeper(shared, 'challenge', lifetime(tabA(), tabA(), MINUTES_5), tabA);
  real = 10_000;
  correction = 60_000;
  // B's GET at 10 s, 290 s left, after the correction: on the wall clock, the step ends at 360 s for B.
  const b = storedKeeper(shared, 'challenge', lifetime(tabB(), tabB(), MINUTES_5 - 10_000), tabB);
  // A's enrollment commits; its answer is lost.
  assert.deepEqual(await sendPasskey(a, ask, send), { kind: 'unavailable' });
  // 250 s: past A's 300 s on the wall clock (310 s), before B's end. Another step's tab removes no entry of this one,
  // and B sends A's passkey again rather than make another: the server ends the step, the device's key the one coffre holds.
  real = 250_000;
  storedKeeper(shared, 'another', lifetime(tabB(), tabB(), MINUTES_5), tabB);
  assert.ok(shared.entries.has('coffre.passkey.challenge'));
  assert.deepEqual(await sendPasskey(b, ask, send), { kind: 'refused', code: 'passkey_exists' });
  assert.equal(asked, 1);
  assert.deepEqual(sent, ['passkey 1', 'passkey 1']);

  // A reload of the step after a correction past the entry's `until` reads it all the same: only a tab of another step
  // removes a lapsed entry. A's next step's answer is lost at 0; the clock moves 400 s ahead; the reload, told 290 s
  // left, sends A's passkey again.
  real = 0;
  correction = 0;
  const a2 = storedKeeper(shared, 'challenge-2', lifetime(tabA(), tabA(), MINUTES_5), tabA);
  replies.push(() => Promise.reject(new TypeError('Failed to fetch')), () => json({ error: 'passkey_exists' }, 400));
  assert.deepEqual(await sendPasskey(a2, ask, send), { kind: 'unavailable' });
  real = 10_000;
  correction = 400_000;
  const reload = storedKeeper(shared, 'challenge-2', lifetime(tabB(), tabB(), MINUTES_5 - 10_000), tabB);
  assert.deepEqual(await sendPasskey(reload, ask, send), { kind: 'refused', code: 'passkey_exists' });
  assert.equal(asked, 2);
  assert.deepEqual(sent.slice(2), ['passkey 2', 'passkey 2']);

  // Either clock ends a step: the wall clock moved back ten minutes leaves the elapsed one to end it; a sleep, which
  // stops the elapsed clock, leaves the wall clock to.
  const back = memoryKeeper(lifetime(at(0), at(0), MINUTES_5), () => ({ wall: MINUTES_5 - 600_000, elapsed: MINUTES_5 }));
  assert.deepEqual(await sendPasskey(back, ask, send), { kind: 'refused', code: 'state_mismatch' });
  const slept = memoryKeeper(lifetime(at(0), at(0), MINUTES_5), () => ({ wall: MINUTES_5, elapsed: 1_000 }));
  assert.deepEqual(await sendPasskey(slept, ask, send), { kind: 'refused', code: 'state_mismatch' });
  assert.equal(asked, 2);
});
