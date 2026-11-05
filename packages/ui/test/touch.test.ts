import test from 'node:test';
import assert from 'node:assert/strict';

import { CoffreError } from '@coffre/client';

import { pressTouch, touchMessage, type HeldTouch, type TouchAnswer } from '../src/lib/touch.ts';
import type { RequestJSON } from '../src/lib/webauthn.ts';

const options = (challenge: string): RequestJSON => ({ challenge, rpId: 'secrets.acme.example', allowCredentials: [], userVerification: 'required', timeout: 300_000 });
const asking = (challenge: string) => new CoffreError(403, 'touch_required', 'approving a terminal takes a touch of your passkey', undefined, undefined, { options: options(challenge), state: `state-${challenge}` });

/** An act's route as the server answers it: `touch_required` until it carries a touch, answered with what it was sent. */
function route(answers: ((touch?: TouchAnswer) => unknown)[]) {
  const sent: (TouchAnswer | undefined)[] = [];
  return {
    sent,
    send: async (touch?: TouchAnswer) => {
      sent.push(touch);
      const answer = answers.shift()!(touch);
      if (answer instanceof Error) throw answer;
      return answer;
    },
  };
}

test('an act sent, refused touch_required, is sent again with a touch for the options the refusal carried', async () => {
  const held: HeldTouch = { asked: null };
  const asked: string[] = [];
  const act = route([() => asking('c1'), (touch) => ({ approved: touch!.state })]);
  const done = await pressTouch(held, act.send, async (given) => {
    asked.push(given.challenge);
    return { id: 'key' };
  });
  assert.deepEqual(done, { approved: 'state-c1' });
  assert.deepEqual(asked, ['c1']);
  assert.deepEqual(act.sent, [undefined, { state: 'state-c1', response: { id: 'key' } }]);
  assert.equal(held.asked, null);
});

test('a person who holds no passkey is asked nothing: the act goes on its first send', async () => {
  const act = route([() => ({ approved: true })]);
  assert.deepEqual(await pressTouch({ asked: null }, act.send, () => assert.fail('the authenticator was asked')), { approved: true });
  assert.deepEqual(act.sent, [undefined]);
});

test("an authenticator that throws keeps the ask, and the next press asks it first, inside its own click, sending nothing before", async () => {
  const held: HeldTouch = { asked: null };
  const act = route([() => asking('c1'), (touch) => ({ approved: touch!.state })]);
  const refused = new DOMException('not allowed', 'NotAllowedError');
  await assert.rejects(pressTouch(held, act.send, async () => { throw refused; }), refused);
  assert.equal(held.asked?.state, 'state-c1');
  assert.match(touchMessage(refused, held.asked?.options.rpId)!, /No passkey answered/);

  const asked: string[] = [];
  const done = await pressTouch(held, act.send, async (given) => {
    asked.push(given.challenge);
    return { id: 'key' };
  });
  assert.deepEqual(done, { approved: 'state-c1' });
  assert.deepEqual(asked, ['c1']);
  assert.equal(act.sent.length, 2, 'the second press sent once, with its touch');
});

test('a touch that came too late is asked again on the next press, once per press', async () => {
  const held: HeldTouch = { asked: null };
  const act = route([() => asking('c1'), () => asking('c2'), (touch) => ({ approved: touch!.state })]);
  let asks = 0;
  const ask = async () => {
    asks += 1;
    return { id: 'key' };
  };
  const late = await pressTouch(held, act.send, ask).then(() => null, (error: unknown) => error);
  assert.ok(late instanceof CoffreError && late.code === 'touch_required');
  assert.equal(asks, 1, 'one ask per press');
  assert.equal(held.asked?.state, 'state-c2');
  assert.match(touchMessage(late, undefined)!, /too late/);
  assert.deepEqual(await pressTouch(held, act.send, ask), { approved: 'state-c2' });
});

test("any other refusal is the act's to say, and holds no ask", async () => {
  const held: HeldTouch = { asked: null };
  const gone = new CoffreError(404, 'not_found', 'that code is unknown or has expired');
  const failed = new CoffreError(403, 'touch_failed', 'that passkey did not confirm it: try again');
  await assert.rejects(pressTouch(held, route([() => gone]).send, () => assert.fail('asked')), gone);
  assert.equal(touchMessage(gone, undefined), null);
  await assert.rejects(pressTouch(held, route([() => asking('c1'), () => failed]).send, async () => ({ id: 'key' })), failed);
  assert.equal(held.asked, null, 'a touch that failed asks afresh on the next press');
  assert.equal(touchMessage(failed, undefined), null);
});

test('a held ask lapses with its options: the press after drops it and asks with the new ones, never the expired challenge', async () => {
  let now = 1_000;
  const clock = { wall: () => now, elapsed: () => now };
  const held: HeldTouch = { asked: null };
  const act = route([() => asking('c1'), () => asking('c2'), (touch) => ({ approved: touch!.state })]);
  const cancelled = new DOMException('cancelled', 'NotAllowedError');
  await assert.rejects(pressTouch(held, act.send, async () => { throw cancelled; }, clock), cancelled);
  assert.equal(held.asked?.state, 'state-c1');

  now += 60_000;
  const timeouts: number[] = [];
  const asked: string[] = [];
  const ask = async (given: RequestJSON) => {
    asked.push(given.challenge);
    timeouts.push(given.timeout);
    throw cancelled;
  };
  await assert.rejects(pressTouch(held, act.send, ask, clock), cancelled);
  assert.deepEqual(timeouts, [240_000], 'a held ask waits only what is left of its five minutes');

  now += 240_001;
  asked.length = 0;
  const done = await pressTouch(held, act.send, async (given) => {
    asked.push(given.challenge);
    return { id: 'key' };
  }, clock);
  assert.deepEqual(asked, ['c2'], 'the lapsed c1 was never asked');
  assert.deepEqual(done, { approved: 'state-c2' });
  assert.deepEqual(act.sent.map((touch) => touch?.state), [undefined, undefined, 'state-c2']);
});
