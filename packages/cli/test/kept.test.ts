// The lock one token's runs take while one exchanges it (`kept.ts`): its holder's alone, kept fresh while held, and
// taken over only once its run stopped keeping it so (review r1 of #561).
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, rmSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { keptFor } from '../src/kept.ts';

const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const TOKEN = `${part({ alg: 'RS256' })}.${part({ sub: 'x', exp: Math.floor(Date.now() / 1000) + 3600 })}.c2ln`;

function kept(t: test.TestContext) {
  const home = mkdtempSync(join(tmpdir(), 'coffre-kept-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const directory = join(home, '.coffre', 'sessions');
  const each = () => keptFor(directory, 'https://secrets.acme.example', 'capy-agent', TOKEN)!;
  const lock = () => join(directory, readdirSync(directory).find((name) => name.endsWith('.lock'))!);
  return { each, lock, locks: () => readdirSync(directory).filter((name) => name.includes('.lock')) };
}

/** Whether `promise` settles within `ms`. */
const within = (promise: Promise<unknown>, ms: number) => Promise.race([promise.then(() => true), new Promise((resolve) => setTimeout(() => resolve(false), ms))]);

test('a run waits for the one holding the lock, and goes on once it releases it', async (t) => {
  const { each, locks } = kept(t);
  const release = await each().hold();
  const next = each().hold();
  assert.equal(await within(next, 300), false, 'the second waits');
  release();
  assert.equal(await within(next, 1_000), true, 'and holds it once released');
  (await next)();
  assert.deepEqual(locks(), []);
});

test("a lock its run stopped keeping fresh is taken over; that run's release then leaves the new holder's, and a third run waits for it", async (t) => {
  const { each, lock, locks } = kept(t);
  const stalled = await each().hold();
  // The run stalled past the lock's life: its file as a dead run's.
  const old = new Date(Date.now() - 60_000);
  utimesSync(lock(), old, old);
  const second = each().hold();
  assert.equal(await within(second, 1_000), true, 'the stale lock is taken over');
  const released = await second;
  stalled();
  assert.equal(locks().length, 1, "the stalled run's release leaves the second's lock");
  const third = each().hold();
  assert.equal(await within(third, 300), false, 'a third waits for the second');
  released();
  assert.equal(await within(third, 1_000), true);
  (await third)();
  assert.deepEqual(locks(), []);
});
