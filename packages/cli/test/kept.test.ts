// The lock one token's runs take while one exchanges it (`kept.ts`): its holder's alone, kept fresh while held, and
// taken over only once its run stopped keeping it so (review r1 of #561).
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { keptFor, lockOf, takeOver, tokenExpiry } from '../src/kept.ts';

const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const TOKEN = `${part({ alg: 'RS256' })}.${part({ sub: 'x', exp: Math.floor(Date.now() / 1000) + 3600 })}.c2ln`;

function kept(t: test.TestContext) {
  const home = mkdtempSync(join(tmpdir(), 'coffre-kept-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const directory = join(home, '.coffre', 'sessions');
  const each = () => keptFor(directory, 'https://secrets.acme.example', 'capy-agent', TOKEN)!;
  const lock = () => join(directory, readdirSync(directory).find((name) => name.endsWith('.lock'))!);
  return { home, directory, each, lock, locks: () => readdirSync(directory).filter((name) => name.includes('.lock')) };
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

test("a token's exp is read to the ms, fractional seconds down, and only a positive finite one keeps a session", () => {
  const token = (payload: unknown) => `${part({ alg: 'RS256' })}.${part(payload)}.c2ln`;
  assert.equal(tokenExpiry(token({ exp: 1794358800 })), 1794358800000);
  assert.equal(tokenExpiry(token({ exp: 1794358800.2509 })), 1794358800250);
  for (const exp of [0, -1, '1794358800', null, undefined]) assert.equal(tokenExpiry(token({ exp })), null, String(exp));
  assert.equal(tokenExpiry('not.a-jwt'), null);
});

// Each contender a process of its own, as runs are: it holds the lock, takes a marker file no one else may hold at
// the same time, and gives both up; every other time it dies holding the lock instead (its file left stale), so that
// the others race to take it over, the interleaving review r2 found could hand one lock to two runs.
const CONTENDER = `
import { closeSync, openSync, rmSync, utimesSync, appendFileSync } from 'node:fs';
const [kept, directory, marker, record, rounds] = process.argv.slice(1);
const { keptFor } = await import(kept);
const token = process.env.TOKEN;
for (let i = 0; i < Number(rounds); i++) {
  const lock = keptFor(directory, 'https://secrets.acme.example', 'capy-agent', token);
  const release = await lock.hold();
  let fd;
  try { fd = openSync(marker, 'wx'); } catch { appendFileSync(record, 'overlap\\n'); process.exit(1); }
  await new Promise((resolve) => setTimeout(resolve, 5));
  closeSync(fd);
  rmSync(marker);
  appendFileSync(record, 'held\\n');
  if (i % 2 === 0) release();
  else for (const name of (await import('node:fs')).readdirSync(directory)) {
    if (name.endsWith('.lock')) { const old = new Date(Date.now() - 60_000); utimesSync(directory + '/' + name, old, old); }
  }
}
process.exit(0);
`;

test('three runs contending for a lock, stale ones among it, never hold it at once', async (t) => {
  const { home, directory, each } = kept(t);
  (await each().hold())();
  const marker = join(home, 'marker');
  const record = join(home, 'record');
  const rounds = 12;
  const children = [0, 1, 2].map(() =>
    spawn(process.execPath, ['--input-type=module', '-e', CONTENDER, new URL('../src/kept.ts', import.meta.url).href, directory, marker, record, String(rounds)], {
      env: { ...process.env, TOKEN },
      stdio: ['ignore', 'inherit', 'inherit'],
    }),
  );
  const codes = await Promise.all(children.map(async (child) => (await once(child, 'exit'))[0]));
  const lines = readFileSync(record, 'utf8').trim().split('\n');
  assert.deepEqual(codes, [0, 0, 0], lines.join(','));
  assert.equal(lines.filter((line) => line === 'held').length, 3 * rounds);
  assert.ok(!lines.includes('overlap'));
});

test('a takeover removes only the stale lock it found: one another run made since stays, fresh or stale, and so does one whose mutex is held (review r2 of #561)', (t) => {
  const { directory } = kept(t);
  mkdirSync(directory, { recursive: true });
  const lock = join(directory, 'x.lock');
  const old = new Date(Date.now() - 60_000);
  const stale = (owner: string) => {
    writeFileSync(lock, owner, { flag: 'wx' });
    utimesSync(lock, old, old);
    return lockOf(lock)!;
  };

  // A waiter finds A stale; before it takes A over, another run does and makes C, fresh.
  const a = stale('a');
  assert.equal(a.owner, 'a');
  rmSync(lock);
  writeFileSync(lock, 'c', { flag: 'wx' });
  assert.equal(takeOver(lock, a), false);
  assert.equal(lockOf(lock)?.owner, 'c', "C's lock stays");

  // C's run died too, and its lock is stale: still not the one the waiter found, which looks again first.
  utimesSync(lock, old, old);
  assert.equal(takeOver(lock, a), false);
  assert.equal(lockOf(lock)?.owner, 'c');

  // A run removing the lock holds its mutex: no other removes one meanwhile.
  const c = lockOf(lock)!;
  writeFileSync(`${lock}.break`, '', { flag: 'wx' });
  assert.equal(takeOver(lock, c), false);
  rmSync(`${lock}.break`);
  assert.equal(takeOver(lock, c), true);
  assert.equal(lockOf(lock), null);
  assert.deepEqual(readdirSync(directory), []);
});

test('a lock that cannot be read fails the run at once rather than spin on it (review r3 of #561)', async (t) => {
  const { directory, each } = kept(t);
  const release = await each().hold();
  const lock = join(directory, readdirSync(directory).find((name) => name.endsWith('.lock'))!);
  release();
  // A link to itself: creating the lock finds it there (EEXIST), opening it fails (ELOOP), as an unreadable one would
  // (EACCES), which root could still read.
  symlinkSync(lock, lock);
  const held = each().hold();
  assert.equal(await within(held.then(() => undefined, () => undefined), 1000), true);
  await assert.rejects(held, { code: 'ELOOP' });
});
