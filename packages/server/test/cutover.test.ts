// The app's door to 0.15's cutover (cutover.ts), as a deploy meets it: a vault of 0.15's log not cut over yet, and the
// app over it, whose first requests try the cutover once at a time, hold a refusal or a failure, and never take back a
// cutover another request made.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { defineSignin, github, signin } from '@coffre/core/identity';

import { SigninService } from '../src/api/signin.ts';
import { runScheduled } from '../src/app.ts';
import { resolveConfig } from '../src/config.ts';
import { CUTTING_OVER_NOW, cutoverReady, type CutoverKnown } from '../src/cutover.ts';
import { createRuntime } from '../src/runtime.ts';
import { logChanges } from '@coffre/db/schema';
import { TEST_HOT_DATABASE_URL } from './db/connections.ts';
import { clientFor, openTestDatabase, resetDatabase, sealedNow, nothingHeld, testDeps, testVault } from './api-fixture.ts';

const ROOT = 'admin@acme.example';
const PUBLIC_URL = 'https://secrets.acme.example';
const SIGNIN = defineSignin({ publicUrl: PUBLIC_URL, providers: [github({ clientId: 'a', clientSecret: 'b' })] });

let db: Awaited<ReturnType<typeof openTestDatabase>>;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
});

/** The deploy: a vault not cut over, and the app over it, whose door cuts it over. */
function deploy(signin = SIGNIN, config: { bulkLimit?: { count: number; windowMinutes: number } } = {}) {
  const vault = testVault([ROOT], { hotDatabase: TEST_HOT_DATABASE_URL, ...config }, undefined, {}, { sealThrough: sealedNow, heldOutside: nothingHeld, cutover: 'app' });
  const deps = testDeps(db.runtime, [ROOT], { vault });
  deps.signin = new SigninService({ db: deps.db, chainKey: deps.chainKey, vault, signin: SIGNIN });
  const runtime = { db: deps.db, vault, chainKey: deps.chainKey, previousChainKeys: [], publicUrl: PUBLIC_URL, auth: { mode: 'signin' as const, signin }, cutover: { done: false } as CutoverKnown };
  return { vault, deps, root: clientFor(deps, ROOT), cutover: async () => (await cutoverReady(runtime))?.why ?? null, runtime };
}

test("the door tries a due cutover once at a time, and holds a failure as a refusal: the requests meanwhile answer from the hold and ask the vault nothing (review, Fable)", async () => {
  const now = deploy();
  const cutover = now.vault.cutover!.bind(now.vault);
  let asked = 0;
  let tries = 0;
  let failing = true;
  // The try waits until the other request has asked too, and has had its answer.
  let both: () => void = () => {};
  const asking = new Promise<void>((resolve) => (both = resolve));
  let probes = 0;
  now.vault.cutover = async (input) => {
    asked += 1;
    if (input === undefined) {
      const answer = await cutover(input);
      probes += 1;
      if (probes === 2) setImmediate(both);
      return answer;
    }
    tries += 1;
    if (!failing) return cutover(input);
    await asking;
    throw new Error('canceling statement due to lock timeout');
  };
  const failed = 'the cutover failed: canceling statement due to lock timeout';
  // Both ask whether it is due; one tries it, the other answers from the hold. Whichever probe
  // answers first is the one that tries, so the two answers come in either order.
  const answers = await Promise.all([now.cutover(), now.cutover()]);
  assert.deepEqual([...answers].sort(), [CUTTING_OVER_NOW, failed].sort());
  assert.equal(tries, 1);
  const before = asked;
  // Held as failed, which the door says apart from a refusal (T170).
  assert.deepEqual(await cutoverReady(now.runtime), { why: failed, failed: true });
  assert.equal(asked, before);
  failing = false;
  now.runtime.cutover.held!.until = 0;
  assert.equal(await now.cutover(), null);
  assert.equal(await now.cutover(), null);
  assert.equal(tries, 2);
});

/**
 * An older request's answer, a refusal, come late: its probe's, or its try's,
 * held back until a second request has cut over. It never takes that back.
 */
async function lateRefusal(late: 'probe' | 'try') {
  const now = deploy();
  const cutover = now.vault.cutover!.bind(now.vault);
  let release: () => void = () => {};
  const released = new Promise<void>((resolve) => (release = resolve));
  let waiting = false;
  now.vault.cutover = async (input) => {
    if (!waiting && (late === 'probe' || input !== undefined)) {
      waiting = true;
      await released;
      return { ok: false, refused: 'refused', why: 'an answer from before the cutover' };
    }
    return cutover(input);
  };
  const older = now.cutover();
  while (!waiting) await new Promise((resolve) => setImmediate(resolve));
  // Its try outlived its hold: the second request tries, and cuts over.
  if (late === 'try') now.runtime.cutover.held!.until = 0;
  assert.equal(await now.cutover(), null);
  release();
  assert.equal(await older, null);
  assert.deepEqual(now.runtime.cutover, { done: true, held: undefined });
  assert.equal(await now.cutover(), null);
}

test("a probe's refusal, answered before a cutover another request made since, never takes it back (review r8)", () => lateRefusal('probe'));

test("a try that outlived its hold, refused, never takes back the cutover another request made since (review r8)", () => lateRefusal('try'));

test("a try that outlived its hold, refused while a newer try runs, leaves the newer one's hold as it is (review r8)", async () => {
  const now = deploy();
  const cutover = now.vault.cutover!.bind(now.vault);
  const gates: (() => void)[] = [];
  let tries = 0;
  // Each try waits for its gate; the older one then answers a refusal, the newer one cuts over.
  now.vault.cutover = async (input) => {
    if (input === undefined) return cutover(input);
    tries += 1;
    const older = tries === 1;
    await new Promise<void>((resolve) => gates.push(resolve));
    return older ? { ok: false, refused: 'refused', why: 'an answer from before the cutover' } : cutover(input);
  };
  const turn = () => new Promise((resolve) => setImmediate(resolve));
  const first = now.cutover();
  while (gates.length < 1) await turn();
  now.runtime.cutover.held!.until = 0;
  const second = now.cutover();
  while (gates.length < 2) await turn();
  const newer = now.runtime.cutover.held;
  gates[0]!();
  assert.equal(await first, 'an answer from before the cutover');
  assert.equal(now.runtime.cutover.held, newer);
  assert.equal(await now.cutover(), CUTTING_OVER_NOW);
  gates[1]!();
  assert.equal(await second, null);
  assert.equal(await now.cutover(), null);
});

test("a deployment with no cutover due answers its first requests at once, together: nothing holds them (review r8 of the hold)", async () => {
  const now = deploy();
  assert.equal(await now.cutover(), null);
  // Its runtime made again, the log cut over: two first requests at once, neither held.
  const runtime = { ...now.runtime, cutover: { done: false } as CutoverKnown };
  assert.deepEqual(await Promise.all([cutoverReady(runtime), cutoverReady(runtime)]), [null, null]);
});

test("the scheduled job, run before any request, as a Node server runs it at its start, cuts over first, then checkpoints", async () => {
  const now = deploy();
  const config = resolveConfig({ publicUrl: PUBLIC_URL, vault: now.vault, auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })] }), auditChainKey: now.deps.chainKey.toString('base64') });
  const runtime = createRuntime(config, now.deps.db, now.vault, { json: async () => assert.fail('the job fetches nothing') });
  await runScheduled(runtime);
  assert.equal(runtime.cutover?.done, true);
  assert.ok((await db.owner.select({ number: logChanges.number }).from(logChanges)).length > 0, "0.15's log holds the cutover");
  // And it runs as it did, once cut over.
  await runScheduled(runtime);
});
