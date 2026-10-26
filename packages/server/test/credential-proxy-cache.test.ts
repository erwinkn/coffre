// The credential proxy's cache of opened values, through the plugin's own
// routes, with a fake coffre that counts each use, the vault's decision,
// and can hold one back or fail it: a steady caller meets no lapse, one
// request asks again near the end while the others are served, and nothing
// serves past the entry's end.
import assert from 'node:assert/strict';
import test from 'node:test';

import { CoffreError } from '@coffre/client';

import type { PluginContext, UseAsked, WorkloadUse } from '../src/plugins.ts';
import { credentialProxy, header } from '../src/plugins/credential-proxy.ts';

const PUBLIC = 'https://coffre.example';
const HANDLE = `coffre_use_${'h'.repeat(43)}`;
const LATER = new Date(Date.now() + 86_400_000).toISOString();

/** coffre, as the proxy sees it: each `use` counted, answered at once, or as `next` says; `held`, the values and end it answers with. */
function coffre() {
  const uses: number[] = [];
  let next: (() => Promise<void>) | null = null;
  const held = { values: { API_KEY: '' } as Record<string, string>, expiresAt: LATER };
  const context: PluginContext = {
    publicUrl: PUBLIC,
    api: () => assert.fail('api'),
    exchange: () => assert.fail('exchange'),
    signOut: () => assert.fail('signOut'),
    workload: async () => null,
    recheck: () => assert.fail('recheck'),
    handle: async () => ({ expiresAt: LATER, paths: ['market/dev'] }),
    use: async (_handle: string | WorkloadUse, _asked: UseAsked) => {
      uses.push(Date.now());
      const nth = uses.length;
      const waiting = next;
      next = null;
      await waiting?.();
      const values = held.values.API_KEY === '' ? { API_KEY: `key-${nth}` } : held.values;
      return { values, plain: [], keys: Object.keys(values), environment: { path: 'market/dev', personal: false }, expiresAt: held.expiresAt };
    },
  };
  return { context, uses, held, hold: (then: () => Promise<void>) => void (next = then) };
}

/** The proxy, its cache a minute long, and what its upstream saw of the key. */
function proxy() {
  const sent: string[] = [];
  const plugin = credentialProxy({
    cacheSeconds: 60,
    credentials: { stripe: { upstream: 'https://api.stripe.example', inject: header('authorization', 'Bearer {API_KEY}'), egress: { fetch: async (_url: URL, init: RequestInit) => {
      sent.push(new Headers(init.headers).get('authorization') ?? '');
      return new Response('ok');
    } } } },
  });
  const ask = (context: PluginContext, handle = HANDLE) => plugin.routes!.fetch(new Request(`${PUBLIC}/use/stripe/v1/charges`, { headers: { 'x-coffre-handle': handle } }), context);
  return { ask, sent };
}

test('a steady caller meets no lapse: in the last quarter of its minute, one request asks again while the others are served', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 1_000_000 });
  const { context, uses, hold } = coffre();
  const { ask, sent } = proxy();
  assert.equal((await ask(context)).status, 200);
  t.mock.timers.tick(30_000);
  assert.equal((await ask(context)).status, 200);
  assert.equal(uses.length, 1, 'served from the cache at 30 s');

  // At 46 s, in the last 15 s: the first request asks again, held; each other meanwhile is served the entry.
  t.mock.timers.tick(16_000);
  let release!: () => void;
  hold(() => new Promise<void>((resolve) => (release = resolve)));
  const asking = ask(context);
  await new Promise((resolve) => setImmediate(resolve));
  const meanwhile = await Promise.all(Array.from({ length: 5 }, () => ask(context)));
  assert.deepEqual(meanwhile.map((response) => response.status), [200, 200, 200, 200, 200]);
  assert.equal(uses.length, 2, 'one request asked the vault again, the five others did not');
  release();
  assert.equal((await asking).status, 200);
  assert.equal(sent.at(-1), 'Bearer key-2', 'the one asking is served what the vault just answered');

  // Past the first minute, the entry it made serves on.
  t.mock.timers.tick(30_000);
  assert.equal((await ask(context)).status, 200);
  assert.equal(uses.length, 2);
  assert.equal(sent.at(-1), 'Bearer key-2');
});

test('the one asking again is served the entry when the vault does not answer, and refused when it refuses; nothing serves past the end', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 1_000_000 });
  const logged: unknown[][] = [];
  t.mock.method(console, 'error', (...args: unknown[]) => void logged.push(args));
  const { context, uses, hold } = coffre();
  const { ask, sent } = proxy();
  assert.equal((await ask(context)).status, 200);

  // Unanswered: served the entry, which still holds.
  t.mock.timers.tick(50_000);
  hold(async () => {
    throw new CoffreError(503, 'unavailable', 'coffre cannot reach what it depends on right now; try again in a moment');
  });
  assert.equal((await ask(context)).status, 200);
  assert.equal(sent.at(-1), 'Bearer key-1');
  assert.equal(uses.length, 2);
  // One at a time: the others are served it, and a second on, the next asks again.
  assert.equal((await ask(context)).status, 200);
  assert.equal(uses.length, 2);
  t.mock.timers.tick(1_000);
  hold(async () => {
    throw new CoffreError(503, 'unavailable', 'coffre cannot reach what it depends on right now; try again in a moment');
  });
  assert.equal((await ask(context)).status, 200);
  assert.equal(uses.length, 3);
  assert.deepEqual(logged.map(([label]) => label), Array(2).fill("the proxy's cache asked the vault again, unanswered; serving what it holds"));

  // Past its end, the vault is asked, and its answer stands.
  t.mock.timers.tick(10_000);
  hold(async () => {
    throw new CoffreError(503, 'unavailable', 'coffre cannot reach what it depends on right now; try again in a moment');
  });
  assert.equal((await ask(context)).status, 503);
  assert.equal(uses.length, 4);

  // Refused while asking again: refused, and the entry goes, so the next request asks too.
  assert.equal((await ask(context)).status, 200);
  t.mock.timers.tick(50_000);
  hold(async () => {
    throw new CoffreError(403, 'forbidden', 'you do not have permission to do that');
  });
  assert.equal((await ask(context)).status, 403);
  assert.equal((await ask(context)).status, 200);
  assert.equal(uses.length, 7);
});

test('an entry serves from when the vault was asked, not when it answered: a slow answer gives a revoked handle no longer', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 1_000_000 });
  const { context, uses, hold } = coffre();
  const { ask } = proxy();
  let release!: () => void;
  hold(() => new Promise<void>((resolve) => (release = resolve)));
  const asking = ask(context);
  await new Promise((resolve) => setImmediate(resolve));
  t.mock.timers.tick(10_000);
  release();
  assert.equal((await asking).status, 200);
  // 61 s after it was asked, 51 s after it answered: lapsed.
  t.mock.timers.tick(51_000);
  assert.equal((await ask(context)).status, 200);
  assert.equal(uses.length, 2);
});

test("an entry the handle's end cuts short is asked for again once, not on each request to that end", async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 1_000_000 });
  const { context, uses, held } = coffre();
  held.expiresAt = new Date(1_000_000 + 30_000).toISOString();
  const { ask } = proxy();
  for (let second = 0; second < 30; second += 1) {
    assert.equal((await ask(context)).status, 200, `at ${second} s`);
    t.mock.timers.tick(1_000);
  }
  // Its first opening, and one more in its last 15 s, which gave it no longer: then no more until it ends.
  assert.equal(uses.length, 2);
});

test('an environment that no longer holds the key, found when asking again, ends the entry', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 1_000_000 });
  const { context, uses, held } = coffre();
  const { ask } = proxy();
  assert.equal((await ask(context)).status, 200);
  t.mock.timers.tick(45_000);
  held.values = { OTHER: 'x' };
  assert.equal((await ask(context)).status, 409);
  assert.equal((await ask(context)).status, 409);
  assert.equal(uses.length, 3, 'the entry went: the next request asked too');
});

test('with no cache, each request asks the vault', async () => {
  const { context, uses } = coffre();
  const plugin = credentialProxy({ cacheSeconds: 0, credentials: { stripe: { upstream: 'https://api.stripe.example', inject: header('authorization', 'Bearer {API_KEY}'), egress: { fetch: async () => new Response('ok') } } } });
  for (let i = 0; i < 3; i++) assert.equal((await plugin.routes!.fetch(new Request(`${PUBLIC}/use/stripe/v1/charges`, { headers: { 'x-coffre-handle': HANDLE } }), context)).status, 200);
  assert.equal(uses.length, 3);
});

test('one asking that never answers, its caller gone, holds the others off 5 s at most: another asks before the entry ends', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 1_000_000 });
  const { context, uses, hold } = coffre();
  const { ask } = proxy();
  assert.equal((await ask(context)).status, 200);
  t.mock.timers.tick(46_000);
  hold(() => new Promise<void>(() => undefined));
  void ask(context);
  await new Promise((resolve) => setImmediate(resolve));
  t.mock.timers.tick(3_000);
  assert.equal((await ask(context)).status, 200);
  assert.equal(uses.length, 2, 'held off while the first asks');
  t.mock.timers.tick(2_500);
  assert.equal((await ask(context)).status, 200);
  assert.equal(uses.length, 3, 'asked again before the entry ended');
});

test("an error that is no vault's not answering is the asker's, and the entry stands for the others", async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 1_000_000 });
  const { context, uses, hold } = coffre();
  const { ask, sent } = proxy();
  assert.equal((await ask(context)).status, 200);
  t.mock.timers.tick(50_000);
  hold(async () => {
    throw new TypeError('a bug');
  });
  await assert.rejects(ask(context), TypeError);
  assert.equal((await ask(context)).status, 200);
  assert.equal(sent.at(-1), 'Bearer key-1');
  assert.equal(uses.length, 2);
});

test("a full cache refreshing one key makes no room at another's cost: the oldest still serves its burst while one request asks", async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 1_000_000 });
  const { context, uses, hold } = coffre();
  const { ask } = proxy();
  const handles = Array.from({ length: 1000 }, (_, i) => `coffre_use_${String(i).padStart(43, 'h')}`);
  for (const handle of handles) assert.equal((await ask(context, handle)).status, 200);
  assert.equal(uses.length, 1000);
  // At 46 s, the second key refreshes, the cache full: the oldest stays.
  t.mock.timers.tick(46_000);
  assert.equal((await ask(context, handles[1])).status, 200);
  assert.equal(uses.length, 1001);
  let release!: () => void;
  hold(() => new Promise<void>((resolve) => (release = resolve)));
  const burst = Array.from({ length: 5 }, () => ask(context, handles[0]));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(uses.length, 1002, 'one request of the burst asked, the others were served');
  release();
  assert.deepEqual((await Promise.all(burst)).map((response) => response.status), [200, 200, 200, 200, 200]);
});

test("a lock that gave up, as the database says it, is the vault's not answering: the entry is served", async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 1_000_000 });
  t.mock.method(console, 'error', () => undefined);
  const { context, uses, hold } = coffre();
  const { ask, sent } = proxy();
  assert.equal((await ask(context)).status, 200);
  t.mock.timers.tick(50_000);
  hold(async () => {
    throw new Error('Failed query: select "principal" …', { cause: Object.assign(new Error('canceling statement due to lock timeout'), { code: '55P03' }) });
  });
  assert.equal((await ask(context)).status, 200);
  assert.equal(sent.at(-1), 'Bearer key-1');
  assert.equal(uses.length, 2);
});

test('two asking at once: a refusal is not undone by an older answer, and a failure is served the newer entry', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 1_000_000 });
  t.mock.method(console, 'error', () => undefined);
  const { context, uses, hold } = coffre();
  const { ask, sent } = proxy();
  assert.equal((await ask(context)).status, 200);

  // A asks at 46 s and is slow; B asks at 51.5 s and is refused: the entry goes, and A's answer, decided before, does not bring it back.
  t.mock.timers.tick(46_000);
  let releaseA!: () => void;
  hold(() => new Promise<void>((resolve) => (releaseA = resolve)));
  const a = ask(context);
  await new Promise((resolve) => setImmediate(resolve));
  t.mock.timers.tick(5_500);
  hold(async () => {
    throw new CoffreError(403, 'forbidden', 'you do not have permission to do that');
  });
  assert.equal((await ask(context)).status, 403);
  releaseA();
  assert.equal((await a).status, 200);
  assert.equal((await ask(context)).status, 200);
  assert.equal(uses.length, 4, 'the next request asked the vault: nothing held');

  // C asks at 46 s on and is slow; D asks 5.5 s later and fails unanswered after C's answer is kept: D is served C's.
  t.mock.timers.tick(46_000);
  let releaseC!: () => void;
  hold(() => new Promise<void>((resolve) => (releaseC = resolve)));
  const c = ask(context);
  await new Promise((resolve) => setImmediate(resolve));
  t.mock.timers.tick(5_500);
  let failD!: () => void;
  hold(() => new Promise<void>((_, reject) => (failD = () => reject(new CoffreError(503, 'unavailable', 'coffre cannot reach what it depends on right now')))));
  const d = ask(context);
  await new Promise((resolve) => setImmediate(resolve));
  releaseC();
  assert.equal((await c).status, 200);
  failD();
  assert.equal((await d).status, 200);
  assert.equal(uses.length, 6);
  assert.equal(sent.at(-1), 'Bearer key-5', "D was served C's answer");
});

