// A WebSocket's admission when the database cannot take the question: the
// door's (`schemaReady`) or the plugin's own. No database here: the runtime's
// is one that fails every query as told.
import test from 'node:test';
import assert from 'node:assert/strict';

import type { CoffreRuntime } from '../src/runtime.ts';
import { admitSocket } from '../src/socket-admission.ts';

const ORIGIN = 'https://coffre.test';

/** Hyperdrive's answer with every connection of its pool busy, as a query sees it. */
const poolFull = () => new Error('Failed query: select 1', { cause: Object.assign(new Error('Timed out while waiting for an open slot in the pool.'), { code: '58000', severity: 'FATAL' }) });

/** A runtime whose every query throws `failure`, with one plugin that takes WebSockets under /sockets. */
function runtimeOf(failure: () => Error, socket: () => Promise<Response>, migrated = false): CoffreRuntime {
  const fails = () => {
    throw failure();
  };
  const db = { execute: async () => fails(), select: () => ({ from: async () => fails() }) };
  return { db, schema: { migrated }, plugins: [{ name: 'sockets', routes: { prefix: '/sockets', fetch: async () => new Response(), socket } }] } as unknown as CoffreRuntime;
}

test("a pool with no connection to give, at the migration door, refuses a plugin's WebSocket with 503 and Retry-After, and its plugin is never asked", async () => {
  let asked = false;
  const answer = await admitSocket(new Request(`${ORIGIN}/sockets/x`), runtimeOf(poolFull, async () => ((asked = true), new Response('admitted'))), null);
  assert.ok(answer instanceof Response);
  assert.deepEqual([answer.status, answer.headers.get('retry-after'), ((await answer.json()) as { error: string }).error], [503, '5', 'unavailable']);
  assert.equal(asked, false);
});

test('a plugin that meets a full pool while it admits is 503 with Retry-After too; one that fails otherwise, 500', async () => {
  const full = await admitSocket(new Request(`${ORIGIN}/sockets/x`), runtimeOf(poolFull, async () => Promise.reject(poolFull()), true), null);
  assert.ok(full instanceof Response);
  assert.deepEqual([full.status, full.headers.get('retry-after')], [503, '5']);
  const broken = await admitSocket(new Request(`${ORIGIN}/sockets/x`), runtimeOf(poolFull, async () => Promise.reject(new Error('a bug')), true), null);
  assert.ok(broken instanceof Response);
  assert.deepEqual([broken.status, await broken.text()], [500, 'the plugin failed']);
});
