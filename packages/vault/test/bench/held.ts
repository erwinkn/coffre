// What a key in flight holds in the vault's isolate over a use's whole life
// (docs/design/limits.md, "Admission: places in flight, from memory and CPU";
// `USE_IN_FLIGHT_BYTES`, @coffre/core/memory): uses admitted, their statements answered, each waiting on its key
// service, which answers none until every key of the run waits there. The heap is collected and read before the run
// and while they all wait; the difference, a key apiece, is what each holds: its call, its statement's row and view,
// its key operation, the request. Two shapes: lone uses (`Vault.use`), and batches of 100 keys (`Vault.useMany`),
// each counted by its keys, as admission counts them.
//
// Node's V8 does not compress pointers, as workerd's does, so its figures bound workerd's from above. Not part of the
// suite. On the suite's Postgres, as a test file, after `scripts/setup-test-database.sh`:
//
//   node --conditions=coffre:source --expose-gc --import ./scripts/test-database-worker.mjs --test packages/vault/test/bench/held.ts
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';

import type { KekRegistry } from '@coffre/core/kek';
import type { UseInput } from '@coffre/core/vault';

import { newRequestId } from '../../src/use.ts';
import { openTestDatabase, type TestDatabase } from '../database.ts';
import { CONFIG, emptyLog, isolate, useDatabases, world } from '../use-world.ts';

const gc = (globalThis as { gc?: () => void }).gc;

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
});
after(() => db.close());

/** The vault's keys, each unwrap once `armed` held until `free`, counted as it starts waiting. */
function heldKeys() {
  let waiting = 0;
  let armed = false;
  let free = () => {};
  const freed = new Promise<void>((resolve) => (free = resolve));
  const keks: KekRegistry = new Proxy(CONFIG.keks, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (key !== 'unwrap' || typeof value !== 'function') return value;
      return async (...args: unknown[]) => {
        if (armed) {
          waiting += 1;
          await freed;
        }
        return (value as (...a: unknown[]) => unknown).apply(target, args);
      };
    },
  });
  return { keks, waiting: () => waiting, free, arm: () => (armed = true) };
}

function heap(): number {
  gc!();
  gc!();
  return process.memoryUsage().heapUsed;
}

async function until(done: () => boolean, ms: number): Promise<void> {
  for (const end = Date.now() + ms; !done() && Date.now() < end;) await new Promise((resolve) => setTimeout(resolve, 5));
}

/** `keys` keys held at the key service at once, as `calls` calls of `per` keys each; bytes a key. */
async function held(calls: number, per: number): Promise<{ keys: number; waiting: number; bytes: number }> {
  await emptyLog();
  const w = await world();
  const ids: string[] = [];
  for (let i = 0; i < 100; i += 1) ids.push(await w.key(`value-${i}-${'x'.repeat(40)}`));
  const { keks, waiting, free, arm } = heldKeys();
  const { vault } = await isolate({ uses: { inFlight: 100_000 } }, { ...CONFIG, keks });
  // Warm: the isolate's first calls read its state, compile, fill its maps; each key used once.
  for (const id of ids) assert.ok((await vault.use!(ask(w, id))).ok);
  arm();
  const before = heap();
  const at = Date.now();
  const deadline = at + 3_000;
  const answers = Array.from({ length: calls }, (_, c) => (per === 1
    ? vault.use!(ask(w, ids[c % ids.length]!, { at, deadline }))
    : vault.useMany!({ credential: w.credentialId, purpose: 'run', at, deadline, items: Array.from({ length: per }, (_, k) => ({ secretId: ids[k % ids.length]!, place: null, requestId: newRequestId() })) })));
  await until(() => waiting() >= calls * per, 2_500);
  const during = heap();
  const counted = waiting();
  free();
  const outcomes = await Promise.all(answers);
  const ok = outcomes.filter((one) => one.ok).length;
  assert.ok(ok === calls, `${calls - ok} of ${calls} calls not answered: ${JSON.stringify(outcomes.find((one) => !one.ok))}`);
  return { keys: calls * per, waiting: counted, bytes: Math.round((during - before) / counted) };
}

function ask(w: { credentialId: string }, secretId: string, extra: Partial<UseInput> = {}): UseInput {
  const at = Date.now();
  return { credential: w.credentialId, secretId, place: null, purpose: 'run', requestId: newRequestId(), at, deadline: at + 3000, ...extra };
}

test('bytes a key in flight holds, over its whole use, its key service holding every key', { timeout: 600_000 }, async () => {
  assert.ok(gc !== undefined, 'run with --expose-gc');
  const runs: { shape: string; keys: number; waiting: number; bytes: number }[] = [];
  for (const n of [250, 500, 1_000]) runs.push({ shape: `${n} lone uses`, ...(await held(n, 1)) });
  for (const n of [5, 10]) runs.push({ shape: `${n} batches of 100 keys`, ...(await held(n, 100)) });
  console.table(runs);
});
