// T169: a checkpointer whose database stalls under a tick, on Node, Postgres
// and SQLite. Its tick stalls within its bound and another opens; meanwhile
// a use answers as ever, a change committed answers unsealed within its
// bound (the app's 503), `sealing()` (readiness) says it does not seal;
// once the database answers, it seals again by itself, the change too.
// (On Workers: log-hosts.test.ts and workers-log.test.ts.)
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, beforeEach, test } from 'node:test';

import { isUnsealed } from '@coffre/core/vault';
import type { Database } from '@coffre/db';
import { sql } from 'drizzle-orm';

import { SEAL_WAIT_MS } from '../src/checkpointer.ts';
import { keepCheckpointer, type KeptCheckpointer } from '../src/checkpointer-node.ts';
import { ENGINE, openTestDatabase, rows, run, type TestDatabase } from './database.ts';
import { ask, change, emptyLog, isolate, SIGNING_KEY, useDatabases, world } from './use-world.ts';

let db: TestDatabase;
let dir: string;

before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
  dir = mkdtempSync(join(tmpdir(), 'coffre-stall-'));
});
after(async () => {
  await db?.close();
  rmSync(dir, { recursive: true, force: true });
});
// A new instance's log, its checkpoints and tiles too: each test's checkpointer starts with no memory.
beforeEach(async () => {
  await emptyLog();
  for (const table of ['log_checkpoints', 'log_tiles']) await run(db.owner, sql.raw(`DELETE FROM ${table}`));
});

const until = async (done: () => boolean | Promise<boolean>, ms: number, what: string) => {
  const end = Date.now() + ms;
  while (!(await done())) {
    if (Date.now() > end) throw new Error(`${what}: not within ${ms} ms`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
};

/**
 * The vault's database as the checkpointer gets it, whose statements can be held before they are sent: a connection
 * that stops answering, a connect that hangs. The vault's own calls and its uses go on the database itself.
 */
function stallable(database: Database) {
  let held: Promise<void> | null = null;
  let release = () => {};
  const asks = new Set(['execute', 'all', 'run', 'get', 'values', 'transaction']);
  const db = new Proxy(database, {
    get(target, key) {
      const value = Reflect.get(target, key) as unknown;
      if (typeof value !== 'function') return value;
      if (!asks.has(key as string)) return (value as (...a: unknown[]) => unknown).bind(target);
      return async (...args: unknown[]) => {
        if (held !== null) await held;
        return (value as (...a: unknown[]) => unknown).apply(target, args);
      };
    },
  });
  return {
    db,
    hold: () => void (held = new Promise<void>((resolve) => (release = resolve))),
    release: () => {
      held = null;
      release();
    },
  };
}

/** A change committed as the change path commits one (use-world.ts): its number, to wait for its seal. */
const commitChange = (w: Awaited<ReturnType<typeof world>>) =>
  change({ kind: 'principal', id: w.principal }, { op: 'access.revoke', place: { projectId: w.project, environmentId: w.dev, environmentSlug: null } }, w.objects.principal, async () => {});

async function opened(database: Database, memory: string): Promise<{ kept: KeptCheckpointer; vault: Awaited<ReturnType<typeof isolate>>['vault']; use: Awaited<ReturnType<typeof isolate>>['use'] }> {
  const kept = await keepCheckpointer({ database, seed: SIGNING_KEY, memory, intervalMs: 20, retryMs: 50, tickBoundMs: 300 });
  const { vault, use } = await isolate({ sealThrough: kept.sealThrough, heldOutside: kept.heldOutside, sealing: kept.sealing });
  return { kept, vault, use };
}

test('T169, Node: statements the checkpointer sends go unanswered: its tick stalls, uses answer, a change answers unsealed within its bound, readiness goes red; answered again, it seals by itself', { timeout: 60_000 }, async () => {
  const w = await world();
  const id = await w.key('postgres://prod');
  const stall = stallable(db.vault);
  const { kept, vault, use } = await opened(stall.db, join(dir, `memory-${ENGINE}-1`));
  try {
    await until(() => kept.sealing().ok, 5000, 'sealing at first');
    assert.ok((await vault.sealing()).ok);
    assert.ok((await use(ask(w, id))).ok);

    stall.hold();
    // Within its bound and a tick, the checkpointer stalled: readiness says so.
    let t0 = Date.now();
    await until(async () => !(await vault.sealing()).ok, 3000, 'red');
    assert.ok(Date.now() - t0 < 3000);
    // A use waits on no checkpointer.
    t0 = Date.now();
    const outcome = await use(ask(w, id));
    assert.ok(outcome.ok, JSON.stringify(outcome));
    assert.ok(Date.now() - t0 < 1000, `the use took ${Date.now() - t0} ms`);
    // So does a fresh isolate's first use, its checkpointer never answering: the cutover was sealed long ago, as a pair
    // the vault's key signed past it says, and it asks no seal.
    const fresh = await isolate({ sealThrough: () => new Promise(() => {}), heldOutside: kept.heldOutside });
    t0 = Date.now();
    assert.ok((await fresh.use(ask(w, id))).ok);
    assert.ok(Date.now() - t0 < 1000, `the fresh isolate's use took ${Date.now() - t0} ms`);
    // A change committed meanwhile answers unsealed, within its bound: the app's 503, try again.
    const number = await commitChange(w);
    t0 = Date.now();
    await assert.rejects(vault.waitSealed!({ number: String(number) }), (error: Error) => isUnsealed(error));
    assert.ok(Date.now() - t0 < SEAL_WAIT_MS + 1000, `unsealed after ${Date.now() - t0} ms`);

    // Answered again: another checkpointer opens by itself and seals, the change among it.
    stall.release();
    await until(() => kept.sealing().ok, 10_000, 'sealing again');
    const sealed = await vault.waitSealed!({ number: String(number) });
    assert.ok(sealed.ok);
    const alarms = await kept.alarms();
    assert.ok(alarms.some((a) => /a checkpoint failed: .*stalled/.test(a.message)), JSON.stringify(alarms));
    assert.deepEqual(alarms.filter((a) => /floor/.test(a.message)), [], 'no floor alarm');
  } finally {
    stall.release();
    await kept.stop();
  }
});

test('T169, Node, Postgres: a barrier that waits in the database past its bound stalls the tick; let go, it lands late, and the checkpointer opened meanwhile takes the floor it raised', { skip: ENGINE === 'postgres' ? false : 'Postgres only: a lock the barrier waits for', timeout: 60_000 }, async () => {
  const w = await world();
  const id = await w.key('postgres://prod');
  const { kept, vault, use } = await opened(db.vault, join(dir, 'memory-postgres-2'));
  let release = () => {};
  let holding: Promise<unknown> = Promise.resolve();
  try {
    await until(() => kept.sealing().ok, 5000, 'sealing at first');
    // The issue lock, which the barrier takes first, held in another session: the barrier waits for it in the database,
    // holding nothing a use needs.
    const held = new Promise<void>((resolve) => (release = resolve));
    let locked = () => {};
    const taken = new Promise<void>((resolve) => (locked = resolve));
    holding = db.owner.transaction(async (tx) => {
      await run(tx, sql`SELECT pg_advisory_xact_lock(1668244070, 1)`);
      locked();
      await held;
    });
    await taken;
    await until(async () => !(await vault.sealing()).ok, 3000, 'red');
    assert.ok((await use(ask(w, id))).ok, 'a use answers while the barrier waits');
    const number = await commitChange(w);
    await assert.rejects(vault.waitSealed!({ number: String(number) }), (error: Error) => isUnsealed(error));
    // Every barrier since waits behind the first: let go, they run, late ones included, and raise the floor.
    const [before] = await rows<{ waiting: number }>(db.owner, sql`SELECT count(*)::int AS waiting FROM pg_locks WHERE locktype = 'advisory' AND NOT granted`);
    assert.ok(before!.waiting >= 1, 'a barrier waits in the database');
    release();
    await holding;
    await until(() => kept.sealing().ok, 10_000, 'sealing again');
    assert.ok((await vault.waitSealed!({ number: String(number) })).ok);
    // A few ticks more on the floor the late barriers left: no alarm.
    const sealedUpto = async () => BigInt((await rows<{ upto: string }>(db.owner, sql`SELECT max(upto)::text AS upto FROM log_checkpoints`))[0]!.upto);
    const later = await commitChange(w);
    await until(async () => (await sealedUpto()) >= BigInt(later), 5000, 'sealed past the late barriers');
    assert.ok(kept.sealing().ok);
    assert.deepEqual((await kept.alarms()).filter((a) => /floor/.test(a.message)), [], 'no floor alarm');
  } finally {
    release();
    await holding.catch(() => {});
    await kept.stop();
  }
});
