// T169: a checkpointer whose database stalls under a tick, on Node, Postgres
// and SQLite. Its tick stalls within its bound and another opens; meanwhile
// a use answers as ever, a change committed answers unsealed within its
// bound (the app's 503), `sealing()` (readiness) says it does not seal;
// once the database answers, it seals again by itself, the change too.
// (On Workers: log-hosts.test.ts and workers-log.test.ts.)
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, beforeEach, test } from 'node:test';

import { isUnsealed } from '@coffre/core/vault';
import type { Database } from '@coffre/db';
import { sql } from 'drizzle-orm';

import { openDatabase } from '@coffre/db/connect';

import { SEAL_WAIT_MS } from '../src/checkpointer.ts';
import { fileMemory, keepCheckpointer, type KeptCheckpointer } from '../src/checkpointer-node.ts';
import { CUTOVER_OBJECT } from '../src/cutover.ts';
import { ENGINE, openTestDatabase, rows, run, VAULT_URL, type TestDatabase } from './database.ts';
import { stallProxy } from './stall-proxy.ts';
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
function stallable(database: Database, which: (text: string) => boolean = () => true) {
  let held: Promise<void> | null = null;
  let release = () => {};
  let answered = 0;
  const asks = new Set(['execute', 'all', 'run', 'get', 'values', 'transaction']);
  const textOf = (query: unknown) => {
    try {
      return (database as unknown as { dialect: { sqlToQuery(q: unknown): { sql: string } } }).dialect.sqlToQuery(query).sql;
    } catch {
      return '';
    }
  };
  const db = new Proxy(database, {
    get(target, key) {
      const value = Reflect.get(target, key) as unknown;
      if (typeof value !== 'function') return value;
      if (!asks.has(key as string)) return (value as (...a: unknown[]) => unknown).bind(target);
      return async (...args: unknown[]) => {
        const mine = typeof args[0] !== 'function' && which(textOf(args[0]));
        if (held !== null && mine) await held;
        const answer = await (value as (...a: unknown[]) => Promise<unknown>).apply(target, args);
        if (mine) answered += 1;
        return answer;
      };
    },
  });
  return {
    db,
    /** How many of the statements it holds have answered. */
    answered: () => answered,
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

test("T169, review r8 of #437, Node, Postgres: a reads' projection hung in the database holds back no runner opened after a stall: let the barrier go and it seals again, the projection still waiting", { skip: ENGINE === 'postgres' ? false : 'Postgres only: a lock the projection waits for', timeout: 60_000 }, async () => {
  const w = await world();
  const { kept, vault } = await opened(db.vault, join(dir, 'memory-postgres-projection'));
  const releases: (() => void)[] = [];
  const holdings: Promise<unknown>[] = [];
  /** A lock held in another session until let go: `statement` taken, then waiting. */
  const hold = async (statement: ReturnType<typeof sql>) => {
    let locked = () => {};
    const taken = new Promise<void>((resolve) => (locked = resolve));
    const held = new Promise<void>((resolve) => releases.push(resolve));
    holdings.push(db.owner.transaction(async (tx) => {
      await run(tx, statement);
      locked();
      await held;
    }));
    await taken;
    return releases.length - 1;
  };
  // A projection waiting on its cursor, in this database: pg_locks lists the whole cluster's.
  const projecting = async () => (await rows<{ n: number }>(db.owner, sql`SELECT count(*)::int AS n FROM pg_locks WHERE relation = 'log_reads_cursor'::regclass AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) AND NOT granted`))[0]!.n > 0;
  try {
    await until(() => kept.sealing().ok, 5000, 'sealing at first');
    // The projection's cursor locked: the projector's next run waits on it in the database, holding its connection.
    await hold(sql`LOCK TABLE log_reads_cursor IN ACCESS EXCLUSIVE MODE`);
    await until(projecting, 5000, 'a projection waiting on its cursor');
    // Then the barrier's lock: the tick stalls past its bound, and the runner is retired.
    const barrier = await hold(sql`SELECT pg_advisory_xact_lock(1668244070, 1)`);
    await until(async () => !(await vault.sealing()).ok, 3000, 'red');
    const number = await commitChange(w);
    // The barrier let go, the projection not: the runner opened meanwhile seals, the change too.
    releases[barrier]!();
    await until(() => kept.sealing().ok, 10_000, 'sealing again, the projection still waiting');
    assert.ok((await vault.waitSealed!({ number: String(number) })).ok);
    assert.ok(await projecting(), 'the projection still waits on its cursor');
  } finally {
    for (const release of releases) release();
    await Promise.all(holdings.map((h) => h.catch(() => {})));
    await kept.stop();
  }
});

test('T169, review r1, Postgres: a cutover change a writer moved into a gap a signed pair covers is no shortcut: a fresh isolate asks for its seal, which proves it', { skip: ENGINE === 'postgres' ? false : 'Postgres only: a gap in the sequence', timeout: 60_000 }, async () => {
  const w = await world();
  const id = await w.key('postgres://prod');
  const { kept, vault } = await opened(db.vault, join(dir, 'memory-postgres-3'));
  try {
    await until(() => kept.sealing().ok, 5000, 'sealing at first');
    // A number handed out and never used, then a change past it, sealed: a signed pair covers the gap.
    const [gap] = await rows<{ n: string }>(db.owner, sql`SELECT nextval('log_number')::text AS n`);
    const number = await commitChange(w);
    assert.ok((await vault.waitSealed!({ number: String(number) })).ok);
    // The cutover's change moved into the gap: its MAC holds, the number is not under it, and the pair covers it.
    await run(db.owner, sql`UPDATE log_changes SET number = ${BigInt(gap!.n)} WHERE object = ${CUTOVER_OBJECT}`);
    const asked: bigint[] = [];
    const fresh = await isolate({
      sealThrough: async (n) => {
        asked.push(n);
        throw new Error('refused: the change is not in the signed changes tree');
      },
      heldOutside: kept.heldOutside,
    });
    await fresh.use(ask(w, id)).catch(() => null);
    assert.deepEqual(asked, [BigInt(gap!.n)], 'the shortcut proved nothing, so the seal was asked');
  } finally {
    await kept.stop();
  }
});

test('T169, review r1, Node, Postgres: stall after stall, each on a connection of its own, which it cuts: none is left holding one; answered again, it seals', { skip: ENGINE === 'postgres' ? false : 'Postgres only: a connection to cut', timeout: 60_000 }, async () => {
  const w = await world();
  const proxy = await stallProxy(VAULT_URL);
  const kept = await keepCheckpointer({
    connect: async () => {
      const { db: session, cut } = await openDatabase(proxy.url, { max: 2 });
      return { db: session, cut };
    },
    seed: SIGNING_KEY, memory: join(dir, 'memory-postgres-4'), intervalMs: 20, retryMs: 50, tickBoundMs: 200,
  });
  const { vault } = await isolate({ sealThrough: kept.sealThrough, heldOutside: kept.heldOutside, sealing: kept.sealing });
  try {
    await until(() => kept.sealing().ok, 5000, 'sealing at first');
    proxy.hold();
    // Many stalls and opens, each a session that gets no answer, each cut once given up on.
    await until(() => !kept.sealing().ok, 10_000, 'red');
    await new Promise((resolve) => setTimeout(resolve, 3000));
    assert.ok(!kept.sealing().ok);
    assert.ok(proxy.clients() <= 3, `${proxy.clients()} connections left open`);
    proxy.release();
    await until(() => kept.sealing().ok, 10_000, 'sealing again');
    const number = await commitChange(w);
    assert.ok((await vault.waitSealed!({ number: String(number) })).ok);
  } finally {
    proxy.release();
    await kept.stop();
    await proxy.close();
  }
});

test('T169, review r3, Node: a tick that stalls in its memory write: the keeper\'s stop returns only once that write has landed, so nothing opened after it over the same file has its pair overwritten', { timeout: 60_000 }, async () => {
  const w = await world();
  const path = join(dir, `memory-${ENGINE}-5`);
  let hold: Promise<void> | null = null;
  let release = () => {};
  let landed = 0;
  const memoryOf = (file: string) => {
    const memory = fileMemory(file);
    return {
      last: () => memory.last(),
      remember: async (record: string) => {
        if (hold !== null) await hold;
        await memory.remember(record);
        landed += 1;
      },
    };
  };
  const kept = await keepCheckpointer({ database: db.vault, seed: SIGNING_KEY, memory: path, intervalMs: 20, retryMs: 50, tickBoundMs: 200, memoryOf });
  let stopping: Promise<unknown> | null = null;
  try {
    await until(() => kept.sealing().ok, 5000, 'sealing at first');
    // Its memory's writes held, then a change for the next tick to sign and remember: the tick stalls in its write.
    hold = new Promise<void>((resolve) => (release = resolve));
    await commitChange(w);
    await until(() => !kept.sealing().ok, 3000, 'stalled in its memory write');
    // Retired by its keeper, its stop waiting on the write: no runner is the keeper's now.
    await new Promise((resolve) => setTimeout(resolve, 300));
    let stopped = false;
    stopping = kept.stop().then(() => (stopped = true));
    await new Promise((resolve) => setTimeout(resolve, 300));
    assert.equal(stopped, false, 'stop waits for the memory write in flight');
    const before = landed;
    release();
    await stopping;
    assert.ok(landed > before, 'the write landed before stop returned');
    const record = readFileSync(path, 'utf8');
    await new Promise((resolve) => setTimeout(resolve, 200));
    assert.equal(readFileSync(path, 'utf8'), record, 'nothing lands after stop');
  } finally {
    release();
    await (stopping ?? kept.stop());
  }
});

test('T169, review r5, Node: an upkeep past its bound retires its runner, as a stall does: another opens, and its upkeep runs again once answered', { timeout: 60_000 }, async () => {
  // Only the upkeep's pruning of the bulk cap's rows goes unanswered; the ticks are answered as ever.
  const stall = stallable(db.vault, (text) => /prune_bulk|DELETE FROM log_bulk/i.test(text));
  stall.hold();
  const kept = await keepCheckpointer({ database: stall.db, seed: SIGNING_KEY, memory: join(dir, `memory-${ENGINE}-6`), intervalMs: 20, retryMs: 50, tickBoundMs: 300, upkeepBoundMs: 300 });
  try {
    await until(async () => (await kept.alarms()).some((a) => /the log's upkeep did not end within 300 ms/.test(a.message)), 10_000, 'the upkeep given up on');
    stall.release();
    await until(() => kept.sealing().ok, 10_000, 'sealing again');
    await until(() => stall.answered() > 0, 10_000, 'an upkeep that ran again');
  } finally {
    stall.release();
    await kept.stop();
  }
});
