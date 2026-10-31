// SQLite's `use_batch` (use.sqlite.ts, `callBatch`, W281): a batch's keys decided on rows read once for them all, the
// principal's cap rows counted in memory. It answers what each key's use alone answers, row for row, and writes what
// they write, around the cap's bound most of all; and a thousand keys cost a statement count that does not grow with
// them but by the batch's statements.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

import type { UseManyInput } from '@coffre/core/vault';
import type { Database } from '@coffre/db';
import { sql } from 'drizzle-orm';

import { periodOf, refreshMs } from '../src/bulk.ts';
import type { UseCall, UseRow } from '../src/use.ts';
import { newRequestId } from '../src/use.ts';
import { callBatch, callUse } from '../src/use.sqlite.ts';
import { openVault, prepareVault } from '../src/vault.ts';
import { ENGINE, openTestDatabase, rows, run, type TestDatabase } from './database.ts';
import { namedWorld } from './named-world.ts';
import { ask, CONFIG, emptyLog, LOG_015, useDatabases } from './use-world.ts';

const sqliteOnly = { skip: ENGINE === 'sqlite' ? false : 'SQLite only: its batch is read in memory (Postgres\'s, `use_batch`, is each key\'s `use_credential`)' };

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
});
after(() => db.close());
beforeEach(emptyLog);

const WINDOW = 15 * 60_000;
const LIMIT = { count: 6, windowMs: WINDOW };

/** What the uses wrote: every entry and every cap row. */
async function written() {
  return {
    uses: await rows(db.owner, sql`SELECT number, at, request_id, credential, secret, purpose, mac, place FROM log_uses ORDER BY number`),
    bulk: await rows(db.owner, sql`SELECT principal, secret, last FROM log_bulk ORDER BY principal, secret`),
  };
}

test('a thousand and one keys at once: the thousandth allowed, the next over the cap, in a statement count by the batch\'s statements, not its keys', { ...sqliteOnly, timeout: 120_000 }, async () => {
  const w = await namedWorld(db);
  const ids: string[] = [];
  for (let i = 0; i < 1001; i += 1) ids.push(await w.key(`v${i}`));
  let statements = 0;
  const counted = (tx: object) => new Proxy(tx, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (key !== 'all') return value;
      return (...args: unknown[]) => {
        statements += 1;
        return (value as (...a: unknown[]) => unknown).apply(target, args);
      };
    },
  });
  const hot = new Proxy(db.vault, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (key !== 'transaction') return value;
      return (work: (tx: object) => Promise<unknown>) => (value as (work: (tx: object) => Promise<unknown>) => Promise<unknown>).call(target, (tx) => work(counted(tx)));
    },
  });
  const prepared = await prepareVault(CONFIG, LOG_015);
  const vault = openVault(db.vault, prepared, hot);
  await vault.about();
  const { secretId: _, place: __, requestId: ___, ...one } = ask(w, ids[0]!, { purpose: 'reveal' });
  const many = (keys: readonly string[]): UseManyInput => ({ ...one, items: keys.map((secretId) => ({ secretId, place: null, requestId: newRequestId() })) });
  const before = statements;
  const outcome = await vault.useMany!(many(ids));
  assert.ok(!outcome.ok && 'code' in outcome, JSON.stringify(outcome).slice(0, 200));
  assert.deepEqual([outcome.index, outcome.code], [1000, 'bulk_limit']);
  // Two rounds (decided, then entered) of 11 statements of at most 100 keys: each a handful of reads for the batch,
  // one a kind for its keys' rows, and its writes; each key's use alone is some 20.
  const calls = 2 * Math.ceil(ids.length / prepared.uses.limits.batch);
  assert.ok(statements - before <= 20 * calls, `${statements - before} statements for ${calls} batch statements`);
  const [set] = await rows<{ n: number }>(db.owner, sql`SELECT count(*) AS n FROM log_bulk WHERE principal = ${w.principal}`);
  assert.equal(Number(set!.n), 1000, 'the cap holds');
});

test('a batch answers each key as its use alone does, row for row, and writes the same, around the cap\'s bound', sqliteOnly, async () => {
  const w = await namedWorld(db, LIMIT);
  const at = Date.now();
  const refresh = refreshMs(LIMIT);
  const period = periodOf(at, refresh);
  const [fresh1, fresh2, stale, older, out, gone] = [await w.key(), await w.key(), await w.key(), await w.key(), await w.key(), await w.key()];
  const entering = [await w.key(), await w.key(), await w.key(), await w.key()];
  const reference = await w.reference('REF');
  const ended = await w.reference('ENDED');
  await w.end(ended);
  await w.remove(gone);
  const elsewhere = await w.key('there', false, await w.environment('staging'));
  const nowhere = randomUUID();
  const covered = await w.key();
  // An entry for `covered`'s cover to name, newer than every input, and one no row holds.
  const [head] = await rows<{ n: number }>(db.owner, sql`SELECT max(number) AS n FROM log_changes`);
  const someoneElse = Array.from({ length: 20 }, () => randomUUID());
  const entry = { number: String(Number(head!.n) + 1), at: at - 1000, requestId: newRequestId(), until: at + 60_000 };
  const entryMac = randomBytes(16);
  const start = async () => {
    await run(db.owner, sql`DELETE FROM log_uses`);
    await run(db.owner, sql`DELETE FROM log_bulk`);
    await run(db.owner, sql`INSERT INTO log_uses (number, at, request_id, credential, secret, purpose, mac, place)
      VALUES (${BigInt(entry.number)}, ${entry.at}, ${BigInt(entry.requestId)}, ${w.credentialId}, ${covered}, 1, ${entryMac}, NULL)`);
    const cap = (secret: string, last: number, principal = w.principal) => run(db.owner, sql`INSERT INTO log_bulk (principal, secret, last) VALUES (${principal}, ${secret}, ${last})`);
    // In the set, this period's; in it, an earlier period's (moved on); past the set, but counted against a new key
    // (`window + refresh + deadline + ahead`); past both.
    await cap(fresh1, period);
    await cap(fresh2, period);
    await cap(covered, period);
    await cap(stale, period - 2 * refresh);
    await cap(older, at - WINDOW - refresh - 1_000);
    await cap(out, at - WINDOW - refresh - 10 * 60_000);
    // Another principal's rows count for nobody here.
    for (const secret of someoneElse) await cap(secret, period, 'token:someone-else');
  };
  // Four in the set or counted (fresh1, fresh2, covered, stale) and one counted only against new keys (older): of
  // count 6, one new key enters, the next is over the cap; repeats in the batch count once; a key with no row, one
  // gone, one elsewhere, a reference, an ended one; `covered` by its entry, `fresh1` by none.
  const keys = [fresh1, entering[0]!, entering[1]!, fresh1, entering[0]!, stale, out, older, reference.holder, ended.holder, gone, elsewhere, nowhere,
    entering[2]!, covered, entering[3]!, fresh2, stale];
  const calls = (decided: (i: number) => boolean, known?: (i: number) => UseCall['known']): UseCall[] => keys.map((secretId, i) => ({
    credential: w.credentialId, secretId, requestId: newRequestId(), at, purpose: 1, place: null, mac: randomBytes(16), deadline: at + 3000,
    way: 0, principal: null,
    ...(secretId === covered ? { cover: entry } : secretId === fresh1 && i === 0 ? { cover: { ...entry, requestId: newRequestId() } } : {}),
    ...(decided(i) ? { decided: true as const } : {}),
    ...(known?.(i) === undefined ? {} : { known: known(i) }),
  }));
  const [newest] = await rows<{ number: number; mac: Buffer }>(db.owner, sql`SELECT number, mac FROM log_changes ORDER BY number DESC LIMIT 1`);
  const cached = { newest: String(newest!.number), newestMac: Buffer.from(newest!.mac), cap: LIMIT };
  const cases: [string, UseCall[]][] = [
    ['decided, probing', calls(() => true)],
    ['decided, from the cache', calls(() => true, () => cached)],
    ['a first call: those that would take the lock answer `decide`', calls(() => false)],
    ['some decided, some not', calls((i) => i % 3 === 0)],
    ['a cap of other bounds: the cache\'s, a shorter window', calls(() => true, () => ({ ...cached, cap: { count: 3, windowMs: 5 * 60_000 } }))],
    // Its first key counts from the shorter window's bound, a later one from the policy's, further back.
    ['keys of two caps in one batch', calls(() => true, (i) => (i % 2 === 0 ? { ...cached, cap: { count: 5, windowMs: 5 * 60_000 } } : undefined))],
  ];
  for (const [name, batch] of cases) {
    await start();
    const alone: UseRow[] = [];
    for (const call of batch) alone.push(await callUse(db.vault, call));
    const wroteAlone = await written();
    await start();
    const together = await callBatch(db.vault, batch, null);
    assert.deepEqual(together, alone, name);
    assert.deepEqual(await written(), wroteAlone, name);
  }
  // What the decided batch did, as the cap's rule has it: the first new key entered, the rest over the cap.
  await start();
  const rowsOf = await callBatch(db.vault, cases[0]![1], null);
  const entered = await rows<{ secret: string }>(db.owner, sql`SELECT secret FROM log_bulk WHERE principal = ${w.principal} AND last = ${period}`);
  assert.ok(entered.some((row) => row.secret === entering[0]), 'the first new key entered');
  assert.ok(!entered.some((row) => row.secret === entering[1]), 'the second, over the cap, did not');
  assert.deepEqual([rowsOf[1]!.others, rowsOf[2]!.others, rowsOf[4]!.in_set], [5, 6, true]);
});

test('a batch past its deadline once written rolls back: nothing of it stays', sqliteOnly, async () => {
  const w = await namedWorld(db);
  const ids = [await w.key(), await w.key()];
  const at = Date.now() - 2_900;
  const batch: UseCall[] = ids.map((secretId) => ({
    credential: w.credentialId, secretId, requestId: newRequestId(), at, purpose: 1, place: null, mac: randomBytes(16), deadline: at + 3000, way: 0, principal: null, decided: true,
  }));
  // Its writes, made once every key is decided, held past the deadline.
  const slowed = new Proxy(db.vault, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (key !== 'transaction') return value;
      return (work: (tx: object) => Promise<unknown>) => (value as (work: (tx: object) => Promise<unknown>) => Promise<unknown>).call(target, (tx) => work(new Proxy(tx, {
        get(inner, name) {
          const all: unknown = Reflect.get(inner, name, inner);
          if (name !== 'all') return all;
          return async (query: { queryChunks: unknown[] }, ...rest: unknown[]) => {
            if (JSON.stringify(query.queryChunks[0]).includes('INSERT INTO log_uses')) await sleep(200);
            return (all as (...a: unknown[]) => unknown).call(inner, query, ...rest);
          };
        },
      })));
    },
  }) as Database;
  await assert.rejects(callBatch(slowed, batch, null), (error: { code?: string }) => error.code === '57014');
  assert.deepEqual(await written(), { uses: [], bulk: [] });
});
