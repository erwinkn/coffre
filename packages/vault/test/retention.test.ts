// Retention (plan PR 7, formal/Seal.tla's retention) over 0.15's log as
// migrations 0022 and 0027 lay it out, through the vault's own login: a day of
// uses dropped below a sealed retention change, changes kept, the log still
// verifying and the uses above the cut provable; and what a database writer
// does about it after, seen. W209's retention tests, on the store: a run across
// midnight, its stragglers kept until their own day goes; a crash between the
// change and the drop; a dropped use put back; the change, a kept change or
// the cut's checkpoint deleted.
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { after, before, beforeEach, test } from 'node:test';

import { leafHash, openPair, pairSigners, pairVerifiers, verifyInclusion, verifyLog, type PairNotes, type PairSigners, type PairVerifiers } from '@coffre/core/merkle';
import { postgresClient, postgresSession } from '@coffre/db/connect';
import { sql } from 'drizzle-orm';

import { Checkpointer } from '../src/checkpointer.ts';
import { logObject } from '../src/inputs.ts';
import { DAYS_AHEAD, upkeep } from '../src/log-checkpointer.ts';
import { authentic, logMacKey, RETENTION_OBJECT, retentionCut } from '../src/log-entry.ts';
import { logStore, type LogStore } from '../src/log-store.ts';
import { checkReads, projectReads } from '../src/reads.ts';
import { DAY_MS, dayOf, retain } from '../src/retention.ts';
import { variableMemory } from './audit-tree.ts';
import { logWriter } from './log-entries.ts';
import { ENGINE, openTestDatabase, rows, run, VAULT_URL, type TestDatabase } from './database.ts';

let db: TestDatabase;
let seed: Buffer;
let signers: PairSigners;
let verifiers: PairVerifiers;
let macKey: Buffer;
let log: ReturnType<typeof logWriter>;

/**
 * The test's days, fixed at its start (`beforeEach`) from `clock` and nothing else, so that a run across 00:00 UTC, or a
 * template migrated the day before, moves none of them: today, ten and nine days ago, and the midnight between them.
 */
let TODAY: string;
let D10: string;
let D9: string;
let MIDNIGHT: number;
/** A small freshness bound, so that a test waits it out: the signer's and retention's alike. */
const FRESH = 150;
/**
 * The signer's clock: the test's start, moved on by `later` alone, which waits as long first, so that every entry,
 * stamped by the real one, is at or past it. Whether a pair is two freshness bounds past a cut is then the test's to
 * say, never a race against a loaded machine's real clock (on CI, the walk and the writes between the cut and the
 * first run took the two bounds' 300 ms, and the day went early).
 */
let clock = 0;
const now = () => clock;
const RANGE = 512;
/** A test's longest span, with room to spare: how close to 00:00 UTC a test may not start. */
const MIDNIGHT_GUARD_MS = 20_000;

before(async () => {
  db = await openTestDatabase();
  seed = randomBytes(32);
  signers = await pairSigners('coffre.test/audit', seed);
  verifiers = await pairVerifiers({ changes: signers.changes.verifierKey, uses: signers.uses.verifierKey });
  macKey = logMacKey(seed);
  log = logWriter(ENGINE === 'sqlite' ? db.vault : db.owner, macKey);
});
after(() => db?.close());
beforeEach(async () => {
  clock = Date.now();
  // `later` moves the clock on within a test, and a day due is a day of the clock: a test starting within its own length of
  // 00:00 UTC waits for it, so that the days its expectations name are the days it ends in.
  if (DAY_MS - (clock % DAY_MS) < MIDNIGHT_GUARD_MS) {
    await sleep(DAY_MS - (clock % DAY_MS) + 50);
    clock = Date.now();
  }
  TODAY = dayOf(clock);
  D10 = dayOf(clock - 10 * DAY_MS);
  D9 = dayOf(clock - 9 * DAY_MS);
  MIDNIGHT = Date.parse(`${D9}T00:00:00Z`);
  await log.empty();
  if (ENGINE === 'postgres') {
    // The days the template was migrated with (its own today, a day behind when the run is past midnight) and any a test
    // left (detached, or dropped by a run it did not make) go, empty as the log is; the days this test relies on are made.
    const left = await rows<{ name: string }>(db.owner, sql`SELECT c.relname AS name FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r' AND c.relname ~ '^log_uses_[0-9]{8}$'`);
    for (const { name } of left) await run(db.owner, sql.raw(`DROP TABLE ${name}`));
    await run(db.owner, sql`SELECT make_day(${D10}::date), make_day(${D9}::date), make_day(${TODAY}::date), make_day(${dayOf(clock + DAY_MS)}::date)`);
  }
});

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * A store whose reads' projection is past every cut, as these tests have no projector: retention waits on it otherwise
 * (T166). The T166 test below opens the store as it is (`projected` false).
 */
const projected = (store: LogStore): LogStore => ({ ...store, readsCursor: async () => ({ through: 2n ** 62n, pair: 0n, at: 0, mac: null }) });

async function open(options: { projected?: boolean } = {}) {
  const alerts: string[] = [];
  const raw = logStore(db.vault, { tileRange: RANGE });
  const store = options.projected === false ? raw : projected(raw);
  const cp = await Checkpointer.open(store, signers, { memory: variableMemory(), authentic: authentic(macKey), alert: (m) => alerts.push(m), freshMs: FRESH, now });
  return { cp, store, alerts };
}

const verify = (store: LogStore, opts: { from?: PairNotes } = {}) =>
  verifyLog(store, { verifiers, cut: retentionCut, check: (e) => (authentic(macKey)(e) ? null : 'mac'), ...opts });

/**
 * The log as a busy midnight leaves it: 600 uses of D10, the last a tenth of a second before midnight, and 40 of D9
 * from just after it, sealed in one pair with a few changes; then today's traffic in a second pair.
 */
async function midnight(cp: Checkpointer) {
  const d10: bigint[] = [];
  const d9: bigint[] = [];
  const changes: bigint[] = [];
  for (let i = 0; i < 600; i += 1) d10.push(await log.use(MIDNIGHT - 100 - (600 - i) * 1000));
  changes.push(await log.change());
  for (let i = 0; i < 40; i += 1) d9.push(await log.use(MIDNIGHT + 100 + i * 1000));
  changes.push(await log.change());
  const first = await cp.tick();
  assert.ok(first.signed, first.failures.join('; '));
  const today: bigint[] = [];
  for (let i = 0; i < 20; i += 1) today.push(await log.use());
  changes.push(await log.change());
  assert.ok((await cp.tick()).signed);
  return { d10, d9, today, changes };
}

/** A new pair, its time two bounds and more on: the log moving on, as weeks of it would before a day is due. */
async function later(cp: Checkpointer) {
  await sleep(2 * FRESH + 50);
  clock += 2 * FRESH + 50;
  await log.change();
  assert.ok((await cp.tick()).signed);
}

const exists = async (table: string) =>
  (await rows<{ found: boolean }>(db.owner, sql`SELECT to_regclass(${`public.${table}`}) IS NOT NULL AS found`))[0]!.found;

test('a day dropped below its sealed retention change, across midnight: stragglers kept until their day goes, the log verifying and provable', async () => {
  const { cp, store, alerts } = await open();
  const { d10, d9, today, changes } = await midnight(cp);
  const cutUpto = (await store.cutAt(MIDNIGHT))!.upto;
  const before = await verify(store);
  assert.ok(before.ok, before.problems.join('\n'));

  // The change is written and sealed, but its pair is not two freshness bounds past the cut yet: nothing is dropped.
  const early = await retain(cp, store, { keepDays: 9, macKey, now });
  assert.deepEqual(early.dropped, []);
  assert.match(early.waiting?.reason ?? '', /not two freshness bounds past it/);
  const [first] = await rows<{ n: number }>(db.owner, sql`SELECT count(*) AS n FROM log_changes WHERE request_id LIKE 'retention:%'`);
  assert.equal(Number(first!.n), 1);

  // Later: D10 goes, alone (D9 is not due yet), with the change written for it; D9's uses numbered below the cut stay.
  await later(cp);
  const r = await retain(cp, store, { keepDays: 9, macKey, now });
  assert.equal(r.waiting, null);
  assert.deepEqual(r.dropped.map((d) => d.day), [D10]);
  for (const n of d10) assert.equal(await store.locate(n), null, `${n} dropped`);
  for (const n of d9) assert.ok(await store.locate(n), `${n}, a straggler below the cut, kept`);
  // On Postgres the day is detached, and dropped by the next run, seconds or an hour later: never right after.
  assert.deepEqual(r.detached, ENGINE === 'postgres' ? [D10] : []);
  if (ENGINE === 'postgres') {
    assert.equal(await exists(`log_uses_${D10.replaceAll('-', '')}`), true);
    assert.deepEqual((await retain(cp, store, { keepDays: 9, macKey, now })).detached, []);
    assert.equal(await exists(`log_uses_${D10.replaceAll('-', '')}`), false);
  }
  // The uses tree's leaf tiles below the cut: the range [0, 512) gone, the tile holding the cut kept, at each level.
  if (ENGINE === 'postgres') {
    assert.equal(await exists('log_tiles_uses_0'), false);
    assert.equal(await exists('log_tiles_uses_512'), true);
  }
  const [low] = await rows<{ n: number }>(db.owner, sql`SELECT count(*) AS n FROM log_tiles WHERE tree = 'uses' AND level = 0 AND leaf + 256 <= 640`);
  assert.equal(Number(low!.n), 0);

  // The walk: the changes tree from genesis, every one kept; the uses tree from the cut.
  const v = await verify(store);
  assert.ok(v.ok, v.problems.join('\n'));
  for (const n of [...today, ...changes]) {
    const p = (await cp.prove(n))!;
    assert.ok(verifyInclusion(leafHash(p.leaf), p.index, p.size, p.proof, cp.pair.pair[p.tree].root), `${n}`);
  }
  assert.equal(await cp.prove(d10[0]!), null);
  assert.ok(cutUpto >= d9.at(-1)!, 'the cut, the first pair past the end of D10, holds D9\'s first uses too');

  // Then D9: covered by the cut already, so no second change; the stragglers go with it, and the log still verifies.
  const next = await retain(cp, store, { keepDays: 1, macKey, now });
  assert.deepEqual(next.dropped, [{ day: D9, change: null }]);
  for (const n of d9) assert.equal(await store.locate(n), null);
  await retain(cp, store, { keepDays: 1, macKey, now });
  assert.deepEqual(await store.days(), [TODAY, dayOf(clock + DAY_MS)].slice(0, ENGINE === 'postgres' ? 2 : 1));
  const again = await verify(store);
  assert.ok(again.ok, again.problems.join('\n'));
  // Incrementally, from a head the walk verified: the uses tree from there on.
  await log.use();
  assert.ok((await cp.tick()).signed);
  const on = await verify(store, { from: again.head! });
  assert.ok(on.ok && on.sealed === 1, on.problems.join('\n'));
  // Ticks go on over the dropped ranges: the edge's tiles are above every cut.
  for (let i = 0; i < 600; i += 1) await log.use();
  assert.ok((await cp.tick()).signed);
  assert.ok((await verify(store)).ok);
  assert.deepEqual(alerts, []);
});

test("the reads' projection goes on across retention's cuts, and the whole log's check of it starts at the cut: nothing found, and no use dropped looked for (T166, review r3)", async () => {
  const { cp, store } = await open({ projected: false });
  // The reads' days beside the uses', as the store's upkeep makes them.
  if (ENGINE === 'postgres') await run(db.owner, sql`SELECT make_reads_day(${D10}::date), make_reads_day(${D9}::date), make_reads_day(${TODAY}::date)`);
  await midnight(cp);
  const keys = { verifiers, mac: macKey };
  const projectedAll = async () => {
    for (let run = 0; run < 100; run += 1) {
      const { through, sealed } = await projectReads(store, keys, { steps: 100 });
      if (through >= sealed) return;
    }
    assert.fail("the projection did not catch up");
  };
  const checked = async () => {
    const problems: string[] = [];
    for (let from: bigint | null = 0n; from !== null;) {
      const stretch = await checkReads(store, keys, from);
      problems.push(...stretch.problems);
      from = stretch.next;
    }
    return problems;
  };
  // D10 due, but none of its reads listed yet: retention waits on the projector, which no day it has yet to read leaves
  // (review r4: a projector stopped through retention once skipped D9's stragglers below the cut, unsaid).
  await later(cp);
  const waiting = await retain(cp, store, { keepDays: 9, macKey, now });
  assert.deepEqual(waiting.dropped, []);
  assert.match(waiting.waiting?.reason ?? '', /the reads' projection \(through 0\) has not reached the cut/);
  await projectedAll();
  assert.deepEqual(await checked(), []);
  // D10 cut, and dropped with its reads; then D9, its stragglers with it; then the log goes on past both.
  await retain(cp, store, { keepDays: 9, macKey, now });
  await retain(cp, store, { keepDays: 9, macKey, now });
  await projectedAll();
  assert.deepEqual(await checked(), []);
  await retain(cp, store, { keepDays: 1, macKey, now });
  await retain(cp, store, { keepDays: 1, macKey, now });
  for (let i = 0; i < 30; i += 1) await log.use();
  assert.ok((await cp.tick()).signed);
  await projectedAll();
  assert.deepEqual(await checked(), []);
});

test('a dropped use put back is never sealed again', async () => {
  const { cp, store, alerts } = await open();
  const { d10 } = await midnight(cp);
  const [copy] = await rows<Record<string, unknown>>(db.owner, sql`SELECT * FROM log_uses WHERE number = ${d10[0]!}`);
  await later(cp);
  assert.deepEqual((await retain(cp, store, { keepDays: 9, macKey, now })).waiting, null);
  await retain(cp, store, { keepDays: 9, macKey, now });
  // A writer who read it before puts it back (its day made again, on Postgres), at a fresh number: its MAC holds, and no
  // original is left for a request-ID check to find. (Beside its original, the replay's key, (at, request_id), refuses
  // it.) Stamped weeks before the floor of `at`, no tick's window reads it (BarrierChecksFloor); one that did would find
  // it older than the signer's pair (FRESH_MS). The walk from genesis reads it, under a pair that does not hold it.
  if (ENGINE === 'postgres') await run(db.owner, sql`SELECT make_day(${D10}::date)`);
  const [n] = await rows<{ n: string }>(db.owner, ENGINE === 'postgres' ? sql`SELECT nextval('log_number')::text AS n` : sql`SELECT CAST(max(number) + 1 AS TEXT) AS n FROM log_changes`);
  const uses = cp.pair.pair.uses.size;
  await run(db.owner, sql`INSERT INTO log_uses (number, at, request_id, credential, secret, purpose, mac, place)
    VALUES (${BigInt(n!.n)}, ${copy!.at as number}, ${copy!.request_id as bigint}, ${copy!.credential as string}, ${copy!.secret as string}, ${copy!.purpose as number}, ${copy!.mac as Buffer}, NULL)`);
  await log.change();
  assert.ok((await cp.tick()).signed);
  assert.equal(cp.pair.pair.uses.size, uses, 'no use sealed');
  assert.equal(await cp.prove(BigInt(n!.n)), null);
  const v = await verify(store);
  assert.ok(!v.ok && v.problems.some((p) => /the uses head differ from the entries/.test(p)), v.problems.join('\n'));
  assert.deepEqual(alerts, []);
});

test('what a writer does below the cut after, seen: the retention change, a kept change, or the cut\'s checkpoint deleted; a forged change', async () => {
  const { cp, store } = await open();
  const { changes } = await midnight(cp);
  await later(cp);
  await retain(cp, store, { keepDays: 1, macKey, now });
  assert.ok((await verify(store)).ok);
  const retention = (await store.retention())!.entry.number;
  const owner = db.owner;
  async function without(table: string, where: ReturnType<typeof sql>, problem: RegExp) {
    const saved = await rows<Record<string, unknown>>(owner, sql`SELECT * FROM ${sql.raw(table)} WHERE ${where}`);
    assert.equal(saved.length, 1);
    await run(owner, sql`DELETE FROM ${sql.raw(table)} WHERE ${where}`);
    const v = await verify(store);
    assert.ok(!v.ok && v.problems.some((p) => problem.test(p)), v.problems.join('\n'));
    const columns = Object.keys(saved[0]!);
    await run(owner, sql`INSERT INTO ${sql.raw(table)} (${sql.raw(columns.join(', '))}) VALUES (${sql.join(columns.map((c) => sql`${saved[0]![c]}`), sql`, `)})`);
    assert.ok((await verify(store)).ok);
  }
  // The retention change: the walk then starts the uses tree at genesis, where its leaves are gone.
  await without('log_changes', sql`number = ${retention}`, /differ from the entries|do not give its signed head/);
  // A change below the cut: the changes tree is never cut.
  await without('log_changes', sql`number = ${changes[0]!}`, /the changes head.* differ from the entries/);
  // The checkpoint at the cut.
  const cut = retentionCut((await store.retention())!.entry)!;
  await without('log_checkpoints', sql`upto = ${cut.upto}`, /no checkpoint at the retention cut/);
  // A retention change made up and slipped into a sealed window, naming a later cut: its MAC fails, and the window's
  // pair no longer holds; one past the newest pair is not sealed, and not honoured.
  const forged = { at: Date.now(), payload: JSON.stringify({ op: 'retention', day: D9, cut: { upto: String(cp.pair.pair.upto), at: 0, uses: 1, root: '00'.repeat(32) } }) };
  const gap = cp.pair.pair.upto + 1n;
  await run(owner, sql`INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
    VALUES (${gap}, ${forged.at}, 'forged', ${RETENTION_OBJECT}, 'system:retention', ${forged.payload}, NULL, ${randomBytes(16)})`);
  const unsealed = await verify(store);
  assert.ok(!unsealed.ok && unsealed.problems.some((p) => /mac/.test(p)), unsealed.problems.join('\n'));
  assert.equal((await store.retention())!.entry.number, retention, 'past the newest pair: not the cut the walk takes');
});

test('a crash between the retention change and the drop: the next run finishes, with no second change', async () => {
  const { cp, store } = await open();
  await midnight(cp);
  await later(cp);
  let crashes = 1;
  const crashing: LogStore = Object.assign(Object.create(store), {
    dropDay: async (day: string) => {
      if (crashes-- > 0) throw new Error('crash');
      return store.dropDay(day);
    },
  });
  await assert.rejects(retain(cp, crashing, { keepDays: 1, macKey, now }), /crash/);
  // The change stands, sealed; the uses below it are not walked, and the log verifies meanwhile.
  assert.ok((await verify(store)).ok);
  await later(cp);
  const r = await retain(cp, crashing, { keepDays: 1, macKey, now });
  // A day a run on Postgres (one DETACH a run); SQLite deletes both at once.
  assert.deepEqual(r.dropped.map((d) => [d.day, d.change]), ENGINE === 'postgres' ? [[D10, null]] : [[D10, null], [D9, null]]);
  for (let i = 0; i < 3; i += 1) await retain(cp, crashing, { keepDays: 1, macKey, now });
  for (const day of [D10, D9]) assert.ok(!(await store.days()).includes(day), `${day} dropped`);
  const [count] = await rows<{ n: number }>(db.owner, sql`SELECT count(*) AS n FROM log_changes WHERE request_id LIKE 'retention:%'`);
  assert.equal(Number(count!.n), 1);
  assert.ok((await verify(store)).ok);
});

test('a reader holding the uses past drop_day\'s lock timeout makes the run wait, no alarm; the next run detaches', { skip: ENGINE === 'postgres' ? false : 'Postgres only: its locks' }, async () => {
  const { cp, store } = await open();
  await midnight(cp);
  await later(cp);
  // A backup's pg_dump, say: the whole table held ACCESS SHARE for the length of its transaction.
  const reader = postgresSession(VAULT_URL);
  await reader.unsafe('BEGIN');
  await reader.unsafe('SELECT count(*) FROM log_uses');
  try {
    const held = await retain(cp, store, { keepDays: 1, macKey, now });
    assert.deepEqual([held.waiting?.day, held.waiting?.lock], [D10, true]);
    assert.match(held.waiting?.reason ?? '', /^a reader holds the table past the lock timeout/);
    assert.deepEqual(held.detached, []);
    assert.equal(await exists(`log_uses_${D10.replaceAll('-', '')}`), true);
  } finally {
    await reader.unsafe('ROLLBACK');
    await reader.end();
  }
  // One day detached a run: D10 now, D9 the next.
  const r = await retain(cp, store, { keepDays: 1, macKey, now });
  assert.deepEqual(r.detached, [D10]);
  assert.equal(r.waiting, null);
  assert.deepEqual((await retain(cp, store, { keepDays: 1, macKey, now })).detached, [D9]);
});

/**
 * The store with the first barriers' floors given, as days past would have left them: the signer signs them as it
 * signs any floor, and reads each window from them. After the last, the database's own floor again.
 */
function pastFloors(store: LogStore, floors: number[]): LogStore {
  let last: number | null = null;
  return Object.assign(Object.create(store) as LogStore, {
    close: async (after: bigint, from: number) => {
      const real = await store.close(after, from);
      const set = floors.shift();
      const floor = set !== undefined ? { found: last ?? real.floor.found, set } : { found: last ?? real.floor.found, set: real.floor.set };
      last = set ?? null;
      return { ...real, floor };
    },
  });
}

test('review r2: two days due at once, each cut its own: a catch-up drops both, though the tiles below the newer cut went first', async () => {
  const alerts: string[] = [];
  const store = pastFloors(projected(logStore(db.vault, { tileRange: RANGE })), [MIDNIGHT - 3_600_000, MIDNIGHT + 10_000, MIDNIGHT + DAY_MS - 3_600_000]);
  const cp = await Checkpointer.open(store, signers, { memory: variableMemory(), authentic: authentic(macKey), alert: (m) => alerts.push(m), freshMs: FRESH, now });
  // D10 sealed below a floor before its end; D9 in two pairs, the first of them past D10's end; then today, past D9's.
  for (let i = 0; i < 300; i += 1) await log.use(MIDNIGHT - 3_000_000 + i * 1000);
  assert.ok((await cp.tick()).signed);
  for (let i = 0; i < 300; i += 1) await log.use(MIDNIGHT + 3_600_000 + i * 1000);
  assert.ok((await cp.tick()).signed);
  for (let i = 0; i < 300; i += 1) await log.use(MIDNIGHT + 7_200_000 + i * 1000);
  assert.ok((await cp.tick()).signed);
  for (let i = 0; i < 20; i += 1) await log.use();
  await log.change();
  assert.ok((await cp.tick()).signed);
  const [d10, d9] = [(await store.cutAt(MIDNIGHT))!, (await store.cutAt(MIDNIGHT + DAY_MS))!];
  assert.ok(d10.upto < d9.upto, 'two cuts');
  await later(cp);
  // A day a run, each cut its own, each with its change; the tiles below each newest cut go as it is sealed and fresh. A
  // day left below a newer cut (a crash, an older version's run) is not proved again from tiles that may be gone.
  const runs = [];
  for (let i = 0; i < 4; i += 1) runs.push(await retain(cp, store, { keepDays: 1, macKey, now }));
  assert.ok(runs.every((r) => r.waiting === null), JSON.stringify(runs.map((r) => r.waiting)));
  assert.deepEqual(runs.map((r) => r.detached), ENGINE === 'postgres' ? [[D10], [D9], [], []] : [[], [], [], []]);
  const changed = runs.flatMap((r) => r.dropped).filter((d) => d.change !== null).map((d) => d.day);
  assert.deepEqual(changed, [D10, D9], 'a change each');
  assert.ok(runs.some((r) => r.tiles > 0));
  for (const day of [D10, D9]) assert.ok(!(await store.days()).includes(day), `${day} dropped`);
  const v = await verify(store);
  assert.ok(v.ok, v.problems.join('\n'));
  assert.deepEqual(alerts, []);
});

test('review r2: rows deleted to push the cut later are refused: the cut is the first pair past the day by its own note', async () => {
  const { cp, store } = await open();
  await midnight(cp);
  await later(cp);
  // The first pair past D10's end and D9's, deleted: the first row past it is now a later pair, whose note says another
  // came before it past the end.
  const first = (await store.cutAt(MIDNIGHT))!;
  await run(db.owner, sql`DELETE FROM log_checkpoints WHERE upto = ${first.upto}`);
  await assert.rejects(retain(cp, store, { keepDays: 1, macKey, now }), /no pair of this log, at or below the signer's \(up to \d+\), that is the first past the day's end/);
  assert.equal((await store.retention()), null, 'no retention change');
});

test('review r2: a day that waits on the same lock for a day is an alarm', { skip: ENGINE === 'postgres' ? false : 'Postgres only: its locks' }, async () => {
  const { cp, store } = await open();
  await midnight(cp);
  await later(cp);
  const held: LogStore = Object.assign(Object.create(store) as LogStore, { dropDay: async () => Promise.reject(Object.assign(new Error('canceling statement due to lock timeout'), { code: '55P03' })) });
  const alerts: string[] = [];
  let t = clock;
  const keep = upkeep(cp, held, { keepDays: 1, seed, now: () => t, alert: (m) => alerts.push(m) });
  await keep();
  t += DAY_MS - 3_600_000;
  await keep();
  assert.deepEqual(alerts, [], 'waiting under a day: no alarm');
  t += 3_600_000;
  await keep();
  assert.equal(alerts.length, 1);
  assert.match(alerts[0]!, new RegExp(`retention has waited on ${D10} since .*a reader holds the table past the lock timeout`));
});

test('review r3: a quiet log, whose pairs have not passed a day\'s end, waits with no alarm, however long', { skip: ENGINE === 'postgres' ? false : 'Postgres only: a day with no use' }, async () => {
  const { cp, store } = await open();
  // Every day before today gone: only today's and the days made ahead are left.
  for (const day of (await store.days()).filter((d) => d < TODAY)) await run(db.owner, sql.raw(`DROP TABLE log_uses_${day.replaceAll('-', '')}`));
  await log.use();
  assert.ok((await cp.tick()).signed);
  // Three days on, today's and tomorrow's days (made ahead) are due: nothing signed past their end yet.
  let t = clock + 3 * DAY_MS;
  const alerts: string[] = [];
  const keep = upkeep(cp, store, { keepDays: 1, seed, now: () => t, alert: (m) => alerts.push(m) });
  await keep();
  assert.match((await retain(cp, store, { keepDays: 1, macKey, now: () => t })).waiting?.reason ?? '', /is not past the day's end yet/);
  for (let i = 0; i < 3; i += 1) {
    t += DAY_MS;
    await keep();
  }
  assert.deepEqual(alerts, []);
});

test('T119, item 2: the store forgets each leaf range it drops, and makes it again if a write needs it', { skip: ENGINE === 'postgres' ? false : 'Postgres only: ranges' }, async () => {
  const { cp, store } = await open();
  await midnight(cp);
  await later(cp);
  await retain(cp, store, { keepDays: 1, macKey, now });
  assert.equal(await exists('log_tiles_uses_0'), false);
  // A write into the range dropped (none does: a write's tiles are at the edge, above every cut) makes it again first.
  const top = cp.pair.pair.upto + 1_000_000n;
  await store.write({ upto: top, notes: cp.pair.notes }, { changes: [], uses: [{ level: 0, index: 0, hashes: randomBytes(32) }] });
  assert.equal(await exists('log_tiles_uses_0'), true);
  await run(db.owner, sql`DELETE FROM log_checkpoints WHERE upto = ${top}`);
});

test('the upkeep makes the next days ahead and prunes the bulk cap\'s rows its window no longer counts', async () => {
  const { cp, store } = await open();
  // The policy's window, as the change path logs it: 15 minutes.
  await log.change(JSON.stringify({ op: 'genesis', value: { kind: 'policy', bulk: { count: 1000, windowMs: 900_000 } } }), Date.now(), logObject('policy', 'instance'));
  await run(db.owner, sql`DELETE FROM log_bulk`);
  const old = Date.now() - 900_000 - 60_000 - 3000 - 3_600_000 - 60_000;
  await run(db.owner, sql`INSERT INTO log_bulk (principal, secret, last) VALUES ('token:a', ${randomUUID()}, ${old}), ('token:a', ${randomUUID()}, ${Date.now()})`);
  const alerts: string[] = [];
  const keep = upkeep(cp, store, { keepDays: null, seed, now, alert: (m) => alerts.push(m) });
  await keep();
  await keep();
  assert.deepEqual(alerts, []);
  const [bulk] = await rows<{ n: number }>(db.owner, sql`SELECT count(*) AS n FROM log_bulk`);
  assert.equal(Number(bulk!.n), 1, 'the old row pruned, the fresh one kept');
  if (ENGINE === 'postgres') {
    for (let d = -1; d <= DAYS_AHEAD; d += 1) assert.ok(await exists(`log_uses_${dayOf(clock + d * DAY_MS).replaceAll('-', '')}`), `day ${d}`);
  }
});

test('the database drops nothing a sealed retention change does not cut, and never yesterday\'s uses', { skip: ENGINE === 'postgres' ? false : 'Postgres only: its functions' }, async () => {
  const { cp, store } = await open();
  await midnight(cp);
  const vault = db.vault;
  const refused = async (query: ReturnType<typeof sql>, said: RegExp) => assert.rejects(run(vault, query), (e: Error) => said.test(`${e.message} ${(e.cause as Error | undefined)?.message}`));
  await refused(sql`SELECT drop_day(${D10}::date)`, /no sealed retention change cuts the uses of/);
  // Yesterday by the database's own clock, which decides what drop_day protects.
  await refused(sql`SELECT drop_day((clock_timestamp() AT TIME ZONE 'UTC')::date - 1)`, /are not past/);
  await refused(sql`SELECT drop_tiles(1)`, /no sealed retention change cuts the uses tree/);
  const payload = JSON.stringify({ op: 'retention', day: D10, cut: { upto: '1', at: 0, uses: 1, root: '00'.repeat(32) } });
  await refused(sql`SELECT log_retention('retention:x', 0, ${payload}, ${randomBytes(16)})`, /is not the first checkpoint past its end/);
  // The checkpoint past the end, named with another uses head: refused too.
  const cut = (await store.cutAt(MIDNIGHT))!;
  const pair = (await openPair(cut.notes, verifiers))!;
  const wrong = JSON.stringify({ op: 'retention', day: D10, cut: { upto: String(cut.upto), at: pair.at, uses: pair.uses.size, root: '00'.repeat(32) } });
  await refused(sql`SELECT log_retention('retention:y', 0, ${wrong}, ${randomBytes(16)})`, /is not the first checkpoint past its end/);
  // A later checkpoint past the end, named with its own head: not the first, refused too.
  const newest = (await store.newest())!;
  const later = (await openPair(newest.notes, verifiers))!;
  const past = JSON.stringify({ op: 'retention', day: D10, cut: { upto: String(newest.upto), at: later.at, uses: later.uses.size, root: later.uses.root.toString('hex') } });
  await refused(sql`SELECT log_retention('retention:z', 0, ${past}, ${randomBytes(16)})`, /is not the first checkpoint past its end/);
  // The vault's login writes no log table itself.
  await refused(sql`DELETE FROM log_uses`, /permission denied/);
});


test('R48: retention\'s reads cost the same at 10k and at 1M entries: a day\'s cut, the newest sealed cut, the newest retention change', { skip: ENGINE === 'postgres' ? false : 'Postgres only: buffers', timeout: 600_000 }, async () => {
  const { cp, store } = await open();
  await midnight(cp);
  await later(cp);
  await retain(cp, store, { keepDays: 1, macKey, now });
  /**
   * History around it: uses from the start of the test's day (a minute back could be yesterday's, a day with no
   * partition), changes of other objects, and checkpoints, one for every hundred entries, their
   * floors rising as a busy log's do (their notes are not opened here).
   */
  let grown = 0;
  const grow = async (total: number) => {
    const now = Date.now();
    const top = BigInt((await rows<{ n: string }>(db.owner, sql`SELECT max(upto)::text AS n FROM log_checkpoints`))[0]!.n);
    await run(db.owner, sql`INSERT INTO log_uses (number, at, request_id, credential, secret, purpose, mac, place)
      SELECT nextval('log_number'), ${Date.parse(`${TODAY}T00:00:00Z`)}::bigint + g % 60000, ${grown}::bigint + g, gen_random_uuid(), gen_random_uuid(), 1, ${randomBytes(16)}, NULL FROM generate_series(1, ${total}) g`);
    grown += total;
    await run(db.owner, sql`INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
      SELECT nextval('log_number'), ${now}, 'history-' || g || '-' || ${String(total)}, gen_random_uuid(), 'system:x', '{"op":"x"}', NULL, ${randomBytes(16)} FROM generate_series(1, ${total / 100}) g`);
    await run(db.owner, sql`INSERT INTO log_checkpoints (upto, at, at_floor, changes_size, changes_root, changes_note, uses_size, uses_root, uses_note)
      SELECT ${top}::bigint + g * 100, ${now}, ${now - 3000}::bigint + g, 0, ${Buffer.alloc(32)}, 'x', 0, ${Buffer.alloc(32)}, 'x' FROM generate_series(1, ${total / 100}) g`);
    await run(db.owner, sql`VACUUM ANALYZE`);
  };
  const vault = postgresClient(VAULT_URL, { max: 1 });
  const statements = {
    cut: `SELECT k.upto, k.changes_note, k.uses_note FROM log_checkpoints k WHERE k.at_floor >= ${MIDNIGHT} ORDER BY k.at_floor, k.upto LIMIT 1`,
    sealed: 'SELECT * FROM log_cut()',
    newest: `SELECT c.number FROM log_changes c WHERE c.object = '${RETENTION_OBJECT}'::uuid AND c.number <= (SELECT coalesce(max(k.upto), -1) FROM log_checkpoints k) ORDER BY c.number DESC LIMIT 1`,
  };
  const buffers = async () => {
    const counted: Record<string, number> = {};
    for (const [name, text] of Object.entries(statements)) {
      for (let i = 0; i < 2; i += 1) {
        const [plan] = await vault.unsafe(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${text}`);
        const node = (plan as unknown as { 'QUERY PLAN': { Plan: { 'Shared Hit Blocks': number; 'Shared Read Blocks': number } }[] })['QUERY PLAN'][0]!.Plan;
        counted[name] = node['Shared Hit Blocks'] + node['Shared Read Blocks'];
      }
    }
    return counted;
  };
  await grow(10_000);
  const small = await buffers();
  await grow(990_000);
  const large = await buffers();
  await vault.end();
  console.log(JSON.stringify({ small, large }));
  for (const name of Object.keys(statements)) assert.ok(large[name]! - small[name]! <= 2, `${name}: ${small[name]} buffers at 10k, ${large[name]} at 1M`);
});
