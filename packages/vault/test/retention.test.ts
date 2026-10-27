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
import { sql } from 'drizzle-orm';
import pg from 'pg';

import { Checkpointer } from '../src/checkpointer.ts';
import { logObject } from '../src/inputs.ts';
import { DAYS_AHEAD, upkeep } from '../src/log-checkpointer.ts';
import { authentic, logMacKey, RETENTION_OBJECT, retentionCut } from '../src/log-entry.ts';
import { logStore, type LogStore } from '../src/log-store.ts';
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

/** Two days, ten and nine days ago, and the midnight between them. */
const D10 = dayOf(Date.now() - 10 * DAY_MS);
const D9 = dayOf(Date.now() - 9 * DAY_MS);
const MIDNIGHT = Date.parse(`${D9}T00:00:00Z`);
/** A small freshness bound, so that a test waits it out: the signer's and retention's alike. */
const FRESH = 150;
const RANGE = 512;

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
  await log.empty();
  await log.days();
  if (ENGINE === 'postgres') {
    // A day a test left detached (dropped by a run it did not make) goes, and both days are made again.
    for (const day of [D10, D9]) await run(db.owner, sql.raw(`DROP TABLE IF EXISTS log_uses_${day.replaceAll('-', '')}`));
    await run(db.owner, sql`SELECT make_day(${D10}::date), make_day(${D9}::date)`);
  }
});

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function open() {
  const alerts: string[] = [];
  const store = logStore(db.vault, { tileRange: RANGE });
  const cp = await Checkpointer.open(store, signers, { memory: variableMemory(), authentic: authentic(macKey), alert: (m) => alerts.push(m), freshMs: FRESH });
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

/** A new pair, its time now: the log moving on, as weeks of it would before a day is due. */
async function later(cp: Checkpointer) {
  await sleep(2 * FRESH + 50);
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
  const early = await retain(cp, store, { keepDays: 9, macKey });
  assert.deepEqual(early.dropped, []);
  assert.match(early.waiting ?? '', /not two freshness bounds past it/);
  const [first] = await rows<{ n: number }>(db.owner, sql`SELECT count(*) AS n FROM log_changes WHERE request_id LIKE 'retention:%'`);
  assert.equal(Number(first!.n), 1);

  // Later: D10 goes, alone (D9 is not due yet), with the change written for it; D9's uses numbered below the cut stay.
  await later(cp);
  const r = await retain(cp, store, { keepDays: 9, macKey });
  assert.equal(r.waiting, null);
  assert.deepEqual(r.dropped.map((d) => d.day), [D10]);
  for (const n of d10) assert.equal(await store.locate(n), null, `${n} dropped`);
  for (const n of d9) assert.ok(await store.locate(n), `${n}, a straggler below the cut, kept`);
  // On Postgres the day is detached, and dropped by the next run, seconds or an hour later: never right after.
  assert.deepEqual(r.detached, ENGINE === 'postgres' ? [D10] : []);
  if (ENGINE === 'postgres') {
    assert.equal(await exists(`log_uses_${D10.replaceAll('-', '')}`), true);
    assert.deepEqual((await retain(cp, store, { keepDays: 9, macKey })).detached, []);
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
  const next = await retain(cp, store, { keepDays: 1, macKey });
  assert.deepEqual(next.dropped, [{ day: D9, change: null }]);
  for (const n of d9) assert.equal(await store.locate(n), null);
  await retain(cp, store, { keepDays: 1, macKey });
  assert.deepEqual(await store.days(), [dayOf(Date.now()), dayOf(Date.now() + DAY_MS)].slice(0, ENGINE === 'postgres' ? 2 : 1));
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

test('a dropped use put back is never sealed again', async () => {
  const { cp, store, alerts } = await open();
  const { d10 } = await midnight(cp);
  const [copy] = await rows<Record<string, unknown>>(db.owner, sql`SELECT * FROM log_uses WHERE number = ${d10[0]!}`);
  await later(cp);
  assert.deepEqual((await retain(cp, store, { keepDays: 9, macKey })).waiting, null);
  await retain(cp, store, { keepDays: 9, macKey });
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
  await retain(cp, store, { keepDays: 1, macKey });
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
  await assert.rejects(retain(cp, crashing, { keepDays: 1, macKey }), /crash/);
  // The change stands, sealed; the uses below it are not walked, and the log verifies meanwhile.
  assert.ok((await verify(store)).ok);
  await later(cp);
  const r = await retain(cp, crashing, { keepDays: 1, macKey });
  assert.deepEqual(r.dropped.map((d) => [d.day, d.change]), [[D10, null], [D9, null]]);
  await retain(cp, crashing, { keepDays: 1, macKey });
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
  const reader = new pg.Client({ connectionString: VAULT_URL });
  await reader.connect();
  await reader.query('BEGIN');
  await reader.query('SELECT count(*) FROM log_uses');
  try {
    const held = await retain(cp, store, { keepDays: 1, macKey });
    assert.match(held.waiting ?? '', new RegExp(`^${D10}: a reader holds the table past the lock timeout`));
    assert.deepEqual(held.detached, []);
    assert.equal(await exists(`log_uses_${D10.replaceAll('-', '')}`), true);
  } finally {
    await reader.query('ROLLBACK');
    await reader.end();
  }
  const r = await retain(cp, store, { keepDays: 1, macKey });
  assert.deepEqual(r.detached, [D10, D9]);
  assert.equal(r.waiting, null);
});

test('the upkeep makes the next days ahead and prunes the bulk cap\'s rows its window no longer counts', async () => {
  const { cp, store } = await open();
  // The policy's window, as the change path logs it: 15 minutes.
  await log.change(JSON.stringify({ op: 'genesis', value: { kind: 'policy', bulk: { count: 1000, windowMs: 900_000 } } }), Date.now(), logObject('policy', 'instance'));
  await run(db.owner, sql`DELETE FROM log_bulk`);
  const old = Date.now() - 900_000 - 60_000 - 3000 - 3_600_000 - 60_000;
  await run(db.owner, sql`INSERT INTO log_bulk (principal, secret, last) VALUES ('token:a', ${randomUUID()}, ${old}), ('token:a', ${randomUUID()}, ${Date.now()})`);
  const alerts: string[] = [];
  const keep = upkeep(cp, store, { keepDays: null, seed, alert: (m) => alerts.push(m) });
  await keep();
  await keep();
  assert.deepEqual(alerts, []);
  const [bulk] = await rows<{ n: number }>(db.owner, sql`SELECT count(*) AS n FROM log_bulk`);
  assert.equal(Number(bulk!.n), 1, 'the old row pruned, the fresh one kept');
  if (ENGINE === 'postgres') {
    for (let d = -1; d <= DAYS_AHEAD; d += 1) assert.ok(await exists(`log_uses_${dayOf(Date.now() + d * DAY_MS).replaceAll('-', '')}`), `day ${d}`);
  }
});

test('the database drops nothing a sealed retention change does not cut, and never yesterday\'s uses', { skip: ENGINE === 'postgres' ? false : 'Postgres only: its functions' }, async () => {
  const { cp, store } = await open();
  await midnight(cp);
  const vault = db.vault;
  const refused = async (query: ReturnType<typeof sql>, said: RegExp) => assert.rejects(run(vault, query), (e: Error) => said.test(`${e.message} ${(e.cause as Error | undefined)?.message}`));
  await refused(sql`SELECT drop_day(${D10}::date)`, /no sealed retention change cuts the uses of/);
  await refused(sql`SELECT drop_day(${dayOf(Date.now() - DAY_MS)}::date)`, /are not past/);
  await refused(sql`SELECT drop_tiles(1)`, /no sealed retention change cuts the uses tree/);
  const payload = JSON.stringify({ op: 'retention', day: D10, cut: { upto: '1', at: 0, uses: 1, root: '00'.repeat(32) } });
  await refused(sql`SELECT log_retention('retention:x', 0, ${payload}, ${randomBytes(16)})`, /is no checkpoint past its end/);
  // The checkpoint past the end, named with another uses head: refused too.
  const cut = (await store.cutAt(MIDNIGHT))!;
  const pair = (await openPair(cut.notes, verifiers))!;
  const wrong = JSON.stringify({ op: 'retention', day: D10, cut: { upto: String(cut.upto), at: pair.at, uses: pair.uses.size, root: '00'.repeat(32) } });
  await refused(sql`SELECT log_retention('retention:y', 0, ${wrong}, ${randomBytes(16)})`, /is no checkpoint past its end/);
  // The vault's login writes no log table itself.
  await refused(sql`DELETE FROM log_uses`, /permission denied/);
});


test('R48: retention\'s reads cost the same at 10k and at 1M entries: a day\'s cut, the newest sealed cut, the newest retention change', { skip: ENGINE === 'postgres' ? false : 'Postgres only: buffers', timeout: 600_000 }, async () => {
  const { cp, store } = await open();
  await midnight(cp);
  await later(cp);
  await retain(cp, store, { keepDays: 1, macKey });
  /**
   * History around it: uses of today, changes of other objects, and checkpoints, one for every hundred entries, their
   * floors rising as a busy log's do (their notes are not opened here).
   */
  const grow = async (total: number) => {
    const now = Date.now();
    const top = BigInt((await rows<{ n: string }>(db.owner, sql`SELECT max(upto)::text AS n FROM log_checkpoints`))[0]!.n);
    await run(db.owner, sql`INSERT INTO log_uses (number, at, request_id, credential, secret, purpose, mac, place)
      SELECT nextval('log_number'), ${now - 60_000}::bigint + g % 60000, g, gen_random_uuid(), gen_random_uuid(), 1, ${randomBytes(16)}, NULL FROM generate_series(1, ${total}) g`);
    await run(db.owner, sql`INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
      SELECT nextval('log_number'), ${now}, 'history-' || g || '-' || ${String(total)}, gen_random_uuid(), 'system:x', '{"op":"x"}', NULL, ${randomBytes(16)} FROM generate_series(1, ${total / 100}) g`);
    await run(db.owner, sql`INSERT INTO log_checkpoints (upto, at, at_floor, changes_size, changes_root, changes_note, uses_size, uses_root, uses_note)
      SELECT ${top}::bigint + g * 100, ${now}, ${now - 3000}::bigint + g, 0, ${Buffer.alloc(32)}, 'x', 0, ${Buffer.alloc(32)}, 'x' FROM generate_series(1, ${total / 100}) g`);
    await run(db.owner, sql`VACUUM ANALYZE`);
  };
  const vault = new pg.Client({ connectionString: VAULT_URL });
  await vault.connect();
  const statements = {
    cut: `SELECT k.upto, k.changes_note, k.uses_note FROM log_checkpoints k WHERE k.at_floor >= ${MIDNIGHT} ORDER BY k.at_floor, k.upto LIMIT 1`,
    sealed: 'SELECT * FROM log_cut()',
    newest: `SELECT c.number FROM log_changes c WHERE c.object = '${RETENTION_OBJECT}'::uuid AND c.number <= (SELECT coalesce(max(k.upto), -1) FROM log_checkpoints k) ORDER BY c.number DESC LIMIT 1`,
  };
  const buffers = async () => {
    const counted: Record<string, number> = {};
    for (const [name, text] of Object.entries(statements)) {
      for (let i = 0; i < 2; i += 1) {
        const { rows: [plan] } = await vault.query(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${text}`);
        const node = (plan as { 'QUERY PLAN': { Plan: { 'Shared Hit Blocks': number; 'Shared Read Blocks': number } }[] })['QUERY PLAN'][0]!.Plan;
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
