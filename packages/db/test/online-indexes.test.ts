// The indexes the migrator builds without blocking writes (T245, `online-indexes.ts`): after the migrations'
// transaction, on every run until each is built, writes going on meanwhile; a build cut short built again; a
// table partitioned by day indexed a day at a time, and a day made since taking its own.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { migrateDatabase, migrationsFolder, ONLINE_LOCK_KEY } from '../src/migrate.ts';
import { buildOnline, onlineIndex, onlineIndexes, unbuiltReason, type OnlineSession } from '../src/online-indexes.ts';
import { postgresClient, postgresSession, quoteIdentifier } from '../src/postgres.ts';

const skip = process.env.COFFRE_TEST_ENGINE === 'sqlite' ? 'Postgres only' : false;
const BASE = `postgresql://coffre_owner:local-dev-only@127.0.0.1:${process.env.COFFRE_POSTGRES_PORT ?? '55432'}/${process.env.COFFRE_TEST_DATABASE ?? 'coffre_test'}`;
const NAME = `${new URL(BASE).pathname.slice(1)}_online_${randomBytes(4).toString('hex')}`;
const url = Object.assign(new URL(BASE), { pathname: `/${NAME}` }).toString();
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const ALL = onlineIndexes([readFileSync(join(migrationsFolder('postgres'), '0082_flat_history.sql'), 'utf8')]);

before(async () => {
  if (skip) return;
  const admin = postgresClient(BASE, { max: 1 });
  try {
    await admin.unsafe(`CREATE DATABASE ${quoteIdentifier(NAME)}`);
  } finally {
    await admin.end();
  }
  assert.deepEqual(await migrateDatabase(url), { unbuilt: [] });
});

after(async () => {
  if (skip) return;
  const admin = postgresClient(BASE, { max: 1 });
  try {
    await admin.unsafe(`DROP DATABASE IF EXISTS ${quoteIdentifier(NAME)} WITH (FORCE)`);
  } finally {
    await admin.end();
  }
});

test('a migration CONCURRENTLY index is read whole, comments before it or not; any other statement is not one', () => {
  assert.deepEqual(ALL.map(({ name, table }) => `${table}.${name}`), [
    'audit_log.audit_log_vault_key_idx',
    'audit_log.audit_log_app_key_idx',
    'audit_log.audit_log_vault_idx',
    'audit_log.audit_log_app_idx',
    'audit_log.audit_log_signed_idx',
    'audit_log.audit_log_checkpoint_idx',
    'audit_log.audit_log_broken_log_idx',
    'audit_log.audit_log_policy_idx',
    'audit_log.audit_log_settings_idx',
    'audit_log.audit_log_rotation_idx',
    'audit_log.audit_log_intent_idx',
    'audit_log.audit_log_key_check_idx',
    'audit_log.audit_log_tamper_idx',
    'audit_log.audit_log_moves_idx',
    'audit_log.audit_log_frozen_idx',
    'log_reads.log_reads_by_number_idx',
    'log_uses.log_uses_by_number_idx',
  ]);
  assert.deepEqual(onlineIndex('-- why\n--\nCREATE UNIQUE INDEX CONCURRENTLY "t_x_idx" ON "t" USING btree ("x") WHERE "t"."y" = 1;'), {
    unique: true,
    name: 't_x_idx',
    table: 't',
    body: 'USING btree ("x") WHERE "t"."y" = 1',
  });
  assert.equal(onlineIndex('CREATE INDEX "t_x_idx" ON "t" USING btree ("x");'), null);
  assert.equal(onlineIndex('-- CREATE INDEX CONCURRENTLY "a" ON "b" (c);\nSELECT 1;'), null);
});

/** Each of the online indexes and whether it is valid; a partitioned one's days too, by their table. */
async function state(session: ReturnType<typeof postgresSession>) {
  return session.unsafe<{ index: string; valid: boolean; days: number; indexed: number }[]>(`
    SELECT c.relname::text AS index, i.indisvalid AS valid,
           (SELECT count(*)::int FROM pg_inherits h WHERE h.inhparent = i.indrelid) AS days,
           (SELECT count(*)::int FROM pg_inherits h WHERE h.inhparent = i.indexrelid) AS indexed
      FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
     WHERE c.relname = ANY($1) ORDER BY 1`, [ALL.map(({ name }) => name)]);
}

test('a migration run builds every online index, each partitioned table on each of its days', { skip }, async () => {
  const session = postgresSession(url);
  try {
    const found = await state(session);
    assert.deepEqual(found.map(({ index, valid }) => [index, valid]), ALL.map(({ name }) => [name, true]).sort());
    for (const { index, days, indexed } of found) {
      if (index.startsWith('log_')) assert.ok(days > 0 && indexed === days, `${index}: ${indexed} of ${days} days`);
    }
  } finally {
    await session.end();
  }
});

test('an online build waits for an older transaction without holding up writes, and the run ends once it ends', { skip }, async () => {
  const session = postgresSession(url);
  const holder = postgresSession(url, { application_name: 'coffre-online-holder' });
  const writer = postgresSession(url);
  try {
    await session.unsafe('DROP INDEX audit_log_vault_key_idx');
    await session.unsafe('DROP INDEX log_uses_by_number_idx');
    // An open snapshot, as a backup's: a concurrent build waits for it to end before it can finish.
    await holder.unsafe('BEGIN ISOLATION LEVEL REPEATABLE READ');
    await holder.unsafe('SELECT count(*) FROM spent_id_tokens');
    let ended = false;
    const run = migrateDatabase(url).finally(() => {
      ended = true;
    });
    for (let waited = 0; ; waited += 50) {
      const [waiting] = await session.unsafe<{ n: number }[]>(`
        SELECT count(*)::int AS n FROM pg_stat_activity
         WHERE application_name = 'coffre-migrations' AND query LIKE 'CREATE INDEX CONCURRENTLY%' AND wait_event_type = 'Lock'`);
      if (waiting!.n > 0) break;
      assert.ok(waited < 20_000, 'the build is waiting for the open snapshot');
      await sleep(50);
    }
    // Meanwhile a write takes its lock at once on either table: the build holds none a write waits for.
    for (const table of ['audit_log', 'log_uses']) {
      await writer.begin(async (tx) => {
        await tx.unsafe(`LOCK TABLE ${table} IN ROW EXCLUSIVE MODE NOWAIT`);
      });
    }
    await sleep(200);
    assert.equal(ended, false, 'the run waits for the snapshot');
    await holder.unsafe('COMMIT');
    assert.deepEqual(await run, { unbuilt: [] });
    assert.ok((await state(session)).every(({ valid }) => valid));
  } finally {
    await Promise.all([session.end(), holder.end(), writer.end()]);
  }
});

test('an index a cut-short build left invalid is dropped and built again; one built is left as it is', { skip }, async () => {
  const session = postgresSession(url);
  try {
    // What a run killed during CREATE INDEX CONCURRENTLY leaves: the index there, invalid.
    await session.unsafe("UPDATE pg_index SET indisvalid = false WHERE indexrelid = 'audit_log_vault_idx'::regclass");
    const [before] = await session.unsafe<{ oid: number }[]>("SELECT 'audit_log_vault_key_idx'::regclass::oid::int AS oid");
    assert.deepEqual(await migrateDatabase(url), { unbuilt: [] });
    assert.ok((await state(session)).every(({ valid }) => valid));
    const [kept] = await session.unsafe<{ oid: number }[]>("SELECT 'audit_log_vault_key_idx'::regclass::oid::int AS oid");
    assert.equal(kept!.oid, before!.oid, 'a valid index is not built again');
  } finally {
    await session.end();
  }
});

test("a run that finds every index built takes no lock a use's insert waits for: a partitioned table's index is asked first", { skip }, async () => {
  const session = postgresSession(url);
  const writer = postgresSession(url);
  try {
    // A use's and a read's insert, open: CREATE INDEX IF NOT EXISTS ... ON ONLY would wait for them (SHARE), and they for it.
    await writer.unsafe('BEGIN');
    await writer.unsafe('LOCK TABLE log_uses, log_reads IN ROW EXCLUSIVE MODE');
    const started = Date.now();
    assert.deepEqual(await migrateDatabase(url), { unbuilt: [] });
    const [waited] = await session.unsafe<{ n: number }[]>("SELECT count(*)::int AS n FROM pg_locks WHERE NOT granted");
    assert.equal(waited!.n, 0);
    assert.ok(Date.now() - started < 5_000, `${Date.now() - started} ms`);
  } finally {
    await writer.unsafe('ROLLBACK').catch(() => {});
    await Promise.all([session.end(), writer.end()]);
  }
});

test('a run that finds another building its indexes says which are not built yet; the next builds them', { skip }, async () => {
  const session = postgresSession(url);
  const other = postgresSession(url);
  try {
    await session.unsafe('DROP INDEX audit_log_vault_key_idx');
    await other.unsafe('SELECT pg_advisory_lock($1::bigint)', [ONLINE_LOCK_KEY]);
    assert.deepEqual(await migrateDatabase(url), { unbuilt: [{ name: 'audit_log_vault_key_idx', table: 'audit_log', reason: 'another migration run is building it' }] });
    await other.unsafe('SELECT pg_advisory_unlock($1::bigint)', [ONLINE_LOCK_KEY]);
    assert.deepEqual(await migrateDatabase(url), { unbuilt: [] });
    assert.ok((await state(session)).every(({ valid }) => valid));
  } finally {
    await Promise.all([session.end(), other.end()]);
  }
});

test("a partitioned table's index left part-built is finished a day at a time, and a day made since takes its own", { skip }, async () => {
  const session = postgresSession(url);
  try {
    // A run cut short after the empty index and one day's: the other days unindexed, the index invalid.
    await session.unsafe('DROP INDEX log_reads_by_number_idx');
    await session.unsafe('CREATE INDEX log_reads_by_number_idx ON ONLY log_reads USING btree (number)');
    const [first] = await session.unsafe<{ day: string }[]>(
      "SELECT c.relname::text AS day FROM pg_inherits h JOIN pg_class c ON c.oid = h.inhrelid WHERE h.inhparent = 'log_reads'::regclass ORDER BY 1 LIMIT 1");
    await session.unsafe(`CREATE INDEX ${quoteIdentifier(`${first!.day}_by_number_idx`)} ON ${quoteIdentifier(first!.day)} USING btree (number)`);
    await session.unsafe(`ALTER INDEX log_reads_by_number_idx ATTACH PARTITION ${quoteIdentifier(`${first!.day}_by_number_idx`)}`);
    assert.equal((await state(session)).find(({ index }) => index === 'log_reads_by_number_idx')?.valid, false);
    assert.deepEqual(await migrateDatabase(url), { unbuilt: [] });
    const reads = (await state(session)).find(({ index }) => index === 'log_reads_by_number_idx')!;
    assert.ok(reads.valid && reads.indexed === reads.days, `${reads.indexed} of ${reads.days} days`);
    // A day made later, as the vault makes them ahead: attached, it takes the index, empty.
    await session.unsafe("SELECT make_reads_day(current_date + 30)");
    await session.unsafe("SELECT make_day(current_date + 30)");
    for (const index of ['log_reads_by_number_idx', 'log_uses_by_number_idx']) {
      const day = (await state(session)).find((found) => found.index === index)!;
      assert.ok(day.valid && day.indexed === day.days, `${index}: ${day.indexed} of ${day.days} days`);
    }
  } finally {
    await session.end();
  }
});

test('a day retention detaches between its build and its ATTACH is left out; a failed ATTACH on a day still there fails the build', { skip }, async () => {
  const session = postgresSession(url);
  const index = ALL.find(({ name }) => name === 'log_uses_by_number_idx')!;
  const days = async () => (await session.unsafe<{ day: string }[]>(
    "SELECT c.relname::text AS day FROM pg_inherits h JOIN pg_class c ON c.oid = h.inhrelid WHERE h.inhparent = 'log_uses'::regclass ORDER BY 1")).map(({ day }) => day);
  // The builder's session, whose wait before each day's ATTACH lets `before` run first: retention's DETACH, here.
  const building = (beforeAttach: (day: number) => Promise<void>): OnlineSession => {
    let waits = 0;
    return {
      client: session,
      briefly: (run) => run(),
      waitShort: async () => {
        if (waits++ > 0) await beforeAttach(waits - 1);
      },
      waitLong: async () => {},
    };
  };
  try {
    await session.unsafe("SELECT make_day(current_date + 40)");
    const [first, ...rest] = await days();
    assert.ok(first !== undefined && rest.length > 0);
    await session.unsafe('DROP INDEX log_uses_by_number_idx');
    await buildOnline(building(async (day) => {
      if (day === 1) await session.unsafe(`ALTER TABLE log_uses DETACH PARTITION ${quoteIdentifier(first)}`);
    }), index);
    const uses = (await state(session)).find(({ index: name }) => name === index.name)!;
    assert.ok(uses.valid && uses.indexed === uses.days && uses.days === rest.length, `${uses.indexed} of ${uses.days} days`);
    // Its own index stays on the detached day, which retention drops with it.
    const [own] = await session.unsafe<{ found: boolean }[]>('SELECT to_regclass($1) IS NOT NULL AS found', [`public.${quoteIdentifier(`${first}_by_number_idx`)}`]);
    assert.equal(own!.found, true);
    await session.unsafe(`DROP TABLE ${quoteIdentifier(first)}`);

    // An ATTACH that fails on a day still attached is no race: the build fails with it.
    await session.unsafe('DROP INDEX log_uses_by_number_idx');
    // Its first brief statement is the empty index on log_uses alone; each after it, a day's ATTACH.
    let brief = 0;
    const failing: OnlineSession = {
      ...building(async () => {}),
      briefly: async (run) => {
        if (brief++ > 0) throw Object.assign(new Error('refused'), { code: '55000' });
        return run();
      },
    };
    await assert.rejects(buildOnline(failing, index), { code: '55000' });
    assert.deepEqual(await migrateDatabase(url), { unbuilt: [] });
    assert.ok((await state(session)).every(({ valid }) => valid));
  } finally {
    await session.end();
  }
});

test("a day retention detaches before the last outstanding ATTACH leaves the table's index valid, as does its only day", { skip }, async () => {
  const session = postgresSession(url);
  const index = { name: 't245_parts_n_idx', table: 't245_parts', unique: false, body: 'USING btree (n)' };
  const valid = async () => (await session.unsafe<{ valid: boolean }[]>('SELECT indisvalid AS valid FROM pg_index WHERE indexrelid = to_regclass($1)', [index.name]))[0]?.valid;
  // The builder's session; `detach` runs at its wait before the `at`-th day's ATTACH (the first wait is the empty index's).
  const detaching = (at: number, day: string): OnlineSession => {
    let waits = 0;
    return {
      client: session,
      briefly: (run) => run(),
      waitShort: async () => {
        if (waits++ === at) await session.unsafe(`ALTER TABLE t245_parts DETACH PARTITION ${day}`);
      },
      waitLong: async () => {},
    };
  };
  try {
    await session.unsafe('CREATE TABLE t245_parts (d int, n int) PARTITION BY RANGE (d)');
    await session.unsafe('CREATE TABLE t245_parts_1 PARTITION OF t245_parts FOR VALUES FROM (1) TO (2)');
    await session.unsafe('CREATE TABLE t245_parts_2 PARTITION OF t245_parts FOR VALUES FROM (2) TO (3)');
    // The first day attached, the second detached before its ATTACH: Postgres checked the parent at the first's, invalid then.
    await buildOnline(detaching(2, 't245_parts_2'), index);
    assert.equal(await valid(), true, 'the index is valid once the last day still there is attached');
    await buildOnline(detaching(-1, ''), index);
    assert.equal(await valid(), true);

    // Its only day detached before its ATTACH: no day is left to check it by.
    await session.unsafe(`DROP INDEX ${index.name}`);
    await buildOnline(detaching(1, 't245_parts_1'), index);
    assert.equal(await valid(), true, 'the index over no day is valid');
    await session.unsafe('CREATE TABLE t245_parts_3 PARTITION OF t245_parts FOR VALUES FROM (3) TO (4)');
    assert.equal(await valid(), true, 'a day made since takes its own');
  } finally {
    await session.unsafe('DROP TABLE IF EXISTS t245_parts, t245_parts_1, t245_parts_2, t245_parts_3');
    await session.end();
  }
});

test('before Postgres 16.14, where attaching a day again checks nothing, an index left invalid is made again, its days oldest first; twice, it is left to the next run', { skip }, async () => {
  const session = postgresSession(url);
  const index = { name: 't245_old_n_idx', table: 't245_old', unique: false, body: 'USING btree (n)' };
  const valid = async () => (await session.unsafe<{ valid: boolean }[]>('SELECT indisvalid AS valid FROM pg_index WHERE indexrelid = to_regclass($1)', [index.name]))[0]?.valid;
  // A day's index attached again is let be, as Postgres before 14.23, 15.18, 16.14 and 17.10 did.
  const attached = async (child: string) => (await session.unsafe<{ held: boolean }[]>('SELECT EXISTS (SELECT 1 FROM pg_inherits WHERE inhrelid = to_regclass($1)) AS held', [child]))[0]!.held;
  const older = (async (text: string, params?: unknown[]) => {
    const attach = /^ALTER INDEX \S+ ATTACH PARTITION "?([^"\s]+)"?$/.exec(text);
    if (attach !== null && (await attached(attach[1]!))) return [];
    return session.unsafe(text, params as never[]);
  }) as unknown as OnlineSession['client']['unsafe'];
  // Its waits: the first before the empty index, then one before each day's ATTACH, its re-check's and its remaking's.
  const detaching = (at: Record<number, string>): OnlineSession => {
    let waits = 0;
    return {
      client: { unsafe: older },
      briefly: (run) => run(),
      waitShort: async () => {
        const day = at[waits++];
        if (day !== undefined) await session.unsafe(`ALTER TABLE t245_old DETACH PARTITION ${day}`);
      },
      waitLong: async () => {},
    };
  };
  const days = async (...made: number[]) => {
    for (const d of made) await session.unsafe(`CREATE TABLE t245_old_${d} PARTITION OF t245_old FOR VALUES FROM (${d}) TO (${d + 1})`);
  };
  try {
    await session.unsafe('CREATE TABLE t245_old (d int, n int) PARTITION BY RANGE (d)');
    await days(1, 2, 3);
    // The newest day detached before its ATTACH (as a run left it, the newest since aged out): the two left indexed,
    // the parent invalid; attaching one again changes nothing, so it is made again, ending on day 2's ATTACH.
    await buildOnline(detaching({ 3: 't245_old_3' }), index);
    assert.equal(await valid(), true, 'made again, the index is valid at its last day attached');
    const [count] = await session.unsafe<{ n: number }[]>("SELECT count(*)::int AS n FROM pg_inherits WHERE inhparent = to_regclass('t245_old_n_idx')");
    assert.equal(count!.n, 2);

    // Its remaking's newest day detached too: left invalid, for the next run, which the migrator reports as unbuilt.
    await session.unsafe(`DROP INDEX ${index.name}`);
    await session.unsafe('DROP TABLE t245_old_3');
    await days(3);
    await assert.rejects(buildOnline(detaching({ 3: 't245_old_3', 7: 't245_old_2' }), index), (error: unknown) => unbuiltReason(error) !== null);
    assert.equal(await valid(), false);
    await buildOnline(detaching({}), index);
    assert.equal(await valid(), true, 'the next run makes it again');
  } finally {
    await session.unsafe('DROP TABLE IF EXISTS t245_old, t245_old_1, t245_old_2, t245_old_3');
    await session.end();
  }
});
