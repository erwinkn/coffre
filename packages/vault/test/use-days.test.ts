// A use costs the same however many days the log keeps (R48, T187): on a connection's first call, on its sixth and
// after, and once a day is made, at a handful of days and at a hundred more, as the hot login runs it and as the
// vault's own login does. The hot login plans `use_credential`'s statements once for any values (0022), and such a plan
// of `log_uses` named every day's partition until 0057: planning it read thousands of buffers more at a hundred days,
// and every use locked each day (26 locks a use at 5 days, 130 at 109, measured), past the 16 a backend takes without
// the shared lock table.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { postgresClient } from '@coffre/db/connect';
import { sql } from 'drizzle-orm';

import { entryMac, logMacKey } from '../src/log-entry.ts';
import { newRequestId } from '../src/use.ts';
import { HOT_URL, openTestDatabase, postgresOnly, rows, run, VAULT_URL, type TestDatabase } from './database.ts';
import { DAY, emptyLog, useDatabases, world } from './use-world.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
  await emptyLog();
});
after(() => db.close());

/** One call's work: its buffers (EXPLAIN's, the function's own statements and their planning included) and the locks its transaction holds after it. */
type Work = { buffers: number; locks: number };

test('T187: a use reads and locks the same at a handful of days and at a hundred more: first call, sixth and after, and once a day is made', { ...postgresOnly('the hot path'), timeout: 600_000 }, async () => {
  const w = await world();
  const id = await w.key();
  const today = new Date(Math.floor(Date.now() / DAY) * DAY);
  const day = (offset: number) => new Date(today.getTime() + offset * DAY).toISOString().slice(0, 10);
  const call = 'use_credential($1, $2, $3, $4, 4::smallint, NULL, $5, $6, $7, $8, $9, $10, $11, $12, $13)';
  // Each call its own `at`, now, and its deadline the longest a use may ask, 3 s on: a deadline past `at` + 3 s is `late`.
  const args = async (cover: { number: string; at: number; request: string } | null) => {
    const [newest] = await rows<{ number: string; mac: Buffer }>(db.owner, sql`SELECT number, mac FROM log_changes ORDER BY number DESC LIMIT 1`);
    const at = Date.now();
    const request = newRequestId();
    const mac = entryMac(logMacKey(randomBytes(32)), { tree: 'uses', row: { at, requestId: BigInt(request), credential: w.credentialId, secret: id, purpose: 4, place: null } });
    return {
      at, request, values: [w.credentialId, id, request, String(at), mac, String(at + 3000), cover?.number ?? null, cover === null ? null : String(cover.at), cover?.request ?? null,
        newest!.number, newest!.mac, 1000, String(15 * 60_000)] as never[],
    };
  };
  // The repeat a hot key's uses mostly are: one entry written (the vault's decided call), then each use rides it as its
  // cover. A cover holds within its cap period (a minute, the refresh of a 15-minute window): each run of calls starts
  // 20 s or more before the period ends, and writes its own.
  const PERIOD = 60_000;
  const covered = async () => {
    const left = PERIOD - (Date.now() % PERIOD);
    if (left < 20_000) await new Promise((done) => setTimeout(done, left + 50));
    const first = await args(null);
    const once = postgresClient(HOT_URL, { max: 1 });
    try {
      const [written] = await once.unsafe(`SELECT ${call.replace(/\)$/, ', p_decided => true)')}::text AS use`, first.values) as unknown as { use: string }[];
      const answered = JSON.parse(written!.use) as { state: string | null; number: string | number | null };
      assert.equal(answered.state, null, written!.use.slice(0, 200));
      return { number: String(answered.number), at: first.at, request: first.request };
    } finally {
      await once.end();
    }
  };

  /** Twelve calls on a connection of `url`'s login, a day made before the tenth: each one's work. Each must ride the cover. */
  const calls = async (url: string, made: string): Promise<Work[]> => {
    const cover = await covered();
    const client = postgresClient(url, { max: 1 });
    const works: Work[] = [];
    try {
      for (let i = 1; i <= 12; i += 1) {
        if (i === 10) await run(db.owner, sql`SELECT make_day(${made}::date)`);
        const { values } = await args(cover);
        let buffers = 0;
        let locks = 0;
        let rode = 0;
        await client.begin(async (tx) => {
          // Its answer filtered to a use that rode its cover: one row if it did, none if it was refused or wrote.
          const [plan] = await tx.unsafe(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT u FROM ${call} AS u WHERE u->>'state' IS NULL AND u->>'covered' = $7::text`, values);
          const node = (plan as unknown as { 'QUERY PLAN': { Plan: { 'Shared Hit Blocks': number; 'Shared Read Blocks': number; 'Actual Rows': number } }[] })['QUERY PLAN'][0]!.Plan;
          buffers = node['Shared Hit Blocks'] + node['Shared Read Blocks'];
          rode = node['Actual Rows'];
          // Every lock a relation of the call's took, held to the commit.
          const [held] = await tx.unsafe(`SELECT count(*)::integer AS n FROM pg_locks WHERE pid = pg_backend_pid() AND locktype = 'relation'`);
          locks = (held as unknown as { n: number }).n;
        });
        assert.equal(rode, 1, `${url === HOT_URL ? 'hot' : 'vault'}, call ${i}: it rode its cover`);
        works.push({ buffers, locks });
      }
    } finally {
      await client.end();
    }
    return works;
  };
  const measured = async (made: number) => ({ hot: await calls(HOT_URL, day(made)), vault: await calls(VAULT_URL, day(made + 1)) });
  const days = async () => Number((await rows<{ n: string }>(db.owner, sql`SELECT count(*)::text AS n FROM pg_inherits WHERE inhparent = 'log_uses'::regclass`))[0]!.n);

  const few = { days: await days(), ...await measured(30) };
  for (let d = 1; d <= 100; d += 1) await run(db.owner, sql`SELECT make_day(${day(-d)}::date)`);
  const many = { days: await days(), ...await measured(40) };
  console.log(JSON.stringify({ few, many }));
  assert.ok(many.days - few.days >= 100, `${few.days} days, then ${many.days}`);
  // Each call measured rode its cover, the probe of `log_uses` made: the four entries, each run's first, and no other.
  const [{ n }] = await rows<{ n: string }>(db.owner, sql`SELECT count(*)::text AS n FROM log_uses WHERE credential = ${w.credentialId}`);
  assert.equal(n, '4', 'the uses measured rode their runs\' first entries');

  for (const login of ['hot', 'vault'] as const) {
    const [a, b] = [few[login], many[login]];
    // Locks: the same on every call, the first, the sixth and after, and the one after a day is made (130 against 26 a
    // use before 0057, and 306 against 98 on the call that planned again).
    for (let i = 0; i < 12; i += 1) {
      assert.equal(b[i]!.locks, a[i]!.locks, `${login}, call ${i + 1}: ${a[i]!.locks} locks at ${few.days} days, ${b[i]!.locks} at ${many.days}`);
    }
    // Buffers past the first call: the same, but for an index page split now and then (eight or so, use-cost.test.ts).
    // A call that plans again (after a day is made, or the sixth on the vault's login) also rebuilds `log_uses`'
    // partition descriptor, about five pages a hundred days: one a ten days more is its own, the 5,800 before 0057 not.
    const steady = Math.min(...a.slice(1).map((c) => c.buffers));
    for (let i = 1; i < 12; i += 1) {
      const margin = 10 + (a[i]!.buffers > steady ? Math.ceil((many.days - few.days) / 10) : 0);
      assert.ok(b[i]!.buffers - a[i]!.buffers <= margin, `${login}, call ${i + 1}: ${a[i]!.buffers} buffers at ${few.days} days, ${b[i]!.buffers} at ${many.days}`);
    }
    // The first call plans every statement, and learns `log_uses`' partitions, a few catalog pages a day, once a
    // connection and once a day is made: 400 buffers more at a hundred days, where it read 5,800 more before 0057.
    assert.ok(b[0]!.buffers - a[0]!.buffers <= 1_000, `${login}, first call: ${a[0]!.buffers} buffers at ${few.days} days, ${b[0]!.buffers} at ${many.days}`);
  }
});
