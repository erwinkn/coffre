// The weighing's own footing (`scripts/matrix-weigh.ts`): what the matrices and `use-route.test.ts` hold a
// call and its twin to the same buffers on.
import test from 'node:test';
import assert from 'node:assert/strict';

import { postgresClient } from '@coffre/db/connect';

import { deletesSettled, horizonHeld, removeDeleted } from '../../../scripts/matrix-weigh.ts';
import { OWNER_URL } from './database.ts';

/** A transaction left open, its snapshot taken (and its id, if `withId`), until `end`. */
const opened = async (client: ReturnType<typeof postgresClient>, withId: boolean) => {
  let end!: () => void;
  const ended = new Promise<void>((resolve) => { end = resolve; });
  let begun!: () => void;
  const started = new Promise<void>((resolve) => { begun = resolve; });
  const done = client.begin('isolation level repeatable read', async (tx) => {
    await tx.unsafe(withId ? 'SELECT pg_current_xact_id()' : 'SELECT 1');
    begun();
    await ended;
  });
  await Promise.race([started, done]);
  return { end: async () => { end(); await done; }, done };
};

/**
 * 2000 rows deleted while a transaction of another database, older than the delete, runs (`deletesSettled` waits on
 * none such), then `deletesSettled` returned; `weighed` reads them by the index alone, as a weighed call's probes do,
 * and as `weigh` weighs a call: a first scan, then the least of three. A scan meets every deleted row's entry and reads
 * its heap page until it knows the row dead to all, when it marks the entry, and no scan after reads it (a bitmap scan
 * reads the pages whatever it knows, and marks nothing). Weighed so, the rows read 66 buffers while a transaction can
 * still see them, and 7 once none can (Postgres 16.14).
 */
const deletedBeside = async (t: { signal: AbortSignal }, run: (world: { owner: ReturnType<typeof postgresClient>; elsewhere: ReturnType<typeof postgresClient>; foreign: Awaited<ReturnType<typeof opened>>; weighed: () => Promise<number> }) => Promise<void>) => {
  const owner = postgresClient(OWNER_URL, { max: 1 });
  const elsewhere = postgresClient(OWNER_URL.replace(/\/[^/?]+$/, '/postgres'), { max: 1 });
  const session = postgresClient(OWNER_URL, { max: 1, connection: { enable_seqscan: 'off', enable_bitmapscan: 'off' } });
  let foreign: Awaited<ReturnType<typeof opened>> | null = null;
  try {
    await owner.unsafe('CREATE TABLE weighed_rows (id int PRIMARY KEY, pad text) WITH (autovacuum_enabled = off)');
    await owner.unsafe("INSERT INTO weighed_rows SELECT n, repeat('x', 200) FROM generate_series(1, 2000) n");
    foreign = await opened(elsewhere, true);
    await owner.unsafe('DELETE FROM weighed_rows');
    await deletesSettled(owner, t.signal);
    const scan = async () => {
      const [{ 'QUERY PLAN': [{ Plan: plan }] }] = await session.unsafe('EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT id FROM weighed_rows WHERE id > 0 ORDER BY id') as unknown as { 'QUERY PLAN': { Plan: { 'Shared Hit Blocks': number; 'Shared Read Blocks': number } }[] }[];
      return plan['Shared Hit Blocks'] + plan['Shared Read Blocks'];
    };
    const weighed = async () => {
      await scan();
      return Math.min(await scan(), await scan(), await scan());
    };
    await run({ owner, elsewhere, foreign, weighed });
  } finally {
    await foreign?.end().catch(() => undefined);
    await session.end();
    await owner.unsafe('DROP TABLE IF EXISTS weighed_rows').catch(() => undefined);
    await owner.end();
    await elsewhere.end();
  }
};

test("a transaction of another database ending while calls are weighed moves no deleted row from maybe seen to dead (horizonHeld, T238 r2: a call 146 buffers beside its twin's 111)", async (t) => {
  await deletedBeside(t, async ({ owner, foreign, weighed }) => {
    const [before, after] = await horizonHeld(owner, t.signal, async () => {
      const before = await weighed();
      await foreign.end();
      return [before, await weighed()];
    });
    // Unheld, 66 buffers beside 7: every heap page while it ran, the index's alone after.
    assert.equal(after, before, `${before} buffers while the other database's transaction ran, ${after} after it ended`);
  });
});

test("a session of this database that took its snapshot while such a transaction ran, ending while calls are weighed, moves no deleted row either (horizonHeld waits for it, T238 r3: 40 and 42 buffers above a twin)", async (t) => {
  await deletedBeside(t, async ({ owner, elsewhere, foreign, weighed }) => {
    // Its snapshot reaches back to the other database's transaction, which then ends: the hold's, taken after, does not.
    // It has an id, as an autovacuum's ANALYZE has (it writes `pg_statistic`): a session reconsiders the horizon only
    // once its snapshot's oldest has moved (`GlobalVisTestShouldUpdate`), which a transaction with no id ending moves
    // not, in a database where nothing else runs.
    const local = postgresClient(OWNER_URL, { max: 1 });
    try {
      const late = await opened(local, true);
      await foreign.end();
      const [{ pid }] = await owner.unsafe('SELECT pg_backend_pid() AS pid') as unknown as { pid: number }[];
      // It ends once the hold is seen waiting on it (its session's last statement the wait's), or else when `measure`,
      // run with it still open, ends it between its scans: the first, a hold that does not wait, fails below.
      let lateEnded = false;
      const endLate = async () => { lateEnded = true; await late.end(); };
      const watching = (async () => {
        while (!lateEnded) {
          const [{ waiting }] = await elsewhere.unsafe("SELECT count(*)::int AS waiting FROM pg_stat_activity WHERE pid = $1 AND query LIKE '%FROM pg_stat_activity%'", [pid]) as unknown as { waiting: number }[];
          if (waiting > 0) return endLate();
          await new Promise((resolve) => setImmediate(resolve));
        }
      })();
      const [before, after] = await horizonHeld(owner, t.signal, async () => {
        const before = await weighed();
        if (!lateEnded) await endLate();
        return [before, await weighed()];
      });
      await watching;
      // Held without the wait, 66 buffers beside 7, as unheld above.
      assert.equal(after, before, `${before} buffers while the late snapshot was open, ${after} after it ended`);
    } finally {
      await local.end();
    }
  });
});

test("rows taken out once settled are read alike by every session, however other databases' transactions come and go (removeDeleted, T240: bulk_cap 9 and 11 blocks beside 8)", async (t) => {
  await deletedBeside(t, async ({ owner, foreign, weighed }) => {
    // A row left, on a page the VACUUM would make all-visible. No hold: what a session takes the deleted rows for,
    // maybe seen or dead, no longer matters once they are gone.
    await owner.unsafe("INSERT INTO weighed_rows VALUES (1, 'left')");
    await removeDeleted(owner, 'weighed_rows', t.signal);
    const before = await weighed();
    await foreign.end();
    const after = await weighed();
    // Left in, 66 buffers beside 7, as unheld above.
    assert.equal(after, before, `${before} buffers while the other database's transaction ran, ${after} after it ended`);
    const [{ visible }] = await owner.unsafe(`SELECT count(*)::int AS visible FROM pg_visibility_map('weighed_rows') WHERE all_visible`) as unknown as { visible: number }[];
    assert.equal(visible, 0, 'no page all-visible, as before the VACUUM');
  });
});

test("a session of this database that takes its snapshot once deletesSettled has returned, while such a transaction runs, leaves no deleted row in (removeDeleted waits for it, Sol's review r1 of T240: all five left)", async (t) => {
  await deletedBeside(t, async ({ owner, foreign, weighed }) => {
    // Its snapshot, taken after `deletesSettled` looked, reaches back to the other database's transaction, which still
    // runs: a VACUUM while it is open leaves every deleted row, as an autovacuum's ANALYZE of the catalogs, or a session
    // starting, would.
    const local = postgresClient(OWNER_URL, { max: 1 });
    // A session of another database, which watches `owner`'s: `elsewhere`'s one connection holds that database's transaction.
    const seer = postgresClient(OWNER_URL.replace(/\/[^/?]+$/, '/postgres'), { max: 1 });
    try {
      const late = await opened(local, false);
      // `owner`'s last statement other than the wait's, so that the wait is told from `deletesSettled`'s, before.
      const [{ pid }] = await owner.unsafe('SELECT pg_backend_pid() AS pid') as unknown as { pid: number }[];
      // It ends once `removeDeleted` is seen waiting on it, or else once `removeDeleted` returned without waiting: the
      // rows a VACUUM beside it left are then counted below.
      let lateEnded = false;
      const endLate = async () => { lateEnded = true; await late.end(); };
      const watching = (async () => {
        while (!lateEnded) {
          const [{ waiting }] = await seer.unsafe("SELECT count(*)::int AS waiting FROM pg_stat_activity WHERE pid = $1 AND query LIKE '%FROM pg_stat_activity%'", [pid]) as unknown as { waiting: number }[];
          if (waiting > 0) return endLate();
          await new Promise((resolve) => setImmediate(resolve));
        }
      })();
      await removeDeleted(owner, 'weighed_rows', t.signal);
      if (!lateEnded) await endLate();
      await watching;
      const [{ left }] = await owner.unsafe("SELECT dead_tuple_count::int AS left FROM pgstattuple('weighed_rows')") as unknown as { left: number }[];
      assert.equal(left, 0, `${left} deleted rows left in`);
      const before = await weighed();
      await foreign.end();
      const after = await weighed();
      assert.equal(after, before, `${before} buffers while the other database's transaction ran, ${after} after it ended`);
    } finally {
      await local.end();
      await seer.end();
    }
  });
});
