// The weighing's own footing (`scripts/matrix-weigh.ts`): what the matrices and `use-route.test.ts`'s T200 hold a
// call and its twin to the same buffers on.
import test from 'node:test';
import assert from 'node:assert/strict';

import { postgresClient } from '@coffre/db/connect';

import { deletesSettled, horizonHeld } from '../../../scripts/matrix-weigh.ts';
import { ENGINE, OWNER_URL } from './database.ts';

test("a transaction of another database ending while calls are weighed moves no deleted row from maybe seen to dead (horizonHeld, T238 r2: a call 146 buffers beside its twin's 111)", { skip: ENGINE !== 'postgres' ? 'Postgres horizons' : false }, async (t) => {
  const owner = postgresClient(OWNER_URL, { max: 1 });
  const elsewhere = postgresClient(OWNER_URL.replace(/\/[^/?]+$/, '/postgres'), { max: 1 });
  // A scan by the index alone, as a weighed call's probes are: it meets every deleted row's entry and reads its heap
  // page until it knows the row dead to all, when it marks the entry, and no scan after reads it (a bitmap scan reads
  // the pages whatever it knows, and marks nothing).
  const session = postgresClient(OWNER_URL, { max: 1, connection: { enable_seqscan: 'off', enable_bitmapscan: 'off' } });
  let end!: () => void;
  const ended = new Promise<void>((resolve) => { end = resolve; });
  let foreign: Promise<unknown> | null = null;
  try {
    await owner.unsafe('CREATE TABLE weighed_rows (id int PRIMARY KEY, pad text) WITH (autovacuum_enabled = off)');
    await owner.unsafe("INSERT INTO weighed_rows SELECT n, repeat('x', 200) FROM generate_series(1, 2000) n");
    // Older than the delete, in another database: `deletesSettled` waits on none such.
    let begun!: () => void;
    const started = new Promise<void>((resolve) => { begun = resolve; });
    foreign = elsewhere.begin(async (tx) => {
      await tx.unsafe('SELECT pg_current_xact_id()');
      begun();
      await ended;
    });
    await Promise.race([started, foreign]);
    await owner.unsafe('DELETE FROM weighed_rows');
    await deletesSettled(owner, t.signal);
    const buffers = async () => {
      const [{ 'QUERY PLAN': [{ Plan: plan }] }] = await session.unsafe('EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT id FROM weighed_rows WHERE id > 0 ORDER BY id') as unknown as { 'QUERY PLAN': { Plan: { 'Shared Hit Blocks': number; 'Shared Read Blocks': number } }[] }[];
      return plan['Shared Hit Blocks'] + plan['Shared Read Blocks'];
    };
    const [before, after] = await horizonHeld(owner, async () => {
      const before = await buffers();
      end();
      await foreign;
      // The first scan after it ends, which would mark the entries were their rows now dead to all, then the one weighed.
      await buffers();
      return [before, await buffers()];
    });
    // Unheld, 66 buffers beside 7 (Postgres 16.14): every heap page while it ran, the index's alone after.
    assert.equal(after, before, `${before} buffers while the other database's transaction ran, ${after} after it ended`);
  } finally {
    end();
    await foreign?.catch(() => undefined);
    await session.end();
    await owner.unsafe('DROP TABLE IF EXISTS weighed_rows').catch(() => undefined);
    await owner.end();
    await elsewhere.end();
  }
});
