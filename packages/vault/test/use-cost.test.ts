// 0.15's use costs one statement, and the same however long the log grows (R42,
// R48): its call's buffers, counted by EXPLAIN over the function's own statements,
// at 10k and at 1M entries of history, uses, changes and 0.14's log alike, in
// both forms (probing, and from the seal cache).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { createDatabase } from '@coffre/db';
import { sql } from 'drizzle-orm';
import pg from 'pg';

import { openVault, prepareVault } from '../src/vault.ts';
import { entryMac } from '../src/log-entry.ts';
import { newRequestId } from '../src/use.ts';
import { HOT_URL, openTestDatabase, postgresOnly, rows, run, type TestDatabase } from './database.ts';
import { ask, CONFIG, emptyLog, LOG_015, useDatabases, world } from './use-world.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
  await emptyLog();
});
after(() => db.close());

/** The hot pool, each statement counted as it is sent. */
function counting(): { pool: pg.Pool; statements: () => number } {
  const pool = new pg.Pool({ connectionString: HOT_URL, max: 2 });
  let statements = 0;
  const query = pool.query.bind(pool);
  pool.query = ((...args: unknown[]) => {
    statements += 1;
    return (query as (...a: unknown[]) => unknown)(...args);
  }) as typeof pool.query;
  return { pool, statements: () => statements };
}

/**
 * History that is not this use's: other credentials' uses, other objects'
 * changes, other principals' bulk rows and 0.14 entries. Uses are most of a
 * log; changes grow with what people do, a hundredth as fast here.
 */
async function grow(total: number): Promise<void> {
  // The smaller tables start past the depth they reach at 1M, so that only the uses' own index can grow a level.
  const uses = Math.round(total * 0.9);
  const changes = Math.max(5_000, Math.round(total * 0.01));
  const others = Math.max(50_000, Math.round(total * 0.09));
  const now = Date.now();
  await run(db.owner, sql`INSERT INTO log_uses (number, at, request_id, credential, secret, purpose, mac, place)
    SELECT nextval('log_number'), ${now - 80_000_000}::bigint + (g * 80000000::bigint / ${uses}), g, gen_random_uuid(), gen_random_uuid(), 1, ${randomBytes(16)}, NULL
      FROM generate_series(1, ${uses}) g`);
  await run(db.owner, sql`INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
    SELECT nextval('log_number'), ${now}, 'history-' || g || '-' || ${String(total)}, gen_random_uuid(), 'system:x', '{"op":"x"}', NULL, ${randomBytes(16)}
      FROM generate_series(1, ${changes}) g`);
  await run(db.owner, sql`INSERT INTO log_bulk (principal, secret, last) SELECT 'token:other-' || (g % 1000), gen_random_uuid(), ${now} FROM generate_series(1, ${others}) g`);
  await run(db.owner, sql`INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, subject_principal, metadata, prev_hash, mac, hash)
    SELECT (SELECT coalesce(max(seq), 0) FROM audit_log) + g, 'vault', 'vault:x', ${now}, 'system:x', CASE WHEN g % 10 = 0 THEN 'access.grant' ELSE 'secret.read' END, 'allow',
           'token:other-' || (g % 1000), '{}', ${Buffer.alloc(32)}, ${Buffer.alloc(32)}, ${Buffer.alloc(32)}
      FROM generate_series(1, ${others}) g`);
  // As autovacuum leaves a table that stopped growing: index-only probes read no heap.
  await run(db.owner, sql`VACUUM ANALYZE`);
}

test('R48: a use is one statement, its buffers the same at 10k and at 1M entries, probing and from the cache', { ...postgresOnly('the hot path'), timeout: 600_000 }, async () => {
  const w = await world();
  const id = await w.key();
  const { pool, statements } = counting();
  const vault = openVault(db.vault, await prepareVault(CONFIG, LOG_015), createDatabase(pool));
  // One statement per use, whichever form: the first probes, the next is from the cache.
  for (const purpose of ['run', 'reveal', 'compare'] as const) {
    const before = statements();
    const outcome = await vault.use!(ask(w, id, { purpose }));
    assert.ok(outcome.ok, JSON.stringify(outcome));
    assert.equal(statements() - before, 1, `a ${purpose} use is one statement`);
  }
  await pool.end();

  // Each form's buffers, as the hot login runs it again on a connection of its own, its plans made.
  const client = new pg.Client({ connectionString: HOT_URL });
  await client.connect();
  const buffers = async (cached: boolean): Promise<number> => {
    let last = 0;
    for (let i = 0; i < 3; i += 1) {
      const [newest] = await rows<{ number: string; mac: Buffer }>(db.owner, sql`SELECT number, mac FROM log_changes ORDER BY number DESC LIMIT 1`);
      const at = Date.now();
      const requestId = newRequestId();
      const mac = entryMac(randomBytes(32), { tree: 'uses', row: { at, requestId: BigInt(requestId), credential: w.credentialId, secret: id, purpose: 4, place: null } });
      const { rows: [plan] } = await client.query(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT * FROM use_credential($1, $2, $3, $4, 4::smallint, NULL, $5, $6, NULL, NULL, NULL, $7, $8, $9, $10)`,
        [w.credentialId, id, requestId, String(at), mac, String(at + 3000), cached ? newest!.number : null, cached ? newest!.mac : null, cached ? 1000 : null, cached ? String(15 * 60_000) : null]);
      const node = (plan as { 'QUERY PLAN': { Plan: { 'Shared Hit Blocks': number; 'Shared Read Blocks': number } }[] })['QUERY PLAN'][0]!.Plan;
      last = node['Shared Hit Blocks'] + node['Shared Read Blocks'];
    }
    return last;
  };
  const at = async (size: number) => ({ size, probing: await buffers(false), cached: await buffers(true) });
  await grow(10_000);
  const small = await at(10_000);
  await grow(990_000);
  const large = await at(1_000_000);
  await client.end();
  console.log(JSON.stringify({ small, large }));
  // Flat: no statement reads history, only probes it by index. Of the indexes a use reads, only the uses' own
  // (at, request_id) grows a level from 10k to 1M here: its insert and a cover's probe of it, a buffer each at most.
  for (const form of ['probing', 'cached'] as const) {
    assert.ok(large[form] - small[form] <= 2, `${form}: ${small[form]} buffers at 10k, ${large[form]} at 1M`);
  }
});
