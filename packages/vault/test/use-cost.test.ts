// 0.15's use costs one statement, and the same however long the log grows (R42,
// R48): its call's buffers, counted by EXPLAIN over the function's own statements,
// at 10k and at 1M entries of history, uses, changes and 0.14's log alike, in
// both forms (probing, and from the seal cache).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { createDatabase } from '@coffre/db';
import { postgresClient, type PostgresClient } from '@coffre/db/connect';
import { sql } from 'drizzle-orm';

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
function counting(): { pool: PostgresClient; statements: () => number } {
  let statements = 0;
  const pool = new Proxy(postgresClient(HOT_URL, { max: 2 }), {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (key !== 'unsafe') return value;
      return (...args: unknown[]) => {
        statements += 1;
        return (value as (...a: unknown[]) => unknown).apply(target, args);
      };
    },
  });
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
  // Written past the cutover, as 0.15's vault writes them (`log015`).
  await run(db.owner, sql`INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, subject_principal, metadata, prev_hash, mac, hash, log015)
    SELECT (SELECT coalesce(max(seq), 0) FROM audit_log) + g, 'vault', 'vault:x', ${now}, 'system:x', CASE WHEN g % 10 = 0 THEN 'access.grant' ELSE 'secret.read' END, 'allow',
           'token:other-' || (g % 1000), '{}', ${Buffer.alloc(32)}, ${Buffer.alloc(32)}, ${Buffer.alloc(32)}, true
      FROM generate_series(1, ${others}) g`);
  // As autovacuum leaves a table that stopped growing: index-only probes read no heap.
  await run(db.owner, sql`VACUUM ANALYZE`);
}

test('R48: a use is one statement, its buffers the same at 10k and at 1M entries, probing and from the cache', { ...postgresOnly('the hot path'), timeout: 600_000 }, async () => {
  const w = await world();
  const id = await w.key();
  const { pool, statements } = counting();
  const vault = openVault(db.vault, await prepareVault(CONFIG, LOG_015), createDatabase(pool));
  // One statement per use, whichever form: the first probes, the next is from the cache. The first, its key not yet in
  // the principal's set, would take their lock: decided first, then made, a second (DecideBeforeLock; review r2 of D153).
  try {
    for (const purpose of ['run', 'reveal', 'compare'] as const) {
      const before = statements();
      const outcome = await vault.use!(ask(w, id, { purpose }));
      assert.ok(outcome.ok, JSON.stringify(outcome));
      assert.equal(statements() - before, purpose === 'run' ? 2 : 1, `a ${purpose} use's statements`);
    }
  } finally {
    await pool.end();
  }

  // Each form's buffers, as the hot login runs it again on a connection of its own, its plans made. The least of
  // several runs: every run inserts its use, and an insert now and then splits an index page or extends the heap,
  // eight or so buffers more (50 and 51 where 41 and 42 are the rule, one run in 400), which no size of history
  // moves. The first run is the cold one, and it costs thousands.
  const client = postgresClient(HOT_URL, { max: 1 });
  // What a named use names (T145, 0034): its token's hash, its place's slugs and its key's name, for which the call
  // also reads the rows the app checks.
  const [names] = await rows<{ token_hash: Buffer; project: string; key: string }>(db.owner, sql`SELECT c.token_hash, p.slug AS project, s.key
    FROM credentials c, secrets s JOIN projects p ON p.id = s.project_id WHERE c.id = ${w.credentialId} AND s.id = ${id}`);
  const buffers = async (cached: boolean, named = false): Promise<number> => {
    let least = Infinity;
    for (let i = 0; i < 6; i += 1) {
      const [newest] = await rows<{ number: string; mac: Buffer }>(db.owner, sql`SELECT number, mac FROM log_changes ORDER BY number DESC LIMIT 1`);
      const at = Date.now();
      const requestId = newRequestId();
      const mac = entryMac({ tag: randomBytes(4), key: randomBytes(32) }, { tree: 'uses', row: { at, requestId: BigInt(requestId), credential: w.credentialId, secret: id, purpose: 4, place: null } });
      // Named, as the app asks: its config accepting the credential (0045's `p_signin`), so that the call reads its names.
      const call = 'use_credential($1, $2, $3, $4, 4::smallint, NULL, $5, $6, NULL, NULL, NULL, $7, $8, $9, $10, $11, $12, $13, $14, p_signin => $15)';
      const argsOf = (request: string, macOf: Buffer) => [w.credentialId, id, request, String(at), macOf, String(at + 3000), cached ? newest!.number : null, cached ? newest!.mac : null,
        cached ? 1000 : null, cached ? String(15 * 60_000) : null, named ? names!.token_hash : null, named ? names!.project : null, named ? 'dev' : null, named ? names!.key : null,
        named ? true : null] as never[];
      const args = argsOf(requestId, mac);
      if (named && i === 0) {
        // A request of its own, beside the one measured: each use's entry is its request's.
        const checked = newRequestId();
        const checkedMac = entryMac({ tag: randomBytes(4), key: randomBytes(32) }, { tree: 'uses', row: { at, requestId: BigInt(checked), credential: w.credentialId, secret: id, purpose: 4, place: null } });
        const [row] = await client.unsafe(`SELECT ${call}::text AS use`, argsOf(checked, checkedMac)) as unknown as { use: string }[];
        const answered = JSON.parse(row!.use) as { state: string | null; n_secret: string | null };
        assert.ok(answered.state !== 'unknown' && answered.n_secret === id, `the names read: ${row!.use.slice(0, 200)}`);
      }
      const [plan] = await client.unsafe(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT * FROM ${call}`, args);
      const node = (plan as unknown as { 'QUERY PLAN': { Plan: { 'Shared Hit Blocks': number; 'Shared Read Blocks': number } }[] })['QUERY PLAN'][0]!.Plan;
      least = Math.min(least, node['Shared Hit Blocks'] + node['Shared Read Blocks']);
    }
    return least;
  };
  const at = async (size: number) => ({ size, probing: await buffers(false), cached: await buffers(true), named: await buffers(true, true) });
  await grow(10_000);
  const small = await at(10_000);
  await grow(990_000);
  const large = await at(1_000_000);
  await client.end();
  console.log(JSON.stringify({ small, large }));
  // Flat: no statement reads history, only probes it by index. Of the indexes a use reads, only the uses' own
  // (at, request_id) grows a level from 10k to 1M here: its insert and a cover's probe of it, a buffer each at most.
  for (const form of ['probing', 'cached', 'named'] as const) {
    assert.ok(large[form] - small[form] <= 2, `${form}: ${small[form]} buffers at 10k, ${large[form]} at 1M`);
  }
});

test("D153: a named use reads what it names by index, its buffers the same at 1k places and at 10k, its ids mapped or not", { ...postgresOnly('the hot path'), timeout: 600_000 }, async () => {
  const w = await world();
  const id = await w.key();
  const [names] = await rows<{ token_hash: Buffer; project: string; key: string }>(db.owner, sql`SELECT c.token_hash, p.slug AS project, s.key
    FROM credentials c, secrets s JOIN projects p ON p.id = s.project_id WHERE c.id = ${w.credentialId} AND s.id = ${id}`);
  /** `count` places more, each a project with its `dev` and a key of the same name: what an index tells apart, and a scan reads. */
  let made = 0;
  const grow = async (count: number) => {
    await run(db.owner, sql`INSERT INTO projects (id, slug, name) SELECT gen_random_uuid(), 'grown-' || (${made} + g), 'Grown' FROM generate_series(1, ${count}) g`);
    await run(db.owner, sql`INSERT INTO environments (id, project_id, slug, name, protected)
      SELECT gen_random_uuid(), p.id, 'dev', 'Development', false FROM projects p WHERE p.slug LIKE 'grown-%' AND NOT EXISTS (SELECT 1 FROM environments e WHERE e.project_id = p.id)`);
    await run(db.owner, sql`INSERT INTO secrets (id, project_id, environment_id, key)
      SELECT gen_random_uuid(), e.project_id, e.id, ${names!.key} FROM environments e JOIN projects p ON p.id = e.project_id
       WHERE p.slug LIKE 'grown-%' AND NOT EXISTS (SELECT 1 FROM secrets s WHERE s.environment_id = e.id)`);
    made += count;
    await run(db.owner, sql`VACUUM ANALYZE`);
  };
  // As the hot login runs it, its plans generic (`force_generic_plan`): the least of several runs, as above.
  const client = postgresClient(HOT_URL, { max: 1 });
  const buffers = async (mapped: boolean): Promise<number> => {
    let least = Infinity;
    for (let i = 0; i < 6; i += 1) {
      const at = Date.now();
      const requestId = newRequestId();
      const mac = entryMac({ tag: randomBytes(4), key: randomBytes(32) }, { tree: 'uses', row: { at, requestId: BigInt(requestId), credential: w.credentialId, secret: id, purpose: 4, place: null } });
      const argsOf = (request: string, macOf: Buffer) =>
        [mapped ? w.credentialId : null, mapped ? id : null, request, String(at), macOf, String(at + 3000), names!.token_hash, names!.project, 'dev', names!.key] as never[];
      const args = argsOf(requestId, mac);
      const call = 'use_credential($1, $2, $3, $4, 4::smallint, NULL, $5, $6, NULL, NULL, NULL, NULL, NULL, NULL, NULL, $7, $8, $9, $10, p_signin => true)';
      // What is measured reads the names: the key resolved by them, never the early answer for a credential not accepted.
      // A request of its own, beside the one measured: each use's entry is its request's.
      if (i === 0) {
        const checked = newRequestId();
        const checkedMac = entryMac({ tag: randomBytes(4), key: randomBytes(32) }, { tree: 'uses', row: { at, requestId: BigInt(checked), credential: w.credentialId, secret: id, purpose: 4, place: null } });
        const [row] = await client.unsafe(`SELECT ${call}::text AS use`, argsOf(checked, checkedMac)) as unknown as { use: string }[];
        const answered = JSON.parse(row!.use) as { state: string | null; n_secret: string | null };
        assert.ok(answered.state !== 'unknown' && answered.n_secret === id, `the names read: ${row!.use.slice(0, 200)}`);
      }
      const [plan] = await client.unsafe(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT * FROM ${call}`, args);
      const node = (plan as unknown as { 'QUERY PLAN': { Plan: { 'Shared Hit Blocks': number; 'Shared Read Blocks': number } }[] })['QUERY PLAN'][0]!.Plan;
      least = Math.min(least, node['Shared Hit Blocks'] + node['Shared Read Blocks']);
    }
    return least;
  };
  const at = async (places: number) => ({ places, mapped: await buffers(true), cold: await buffers(false) });
  await grow(100);
  const few = await at(100);
  await grow(900);
  const small = await at(1_000);
  await grow(9_000);
  const large = await at(10_000);
  await client.end();
  console.log(JSON.stringify({ few, small, large }));
  // Flat: the credential by its token's hash, the place by its slugs, the key by its name there, each by a unique index;
  // a scan of the places, or of their keys, would read a page per hundred of them. From 100 places to 1k, each index of
  // the places' tables grows a level, a page more for each probe of them, the use's own reads of its rows included:
  // past it, none until some hundred thousand.
  for (const form of ['mapped', 'cold'] as const) {
    assert.ok(large[form] - small[form] <= 2, `${form}: ${small[form]} buffers at 100 places, ${large[form]} at 10k`);
  }
});
