// 0.15's use costs one statement, and the same however long the log grows (R42,
// R48): its call's buffers, counted by EXPLAIN over the function's own statements,
// at 10k and at 1M entries of history, uses, changes and 0.14's log alike, in
// both forms (probing, and from the seal cache).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { createDatabase, type Database } from '@coffre/db';
import { postgresClient, type PostgresClient } from '@coffre/db/connect';
import { sql } from 'drizzle-orm';

import { GATE_ROLES } from '../src/decide.ts';
import { readObject } from '../src/store.ts';
import { openVault, prepareVault } from '../src/vault.ts';
import type { Input } from '../src/inputs.ts';
import { entryMac, logMacKey } from '../src/log-entry.ts';
import { newRequestId } from '../src/use.ts';
import { HOT_URL, openTestDatabase, rows, run, VAULT_URL, type TestDatabase } from './database.ts';
import { namedWorld } from './named-world.ts';
import { ask, change, CONFIG, emptyLog, LOG_015, ROOT, seal, useDatabases, world } from './use-world.ts';
import { inBulkPeriod } from './window-fixture.ts';
import { secrets } from '@coffre/db/schema';

/** What the statement-counting uses need of one bulk-cap period: each call before the last measured one may take its 3 s deadline, so room for two of them and a margin (T218). */
const PERIOD_ROOM_MS = 10_000;

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
    SELECT nextval('log_next'), ${now - 80_000_000}::bigint + (g * 80000000::bigint / ${uses}), g, gen_random_uuid(), gen_random_uuid(), 1, ${randomBytes(16)}, NULL
      FROM generate_series(1, ${uses}) g`);
  await run(db.owner, sql`INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
    SELECT nextval('log_next'), ${now}, 'history-' || g || '-' || ${String(total)}, gen_random_uuid(), 'system:x', '{"op":"x"}', NULL, ${randomBytes(16)}
      FROM generate_series(1, ${changes}) g`);
  await run(db.owner, sql`INSERT INTO bulk_cap (principal, secret, last) SELECT 'token:other-' || (g % 1000), gen_random_uuid(), ${now} FROM generate_series(1, ${others}) g`);
  // Written past the cutover, as 0.15's vault writes them (`log015`).
  await run(db.owner, sql`INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, subject_principal, metadata, prev_hash, mac, hash, log015)
    SELECT (SELECT coalesce(max(seq), 0) FROM audit_log) + g, 'vault', 'vault:x', ${now}, 'system:x', CASE WHEN g % 10 = 0 THEN 'access.grant' ELSE 'secret.read' END, 'allow',
           'token:other-' || (g % 1000), '{}', ${Buffer.alloc(32)}, ${Buffer.alloc(32)}, ${Buffer.alloc(32)}, true
      FROM generate_series(1, ${others}) g`);
  // As autovacuum leaves a table that stopped growing: index-only probes read no heap.
  await run(db.owner, sql`VACUUM (ANALYZE, PARALLEL 0)`);
}

test('R48: a use is one statement, its buffers the same at 10k and at 1M entries, probing and from the cache', { timeout: 600_000 }, async () => {
  const w = await world();
  const id = await w.key();
  const { pool, statements } = counting();
  const vault = openVault(db.vault, await prepareVault(CONFIG, LOG_015), createDatabase(pool));
  // The key enters the set in the first use; a period turning over before the next would have it write its row again (T218).
  await inBulkPeriod(PERIOD_ROOM_MS, [{ principal: w.principal, key: id }]);
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
      const mac = entryMac(logMacKey(randomBytes(32)), { tree: 'uses', row: { at, requestId: BigInt(requestId), credential: w.credentialId, secret: id, purpose: 4, place: null } });
      // Named, as the app asks: its config accepting the credential (0045's `p_signin`), so that the call reads its names.
      const call = 'use_credential($1, $2, $3, $4, 4::smallint, NULL, $5, $6, NULL, NULL, NULL, $7, $8, $9, $10, $11, $12, $13, $14, p_signin => $15)';
      const argsOf = (request: string, macOf: Buffer) => [w.credentialId, id, request, String(at), macOf, String(at + 3000), cached ? newest!.number : null, cached ? newest!.mac : null,
        cached ? 1000 : null, cached ? String(15 * 60_000) : null, named ? names!.token_hash : null, named ? names!.project : null, named ? 'dev' : null, named ? names!.key : null,
        named ? true : null] as never[];
      const args = argsOf(requestId, mac);
      if (named && i === 0) {
        // A request of its own, beside the one measured: each use's entry is its request's.
        const checked = newRequestId();
        const checkedMac = entryMac(logMacKey(randomBytes(32)), { tree: 'uses', row: { at, requestId: BigInt(checked), credential: w.credentialId, secret: id, purpose: 4, place: null } });
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

test("D153: a named use reads what it names by index, its buffers the same at 1k places and at 10k, its ids mapped or not", { timeout: 600_000 }, async () => {
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
    await run(db.owner, sql`VACUUM (ANALYZE, PARALLEL 0)`);
  };
  // As the hot login runs it, on the plans its cache settles on after its first five (T207): the least of several runs, as above.
  const client = postgresClient(HOT_URL, { max: 1 });
  const buffers = async (mapped: boolean): Promise<number> => {
    let least = Infinity;
    for (let i = 0; i < 6; i += 1) {
      const at = Date.now();
      const requestId = newRequestId();
      const mac = entryMac(logMacKey(randomBytes(32)), { tree: 'uses', row: { at, requestId: BigInt(requestId), credential: w.credentialId, secret: id, purpose: 4, place: null } });
      const argsOf = (request: string, macOf: Buffer) =>
        [mapped ? w.credentialId : null, mapped ? id : null, request, String(at), macOf, String(at + 3000), names!.token_hash, names!.project, 'dev', names!.key] as never[];
      const args = argsOf(requestId, mac);
      const call = 'use_credential($1, $2, $3, $4, 4::smallint, NULL, $5, $6, NULL, NULL, NULL, NULL, NULL, NULL, NULL, $7, $8, $9, $10, p_signin => true)';
      // What is measured reads the names: the key resolved by them, never the early answer for a credential not accepted.
      // A request of its own, beside the one measured: each use's entry is its request's.
      if (i === 0) {
        const checked = newRequestId();
        const checkedMac = entryMac(logMacKey(randomBytes(32)), { tree: 'uses', row: { at, requestId: BigInt(checked), credential: w.credentialId, secret: id, purpose: 4, place: null } });
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

test("T165: a named use at a fork, and at `dev@me`, walks the place's chain and its dismissals by index: its buffers the same at 1k forks and at 10k", { timeout: 600_000 }, async () => {
  const w = await namedWorld(db, { caller: 'person' });
  const fork = await w.fork('feature');
  await w.grantAt(fork, 'viewer');
  await w.personal();
  // Inherited, in each: dev's key, which neither the fork nor the config holds; and a name each removed, at the fork.
  const id = await w.key();
  const [names] = await rows<{ token_hash: Buffer; project: string; key: string }>(db.owner, sql`SELECT c.token_hash, p.slug AS project, s.key
    FROM credentials c, secrets s JOIN projects p ON p.id = s.project_id WHERE c.id = ${w.credentialId} AND s.id = ${id}`);
  await w.dismiss(fork, 'REMOVED');
  /** `count` projects more, each with its dev, a fork and a personal config of it, a key of that name and a dismissal of it in each. */
  let made = 0;
  const grow = async (count: number) => {
    await run(db.owner, sql`INSERT INTO projects (id, slug, name) SELECT gen_random_uuid(), 'forked-' || (${made} + g), 'Grown' FROM generate_series(1, ${count}) g`);
    await run(db.owner, sql`INSERT INTO environments (id, project_id, slug, name, protected)
      SELECT gen_random_uuid(), p.id, 'dev', 'Development', false FROM projects p WHERE p.slug LIKE 'forked-%' AND NOT EXISTS (SELECT 1 FROM environments e WHERE e.project_id = p.id)`);
    await run(db.owner, sql`INSERT INTO environments (id, project_id, slug, name, protected, parent_id)
      SELECT gen_random_uuid(), e.project_id, 'feature', 'Feature', false, e.id FROM environments e JOIN projects p ON p.id = e.project_id
       WHERE p.slug LIKE 'forked-%' AND e.slug = 'dev' AND NOT EXISTS (SELECT 1 FROM environments f WHERE f.parent_id = e.id)`);
    await run(db.owner, sql`INSERT INTO environments (id, project_id, slug, name, protected, parent_id, owner)
      SELECT gen_random_uuid(), e.project_id, 'dev-p-' || substr(md5(e.id::text), 1, 8), 'Mine', false, e.id, ${w.principal} FROM environments e JOIN projects p ON p.id = e.project_id
       WHERE p.slug LIKE 'forked-%' AND e.slug = 'dev' AND NOT EXISTS (SELECT 1 FROM environments f WHERE f.parent_id = e.id AND f.owner IS NOT NULL)`);
    await run(db.owner, sql`INSERT INTO secrets (id, project_id, environment_id, key)
      SELECT gen_random_uuid(), e.project_id, e.id, ${names!.key} FROM environments e JOIN projects p ON p.id = e.project_id
       WHERE p.slug LIKE 'forked-%' AND NOT EXISTS (SELECT 1 FROM secrets s WHERE s.environment_id = e.id)`);
    await run(db.owner, sql`INSERT INTO dismissed_keys (environment_id, key, dismissed_by)
      SELECT e.id, 'REMOVED', 'grown' FROM environments e JOIN projects p ON p.id = e.project_id
       WHERE p.slug LIKE 'forked-%' AND e.parent_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM dismissed_keys d WHERE d.environment_id = e.id)`);
    made += count;
    await run(db.owner, sql`VACUUM (ANALYZE, PARALLEL 0)`);
  };
  const client = postgresClient(HOT_URL, { max: 1 });
  /** The least of several runs' buffers, a named call by no ids (a cold isolate's), of `key` at `environment`. */
  const buffers = async (environment: string, key: string): Promise<number> => {
    let least = Infinity;
    for (let i = 0; i < 6; i += 1) {
      const at = Date.now();
      const requestId = newRequestId();
      const mac = entryMac(logMacKey(randomBytes(32)), { tree: 'uses', row: { at, requestId: BigInt(requestId), credential: w.credentialId, secret: id, purpose: 4, place: null } });
      const args = [requestId, String(at), mac, String(at + 3000), names!.token_hash, names!.project, environment, key] as never[];
      const call = `use_credential(NULL, NULL, $1, $2, 4::smallint, NULL, $3, $4, NULL, NULL, NULL, NULL, NULL, NULL, NULL, $5, $6, $7, $8,
        p_signin => true, p_roles => '${GATE_ROLES.replaceAll("'", "''")}'::jsonb, p_forks => true)`;
      if (i === 0) {
        const [row] = await client.unsafe(`SELECT ${call}::text AS use`, args) as unknown as { use: string }[];
        const answered = JSON.parse(row!.use) as { state: string | null; n_standing: boolean | null };
        assert.equal(answered.n_standing, true, `the names read, and standing: ${row!.use.slice(0, 200)}`);
      }
      const [plan] = await client.unsafe(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT * FROM ${call}`, args);
      const node = (plan as unknown as { 'QUERY PLAN': { Plan: { 'Shared Hit Blocks': number; 'Shared Read Blocks': number } }[] })['QUERY PLAN'][0]!.Plan;
      least = Math.min(least, node['Shared Hit Blocks'] + node['Shared Read Blocks']);
    }
    return least;
  };
  const at = async (places: number) => ({
    places, inherited: await buffers('feature', names!.key), removed: await buffers('feature', 'REMOVED'), mine: await buffers('dev@me', names!.key),
  });
  await grow(100);
  const few = await at(100);
  await grow(900);
  const small = await at(1_000);
  await grow(9_000);
  const large = await at(10_000);
  await client.end();
  console.log(JSON.stringify({ few, small, large }));
  for (const form of ['inherited', 'removed', 'mine'] as const) {
    assert.ok(large[form] - small[form] <= 2, `${form}: ${small[form]} buffers at 1k forks, ${large[form]} at 10k`);
  }
});

test("T165 (PR 2): a named batch's first statement reads no key without standing, the same buffers whatever the place holds; and, standing, its gate's and each key's lone use's, its own the same at 1k forks and at 10k", { timeout: 600_000 }, async (t) => {
  const w = await namedWorld(db);
  const fork = await w.fork('feature');
  await w.grantAt(fork, 'viewer');
  // Three keys of dev's, which the fork inherits, and one of its own.
  const ids = [await w.key('a'), await w.key('b'), await w.key('c'), await w.key('own', false, fork)];
  const [names] = await rows<{ token_hash: Buffer; project: string }>(db.owner, sql`SELECT c.token_hash, p.slug AS project
    FROM credentials c, projects p WHERE c.id = ${w.credentialId} AND p.id = ${w.project}`);
  const keys = await Promise.all(ids.map((id) => w.nameOf(id)));
  let made = 0;
  /** `count` projects more, each with its dev and a fork of it, three keys in each and a dismissal at the fork. */
  const grow = async (count: number) => {
    await run(db.owner, sql`INSERT INTO projects (id, slug, name) SELECT gen_random_uuid(), 'batched-' || (${made} + g), 'Grown' FROM generate_series(1, ${count}) g`);
    await run(db.owner, sql`INSERT INTO environments (id, project_id, slug, name, protected)
      SELECT gen_random_uuid(), p.id, 'dev', 'Development', false FROM projects p WHERE p.slug LIKE 'batched-%' AND NOT EXISTS (SELECT 1 FROM environments e WHERE e.project_id = p.id)`);
    await run(db.owner, sql`INSERT INTO environments (id, project_id, slug, name, protected, parent_id)
      SELECT gen_random_uuid(), e.project_id, 'feature', 'Feature', false, e.id FROM environments e JOIN projects p ON p.id = e.project_id
       WHERE p.slug LIKE 'batched-%' AND e.slug = 'dev' AND NOT EXISTS (SELECT 1 FROM environments f WHERE f.parent_id = e.id)`);
    await run(db.owner, sql`INSERT INTO secrets (id, project_id, environment_id, key)
      SELECT gen_random_uuid(), e.project_id, e.id, k FROM environments e JOIN projects p ON p.id = e.project_id CROSS JOIN unnest(${sql.param(keys.slice(0, 3))}::text[]) k
       WHERE p.slug LIKE 'batched-%' AND NOT EXISTS (SELECT 1 FROM secrets s WHERE s.environment_id = e.id)`);
    await run(db.owner, sql`INSERT INTO dismissed_keys (environment_id, key, dismissed_by)
      SELECT e.id, 'REMOVED', 'grown' FROM environments e JOIN projects p ON p.id = e.project_id
       WHERE p.slug LIKE 'batched-%' AND e.parent_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM dismissed_keys d WHERE d.environment_id = e.id)`);
    made += count;
    await run(db.owner, sql`VACUUM (ANALYZE, PARALLEL 0)`);
  };
  const client = postgresClient(HOT_URL, { max: 1 });
  // Ended however the test ends: a client left open keeps the file running to its timeout.
  t.after(() => client.end());
  const roles = `'${GATE_ROLES.replaceAll("'", "''")}'::jsonb`;
  /** The least of several runs' buffers of `call`, each with a fresh time and read MAC; `check` reads the first run's answer. */
  const least = async (call: string, argsOf: (at: number, read: Buffer) => unknown[], check: (answer: string) => void): Promise<number> => {
    let fewest = Infinity;
    for (let i = 0; i < 6; i += 1) {
      const at = Date.now();
      const read = Buffer.concat([logMacKey(randomBytes(32)).tag, Buffer.alloc(12)]);
      const args = argsOf(at, read) as never[];
      if (i === 0) {
        const [row] = await client.unsafe(`SELECT ${call}::text AS answer`, args) as unknown as { answer: string }[];
        check(row!.answer);
      }
      const [plan] = await client.unsafe(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT * FROM ${call}`, args);
      const node = (plan as unknown as { 'QUERY PLAN': { Plan: { 'Shared Hit Blocks': number; 'Shared Read Blocks': number } }[] })['QUERY PLAN'][0]!.Plan;
      fewest = Math.min(fewest, node['Shared Hit Blocks'] + node['Shared Read Blocks']);
    }
    return fewest;
  };
  /** A named batch's first statement by names alone (a cold isolate's), of `asked` at `environment`. */
  const buffers = (environment: string, asked: readonly string[] | null, stands: boolean): Promise<number> => {
    const n = asked?.length ?? 0;
    const list = <T>(value: T) => (asked === null ? null : Array.from({ length: n }, () => value));
    return least(`use_named_batch($1, $2, $3, false, '{}', true, '{}', ${roles}, $4, 4::smallint, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, 0::smallint, NULL, 100)`,
      (at, read) => [names!.token_hash, names!.project, environment, String(at), String(at + 3000), read, asked === null ? null : [...asked],
        list(null), list(null), list(null), list('0'), list(read), list(null), list(null), list(null), list(null), list(null), list(null), list(null)],
      (answer) => {
        const answered = JSON.parse(answer) as { gate: { n_standing: boolean | null }; rows: unknown[] };
        assert.equal(answered.gate.n_standing, stands, answer.slice(0, 300));
        assert.equal(answered.rows.length, stands ? (asked?.length ?? 4) : 0, 'a key read only for one who stands');
      });
  };
  /** A lone named use of `key` at `environment` by names alone, as the batch makes each of its own; null, the batch's gate. */
  const lone = (environment: string, key: string | null): Promise<number> =>
    least(`use_credential(NULL::uuid, NULL::uuid, 0::bigint, $1::bigint, 4::smallint, NULL::uuid, $2::bytea, $3::bigint,
        NULL::bigint, NULL::bigint, NULL::bigint, NULL::bigint, NULL::bytea, NULL::integer, NULL::bigint, $4::bytea, $5::text, $6::text, $7::text,
        false, false, '{}'::text[], true, '{}'::text[], ${roles}, 0::smallint, NULL::text, true)`,
      (at, read) => [String(at), read, String(at + 3000), names!.token_hash, names!.project, environment, key],
      (answer) => assert.equal((JSON.parse(answer) as { n_standing: boolean | null }).n_standing, true, answer.slice(0, 300)));
  // A batch is its gate and a lone named use of each key, in one statement, and its listing: the lone use's own buffers
  // grow with its indexes' depth, which the test above holds to the use's; what the batch adds is held flat here.
  const listedKeys = [...keys].sort();
  const namedKeys = [keys[0]!, 'NEVER_MADE', 'REMOVED'];
  const standing = async () => {
    const gate = await lone('feature', null);
    const each = async (asked: readonly string[]) => {
      let sum = gate;
      for (const key of asked) sum += await lone('feature', key);
      return sum;
    };
    const listed = await buffers('feature', null, true);
    const named = await buffers('feature', namedKeys, true);
    return { listed, named, over: { listed: listed - (await each(listedKeys)), named: named - (await each(namedKeys)) } };
  };
  await grow(100);
  const few = await standing();
  await grow(900);
  const small = await standing();
  await grow(9_000);
  const large = await standing();
  console.log(JSON.stringify({ few, small, large }));
  for (const form of ['listed', 'named'] as const) {
    // One-sided, as above: below its crossover the planner may scan a small table whole, which costs less at 10k, not more.
    assert.ok(large.over[form] - small.over[form] <= 4, `${form}: the batch's own ${small.over[form]} buffers at 1k forks, ${large.over[form]} at 10k`);
    // Its lone uses' indexes one level deeper at most: nothing read row by row, which would cost hundreds more at 10k.
    assert.ok(large[form] <= small[form] * 1.15, `${form}: ${small[form]} buffers at 1k forks, ${large[form]} at 10k`);
  }
  // Revoked at the fork: whatever is asked and whatever the place holds, the gate's buffers alone.
  await w.revokeAt(fork);
  const refused = {
    listed: await buffers('feature', null, false),
    held: await buffers('feature', keys, false),
    never: await buffers('feature', ['NEVER_1', 'NEVER_2', 'NEVER_3', 'NEVER_4'], false),
  };
  // Forty keys more at the fork: a refusal still reads none of them.
  await run(db.owner, sql`INSERT INTO secrets (id, project_id, environment_id, key) SELECT gen_random_uuid(), ${w.project}, ${fork}, 'MORE_' || g FROM generate_series(1, 40) g`);
  await run(db.owner, sql`VACUUM (ANALYZE, PARALLEL 0)`);
  const grown = await buffers('feature', null, false);
  console.log(JSON.stringify({ few, small, large, refused, grown }));
  assert.ok(Math.max(refused.listed, refused.held, refused.never, grown) - Math.min(refused.listed, refused.held, refused.never, grown) <= 2,
    `a refusal's buffers: ${JSON.stringify({ ...refused, grown })}`);
});

/**
 * T220: a use of a reference reads its key's newest reference row by `secret_references_holder_idx`, never the
 * references other keys made since. As `y.secret_id = s.id ORDER BY y.created_seq DESC LIMIT 1` (0068 and before),
 * where few keys hold many reference rows, Postgres walked `secret_references_created_seq_key` backwards instead,
 * reading each newer row of another key's before the key's own: here 5,000 of them, a key repointed over and over.
 * Another key's 5,000 older rows are there from the start, so that both measures read indexes of the same depth.
 */
test("T220: a reference's use reads its newest reference by its holder, its buffers the same however many references another key made since", { timeout: 600_000 }, async () => {
  const w = await world();
  const source = await w.key('the source');
  /**
   * A key of dev's with no value of its own and `count` reference rows to the source, each made by an entry of 0.14's
   * log past the cutover, as `grow` writes them (a row's `created_seq` names its entry): its newest row's id.
   */
  const referring = async (count: number): Promise<{ id: string; reference: string }> => {
    const id = randomUUID();
    await db.owner.insert(secrets).values({ id, projectId: w.project, environmentId: w.dev, key: `HELD_${id.slice(0, 8)}` });
    const [newest] = await rows<{ reference: string }>(db.owner, sql`WITH made AS (
        INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, metadata, prev_hash, mac, hash, log015)
        SELECT (SELECT coalesce(max(seq), 0) FROM audit_log) + g, 'vault', 'vault:x', ${Date.now()}, 'system:x', 'reference.create', 'allow', '{}',
               ${Buffer.alloc(32)}, ${Buffer.alloc(32)}, ${Buffer.alloc(32)}, true
          FROM generate_series(1, ${count}) g RETURNING seq
      ), rows AS (
        INSERT INTO secret_references (id, project_id, environment_id, secret_id, source_project_id, source_environment_id, source_secret_id, created_seq, created_by)
        SELECT gen_random_uuid(), ${w.project}, ${w.dev}, ${id}, ${w.project}, ${w.dev}, ${source}, seq, ${ROOT} FROM made RETURNING id, created_seq
      )
      SELECT id AS reference FROM rows ORDER BY created_seq DESC LIMIT 1`);
    return { id, reference: newest!.reference };
  };
  await referring(5000);
  // The key used, sealed as 0.15's vault makes one (use.test.ts).
  const { id: holder, reference } = await referring(1);
  const object: Input = { kind: 'secret', id: holder, projectId: w.project, environmentId: w.dev, version: '', nature: 'secret', key: null, digest: null, source, reference };
  await change({ kind: 'secret', id: holder }, { op: 'genesis', value: object }, object, seal('secrets', 'id', holder));
  const call = 'use_credential($1, $2, $3, $4, 4::smallint, NULL, $5, $6)';
  /**
   * A probing use of `key`'s buffers, the least of five runs on a connection of its own (the R48 test says why),
   * after one that checks what it read of the key: `read`, its source and reference.
   */
  const buffers = async (key: string, read: [string | null, string | null]): Promise<number> => {
    const client = postgresClient(HOT_URL, { max: 1 });
    try {
      let least = Infinity;
      for (let i = 0; i < 6; i += 1) {
        const at = Date.now();
        const requestId = newRequestId();
        const mac = entryMac(logMacKey(randomBytes(32)), { tree: 'uses', row: { at, requestId: BigInt(requestId), credential: w.credentialId, secret: key, purpose: 4, place: null } });
        const args = [w.credentialId, key, requestId, String(at), mac, String(at + 3000)] as never[];
        if (i === 0) {
          const [row] = await client.unsafe(`SELECT ${call}::text AS use`, args) as unknown as { use: string }[];
          const answered = JSON.parse(row!.use) as { s_source: string | null; s_reference: string | null };
          assert.deepEqual([answered.s_source, answered.s_reference], read, `what the use read of the key: ${row!.use.slice(0, 200)}`);
          continue;
        }
        const [plan] = await client.unsafe(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT * FROM ${call}`, args);
        const node = (plan as unknown as { 'QUERY PLAN': { Plan: { 'Shared Hit Blocks': number; 'Shared Read Blocks': number } }[] })['QUERY PLAN'][0]!.Plan;
        least = Math.min(least, node['Shared Hit Blocks'] + node['Shared Read Blocks']);
      }
      return least;
    } finally {
      await client.end();
    }
  };
  // As autovacuum leaves a table that stopped growing.
  const settle = () => run(db.owner, sql`VACUUM (ANALYZE, PARALLEL 0) secret_references, secrets, audit_log`);
  await settle();
  // The reference's use, and the source's, a key with a value of its own. On 0068, the reference's read 254 buffers
  // alone, 105 here: its source holds no reference row, which its source's lookup (`xref`) found only once it had
  // read every row there is; and 542 behind the newer rows.
  /**
   * The statements `read` sends on the vault's login, each run again under EXPLAIN once they are planned: their
   * buffers, summed. What a change reads of a key's object (`readObject`, store.ts).
   */
  const sent = async (read: (db: Database) => Promise<unknown>): Promise<number> => {
    const statements: { text: string; values: unknown[] }[] = [];
    const client = postgresClient(VAULT_URL, { max: 1 });
    const recording = new Proxy(client, {
      get(target, key) {
        const value: unknown = Reflect.get(target, key, target);
        if (key !== 'unsafe') return value;
        return (text: string, values: unknown[] = [], ...rest: unknown[]) => {
          statements.push({ text, values });
          return (value as (...a: unknown[]) => unknown).apply(target, [text, values, ...rest]);
        };
      },
    });
    try {
      await read(createDatabase(recording));
      statements.length = 0;
      await read(createDatabase(recording));
      let total = 0;
      for (const { text, values } of statements) {
        const [plan] = await client.unsafe(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${text}`, values as never[]);
        const node = (plan as unknown as { 'QUERY PLAN': { Plan: { 'Shared Hit Blocks': number; 'Shared Read Blocks': number } }[] })['QUERY PLAN'][0]!.Plan;
        total += node['Shared Hit Blocks'] + node['Shared Read Blocks'];
      }
      return total;
    } finally {
      await client.end();
    }
  };
  const objectOf = (id: string) => async (db: Database) => {
    const { row } = await readObject(db, { kind: 'secret', id });
    assert.equal(row?.kind === 'secret' ? row.source : undefined, id === holder ? source : null, "the object's source");
  };
  const measure = async () => ({
    reference: await buffers(holder, [source, reference]), value: await buffers(source, [null, null]),
    "a reference's object": await sent(objectOf(holder)), "a value's object": await sent(objectOf(source)),
  });
  const alone = await measure();
  // Another key of dev's, repointed 5,000 times since: each row newer than the key's.
  await referring(5000);
  await settle();
  const behind = await measure();
  console.log(JSON.stringify({ alone, behind }));
  for (const [form, before] of Object.entries(alone)) {
    const after = behind[form as keyof typeof behind];
    assert.ok(after - before <= 2, `${form}: ${before} buffers alone, ${after} behind another key's 5,000 newer references`);
  }
});
