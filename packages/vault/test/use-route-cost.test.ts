// A route use costs one statement on a warm map, and the same however long the log grows (R44, R48; T186 PR C;
// docs/design/proxy-ui.md, section 4): `use_route`'s buffers, counted by EXPLAIN over the function's own statements, at
// 10k and at 1M entries of history; and its rows the same with one definition in the environment and with 256, whose
// index grows (the buffers it adds are stated, not held flat: the index is read whole, its seal over all of it). A warm
// use of a route of one key is the route's named call (T205, 0071): `use_credential` as the vault sends it, held flat too.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { createDatabase } from '@coffre/db';
import { postgresClient, type PostgresClient } from '@coffre/db/connect';
import { sql } from 'drizzle-orm';

import { GATE_ROLES } from '../src/decide.ts';
import { purposeCode } from '../src/log-replay.ts';
import { newRequestId } from '../src/use.ts';
import { openVault, prepareVault } from '../src/vault.ts';
import { HOT_URL, openTestDatabase, postgresOnly, rows, run, type TestDatabase } from './database.ts';
import { route, routeWorld } from './route-world.ts';
import { CONFIG, emptyLog, LOG_015, useDatabases } from './use-world.ts';
import { inBulkPeriod } from './window-fixture.ts';

/** What the statement-counting uses need of one bulk-cap period: each call before the last measured one may take its 3 s deadline, so room for two of them and a margin (T218). */
const PERIOD_ROOM_MS = 10_000;

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
  await emptyLog();
});
after(() => db.close());

/**
 * How many buffers fewer the light gate's statement reads than the whole gate's at least (T200): the whole gate's main
 * statement, the caller's credential, account, grants, roles, policy and place with each's newest change, which the
 * key's use reads again. Measured: 33 to 34 fewer at every size below (light 77 to 113, whole 110 to 147).
 */
const LIGHTER = 30;

/** A statement as the vault sent it: its text and its parameters. */
type Sent = { text: string; params: unknown[] };

/** The hot pool, each statement counted as it is sent, the last one kept. */
function counting(): { pool: PostgresClient; statements: () => number; last: () => Sent | null } {
  let statements = 0;
  let last: Sent | null = null;
  const pool = new Proxy(postgresClient(HOT_URL, { max: 2 }), {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (key !== 'unsafe') return value;
      return (...args: unknown[]) => {
        statements += 1;
        last = { text: String(args[0]), params: [...((args[1] as unknown[] | undefined) ?? [])] };
        return (value as (...a: unknown[]) => unknown).apply(target, args);
      };
    },
  });
  return { pool, statements: () => statements, last: () => last };
}

/** History that is not this use's: other credentials' uses, other objects' changes, other principals' bulk rows. */
async function grow(total: number): Promise<void> {
  const uses = Math.round(total * 0.9);
  const changes = Math.max(5_000, Math.round(total * 0.01));
  const others = Math.max(50_000, Math.round(total * 0.09));
  const now = Date.now();
  await run(db.owner, sql`INSERT INTO log_uses (number, at, request_id, credential, secret, purpose, mac, place, route)
    SELECT nextval('log_number'), ${now - 80_000_000}::bigint + (g * 80000000::bigint / ${uses}), g, gen_random_uuid(), gen_random_uuid(), 4, ${randomBytes(16)}, NULL,
           CASE WHEN g % 3 = 0 THEN 'openai' END
      FROM generate_series(1, ${uses}) g`);
  await run(db.owner, sql`INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
    SELECT nextval('log_number'), ${now}, 'history-' || g || '-' || ${String(total)}, gen_random_uuid(), 'system:x', '{"op":"x"}', NULL, ${randomBytes(16)}
      FROM generate_series(1, ${changes}) g`);
  await run(db.owner, sql`INSERT INTO log_bulk (principal, secret, last) SELECT 'token:other-' || (g % 1000), gen_random_uuid(), ${now} FROM generate_series(1, ${others}) g`);
  await run(db.owner, sql`VACUUM ANALYZE`);
}

test('R48: a route use is one statement on a warm map, its buffers the same at 10k and at 1M entries and at 1k and 10k environments, the route\'s named call\'s too (T205); its rows the same at 1 definition and at 256', { ...postgresOnly('the hot path'), timeout: 900_000 }, async () => {
  const w = await routeWorld(db);
  const key = await w.key('sk');
  const name = await w.nameOf(key);
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  await w.save({ openai: { definition: route('openai', [name]), editor: ada } });
  const { pool, statements, last } = counting();
  let named: Sent | null = null;
  const vault = openVault(db.vault, await prepareVault(CONFIG, LOG_015), createDatabase(pool));
  try {
    // The key enters the set in the cold use; a period turning over before the warm one would have it write its row again (T218).
    await inBulkPeriod(PERIOD_ROOM_MS, [{ principal: w.principal, key }]);
    // Cold: the map's miss reads the ids (one statement), then the use, its key entering the set, decided first and made
    // under the lock (two more). Warm, its key in the set: one.
    const cold = await vault.useRoute(w.askRoute('openai'));
    assert.ok(cold.served && cold.route === 'name' && cold.outcome.ok, JSON.stringify(cold));
    const before = statements();
    const warm = await vault.useRoute(w.askRoute('openai'));
    assert.ok(warm.served && warm.route === 'name' && warm.outcome.ok, JSON.stringify(warm));
    assert.equal(statements() - before, 1, 'a warm route use is one statement');
    named = last();
    assert.ok(named !== null && named.text.includes('use_credential('), 'the route\'s named call (T205)');
  } finally {
    await pool.end();
  }

  const client = postgresClient(HOT_URL, { max: 1 });
  const [made] = await rows<{ places: string | null }>(db.owner, sql`SELECT places FROM credentials WHERE id = ${w.credentialId}`);
  assert.ok(made !== undefined);
  /**
   * The statement's work, as the hot login runs it on a connection of its own, its plans made: the least of several runs.
   * `light`: made by the map's ids, its gate light, as the vault asks it (T200, 0060); `whole`: the same, its gate whole,
   * as a vault before asked it; `miss`: no ids, which makes no use and reads the handle's places by path (`made_for`).
   */
  const measure = async (mode: 'light' | 'whole' | 'miss'): Promise<{ buffers: number; rows: number }> => {
    let least = Infinity;
    let read = 0;
    for (let i = 0; i < 6; i += 1) {
      const at = Date.now();
      const args = [
        w.tokenHash, w.slug, 'dev', 'openai', null, 1, true, [], GATE_ROLES,
        w.credentialId, null, null, null,
        String(at), purposeCode({ purpose: 'use', keepsSensitive: false }), String(at + 3000), randomBytes(16),
        ...(mode === 'miss' ? [null, null, null, null, null, null, null, null] : [[key], [null], [newRequestId()], [randomBytes(16)], [null], [null], [null], [false]]),
        0, 100, null, true, mode === 'light',
      ] as never[];
      const call = 'use_route($1::bytea, $2::text, $3::text, $4::text, $5::text, $6::smallint, $7::boolean, $8::text[], $9::jsonb, $10::uuid, $11::smallint, $12::text, $13::uuid, '
        + '$14::bigint, $15::smallint, $16::bigint, $17::bytea, $18::uuid[], $19::uuid[], $20::bigint[], $21::bytea[], $22::bigint[], $23::bigint[], $24::bigint[], $25::boolean[], '
        + '$26::integer, $27::integer, $28::text, $29::boolean, $30::boolean)';
      const [plan] = await client.unsafe(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT * FROM ${call}`, args);
      const node = (plan as unknown as { 'QUERY PLAN': { Plan: { 'Shared Hit Blocks': number; 'Shared Read Blocks': number; 'Actual Rows': number } }[] })['QUERY PLAN'][0]!.Plan;
      least = Math.min(least, node['Shared Hit Blocks'] + node['Shared Read Blocks']);
      // Its answer, made by the ids: each use one entry.
      const [answer] = await client.unsafe(`SELECT ${call}::text AS route`, args.map((arg, k) => (k === 19 ? [newRequestId()] : arg)) as never[]) as unknown as { route: string }[];
      const parsed = JSON.parse(answer!.route) as { made: boolean; levels: unknown[]; rows: unknown[]; made_for: unknown; gate: { state: string } };
      assert.equal(parsed.made, mode !== 'miss', 'made by the ids, and only by them');
      assert.equal(parsed.gate.state, mode === 'light' ? 'stood' : 'moved', 'the gate light only where the vault asked it');
      assert.equal(parsed.made_for === null, mode !== 'miss', 'the places by path only where no use is made');
      read = parsed.levels.length + parsed.rows.length;
    }
    return { buffers: least, rows: read };
  };
  /**
   * The route's named call's work (T205): the warm use's own statement, sent again as the vault sent it, its request,
   * time and deadline new (`use_credential`'s 3rd, 4th and 8th parameters, 0071), its use made by the map's ids.
   */
  const measureNamed = async (): Promise<number> => {
    const sent = named!;
    let least = Infinity;
    for (let i = 0; i < 6; i += 1) {
      const fresh = () => {
        const at = Date.now();
        return sent.params.map((arg, k) => (k === 2 ? newRequestId() : k === 3 ? String(at) : k === 7 ? String(at + 3000) : arg)) as never[];
      };
      const [plan] = await client.unsafe(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${sent.text}`, fresh());
      const node = (plan as unknown as { 'QUERY PLAN': { Plan: { 'Shared Hit Blocks': number; 'Shared Read Blocks': number } }[] })['QUERY PLAN'][0]!.Plan;
      least = Math.min(least, node['Shared Hit Blocks'] + node['Shared Read Blocks']);
      const [answer] = await client.unsafe(sent.text, fresh()) as unknown as { use: string }[];
      const parsed = JSON.parse(answer!.use) as { route: { made: boolean; keyed: boolean; levels: unknown[] } | null };
      assert.deepEqual([parsed.route?.made, parsed.route?.keyed, parsed.route?.levels.length], [true, true, 1], 'made by the map\'s ids, its route read');
    }
    return least;
  };
  /** Each form's work: the light gate's, the vault's on a warm map; the whole gate's; a miss's; and the route's named call's. */
  const measured = async () => {
    // The light and the whole gate are held to each other, so both read the key's row in one period: a period turning over between them has the first write the row and the other not (T218).
    await inBulkPeriod(PERIOD_ROOM_MS, [{ principal: w.principal, key }]);
    return { ...(await measure('light')), whole: (await measure('whole')).buffers, miss: (await measure('miss')).buffers, named: await measureNamed() };
  };
  await grow(10_000);
  const small = await measured();
  await grow(990_000);
  const large = await measured();
  // 255 more definitions in dev: its index read whole, every use.
  const many: Parameters<typeof w.save>[0] = {};
  for (let i = 0; i < 255; i += 1) many[`r${String(i).padStart(3, '0')}`] = { definition: route(`r${String(i).padStart(3, '0')}`, [name]), editor: ada };
  await w.save(many);
  await run(db.owner, sql`VACUUM ANALYZE proxy_definitions`);
  const wide = await measured();
  // The handle's made-for list is read by its environments' ids (review r1 of #464): the same buffers at 1k
  // environments in the instance and at 10k.
  await run(db.owner, sql`UPDATE credentials SET places = ${JSON.stringify([{ environmentId: w.dev }])} WHERE id = ${w.credentialId}`);
  const environments = async (count: number) => {
    await run(db.owner, sql`INSERT INTO environments (id, project_id, slug, name)
      SELECT gen_random_uuid(), ${w.project}::uuid, 'e-' || ${String(count)} || '-' || g, 'E' FROM generate_series(1, ${count}) g`);
    await run(db.owner, sql`VACUUM ANALYZE environments`);
  };
  await environments(1_000);
  const few = await measured();
  await environments(9_000);
  const crowded = await measured();
  await client.end();
  console.log(JSON.stringify({ small, large, wide, few, crowded }));
  for (const form of ['buffers', 'whole', 'miss', 'named'] as const) {
    assert.ok(crowded[form] - few[form] <= 2, `${form}: ${few[form]} buffers at 1k environments, ${crowded[form]} at 10k`);
    // Flat: no statement reads history, only probes it by index (the uses' own index may grow a level: its insert, a buffer).
    assert.ok(large[form] - small[form] <= 2, `${form}: ${small[form]} buffers at 10k, ${large[form]} at 1M`);
  }
  // T200: the light gate reads the caller's rows once, by the key's use, where the whole gate read them a second time.
  for (const at of [small, large, wide, few, crowded]) assert.ok(at.buffers <= at.whole - LIGHTER, `light ${at.buffers} buffers, whole ${at.whole}`);
  assert.equal(wide.rows, small.rows, 'the same rows at 256 definitions: its route\'s item and the index, never every item');
});
