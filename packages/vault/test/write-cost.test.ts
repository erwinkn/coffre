// A key write's two statements cost the same however long the log grows (R48; T179 PR 3, docs/design/two-trips.md,
// "Cost, flat as the log grows"): the vault's (`write_request`) and the app's hold (`hold_inputs`) each read the
// request's objects and names by id and slug, and each object's newest change by one probe of its index, never
// history. Their buffers, counted by EXPLAIN over the functions' own statements, at 10k and at 1M entries of uses,
// other objects' changes and 0.14's log.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { postgresClient } from '@coffre/db/connect';
import { sql } from 'drizzle-orm';

import { OWNER_URL, openTestDatabase, postgresOnly, rows, run, VAULT_URL, type TestDatabase } from './database.ts';
import { emptyLog, useDatabases, world } from './use-world.ts';

const APP_URL = OWNER_URL.replace('coffre_owner:local-dev-only', 'coffre_runtime:local-runtime-only');

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
  await emptyLog();
});
after(() => db.close());

/** History that is not this write's: uses, other objects' changes, 0.14's entries about others. */
async function grow(total: number): Promise<void> {
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
  await run(db.owner, sql`INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, subject_principal, metadata, prev_hash, mac, hash, log015)
    SELECT (SELECT coalesce(max(seq), 0) FROM audit_log) + g, 'vault', 'vault:x', ${now}, 'system:x', CASE WHEN g % 10 = 0 THEN 'access.grant' ELSE 'secret.read' END, 'allow',
           'token:other-' || (g % 1000), '{}', ${Buffer.alloc(32)}, ${Buffer.alloc(32)}, ${Buffer.alloc(32)}, true
      FROM generate_series(1, ${others}) g`);
  await run(db.owner, sql`VACUUM ANALYZE`);
}

test("R48: a key write's vault statement and its app's hold read as many buffers at 10k entries as at 1M", { ...postgresOnly("a key write's statements are Postgres's"), timeout: 600_000 }, async () => {
  const w = await world({ role: 'developer' });
  await w.key();
  const [names] = await rows<{ token_hash: Buffer; project: string; key: string }>(db.owner, sql`SELECT c.token_hash, p.slug AS project, s.key
    FROM credentials c, secrets s JOIN projects p ON p.id = s.project_id WHERE c.id = ${w.credentialId} AND s.id = ${w.keys[0]!.id}`);
  const keys = [names!.key, 'NEW_KEY'];
  const vault = postgresClient(VAULT_URL, { max: 1 });
  const app = postgresClient(APP_URL, { max: 1 });
  const least = async (client: typeof vault, call: string, args: () => Promise<unknown[]>): Promise<number> => {
    let fewest = Infinity;
    // The least of several runs: the first plans, and a run now and then splits an index page, which no size of history moves.
    for (let i = 0; i < 6; i += 1) {
      const [plan] = await client.unsafe(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT * FROM ${call}`, (await args()) as never[]);
      const node = (plan as unknown as { 'QUERY PLAN': { Plan: { 'Shared Hit Blocks': number; 'Shared Read Blocks': number } }[] })['QUERY PLAN'][0]!.Plan;
      fewest = Math.min(fewest, node['Shared Hit Blocks'] + node['Shared Read Blocks']);
    }
    return fewest;
  };
  const request = () => least(vault, 'write_request($1, $2, $3, $4, $5)', async () => [String(Date.now()), names!.token_hash, names!.project, 'dev', keys]);
  // The hold as the app's transaction asks it, its digest the read's now, so that it holds (a moved read raises, which EXPLAIN cannot count).
  const hold = () => least(app, 'hold_inputs($1, $2, $3, $4, $5)', async () => {
    const [read] = await rows<{ digest: Buffer }>(db.owner, sql`SELECT sha256(convert_to(write_inputs(${names!.token_hash}::bytea, ${names!.project}, 'dev', ${sql.param(keys)}::text[]), 'UTF8')) AS digest`);
    return [names!.token_hash, names!.project, 'dev', keys, read!.digest];
  });
  try {
    await grow(10_000);
    const small = { request: await request(), hold: await hold() };
    await grow(990_000);
    const large = { request: await request(), hold: await hold() };
    console.log(JSON.stringify({ small, large }));
    // Flat: each object's newest change by one probe of `log_changes_object_idx`, which grows a level at most.
    for (const form of ['request', 'hold'] as const) {
      assert.ok(large[form] - small[form] <= 4, `${form}: ${small[form]} buffers at 10k, ${large[form]} at 1M`);
    }
  } finally {
    await vault.end();
    await app.end();
  }
});
