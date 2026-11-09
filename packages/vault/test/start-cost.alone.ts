// A fresh isolate's start costs the same however long the log grows (R48, T206): the reads each step of its start
// begins with, asked together before it knows which it needs, read as many pages at a handful of days and entries as
// at a hundred days and 100,000 entries more. One of them, the vault's first entry under its key, had no index until
// 0.16 and walked the log from its start; now one step of `audit_log_vault_key_idx` (T245), whether the key wrote or not.
//
// It runs alone, after the suite (scripts/test-suite.sh): another test's migration in the cluster makes the next call
// of every backend plan everything again (use-days.alone.ts), which reads the catalog, not the log.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { createDatabase, type Database } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';
import { sql } from 'drizzle-orm';

import { resolveVaultConfig } from '../src/config.ts';
import { firstVaultEntryUnder } from '../src/store.ts';
import { openVault, prepareVault } from '../src/vault.ts';
import { openTestDatabase, postgresOnly, rows, sealed, VAULT_URL, withLogUnlocked, type TestDatabase } from './database.ts';
import { DAY, emptyLog, KEK, LOG_015, SIGNING_KEY, useDatabases, world } from './use-world.ts';

let db: TestDatabase;
let hot: Database;
before(async () => {
  db = await openTestDatabase();
  hot = await useDatabases(db);
  await emptyLog();
});
after(() => db.close());

type Statement = { text: string; values: unknown[] };

/** A hash's or a MAC's width of zeros: rows no check here reads. */
const ZERO = Buffer.alloc(32);

/** The pages a statement reads, run again under EXPLAIN as the vault's login: shared buffers, cached or not. */
async function pages(statement: Statement): Promise<number> {
  const one = postgresClient(VAULT_URL, { max: 1 });
  try {
    // Planned once first: what a first call reads of the catalog is the connection's, not the log's.
    await one.unsafe(`EXPLAIN ${statement.text}`, statement.values as never[]);
    const [row] = await one.unsafe(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${statement.text}`, statement.values as never[]);
    const [{ Plan: plan }] = (row as unknown as { 'QUERY PLAN': [{ Plan: { 'Shared Hit Blocks': number; 'Shared Read Blocks': number } }] })['QUERY PLAN'];
    return plan['Shared Hit Blocks'] + plan['Shared Read Blocks'];
  } finally {
    await one.end();
  }
}

/** `count` entries older than any, `author`'s under `key`, in parts: what a read that walks the log from its start would walk. */
async function older(count: number, author: 'app' | 'vault' = 'app', key = 'app:grown'): Promise<void> {
  for (let left = count; left > 0; left -= 20_000) {
    await withLogUnlocked(db.owner, (tx) => tx.execute(sql`
      INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, prev_hash, mac, hash, metadata)
      SELECT (SELECT least(min(seq), 0) FROM audit_log) - g, ${author}, ${key}, ${Date.now() - 200 * DAY}::bigint + g, 'token:grown', 'secret.read', 'allow',
        ${ZERO}, ${ZERO}, ${ZERO}, '{}'
      FROM generate_series(1, ${Math.min(20_000, left)}) g`));
  }
  await db.owner.execute(sql`VACUUM (ANALYZE, PARALLEL 0) audit_log`);
}

test("a fresh isolate's start reads as many pages at a handful of days and entries as at a hundred days and 100,000 entries more", { ...postgresOnly('the log by day'), timeout: 600_000 }, async (t) => {
  const w = await world();
  const config = resolveVaultConfig({ kek: KEK, signingKey: SIGNING_KEY.toString('base64'), owners: ['root@acme.example'] });
  // The decision that makes root the Owner the configuration names waits for its seal, which no checkpointer here makes.
  const options = { ...LOG_015, sealThrough: sealed };
  /** A fresh isolate's first call, each statement its vault's database sent. */
  const start = async (): Promise<Statement[]> => {
    const client = postgresClient(VAULT_URL, { max: 1 });
    const sent: Statement[] = [];
    const unsafe = client.unsafe;
    (client as { unsafe: unknown }).unsafe = (text: string, values: unknown[] = [], ...rest: unknown[]) => {
      sent.push({ text, values });
      return (unsafe as (...args: unknown[]) => unknown)(text, values, ...rest);
    };
    try {
      const vault = openVault(createDatabase(client), await prepareVault(config, options), hot);
      // Its row reported (the fixture's 0.4 MAC is none), the same each time: what is measured is what the start reads.
      await vault.access(w.principal);
      return sent.filter(({ text }) => /^\s*(select|with)\b/i.test(text));
    } finally {
      await client.end();
    }
  };
  const measure = async () => {
    const statements = await start();
    return Promise.all(statements.map(async (statement) => ({ text: statement.text.replace(/\s+/g, ' ').slice(0, 100), pages: await pages(statement) })));
  };
  // The first start makes root the Owner; each after it, as an instance that has served, finds them one.
  await start();
  const small = await measure();
  assert.ok(small.length > 0);
  // 105 days more of uses' partitions, 108 in all, and 100,000 entries before any.
  const today = Math.floor(Date.now() / DAY) * DAY;
  for (let d = 2; d <= 106; d += 1) await db.owner.execute(sql`SELECT make_day(${new Date(today - d * DAY).toISOString().slice(0, 10)}::date)`);
  await older(100_000);
  const grown = await measure();
  t.diagnostic(`pages, each statement, then grown: ${JSON.stringify(small.map(({ text, pages: before }, i) => [text.slice(0, 48), before, grown[i]?.pages]))}`);
  assert.deepEqual(grown.map(({ text }) => text), small.map(({ text }) => text), 'the start ran other statements');
  for (const [i, { text, pages: before }] of small.entries()) {
    const after = grown[i]!.pages;
    assert.ok(after <= 2 * before + 16, `${text} read ${after} pages once the log grew, ${before} before`);
  }
});

test("the vault's first entry under a key is one step of the index, whether the key wrote, wrote after 100,000 entries, or never wrote", postgresOnly('the plans'), async () => {
  const to = `vault:${randomBytes(4).toString('hex')}`;
  const first = (unlessRotated: boolean) => firstVaultEntryUnder(db.vault, to, { unlessRotated });
  const pagesOf = async (unlessRotated: boolean, key = to) => {
    const [row] = await rows<{ 'QUERY PLAN': [{ Plan: { 'Shared Hit Blocks': number; 'Shared Read Blocks': number } }] }>(db.owner, sql`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
      SELECT seq FROM audit_log WHERE author = 'vault' AND key_id = ${key}
      ${unlessRotated ? sql`AND NOT EXISTS (SELECT 1 FROM audit_log r WHERE r.author = 'vault' AND r.action = 'key.rotate' AND r.decision = 'allow' AND r.key_id = ${key})` : sql``}
      ORDER BY seq LIMIT 1`);
    const plan = row!['QUERY PLAN'][0].Plan;
    return plan['Shared Hit Blocks'] + plan['Shared Read Blocks'];
  };
  // 100,000 entries of the vault's under the key it then rotated from, and the rotation: the start, finding it, never walks them.
  await older(100_000, 'vault', 'vault:old');
  await withLogUnlocked(db.owner, (tx) => tx.execute(sql`
    INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, prev_hash, mac, hash, metadata)
    VALUES ((SELECT max(seq) FROM audit_log) + 1, 'vault', ${to}, ${Date.now()}::bigint, 'system:vault', 'key.rotate', 'allow', ${ZERO}, ${ZERO}, ${ZERO}, '{}')`));
  assert.equal(await first(true), undefined, 'none read once a rotation to the key is logged');
  assert.notEqual(await first(false), undefined, 'the entry is there, past the entries it walks to it');
  const [found, probed, never] = [await pagesOf(false), await pagesOf(true), await pagesOf(false, 'vault:never')];
  for (const [what, pages] of [['found past the old key\'s', found], ['once rotated', probed], ['for a key that never wrote', never]] as const) {
    assert.ok(pages <= 16, `${pages} pages ${what}`);
  }
});
