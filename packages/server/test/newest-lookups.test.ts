// The server's reads of the newest entries of a kind (or the first, or a page back by `seq`) cost the same however long
// the run of other entries since (T245, R48), as the vault's do (`packages/vault/test/newest-lookups.test.ts`, which says
// why): each against a run of its kind, then a long tail of others that the same walk back by `seq` would read. Each read
// must take the index it names and read at most `PAGES`; on SQLite, take it. `packages/db/test/newest-lookups.test.ts`
// holds every such read in the sources to being one of these, or the vault's.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';

import { createDatabase, type Database } from '@coffre/db';
import { openDatabase, postgresClient } from '@coffre/db/connect';
import { rowsOf } from '@coffre/db/dialect';
import { indexOf } from '@coffre/db/log';
import { sql } from 'drizzle-orm';

import { policySeqAndSettings } from '../src/db/answers.ts';
import { latestCheckpoint, latestTallied, talliedAfter } from '../src/db/queries.ts';
import { newestAppEntry, newestMove, wroteUnder } from '../src/db/rotation.ts';
import { TEST_RUNTIME_DATABASE_URL } from './db/connections.ts';
import { emptyLog, openTestDatabase, TEST_ENGINE, withLogUnlocked } from './db/engine.ts';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
before(async () => {
  db = await openTestDatabase();
});
after(() => db.close());

/** The most pages a read here may take: a step down its index, and the rows it returns. */
const PAGES = 16;
// A tenth on SQLite, whose plans alone are held, and which clears a log entry by entry, each checked against the rest.
const RUN = TEST_ENGINE === 'postgres' ? 30_000 : 3_000;
const TAIL = TEST_ENGINE === 'postgres' ? 20_000 : 2_000;

type Rows = { author: 'app' | 'vault'; action: string; decision?: 'allow' | 'deny'; code?: string; key?: string; count?: number; signs?: boolean };

type Lookup = {
  name: string;
  head?: Rows[];
  run: Rows;
  tail: Rows[];
  /** The indexes its statements on the audit log take: each takes one of them. */
  indexes: string[];
  ask: (app: Database, run: { first: bigint; newest: bigint }) => Promise<void>;
};

const ZERO = Buffer.alloc(32);

const LOOKUPS: Lookup[] = [
  {
    name: 'newestMove',
    run: { author: 'app', action: 'key.reseal' },
    tail: [{ author: 'app', action: 'secret.read' }],
    indexes: [indexOf('moves')],
    ask: async (app, { newest }) => assert.equal((await newestMove(app))?.seq, newest),
  },
  {
    name: 'newestAppEntry',
    run: { author: 'app', action: 'secret.read' },
    tail: [{ author: 'vault', action: 'key.unwrap' }],
    indexes: ['audit_log_app_idx'],
    ask: async (app, { newest }) => assert.equal((await newestAppEntry(app))?.seq, newest),
  },
  {
    name: 'wroteUnder',
    // Under the app's previous key, after one before it: the first of its entries, past every one of the other's.
    head: [{ author: 'app', action: 'secret.read', key: 'app:first', count: TAIL }],
    run: { author: 'app', action: 'secret.read', key: 'app:previous' },
    tail: [],
    indexes: ['audit_log_app_key_idx'],
    ask: async (app) => assert.equal(await wroteUnder(app, 'app:previous'), true),
  },
  {
    name: 'latestCheckpoint, latestTallied, talliedAfter',
    run: { author: 'vault', action: 'audit.checkpoint', signs: true },
    tail: [{ author: 'vault', action: 'audit.checkpoint', decision: 'deny', code: 'wrong_kek' }],
    indexes: [indexOf('signed')],
    ask: async (app, { newest }) => {
      assert.notEqual(await latestCheckpoint(app), null);
      assert.equal((await latestTallied(app))?.entry, newest);
      assert.deepEqual((await talliedAfter(app, newest - 1n, 32)).map(({ entry }) => entry), [newest]);
    },
  },
  ...(['policy', 'settings'] as const).map((kind): Lookup => ({
    name: `policySeqAndSettings (${kind})`,
    run: { author: 'vault', action: `${kind}.change` },
    tail: [{ author: 'vault', action: `${kind}.change`, decision: 'deny', count: TAIL / 2 }, { author: 'vault', action: 'key.unwrap', count: TAIL / 2 }],
    indexes: [indexOf('policy'), indexOf('settings')],
    ask: async (app, { newest }) => {
      const { policySeq } = await policySeqAndSettings(app);
      if (kind === 'policy') assert.equal(policySeq, newest);
    },
  })),
];

async function append(entries: Rows): Promise<void> {
  const { author, action, decision = entries.code === undefined ? 'allow' : 'deny', code = null, key = `${author}:k`, count = RUN, signs = false } = entries;
  // A recursive count, which both engines have (Postgres's `generate_series` SQLite has not), 20,000 at a time.
  for (let left = count; left > 0; left -= 20_000) {
    await withLogUnlocked(db.owner, (tx) => rowsOf(tx, sql`
      WITH RECURSIVE g (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM g WHERE n < ${Math.min(20_000, left)})
      INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, code, related_seq, prev_hash, mac, hash, metadata)
      SELECT head.newest + g.n, ${author}, ${key}, CAST(${Date.now()} AS BIGINT) + g.n, 'system:coffre', ${action}, ${decision}, ${code},
        CASE WHEN ${signs ? 1 : 0} = 1 AND head.newest + g.n > 1 THEN head.newest + g.n - 1 END, ${ZERO}, ${ZERO}, ${ZERO}, '{}'
      FROM (SELECT coalesce(max(seq), 0) AS newest FROM audit_log) head, g`));
  }
}

async function newestSeq(): Promise<bigint> {
  const [row] = await rowsOf<{ seq: string }>(db.owner, sql`SELECT CAST(coalesce(max(seq), 0) AS TEXT) AS seq FROM audit_log`);
  return BigInt(row!.seq);
}

type Statement = { text: string; values: unknown[] };
type Node = { 'Shared Hit Blocks': number; 'Shared Read Blocks': number; 'Index Name'?: string; Plans?: Node[] };
type Libsql = { execute: (query: unknown) => Promise<{ rows: { detail: string }[] }> };

/** Each statement on the audit log `work` sends as the app: through a client of the app's login on Postgres. */
async function sent(work: (app: Database) => Promise<unknown>): Promise<Statement[]> {
  const seen: Statement[] = [];
  if (TEST_ENGINE === 'postgres') {
    const client = postgresClient(TEST_RUNTIME_DATABASE_URL, { max: 1 });
    const unsafe = client.unsafe;
    (client as { unsafe: unknown }).unsafe = (text: string, values: unknown[] = [], ...rest: unknown[]) => {
      seen.push({ text, values });
      return (unsafe as (...args: unknown[]) => unknown)(text, values, ...rest);
    };
    try {
      await work(createDatabase(client));
    } finally {
      await client.end();
    }
  } else {
    // A connection of its own, whose reads see the log as it is now: one kept open across cases has been seen to read
    // an older one. Each statement as Drizzle prepares it: the libsql client is a proxy, which a wrapper of its
    // `execute` would call back into.
    const opened = await openDatabase(process.env.COFFRE_TEST_DATABASE_URL!);
    const session = (opened.db as unknown as { session: { prepareQuery: (query: { sql: string; params: unknown[] }, ...rest: unknown[]) => unknown } }).session;
    const prepare = session.prepareQuery;
    session.prepareQuery = function (this: unknown, query, ...rest) {
      seen.push({ text: query.sql, values: query.params });
      return prepare.call(this, query, ...rest);
    };
    try {
      await work(opened.db);
    } finally {
      await opened.close();
    }
  }
  return seen.filter(({ text }) => /\baudit_log\b/.test(text) && /^\s*(select|with)\b/i.test(text));
}

/** The pages `statement` reads, run again under EXPLAIN as the app's login, and the indexes it reads them by; on SQLite, its plan's indexes. */
async function measure(statement: Statement): Promise<{ pages: number; indexes: string[] }> {
  if (TEST_ENGINE !== 'postgres') {
    const client = (db.owner as unknown as { session: { client: Libsql } }).session.client;
    const { rows } = await client.execute({ sql: `EXPLAIN QUERY PLAN ${statement.text}`, args: statement.values.map((value) => (typeof value === 'object' && value !== null && !Buffer.isBuffer(value) ? null : value)) });
    return { pages: 0, indexes: rows.flatMap(({ detail }) => [...detail.matchAll(/USING (?:COVERING )?INDEX (\w+)/g)].map((found) => found[1]!)) };
  }
  const one = postgresClient(TEST_RUNTIME_DATABASE_URL, { max: 1 });
  try {
    const explained = `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${statement.text}`;
    await one.unsafe(explained, statement.values as never[]);
    const [row] = await one.unsafe(explained, statement.values as never[]);
    const plan = (row as unknown as { 'QUERY PLAN': [{ Plan: Node }] })['QUERY PLAN'][0].Plan;
    const indexes = (node: Node): string[] => [...(node['Index Name'] === undefined ? [] : [node['Index Name']]), ...(node.Plans ?? []).flatMap(indexes)];
    return { pages: plan['Shared Hit Blocks'] + plan['Shared Read Blocks'], indexes: indexes(plan) };
  } finally {
    await one.end();
  }
}

for (const lookup of LOOKUPS) {
  test(`${lookup.name}: one step of its index, however long the run of other entries since (T245, R48)`, { timeout: 300_000 }, async () => {
    await emptyLog(db.owner);
    for (const rows of lookup.head ?? []) await append(rows);
    const first = (await newestSeq()) + 1n;
    await append(lookup.run);
    const newest = await newestSeq();
    for (const rows of lookup.tail) await append(rows);
    await rowsOf(db.owner, sql.raw(TEST_ENGINE === 'postgres' ? 'VACUUM (ANALYZE, PARALLEL 0) audit_log' : 'ANALYZE'));
    const statements = await sent((app) => lookup.ask(app, { first, newest }));
    assert.ok(statements.length > 0, 'the read asked the audit log');
    for (const statement of statements) {
      const { pages, indexes } = await measure(statement);
      const said = JSON.stringify({ statement: statement.text, pages, indexes });
      assert.ok(indexes.some((index) => lookup.indexes.includes(index)), `takes one of ${lookup.indexes.join(', ')}: ${said}`);
      assert.ok(pages <= PAGES, `reads at most ${PAGES} pages: ${said}`);
    }
  });
}
