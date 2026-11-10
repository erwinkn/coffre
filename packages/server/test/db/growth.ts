// What a read costs at two sizes of a history (R48; T248): the statements a read sends as the app's login, each run
// again under EXPLAIN, on a log `small` long in the shape that is worst for it and on one ten times longer. A
// statement grows with history when it reads at least twice the pages and eight more (a flat one gains an index level
// at most, a page for each index it steps down, and its rows): the history sweep's rule (scripts/history-sweep.mjs).
// On SQLite, whose plans alone are held, it scans no log whole.
import assert from 'node:assert/strict';

import { createDatabase, type Database } from '@coffre/db';
import { openDatabase, postgresClient } from '@coffre/db/connect';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { TEST_RUNTIME_DATABASE_URL } from './connections.ts';
import { emptyLog, TEST_ENGINE, withLogUnlocked, withTriggersLifted } from './engine.ts';

/** The two sizes: ten times apart; a tenth on SQLite, which clears and checks a log entry by entry. */
export const SMALL = TEST_ENGINE === 'postgres' ? 4_000 : 400;
export const LARGE = 10 * SMALL;

/** The log tables a read must not scan whole. */
const LOGS = ['audit_log', 'log_changes', 'log_uses', 'log_reads'];

/** Entries of 0.14's log, `count` alike, after its newest: no MAC or hash of anyone's, which the reads here do not check. */
export type Rows = {
  author: 'app' | 'vault'; action: string; count: number; decision?: 'allow' | 'deny'; code?: string | null; actor?: string; subject?: string | null;
  secret?: string | null; project?: string | null; metadata?: string;
};

const ZERO = Buffer.alloc(32);

/** Appends `rows` to the audit log, as the owner with its triggers lifted, 20,000 at a time, by a recursive count both engines have. */
export async function append(owner: Database, rows: Rows): Promise<void> {
  const { author, action, count, decision = 'allow', code = null, actor = 'system:coffre', subject = null, secret = null, project = null, metadata = '{}' } = rows;
  const uuid = (value: string | null) => (value === null || TEST_ENGINE !== 'postgres' ? sql`${value}` : sql`CAST(${value} AS uuid)`);
  for (let left = count; left > 0; left -= 20_000) {
    await withLogUnlocked(owner, (tx) => rowsOf(tx, sql`
      WITH RECURSIVE g (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM g WHERE n < ${Math.min(20_000, left)})
      INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, code, subject_principal, secret_id, project_id, prev_hash, mac, hash, metadata)
      SELECT head.newest + g.n, ${author}, ${`${author}:k`}, CAST(${Date.now()} AS BIGINT) + g.n, ${actor}, ${action}, ${decision}, ${code}, ${subject},
        ${uuid(secret)}, ${uuid(project)}, ${ZERO}, ${ZERO}, ${ZERO}, ${metadata}
      FROM (SELECT coalesce(max(seq), 0) AS newest FROM audit_log) head, g`));
  }
}

/** Empties both logs, 0.14's and 0.15's changes, uses and reads, as the owner: a case's history starts from nothing. */
export async function emptyLogs(owner: Database): Promise<void> {
  await emptyLog(owner);
  await withTriggersLifted(owner, 'log_changes', (tx) => rowsOf(tx, sql.raw(TEST_ENGINE === 'postgres' ? 'TRUNCATE log_changes CASCADE' : 'DELETE FROM log_changes')));
  for (const table of ['log_uses', 'log_reads', 'log_read_days', 'log_read_newest']) await rowsOf(owner, sql.raw(`DELETE FROM ${table}`));
}

type Statement = { text: string; values: unknown[] };

/** Each statement on a log, or on one of `tables`, that `work` sends as the app's login: through a client of its own on Postgres, as Drizzle prepares it on SQLite. */
export async function sent(work: (app: Database) => Promise<unknown>, tables: readonly string[] = LOGS): Promise<Statement[]> {
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
  return seen.filter(({ text }) => tables.some((log) => new RegExp(`\\b${log}\\b`).test(text)) && /^\s*(select|with)\b/i.test(text));
}

type Node = { 'Node Type': string; 'Relation Name'?: string; 'Shared Hit Blocks': number; 'Shared Read Blocks': number; 'Index Name'?: string; Plans?: Node[] };
type Libsql = { execute: (query: unknown) => Promise<{ rows: { detail: string }[] }> };

/** What `statement` reads run again as the app's login: its pages and indexes on Postgres; on SQLite, its plan's lines. */
async function measure(owner: Database, statement: Statement): Promise<{ pages: number; indexes: string[]; plan: string[] }> {
  if (TEST_ENGINE !== 'postgres') {
    // On a connection of its own, closed after: libsql keeps the read lock of the next read of a connection that ran an
    // `EXPLAIN QUERY PLAN`, and the next case's writes would wait on it.
    const opened = await openDatabase(process.env.COFFRE_TEST_DATABASE_URL!);
    try {
      const client = (opened.db as unknown as { session: { client: Libsql } }).session.client;
      const { rows } = await client.execute({ sql: `EXPLAIN QUERY PLAN ${statement.text}`, args: statement.values.map((value) => (typeof value === 'object' && value !== null && !Buffer.isBuffer(value) ? null : value)) });
      return { pages: 0, indexes: [], plan: rows.map(({ detail }) => detail) };
    } finally {
      await opened.close();
    }
  }
  const one = postgresClient(TEST_RUNTIME_DATABASE_URL, { max: 1 });
  try {
    const explained = `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${statement.text}`;
    await one.unsafe(explained, statement.values as never[]);
    const [row] = await one.unsafe(explained, statement.values as never[]);
    const plan = (row as unknown as { 'QUERY PLAN': [{ Plan: Node }] })['QUERY PLAN'][0].Plan;
    const nodes = (node: Node): Node[] => [node, ...(node.Plans ?? []).flatMap(nodes)];
    return {
      pages: plan['Shared Hit Blocks'] + plan['Shared Read Blocks'],
      indexes: nodes(plan).flatMap((node) => (node['Index Name'] === undefined ? [] : [node['Index Name']])),
      plan: nodes(plan).map((node) => `${node['Node Type']}${node['Index Name'] === undefined ? '' : ` ${node['Index Name']}`}${node['Relation Name'] === undefined ? '' : ` on ${node['Relation Name']}`}`),
    };
  } finally {
    await one.end();
  }
}

export type Growth = {
  /** The history at `size`, after `emptyLogs`: the shape that is worst for the read. */
  grow: (owner: Database, size: number) => Promise<void>;
  /** The read, as the app's login, and what it must answer at `size`. */
  ask: (app: Database, size: number) => Promise<void>;
  /** Indexes the read's statements take between them on Postgres, each one of them. */
  indexes?: string[];
  /**
   * Tables besides the logs that grow with the history `grow` makes, held as the logs are: what a summary of a log
   * keeps (`log_read_newest`, T252), or a key's versions, which its restores add to.
   */
  also?: string[];
};

/**
 * Holds `read` flat: the same statements at both sizes, each reading no more at the larger by the sweep's rule; and
 * on SQLite, none scanning a log at all (a `SCAN` of one, by an index or not, which `SEARCH` is not). A `LIMIT`
 * excuses none: a count of the whole log (`count(*) … LIMIT 1`) or a subquery of its own has one as well, and SQLite's
 * plans hold the shape alone (review r2 of #559). A page back from the newest is a `SEARCH` of its index from the
 * newest `seq` (`entriesOf`'s `seq >= 0`).
 */
export async function holdsFlat(owner: Database, read: Growth): Promise<void> {
  const measured: { text: string; values: unknown[]; pages: number; indexes: string[]; plan: string[] }[][] = [];
  const held = [...LOGS, ...(read.also ?? [])];
  for (const size of [SMALL, LARGE]) {
    await emptyLogs(owner);
    await read.grow(owner, size);
    if (TEST_ENGINE === 'postgres') for (const table of held) await rowsOf(owner, sql.raw(`VACUUM (ANALYZE, PARALLEL 0) ${table}`));
    else await rowsOf(owner, sql`ANALYZE`);
    const statements = await sent((app) => read.ask(app, size), held);
    assert.ok(statements.length > 0, 'the read asked a log');
    measured.push(await Promise.all(statements.map(async (statement) => ({ text: statement.text, values: statement.values, ...(await measure(owner, statement)) }))));
  }
  const [small, large] = measured as [typeof measured[number], typeof measured[number]];
  assert.deepEqual(large.map(({ text }) => text), small.map(({ text }) => text), 'the read sent other statements at the larger size');
  for (const [i, at] of large.entries()) {
    const text = at.text.replace(/\s+/g, ' ');
    const said = JSON.stringify({ statement: text.length > 600 ? `${text.slice(0, 300)} … ${text.slice(-300)}` : text, values: small[i]!.values, pages: [small[i]!.pages, at.pages], plan: at.plan }, (_, value: unknown) => (typeof value === 'bigint' ? String(value) : value));
    if (TEST_ENGINE !== 'postgres') {
      // Only a whole scan fails here: a walk of index searches, one a day (0.15's `readsBy`), passes on SQLite. The
      // page bound below is the guard, on Postgres, the engine deployments run (review r5 of #560).
      // SQLite's plan names a table by the statement's name for it (`SCAN r` for `log_reads r`): each such name too.
      const names = [...held, ...held.flatMap((table) => [...at.text.matchAll(new RegExp(`\\b${table}\\s+(?:AS\\s+)?(\\w+)`, 'gi'))].map((match) => match[1]!))]
        .filter((name) => !/^(?:WHERE|JOIN|LEFT|INNER|CROSS|ON|USING|GROUP|ORDER|LIMIT|UNION|SET|VALUES|WITH|AS|SELECT|FROM|INDEXED|NOT)$/i.test(name));
      assert.deepEqual(at.plan.filter((line) => new RegExp(`^SCAN (${names.join('|')})\\b`).test(line)), [], `scans no log whole: ${said}`);
      continue;
    }
    assert.ok(!(at.pages >= 2 * small[i]!.pages && at.pages - small[i]!.pages >= 8), `reads as many pages ${LARGE.toLocaleString('en')} entries in as ${SMALL.toLocaleString('en')}: ${said}`);
  }
  if (TEST_ENGINE === 'postgres') {
    // A day's index of a table partitioned by day, `log_reads_20261110_seen_idx`, as its parent's.
    const taken = new Set(large.flatMap(({ indexes }) => indexes.map((index) => index.replace(/_\d{8}_/, '_'))));
    assert.deepEqual((read.indexes ?? []).filter((index) => !taken.has(index)), [], `the read takes each of its indexes: ${JSON.stringify(large.map(({ plan }) => plan))}`);
  }
}
