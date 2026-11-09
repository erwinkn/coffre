// Every runtime read of the vault's that asks the audit log for the newest entry of a kind (or the first, or a page back
// from the newest) costs the same however long the run of other entries since (T245, R48), held here against the worst
// history for it: a run of the kind's entries, then a long tail of others that the same walk back by `seq` would read.
// Postgres's statistics then hold the kind common, and it takes any index that yields `seq` order with the rest as a
// filter, expecting to meet the kind at once: before each kind had an index of its own (`KINDS`), the newest rotation
// read 641 pages behind 20,000 checkpoints, the newest checkpoint 3,731 behind 100,000 unwraps (Postgres 16). Each read
// here must take the index it names and read at most `PAGES`; on SQLite, take it. `packages/db/test/newest-lookups.test.ts`
// holds every such read in the sources and the database's functions to being one of these, or the server's
// (`packages/server/test/newest-lookups.test.ts`).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';

import { createDatabase, type Database } from '@coffre/db';
import { openDatabase, postgresClient } from '@coffre/db/connect';
import { rowsOf } from '@coffre/db/dialect';
import { newestAccess, reportStands } from '@coffre/db/grants';
import { indexOf, newestVaultSeq } from '@coffre/db/log';
import { sql } from 'drizzle-orm';

import { snapshot } from '../src/snapshot.ts';
import {
  firstVaultEntryUnder, keyChecks, latestRotation, latestSigned, latestTallied, memberLogs, newestBrokenLog, newestCheckpointEntry,
  newestVaultEntries, talliedAfter, vaultPage,
} from '../src/store.ts';
import { ENGINE, openTestDatabase, rows, run, VAULT_URL, withLogUnlocked, type TestDatabase } from './database.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
});
after(() => db.close());

/** The most pages a read here may take: a step down its index, and the rows it returns, 32 at most. */
const PAGES = 16;
/** How many entries a run holds, and each part of a tail. */
// A tenth on SQLite, whose plans alone are held, and which clears a log entry by entry, each checked against the rest.
const RUN = ENGINE === 'postgres' ? 30_000 : 3_000;
const TAIL = ENGINE === 'postgres' ? 20_000 : 2_000;

/** Entries alike, oldest first: `signs`, each allowed checkpoint's prefix, through the entry before it. */
type Rows = { author: 'app' | 'vault'; action: string; decision?: 'allow' | 'deny'; code?: string; subject?: string; key?: string; count?: number; signs?: boolean; metadata?: string };

/** A read, the history that is worst for it, and the index each of its statements is to take. */
type Lookup = {
  name: string;
  /** Before the run, for a read of the oldest. */
  head?: Rows[];
  run: Rows;
  tail: Rows[];
  /** The indexes its statements on the audit log take: each takes one of them. */
  indexes: string[];
  /** The read, as the runtime asks it, holding its answer to `newest`, the run's last entry, and `first`, its first. */
  ask: (vault: Database, run: { first: bigint; newest: bigint }) => Promise<void>;
};

const ZERO = Buffer.alloc(32);
const FREEZE = JSON.stringify({ target: 'instance' });
const unwraps = (count = TAIL): Rows => ({ author: 'vault', action: 'key.unwrap', count });

const LOOKUPS: Lookup[] = [
  {
    name: 'newestCheckpointEntry',
    run: { author: 'vault', action: 'audit.checkpoint', signs: true },
    tail: [unwraps()],
    indexes: [indexOf('checkpoint')],
    ask: async (vault, { newest }) => assert.equal((await newestCheckpointEntry(vault))?.seq, newest),
  },
  {
    name: 'latestSigned, latestTallied, talliedAfter',
    run: { author: 'vault', action: 'audit.checkpoint', signs: true },
    tail: [{ author: 'vault', action: 'audit.checkpoint', decision: 'deny', code: 'wrong_kek' }],
    indexes: [indexOf('signed')],
    ask: async (vault, { newest }) => {
      assert.equal((await latestSigned(vault))?.seq, newest);
      assert.equal((await latestTallied(vault))?.seq, newest);
      assert.deepEqual((await talliedAfter(vault, newest - 1n, 32)).map(({ seq }) => seq), [newest]);
    },
  },
  {
    name: 'newestBrokenLog',
    run: { author: 'vault', action: 'audit.checkpoint', decision: 'deny', code: 'log_broken' },
    tail: [{ author: 'vault', action: 'audit.checkpoint', decision: 'deny', code: 'wrong_kek' }],
    indexes: [indexOf('brokenLog')],
    ask: async (vault, { newest }) => assert.equal((await newestBrokenLog(vault, -1n))?.seq, newest),
  },
  ...(['policy', 'settings'] as const).map((kind): Lookup => {
    const action = `${kind}.change`;
    return {
      name: `newestVaultSeq(${kind}), newestVaultEntries(${kind}), snapshot`,
      run: { author: 'vault', action },
      tail: [{ author: 'vault', action, decision: 'deny', count: TAIL / 2 }, unwraps(TAIL / 2)],
      indexes: [indexOf(kind)],
      ask: async (vault, { newest }) => {
        assert.equal(await newestVaultSeq(vault, kind), newest);
        assert.equal((await newestVaultEntries(vault, kind, 1))[0]?.seq, newest);
        // A page back from an entry, on Postgres: SQLite reads `seq < ?` by its rowid, past the tail, whose cost no
        // deployment meets (none runs on SQLite, AGENTS.md).
        if (ENGINE === 'postgres') {
          const page = await newestVaultEntries(vault, kind, 32, newest);
          assert.deepEqual([page.length, page[0]?.seq], [32, newest - 1n]);
        }
        // The vault's own read of a member, the policy and the settings, in one statement (Postgres; SQLite's reads the same apart).
        if (ENGINE === 'postgres') await snapshot(vault, { principals: ['user:nobody'], settings: true });
      },
    };
  }),
  {
    name: 'latestRotation',
    run: { author: 'vault', action: 'key.rotate' },
    tail: [{ author: 'vault', action: 'audit.checkpoint', signs: true }],
    indexes: [indexOf('rotation')],
    ask: async (vault, { newest }) => assert.equal((await latestRotation(vault))?.seq, newest),
  },
  {
    name: 'newestVaultEntries(intent), recentIntents',
    run: { author: 'vault', action: 'key.intent' },
    tail: [{ author: 'vault', action: 'key.wrap' }],
    indexes: [indexOf('intent')],
    ask: async (vault, { newest }) => assert.equal((await newestVaultEntries(vault, 'intent', 32))[0]?.seq, newest),
  },
  {
    name: 'keyChecks',
    head: [unwraps()],
    run: { author: 'vault', action: 'key.check' },
    tail: [],
    indexes: [indexOf('keyCheck')],
    ask: async (vault, { first }) => assert.equal((await keyChecks(vault, 32))[0]?.seq, first),
  },
  {
    name: 'newestAccess, reportStands, memberLogs, snapshot',
    // Of a member whose own entries are most of the vault's: their grants, then their reads.
    run: { author: 'vault', action: 'access.grant', subject: 'user:u1' },
    tail: [{ author: 'vault', action: 'secret.read', subject: 'user:u1' }],
    indexes: ['audit_log_access_idx', indexOf('tamper')],
    ask: async (vault, { newest }) => {
      const check = { authentic: () => true, forged: () => {} };
      const found = await newestAccess(vault, 'user:u1', check);
      assert.equal(typeof found === 'string' ? found : found.seq, newest);
      await reportStands(vault, 'user:u1', check, null);
      assert.equal((await memberLogs(vault, ['user:u1'])).get('user:u1')?.access, newest);
      if (ENGINE === 'postgres') assert.equal((await snapshot(vault, { principals: ['user:u1'] })).newestAccess.get('user:u1')?.seq, newest);
    },
  },
  {
    name: 'reportStands (tamper reports)',
    run: { author: 'vault', action: 'vault.tampered', decision: 'deny', code: 'mac', subject: 'user:u1' },
    tail: [{ author: 'vault', action: 'secret.read', subject: 'user:u1' }],
    indexes: ['audit_log_access_idx', indexOf('tamper')],
    ask: async (vault) => {
      assert.equal(await reportStands(vault, 'user:u1', { authentic: () => true, forged: () => {} }, null), true);
    },
  },
  {
    name: 'vaultPage',
    run: { author: 'vault', action: 'key.unwrap' },
    tail: [{ author: 'app', action: 'secret.read' }],
    indexes: ['audit_log_vault_idx'],
    ask: async (vault, { newest }) => assert.equal((await vaultPage(vault, undefined, 32))[0]?.seq, newest),
  },
  {
    name: 'firstVaultEntryUnder',
    head: [{ ...unwraps(), key: 'vault:old' }],
    run: { author: 'vault', action: 'key.unwrap', key: 'vault:new' },
    tail: [],
    indexes: ['audit_log_vault_key_idx'],
    ask: async (vault, { first }) => assert.equal(await firstVaultEntryUnder(vault, 'vault:new'), first),
  },
];

/** Appends `rows`, oldest first, after the newest entry, as the owner with the log's triggers lifted. */
async function append(entries: Rows): Promise<void> {
  const { author, action, decision = entries.code === undefined ? 'allow' : 'deny', code = null, subject = null, key = `${author}:k`, count = RUN, signs = false, metadata = '{}' } = entries;
  // A recursive count, which both engines have (Postgres's `generate_series` SQLite has not), 20,000 at a time.
  for (let left = count; left > 0; left -= 20_000) {
    await withLogUnlocked(db.owner, (tx) => rowsOf(tx, sql`
      WITH RECURSIVE g (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM g WHERE n < ${Math.min(20_000, left)})
      INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, code, subject_principal, related_seq, prev_hash, mac, hash, metadata)
      SELECT head.newest + g.n, ${author}, ${key}, CAST(${Date.now()} AS BIGINT) + g.n, 'system:coffre', ${action}, ${decision}, ${code}, ${subject},
        CASE WHEN ${signs ? 1 : 0} = 1 AND head.newest + g.n > 1 THEN head.newest + g.n - 1 END, ${ZERO}, ${ZERO}, ${ZERO}, ${metadata}
      FROM (SELECT coalesce(max(seq), 0) AS newest FROM audit_log) head, g`));
  }
}

async function newestSeq(): Promise<bigint> {
  const [row] = await rows<{ seq: string | null }>(db.owner, sql`SELECT CAST(coalesce(max(seq), 0) AS TEXT) AS seq FROM audit_log`);
  return BigInt(row!.seq ?? 0);
}

async function startOver(): Promise<void> {
  // Truncated on Postgres: a delete checks each entry's `related_seq` against the rest, which no index serves.
  if (ENGINE === 'postgres') await withLogUnlocked(db.owner, (tx) => rowsOf(tx, sql`TRUNCATE audit_log CASCADE`));
  else await withLogUnlocked(db.owner, async (tx) => {
    await run(tx, sql`UPDATE audit_log SET related_seq = NULL WHERE related_seq IS NOT NULL`);
    await run(tx, sql`DELETE FROM audit_log`);
  });
}

type Statement = { text: string; values: unknown[] };
type Node = { 'Shared Hit Blocks': number; 'Shared Read Blocks': number; 'Index Name'?: string; Plans?: Node[] };

/** Each statement on the audit log `work` sends, through a client of the vault's login: Postgres's, or SQLite's. */
async function sent(work: (vault: Database) => Promise<unknown>): Promise<Statement[]> {
  const seen: Statement[] = [];
  if (ENGINE === 'postgres') {
    const client = postgresClient(VAULT_URL, { max: 1 });
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

/** The pages `statement` reads, run again under EXPLAIN as the vault's login, and the indexes it reads them by; on SQLite, its plan's indexes alone. */
async function measure(statement: Statement): Promise<{ pages: number; indexes: string[] }> {
  if (ENGINE === 'sqlite') {
    const client = (db.owner as unknown as { session: { client: { execute: (query: unknown) => Promise<{ rows: { detail: string }[] }> } } }).session.client;
    const { rows } = await client.execute({ sql: `EXPLAIN QUERY PLAN ${statement.text}`, args: statement.values.map((value) => (typeof value === 'object' && value !== null && !Buffer.isBuffer(value) ? null : value)) });
    const details = rows.map((row) => row.detail);
    return { pages: 0, indexes: details.flatMap((detail) => [...detail.matchAll(/USING (?:COVERING )?INDEX (\w+)/g)].map((found) => found[1]!)) };
  }
  const one = postgresClient(VAULT_URL, { max: 1 });
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

/** A log of `head`, then `run`, then `tail`, its statistics fresh: the run's first entry and its newest. */
async function history({ head = [], run: matching, tail }: Pick<Lookup, 'head' | 'run' | 'tail'>): Promise<{ first: bigint; newest: bigint }> {
  await startOver();
  for (const rows of head) await append(rows);
  const first = (await newestSeq()) + 1n;
  await append(matching);
  const newest = await newestSeq();
  for (const rows of tail) await append(rows);
  await rowsOf(db.owner, ENGINE === 'postgres' ? sql`VACUUM (ANALYZE, PARALLEL 0) audit_log` : sql`ANALYZE`);
  return { first, newest };
}

for (const lookup of LOOKUPS) {
  test(`${lookup.name}: one step of its index, however long the run of other entries since (T245, R48)`, { timeout: 300_000 }, async () => {
    const { first, newest } = await history(lookup);
    const statements = await sent((vault) => lookup.ask(vault, { first, newest }));
    assert.ok(statements.length > 0, 'the read asked the audit log');
    for (const statement of statements) {
      const { pages, indexes } = await measure(statement);
      const said = JSON.stringify({ statement: statement.text, pages, indexes });
      assert.ok(indexes.some((index) => lookup.indexes.includes(index)), `takes one of ${lookup.indexes.join(', ')}: ${said}`);
      assert.ok(pages <= PAGES, `reads at most ${PAGES} pages: ${said}`);
    }
  });
}

/**
 * The database's functions' lookups (a use's, a sign-in's, an issue's): each of these kinds, as they write it, and the
 * history that is worst for it. PL/pgSQL plans a statement for any values from its sixth call, so each is held to its
 * index under a generic plan, its variable a parameter.
 */
const FUNCTION_KINDS = [
  {
    kind: 'policy',
    where: /^a\.author = 'vault' AND a\.action = 'policy\.change' AND a\.decision = 'allow'$/,
    index: indexOf('policy'),
    value: null,
    history: { run: { author: 'vault', action: 'policy.change' }, tail: [{ author: 'vault', action: 'policy.change', decision: 'deny', count: TAIL / 2 }, unwraps(TAIL / 2)] },
  },
  {
    kind: 'access',
    where: /^a\.author = 'vault' AND a\.subject_principal = ([\w.]+) AND a\.decision = 'allow' AND a\.action IN \('member\.add', 'member\.restore', 'member\.owner', 'member\.role', 'member\.remove', 'access\.grant', 'access\.revoke'\)$/,
    index: 'audit_log_access_idx',
    value: 'user:u1',
    history: { run: { author: 'vault', action: 'access.grant', subject: 'user:u1' }, tail: [{ author: 'vault', action: 'secret.read', subject: 'user:u1' }] },
  },
  {
    kind: 'freeze',
    where: /^a\.author = 'app' AND a\.action IN \('workload\.freeze', 'workload\.unfreeze'\) AND a\.decision = 'allow' AND \(a\.metadata::jsonb ->> 'target'\) = ([\w.]+)$/,
    index: 'audit_log_frozen_idx',
    value: 'instance',
    // 200 freezes of one target, a churn no person makes, among a long tail of the app's entries. A plan for any target
    // reads the target's freezes and lifts by `audit_log_frozen_idx` and sorts them, which it expects few of: a cost
    // that grows with them, not with the log (69 pages at 2,000). Were they most of the app's entries, it would walk
    // `audit_log_app_idx` back instead, which only ordering by the target first (`keyedBy`) rules out: that takes
    // `sign_in` written again, left to its next change (T245).
    history: { run: { author: 'app', action: 'workload.freeze', metadata: FREEZE, count: 200 }, tail: [{ author: 'app', action: 'secret.read', metadata: FREEZE }] },
  },
] satisfies { kind: string; where: RegExp; index: string; value: string | null; history: Pick<Lookup, 'run' | 'tail'> }[];

test("every newest lookup in the database's functions is a kind held here, one step of its index under a generic plan (T245, R48)", { skip: ENGINE === 'postgres' ? false : 'Postgres only: its functions', timeout: 300_000 }, async () => {
  const functions = await rows<{ name: string; body: string }>(db.owner, sql`
    SELECT p.proname AS name, p.prosrc AS body FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public' AND p.prosrc ~ 'audit_log'`);
  const found = new Map<string, string[]>(FUNCTION_KINDS.map(({ kind }) => [kind, []]));
  const unknown: string[] = [];
  for (const { name, body } of functions) {
    const flat = body.replace(/--[^\n]*/g, '').replace(/\s+/g, ' ');
    const lookups = [...flat.matchAll(/\(\s*SELECT ([\w.:]+) FROM public\.audit_log a WHERE ((?:(?!SELECT |FROM ).)+?) ORDER BY a\.seq DESC LIMIT 1\s*\)/g)];
    // Any other order of the log by `seq`, which the pattern would miss.
    if ([...flat.matchAll(/ORDER BY a\.seq/g)].length !== lookups.length) unknown.push(`${name}: a lookup of another shape`);
    for (const [, column, where] of lookups) {
      const kind = FUNCTION_KINDS.find((known) => known.where.test(where!));
      if (kind === undefined) unknown.push(`${name}: ${where}`);
      else found.get(kind.kind)!.push(`SELECT ${column} FROM public.audit_log a WHERE ${where!.replace(kind.where, (whole, variable: string | number) => (typeof variable === 'string' ? whole.replace(variable, () => '$1') : whole))} ORDER BY a.seq DESC LIMIT 1`);
    }
  }
  assert.deepEqual(unknown, [], 'a lookup in a function none of FUNCTION_KINDS names: name its kind, with its index and its worst history');
  for (const { kind, index, value, history: worst } of FUNCTION_KINDS) {
    const statements = [...new Set(found.get(kind))];
    assert.ok(statements.length > 0, `the functions look ${kind} up`);
    await history(worst);
    const one = postgresClient(VAULT_URL, { max: 1, connection: { plan_cache_mode: 'force_generic_plan' } });
    try {
      for (const [i, text] of statements.entries()) {
        await one.unsafe(value === null ? `PREPARE lookup${i} AS ${text}` : `PREPARE lookup${i} (text) AS ${text}`);
        const explained = `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE lookup${i}${value === null ? '' : `('${value}')`}`;
        await one.unsafe(explained);
        const [row] = await one.unsafe(explained);
        const plan = (row as unknown as { 'QUERY PLAN': [{ Plan: Node }] })['QUERY PLAN'][0].Plan;
        const indexes = (node: Node): string[] => [...(node['Index Name'] === undefined ? [] : [node['Index Name']]), ...(node.Plans ?? []).flatMap(indexes)];
        const pages = plan['Shared Hit Blocks'] + plan['Shared Read Blocks'];
        const said = JSON.stringify({ text, pages, indexes: indexes(plan) });
        assert.ok(indexes(plan).includes(index), `takes ${index}: ${said}`);
        assert.ok(pages <= PAGES, `reads at most ${PAGES} pages: ${said}`);
      }
    } finally {
      await one.end();
    }
  }
});
