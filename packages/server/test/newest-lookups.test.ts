// The server's reads of the newest entries of a kind (or the first, or a page back by `seq`) cost the same however long
// the run of other entries since, as the vault's do (`packages/vault/test/newest-lookups.test.ts`, which says
// why): each against a run of its kind, then a long tail of others that the same walk back by `seq` would read. Each read
// must take the index it names and read at most `PAGES`. `packages/db/test/newest-lookups.test.ts`
// holds every such read in the sources to being one of these, or the vault's.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';

import { createDatabase, type Database } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';
import { rowsOf } from '@coffre/db/dialect';
import { indexOf, logObject } from '@coffre/db/log';
import { sql } from 'drizzle-orm';

import { policySeqAndSettings } from '../src/db/answers.ts';
import { hasTombstone, latestCheckpoint, latestTallied, memberAccess, missingMembers, originsOf, talliedAfter } from '../src/db/queries.ts';
import { newestAppEntry, newestMove, wroteUnder } from '../src/db/rotation.ts';
import { TEST_RUNTIME_DATABASE_URL } from './db/connections.ts';
import { emptyLog, openTestDatabase, withLogUnlocked, withTriggersLifted } from './db/engine.ts';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
before(async () => {
  db = await openTestDatabase();
});
after(() => db.close());

/** The most pages a read here may take: a step down its index, and the rows it returns. */
const PAGES = 16;
const RUN = 30_000;
const TAIL = 20_000;

type Rows = { author: 'app' | 'vault'; action: string; decision?: 'allow' | 'deny'; code?: string; key?: string; count?: number; signs?: boolean; actor?: string; subject?: string; metadata?: string };

/** Changes of one object in `log_changes`, by its key (`logObject`), each with `payload`. */
type Changes = { object: string; count?: number; payload?: string };

type Lookup = {
  name: string;
  head?: Rows[];
  run?: Rows;
  tail: Rows[];
  /** `log_changes` after the audit log's history, oldest first. */
  changes?: Changes[];
  /** The indexes its statements on the audit log take: each takes one of them. */
  indexes: string[];
  /** The most pages each may read, if not `PAGES`. */
  pages?: number;
  ask: (app: Database, run: { first: bigint; newest: bigint }) => Promise<void>;
};

const ZERO = Buffer.alloc(32);
/** A change's seal and its MAC, both 16 bytes: no MAC of the vault's, which the reads here do not check. */
const SEAL = Buffer.alloc(16);
const CREDENTIAL = '00000000-0000-4000-8000-0000000000c1';

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
  {
    // A member's newest access entry, then a long run of reads about them (the member page's, beside their grants).
    name: 'memberAccess',
    run: { author: 'vault', action: 'access.grant', subject: 'user:u1' },
    tail: [{ author: 'vault', action: 'secret.read', subject: 'user:u1' }],
    indexes: ['audit_log_access_idx'],
    // One statement of nine probes: the member's row, their findings of either kind, their newest change and access
    // entry, their grants and the projects; a step each.
    pages: 2 * PAGES,
    ask: async (app) => {
      // Their row, which the read starts from: its MAC unchecked here.
      await rowsOf(db.owner, sql`INSERT INTO principals (principal, status, created_at, created_by, status_changed_at, status_changed_by, access_seq, mac)
        VALUES ('user:u1', 'active', 0, 'system:coffre', 0, 'system:coffre', 0, ${ZERO}) ON CONFLICT DO NOTHING`);
      assert.equal((await memberAccess(app, 'user:u1', new Date())).member?.tampered, false);
    },
  },
  {
    // A credential's first change, its sign-in, behind a long run of another object's changes before it: the
    // oldest of the object's, not the oldest of all.
    name: 'originsOf',
    tail: [],
    changes: [
      { object: logObject('secret', '00000000-0000-4000-8000-0000000000b1'), count: TAIL },
      { object: logObject('credential', CREDENTIAL), payload: JSON.stringify({ signIn: { run: { job: 'deploy' } } }) },
    ],
    indexes: ['log_changes_object_idx'],
    ask: async (app) => {
      const origin = (await originsOf(app, [CREDENTIAL])).get(CREDENTIAL);
      assert.deepEqual(origin?.kind === 'signIn' && [origin.seq, origin.run], [BigInt(TAIL) + 1n, { job: 'deploy' }]);
    },
  },
  {
    // Whether a member no row names is one the logs hold (`EXISTS` gates): of `log_changes`, by the object's
    // index, behind a long run of another's; of the allowed access entries, by `audit_log_access_idx`, behind a long run
    // about another member and refusals about this one. Members no other case adds a row for.
    name: 'missingMembers',
    run: { author: 'vault', action: 'access.grant', subject: 'user:m2' },
    tail: [{ author: 'vault', action: 'access.grant', decision: 'deny', code: 'forbidden', subject: 'user:m1' }],
    changes: [{ object: logObject('principal', 'user:m2'), count: TAIL }],
    indexes: ['log_changes_object_idx', 'audit_log_access_idx'],
    ask: async (app) => {
      assert.deepEqual(await missingMembers(app, { type: 'user', id: 'm1' }), []);
      assert.deepEqual(await missingMembers(app, { type: 'user', id: 'm2' }), ['user:m2']);
    },
  },
  {
    // Whether a binding has a tombstone (`EXISTS`): one probe of `audit_log_unbind_idx` keyed by the binding,
    // past a long run of other bindings' unbinds.
    name: 'hasTombstone',
    run: { author: 'app', action: 'token.unbind', metadata: JSON.stringify({ bindingId: 'binding:other' }) },
    tail: [{ author: 'app', action: 'secret.read' }],
    indexes: ['audit_log_unbind_idx'],
    ask: async (app) => {
      const [none, other] = await Promise.all(['binding:none', 'binding:other'].map(async (id) => {
        const [row] = await rowsOf<{ t: boolean }>(app, sql`SELECT ${hasTombstone(id)} AS t`);
        return Boolean(row!.t);
      }));
      assert.deepEqual([none, other], [false, true]);
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
  const { author, action, decision = entries.code === undefined ? 'allow' : 'deny', code = null, key = `${author}:k`, count = RUN, signs = false, actor = 'system:coffre', subject = null, metadata = '{}' } = entries;
  // A recursive count, 20,000 at a time.
  for (let left = count; left > 0; left -= 20_000) {
    await withLogUnlocked(db.owner, (tx) => rowsOf(tx, sql`
      WITH RECURSIVE g (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM g WHERE n < ${Math.min(20_000, left)})
      INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, code, subject_principal, related_seq, prev_hash, mac, hash, metadata)
      SELECT head.newest + g.n, ${author}, ${key}, CAST(${Date.now()} AS BIGINT) + g.n, ${actor}, ${action}, ${decision}, ${code}, ${subject},
        CASE WHEN ${signs ? 1 : 0} = 1 AND head.newest + g.n > 1 THEN head.newest + g.n - 1 END, ${ZERO}, ${ZERO}, ${ZERO}, ${metadata}
      FROM (SELECT coalesce(max(seq), 0) AS newest FROM audit_log) head, g`));
  }
}

/** Appends `count` changes of `object` to `log_changes`, after its newest, as the owner with its triggers lifted. */
async function appendChanges({ object, count = RUN, payload = '{}' }: Changes): Promise<void> {
  const uuid = sql`CAST(${object} AS uuid)`;
  for (let left = count; left > 0; left -= 20_000) {
    await withTriggersLifted(db.owner, 'log_changes', (tx) => rowsOf(tx, sql`
      WITH RECURSIVE g (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM g WHERE n < ${Math.min(20_000, left)})
      INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
      SELECT head.newest + g.n, CAST(${Date.now()} AS BIGINT) + g.n, 'request:' || CAST(head.newest + g.n AS TEXT), ${uuid}, 'service:ci', ${payload}, ${SEAL}, ${SEAL}
      FROM (SELECT coalesce(max(number), 0) AS newest FROM log_changes) head, g`));
  }
}

async function newestSeq(): Promise<bigint> {
  const [row] = await rowsOf<{ seq: string }>(db.owner, sql`SELECT CAST(coalesce(max(seq), 0) AS TEXT) AS seq FROM audit_log`);
  return BigInt(row!.seq);
}

type Statement = { text: string; values: unknown[] };
type Node = { 'Shared Hit Blocks': number; 'Shared Read Blocks': number; 'Index Name'?: string; Plans?: Node[] };

/** Each statement on the audit log `work` sends as the app: through a client of the app's login. */
async function sent(work: (app: Database) => Promise<unknown>): Promise<Statement[]> {
  const seen: Statement[] = [];
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
  return seen.filter(({ text }) => /\baudit_log\b/.test(text) && /^\s*(select|with)\b/i.test(text));
}

/** The pages `statement` reads, run again under EXPLAIN as the app's login, and the indexes it reads them by. */
async function measure(statement: Statement): Promise<{ pages: number; indexes: string[] }> {
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
    await withTriggersLifted(db.owner, 'log_changes', (tx) => rowsOf(tx, sql.raw('TRUNCATE log_changes CASCADE')));
    for (const rows of lookup.head ?? []) await append(rows);
    const first = (await newestSeq()) + 1n;
    if (lookup.run !== undefined) await append(lookup.run);
    const newest = await newestSeq();
    for (const rows of lookup.tail) await append(rows);
    for (const changes of lookup.changes ?? []) await appendChanges(changes);
    for (const table of ['audit_log', 'log_changes']) await rowsOf(db.owner, sql.raw(`VACUUM (ANALYZE, PARALLEL 0) ${table}`));
    const statements = await sent((app) => lookup.ask(app, { first, newest }));
    assert.ok(statements.length > 0, 'the read asked the audit log');
    for (const statement of statements) {
      const { pages, indexes } = await measure(statement);
      const said = JSON.stringify({ statement: statement.text, pages, indexes });
      assert.ok(indexes.some((index) => lookup.indexes.includes(index)), `takes one of ${lookup.indexes.join(', ')}: ${said}`);
      assert.ok(pages <= (lookup.pages ?? PAGES), `reads at most ${lookup.pages ?? PAGES} pages: ${said}`);
    }
  });
}
