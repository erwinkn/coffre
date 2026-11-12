// Every runtime read of the vault's that asks the audit log for the newest entry of a kind (or the first, or a page back
// from the newest) costs the same however long the run of other entries since (T245, R48), held here against the worst
// history for it: a run of the kind's entries, then a long tail of others that the same walk back by `seq` would read.
// Postgres's statistics then hold the kind common, and it takes any index that yields `seq` order with the rest as a
// filter, expecting to meet the kind at once: before each kind had an index of its own (`KINDS`), the newest rotation
// read 641 pages behind 20,000 checkpoints, the newest checkpoint 3,731 behind 100,000 unwraps (Postgres 16). Each read
// here must take the index it names and read at most `PAGES`. `packages/db/test/newest-lookups.test.ts`
// holds every such read in the sources and the database's functions to being one of these, or the server's
// (`packages/server/test/newest-lookups.test.ts`).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';

import { createDatabase, type Database } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';
import { rowsOf } from '@coffre/db/dialect';
import { findingsOf, newestAccess, newestChangeNames, reportStands } from '@coffre/db/grants';
import { changesOf, indexOf, KeyRetired, lockLogHeadRead, newestVaultSeq } from '@coffre/db/log';
import type { LogKey } from '@coffre/core/audit';
import { sql } from 'drizzle-orm';
import { PgDialect } from 'drizzle-orm/pg-core';

import { objectKey, type Ref } from '../src/inputs.ts';
import { snapshot } from '../src/snapshot.ts';
import {
  firstVaultEntryUnder, keyChecks, latestRotation, latestSigned, latestTallied, loggedChanges, memberLogs, newestBrokenLog, newestChange,
  newestCheckpointEntry, newestVaultEntries, talliedAfter, vaultPage,
} from '../src/store.ts';
import { openTestDatabase, rows, VAULT_URL, withLogUnlocked, withTriggersLifted, type TestDatabase } from './database.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
});
after(() => db.close());

/** The most pages a read here may take: a step down its index, and the rows it returns, 32 at most. */
const PAGES = 16;
/** How many entries a run holds, and each part of a tail. */
const RUN = 30_000;
const TAIL = 20_000;

/** Entries alike, oldest first: `signs`, each allowed checkpoint's prefix, through the entry before it. */
type Rows = { author: 'app' | 'vault'; action: string; decision?: 'allow' | 'deny'; code?: string; subject?: string; key?: string; count?: number; signs?: boolean; metadata?: string };

/** A read, the history that is worst for it, and the index each of its statements is to take. */
type Lookup = {
  name: string;
  /** Before the run, for a read of the oldest. */
  head?: Rows[];
  run?: Rows;
  tail: Rows[];
  /** 0.15's log after the audit log's history, oldest first: a run of changes of each object (`Changes`). */
  changes?: Changes[];
  /** The indexes its statements on the logs take: each takes one of them. */
  indexes: string[];
  /** The read, as the runtime asks it, holding its answer to `newest`, the run's last entry, and `first`, its first. */
  ask: (vault: Database, run: { first: bigint; newest: bigint }) => Promise<void>;
};

/** Changes of one object in 0.15's log, by its key (`objectKey`), each sealed. */
type Changes = { object: string; count?: number };

const ZERO = Buffer.alloc(32);
/** A change's seal and its MAC, both 16 bytes: no MAC of the vault's, which the reads here do not check. */
const SEAL = Buffer.alloc(16);
const FREEZE = JSON.stringify({ target: 'instance' });
const unwraps = (count = TAIL): Rows => ({ author: 'vault', action: 'key.unwrap', count });
/** A member's tamper reports: of 0.15's log, naming change `change`; of 0.14's, naming none. */
const reports = (change: string | null, count = RUN): Rows => ({
  author: 'vault', action: 'vault.tampered', decision: 'deny', code: 'mac', subject: 'user:u1', count, metadata: JSON.stringify(change === null ? {} : { change }),
});
const SECRET: Ref = { kind: 'secret', id: '00000000-0000-4000-8000-00000000000a' };
const MEMBER: Ref = { kind: 'principal', id: 'user:u1' };
/** Another object's changes, after the run of the one asked about. */
const others = (count = TAIL): Changes => ({ object: objectKey({ kind: 'secret', id: '00000000-0000-4000-8000-00000000000b' }), count });
const check = { authentic: () => true, forged: () => {} };

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
        // A page back from an entry.
        const page = await newestVaultEntries(vault, kind, 32, newest);
        assert.deepEqual([page.length, page[0]?.seq], [32, newest - 1n]);
        // The vault's own read of a member, the policy and the settings, in one statement.
        await snapshot(vault, { principals: ['user:nobody'], settings: true });
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
      assert.equal((await snapshot(vault, { principals: ['user:u1'] })).newestAccess.get('user:u1')?.seq, newest);
    },
  },
  {
    name: 'reportStands (tamper reports)',
    run: reports(null),
    tail: [{ author: 'vault', action: 'secret.read', subject: 'user:u1' }],
    indexes: ['audit_log_access_idx', indexOf('tamper')],
    ask: async (vault) => {
      assert.equal(await reportStands(vault, 'user:u1', check, null), true);
    },
  },
  {
    // 0.15's reports naming one change, then a long run naming another: the first's newest, and one naming a third,
    // which none does, and then 0.14's, of which there are none.
    name: 'reportStands (named), findingsOf',
    run: reports('change:a'),
    tail: [reports('change:b', TAIL)],
    indexes: ['audit_log_access_idx', indexOf('tamper')],
    ask: async (vault) => {
      assert.equal(await reportStands(vault, 'user:u1', check, 'change:a'), true);
      assert.equal(await reportStands(vault, 'user:u1', check, 'change:c'), false);
      const { legacy, named } = findingsOf('user:u1');
      assert.deepEqual(await rowsOf(vault, sql`SELECT ${legacy} AS legacy, ${named} AS named`), [{ legacy: null, named: 0 }]);
    },
  },
  {
    // 0.14's, then a long run of 0.15's naming a change: 0.14's newest, past them.
    name: 'reportStands (legacy), findingsOf',
    run: reports(null),
    tail: [reports('change:b', TAIL)],
    indexes: ['audit_log_access_idx', indexOf('tamper')],
    ask: async (vault, { newest }) => {
      assert.equal(await reportStands(vault, 'user:u1', check, null), true);
      const { legacy } = findingsOf('user:u1');
      assert.deepEqual(await rowsOf(vault, sql`SELECT ${legacy} AS legacy`), [{ legacy: String(newest) }]);
    },
  },
  {
    // An object's newest change, a long run of another's since (0.15's log, `changesOf`).
    name: 'newestChange, loggedChanges',
    tail: [],
    changes: [{ object: objectKey(SECRET) }, others()],
    indexes: ['log_changes_object_idx'],
    ask: async (vault) => {
      assert.equal((await newestChange(vault, SECRET, []))?.holds, false);
      assert.equal((await loggedChanges(vault, [], [SECRET], [SECRET])).get(objectKey(SECRET))?.length, 2);
    },
  },
  {
    name: 'memberLogs, newestChangeNames, snapshot (changes)',
    tail: [],
    changes: [{ object: objectKey(MEMBER) }, others()],
    indexes: ['log_changes_object_idx'],
    ask: async (vault) => {
      assert.notEqual((await memberLogs(vault, ['user:u1'])).get('user:u1')?.newest, null);
      assert.notEqual((await newestChangeNames(vault, ['user:u1'])).get('user:u1'), 'none');
      assert.notEqual((await snapshot(vault, { principals: ['user:u1'], seals: true })).memberLogs.get('user:u1')?.newest, null);
    },
  },
  {
    // The shape every newest change goes through (`changesOf`), of a value, of `log_object(…)`, and of a
    // column of the row it is read beside, as the functions read them; under a plan for any value, the functions' test.
    name: 'changesOf',
    tail: [],
    changes: [{ object: objectKey(MEMBER) }, others()],
    indexes: ['log_changes_object_idx'],
    ask: async (vault) => {
      const value = changesOf('x', objectKey(MEMBER));
      assert.equal((await rowsOf(vault, sql`SELECT x.number FROM log_changes x WHERE ${value.where} ORDER BY ${value.order} LIMIT 1`)).length, 1);
      const named = changesOf('x', sql`log_object('principal', 'user:u1')`);
      assert.equal((await rowsOf(vault, sql`SELECT x.number FROM log_changes x WHERE ${named.where} ORDER BY ${named.order} LIMIT 1`)).length, 1);
      const beside = changesOf('x', sql`k.object`);
      assert.equal((await rowsOf(vault, sql`SELECT l.number FROM (VALUES (CAST(${objectKey(MEMBER)} AS uuid))) k (object)
        CROSS JOIN LATERAL (SELECT x.number FROM log_changes x WHERE ${beside.where} ORDER BY ${beside.order} LIMIT 1) l`)).length, 1);
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
    // What a fresh isolate's start asks (`#start`, T206): its key's first entry, past the vault's entries under the
    // keys before it and every rotation between them, which its old `NOT EXISTS` gate walked (4,741 pages past 40,000).
    name: 'firstVaultEntryUnder',
    head: [{ ...unwraps(), key: 'vault:old' }, { author: 'vault', action: 'key.rotate', key: 'vault:old', count: TAIL }],
    run: { author: 'vault', action: 'key.unwrap', key: 'vault:new' },
    tail: [{ author: 'vault', action: 'key.rotate', key: 'vault:newer', count: TAIL }],
    indexes: ['audit_log_vault_key_idx'],
    ask: async (vault, { first }) => assert.equal(await firstVaultEntryUnder(vault, 'vault:new'), first),
  },
  {
    // An append's read under the head: whether its key was moved from (`retired`, an `EXISTS` of the moves from it), by
    // `audit_log_subject_idx` keyed by the key, past a long run of the vault's reseals and rotations from other keys and
    // the app's; and the newest entry, the primary key's first step.
    name: 'lockLogHeadRead',
    head: [{ author: 'vault', action: 'key.reseal', subject: 'vault:older' }],
    run: { author: 'vault', action: 'key.rotate', subject: 'vault:old', count: 1 },
    tail: [{ author: 'app', action: 'key.reseal', subject: 'app:old' }],
    indexes: ['audit_log_subject_idx', 'audit_log_pkey'],
    ask: async (vault) => {
      for (const [keyId, retired] of [['vault:k', false], ['vault:old', true]] as const) {
        const held = await vault.transaction((tx) => lockLogHeadRead(tx, { author: 'vault', keyId } as LogKey)).then(() => false, (error: unknown) => {
          if (error instanceof KeyRetired) return true;
          throw error;
        });
        assert.equal(held, retired, keyId);
      }
    },
  },
];

/** Appends `rows`, oldest first, after the newest entry, as the owner with the log's triggers lifted. */
async function append(entries: Rows): Promise<void> {
  const { author, action, decision = entries.code === undefined ? 'allow' : 'deny', code = null, subject = null, key = `${author}:k`, count = RUN, signs = false, metadata = '{}' } = entries;
  // A recursive count, 20,000 at a time.
  for (let left = count; left > 0; left -= 20_000) {
    await withLogUnlocked(db.owner, (tx) => rowsOf(tx, sql`
      WITH RECURSIVE g (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM g WHERE n < ${Math.min(20_000, left)})
      INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, code, subject_principal, related_seq, prev_hash, mac, hash, metadata)
      SELECT head.newest + g.n, ${author}, ${key}, CAST(${Date.now()} AS BIGINT) + g.n, 'system:coffre', ${action}, ${decision}, ${code}, ${subject},
        CASE WHEN ${signs ? 1 : 0} = 1 AND head.newest + g.n > 1 THEN head.newest + g.n - 1 END, ${ZERO}, ${ZERO}, ${ZERO}, ${metadata}
      FROM (SELECT coalesce(max(seq), 0) AS newest FROM audit_log) head, g`));
  }
}

/** Appends `count` changes of `object` to 0.15's log, after its newest, as the owner with its triggers lifted. */
async function appendChanges({ object, count = RUN }: Changes): Promise<void> {
  const uuid = sql`CAST(${object} AS uuid)`;
  for (let left = count; left > 0; left -= 20_000) {
    await withTriggersLifted(db.owner, 'log_changes', (tx) => rowsOf(tx, sql`
      WITH RECURSIVE g (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM g WHERE n < ${Math.min(20_000, left)})
      INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
      SELECT head.newest + g.n, CAST(${Date.now()} AS BIGINT) + g.n, 'request:' || CAST(head.newest + g.n AS TEXT), ${uuid}, 'system:coffre', '{}', ${SEAL}, ${SEAL}
      FROM (SELECT coalesce(max(number), 0) AS newest FROM log_changes) head, g`));
  }
}


async function newestSeq(): Promise<bigint> {
  const [row] = await rows<{ seq: string | null }>(db.owner, sql`SELECT CAST(coalesce(max(seq), 0) AS TEXT) AS seq FROM audit_log`);
  return BigInt(row!.seq ?? 0);
}

async function startOver(): Promise<void> {
  // Truncated: a delete checks each entry's `related_seq` against the rest, which no index serves.
  await withLogUnlocked(db.owner, (tx) => rowsOf(tx, sql`TRUNCATE audit_log, log_changes CASCADE`));
}

type Statement = { text: string; values: unknown[] };
type Node = { 'Shared Hit Blocks': number; 'Shared Read Blocks': number; 'Index Name'?: string; Plans?: Node[] };

/** Each statement on the logs (0.14's, 0.15's changes) `work` sends, through a client of the vault's login. */
async function sent(work: (vault: Database) => Promise<unknown>): Promise<Statement[]> {
  const seen: Statement[] = [];
  const client = postgresClient(VAULT_URL, { max: 1 });
  type Asks = { unsafe: unknown; savepoint?: unknown };
  const wrapped = new WeakSet<object>();
  // Each client's statements, once however often it is handed out: the pool's, a transaction's, on the
  // connection its BEGIN holds (`Session.transaction`, @coffre/db), and a savepoint's inside it, a client of
  // its own (Drizzle's nested `tx.transaction`), so a read there is measured as any other (review r9 of #556).
  const kept = (on: Asks) => {
    if (wrapped.has(on)) return on;
    wrapped.add(on);
    const unsafe = on.unsafe as (...args: unknown[]) => unknown;
    on.unsafe = (text: string, values: unknown[] = [], ...rest: unknown[]) => {
      seen.push({ text, values });
      return unsafe.call(on, text, values, ...rest);
    };
    const savepoint = on.savepoint as ((...args: unknown[]) => unknown) | undefined;
    if (savepoint !== undefined) on.savepoint = (...args: unknown[]) => {
      const work = args.pop() as (sp: Asks) => unknown;
      return savepoint.call(on, ...args, (sp: Asks) => work(kept(sp)));
    };
    return on;
  };
  kept(client as Asks);
  const begin = client.begin as (...args: unknown[]) => unknown;
  (client as { begin: unknown }).begin = (...args: unknown[]) => {
    const work = args.pop() as (tx: Asks) => unknown;
    return begin.call(client, ...args, (tx: Asks) => work(kept(tx)));
  };
  try {
    await work(createDatabase(client));
  } finally {
    await client.end();
  }
  return seen.filter(({ text }) => /\b(audit_log|log_changes)\b/.test(text) && /^\s*(select|with)\b/i.test(text));
}

/** The pages `statement` reads, run again under EXPLAIN as the vault's login, and the indexes it reads them by. */
async function measure(statement: Statement): Promise<{ pages: number; indexes: string[] }> {
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
async function history({ head = [], run: matching, tail, changes = [] }: Pick<Lookup, 'head' | 'run' | 'tail' | 'changes'>): Promise<{ first: bigint; newest: bigint }> {
  await startOver();
  for (const rows of head) await append(rows);
  const first = (await newestSeq()) + 1n;
  if (matching !== undefined) await append(matching);
  const newest = await newestSeq();
  for (const rows of tail) await append(rows);
  for (const run of changes) await appendChanges(run);
  for (const table of ['audit_log', 'log_changes']) await rowsOf(db.owner, sql.raw(`VACUUM (ANALYZE, PARALLEL 0) ${table}`));
  return { first, newest };
}

for (const lookup of LOOKUPS) {
  test(`${lookup.name}: one step of its index, however long the run of other entries since (T245, R48)`, { timeout: 300_000 }, async () => {
    const { first, newest } = await history(lookup);
    const statements = await sent((vault) => lookup.ask(vault, { first, newest }));
    assert.ok(statements.length > 0, 'the read asked the logs');
    for (const statement of statements) {
      const { pages, indexes } = await measure(statement);
      const said = JSON.stringify({ statement: statement.text, pages, indexes });
      assert.ok(indexes.some((index) => lookup.indexes.includes(index)), `takes one of ${lookup.indexes.join(', ')}: ${said}`);
      assert.ok(pages <= PAGES, `reads at most ${PAGES} pages: ${said}`);
    }
  });
}

test("a lookup is held by every read it sends of the logs, one inside a transaction's savepoint too (review r9 of #556)", async () => {
  const statements = await sent((vault) => vault.transaction(async (tx) => {
    await rowsOf(tx, sql`SELECT seq FROM audit_log WHERE seq = 1`);
    await tx.transaction((inner) => rowsOf(inner, sql`SELECT seq FROM audit_log WHERE seq = 2`));
  }));
  assert.deepEqual(statements.map(({ text }) => /seq = (\d)/.exec(text)?.[1]), ['1', '2']);
});

/**
 * The database's functions' lookups of 0.14's log (a use's, a sign-in's, an issue's): each of these kinds, as they write
 * it, and the history that is worst for it. PL/pgSQL plans a statement for its values for a session's first five
 * calls, then for any values, so each is held to its index under both plans, its variable a parameter.
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
    // A target's freezes and lifts, most of the app's entries, then a long tail of others: through `= ANY` of the
    // target, ordered by it (`keyedBy`), only `audit_log_frozen_idx` yields the order; asked by `= target`, a plan for
    // any target walked `audit_log_app_idx` back, 701 pages behind 20,000 (0082).
    kind: 'freeze',
    where: /^a\.author = 'app' AND a\.action IN \('workload\.freeze', 'workload\.unfreeze'\) AND a\.decision = 'allow' AND \(a\.metadata::jsonb ->> 'target'\) = ANY\(ARRAY\[([\w.]+)\]\)$/,
    index: 'audit_log_frozen_idx',
    value: 'instance',
    history: { run: { author: 'app', action: 'workload.freeze', metadata: FREEZE }, tail: [{ author: 'app', action: 'secret.read', metadata: FREEZE }] },
  },
] satisfies { kind: string; where: RegExp; index: string; value: string | null; history: Pick<Lookup, 'run' | 'tail'> }[];

/** The functions' bodies, comments out and on one line. */
async function functionBodies(): Promise<{ name: string; flat: string }[]> {
  const functions = await rows<{ name: string; body: string }>(db.owner, sql`
    SELECT p.proname AS name, p.prosrc AS body FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public' AND p.prosrc ~ '(audit_log|log_changes)'`);
  return functions.map(({ name, body }) => ({ name, flat: body.replace(/--[^\n]*/g, '').replace(/\s+/g, ' ') }));
}

/** `statements`, each its one parameter of type `type` set to `value` (none if null), under a plan for its values, then one for any: the index each takes and the pages it reads. */
async function heldUnderBothPlans(statements: string[], type: string, value: string | null, index: string): Promise<void> {
  for (const mode of ['force_custom_plan', 'force_generic_plan']) {
    const one = postgresClient(VAULT_URL, { max: 1, connection: { plan_cache_mode: mode } });
    try {
      for (const [i, text] of statements.entries()) {
        await one.unsafe(value === null ? `PREPARE lookup${i} AS ${text}` : `PREPARE lookup${i} (${type}) AS ${text}`);
        const explained = `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE lookup${i}${value === null ? '' : `('${value}')`}`;
        await one.unsafe(explained);
        const [row] = await one.unsafe(explained);
        const plan = (row as unknown as { 'QUERY PLAN': [{ Plan: Node }] })['QUERY PLAN'][0].Plan;
        const indexes = (node: Node): string[] => [...(node['Index Name'] === undefined ? [] : [node['Index Name']]), ...(node.Plans ?? []).flatMap(indexes)];
        const pages = plan['Shared Hit Blocks'] + plan['Shared Read Blocks'];
        const said = JSON.stringify({ mode, text, pages, indexes: indexes(plan) });
        assert.ok(indexes(plan).includes(index), `takes ${index}: ${said}`);
        assert.ok(pages <= PAGES, `reads at most ${PAGES} pages: ${said}`);
      }
    } finally {
      await one.end();
    }
  }
}

test("every newest lookup of 0.14's log in the database's functions is a kind held here, one step of its index under either plan (T245, R48)", { timeout: 600_000 }, async () => {
  const found = new Map<string, string[]>(FUNCTION_KINDS.map(({ kind }) => [kind, []]));
  const unknown: string[] = [];
  for (const { name, flat } of await functionBodies()) {
    const lookups = [...flat.matchAll(/\(\s*SELECT ([\w.:]+) FROM public\.audit_log a WHERE ((?:(?!SELECT |FROM ).)+?) ORDER BY ((?:\(a\.metadata::jsonb ->> 'target'\) DESC, )?a\.seq DESC) LIMIT 1\s*\)/g)];
    // Any other order of the log by `seq`, or its newest by `max`, which the pattern would miss.
    if ([...flat.matchAll(/ORDER BY (?:[^;]{0,60}, )?a\.seq|\b(?:max|min)\(a\.seq\)/g)].length !== lookups.length) unknown.push(`${name}: a lookup of another shape`);
    for (const [, column, where, order] of lookups) {
      const kind = FUNCTION_KINDS.find((known) => known.where.test(where!));
      if (kind === undefined) unknown.push(`${name}: ${where}`);
      else found.get(kind.kind)!.push(`SELECT ${column} FROM public.audit_log a WHERE ${where!.replace(kind.where, (whole, variable: string | number) => (typeof variable === 'string' ? whole.replace(variable, () => '$1') : whole))} ORDER BY ${order} LIMIT 1`);
    }
  }
  assert.deepEqual(unknown, [], 'a lookup in a function none of FUNCTION_KINDS names: name its kind, with its index and its worst history');
  for (const { kind, index, value, history: worst } of FUNCTION_KINDS) {
    const statements = [...new Set(found.get(kind))];
    assert.ok(statements.length > 0, `the functions look ${kind} up`);
    await history(worst);
    await heldUnderBothPlans(statements, 'text', value, index);
  }
});

test("every lookup of an object's newest change in the database's functions is `changesOf`'s, one step of the object's index under either plan (T245, R48)", { timeout: 600_000 }, async () => {
  const statements = new Set<string>();
  const unknown: string[] = [];
  // The log's newest change of all, the primary key's first step, with nothing to filter.
  const head = /FROM public\.log_changes (\w+) ORDER BY \1\.number DESC LIMIT 1/g;
  const keyed = /FROM public\.log_changes (\w+) WHERE \1\.object = ANY\(ARRAY\[(.+?)::uuid\]\)((?:(?!ORDER BY|;).)*?) ORDER BY \1\.object DESC, \1\.number DESC LIMIT 1/g;
  for (const { name, flat } of await functionBodies()) {
    const lookups = [...flat.matchAll(keyed)];
    // Every order of the changes by number, or their newest or oldest by `max` or `min`, its table the one its alias
    // names last before it: each one of the two shapes.
    const ordered = [...flat.matchAll(/ORDER BY (?:[^;]{0,60}?, )?(\w+)\.number\b|\b(?:max|min)\((\w+)\.number\)/g)].filter((order) => {
      const alias = order[1] ?? order[2]!;
      // An order's FROM comes before it; an aggregate's after it, before the next.
      const upTo = order[1] === undefined ? order.index + order[0].length + 60 : order.index;
      const tables = [...flat.slice(0, upTo).matchAll(new RegExp(`\\bpublic\\.(\\w+) ${alias}\\b`, 'g'))];
      return tables.at(-1)?.[1] === 'log_changes';
    }).length;
    if (ordered !== lookups.length + [...flat.matchAll(head)].length) unknown.push(`${name}: a lookup of its changes of another shape`);
    for (const [, alias, , rest] of lookups) {
      statements.add(`SELECT ${alias}.* FROM public.log_changes ${alias} WHERE ${alias}.object = ANY(ARRAY[$1::uuid])${rest} ORDER BY ${alias}.object DESC, ${alias}.number DESC LIMIT 1`);
    }
  }
  assert.deepEqual(unknown, [], "a lookup of an object's changes in a function by another shape than `changesOf`'s: the primary key's walk back");
  assert.ok(statements.size > 0, 'the functions look changes up');
  // `changesOf`'s own, of a value, as the sources ask it.
  const value = changesOf('x', sql.raw('$1'));
  const { sql: text } = new PgDialect().sqlToQuery(sql`SELECT x.* FROM log_changes x WHERE ${value.where} ORDER BY ${value.order} LIMIT 1`);
  statements.add(text);
  await history({ tail: [], changes: [{ object: objectKey(MEMBER) }, others()] });
  await heldUnderBothPlans([...statements], 'uuid', objectKey(MEMBER), 'log_changes_object_idx');
});
