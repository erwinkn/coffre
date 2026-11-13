// The audit page's check plans and locks the same however many days of uses the log keeps (T277, D200; audit-check.ts,
// `checkRead`). Its one statement bounds the uses above the newest checkpoint by that row's floor of `at`, a value of
// the statement's own, which Postgres cannot prune `log_uses`' day partitions by: without the signer's floor beside it,
// a constant, every visit planned and locked every day kept (without it, measured here: 380 locks and 290 planning
// buffers at 104 days, against 83 and 92 at 5; 0054 was the same for `log_reads`). The 0.15 page check (`verifyTrees`) reads through the same
// statement, its bound the pairs held outside. Both are held here, at a handful of days and at a hundred more.
//
// It runs alone, after the suite (scripts/test-suite.sh), as use-days.alone.ts does and for its reason: a commit of
// thousands of catalog changes elsewhere in the cluster makes a backend plan everything again.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import type { CheckInput } from '@coffre/core/vault';
import { createDatabase, type Database } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';
import { sql } from 'drizzle-orm';

import { checkAudit } from '../src/audit-check.ts';
import { reachedOf } from '../src/checkpointer.ts';
import { openLogCheckpointer } from '../src/log-checkpointer.ts';
import { logMacKey } from '../src/log-entry.ts';
import { logStore } from '../src/log-store.ts';
import { verifierKeys, verifyTrees } from '../src/verifier.ts';
import { variableMemory } from './audit-tree.ts';
import { logWriter } from './log-entries.ts';
import { openTestDatabase, rows, run, VAULT_URL, type TestDatabase } from './database.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
});
after(() => db.close());

const DAY = 86_400_000;

/** A statement as the vault sent it: its text and its values. */
type Sent = { query: string; params: unknown[] };

/** The vault's database, each statement it sends kept (`sent`). */
function capturing(): { db: Database; sent: Sent[]; close: () => Promise<void> } {
  const sent: Sent[] = [];
  const pool = postgresClient(VAULT_URL, { max: 1 });
  const client = new Proxy(pool, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (typeof value !== 'function') return value;
      if (key === 'unsafe') {
        return (query: string, params: unknown[] = [], ...rest: unknown[]) => {
          sent.push({ query, params });
          return (value as (...a: unknown[]) => unknown).apply(target, [query, params, ...rest]);
        };
      }
      return (value as (...a: unknown[]) => unknown).bind(target);
    },
  });
  return { db: createDatabase(client), sent, close: () => pool.end() };
}

/** A statement's planning buffers, warm (its second plan on the connection), and the relation locks its run takes. */
async function work({ query, params }: Sent): Promise<{ planning: number; locks: number }> {
  const client = postgresClient(VAULT_URL, { max: 1 });
  try {
    let measured = { planning: 0, locks: 0 };
    for (let i = 0; i < 2; i += 1) {
      await client.begin(async (tx) => {
        const [plan] = await tx.unsafe(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${query}`, params as never[]);
        const planned = (plan as unknown as { 'QUERY PLAN': { Planning?: { 'Shared Hit Blocks': number; 'Shared Read Blocks': number } }[] })['QUERY PLAN'][0]!.Planning;
        const [held] = await tx.unsafe(`SELECT count(*)::integer AS n FROM pg_locks WHERE pid = pg_backend_pid() AND locktype = 'relation'`);
        measured = { planning: (planned?.['Shared Hit Blocks'] ?? 0) + (planned?.['Shared Read Blocks'] ?? 0), locks: (held as unknown as { n: number }).n };
      });
    }
    return measured;
  } finally {
    await client.end();
  }
}

test('D200: a visit\'s check, and the 0.15 page check, plan and lock the same at a handful of days and at a hundred more', { timeout: 300_000 }, async () => {
  const seed = randomBytes(32);
  const mac = logMacKey(seed);
  const log = logWriter(db.owner, mac);
  await log.empty();
  await log.days();
  const cp = await openLogCheckpointer({ store: logStore(db.vault), signingKeys: [seed], memory: variableMemory() });
  const keys = await verifierKeys([seed]);
  await log.uses(200);
  assert.ok((await cp.tick()).signed);
  await log.uses(10);
  const input: CheckInput = { events: [], cursor: { through: '0', pair: '0', at: 0, oldFrom: '0', oldHash: '0'.repeat(64), mac: null } };

  const statements = async () => {
    const capture = capturing();
    try {
      const checked = await checkAudit(capture.db, keys, input, { reached: reachedOf(cp, { ok: true }), upgraded: false });
      assert.equal(checked.state, 'ok', checked.reason ?? '');
      const [visit] = capture.sent.splice(0);
      const walked = await verifyTrees(capture.db, keys, { anchors: [cp.pair.notes] });
      assert.ok(walked.ok, walked.problems.join('; '));
      const [page] = capture.sent;
      assert.ok(visit !== undefined && page !== undefined && capture.sent.length === 1, 'each one statement');
      return { visit: await work(visit), page: await work(page) };
    } finally {
      await capture.close();
    }
  };
  const days = async () => Number((await rows<{ n: string }>(db.owner, sql`SELECT count(*)::text AS n FROM pg_inherits WHERE inhparent = 'log_uses'::regclass`))[0]!.n);

  const few = { days: await days(), ...await statements() };
  const today = Math.floor(Date.now() / DAY) * DAY;
  for (let d = 1; d <= 100; d += 1) await run(db.owner, sql`SELECT make_day(${new Date(today - d * DAY).toISOString().slice(0, 10)}::date)`);
  const many = { days: await days(), ...await statements() };
  console.log(JSON.stringify({ few, many }));
  assert.ok(many.days - few.days >= 95, `${few.days} days, then ${many.days}`);
  for (const which of ['visit', 'page'] as const) {
    const [a, b] = [few[which], many[which]];
    // A lock on each day's partition and its indexes, unpruned: hundreds more at a hundred days.
    assert.equal(b.locks, a.locks, `${which}: ${a.locks} locks at ${few.days} days, ${b.locks} at ${many.days}`);
    // Planning every day read about 2 buffers a day more (290 against 92, measured); pruned, a page or two of the
    // partition descriptor at most.
    assert.ok(b.planning - a.planning <= 20, `${which}: ${a.planning} planning buffers at ${few.days} days, ${b.planning} at ${many.days}`);
  }
});
