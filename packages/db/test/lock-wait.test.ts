// The app's write transactions wait for a lock `LOCK_WAIT_MS` at most: a write waiting for the fence holds
// back every use behind it in Postgres's queue, so it leaves the queue within half a use's own wait, and fails as
// unavailable, rather than queue on. Set in the transaction's first Sync (`createDatabase`'s `lockWaitMs`), never past it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { sql } from 'drizzle-orm';

import { HOT_LOCK_TIMEOUT_MS, LOCK_WAIT_MS } from '@coffre/core/vault';

import { createDatabase } from '../src/database.ts';
import { gaveUp } from '../src/dialect.ts';
import { postgresClient } from '../src/postgres.ts';

const url = `postgresql://coffre_owner:local-dev-only@127.0.0.1:${process.env.COFFRE_POSTGRES_PORT ?? '55432'}/${process.env.COFFRE_TEST_DATABASE ?? 'coffre_test'}`;

test("a transaction of a database made with lockWaitMs gives up a lock after it, and the next statement outside it waits as Postgres's default", async () => {
  const holder = postgresClient(url, { max: 1 });
  const client = postgresClient(url, { max: 1 });
  const db = createDatabase(client, { lockWaitMs: LOCK_WAIT_MS });
  let letGo = () => {};
  const held = new Promise<void>((resolve) => (letGo = resolve));
  let holding = () => {};
  const holds = new Promise<void>((resolve) => (holding = resolve));
  try {
    const holder_ = holder.begin(async (tx) => {
      await tx.unsafe('SELECT 1 FROM audit_chain_head WHERE only_row FOR UPDATE');
      holding();
      await held;
    });
    await holds;
    const started = Date.now();
    await assert.rejects(
      db.transaction(async (tx) => tx.execute(sql`SELECT 1 FROM audit_chain_head WHERE only_row FOR UPDATE`)),
      (error: unknown) => gaveUp(error),
    );
    const took = Date.now() - started;
    // At its bound, by Postgres's clock: never before it; after, by Node's, a watchdog for a hang alone.
    assert.ok(took >= LOCK_WAIT_MS && took < LOCK_WAIT_MS + 30_000, `it gave up after ${took} ms`);
    letGo();
    await holder_;
    // SET LOCAL: the bound ends with its transaction, and the connection's next statement has Postgres's own.
    const [{ lock_timeout: after }] = await client.unsafe<{ lock_timeout: string }[]>('SHOW lock_timeout');
    assert.equal(after, '0');
    // A transaction that asks nothing commits with the bound alone, and one that does reads it set.
    const [{ lock_timeout: within }] = await db.transaction(async (tx) => (await tx.execute(sql`SHOW lock_timeout`)) as unknown as { lock_timeout: string }[]);
    assert.equal(within, `${LOCK_WAIT_MS}ms`);
    await db.transaction(async () => {});
  } finally {
    letGo();
    await Promise.allSettled([holder.end(), client.end()]);
  }
});

test("the credential writes that take the fence wait LOCK_WAIT_MS for each lock, and the issues a use's whole wait (migration 0078)", async () => {
  const client = postgresClient(url, { max: 1 });
  try {
    const rows = await client.unsafe<{ name: string; config: string[] | null }[]>(
      `SELECT proname AS name, proconfig AS config FROM pg_proc WHERE pronamespace = 'public'::regnamespace
         AND proname IN ('revoke_credential', 'change_bindings', 'sign_in', 'issue_token') ORDER BY proname, pronargs`);
    const waits = rows.map(({ name, config }) => [name, (config ?? []).find((setting) => setting.startsWith('lock_timeout='))]);
    assert.deepEqual(waits, [
      // 0.15.0's (53 arguments, which 0079 makes delegate) and 0079's with its sweep (54): both wait LOCK_WAIT_MS, as a
      // `CREATE OR REPLACE` names its settings again.
      ['change_bindings', `lock_timeout=${LOCK_WAIT_MS}ms`],
      ['change_bindings', `lock_timeout=${LOCK_WAIT_MS}ms`],
      ['issue_token', `lock_timeout=${HOT_LOCK_TIMEOUT_MS / 1000}s`],
      ['issue_token', `lock_timeout=${HOT_LOCK_TIMEOUT_MS / 1000}s`],
      ['revoke_credential', `lock_timeout=${LOCK_WAIT_MS}ms`],
      // 0037's and 0075's, both kept.
      ['sign_in', `lock_timeout=${HOT_LOCK_TIMEOUT_MS / 1000}s`],
      ['sign_in', `lock_timeout=${HOT_LOCK_TIMEOUT_MS / 1000}s`],
    ]);
  } finally {
    await client.end();
  }
});
