// What an unhandled error leaves in the log: its message, and on Postgres
// the fields that say what went wrong, but never the query's parameters,
// which may hold a value. Logged as it was, an error showed only its stack
// on Workers.
import { after, test } from 'node:test';
import assert from 'node:assert/strict';

import { isUnavailable } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { toErrorBody } from '../src/api/errors.ts';
import { openTestDatabase } from './api-fixture.ts';
import { TEST_ENGINE } from './db/engine.ts';

const db = await openTestDatabase();
after(() => db.close());

test('an unhandled database error is logged with its message and what Postgres said, never its parameters', async (t) => {
  const value = 'coffre-canary-not-for-the-log';
  const error = await db.runtime.select({ v: sql`${value}` }).from(sql`no_such_table`).then(
    () => assert.fail('the query ran'),
    (thrown: unknown) => thrown,
  );
  const logged: unknown[][] = [];
  t.mock.method(console, 'error', (...args: unknown[]) => void logged.push(args));
  assert.equal(toErrorBody(error).status, 500);
  assert.equal(logged.length, 1);
  const [label, line] = logged[0] as [string, Record<string, unknown>];
  assert.equal(label, 'unhandled API error');
  assert.ok(!JSON.stringify(logged).includes(value), 'a parameter in the log');
  assert.match(String(line.message), /^Failed query: select (\$1|\?) from no_such_table/);
  assert.ok(typeof line.stack === 'string' && line.stack.includes('logged.test.ts'), 'no stack');
  const cause = line.cause as Record<string, unknown>;
  assert.ok(typeof cause.message === 'string' && cause.message.length > 0, 'no cause');
  if (TEST_ENGINE === 'postgres') {
    assert.deepEqual([cause.code, cause.severity, cause.routine !== undefined], ['42P01', 'ERROR', true]);
    assert.match(String(cause.message), /relation "no_such_table" does not exist/);
  }
});

test("a database that does not answer is 503 unavailable, the request's to ask again, and logged as such", (t) => {
  const logged: unknown[][] = [];
  t.mock.method(console, 'error', (...args: unknown[]) => void logged.push(args));
  // As the vault's error reached the app on 2026-10-25, across its RPC: Drizzle's, Hyperdrive's beneath.
  const pool = new Error('Failed query: select "secret_versions"."id" …', {
    cause: Object.assign(new Error('Timed out while waiting for an open slot in the pool.'), { code: '58000', severity: 'FATAL' }),
  });
  const lock = new Error('Failed query: select "principal" …', { cause: Object.assign(new Error('canceling statement due to lock timeout'), { code: '55P03' }) });
  const acquire = new Error('Failed query: select 1', { cause: new Error('Failed to acquire a connection from the pool.') });
  for (const error of [pool, acquire, new Error('Connection terminated unexpectedly'), Object.assign(new Error('sorry, too many clients already'), { code: '53300' }), lock]) {
    assert.equal(isUnavailable(error), true, error.message);
    assert.deepEqual(toErrorBody(error), { status: 503, body: { error: 'unavailable', message: 'coffre cannot reach its database right now; try again in a moment' } });
  }
  // A lock waited on past its bound is an outage under a busy database, and a transaction held too long otherwise: logged apart.
  assert.deepEqual(logged.map(([label]) => label), [...Array(4).fill('the database did not answer'), 'a statement gave up waiting']);
  // A query that is wrong is a bug, whatever its words.
  assert.equal(isUnavailable(Object.assign(new Error('syntax error at or near "selec"'), { code: '42601' })), false);
});
