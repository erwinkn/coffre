// What an unhandled error leaves in the log: its message, and on Postgres
// its code and the names it gives, but never its words or the query's
// parameters, either of which may quote a value. Logged as it was, an error showed only its stack
// on Workers. And what the request is told: an outage is 503 `unavailable`,
// which says when to ask again; anything else is a bug's 500.
import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { inspect } from 'node:util';

import { openDatabase } from '@coffre/db/connect';
import { sql } from 'drizzle-orm';

import { ApiError, toErrorBody } from '../src/api/errors.ts';
import { errorResponse } from '../src/http.ts';
import { TEST_OWNER_DATABASE_URL } from './db/connections.ts';

const { db, close } = await openDatabase(TEST_OWNER_DATABASE_URL);
after(() => close());

const UNAVAILABLE = { status: 503, body: { error: 'unavailable', message: 'coffre cannot reach what it depends on right now; try again in a moment' } };
const INTERNAL = { status: 500, body: { error: 'internal_error', message: 'something went wrong; see the server log' } };

/** What `work` logged with `console.error`, each call's arguments. */
function logs(t: { mock: { method: (object: Console, name: 'error', fn: (...args: unknown[]) => void) => unknown } }): unknown[][] {
  const logged: unknown[][] = [];
  t.mock.method(console, 'error', (...args: unknown[]) => void logged.push(args));
  return logged;
}

const failed = (work: () => Promise<unknown>) => work().then(() => assert.fail('the query ran'), (thrown: unknown) => thrown);

test("an unhandled database error is logged with its query and Postgres's code, never its parameters", async (t) => {
  // A parameter whose lines look like a stack's frames: the stack begins with the message, and so with it.
  const value = 'coffre-canary-not-for-the-log\n    at private-request-value (frame.js:1:1)';
  const error = await failed(() => db.select({ v: sql`${value}` }).from(sql`no_such_table`));
  assert.ok(String((error as Error).stack).includes('private-request-value'));
  const logged = logs(t);
  assert.deepEqual(toErrorBody(error), INTERNAL);
  assert.equal(logged.length, 1);
  const [label, line] = logged[0] as [string, Record<string, unknown>];
  assert.equal(label, 'unhandled API error');
  assert.ok(!inspect(logged, { depth: null }).includes('coffre-canary'), 'a parameter in the log');
  assert.ok(!inspect(logged, { depth: null }).includes('private-request-value'), 'a parameter in the stack');
  assert.match(String(line.message), /^Failed query: select \$1 from no_such_table$/);
  // The frames, which name this file, and not the message the stack begins with.
  assert.ok(typeof line.stack === 'string' && line.stack.includes('logged.test.ts'), 'no stack');
  assert.ok(!String(line.stack).includes('Failed query'), 'the stack repeats the message');
  const cause = line.cause as Record<string, unknown>;
  assert.deepEqual([cause.code, cause.severity, typeof cause.routine], ['42P01', 'ERROR', 'string']);
  assert.equal(cause.message, "Postgres's words are left out: they may quote a value");
});

test('a value Postgres quotes, a cast it could not make or a row a constraint refused, never reaches the log, nor one an error rebuilt across a call quotes', async (t) => {
  const value = 'coffre-canary-cast';
  const cast = await failed(() => db.execute(sql`SELECT ${value}::uuid`));
  const twice = await failed(() => db.transaction(async (tx) => {
    await tx.execute(sql`CREATE TEMPORARY TABLE kept (key text CONSTRAINT kept_key_unique UNIQUE) ON COMMIT DROP`);
    await tx.execute(sql`INSERT INTO kept VALUES (${value}), (${value})`);
  }));
  // As the vault's errors reach the app across its call: their words, and Postgres's code, kept.
  const rebuilt = [Object.assign(new Error(`invalid input syntax for type uuid: "${value}"`), { code: '22P02' }), new Error(`Failed query: select $1\nparams: ${value}`)];
  // Each quotes the value, as it is: the log is what leaves it out.
  for (const error of [cast, twice, ...rebuilt]) assert.ok(inspect(error, { depth: null }).includes(value));
  const logged = logs(t);
  for (const error of [cast, twice, ...rebuilt]) assert.deepEqual(toErrorBody(error), INTERNAL);
  assert.equal(logged.length, 4);
  assert.ok(!inspect(logged, { depth: null }).includes(value), 'a value in the log');
  const [castLine, twiceLine, rebuiltLine, drizzleLine] = logged.map(([, line]) => line as Record<string, unknown>);
  assert.deepEqual([(castLine!.cause as Record<string, unknown>).code, (twiceLine!.cause as Record<string, unknown>).constraint, rebuiltLine!.code], ['22P02', 'kept_key_unique', '22P02']);
  assert.equal(drizzleLine!.message, 'Failed query: select $1');
});

test('a broken constraint is logged by its name and its table, and not the row that broke it', async (t) => {
  const value = 'coffre-canary-twice';
  const error = await failed(() => db.transaction(async (tx) => {
    await tx.execute(sql`CREATE TEMPORARY TABLE kept (key text CONSTRAINT kept_key_unique UNIQUE) ON COMMIT DROP`);
    await tx.execute(sql`INSERT INTO kept VALUES (${value})`);
    await tx.execute(sql`INSERT INTO kept VALUES (${value})`);
  }));
  const logged = logs(t);
  assert.deepEqual(toErrorBody(error), INTERNAL);
  const [label, line] = logged[0] as [string, Record<string, unknown>];
  assert.equal(label, 'unhandled API error');
  const cause = line.cause as Record<string, unknown>;
  assert.deepEqual([cause.code, cause.constraint, cause.table], ['23505', 'kept_key_unique', 'kept']);
  // Postgres's detail quotes the key that broke it, the value with it: nowhere in the line, its causes' included.
  assert.ok(!JSON.stringify(logged).includes(value), 'the row in the log');
});

test("a database that does not answer is 503 unavailable, the request's to ask again, and a statement that gave up waiting is logged apart", (t) => {
  const logged = logs(t);
  // As the vault's error reached the app on 2026-10-25, across its RPC: Drizzle's, Hyperdrive's beneath.
  const pool = new Error('Failed query: select "secret_versions"."id" …', {
    cause: Object.assign(new Error('Timed out while waiting for an open slot in the pool.'), { code: '58000', severity: 'FATAL' }),
  });
  const acquire = new Error('Failed query: select 1', { cause: new Error('Failed to acquire a connection from the pool.') });
  const lock = new Error('Failed query: select "principal" …', { cause: Object.assign(new Error('canceling statement due to lock timeout'), { code: '55P03' }) });
  for (const error of [pool, acquire, new Error('Connection terminated unexpectedly'), Object.assign(new Error('sorry, too many clients already'), { code: '53300' }), lock]) {
    assert.deepEqual(toErrorBody(error), UNAVAILABLE, error.message);
  }
  // A lock waited on past its bound is an outage under a busy database, and a transaction held too long otherwise.
  assert.deepEqual(logged.map(([label]) => label), [...Array(4).fill('a dependency did not answer'), 'a statement gave up waiting']);
  // What the words said, which the log leaves out, as a fixed word: 58000 alone is many a failure.
  assert.deepEqual(logged.map(([, line]) => (line as { failure?: string }).failure), ['pool full', 'pool full', 'unreachable', 'pool full', 'gave up waiting']);

  // A query that is wrong is a bug, whatever its words, a parameter Drizzle quotes included.
  logged.length = 0;
  const quoted = Object.assign(new Error('Failed query: update members set note = $1\nparams: connection terminated'), {
    query: 'update members set note = $1',
    params: ['connection terminated'],
    cause: Object.assign(new Error('insert or update violates foreign key constraint'), { code: '23503' }),
  });
  for (const error of [
    Object.assign(new Error('syntax error at or near "selec"'), { code: '42601' }),
    quoted,
    Object.assign(new Error('invalid input syntax for type uuid: "connection timeout"'), { code: '22P02' }),
    // Postgres answered, telling the client it broke the protocol: the same request fails the same way.
    Object.assign(new Error('bind message supplies 1 parameters, but prepared statement "" requires 2'), { code: '08P01' }),
  ]) {
    assert.deepEqual(toErrorBody(error), INTERNAL, error.message);
  }
  assert.deepEqual(logged.map(([label]) => label), Array(4).fill('unhandled API error'));
  // Drizzle's message is logged as its query alone: the parameter it quotes stays out.
  assert.equal((logged[1]![1] as { message: string }).message, 'Failed query: update members set note = $1');
});

test("a moment's 503 says when to ask again, 5 seconds, and nothing else does", (t) => {
  logs(t);
  const lock = new Error('Failed query: select "principal" …', { cause: Object.assign(new Error('canceling statement due to lock timeout'), { code: '55P03' }) });
  for (const error of [lock, new ApiError('unavailable', 'coffre cannot check who you are right now'), new ApiError('adopting', "coffre's vault has not taken over its database yet")]) {
    const response = errorResponse(error, { 'x-kept': 'yes' });
    assert.deepEqual([response.status, response.headers.get('retry-after'), response.headers.get('x-kept')], [503, '5', 'yes'], error.message);
  }
  // One that waits on an operator, or that says its own wait, is left as it is; so is any other status.
  assert.equal(errorResponse(new ApiError('unavailable', 'the vault holds another key', 'wrong_kek')).headers.get('retry-after'), null);
  assert.equal(errorResponse(new ApiError('migrating', 'migrate first'), { 'retry-after': '30' }).headers.get('retry-after'), '30');
  assert.equal(errorResponse(new ApiError('unavailable', 'coffre cannot reach what it depends on right now'), { 'retry-after': '30' }).headers.get('retry-after'), '30');
  for (const error of [new ApiError('forbidden', 'no'), new ApiError('tampered', 'a row'), new ApiError('too_many_requests', 'later'), new Error('a bug')]) {
    assert.equal(errorResponse(error).headers.get('retry-after'), null, error.message);
  }
});
