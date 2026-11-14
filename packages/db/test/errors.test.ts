// Which failures of a query are an outage, the request's to ask again, and
// which are an answer: what the app's migration door lets through
// (`isUnreachable`), and what the API answers 503 (`isUnavailable`), a
// statement that gave up waiting (`gaveUp`) among them. Read by code first,
// then, for what says none, by the driver's and Hyperdrive's words.
import test from 'node:test';
import assert from 'node:assert/strict';

import { gaveUp, gaveUpCode, isUnavailable, isUnreachable } from '../src/dialect.ts';

const coded = (message: string, code: string, more: Record<string, unknown> = {}) => Object.assign(new Error(message), { code, ...more });
/** As Drizzle wraps what the driver threw: its own words quote the query, and the driver's error is its cause. */
const failedQuery = (cause: unknown) => new Error('Failed query: select 1\nparams: ', { cause });

test('a database that cannot be reached, or that dropped the connection, is unreachable: by its code, or by the words of what says none', () => {
  for (const error of [
    coded('connect ECONNREFUSED 127.0.0.1:1', 'ECONNREFUSED'),
    coded('write EPIPE', 'EPIPE'),
    coded('write CONNECTION_CLOSED', 'CONNECTION_CLOSED'),
    coded('connection failure', '08006'),
    coded('the database system is shutting down', '57P03'),
    new Error('query failed', { cause: coded('terminating connection due to administrator command', '57P01') }),
    // Workers' sockets say it in words, with no code.
    new Error('Connection terminated unexpectedly'),
    new Error('Network connection lost.'),
    // A call Workers cancelled as hung: the vault, or its database, never answered.
    new Error("The Workers runtime canceled this request because it detected that your Worker's code had hung"),
    // Hyperdrive, with no connection to the database to be made. A pool with none to give is busy, no outage (dialect.test.ts, D238).
    new Error('Server connection attempt failed: destination_unavailable'),
  ]) {
    assert.equal(isUnreachable(error), true, error.message);
    assert.equal(isUnavailable(error), true, error.message);
  }
});

test('an answer from the database is no outage, whatever its words: a missing ledger, a denied permission, a wrong query, a broken protocol', () => {
  for (const error of [
    // What the migration door reads of a database never migrated, or one whose login lacks the grant: below the door, not past it.
    coded('relation "drizzle.__drizzle_migrations" does not exist', '42P01'),
    coded('permission denied for schema drizzle', '42501'),
    coded('syntax error at or near "selec"', '42601'),
    // Postgres's words may quote input: an error with a code is read by its code.
    coded('invalid input syntax for type uuid: "connection timeout"', '22P02'),
    // The client broke the protocol: asked again, it fails the same way.
    coded('bind message supplies 1 parameters, but prepared statement "" requires 2', '08P01'),
    // Drizzle's own words quote the parameters, which may say anything; its cause is what the database said.
    Object.assign(new Error('Failed query: update members set note = $1\nparams: connection terminated'), {
      query: 'update members set note = $1',
      params: ['connection terminated'],
      cause: coded('insert or update violates foreign key constraint', '23503'),
    }),
    // A code beside words of an outage: the code says what it is.
    coded('Timed out while waiting for an open slot in the pool.', '42P01'),
    new Error('a bug'),
    null,
    'connection terminated',
  ]) {
    assert.equal(isUnreachable(error), false, String(error));
    assert.equal(isUnavailable(error), false, String(error));
  }
});

test('a statement that gave up waiting had its connection: unavailable, but never unreachable, so the migration door does not let it through', () => {
  for (const [code, message] of [['55P03', 'canceling statement due to lock timeout'], ['57014', 'canceling statement due to statement timeout']] as const) {
    const error = failedQuery(coded(message, code));
    assert.deepEqual([gaveUp(error), gaveUpCode(error), isUnavailable(error), isUnreachable(error)], [true, code, true, false], code);
  }
  assert.deepEqual([gaveUp(coded('connection failure', '08006')), gaveUpCode(new Error('a bug'))], [false, undefined]);
});
