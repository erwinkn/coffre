import test from 'node:test';
import assert from 'node:assert/strict';

import { gaveUp, isUnavailable, isUnreachable, poolFull } from '../src/dialect.ts';

/** As Drizzle wraps a driver's error: its own words quote the query, the driver's are its cause's. */
const failed = (cause: Error) => new Error('Failed query: select 1\nparams: ', { cause });
const coded = (message: string, code: string) => Object.assign(new Error(message), { code });

test('a pool with no connection to give is the database busy: unavailable, and no outage (D238)', () => {
  for (const full of [
    // Hyperdrive, every connection of its pool busy for 15 s, and its words for no connection to give, which carry no code.
    failed(Object.assign(coded('Timed out while waiting for an open slot in the pool.', '58000'), { severity: 'FATAL' })),
    failed(new Error('Failed to acquire a connection from the pool.')),
    // Postgres out of connections, which Hyperdrive gives Workers past its own limit too.
    failed(coded('sorry, too many clients already', '53300')),
    // The code the vault's answer gives it, across its RPC or socket.
    { code: '53000' },
  ]) {
    assert.deepEqual([poolFull(full), isUnreachable(full), gaveUp(full), isUnavailable(full)], [true, false, false, true]);
  }
});

test('a database that cannot be reached is an outage, and no pool full', () => {
  for (const down of [
    failed(coded('connect ECONNREFUSED 127.0.0.1:5432', 'ECONNREFUSED')),
    failed(coded('write CONNECTION_CLOSED abc.hyperdrive.local:5432', 'CONNECTION_CLOSED')),
    failed(coded('terminating connection due to administrator command', '57P01')),
    // Hyperdrive with no connection to be made; local workerd's says less.
    failed(new Error('Server connection attempt failed: destination_unavailable')),
    failed(new Error('connection attempt failed')),
  ]) {
    assert.deepEqual([isUnreachable(down), poolFull(down), isUnavailable(down)], [true, false, true]);
  }
});

test("words count only as the driver's, never a query's parameters, and a code is read by its code", () => {
  const quoted = Object.assign(new Error('Failed query: update members set note = $1\nparams: open slot in the pool'), { params: ['open slot in the pool'] });
  assert.deepEqual([poolFull(quoted), isUnavailable(quoted)], [false, false]);
  const input = coded('invalid input syntax for type uuid: "Failed to acquire a connection from the pool"', '22P02');
  assert.deepEqual([poolFull(input), isUnavailable(input)], [false, false]);
});
