import test, { before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';

import { appendAudit, readAuditRows } from '../src/audit.ts';
import { verifyChain, GENESIS_HASH } from '../../core/src/audit/chain.ts';
import {
  TEST_OWNER_DATABASE_URL,
  TEST_RUNTIME_DATABASE_URL,
} from './connections.ts';

const CHAIN_KEY = randomBytes(32);

let ownerPool: pg.Pool;
let runtimePool: pg.Pool;

before(async () => {
  ownerPool = new pg.Pool({ connectionString: TEST_OWNER_DATABASE_URL });
  runtimePool = new pg.Pool({ connectionString: TEST_RUNTIME_DATABASE_URL });
});

after(async () => {
  await runtimePool.end();
  await ownerPool.end();
});

beforeEach(async () => {
  const client = await ownerPool.connect();
  try {
    await client.query('DELETE FROM audit_log');
    await client.query(
      "UPDATE audit_chain_head SET next_seq = 0, head_hash = decode(repeat('00', 32), 'hex')",
    );
  } finally {
    client.release();
  }
});

async function inTransaction<T>(fn: (tx: pg.PoolClient) => Promise<T>): Promise<T> {
  const client = await runtimePool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

test('appended rows verify as a chain when read back from the database', async () => {
  await inTransaction((tx) =>
    appendAudit(tx, CHAIN_KEY, [
      { actorType: 'user', actorId: 'erwin@equisafe.io', action: 'secret.read', decision: 'allow' },
      { actorType: 'service', actorId: 'ci.access', action: 'secret.read', decision: 'allow' },
      { actorType: 'user', actorId: 'erwin@equisafe.io', action: 'secret.read', decision: 'deny' },
    ]),
  );

  const rows = await inTransaction((tx) => readAuditRows(tx));
  assert.equal(rows.length, 3);

  // The important property: the hash computed at write time still verifies
  // after a full round trip through Postgres. If timestamp or metadata
  // rendering drifted, this fails.
  const result = verifyChain(CHAIN_KEY, rows, GENESIS_HASH);
  assert.equal(result.ok, true, result.ok ? '' : result.reason);
});

test('the chain continues correctly across separate transactions', async () => {
  await inTransaction((tx) =>
    appendAudit(tx, CHAIN_KEY, [
      { actorType: 'user', actorId: 'a@equisafe.io', action: 'secret.read', decision: 'allow' },
    ]),
  );
  await inTransaction((tx) =>
    appendAudit(tx, CHAIN_KEY, [
      { actorType: 'user', actorId: 'b@equisafe.io', action: 'secret.read', decision: 'allow' },
    ]),
  );

  const rows = await inTransaction((tx) => readAuditRows(tx));
  assert.equal(rows.length, 2);
  assert.equal(verifyChain(CHAIN_KEY, rows, GENESIS_HASH).ok, true);
});

test('a rolled-back transaction leaves no gap in the sequence', async () => {
  await inTransaction((tx) =>
    appendAudit(tx, CHAIN_KEY, [
      { actorType: 'user', actorId: 'a@equisafe.io', action: 'secret.read', decision: 'allow' },
    ]),
  );

  // A read that fails after its audit row was written must leave nothing
  // behind. If seq came from a bigserial, this would burn seq 1 and the gap
  // would be indistinguishable from a deleted row.
  await assert.rejects(
    inTransaction(async (tx) => {
      await appendAudit(tx, CHAIN_KEY, [
        { actorType: 'user', actorId: 'b@equisafe.io', action: 'secret.read', decision: 'allow' },
      ]);
      throw new Error('simulated failure after the audit write');
    }),
  );

  await inTransaction((tx) =>
    appendAudit(tx, CHAIN_KEY, [
      { actorType: 'user', actorId: 'c@equisafe.io', action: 'secret.read', decision: 'allow' },
    ]),
  );

  const rows = await inTransaction((tx) => readAuditRows(tx));
  assert.deepEqual(
    rows.map((r) => r.seq),
    [0n, 1n],
    'sequence must be contiguous, so any gap means tampering',
  );
  assert.deepEqual(
    rows.map((r) => r.actorId),
    ['a@equisafe.io', 'c@equisafe.io'],
  );
  assert.equal(verifyChain(CHAIN_KEY, rows, GENESIS_HASH).ok, true);
});

test('a bulk read writes one row per secret, sharing a bundle id', async () => {
  const bundleId = '99999999-9999-4999-8999-999999999999';

  await inTransaction((tx) =>
    appendAudit(
      tx,
      CHAIN_KEY,
      ['DATABASE_URL', 'STRIPE_KEY', 'JWT_SECRET'].map((key) => ({
        actorType: 'service' as const,
        actorId: 'ci.access',
        action: 'secret.read',
        decision: 'allow' as const,
        bundleId,
        metadata: { key },
      })),
    ),
  );

  const rows = await inTransaction((tx) => readAuditRows(tx));

  // "They read the whole environment" is a useless answer to "who read which
  // secret". One row per secret is what makes the log answer the question.
  assert.equal(rows.length, 3);
  assert.ok(rows.every((r) => r.bundleId === bundleId));
  assert.deepEqual(
    rows.map((r) => JSON.parse(r.metadata).key),
    ['DATABASE_URL', 'STRIPE_KEY', 'JWT_SECRET'],
  );
  assert.equal(verifyChain(CHAIN_KEY, rows, GENESIS_HASH).ok, true);
});

test('tampering with a stored row is detected on read', async () => {
  await inTransaction((tx) =>
    appendAudit(tx, CHAIN_KEY, [
      { actorType: 'user', actorId: 'erwin@equisafe.io', action: 'secret.read', decision: 'allow' },
      { actorType: 'user', actorId: 'erwin@equisafe.io', action: 'secret.read', decision: 'deny' },
    ]),
  );

  // As the owner role -- coffre_app cannot do this at all, which is checked in
  // schema-guarantees.sql. This simulates someone with higher privilege
  // rewriting history directly in the database.
  await ownerPool.query("UPDATE audit_log SET decision = 'allow' WHERE seq = 1");

  const rows = await inTransaction((tx) => readAuditRows(tx));
  const result = verifyChain(CHAIN_KEY, rows, GENESIS_HASH);

  assert.equal(result.ok, false);
  assert.equal(result.ok === false && result.failedAtSeq, 1n);
});

test('appendAudit refuses to write nothing', async () => {
  await assert.rejects(
    () => inTransaction((tx) => appendAudit(tx, CHAIN_KEY, [])),
    /no entries/,
  );
});
