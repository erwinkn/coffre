import test, { before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { sql } from 'drizzle-orm';
import pg from 'pg';

import { appendAudit } from '../src/audit.ts';
import { createDatabase, type Database, type Transaction } from '../src/database.ts';
import { canonicalTimestamp } from '../src/dialect.ts';
import { auditRange } from '../src/queries.ts';
import { verifyChain, GENESIS_HASH } from '../../core/src/audit/chain.ts';
import {
  TEST_OWNER_DATABASE_URL,
  TEST_RUNTIME_DATABASE_URL,
} from './connections.ts';

const CHAIN_KEY = randomBytes(32);

let ownerPool: pg.Pool;
let runtimePool: pg.Pool;
let db: Database;

before(async () => {
  ownerPool = new pg.Pool({ connectionString: TEST_OWNER_DATABASE_URL });
  runtimePool = new pg.Pool({ connectionString: TEST_RUNTIME_DATABASE_URL });
  db = createDatabase(runtimePool);
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

function inTransaction<T>(fn: (tx: Transaction) => Promise<T>): Promise<T> {
  return db.transaction(fn);
}

test('appended rows verify as a chain when read back from the database', async () => {
  await inTransaction((tx) =>
    appendAudit(tx, CHAIN_KEY, [
      { actorType: 'user', actorId: 'admin@acme.example', action: 'secret.read', decision: 'allow' },
      { actorType: 'service', actorId: 'ci.access', action: 'secret.read', decision: 'allow' },
      { actorType: 'user', actorId: 'admin@acme.example', action: 'secret.read', decision: 'deny' },
    ]),
  );

  const rows = await inTransaction((tx) => auditRange(tx));
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
      { actorType: 'user', actorId: 'a@acme.example', action: 'secret.read', decision: 'allow' },
    ]),
  );
  await inTransaction((tx) =>
    appendAudit(tx, CHAIN_KEY, [
      { actorType: 'user', actorId: 'b@acme.example', action: 'secret.read', decision: 'allow' },
    ]),
  );

  const rows = await inTransaction((tx) => auditRange(tx));
  assert.equal(rows.length, 2);
  assert.equal(verifyChain(CHAIN_KEY, rows, GENESIS_HASH).ok, true);
});

test('a rolled-back transaction leaves no gap in the sequence', async () => {
  await inTransaction((tx) =>
    appendAudit(tx, CHAIN_KEY, [
      { actorType: 'user', actorId: 'a@acme.example', action: 'secret.read', decision: 'allow' },
    ]),
  );

  // A read that fails after its audit row was written must leave nothing
  // behind. If seq came from a bigserial, this would burn seq 1 and the gap
  // would be indistinguishable from a deleted row.
  await assert.rejects(
    inTransaction(async (tx) => {
      await appendAudit(tx, CHAIN_KEY, [
        { actorType: 'user', actorId: 'b@acme.example', action: 'secret.read', decision: 'allow' },
      ]);
      throw new Error('simulated failure after the audit write');
    }),
  );

  await inTransaction((tx) =>
    appendAudit(tx, CHAIN_KEY, [
      { actorType: 'user', actorId: 'c@acme.example', action: 'secret.read', decision: 'allow' },
    ]),
  );

  const rows = await inTransaction((tx) => auditRange(tx));
  assert.deepEqual(
    rows.map((r) => r.seq),
    [0n, 1n],
    'sequence must be contiguous, so any gap means tampering',
  );
  assert.deepEqual(
    rows.map((r) => r.actorId),
    ['a@acme.example', 'c@acme.example'],
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

  const rows = await inTransaction((tx) => auditRange(tx));

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
      { actorType: 'user', actorId: 'admin@acme.example', action: 'secret.read', decision: 'allow' },
      { actorType: 'user', actorId: 'admin@acme.example', action: 'secret.read', decision: 'deny' },
    ]),
  );

  // As the owner role -- coffre_app cannot do this at all, which is checked in
  // schema-guarantees.sql. This simulates someone with higher privilege
  // rewriting history directly in the database.
  await ownerPool.query("UPDATE audit_log SET decision = 'allow' WHERE seq = 1");

  const rows = await inTransaction((tx) => auditRange(tx));
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

test('timestamps render as UTC with microseconds, whatever shape the database returns', () => {
  assert.equal(canonicalTimestamp('2026-09-27 12:34:56.123456+00'), '2026-09-27T12:34:56.123456Z');
  assert.equal(canonicalTimestamp('2026-09-27 12:34:56.1+02'), '2026-09-27T10:34:56.100000Z');
  assert.equal(canonicalTimestamp('2026-09-27 00:10:00-05:30'), '2026-09-27T05:40:00.000000Z');
  assert.equal(canonicalTimestamp('2026-09-27T12:34:56.123456Z'), '2026-09-27T12:34:56.123456Z');
  assert.throws(() => canonicalTimestamp('yesterday'), /unexpected timestamp/);
});

test('a session in another time zone reads back the same chain', async () => {
  await inTransaction((tx) =>
    appendAudit(tx, CHAIN_KEY, [
      { actorType: 'user', actorId: 'a@acme.example', action: 'secret.read', decision: 'allow' },
    ]),
  );
  const rows = await inTransaction(async (tx) => {
    await tx.execute(sql`SET LOCAL TIME ZONE 'Asia/Kolkata'`);
    return auditRange(tx);
  });
  assert.match(rows[0].occurredAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/);
  assert.equal(verifyChain(CHAIN_KEY, rows, GENESIS_HASH).ok, true);
});
