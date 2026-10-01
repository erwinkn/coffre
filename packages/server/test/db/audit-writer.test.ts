import test, { before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { verifyEntries } from '@coffre/core/audit';
import type { Database, Transaction } from '@coffre/db';
import { canonicalTimestamp } from '@coffre/db/dialect';
import { LogHeadMismatch, LogRewound } from '@coffre/db/log';
import { eq, gte, sql } from 'drizzle-orm';

import { actorOf, actorParts, appendAudit, appLogKey } from '../../src/db/audit.ts';
import { auditRange } from '../../src/db/queries.ts';
import { emptyLog, openTestDatabase, postgresOnly, withLogUnlocked } from './engine.ts';
import { auditChainHead, auditLog } from './tables.ts';

const CHAIN_KEY = randomBytes(32);
const KEYS = { keys: [appLogKey(CHAIN_KEY)] };

let owner: Database;
let db: Database;
let close: () => Promise<void>;

before(async () => {
  ({ owner, runtime: db, close } = await openTestDatabase());
});

after(() => close());

beforeEach(() => emptyLog(owner));

function inTransaction<T>(fn: (tx: Transaction) => Promise<T>): Promise<T> {
  return db.transaction(fn);
}

test('appended entries verify as a chain when read back from the database', async () => {
  await inTransaction((tx) =>
    appendAudit(tx, CHAIN_KEY, [
      { actorType: 'user', actorId: 'admin@acme.example', action: 'secret.read', decision: 'allow' },
      { actorType: 'service', actorId: 'ci.access', action: 'secret.read', decision: 'allow' },
      { actorType: 'user', actorId: 'admin@acme.example', action: 'secret.read', decision: 'deny' },
    ]),
  );

  const rows = await inTransaction((tx) => auditRange(tx));
  assert.equal(rows.length, 3);
  assert.deepEqual(rows.map((row) => [row.author, row.actor]), [
    ['app', 'user:admin@acme.example'],
    ['app', 'token:ci.access'],
    ['app', 'user:admin@acme.example'],
  ]);

  // The important property: the MAC and hash computed at write time still
  // verify after a round trip through the database. If the time or the
  // metadata came back in another shape, this fails.
  const result = verifyEntries(rows, KEYS);
  assert.equal(result.ok, true, result.ok ? '' : result.reason);
  assert.equal(result.ok && result.authenticated, 3);
});

test('the chain continues correctly across separate transactions', async () => {
  for (const id of ['a@acme.example', 'b@acme.example']) {
    await inTransaction((tx) =>
      appendAudit(tx, CHAIN_KEY, [{ actorType: 'user', actorId: id, action: 'secret.read', decision: 'allow' }]),
    );
  }

  const rows = await inTransaction((tx) => auditRange(tx));
  assert.equal(rows.length, 2);
  assert.equal(verifyEntries(rows, KEYS).ok, true);
});

test('a rolled-back transaction leaves no gap in the sequence', async () => {
  await inTransaction((tx) =>
    appendAudit(tx, CHAIN_KEY, [
      { actorType: 'user', actorId: 'a@acme.example', action: 'secret.read', decision: 'allow' },
    ]),
  );

  // A read that fails after its entry was written must leave nothing behind.
  // If seq came from a bigserial, this would burn seq 1 and the gap would be
  // indistinguishable from a deleted entry.
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
  assert.deepEqual(rows.map((r) => r.seq), [0n, 1n], 'sequence must be contiguous, so any gap means tampering');
  assert.deepEqual(rows.map((r) => r.actor), ['user:a@acme.example', 'user:c@acme.example']);
  assert.equal(verifyEntries(rows, KEYS).ok, true);
});

test('a bulk read writes one entry per secret, sharing an operation id', async () => {
  const operationId = '99999999-9999-4999-8999-999999999999';

  await inTransaction((tx) =>
    appendAudit(
      tx,
      CHAIN_KEY,
      ['DATABASE_URL', 'STRIPE_KEY', 'JWT_SECRET'].map((key) => ({
        actorType: 'service' as const,
        actorId: 'ci.access',
        action: 'secret.read',
        decision: 'allow' as const,
        bundleId: operationId,
        metadata: { key },
      })),
    ),
  );

  const rows = await inTransaction((tx) => auditRange(tx));

  // "They read the whole environment" is a useless answer to "who read which
  // secret". One entry per secret is what makes the log answer the question.
  assert.equal(rows.length, 3);
  assert.ok(rows.every((r) => r.operationId === operationId));
  assert.deepEqual(rows.map((r) => JSON.parse(r.metadata).key), ['DATABASE_URL', 'STRIPE_KEY', 'JWT_SECRET']);
  assert.equal(verifyEntries(rows, KEYS).ok, true);
});

test('an entry changed in the database is caught on read', async () => {
  await inTransaction((tx) =>
    appendAudit(tx, CHAIN_KEY, [
      { actorType: 'user', actorId: 'admin@acme.example', action: 'secret.read', decision: 'allow' },
      { actorType: 'user', actorId: 'admin@acme.example', action: 'secret.read', decision: 'deny' },
    ]),
  );

  // As the owner, with the append-only triggers lifted: the runtime login
  // cannot do this at all, which schema-guarantees.sql checks.
  await withLogUnlocked(owner, (owned) => owned.update(auditLog).set({ decision: 'allow' }).where(eq(auditLog.seq, 1n)));

  const result = verifyEntries(await inTransaction((tx) => auditRange(tx)), KEYS);
  assert.deepEqual(result.ok ? null : [result.failedAtSeq, result.reason], [1n, 'hash does not match the entry']);
});

test('the log refuses changes and deletions, from its owner too', async () => {
  await inTransaction((tx) =>
    appendAudit(tx, CHAIN_KEY, [{ actorType: 'user', actorId: 'a@acme.example', action: 'secret.read', decision: 'allow' }]),
  );
  const appendOnly = (error: unknown) => /append-only/.test(`${error} ${(error as { cause?: unknown }).cause}`);
  await assert.rejects(owner.update(auditLog).set({ decision: 'deny' }), appendOnly);
  await assert.rejects(owner.delete(auditLog), appendOnly);
});

test('an append refuses when the head does not name the last entry', async () => {
  await inTransaction((tx) =>
    appendAudit(tx, CHAIN_KEY, [{ actorType: 'user', actorId: 'a@acme.example', action: 'secret.read', decision: 'allow' }]),
  );
  // The newest entry deleted, the head left where it was.
  await withLogUnlocked(owner, (owned) => owned.delete(auditLog).where(eq(auditLog.seq, 0n)));

  await assert.rejects(
    inTransaction((tx) =>
      appendAudit(tx, CHAIN_KEY, [{ actorType: 'user', actorId: 'b@acme.example', action: 'secret.read', decision: 'allow' }]),
    ),
    (error) => error instanceof LogHeadMismatch,
  );
});

test('an append refuses a log rolled back behind a head this process found', async () => {
  // The process remembers the head it found, committed, under each append's
  // lock: after these three, the head before the third.
  for (const id of ['a@acme.example', 'b@acme.example', 'c@acme.example']) {
    await inTransaction((tx) =>
      appendAudit(tx, CHAIN_KEY, [{ actorType: 'user', actorId: id, action: 'secret.read', decision: 'allow' }]),
    );
  }
  // Cut the newest entry and put the head back, as a restore would: the head
  // names the last entry again, so only this process's memory can tell.
  const [first] = await inTransaction((tx) => auditRange(tx));
  await withLogUnlocked(owner, (owned) => owned.delete(auditLog).where(gte(auditLog.seq, 1n)));
  await owner.update(auditChainHead).set({ nextSeq: 1n, headHash: first.hash });

  await assert.rejects(
    inTransaction((tx) =>
      appendAudit(tx, CHAIN_KEY, [{ actorType: 'user', actorId: 'd@acme.example', action: 'secret.read', decision: 'allow' }]),
    ),
    (error) => error instanceof LogRewound,
  );
});

test('appendAudit refuses to write nothing', async () => {
  await assert.rejects(() => inTransaction((tx) => appendAudit(tx, CHAIN_KEY, [])), /no entries/);
});

test('actors read back as the API shows them', () => {
  for (const [type, id] of [['user', 'ada@acme.example'], ['service', 'ci-deploy'], ['system', 'coffre-scheduler'], ['system', 'sync:7f3c']] as const) {
    assert.deepEqual(actorParts(actorOf(type, id)), { actorType: type, actorId: id });
  }
  assert.equal(actorOf('system', 'sync:7f3c'), 'sync:7f3c');
});

test('timestamps read as text render as UTC with microseconds, whatever shape the database returns', () => {
  assert.equal(canonicalTimestamp('2026-09-27 12:34:56.123456+00'), '2026-09-27T12:34:56.123456Z');
  assert.equal(canonicalTimestamp('2026-09-27 12:34:56.1+02'), '2026-09-27T10:34:56.100000Z');
  assert.equal(canonicalTimestamp('2026-09-27 00:10:00-05:30'), '2026-09-27T05:40:00.000000Z');
  assert.equal(canonicalTimestamp('2026-09-27T12:34:56.123456Z'), '2026-09-27T12:34:56.123456Z');
  assert.throws(() => canonicalTimestamp('yesterday'), /unexpected timestamp/);
});

test(
  'a session in another time zone reads back the same chain',
  postgresOnly('the session time zone is a Postgres setting'),
  async () => {
    await inTransaction((tx) =>
      appendAudit(tx, CHAIN_KEY, [
        { actorType: 'user', actorId: 'a@acme.example', action: 'secret.read', decision: 'allow' },
      ]),
    );
    const rows = await inTransaction(async (tx) => {
      await tx.execute(sql`SET LOCAL TIME ZONE 'Asia/Kolkata'`);
      return auditRange(tx);
    });
    assert.equal(typeof rows[0].occurredAt, 'number');
    assert.equal(verifyEntries(rows, KEYS).ok, true);
  },
);

test('concurrent appends queue on the chain head and form one linear chain', async () => {
  // Each append is its own transaction, as each request's is. They all want
  // the head at once; the lock (a queue of one on SQLite) lets them through
  // in turn, so every entry links to the one before it.
  await Promise.all(
    Array.from({ length: 24 }, (_, index) =>
      inTransaction((tx) =>
        appendAudit(tx, CHAIN_KEY, [
          { actorType: 'user', actorId: `user${index}@acme.example`, action: 'secret.read', decision: 'allow' },
        ]),
      ),
    ),
  );

  const rows = await inTransaction((tx) => auditRange(tx));
  assert.deepEqual(rows.map((r) => r.seq), Array.from({ length: 24 }, (_, index) => BigInt(index)));
  assert.equal(new Set(rows.map((r) => r.actor)).size, 24);
  assert.equal(verifyEntries(rows, KEYS).ok, true);
  // Each entry's time was read after its append took the lock, so time
  // never runs backwards along the chain.
  assert.ok(rows.every((row, i) => i === 0 || row.occurredAt >= rows[i - 1].occurredAt));
});
