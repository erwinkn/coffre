import test, { before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { GENESIS_HASH, sealEntry, verifyEntries, type LogFields } from '@coffre/core/audit';
import type { Database, Transaction } from '@coffre/db';
import { canonicalTimestamp } from '@coffre/db/dialect';
import { LogHeadMismatch, LogRewound } from '@coffre/db/log';
import { eq, gte, sql, type SQL } from 'drizzle-orm';

import { actorOf, actorParts, appendAudit, appLogKey } from '../../src/db/audit.ts';
import { auditHead, auditRange } from '../../src/db/queries.ts';
import { emptyLog, openTestDatabase, postgresOnly, TEST_ENGINE, withLogUnlocked } from './engine.ts';
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

test('an append refuses a log that lost the last batch this process committed', async () => {
  const entry = { actorType: 'user' as const, actorId: 'a@acme.example', action: 'secret.read', decision: 'allow' as const };
  await inTransaction((tx) => appendAudit(tx, CHAIN_KEY, [entry]));
  const [first] = await inTransaction((tx) => auditRange(tx));
  await inTransaction((tx) => appendAudit(tx, CHAIN_KEY, Array.from({ length: 12 }, () => entry)));
  // The whole of the newest batch cut, and the head put back on the entry before it.
  await withLogUnlocked(owner, (owned) => owned.delete(auditLog).where(gte(auditLog.seq, 1n)));
  await owner.update(auditChainHead).set({ nextSeq: 1n, headHash: first.hash });

  await assert.rejects(inTransaction((tx) => appendAudit(tx, CHAIN_KEY, [entry])), (error) => error instanceof LogRewound);
});

test('a transaction that rolls back leaves nothing for the process to remember', async () => {
  const entry = { actorType: 'user' as const, actorId: 'a@acme.example', action: 'secret.read', decision: 'allow' as const };
  // The second append sees the first's head, which never commits.
  await assert.rejects(
    inTransaction(async (tx) => {
      await appendAudit(tx, CHAIN_KEY, [entry]);
      await appendAudit(tx, CHAIN_KEY, [entry]);
      throw new Error('rolled back');
    }),
    /rolled back/,
  );
  await inTransaction((tx) => appendAudit(tx, CHAIN_KEY, [entry]));
  assert.deepEqual((await inTransaction((tx) => auditRange(tx))).map((row) => row.seq), [0n]);
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

test('64-bit sequences, related entries and the head round-trip above 2^53', async () => {
  const key = appLogKey(CHAIN_KEY);
  const seq = 9007199254740993n;
  const fields: LogFields = {
    seq, author: key.author, keyId: key.keyId, occurredAt: 1_790_841_600_000,
    actor: 'system:test', action: 'test', decision: 'allow', code: null,
    subjectPrincipal: null, projectId: null, environmentId: null, secretId: null,
    secretVersionId: null, operationId: null, requestId: null, sourceIp: null,
    relatedSeq: null, metadata: '{}',
  };
  const first = { ...fields, prevHash: GENESIS_HASH, ...sealEntry(key, GENESIS_HASH, fields) };
  const following = { ...fields, seq: seq + 1n, relatedSeq: seq };
  const second = { ...following, prevHash: first.hash, ...sealEntry(key, first.hash, following) };
  try {
    await inTransaction(async (tx) => {
      await tx.insert(auditLog).values([first, second]);
      await tx.update(auditChainHead).set({ nextSeq: seq + 2n, headHash: second.hash });
      assert.deepEqual((await auditRange(tx, seq)).map((row) => [row.seq, row.relatedSeq]), [[seq, null], [seq + 1n, seq]]);
      assert.equal((await auditHead(tx))?.nextSeq, seq + 2n);
    });
    const rows = await auditRange(db, seq);
    assert.equal(verifyEntries(rows, { startSeq: seq, keys: [key] }).ok, true);
    assert.deepEqual(rows.map((row) => [row.seq, row.relatedSeq]), [[seq, null], [seq + 1n, seq]]);
    assert.equal((await auditHead(db))?.nextSeq, seq + 2n);
  } finally {
    // RESTRICT checks each deletion, so remove the referencing entry first.
    await withLogUnlocked(owner, async (owned) => {
      await owned.delete(auditLog).where(eq(auditLog.seq, seq + 1n));
      await owned.delete(auditLog).where(eq(auditLog.seq, seq));
    });
  }
});

test('SQLite refuses replacing an audit entry through INSERT OR REPLACE', { skip: TEST_ENGINE !== 'sqlite' }, async () => {
  await inTransaction((tx) => appendAudit(tx, CHAIN_KEY, [
    { actorType: 'system', actorId: 'test', action: 'test', decision: 'allow' },
  ]));
  const sqlite = db as unknown as { run(query: SQL): Promise<unknown> };
  await assert.rejects(sqlite.run(sql`INSERT OR REPLACE INTO audit_log
    (seq, author, key_id, occurred_at, actor, action, decision, prev_hash, mac, hash)
    SELECT seq, author, key_id, occurred_at, actor, 'rewritten', decision, prev_hash, mac, hash FROM audit_log`),
  (error: unknown) => /append-only/.test(`${error} ${(error as { cause?: unknown }).cause}`));
  assert.equal((await auditRange(db))[0].action, 'test');
});
