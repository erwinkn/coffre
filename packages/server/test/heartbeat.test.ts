import { after, beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';

import { createDatabase } from '@coffre/db';
import { asc, eq } from 'drizzle-orm';

import { heartbeat } from '../src/db/queries.ts';
import { auditChainHead, auditHeartbeat, auditLog } from './db/tables.ts';
import {
  auditReadiness,
  checkpointAudit,
  HEARTBEAT_STALE_AFTER_SECONDS,
  vaultBehind,
  writeAuditHeartbeat,
} from '../src/heartbeat.ts';
import { openTestDatabase, resetDatabase, testVault } from './api-fixture.ts';
import { withLogUnlocked } from './db/engine.ts';

const db = await openTestDatabase();
const vault = testVault(['root@example.com']);
after(() => db.close());
beforeEach(() => resetDatabase(db.owner));

const quiet = { warn: () => assert.fail('successful heartbeat must not warn') };

/** Moves the last beat `seconds` into the past, by the database's clock. */
async function beatAgo(seconds: number) {
  const { now } = (await heartbeat(db.owner))!;
  await db.owner.update(auditHeartbeat).set({ lastBeatAt: new Date(Date.parse(now) - seconds * 1000) });
}

test('the scheduled heartbeat updates the database-owned signal', async () => {
  await beatAgo(600);
  assert.equal(await writeAuditHeartbeat(db.runtime, Buffer.alloc(32, 1), vault, quiet), true);

  const logged = await db.owner.select().from(auditLog).orderBy(asc(auditLog.seq));
  assert.deepEqual(logged.map((row) => row.action), ['audit.heartbeat', 'audit.checkpoint']);
  assert.ok(logged.every((row) => row.actor === 'system:coffre-scheduler'));
  const [beat] = await db.owner.select().from(auditHeartbeat);
  assert.equal(beat.lastSeq, 1n);
  assert.ok(Date.now() - beat.lastBeatAt.getTime() < 60_000);

  // The vault signed the head the beat left, with its own log's (empty),
  // and the app recorded what it signed.
  const { checkpoint } = await vault.latestCheckpoint();
  assert.equal(checkpoint?.seq, 0);
  assert.equal(checkpoint?.headHash, logged[0].hash.toString('hex'));
  assert.deepEqual(checkpoint?.vault, { seq: 0, hash: '0'.repeat(64) });
  assert.deepEqual(JSON.parse(logged[1].metadata), checkpoint);
  const [head] = await db.owner.select().from(auditChainHead);
  assert.equal(head.nextSeq, 2n);
  assert.deepEqual(head.headHash, logged[1].hash);
});

test('each beat checkpoints a head that extends the last one, and never a rewritten one', async () => {
  const chainKey = Buffer.alloc(32, 1);
  await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);
  await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);
  // Beat, checkpoint recorded, beat: the second checkpoint covers the first's record.
  assert.equal((await vault.latestCheckpoint()).checkpoint?.seq, 2);

  // Someone with the database rewrites that row: the vault will not sign past it.
  await withLogUnlocked(db.owner, (owner) => owner.update(auditLog).set({ hash: Buffer.alloc(32, 9) }).where(eq(auditLog.seq, 2n)));
  let warned: unknown = null;
  const written = await writeAuditHeartbeat(db.runtime, chainKey, vault, {
    warn: (value: unknown) => {
      warned = value;
    },
  });
  assert.equal(written, false);
  assert.deepEqual(warned, { code: 'checkpoint_diverged' });
  assert.equal((await vault.latestCheckpoint()).checkpoint?.seq, 2);
});

test('a vault emptied behind the checkpoint the app recorded is not signed over', async () => {
  const chainKey = Buffer.alloc(32, 1);
  await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);

  // Its store starts over, checkpoints and all: the app's record says it had one.
  await vault.reset();
  let warning = '';
  const written = await writeAuditHeartbeat(db.runtime, chainKey, vault, {
    warn: (_value: unknown, message: string) => {
      warning = message;
    },
  });
  assert.equal(written, false);
  assert.match(warning, /^the vault has no checkpoint, but the audit log recorded one at seq 0/);
  assert.equal((await vault.latestCheckpoint()).checkpoint, null);
});

test('a refused checkpoint leaves readiness stale', async () => {
  const chainKey = Buffer.alloc(32, 1);
  await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);
  await withLogUnlocked(db.owner, (owner) => owner.update(auditLog).set({ hash: Buffer.alloc(32, 9) }).where(eq(auditLog.seq, 0n)));
  await beatAgo(HEARTBEAT_STALE_AFTER_SECONDS + 60);
  const [before] = await db.owner.select().from(auditHeartbeat);
  assert.equal((await auditReadiness(db.runtime)).ok, false);

  assert.equal(await writeAuditHeartbeat(db.runtime, chainKey, vault, { warn() {} }), false);
  assert.equal((await auditReadiness(db.runtime)).ok, false);
  assert.deepEqual(await db.owner.select().from(auditHeartbeat), [before]);
});

test('a checkpoint whose audit entry rolls back leaves readiness stale', async (t) => {
  await beatAgo(HEARTBEAT_STALE_AFTER_SECONDS + 60);
  const [before] = await db.owner.select().from(auditHeartbeat);
  const transaction = db.runtime.transaction.bind(db.runtime);
  let calls = 0;
  t.mock.method(db.runtime, 'transaction', ((work, options) => transaction(async (tx) => {
    const call = ++calls;
    const result = await work(tx);
    if (call === 2) throw new Error('checkpoint commit failed');
    return result;
  }, options)) as typeof db.runtime.transaction);

  assert.equal(await writeAuditHeartbeat(db.runtime, Buffer.alloc(32, 1), vault, { warn() {} }), false);
  assert.notEqual((await vault.latestCheckpoint()).checkpoint, null);
  assert.deepEqual((await db.owner.select().from(auditLog)).map((row) => row.action), ['audit.heartbeat']);
  assert.equal((await auditReadiness(db.runtime)).ok, false);
  assert.deepEqual(await db.owner.select().from(auditHeartbeat), [before]);
});

test('a vault checkpoint behind the one recorded means its store went back', () => {
  const checkpoint = (seq: number, signature = `s${seq}`) => ({
    seq,
    headHash: 'a'.repeat(64),
    vault: { seq: 3, hash: 'b'.repeat(64) },
    signedAt: '2026-09-30T00:00:00.000Z',
    keyId: 'k',
    signature,
  });
  assert.equal(vaultBehind(null, null), null);
  assert.equal(vaultBehind(checkpoint(4), null), null);
  assert.equal(vaultBehind(checkpoint(4), checkpoint(4)), null);
  assert.equal(vaultBehind(checkpoint(6), checkpoint(4)), null);
  assert.match(vaultBehind(checkpoint(2), checkpoint(4))!, /put back to an older copy$/);
  assert.match(vaultBehind(checkpoint(4, 'other'), checkpoint(4))!, /put back to an older copy$/);
  assert.match(vaultBehind(null, checkpoint(4))!, /its store was emptied$/);
});

test('an empty log has nothing to checkpoint', async () => {
  assert.equal(await checkpointAudit(db.runtime, Buffer.alloc(32, 1), vault, quiet), true);
  assert.equal((await vault.latestCheckpoint()).checkpoint, null);
});

test('the scheduled heartbeat rejects a missing singleton row', async () => {
  await db.owner.delete(auditHeartbeat);
  try {
    let warning = '';
    const written = await writeAuditHeartbeat(db.runtime, Buffer.alloc(32, 1), vault, {
      warn: (_value: unknown, message: string) => {
        warning = message;
      },
    });
    assert.equal(written, false);
    assert.equal(warning, 'audit heartbeat singleton is missing');
    assert.deepEqual(await db.owner.select().from(auditLog), []);
  } finally {
    await db.owner.insert(auditHeartbeat).values({ onlyRow: true });
  }
});

test('readiness accepts a recent audit heartbeat and rejects a stale one', async () => {
  await beatAgo(12);
  const recent = await auditReadiness(db.runtime);
  assert.equal(recent.ok, true);
  assert.ok(Math.abs(recent.auditHeartbeatAgeSeconds! - 12) < 5);

  // A Cron run that fires a few seconds late is not a logging failure.
  await beatAgo(307);
  assert.equal((await auditReadiness(db.runtime)).ok, true);

  await beatAgo(HEARTBEAT_STALE_AFTER_SECONDS + 60);
  const stale = await auditReadiness(db.runtime);
  assert.equal(stale.ok, false);
  assert.ok(stale.auditHeartbeatAgeSeconds! > HEARTBEAT_STALE_AFTER_SECONDS);
});

test('readiness rejects a database without the expected Drizzle schema prefix', async () => {
  // The migrations count, in Drizzle's array row mode: none applied.
  const query = async () => ({ rows: [[0]], fields: [] });
  const empty = createDatabase({ query, connect: async () => ({ query, release: () => {} }) } as never);
  assert.deepEqual(await auditReadiness(empty), { ok: false, auditHeartbeatAgeSeconds: null });
});
