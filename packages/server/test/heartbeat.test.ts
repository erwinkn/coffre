import { after, beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';

import { eq } from 'drizzle-orm';

import { createDatabase } from '../../db/src/database.ts';
import { heartbeat } from '../../db/src/queries.ts';
import { auditChainHead, auditHeartbeat, auditLog } from '../../db/test/tables.ts';
import {
  auditReadiness,
  checkpointAudit,
  HEARTBEAT_STALE_AFTER_SECONDS,
  writeAuditHeartbeat,
} from '../src/heartbeat.ts';
import { openTestDatabase, resetDatabase, testVault } from './api-fixture.ts';

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

  const logged = await db.owner.select().from(auditLog);
  assert.equal(logged.length, 1);
  assert.equal(logged[0].action, 'audit.heartbeat');
  assert.equal(logged[0].actorId, 'coffre-scheduler');
  const [head] = await db.owner.select().from(auditChainHead);
  assert.equal(head.nextSeq, 1n);
  assert.deepEqual(head.headHash, logged[0].hash);
  const [beat] = await db.owner.select().from(auditHeartbeat);
  assert.equal(beat.lastSeq, head.nextSeq);
  assert.ok(Date.now() - beat.lastBeatAt.getTime() < 60_000);

  // And the vault signed the head it left.
  const { checkpoint } = await vault.latestCheckpoint();
  assert.equal(checkpoint?.seq, 0);
  assert.equal(checkpoint?.headHash, head.headHash.toString('hex'));
});

test('each beat checkpoints a head that extends the last one, and never a rewritten one', async () => {
  const chainKey = Buffer.alloc(32, 1);
  await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);
  await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);
  assert.equal((await vault.latestCheckpoint()).checkpoint?.seq, 1);

  // Someone with the database rewrites the first row: the vault will not sign past it.
  await db.owner.update(auditLog).set({ hash: Buffer.alloc(32, 9) }).where(eq(auditLog.seq, 1n));
  let warned: unknown = null;
  const written = await writeAuditHeartbeat(db.runtime, chainKey, vault, {
    warn: (value: unknown) => {
      warned = value;
    },
  });
  assert.equal(written, false);
  assert.deepEqual(warned, { code: 'checkpoint_diverged' });
  assert.equal((await vault.latestCheckpoint()).checkpoint?.seq, 1);
});

test('an empty log has nothing to checkpoint', async () => {
  assert.equal(await checkpointAudit(db.runtime, vault, quiet), true);
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
