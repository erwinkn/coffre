import { after, beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';

import { sql } from 'drizzle-orm';

import { createDatabase } from '../../../packages/db/src/database.ts';
import { auditChainHead, auditHeartbeat, auditLog } from '../../../packages/db/src/schema.ts';
import {
  auditReadiness,
  HEARTBEAT_STALE_AFTER_SECONDS,
  writeAuditHeartbeat,
} from '../src/server/heartbeat.ts';
import { openTestDatabase, resetDatabase } from './api-fixture.ts';

const db = openTestDatabase();
after(() => db.close());
beforeEach(() => resetDatabase(db.owner));

const quiet = { warn: () => assert.fail('successful heartbeat must not warn') };

/** Moves the last beat `seconds` into the past, by the database's clock. */
async function beatAgo(seconds: number) {
  await db.owner
    .update(auditHeartbeat)
    .set({ lastBeatAt: sql`CURRENT_TIMESTAMP - make_interval(secs => ${seconds})` });
}

test('the scheduled heartbeat updates the database-owned signal', async () => {
  await beatAgo(600);
  assert.equal(await writeAuditHeartbeat(db.runtime, Buffer.alloc(32, 1), quiet), true);

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
});

test('the scheduled heartbeat rejects a missing singleton row', async () => {
  await db.owner.delete(auditHeartbeat);
  try {
    let warning = '';
    const written = await writeAuditHeartbeat(db.runtime, Buffer.alloc(32, 1), {
      warn: (_value, message) => {
        warning = message;
      },
    });
    assert.equal(written, false);
    assert.equal(warning, 'audit heartbeat singleton is missing');
    assert.deepEqual(await db.owner.select().from(auditLog), []);
  } finally {
    await db.owner.insert(auditHeartbeat).values({}).onConflictDoNothing();
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
