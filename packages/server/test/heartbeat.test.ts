import { after, beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';

import { verifyCheckpoint, type Vault } from '@coffre/core/vault';
import { createDatabase } from '@coffre/db';
import { asc, desc, eq } from 'drizzle-orm';

import { appendAudit } from '../src/db/audit.ts';
import { latestCheckpoint } from '../src/db/queries.ts';
import { auditReadiness, HEARTBEAT_STALE_AFTER_SECONDS, writeAuditHeartbeat } from '../src/heartbeat.ts';
import { openTestDatabase, resetDatabase, testVault } from './api-fixture.ts';
import { auditLog } from './db/tables.ts';
import { withLogUnlocked } from './db/engine.ts';

const db = await openTestDatabase();
const vault = testVault(['root@example.com']);
const chainKey = Buffer.alloc(32, 1);
after(() => db.close());
beforeEach(() => resetDatabase(db.owner));

const quiet = { warn: () => assert.fail('successful heartbeat must not warn') };

function entries() {
  return db.owner.select().from(auditLog).orderBy(asc(auditLog.seq));
}

/** Moves the newest beat `seconds` into the past. Readiness reads its date, not its chain. */
async function beatAgo(seconds: number) {
  const [beat] = await db.owner
    .select({ seq: auditLog.seq })
    .from(auditLog)
    .where(eq(auditLog.action, 'audit.heartbeat'))
    .orderBy(desc(auditLog.seq))
    .limit(1);
  await withLogUnlocked(db.owner, (owner) =>
    owner.update(auditLog).set({ occurredAt: Date.now() - seconds * 1000 }).where(eq(auditLog.seq, beat.seq)),
  );
}

test('a beat is an app entry, and the vault checkpoints it in an entry of its own', async () => {
  assert.equal(await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet), true);

  const logged = await entries();
  assert.deepEqual(logged.map((row) => [row.author, row.actor, row.action]), [
    ['app', 'system:coffre-scheduler', 'audit.heartbeat'],
    ['vault', 'system:coffre-scheduler', 'audit.checkpoint'],
  ]);
  // The checkpoint signs everything before it: here, the beat.
  const [checkpoint, { checkpointKeys }] = await Promise.all([latestCheckpoint(db.owner), vault.about()]);
  const { publicKey } = checkpointKeys[checkpoint!.keyId]!;
  assert.equal(checkpoint?.seq, 0);
  assert.equal(checkpoint?.hash, logged[0].hash.toString('hex'));
  assert.deepEqual(JSON.parse(logged[1].metadata), checkpoint);
  assert.equal(await verifyCheckpoint(checkpoint!, publicKey), true);

  const ready = await auditReadiness(db.runtime, vault);
  assert.equal(ready.ok, true);
  assert.equal(ready.checkpointed, true);
  assert.ok(ready.heartbeatAgeSeconds! < 60);
});

test('each checkpoint extends the last, and nothing new signs nothing new', async () => {
  await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);
  await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);
  // Beat, checkpoint, beat, checkpoint: the second covers the first and the second beat.
  assert.equal((await latestCheckpoint(db.owner))?.seq, 2);

  const again = await vault.checkpoint();
  assert.ok(again.ok);
  assert.equal(again.checkpoint.seq, 2);
  assert.equal((await entries()).length, 4);
});

test('a rewritten entry is never signed over, and readiness goes red', async () => {
  await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);
  await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);
  // Someone with the database rewrites the beat the last checkpoint signed.
  await withLogUnlocked(db.owner, (owner) => owner.update(auditLog).set({ hash: Buffer.alloc(32, 9) }).where(eq(auditLog.seq, 2n)));

  let warned: unknown = null;
  const written = await writeAuditHeartbeat(db.runtime, chainKey, vault, {
    warn: (value: unknown) => {
      warned = value;
    },
  });
  assert.equal(written, false);
  assert.deepEqual(warned, { code: 'log_broken' });
  assert.equal((await latestCheckpoint(db.owner))?.seq, 2);
  // The refusal is in the log too.
  const [refused] = (await entries()).filter((row) => row.decision === 'deny');
  assert.equal(refused.action, 'audit.checkpoint');
  assert.equal(refused.code, 'log_broken');

  const ready = await auditReadiness(db.runtime, vault);
  assert.equal(ready.ok, false);
  assert.equal(ready.checkpointed, false);
});

test('a beat the vault did not checkpoint leaves readiness red', async (t) => {
  t.mock.method(vault, 'checkpoint', async () => {
    throw new Error('the vault is down');
  });
  let warning = '';
  const written = await writeAuditHeartbeat(db.runtime, chainKey, vault, {
    warn: (_value: unknown, message: string) => {
      warning = message;
    },
  });
  assert.equal(written, false);
  assert.equal(warning, 'audit checkpoint failed');
  assert.deepEqual((await entries()).map((row) => row.action), ['audit.heartbeat']);
  const ready = await auditReadiness(db.runtime, vault);
  assert.equal(ready.ok, false);
  assert.equal(ready.checkpointed, false);
});

test('readiness trusts only a checkpoint the vault signed', async () => {
  await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);
  assert.equal((await auditReadiness(db.runtime, vault)).ok, true);
  // A checkpoint entry with another signature, as anyone who can write the database could make.
  const [, signed] = await entries();
  const forged = { ...JSON.parse(signed.metadata), signature: Buffer.alloc(64, 7).toString('base64') };
  await withLogUnlocked(db.owner, (owner) =>
    owner.update(auditLog).set({ metadata: JSON.stringify(forged) }).where(eq(auditLog.seq, signed.seq)),
  );
  const ready = await auditReadiness(db.runtime, vault);
  assert.equal(ready.ok, false);
  assert.equal(ready.checkpointed, false);
});

test('readiness counts a checkpoint under a key the vault replaced only over a prefix before the rotation', async () => {
  await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);
  const checkpoint = (await latestCheckpoint(db.owner))!;
  const { publicKey } = (await vault.about()).checkpointKeys[checkpoint.keyId]!;
  // The vault as after a rotation at entry `until`: the key that signed this checkpoint is one it replaced.
  const rotatedAt = (until: number) =>
    ({ about: async () => ({ checkpointKeys: { [checkpoint.keyId]: { publicKey, until } }, rootAdmins: [] }) }) as unknown as Vault;
  assert.equal((await auditReadiness(db.runtime, rotatedAt(checkpoint.seq + 1))).ok, true);
  assert.equal((await auditReadiness(db.runtime, rotatedAt(checkpoint.seq))).checkpointed, false);
});

test('an empty log has nothing to checkpoint, and logs nothing for it', async () => {
  const refused = await vault.checkpoint();
  assert.ok(!refused.ok);
  assert.equal(refused.refusal.code, 'invalid');
  assert.deepEqual(await entries(), []);
  assert.equal(await latestCheckpoint(db.owner), null);
  assert.deepEqual(await auditReadiness(db.runtime, vault), { ok: false, heartbeatAgeSeconds: null, checkpointed: false });
});

test('readiness accepts a recent beat and rejects a stale one', async () => {
  await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);
  await beatAgo(12);
  const recent = await auditReadiness(db.runtime, vault);
  assert.equal(recent.ok, true);
  assert.ok(Math.abs(recent.heartbeatAgeSeconds! - 12) < 5);

  // A Cron run that fires a few seconds late is not a logging failure.
  await beatAgo(307);
  assert.equal((await auditReadiness(db.runtime, vault)).ok, true);

  await beatAgo(HEARTBEAT_STALE_AFTER_SECONDS + 60);
  const stale = await auditReadiness(db.runtime, vault);
  assert.equal(stale.ok, false);
  assert.equal(stale.checkpointed, true);
  assert.ok(stale.heartbeatAgeSeconds! > HEARTBEAT_STALE_AFTER_SECONDS);
});

test('a checkpoint before the newest beat does not cover it', async () => {
  await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);
  await db.runtime.transaction((tx) =>
    appendAudit(tx, chainKey, [{ actorType: 'system', actorId: 'coffre-scheduler', action: 'audit.heartbeat', decision: 'allow' }]),
  );
  const ready = await auditReadiness(db.runtime, vault);
  assert.equal(ready.ok, false);
  assert.equal(ready.checkpointed, false);
});

test('readiness rejects a database without the expected Drizzle schema prefix', async () => {
  // The migrations count, in Drizzle's array row mode: none applied.
  const query = async () => ({ rows: [[0]], fields: [] });
  const empty = createDatabase({ query, connect: async () => ({ query, release: () => {} }) } as never);
  assert.deepEqual(await auditReadiness(empty, vault), { ok: false, heartbeatAgeSeconds: null, checkpointed: false });
});
