import { after, beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';

import { LogHeadMismatch } from '@coffre/db/log';
import { eq } from 'drizzle-orm';

import { appendAudit, type AuditEntry } from '../src/db/audit.ts';
import { withLogUnlocked } from './db/engine.ts';
import { auditChainHead, auditLog } from './db/tables.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps } from './api-fixture.ts';

const db = await openTestDatabase();
const deps = testDeps(db.runtime, ['root@acme.example']);
const root = clientFor(deps, 'root@acme.example');
beforeEach(() => resetDatabase(db.owner));
after(async () => {
  await resetDatabase(db.owner);
  await db.close();
});

const entry: AuditEntry = { actorType: 'system', actorId: 'test', action: 'test', decision: 'allow' };

for (const preceding of [0, 5_000]) {
  test(`the runtime login moving the head forward stops the next append, after ${preceding} entries`, async () => {
    await write(preceding);
    // Review F4: a gap made by moving the head, which an honest append then
    // filled in after. The append checks that the head names the last entry.
    await db.runtime.update(auditChainHead).set({ nextSeq: BigInt(preceding + 5) });
    await assert.rejects(
      db.runtime.transaction((tx) => appendAudit(tx, deps.chainKey, [entry])),
      (error) => error instanceof LogHeadMismatch,
    );
  });

  test(`audit verification rejects a sequence gap after ${preceding} entries`, async () => {
    await write(preceding + 2);
    // An entry deleted by the owner, at the first entry of a verification
    // batch: the check carries the expected number across batches.
    await withLogUnlocked(db.owner, (owner) => owner.delete(auditLog).where(eq(auditLog.seq, BigInt(preceding))));

    assert.deepEqual(await root.audit.verify(), {
      ok: false,
      log: 'audit',
      failedAtSeq: preceding + 1,
      reason: `sequence gap: expected seq ${preceding}, found ${preceding + 1}`,
    });
  });
}

async function write(entries: number): Promise<void> {
  // Keep each insert below the database's parameter limit.
  for (let written = 0; written < entries; written += 500) {
    const batch = Math.min(500, entries - written);
    await db.runtime.transaction((tx) => appendAudit(tx, deps.chainKey, Array.from({ length: batch }, () => entry)));
  }
}
