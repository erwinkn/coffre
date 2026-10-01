import { after, beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';

import { appendAudit, type AuditEntry } from '../src/db/audit.ts';
import { auditChainHead } from './db/tables.ts';
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
  test(`audit verification rejects a sequence gap after ${preceding} entries`, async () => {
    // Keep each insert below the database's parameter limit.
    for (let written = 0; written < preceding; written += 500) {
      await db.runtime.transaction((tx) => appendAudit(tx, deps.chainKey, Array.from({ length: 500 }, () => entry)));
    }
    const next = BigInt(preceding + 5);
    await db.runtime.update(auditChainHead).set({ nextSeq: next });
    await db.runtime.transaction((tx) => appendAudit(tx, deps.chainKey, [entry]));

    assert.deepEqual(await root.audit.verify(), {
      ok: false,
      log: 'audit',
      failedAtSeq: Number(next),
      reason: `sequence gap: expected seq ${preceding}, found ${next}`,
    });
  });
}
