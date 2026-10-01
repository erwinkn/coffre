import { after, beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import { deriveLogKey, entryHash } from '@coffre/core/audit';
import { appendEntries, LogHeadMismatch } from '@coffre/db/log';
import { eq } from 'drizzle-orm';

import { appendAudit, type AuditEntry } from '../src/db/audit.ts';
import { postgresOnly, withLogUnlocked } from './db/engine.ts';
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

/** An entry in the vault's name, with a MAC made up, linked after the log's last as anyone could: review of #28, R1. */
async function forgeVaultEntry(writer: typeof db.owner): Promise<void> {
  const [head] = await db.owner.select().from(auditChainHead);
  const fields = {
    seq: head.nextSeq, author: 'vault' as const, keyId: 'vault:0000000000000000', occurredAt: Date.now(),
    actor: 'user:victim@acme.example', action: 'unwrap', decision: 'allow', code: null, subjectPrincipal: null,
    projectId: null, environmentId: null, secretId: null, secretVersionId: null, operationId: null, requestId: null,
    sourceIp: null, relatedSeq: null, metadata: '{}',
  };
  const mac = Buffer.alloc(32, 0x41);
  const hash = entryHash(head.headHash, fields, mac);
  await writer.transaction(async (tx) => {
    await tx.insert(auditLog).values({ ...fields, prevHash: head.headHash, mac, hash });
    await tx.update(auditChainHead).set({ nextSeq: fields.seq + 1n, headHash: hash });
  });
}

test('an entry in the vault\'s name that the vault did not write fails verification', async () => {
  await write(1);
  // As the database's owner, whom row-level security does not stop: only
  // the vault's MAC tells, and only the vault holds its key.
  await forgeVaultEntry(db.owner);
  // An honest append takes the forged head as its predecessor.
  await write(1);
  assert.deepEqual(await root.audit.verify(), {
    ok: false,
    log: 'vault',
    failedAtSeq: 1,
    reason: 'written under vault:0000000000000000, a key this verifier does not hold',
  });
});

test('the app\'s login cannot write an entry in the vault\'s name at all', postgresOnly('logins are Postgres\'s'), async () => {
  await write(1);
  await assert.rejects(forgeVaultEntry(db.runtime), (error) => /row-level security/.test(`${error} ${(error as { cause?: unknown }).cause}`));
});

async function write(entries: number): Promise<void> {
  // Keep each insert below the database's parameter limit.
  for (let written = 0; written < entries; written += 500) {
    const batch = Math.min(500, entries - written);
    await db.runtime.transaction((tx) => appendAudit(tx, deps.chainKey, Array.from({ length: batch }, () => entry)));
  }
}

test('audit verification reports live key operations without calling the log broken', async () => {
  await db.owner.transaction((tx) => appendEntries(tx, deriveLogKey('vault', deps.vault.signingKey), [{
    actor: 'user:root@acme.example', action: 'key.intent', decision: 'allow', operationId: randomUUID(),
    metadata: JSON.stringify({ operation: 'wrap', expiresAt: Date.now() + 60_000, keys: [{
      item: 0, secretId: randomUUID(), subject: 'market/dev/KEY', version: 1,
    }] }),
  }]));
  const verified = await root.audit.verify();
  assert.ok(verified.ok);
  assert.equal(verified.vault.pending, 1);
  const page = await root.audit.vault({ full: 'true' });
  assert.ok(page.verification.ok);
  assert.equal(page.verification.pending, 1);

  deps.vault.advance(120_000);
  const overdue = await root.audit.verify();
  assert.ok(!overdue.ok);
  assert.equal(overdue.log, 'vault');
  assert.match(overdue.reason, /overdue/);
});
