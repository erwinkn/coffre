import { after, beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import { deriveLogKey, entryHash } from '@coffre/core/audit';
import { appendEntries, BATCH_BYTES, LogHeadMismatch, withinBytes } from '@coffre/db/log';
import { and, desc, eq, lte, or } from 'drizzle-orm';

import { appendAudit, CHAIN_WALK, type AuditEntry } from '../src/db/audit.ts';
import { writeAuditHeartbeat } from '../src/heartbeat.ts';
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
      // Up to the entry before the one missing, which with none before is nothing.
      through: preceding === 0 ? null : preceding - 1,
      failedAtSeq: preceding + 1,
      author: 'app',
      reason: `sequence gap: expected seq ${preceding}, found ${preceding + 1}`,
    });
  });
}

/** An entry in the vault's name, with a MAC made up, linked after the log's last as anyone could: review of #28, R1. */
async function forgeVaultEntry(writer: typeof db.owner): Promise<void> {
  const [head] = await db.owner.select().from(auditChainHead);
  const fields = {
    seq: head.nextSeq, author: 'vault' as const, keyId: 'vault:0000000000000000', occurredAt: Date.now(),
    actor: 'user:victim@acme.example', action: 'secret.read', decision: 'allow', code: null, subjectPrincipal: null,
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
  // The Owner signed in before it, as the instance's first sign-in: the entry that made them one is the vault's.
  assert.equal((await root.me()).instanceRole, 'owner');
  await write(1);
  // As the database's owner, whom row-level security does not stop: only
  // the vault's MAC tells, and only the vault holds its key.
  await forgeVaultEntry(db.owner);
  // An honest append takes the forged head as its predecessor.
  await write(1);
  // The vault's making root an Owner, the app's entry; then the forged one.
  assert.deepEqual(await root.audit.verify(), {
    ok: false,
    through: 1,
    failedAtSeq: 2,
    author: 'vault',
    reason: `written under vault:0000000000000000, a key this verifier does not hold: either it is forged, or the vault wrote it under another vault key or signing key, which must stay configured: a vault key that was replaced stays in the vault's config, in previousKeks`,
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

test('a log of large entries is verified whole, in batches that hold no more than BATCH_BYTES between them', async () => {
  // A read of thousands of secrets lists them all: a few such entries of each author's outrun one batch's bytes.
  const listing = 'x'.repeat(Math.ceil(BATCH_BYTES / 3));
  const vaultKey = deriveLogKey('vault', deps.vault.signingKey);
  for (let i = 0; i < 4; i++) {
    await db.runtime.transaction((tx) => appendAudit(tx, deps.chainKey, [{ ...entry, metadata: { listing } }]));
    await db.owner.transaction((tx) => appendEntries(tx, vaultKey, [{ actor: 'user:root@acme.example', action: 'secret.read', decision: 'allow', metadata: JSON.stringify({ listing }) }]));
    await write(2);
  }
  const [head] = await db.owner.select().from(auditChainHead);
  const first = await withinBytes(db.owner, undefined, 10_000);
  assert.ok(first !== null && first.cut && first.to < head.nextSeq - 1n, 'one batch held every large entry');
  const verified = await root.audit.verify();
  assert.ok(verified.ok, JSON.stringify(verified));
  // Through every entry: the large ones, and those the request itself wrote after them.
  assert.ok(verified.through !== null && verified.through >= Number(head.nextSeq - 1n) && verified.entries === verified.through + 1, JSON.stringify(verified));
});

test('a page of the log holds no more than BATCH_BYTES of what its entries list, and says there is more: the pages still tile it', async () => {
  const listing = 'x'.repeat(Math.ceil(BATCH_BYTES / 3));
  for (let i = 0; i < 4; i++) {
    await db.runtime.transaction((tx) => appendAudit(tx, deps.chainKey, [{ ...entry, action: 'large', metadata: { listing } }]));
    await write(1);
  }
  const seen: number[] = [];
  const sizes: number[] = [];
  for (let before: number | undefined; ;) {
    const page = await root.audit.list({ before, limit: 100 });
    seen.push(...page.entries.filter((found) => found.action === 'large' || found.action === 'test').map((found) => found.seq));
    sizes.push(page.entries.length);
    if (!page.more) break;
    before = page.entries.at(-1)!.seq;
  }
  // Two large entries a page at most, every entry once, newest first.
  assert.ok(sizes.length >= 2 && sizes[0]! < 100, JSON.stringify(sizes));
  assert.equal(seen.length, 8);
  assert.deepEqual(seen, [...seen].sort((a, b) => b - a));
  assert.equal(new Set(seen).size, 8);
});

test('audit verification reports live key operations without calling the log broken', async () => {
  await db.owner.transaction((tx) => appendEntries(tx, deriveLogKey('vault', deps.vault.signingKey), [{
    actor: 'user:root@acme.example', action: 'key.intent', decision: 'allow', operationId: randomUUID(),
    metadata: JSON.stringify({ intent: randomUUID(), operation: 'key.wrap', expiresAt: Date.now() + 60_000, keys: [{
      item: 0, secretId: randomUUID(), subject: 'market/dev/KEY', version: 1,
    }] }),
  }]));
  const verified = await root.audit.verify();
  assert.ok(verified.ok);
  assert.equal(verified.pending, 1);

  deps.vault.advance(120_000);
  const overdue = await root.audit.verify();
  assert.ok(!overdue.ok);
  assert.equal(overdue.author, 'vault');
  assert.match(overdue.reason, /overdue/);
});

/** The scheduled beat, as the Cron trigger runs it: the app's walk, its heartbeat, then the vault's checkpoint. */
async function beat(warned: string[] = []): Promise<void> {
  assert.equal(await writeAuditHeartbeat(db.runtime, deps.chainKey, deps.vault, { warn: (_, message) => warned.push(message) }), true);
}

/** Reads in the vault's name, as the vault logs them. */
async function reads(entries: number): Promise<void> {
  const vaultKey = deriveLogKey('vault', deps.vault.signingKey);
  await db.owner.transaction((tx) => appendEntries(tx, vaultKey, Array.from({ length: entries }, () => ({
    actor: 'user:root@acme.example', action: 'secret.read', decision: 'allow' as const, metadata: '{"purpose":"reveal"}',
  }))));
}

test('the page checks what was written since the last beat, and only the walk from the first entry reads what came before', async () => {
  assert.equal((await root.me()).instanceRole, 'owner');
  await write(300);
  await reads(50);
  await beat();
  await write(5);
  await reads(5);
  const [{ verified }] = await heartbeats();
  // Everything the beat verified, both authors' (but for the vault's access entries, which every request reads),
  // edited in place, its hash left as it was: whoever reads the log as it is sees another actor.
  await withLogUnlocked(db.owner, (owner) => owner.update(auditLog).set({ actor: 'system:edited' })
    .where(and(lte(auditLog.seq, BigInt(verified!.seq)), or(eq(auditLog.author, 'app'), eq(auditLog.action, 'secret.read')))));

  // The check goes on from where the beat's walk ended, and the vault's from its checkpoint after it: neither
  // reads an entry before, so neither finds the edits.
  const [head] = await db.owner.select().from(auditChainHead);
  const page = await root.audit.verify();
  assert.deepEqual(page.ok && [page.from, page.through, page.remaining], [verified!.seq + 1, Number(head.nextSeq) - 1, 0], JSON.stringify(page));
  // The walk from the first entry reads them all, and fails at the first.
  const whole = await root.audit.verifyWhole();
  assert.deepEqual(!whole.ok && [whole.failedAtSeq, whole.author, whole.reason], [1, 'app', 'hash does not match the entry']);
});

test("an entry forged in the app's name is found by the next check, though checkpoints sign over it", async () => {
  await write(3);
  await beat();
  await forgeAppEntry();
  const forged = Number((await db.owner.select().from(auditChainHead))[0].nextSeq) - 1;
  await write(1);
  // The beat's walk finds it and leaves its `verified` where it was; the vault, which checks only its own
  // MACs, signs over it. So the page's check starts before it, and finds it.
  const warned: string[] = [];
  await beat(warned);
  assert.deepEqual(warned, ['the audit log does not verify from the last heartbeat']);
  const [newest, previous] = await heartbeats();
  assert.deepEqual(newest.verified, previous.verified);
  assert.deepEqual(await root.audit.verify(), {
    ok: false, through: forged - 1, failedAtSeq: forged, author: 'app', reason: 'not written by the app: its MAC does not match',
  });
});

test('a log longer than one walk is checked as far as one goes, and walked from its first entry a stretch at a time', async () => {
  assert.equal((await root.me()).instanceRole, 'owner');
  await write(12_000);
  // Someone admitted past where one walk reaches: the rows hold them, the walk does not, and that is no tampering.
  assert.equal((await deps.vault.admit({ actor: 'user:root@acme.example', principal: 'user:ada@acme.example' })).ok, true);
  // No beat yet, as after an upgrade from 0.10.0: the check starts at the first entry, and stops one walk on.
  const [{ nextSeq }] = await db.owner.select().from(auditChainHead);
  const first = await root.audit.verify();
  assert.deepEqual(first.ok && [first.from, first.through, first.remaining], [0, CHAIN_WALK - 1, Number(nextSeq) - CHAIN_WALK], JSON.stringify(first));
  // Nor is the walk from the first entry whole: it ends where the page's does, saying what it left.
  const partial = await root.audit.verifyWhole();
  assert.deepEqual(partial.ok && [partial.through, partial.remaining, partial.next], [CHAIN_WALK - 1, Number(nextSeq) - CHAIN_WALK, null], JSON.stringify(partial));

  // Beats catch up, a checkpoint each, signed a walk at a time; then more is written, and beaten.
  for (let i = 0; i < 3; i++) await beat();
  await write(6_000);
  await beat();
  await beat();
  const caught = await root.audit.verify();
  assert.ok(caught.ok && caught.remaining === 0, JSON.stringify(caught));

  // The walk from the first entry, a request a stretch, each ending at a checkpoint no further than one walk on.
  const stretches: { from: number; through: number | null; next: number | null | undefined }[] = [];
  const whole = await root.audit.verifyWhole((stretch) => {
    assert.ok(stretch.ok, JSON.stringify(stretch));
    stretches.push({ from: stretch.from, through: stretch.through, next: stretch.next });
  });
  assert.ok(whole.ok && whole.remaining === 0 && whole.through === caught.through, JSON.stringify(whole));
  assert.ok(stretches.length >= 3, JSON.stringify(stretches));
  for (const [i, stretch] of stretches.entries()) {
    assert.ok(stretch.through! - stretch.from < CHAIN_WALK, `stretch ${i} is longer than one walk: ${JSON.stringify(stretch)}`);
    if (i > 0) assert.equal(stretch.from, stretches[i - 1]!.through! + 1, 'the stretches leave a gap');
  }
  assert.deepEqual(stretches.at(-1)!.next, null);
});

/** The app's newest heartbeats, newest first: how far each says the app verified. */
async function heartbeats(): Promise<{ seq: bigint; verified?: { seq: number; hash: string } }[]> {
  const rows = await db.owner.select().from(auditLog).where(eq(auditLog.action, 'audit.heartbeat')).orderBy(desc(auditLog.seq));
  return rows.map((row) => ({ seq: row.seq, ...(JSON.parse(row.metadata) as { verified?: { seq: number; hash: string } }) }));
}

/** An entry in the app's name, with a MAC made up, linked after the log's last as anyone could. */
async function forgeAppEntry(): Promise<void> {
  const [head] = await db.owner.select().from(auditChainHead);
  const fields = {
    seq: head.nextSeq, author: 'app' as const, keyId: deriveLogKey('app', deps.chainKey).keyId, occurredAt: Date.now(),
    actor: 'user:root@acme.example', action: 'secret.write', decision: 'allow', code: null, subjectPrincipal: null,
    projectId: null, environmentId: null, secretId: null, secretVersionId: null, operationId: null, requestId: null,
    sourceIp: null, relatedSeq: null, metadata: '{}',
  };
  const mac = Buffer.alloc(32, 0x41);
  const hash = entryHash(head.headHash, fields, mac);
  await db.owner.transaction(async (tx) => {
    await tx.insert(auditLog).values({ ...fields, prevHash: head.headHash, mac, hash });
    await tx.update(auditChainHead).set({ nextSeq: fields.seq + 1n, headHash: hash });
  });
}
