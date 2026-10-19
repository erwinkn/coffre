import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

import { deriveLogKey, entryHash, entryMac, type LogKey, type StoredEntry } from '@coffre/core/audit';
import {
  awsKms,
  KEY_CHECK,
  KEY_CHECK_CONTEXT,
  KEY_CHECK_VALUE,
  KekRegistry,
  KekUnavailableError,
  LocalKekProvider,
  opensKeyCheck,
  type KekProvider,
  type KeyOperation,
} from '@coffre/core/kek';
import { EVERYWHERE, type Scope } from '@coffre/core/access';
import { checkpointMessage, verifyCheckpoint, type Checkpoint, type SecretRef, type WrappedKey } from '@coffre/core/vault';
import { tablesOf, type Database } from '@coffre/db';
import { everyProjectPreview } from '@coffre/db/grants';
import { SNAPSHOT } from '@coffre/db/dialect';
import { appendEntries, BATCH_BYTES, forgetLogHeads, lockLogHead, LogHeadMismatch, LogRewound } from '@coffre/db/log';
import { and, asc, desc, eq, gt, gte, lte, sql } from 'drizzle-orm';

import { checkOwners, derivedSigningKey, resolveVaultConfig, type ResolvedVaultConfig, type VaultConfig } from '../src/config.ts';
import { openLocalVault, type LocalVault } from '../src/local.ts';
import { signer } from '../src/checkpoint.ts';
import { entryView, vaultLogKey } from '../src/log.ts';
import { memberMac, rowKey, sealed } from '../src/rows.ts';
import * as store from '../src/store.ts';
import { KekBadClaimError as ExportedBadClaim } from '../src/index.ts';
import { openVault, prepareVault, type VaultOptions } from '../src/vault.ts';
import {
  emptyDatabase,
  ENGINE,
  newEnvironment,
  newProject,
  openTestDatabase,
  places,
  storedVersions,
  postgresOnly,
  rows,
  run,
  withLogUnlocked,
  type TestDatabase,
} from './database.ts';

/** Every vault here signs, and MACs its entries, with this; a vault started afresh needs it too. */
const SIGNING_KEY = randomBytes(32);
const VAULT_KEY = vaultLogKey(SIGNING_KEY);
/** What each call logs, one entry per key. */
const LOGGED = { wrap: 'key.wrap', unwrap: 'secret.read', rewrap: 'key.rewrap' } as const;

const ROOT = 'user:root@acme.example';
const ADA = 'user:ada@acme.example';
const BOB = 'user:bob@acme.example';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
});
after(() => db.close());
beforeEach(() => emptyDatabase(db.owner));

type World = Awaited<ReturnType<typeof places>> & {
  vault: LocalVault;
  clock: { offset: number };
  /** Another instance of the same vault, over connections of its own, as a second process or isolate. */
  twin(): Promise<LocalVault>;
};

function configure(overrides: Partial<ResolvedVaultConfig> = {}): ResolvedVaultConfig {
  return {
    keks: new KekRegistry(LocalKekProvider.generate('test-kek-1')),
    owners: ['root@acme.example'],
    signingKeys: [SIGNING_KEY],
    bulkLimit: { count: 1000, windowMs: 15 * 60_000 },
    ...overrides,
  };
}

/**
 * A vault that names nobody, which no deployment's can (`checkOwners`): the
 * rules that hold whatever the list, about Owners it does not name, as
 * after it changed, or while it names only one whose row the vault cannot
 * start over.
 */
const UNNAMED = { owners: [] };

async function world(overrides: Partial<ResolvedVaultConfig> = {}, options: VaultOptions = {}): Promise<World> {
  const config = configure(overrides);
  const clock = { offset: 0 };
  const open = async (database: Database) => openLocalVault(database, config, { clockOffset: () => clock.offset, ...options });
  const vault = await open(db.vault);
  // Root signs in first, as on a new instance whose deployment names them: the vault makes them its Owner.
  // A vault that names someone else, or nobody, finds them one.
  const named = config.owners.includes('root@acme.example') ? vault : await openLocalVault(db.vault, configure(), options);
  assert.equal((await named.access(ROOT)).role, 'owner');
  return { ...(await places(db.owner)), vault, clock, twin: async () => open(await db.connect()) };
}

/** A vault started afresh over the same database: it has verified nothing yet. */
function fresh(): Promise<LocalVault> {
  return openLocalVault(db.vault, configure());
}

/** Admit `principal` and grant `role` at each place. */
async function member(w: World, principal: string, grants: [string | null, string, number?][]) {
  assert.equal((await w.vault.admit({ actor: ROOT, principal })).ok, true);
  const result = await w.vault.setAccess({
    actor: ROOT,
    principal,
    changes: grants.map(([environmentId, role, expiresAt]) => ({
      projectId: w.project,
      environmentId,
      role: role as 'viewer',
      expiresAt: expiresAt === undefined ? null : new Date(expiresAt).toISOString(),
    })),
  });
  assert.equal(result.ok, true, JSON.stringify(result));
}

async function wrapped(w: World, secret: SecretRef): Promise<WrappedKey> {
  const result = await w.vault.wrap({ principal: ROOT, items: [{ secret, key: randomBytes(32).toString('base64') }] });
  assert.ok(result.ok, JSON.stringify(result));
  return result.wrapped[0];
}

function versionItems(items: { secret: SecretRef; wrapped: WrappedKey }[]) {
  return storedVersions(db.owner, items);
}

/** The vault's entries, oldest first, as stored in the log. */
async function vaultLog(_w?: World) {
  return (await store.vaultPage(db.owner, undefined, 200)).map(entryView).reverse();
}

/** What a checkpoint's entry says its signature covers, without the tally it keeps beside it. */
function signedOf(detail: Record<string, unknown>): Checkpoint {
  const { seq, hash, signedAt, keyId, signature } = detail as Checkpoint;
  return { seq, hash, signedAt, keyId, signature };
}

/** What an append-only refusal looks like through Drizzle, which wraps the database's error. */
const appendOnly = (error: unknown) => /append-only/.test(`${error} ${(error as { cause?: unknown }).cause}`);

test('a read needs a live grant on the environment, and unwraps the key it was wrapped with', async () => {
  const w = await world();
  await member(w, ADA, [[w.dev, 'developer']]);
  const devSecret = await w.secret(w.dev);
  const key = randomBytes(32).toString('base64');
  const wrap = await w.vault.wrap({ principal: ADA, items: [{ secret: devSecret, key }] });
  assert.ok(wrap.ok);
  const read = await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: await versionItems([{ secret: devSecret, wrapped: wrap.wrapped[0] }]) });
  assert.deepEqual(read, { ok: true, keys: [key] });

  const prodSecret = await w.secret(w.prod);
  const refused = await w.vault.unwrap({
    principal: ADA,
    purpose: 'reveal',
    items: await versionItems([{ secret: prodSecret, wrapped: await wrapped(w, prodSecret) }]),
  });
  assert.equal(!refused.ok && refused.refusal.code, 'no_grant');
  const write = await w.vault.wrap({ principal: ADA, items: [{ secret: prodSecret, key }] });
  assert.equal(!write.ok && write.refusal.code, 'no_grant');
});

test("a sensitive value is never handed back to a person, an Owner included: used for them, copied for a fork that keeps it so, read by a service", async () => {
  const w = await world();
  await member(w, ADA, [[w.dev, 'developer']]);
  const SERVICE = 'token:deploy';
  await member(w, SERVICE, [[w.dev, 'viewer']]);
  const secret = { ...(await w.secret(w.dev)), sensitive: true };
  const key = randomBytes(32).toString('base64');
  const wrap = await w.vault.wrap({ principal: ADA, items: [{ secret, key }] });
  assert.ok(wrap.ok);
  assert.deepEqual(wrap.sensitive, [true], 'the vault says it bound the key as sensitive');
  const items = await versionItems([{ secret, wrapped: wrap.wrapped[0] }]);
  for (const principal of [ADA, ROOT]) {
    for (const purpose of ['reveal', 'run', 'compare', 'expose'] as const) {
      const refused = await w.vault.unwrap({ principal, purpose, items });
      assert.equal(!refused.ok && refused.refusal.code, 'sensitive', `${principal} to ${purpose}`);
    }
    assert.deepEqual(await w.vault.unwrap({ principal, purpose: 'use', items }), { ok: true, keys: [key] });
    assert.deepEqual(await w.vault.unwrap({ principal, purpose: 'copy', keepsSensitive: true, items }), { ok: true, keys: [key] });
    // A copy by an app before 0.10, which would write the value as a secret anyone with read sees.
    const old = await w.vault.unwrap({ principal, purpose: 'copy', items });
    assert.equal(!old.ok && old.refusal.code, 'sensitive', `${principal}'s copy that keeps nothing sensitive`);
  }
  // A purpose a later app may name is one that hands values back.
  const unknown = await w.vault.unwrap({ principal: ADA, purpose: 'peek' as 'reveal', items });
  assert.equal(!unknown.ok && unknown.refusal.code, 'sensitive');
  assert.deepEqual(await w.vault.unwrap({ principal: SERVICE, purpose: 'run', items }), { ok: true, keys: [key] });
  // A service account's fork, through an app of 0.9 that would write the copy as a secret, copies nothing sensitive either.
  const serviceCopy = await w.vault.unwrap({ principal: SERVICE, purpose: 'copy', items });
  assert.equal(!serviceCopy.ok && serviceCopy.refusal.code, 'sensitive');
  assert.deepEqual(await w.vault.unwrap({ principal: SERVICE, purpose: 'copy', keepsSensitive: true, items }), { ok: true, keys: [key] });
  // A batch is all or nothing: a secret beside it is refused with it, its own entry saying why.
  const plain = await w.secret(w.dev);
  const both = [...items, ...(await versionItems([{ secret: plain, wrapped: await wrapped(w, plain) }]))];
  const batch = await w.vault.unwrap({ principal: ADA, purpose: 'run', items: both });
  assert.equal(!batch.ok && batch.refusal.code, 'sensitive');
  const denied = (await vaultLog()).filter((entry) => entry.action === 'secret.read' && entry.outcome === 'refuse');
  assert.ok(denied.some((entry) => entry.code === 'sensitive'));
});

test("a sensitive version's key opens as nothing else: its column flipped back is a bad claim, for everyone", async () => {
  const w = await world();
  const secret = { ...(await w.secret(w.dev)), sensitive: true };
  const sealed = await wrapped(w, secret);
  const flipped = await versionItems([{ secret: { ...secret, sensitive: false }, wrapped: sealed }]);
  const SERVICE = 'token:deploy';
  await member(w, SERVICE, [[w.dev, 'viewer']]);
  const read = await w.vault.unwrap({ principal: SERVICE, purpose: 'run', items: flipped });
  assert.equal(!read.ok && read.refusal.code, 'bad_claim');
  // And a secret's key read as sensitive does not open either.
  const other = await w.secret(w.dev);
  const marked = await versionItems([{ secret: { ...other, sensitive: true }, wrapped: await wrapped(w, other) }]);
  const as = await w.vault.unwrap({ principal: SERVICE, purpose: 'run', items: marked });
  assert.equal(!as.ok && as.refusal.code, 'bad_claim');
});

test('a rewrap makes a value stricter, never looser: not from a sensitive version, nor of a secret whose newest is', async () => {
  const w = await world();
  await member(w, ADA, [[w.dev, 'developer']]);
  const base = await w.secret(w.dev);
  const v1 = await versionItems([{ secret: base, wrapped: await wrapped(w, base) }]);
  // Secret to sensitive, with no value: a new version, its key wrapped again as sensitive.
  const tightened = await w.vault.rewrap({ principal: ADA, items: [{ secret: { ...base, version: 2, sensitive: true }, ...v1[0]! }] });
  assert.ok(tightened.ok, JSON.stringify(tightened));
  assert.deepEqual(tightened.sensitive, [true]);
  const v2 = await versionItems([{ secret: { ...base, version: 2, sensitive: true }, wrapped: tightened.wrapped[0]! }]);
  // Back to secret from it, or the old secret version restored as one while the newest is sensitive: refused.
  for (const item of [{ secret: { ...base, version: 3 }, ...v2[0]! }, { secret: { ...base, version: 3, sensitive: false }, ...v1[0]! }]) {
    const looser = await w.vault.rewrap({ principal: ROOT, items: [item] });
    assert.equal(!looser.ok && looser.refusal.code, 'invalid');
    assert.match(!looser.ok ? looser.refusal.message : '', /only by writing it again/);
  }
  // The old version restored as sensitive is fine.
  assert.ok((await w.vault.rewrap({ principal: ADA, items: [{ secret: { ...base, version: 3, sensitive: true }, ...v1[0]! }] })).ok);
  // A new value may be anything: writing it again is how a value is made looser.
  assert.ok((await w.vault.wrap({ principal: ADA, items: [{ secret: { ...base, version: 4 }, key: randomBytes(32).toString('base64') }] })).ok);
});

test('a rewrap is held to its secret\'s newest version as the decision commits: one written sensitive meanwhile refuses it', postgresOnly('SQLite runs one writer at a time'), async () => {
  const remote = service();
  const w = await world({ keks: remote.keks });
  const base = await w.secret(w.dev);
  const [v1] = await versionItems([{ secret: base, wrapped: await wrapped(w, base) }]);
  const sensitive = { ...base, version: 2, sensitive: true };
  const later = await wrapped(w, sensitive);
  // The key service takes its time over the old key, as the rewrap waits under its decision; meanwhile a sensitive
  // version, wrapped before, is stored.
  remote.seen.hanging.add(base.secretId);
  const rewrap = w.vault.rewrap({ principal: ROOT, items: [{ secret: { ...base, version: 3 }, ...v1! }] });
  await sleep(100);
  await versionItems([{ secret: sensitive, wrapped: later }]);
  const refused = await rewrap;
  assert.equal(!refused.ok && refused.refusal.code, 'invalid', JSON.stringify(refused));
});

test('a read records the stored version instead of the app claim', async () => {
  const w = await world();
  const secret = await w.secret(w.dev);
  const key = randomBytes(32).toString('base64');
  const sealed = await w.vault.wrap({ principal: ROOT, items: [{ secret, key }] });
  assert.ok(sealed.ok);
  const { secretVersions, auditLog } = tablesOf(db.owner);
  const id = randomUUID();
  await db.owner.insert(secretVersions).values({
    id, secretId: secret.secretId, version: 1, envelopeVersion: 1,
    ciphertext: Buffer.from('value'), iv: Buffer.alloc(12), authTag: Buffer.alloc(16),
    wrappedDek: Buffer.from(sealed.wrapped[0].bytes, 'base64'),
    kekProvider: sealed.wrapped[0].kekProvider, kekId: sealed.wrapped[0].kekId,
    kekVersion: sealed.wrapped[0].kekVersion, createdBy: ROOT,
  });
  // Extra fields from an app acting outside the contract must not name the released version.
  const input = { principal: ROOT, purpose: 'reveal' as const, items: [{
    secretVersionId: id, secret: { ...secret, version: 9 }, wrapped: sealed.wrapped[0],
  }] };
  assert.deepEqual(await w.vault.unwrap(input), { ok: true, keys: [key] });
  const [entry] = await db.owner.select().from(auditLog).where(eq(auditLog.action, 'secret.read'));
  assert.equal(JSON.parse(entry.metadata!).version, 1);
  assert.equal(entry.secretVersionId, id);
});

test('a restore records the stored source version instead of the app claim', async () => {
  const w = await world();
  const secret = await w.secret(w.dev);
  const sealed = await wrapped(w, secret);
  const [source] = await versionItems([{ secret, wrapped: sealed }]);
  const input = { principal: ROOT, items: [{
    secret: { ...secret, version: 2 }, ...source, from: 9, wrapped: sealed,
  }] };
  assert.ok((await w.vault.rewrap(input)).ok);
  const { auditLog } = tablesOf(db.owner);
  const [entry] = await db.owner.select().from(auditLog).where(eq(auditLog.action, 'key.rewrap'));
  assert.equal(JSON.parse(entry.metadata!).from, 1);
  assert.equal(entry.secretVersionId, source.secretVersionId);
});

test('a missing version refuses the whole batch before a key service sees it', async () => {
  const remote = service();
  const w = await world({ keks: remote.keks });
  const secret = await w.secret(w.dev);
  const sealed = await wrapped(w, secret);
  const [source] = await versionItems([{ secret, wrapped: sealed }]);
  const missing = randomUUID();
  const input = { principal: ROOT, purpose: 'run' as const, items: [
    { ...source, secret, wrapped: sealed },
    { secretVersionId: missing, secret, wrapped: sealed },
  ] };
  const result = await w.vault.unwrap(input);
  assert.equal(!result.ok && result.refusal.code, 'bad_claim');
  assert.equal(remote.seen.unwrap, 0);
  const { auditLog } = tablesOf(db.owner);
  const entries = await db.owner.select().from(auditLog).where(eq(auditLog.action, 'secret.read')).orderBy(asc(auditLog.seq));
  assert.deepEqual(entries.map((entry) => [entry.decision, entry.code, entry.secretVersionId]), [
    ['deny', 'bad_claim', source.secretVersionId], ['deny', 'bad_claim', null],
  ]);
  assert.equal(JSON.parse(entries[1].metadata!).secretVersionId, missing);
});

test('a restore cannot use a stored version belonging to another secret', async () => {
  const w = await world();
  const secret = await w.secret(w.dev);
  const other = await w.secret(w.dev);
  const sealed = await wrapped(w, secret);
  // Even a source row carrying the target's wrapped key cannot change which secret it belongs to.
  const [source] = await versionItems([{ secret: other, wrapped: sealed }]);
  const input = { principal: ROOT, items: [{ secret, ...source, from: 1, wrapped: sealed }] };
  const result = await w.vault.rewrap(input);
  assert.equal(!result.ok && result.refusal.code, 'bad_claim');
});

test('aliased restore targets keep each source version in its own entry', async () => {
  const config = configure();
  const w = await world(config);
  const first = await w.secret(w.dev);
  const second = { ...first, version: 2 };
  const wrappedKeys = [await wrapped(w, first), await wrapped(w, second)];
  const sources = await versionItems([first, second].map((secret, i) => ({ secret, wrapped: wrappedKeys[i] })));
  const target = { ...first, version: 3 };
  // Workers RPC can preserve aliases; use the implementation without the local JSON transport.
  const vault = openVault(db.vault, await prepareVault(config));
  const result = await vault.rewrap({ principal: ROOT, items: sources.map((source, i) => ({
    secret: target, ...source, from: i + 1, wrapped: wrappedKeys[i],
  })) });
  assert.ok(result.ok);
  const { auditLog } = tablesOf(db.owner);
  const entries = await db.owner.select().from(auditLog).where(eq(auditLog.action, 'key.rewrap')).orderBy(asc(auditLog.seq));
  assert.deepEqual(entries.map((entry) => entry.secretVersionId), sources.map((source) => source.secretVersionId));
  assert.deepEqual(entries.map((entry) => JSON.parse(entry.metadata!).from), [1, 2]);
});

test('a batch is all or nothing, and every item is logged either way', async () => {
  const w = await world();
  await member(w, ADA, [[w.dev, 'viewer']]);
  const devSecret = await w.secret(w.dev);
  const prodSecret = await w.secret(w.prod);
  const items = [
    { secret: devSecret, wrapped: await wrapped(w, devSecret) },
    { secret: prodSecret, wrapped: await wrapped(w, prodSecret) },
  ];
  const result = await w.vault.unwrap({ principal: ADA, purpose: 'run', items: await versionItems(items), requestId: 'req-1' });
  assert.equal(!result.ok && result.refusal.code, 'no_grant');

  const reads = (await vaultLog(w)).filter((entry) => entry.action === 'secret.read');
  assert.deepEqual(
    reads.map((entry) => [entry.subject, entry.outcome, entry.code, entry.detail.purpose, entry.detail.secretId, entry.detail.requestId]),
    [
      [devSecret.path, 'refuse', 'no_grant', 'run', devSecret.secretId, 'req-1'],
      [prodSecret.path, 'refuse', 'no_grant', 'run', prodSecret.secretId, 'req-1'],
    ],
  );
});

test('a read of several secrets is one entry for each place it read at, listing each secret and its version', async () => {
  const w = await world();
  await member(w, ADA, [[w.dev, 'viewer'], [w.prod, 'viewer']]);
  const dev = [await w.secret(w.dev, 'A'), await w.secret(w.dev, 'B'), await w.secret(w.dev, 'C')];
  const prod = await w.secret(w.prod, 'D');
  const items = await Promise.all([...dev, prod].map(async (secret) => ({ secret, wrapped: await wrapped(w, secret) })));
  const versions = await versionItems(items);
  const operationId = randomUUID();
  const read = await w.vault.unwrap({ principal: ADA, purpose: 'run', items: versions, requestId: 'req-1', operationId });
  assert.ok(read.ok, JSON.stringify(read));

  const { auditLog } = tablesOf(db.owner);
  const entries = await db.owner.select().from(auditLog)
    .where(and(eq(auditLog.action, 'secret.read'), eq(auditLog.actor, ADA))).orderBy(asc(auditLog.seq));
  // dev's three in one entry that lists them; prod's one, as a read of one secret always was.
  assert.deepEqual(entries.map((entry) => [entry.environmentId, entry.secretId, entry.secretVersionId, entry.operationId, entry.requestId]), [
    [w.dev, null, null, operationId, 'req-1'],
    [w.prod, prod.secretId, versions[3]!.secretVersionId, operationId, 'req-1'],
  ]);
  assert.deepEqual(JSON.parse(entries[0]!.metadata), {
    purpose: 'run',
    secrets: dev.map((secret, i) => ({ secretId: secret.secretId, secretVersionId: versions[i]!.secretVersionId, subject: secret.path, version: 1 })),
  });
  assert.deepEqual(JSON.parse(entries[1]!.metadata), { subject: prod.path, version: 1, purpose: 'run' });
  assert.ok((await w.vault.verifyLog({})).ok);
});

test('a wrapped key presented as another secret is a bad claim', async () => {
  const w = await world();
  await member(w, ADA, [[null, 'viewer']]);
  const devSecret = await w.secret(w.dev);
  const result = await w.vault.unwrap({
    principal: ADA,
    purpose: 'reveal',
    items: await versionItems([{ secret: await w.secret(w.prod), wrapped: await wrapped(w, devSecret) }]),
  });
  assert.equal(!result.ok && result.refusal.code, 'bad_claim');
});

/**
 * A key service: a local KEK behind the interface, so the vault treats it
 * as one, which counts what reaches it and can be made to fail, or to take
 * its time, per secret.
 */
function service(options: { delayMs?: number } = {}) {
  const inner = LocalKekProvider.generate('test-kek-1');
  const seen = { wrap: 0, unwrap: 0, down: false, failing: new Set<string>(), hanging: new Set<string>(), opened: [] as Buffer[] };
  const answer = async <T>(secretId: string, work: () => Promise<T>, operation?: KeyOperation) => {
    try {
      if (options.delayMs) await sleep(options.delayMs, undefined, { signal: operation?.signal });
      if (seen.hanging.has(secretId)) await sleep(500, undefined, { signal: operation?.signal });
    } catch (error) {
      if (operation?.signal.aborted) throw new KekUnavailableError('test key operation cancelled', true);
      throw error;
    }
    if (seen.down || seen.failing.has(secretId)) throw new KekUnavailableError('KMS Decrypt failed 3 times: KMSInternalException');
    return work();
  };
  const kek: KekProvider = {
    provider: inner.provider,
    keyId: inner.keyId,
    keyVersion: inner.keyVersion,
    wrap: (dek, ctx, operation) => (seen.wrap++, answer(ctx.secretId, () => inner.wrap(dek, ctx, operation), operation)),
    unwrap: (wrapped, ctx, operation) => (
      seen.unwrap++,
      answer(ctx.secretId, async () => {
        const key = await inner.unwrap(wrapped, ctx, operation);
        seen.opened.push(key);
        return key;
      }, operation)
    ),
  };
  return { keks: new KekRegistry(kek), seen };
}

/** Make every append of these vault actions fail, as a database that refuses the write would. */
async function failAppends(owner: Database, actions: string[]): Promise<() => Promise<void>> {
  const list = actions.map((action) => `'${action}'`).join(', ');
  if (ENGINE === 'postgres') {
    await run(owner, sql.raw(`CREATE FUNCTION test_refuse_append() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN IF NEW.author = 'vault' AND NEW.action IN (${list}) THEN RAISE EXCEPTION 'test log failure'; END IF; RETURN NEW; END $$`));
    await run(owner, sql`CREATE TRIGGER test_refuse_append BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION test_refuse_append()`);
    return async () => {
      await run(owner, sql`DROP TRIGGER test_refuse_append ON audit_log`);
      await run(owner, sql`DROP FUNCTION test_refuse_append()`);
    };
  }
  await run(owner, sql.raw(`CREATE TRIGGER test_refuse_append BEFORE INSERT ON audit_log
    WHEN NEW.author = 'vault' AND NEW.action IN (${list}) BEGIN SELECT RAISE(ABORT, 'test log failure'); END`));
  return () => run(owner, sql`DROP TRIGGER test_refuse_append`);
}

for (const [operation, failure] of [
  ['wrap', null], ['wrap', 'provider'], ['wrap', 'log'], ['unwrap', null], ['unwrap', 'log'],
] as const) {
  test(`${operation} clears the DEK buffer after ${failure === null ? 'success' : `${failure} failure`}`, async (t) => {
    const inner = LocalKekProvider.generate('test-kek-1');
    const held: Buffer[] = [];
    let fail = false;
    const kek: KekProvider = {
      provider: inner.provider,
      keyId: inner.keyId,
      keyVersion: inner.keyVersion,
      wrap: async (key, ctx) => {
        held.push(key);
        if (fail && failure === 'provider') throw new KekUnavailableError('test provider failure');
        return inner.wrap(key, ctx);
      },
      unwrap: async (wrapped, ctx) => {
        const key = await inner.unwrap(wrapped, ctx);
        held.push(key);
        return key;
      },
    };
    const w = await world({ keks: new KekRegistry(kek) });
    const secret = await w.secret(w.dev);
    const key = randomBytes(32).toString('base64');
    const sealed = await w.vault.wrap({ principal: ROOT, items: [{ secret, key }] });
    assert.ok(sealed.ok);
    held.length = 0;
    fail = true;
    if (failure === 'log') t.after(await failAppends(db.owner, [LOGGED[operation]]));
    const call = operation === 'wrap'
      ? w.vault.wrap({ principal: ROOT, items: [{ secret, key }] })
      : w.vault.unwrap({ principal: ROOT, purpose: 'reveal', items: await versionItems([{ secret, wrapped: sealed.wrapped[0] }]) });
    if (failure === 'log') {
      await assert.rejects(call, (error) => /test log failure/.test(`${error} ${(error as { cause?: unknown }).cause}`));
    } else if (failure === 'provider') {
      await assert.rejects(call, KekUnavailableError);
    } else {
      const result = await call;
      assert.ok(result.ok);
      if ('keys' in result) assert.deepEqual(result.keys, [key]);
    }
    assert.equal(held.length, 1);
    assert.deepEqual(held[0], Buffer.alloc(32), 'no raw DEK remains in the buffer handed to or returned by the provider');
  });
}

test('only a call the rules allow reaches the KEK', async () => {
  const { keks, seen } = service();
  const w = await world({ keks, bulkLimit: { count: 2, windowMs: 60_000 } });
  await member(w, ADA, [[w.dev, 'viewer']]);
  const [dev, prod] = [await w.secret(w.dev), await w.secret(w.prod)];
  const items = [
    { secret: dev, wrapped: await wrapped(w, dev) },
    { secret: prod, wrapped: await wrapped(w, prod) },
  ];
  const before = { ...seen };
  const code = (outcome: { ok: boolean; refusal?: { code: string } }) => outcome.refusal?.code;

  assert.equal(code(await w.vault.unwrap({ principal: ADA, purpose: 'run', items: await versionItems(items) })), 'no_grant');
  assert.equal(code(await w.vault.unwrap({ principal: BOB, purpose: 'run', items: await versionItems(items.slice(0, 1)) })), 'not_a_member');
  assert.equal(code(await w.vault.wrap({ principal: ADA, items: [{ secret: dev, key: randomBytes(32).toString('base64') }] })), 'no_grant');
  const again = { ...dev, version: 2 };
  assert.equal(code(await w.vault.rewrap({ principal: ADA, items: [{ secret: again, ...(await versionItems(items.slice(0, 1)))[0] }] })), 'no_grant');
  assert.deepEqual({ wrap: seen.wrap, unwrap: seen.unwrap }, { wrap: before.wrap, unwrap: before.unwrap }, 'refused, so no key was wrapped or unwrapped');

  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'run', items: await versionItems(items.slice(0, 1)) })).ok, true);
  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'run', items: await versionItems(items.slice(0, 1)) })).ok, true);
  assert.equal(code(await w.vault.unwrap({ principal: ADA, purpose: 'run', items: await versionItems(items.slice(0, 1)) })), 'bulk_limit');
  assert.equal(seen.unwrap, before.unwrap + 2, 'past the bulk limit, nothing reaches the KEK either');

  // With a key service, each call that reaches it is announced first, and a
  // refused one is not: its refusal is all there is.
  const intents = (await vaultLog(w)).filter((entry) => entry.action === 'key.intent' && entry.actor === ADA);
  assert.deepEqual(intents.map((entry) => entry.detail.operation), ['secret.read', 'secret.read']);
});

test('a key service that cannot answer fails the call, with each key it was asked for on the record', async () => {
  const { keks, seen } = service();
  const w = await world({ keks });
  await member(w, ADA, [[w.dev, 'viewer']]);
  const secret = await w.secret(w.dev);
  const items = [{ secret, wrapped: await wrapped(w, secret) }];
  seen.down = true;
  await assert.rejects(w.vault.unwrap({ principal: ADA, purpose: 'run', items: await versionItems(items) }), KekUnavailableError);
  const entries = (await vaultLog(w)).filter((entry) => entry.actor === ADA);
  assert.deepEqual(
    entries.map((entry) => [entry.action, entry.outcome, entry.code]),
    [['key.intent', 'allow', null], ['secret.read', 'refuse', 'kms_unavailable']],
    'the intent, and the outcome: no key released, none to count against the bulk limit',
  );

  seen.down = false;
  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'run', items: await versionItems(items) })).ok, true, 'and the next call goes through');
});

test('a key service failing part of a batch leaves each key\'s outcome, and the keys it opened are withheld', async () => {
  // Review F5: a KMS failure halfway through a batch left no record of the keys KMS did open.
  const { keks, seen } = service();
  const w = await world({ keks });
  await member(w, ADA, [[w.dev, 'viewer']]);
  const secrets = [await w.secret(w.dev, 'A'), await w.secret(w.dev, 'B'), await w.secret(w.dev, 'C')];
  const items = await Promise.all(secrets.map(async (secret) => ({ secret, wrapped: await wrapped(w, secret) })));
  seen.failing.add(secrets[1].secretId);
  seen.opened.length = 0;

  await assert.rejects(w.vault.unwrap({ principal: ADA, purpose: 'run', items: await versionItems(items) }), /did not answer for 1 of 3 keys/);
  const entries = (await vaultLog(w)).filter((entry) => entry.actor === ADA);
  // One entry per outcome at the place: each lists its keys, by their item of the intent.
  const listed = (entry: (typeof entries)[number]) =>
    (entry.detail.secrets as { subject: string; item: number }[] | undefined)?.map((key) => [key.item, key.subject]) ?? [[entry.detail.item, entry.subject]];
  assert.deepEqual(
    entries.map((entry) => [entry.action, entry.code, entry.action === 'secret.read' ? listed(entry) : null]),
    [
      ['key.intent', null, null],
      ['secret.read', 'withheld', [[0, items[0].secret.path], [2, items[2].secret.path]]],
      ['secret.read', 'kms_unavailable', [[1, items[1].secret.path]]],
    ],
  );
  assert.deepEqual(
    (entries[0].detail.keys as { subject: string }[]).map((key) => key.subject),
    items.map((item) => item.secret.path),
  );
  assert.equal(seen.opened.length, 2);
  assert.ok(seen.opened.every((key) => key.equals(Buffer.alloc(32))), 'the keys KMS opened are wiped, not released');
});

test('through a key service, a read of several logs its intent, then one entry of outcomes for the place, each key its item', async () => {
  const { keks } = service();
  const w = await world({ keks });
  await member(w, ADA, [[w.dev, 'viewer']]);
  const secrets = [await w.secret(w.dev, 'A'), await w.secret(w.dev, 'B'), await w.secret(w.dev, 'C')];
  const items = await Promise.all(secrets.map(async (secret) => ({ secret, wrapped: await wrapped(w, secret) })));
  assert.ok((await w.vault.unwrap({ principal: ADA, purpose: 'run', items: await versionItems(items) })).ok);

  const entries = (await vaultLog(w)).filter((entry) => entry.actor === ADA);
  assert.deepEqual(entries.map((entry) => [entry.action, entry.outcome]), [['key.intent', 'allow'], ['secret.read', 'allow']]);
  const [intent, read] = entries as [(typeof entries)[number], (typeof entries)[number]];
  assert.equal(read.detail.relatedSeq, String(intent.seq));
  assert.equal(read.detail.intent, intent.detail.intent);
  assert.deepEqual((read.detail.secrets as { item: number; subject: string }[]).map((key) => [key.item, key.subject]), secrets.map((secret, i) => [i, secret.path]));
  // Every key of the intent is accounted for, in the one entry: no batch is left pending.
  const verified = await w.vault.verifyLog({});
  assert.ok(verified.ok && verified.pending === undefined, JSON.stringify(verified));
});

test('a key service past the budget is cancelled, and opened keys are wiped', async () => {
  const { keks, seen } = service();
  const w = await world({ keks }, { keyBudgetMs: 100 });
  await member(w, ADA, [[w.dev, 'viewer']]);
  const [fast, slow] = [await w.secret(w.dev, 'FAST'), await w.secret(w.dev, 'SLOW')];
  const items = [{ secret: fast, wrapped: await wrapped(w, fast) }, { secret: slow, wrapped: await wrapped(w, slow) }];
  seen.hanging.add(slow.secretId);
  seen.opened.length = 0;

  await assert.rejects(w.vault.unwrap({ principal: ADA, purpose: 'run', items: await versionItems(items) }), KekUnavailableError);
  const outcomes = (await vaultLog(w)).filter((entry) => entry.action === 'secret.read' && entry.actor === ADA);
  assert.deepEqual(outcomes.map((entry) => entry.code), ['withheld', 'kms_uncertain']);
  assert.equal(seen.opened.length, 1, 'the slow operation was cancelled');
  assert.ok(seen.opened.every((key) => key.equals(Buffer.alloc(32))), 'and was wiped as it came');
});

test('a provider of a deployment\'s own refuses a key with the KekBadClaimError @coffre/vault exports', async () => {
  const inner = LocalKekProvider.generate('test-kek-1');
  let refusing = false;
  const own: KekProvider = {
    provider: inner.provider,
    keyId: inner.keyId,
    keyVersion: inner.keyVersion,
    wrap: (key, ctx) => inner.wrap(key, ctx),
    unwrap: (wrapped, ctx) => (refusing ? Promise.reject(new ExportedBadClaim('not this key')) : inner.unwrap(wrapped, ctx)),
  };
  const w = await world({ keks: new KekRegistry(own) });
  const secret = await w.secret(w.dev);
  const items = await versionItems([{ secret, wrapped: await wrapped(w, secret) }]);
  refusing = true;
  const read = await w.vault.unwrap({ principal: ROOT, purpose: 'reveal', items });
  assert.equal(!read.ok && read.refusal.code, 'bad_claim', 'refused as a claim, not failed as a fault');
});

test('a key service failing for its own reasons fails the call, and is no verdict on the claim', async () => {
  const inner = LocalKekProvider.generate('test-kek-1');
  const broken: KekProvider = {
    provider: inner.provider,
    keyId: inner.keyId,
    keyVersion: inner.keyVersion,
    wrap: async () => {
      throw new Error('the key policy forbids Encrypt');
    },
    unwrap: (wrapped, ctx) => inner.unwrap(wrapped, ctx),
  };
  // Its check value, recorded while the key service still encrypted.
  const before = await world({ keks: new KekRegistry(inner) });
  await wrapped(before, await before.secret(before.dev));
  const w = await world({ keks: new KekRegistry(broken) });
  const secret = await w.secret(w.dev);
  await assert.rejects(
    w.vault.wrap({ principal: ROOT, items: [{ secret, key: randomBytes(32).toString('base64') }] }),
    /the key policy forbids Encrypt/,
  );
  assert.deepEqual(
    (await vaultLog(w)).filter((entry) => entry.action === 'key.wrap').map((entry) => entry.code),
    [null, 'key_error'],
    'the unexpected fault is recorded before it is rethrown',
  );
});

test('an expired grant refuses with its own code', async () => {
  const w = await world();
  await member(w, ADA, [[w.dev, 'viewer', Date.now() + 60_000]]);
  const secret = await w.secret(w.dev);
  const items = [{ secret, wrapped: await wrapped(w, secret) }];
  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: await versionItems(items) })).ok, true);
  w.clock.offset += 61_000;
  const result = await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: await versionItems(items) });
  assert.equal(!result.ok && result.refusal.code, 'expired');
  assert.deepEqual((await w.vault.access(ADA)).grants, []);
});

test('a read that waits for the log\'s head is decided as of when it holds it: a grant that lapsed meanwhile refuses', postgresOnly('SQLite runs one writer at a time'), async () => {
  const w = await world();
  await member(w, ADA, [[w.dev, 'viewer', Date.now() + 1_500]]);
  const secret = await w.secret(w.dev);
  const items = await versionItems([{ secret, wrapped: await wrapped(w, secret) }]);
  // Another transaction holds the head past the grant's end, then commits writing nothing: the read waits for it.
  const other = await db.connect();
  let holding!: () => void;
  const held = new Promise<void>((resolve) => (holding = resolve));
  const holder = other.transaction(async (tx) => {
    await lockLogHead(tx);
    holding();
    await sleep(2_500);
  });
  await held;
  const result = await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items });
  await holder;
  assert.equal(!result.ok && result.refusal.code, 'expired');
});

test('the bulk limit counts keys per principal over a rolling window', async () => {
  const w = await world({ bulkLimit: { count: 5, windowMs: 60_000 } });
  await member(w, ADA, [[w.dev, 'viewer']]);
  await member(w, BOB, [[w.dev, 'viewer']]);
  const secrets = [await w.secret(w.dev), await w.secret(w.dev), await w.secret(w.dev)];
  const items = await Promise.all(secrets.map(async (secret) => ({ secret, wrapped: await wrapped(w, secret) })));

  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'run', items: await versionItems(items) })).ok, true);
  const over = await w.vault.unwrap({ principal: ADA, purpose: 'run', items: await versionItems(items) });
  assert.equal(!over.ok && over.refusal.code, 'bulk_limit');
  // Refusals do not count, and neither does anyone else's reading.
  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'run', items: await versionItems(items.slice(0, 2)) })).ok, true);
  assert.equal((await w.vault.unwrap({ principal: BOB, purpose: 'run', items: await versionItems(items) })).ok, true);
  const stillOver = await w.vault.unwrap({ principal: ADA, purpose: 'run', items: await versionItems(items.slice(0, 1)) });
  assert.equal(!stillOver.ok && stillOver.refusal.code, 'bulk_limit');

  w.clock.offset += 60_001;
  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'run', items: await versionItems(items) })).ok, true);
  // Each refused read is one entry, its keys listed.
  assert.deepEqual((await vaultLog(w)).filter((entry) => entry.code === 'bulk_limit').map((entry) => (entry.detail.secrets as unknown[] | undefined)?.length ?? 1), [3, 1]);
});

test('two instances share one log, one bulk limit and one set of generations', async () => {
  // Review F2: a second Durable Object loaded the same KEK with an empty log
  // and a fresh bulk counter. Every instance now decides in the database.
  const w = await world({ bulkLimit: { count: 5, windowMs: 60_000 } });
  const other = await w.twin();
  await member(w, ADA, [[w.dev, 'viewer']]);
  const secret = await w.secret(w.dev);
  const items = [{ secret, wrapped: await wrapped(w, secret) }];

  const reads = await Promise.all(
    Array.from({ length: 12 }, async (_, i) => (i % 2 === 0 ? w.vault : other).unwrap({ principal: ADA, purpose: 'run', items: await versionItems(items) })),
  );
  assert.equal(reads.filter((read) => read.ok).length, 5, 'exactly the limit, across both');
  assert.ok(reads.filter((read) => !read.ok).every((read) => !read.ok && read.refusal.code === 'bulk_limit'));

  assert.equal((await other.remove({ actor: ROOT, principal: ADA })).ok, true);
  assert.deepEqual(
    [(await w.vault.access(ADA)).status, (await w.vault.access(ADA)).generation],
    ['removed', 1],
    'one instance removes, the other sees it at once',
  );
  assert.equal((await w.vault.verifyLog({})).ok, true);
});

test('two processes on one SQLite file share the bulk limit exactly', { skip: ENGINE !== 'sqlite' && 'two processes on one file is SQLite\'s case' }, async () => {
  // Postgres serialises a member's reads on their row; SQLite on its file's
  // write lock, which other processes wait for, as a second server would.
  const kek = randomBytes(32);
  const bulkLimit = { count: 6, windowMs: 60_000 };
  const w = await world({ keks: new KekRegistry(new LocalKekProvider(kek, 'test-kek-1')), bulkLimit });
  await member(w, ADA, [[w.dev, 'viewer']]);
  const secret = await w.secret(w.dev);
  const input = { principal: ADA, purpose: 'run' as const, items: await versionItems([{ secret, wrapped: await wrapped(w, secret) }]) };

  const reader = spawn(
    process.execPath,
    [
      '--conditions=coffre:source',
      fileURLToPath(new URL('reader.ts', import.meta.url)),
      JSON.stringify({ url: process.env.COFFRE_TEST_DATABASE_URL, kek: kek.toString('base64'), signingKey: SIGNING_KEY.toString('base64'), bulkLimit, input, reads: 6 }),
    ],
    { stdio: ['ignore', 'pipe', 'inherit'] },
  );
  const theirs = new Promise<string[]>((resolve, reject) => {
    let out = '';
    reader.stdout.on('data', (chunk: Buffer) => (out += chunk));
    reader.once('exit', (code) => (code === 0 ? resolve(JSON.parse(out) as string[]) : reject(new Error(`the reader exited ${code}`))));
  });
  const ours = Promise.all(Array.from({ length: 6 }, () => w.vault.unwrap(input))).then((outcomes) =>
    outcomes.map((outcome) => (outcome.ok ? 'ok' : outcome.refusal.code)),
  );
  const all = [...(await theirs), ...(await ours)];
  assert.equal(all.filter((outcome) => outcome === 'ok').length, 6, JSON.stringify(all));
  assert.equal(all.filter((outcome) => outcome === 'bulk_limit').length, 6);
});

test('a removal waits for a read in flight at the key service, and the next read is refused before it', async () => {
  const { keks, seen } = service({ delayMs: 300 });
  const w = await world({ keks });
  const other = await w.twin();
  await member(w, ADA, [[w.dev, 'viewer']]);
  const secret = await w.secret(w.dev);
  const items = [{ secret, wrapped: await wrapped(w, secret) }];

  const read = w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: await versionItems(items) });
  await sleep(150);
  const asked = seen.unwrap;
  const removal = other.remove({ actor: ROOT, principal: ADA });
  const [released, removed] = await Promise.all([read, removal]);
  assert.equal(released.ok, true, 'the read in flight finishes');
  assert.equal(removed.ok, true);
  const log = await vaultLog(w);
  const release = log.findLast((entry) => entry.action === 'secret.read' && entry.outcome === 'allow')!;
  const removal_ = log.find((entry) => entry.action === 'member.remove')!;
  assert.ok(release.seq < removal_.seq, 'and is logged before the removal, which waited for it');

  const next = await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: await versionItems(items) });
  assert.equal(!next.ok && next.refusal.code, 'removed');
  assert.equal(seen.unwrap, asked, 'refused before the key service is asked');
});

// --- the KEK -------------------------------------------------------------------

/** The vault's records of a KEK's check value. */
async function keyChecks(w: World) {
  return (await vaultLog(w)).filter((entry) => entry.action === 'key.check');
}

const aKey = () => randomBytes(32).toString('base64');

test('a vault checks its KEK before its first key operation, against a check value recorded once', async () => {
  const keks = new KekRegistry(LocalKekProvider.generate('test-kek-1'));
  const w = await world({ keks });
  await member(w, ADA, [[w.dev, 'viewer']]);
  const secret = await w.secret(w.dev);
  const items = await versionItems([{ secret, wrapped: await wrapped(w, secret) }]);
  // A fresh database holds nothing to prove the KEK on: its check value is recorded.
  const [check] = await keyChecks(w);
  assert.deepEqual(
    [check.actor, check.detail.kekProvider, check.detail.kekId, check.detail.proof],
    ['system:vault', keks.primary.provider, 'test-kek-1', null],
  );

  // Another process with the same KEK opens the check value, and records nothing more.
  const twin = await w.twin();
  assert.equal((await twin.unwrap({ principal: ADA, purpose: 'reveal', items })).ok, true);
  assert.equal((await keyChecks(w)).length, 1);

  // A vault given another key under the same id refuses every key operation, saying why, naming the KEK and no key.
  const misled = await fresh();
  const read = await misled.unwrap({ principal: ADA, purpose: 'reveal', items });
  assert.deepEqual(!read.ok && read.refusal, {
    code: 'wrong_kek',
    message: "the vault key test-kek-1, kek or previousKeks in the vault's config, is not the one that wrapped these values",
  });
  const write = await misled.wrap({ principal: ROOT, items: [{ secret, key: aKey() }] });
  assert.equal(!write.ok && write.refusal.code, 'wrong_kek');
  assert.deepEqual(
    (await vaultLog(w)).filter((entry) => entry.code === 'wrong_kek').map((entry) => entry.action),
    ['secret.read', 'key.wrap'],
  );
  // Its scheduled checkpoint is refused too, which readiness shows.
  const checkpoint = await misled.checkpoint();
  assert.equal(!checkpoint.ok && checkpoint.refusal.code, 'wrong_kek');

  // The right KEK goes on working.
  assert.equal((await twin.unwrap({ principal: ADA, purpose: 'reveal', items })).ok, true);
});

test('a KEK with no check value yet is proved on the keys it wrapped before one is recorded', async () => {
  const keks = new KekRegistry(LocalKekProvider.generate('test-kek-1'));
  const w = await world({ keks });
  const secret = await w.secret(w.dev);
  const sealed = await wrapped(w, secret);
  const { auditLog, secretVersions } = tablesOf(db.owner);
  await db.owner.insert(secretVersions).values({
    id: randomUUID(), secretId: secret.secretId, version: 1, envelopeVersion: 1, ciphertext: Buffer.alloc(8), iv: Buffer.alloc(12), authTag: Buffer.alloc(16),
    wrappedDek: Buffer.from(sealed.bytes, 'base64'), kekProvider: sealed.kekProvider, kekId: sealed.kekId, kekVersion: sealed.kekVersion,
    createdBy: ROOT,
  });
  // As data written before check values were.
  await withLogUnlocked(db.owner, (owned) => owned.delete(auditLog).where(eq(auditLog.action, 'key.check')));

  const write = await (await fresh()).wrap({ principal: ROOT, items: [{ secret, key: aKey() }] });
  assert.equal(!write.ok && write.refusal.code, 'wrong_kek');
  assert.deepEqual(await keyChecks(w), []);

  assert.equal((await (await w.twin()).wrap({ principal: ROOT, items: [{ secret, key: aKey() }] })).ok, true);
  const [check] = await keyChecks(w);
  assert.deepEqual(check.detail.proof, { secretId: secret.secretId, version: 1 }, 'the key it opened to prove it is on the record');
});

test('a key service that cannot answer leaves the KEK unchecked, and the next call asks again', async () => {
  const remote = service();
  const w = await world({ keks: remote.keks });
  await member(w, ADA, []);
  const secret = await w.secret(w.dev);
  remote.seen.down = true;
  await assert.rejects(w.vault.wrap({ principal: ROOT, items: [{ secret, key: aKey() }] }), KekUnavailableError);
  assert.deepEqual(await keyChecks(w), []);
  // Unchecked is no verdict: the scheduled checkpoint goes on.
  assert.equal((await w.vault.checkpoint()).ok, true);

  remote.seen.down = false;
  assert.equal((await w.vault.wrap({ principal: ROOT, items: [{ secret, key: aKey() }] })).ok, true);
  assert.equal((await keyChecks(w)).length, 1);
});

test('a removed member is refused everything until admitted again, with no grants', async () => {
  const w = await world();
  await member(w, ADA, [[w.dev, 'viewer'], [null, 'access-manager']]);
  const secret = await w.secret(w.dev);
  const items = [{ secret, wrapped: await wrapped(w, secret) }];

  const removed = await w.vault.remove({ actor: ROOT, principal: ADA });
  assert.ok(removed.ok);
  assert.deepEqual(removed.revoked.map((grant) => grant.role).sort(), ['access-manager', 'viewer']);
  const read = await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: await versionItems(items) });
  assert.equal(!read.ok && read.refusal.code, 'removed');
  const manage = await w.vault.setAccess({
    actor: ADA,
    principal: BOB,
    changes: [{ projectId: w.project, environmentId: null, role: 'viewer', expiresAt: null }],
  });
  assert.equal(!manage.ok && manage.refusal.code, 'not_allowed');
  const regrant = await w.vault.setAccess({
    actor: ROOT,
    principal: ADA,
    changes: [{ projectId: w.project, environmentId: w.dev, role: 'viewer', expiresAt: null }],
  });
  assert.equal(!regrant.ok && regrant.refusal.code, 'removed');

  assert.deepEqual(await w.vault.admit({ actor: ROOT, principal: ADA }), { ok: true, created: true, role: 'member', scope: EVERYWHERE, generation: 1 });
  const access = await w.vault.access(ADA);
  assert.equal(access.status, 'active');
  assert.deepEqual(access.grants, []);
  const again = await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: await versionItems(items) });
  assert.equal(!again.ok && again.refusal.code, 'no_grant');
});

test('access is managed with the same rules as the app, and the last Owner stays one', async () => {
  const w = await world(UNNAMED);
  await member(w, ADA, [[null, 'access-manager']]);
  await member(w, BOB, []);
  const change = (role: string | null, environmentId: string | null = w.dev) => ({
    projectId: w.project,
    environmentId,
    role: role as 'viewer' | null,
    expiresAt: null,
  });

  const granted = await w.vault.setAccess({ actor: ADA, principal: BOB, changes: [change('developer'), change('viewer', null)] });
  assert.deepEqual(granted, { ok: true, changes: ['created', 'created'] });
  const same = await w.vault.setAccess({ actor: ADA, principal: BOB, changes: [change('developer'), change('maintainer', null)] });
  assert.deepEqual(same, { ok: true, changes: ['unchanged', 'updated'] });

  // One bad change refuses the lot.
  const mixed = await w.vault.setAccess({ actor: ADA, principal: BOB, changes: [change(null), change('access-manager')] });
  assert.equal(!mixed.ok && mixed.refusal.code, 'invalid');
  assert.equal((await w.vault.access(BOB)).grants.length, 2);
  // A place must be one: an environment of the project it is named with.
  const elsewhere = await newProject(db.owner);
  const misplaced = await w.vault.setAccess({ actor: ROOT, principal: BOB, changes: [{ ...change('viewer'), projectId: elsewhere }] });
  assert.equal(!misplaced.ok && misplaced.refusal.code, 'invalid');

  const byBob = await w.vault.setAccess({ actor: BOB, principal: ADA, changes: [change(null, null)] });
  assert.equal(!byBob.ok && byBob.refusal.code, 'not_allowed');
  const toRoot = await w.vault.setAccess({ actor: ROOT, principal: ROOT, changes: [change('viewer')] });
  assert.equal(!toRoot.ok && toRoot.refusal.code, 'not_allowed');
  const removeRoot = await w.vault.remove({ actor: ROOT, principal: ROOT });
  assert.deepEqual(!removeRoot.ok && removeRoot.refusal, { code: 'last_owner', message: "you're the last Owner of the whole instance: make someone else an Owner first" });
  const stranger = await w.vault.setAccess({ actor: ROOT, principal: 'user:eve@acme.example', changes: [change('viewer')] });
  assert.equal(!stranger.ok && stranger.refusal.code, 'not_a_member');
  const notOwner = await w.vault.admit({ actor: ADA, principal: 'user:eve@acme.example' });
  assert.equal(!notOwner.ok && notOwner.refusal.code, 'not_allowed');
  const ownerToken = await w.vault.admit({ actor: ROOT, principal: 'token:ci', role: 'admin' });
  assert.equal(!ownerToken.ok && ownerToken.refusal.code, 'invalid');

  const revoked = await w.vault.setAccess({ actor: ADA, principal: BOB, changes: [change(null), change(null, null)] });
  assert.deepEqual(revoked, { ok: true, changes: ['revoked', 'revoked'] });
  assert.deepEqual((await w.vault.access(BOB)).grants, []);
});

// --- instance roles --------------------------------------------------------------

/** Each secret's first version, stored once. */
const firstVersions = new Map<string, Promise<{ secretVersionId: string }[]>>();

/** Read and write one secret as `principal`: what each of the two came to. */
async function readWrite(w: World, principal: string, secret: SecretRef): Promise<[string, string]> {
  if (!firstVersions.has(secret.secretId)) firstVersions.set(secret.secretId, wrapped(w, secret).then((stored) => versionItems([{ secret, wrapped: stored }])));
  const read = await w.vault.unwrap({ principal, purpose: 'reveal', items: await firstVersions.get(secret.secretId)! });
  const write = await w.vault.wrap({ principal, items: [{ secret: { ...secret, version: secret.version + 1 }, key: randomBytes(32).toString('base64') }] });
  return [read.ok ? 'ok' : read.refusal.code, write.ok ? 'ok' : write.refusal.code];
}

/** A project made now, with a dev and a prod of its own, and a secret in each. */
async function laterProject(): Promise<{ project: string; dev: SecretRef; prod: SecretRef; devId: string; prodId: string }> {
  const { environments, secrets } = tablesOf(db.owner);
  const project = await newProject(db.owner);
  const [devId, prodId] = [randomUUID(), randomUUID()];
  await db.owner.insert(environments).values([
    { id: devId, projectId: project, slug: 'dev', name: 'Development' },
    { id: prodId, projectId: project, slug: 'prod', name: 'Production' },
  ]);
  const secretIn = async (environmentId: string): Promise<SecretRef> => {
    const id = randomUUID();
    await db.owner.insert(secrets).values({ id, projectId: project, environmentId, key: `KEY_${id.slice(0, 8)}` });
    return { projectId: project, environmentId, secretId: id, version: 1, path: `later/${id}` };
  };
  return { project, devId, prodId, dev: await secretIn(devId), prod: await secretIn(prodId) };
}

const DEV_ONLY: Scope = { projects: 'all', environments: { only: ['dev'] } };

test('a person sets up a service account in the vault too: no more than they hold, only one they reach whole, inside the setting', async () => {
  const w = await world();
  const CI = 'token:ci';
  const grant = (actor: string, environmentId: string | null, role: string | null, principal = CI) =>
    w.vault.setAccess({ actor, principal, changes: [{ projectId: w.project, environmentId, role: role as 'viewer' | null, expiresAt: null }] });
  const code = (outcome: { ok: boolean; refusal?: { code: string } }) => (outcome.ok ? 'ok' : outcome.refusal!.code);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA, role: 'developer', scope: DEV_ONLY })).ok);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: BOB })).ok);

  // A person who holds nothing sets up nothing; one who holds dev adds an account, and gives it what she holds there.
  assert.equal(code(await w.vault.admit({ actor: BOB, principal: 'token:bob' })), 'not_allowed');
  assert.ok((await w.vault.admit({ actor: ADA, principal: CI })).ok);
  assert.equal(code(await w.vault.admit({ actor: ADA, principal: 'user:eve@acme.example' })), 'not_allowed', 'never a person');
  assert.equal(code(await grant(ADA, w.dev, 'developer')), 'ok');
  assert.equal(code(await grant(ADA, w.prod, 'viewer')), 'not_allowed', 'prod, which she does not hold');
  assert.equal(code(await grant(ADA, null, 'viewer')), 'not_allowed', 'the project, which reaches prod');
  assert.equal(code(await grant(ADA, w.dev, 'auditor')), 'not_allowed', 'a role she does not hold');
  assert.equal(code(await grant(ADA, w.dev, 'viewer', BOB)), 'not_allowed', 'never to a person');

  // Once it holds prod, it is out of her hands: no change, no removal.
  assert.equal(code(await grant(ROOT, w.prod, 'viewer')), 'ok');
  assert.equal(code(await grant(ADA, w.dev, 'viewer')), 'not_allowed');
  assert.equal(code(await grant(ADA, w.dev, null)), 'not_allowed');
  assert.equal(code(await w.vault.remove({ actor: ADA, principal: CI })), 'not_allowed');
  assert.equal(code(await grant(ROOT, w.prod, null)), 'ok');
  assert.equal(code(await grant(ADA, w.dev, 'viewer')), 'ok');

  // The setting: only who runs the instance changes it, logged with what it was; dev kept to Admins, she sets up nothing there.
  const PROD_ONLY: Scope = { projects: 'all', environments: { only: ['prod'] } };
  assert.equal(code(await w.vault.setSettings({ actor: ADA, settings: { serviceAccounts: PROD_ONLY } })), 'not_allowed');
  assert.deepEqual(await w.vault.setSettings({ actor: ROOT, settings: { serviceAccounts: PROD_ONLY } }), { ok: true, settings: { serviceAccounts: PROD_ONLY } });
  assert.deepEqual(await w.vault.settings(), { serviceAccounts: PROD_ONLY });
  assert.equal(code(await grant(ADA, w.dev, 'developer')), 'not_allowed');
  assert.equal(code(await w.vault.remove({ actor: ADA, principal: CI })), 'not_allowed');
  assert.equal(code(await w.vault.admit({ actor: ADA, principal: 'token:ci-2' })), 'not_allowed');
  const changes = (await vaultLog(w)).filter((entry) => entry.action === 'settings.change');
  assert.deepEqual(changes.map((entry) => [entry.actor, entry.outcome]), [[ADA, 'refuse'], [ROOT, 'allow']]);
  assert.deepEqual(changes[1]!.detail.previous, { serviceAccounts: EVERYWHERE });

  // A setting written in the vault's name around it is passed over.
  const { auditLog, auditChainHead } = tablesOf(db.owner);
  const [head] = await db.owner.select().from(auditChainHead);
  const fields = {
    seq: head.nextSeq, author: 'vault' as const, keyId: VAULT_KEY.keyId, occurredAt: Date.now(), actor: ROOT,
    action: 'settings.change', decision: 'allow', code: null, subjectPrincipal: null, projectId: null, environmentId: null,
    secretId: null, secretVersionId: null, operationId: null, requestId: null, sourceIp: null, relatedSeq: null,
    metadata: JSON.stringify({ serviceAccounts: EVERYWHERE }),
  };
  const mac = Buffer.alloc(32, 7);
  const hash = entryHash(head.headHash, fields, mac);
  await db.owner.insert(auditLog).values({ ...fields, prevHash: head.headHash, mac, hash });
  await db.owner.update(auditChainHead).set({ nextSeq: head.nextSeq + 1n, headHash: hash });
  assert.deepEqual(await w.vault.settings(), { serviceAccounts: PROD_ONLY });
  assert.equal(code(await grant(ADA, w.dev, 'developer')), 'not_allowed');
});

/**
 * `count` entries in the vault's name, linked to the chain, each with a
 * made-up MAC: what anyone who can insert rows can write.
 */
async function forgeEntries(count: number, entry: { action: string; actor?: string; code?: string; subjectPrincipal?: string; metadata?: string }): Promise<void> {
  const { auditLog, auditChainHead } = tablesOf(db.owner);
  const [head] = await db.owner.select().from(auditChainHead);
  const mac = Buffer.alloc(32, 7);
  let [seq, prevHash] = [head.nextSeq, head.headHash];
  const rows = [];
  for (let i = 0; i < count; i += 1) {
    const fields = {
      seq, author: 'vault' as const, keyId: VAULT_KEY.keyId, occurredAt: Date.now(), actor: entry.actor ?? ROOT,
      action: entry.action, decision: entry.action === 'vault.tampered' ? 'deny' : 'allow', code: entry.code ?? null,
      subjectPrincipal: entry.subjectPrincipal ?? null, projectId: null, environmentId: null, secretId: null, secretVersionId: null,
      operationId: null, requestId: null, sourceIp: null, relatedSeq: null, metadata: entry.metadata ?? '{}',
    };
    const hash = entryHash(prevHash, fields, mac);
    rows.push({ ...fields, prevHash, mac, hash });
    [seq, prevHash] = [seq + 1n, hash];
  }
  for (let i = 0; i < rows.length; i += 100) await db.owner.insert(auditLog).values(rows.slice(i, i + 100));
  await db.owner.update(auditChainHead).set({ nextSeq: seq, headHash: prevHash });
}

test('settings forged in the vault\'s name above its own are passed over and reported; too many to see past, or none of its own, close the setting', async () => {
  const w = await world();
  const code = (outcome: { ok: boolean; refusal?: { code: string } }) => (outcome.ok ? 'ok' : outcome.refusal!.code);
  const CLOSED: Scope = { projects: { only: [] }, environments: 'all' };
  const forgedSetting = { action: 'settings.change', metadata: JSON.stringify({ serviceAccounts: EVERYWHERE }) };
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA, role: 'developer', scope: DEV_ONLY })).ok);

  // No setting at all is the default; one the vault did not write, with none of its own, closes it.
  assert.deepEqual(await w.vault.settings(), { serviceAccounts: EVERYWHERE });
  await forgeEntries(1, forgedSetting);
  assert.deepEqual(await w.vault.settings(), { serviceAccounts: CLOSED });
  assert.equal(code(await w.vault.admit({ actor: ADA, principal: 'token:ci' })), 'not_allowed');

  // Its own, under more forged ones than a page holds, still holds.
  assert.ok((await w.vault.setSettings({ actor: ROOT, settings: { serviceAccounts: DEV_ONLY } })).ok);
  await forgeEntries(33, forgedSetting);
  assert.deepEqual(await w.vault.settings(), { serviceAccounts: DEV_ONLY });
  const give = (environmentId: string) => w.vault.setAccess({ actor: ADA, principal: 'token:ci', changes: [{ projectId: w.project, environmentId, role: 'viewer', expiresAt: null }] });
  assert.equal(code(await w.vault.admit({ actor: ADA, principal: 'token:ci' })), 'ok');
  assert.equal(code(await give(w.dev)), 'ok');
  assert.equal(code(await give(w.prod)), 'not_allowed');
  const reports = await tamperings(w);
  assert.equal(reports.length, 34);
  assert.ok(reports.every(([subject, fault]) => subject === null && fault === 'forged_entry'));

  // More than the vault reads back: closed, never the default.
  await forgeEntries(32 * 32, forgedSetting);
  assert.deepEqual(await w.vault.settings(), { serviceAccounts: CLOSED });
  assert.equal(code(await w.vault.admit({ actor: ADA, principal: 'token:ci-2' })), 'not_allowed');
  assert.equal(code(await give(w.dev)), 'not_allowed');
  assert.equal(code(await w.vault.remove({ actor: ADA, principal: 'token:ci' })), 'not_allowed');
});

test('a person brings back a service account they removed, never one someone else did', async () => {
  const w = await world();
  const code = (outcome: { ok: boolean; refusal?: { code: string; message: string } }) => (outcome.ok ? 'ok' : outcome.refusal!.code);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA, role: 'developer', scope: DEV_ONLY })).ok);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: BOB, role: 'developer', scope: DEV_ONLY })).ok);
  for (const account of ['token:hers', 'token:theirs']) assert.equal(code(await w.vault.admit({ actor: ADA, principal: account })), 'ok');

  assert.equal(code(await w.vault.remove({ actor: ADA, principal: 'token:hers' })), 'ok');
  assert.equal(code(await w.vault.remove({ actor: ROOT, principal: 'token:theirs' })), 'ok');
  assert.equal(code(await w.vault.admit({ actor: BOB, principal: 'token:hers' })), 'not_allowed', 'not one Ada removed');
  const refused = await w.vault.admit({ actor: ADA, principal: 'token:theirs' });
  assert.match(refused.ok ? '' : refused.refusal.message, /^user:root@acme\.example removed this service account/);
  assert.deepEqual(await w.vault.admit({ actor: ADA, principal: 'token:hers' }), { ok: true, created: true, role: 'member', scope: EVERYWHERE, generation: 1 });
  assert.equal(code(await w.vault.admit({ actor: ROOT, principal: 'token:theirs' })), 'ok', 'who runs the instance brings back any');
});

test('a service account admitted with its first grant is one decision: a grant refused admits nobody', async () => {
  const w = await world();
  const code = (outcome: { ok: boolean; refusal?: { code: string } }) => (outcome.ok ? 'ok' : outcome.refusal!.code);
  const admitWith = (actor: string, principal: string, environmentId: string | null, role: string) =>
    w.vault.setAccess({ actor, principal, admit: true, changes: [{ projectId: w.project, environmentId, role: role as 'viewer', expiresAt: null }] });
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA, role: 'developer', scope: DEV_ONLY })).ok);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: BOB })).ok);

  // Without `admit`, as an older vault answers it too: no member, no grant.
  assert.equal(code(await w.vault.setAccess({ actor: ROOT, principal: 'token:plain', changes: [{ projectId: w.project, environmentId: w.dev, role: 'viewer', expiresAt: null }] })), 'not_a_member');
  assert.deepEqual(await admitWith(ADA, 'token:ci', w.dev, 'developer'), {
    ok: true,
    changes: ['created'],
    admitted: { created: true, role: 'member', scope: EVERYWHERE, generation: 0 },
  });
  const access = await w.vault.access('token:ci');
  assert.deepEqual([access.status, access.by, access.grants.map((grant) => grant.role)], ['active', ADA, ['developer']]);
  const entries = (await vaultLog(w)).filter((entry) => entry.subject === 'token:ci');
  assert.deepEqual(entries.map((entry) => [entry.action, entry.outcome]), [['member.add', 'allow'], ['access.grant', 'allow']]);

  // Refused, whoever refuses: nothing admitted, and the refusal logged.
  assert.equal(code(await admitWith(ADA, 'token:prod', w.prod, 'viewer')), 'not_allowed', 'prod, which she does not hold');
  assert.equal(code(await admitWith(ADA, 'token:auditor', w.dev, 'auditor')), 'not_allowed', 'a role she does not hold');
  assert.equal(code(await admitWith(BOB, 'token:bob', w.dev, 'viewer')), 'not_allowed', 'who holds nothing sets up nothing');
  assert.equal(code(await admitWith(ROOT, 'token:owner', w.dev, 'owner')), 'invalid', 'a role only a project takes');
  assert.equal(code(await admitWith(ROOT, 'user:eve@acme.example', w.dev, 'viewer')), 'invalid', 'never a person');
  for (const principal of ['token:prod', 'token:auditor', 'token:bob', 'token:owner', 'user:eve@acme.example']) {
    assert.equal((await w.vault.access(principal)).status, 'unknown', principal);
  }
  const refused = (await vaultLog(w)).filter((entry) => entry.subject === 'token:bob');
  assert.deepEqual(refused.map((entry) => [entry.action, entry.outcome]), [['member.add', 'refuse']]);

  // One already a member is granted as `setAccess` grants it, and one removed comes back as `admit` brings it.
  assert.deepEqual(await admitWith(ADA, 'token:ci', w.dev, 'viewer'), { ok: true, changes: ['updated'] });
  assert.ok((await w.vault.remove({ actor: ROOT, principal: 'token:ci' })).ok);
  assert.equal(code(await admitWith(ADA, 'token:ci', w.dev, 'viewer')), 'not_allowed', 'not one someone else removed');
  assert.equal((await w.vault.access('token:ci')).status, 'removed');
  const back = await admitWith(ROOT, 'token:ci', w.dev, 'viewer');
  assert.deepEqual(back.ok && back.admitted, { created: true, role: 'member', scope: EVERYWHERE, generation: 1 });
  assert.equal((await w.vault.checkpoint()).ok, true, 'every row seals over what the log says');
});

test('a service account whose row was deleted is refused, under forged entries about it too, and never comes back from nothing', async () => {
  const w = await world();
  const { vaultMembers } = tablesOf(db.owner);
  const code = (outcome: { ok: boolean; refusal?: { code: string } }) => (outcome.ok ? 'ok' : outcome.refusal!.code);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA, role: 'developer', scope: DEV_ONLY })).ok);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: 'token:ci' })).ok);
  assert.ok((await w.vault.remove({ actor: ROOT, principal: 'token:ci' })).ok);

  // Root removed it; its row deleted, the log still says so, under a page of forged entries and under more than the vault reads back.
  await db.owner.delete(vaultMembers).where(eq(vaultMembers.principal, 'token:ci'));
  assert.equal((await w.vault.access('token:ci')).status, 'tampered');
  await forgeEntries(32, { action: 'member.add', subjectPrincipal: 'token:ci' });
  assert.equal(code(await w.vault.admit({ actor: ADA, principal: 'token:ci' })), 'tampered');
  await forgeEntries(32 * 32, { action: 'member.add', subjectPrincipal: 'token:ci' });
  assert.equal(code(await w.vault.admit({ actor: ADA, principal: 'token:ci' })), 'tampered');

  // Started over, it comes back past the removal's generation.
  assert.ok((await w.vault.remove({ actor: ROOT, principal: 'token:ci' })).ok);
  assert.deepEqual(await w.vault.admit({ actor: ROOT, principal: 'token:ci' }), { ok: true, created: true, role: 'member', scope: EVERYWHERE, generation: 2 });

  // Forged entries about one the vault never admitted lock nobody out.
  await forgeEntries(3, { action: 'member.add', subjectPrincipal: 'token:new' });
  assert.deepEqual(await w.vault.admit({ actor: ADA, principal: 'token:new' }), { ok: true, created: true, role: 'member', scope: EVERYWHERE, generation: 0 });
});

test('an instance role reaches every project in its scope, the ones made later too, and grants add to it', async () => {
  const w = await world();
  const { environments } = tablesOf(db.owner);
  assert.deepEqual(await w.vault.admit({ actor: ROOT, principal: ADA, role: 'developer', scope: DEV_ONLY }), {
    ok: true, created: true, role: 'developer', scope: DEV_ONLY, generation: 0,
  });
  assert.ok((await w.vault.admit({ actor: ROOT, principal: BOB, role: 'admin' })).ok);
  const later = await laterProject();

  assert.deepEqual(await readWrite(w, ADA, later.dev), ['ok', 'ok'], 'a project made later, by its slug');
  assert.deepEqual(await readWrite(w, ADA, await w.secret(w.dev)), ['ok', 'ok']);
  assert.deepEqual(await readWrite(w, ADA, later.prod), ['no_grant', 'no_grant'], 'never another environment');
  assert.deepEqual(await readWrite(w, BOB, await w.secret(w.dev)), ['no_grant', 'no_grant'], 'an admin reads no values');
  // A grant reaches past the scope.
  assert.ok((await w.vault.setAccess({ actor: ROOT, principal: ADA, changes: [{ projectId: w.project, environmentId: w.prod, role: 'viewer', expiresAt: null }] })).ok);
  assert.deepEqual(await readWrite(w, ADA, await w.secret(w.prod)), ['ok', 'no_grant']);
  // A dev claimed in another project than its own is no dev at all.
  const misclaimed = await w.vault.wrap({ principal: ADA, items: [{ secret: { ...later.dev, projectId: w.project }, key: randomBytes(32).toString('base64') }] });
  assert.equal(!misclaimed.ok && misclaimed.refusal.code, 'no_grant');

  // The slug is read at each decision: a rename moves the environment in or out.
  await db.owner.update(environments).set({ slug: 'development' }).where(eq(environments.id, later.devId));
  assert.deepEqual(await readWrite(w, ADA, later.dev), ['no_grant', 'no_grant']);
  await db.owner.update(environments).set({ slug: 'dev' }).where(eq(environments.id, later.prodId));
  assert.deepEqual(await readWrite(w, ADA, later.prod), ['ok', 'ok']);

  // What they hold says so, and the log replays it.
  const access = await w.vault.access(ADA);
  assert.deepEqual([access.role, access.scope], ['developer', DEV_ONLY]);
  assert.deepEqual((await w.vault.access(ROOT)).role, 'owner');
  const added = (await vaultLog(w)).find((entry) => entry.action === 'member.add' && entry.subject === ADA);
  assert.deepEqual([added?.detail.role, added?.detail.scope], ['developer', DEV_ONLY]);
  assert.equal((await w.vault.verifyLog({})).ok, true);
});

test('only those who run the instance set roles, never their own, and a scoped admin manages only inside its scope', async () => {
  const w = await world();
  const CAROL = 'user:carol@acme.example';
  const other = await newProject(db.owner);
  const otherEnvironment = await newEnvironment(db.owner, other);
  const at = (projectId: string, environmentId: string | null, role: 'viewer' | 'access-manager' | null = 'viewer') => ({ projectId, environmentId, role, expiresAt: null });
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA, role: 'admin' })).ok);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: BOB, role: 'admin', scope: { projects: { only: [w.project] }, environments: { only: ['dev'] } } })).ok);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: CAROL })).ok);

  // An admin of the whole instance sets someone else's role; nobody sets their own.
  assert.deepEqual(await w.vault.admit({ actor: ADA, principal: CAROL, role: 'developer' }), { ok: true, created: false, role: 'developer', scope: EVERYWHERE, generation: 0 });
  const selfAdmin = await w.vault.admit({ actor: ADA, principal: ADA, role: 'owner' });
  assert.equal(!selfAdmin.ok && selfAdmin.refusal.code, 'not_allowed', 'an admin making itself owner');
  // Admitting oneself as one is changes nothing, and is no change.
  assert.equal((await w.vault.admit({ actor: ADA, principal: ADA, role: 'admin' })).ok, true);

  // A scoped admin sets no role, its own or anyone's, and adds nobody.
  for (const [principal, role, why] of [
    [BOB, 'admin', 'a scoped admin widening itself'],
    [CAROL, 'owner', 'a scoped admin promoting someone'],
    ['user:dan@acme.example', 'member', 'a scoped admin adding someone'],
  ] as const) {
    const result = await w.vault.admit({ actor: BOB, principal, role });
    assert.equal(!result.ok && result.refusal.code, 'not_allowed', why);
  }
  const removing = await w.vault.remove({ actor: BOB, principal: CAROL });
  assert.equal(!removing.ok && removing.refusal.code, 'not_allowed');

  // It grants inside its scope, and nowhere else: not a project around its environment, not another project.
  assert.deepEqual(await w.vault.setAccess({ actor: BOB, principal: CAROL, changes: [at(w.project, w.dev)] }), { ok: true, changes: ['created'] });
  for (const [change, why] of [
    [at(w.project, w.prod), 'an environment its scope leaves out'],
    [at(w.project, null), 'the project, which reaches prod too'],
    [at(other, otherEnvironment), 'another project'],
    [at(w.project, w.dev, null), 'not even to revoke'],
  ] as const) {
    if (change.role === null) {
      // The grant it made it may revoke; one it could not have made, not.
      assert.ok((await w.vault.setAccess({ actor: ROOT, principal: CAROL, changes: [at(w.project, w.prod)] })).ok);
      const revoke = await w.vault.setAccess({ actor: BOB, principal: CAROL, changes: [at(w.project, w.prod, null)] });
      assert.equal(!revoke.ok && revoke.refusal.code, 'not_allowed', why);
      continue;
    }
    const result = await w.vault.setAccess({ actor: BOB, principal: CAROL, changes: [change] });
    assert.equal(!result.ok && result.refusal.code, 'not_allowed', why);
  }
  // Nor gives itself what it may give others outside it, nor inside: managing access never reads a value.
  const toItself = await w.vault.setAccess({ actor: BOB, principal: BOB, changes: [at(w.project, null, 'access-manager')] });
  assert.equal(!toItself.ok && toItself.refusal.code, 'not_allowed');
  const readsItself = await w.vault.setAccess({ actor: BOB, principal: BOB, changes: [at(w.project, w.dev)] });
  assert.equal(!readsItself.ok && readsItself.refusal.code, 'not_allowed', 'a scoped admin giving itself a reading role in its scope');
  const adminReads = await w.vault.setAccess({ actor: ADA, principal: ADA, changes: [at(w.project, null)] });
  assert.equal(!adminReads.ok && adminReads.refusal.code, 'not_allowed', 'an admin giving itself a reading role');

  // A service account holds no instance role, and nothing grants on every project any more.
  const serviceRole = await w.vault.admit({ actor: ROOT, principal: 'token:ci', role: 'developer' });
  assert.equal(!serviceRole.ok && serviceRole.refusal.code, 'invalid');
  assert.ok((await w.vault.admit({ actor: ROOT, principal: 'token:ci', role: 'member' })).ok);
  const everywhere = await w.vault.setAccess({ actor: ROOT, principal: CAROL, changes: [{ projectId: null, environmentId: null, role: 'viewer', expiresAt: null }] });
  assert.equal(!everywhere.ok && everywhere.refusal.code, 'invalid');
  const badScope = await w.vault.admit({ actor: ROOT, principal: CAROL, role: 'developer', scope: { projects: 'some' } as never });
  assert.equal(!badScope.ok && badScope.refusal.code, 'invalid');

  // Each change is logged, the old role beside the new, and replays.
  const changed = (await vaultLog(w)).filter((entry) => entry.action === 'member.role' && entry.outcome === 'allow');
  assert.deepEqual(changed.map((entry) => [entry.actor, entry.subject, entry.detail.previousRole, entry.detail.role]), [[ADA, CAROL, 'member', 'developer']]);
  assert.equal((await w.vault.verifyLog({})).ok, true);
});

/**
 * A grant on every project as 0.4 wrote it: its row, its `access.grant`
 * entry under the vault's key, and the member's row sealed over it, as the
 * vault of 0.4 would have left them.
 */
async function everyProjectGrant(principal: string, slug: string | null, role: string, expiresAt: number | null = null): Promise<void> {
  const { vaultGrants, vaultMembers } = tablesOf(db.owner);
  const metadata = JSON.stringify({ role, expiresAt: expiresAt === null ? null : new Date(expiresAt).toISOString(), previousRole: null, place: slug === null ? '*' : `*/${slug}` });
  const appended = await db.vault.transaction((tx) => appendEntries(tx, VAULT_KEY, [{ actor: ROOT, action: 'access.grant', decision: 'allow', subjectPrincipal: principal, metadata }]));
  await db.owner.insert(vaultGrants).values({ principal, projectId: null, environmentId: null, environmentSlug: slug, role, expiresAt, grantedAt: appended.occurredAt, grantedBy: ROOT });
  await db.owner.update(vaultMembers).set({ accessSeq: appended.seqStart }).where(eq(vaultMembers.principal, principal));
  await reseal(principal);
}

test('a vault of 0.5 replaces the grants on every project of 0.4 once, holding no more than before, and the log replays it', async () => {
  const w = await world();
  const SERVICE = 'token:ci';
  const CAROL = 'user:carol@acme.example';
  const DAN = 'user:dan@acme.example';
  await member(w, ADA, []);
  await member(w, BOB, [[null, 'viewer']]);
  await member(w, CAROL, []);
  await member(w, DAN, []);
  await member(w, SERVICE, []);
  const other = await laterProject();
  await everyProjectGrant(ADA, 'dev', 'developer');
  await everyProjectGrant(BOB, null, 'maintainer');
  await everyProjectGrant(CAROL, null, 'viewer', Date.now() + 86_400_000);
  await everyProjectGrant(DAN, null, 'auditor', Date.now() - 1_000);
  await everyProjectGrant(SERVICE, 'dev', 'developer');
  assert.equal((await w.vault.verifyLog({})).ok, true, 'as 0.4 left it');

  // What `coffre migrate` says the vault will do, read with the owner's login.
  const preview = await everyProjectPreview(db.owner, Date.now());
  assert.deepEqual(preview.map(({ principal, conversion }) => [principal, conversion.role, conversion.grants.length]), [
    [SERVICE, 'member', 2], [ADA, 'developer', 0], [BOB, 'developer', 2], [CAROL, 'member', 2],
  ], 'a lapsed grant is no case');

  // A vault started afresh, as a deploy of 0.5 is, converts before its first call answers.
  const upgraded = await fresh();
  const ada = await upgraded.access(ADA);
  assert.deepEqual([ada.role, ada.scope, ada.grants], ['developer', DEV_ONLY, []]);
  const bob = await upgraded.access(BOB);
  assert.deepEqual([bob.role, bob.scope], ['developer', EVERYWHERE]);
  assert.deepEqual(bob.grants.map((grant) => [grant.projectId, grant.environmentId, grant.role, grant.grantedBy]).sort(), [
    [other.project, null, 'maintainer', 'system:vault'],
    [w.project, null, 'maintainer', 'system:vault'],
  ].sort(), 'maintainer replaces the viewer it held on the project');
  const carol = await upgraded.access(CAROL);
  assert.deepEqual([carol.role, carol.grants.map((grant) => [grant.role, grant.expiresAt !== null])], ['member', [['viewer', true], ['viewer', true]]], 'an end date keeps');
  assert.deepEqual([(await upgraded.access(DAN)).role, (await upgraded.access(DAN)).grants], ['member', []], 'a lapsed one goes');
  const service = await upgraded.access(SERVICE);
  assert.deepEqual([service.role, service.grants.map((grant) => [grant.environmentId, grant.role]).sort()], ['member', [[other.devId, 'developer'], [w.dev, 'developer']].sort()]);

  // None is left; the log says what became of each, and still replays.
  const { vaultGrants } = tablesOf(db.owner);
  assert.deepEqual(await db.owner.select().from(vaultGrants).where(sql`${vaultGrants.projectId} IS NULL AND ${vaultGrants.environmentId} IS NULL`), []);
  const log = (await vaultLog(w)).filter((entry) => entry.actor === 'system:vault');
  const revoked = log.filter((entry) => entry.action === 'access.revoke');
  assert.deepEqual(revoked.map((entry) => [entry.subject, entry.detail.place, entry.detail.previousRole]).sort(), [
    [ADA, '*/dev', 'developer'],
    [BOB, '*', 'maintainer'],
    [CAROL, '*', 'viewer'],
    [SERVICE, '*/dev', 'developer'],
  ].sort());
  assert.deepEqual(revoked.find((entry) => entry.subject === BOB)?.detail.narrowed, [{ kind: 'later-projects' }]);
  assert.deepEqual(log.filter((entry) => entry.action === 'member.role').map((entry) => [entry.subject, entry.detail.role]).sort(), [[ADA, 'developer'], [BOB, 'developer']]);
  assert.equal((await upgraded.verifyLog({})).ok, true);
  // A second vault finds nothing left to do.
  const entries = (await vaultLog(w)).length;
  await (await fresh()).access(ADA);
  assert.equal((await vaultLog(w)).length, entries);
});

test('the conversion takes no read away: viewer on every project beside auditor on a project reads its environments still', async () => {
  const w = await world();
  const EVE = 'user:eve@acme.example';
  await member(w, EVE, [[null, 'auditor']]);
  const other = await laterProject();
  await everyProjectGrant(EVE, null, 'viewer');
  const secret = await w.secret(w.prod);
  const items = await versionItems([{ secret, wrapped: await wrapped(w, secret) }]);

  const [preview] = await everyProjectPreview(db.owner, Date.now());
  assert.deepEqual(preview?.conversion.narrowed.map(({ grant: _, ...loss }) => loss), [{ kind: 'later-projects' }, { kind: 'environments', projectId: w.project, role: 'viewer' }]);

  const upgraded = await fresh();
  const eve = await upgraded.access(EVE);
  assert.deepEqual(eve.grants.map((grant) => [grant.projectId, grant.environmentId, grant.role]).sort(), [
    [other.project, null, 'viewer'],
    [w.project, null, 'auditor'],
    [w.project, w.dev, 'viewer'],
    [w.project, w.prod, 'viewer'],
  ].sort());
  // Read through the vault that wrapped it: one started afresh holds a key of its own.
  const read = await w.vault.unwrap({ principal: EVE, purpose: 'reveal', items });
  assert.ok(read.ok, JSON.stringify(read));
  const revoked = (await vaultLog(w)).find((entry) => entry.actor === 'system:vault' && entry.action === 'access.revoke');
  assert.deepEqual(revoked?.detail.narrowed, [{ kind: 'later-projects' }, { kind: 'environments', projectId: w.project, role: 'viewer' }]);
  assert.equal((await upgraded.verifyLog({})).ok, true);
});

test('migrate marks a member whose row the vault found tampered with, whose grants it leaves as they are', async () => {
  const w = await world();
  const { vaultGrants } = tablesOf(db.owner);
  await member(w, ADA, []);
  await member(w, BOB, []);
  await everyProjectGrant(ADA, null, 'viewer');
  await everyProjectGrant(BOB, null, 'viewer');
  await db.owner.update(vaultGrants).set({ role: 'owner' }).where(eq(vaultGrants.principal, BOB));
  assert.equal((await w.vault.access(BOB)).status, 'tampered');
  assert.deepEqual((await everyProjectPreview(db.owner, Date.now())).map((preview) => [preview.principal, preview.reported]), [[ADA, false], [BOB, true]]);
  await (await fresh()).access(ADA);
  assert.deepEqual((await db.owner.select().from(vaultGrants).where(sql`${vaultGrants.projectId} IS NULL AND ${vaultGrants.environmentId} IS NULL`)).map((grant) => grant.principal), [BOB]);
});

test('a genuine row put back after a tamper report is left as migrate says, until a change to what they hold settles it', async () => {
  const w = await world();
  const { vaultGrants } = tablesOf(db.owner);
  await member(w, BOB, []);
  await everyProjectGrant(BOB, null, 'viewer');
  await db.owner.update(vaultGrants).set({ role: 'owner' }).where(eq(vaultGrants.principal, BOB));
  assert.equal((await w.vault.access(BOB)).status, 'tampered');
  // The exact row put back: it checks out again, and no entry says so.
  await db.owner.update(vaultGrants).set({ role: 'viewer' }).where(eq(vaultGrants.principal, BOB));
  assert.equal((await w.vault.access(BOB)).status, 'active');

  // migrate, which holds no key, marks BOB reported; the vault leaves him as he is.
  assert.deepEqual((await everyProjectPreview(db.owner, Date.now())).map((preview) => [preview.principal, preview.reported]), [[BOB, true]]);
  await (await fresh()).access(BOB);
  const everyProject = sql`${vaultGrants.projectId} IS NULL AND ${vaultGrants.environmentId} IS NULL`;
  assert.deepEqual((await db.owner.select().from(vaultGrants).where(everyProject)).map((grant) => grant.principal), [BOB]);

  // A change to what he holds is newer than the report: both convert him again.
  assert.ok((await w.vault.setAccess({ actor: ROOT, principal: BOB, changes: [{ projectId: w.project, environmentId: w.dev, role: 'viewer', expiresAt: null }] })).ok);
  assert.deepEqual((await everyProjectPreview(db.owner, Date.now())).map((preview) => [preview.principal, preview.reported]), [[BOB, false]]);
  await (await fresh()).access(BOB);
  assert.deepEqual(await db.owner.select().from(vaultGrants).where(everyProject), []);
});

test('tamper reports forged in the vault\'s name above its own leave the one it wrote standing', async () => {
  const w = await world();
  const { vaultGrants } = tablesOf(db.owner);
  await member(w, BOB, []);
  await everyProjectGrant(BOB, null, 'viewer');
  await db.owner.update(vaultGrants).set({ role: 'owner' }).where(eq(vaultGrants.principal, BOB));
  assert.equal((await w.vault.access(BOB)).status, 'tampered');
  await db.owner.update(vaultGrants).set({ role: 'viewer' }).where(eq(vaultGrants.principal, BOB));
  assert.equal((await w.vault.access(BOB)).status, 'active');

  // More forged reports than a page holds, above the vault's own: it still stands, as migrate says.
  await forgeEntries(33, { action: 'vault.tampered', code: 'stale', subjectPrincipal: BOB });
  assert.deepEqual((await everyProjectPreview(db.owner, Date.now())).map((preview) => [preview.principal, preview.reported]), [[BOB, true]]);
  await (await fresh()).access(BOB);
  const everyProject = sql`${vaultGrants.projectId} IS NULL AND ${vaultGrants.environmentId} IS NULL`;
  assert.deepEqual((await db.owner.select().from(vaultGrants).where(everyProject)).map((grant) => grant.principal), [BOB]);
  assert.equal((await tamperings(w)).filter(([, fault]) => fault === 'forged_entry').length, 33);
});

test('tamper reports forged in the vault\'s name before a change to what a member holds leave the conversion to run, as migrate says', async () => {
  const w = await world();
  const { vaultGrants } = tablesOf(db.owner);
  await member(w, 'token:legacy', []);
  // As many as the vault reads back, all before the grant: none can stand.
  await forgeEntries(32 * 32, { action: 'vault.tampered', code: 'stale', subjectPrincipal: 'token:legacy' });
  await everyProjectGrant('token:legacy', null, 'viewer');
  assert.deepEqual((await everyProjectPreview(db.owner, Date.now())).map(({ principal, conversion, reported }) => [principal, conversion.grants.length, reported]), [['token:legacy', 1, false]]);
  const converted = await (await fresh()).access('token:legacy');
  assert.deepEqual(converted.grants.map((grant) => [grant.projectId, grant.environmentId, grant.role]), [[w.project, null, 'viewer']]);
  assert.deepEqual(await db.owner.select().from(vaultGrants).where(sql`${vaultGrants.projectId} IS NULL AND ${vaultGrants.environmentId} IS NULL`), []);
});

// Forged after the grant, they are what the vault would leave the grant for, were they its own: migrate cannot tell.
for (const forged of [1, 32, 33, 32 * 32 - 1, 32 * 32]) {
  const within = forged < 32 * 32;
  test(`after ${forged} tamper report${forged === 1 ? '' : 's'} forged in the vault's name, ${within ? 'migrate lists the conversion of a grant on every project, which the vault makes' : 'more than it reads past, the vault leaves a grant on every project, as migrate warns'}`, async () => {
    const w = await world();
    const { vaultGrants } = tablesOf(db.owner);
    await member(w, 'token:legacy', []);
    await everyProjectGrant('token:legacy', null, 'viewer');
    await forgeEntries(forged, { action: 'vault.tampered', code: 'stale', subjectPrincipal: 'token:legacy' });

    // Listed with its conversion, and marked: the vault, which checks the reports, decides between the two.
    const preview = await everyProjectPreview(db.owner, Date.now());
    assert.deepEqual(preview.map(({ principal, conversion, reported }) => [principal, conversion.grants.map((grant) => [grant.projectId, grant.role]), reported]), [
      ['token:legacy', [[w.project, 'viewer']], true],
    ]);
    const converted = await (await fresh()).access('token:legacy');
    const left = await db.owner.select().from(vaultGrants).where(sql`${vaultGrants.projectId} IS NULL AND ${vaultGrants.environmentId} IS NULL`);
    if (within) {
      assert.deepEqual(converted.grants.map((grant) => [grant.projectId, grant.environmentId, grant.role]), [[w.project, null, 'viewer']]);
      assert.deepEqual(left, []);
    } else {
      assert.deepEqual(left.map((grant) => grant.principal), ['token:legacy']);
    }
  });
}

for (const history of ['none', 'forged'] as const) {
  test(`a member with ${history === 'none' ? 'no access entry' : 'only access entries forged in the vault\'s name'} is left as they are under forged reports, and migrate marks them`, async () => {
    const w = await world();
    const { auditLog, vaultGrants, vaultMembers } = tablesOf(db.owner);
    const LEGACY = 'token:legacy';
    await member(w, ADA, []);
    if (history === 'forged') await forgeEntries(3, { action: 'member.add', subjectPrincipal: LEGACY });
    // ADA's row, as LEGACY's, naming the newest entry about LEGACY, or one about nobody, and sealed with a grant on every project.
    const [newest] = await db.owner.select({ seq: auditLog.seq }).from(auditLog).orderBy(desc(auditLog.seq)).limit(1);
    const [row] = await db.owner.select().from(vaultMembers).where(eq(vaultMembers.principal, ADA));
    await db.owner.insert(vaultMembers).values({ ...row, principal: LEGACY, accessSeq: newest.seq });
    await db.owner.insert(vaultGrants).values({ principal: LEGACY, projectId: null, environmentId: null, environmentSlug: null, role: 'viewer', expiresAt: null, grantedAt: Date.now(), grantedBy: ROOT });
    await reseal(LEGACY);
    await forgeEntries(1, { action: 'vault.tampered', code: 'stale', subjectPrincipal: LEGACY });

    assert.deepEqual((await everyProjectPreview(db.owner, Date.now())).map(({ principal, reported }) => [principal, reported]), [[LEGACY, true]]);
    // Its row names no entry of the vault's own: stale, so it never comes to the reports.
    await (await fresh()).access(ADA);
    const left = await db.owner.select().from(vaultGrants).where(sql`${vaultGrants.projectId} IS NULL AND ${vaultGrants.environmentId} IS NULL`);
    assert.deepEqual(left.map((grant) => grant.principal), [LEGACY]);
    const reported = (await vaultLog(w)).filter((entry) => entry.action === 'vault.tampered' && entry.actor === 'system:vault' && entry.subject === LEGACY);
    assert.deepEqual(reported.map((entry) => entry.code).filter((code) => code !== 'forged_entry'), ['stale']);
  });
}

test('an environment grant whose environment is gone seals as that environment, never as one on every project', () => {
  const key = rowKey(SIGNING_KEY);
  const row = {
    principal: ADA, status: 'active' as const, role: 'member' as const, scope: EVERYWHERE, generation: 0, accessSeq: 7n,
    createdAt: 1, createdBy: ROOT, statusChangedAt: 1, statusChangedBy: ROOT,
  };
  const grant = { principal: ADA, environmentSlug: null, role: 'viewer', expiresAt: null, grantedAt: 2, grantedBy: ROOT };
  // What readGrants returns for an environment grant whose environment row is missing: no project.
  const orphan = { ...grant, projectId: null, environmentId: 'e' };
  const everywhere = { ...grant, projectId: null, environmentId: null };
  assert.notDeepEqual(memberMac(key, row, [orphan]), memberMac(key, row, [everywhere]));
  assert.deepEqual(memberMac(key, row, [orphan]), memberMac(key, row, [{ ...orphan, projectId: 'p' }]), 'sealed by its environment alone');
});

test('a Member or an Admin everywhere keeps the MAC 0.4 sealed, and any other role seals as itself', () => {
  const key = rowKey(SIGNING_KEY);
  const row = {
    principal: ADA, status: 'active' as const, role: 'member' as const, scope: EVERYWHERE, generation: 0, accessSeq: 7n,
    createdAt: 1, createdBy: ROOT, statusChangedAt: 1, statusChangedBy: ROOT,
  };
  const held = [
    { principal: ADA, projectId: 'p', environmentId: null, environmentSlug: null, role: 'owner', expiresAt: null, grantedAt: 2, grantedBy: ROOT },
    { principal: ADA, projectId: 'p', environmentId: 'e', environmentSlug: null, role: 'viewer', expiresAt: 9, grantedAt: 3, grantedBy: ROOT },
  ];
  // The tuple as 0.3.0 wrote it: whether an owner, then each grant's kind, its place's id, role, end and grant.
  const before = (owner: boolean) => createHmac('sha256', key).update(JSON.stringify(['coffre.vault.member.v1', ADA, 'active', owner, 0, '7', 1, ROOT, 1, ROOT, [
    JSON.stringify(['environment', 'e', 'viewer', 9, 3, ROOT]),
    JSON.stringify(['project', 'p', 'owner', null, 2, ROOT]),
  ]])).digest();
  assert.deepEqual(memberMac(key, row, held), before(false));
  assert.deepEqual(memberMac(key, { ...row, role: 'admin' }, held), before(true));
  const seals = new Set([
    memberMac(key, { ...row, role: 'owner' }, held),
    memberMac(key, { ...row, role: 'developer' }, held),
    memberMac(key, { ...row, role: 'admin', scope: DEV_ONLY }, held),
    memberMac(key, { ...row, role: 'admin', scope: { projects: { except: ['p'] }, environments: 'all' } }, held),
  ].map((mac) => mac.toString('hex')));
  assert.equal(seals.size, 4);
  for (const mac of seals) assert.ok(mac !== before(false).toString('hex') && mac !== before(true).toString('hex'));
});

test('the log is chained, append-only, and shows a rewritten entry', async () => {
  const w = await world();
  const { auditLog } = tablesOf(db.owner);
  await member(w, ADA, [[w.dev, 'viewer']]);
  const secret = await w.secret(w.dev);
  await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: await versionItems([{ secret, wrapped: await wrapped(w, secret) }]) });

  assert.equal((await w.vault.verifyLog({})).ok, true);

  await assert.rejects(db.owner.update(auditLog).set({ decision: 'deny' }).where(eq(auditLog.action, 'secret.read')), appendOnly);
  await assert.rejects(db.owner.delete(auditLog), appendOnly);

  // Whoever owns the database can lift the triggers; the chain still shows it.
  await withLogUnlocked(db.owner, (owned) => owned.update(auditLog).set({ actor: BOB }).where(eq(auditLog.action, 'secret.read')));
  const tampered = (await vaultLog(w)).find((entry) => entry.action === 'secret.read')!;
  const after = await w.vault.verifyLog({});
  assert.equal(!after.ok && after.failedAtSeq, tampered.seq);
  assert.equal(!after.ok && after.reason, 'hash does not match the entry');
});

test('the vault appends only as itself, and writes none of the app\'s rows', postgresOnly('logins are Postgres\'s'), async () => {
  const { auditLog, projects } = tablesOf(db.vault);
  const w = await world();
  await member(w, ADA, []);
  const forged = {
    seq: 1000n, author: 'app', keyId: 'app:0', occurredAt: 0, actor: 'user:ada@acme.example', action: 'secret.read',
    decision: 'allow', prevHash: Buffer.alloc(32), mac: Buffer.alloc(32), hash: Buffer.alloc(32),
  };
  const refusedBy = (pattern: RegExp) => (error: unknown) => pattern.test(`${error} ${(error as { cause?: unknown }).cause}`);
  await assert.rejects(db.vault.insert(auditLog).values(forged), refusedBy(/row-level security/));
  await assert.rejects(db.vault.update(projects).set({ name: 'renamed' }), refusedBy(/permission denied/));
});

/** A vault whose log holds `n` wraps and an admission, as the Owner made them. */
async function longLog(n: number) {
  const w = await world();
  const items = await Promise.all(
    Array.from({ length: n }, async (_, i) => ({ secret: await w.secret(w.dev, `KEY_${i}`), key: randomBytes(32).toString('base64') })),
  );
  assert.ok((await w.vault.wrap({ principal: ROOT, items })).ok);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA })).ok);
  return w;
}

/**
 * Change entry `seq`'s actor, as whoever owns the database could: in place,
 * leaving its hash as it was; or chained again from there, the hashes made
 * anew and the MACs kept, which needs no key; or sealed again too, under
 * `key`, which needs the vault's.
 */
async function rewrite(seq: bigint, how: 'in place' | 'chained' | LogKey) {
  const { auditLog, auditChainHead } = tablesOf(db.owner);
  const entries = (await db.owner.select().from(auditLog).where(gte(auditLog.seq, seq)).orderBy(asc(auditLog.seq))) as StoredEntry[];
  await withLogUnlocked(db.owner, async (owned) => {
    if (how === 'in place') {
      await owned.update(auditLog).set({ actor: BOB }).where(eq(auditLog.seq, seq));
      return;
    }
    let prevHash = entries[0].prevHash;
    for (const entry of entries) {
      const changed = { ...entry, actor: entry.seq === seq ? BOB : entry.actor, prevHash };
      const mac = typeof how === 'object' && entry.author === how.author ? entryMac(how.key, prevHash, changed) : entry.mac;
      const hash = entryHash(prevHash, changed, mac);
      await owned.update(auditLog).set({ actor: changed.actor, prevHash, mac, hash }).where(eq(auditLog.seq, entry.seq));
      prevHash = hash;
    }
    await owned.update(auditChainHead).set({ headHash: prevHash });
  });
}

test('an entry edited in place is found by a full check', async () => {
  const w = await longLog(50);
  assert.equal((await w.vault.verifyLog({})).ok, true);
  await rewrite(3n, 'in place');
  const check = await w.vault.verifyLog({});
  assert.deepEqual(!check.ok && [check.failedAtSeq, check.reason], [3, 'hash does not match the entry']);
});

test('a rewrite chained again without the vault\'s key is found by any full check', async () => {
  await longLog(50);
  await rewrite(3n, 'chained');
  const check = await (await fresh()).verifyLog({});
  assert.deepEqual(!check.ok && [check.failedAtSeq, check.reason], [3, 'not written by the vault: its MAC does not match']);
});

test('a rewrite sealed again with the vault\'s key is found against the head it last verified', async () => {
  const w = await longLog(50);
  assert.equal((await w.vault.verifyLog({})).ok, true);

  await rewrite(3n, VAULT_KEY);
  const check = await w.vault.verifyLog({});
  assert.equal(!check.ok && check.reason, 'changed since the vault last verified it');
  // A vault that never saw the head before cannot tell: whoever holds the
  // key can seal anything. The heads checkpoints signed can; see below.
  assert.equal((await (await fresh()).verifyLog({})).ok, true);
});

test('a log of large entries is checked whole and signed, a batch of it in memory at a time', async () => {
  const w = await world();
  // A read of thousands of secrets lists them all: a few such entries outrun one batch's bytes.
  const listing = 'x'.repeat(Math.ceil(BATCH_BYTES / 3));
  for (let i = 0; i < 7; i++) {
    await db.vault.transaction((tx) => appendEntries(tx, VAULT_KEY, [{ actor: ADA, action: 'secret.read', decision: 'allow', metadata: JSON.stringify({ listing }) }]));
  }
  const fresh = await openLocalVault(db.vault, configure());
  const verified = await fresh.verifyLog({});
  const { auditLog } = tablesOf(db.owner);
  const written = await db.owner.select({ seq: auditLog.seq }).from(auditLog).where(eq(auditLog.author, 'vault'));
  const through = Math.max(...written.map(({ seq }) => Number(seq)));
  assert.deepEqual(verified, { ok: true, entries: written.length, through }, 'the check stopped short of the last entry');
  const signed = await fresh.checkpoint();
  assert.ok(signed.ok, JSON.stringify(signed));
  const [head] = await store.vaultPage(db.owner, undefined, 1);
  assert.equal(signed.checkpoint.seq, Number(head!.seq) - 1, 'the checkpoint signs every entry before its own');
});

test('a checkpoint signs the log up to its last entry, in an entry of its own', async () => {
  // An empty log has nothing to sign, and the refusal writes nothing to sign next.
  const empty = await (await fresh()).checkpoint();
  assert.equal(!empty.ok && empty.refusal.code, 'invalid');
  assert.equal((await store.vaultPage(db.owner, undefined, 1)).length, 0);
  const w = await world();
  const { auditLog } = tablesOf(db.owner);
  const { checkpointKeys } = await w.vault.about();
  const signed = async () => (await vaultLog(w)).filter((entry) => entry.action === 'audit.checkpoint' && entry.outcome === 'allow');
  assert.deepEqual(await signed(), []);

  await member(w, ADA, [[w.dev, 'viewer']]);
  const last = (await vaultLog(w)).at(-1)!;
  const first = await w.vault.checkpoint();
  assert.ok(first.ok);
  assert.deepEqual([first.checkpoint.seq, first.checkpoint.hash], [last.seq, last.hash]);
  const { publicKey } = checkpointKeys[first.checkpoint.keyId]!;
  assert.equal(await verifyCheckpoint(first.checkpoint, publicKey), true);
  assert.equal(await verifyCheckpoint({ ...first.checkpoint, hash: 'b'.repeat(64) }, publicKey), false);
  const entries = await vaultLog(w);
  // Its entry names the last entry it signs as related, and keeps its tally beside the signature.
  const kept = entries.at(-1)!;
  assert.deepEqual([kept.action, signedOf(kept.detail), kept.detail.relatedSeq], ['audit.checkpoint', first.checkpoint, String(first.checkpoint.seq)]);
  assert.deepEqual(Object.keys(kept.detail.tally as object).sort(), ['access', 'accounting', 'entries', 'keys', 'replayFault', 'v']);

  // Nothing new signs nothing new.
  assert.deepEqual(await w.vault.checkpoint(), first);
  assert.equal((await vaultLog(w)).length, entries.length);
  await member(w, BOB, []);
  const next = await w.vault.checkpoint();
  assert.ok(next.ok && next.checkpoint.seq > first.checkpoint.seq);
  assert.deepEqual(signedOf((await signed()).at(-1)!.detail), next.checkpoint);

  // Each is an entry of the log, and as append-only.
  await assert.rejects(db.owner.delete(auditLog).where(eq(auditLog.action, 'audit.checkpoint')), appendOnly);
});

test('no checkpoint is signed over a rewritten entry, and a full check finds the prefix gone', async () => {
  const w = await world();
  await member(w, ADA, [[w.dev, 'viewer']]);
  const first = await w.vault.checkpoint();
  assert.ok(first.ok);

  // Someone holding the database and the vault's keys rewrites an entry the
  // checkpoint covers, and seals again. The instance that wrote the head
  // they replaced refuses to write after it at all.
  await member(w, BOB, [[w.dev, 'viewer']]);
  await rewrite(1n, VAULT_KEY);
  await assert.rejects(w.vault.checkpoint(), LogRewound);
  // Another refuses to sign over it.
  const started = await fresh();
  const next = await started.checkpoint();
  assert.equal(!next.ok && next.refusal.code, 'log_broken');
  assert.equal((await vaultLog(w)).at(-1)!.detail.reason, `the log up to entry ${first.checkpoint.seq} is not the prefix the last checkpoint signed`);

  // Every entry carries a good MAC, but the checkpoint's prefix is not there.
  const signed = (await vaultLog(w)).find((entry) => entry.action === 'audit.checkpoint' && entry.outcome === 'allow')!;
  assert.deepEqual(await started.verifyLog({}), {
    ok: false,
    failedAtSeq: signed.seq,
    reason: `the log up to entry ${first.checkpoint.seq} is not the prefix this checkpoint signed: it was rewritten`,
  });
});

test("given the app's head, the vault checks its own entries and leaves the chain's links to the app, which recomputed them", async () => {
  const w = await world();
  const { auditLog } = tablesOf(db.owner);
  await member(w, ADA, []);
  // One of the app's entries, as the app appends one, between two of the vault's.
  await db.owner.transaction((tx) =>
    appendEntries(tx, deriveLogKey('app', randomBytes(32)), [{ actor: 'system:coffre-scheduler', action: 'audit.heartbeat', decision: 'allow', metadata: '{}' }]),
  );
  await member(w, BOB, []);
  const rows = (await db.owner.select().from(auditLog).orderBy(asc(auditLog.seq))) as StoredEntry[];
  const last = rows.at(-1)!;
  const upTo = { seq: Number(last.seq), hash: last.hash.toString('hex') };
  const own = rows.filter((row) => row.author === 'vault').length;
  assert.deepEqual(await w.vault.verifyLog({ upTo }), { ok: true, entries: own, through: upTo.seq });

  // The app's entry edited in place, its hash left as it was: the chain no longer recomputes. Given the app's head,
  // which the app only reports once it has recomputed every link through it, that is the app's to find, and the
  // vault's own entries still hold. Without one, nobody else rehashed the chain, and the vault does.
  const app = rows.find((row) => row.author === 'app')!;
  await withLogUnlocked(db.owner, (owned) => owned.update(auditLog).set({ actor: 'system:edited' }).where(eq(auditLog.seq, app.seq)));
  assert.deepEqual(await w.vault.verifyLog({ upTo }), { ok: true, entries: own, through: upTo.seq });
  const alone = await w.vault.verifyLog({});
  assert.deepEqual(!alone.ok && [alone.failedAtSeq, alone.reason], [Number(app.seq), 'hash does not match the entry']);

  // One of the vault's own, edited the same way, is refused either way.
  const vaultEntry = rows.find((row) => row.author === 'vault' && row.seq > app.seq)!;
  await withLogUnlocked(db.owner, (owned) => owned.update(auditLog).set({ actor: 'user:mallory@acme.example' }).where(eq(auditLog.seq, vaultEntry.seq)));
  const withHead = await w.vault.verifyLog({ upTo });
  assert.deepEqual(!withHead.ok && [withHead.failedAtSeq, withHead.reason], [Number(vaultEntry.seq), 'hash does not match the entry']);
});

test('a full check covers the head the app verified up to, and refuses an entry forged under no key', async () => {
  const w = await world();
  const { auditLog, auditChainHead } = tablesOf(db.owner);
  await member(w, ADA, []);
  const [last] = (await db.owner.select().from(auditLog).orderBy(asc(auditLog.seq))).slice(-1) as StoredEntry[];
  const upTo = { seq: Number(last.seq), hash: last.hash.toString('hex') };
  // Root made an Owner, as the deployment names them, and Ada's admission.
  assert.deepEqual(await w.vault.verifyLog({ upTo }), { ok: true, entries: 2, through: upTo.seq });
  assert.deepEqual(await w.vault.verifyLog({ upTo: { ...upTo, hash: 'f'.repeat(64) } }), {
    ok: false,
    failedAtSeq: upTo.seq,
    reason: 'not the entry the app verified up to: the log changed between the two checks',
  });

  // Review of #28, F1: a vault entry anyone could link to the chain, with a
  // MAC made up, is the vault's to refuse.
  const fields = {
    seq: last.seq + 1n, author: 'vault' as const, keyId: 'vault:0000000000000000', occurredAt: Date.now(),
    actor: 'user:victim@acme.example', action: 'secret.read', decision: 'allow', code: null, subjectPrincipal: null,
    projectId: null, environmentId: null, secretId: null, secretVersionId: null, operationId: null, requestId: null,
    sourceIp: null, relatedSeq: null, metadata: '{}',
  };
  const mac = Buffer.alloc(32, 0x41);
  const hash = entryHash(last.hash, fields, mac);
  await db.owner.insert(auditLog).values({ ...fields, prevHash: last.hash, mac, hash });
  await db.owner.update(auditChainHead).set({ nextSeq: fields.seq + 1n, headHash: hash });
  assert.deepEqual(await w.vault.verifyLog({}), {
    ok: false,
    failedAtSeq: Number(fields.seq),
    reason: `written under vault:0000000000000000, a key this verifier does not hold: either it is forged, or the vault wrote it under another vault key or signing key, which must stay configured: a vault key that was replaced stays in the vault's config, in previousKeks`,
  });
});

test('a full check replays who holds what from the log, and finds what a holder of the vault\'s key wrote around it', async () => {
  const w = await world();
  const { vaultGrants, vaultMembers } = tablesOf(db.owner);
  const change = async (principal: string, environmentId: string | null, role: string | null) =>
    assert.ok(
      (
        await w.vault.setAccess({
          actor: ROOT,
          principal,
          changes: [{ projectId: w.project, environmentId, role: role as 'viewer' | null, expiresAt: null }],
        })
      ).ok,
    );
  // Every kind of change: admit, grant, update, owner, remove, restore, and a
  // lapsed grant cleared, which changes nothing and is not logged.
  await member(w, ADA, [[w.dev, 'developer'], [w.prod, 'viewer', Date.now() + 60_000]]);
  await member(w, BOB, [[null, 'maintainer']]);
  await change(ADA, w.dev, 'viewer');
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA, role: 'admin' })).ok);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA, role: 'developer', scope: { projects: 'all', environments: { except: ['prod'] } } })).ok);
  assert.ok((await w.vault.remove({ actor: ROOT, principal: BOB })).ok);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: BOB })).ok);
  w.clock.offset += 120_000;
  await change(ADA, w.prod, null);
  const whole = await w.vault.verifyLog({});
  assert.ok(whole.ok, JSON.stringify(whole));

  // A grant written straight into the database, and BOB's row sealed again
  // over it by someone holding the vault's key: the MAC holds, the replay
  // does not.
  await db.owner.insert(vaultGrants).values({
    principal: BOB, projectId: w.project, environmentId: null, role: 'owner', expiresAt: null, grantedAt: Date.now(), grantedBy: ROOT,
  });
  await reseal(BOB);
  const extra = {
    ok: false,
    failedAtSeq: null,
    reason: `the store holds a grant the log never gave: ${BOB} as owner on ${w.project}`,
    fault: { kind: 'unlogged-grant', grant: { principal: BOB, projectId: w.project, environmentId: null, environmentSlug: null, role: 'owner' } },
  };
  assert.deepEqual(await w.vault.verifyLog({}), extra);

  // Or a removal undone, grants and all.
  await db.owner.delete(vaultGrants).where(eq(vaultGrants.role, 'owner'));
  assert.ok((await w.vault.remove({ actor: ROOT, principal: ADA })).ok);
  await db.owner.update(vaultMembers).set({ status: 'active', role: 'owner' }).where(eq(vaultMembers.principal, ADA));
  await db.owner.insert(vaultGrants).values({
    principal: ADA, projectId: null, environmentId: w.dev, role: 'viewer', expiresAt: null, grantedAt: 0, grantedBy: ROOT,
  });
  await reseal(BOB);
  await reseal(ADA);
  assert.deepEqual(await w.vault.verifyLog({}), {
    ok: false,
    failedAtSeq: null,
    reason: `the store's ${ADA} differs from the log's in status, role`,
    fault: { kind: 'member-differs', principal: ADA, fields: ['status', 'role'] },
  });
});

/** Seal `principal`'s row again over what the database now holds, as only the holder of the vault's key can. */
async function reseal(principal: string) {
  const { vaultMembers } = tablesOf(db.owner);
  const row = (await store.member(db.owner, principal))!;
  const mac = memberMac(rowKey(SIGNING_KEY), row, await store.grants(db.owner, principal));
  await db.owner.update(vaultMembers).set({ mac }).where(eq(vaultMembers.principal, principal));
}

// --- member integrity -------------------------------------------------------------

/** A member's row and grants as they are now, to put back later as the database's owner could. */
async function snapshot(principal: string) {
  const { vaultMembers, vaultGrants } = tablesOf(db.owner);
  const [row] = await db.owner.select().from(vaultMembers).where(eq(vaultMembers.principal, principal));
  const held = await db.owner.select().from(vaultGrants).where(eq(vaultGrants.principal, principal));
  return async () => {
    await db.owner.delete(vaultGrants).where(eq(vaultGrants.principal, principal));
    await db.owner.update(vaultMembers).set(row).where(eq(vaultMembers.principal, principal));
    if (held.length > 0) await db.owner.insert(vaultGrants).values(held);
  };
}

/** The `vault.tampered` entries, oldest first, as `[subject, code]`. */
async function tamperings(w: World) {
  return (await vaultLog(w)).filter((entry) => entry.action === 'vault.tampered').map((entry) => [entry.subject, entry.code]);
}

for (const edit of ['forged', 'edited', 'deleted'] as const) {
  test(`a grant ${edit} in the database leaves its member refused as tampered, until an owner starts them over`, async () => {
    const w = await world();
    const { vaultGrants } = tablesOf(db.owner);
    await member(w, ADA, [[w.dev, 'viewer']]);
    const secret = await w.secret(w.dev);
    const items = [{ secret, wrapped: await wrapped(w, secret) }];
    assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: await versionItems(items) })).ok, true);

    if (edit === 'forged') {
      await db.owner.insert(vaultGrants).values({
        principal: ADA, projectId: w.project, environmentId: null, role: 'owner', expiresAt: null, grantedAt: Date.now(), grantedBy: ROOT,
      });
    } else if (edit === 'edited') {
      await db.owner.update(vaultGrants).set({ role: 'developer' }).where(eq(vaultGrants.principal, ADA));
    } else {
      await db.owner.delete(vaultGrants).where(eq(vaultGrants.principal, ADA));
    }

    const access = await w.vault.access(ADA);
    assert.deepEqual([access.status, access.grants], ['tampered', []]);
    const read = await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: await versionItems(items) });
    assert.equal(!read.ok && read.refusal.code, 'tampered');
    const regrant = await w.vault.setAccess({
      actor: ROOT, principal: ADA, changes: [{ projectId: w.project, environmentId: w.prod, role: 'viewer', expiresAt: null }],
    });
    assert.equal(!regrant.ok && regrant.refusal.code, 'tampered');
    assert.deepEqual(await tamperings(w), [[ADA, 'mac']], 'found once, logged once');
    assert.deepEqual(await w.vault.verifyLog({}), {
      ok: false,
      failedAtSeq: null,
      reason: `the store's ${ADA}, or their grants, were changed outside the vault`,
      fault: { kind: 'tampered-member', principal: ADA, why: 'mac' },
    });

    // An owner removes them, which starts over from the log, and adds them back.
    const removed = await w.vault.remove({ actor: ROOT, principal: ADA });
    assert.deepEqual(removed, { ok: true, revoked: [], generation: 1 });
    assert.equal((await w.vault.access(ADA)).status, 'removed');
    assert.equal((await w.vault.admit({ actor: ROOT, principal: ADA })).ok, true);
    await member(w, ADA, [[w.dev, 'viewer']]);
    assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: await versionItems(items) })).ok, true);
    assert.equal((await w.vault.verifyLog({})).ok, true);
  });
}

/**
 * Hold the log's head as its owner, run `during` while a decision about
 * someone waits for it, then let go: the window between the decision's
 * lock on a member's row and everything it reads under the head, which the
 * owner can widen at will.
 */
async function whileHeadHeld<T>(decision: () => Promise<T>, during: () => Promise<void>): Promise<T> {
  let release!: () => void;
  const released = new Promise<void>((resolve) => (release = resolve));
  let holding!: () => void;
  const held = new Promise<void>((resolve) => (holding = resolve));
  const holder = db.owner.transaction(async (tx) => {
    await run(tx, sql`SELECT 1 FROM audit_chain_head FOR UPDATE`);
    holding();
    await released;
  });
  await held;
  const pending = decision();
  // Until the vault's login queues on the head.
  for (let i = 0; ; i++) {
    const [waiting] = await rows<{ n: number }>(db.owner, sql`SELECT count(*)::int AS n FROM pg_stat_activity
      WHERE datname = current_database() AND usename = 'coffre_vault_runtime' AND wait_event_type = 'Lock'`);
    if (waiting.n > 0) break;
    assert.ok(i < 200, 'the decision never waited on the head');
    await sleep(25);
  }
  await during();
  release();
  await holder;
  return pending;
}

test('a grant written around the vault while it decides about its member is refused, not sealed in (review R2)', postgresOnly('SQLite lets no write in beside a decision'), async () => {
  const w = await world();
  const { vaultGrants } = tablesOf(db.owner);
  // Mallory manages access on a sandbox project, holds nothing on market, and has the owner's login.
  const sandbox = await newProject(db.owner);
  const sandboxEnv = await newEnvironment(db.owner, sandbox);
  assert.equal((await w.vault.admit({ actor: ROOT, principal: ADA })).ok, true);
  assert.ok((await w.vault.setAccess({ actor: ROOT, principal: ADA, changes: [{ projectId: sandbox, environmentId: null, role: 'access-manager', expiresAt: null }] })).ok);
  const prod = await w.secret(w.prod);
  const items = await versionItems([{ secret: prod, wrapped: await wrapped(w, prod) }]);

  // Through the app, as herself, she gives herself viewer on a sandbox environment; while that
  // decision waits on the head she holds, she inserts a grant on market/prod for herself.
  const change = await whileHeadHeld(
    () => w.vault.setAccess({ actor: ADA, principal: ADA, changes: [{ projectId: sandbox, environmentId: sandboxEnv, role: 'viewer', expiresAt: null }] }),
    async () => {
      await db.owner.insert(vaultGrants).values({
        principal: ADA, projectId: null, environmentId: w.prod, role: 'developer', expiresAt: null, grantedAt: Date.now(), grantedBy: ROOT,
      });
    },
  );
  // The decision finds the table holds more than it decided, and is refused; the finding is logged.
  assert.equal(!change.ok && change.refusal.code, 'tampered');
  assert.deepEqual(await tamperings(w), [[ADA, 'mac']]);
  const read = await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items });
  assert.equal(!read.ok && read.refusal.code, 'tampered', 'a grant the database owner wrote is not honoured');
  assert.ok(!(await w.vault.access(ADA)).grants.some((grant) => grant.environmentId === w.prod));
});

test('a grant written around the vault while it removes a member goes with the removal', postgresOnly('SQLite lets no write in beside a decision'), async () => {
  const w = await world();
  const { vaultGrants } = tablesOf(db.owner);
  await member(w, ADA, [[w.dev, 'viewer']]);
  const removal = await whileHeadHeld(
    () => w.vault.remove({ actor: ROOT, principal: ADA }),
    async () => {
      await db.owner.insert(vaultGrants).values({
        principal: ADA, projectId: null, environmentId: w.prod, role: 'developer', expiresAt: null, grantedAt: Date.now(), grantedBy: ROOT,
      });
    },
  );
  // The removal reads her under the head, the grant written around it included: her row fails, which it logs, and it
  // starts her over from the log, taking every grant and sealing none.
  assert.equal(removal.ok, true);
  assert.equal((await w.vault.access(ADA)).status, 'removed');
  // Admitted again, they start from nothing: no grant written around the vault comes back with them.
  assert.equal((await w.vault.admit({ actor: ROOT, principal: ADA })).ok, true);
  assert.deepEqual((await w.vault.access(ADA)).grants, []);
  assert.deepEqual(await tamperings(w), [[ADA, 'mac']]);
});

test('a checkpoint refuses to sign over entries cut from the middle of the log (review R1b)', async () => {
  const w = await world();
  const { auditLog, vaultGrants, vaultMembers } = tablesOf(db.owner);
  await member(w, ADA, [[w.dev, 'developer']]);
  // Mallory keeps Ada's row and grants from before her removal.
  const [kept] = await db.owner.select().from(vaultMembers).where(eq(vaultMembers.principal, ADA));
  const keptGrants = await db.owner.select().from(vaultGrants).where(eq(vaultGrants.principal, ADA));
  assert.equal((await w.vault.remove({ actor: ROOT, principal: ADA })).ok, true);
  await wrapped(w, await w.secret(w.prod));
  assert.equal((await w.vault.checkpoint()).ok, true, 'a checkpoint signs a prefix that holds the removal');

  // She cuts the removal out of the log, now before the newest checkpoint, and puts Ada's rows back.
  await withLogUnlocked(db.owner, async (owned) => {
    await owned.delete(auditLog).where(and(eq(auditLog.author, 'vault'), eq(auditLog.subjectPrincipal, ADA), gt(auditLog.seq, kept.accessSeq)));
    await owned.update(vaultMembers).set(kept).where(eq(vaultMembers.principal, ADA));
    await owned.insert(vaultGrants).values(keptGrants);
  });
  await wrapped(w, await w.secret(w.prod));
  // The prefix the last checkpoint signed is short of entries: one count of its index finds it, and where.
  const checkpoint = await w.vault.checkpoint();
  assert.equal(!checkpoint.ok && checkpoint.refusal.code, 'log_broken', 'a checkpoint signed over a log with entries cut from its middle');
  assert.match(String((await vaultLog(w)).at(-1)!.detail.reason), /^sequence gap: expected seq \d+/, 'it names the gap');
});

test('an entry edited in place behind the newest checkpoint is found by the rehash of the past, within its lap', async () => {
  // Two entries of the past rehashed a checkpoint, so that a lap over this log takes several.
  const w = await world({}, { walks: { scrub: 2 } });
  for (const name of ['ada', 'bob', 'cy', 'di']) await member(w, `user:${name}@acme.example`, [[w.dev, 'viewer']]);
  const signed = await w.vault.checkpoint();
  assert.ok(signed.ok);
  // An entry near the end of what it signed, edited in place, its hash left as it was.
  const edited = BigInt(signed.checkpoint.seq - 1);
  await rewrite(edited, 'in place');

  // Every check goes on from the newest checkpoint's tally, and reads nothing before it but its hash, which is
  // still there: none of them finds the edit. The walk from the first entry, asked for, does at once.
  const whole = await w.vault.verifyLog({ from: 'start' });
  assert.deepEqual(!whole.ok && [whole.failedAtSeq, whole.reason], [Number(edited), 'hash does not match the entry']);
  const laps: boolean[] = [];
  for (let beat = 0; beat < signed.checkpoint.seq; beat++) {
    assert.equal((await w.vault.verifyLog({})).ok, true, 'a verification read the past');
    await member(w, `user:p${beat}@acme.example`, []);
    const next = await w.vault.checkpoint();
    laps.push(next.ok);
    if (!next.ok) {
      assert.equal(next.refusal.code, 'log_broken');
      assert.deepEqual([(await vaultLog(w)).at(-1)!.detail.failedAtSeq, (await vaultLog(w)).at(-1)!.detail.reason], [Number(edited), 'hash does not match the entry']);
      // And every verification says so from then on, though it reads nothing before the newest checkpoint.
      const told = await w.vault.verifyLog({});
      assert.deepEqual(!told.ok && [told.failedAtSeq, told.reason], [Number(edited), 'the last checkpoint was refused: hash does not match the entry']);
      // A refusal of another kind after it, a vault with the wrong KEK, hides nothing.
      await wrapped(w, await w.secret(w.dev));
      const wrong = await fresh();
      // It finds its KEK wrong at its first key work, as here, where it checks its key.
      await wrong.keyChecks();
      const misled = await wrong.checkpoint();
      assert.equal(!misled.ok && misled.refusal.code, 'wrong_kek');
      assert.deepEqual(await w.vault.verifyLog({}), told);
      break;
    }
  }
  // Two entries a beat from the first, so the edit is found at the beat whose stretch holds it, not before.
  assert.deepEqual(laps, [...Array(Number(edited) / 2 | 0).fill(true), false]);
});

test('a lap of the rehash of the past ends where it began to, so a log growing faster than it still gets back to its start', async () => {
  const w = await world({}, { walks: { scrub: 2 } });
  for (const name of ['ada', 'bob', 'cy']) await member(w, `user:${name}@acme.example`, [[w.dev, 'viewer']]);
  assert.ok((await w.vault.checkpoint()).ok);
  // The first lap begins, and rehashes entries 0 and 1; then entry 0 is edited, behind it.
  await reads(1);
  assert.ok((await w.vault.checkpoint()).ok);
  await rewrite(0n, 'in place');
  // Five entries a beat, where the rehash takes two: a lap that ran to the newest prefix would never end.
  let beats = 0;
  for (; beats < 40; beats++) {
    await reads(5);
    const next = await w.vault.checkpoint();
    if (!next.ok) {
      assert.deepEqual([(await vaultLog(w)).at(-1)!.detail.failedAtSeq, (await vaultLog(w)).at(-1)!.detail.reason], [0, 'hash does not match the entry']);
      break;
    }
  }
  assert.ok(beats < 40, 'the rehash of the past never got back to entry 0');
});

test('a rehash of the past the database fails leaves its lap where it was, and the checkpoint is signed all the same, saying why', async () => {
  const w = await world({}, { walks: { scrub: 2 } });
  await reads(10);
  assert.ok((await w.vault.checkpoint()).ok);
  await reads(1);
  assert.ok((await w.vault.checkpoint()).ok);
  const lap = async () => (await vaultLog(w)).filter((entry) => entry.action === 'audit.checkpoint' && entry.outcome === 'allow').at(-1)!.detail.scrub;
  const before = await lap();
  assert.notEqual(before, null);
  await reads(1);
  // The database drops the connection under the rehash's own snapshot, the second a checkpoint opens.
  let snapshots = 0;
  const failing = new Proxy(db.vault, {
    get(target, key, receiver) {
      if (key !== 'transaction') return Reflect.get(target, key, receiver) as unknown;
      return (work: never, options?: unknown) => (options === SNAPSHOT && ++snapshots === 2
        ? Promise.reject(Object.assign(new Error('connection reset'), { code: 'ECONNRESET' }))
        : target.transaction(work, options as never));
    },
  });
  const vault = await openLocalVault(failing, configure(), { walks: { scrub: 2 } });
  const signed = await vault.checkpoint();
  assert.ok(signed.ok && /the rehash of the past did not run/.test(signed.warning ?? ''), JSON.stringify(signed));
  assert.deepEqual(await lap(), before);
});

test("a tally whose members and grants are kept nowhere is refused wherever a walk would read it", async () => {
  const w = await world();
  await member(w, ADA, [[w.dev, 'viewer']]);
  const first = await w.vault.checkpoint();
  assert.ok(first.ok);
  await reads(1);
  const second = await w.vault.checkpoint();
  assert.ok(second.ok);
  await reads(1);
  const third = await w.vault.checkpoint();
  assert.ok(third.ok);
  // The second keeps its members and grants in an entry that holds none, its digest kept: a stretch passing it finds
  // that, as a walk resuming from it would.
  await rewriteMetadata(BigInt(second.checkpoint.seq + 1), (metadata) => {
    const tally = metadata.tally as { access: { digest: string } };
    return { ...metadata, tally: { ...tally, access: { digest: tally.access.digest, at: 0 } } };
  });
  const vault = await fresh();
  const whole = await vault.verifyLog({ from: 'start', to: third.checkpoint.seq + 1 });
  assert.deepEqual(!whole.ok && [whole.failedAtSeq, whole.reason], [second.checkpoint.seq + 1, 'its tally keeps its members and grants in entry 0, which holds none']);
  const resumed = await vault.verifyLog({ from: second.checkpoint.seq + 1 });
  assert.deepEqual(!resumed.ok && [resumed.failedAtSeq, resumed.reason], [second.checkpoint.seq + 1, 'its tally keeps its members and grants in entry 0, which holds none']);
});

/** Reads in the vault's name, as the vault logs them, many at once. */
async function reads(entries: number) {
  await db.vault.transaction((tx) => appendEntries(tx, VAULT_KEY, Array.from({ length: entries }, () => ({
    actor: ROOT, action: 'secret.read', decision: 'allow' as const, metadata: '{"purpose":"reveal"}',
  }))));
}

test('checkpoints and checks go on from the newest tally, and read nothing before it but its hash', async () => {
  await world();
  await reads(300);
  const signed = await (await fresh()).checkpoint();
  assert.ok(signed.ok);
  await reads(5);
  // Every read the checkpoint signed edited in place, its hash left as it was.
  const { auditLog } = tablesOf(db.owner);
  await withLogUnlocked(db.owner, (owned) => owned.update(auditLog).set({ actor: BOB })
    .where(and(eq(auditLog.action, 'secret.read'), lte(auditLog.seq, BigInt(signed.checkpoint.seq)))));

  // A vault that walks no more than the checkpoint's entry and the five since, rehashing nothing of the past,
  // verifies the log to its head, and signs it.
  const bounded = await openLocalVault(db.vault, configure(), { walks: { verify: 6, checkpoint: 6, scrub: 0 } });
  const [head] = await store.vaultPage(db.owner, undefined, 1);
  const verified = await bounded.verifyLog({});
  assert.deepEqual(verified.ok && verified.through, Number(head!.seq), JSON.stringify(verified));
  const next = await bounded.checkpoint();
  assert.ok(next.ok && next.checkpoint.seq === Number(head!.seq), JSON.stringify(next));
  // The walk from the first entry reads it all.
  const whole = await bounded.verifyLog({ from: 'start' });
  assert.deepEqual(!whole.ok && whole.reason, 'hash does not match the entry');
});

test('a log no checkpoint kept a tally of, as 0.10.0 left it, is signed again from its first entry, a walk a call', async () => {
  await world();
  await reads(250);
  const vault = await openLocalVault(db.vault, configure(), { walks: { checkpoint: 100, verify: 100 } });
  // A check goes as far as one walk.
  const partial = await vault.verifyLog({});
  assert.deepEqual(partial.ok && partial.through, 99);
  const signed: number[] = [];
  for (let call = 0; call < 5; call++) {
    const checkpoint = await vault.checkpoint();
    assert.ok(checkpoint.ok, JSON.stringify(checkpoint));
    signed.push(checkpoint.checkpoint.seq);
    const [newest] = await store.vaultPage(db.owner, undefined, 1);
    if (checkpoint.checkpoint.seq === Number(newest!.seq) - 1) break;
  }
  // A walk a call, behind the head, until it reaches it: then it signs every entry before its own.
  assert.deepEqual(signed.slice(0, 2), [99, 199]);
  assert.equal(signed.length, 3);
  const caught = await vault.verifyLog({});
  assert.ok(caught.ok, JSON.stringify(caught));
});

test("a tally rewritten by a holder of the vault's key is found by the walk from the first entry", async () => {
  const w = await world();
  await member(w, ADA, [[w.dev, 'viewer']]);
  assert.ok((await w.vault.checkpoint()).ok);
  await member(w, BOB, [[w.dev, 'viewer']]);
  const signed = await w.vault.checkpoint();
  assert.ok(signed.ok);
  const entry = BigInt(signed.checkpoint.seq + 1);
  // One more entry than the log holds, its digest kept as it was: the members and grants are as they were.
  await rewriteMetadata(entry, (metadata) => ({ ...metadata, tally: { ...metadata.tally as object, entries: 99 } }));
  const whole = await w.vault.verifyLog({ from: 'start', to: Number(entry) });
  assert.deepEqual(!whole.ok && [whole.failedAtSeq, whole.reason], [Number(entry), 'the tally this checkpoint keeps does not follow from the log before it']);
  // Members and grants changed, but not their digest: the tally is refused wherever a walk starts from it.
  await rewriteMetadata(entry, (metadata) => {
    const tally = metadata.tally as { access: { members: unknown[] } };
    return { ...metadata, tally: { ...tally, access: { ...tally.access, members: [] } } };
  });
  const resumed = await w.vault.verifyLog({});
  assert.deepEqual(!resumed.ok && [resumed.failedAtSeq, resumed.reason], [Number(entry), "its tally's members and grants do not match their digest"]);
});

test("a checkpoint's tally rewritten in the middle of a stretch is found there, though the stretch's end is sound", async () => {
  const w = await world();
  await member(w, ADA, [[w.dev, 'viewer']]);
  const first = await w.vault.checkpoint();
  assert.ok(first.ok);
  await member(w, BOB, [[w.dev, 'viewer']]);
  const second = await w.vault.checkpoint();
  assert.ok(second.ok);
  await rewriteMetadata(BigInt(first.checkpoint.seq + 1), (metadata) => ({ ...metadata, tally: { ...metadata.tally as object, entries: 99 } }));
  // The newest checkpoint's tally is sound, so the page's check, from it, holds; a stretch from the first entry
  // to it passes the first checkpoint on the way, and holds it to the walk.
  const fresh = await openLocalVault(db.vault, configure());
  assert.equal((await fresh.verifyLog({})).ok, true);
  const whole = await fresh.verifyLog({ from: 'start', to: second.checkpoint.seq + 1 });
  assert.deepEqual(!whole.ok && [whole.failedAtSeq, whole.reason], [first.checkpoint.seq + 1, 'the tally this checkpoint keeps does not follow from the log before it']);
});

test("a stretch holds each tally to the walk as it stood at that tally's prefix, the vault's keys included", async () => {
  // The app's entry first, as on a deployment whose first beat comes before anyone signs in: the first checkpoint
  // signs it with no key of the vault's yet, and the vault's entries after it, in the same batch, bring one.
  await db.owner.transaction((tx) =>
    appendEntries(tx, deriveLogKey('app', randomBytes(32)), [{ actor: 'system:coffre-scheduler', action: 'audit.heartbeat', decision: 'allow', metadata: '{}' }]),
  );
  const vault = await fresh();
  const first = await vault.checkpoint();
  assert.ok(first.ok && first.checkpoint.seq === 0, JSON.stringify(first));
  await reads(3);
  const second = await vault.checkpoint();
  assert.ok(second.ok);
  const whole = await vault.verifyLog({ from: 'start', to: second.checkpoint.seq + 1 });
  assert.ok(whole.ok, JSON.stringify(whole));
});

test('an app older than 0.10.1, which names no `from`, gets an ok only for the whole of its head', async () => {
  const w = await world();
  await reads(5);
  const [head] = await store.vaultPage(db.owner, undefined, 1);
  const upTo = { seq: Number(head!.seq), hash: head!.hash.toString('hex') };
  const short = await openLocalVault(db.vault, configure(), { walks: { verify: 3 } });
  const legacy = await short.verifyLog({ upTo });
  assert.ok(!legacy.ok && /update the app/.test(legacy.reason), JSON.stringify(legacy));
  // Naming where it starts, a caller takes `through` for what it is.
  const current = await short.verifyLog({ upTo, from: 'start' });
  assert.ok(current.ok && current.through! < upTo.seq, JSON.stringify(current));
  // A walk whose budget ends at the last entry is done, and holds the rows to it.
  const exact = await openLocalVault(db.vault, configure(), { walks: { verify: 6 } });
  assert.deepEqual(await exact.verifyLog({ upTo, from: 'start' }), { ok: true, entries: 6, through: upTo.seq });
  void w;
});

test('a stretch ends no further than the checkpoints one call holds it to', async () => {
  const w = await world();
  const signed: number[] = [];
  for (let i = 0; i < 4; i++) {
    await reads(1);
    const checkpoint = await w.vault.checkpoint();
    assert.ok(checkpoint.ok);
    signed.push(checkpoint.checkpoint.seq + 1);
  }
  const short = await openLocalVault(db.vault, configure(), { walks: { verify: 2 } });
  const far = await short.verifyLog({ from: 'start', to: signed.at(-1)! });
  assert.deepEqual(!far.ok && [far.failedAtSeq, far.reason], [signed.at(-1), 'a stretch passes no more than 2 checkpoints: end one sooner']);
  assert.equal((await short.verifyLog({ from: 'start', to: signed[1]! })).ok, true);
});

test('a verification counts the prefix it resumes from: an entry cut before the newest checkpoint is found', async () => {
  const w = await world();
  await reads(10);
  const signed = await w.vault.checkpoint();
  assert.ok(signed.ok);
  await reads(2);
  const { auditLog } = tablesOf(db.owner);
  await withLogUnlocked(db.owner, (owned) => owned.delete(auditLog).where(eq(auditLog.seq, 5n)));
  const verdict = await (await fresh()).verifyLog({});
  assert.deepEqual(!verdict.ok && [verdict.failedAtSeq, verdict.reason], [6, 'sequence gap: expected seq 5, found 6']);
});

test("access changed after the app's head is read by the vault's own walk, not taken for tampering", async () => {
  const w = await world();
  await member(w, ADA, [[w.dev, 'viewer']]);
  const [head] = await store.vaultPage(db.owner, undefined, 1);
  const upTo = { seq: Number(head!.seq), hash: head!.hash.toString('hex') };
  // Bob admitted, and Ada's grant gone, between the app's snapshot and the vault's.
  await member(w, BOB, [[w.dev, 'viewer']]);
  assert.equal((await w.vault.setAccess({ actor: ROOT, principal: ADA, changes: [{ projectId: w.project, environmentId: w.dev, role: null, expiresAt: null }] })).ok, true);
  const verdict = await w.vault.verifyLog({ upTo });
  assert.deepEqual(verdict.ok && verdict.through, upTo.seq, JSON.stringify(verdict));
});

/**
 * Change entry `seq`'s metadata, then chain the log again from there, seal the vault's entries under its key and
 * sign its checkpoints over the new hashes: all that a holder of its key could.
 */
async function rewriteMetadata(seq: bigint, change: (metadata: Record<string, unknown>) => Record<string, unknown>) {
  const { auditLog, auditChainHead } = tablesOf(db.owner);
  const entries = (await db.owner.select().from(auditLog).where(gte(auditLog.seq, seq)).orderBy(asc(auditLog.seq))) as StoredEntry[];
  const signing = await signer(SIGNING_KEY);
  const hashes = new Map<bigint, string>();
  await withLogUnlocked(db.owner, async (owned) => {
    let prevHash = entries[0]!.prevHash;
    for (const entry of entries) {
      let metadata = entry.seq === seq ? JSON.stringify(change(JSON.parse(entry.metadata) as Record<string, unknown>)) : entry.metadata;
      if (entry.seq > seq && entry.action === 'audit.checkpoint' && entry.decision === 'allow') {
        const kept = JSON.parse(metadata) as Checkpoint;
        const hash = hashes.get(BigInt(kept.seq)) ?? kept.hash;
        metadata = JSON.stringify({ ...kept, hash, signature: await signing.sign(checkpointMessage({ seq: kept.seq, hash, signedAt: kept.signedAt })) });
      }
      const changed = { ...entry, metadata, prevHash };
      const mac = entry.author === 'vault' ? entryMac(VAULT_KEY.key, prevHash, changed) : entry.mac;
      const hash = entryHash(prevHash, changed, mac);
      await owned.update(auditLog).set({ metadata, prevHash, mac, hash }).where(eq(auditLog.seq, entry.seq));
      hashes.set(entry.seq, hash.toString('hex'));
      prevHash = hash;
    }
    await owned.update(auditChainHead).set({ headHash: prevHash });
  });
  forgetLogHeads();
}

test('a checkpoint finds a row changed around the vault before its member asks for anything', async () => {
  const w = await world();
  const { vaultGrants } = tablesOf(db.owner);
  await member(w, ADA, [[w.dev, 'viewer']]);
  await member(w, BOB, [[w.dev, 'viewer']]);
  assert.ok((await w.vault.checkpoint()).ok);
  assert.deepEqual(await tamperings(w), []);

  // Lists read rows without the vault, so the scheduled checkpoint is what looks.
  await db.owner.insert(vaultGrants).values({
    principal: ADA, projectId: w.project, environmentId: null, role: 'owner', expiresAt: null, grantedAt: Date.now(), grantedBy: ROOT,
  });
  assert.ok((await w.vault.checkpoint()).ok);
  assert.deepEqual(await tamperings(w), [[ADA, 'mac']]);
  // Found once, logged once.
  assert.ok((await w.vault.checkpoint()).ok);
  assert.deepEqual(await tamperings(w), [[ADA, 'mac']]);
});

test('an old member row put back with its grants is refused: the log holds the later change', async () => {
  const w = await world();
  await member(w, ADA, [[null, 'maintainer']]);
  const putBack = await snapshot(ADA);
  const secret = await w.secret(w.dev);
  const items = [{ secret, wrapped: await wrapped(w, secret) }];

  assert.equal((await w.vault.remove({ actor: ROOT, principal: ADA })).ok, true);
  // Every byte genuine, MAC and all: only its age gives it away.
  await putBack();
  const access = await w.vault.access(ADA);
  assert.equal(access.status, 'tampered');
  const read = await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: await versionItems(items) });
  assert.equal(!read.ok && read.refusal.code, 'tampered');
  assert.deepEqual((await tamperings(w)).map(([, code]) => code), ['stale']);
  const verdict = await w.vault.verifyLog({});
  assert.deepEqual(!verdict.ok && verdict.fault, { kind: 'tampered-member', principal: ADA, why: 'stale' });

  // Starting over moves the generation past the row's and the log's.
  assert.equal((await w.vault.remove({ actor: ROOT, principal: ADA })).ok, true);
  assert.deepEqual([(await w.vault.access(ADA)).status, (await w.vault.access(ADA)).generation], ['removed', 2]);
  assert.equal((await w.vault.verifyLog({})).ok, true);
});

test('a generation edited back is refused, and so is a member row deleted outright', async () => {
  const w = await world();
  const { vaultMembers } = tablesOf(db.owner);
  await member(w, ADA, []);
  await member(w, BOB, []);
  assert.equal((await w.vault.remove({ actor: ROOT, principal: ADA })).ok, true);
  assert.equal((await w.vault.admit({ actor: ROOT, principal: ADA })).ok, true);

  // Back to the generation an old session was issued under.
  await db.owner.update(vaultMembers).set({ generation: 0 }).where(eq(vaultMembers.principal, ADA));
  assert.deepEqual([(await w.vault.access(ADA)).status, (await w.vault.access(ADA)).generation], ['tampered', 0]);

  // A row the log admitted, gone: not a stranger, but a member taken out.
  await db.owner.delete(vaultMembers).where(eq(vaultMembers.principal, BOB));
  assert.equal((await w.vault.access(BOB)).status, 'tampered');
  const admitted = await w.vault.admit({ actor: ROOT, principal: BOB });
  assert.equal(!admitted.ok && admitted.refusal.code, 'tampered');
  assert.equal((await w.vault.remove({ actor: ROOT, principal: BOB })).ok, true, 'removal puts the row back, removed');
  assert.deepEqual([(await w.vault.access(BOB)).status, (await w.vault.access(BOB)).generation], ['removed', 1]);

  assert.equal((await w.vault.remove({ actor: ROOT, principal: ADA })).ok, true);
  assert.equal((await w.vault.access(ADA)).generation, 2, 'past the log\'s 1, whatever the row said');
  assert.equal((await w.vault.verifyLog({})).ok, true);
});

test('an entry forged in the vault\'s name about a member is passed over and reported, not obeyed', async () => {
  const w = await world();
  const { auditLog, auditChainHead } = tablesOf(db.owner);
  await member(w, ADA, [[w.dev, 'viewer']]);
  const secret = await w.secret(w.dev);
  const items = [{ secret, wrapped: await wrapped(w, secret) }];

  // A "removal" of Ada, linked to the chain, with a MAC made up: were it
  // believed, her row would look stale and she would be locked out.
  const [head] = await db.owner.select().from(auditChainHead);
  const fields = {
    seq: head.nextSeq, author: 'vault' as const, keyId: VAULT_KEY.keyId, occurredAt: Date.now(), actor: ROOT,
    action: 'member.remove', decision: 'allow', code: null, subjectPrincipal: ADA, projectId: null, environmentId: null,
    secretId: null, secretVersionId: null, operationId: null, requestId: null, sourceIp: null, relatedSeq: null, metadata: '{}',
  };
  const mac = Buffer.alloc(32, 7);
  const hash = entryHash(head.headHash, fields, mac);
  await db.owner.insert(auditLog).values({ ...fields, prevHash: head.headHash, mac, hash });
  await db.owner.update(auditChainHead).set({ nextSeq: head.nextSeq + 1n, headHash: hash });

  assert.equal((await w.vault.access(ADA)).status, 'active');
  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: await versionItems(items) })).ok, true);
  assert.deepEqual(await tamperings(w), [[ADA, 'forged_entry']]);
  const verdict = await w.vault.verifyLog({});
  assert.deepEqual(verdict.ok ? null : [verdict.failedAtSeq, verdict.reason], [Number(fields.seq), 'not written by the vault: its MAC does not match']);
});

test('the newest entries cut from the log without its head stop the next decision', async () => {
  const w = await world();
  const { auditLog } = tablesOf(db.owner);
  await member(w, ADA, [[w.dev, 'viewer']]);
  const [last] = await db.owner.select({ seq: auditLog.seq }).from(auditLog).orderBy(desc(auditLog.seq)).limit(1);
  await withLogUnlocked(db.owner, (owned) => owned.delete(auditLog).where(eq(auditLog.seq, last.seq)));

  await assert.rejects(
    w.vault.setAccess({ actor: ROOT, principal: ADA, changes: [{ projectId: w.project, environmentId: w.prod, role: 'viewer', expiresAt: null }] }),
    (error) => error instanceof LogHeadMismatch,
  );
  const verdict = await w.vault.verifyLog({});
  assert.equal(verdict.ok, false);
});

test('the database holds no key', async () => {
  const kek = randomBytes(32);
  const w = await world({ keks: new KekRegistry(new LocalKekProvider(kek, 'test-kek-1')) });
  await member(w, ADA, [[w.dev, 'developer']]);
  const secret = await w.secret(w.dev);
  const key = randomBytes(32);
  const wrap = await w.vault.wrap({ principal: ADA, items: [{ secret, key: key.toString('base64') }] });
  assert.ok(wrap.ok);
  await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: await versionItems([{ secret, wrapped: wrap.wrapped[0] }]) });
  const everything = [];
  for (const table of ['audit_log', 'audit_chain_head', 'vault_members', 'vault_grants']) {
    everything.push(...(await rows<Record<string, unknown>>(db.owner, sql.raw(`SELECT * FROM ${table}`))));
  }
  const dump = Buffer.concat(
    everything.flatMap((row) => Object.values(row).map((value) => (Buffer.isBuffer(value) ? value : Buffer.from(String(value))))),
  );
  assert.ok(dump.includes(secret.path), 'the log entry is where this looks');
  for (const needle of [kek, key]) {
    assert.equal(dump.includes(needle), false);
    for (const encoding of ['base64', 'hex'] as const) assert.equal(dump.includes(needle.toString(encoding)), false);
  }
});

// --- the vault's own keys, from its KEK ---------------------------------------------

const localKek = (id: string) => ({ id, key: randomBytes(32).toString('base64') });
const hex = (key: Uint8Array) => Buffer.from(key).toString('hex');

/** A vault from a deployment's own configuration, over places already made: several can follow one another. */
async function configured(placed: Awaited<ReturnType<typeof places>>, keys: Pick<VaultConfig, 'kek' | 'previousKeks' | 'signingKey'>): Promise<World> {
  const resolved = resolveVaultConfig({ owners: ['root@acme.example'], ...keys });
  const clock = { offset: 0 };
  const vault = await openLocalVault(db.vault, resolved, { clockOffset: () => clock.offset });
  // Root, signing in, owns the instance: the first such vault makes them its Owner, and the others find them one.
  // One whose key the log moved on from answers nobody (`access`), and its test says how.
  await vault.access(ROOT).catch((error: unknown) => assert.match(String(error), /a key this vault does not hold|the log moved on/));
  return { ...placed, vault, clock, twin: async () => openLocalVault(await db.connect(), resolved) };
}

test('a local KEK stands for one signing key: the same for the same KEK, another for another, never the KEK', () => {
  const kek = localKek('kek-1');
  const one = resolveVaultConfig({ kek, owners: ['root@acme.example'] });
  assert.equal(one.signingKeys.length, 1);
  assert.deepEqual(resolveVaultConfig({ kek, owners: ['root@acme.example'] }).signingKeys.map(hex), one.signingKeys.map(hex));
  const other = resolveVaultConfig({ kek: localKek('kek-1'), owners: ['root@acme.example'] });
  assert.notEqual(hex(other.signingKeys[0]!), hex(one.signingKeys[0]!));
  assert.notEqual(hex(one.signingKeys[0]!), Buffer.from(kek.key, 'base64').toString('hex'));
  // A signing key given is the one it signs with; the KEK's own only verifies, as after a move to KMS.
  const given = resolveVaultConfig({ kek, owners: ['root@acme.example'], signingKey: SIGNING_KEY.toString('base64') });
  assert.deepEqual(given.signingKeys.map(hex), [hex(SIGNING_KEY), hex(one.signingKeys[0]!)]);
});

test('a vault given only a KEK signs and verifies its checkpoints, and the member rows it seals hold', async () => {
  const placed = await places(db.owner);
  const kek = localKek('kek-1');
  const w = await configured(placed, { kek });
  await member(w, ADA, [[w.dev, 'developer']]);
  const secret = await w.secret(w.dev);
  const items = await versionItems([{ secret, wrapped: await wrapped(w, secret) }]);
  const signed = await w.vault.checkpoint();
  assert.ok(signed.ok);
  const { checkpointKeys } = await w.vault.about();
  assert.deepEqual(Object.keys(checkpointKeys), [signed.checkpoint.keyId]);
  assert.equal(checkpointKeys[signed.checkpoint.keyId]!.until, null);
  assert.equal(await verifyCheckpoint(signed.checkpoint, checkpointKeys[signed.checkpoint.keyId]!.publicKey), true);

  // Another process, started from the same KEK, holds the same keys.
  const again = await configured(placed, { kek });
  assert.equal((await again.vault.access(ADA)).status, 'active');
  assert.equal((await again.vault.unwrap({ principal: ADA, purpose: 'reveal', items })).ok, true);
  assert.equal((await again.vault.verifyLog({})).ok, true);
  assert.ok((await again.vault.checkpoint()).ok);
});

/** The keys a vault derives from `kek`: what whoever kept the KEK could forge with. */
function keysFrom(kek: { key: string }) {
  const seed = derivedSigningKey(Buffer.from(kek.key, 'base64'));
  return { log: vaultLogKey(seed), row: rowKey(seed) };
}

/** Each checkpoint key's `until`, by key id. */
async function bounds(w: World) {
  return Object.fromEntries(Object.entries((await w.vault.about()).checkpointKeys).map(([keyId, key]) => [keyId, key.until]));
}

test('a KEK rotation moves the log and every member row to the new key at the first call, and the past verifies under the old one', async () => {
  const placed = await places(db.owner);
  const [old, next] = [localKek('kek-1'), localKek('kek-2')];
  const before = await configured(placed, { kek: old });
  await member(before, ADA, [[before.dev, 'developer']]);
  const secret = await before.secret(before.dev);
  const items = await versionItems([{ secret, wrapped: await wrapped(before, secret) }]);
  const first = await before.vault.checkpoint();
  assert.ok(first.ok);

  const after = await configured(placed, { kek: next, previousKeks: [old] });
  // Its first call, whatever it is, writes the rotation, its first entry under the new key, and seals Ada's row again under it.
  assert.equal((await after.vault.access(ADA)).status, 'active');
  const rotation = (await vaultLog(after)).at(-1)!;
  assert.deepEqual([rotation.action, rotation.detail], ['key.rotate', { from: keysFrom(old).log.keyId }]);
  assert.equal((await store.vaultPage(db.owner, undefined, 1))[0]!.keyId, keysFrom(next).log.keyId);
  assert.ok(sealed(keysFrom(next).row, (await store.member(db.owner, ADA))!, await store.grants(db.owner, ADA)));
  // Her data key, wrapped under the old KEK, opens.
  assert.equal((await after.vault.unwrap({ principal: ADA, purpose: 'reveal', items })).ok, true);
  await wrapped(after, await after.secret(after.prod));
  const second = await after.vault.checkpoint();
  assert.ok(second.ok);
  assert.notEqual(second.checkpoint.keyId, first.checkpoint.keyId, 'the new KEK signs under a key of its own');
  // The old key's checkpoints count only over prefixes before the rotation.
  assert.deepEqual(await bounds(after), { [second.checkpoint.keyId]: null, [first.checkpoint.keyId]: rotation.seq });
  assert.equal((await after.vault.verifyLog({})).ok, true, 'every entry, both checkpoints, and the rows replayed');
  // Another instance with the same keys finds the rotation, and writes none of its own.
  const twin = await configured(placed, { kek: next, previousKeks: [old] });
  assert.equal((await twin.vault.access(ADA)).status, 'active');
  assert.deepEqual(await bounds(twin), await bounds(after));
  assert.equal((await vaultLog(after)).filter((entry) => entry.action === 'key.rotate').length, 1);

  // Without the old KEK, what its key signed no longer verifies: it must stay configured.
  const forgot = await configured(placed, { kek: next });
  const verdict = await forgot.vault.verifyLog({ from: 'start' });
  assert.ok(!verdict.ok);
  assert.match(verdict.reason, /a key this verifier does not hold: either it is forged, or the vault wrote it under another vault key or signing key/);
  // Nor does a checkpoint go on from a tally it keeps in an entry the old key wrote.
  const refused = await forgot.vault.checkpoint();
  assert.equal(!refused.ok && refused.refusal.code, 'log_broken');
});

test('after a rotation, the replaced KEK vouches for nothing new: entries and rows forged under its keys fail, and what it wrote before still verifies', async () => {
  const placed = await places(db.owner);
  const [old, next] = [localKek('kek-1'), localKek('kek-2')];
  const before = await configured(placed, { kek: old });
  await member(before, ADA, [[before.dev, 'viewer']]);
  assert.ok((await before.vault.checkpoint()).ok);
  const after = await configured(placed, { kek: next, previousKeks: [old] });
  assert.ok((await after.vault.checkpoint()).ok);
  assert.equal((await after.vault.verifyLog({})).ok, true, 'the entries and checkpoint written under the old key');

  // Whoever kept the old KEK, and can write the database, forges with its keys.
  const leaked = keysFrom(old);
  // An access entry about Ada is passed over, and reported.
  const forged = await db.vault.transaction((tx) =>
    appendEntries(tx, leaked.log, [{ actor: ROOT, action: 'access.grant', decision: 'allow', subjectPrincipal: ADA, metadata: '{}' }]),
  );
  assert.equal((await after.vault.access(ADA)).status, 'active');
  assert.deepEqual(await tamperings(after), [[ADA, 'forged_entry']]);
  // A grant given to her, with her row sealed again under the old row key, leaves her tampered.
  const { vaultGrants, vaultMembers } = tablesOf(db.owner);
  await db.owner.insert(vaultGrants).values({
    principal: ADA, projectId: after.project, environmentId: null, role: 'owner', expiresAt: null, grantedAt: Date.now(), grantedBy: ROOT,
  });
  const row = (await store.member(db.owner, ADA))!;
  const mac = memberMac(leaked.row, row, await store.grants(db.owner, ADA));
  await db.owner.update(vaultMembers).set({ mac }).where(eq(vaultMembers.principal, ADA));
  assert.equal((await after.vault.access(ADA)).status, 'tampered');
  // And the log stops verifying where the old key wrote again, so the vault signs it no more.
  const verdict = await after.vault.verifyLog({});
  assert.ok(!verdict.ok);
  assert.equal(verdict.failedAtSeq, Number(forged.seqStart));
  assert.match(verdict.reason, /^written under vault:\S+ after the vault moved to vault:\S+: a key it replaced verifies only what came before$/);
  const refused = await after.vault.checkpoint();
  assert.equal(!refused.ok && refused.refusal.code, 'log_broken');
});

test('a vault still running with the replaced KEK, as during a deploy, writes nothing after the rotation', async () => {
  const placed = await places(db.owner);
  const [old, next] = [localKek('kek-1'), localKek('kek-2')];
  const before = await configured(placed, { kek: old });
  await member(before, ADA, [[before.dev, 'viewer']]);
  const after = await configured(placed, { kek: next, previousKeks: [old] });
  assert.equal((await after.vault.access(ADA)).status, 'active');
  const logged = (await vaultLog(after)).length;

  // The old instance settled before the rotation: its next write finds it, under the log's lock, and fails.
  const change = { projectId: before.project, environmentId: before.prod, role: 'viewer' as const, expiresAt: null };
  await assert.rejects(
    before.vault.setAccess({ actor: ROOT, principal: ADA, changes: [change] }),
    /^Error: the log moved on to vault:\S+, a key this vault does not hold: a vault given a newer vault key replaced it/,
  );
  // From then on it refuses, as does one started afresh with the old KEK.
  const late = await configured(placed, { kek: old });
  for (const vault of [before.vault, late.vault]) {
    const refused = await vault.setAccess({ actor: ROOT, principal: ADA, changes: [change] });
    assert.equal(!refused.ok && refused.refusal.code, 'wrong_kek');
    const unsigned = await vault.checkpoint();
    assert.equal(!unsigned.ok && unsigned.refusal.code, 'wrong_kek');
  }
  const refused = await late.vault.setAccess({ actor: ROOT, principal: ADA, changes: [change] });
  assert.match(!refused.ok ? refused.refusal.message : '', /^the log moved on from this vault's key, vault:\S+, to vault:\S+: a vault given a newer vault key replaced it/);
  // Nor does it say who anyone is: it can check no row, and it is an outage, not a verdict on Ada.
  await assert.rejects(late.vault.access(ADA), /^Error: the log moved on from this vault's key/);
  assert.equal((await vaultLog(after)).length, logged, 'neither wrote anything');
  assert.equal((await after.vault.verifyLog({})).ok, true);
});

test("what an escrowed vault key is checked against: each key's check, newest first, the current key named, and only the checks the vault wrote", async () => {
  const placed = await places(db.owner);
  const [old, next] = [localKek('kek-1'), localKek('kek-2')];
  // A vault that has opened nothing yet writes its key's check when asked, as before its first key operation.
  const before = await configured(placed, { kek: old });
  const first = await before.vault.keyChecks();
  assert.deepEqual(first.current, { kekProvider: 'local', kekId: 'kek-1' });
  assert.deepEqual(first.checks.map(({ kekId }) => kekId), ['kek-1']);

  const after = await configured(placed, { kek: next, previousKeks: [old] });
  const { current, checks } = await after.vault.keyChecks();
  assert.deepEqual(current, { kekProvider: 'local', kekId: 'kek-2' });
  assert.deepEqual(checks.map(({ kekId }) => kekId), ['kek-2', 'kek-1']);
  assert.ok(checks[0]!.seq > checks[1]!.seq);
  // Each opens under its own key, and only there: none of it is a secret.
  const opens = (kek: { key: string }, check: WrappedKey) => opensKeyCheck(Buffer.from(kek.key, 'base64'), { ...check, bytes: Buffer.from(check.bytes, 'base64') });
  assert.deepEqual(
    await Promise.all([opens(next, checks[0]!), opens(old, checks[1]!), opens(old, checks[0]!), opens(localKek('kek-2'), checks[0]!)]),
    [true, true, false, false],
  );

  // A check in the vault's name that it did not write, newer, under a key whoever wrote it knows, is not given.
  const forger = localKek('kek-2');
  const wrapped = await new LocalKekProvider(Buffer.from(forger.key, 'base64'), 'kek-2').wrap(Buffer.from(KEY_CHECK_VALUE), KEY_CHECK_CONTEXT);
  const metadata = JSON.stringify({ kekProvider: 'local', kekId: 'kek-2', kekVersion: wrapped.kekVersion, bytes: wrapped.bytes.toString('base64'), proof: null });
  await db.vault.transaction((tx) => appendEntries(tx, keysFrom(forger).log, [{ actor: 'system:vault', action: KEY_CHECK, decision: 'allow', metadata }]));
  assert.deepEqual((await after.vault.keyChecks()).checks, checks);
});

test('a KEK a key service holds needs a signing key, and the error says why', () => {
  const kms = awsKms({ keyArn: 'arn:aws:kms:eu-west-3:123456789012:key/kms', credentials: { accessKeyId: 'a', secretAccessKey: 'b' } });
  assert.throws(
    () => resolveVaultConfig({ kek: kms, owners: ['root@acme.example'] }),
    /^Error: signingKey is required with the aws-kms vault key arn:aws:kms:eu-west-3:123456789012:key\/kms: the vault derives its signing key only from a vault key it holds/,
  );
  const moved = resolveVaultConfig({
    kek: kms, previousKeks: [localKek('kek-1')], owners: ['root@acme.example'], signingKey: SIGNING_KEY.toString('base64'),
  });
  assert.equal(moved.signingKeys.length, 2, 'the signing key, and the key of the local KEK it replaced, for what that signed');
});

test('configuration', () => {
  const key = randomBytes(32).toString('base64');
  const base = { kek: { id: 'kek-1', key }, owners: ['admin@example.com'], signingKey: key };
  const resolved = resolveVaultConfig({
    ...base,
    previousKeks: [{ id: 'kek-0', key: randomBytes(32).toString('base64') }],
    bulkLimit: { count: 20, windowMinutes: 0.5 },
  });
  assert.equal(resolved.keks.primary.keyId, 'kek-1');
  assert.deepEqual(resolved.bulkLimit, { count: 20, windowMs: 30_000 });
  assert.deepEqual(resolveVaultConfig(base).bulkLimit, { count: 1000, windowMs: 900_000 });
  assert.throws(() => resolveVaultConfig({ ...base, bulkLimit: { count: 0, windowMinutes: 1 } }), /bulkLimit/);
  assert.throws(() => resolveVaultConfig({ ...base, kek: { id: 'kek-1', key: 'c2hvcnQ=' } }), /32 bytes/);
  assert.throws(() => resolveVaultConfig({ ...base, signingKey: '' }), /signing key/);
  assert.throws(() => resolveVaultConfig({ ...base, previousKeks: [{ id: 'kek-1', key }] }), /share an id/);
  assert.throws(() => resolveVaultConfig({ ...base, kek: { id: 'kek 1', key } }), /the vault key's ID/);

  // A key service's KEK, with the local one before it still opening what it wrapped.
  const keyArn = 'arn:aws:kms:eu-west-3:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab';
  const credentials = { accessKeyId: 'AKIAEXAMPLE', secretAccessKey: 'secret' };
  const kms = resolveVaultConfig({ ...base, kek: awsKms({ keyArn, credentials }), previousKeks: [base.kek] });
  assert.deepEqual([kms.keks.primary.provider, kms.keks.primary.keyId], ['aws-kms', keyArn]);
  assert.throws(
    () => resolveVaultConfig({ ...base, kek: awsKms({ keyArn, credentials }), previousKeks: [awsKms({ keyArn, credentials })] }),
    /two vault keys share an id: aws-kms:arn:aws:kms:eu-west-3/,
  );
  const own = LocalKekProvider.generate('own-1');
  for (const [kek, message] of [
    [Object.assign(Object.create(own) as KekProvider, { provider: 'Vault Transit' }), /name \(kek\.provider\) must be 1-32 lowercase letters/],
    [Object.assign(Object.create(own) as KekProvider, { keyId: 'has space' }), /keyId and keyVersion must be 1-255 visible ASCII/],
    [{ provider: 'transit', keyId: 'k', keyVersion: '1', wrap: own.wrap } as unknown as KekProvider, /transit:k needs wrap\(\) and unwrap\(\)/],
  ] as const) {
    assert.throws(() => resolveVaultConfig({ ...base, kek }), message);
  }
  assert.deepEqual(checkOwners(['First.Admin@example.com', ' second@example.org ']), ['first.admin@example.com', 'second@example.org']);
  assert.throws(() => checkOwners([]), /at least one/);
  assert.throws(() => checkOwners(['admin@example,com']), /human email/);
  assert.throws(() => checkOwners(['ci-deploy.access']), /human email/);
  // 0.5's name, which a deployment's vault reads until 0.7, is the same list.
  // `bootstrapOwners`, and 0.5's `rootAdmins`, name them until 0.7.
  const { owners: _, ...unnamed } = base;
  assert.deepEqual(resolveVaultConfig({ ...unnamed, bootstrapOwners: ['Sam@example.com'] }).owners, ['sam@example.com']);
  assert.deepEqual(resolveVaultConfig({ ...unnamed, rootAdmins: ['Old.Root@example.com'] }).owners, ['old.root@example.com']);
  for (const malformed of [
    'admin@.example.com',
    'admin@example..com',
    'admin@example.com.',
    '.admin@example.com',
    'admin..root@example.com',
    'admin@-example.com',
  ]) {
    assert.throws(() => checkOwners([malformed]), /human email/, malformed);
  }
});

test('membership generations advance on removal even when time does not', async () => {
  const w = await world();
  await member(w, ADA, []);
  assert.equal((await w.vault.access(ADA)).generation, 0);
  assert.equal((await w.vault.remove({ actor: ROOT, principal: ADA })).ok, true);
  assert.equal((await w.vault.access(ADA)).generation, 1);
  assert.equal((await w.vault.admit({ actor: ROOT, principal: ADA })).ok, true);
  assert.equal((await w.vault.access(ADA)).generation, 1);
  assert.equal((await w.vault.remove({ actor: ROOT, principal: ADA })).ok, true);
  assert.equal((await w.vault.access(ADA)).generation, 2);
  assert.equal((await w.vault.verifyLog({})).ok, true);
});


test('a deadline aborts KMS requests and drops queued keys before a removal can commit', async () => {
  const arn = 'arn:aws:kms:eu-west-3:123456789012:key/deadline';
  let started = 0;
  let active = 0;
  const kek = awsKms({
    keyArn: arn,
    credentials: { accessKeyId: 'test', secretAccessKey: 'test' },
    fetch: async (_url, init) => {
      // The KEK's check value, wrapped once before the first key operation.
      if (new Headers(init?.headers).get('x-amz-target') === 'TrentService.Encrypt') {
        return Response.json({ KeyId: arn, CiphertextBlob: Buffer.alloc(48, 1).toString('base64') });
      }
      started++;
      active++;
      try {
        await sleep(300, undefined, { signal: init?.signal ?? undefined });
        return Response.json({ KeyId: arn, Plaintext: Buffer.alloc(32, 7).toString('base64') });
      } finally {
        active--;
      }
    },
  });
  const w = await world({ keks: new KekRegistry(kek) }, { keyBudgetMs: 100 });
  await member(w, ADA, [[w.dev, 'developer']]);
  // The KEK's check first, so that the batch below is all the KMS work there is.
  await wrapped(w, await w.secret(w.dev));
  const items = [];
  for (let i = 0; i < 9; i++) {
    items.push({ secret: await w.secret(w.dev), wrapped: { kekProvider: 'aws-kms', kekId: arn, kekVersion: '1', bytes: 'Y2lwaGVydGV4dA==' } });
  }
  try {
    await assert.rejects(w.vault.unwrap({ principal: ADA, purpose: 'run', items: await versionItems(items) }), KekUnavailableError);
    assert.equal(active, 0, 'all in-flight requests settled before the decision ended');
    assert.equal(started, 8, 'the queued key never reached KMS');
    assert.ok((await (await w.twin()).remove({ actor: ROOT, principal: ADA })).ok);
    // One entry per outcome at the place, listing the keys it was: eight uncertain, one never sent.
    const outcomes = (await vaultLog(w)).filter((entry) => entry.action === 'secret.read');
    assert.deepEqual(outcomes.map((entry) => [entry.code, (entry.detail.secrets as unknown[] | undefined)?.length ?? 1]), [['kms_uncertain', 8], ['cancelled', 1]]);
  } finally {
    await sleep(650);
  }
  assert.equal(started, 8, 'no queued request started after removal');
});

for (const action of ['unwrap', 'rewrap'] as const) {
  test(`a mixed ${action} batch records opened keys as withheld and failed claims as bad_claim`, async () => {
    const remote = service();
    const w = await world({ keks: remote.keks });
    await member(w, ADA, [[w.dev, 'developer']]);
    const good = await w.secret(w.dev), bad = await w.secret(w.dev);
    const sealed = await wrapped(w, good);
    const items = [{ secret: good, wrapped: sealed, from: 1 }, { secret: bad, wrapped: sealed, from: 1 }];
    const result = action === 'unwrap'
      ? await w.vault.unwrap({ principal: ADA, purpose: 'run', items: await versionItems(items) })
      : await w.vault.rewrap({ principal: ADA, items: await Promise.all(items.map(async (item) => ({ secret: item.secret, ...(await versionItems([item]))[0] }))) });
    assert.equal(!result.ok && result.refusal.code, 'bad_claim');
    assert.equal(remote.seen.opened.length, 1);
    assert.ok(remote.seen.opened[0].every((byte) => byte === 0));
    assert.deepEqual((await vaultLog(w)).filter((entry) => entry.action === LOGGED[action]).map((entry) => entry.code), ['withheld', 'bad_claim']);
  });
}

test('the whole wrap batch is validated before any key reaches KMS', async () => {
  const remote = service();
  const w = await world({ keks: remote.keks });
  await member(w, ADA, [[w.dev, 'developer']]);
  const first = await w.secret(w.dev), second = await w.secret(w.dev);
  await assert.rejects(w.vault.wrap({ principal: ADA, items: [
    { secret: first, key: randomBytes(32).toString('base64') },
    { secret: second, key: Buffer.alloc(1).toString('base64') },
  ] }), /DEK must be/);
  assert.equal(remote.seen.wrap, 0);
  assert.equal((await vaultLog(w)).filter((entry) => entry.action === 'key.intent').length, 0);
});

test('unexpected provider errors are rethrown after every known key outcome commits', async () => {
  const inner = LocalKekProvider.generate('test-kek-1');
  const fault = new Error('unexpected provider error');
  let calls = 0;
  const kek: KekProvider = {
    provider: inner.provider, keyId: inner.keyId, keyVersion: inner.keyVersion,
    unwrap: (key, ctx) => inner.unwrap(key, ctx),
    // The first wraps the KEK's check value.
    wrap: (key, ctx) => ++calls === 3 ? Promise.reject(fault) : inner.wrap(key, ctx),
  };
  const w = await world({ keks: new KekRegistry(kek) });
  await member(w, ADA, [[w.dev, 'developer']]);
  const items = [];
  for (let i = 0; i < 2; i++) items.push({ secret: await w.secret(w.dev), key: randomBytes(32).toString('base64') });
  await assert.rejects(w.vault.wrap({ principal: ADA, items }), (error) => error === fault);
  assert.equal(calls, 3);
  const outcomes = (await vaultLog(w)).filter((entry) => entry.action === 'key.wrap');
  assert.deepEqual(outcomes.map((entry) => entry.code), ['withheld', 'key_error']);
  assert.ok((await w.vault.verifyLog({})).ok);
});

test('intents and outcomes have their own identities even when caller request ids repeat', async () => {
  const remote = service();
  const w = await world({ keks: remote.keks });
  const secret = await w.secret(w.dev);
  const operations = [randomUUID(), randomUUID()];
  for (const operationId of operations) {
    assert.ok((await w.vault.wrap({ principal: ROOT, requestId: 'repeated', operationId, items: [
      { secret, key: randomBytes(32).toString('base64') }, { secret, key: randomBytes(32).toString('base64') },
    ] })).ok);
  }
  const { auditLog } = tablesOf(db.owner);
  const log = await db.owner.select().from(auditLog).where(eq(auditLog.requestId, 'repeated')).orderBy(asc(auditLog.seq));
  const intents = log.filter((entry) => entry.action === 'key.intent');
  const ids = intents.map((entry) => JSON.parse(entry.metadata).intent);
  assert.equal(intents.length, 2);
  assert.ok(ids[0]);
  assert.notEqual(ids[0], ids[1]);
  // The operation id is the caller's, which every entry of the call carries.
  assert.deepEqual(intents.map((entry) => entry.operationId), operations);
  for (const [i, intent] of intents.entries()) {
    const outcomes = log.filter((entry) => entry.relatedSeq === intent.seq);
    assert.equal(outcomes.length, 2);
    assert.deepEqual(outcomes.map((entry) => JSON.parse(entry.metadata).item), [0, 1]);
    assert.ok(outcomes.every((entry) => JSON.parse(entry.metadata).intent === ids[i] && entry.operationId === intent.operationId));
  }
  assert.ok((await w.vault.verifyLog({})).ok);
});

for (const overdue of [false, true]) {
  test(`verification reports a ${overdue ? 'overdue' : 'still-running'} intent with no outcomes`, async () => {
    const w = await world();
    const operationId = randomUUID();
    const appended = await db.vault.transaction((tx) => appendEntries(tx, VAULT_KEY, [{
      actor: ADA, action: 'key.intent', decision: 'allow', operationId,
      metadata: JSON.stringify({ intent: randomUUID(), operation: 'key.wrap', expiresAt: Date.now() + 60_000, keys: [{ item: 0, subject: 'market/dev/KEY', secretId: randomUUID(), version: 1 }] }),
    }]));
    if (overdue) w.clock.offset = 120_000;
    const verification = await w.vault.verifyLog({});
    if (overdue) {
      assert.ok(!verification.ok);
      assert.equal(verification.failedAtSeq, Number(appended.seqStart));
      assert.match(verification.reason, /overdue/);
    } else {
      // Root made an Owner, as the deployment names them, and the intent.
      assert.deepEqual(verification, { ok: true, entries: 2, through: Number(appended.seqStart), pending: 1 });
    }
  });
}

for (const action of ['wrap', 'unwrap', 'rewrap'] as const) {
  test(`a malformed later context prevents all remote ${action} work`, async () => {
    const remote = service();
    const w = await world({ keks: remote.keks });
    const first = await w.secret(w.dev), second = await w.secret(w.dev);
    const sealed = await wrapped(w, first);
    remote.seen.wrap = 0;
    remote.seen.unwrap = 0;
    const items = [first, { ...second, secretId: 'not-a-uuid' }].map((secret) => ({
      secret, key: randomBytes(32).toString('base64'), wrapped: sealed, from: 1,
    }));
    const versions = await versionItems([{ secret: first, wrapped: sealed }, { secret: second, wrapped: sealed }]);
    const call = action === 'wrap' ? w.vault.wrap({ principal: ROOT, items })
      : action === 'unwrap' ? w.vault.unwrap({ principal: ROOT, purpose: 'run', items: [versions[0], { secretVersionId: 'not-a-uuid' }] })
      : w.vault.rewrap({ principal: ROOT, items: items.map((item, i) => ({ secret: item.secret, ...versions[i] })) });
    await assert.rejects(call, /must be a lowercase UUID/);
    assert.equal(remote.seen.wrap + remote.seen.unwrap, 0);
  });
}

for (const action of ['unwrap', 'rewrap'] as const) {
  test(`an unexpected ${action} error is recorded and rethrown rather than called a bad claim`, async () => {
    const inner = LocalKekProvider.generate('test-kek-1');
    const fault = new Error('unexpected decrypt fault');
    const kek: KekProvider = {
      provider: inner.provider, keyId: inner.keyId, keyVersion: inner.keyVersion,
      wrap: (key, ctx) => inner.wrap(key, ctx),
      unwrap: () => Promise.reject(fault),
    };
    const w = await world({ keks: new KekRegistry(kek) });
    const secret = await w.secret(w.dev);
    const items = [{ secret, wrapped: await wrapped(w, secret), from: 1 }];
    const versions = await versionItems(items);
    const call = action === 'unwrap' ? w.vault.unwrap({ principal: ROOT, purpose: 'run', items: versions })
      : w.vault.rewrap({ principal: ROOT, items: [{ secret, ...versions[0] }] });
    await assert.rejects(call, (error) => error === fault);
    const outcomes = (await vaultLog(w)).filter((entry) => entry.action === LOGGED[action]);
    assert.deepEqual(outcomes.map((entry) => entry.code), ['key_error']);
    assert.equal(outcomes[0].detail.uncertain, true);
    assert.ok((await w.vault.verifyLog({})).ok);
  });
}

for (const duplicate of [false, true]) {
  test(`verification refuses ${duplicate ? 'duplicate' : 'missing'} item outcomes`, async () => {
    const w = await world();
    const operationId = randomUUID();
    const intentId = randomUUID();
    const secret = await w.secret(w.dev);
    const intent = await db.vault.transaction((tx) => appendEntries(tx, VAULT_KEY, [{
      actor: ADA, action: 'key.intent', decision: 'allow', operationId,
      metadata: JSON.stringify({ intent: intentId, operation: 'key.wrap', expiresAt: Date.now() + 60_000, keys: [0, 1].map((item) => ({
        item, subject: secret.path, secretId: secret.secretId, version: secret.version,
      })) }),
    }]));
    const outcome = {
      actor: ADA, action: 'key.wrap', decision: 'allow' as const, operationId, relatedSeq: intent.seqStart,
      metadata: JSON.stringify({ intent: intentId, item: 0, subject: secret.path, secretId: secret.secretId, version: secret.version }),
    };
    await db.vault.transaction((tx) => appendEntries(tx, VAULT_KEY, duplicate ? [outcome, outcome] : [outcome]));
    if (!duplicate) w.clock.offset = 120_000;
    const result = await w.vault.verifyLog({});
    assert.equal(result.ok, false);
    if (!result.ok) assert.match(result.reason, duplicate ? /does not identify one item/ : /1 of 2 outcomes missing/);
  });
}

for (const forged of ['repeats an item', 'names another version'] as const) {
  test(`verification refuses a read of several whose outcome ${forged}`, async () => {
    const w = await world();
    const operationId = randomUUID();
    const intentId = randomUUID();
    const secrets = [await w.secret(w.dev, 'A'), await w.secret(w.dev, 'B')];
    const keys = secrets.map((secret, item) => ({ item, subject: secret.path, secretId: secret.secretId, version: secret.version }));
    const intent = await db.vault.transaction((tx) => appendEntries(tx, VAULT_KEY, [{
      actor: ADA, action: 'key.intent', decision: 'allow', operationId,
      metadata: JSON.stringify({ intent: intentId, operation: 'secret.read', expiresAt: Date.now() + 60_000, keys }),
    }]));
    const listed = forged === 'repeats an item' ? [keys[0], keys[0]] : [keys[0], { ...keys[1]!, version: 2 }];
    await db.vault.transaction((tx) => appendEntries(tx, VAULT_KEY, [{
      actor: ADA, action: 'secret.read', decision: 'allow', operationId, relatedSeq: intent.seqStart,
      projectId: w.project, environmentId: w.dev,
      metadata: JSON.stringify({ purpose: 'run', intent: intentId, secrets: listed }),
    }]));
    const result = await w.vault.verifyLog({});
    assert.equal(result.ok, false);
    if (!result.ok) assert.match(result.reason, forged === 'repeats an item' ? /does not identify one item/ : /does not match its intended secret/);
  });
}

// --- Owners of the whole instance -------------------------------------------------

const SAM = 'user:sam@acme.example';
const CAROL = 'user:carol@acme.example';
const DAN = 'user:dan@acme.example';

/** A vault whose deployment names `emails` its Owners (`owners`). */
function namingOwners(...emails: string[]): Promise<LocalVault> {
  return openLocalVault(db.vault, configure({ owners: emails }));
}

/** The vault's entries about members, oldest first, as `[action, subject, outcome, reason or code]`. */
async function ownership() {
  return (await store.vaultPage(db.owner, undefined, 200)).map(entryView).reverse()
    .filter((entry) => entry.action.startsWith('member.'))
    .map((entry) => [entry.action, entry.subject, entry.outcome, entry.code ?? entry.detail.reason ?? null]);
}

/** An outcome as `ok`, or its refusal as `code: message`. */
function outcomeOf(outcome: { ok: boolean; refusal?: { code: string; message: string } }): string {
  return outcome.ok ? 'ok' : `${outcome.refusal!.code}: ${outcome.refusal!.message}`;
}

/** Why nobody changes `email`, whom the deployment names. */
const named = (email: string) => `not_allowed: the deployment names ${email} an Owner (owners, in the vault's configuration): take them off that list and deploy first`;

test('on a new instance, the first person its deployment names to sign in becomes an Owner, then the rest of the list, signed in or not', async () => {
  await places(db.owner);
  const vault = await namingOwners('root@acme.example', 'sam@acme.example');
  // Ada, whom it does not name, is nobody, and makes nobody anything.
  assert.equal((await vault.access(ADA)).status, 'unknown');
  assert.deepEqual(await ownership(), []);
  const root = await vault.access(ROOT);
  assert.deepEqual([root.status, root.role, root.scope], ['active', 'owner', EVERYWHERE]);
  // The vault's next call, whoever's, makes Sam one too: he never signed in.
  assert.equal((await vault.access(ADA)).status, 'unknown');
  assert.deepEqual(await ownership(), [['member.add', ROOT, 'allow', 'owners'], ['member.add', SAM, 'allow', 'owners']]);
  const added = (await vaultLog()).filter((entry) => entry.action === 'member.add');
  assert.deepEqual(added.map((entry) => [entry.actor, entry.detail.role, entry.detail.scope]), [['system:vault', 'owner', EVERYWHERE], ['system:vault', 'owner', EVERYWHERE]]);
  // Started again, the vault finds them Owners, and writes nothing.
  const again = await namingOwners('root@acme.example', 'sam@acme.example');
  assert.deepEqual([(await again.access(SAM)).role, (await again.about()).owners], ['owner', ['root@acme.example', 'sam@acme.example']]);
  assert.equal((await ownership()).length, 2);
  assert.equal((await again.verifyLog({})).ok, true);
});

test('two people the list names, signing in at once on a new instance, both become Owners', postgresOnly('SQLite runs one writer at a time'), async () => {
  await places(db.owner);
  const first = await namingOwners('root@acme.example', 'sam@acme.example');
  const second = await openLocalVault(await db.connect(), configure({ owners: ['root@acme.example', 'sam@acme.example'] }));
  const [root, sam] = await headHeldWhile(() => [first.access(ROOT), second.access(SAM)]);
  assert.deepEqual([root, sam].map((access) => [access.status, access.role]), [['active', 'owner'], ['active', 'owner']]);
  assert.deepEqual((await store.instanceOwners(db.owner)).map((row) => row.principal).sort(), [ROOT, SAM]);
});

test('nobody demotes, narrows or removes an Owner the deployment names: not another Owner, nor they themselves', async () => {
  const w = await world();
  const market = { projects: { only: [w.project] }, environments: 'all' as const };
  assert.ok((await w.vault.admit({ actor: ROOT, principal: BOB, role: 'owner' })).ok);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA, role: 'admin' })).ok);
  const tries = {
    'step down': await w.vault.admit({ actor: ROOT, principal: ROOT, role: 'admin' }),
    'narrow their own scope': await w.vault.admit({ actor: ROOT, principal: ROOT, role: 'owner', scope: market }),
    leave: await w.vault.remove({ actor: ROOT, principal: ROOT }),
    'be demoted by an Owner': await w.vault.admit({ actor: BOB, principal: ROOT, role: 'developer' }),
    'be removed by an Owner': await w.vault.remove({ actor: BOB, principal: ROOT }),
    'be demoted by an Admin': await w.vault.admit({ actor: ADA, principal: ROOT, role: 'developer' }),
    'be removed by an Admin': await w.vault.remove({ actor: ADA, principal: ROOT }),
  };
  const rule = named('root@acme.example');
  assert.deepEqual(Object.fromEntries(Object.entries(tries).map(([what, outcome]) => [what, outcomeOf(outcome)])), Object.fromEntries(Object.keys(tries).map((what) => [what, rule])));
  // As they are, which changes nothing, is anyone's to say.
  assert.equal(outcomeOf(await w.vault.admit({ actor: BOB, principal: ROOT, role: 'owner' })), 'ok');
  // Bob, whom it does not name, steps down as any Owner may.
  assert.equal(outcomeOf(await w.vault.admit({ actor: BOB, principal: BOB, role: 'admin' })), 'ok');
  assert.deepEqual([(await w.vault.access(ROOT)).role, (await w.vault.access(BOB)).role], ['owner', 'admin']);
  const refused = (await vaultLog(w)).filter((entry) => entry.outcome === 'refuse' && entry.subject === ROOT);
  assert.deepEqual(refused.map((entry) => [entry.action, entry.actor, entry.code]), [
    ['member.add', ROOT, 'not_allowed'], ['member.add', ROOT, 'not_allowed'], ['member.remove', ROOT, 'not_allowed'],
    ['member.add', BOB, 'not_allowed'], ['member.remove', BOB, 'not_allowed'], ['member.add', ADA, 'not_allowed'], ['member.remove', ADA, 'not_allowed'],
  ]);
  assert.equal((await w.vault.verifyLog({})).ok, true);
});

test('an app of 0.5, running beside this vault during a deploy, still finds the root admins it lists: none', async () => {
  const w = await world();
  // What 0.5's members list, admit and remove do with the field (server api/members.ts of 0.5).
  const rootAdmins = (await w.vault.about()).rootAdmins as string[];
  assert.ok(Array.isArray(rootAdmins) && rootAdmins.length === 0);
  assert.equal(new Set(rootAdmins).has(ROOT), false);
  assert.deepEqual(rootAdmins.filter((root) => root === ROOT), []);
  assert.equal(rootAdmins.includes(ROOT), false, 'so 0.5 adds and removes root like anyone, and the vault decides');
  // Its other half, `access`, still holds what 0.5 reads: root's role, everywhere, and no `isRootAdmin`, which reads as false.
  const root = (await w.vault.access(ROOT)) as { role: string; scope: unknown; isRootAdmin?: boolean };
  assert.deepEqual([root.role, root.scope, root.isRootAdmin ?? false], ['owner', EVERYWHERE, false]);
  // Its Users page offers to remove root, whom this vault's deployment names: the vault refuses, and says where.
  assert.equal(outcomeOf(await w.vault.remove({ actor: ROOT, principal: ROOT })), named('root@acme.example'));
});

test('the last Owner of the whole instance is not demoted, narrowed or removed, themselves included', async () => {
  const w = await world(UNNAMED);
  const last = (outcome: { ok: boolean; refusal?: { code: string; message: string } }) => !outcome.ok && outcome.refusal;
  const yours = { code: 'last_owner', message: "you're the last Owner of the whole instance: make someone else an Owner first" };
  assert.deepEqual(last(await w.vault.admit({ actor: ROOT, principal: ROOT, role: 'admin' })), yours);
  assert.deepEqual(last(await w.vault.admit({ actor: ROOT, principal: ROOT, role: 'owner', scope: { projects: { only: [w.project] }, environments: 'all' } })), yours);
  assert.deepEqual(last(await w.vault.remove({ actor: ROOT, principal: ROOT })), yours);
  // An Owner of one project owns no instance, and counts for nothing here.
  assert.ok((await w.vault.admit({ actor: ROOT, principal: BOB, role: 'owner', scope: { projects: { only: [w.project] }, environments: 'all' } })).ok);
  assert.deepEqual(last(await w.vault.remove({ actor: ROOT, principal: ROOT })), yours);
  // Another Owner of all of it, and either may step down, or go.
  assert.ok((await w.vault.admit({ actor: ROOT, principal: BOB, role: 'owner' })).ok);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ROOT, role: 'admin' })).ok);
  assert.deepEqual(last(await w.vault.remove({ actor: BOB, principal: BOB })), yours);
  assert.equal((await w.vault.access(ROOT)).role, 'admin');
  const refused = (await vaultLog(w)).filter((entry) => entry.code === 'last_owner');
  assert.deepEqual(refused.map((entry) => [entry.action, entry.actor, entry.subject]), [
    ['member.add', ROOT, ROOT], ['member.add', ROOT, ROOT], ['member.remove', ROOT, ROOT], ['member.remove', ROOT, ROOT], ['member.remove', BOB, BOB],
  ]);
  assert.equal((await w.vault.verifyLog({})).ok, true);
});


test('only an Owner of the whole instance makes someone an Owner, or changes or removes one, scoped or not', async () => {
  const w = await world(UNNAMED);
  const market = { projects: { only: [w.project] }, environments: 'all' as const };
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA, role: 'admin' })).ok);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: BOB, role: 'owner', scope: market })).ok);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: CAROL })).ok);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: SAM })).ok);
  assert.ok((await w.vault.remove({ actor: ROOT, principal: SAM })).ok);
  const code = outcomeOf;
  const refused = 'not_allowed: only an Owner of the whole instance makes someone an Owner, or changes or removes one';
  // Ada runs the instance, as an Admin of all of it: no Owner is hers to make, change or remove.
  const tries = {
    promote: await w.vault.admit({ actor: ADA, principal: CAROL, role: 'owner' }),
    'promote within a scope': await w.vault.admit({ actor: ADA, principal: CAROL, role: 'owner', scope: market }),
    'add as one': await w.vault.admit({ actor: ADA, principal: DAN, role: 'owner' }),
    'bring back as one': await w.vault.admit({ actor: ADA, principal: SAM, role: 'owner', scope: market }),
    demote: await w.vault.admit({ actor: ADA, principal: BOB, role: 'admin' }),
    'widen the scope': await w.vault.admit({ actor: ADA, principal: BOB, role: 'owner' }),
    'remove a scoped one': await w.vault.remove({ actor: ADA, principal: BOB }),
    'remove the last': await w.vault.remove({ actor: ADA, principal: ROOT }),
    'demote the last': await w.vault.admit({ actor: ADA, principal: ROOT, role: 'admin' }),
  };
  assert.deepEqual(Object.fromEntries(Object.entries(tries).map(([what, outcome]) => [what, code(outcome)])), Object.fromEntries(Object.keys(tries).map((what) => [what, refused])));
  // Everything else is hers still: another's role, and an Owner as they are, which changes nothing.
  assert.equal(code(await w.vault.admit({ actor: ADA, principal: CAROL, role: 'developer' })), 'ok');
  assert.equal(code(await w.vault.admit({ actor: ADA, principal: BOB, role: 'owner', scope: market })), 'ok');
  assert.equal(code(await w.vault.admit({ actor: ADA, principal: BOB })), 'ok');
  // Nor is her own role hers to change, Owner or not.
  assert.match(code(await w.vault.admit({ actor: ADA, principal: ADA, role: 'owner' })), /^not_allowed/);
  assert.equal(code(await w.vault.admit({ actor: ADA, principal: ADA, role: 'auditor' })), 'not_allowed: nobody changes their own instance role: ask another admin');
  // An Owner of one project runs no instance, and makes no Owner either.
  assert.match(code(await w.vault.admit({ actor: BOB, principal: CAROL, role: 'owner', scope: market })), /^not_allowed/);
  // Root, an Owner of all of it, does each.
  assert.equal(code(await w.vault.admit({ actor: ROOT, principal: CAROL, role: 'owner', scope: market })), 'ok');
  assert.equal(code(await w.vault.admit({ actor: ROOT, principal: CAROL, role: 'owner' })), 'ok');
  assert.equal(code(await w.vault.admit({ actor: ROOT, principal: BOB, role: 'admin' })), 'ok');
  assert.equal(code(await w.vault.remove({ actor: ROOT, principal: CAROL })), 'ok');
  assert.deepEqual((await vaultLog(w)).filter((entry) => entry.actor === ADA && entry.outcome === 'refuse').map((entry) => [entry.action, entry.subject]), [
    ['member.add', CAROL], ['member.add', CAROL], ['member.add', DAN], ['member.add', SAM], ['member.add', BOB], ['member.add', BOB],
    ['member.remove', BOB], ['member.remove', ROOT], ['member.add', ROOT], ['member.add', ADA], ['member.add', ADA],
  ]);
  assert.equal((await w.vault.verifyLog({})).ok, true);
});

/**
 * `both` at once, each under rows the other does not lock, while another
 * connection holds the log's head: each gets as far as it can without it,
 * and only then may one take it. A check made before the head is made by
 * both, on the same state; one made under it, by one after the other.
 */
async function headHeldWhile<T>(both: () => Promise<T>[]): Promise<T[]> {
  const holder = await db.connect();
  let release = () => {};
  const held = new Promise<void>((resolve) => (release = resolve));
  let locked = () => {};
  const isLocked = new Promise<void>((resolve) => (locked = resolve));
  const holding = holder.transaction(async (tx) => {
    await lockLogHead(tx);
    locked();
    await held;
  });
  await isLocked;
  const running = both();
  await sleep(300);
  release();
  await holding;
  return Promise.all(running);
}

for (const how of ['each leaving', 'each stepping down'] as const) {
  test(`two Owners, ${how}, at once, leave one`, postgresOnly('SQLite runs one writer at a time'), async () => {
    const w = await world(UNNAMED);
    const other = await w.twin();
    assert.ok((await w.vault.admit({ actor: ROOT, principal: BOB, role: 'owner' })).ok);
    // Each about themselves, so each locks only their own row.
    const outcomes: { ok: boolean; refusal?: { code: string } }[] = await headHeldWhile<{ ok: boolean; refusal?: { code: string } }>(() => how === 'each leaving'
      ? [w.vault.remove({ actor: ROOT, principal: ROOT }), other.remove({ actor: BOB, principal: BOB })]
      : [w.vault.admit({ actor: ROOT, principal: ROOT, role: 'admin' }), other.admit({ actor: BOB, principal: BOB, role: 'admin' })]);
    assert.deepEqual(outcomes.map((outcome) => (outcome.ok ? 'ok' : outcome.refusal!.code)).sort(), ['last_owner', 'ok']);
    assert.equal((await store.instanceOwners(db.owner)).length, 1);
    assert.equal((await w.vault.verifyLog({})).ok, true);
  });
}

/**
 * `first`, then `second`, while another connection holds the log's head:
 * `first` takes its rows and waits for the head, `second` waits for a row
 * `first` holds, and decides only once `first` has committed. A check made
 * on rows read before their lock would see what was there before `first`.
 */
async function inTurn<A, B>(first: () => Promise<A>, second: () => Promise<B>): Promise<[A, B]> {
  const holder = await db.connect();
  let release = () => {};
  const held = new Promise<void>((resolve) => (release = resolve));
  let locked = () => {};
  const isLocked = new Promise<void>((resolve) => (locked = resolve));
  const holding = holder.transaction(async (tx) => {
    await lockLogHead(tx);
    locked();
    await held;
  });
  await isLocked;
  const one = first();
  await sleep(200);
  const two = second();
  await sleep(200);
  release();
  await holding;
  return [await one, await two];
}

test('an Owner demoted while they make another sees it: the promotion decides under their row\'s lock', postgresOnly('SQLite runs one writer at a time'), async () => {
  const w = await world();
  const other = await w.twin();
  assert.ok((await w.vault.admit({ actor: ROOT, principal: BOB, role: 'owner' })).ok);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: CAROL })).ok);
  // Root takes Bob's Owner away; Bob, still one when he asked, makes Carol an Owner.
  const [demoted, promoted] = await inTurn(
    () => w.vault.admit({ actor: ROOT, principal: BOB, role: 'admin' }),
    () => other.admit({ actor: BOB, principal: CAROL, role: 'owner' }),
  );
  assert.ok(demoted.ok);
  assert.deepEqual(!promoted.ok && promoted.refusal.code, 'not_allowed');
  assert.deepEqual((await store.instanceOwners(db.owner)).map((row) => row.principal), [ROOT]);
});

test('an Admin removing someone just made an Owner sees it: the removal decides under their row\'s lock', postgresOnly('SQLite runs one writer at a time'), async () => {
  const w = await world();
  const other = await w.twin();
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA, role: 'admin' })).ok);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: CAROL })).ok);
  const [promoted, removed] = await inTurn(
    () => w.vault.admit({ actor: ROOT, principal: CAROL, role: 'owner' }),
    () => other.remove({ actor: ADA, principal: CAROL }),
  );
  assert.ok(promoted.ok);
  assert.deepEqual(!removed.ok && removed.refusal.code, 'not_allowed');
  assert.equal((await w.vault.access(CAROL)).role, 'owner');
});


test('naming someone makes them an Owner again as the vault starts, however they were demoted or removed: the way back in once no Owner can sign in', async () => {
  const w = await world();
  assert.ok((await w.vault.admit({ actor: ROOT, principal: SAM, role: 'owner' })).ok);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: SAM, role: 'developer' })).ok);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: CAROL, role: 'owner' })).ok);
  assert.ok((await w.vault.remove({ actor: ROOT, principal: CAROL })).ok);
  // Root, the only Owner, can sign in no more: the deployment names Sam and Carol instead, and deploys.
  const deployed = await namingOwners('sam@acme.example', 'carol@acme.example');
  // Its first call, whoever's, makes them Owners, before either signs in: Sam given the role, Carol brought back.
  assert.equal((await deployed.access(ADA)).status, 'unknown');
  assert.deepEqual((await ownership()).slice(-2), [['member.role', SAM, 'allow', 'owners'], ['member.restore', CAROL, 'allow', 'owners']]);
  const [sam, carol] = [await store.member(db.owner, SAM), await store.member(db.owner, CAROL)];
  assert.deepEqual([sam!.status, sam!.role, carol!.status, carol!.role, carol!.generation], ['active', 'owner', 'active', 'owner', 1]);
  // Sam kept the grants he held; root, no longer named, is an Owner as before, now Sam's to demote.
  assert.equal(outcomeOf(await deployed.admit({ actor: SAM, principal: ROOT, role: 'admin' })), 'ok');
  assert.equal((await deployed.verifyLog({})).ok, true);
});

test('a list changed from one person to another makes the new one an Owner at the next start, and leaves the old one an Owner', async () => {
  await places(db.owner);
  const ALICE = 'user:alice@acme.example';
  const first = await namingOwners('alice@acme.example');
  assert.equal((await first.access(ALICE)).role, 'owner');
  // Deployed again naming Bob instead, while Alice owns the instance: its first call makes Bob one, before he signs in.
  const deployed = await namingOwners('bob@acme.example');
  assert.equal((await deployed.access(ADA)).status, 'unknown');
  assert.deepEqual([(await store.member(db.owner, BOB))?.role, (await store.member(db.owner, ALICE))?.role], ['owner', 'owner']);
  assert.deepEqual((await ownership()).at(-1), ['member.add', BOB, 'allow', 'owners']);
  assert.deepEqual(await deployed.access(BOB).then(({ status, role, scope }) => [status, role, scope]), ['active', 'owner', EVERYWHERE]);
  assert.equal((await deployed.access(ALICE)).role, 'owner');
});

test('taking someone off the list leaves them an Owner, whom an Owner may then demote, and who may step down', async () => {
  const w = await world({ owners: ['root@acme.example', 'sam@acme.example'] });
  assert.equal((await w.vault.access(SAM)).role, 'owner');
  assert.equal(outcomeOf(await w.vault.admit({ actor: ROOT, principal: SAM, role: 'admin' })), named('sam@acme.example'));
  // Deployed again without Sam: still an Owner, as his row says, and one like any other.
  const deployed = await namingOwners('root@acme.example');
  assert.deepEqual(await deployed.access(SAM).then(({ role, scope }) => [role, scope]), ['owner', EVERYWHERE]);
  assert.deepEqual((await deployed.about()).owners, ['root@acme.example']);
  assert.equal(outcomeOf(await deployed.admit({ actor: SAM, principal: SAM, role: 'admin' })), 'ok');
  assert.equal(outcomeOf(await deployed.admit({ actor: ROOT, principal: SAM, role: 'owner' })), 'ok');
  assert.equal(outcomeOf(await deployed.admit({ actor: ROOT, principal: SAM, role: 'developer' })), 'ok');
  // The next start makes nothing of him.
  assert.equal((await (await namingOwners('root@acme.example')).access(SAM)).role, 'developer');
  assert.equal((await ownership()).filter(([, subject, , reason]) => subject === SAM && reason === 'owners').length, 1);
});

test('an Owner the deployment names whose row was changed around the vault is started over and made one again: at their next request, and as a vault starts', async () => {
  const w = await world();
  // Someone with the database demotes root, the only Owner, writing their row.
  const { vaultMembers } = tablesOf(db.owner);
  await db.owner.update(vaultMembers).set({ role: 'developer', owner: false }).where(eq(vaultMembers.principal, ROOT));
  // Root's next request finds it changed: started over, as removing them would, and made an Owner again, by the vault.
  const root = await w.vault.access(ROOT);
  assert.deepEqual([root.status, root.role, root.scope, root.generation], ['active', 'owner', EVERYWHERE, 1]);
  assert.deepEqual((await ownership()).filter(([, , outcome]) => outcome === 'allow').slice(-2), [['member.remove', ROOT, 'allow', null], ['member.restore', ROOT, 'allow', 'owners']]);
  // Again, and a new process: its start does it before anyone asks about root.
  await db.owner.update(vaultMembers).set({ generation: 7 }).where(eq(vaultMembers.principal, ROOT));
  const deployed = await namingOwners('root@acme.example');
  assert.equal((await deployed.access(ADA)).status, 'unknown');
  const row = await store.member(db.owner, ROOT);
  assert.deepEqual([row!.status, row!.role, row!.generation], ['active', 'owner', 8]);
  assert.equal((await deployed.verifyLog({})).ok, true);
});

test('a row edited to an Owner\'s around the vault makes nobody an Owner, nor anyone the deployment names', async () => {
  const w = await world();
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA })).ok);
  const { vaultMembers } = tablesOf(db.owner);
  await db.owner.update(vaultMembers).set({ role: 'owner', owner: true, scope: null }).where(eq(vaultMembers.principal, ADA));
  const ada = await w.vault.access(ADA);
  assert.deepEqual([ada.status, ada.role], ['tampered', 'member']);
  // The list is the deployment's: no row adds to it.
  assert.deepEqual((await w.vault.about()).owners, ['root@acme.example']);
  assert.equal(outcomeOf(await w.vault.admit({ actor: ADA, principal: BOB, role: 'owner' })), 'tampered: this member\'s record failed the vault\'s integrity check');
  assert.deepEqual((await store.instanceOwners(db.owner)).map((row) => row.principal).sort(), [ADA, ROOT].sort());
  assert.equal((await (await namingOwners('root@acme.example')).access(ADA)).status, 'tampered');
});

test('an Owner\'s scope written another way around the vault is still everywhere: a vault that starts writes nothing for them', async () => {
  // The column says everywhere as JSON, not null: the row's MAC reads it parsed, and holds.
  const w = await world({ owners: ['root@acme.example', 'sam@acme.example'] });
  assert.equal((await w.vault.access(SAM)).role, 'owner');
  const { vaultMembers } = tablesOf(db.owner);
  const before = (await ownership()).length;
  await db.owner.update(vaultMembers).set({ scope: JSON.stringify(EVERYWHERE) }).where(eq(vaultMembers.principal, ROOT));
  const deployed = await namingOwners('root@acme.example', 'sam@acme.example');
  assert.deepEqual(await deployed.access(ROOT).then(({ status, role, scope }) => [status, role, scope]), ['active', 'owner', EVERYWHERE]);
  assert.deepEqual(await deployed.access(SAM).then(({ status, role }) => [status, role]), ['active', 'owner']);
  assert.equal((await ownership()).length, before);
});
/** A root admin's row as 0.5 gave them one the first time anyone asked about them: a Member, `rootAdmin: true`. */
function rootRowOf05(principal: string): Promise<void> {
  return rowOf05(principal, { role: 'member', rootAdmin: true }, 'system:vault');
}

/** A Member's row as a vault of 0.5 wrote it, admitted by `actor`, its `member.add` saying `detail`. */
async function rowOf05(principal: string, detail: Record<string, unknown>, actor: string): Promise<void> {
  const appended = await db.vault.transaction((tx) => appendEntries(tx, VAULT_KEY, [{ actor, action: 'member.add', decision: 'allow', subjectPrincipal: principal, metadata: JSON.stringify(detail) }]));
  const at = appended.occurredAt;
  await db.owner.transaction((tx) => store.insertMember(tx, {
    principal, status: 'active', role: 'member', scope: EVERYWHERE, generation: 0, createdAt: at, createdBy: actor,
    statusChangedAt: at, statusChangedBy: actor, accessSeq: appended.seqStart, mac: Buffer.alloc(32),
  }));
  await reseal(principal);
}


test('on an instance that ran 0.5, everyone the deployment names becomes an Owner, root admins who signed in or not, and nobody else 0.5 let in', async () => {
  await places(db.owner);
  // 0.5 named root and Sam root admins; root signed in, Sam never did. Carol did, under a list since changed.
  await rootRowOf05(ROOT);
  await rootRowOf05(CAROL);
  const upgraded = await namingOwners('root@acme.example', 'sam@acme.example');
  // Its first call, whatever it is, makes root and Sam Owners: Carol stays the Member 0.5 made her.
  assert.equal((await upgraded.access(ADA)).status, 'unknown');
  for (const principal of [ROOT, SAM]) {
    const access = await upgraded.access(principal);
    assert.deepEqual([access.status, access.role, access.scope], ['active', 'owner', EVERYWHERE], principal);
  }
  assert.equal((await upgraded.access(CAROL)).role, 'member');
  assert.deepEqual(await ownership(), [
    ['member.add', ROOT, 'allow', null], ['member.add', CAROL, 'allow', null], ['member.role', ROOT, 'allow', 'owners'], ['member.add', SAM, 'allow', 'owners'],
  ]);
  // Sam, taken off the list, is demoted. Rolled back to 0.5, whose list names him still and lets Dan in as a
  // root admin, then forward: the vault reads the list it is given, not 0.5's, so both stay as they are.
  const without = await namingOwners('root@acme.example');
  assert.ok((await without.admit({ actor: ROOT, principal: SAM, role: 'developer' })).ok);
  await rootRowOf05(DAN);
  const forward = await namingOwners('root@acme.example');
  assert.deepEqual([(await forward.access(SAM)).role, (await forward.access(DAN)).role], ['developer', 'member']);
  assert.equal((await forward.verifyLog({})).ok, true, 'the log replays to every row');
});

test('a root admin of 0.5 still holding grants on every project gets what `coffre migrate` says, then becomes an Owner', async () => {
  await places(db.owner);
  const other = await laterProject();
  // 0.5 left a root admin's grants on every project as they were; root's row is older than the list, a Member's.
  await rowOf05(ROOT, { role: 'member' }, 'user:someone@acme.example');
  await everyProjectGrant(ROOT, null, 'maintainer');
  const [preview] = await everyProjectPreview(db.owner, Date.now());
  assert.deepEqual([preview!.principal, preview!.conversion.role, preview!.conversion.grants.map((grant) => [grant.projectId, grant.role]).sort()], [
    ROOT, 'developer', [[other.project, 'maintainer'], [(await store.liveProjects(db.owner)).find((project) => project.id !== other.project)!.id, 'maintainer']].sort(),
  ]);
  const upgraded = await namingOwners('root@acme.example');
  const root = await upgraded.access(ROOT);
  // Exactly what migrate said of the grants, and then an Owner of the whole instance, as the deployment names root.
  assert.deepEqual([root.role, root.scope], ['owner', EVERYWHERE]);
  assert.deepEqual(root.grants.map((grant) => [grant.projectId, grant.role]).sort(), preview!.conversion.grants.map((grant) => [grant.projectId, grant.role]).sort());
  const roles = (await store.vaultPage(db.owner, undefined, 50)).map(entryView).reverse().filter((entry) => entry.action === 'member.role' && entry.subject === ROOT);
  assert.deepEqual(roles.map((entry) => [entry.subject, entry.detail.role, entry.detail.reason]), [[ROOT, 'developer', 'every-project'], [ROOT, 'owner', 'owners']]);
  assert.equal((await upgraded.verifyLog({})).ok, true);
});
/**
 * `database`, whose first read about `principal` in `table` (their entries
 * in the log, unless named), once armed, waits after its answer arrived
 * until released: another request runs in between, as on a busy instance.
 */
function pausedReadAbout(database: Database, principal: string, table = 'audit_log') {
  let paused = () => {};
  let release = () => {};
  const reached = new Promise<void>((resolve) => (paused = resolve));
  const released = new Promise<void>((resolve) => (release = resolve));
  let armed = false;
  const wrap = <Q extends object>(query: Q): Q => new Proxy(query, {
    get(target, property) {
      const value = Reflect.get(target, property, target) as unknown;
      if (property === 'then' && typeof value === 'function') {
        return (resolve: (result: unknown) => void, reject: (error: unknown) => void) =>
          (value as (ok: (result: unknown) => unknown) => Promise<unknown>).call(target, async (result: unknown) => {
            const { sql, params } = (target as { toSQL(): { sql: string; params: unknown[] } }).toSQL();
            if (armed && sql.includes(table) && params.includes(principal)) {
              armed = false;
              paused();
              await released;
            }
            return result;
          }).then(resolve, reject);
      }
      if (typeof value !== 'function') return value;
      return (...args: unknown[]) => {
        const result = (value as (...args: unknown[]) => unknown).apply(target, args);
        return typeof result === 'object' && result !== null && 'toSQL' in result ? wrap(result) : result;
      };
    },
  });
  const wrapped = new Proxy(database, {
    get(target, property) {
      if (property === 'select') return (...args: Parameters<Database['select']>) => wrap(target.select(...args));
      const value = Reflect.get(target, property, target) as unknown;
      return typeof value === 'function' ? (value as (...args: unknown[]) => unknown).bind(target) : value;
    },
  });
  return { database: wrapped, arm: () => void (armed = true), reached, release };
}

for (const [shared, joined] of [[false, false], [true, false], [false, true]] as const) {
  test(`a person's request that read them before another request of theirs made them an Owner answers them one (${shared ? 'one process' : 'two processes'}${joined ? ', another Owner made since' : ''})`, { timeout: 10_000 }, async () => {
    await places(db.owner);
    const config = configure({ owners: ['root@acme.example', 'sam@acme.example'] });
    const prepared = await prepareVault(config);
    const slow = pausedReadAbout(db.vault, ROOT);
    const first = openVault(slow.database, prepared);
    const other = openVault(await db.connect(), shared ? prepared : await prepareVault(config));
    // Both settled first, so that only root's requests remain.
    assert.equal((await first.access(ADA)).status, 'unknown');
    assert.equal((await other.access(ADA)).status, 'unknown');
    slow.arm();
    const pending = first.access(ROOT);
    await slow.reached;
    assert.equal((await other.access(ROOT)).role, 'owner');
    // Ada, made an Owner since, comes first among the Owners the quick check finds.
    if (joined) assert.ok((await other.admit({ actor: ROOT, principal: ADA, role: 'owner' })).ok);
    slow.release();
    const answer = await pending;
    assert.deepEqual([answer.status, answer.role], ['active', 'owner']);
  });
}

test('a row the log never admitted makes nobody an Owner, and is not taken for one: the others the deployment names become Owners', async () => {
  await places(db.owner);
  const prepared = await prepareVault(configure({ owners: ['root@acme.example', 'sam@acme.example'] }));
  const vault = openVault(db.vault, prepared);
  assert.equal((await vault.access(ADA)).status, 'unknown');
  // Root's row, written around the vault, with no entry of the vault's behind it.
  await db.owner.transaction((tx) => store.insertMember(tx, {
    principal: ROOT, status: 'active', role: 'member', scope: EVERYWHERE, generation: 0, createdAt: Date.now(), createdBy: 'system:vault',
    statusChangedAt: Date.now(), statusChangedBy: 'system:vault', accessSeq: 0n, mac: Buffer.alloc(32),
  }));
  assert.equal((await vault.access(ROOT)).status, 'tampered');
  assert.equal((await vault.access(SAM)).role, 'owner');
  // Asked again at each of root's requests, and at each start, it stays as it is: no entry made them anything.
  assert.equal((await vault.access(ROOT)).status, 'tampered');
  assert.equal((await (await namingOwners('root@acme.example', 'sam@acme.example')).access(ROOT)).status, 'tampered');
  assert.deepEqual((await ownership()).filter(([, subject]) => subject === ROOT), []);
});

test('a vault starting while another makes someone on its list an Owner finds them one, its quick read of their row outrun', async () => {
  await places(db.owner);
  assert.equal((await (await namingOwners('root@acme.example')).access(ROOT)).role, 'owner');
  const config = configure({ owners: ['root@acme.example', 'bob@acme.example'] });
  // Its start reads that Bob has no row, then waits while another process, deployed with the same list, admits him an Owner.
  const slow = pausedReadAbout(db.vault, BOB, 'vault_members');
  const starting = openVault(slow.database, await prepareVault(config));
  slow.arm();
  const pending = starting.access(ADA);
  await slow.reached;
  assert.equal((await (await openLocalVault(await db.connect(), config)).access(BOB)).role, 'owner');
  slow.release();
  assert.equal((await pending).status, 'unknown');
  assert.equal((await starting.access(BOB)).role, 'owner');
  assert.deepEqual((await ownership()).filter(([, subject]) => subject === BOB), [['member.add', BOB, 'allow', 'owners']]);
});

test('an Owner the deployment names is not brought back as anything less, as during a deploy that changed the list', async () => {
  const w = await world();
  // A process deployed before the list named Bob removes him; this one, which names him, is asked to bring him back a Developer, or a Member.
  const listing = await namingOwners('root@acme.example', 'bob@acme.example');
  assert.equal((await listing.access(BOB)).role, 'owner');
  assert.ok((await w.vault.remove({ actor: ROOT, principal: BOB })).ok);
  assert.equal(outcomeOf(await listing.admit({ actor: ROOT, principal: BOB, role: 'developer' })), named('bob@acme.example'));
  assert.equal(outcomeOf(await listing.admit({ actor: ROOT, principal: BOB })), named('bob@acme.example'));
  assert.equal((await store.member(db.owner, BOB))?.status, 'removed');
  // As an Owner of the whole instance, as it would itself.
  assert.equal(outcomeOf(await listing.admit({ actor: ROOT, principal: BOB, role: 'owner' })), 'ok');
  assert.deepEqual(await listing.access(BOB).then(({ status, role, scope }) => [status, role, scope]), ['active', 'owner', EVERYWHERE]);
});
