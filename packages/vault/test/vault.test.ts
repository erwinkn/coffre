import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

import { entryHash, entryMac, type LogKey, type StoredEntry } from '@coffre/core/audit';
import { awsKms, KekRegistry, KekUnavailableError, LocalKekProvider, type KekProvider, type KeyOperation } from '@coffre/core/kek';
import { verifyCheckpoint, type SecretRef, type WrappedKey } from '@coffre/core/vault';
import { tablesOf, type Database } from '@coffre/db';
import { appendEntries, LogHeadMismatch, LogRewound } from '@coffre/db/log';
import { asc, desc, eq, gte, sql } from 'drizzle-orm';

import { checkRootAdmins, resolveVaultConfig, type ResolvedVaultConfig } from '../src/config.ts';
import { openLocalVault, type LocalVault } from '../src/local.ts';
import { entryView, vaultLogKey } from '../src/log.ts';
import { memberMac, rowKey } from '../src/rows.ts';
import * as store from '../src/store.ts';
import type { VaultOptions } from '../src/vault.ts';
import {
  emptyDatabase,
  ENGINE,
  newEnvironment,
  newProject,
  openTestDatabase,
  places,
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
    rootAdmins: ['root@acme.example'],
    signingKey: SIGNING_KEY,
    bulkLimit: { count: 1000, windowMs: 15 * 60_000 },
    ...overrides,
  };
}

async function world(overrides: Partial<ResolvedVaultConfig> = {}, options: VaultOptions = {}): Promise<World> {
  const config = configure(overrides);
  const clock = { offset: 0 };
  const open = async (database: Database) => openLocalVault(database, config, { clockOffset: () => clock.offset, ...options });
  return { ...(await places(db.owner)), vault: await open(db.vault), clock, twin: async () => open(await db.connect()) };
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

/** The vault's entries, oldest first, as stored in the log. */
async function vaultLog(_w: World) {
  return (await store.vaultPage(db.owner, undefined, 200)).map(entryView).reverse();
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
  const read = await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: [{ secret: devSecret, wrapped: wrap.wrapped[0] }] });
  assert.deepEqual(read, { ok: true, keys: [key] });

  const prodSecret = await w.secret(w.prod);
  const refused = await w.vault.unwrap({
    principal: ADA,
    purpose: 'reveal',
    items: [{ secret: prodSecret, wrapped: await wrapped(w, prodSecret) }],
  });
  assert.equal(!refused.ok && refused.refusal.code, 'no_grant');
  const write = await w.vault.wrap({ principal: ADA, items: [{ secret: prodSecret, key }] });
  assert.equal(!write.ok && write.refusal.code, 'no_grant');
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
  const result = await w.vault.unwrap({ principal: ADA, purpose: 'run', items, requestId: 'req-1' });
  assert.equal(!result.ok && result.refusal.code, 'no_grant');

  const reads = (await vaultLog(w)).filter((entry) => entry.action === 'secret.read');
  assert.deepEqual(
    reads.map((entry) => [entry.subject, entry.outcome, entry.code, entry.detail.purpose, entry.detail.secretId, entry.detail.requestId]),
    [
      ['market/dev/DATABASE_URL', 'refuse', 'no_grant', 'run', devSecret.secretId, 'req-1'],
      ['market/prod/DATABASE_URL', 'refuse', 'no_grant', 'run', prodSecret.secretId, 'req-1'],
    ],
  );
});

test('a wrapped key presented as another secret is a bad claim', async () => {
  const w = await world();
  await member(w, ADA, [[null, 'viewer']]);
  const devSecret = await w.secret(w.dev);
  const result = await w.vault.unwrap({
    principal: ADA,
    purpose: 'reveal',
    items: [{ secret: await w.secret(w.prod), wrapped: await wrapped(w, devSecret) }],
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
      : w.vault.unwrap({ principal: ROOT, purpose: 'reveal', items: [{ secret, wrapped: sealed.wrapped[0] }] });
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

  assert.equal(code(await w.vault.unwrap({ principal: ADA, purpose: 'run', items })), 'no_grant');
  assert.equal(code(await w.vault.unwrap({ principal: BOB, purpose: 'run', items: items.slice(0, 1) })), 'not_a_member');
  assert.equal(code(await w.vault.wrap({ principal: ADA, items: [{ secret: dev, key: randomBytes(32).toString('base64') }] })), 'no_grant');
  const again = { ...dev, version: 2 };
  assert.equal(code(await w.vault.rewrap({ principal: ADA, items: [{ secret: again, from: 1, wrapped: items[0]!.wrapped }] })), 'no_grant');
  assert.deepEqual({ wrap: seen.wrap, unwrap: seen.unwrap }, { wrap: before.wrap, unwrap: before.unwrap }, 'refused, so no key was wrapped or unwrapped');

  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'run', items: items.slice(0, 1) })).ok, true);
  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'run', items: items.slice(0, 1) })).ok, true);
  assert.equal(code(await w.vault.unwrap({ principal: ADA, purpose: 'run', items: items.slice(0, 1) })), 'bulk_limit');
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
  await assert.rejects(w.vault.unwrap({ principal: ADA, purpose: 'run', items }), KekUnavailableError);
  const entries = (await vaultLog(w)).filter((entry) => entry.actor === ADA);
  assert.deepEqual(
    entries.map((entry) => [entry.action, entry.outcome, entry.code]),
    [['key.intent', 'allow', null], ['secret.read', 'refuse', 'kms_unavailable']],
    'the intent, and the outcome: no key released, none to count against the bulk limit',
  );

  seen.down = false;
  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'run', items })).ok, true, 'and the next call goes through');
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

  await assert.rejects(w.vault.unwrap({ principal: ADA, purpose: 'run', items }), /did not answer for 1 of 3 keys/);
  const entries = (await vaultLog(w)).filter((entry) => entry.actor === ADA);
  assert.deepEqual(
    entries.map((entry) => [entry.action, entry.subject, entry.code]),
    [
      ['key.intent', null, null],
      ['secret.read', 'market/dev/A', 'withheld'],
      ['secret.read', 'market/dev/B', 'kms_unavailable'],
      ['secret.read', 'market/dev/C', 'withheld'],
    ],
  );
  assert.deepEqual(
    (entries[0].detail.keys as { subject: string }[]).map((key) => key.subject),
    ['market/dev/A', 'market/dev/B', 'market/dev/C'],
  );
  assert.equal(seen.opened.length, 2);
  assert.ok(seen.opened.every((key) => key.equals(Buffer.alloc(32))), 'the keys KMS opened are wiped, not released');
});

test('a key service past the budget is cancelled, and opened keys are wiped', async () => {
  const { keks, seen } = service();
  const w = await world({ keks }, { keyBudgetMs: 100 });
  await member(w, ADA, [[w.dev, 'viewer']]);
  const [fast, slow] = [await w.secret(w.dev, 'FAST'), await w.secret(w.dev, 'SLOW')];
  const items = [{ secret: fast, wrapped: await wrapped(w, fast) }, { secret: slow, wrapped: await wrapped(w, slow) }];
  seen.hanging.add(slow.secretId);
  seen.opened.length = 0;

  await assert.rejects(w.vault.unwrap({ principal: ADA, purpose: 'run', items }), KekUnavailableError);
  const outcomes = (await vaultLog(w)).filter((entry) => entry.action === 'secret.read' && entry.actor === ADA);
  assert.deepEqual(outcomes.map((entry) => entry.code), ['withheld', 'kms_uncertain']);
  assert.equal(seen.opened.length, 1, 'the slow operation was cancelled');
  assert.ok(seen.opened.every((key) => key.equals(Buffer.alloc(32))), 'and was wiped as it came');
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
  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items })).ok, true);
  w.clock.offset += 61_000;
  const result = await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items });
  assert.equal(!result.ok && result.refusal.code, 'expired');
  assert.deepEqual((await w.vault.access(ADA)).grants, []);
});

test('the bulk limit counts keys per principal over a rolling window', async () => {
  const w = await world({ bulkLimit: { count: 5, windowMs: 60_000 } });
  await member(w, ADA, [[w.dev, 'viewer']]);
  await member(w, BOB, [[w.dev, 'viewer']]);
  const secrets = [await w.secret(w.dev), await w.secret(w.dev), await w.secret(w.dev)];
  const items = await Promise.all(secrets.map(async (secret) => ({ secret, wrapped: await wrapped(w, secret) })));

  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'run', items })).ok, true);
  const over = await w.vault.unwrap({ principal: ADA, purpose: 'run', items });
  assert.equal(!over.ok && over.refusal.code, 'bulk_limit');
  // Refusals do not count, and neither does anyone else's reading.
  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'run', items: items.slice(0, 2) })).ok, true);
  assert.equal((await w.vault.unwrap({ principal: BOB, purpose: 'run', items })).ok, true);
  const stillOver = await w.vault.unwrap({ principal: ADA, purpose: 'run', items: items.slice(0, 1) });
  assert.equal(!stillOver.ok && stillOver.refusal.code, 'bulk_limit');

  w.clock.offset += 60_001;
  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'run', items })).ok, true);
  assert.equal((await vaultLog(w)).filter((entry) => entry.code === 'bulk_limit').length, 4);
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
    Array.from({ length: 12 }, (_, i) => (i % 2 === 0 ? w.vault : other).unwrap({ principal: ADA, purpose: 'run', items })),
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
  const input = { principal: ADA, purpose: 'run' as const, items: [{ secret, wrapped: await wrapped(w, secret) }] };

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

  const read = w.vault.unwrap({ principal: ADA, purpose: 'reveal', items });
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

  const next = await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items });
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
  const items = [{ secret, wrapped: await wrapped(w, secret) }];
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
    message: `this vault's ${keks.primary.provider} KEK test-kek-1 does not open the data it holds: it is not the key that wrapped it`,
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
  const read = await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items });
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

  assert.deepEqual(await w.vault.admit({ actor: ROOT, principal: ADA }), { ok: true, created: true, owner: false, generation: 1 });
  const access = await w.vault.access(ADA);
  assert.equal(access.status, 'active');
  assert.deepEqual(access.grants, []);
  const again = await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items });
  assert.equal(!again.ok && again.refusal.code, 'no_grant');
});

test('access is managed with the same rules as the app, and root admins are fixed', async () => {
  const w = await world();
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
  assert.equal(!toRoot.ok && toRoot.refusal.code, 'root_admin');
  const removeRoot = await w.vault.remove({ actor: ROOT, principal: ROOT });
  assert.equal(!removeRoot.ok && removeRoot.refusal.code, 'root_admin');
  const stranger = await w.vault.setAccess({ actor: ROOT, principal: 'user:eve@acme.example', changes: [change('viewer')] });
  assert.equal(!stranger.ok && stranger.refusal.code, 'not_a_member');
  const notOwner = await w.vault.admit({ actor: ADA, principal: 'user:eve@acme.example' });
  assert.equal(!notOwner.ok && notOwner.refusal.code, 'not_allowed');
  const ownerToken = await w.vault.admit({ actor: ROOT, principal: 'token:ci', owner: true });
  assert.equal(!ownerToken.ok && ownerToken.refusal.code, 'invalid');

  const revoked = await w.vault.setAccess({ actor: ADA, principal: BOB, changes: [change(null), change(null, null)] });
  assert.deepEqual(revoked, { ok: true, changes: ['revoked', 'revoked'] });
  assert.deepEqual((await w.vault.access(BOB)).grants, []);

  // Root admins are the vault's configuration, which it says; members are rows anyone may list.
  assert.deepEqual((await w.vault.about()).rootAdmins, [ROOT]);
});

test('a sync is a member from its first grant, and whoever manages environments can stop it', async () => {
  const w = await world();
  const MAINTAINER = 'user:mia@acme.example';
  await member(w, MAINTAINER, [[null, 'maintainer']]);
  const sync = `sync:${randomUUID()}`;
  const grant = (role: 'viewer' | 'developer' | null, environmentId: string | null = w.dev) =>
    w.vault.setAccess({ actor: MAINTAINER, principal: sync, changes: [{ projectId: w.project, environmentId, role, expiresAt: null }] });

  assert.deepEqual(await grant('viewer'), { ok: true, changes: ['created'] });
  assert.equal((await w.vault.access(sync)).status, 'active');
  // Only reading, and only on an environment.
  assert.equal((await grant('developer')).ok, false);
  assert.equal((await grant('viewer', null)).ok, false);

  const secret = await w.secret(w.dev);
  const items = [{ secret, wrapped: await wrapped(w, secret) }];
  assert.equal((await w.vault.unwrap({ principal: sync, purpose: 'sync', items })).ok, true);
  assert.deepEqual(await grant(null), { ok: true, changes: ['revoked'] });
  const stopped = await w.vault.unwrap({ principal: sync, purpose: 'sync', items });
  assert.equal(!stopped.ok && stopped.refusal.code, 'no_grant');

  assert.equal((await grant('viewer')).ok, true);
  assert.equal((await w.vault.remove({ actor: MAINTAINER, principal: sync })).ok, true);
  assert.equal((await w.vault.access(sync)).status, 'removed');

  // Its credential lives in a project the maintainer does not manage. Once
  // its source grant is gone, naming the source is what lets them stop it.
  const other = `sync:${randomUUID()}`;
  const credentialProject = await newProject(db.owner);
  const credential = {
    projectId: credentialProject,
    environmentId: await newEnvironment(db.owner, credentialProject),
    role: 'viewer' as const,
    expiresAt: null,
  };
  assert.equal((await w.vault.setAccess({ actor: ROOT, principal: other, changes: [credential] })).ok, true);
  const source = { projectId: w.project, environmentId: w.dev };
  const refused = await w.vault.remove({ actor: MAINTAINER, principal: other });
  assert.equal(!refused.ok && refused.refusal.code, 'not_allowed');
  assert.equal((await w.vault.remove({ actor: BOB, principal: other, source })).ok, false);
  assert.equal((await w.vault.remove({ actor: MAINTAINER, principal: other, source })).ok, true);
});

test('the log is chained, append-only, and shows a rewritten entry', async () => {
  const w = await world();
  const { auditLog } = tablesOf(db.owner);
  await member(w, ADA, [[w.dev, 'viewer']]);
  const secret = await w.secret(w.dev);
  await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: [{ secret, wrapped: await wrapped(w, secret) }] });

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

/** A vault whose log holds `n` wraps and an admission, as the root admin made them. */
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

test('a checkpoint signs the log up to its last entry, in an entry of its own', async () => {
  const w = await world();
  const { auditLog } = tablesOf(db.owner);
  const { publicKey } = await w.vault.about();
  const signed = async () => (await vaultLog(w)).filter((entry) => entry.action === 'audit.checkpoint' && entry.outcome === 'allow');
  assert.deepEqual(await signed(), []);
  // An empty log has nothing to sign, and the refusal writes nothing to sign next.
  const empty = await w.vault.checkpoint();
  assert.equal(!empty.ok && empty.refusal.code, 'invalid');
  assert.deepEqual(await vaultLog(w), []);

  await member(w, ADA, [[w.dev, 'viewer']]);
  const last = (await vaultLog(w)).at(-1)!;
  const first = await w.vault.checkpoint();
  assert.ok(first.ok);
  assert.deepEqual([first.checkpoint.seq, first.checkpoint.hash], [last.seq, last.hash]);
  assert.equal(await verifyCheckpoint(first.checkpoint, publicKey), true);
  assert.equal(await verifyCheckpoint({ ...first.checkpoint, hash: 'b'.repeat(64) }, publicKey), false);
  const entries = await vaultLog(w);
  assert.deepEqual([entries.at(-1)!.action, entries.at(-1)!.detail], ['audit.checkpoint', first.checkpoint]);

  // Nothing new signs nothing new.
  assert.deepEqual(await w.vault.checkpoint(), first);
  assert.equal((await vaultLog(w)).length, entries.length);
  await member(w, BOB, []);
  const next = await w.vault.checkpoint();
  assert.ok(next.ok && next.checkpoint.seq > first.checkpoint.seq);
  assert.deepEqual((await signed()).at(-1)?.detail, next.checkpoint);

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

  // Every entry carries a good MAC, but the checkpoint's prefix is not there.
  const signed = (await vaultLog(w)).find((entry) => entry.action === 'audit.checkpoint' && entry.outcome === 'allow')!;
  assert.deepEqual(await started.verifyLog({}), {
    ok: false,
    failedAtSeq: signed.seq,
    reason: `the log up to entry ${first.checkpoint.seq} is not the prefix this checkpoint signed: it was rewritten`,
  });
});

test('a full check covers the head the app verified up to, and refuses an entry forged under no key', async () => {
  const w = await world();
  const { auditLog, auditChainHead } = tablesOf(db.owner);
  await member(w, ADA, []);
  const [last] = (await db.owner.select().from(auditLog).orderBy(asc(auditLog.seq))).slice(-1) as StoredEntry[];
  const upTo = { seq: Number(last.seq), hash: last.hash.toString('hex') };
  assert.deepEqual(await w.vault.verifyLog({ upTo }), { ok: true, entries: 1 });
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
    reason: 'written under vault:0000000000000000, a key this verifier does not hold',
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
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA, owner: true })).ok);
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
    fault: { kind: 'unlogged-grant', grant: { principal: BOB, projectId: w.project, environmentId: null, role: 'owner' } },
  };
  assert.deepEqual(await w.vault.verifyLog({}), extra);

  // Or a removal undone, grants and all.
  await db.owner.delete(vaultGrants).where(eq(vaultGrants.role, 'owner'));
  assert.ok((await w.vault.remove({ actor: ROOT, principal: ADA })).ok);
  await db.owner.update(vaultMembers).set({ status: 'active', owner: true }).where(eq(vaultMembers.principal, ADA));
  await db.owner.insert(vaultGrants).values({
    principal: ADA, projectId: null, environmentId: w.dev, role: 'viewer', expiresAt: null, grantedAt: 0, grantedBy: ROOT,
  });
  await reseal(BOB);
  await reseal(ADA);
  assert.deepEqual(await w.vault.verifyLog({}), {
    ok: false,
    failedAtSeq: null,
    reason: `the store's ${ADA} differs from the log's in status, owner`,
    fault: { kind: 'member-differs', principal: ADA, fields: ['status', 'owner'] },
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
    assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items })).ok, true);

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
    const read = await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items });
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
    assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items })).ok, true);
    assert.equal((await w.vault.verifyLog({})).ok, true);
  });
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
  const read = await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items });
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
  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items })).ok, true);
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
  await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: [{ secret, wrapped: wrap.wrapped[0] }] });
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

test('configuration', () => {
  const key = randomBytes(32).toString('base64');
  const base = { kek: { id: 'kek-1', key }, rootAdmins: ['admin@example.com'], signingKey: key };
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
  assert.throws(() => resolveVaultConfig({ ...base, kek: { id: 'kek 1', key } }), /KEK id/);

  // A key service's KEK, with the local one before it still opening what it wrapped.
  const keyArn = 'arn:aws:kms:eu-west-3:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab';
  const credentials = { accessKeyId: 'AKIAEXAMPLE', secretAccessKey: 'secret' };
  const kms = resolveVaultConfig({ ...base, kek: awsKms({ keyArn, credentials }), previousKeks: [base.kek] });
  assert.deepEqual([kms.keks.primary.provider, kms.keks.primary.keyId], ['aws-kms', keyArn]);
  assert.throws(
    () => resolveVaultConfig({ ...base, kek: awsKms({ keyArn, credentials }), previousKeks: [awsKms({ keyArn, credentials })] }),
    /two KEKs share an id: aws-kms:arn:aws:kms:eu-west-3/,
  );
  const own = LocalKekProvider.generate('own-1');
  for (const [kek, message] of [
    [Object.assign(Object.create(own) as KekProvider, { provider: 'Vault Transit' }), /name must be 1-32 lowercase letters/],
    [Object.assign(Object.create(own) as KekProvider, { keyId: 'has space' }), /keyId and keyVersion must be 1-255 visible ASCII/],
    [{ provider: 'transit', keyId: 'k', keyVersion: '1', wrap: own.wrap } as unknown as KekProvider, /transit:k needs wrap\(\) and unwrap\(\)/],
  ] as const) {
    assert.throws(() => resolveVaultConfig({ ...base, kek }), message);
  }
  assert.deepEqual(checkRootAdmins(['First.Admin@example.com', ' second@example.org ']), ['first.admin@example.com', 'second@example.org']);
  assert.throws(() => checkRootAdmins([]), /at least one/);
  assert.throws(() => checkRootAdmins(['admin@example,com']), /human email/);
  assert.throws(() => checkRootAdmins(['ci-deploy.access']), /human email/);
  for (const malformed of [
    'admin@.example.com',
    'admin@example..com',
    'admin@example.com.',
    '.admin@example.com',
    'admin..root@example.com',
    'admin@-example.com',
  ]) {
    assert.throws(() => checkRootAdmins([malformed]), /human email/, malformed);
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
  const items = [];
  for (let i = 0; i < 9; i++) {
    items.push({ secret: await w.secret(w.dev), wrapped: { kekProvider: 'aws-kms', kekId: arn, kekVersion: '1', bytes: 'Y2lwaGVydGV4dA==' } });
  }
  try {
    await assert.rejects(w.vault.unwrap({ principal: ADA, purpose: 'run', items }), KekUnavailableError);
    assert.equal(active, 0, 'all in-flight requests settled before the decision ended');
    assert.equal(started, 8, 'the queued key never reached KMS');
    assert.ok((await (await w.twin()).remove({ actor: ROOT, principal: ADA })).ok);
    const outcomes = (await vaultLog(w)).filter((entry) => entry.action === 'secret.read');
    assert.deepEqual(outcomes.map((entry) => entry.code), [...Array<string>(8).fill('kms_uncertain'), 'cancelled']);
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
      ? await w.vault.unwrap({ principal: ADA, purpose: 'run', items })
      : await w.vault.rewrap({ principal: ADA, items });
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
      assert.deepEqual(verification, { ok: true, entries: 1, pending: 1 });
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
    const input = { principal: ROOT, items, purpose: 'run' as const };
    await assert.rejects(w.vault[action](input), /must be a lowercase UUID/);
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
    await assert.rejects(w.vault[action]({ principal: ROOT, purpose: 'run', items }), (error) => error === fault);
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
