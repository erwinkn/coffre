import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import Database from 'libsql';

import { LocalKekProvider } from '../../core/src/kek/local.ts';
import { KekRegistry } from '../../core/src/kek/registry.ts';
import { verifyCheckpoint } from '../src/checkpoint.ts';
import { parseBulkLimit, parseRootAdmins, type VaultConfig } from '../src/config.ts';
import { embeddedMigrations } from '../src/generate.ts';
import { localVault, type LocalVault } from '../src/local.ts';
import type { SecretRef, WrappedKey } from '../src/types.ts';

const ROOT = 'user:root@acme.example';
const ADA = 'user:ada@acme.example';
const BOB = 'user:bob@acme.example';

type World = {
  vault: LocalVault;
  path: string;
  clock: { now: number };
  project: string;
  dev: string;
  prod: string;
  secret(environmentId: string, key?: string): SecretRef;
};

async function world(t: test.TestContext, config: Partial<VaultConfig> = {}): Promise<World> {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-vault-'));
  const path = join(dir, 'vault.db');
  const clock = { now: Date.UTC(2026, 8, 1, 12) };
  const vault = await localVault(
    path,
    {
      keks: new KekRegistry(LocalKekProvider.generate('test-kek-1')),
      rootAdmins: ['root@acme.example'],
      signingKey: randomBytes(32),
      bulkLimit: { count: 1000, windowMs: 15 * 60_000 },
      ...config,
    },
    { now: () => clock.now },
  );
  t.after(() => {
    vault.close();
    rmSync(dir, { recursive: true, force: true });
  });
  const project = randomUUID();
  const dev = randomUUID();
  const prod = randomUUID();
  const secret = (environmentId: string, key = 'DATABASE_URL'): SecretRef => ({
    projectId: project,
    environmentId,
    secretId: randomUUID(),
    version: 1,
    path: `market/${environmentId === dev ? 'dev' : 'prod'}/${key}`,
  });
  return { vault, path, clock, project, dev, prod, secret };
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
  assert.ok(result.ok);
  return result.wrapped[0];
}

function raw(w: World) {
  return new Database(w.path);
}

test('src/migrations.ts is migrations/, embedded', async () => {
  const embedded = readFileSync(new URL('../src/migrations.ts', import.meta.url), 'utf8');
  assert.equal(embedded, await embeddedMigrations(), 'run `pnpm --dir packages/vault generate`');
});

test('a read needs a live grant on the environment, and unwraps the key it was wrapped with', async (t) => {
  const w = await world(t);
  await member(w, ADA, [[w.dev, 'developer']]);
  const devSecret = w.secret(w.dev);
  const key = randomBytes(32).toString('base64');
  const wrap = await w.vault.wrap({ principal: ADA, items: [{ secret: devSecret, key }] });
  assert.ok(wrap.ok);
  const read = await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: [{ secret: devSecret, wrapped: wrap.wrapped[0] }] });
  assert.deepEqual(read, { ok: true, keys: [key] });

  const prodSecret = w.secret(w.prod);
  const refused = await w.vault.unwrap({
    principal: ADA,
    purpose: 'reveal',
    items: [{ secret: prodSecret, wrapped: await wrapped(w, prodSecret) }],
  });
  assert.equal(refused.ok, false);
  assert.equal(!refused.ok && refused.refusal.code, 'no_grant');
  const write = await w.vault.wrap({ principal: ADA, items: [{ secret: prodSecret, key }] });
  assert.equal(!write.ok && write.refusal.code, 'no_grant');
});

test('a batch is all or nothing, and every item is logged either way', async (t) => {
  const w = await world(t);
  await member(w, ADA, [[w.dev, 'viewer']]);
  const devSecret = w.secret(w.dev);
  const prodSecret = w.secret(w.prod);
  const items = [
    { secret: devSecret, wrapped: await wrapped(w, devSecret) },
    { secret: prodSecret, wrapped: await wrapped(w, prodSecret) },
  ];
  const result = await w.vault.unwrap({ principal: ADA, purpose: 'run', items });
  assert.equal(!result.ok && result.refusal.code, 'no_grant');

  const log = await w.vault.log({ actor: ROOT });
  assert.ok(log.ok);
  const reads = log.entries.filter((entry) => entry.action === 'unwrap').reverse();
  assert.deepEqual(
    reads.map((entry) => [entry.subject, entry.outcome, entry.code, entry.detail.purpose]),
    [
      ['market/dev/DATABASE_URL', 'refuse', 'no_grant', 'run'],
      ['market/prod/DATABASE_URL', 'refuse', 'no_grant', 'run'],
    ],
  );
});

test('a wrapped key presented as another secret is a bad claim', async (t) => {
  const w = await world(t);
  await member(w, ADA, [[null, 'viewer']]);
  const devSecret = w.secret(w.dev);
  const result = await w.vault.unwrap({
    principal: ADA,
    purpose: 'reveal',
    items: [{ secret: w.secret(w.prod), wrapped: await wrapped(w, devSecret) }],
  });
  assert.equal(!result.ok && result.refusal.code, 'bad_claim');
});

test('an expired grant refuses with its own code', async (t) => {
  const w = await world(t);
  await member(w, ADA, [[w.dev, 'viewer', w.clock.now + 60_000]]);
  const secret = w.secret(w.dev);
  const items = [{ secret, wrapped: await wrapped(w, secret) }];
  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items })).ok, true);
  w.clock.now += 61_000;
  const result = await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items });
  assert.equal(!result.ok && result.refusal.code, 'expired');
  assert.deepEqual((await w.vault.access(ADA)).grants, []);
});

test('the bulk limit counts keys per principal over a rolling window', async (t) => {
  const w = await world(t, { bulkLimit: { count: 5, windowMs: 60_000 } });
  await member(w, ADA, [[w.dev, 'viewer']]);
  await member(w, BOB, [[w.dev, 'viewer']]);
  const secrets = Array.from({ length: 3 }, () => w.secret(w.dev));
  const items = await Promise.all(secrets.map(async (secret) => ({ secret, wrapped: await wrapped(w, secret) })));

  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'run', items })).ok, true);
  const over = await w.vault.unwrap({ principal: ADA, purpose: 'run', items });
  assert.equal(!over.ok && over.refusal.code, 'bulk_limit');
  // Refusals do not count, and neither does anyone else's reading.
  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'run', items: items.slice(0, 2) })).ok, true);
  assert.equal((await w.vault.unwrap({ principal: BOB, purpose: 'run', items })).ok, true);
  const stillOver = await w.vault.unwrap({ principal: ADA, purpose: 'run', items: items.slice(0, 1) });
  assert.equal(!stillOver.ok && stillOver.refusal.code, 'bulk_limit');

  w.clock.now += 60_001;
  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'run', items })).ok, true);

  const log = await w.vault.log({ actor: ROOT, limit: 200 });
  assert.ok(log.ok);
  assert.equal(log.entries.filter((entry) => entry.code === 'bulk_limit').length, 4);
});

test('a removed member is refused everything until admitted again, with no grants', async (t) => {
  const w = await world(t);
  await member(w, ADA, [[w.dev, 'viewer'], [null, 'access-manager']]);
  const secret = w.secret(w.dev);
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

  assert.deepEqual(await w.vault.admit({ actor: ROOT, principal: ADA }), { ok: true, created: true, owner: false });
  const access = await w.vault.access(ADA);
  assert.equal(access.status, 'active');
  assert.deepEqual(access.grants, []);
  const again = await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items });
  assert.equal(!again.ok && again.refusal.code, 'no_grant');
});

test('access is managed with the same rules as the app, and root admins are fixed', async (t) => {
  const w = await world(t);
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

  const members = await w.vault.members();
  assert.deepEqual(
    members.map((m) => [m.principal, m.status, m.isRootAdmin]),
    [
      [ADA, 'active', false],
      [BOB, 'active', false],
      [ROOT, 'active', true],
    ],
  );
});

test('a sync is a member from its first grant, and whoever manages environments can stop it', async (t) => {
  const w = await world(t);
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

  const secret = w.secret(w.dev);
  const items = [{ secret, wrapped: await wrapped(w, secret) }];
  assert.equal((await w.vault.unwrap({ principal: sync, purpose: 'sync', items })).ok, true);
  assert.deepEqual(await grant(null), { ok: true, changes: ['revoked'] });
  const stopped = await w.vault.unwrap({ principal: sync, purpose: 'sync', items });
  assert.equal(!stopped.ok && stopped.refusal.code, 'no_grant');

  assert.equal((await grant('viewer')).ok, true);
  assert.equal((await w.vault.remove({ actor: MAINTAINER, principal: sync })).ok, true);
  assert.equal((await w.vault.access(sync)).status, 'removed');
});

test('the log is hash-chained, append-only, and shows a rewritten entry', async (t) => {
  const w = await world(t);
  await member(w, ADA, [[w.dev, 'viewer']]);
  const secret = w.secret(w.dev);
  await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: [{ secret, wrapped: await wrapped(w, secret) }] });

  const before = await w.vault.log({ actor: ROOT });
  assert.ok(before.ok);
  assert.equal(before.verification.ok, true);
  const refused = await w.vault.log({ actor: ADA });
  assert.equal(!refused.ok && refused.refusal.code, 'not_allowed');

  const db = raw(w);
  t.after(() => db.close());
  assert.throws(() => db.prepare(`UPDATE log SET outcome = 'refuse' WHERE action = 'unwrap'`).run(), /append-only/);
  assert.throws(() => db.prepare('DELETE FROM log').run(), /append-only/);

  // Someone holding the file itself can drop the trigger; the chain still shows it.
  db.exec('DROP TRIGGER log_no_update');
  db.prepare(`UPDATE log SET actor = 'user:bob@acme.example' WHERE action = 'unwrap'`).run();
  const after = await w.vault.log({ actor: ROOT });
  assert.ok(after.ok);
  const tampered = after.entries.find((entry) => entry.action === 'unwrap')!;
  assert.deepEqual(after.verification, { ok: false, failedAtSeq: tampered.seq, reason: 'hash does not match the entry' });
});

test('checkpoints are signed only while they extend the last one', async (t) => {
  const w = await world(t);
  const { checkpoint: none, publicKey } = await w.vault.latestCheckpoint();
  assert.equal(none, null);

  const first = await w.vault.checkpoint({ seq: 10, headHash: 'a'.repeat(64), previous: null });
  assert.ok(first.ok);
  assert.equal(await verifyCheckpoint(first.checkpoint, publicKey), true);
  assert.equal(await verifyCheckpoint({ ...first.checkpoint, headHash: 'b'.repeat(64) }, publicKey), false);

  const next = await w.vault.checkpoint({ seq: 20, headHash: 'c'.repeat(64), previous: { seq: 10, hash: 'a'.repeat(64) } });
  assert.ok(next.ok);
  // The row at 20 changed since it was signed: the log was rewritten.
  const rewritten = await w.vault.checkpoint({ seq: 30, headHash: 'd'.repeat(64), previous: { seq: 20, hash: 'e'.repeat(64) } });
  assert.equal(!rewritten.ok && rewritten.refusal.code, 'checkpoint_diverged');
  const restart = await w.vault.checkpoint({ seq: 5, headHash: 'f'.repeat(64), previous: null });
  assert.equal(!restart.ok && restart.refusal.code, 'checkpoint_diverged');
  assert.deepEqual((await w.vault.latestCheckpoint()).checkpoint, next.checkpoint);

  const log = await w.vault.log({ actor: ROOT });
  assert.ok(log.ok);
  assert.equal(log.entries.filter((entry) => entry.code === 'checkpoint_diverged').length, 2);
});

test('the store holds no key', async (t) => {
  const kek = randomBytes(32);
  const w = await world(t, { keks: new KekRegistry(new LocalKekProvider(kek, 'test-kek-1')) });
  await member(w, ADA, [[w.dev, 'developer']]);
  const secret = w.secret(w.dev);
  const key = randomBytes(32);
  const wrap = await w.vault.wrap({ principal: ADA, items: [{ secret, key: key.toString('base64') }] });
  assert.ok(wrap.ok);
  await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: [{ secret, wrapped: wrap.wrapped[0] }] });
  const file = readFileSync(w.path);
  for (const needle of [kek, key]) {
    assert.equal(file.includes(needle), false);
    assert.equal(file.includes(Buffer.from(needle.toString('base64'))), false);
  }
});

test('configuration', () => {
  assert.deepEqual(parseBulkLimit('1000/15m'), { count: 1000, windowMs: 900_000 });
  assert.deepEqual(parseBulkLimit(' 20 / 30s '), { count: 20, windowMs: 30_000 });
  assert.throws(() => parseBulkLimit('1000'), /1000\/15m/);
  assert.throws(() => parseBulkLimit('0/1m'), /1000\/15m/);
  assert.deepEqual(parseRootAdmins('First.Admin@example.com, second@example.org'), ['first.admin@example.com', 'second@example.org']);
  assert.throws(() => parseRootAdmins(''), /at least one/);
  assert.throws(() => parseRootAdmins('admin@example,com'), /human email/);
  assert.throws(() => parseRootAdmins('ci-deploy.access'), /human email/);
});
