import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { awsKms, KekRegistry, KekUnavailableError, LocalKekProvider, type KekProvider } from '@coffre/core/kek';
import { verifyCheckpoint, type SecretRef, type WrappedKey } from '@coffre/core/vault';

import { checkRootAdmins, resolveVaultConfig, type ResolvedVaultConfig } from '../src/config.ts';
import { openLocalVault, type LocalVault } from '../src/local.ts';
import { entryHash, logKey } from '../src/log.ts';
import type { Sqlite, SqlValue } from '../src/sqlite.ts';
import { nodeSqlite } from '../src/sqlite-node.ts';
import type { LogRow } from '../src/store.ts';
import { openVault } from '../src/vault.ts';

/** Every vault here signs, and chains its log, with this; `reopen` needs the same to verify it. */
const SIGNING_KEY = randomBytes(32);

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

async function world(t: test.TestContext, config: Partial<ResolvedVaultConfig> = {}): Promise<World> {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-vault-'));
  const path = join(dir, 'vault.db');
  const clock = { now: Date.UTC(2026, 8, 1, 12) };
  const vault = await openLocalVault(
    path,
    {
      keks: new KekRegistry(LocalKekProvider.generate('test-kek-1')),
      rootAdmins: ['root@acme.example'],
      signingKey: SIGNING_KEY,
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
  return new DatabaseSync(w.path);
}

/** Another vault over the same file, as after a restart: it has verified nothing yet. */
async function reopen(t: test.TestContext, path: string) {
  const db = nodeSqlite(path);
  t.after(() => db.close());
  return openVault(db, {
    keks: new KekRegistry(LocalKekProvider.generate('test-kek-1')),
    rootAdmins: ['root@acme.example'],
    signingKey: SIGNING_KEY,
    bulkLimit: { count: 1000, windowMs: 15 * 60_000 },
  });
}

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

/** A local KEK that counts what reaches it, and can be made to act as a key service that is down. */
function watched() {
  const inner = LocalKekProvider.generate('test-kek-1');
  const seen = { wrap: 0, unwrap: 0, down: false };
  const kek: KekProvider = {
    provider: inner.provider,
    keyId: inner.keyId,
    keyVersion: inner.keyVersion,
    wrap: (dek, ctx) => (seen.wrap++, inner.wrap(dek, ctx)),
    unwrap: async (wrapped, ctx) => {
      seen.unwrap++;
      if (seen.down) throw new KekUnavailableError('KMS Decrypt failed 3 times: KMSInternalException');
      return inner.unwrap(wrapped, ctx);
    },
  };
  return { keks: new KekRegistry(kek), seen };
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
    const w = await world(t, { keks: new KekRegistry(kek) });
    const secret = w.secret(w.dev);
    const key = randomBytes(32).toString('base64');
    const sealed = await w.vault.wrap({ principal: ROOT, items: [{ secret, key }] });
    assert.ok(sealed.ok);
    held.length = 0;
    fail = true;
    if (failure === 'log') {
      const db = raw(w);
      t.after(() => db.close());
      db.exec("CREATE TRIGGER refuse_log BEFORE INSERT ON log BEGIN SELECT RAISE(ABORT, 'test log failure'); END");
    }
    const call = operation === 'wrap'
      ? w.vault.wrap({ principal: ROOT, items: [{ secret, key }] })
      : w.vault.unwrap({ principal: ROOT, purpose: 'reveal', items: [{ secret, wrapped: sealed.wrapped[0] }] });
    if (failure !== null) {
      await assert.rejects(call, /test (provider|log) failure/);
    } else {
      const result = await call;
      assert.ok(result.ok);
      if ('keys' in result) assert.deepEqual(result.keys, [key]);
    }
    assert.equal(held.length, 1);
    assert.deepEqual(held[0], Buffer.alloc(32), 'no raw DEK remains in the buffer handed to or returned by the provider');
  });
}

test('only a call the rules allow reaches the KEK', async (t) => {
  const { keks, seen } = watched();
  const w = await world(t, { keks, bulkLimit: { count: 2, windowMs: 60_000 } });
  await member(w, ADA, [[w.dev, 'viewer']]);
  const [dev, prod] = [w.secret(w.dev), w.secret(w.prod)];
  const items = [
    { secret: dev, wrapped: await wrapped(w, dev) },
    { secret: prod, wrapped: await wrapped(w, prod) },
  ];
  const before = { ...seen };
  const code = (outcome: { ok: boolean; refusal?: { code: string } }) => outcome.refusal?.code;

  assert.equal(code(await w.vault.unwrap({ principal: ADA, purpose: 'run', items })), 'no_grant');
  assert.equal(code(await w.vault.unwrap({ principal: BOB, purpose: 'run', items: items.slice(0, 1) })), 'not_a_member');
  assert.equal(code(await w.vault.wrap({ principal: ADA, items: [{ secret: dev, key: randomBytes(32).toString('base64') }] })), 'no_grant');
  const again = { ...w.secret(w.dev), secretId: dev.secretId, version: 2 };
  assert.equal(code(await w.vault.rewrap({ principal: ADA, items: [{ secret: again, from: 1, wrapped: items[0]!.wrapped }] })), 'no_grant');
  assert.deepEqual(seen, before, 'refused, so no key was wrapped or unwrapped');

  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'run', items: items.slice(0, 1) })).ok, true);
  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'run', items: items.slice(0, 1) })).ok, true);
  assert.equal(code(await w.vault.unwrap({ principal: ADA, purpose: 'run', items: items.slice(0, 1) })), 'bulk_limit');
  assert.equal(seen.unwrap, before.unwrap + 2, 'past the bulk limit, nothing reaches the KEK either');
});

test('a key service that cannot answer fails the call, and refuses nothing', async (t) => {
  const { keks, seen } = watched();
  const w = await world(t, { keks });
  await member(w, ADA, [[w.dev, 'viewer']]);
  const secret = w.secret(w.dev);
  const items = [{ secret, wrapped: await wrapped(w, secret) }];
  seen.down = true;
  await assert.rejects(w.vault.unwrap({ principal: ADA, purpose: 'run', items }), /KMS Decrypt failed 3 times/);
  const log = await w.vault.log({ actor: ROOT });
  assert.ok(log.ok);
  assert.equal(log.entries.filter((entry) => entry.action === 'unwrap').length, 0, 'no refusal, and no read, to log');

  seen.down = false;
  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'run', items })).ok, true, 'and the next call goes through');
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

  // Its credential lives in a project the maintainer does not manage. Once
  // its source grant is gone, naming the source is what lets them stop it.
  const other = `sync:${randomUUID()}`;
  const credential = { projectId: randomUUID(), environmentId: randomUUID(), role: 'viewer' as const, expiresAt: null };
  assert.equal((await w.vault.setAccess({ actor: ROOT, principal: other, changes: [credential] })).ok, true);
  const source = { projectId: w.project, environmentId: w.dev };
  const refused = await w.vault.remove({ actor: MAINTAINER, principal: other });
  assert.equal(!refused.ok && refused.refusal.code, 'not_allowed');
  assert.equal((await w.vault.remove({ actor: BOB, principal: other, source })).ok, false);
  assert.equal((await w.vault.remove({ actor: MAINTAINER, principal: other, source })).ok, true);
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

/** `db`, counting the rows it hands back. */
function counting(db: Sqlite): Sqlite & { rows: number } {
  const counted = {
    rows: 0,
    run: (sql: string, ...params: SqlValue[]) => db.run(sql, ...params),
    get<T>(sql: string, ...params: SqlValue[]) {
      const row = db.get<T>(sql, ...params);
      if (row !== undefined) counted.rows += 1;
      return row;
    },
    all<T>(sql: string, ...params: SqlValue[]) {
      const rows = db.all<T>(sql, ...params);
      counted.rows += rows.length;
      return rows;
    },
    *iterate<T>(sql: string, ...params: SqlValue[]) {
      for (const row of db.iterate<T>(sql, ...params)) {
        counted.rows += 1;
        yield row;
      }
    },
    transaction: <T>(fn: () => T) => db.transaction(fn),
  };
  return counted;
}

/** A vault whose log holds `n` wraps and an admission, over a store that counts what it reads. */
async function longLog(t: test.TestContext, n: number) {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-vault-'));
  const path = join(dir, 'vault.db');
  const file = nodeSqlite(path);
  const db = counting(file);
  const vault = await openVault(db, {
    keks: new KekRegistry(LocalKekProvider.generate('test-kek-1')),
    rootAdmins: ['root@acme.example'],
    signingKey: SIGNING_KEY,
    bulkLimit: { count: 1000, windowMs: 15 * 60_000 },
  });
  t.after(() => {
    file.close();
    rmSync(dir, { recursive: true, force: true });
  });
  const place = { projectId: randomUUID(), environmentId: randomUUID(), version: 1 };
  const items = Array.from({ length: n }, (_, i) => ({
    secret: { ...place, secretId: randomUUID(), path: `market/dev/KEY_${i}` },
    key: randomBytes(32).toString('base64'),
  }));
  assert.ok((await vault.wrap({ principal: ROOT, items })).ok);
  assert.ok((await vault.admit({ actor: ROOT, principal: ADA })).ok);
  return { vault, db, path };
}

/**
 * Rewrite entry `seq` in the file, as someone holding it could, and re-chain
 * what follows under `rechain`: the vault's log key for someone who also
 * holds its configuration, any other for someone who does not.
 */
function rewrite(path: string, seq: number, rechain: Uint8Array | null) {
  const file = new DatabaseSync(path);
  try {
    file.exec('DROP TRIGGER log_no_update');
    const rows = file.prepare(`SELECT ${LOG_COLUMNS} FROM log WHERE seq >= ? ORDER BY seq`).all(seq) as LogRow[];
    let prevHash = rows[0].prevHash;
    for (const row of rechain ? rows : rows.slice(0, 1)) {
      const actor = row.seq === seq ? BOB : row.actor;
      const hash = rechain ? entryHash(rechain, prevHash, { ...row, actor }) : row.hash;
      file.prepare('UPDATE log SET actor = ?, prev_hash = ?, hash = ? WHERE seq = ?').run(actor, prevHash, hash, row.seq);
      prevHash = hash;
    }
  } finally {
    file.close();
  }
}

const LOG_COLUMNS = 'seq, at, actor, action, outcome, code, subject, detail, prev_hash AS prevHash, hash';

test('a log view rehashes the page and what is new, not the whole chain', async (t) => {
  const { vault, db } = await longLog(t, 300);
  const view = async (input: { before?: number; full?: boolean } = {}) => {
    db.rows = 0;
    const page = await vault.log({ actor: ROOT, limit: 10, ...input });
    assert.ok(page.ok);
    assert.deepEqual(page.verification, { ok: true, entries: 301 });
    return db.rows;
  };
  // The first view after a start has nothing to go on: all of it.
  assert.ok((await view()) > 300);
  assert.ok((await view()) < 20);
  assert.ok((await view({ before: 100 })) < 20);
  assert.ok((await view({ full: true })) > 300);
});

test('an entry edited in place is found on its page, or by a full check', async (t) => {
  const { vault, path } = await longLog(t, 50);
  assert.ok((await vault.log({ actor: ROOT })).ok);

  // Off the page and edited in place: only a full check rehashes it.
  rewrite(path, 3, null);
  const view = await vault.log({ actor: ROOT, limit: 10 });
  assert.ok(view.ok && view.verification.ok);
  const onPage = await vault.log({ actor: ROOT, before: 10 });
  assert.deepEqual(onPage.ok && onPage.verification, { ok: false, failedAtSeq: 3, reason: 'hash does not match the entry' });
  const full = await vault.log({ actor: ROOT, limit: 10, full: true });
  assert.deepEqual(full.ok && full.verification, { ok: false, failedAtSeq: 3, reason: 'hash does not match the entry' });
});

test('a rewrite re-chained without the vault\'s key is found by any full check', async (t) => {
  const { path } = await longLog(t, 50);
  rewrite(path, 3, randomBytes(32));
  const fresh = await (await reopen(t, path)).log({ actor: ROOT, full: true });
  assert.deepEqual(fresh.ok && fresh.verification, { ok: false, failedAtSeq: 3, reason: 'hash does not match the entry' });
});

test('a rewrite re-chained with the vault\'s key is found against the head it last verified', async (t) => {
  const { vault, path } = await longLog(t, 50);
  assert.ok((await vault.log({ actor: ROOT })).ok);

  rewrite(path, 3, logKey(SIGNING_KEY));
  const view = await vault.log({ actor: ROOT, limit: 10 });
  assert.deepEqual(view.ok && view.verification, { ok: false, failedAtSeq: 51, reason: 'changed since the vault last verified it' });
  // A vault that never saw the head before cannot tell: whoever holds the
  // key can chain anything. The heads checkpoints signed can; see below.
  const unaware = await (await reopen(t, path)).log({ actor: ROOT, full: true });
  assert.ok(unaware.ok && unaware.verification.ok);
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

  // Append-only, as the log is.
  const db = raw(w);
  t.after(() => db.close());
  assert.throws(() => db.prepare('DELETE FROM checkpoints WHERE seq = 20').run(), /append-only/);
  assert.throws(() => db.prepare(`UPDATE checkpoints SET head_hash = 'e'`).run(), /append-only/);
});

test('a checkpoint signs the vault log\'s head too, and none is signed over that log rewritten', async (t) => {
  const w = await world(t);
  await member(w, ADA, [[w.dev, 'viewer']]);
  const page = await w.vault.log({ actor: ROOT, limit: 1 });
  assert.ok(page.ok);
  const head = { seq: page.entries[0].seq, hash: page.entries[0].hash };

  const first = await w.vault.checkpoint({ seq: 10, headHash: 'a'.repeat(64), previous: null });
  assert.ok(first.ok);
  assert.deepEqual(first.checkpoint.vault, head);
  const { publicKey } = await w.vault.latestCheckpoint();
  assert.equal(await verifyCheckpoint({ ...first.checkpoint, vault: { ...head, seq: 1 } }, publicKey), false);

  // Someone holding the file and the vault's keys rewrites an entry the
  // checkpoint covers, and chains again.
  await member(w, BOB, [[w.dev, 'viewer']]);
  rewrite(w.path, 1, logKey(SIGNING_KEY));
  const next = await w.vault.checkpoint({ seq: 20, headHash: 'b'.repeat(64), previous: { seq: 10, hash: 'a'.repeat(64) } });
  assert.equal(!next.ok && next.refusal.code, 'log_broken');

  // A vault started afresh has no head of its own to go on, but the one
  // the app recorded, and the last checkpoint's, are no longer there.
  const fresh = await reopen(t, w.path);
  const rewritten = 'the log was rewritten or cut back';
  assert.deepEqual(await fresh.verifyLog({ through: head }), {
    ok: false,
    failedAtSeq: head.seq,
    reason: `not the entry a checkpoint the app recorded signed: ${rewritten}`,
  });
  assert.deepEqual(await fresh.verifyLog({ through: null }), {
    ok: false,
    failedAtSeq: head.seq,
    reason: `not the entry the last checkpoint signed: ${rewritten}`,
  });
});

test('a full check replays who holds what from the log, and finds what was written around it', async (t) => {
  const w = await world(t);
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
  await member(w, ADA, [[w.dev, 'developer'], [w.prod, 'viewer', w.clock.now + 60_000]]);
  await member(w, BOB, [[null, 'maintainer']]);
  await change(ADA, w.dev, 'viewer');
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA, owner: true })).ok);
  assert.ok((await w.vault.remove({ actor: ROOT, principal: BOB })).ok);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: BOB })).ok);
  w.clock.now += 120_000;
  await change(ADA, w.prod, null);
  const whole = await w.vault.verifyLog({ through: null });
  assert.ok(whole.ok);

  // A grant written straight into the store: the chain holds, the replay does not.
  const db = raw(w);
  t.after(() => db.close());
  db.prepare(`INSERT INTO grants VALUES (?, ?, NULL, 'owner', NULL, ?, ?)`).run(BOB, w.project, w.clock.now, ROOT);
  const extra = {
    ok: false,
    failedAtSeq: null,
    reason: `the store holds a grant the log never gave: ${BOB} as owner on ${w.project}`,
    fault: { kind: 'unlogged-grant', grant: { principal: BOB, projectId: w.project, environmentId: null, role: 'owner' } },
  };
  assert.deepEqual(await w.vault.verifyLog({ through: null }), extra);
  const full = await w.vault.log({ actor: ROOT, full: true });
  assert.deepEqual(full.ok && full.verification, extra);
  // A view that is not full does not replay.
  const view = await w.vault.log({ actor: ROOT });
  assert.deepEqual(view.ok && view.verification, whole);

  // Or a removal undone, grants and all.
  db.prepare('DELETE FROM grants WHERE principal = ? AND role = ?').run(BOB, 'owner');
  assert.ok((await w.vault.remove({ actor: ROOT, principal: ADA })).ok);
  db.prepare(`UPDATE principals SET status = 'active', owner = 1 WHERE principal = ?`).run(ADA);
  db.prepare(`INSERT INTO grants VALUES (?, ?, ?, 'viewer', NULL, 0, ?)`).run(ADA, w.project, w.dev, ROOT);
  assert.deepEqual(await w.vault.verifyLog({ through: null }), {
    ok: false,
    failedAtSeq: null,
    reason: `the store's ${ADA} differs from the log's in status, owner`,
    fault: { kind: 'member-differs', principal: ADA, fields: ['status', 'owner'] },
  });
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
  // In WAL, the newest writes are in the -wal until a checkpoint moves them.
  const file = Buffer.concat([w.path, `${w.path}-wal`].map((name) => readFileSync(name)));
  assert.ok(file.includes(secret.path), 'the log entry is where this looks');
  for (const needle of [kek, key]) {
    assert.equal(file.includes(needle), false);
    assert.equal(file.includes(Buffer.from(needle.toString('base64'))), false);
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
