// The restore drill on 0.15's log (docs/restore.md, "On 0.15's log"; PR 9b), as scripts/restore-drill.sh runs it on
// 0.14's: an instance cut over and writing under 0.15, its checkpointer sealing, backed up with `coffre backup`,
// restored with `coffre restore --keys` into an empty database, and checked to have come back on 0.15: its log
// cut over, its trees signed by its vault key and verified, its rows the log's, a token's use serving the value it
// served, and new changes sealed on top. The signer's memory of a pair the backup predates refuses the restored log
// (the database lost entries it signed), as a writer's rollback would be refused, until it is given a new memory.
// The wrong vault key verifies nothing. A backup from before a rotation of the vault key comes back under the new
// key, the log moving on from the old one again (T168). Postgres only, with PostgreSQL 16's pg_dump and pg_restore on PATH, as the
// CLI's backup tests (packages/cli/test/backup.test.ts) need them.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { decrypt } from '@coffre/core/envelope';
import { defineSignin, github } from '@coffre/core/identity';
import { derivedSigningKey } from '@coffre/core/kek';
import type { UseOutcome } from '@coffre/core/vault';
import { openDatabase, postgresClient } from '@coffre/db/connect';
import { logObject } from '@coffre/db/log';
import { migrateDatabase } from '@coffre/db/migrate';
import { localVault, replayStored, runCheckpointer, type LocalVault, type RunningCheckpointer } from '@coffre/vault/node';
import { eq } from 'drizzle-orm';

import { SigninService } from '../src/api/signin.ts';
import { clientFor, resetDatabase, testDeps, testVault, type TestVault } from './api-fixture.ts';
import { TEST_HOT_DATABASE_URL, TEST_OWNER_DATABASE_URL } from './db/connections.ts';
import { openTestDatabase, openVaultDatabase, TEST_ENGINE } from './db/engine.ts';
import { environments, logBulk, logChanges, logCheckpoints, logFence, logTiles, logUses, projects, secrets } from './db/tables.ts';

const ROOT = 'admin@acme.example';
const CI = 'token:ci';
const main = fileURLToPath(new URL('../../cli/src/main.ts', import.meta.url));

let db: Awaited<ReturnType<typeof openTestDatabase>>;
const scratch = mkdtempSync(join(tmpdir(), 'coffre-restore-015-'));
const running: RunningCheckpointer[] = [];
const source = new URL(TEST_OWNER_DATABASE_URL).pathname.slice(1);
const restored = `${source.slice(0, 60)}_r`;
const checked = `${source.slice(0, 60)}_w`;
const rotatedBack = `${source.slice(0, 60)}_k`;
/** The log's own object for its rotations (log-entry.ts, KEY_OBJECT). */
const KEY_OBJECT = logObject('log', 'key');
/** The test's server, as `login`, over `database`. */
const urlOf = (database: string, login = 'coffre_owner:local-dev-only') => {
  const url = new URL(TEST_OWNER_DATABASE_URL);
  [url.username, url.password] = login.split(':') as [string, string];
  url.pathname = `/${database}`;
  return url.href;
};

const tools = spawnSync('pg_restore', ['--version'], { encoding: 'utf8' });
const toolsMajor = /(\d+)\.\d+/.exec(tools.stdout ?? '')?.[1] ?? null;
const major = TEST_ENGINE !== 'postgres' || tools.status !== 0 ? null : await serverMajor(urlOf('postgres'));
const postgres = {
  skip: TEST_ENGINE !== 'postgres' ? 'Postgres only: coffre backup runs pg_dump'
    : tools.status !== 0 ? 'needs pg_dump and pg_restore on PATH'
    : toolsMajor !== major ? `needs PostgreSQL ${major} pg_dump and pg_restore on PATH, the server's major version, not ${toolsMajor}` : false,
};

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  for (const checkpointer of running) await checkpointer.stop().catch(() => {});
  if (postgres.skip === false) await asServer(async (client) => {
    for (const name of [restored, checked, rotatedBack]) await client.unsafe(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
  });
  await db.close();
  rmSync(scratch, { recursive: true, force: true });
});

/** The server's major version, as PostgreSQL's tools must have it: a newer `pg_restore` sends settings an older server lacks. */
async function serverMajor(url: string): Promise<string> {
  const client = postgresClient(url);
  try {
    const [row] = await client.unsafe<{ server_version_num: string }[]>('SHOW server_version_num');
    return String(Math.floor(Number(row!.server_version_num) / 10_000));
  } finally {
    await client.end();
  }
}

async function asServer<T>(work: (client: ReturnType<typeof postgresClient>) => Promise<T>): Promise<T> {
  const client = postgresClient(urlOf('postgres'));
  try {
    return await work(client);
  } finally {
    await client.end();
  }
}

/** The CLI, with `stdin` piped in: no terminal, as in a pipeline. */
function coffre(args: string[], stdin: string): Promise<{ code: number | null; stderr: string; stdout: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--conditions=coffre:source', main, ...args], { cwd: scratch, env: { ...process.env, HOME: scratch }, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8').on('data', (chunk: string) => (stdout += chunk));
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(stdin);
  });
}

async function checkpointerOver(database: Parameters<typeof runCheckpointer>[0]['database'], seed: Buffer | readonly Buffer[], memory: string): Promise<RunningCheckpointer> {
  const made = await runCheckpointer({ database, signingKeys: Buffer.isBuffer(seed) ? [seed] : seed, memory: join(scratch, memory), intervalMs: 3_600_000 });
  running.push(made);
  return made;
}

let request = 0;

function use(vault: Pick<TestVault, 'use'> | LocalVault, credential: string, secretId: string): Promise<UseOutcome> {
  const at = Date.now();
  request += 1;
  return vault.use!({ credential, secretId, place: null, purpose: 'run', requestId: String(at * 1000 + request), at, deadline: at + 3000 });
}

function opened(outcome: UseOutcome, secretId: string, environmentId: string, projectId: string): string {
  assert.ok(outcome.ok, JSON.stringify(outcome));
  const { envelope, key } = outcome.value;
  return decrypt(
    { envelopeVersion: envelope.version, ciphertext: Buffer.from(envelope.ciphertext, 'base64'), iv: Buffer.from(envelope.iv, 'base64'), authTag: Buffer.from(envelope.authTag, 'base64') },
    { projectId, environmentId, secretId }, Buffer.from(key, 'base64'),
  ).toString();
}

test("a 0.15 instance backed up and restored comes back on 0.15: cut over, its trees signed by its vault key, its rows the log's, a token's use serving its value; the signer's memory of later pairs refuses it, a new one takes it; the wrong vault key verifies nothing", postgres, async () => {
  await resetDatabase(db.owner);
  for (const table of [logUses, logBulk, logCheckpoints, logTiles]) await db.owner.delete(table);
  await db.owner.update(logFence).set({ atFloor: Date.now() - 60_000 });

  // The instance: its vault under 0.15's log, cut over as it opens, its checkpointer sealing every change.
  const kek = randomBytes(32);
  const seed = derivedSigningKey(kek);
  const signer = await checkpointerOver(await openVaultDatabase(), seed, 'memory');
  const vault = testVault([ROOT], { hotDatabase: TEST_HOT_DATABASE_URL }, { kek }, {}, { log: '0.15', sealThrough: signer.sealThrough });
  const deps = testDeps(db.runtime, [ROOT], { vault });
  deps.signin = new SigninService({ db: deps.db, chainKey: deps.chainKey, vault, signin: defineSignin({ publicUrl: 'https://secrets.acme.example', providers: [github({ clientId: 'a', clientSecret: 'b' })] }) });
  const root = clientFor(deps, ROOT);
  await root.members.add(CI);
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { A: 'one' });
  await root.access.set(CI, { 'market/dev': 'viewer' });
  const token = await root.tokens.issue(CI, { label: 'ci', expiresInDays: 30 });
  const [place] = await db.owner.select({ environmentId: environments.id, projectId: projects.id }).from(environments).innerJoin(projects, eq(projects.id, environments.projectId));
  const [key] = await db.owner.select({ id: secrets.id }).from(secrets).where(eq(secrets.key, 'A'));
  const { environmentId, projectId } = place!;
  assert.equal(opened(await use(vault, token.id, key!.id), key!.id, environmentId, projectId), 'one');
  await signer.checkpointer.tick();

  // Backed up, as a pipeline does it: the backup login's connection string on stdin.
  const dump = join(scratch, 'coffre.dump');
  const backedUp = await coffre(['backup', dump], urlOf(source, 'coffre_backup_login:local-backup-only'));
  assert.equal(backedUp.code, 0, backedUp.stderr);
  // The instance goes on after the backup: a change the signer seals, which the restored database will not hold.
  await root.secrets.set('market/dev', { A: 'two' });
  await signer.checkpointer.tick();

  // Restored into an empty database, checked whole with its keys, then migrated, which grants what a dump leaves out.
  await asServer(async (client) => {
    for (const name of [restored, checked]) {
      await client.unsafe(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
      await client.unsafe(`CREATE DATABASE "${name}" OWNER coffre_owner`);
    }
  });
  const owner = urlOf(restored);
  const back = await coffre(['restore', dump, '--keys'], `${owner}\n${kek.toString('base64')}\n${deps.chainKey.toString('base64')}\n`);
  assert.equal(back.code, 0, `${back.stdout}\n${back.stderr}`);
  await migrateDatabase(owner, { backupLogin: 'coffre_backup_login' });

  // Its vault login over it, as a deployment points its vault at the restored database.
  const restoredVault = await openDatabase(urlOf(restored, 'coffre_vault_runtime:local-vault-only'));
  const restoredOwner = await openDatabase(owner);
  try {
    // The signer, remembering the pair it signed after the backup: the restored log lost entries it sealed, refused.
    await assert.rejects(checkpointerOver(restoredVault.db, seed, 'memory'), /lost entries the signer sealed/);
    // Given a new memory, it takes the database's newest pair, and says so.
    const fresh = await checkpointerOver(restoredVault.db, seed, 'memory-restored');
    const again = await localVault(
      { database: restoredVault.db, kek: { id: 'test-kek-1', key: kek.toString('base64') }, owners: [ROOT], hotDatabase: urlOf(restored, 'coffre_vault_hot:local-hot-only') },
      { log: '0.15', sealThrough: fresh.sealThrough },
    );
    assert.deepEqual(await again.cutover!(), { ok: true, done: true });
    const trees = await again.verifyTrees!();
    assert.ok(trees.kept && trees.ok && trees.checkpoint !== null, JSON.stringify(trees));
    // The token serves the value it served at the backup, and the log replays to every use it decided.
    assert.equal(opened(await use(again, token.id, key!.id), key!.id, environmentId, projectId), 'one');
    const replayed = await replayStored(restoredOwner.db, [seed]);
    assert.deepEqual(replayed.faults, []);
    assert.ok([...replayed.decided.values()].every((code) => code === null), JSON.stringify([...replayed.decided]));
    // A change on top, sealed by the new signer.
    const before = (await restoredOwner.db.select({ number: logChanges.number }).from(logChanges)).length;
    assert.ok((await again.setAccess({ actor: `user:${ROOT}`, caller: 'person', principal: CI, changes: [{ projectId, environmentId, role: 'developer', expiresAt: null }] })).ok);
    assert.equal((await restoredOwner.db.select({ number: logChanges.number }).from(logChanges)).length, before + 1);
    const after = await again.verifyTrees!();
    assert.ok(after.kept && after.ok, JSON.stringify(after));

    // The wrong vault key: its signer refuses the log's checkpoints, and `coffre verify backup` refuses the backup.
    await assert.rejects(checkpointerOver(restoredVault.db, derivedSigningKey(randomBytes(32)), 'memory-wrong'), /not a pair signed by this log/);
    const wrong = await coffre(['verify', 'backup', dump, '--keys'], `${urlOf(checked)}\n${randomBytes(32).toString('base64')}\n${deps.chainKey.toString('base64')}\n`);
    assert.notEqual(wrong.code, 0);
    assert.match(`${wrong.stdout}${wrong.stderr}`, /none of the vault keys given is this instance's/);
  } finally {
    await restoredVault.close();
    await restoredOwner.close();
  }
});

test('a backup taken before the vault key was rotated, restored under the new key: the old memory refuses it, a new one takes it and moves the log on again (T168)', postgres, async () => {
  await resetDatabase(db.owner);
  for (const table of [logUses, logBulk, logCheckpoints, logTiles]) await db.owner.delete(table);
  await db.owner.update(logFence).set({ atFloor: Date.now() - 60_000, retired: [] });

  // The instance under the old vault key, a value and a token's use of it, sealed; then backed up.
  const [oldKek, newKek] = [randomBytes(32), randomBytes(32)];
  const [oldSeed, newSeed] = [derivedSigningKey(oldKek), derivedSigningKey(newKek)];
  const signer = await checkpointerOver(await openVaultDatabase(), oldSeed, 'rotated-memory');
  const vault = testVault([ROOT], { hotDatabase: TEST_HOT_DATABASE_URL }, { kek: oldKek }, {}, { log: '0.15', sealThrough: signer.sealThrough });
  const deps = testDeps(db.runtime, [ROOT], { vault });
  deps.signin = new SigninService({ db: deps.db, chainKey: deps.chainKey, vault, signin: defineSignin({ publicUrl: 'https://secrets.acme.example', providers: [github({ clientId: 'a', clientSecret: 'b' })] }) });
  const root = clientFor(deps, ROOT);
  await root.members.add(CI);
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { A: 'one' });
  await root.access.set(CI, { 'market/dev': 'viewer' });
  const token = await root.tokens.issue(CI, { label: 'ci', expiresInDays: 30 });
  const [place] = await db.owner.select({ environmentId: environments.id, projectId: projects.id }).from(environments).innerJoin(projects, eq(projects.id, environments.projectId));
  const [key] = await db.owner.select({ id: secrets.id }).from(secrets).where(eq(secrets.key, 'A'));
  const { environmentId, projectId } = place!;
  assert.equal(opened(await use(vault, token.id, key!.id), key!.id, environmentId, projectId), 'one');
  await signer.checkpointer.tick();
  const dump = join(scratch, 'rotated.dump');
  const backedUp = await coffre(['backup', dump], urlOf(source, 'coffre_backup_login:local-backup-only'));
  assert.equal(backedUp.code, 0, backedUp.stderr);

  // The rotation: the new vault key, the old one previous; the checkpointer carries its memory across and moves on.
  await signer.stop();
  const keys = { kek: { id: 'test-kek-2', key: newKek.toString('base64') }, previousKeks: [{ id: 'test-kek-1', key: oldKek.toString('base64') }] };
  const rotated = await checkpointerOver(await openVaultDatabase(), [newSeed, oldSeed], 'rotated-memory');
  const under = await localVault({ database: await openVaultDatabase(), ...keys, owners: [ROOT], hotDatabase: TEST_HOT_DATABASE_URL }, { log: '0.15', sealThrough: rotated.sealThrough });
  assert.ok((await under.setAccess({ actor: `user:${ROOT}`, caller: 'person', principal: CI, changes: [{ projectId, environmentId, role: 'developer', expiresAt: null }] })).ok);
  assert.equal((await db.owner.select().from(logChanges).where(eq(logChanges.object, KEY_OBJECT))).length, 1);

  // Restored, as the first test restores, its keys checked with the vault key it was written under.
  await asServer(async (client) => {
    await client.unsafe(`DROP DATABASE IF EXISTS "${rotatedBack}" WITH (FORCE)`);
    await client.unsafe(`CREATE DATABASE "${rotatedBack}" OWNER coffre_owner`);
  });
  const owner = urlOf(rotatedBack);
  const back = await coffre(['restore', dump, '--keys'], `${owner}\n${oldKek.toString('base64')}\n${deps.chainKey.toString('base64')}\n`);
  assert.equal(back.code, 0, `${back.stdout}\n${back.stderr}`);
  await migrateDatabase(owner, { backupLogin: 'coffre_backup_login' });
  const restoredVault = await openDatabase(urlOf(rotatedBack, 'coffre_vault_runtime:local-vault-only'));
  const restoredOwner = await openDatabase(owner);
  try {
    // The memory, a pair under the new key past the backup: the restored log lost entries it sealed.
    await assert.rejects(checkpointerOver(restoredVault.db, [newSeed, oldSeed], 'rotated-memory'), /lost entries the signer sealed/);
    // A new memory takes the database's newest pair, under the old key, and moves the log on from it again.
    const fresh = await checkpointerOver(restoredVault.db, [newSeed, oldSeed], 'rotated-memory-restored');
    const moved = await restoredOwner.db.select().from(logChanges).where(eq(logChanges.object, KEY_OBJECT));
    assert.equal(moved.length, 1);
    const again = await localVault(
      { database: restoredVault.db, ...keys, owners: [ROOT], hotDatabase: urlOf(rotatedBack, 'coffre_vault_hot:local-hot-only') },
      { log: '0.15', sealThrough: fresh.sealThrough },
    );
    assert.equal(opened(await use(again, token.id, key!.id), key!.id, environmentId, projectId), 'one');
    assert.ok((await again.setAccess({ actor: `user:${ROOT}`, caller: 'person', principal: CI, changes: [{ projectId, environmentId, role: 'developer', expiresAt: null }] })).ok);
    const trees = await again.verifyTrees!();
    assert.ok(trees.kept && trees.ok, JSON.stringify(trees));
    assert.ok(BigInt(trees.checkpoint!.upto) > moved[0]!.number, 'the rotation sealed under the new key');
    const replayed = await replayStored(restoredOwner.db, [newSeed, oldSeed]);
    assert.deepEqual(replayed.faults, []);
  } finally {
    await restoredVault.close();
    await restoredOwner.close();
  }
});
