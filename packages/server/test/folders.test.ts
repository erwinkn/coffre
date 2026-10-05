import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import type { CoffreClient } from '@coffre/client';
import { migrationLedger } from '@coffre/db/dialect';
import { and, asc, eq, gte, sql, type SQL } from 'drizzle-orm';

import { auditChainHead, auditLog } from './db/tables.ts';
import { TEST_ENGINE } from './db/engine.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';
import { FOLDERS_MIGRATION } from '../src/api/folders.ts';
import { KNOWN_MIGRATIONS } from '@coffre/db/schema-version';

const ROOT = 'admin@acme.example';
const DEVELOPER = 'developer@acme.example';
const READER = 'reader@acme.example';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let root: CoffreClient;
let developer: CoffreClient;
let reader: CoffreClient;
let firstSeq: bigint;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  root = clientFor(deps, ROOT);
  developer = clientFor(deps, DEVELOPER);
  reader = clientFor(deps, READER);
  await root.projects.create('market', { name: 'Market' });
  await root.projects.create('acme', { name: 'Acme' });
  await root.environments.create('market/prod', { name: 'Prod' });
  await root.members.add(`user:${DEVELOPER}`);
  await root.members.add(`user:${READER}`);
  await root.access.set(`user:${DEVELOPER}`, { 'market/prod': 'developer', acme: 'viewer' });
  await root.access.set(`user:${READER}`, { 'market/prod': 'viewer' });
  await root.secrets.set('market/prod', { DATABASE_URL: 'postgres://db', STRIPE_KEY: 'sk_live', PORT: '8080' });
  const [head] = await db.owner.select({ nextSeq: auditChainHead.nextSeq }).from(auditChainHead);
  firstSeq = head.nextSeq;
});

/** The app's entries of `action` since the setup. */
async function logged(action: string) {
  const rows = await db.owner
    .select({ actor: auditLog.actor, decision: auditLog.decision, metadata: auditLog.metadata })
    .from(auditLog)
    .where(and(eq(auditLog.author, 'app'), eq(auditLog.action, action), gte(auditLog.seq, firstSeq)))
    .orderBy(asc(auditLog.seq));
  return rows.map((row) => ({ ...row, metadata: JSON.parse(row.metadata) as Record<string, unknown> }));
}

const folderOf = async (client: CoffreClient, slug: string) =>
  (await client.projects.list()).projects.find((project) => project.slug === slug)?.folder;

test('a project moves into a folder and out of it, logged, by whoever manages it', async () => {
  assert.equal(await folderOf(root, 'acme'), null);
  assert.equal((await root.projects.update('acme', { folder: 'Clients' })).project.folder, 'Clients');
  assert.equal(await folderOf(developer, 'acme'), 'Clients');
  // Moving it where it is changes nothing and logs nothing.
  await root.projects.update('acme', { folder: 'Clients' });
  await root.projects.update('acme', { folder: null });
  assert.equal(await folderOf(root, 'acme'), null);
  assert.deepEqual((await logged('project.move')).map((entry) => entry.metadata), [
    { slug: 'acme', from: null, to: 'Clients' },
    { slug: 'acme', from: 'Clients', to: null },
  ]);
  // A viewer of the project does not arrange the instance's list.
  await assert.rejects(developer.projects.update('acme', { folder: 'Mine' }), { status: 403 });
  assert.equal(await folderOf(root, 'acme'), null);
});

test("a secret's folder arranges its environment's list, and changes nothing else", async () => {
  await developer.secrets.update('market/prod/DATABASE_URL', { folder: 'database' });
  await developer.secrets.update('market/prod/STRIPE_KEY', { folder: 'stripe' });
  const { keys } = await reader.secrets.list('market/prod');
  assert.deepEqual(keys.map((key) => [key.key, key.folder]), [['DATABASE_URL', 'database'], ['PORT', null], ['STRIPE_KEY', 'stripe']]);
  // Keys are injected by their names, wherever they are filed.
  assert.deepEqual(Object.keys((await reader.secrets.reveal('market/prod')).values).sort(), ['DATABASE_URL', 'PORT', 'STRIPE_KEY']);
  // A rename keeps its folder; a version keeps it too.
  await developer.secrets.rename('market/prod/STRIPE_KEY', 'STRIPE_SECRET_KEY');
  await developer.secrets.set('market/prod', { STRIPE_SECRET_KEY: 'sk_live_2' });
  assert.equal((await reader.secrets.list('market/prod')).keys.find((key) => key.key === 'STRIPE_SECRET_KEY')?.folder, 'stripe');
  assert.deepEqual((await logged('secret.move')).map((entry) => [entry.actor, entry.metadata]), [
    [`user:${DEVELOPER}`, { key: 'DATABASE_URL', from: null, to: 'database' }],
    [`user:${DEVELOPER}`, { key: 'STRIPE_KEY', from: null, to: 'stripe' }],
  ]);
  // Moving needs write, as renaming does.
  await assert.rejects(reader.secrets.update('market/prod/PORT', { folder: 'web' }), { status: 403 });
});

test('a folder is a plain name: no slash, no control character, no space at either end', async () => {
  for (const folder of ['a/b', ' padded', 'padded ', '', 'tab\there', 'x'.repeat(65)]) {
    await assert.rejects(root.projects.update('acme', { folder }), { status: 400 }, JSON.stringify(folder));
    await assert.rejects(root.secrets.update('market/prod/PORT', { folder }), { status: 400 }, JSON.stringify(folder));
  }
  assert.equal((await root.projects.update('acme', { folder: 'Clients · EU' })).project.folder, 'Clients · EU');
});

test('before its migration, this release lists everything in no folder, writes secrets as before, and refuses to move', async () => {
  await root.projects.update('acme', { folder: 'Clients' });
  // A database deployed to before `coffre migrate`: no folder tables, and the ledger without them.
  const ledger = migrationLedger(db.owner);
  const later = (await rows(sql`SELECT * FROM ${ledger} ORDER BY created_at`)).slice(KNOWN_MIGRATIONS.postgres.indexOf(FOLDERS_MIGRATION));
  for (const entry of later) await run(sql`DELETE FROM ${ledger} WHERE hash = ${entry.hash}`);
  await run(sql`ALTER TABLE project_folders RENAME TO project_folders_away`);
  await run(sql`ALTER TABLE secret_folders RENAME TO secret_folders_away`);
  try {
    assert.equal(await folderOf(root, 'acme'), null);
    await developer.secrets.set('market/prod', { NEW_KEY: 'new' });
    assert.deepEqual((await reader.secrets.list('market/prod')).keys.map((key) => key.folder), [null, null, null, null]);
    assert.equal((await reader.secrets.reveal('market/prod/NEW_KEY')).values.NEW_KEY, 'new');
    await developer.secrets.rename('market/prod/NEW_KEY', 'NEWER_KEY');
    await assert.rejects(root.projects.update('acme', { folder: 'Other' }), { status: 503 });
    await assert.rejects(developer.secrets.update('market/prod/PORT', { folder: 'web' }), { status: 503 });
  } finally {
    await run(sql`ALTER TABLE project_folders_away RENAME TO project_folders`);
    await run(sql`ALTER TABLE secret_folders_away RENAME TO secret_folders`);
    for (const entry of later) {
      const columns = Object.keys(entry);
      await run(sql`INSERT INTO ${ledger} (${sql.join(columns.map((column) => sql.identifier(column)), sql`, `)})
        VALUES (${sql.join(columns.map((column) => sql`${entry[column]}`), sql`, `)})`);
    }
  }
  assert.equal(await folderOf(root, 'acme'), 'Clients');
});

/** Raw SQL as the owner, on either engine. */
async function rows(query: SQL): Promise<Record<string, unknown>[]> {
  if (TEST_ENGINE === 'sqlite') return (db.owner as unknown as { all: (q: SQL) => Promise<Record<string, unknown>[]> }).all(query);
  return (await (db.owner as unknown as { execute: (q: SQL) => Promise<{ rows: Record<string, unknown>[] }> }).execute(query)).rows;
}

async function run(query: SQL): Promise<void> {
  if (TEST_ENGINE === 'sqlite') await (db.owner as unknown as { run: (q: SQL) => Promise<unknown> }).run(query);
  else await (db.owner as unknown as { execute: (q: SQL) => Promise<unknown> }).execute(query);
}
