import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import type { CoffreClient } from '@coffre/client';
import { and, asc, eq, gte } from 'drizzle-orm';

import { auditChainHead, auditLog } from './db/tables.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';

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

test("an environment's key folder renames and removes as a whole, by who writes there, archived keys too", async () => {
  await developer.secrets.update('market/prod/DATABASE_URL', { folder: 'database' });
  await developer.secrets.update('market/prod/STRIPE_KEY', { folder: 'database' });
  await root.secrets.update('market/prod/STRIPE_KEY', { archived: true });
  assert.deepEqual(await developer.folders.renameKeys('market/prod', 'database', 'db'), { folder: 'db', moved: ['DATABASE_URL', 'STRIPE_KEY'] });
  assert.deepEqual((await reader.secrets.list('market/prod')).keys.map((key) => [key.key, key.folder]), [['DATABASE_URL', 'db'], ['PORT', null], ['STRIPE_KEY', 'db']]);
  await assert.rejects(reader.folders.renameKeys('market/prod', 'db', 'x'), { status: 403 }, 'renaming needs write, as moving does');
  await assert.rejects(reader.folders.removeKeys('market/prod', 'db'), { status: 403 });
  assert.deepEqual(await developer.folders.removeKeys('market/prod', 'db'), { folder: null, moved: ['DATABASE_URL', 'STRIPE_KEY'] });
  assert.deepEqual((await reader.secrets.list('market/prod')).keys.map((key) => key.folder), [null, null, null]);
  await assert.rejects(developer.folders.removeKeys('market/prod', 'db'), { status: 404 });
  assert.deepEqual((await logged('secret.move')).filter((entry) => entry.decision === 'allow').slice(2).map((entry) => entry.metadata), [
    { key: 'DATABASE_URL', from: 'database', to: 'db' },
    { key: 'STRIPE_KEY', from: 'database', to: 'db' },
    { key: 'DATABASE_URL', from: 'db', to: null },
    { key: 'STRIPE_KEY', from: 'db', to: null },
  ]);
  // A folder named like a route's own word is just a folder.
  await developer.secrets.update('market/prod/PORT', { folder: 'reference' });
  assert.deepEqual(await developer.folders.removeKeys('market/prod', 'reference'), { folder: null, moved: ['PORT'] });
});

test("a key's folder is a plain name: no slash, no control character, no space at either end", async () => {
  for (const folder of ['a/b', ' padded', 'padded ', '', 'tab\there', 'x'.repeat(65)]) {
    await assert.rejects(root.secrets.update('market/prod/PORT', { folder }), { status: 400 }, JSON.stringify(folder));
  }
});
