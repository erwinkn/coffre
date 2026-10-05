import { readFileSync } from 'node:fs';
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import type { CoffreClient } from '@coffre/client';
import { and, asc, count, eq } from 'drizzle-orm';

import { auditLog, projects, vaultMembers } from './db/tables.ts';
import {
  clientFor,
  openTestDatabase,
  resetDatabase,
  testDeps,
  type FixtureDeps,
} from './api-fixture.ts';

const ROOT = 'admin@acme.example';
const LEAD = 'user:lead@acme.example';
const READER = 'user:reader@acme.example';
const OWNER = 'user:instance-owner@acme.example';
const CI = 'token:ci-deploy';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let root: CoffreClient;
let lead: CoffreClient;
let reader: CoffreClient;
let owner: CoffreClient;
let outsider: CoffreClient;

before(async () => {
  db = await openTestDatabase();
  deps = testDeps(db.runtime, [ROOT]);
  root = clientFor(deps, ROOT);
  lead = clientFor(deps, 'lead@acme.example');
  reader = clientFor(deps, 'reader@acme.example');
  owner = clientFor(deps, 'instance-owner@acme.example');
  outsider = clientFor(deps, 'outsider@acme.example');
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  await root.members.add(LEAD);
  await root.members.add(READER);
  await root.members.add(CI);
});

async function seedProject(): Promise<void> {
  await root.projects.create('market', { name: 'Acme Market' });
  await root.environments.create('market/prod', { name: 'Production' });
  await root.access.set(LEAD, { market: 'owner' });
}

/** The log's actions, the app's and the vault's, oldest first. */
async function auditActions(): Promise<{ action: string; decision: string }[]> {
  return db.owner
    .select({ action: auditLog.action, decision: auditLog.decision })
    .from(auditLog)
    .orderBy(asc(auditLog.seq));
}

async function auditCount(): Promise<number> {
  const [row] = await db.owner.select({ n: count() }).from(auditLog);
  return row.n;
}

test('root admins and instance owners create projects without implicit secret grants', async () => {
  await root.members.add(OWNER, { owner: true });
  assert.deepEqual(await root.projects.create('market', { name: 'Market' }), {
    project: { slug: 'market', name: 'Market', archivedAt: null },
    created: true,
    inherited: [],
  });
  assert.deepEqual(await owner.projects.create('operations', { name: 'Operations' }), {
    project: { slug: 'operations', name: 'Operations', archivedAt: null },
    created: true,
    inherited: [],
  });
  await assert.rejects(outsider.projects.create('sneaky', { name: 'Sneaky' }), { status: 403 });
  assert.deepEqual((await auditActions()).slice(-4), [
    { action: 'member.add', decision: 'allow' },
    { action: 'project.create', decision: 'allow' },
    { action: 'project.create', decision: 'allow' },
    { action: 'project.create', decision: 'deny' },
  ]);
  assert.equal((await db.owner.select({ n: count() }).from(projects))[0].n, 2);
  assert.deepEqual((await deps.vault.access('user:instance-owner@acme.example')).grants, []);
});

test('creating a project or environment that exists changes nothing and logs nothing', async () => {
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/prod', { name: 'Production' });
  const logged = await auditCount();
  assert.deepEqual(await root.projects.create('market', { name: 'Again' }), {
    project: { slug: 'market', name: 'Market', archivedAt: null },
    created: false,
    inherited: [],
  });
  assert.deepEqual(await root.environments.create('market/prod', { name: 'Again' }), {
    environment: { slug: 'prod', name: 'Production', archivedAt: null },
    created: false,
    inherited: [],
  });
  assert.equal(await auditCount(), logged);
});

test('only configured bootstrap principals project as root admins', async () => {
  const me = await root.me();
  assert.equal(me.instanceRole, 'root-admin');
  assert.equal(me.canReadAudit, true);
  const them = await outsider.me();
  assert.equal(them.instanceRole, 'user');
  assert.equal(them.canReadAudit, false);
});

test('renaming a project slug preserves its encrypted secrets', async () => {
  await seedProject();
  await root.secrets.set('market/prod', { DATABASE_URL: 'postgres://x' });
  await root.projects.update('market', { slug: 'marketplace' });
  assert.equal(
    (await root.secrets.reveal('marketplace/prod/DATABASE_URL')).values.DATABASE_URL,
    'postgres://x',
  );
});

test('renaming projects and environments to existing slugs is a conflict and is audited', async () => {
  await seedProject();
  await root.projects.create('other', { name: 'Other' });
  await root.environments.create('market/dev', { name: 'Development' });

  await assert.rejects(root.projects.update('market', { slug: 'other' }), { status: 409 });
  await assert.rejects(root.environments.update('market/prod', { slug: 'dev' }), { status: 409 });

  const denials = await db.owner
    .select({ action: auditLog.action, metadata: auditLog.metadata })
    .from(auditLog)
    .where(and(eq(auditLog.author, 'app'), eq(auditLog.decision, 'deny')))
    .orderBy(asc(auditLog.seq));
  assert.deepEqual(
    denials.map((row) => [row.action, JSON.parse(row.metadata).reason]),
    [
      ['project.update', 'slug_taken'],
      ['environment.update', 'slug_taken'],
    ],
  );
});

test('project owners create environments; environment-scoped grants do not', async () => {
  await seedProject();
  assert.deepEqual(await lead.environments.create('market/staging', { name: 'Staging' }), {
    environment: { slug: 'staging', name: 'Staging', archivedAt: null },
    created: true,
    inherited: [],
  });
  await root.access.set(READER, { 'market/prod': 'developer' });
  await assert.rejects(reader.environments.create('market/nope', { name: 'Nope' }), { status: 403 });
  assert.deepEqual((await auditActions()).at(-1), { action: 'environment.create', decision: 'deny' });
});

test('project-only roles cannot be scoped to one environment', async () => {
  await seedProject();
  await assert.rejects(root.access.set(READER, { 'market/prod': 'owner' }), { status: 409 });
  const [last] = await db.owner
    .select({ decision: auditLog.decision, metadata: auditLog.metadata })
    .from(auditLog)
    .where(eq(auditLog.author, 'app'))
    .orderBy(asc(auditLog.seq))
    .then((rows) => rows.slice(-1));
  assert.equal(last.decision, 'deny');
  assert.equal(JSON.parse(last.metadata).reason, 'role_is_project_scoped');
});

test('environment archiving hides reads, is reversible, and preserves values', async () => {
  await seedProject();
  await root.secrets.set('market/prod', { API_KEY: 'still-here' });
  await root.environments.update('market/prod', { archived: true });
  await assert.rejects(root.secrets.reveal('market/prod/API_KEY'), { status: 404 });
  assert.deepEqual((await root.me()).environments, []);
  await root.environments.update('market/prod', { archived: false });
  assert.equal((await root.secrets.reveal('market/prod/API_KEY')).values.API_KEY, 'still-here');
});

test('project archiving hides every environment', async () => {
  await seedProject();
  await root.environments.create('market/dev', { name: 'Development' });
  await root.projects.update('market', { archived: true });
  assert.deepEqual((await root.me()).environments, []);
});

test('archived projects stay visible only to project and instance administrators', async () => {
  await seedProject();
  await root.access.set(READER, { market: 'viewer' });
  await root.projects.update('market', { archived: true });

  assert.deepEqual((await reader.projects.list()).projects, []);
  assert.notEqual((await lead.projects.list()).projects[0].archivedAt, null);
  assert.notEqual((await root.projects.list()).projects[0].archivedAt, null);
});

test('project grants cover every environment and combine with environment grants', async () => {
  await seedProject();
  await root.environments.create('market/dev', { name: 'Development' });
  await root.access.set(READER, { market: 'viewer', 'market/prod': 'developer' });
  const { environments } = await reader.me();
  assert.deepEqual(environments.map((entry) => entry.environment).sort(), ['dev', 'prod']);
  assert.deepEqual(
    environments.find((entry) => entry.environment === 'prod')?.permissions.sort(),
    ['secret.read', 'secret.write'],
  );
});

test('changing and revoking access works in place and is audited', async () => {
  await seedProject();
  assert.deepEqual(await root.access.set(READER, { market: 'viewer' }), { changes: { market: 'created' } });
  assert.equal((await reader.me()).environments.length, 1);

  const logged = await auditCount();
  assert.deepEqual(await root.access.set(READER, { market: 'viewer' }), { changes: { market: 'unchanged' } });
  assert.equal(await auditCount(), logged);

  assert.deepEqual(await root.access.set(READER, { market: 'developer' }), { changes: { market: 'updated' } });
  assert.ok((await reader.me()).environments[0].permissions.includes('secret.write'));
  assert.deepEqual(await root.access.set(READER, { market: null }), { changes: { market: 'revoked' } });
  assert.deepEqual((await reader.me()).environments, []);
  assert.equal(
    (await root.members.list('market')).members.some((entry) => entry.member === READER),
    false,
  );
  // Granted, granted again with another role, revoked: by the vault, and once each.
  assert.deepEqual((await auditActions()).filter(({ action }) => action.startsWith('access.')).slice(-3), [
    { action: 'access.grant', decision: 'allow' },
    { action: 'access.grant', decision: 'allow' },
    { action: 'access.revoke', decision: 'allow' },
  ]);
});

test('an access change that fails anywhere changes nothing', async () => {
  await seedProject();
  await assert.rejects(
    root.access.set(READER, { market: 'viewer', 'market/prod': 'owner' }),
    { status: 409 },
  );
  assert.deepEqual((await reader.me()).environments, []);
  assert.deepEqual((await deps.vault.access('user:reader@acme.example')).grants, []);
});

test('removing a member revokes every grant and is audited', async () => {
  await seedProject();
  await root.environments.create('market/dev', { name: 'Development' });
  await root.access.set(READER, { market: 'viewer', 'market/dev': 'developer' });
  assert.equal((await root.members.remove(READER)).revoked.grants, 2);
  assert.deepEqual((await reader.me()).environments, []);
  const actions = (await auditActions()).map(({ action }) => action);
  assert.deepEqual(actions.slice(-3), ['access.revoke', 'access.revoke', 'member.remove']);
});

test('instance owners manage every project without receiving secret access', async () => {
  await seedProject();
  await root.members.add(OWNER, { owner: true });
  await owner.members.add('token:reporting');
  await owner.environments.create('market/staging', { name: 'Staging' });
  await owner.projects.update('market', { name: 'Market platform' });
  const me = await owner.me();
  assert.equal(me.instanceRole, 'owner');
  assert.deepEqual(me.environments, []);
  const project = (await owner.projects.list()).projects[0];
  assert.equal(project.name, 'Market platform');
  assert.deepEqual(project.permissions.sort(), [
    'environment.manage',
    'grant.manage',
    'project.manage',
  ]);
  assert.ok(
    project.environments.every(
      (environment) =>
        !environment.accessible
        && environment.details !== null
        && environment.details.secretCount === null,
    ),
  );
  assert.ok((await owner.members.list()).members.some((entry) => entry.member === 'token:reporting'));
});

test('environment grants expose only the listed names of inaccessible siblings', async () => {
  await seedProject();
  await root.environments.create('market/dev', { name: 'Development' });
  await root.secrets.set('market/prod', { PROD_ONLY: 'one' });
  await root.secrets.set('market/dev', { DEV_ONLY: 'two' });
  await root.access.set(READER, { 'market/dev': 'viewer' });

  const project = (await reader.projects.list()).projects[0];
  const dev = project.environments.find((environment) => environment.slug === 'dev');
  const prod = project.environments.find((environment) => environment.slug === 'prod');
  assert.deepEqual(dev, {
    slug: 'dev',
    name: 'Development',
    accessible: true,
    details: { archivedAt: null, secretCount: 1 },
  });
  assert.deepEqual(prod, {
    slug: 'prod',
    name: 'Production',
    accessible: false,
    details: null,
  });
});

test('an instance tells owners and root admins its version and migrations, and nobody else', async () => {
  const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };
  const journal = JSON.parse(
    readFileSync(new URL(`../../db/src/migrations/${process.env.COFFRE_TEST_ENGINE ?? 'postgres'}/meta/_journal.json`, import.meta.url), 'utf8'),
  ) as { entries: { tag: string }[] };
  const instance = (await root.me()).instance;
  assert.deepEqual(instance, {
    version: manifest.version,
    migrations: { applied: journal.entries.length, known: journal.entries.map((entry) => entry.tag) },
  });

  await root.members.add(OWNER, { owner: true });
  assert.deepEqual((await owner.me()).instance, instance);
  assert.equal((await reader.me()).instance, null);
  assert.equal((await lead.me()).instance, null);
});

test('a project counts each secret name once, across the environments the caller can open', async () => {
  await seedProject();
  await root.environments.create('market/dev', { name: 'Development' });
  await root.secrets.set('market/prod', { SHARED: 'one', PROD_ONLY: 'two' });
  await root.secrets.set('market/dev', { SHARED: 'three', DEV_ONLY: 'four' });

  await root.access.set(READER, { 'market/dev': 'viewer' });
  assert.equal((await reader.projects.list()).projects[0].secretCount, 2);
  await root.access.set(READER, { market: 'viewer' });
  assert.equal((await reader.projects.list()).projects[0].secretCount, 3);

  // Managing a project opens none of its secrets, so there is nothing to count.
  await root.members.add(OWNER, { owner: true });
  assert.equal((await owner.projects.list()).projects[0].secretCount, null);
});

test('removed members must be explicitly re-added before regranting access', async () => {
  await seedProject();
  await root.access.set(READER, { market: 'viewer' });
  await root.members.remove(READER);
  await assert.rejects(root.access.set(READER, { market: 'viewer' }), { status: 409 });
  await root.members.add(READER);
  await root.access.set(READER, { market: 'viewer' });
  assert.equal((await reader.me()).environments.length, 1);
});

test('two owners adding the same member at once both succeed, and one of them creates it', async () => {
  await root.members.add(OWNER, { owner: true });
  const added = await Promise.all([
    root.members.add('user:new@acme.example'),
    owner.members.add('user:new@acme.example'),
  ]);
  assert.deepEqual(added.map((result) => result.created).sort(), [false, true]);
  const creates = await db.owner
    .select({ subject: auditLog.subjectPrincipal })
    .from(auditLog)
    .where(and(eq(auditLog.action, 'member.add'), eq(auditLog.decision, 'allow')))
    .orderBy(asc(auditLog.seq));
  // The root admin's own row, made on first use; LEAD, READER, CI, OWNER; then the new member once.
  assert.deepEqual(creates.map(({ subject }) => subject), [
    'user:admin@acme.example', LEAD, READER, CI, OWNER, 'user:new@acme.example',
  ]);
});

test('an email is one member however it is capitalised, accents included', async () => {
  // SQLite's lower() folds ASCII only, so its lowercase check cannot catch an
  // É; the server folds every email before it reaches the database.
  assert.equal((await root.members.add('user:Émile@Acme.example')).created, true);
  assert.equal((await root.members.add('user:ÉMILE@acme.EXAMPLE')).created, false);
  const stored = await db.owner.select({ principal: vaultMembers.principal }).from(vaultMembers);
  assert.deepEqual(stored.map((row) => row.principal).filter((principal) => principal.startsWith('user:é')), ['user:émile@acme.example']);
});

test('ordinary users cannot manage the instance directory', async () => {
  await seedProject();
  await assert.rejects(reader.members.list(), { status: 403 });
  await assert.rejects(lead.members.add('user:new@acme.example'), { status: 403 });
  await assert.rejects(lead.members.get(READER), { status: 403 });
  await assert.rejects(lead.members.remove(READER), { status: 403 });
  // A project owner sees only the members of their own projects.
  assert.deepEqual(
    (await lead.members.list()).members.map((entry) => entry.member),
    [LEAD],
  );
});

test('service accounts cannot be owners and configured roots cannot be edited', async () => {
  await assert.rejects(root.members.add('token:service', { owner: true }), { status: 409 });
  await assert.rejects(root.members.add(`user:${ROOT}`, { owner: false }), { status: 409 });
  await assert.rejects(root.members.remove(`user:${ROOT}`), { status: 409 });
});

test('service principals receive grants by token name', async () => {
  await seedProject();
  await root.access.set(CI, { market: 'viewer' });
  assert.equal((await clientFor(deps, 'ci-deploy', 'service').me()).environments.length, 1);
});

test('project owners cannot change access in another project', async () => {
  await seedProject();
  await root.projects.create('other', { name: 'Other' });
  await root.access.set(READER, { other: 'viewer' });
  await assert.rejects(lead.access.set(READER, { other: null }), { status: 403 });
  assert.ok((await root.members.list('other')).members.some((entry) => entry.member === READER));
});

test('the audit chain verifies after structural changes', async () => {
  await seedProject();
  await root.access.set(READER, { market: 'viewer' });
  await root.access.set(READER, { market: 'developer' });
  await root.environments.update('market/prod', { slug: 'live' });
  await root.environments.update('market/live', { archived: true });
  await root.access.set(READER, { market: null });
  assert.equal((await root.audit.verify()).ok, true);
});
