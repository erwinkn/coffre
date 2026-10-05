import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import type { CoffreClient } from '@coffre/client';
import { and, asc, eq } from 'drizzle-orm';

import { auditLog, vaultGrants } from './db/tables.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';

// Grants on every project (`*`), and on one environment slug in every
// project (`*` and the slug): docs/design/instance-grants.md.

const ROOT = 'admin@acme.example';
const ADA = 'user:ada@acme.example';
const LEAD = 'user:lead@acme.example';
const CI = 'token:ci-deploy';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let root: CoffreClient;
let ada: CoffreClient;
let lead: CoffreClient;
let ci: CoffreClient;

before(async () => {
  db = await openTestDatabase();
  deps = testDeps(db.runtime, [ROOT]);
  root = clientFor(deps, ROOT);
  ada = clientFor(deps, 'ada@acme.example');
  lead = clientFor(deps, 'lead@acme.example');
  ci = clientFor(deps, 'ci-deploy', 'service');
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  for (const member of [ADA, LEAD, CI]) await root.members.add(member);
  await root.projects.create('market', { name: 'Market' });
  for (const environment of ['dev', 'prod']) await root.environments.create(`market/${environment}`, { name: environment });
  await root.secrets.set('market/dev', { API_URL: 'https://dev.market' });
  await root.secrets.set('market/prod', { API_URL: 'https://market' });
  await root.access.set(LEAD, { market: 'owner' });
});

/** The app's and the vault's refusals, oldest first, with the place each names. */
async function refusals() {
  const rows = await db.owner
    .select({ author: auditLog.author, action: auditLog.action, projectId: auditLog.projectId, metadata: auditLog.metadata })
    .from(auditLog)
    .where(eq(auditLog.decision, 'deny'))
    .orderBy(asc(auditLog.seq));
  return rows.map((row) => ({ author: row.author, action: row.action, projectId: row.projectId, place: JSON.parse(row.metadata).place }));
}

test('a grant on every project reaches a project made after it', async () => {
  assert.deepEqual(await root.access.set(ADA, { '*': 'viewer' }), { changes: { '*': 'created' } });
  await root.projects.create('billing', { name: 'Billing' });
  await root.environments.create('billing/prod', { name: 'Production' });
  await root.secrets.set('billing/prod', { STRIPE_KEY: 'sk_live' });

  assert.deepEqual((await ada.secrets.reveal('billing/prod')).values, { STRIPE_KEY: 'sk_live' });
  await assert.rejects(ada.secrets.set('billing/prod', { STRIPE_KEY: 'mine' }), { status: 403 });
  assert.deepEqual((await ada.projects.list()).projects.map((project) => project.slug), ['billing', 'market']);
  assert.deepEqual(
    (await ada.me()).environments.map(({ project, environment }) => `${project}/${environment}`),
    ['billing/prod', 'market/dev', 'market/prod'],
  );
});

test('a grant on one slug in every project reaches environments of that slug, and never another', async () => {
  await root.access.set(CI, { '*/dev': 'developer' });
  await root.projects.create('billing', { name: 'Billing' });
  await root.environments.create('billing/staging', { name: 'Staging' });

  await ci.secrets.set('market/dev', { API_URL: 'https://dev2.market' });
  assert.deepEqual((await ci.secrets.reveal('market/dev')).values, { API_URL: 'https://dev2.market' });
  await assert.rejects(ci.secrets.reveal('market/prod'), { status: 403 });
  await assert.rejects(ci.secrets.set('market/prod', { API_URL: 'x' }), { status: 403 });
  // Not the project either: an environment's grant never reaches up.
  await assert.rejects(ci.environments.create('market/qa', { name: 'QA' }), { status: 403 });
  assert.deepEqual((await ci.projects.list()).projects.map((project) => project.slug), ['market'], 'billing has no dev');

  // Renamed to dev, staging comes in, and the answer says who that brings.
  const renamed = await root.environments.update('billing/staging', { slug: 'dev' });
  assert.deepEqual(renamed.inherited, [{ member: CI, place: '*/dev', role: 'developer', roleName: 'Developer', expiresAt: null }]);
  await ci.secrets.set('billing/dev', { STRIPE_KEY: 'sk_test' });
  await root.environments.update('market/dev', { slug: 'development' });
  await assert.rejects(ci.secrets.reveal('market/development'), { status: 403 });
});

test('only instance owners and root admins grant on every project', async () => {
  // Owner of a project, or of every project, manages project grants, and not these.
  await assert.rejects(lead.access.set(ADA, { '*': 'viewer' }), { status: 403 });
  await root.access.set(LEAD, { '*': 'owner' });
  await lead.access.set(ADA, { market: 'viewer' });
  await assert.rejects(lead.access.set(ADA, { '*/dev': 'viewer' }), { status: 403 });
  await assert.rejects(lead.access.set(ADA, { market: null, '*': 'viewer' }), { status: 403 }, 'all of it or none');
  assert.deepEqual(await refusals(), [
    { author: 'app', action: 'access.grant', projectId: null, place: '*' },
    { author: 'app', action: 'access.grant', projectId: null, place: '*/dev' },
    { author: 'app', action: 'access.grant', projectId: null, place: '*' },
  ]);

  await root.members.add('user:owner@acme.example', { owner: true });
  const owner = clientFor(deps, 'owner@acme.example');
  assert.deepEqual(await owner.access.set(ADA, { '*/dev': 'viewer' }), { changes: { '*/dev': 'created' } });
  assert.deepEqual(await owner.access.set(ADA, { '*/dev': null }), { changes: { '*/dev': 'revoked' } });
});

test('a slug takes only the roles an environment can hold, and must be a slug', async () => {
  await assert.rejects(root.access.set(ADA, { '*/dev': 'maintainer' }), { status: 409 });
  await assert.rejects(root.access.set(ADA, { '*/Dev': 'viewer' }), { status: 400 });
  await assert.rejects(root.access.set(ADA, { '*/dev/KEY': 'viewer' }), { status: 400 });
  assert.deepEqual(await root.access.set(ADA, { '*': { role: 'maintainer', until: '2099-01-01' } }), { changes: { '*': 'created' } });
});

test("a project's access list shows who reaches it through grants on every project, and the member page all of them", async () => {
  await root.access.set(ADA, { '*': 'auditor', '*/dev': 'developer', '*/qa': 'viewer' });
  const grantsOf = (members: { member: string; grants: { id: string; project: string; environment: string | null; role: string }[] }[], who: string) =>
    members.find((member) => member.member === who)?.grants.map(({ id, project, environment, role }) => ({ id, project, environment, role }));

  // On market, as its access manager sees it: qa is in no project of it.
  assert.deepEqual(grantsOf((await lead.members.list('market')).members, ADA), [
    { id: `${ADA}/*/dev`, project: '*', environment: 'dev', role: 'developer' },
    { id: `${ADA}/*`, project: '*', environment: null, role: 'auditor' },
  ]);
  assert.deepEqual(grantsOf((await lead.members.list('market/prod')).members, ADA), [
    { id: `${ADA}/*`, project: '*', environment: null, role: 'auditor' },
  ]);
  // Everything, as an owner lists the instance, and only these with `*`.
  assert.deepEqual(grantsOf((await root.members.list()).members, ADA)?.map((grant) => grant.id), [`${ADA}/*/dev`, `${ADA}/*/qa`, `${ADA}/*`]);
  assert.deepEqual(grantsOf((await root.members.list('*/qa')).members, ADA)?.map((grant) => grant.id), [`${ADA}/*/qa`]);
  assert.equal(grantsOf((await root.members.list('*')).members, LEAD), undefined);
});

test('making a project or an environment answers who reaches it already', async () => {
  await root.access.set(ADA, { '*': 'viewer' });
  await root.access.set(CI, { '*/dev': 'developer' });
  const viewer = { member: ADA, place: '*', role: 'viewer', roleName: 'Viewer', expiresAt: null };
  const developer = { member: CI, place: '*/dev', role: 'developer', roleName: 'Developer', expiresAt: null };

  assert.deepEqual((await root.projects.create('billing', { name: 'Billing' })).inherited, [viewer]);
  assert.deepEqual((await root.environments.create('billing/dev', { name: 'Dev' })).inherited, [developer, viewer]);
  assert.deepEqual((await lead.environments.create('market/qa', { name: 'QA' })).inherited, [viewer]);
  // Who makes places is shown them all beforehand; who cannot, nothing.
  assert.deepEqual((await lead.projects.list()).everyProject, [developer, viewer]);
  assert.deepEqual((await ada.projects.list()).everyProject, []);
});

test("grants on every project are shown to exactly those who see a project's grants, and none of a tampered member", async () => {
  const MAINT = 'user:maint@acme.example';
  await root.members.add(MAINT);
  await root.access.set(MAINT, { market: 'maintainer' });
  const maint = clientFor(deps, 'maint@acme.example');
  await root.access.set(ADA, { '*': 'viewer', '*/qa': 'developer' });
  const viewer = { member: ADA, place: '*', role: 'viewer', roleName: 'Viewer', expiresAt: null };
  const qa = { member: ADA, place: '*/qa', role: 'developer', roleName: 'Developer', expiresAt: null };

  // A maintainer makes environments, and does not see who holds what in the project: nor these.
  assert.equal((await maint.members.list('market').catch((error: { status: number }) => error.status)), 403);
  assert.deepEqual((await maint.environments.create('market/qa', { name: 'QA' })).inherited, []);
  assert.deepEqual((await maint.projects.list()).everyProject, []);
  // Market's access manager sees them where they reach market: qa does, now.
  assert.deepEqual((await lead.environments.update('market/qa', { name: 'Q.A.' })).inherited, [viewer, qa]);
  assert.deepEqual((await lead.projects.list()).everyProject, [viewer, qa]);
  await root.environments.update('market/qa', { slug: 'staging' });
  assert.deepEqual((await lead.projects.list()).everyProject, [viewer], 'one on qa reaches no project of theirs');
  assert.deepEqual((await root.projects.list()).everyProject, [viewer, qa], 'owners see them all');

  // A grant written around the vault: the vault refuses its member, and the previews leave it out.
  await db.owner.insert(vaultGrants).values({ principal: CI, role: 'viewer', grantedAt: Date.now(), grantedBy: `user:${ROOT}` });
  assert.equal((await deps.vault.access(CI)).status, 'tampered');
  assert.deepEqual((await root.projects.list()).everyProject, [viewer, qa]);
});

test('offboarding removes grants on every project, each with its entry', async () => {
  await root.access.set(ADA, { '*': 'viewer', '*/dev': 'developer', 'market/prod': 'viewer' });
  assert.equal((await root.members.get(ADA)).live.grants, 3);
  const removed = await root.members.remove(ADA);
  assert.equal(removed.revoked.grants, 3);
  await assert.rejects(ada.secrets.reveal('market/dev'), { status: 403 });
  const revokes = await db.owner
    .select({ metadata: auditLog.metadata, environmentId: auditLog.environmentId })
    .from(auditLog)
    .where(and(eq(auditLog.action, 'access.revoke'), eq(auditLog.author, 'vault')));
  assert.deepEqual(revokes.map((row) => JSON.parse(row.metadata).place ?? 'market/prod').sort(), ['*', '*/dev', 'market/prod']);
  assert.equal((await root.audit.verify()).ok, true);
});

test('an auditor on every project reads every project\'s log, not the instance\'s', async () => {
  await root.access.set(ADA, { '*': 'auditor' });
  const { entries } = await ada.audit.list({ detail: '1' });
  assert.ok(entries.some((entry) => entry.project === 'market'));
  assert.ok(entries.every((entry) => entry.project !== null), 'entries about no project are owners\' alone');
});
