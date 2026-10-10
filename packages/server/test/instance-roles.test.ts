import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import type { CoffreClient } from '@coffre/client';
import { and, asc, eq } from 'drizzle-orm';

import { memberAccess } from '../src/db/queries.ts';
import { auditLog } from './db/tables.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';

// A person's instance role and its scope, which project grants add to:
// docs/design/instance-roles.md.

const ROOT = 'admin@acme.example';
const ADA = 'user:ada@acme.example';
const LEAD = 'user:lead@acme.example';
const BOSS = 'user:boss@acme.example';
const CI = 'token:ci-deploy';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let root: CoffreClient;
let ada: CoffreClient;
let lead: CoffreClient;
let boss: CoffreClient;

before(async () => {
  db = await openTestDatabase();
  deps = testDeps(db.runtime, [ROOT]);
  root = clientFor(deps, ROOT);
  ada = clientFor(deps, 'ada@acme.example');
  lead = clientFor(deps, 'lead@acme.example');
  boss = clientFor(deps, 'boss@acme.example');
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  for (const member of [ADA, LEAD, CI]) await root.members.add(member);
  await root.members.add(BOSS, { role: 'admin' });
  for (const project of ['market', 'billing']) {
    await root.projects.create(project, { name: project });
    for (const environment of ['dev', 'prod']) {
      await root.environments.create(`${project}/${environment}`, { name: environment });
      await root.secrets.set(`${project}/${environment}`, { API_URL: `https://${environment}.${project}` });
    }
  }
});

/** The app's refusals, oldest first, by action and reason. */
async function refusals() {
  const rows = await db.owner
    .select({ action: auditLog.action, metadata: auditLog.metadata })
    .from(auditLog)
    .where(and(eq(auditLog.decision, 'deny'), eq(auditLog.author, 'app')))
    .orderBy(asc(auditLog.seq));
  return rows.map((row) => [row.action, JSON.parse(row.metadata).reason]);
}

test('a Developer reads and writes every project, the ones made later too; scoped to dev, only each dev', async () => {
  assert.deepEqual(await root.members.add(ADA, { role: 'developer', scope: { environments: { only: ['dev'] } } }), {
    member: ADA, instanceRole: 'developer', scope: { projects: 'all', environments: { only: ['dev'] } }, created: false,
  });
  await root.projects.create('later', { name: 'Later' });
  for (const environment of ['dev', 'staging']) await root.environments.create(`later/${environment}`, { name: environment });
  await root.secrets.set('later/dev', { KEY: 'one' });

  assert.deepEqual((await ada.secrets.reveal('later/dev')).values, { KEY: 'one' });
  await ada.secrets.set('market/dev', { API_URL: 'https://dev2.market' });
  await assert.rejects(ada.secrets.reveal('market/prod'), { status: 403 });
  await assert.rejects(ada.secrets.set('billing/prod', { API_URL: 'x' }), { status: 403 });
  // Never a project around its environments: making one there is environment.manage on the project.
  await assert.rejects(ada.environments.create('market/qa', { name: 'QA' }), { status: 403 });
  assert.deepEqual((await ada.projects.list()).projects.map((project) => project.slug), ['billing', 'later', 'market']);
  assert.deepEqual((await ada.me()).environments.map(({ project, environment }) => `${project}/${environment}`), ['billing/dev', 'later/dev', 'market/dev']);
  // A grant adds to it, past its scope.
  await root.access.set(ADA, { 'billing/prod': 'viewer' });
  assert.deepEqual((await ada.secrets.reveal('billing/prod')).values, { API_URL: 'https://prod.billing' });

  // Environments match by slug: renamed to dev, staging comes in.
  await root.environments.update('later/staging', { slug: 'qa' });
  await root.environments.update('later/dev', { slug: 'development' });
  await assert.rejects(ada.secrets.reveal('later/development'), { status: 403 });
  await root.environments.update('later/qa', { slug: 'dev' });
  assert.deepEqual((await ada.secrets.reveal('later/dev')).values, {});
});

test('a scope by project keeps out the projects it leaves out, by id, whatever they are called', async () => {
  await root.members.add(ADA, { role: 'developer', scope: { projects: { except: ['billing'] } } });
  await assert.rejects(ada.secrets.reveal('billing/dev'), { status: 403 });
  assert.deepEqual((await ada.projects.list()).projects.map((project) => project.slug), ['market']);
  // Renamed, billing is still the project left out, and the scope names it by its new slug.
  await root.projects.update('billing', { slug: 'payments' });
  await assert.rejects(ada.secrets.reveal('payments/dev'), { status: 403 });
  const listed = (await root.members.list()).members.find((member) => member.member === ADA);
  assert.deepEqual([listed?.instanceRole, listed?.scope], ['developer', { projects: { except: ['payments'] }, environments: 'all' }]);
  // A project made later is in it.
  await root.projects.create('later', { name: 'Later' });
  await root.environments.create('later/dev', { name: 'dev' });
  assert.deepEqual((await ada.secrets.reveal('later/dev')).values, {});
  await assert.rejects(root.members.add(ADA, { role: 'developer', scope: { projects: { only: ['nowhere'] } } }), { status: 404 });
});

test('an Admin manages every project but reads no value; an Owner reads them too', async () => {
  await boss.access.set(ADA, { 'market/dev': 'viewer' });
  await boss.environments.create('market/qa', { name: 'QA' });
  await boss.projects.create('later', { name: 'Later' });
  await assert.rejects(boss.secrets.reveal('market/dev'), { status: 403 });
  assert.equal((await boss.me()).runsInstance, true);

  await root.members.add(BOSS, { role: 'owner' });
  assert.deepEqual((await boss.secrets.reveal('market/dev')).values, { API_URL: 'https://dev.market' });
});

test('nobody changes their own instance role, and a scoped admin sets nobody\'s and grants only inside its scope', async () => {
  // An admin of the whole instance sets someone else's role, and never its own.
  await boss.members.add(LEAD, { role: 'admin', scope: { projects: { only: ['market'] }, environments: { only: ['dev'] } } });
  await assert.rejects(boss.members.add(BOSS, { role: 'owner' }), { status: 409 });
  // Saying what it is already changes nothing, and is no refusal.
  assert.equal((await boss.members.add(BOSS, { role: 'admin' })).instanceRole, 'admin');

  // Lead, an admin scoped to market/dev, sets no role, its own or anyone's, adds nobody, and removes nobody.
  await assert.rejects(lead.members.add(LEAD, { role: 'admin' }), { status: 403 }, 'widening itself');
  await assert.rejects(lead.members.add(ADA, { role: 'owner' }), { status: 403 }, 'promoting someone');
  await assert.rejects(lead.members.add('user:new@acme.example'), { status: 403 }, 'adding someone');
  await assert.rejects(lead.members.remove(ADA), { status: 403 });
  // It grants inside its scope, and nowhere else.
  assert.deepEqual(await lead.access.set(ADA, { 'market/dev': 'developer' }), { changes: { 'market/dev': 'created' } });
  await assert.rejects(lead.access.set(ADA, { 'market/prod': 'viewer' }), { status: 403 }, 'an environment it leaves out');
  await assert.rejects(lead.access.set(ADA, { market: 'viewer' }), { status: 403 }, 'the project, which reaches prod');
  await assert.rejects(lead.access.set(ADA, { 'billing/dev': 'viewer' }), { status: 403 }, 'another project');
  await assert.rejects(lead.access.set(LEAD, { market: 'owner' }), { status: 403 }, 'giving itself more');
  await assert.rejects(lead.access.set(LEAD, { 'market/dev': 'viewer' }), { status: 409 }, 'giving itself a reading role in its scope');
  await assert.rejects(boss.access.set(BOSS, { market: 'viewer' }), { status: 409 }, 'an admin giving itself a reading role');
  await assert.rejects(lead.access.set(CI, { 'market/dev': 'viewer', 'billing/dev': 'viewer' }), { status: 403 }, 'all of it or none');
  // It makes no project: its scope lists only market.
  await assert.rejects(lead.projects.create('later', { name: 'Later' }), { status: 403 });
  assert.equal((await lead.me()).runsInstance, false);
  assert.deepEqual(await refusals(), [
    ['member.add', 'own_role'],
    ['member.add', 'requires_instance_admin'],
    ['member.add', 'requires_instance_admin'],
    ['member.add', 'requires_instance_admin'],
    ['member.remove', 'requires_instance_admin'],
    ['access.grant', 'missing_grant_manage'],
    ['access.grant', 'missing_grant_manage'],
    ['access.grant', 'missing_grant_manage'],
    ['access.grant', 'missing_grant_manage'],
    ['access.grant', 'own_grant'],
    ['access.grant', 'own_grant'],
    ['access.grant', 'missing_grant_manage'],
    ['project.create', 'requires_instance_admin'],
  ]);

  // It sees everyone, with the grants it manages, and none it does not.
  await root.access.set(ADA, { 'billing/prod': 'viewer' });
  const listed = (await lead.members.list()).members.find((member) => member.member === ADA);
  assert.deepEqual(listed?.grants.map((grant) => grant.id), [`${ADA}/market/dev`]);
  assert.equal((await lead.members.list()).removed.length, 0);
  await assert.rejects(lead.members.get(ADA), { status: 403 });

  // Scoped to all but billing, a project made now is in its scope: it makes one.
  await root.members.add(LEAD, { role: 'admin', scope: { projects: { except: ['billing'] } } });
  assert.equal((await lead.projects.create('later', { name: 'Later' })).created, true);
  await lead.access.set(ADA, { later: 'viewer' });
});

test('a service account holds project grants only, and no grant is on every project any more', async () => {
  await assert.rejects(root.members.add(CI, { role: 'developer' }), { status: 409 });
  await assert.rejects(root.access.set(CI, { '*': 'viewer' }), { status: 400 });
  await assert.rejects(root.access.set(ADA, { '*/dev': 'viewer' }), { status: 400 });
  assert.deepEqual(await root.access.set(CI, { 'market/dev': 'developer' }), { changes: { 'market/dev': 'created' } });
  assert.deepEqual(await refusals(), [['member.add', 'service_cannot_hold_role']]);
});

test("a project's access list shows who reaches it by their instance role, with no grant", async () => {
  await root.members.add(ADA, { role: 'developer', scope: { environments: { only: ['dev'] } } });
  await root.members.add(LEAD, { role: 'auditor', scope: { projects: { only: ['billing'] } } });
  await root.access.set(CI, { 'market/prod': 'viewer' });
  const reach = async (path: string) => (await root.members.list(path)).members.map((member) => [member.member, member.instanceRole, member.grants.length, member.reachesByRole]);
  // Services first, then people, as every list is.
  assert.deepEqual(await reach('market'), [[CI, 'member', 1, false], [ADA, 'developer', 0, true], [BOSS, 'admin', 0, true]]);
  assert.deepEqual(await reach('market/prod'), [[CI, 'member', 1, false], [BOSS, 'admin', 0, true]]);
  assert.deepEqual(await reach('billing/dev'), [[ADA, 'developer', 0, true], [BOSS, 'admin', 0, true], [LEAD, 'auditor', 0, true]]);
});

test('an auditor reads the log of the places in its scope, and never the instance\'s', async () => {
  await root.members.add(ADA, { role: 'auditor', scope: { projects: { only: ['market'] }, environments: { only: ['dev'] } } });
  const { entries } = await ada.audit.list({ detail: '1' });
  assert.ok(entries.length > 0);
  assert.ok(entries.every((entry) => entry.project === 'market' && entry.environment === 'dev'), JSON.stringify(entries.map((entry) => [entry.project, entry.environment])));
  // Unscoped, every project's, still not the instance's own: sign-ins, people.
  await root.members.add(ADA, { role: 'auditor' });
  const everywhere = (await ada.audit.list({ detail: '1' })).entries;
  assert.ok(everywhere.some((entry) => entry.project === 'billing'));
  assert.ok(everywhere.every((entry) => entry.project !== null));
  await assert.rejects(ada.audit.verify(), { status: 403 });
  assert.ok((await boss.audit.list({})).entries.some((entry) => entry.project === null), 'an admin of the whole instance reads it all');
});

test('offboarding takes the role with the grants, and coming back starts as a member', async () => {
  await root.members.add(ADA, { role: 'developer' });
  await root.access.set(ADA, { 'market/prod': 'viewer' });
  assert.equal((await root.members.remove(ADA)).revoked.grants, 1);
  await assert.rejects(ada.secrets.reveal('market/dev'), { status: 403 });
  assert.equal((await root.members.add(ADA)).instanceRole, 'member');
  await assert.rejects(ada.secrets.reveal('market/dev'), { status: 403 });
  assert.equal((await root.audit.verify()).ok, true);
});

test("a member's page reads their whole access in one request, which the server answers in one query", async () => {
  await root.members.add(ADA, { role: 'developer', scope: { projects: { except: ['billing'] }, environments: { only: ['dev'] } } });
  for (let i = 0; i < 12; i++) {
    await root.projects.create(`p${i}`, { name: `P${i}` });
    await root.environments.create(`p${i}/dev`, { name: 'dev' });
    await root.access.set(ADA, { [`p${i}`]: 'viewer', [`p${i}/dev`]: { role: 'developer', until: '2099-01-01' } });
  }
  await root.access.set(ADA, { 'billing/prod': 'viewer' });

  // However many grants: one statement, the member row, their grants and the projects their scope names.
  let statements = 0;
  const counted = new Proxy(db.owner, {
    get(target, key, receiver) {
      const value = Reflect.get(target, key, receiver);
      if (typeof value !== 'function') return value;
      return (...args: unknown[]) => {
        if (['execute', 'all', 'select', 'selectDistinct', 'transaction'].includes(String(key))) statements += 1;
        return value.apply(target, args);
      };
    },
  });
  const stored = await memberAccess(counted, ADA, new Date());
  assert.equal(statements, 1);
  assert.equal(stored.grants.length, 25);

  const seen = await root.members.access(ADA);
  assert.deepEqual([seen.instanceRole, seen.scope, seen.status], ['developer', { projects: { except: ['billing'] }, environments: { only: ['dev'] } }, 'active']);
  assert.equal(seen.grants.length, 25);
  assert.deepEqual(seen.grants.slice(0, 2).map((grant) => grant.id), [`${ADA}/billing/prod`, `${ADA}/p0/dev`]);
  // Each caller sees the grants they manage: an admin scoped to billing, billing's alone.
  await root.members.add(BOSS, { role: 'admin', scope: { projects: { only: ['billing'] } } });
  assert.deepEqual((await boss.members.access(ADA)).grants.map((grant) => grant.id), [`${ADA}/billing/prod`]);
  // Nobody who manages no access asks; nobody who is no member is found.
  await assert.rejects(ada.members.access(ADA), { status: 403 });
  await assert.rejects(root.members.access('user:nobody@acme.example'), { status: 404 });
  // A root admin, with no row, is one; a removed member holds nothing.
  assert.equal((await root.members.access(`user:${ROOT}`)).instanceRole, 'root-admin');
  await root.members.remove(ADA);
  assert.deepEqual(await root.members.access(ADA).then(({ status, grants, instanceRole }) => [status, grants, instanceRole]), ['removed', [], 'member']);
});
