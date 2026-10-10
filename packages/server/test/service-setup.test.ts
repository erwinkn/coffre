import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import type { CoffreClient } from '@coffre/client';
import { defineSignin, github, type BindingClaims } from '@coffre/core/identity';
import { and, asc, eq, inArray } from 'drizzle-orm';

import { SigninService } from '../src/api/signin.ts';
import { WorkloadService } from '../src/api/workloads.ts';
import { processLimits } from '../src/workloads/limits.ts';
import type { WorkloadTransport } from '../src/workloads/transport.ts';
import { auditLog } from './db/tables.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';

// People who set up service accounts without running the instance (D97,
// D99): docs/design/instance-roles.md, "Setting up service accounts".

const ROOT = 'admin@acme.example';
const ADA = 'user:ada@acme.example';
const BO = 'user:bo@acme.example';
const NEMO = 'user:nemo@acme.example';
const BOSS = 'user:boss@acme.example';
const CI = 'token:ci-dev';
const GITHUB = 'https://token.actions.githubusercontent.com';

/** `ci.yml`, run for pushes and pull requests to `main` of `acme/api`. */
const CHECKS: BindingClaims = {
  repository_owner_id: '9919',
  repository_id: '41532',
  workflow_ref: 'acme/api/.github/workflows/ci.yml@refs/heads/main',
  ref: 'refs/heads/main',
  event_name: ['push', 'pull_request'],
};

const SIGNIN = defineSignin({
  publicUrl: 'https://secrets.acme.example',
  providers: [github({ clientId: 'a', clientSecret: 'b' })],
  workloads: { limits: processLimits() },
});
const transport: WorkloadTransport = {
  json: async (url) => {
    if (url.href !== `${GITHUB}/.well-known/openid-configuration`) throw new Error(`asked ${url.href}`);
    return { issuer: GITHUB, jwks_uri: `${GITHUB}/.well-known/jwks` };
  },
};

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let root: CoffreClient;
/** A Developer of every project's dev, and nothing else. */
let ada: CoffreClient;
/** A Developer everywhere. */
let bo: CoffreClient;
/** A member, who holds nothing. */
let nemo: CoffreClient;
/** An Admin of market only. */
let boss: CoffreClient;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  const signin = new SigninService({ db: deps.db, chainKey: deps.chainKey, vault: deps.vault, signin: SIGNIN });
  deps.signin = signin;
  deps.workloads = new WorkloadService({
    db: deps.db, chainKey: deps.chainKey, vault: deps.vault, config: SIGNIN.workloads!, transport, signin, publicUrl: SIGNIN.publicUrl,
  });
  root = clientFor(deps, ROOT);
  ada = clientFor(deps, 'ada@acme.example');
  bo = clientFor(deps, 'bo@acme.example');
  nemo = clientFor(deps, 'nemo@acme.example');
  boss = clientFor(deps, 'boss@acme.example');
  for (const project of ['market', 'billing']) {
    await root.projects.create(project, { name: project });
    for (const environment of ['dev', 'prod']) await root.environments.create(`${project}/${environment}`, { name: environment });
  }
  await root.members.add(ADA, { role: 'developer', scope: { environments: { only: ['dev'] } } });
  await root.members.add(BO, { role: 'developer' });
  await root.members.add(NEMO);
  await root.members.add(BOSS, { role: 'admin', scope: { projects: { only: ['market'] } } });
});

/** Each of these actions' entries, oldest first: who, what, allowed or not, and why not. */
async function logged(...actions: string[]) {
  const rows = await db.owner
    .select({ actor: auditLog.actor, action: auditLog.action, decision: auditLog.decision, code: auditLog.code, metadata: auditLog.metadata })
    .from(auditLog)
    .where(inArray(auditLog.action, actions))
    .orderBy(asc(auditLog.seq));
  return rows.map((row) => [row.actor, row.action, row.decision, row.code ?? JSON.parse(row.metadata).reason ?? null]);
}

test('a Developer of dev sets up CI for dev: the account, its grant, a token and a trust binding, each in the log', async () => {
  assert.equal((await ada.me()).setsUpServices, true);
  assert.deepEqual(await ada.members.add(CI), { member: CI, instanceRole: 'member', scope: { projects: 'all', environments: 'all' }, created: true });
  assert.deepEqual(await ada.access.set(CI, { 'market/dev': 'developer', 'billing/dev': 'viewer' }), {
    changes: { 'market/dev': 'created', 'billing/dev': 'created' },
  });
  const issued = await ada.tokens.issue(CI, { label: 'ci', expiresInDays: 30 });
  const { binding } = await ada.bindings.create(CI, { profile: 'github', claims: CHECKS });
  assert.deepEqual(binding.claims.event_name, ['push', 'pull_request'], 'one binding for its workflow, on several events');
  assert.deepEqual((await ada.tokens.list(CI)).tokens.map((token) => token.id), [issued.id]);
  assert.deepEqual((await ada.bindings.list(CI)).bindings.map((found) => found.id), [binding.id]);
  await ada.tokens.revoke(CI, issued.id);
  await ada.bindings.remove(CI, binding.id);
  await ada.access.set(CI, { 'billing/dev': null });

  const steps = await logged('member.add', 'access.grant', 'access.revoke', 'token.create', 'token.revoke', 'token.bind', 'token.unbind');
  assert.deepEqual(steps.filter(([actor]) => actor === ADA), [
    [ADA, 'member.add', 'allow', null],
    [ADA, 'access.grant', 'allow', null],
    [ADA, 'access.grant', 'allow', null],
    [ADA, 'token.create', 'allow', null],
    [ADA, 'token.bind', 'allow', null],
    [ADA, 'token.revoke', 'allow', null],
    [ADA, 'token.unbind', 'allow', 'removed'],
    [ADA, 'access.revoke', 'allow', null],
  ], 'who did each step');

  // Removing it is theirs too; its report, which names what it read anywhere, is not.
  const removed = await ada.members.remove(CI);
  assert.equal(removed.report, null);
  assert.equal(removed.revoked.grants, 1);
});

test('nobody gives a service account more than they hold: not prod, not a project, not a role above their own', async () => {
  await ada.members.add(CI);
  // Not where they hold nothing, and not a project around the environment they hold.
  await assert.rejects(ada.access.set(CI, { 'market/prod': 'viewer' }), { status: 403 });
  await assert.rejects(ada.access.set(CI, { market: 'viewer' }), { status: 403 });
  // A Developer everywhere gives viewer or developer, never owner, maintainer or access-manager.
  await bo.members.add('token:ci-bo');
  for (const role of ['owner', 'maintainer', 'access-manager', 'auditor'] as const) {
    await assert.rejects(bo.access.set('token:ci-bo', { market: role }), { status: 403 }, role);
  }
  assert.deepEqual(await bo.access.set('token:ci-bo', { market: 'developer' }), { changes: { market: 'created' } });
  // All or nothing: one place out of reach refuses the call.
  await assert.rejects(ada.access.set(CI, { 'market/dev': 'developer', 'market/prod': 'developer' }), { status: 403 });
  assert.deepEqual((await root.members.access(CI)).grants, []);
  // Never a person, nor anyone's instance role.
  await assert.rejects(ada.members.add('user:eve@acme.example'), { status: 403 });
  await assert.rejects(ada.access.set(NEMO, { 'market/dev': 'viewer' }), { status: 403 });
  await assert.rejects(ada.members.add(CI, { role: 'developer' }), { status: 403 });
  // A member who holds nothing sets up nothing.
  assert.equal((await nemo.me()).setsUpServices, false);
  await assert.rejects(nemo.members.add('token:ci-nemo'), { status: 403 });
  assert.ok((await logged('access.grant')).some(([actor, , decision, reason]) => actor === ADA && decision === 'deny' && reason === 'not_service_manager'));
});

test('an account that holds prod is out of a dev Developer\'s hands: no token, no binding, no grant, no removal', async () => {
  await ada.members.add(CI);
  await ada.access.set(CI, { 'market/dev': 'developer' });
  const before = await ada.tokens.issue(CI, { label: 'before', expiresInDays: 30 });
  await root.access.set(CI, { 'market/prod': 'viewer' });

  await assert.rejects(ada.tokens.issue(CI, { label: 'after', expiresInDays: 30 }), { status: 403 });
  await assert.rejects(ada.bindings.create(CI, { profile: 'github', claims: CHECKS }), { status: 403 });
  await assert.rejects(ada.bindings.preview(CI, { profile: 'github', claims: CHECKS }), { status: 403 });
  await assert.rejects(ada.tokens.list(CI), { status: 403 });
  await assert.rejects(ada.tokens.revoke(CI, before.id), { status: 403 });
  await assert.rejects(ada.access.set(CI, { 'market/dev': 'viewer' }), { status: 403 });
  await assert.rejects(ada.access.set(CI, { 'market/dev': null }), { status: 403 });
  await assert.rejects(ada.members.remove(CI), { status: 403 });
  // It leaves their list, and its grants with it.
  assert.deepEqual((await ada.members.list()).members.map((member) => member.member), []);
  assert.equal((await ada.members.access(CI).catch((error: { status: number }) => error.status)), 403);
  // A Developer everywhere holds what it holds, and manages it.
  assert.equal((await bo.tokens.issue(CI, { label: 'bo', expiresInDays: 1 })).expiresAt.length > 0, true);

  assert.deepEqual((await logged('token.create')).filter(([actor]) => actor === ADA).map(([, , decision, reason]) => [decision, reason]), [
    ['allow', null],
    ['deny', 'not_service_manager'],
  ]);
});

test('an account with no grant is its maker\'s, or theirs who run the instance', async () => {
  await root.members.add(CI);
  await assert.rejects(ada.tokens.issue(CI, { label: 'x', expiresInDays: 1 }), { status: 403 });
  await assert.rejects(ada.access.set(CI, { 'market/dev': 'viewer' }), { status: 403 });
  await ada.members.add('token:ci-ada');
  await assert.rejects(bo.tokens.issue('token:ci-ada', { label: 'x', expiresInDays: 1 }), { status: 403 });
  assert.equal((await ada.tokens.issue('token:ci-ada', { label: 'x', expiresInDays: 1 })).token.length > 0, true);
  assert.deepEqual((await ada.members.list()).members.map((member) => [member.member, member.managed]), [['token:ci-ada', true]]);
});

test('the setting keeps prod to Admins: a prod Developer sets up dev only, an Admin of market sets up market/prod', async () => {
  await assert.rejects(ada.settings.set({ serviceAccounts: { environments: { except: ['prod'] } } }), { status: 403 });
  await assert.rejects(boss.settings.set({ serviceAccounts: { environments: { except: ['prod'] } } }), { status: 403 }, 'a scoped Admin runs no instance');
  assert.deepEqual(await root.settings.set({ serviceAccounts: { environments: { except: ['prod'] } } }), {
    serviceAccounts: { projects: 'all', environments: { except: ['prod'] } },
  });
  assert.deepEqual(await root.settings.get(), { serviceAccounts: { projects: 'all', environments: { except: ['prod'] } } });
  await assert.rejects(ada.settings.get(), { status: 403 });

  await bo.members.add(CI);
  await assert.rejects(bo.access.set(CI, { 'market/prod': 'viewer' }), { status: 403 });
  await assert.rejects(bo.access.set(CI, { market: 'viewer' }), { status: 403 }, 'a project takes in its prod');
  await bo.access.set(CI, { 'market/dev': 'developer' });
  // An Admin of market manages access there, as before, the setting aside.
  await boss.access.set(CI, { 'market/prod': 'viewer' });
  assert.equal((await boss.tokens.issue(CI, { label: 'deploy', expiresInDays: 7 })).token.length > 0, true);
  await assert.rejects(bo.tokens.issue(CI, { label: 'x', expiresInDays: 1 }), { status: 403 });
  assert.deepEqual((await ada.me()).serviceSetup, { projects: 'all', environments: { except: ['prod'] } });

  // Nowhere: only an Admin, within its scope, and who runs the instance.
  await root.settings.set({ serviceAccounts: { projects: { only: [] } } });
  assert.equal((await ada.me()).setsUpServices, false);
  await assert.rejects(ada.members.add('token:ci-2'), { status: 403 });
  assert.equal((await boss.me()).setsUpServices, true);

  const changes = await db.owner
    .select({ actor: auditLog.actor, decision: auditLog.decision, author: auditLog.author, metadata: auditLog.metadata })
    .from(auditLog)
    .where(and(eq(auditLog.action, 'settings.change'), eq(auditLog.author, 'vault')))
    .orderBy(asc(auditLog.seq));
  assert.deepEqual(changes.map((row) => [row.actor, row.decision]), [[`user:${ROOT}`, 'allow'], [`user:${ROOT}`, 'allow']]);
  assert.deepEqual(JSON.parse(changes[0].metadata).previous, { serviceAccounts: { projects: 'all', environments: 'all' } });
  assert.deepEqual(await logged('settings.change').then((entries) => entries.filter(([, , decision]) => decision === 'deny').map(([actor]) => actor)), [ADA, BOSS]);
  assert.equal((await root.audit.verify()).ok, true);
});

test("a person's list shows the accounts they manage, all they hold, and nobody else's", async () => {
  await ada.members.add(CI);
  await ada.access.set(CI, { 'market/dev': 'developer' });
  await bo.members.add('token:ci-prod');
  await bo.access.set('token:ci-prod', { 'market/prod': 'viewer' });
  await root.members.add('token:other');
  await root.access.set('token:other', { 'billing/dev': 'viewer', 'billing/prod': 'viewer' });

  const listed = (await ada.members.list()).members;
  assert.deepEqual(listed.map((member) => [member.member, member.managed, member.grants.map((grant) => grant.id)]), [
    [CI, true, [`${CI}/market/dev`]],
  ]);
  const everyone = (await bo.members.list()).members;
  assert.deepEqual(everyone.map((member) => member.member), [CI, 'token:ci-prod', 'token:other']);
  const other = await bo.members.access('token:other');
  assert.deepEqual([other.managed, other.grants.length], [true, 2]);
  await assert.rejects(ada.members.access('token:other'), { status: 403 });
  // People are never in a manager's list.
  assert.ok(everyone.every((member) => member.principalType === 'service'));
});

test('a person who loses access keeps no hold on the accounts they made', async () => {
  await ada.members.add(CI);
  await ada.access.set(CI, { 'market/dev': 'developer' });
  await root.members.add(ADA, { role: 'member' });
  await assert.rejects(ada.tokens.issue(CI, { label: 'x', expiresInDays: 1 }), { status: 403 });
  await assert.rejects(ada.members.remove(CI), { status: 403 });
  // The account stays, as it was, with whoever reaches it.
  assert.deepEqual((await bo.members.access(CI)).grants.map((grant) => grant.role), ['developer']);
});
