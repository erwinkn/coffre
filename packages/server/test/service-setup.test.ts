import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import type { CoffreClient } from '@coffre/client';
import { defineSignin, github, type BindingClaims } from '@coffre/core/identity';
import { and, asc, eq, inArray } from 'drizzle-orm';

import { SigninService } from '../src/api/signin.ts';
import { WorkloadService } from '../src/api/workloads.ts';
import { processLimits } from '../src/workloads/limits.ts';
import type { WorkloadTransport } from '../src/workloads/transport.ts';
import { auditLog, projects } from './db/tables.ts';
import { clientFor, LOG, openTestDatabase, resetDatabase, revokesLogged, testDeps, type FixtureDeps } from './api-fixture.ts';

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
    // With 0.15's log, the vault revokes the token (T149), and its change records who (D147).
    ...(LOG === '0.14' ? [[ADA, 'token.revoke', 'allow', null]] : []),
    [ADA, 'token.unbind', 'allow', 'removed'],
    [ADA, 'access.revoke', 'allow', null],
  ], 'who did each step');
  if (LOG === '0.15') assert.deepEqual(await revokesLogged(db.owner), [{ actor: ADA, reason: 'revoke', targetCredentialId: issued.id }]);

  // Removing it is theirs too; its report, which names what it read anywhere, is not.
  const removed = await ada.members.remove(CI);
  assert.equal(removed.report, null);
  assert.equal(removed.revoked.grants, 1);
});

test('an account made with its first grant, in one call: its maker manages it, and the log shows both', async () => {
  assert.deepEqual(await ada.members.add(CI, { access: { 'market/dev': 'developer' } }), {
    member: CI,
    instanceRole: 'member',
    scope: { projects: 'all', environments: 'all' },
    created: true,
    changes: { 'market/dev': 'created' },
  });
  assert.deepEqual((await ada.members.list()).members.map((member) => [member.member, member.managed, member.grants.map((grant) => grant.id)]), [
    [CI, true, [`${CI}/market/dev`]],
  ]);
  assert.equal((await ada.tokens.issue(CI, { label: 'ci', expiresInDays: 1 })).token.length > 0, true);
  // Who runs the instance gives one an end too; one already a member is granted as it is.
  assert.equal((await root.members.add('token:deploy', { access: { market: { role: 'viewer', until: '2999-12-31' } } })).created, true);
  assert.deepEqual((await root.members.access('token:deploy')).grants.map((grant) => [grant.project, grant.role, grant.expiresAt?.slice(0, 10)]), [['market', 'viewer', '2999-12-31']]);
  assert.deepEqual(await ada.members.add(CI, { access: { 'billing/dev': 'viewer' } }), {
    member: CI, instanceRole: 'member', scope: { projects: 'all', environments: 'all' }, created: false, changes: { 'billing/dev': 'created' },
  });
  assert.deepEqual((await logged('member.add', 'access.grant')).filter(([actor]) => actor === ADA), [
    [ADA, 'member.add', 'allow', null],
    [ADA, 'access.grant', 'allow', null],
    [ADA, 'access.grant', 'allow', null],
  ]);
  assert.equal((await root.audit.verify()).ok, true);
});

test('a grant refused, by the app or the vault, leaves no account behind', async () => {
  const made = async () => (await root.members.list()).members.filter((member) => member.principalType === 'service').map((member) => member.member);
  // Beyond what they hold: prod, a project around their dev, a role above their own, one place of two.
  await assert.rejects(ada.members.add('token:ci-prod', { access: { 'market/prod': 'viewer' } }), { status: 403 });
  await assert.rejects(ada.members.add('token:ci-market', { access: { market: 'viewer' } }), { status: 403 });
  await assert.rejects(bo.members.add('token:ci-bo', { access: { market: 'maintainer' } }), { status: 403 });
  await assert.rejects(ada.members.add('token:ci-two', { access: { 'market/dev': 'developer', 'market/prod': 'developer' } }), { status: 403 });
  // Who sets up nothing, a role only a project takes, a place that is not there.
  await assert.rejects(nemo.members.add('token:ci-nemo', { access: { 'market/dev': 'viewer' } }), { status: 403 });
  await assert.rejects(root.members.add('token:ci-owner', { access: { 'market/dev': 'owner' } }), { status: 409 });
  await assert.rejects(root.members.add('token:ci-nowhere', { access: { 'nowhere/dev': 'viewer' } }), { status: 404 });
  // Never a person, nor with a role; and access names a place.
  await assert.rejects(root.members.add('user:eve@acme.example', { access: { market: 'viewer' } }), { status: 400 });
  await assert.rejects(root.members.add(CI, { role: 'member', access: { market: 'viewer' } }), { status: 400 });
  await assert.rejects(root.members.add(CI, { access: {} }), { status: 400 });
  assert.deepEqual(await made(), []);
  // The vault decides too: the app's check passed over, as a race would, it refuses and admits nobody.
  const [market] = await db.owner.select({ id: projects.id }).from(projects).where(eq(projects.slug, 'market'));
  const raced = await deps.vault.setAccess({ actor: ADA, principal: 'token:ci-raced', admit: true, changes: [{ projectId: market.id, environmentId: null, role: 'viewer', expiresAt: null }] });
  assert.equal(raced.ok ? 'ok' : raced.refusal.code, 'not_allowed');
  assert.deepEqual(await made(), []);
  // Each refusal logged as what was refused: setting one up, or the grant it was made for.
  assert.deepEqual((await logged('member.add')).filter(([, , decision]) => decision === 'deny').map(([actor, , , reason]) => [actor, reason]), [[NEMO, 'not_service_manager']]);
  assert.ok((await logged('access.grant')).some(([actor, , decision, reason]) => actor === ADA && decision === 'deny' && reason === 'not_allowed'));
});

test('an account someone else removed is not made again with a grant, by the one who could not bring it back', async () => {
  await bo.members.add('token:ci-gone', { access: { 'market/dev': 'viewer' } });
  await root.members.remove('token:ci-gone');
  await assert.rejects(bo.members.add('token:ci-gone', { access: { 'market/dev': 'viewer' } }), { status: 403 });
  assert.equal((await root.members.access('token:ci-gone')).status, 'removed');
  // Who runs the instance brings it back, with its grant, and its old tokens stay dead.
  assert.deepEqual((await root.members.add('token:ci-gone', { access: { 'market/dev': 'viewer' } })).created, true);
  assert.deepEqual((await root.members.access('token:ci-gone')).grants.map((grant) => grant.role), ['viewer']);
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
  // Its maker manages it, though a token would reach nothing: it needs a grant first.
  await assert.rejects(ada.tokens.issue('token:ci-ada', { label: 'x', expiresInDays: 1 }), { status: 400, message: /give the account a grant first/ });
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

test('an Admin of the whole instance whose role holds nothing still sees the setting name every project it names', async () => {
  // An Owner keeps Admins for people alone: the role reads no project, and its holders still run the instance.
  await root.roles.set('admin', { name: 'Admin', description: 'People, not projects.', permissions: [], protected: [] }, { instance: true });
  await root.members.add('user:hr@acme.example', { role: 'admin' });
  await root.settings.set({ serviceAccounts: { projects: { except: ['billing'] } } });
  const hr = await clientFor(deps, 'hr@acme.example').me();
  assert.equal(hr.runsInstance, true);
  assert.deepEqual(hr.serviceSetup, { projects: { except: ['billing'] }, environments: 'all' });
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
