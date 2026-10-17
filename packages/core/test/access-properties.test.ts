import assert from 'node:assert/strict';
import test from 'node:test';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';

import {
  allows,
  assignableToEnvironment,
  covers,
  DELEGABLE_ROLES,
  givesService,
  grantKind,
  inScope,
  isCredentialScope,
  issuesCredential,
  instanceRoleGrants,
  makesProjects,
  mayManageAccess,
  normalScope,
  ownsInstance,
  readsWholeLog,
  roleGrants,
  runsInstance,
  type Filter,
  type Holdings,
  type InstanceRole,
  type Permission,
  type Place,
  type Role,
  type Scope,
} from '../src/access.ts';
import { propertySettings } from './properties.ts';

// Independent specification from README's Roles tables. Do not derive these
// tables or the scope rules from the implementation's constants/helpers.
const permissions = ['secret.read', 'secret.write', 'secret.archive', 'audit.read', 'environment.manage', 'grant.manage', 'project.manage'] as const;
const roles = ['viewer', 'developer', 'maintainer', 'access-manager', 'auditor', 'owner'] as const;
const rights: Record<Role, readonly Permission[]> = {
  viewer: ['secret.read'],
  developer: ['secret.read', 'secret.write'],
  maintainer: ['secret.read', 'secret.write', 'secret.archive', 'environment.manage'],
  'access-manager': ['grant.manage'],
  auditor: ['audit.read'],
  owner: permissions,
};
const instanceRoles = ['member', 'auditor', 'developer', 'admin', 'owner'] as const;
const instanceRights: Record<InstanceRole, readonly Permission[]> = {
  member: [],
  auditor: ['audit.read'],
  developer: ['secret.read', 'secret.write'],
  admin: ['audit.read', 'environment.manage', 'grant.manage', 'project.manage'],
  owner: permissions,
};
const management = ['environment.manage', 'grant.manage', 'project.manage'];
const projects = ['market', 'ops', 'other'] as const;
const slugs = ['dev', 'prod', 'other'] as const;

// An environment's id is its project's and its slug, so that `market/dev`
// and `ops/dev` are two environments with one slug.
const grant = gs.record({
  projectId: gs.sampledFrom(['market', 'ops']),
  environment: gs.sampledFrom([null, 'dev', 'prod']),
  role: gs.sampledFrom(roles),
}).map(({ projectId, environment, role }) => {
  const slug = rights[role].some((permission) => management.includes(permission)) ? null : environment;
  return { projectId, environmentId: slug === null ? null : `${projectId}/${slug}`, role };
});
const filter = (values: readonly string[]) => gs.oneOf(
  gs.just('all' as Filter),
  gs.arrays(gs.sampledFrom(values), { minSize: 0, maxSize: 2 }).map((only): Filter => ({ only })),
  gs.arrays(gs.sampledFrom(values), { minSize: 1, maxSize: 2 }).map((except): Filter => ({ except })),
);
const scope = gs.record({ projects: filter(projects), environments: filter(slugs) });
const holder = gs.record({
  role: gs.sampledFrom(instanceRoles),
  scope,
  grants: gs.arrays(grant, { maxSize: 8 }).map((held) => [...new Map(held.map((item) => [JSON.stringify([item.projectId, item.environmentId]), item])).values()]),
});

function modelAdmits(filter: Filter, value: string | null): boolean {
  if (filter === 'all') return true;
  if (value === null) return false;
  return 'only' in filter ? filter.only.includes(value) : !filter.except.includes(value);
}

/**
 * An instance role reaches the projects its scope takes in, and the
 * environments of the slugs it keeps, a project as a whole only when it
 * keeps them all. A grant on a project reaches it and its environments; on
 * an environment, that environment.
 */
function modelAllows(member: Holdings, permission: Permission, place: Place): boolean {
  const slug = place.environmentId == null ? undefined : place.environmentSlug;
  const scoped = modelAdmits(member.scope.projects, place.projectId)
    && (slug === undefined ? member.scope.environments === 'all' : modelAdmits(member.scope.environments, slug));
  if (scoped && instanceRights[member.role].includes(permission)) return true;
  for (const held of member.grants) {
    if (held.projectId !== place.projectId) continue;
    if (held.environmentId !== null && held.environmentId !== place.environmentId) continue;
    if (rights[held.role].includes(permission)) return true;
  }
  return false;
}

function everyPlace(): Place[] {
  return projects.flatMap((projectId): Place[] => [
    { projectId },
    ...[...slugs, null].map((slug): Place => ({ projectId, environmentId: `${projectId}/${slug}`, environmentSlug: slug })),
  ]);
}

const settings = propertySettings(128);
test(`access decisions match the independent role and scope model, seed ${settings.seed}`, () => hegel.test((tc) => {
  const member = tc.draw(holder);
  // Holdings is the core boundary: membership, expiry and credential validity
  // have already been checked by the vault/caller. A service account is a
  // member everywhere, holding only its grants.
  for (const kind of ['user', 'token'] as const) {
    const holdings: Holdings = kind === 'token' ? { ...member, role: 'member', scope: { projects: 'all', environments: 'all' } } : member;
    for (const place of everyPlace()) {
      for (const permission of permissions) {
        assert.equal(allows(holdings, permission, place), modelAllows(holdings, permission, place), JSON.stringify({ kind, holdings, permission, place }));
        assert.equal(mayManageAccess(holdings, place), modelAllows(holdings, 'grant.manage', place));
      }
    }
  }
}, settings));

test(`roles, scopes and running the instance match the model, seed ${settings.seed}`, () => hegel.test((tc) => {
  const actor = tc.draw(holder);
  for (const role of roles) {
    for (const permission of permissions) assert.equal(roleGrants(role, permission), rights[role].includes(permission));
    assert.equal(assignableToEnvironment(role), rights[role].every((permission) => !management.includes(permission)));
  }
  for (const role of instanceRoles) {
    for (const permission of permissions) assert.equal(instanceRoleGrants(role, permission), instanceRights[role].includes(permission));
  }
  const administers = actor.role === 'admin' || actor.role === 'owner';
  const everywhere = actor.scope.projects === 'all' && actor.scope.environments === 'all';
  assert.equal(runsInstance(actor), administers && everywhere);
  // An Owner of the whole instance is an Owner whose scope narrows nothing: one of a project owns no instance.
  assert.equal(ownsInstance(actor), actor.role === 'owner' && everywhere);
  // A project made now is one no `only` lists, and none `except` lists.
  const takesNewProjects = actor.scope.projects === 'all' || 'except' in actor.scope.projects;
  assert.equal(makesProjects(actor), administers && takesNewProjects && actor.scope.environments === 'all');
  // A scope written another way decides the same.
  const normal = normalScope(actor.scope);
  for (const place of everyPlace()) assert.equal(inScope(normal, place), inScope(actor.scope, place));
}, settings));

const grants = gs.arrays(grant, { maxSize: 6 }).map((held) => [...new Map(held.map((item) => [JSON.stringify([item.projectId, item.environmentId]), item])).values()]);

/** A service account as `issuesCredential` weighs it, its grants' places named as checks name them. */
function account(held: Holdings['grants']) {
  const place = (item: Holdings['grants'][number]): Place => item.environmentId === null
    ? { projectId: item.projectId! }
    : { projectId: item.projectId!, environmentId: item.environmentId, environmentSlug: item.environmentId.split('/')[1]! };
  return { grants: held.map((item) => ({ role: item.role, place: place(item) })), admittedBy: null };
}

test(`a credential reaches what both its scope and its account hold, and never more than the account held when it was issued, seed ${settings.seed}`, () => hegel.test((tc) => {
  const atIssue = tc.draw(grants);
  const scope = tc.draw(grants);
  const now = tc.draw(grants);
  const service = (held: Holdings['grants'], credentialScope: Holdings['credentialScope'] = null): Holdings =>
    ({ role: 'member', scope: { projects: 'all', environments: 'all' }, grants: held, credentialScope });
  assert.equal(isCredentialScope(scope), true);
  // Who runs the instance gives anything, so only the account bounds what they issue.
  const owner: Holdings = { role: 'owner', scope: { projects: 'all', environments: 'all' }, grants: [] };
  const issued = issuesCredential(owner, null, 'user:root', account(atIssue), account(scope).grants);
  for (const place of everyPlace()) {
    for (const permission of permissions) {
      const through = allows(service(now, scope), permission, place);
      assert.equal(through, modelAllows(service(now), permission, place) && modelAllows(service(scope), permission, place));
      // Issued, whatever the account holds now, a request with it holds no more than the account did then.
      if (issued && through) assert.equal(modelAllows(service(atIssue), permission, place), true, JSON.stringify({ atIssue, scope, now, permission, place }));
    }
  }
  // Issued only within the account: each of its grants' every permission, where it is.
  const within = account(scope).grants.every(({ role, place }) => rights[role].every((permission) => modelAllows(service(atIssue), permission, place)));
  assert.equal(issued, within);
}, settings));

test('a scope narrows only the role: grants reach past it, and a project is in it only with all its environments', () => {
  const scope: Scope = { projects: 'all', environments: { only: ['dev'] } };
  const developer: Holdings = { role: 'developer', scope, grants: [{ projectId: 'billing', environmentId: null, role: 'viewer' }] };
  const at = (projectId: string, slug: string): Place => ({ projectId, environmentId: `${projectId}/${slug}`, environmentSlug: slug });
  assert.equal(allows(developer, 'secret.write', at('market', 'dev')), true);
  assert.equal(allows(developer, 'secret.read', at('market', 'prod')), false);
  assert.equal(allows(developer, 'secret.read', at('billing', 'prod')), true, 'the grant reaches past the scope');
  assert.equal(allows(developer, 'secret.write', at('billing', 'prod')), false);
  const admin: Holdings = { role: 'admin', scope, grants: [] };
  assert.equal(mayManageAccess(admin, at('market', 'dev')), true);
  assert.equal(mayManageAccess(admin, { projectId: 'market' }), false, 'a grant on market would reach market/prod');
  assert.equal(allows(admin, 'secret.read', at('market', 'dev')), false, 'an admin reads no values');
  assert.equal(runsInstance(admin), false);
  // A slug not read is in no scope that names environments.
  assert.equal(inScope(scope, { projectId: 'market', environmentId: 'market/dev', environmentSlug: null }), false);
  assert.equal(inScope({ projects: 'all', environments: 'all' }, { projectId: 'market', environmentId: 'market/dev', environmentSlug: null }), true);
});

test("a person's personal token holds their places within its scope, and nothing of the instance's: no running it, whole log, new project or service account", () => {
  const everywhere: Scope = { projects: 'all', environments: 'all' };
  const owner: Holdings = { role: 'owner', scope: everywhere, grants: [] };
  const token: Holdings = { ...owner, credentialScope: [{ projectId: 'market', environmentId: null, role: 'maintainer' }] };
  const dev: Place = { projectId: 'market', environmentId: 'market/dev', environmentSlug: 'dev' };
  assert.deepEqual([runsInstance(owner), readsWholeLog(owner), makesProjects(owner)], [true, true, true]);
  assert.deepEqual([runsInstance(token), readsWholeLog(token), makesProjects(token)], [false, false, false]);
  assert.equal(allows(token, 'secret.write', dev), true);
  assert.equal(allows(token, 'audit.read', dev), false, 'a maintainer reads no log');
  assert.equal(allows(token, 'secret.read', { projectId: 'billing' }), false);
  // Where people set up service accounts, a Developer gives one what they hold; through a token, never.
  const developer: Holdings = { role: 'developer', scope: everywhere, grants: [] };
  assert.equal(givesService(developer, everywhere, 'viewer', dev), true);
  assert.equal(givesService({ ...developer, credentialScope: [{ projectId: 'market', environmentId: 'market/dev', role: 'developer' }] }, everywhere, 'viewer', dev), false);
  // No role it may name manages access, so it gives and takes no grant anywhere.
  assert.deepEqual(DELEGABLE_ROLES, ['viewer', 'developer', 'maintainer', 'auditor']);
  assert.ok(DELEGABLE_ROLES.every((role) => !roleGrants(role, 'grant.manage')));
});

test('a grant whose fields name no coherent place covers nothing', () => {
  // An environment grant whose environment row is gone reads back with no
  // project, and a grant on every project of 0.4 names neither.
  for (const grant of [
    { projectId: null, environmentId: 'market/dev', role: 'owner' as const },
    { projectId: null, environmentId: null, role: 'owner' as const },
  ]) {
    assert.equal(grantKind(grant), null);
    const holder: Holdings = { role: 'member', scope: { projects: 'all', environments: 'all' }, grants: [grant] };
    for (const place of everyPlace()) {
      assert.equal(covers(grant, place), false, JSON.stringify({ grant, place }));
      for (const permission of permissions) assert.equal(allows(holder, permission, place), false);
    }
  }
});
