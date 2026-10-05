import assert from 'node:assert/strict';
import test from 'node:test';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';

import { allows, assignableToEnvironment, covers, grantKind, mayManageAccess, roleGrants, type Holdings, type Permission, type Place, type Role } from '../src/access.ts';
import { propertySettings } from './properties.ts';

// Independent specification from README's Roles table. Do not derive this
// table or the scope rules from the implementation's constants/helpers.
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
const management = ['environment.manage', 'grant.manage', 'project.manage'];
// An environment's id is its project's and its slug, so that `market/dev`
// and `ops/dev` are two environments with one slug.
const grant = gs.record({
  projectId: gs.sampledFrom(['market', 'ops', null]),
  environment: gs.sampledFrom([null, 'dev', 'prod']),
  role: gs.sampledFrom(roles),
}).map(({ projectId, environment, role }) => {
  const slug = rights[role].some((permission) => management.includes(permission)) ? null : environment;
  return projectId === null
    ? { projectId, environmentId: null, environmentSlug: slug, role }
    : { projectId, environmentId: slug === null ? null : `${projectId}/${slug}`, environmentSlug: null, role };
});
const holder = gs.record({ isRootAdmin: gs.booleans(), isOwner: gs.booleans(), grants: gs.arrays(grant, { maxSize: 8 }).map((held) => [...new Map(held.map((item) => [JSON.stringify([item.projectId, item.environmentId, item.environmentSlug]), item])).values()]) });

/**
 * A grant on a project reaches it and its environments; on an environment,
 * that environment; on every project (`*`), everything; on one slug in
 * every project, each environment of that slug and nothing else.
 */
function modelAllows(member: Holdings, permission: Permission, place: Place): boolean {
  if (member.isRootAdmin) return true;
  if (place.environmentId == null && member.isOwner && management.includes(permission)) return true;
  for (const held of member.grants) {
    if (held.projectId === null) {
      if (held.environmentSlug !== null && (place.environmentId == null || place.environmentSlug !== held.environmentSlug)) continue;
    } else {
      if (held.projectId !== place.projectId) continue;
      if (held.environmentId !== null && held.environmentId !== place.environmentId) continue;
    }
    if (rights[held.role].includes(permission)) return true;
  }
  return false;
}

const settings = propertySettings(128);
test(`access decisions match the independent role/scope model, seed ${settings.seed}`, () => hegel.test((tc) => {
  const member = tc.draw(holder);
  // Holdings is the core boundary: membership, expiry and credential validity
  // have already been checked by the vault/caller. The same grant decisions
  // apply to people and service tokens; a token is never an instance owner.
  for (const kind of ['user', 'token'] as const) {
    const holdings = kind === 'token' ? { ...member, isRootAdmin: false, isOwner: false } : member;
    for (const projectId of ['market', 'ops', 'other']) {
      for (const slug of [undefined, null, 'dev', 'prod', 'other']) {
        const place: Place = slug == null
          ? { projectId, environmentId: slug }
          : { projectId, environmentId: `${projectId}/${slug}`, environmentSlug: slug };
        for (const permission of permissions) {
          assert.equal(allows(holdings, permission, place), modelAllows(holdings, permission, place), JSON.stringify({ kind, holdings, permission, place }));
        }
      }
    }
  }
}, settings));

test(`roles and grant management match the model, seed ${settings.seed}`, () => hegel.test((tc) => {
  const actor = tc.draw(holder);
  const change = tc.draw(grant);
  for (const role of roles) {
    for (const permission of permissions) assert.equal(roleGrants(role, permission), rights[role].includes(permission));
    assert.equal(assignableToEnvironment(role), rights[role].every((permission) => !management.includes(permission)));
  }
  for (const role of [...roles, null]) {
    const place = { ...change, role };
    // Only owners and root admins grant on every project, whatever they hold there.
    const canManage = place.projectId === null
      ? actor.isOwner || actor.isRootAdmin
      : modelAllows(actor, 'grant.manage', { projectId: place.projectId });
    assert.equal(mayManageAccess(actor, place), canManage, JSON.stringify({ actor, place }));
  }
}, settings));

test('a grant whose fields name no coherent place covers nothing, and is no grant on every project', () => {
  // An environment grant whose environment row is gone reads back with no project: never `*`.
  const orphan = { projectId: null, environmentId: 'market/dev', environmentSlug: null, role: 'owner' as const };
  const slugInProject = { projectId: 'market', environmentId: null, environmentSlug: 'dev', role: 'owner' as const };
  for (const grant of [orphan, slugInProject]) {
    assert.equal(grantKind(grant), null);
    const holder = { isRootAdmin: false, isOwner: false, grants: [grant] };
    for (const place of [{ projectId: 'market' }, { projectId: 'other' }, { projectId: 'market', environmentId: 'market/dev', environmentSlug: 'dev' }] as Place[]) {
      assert.equal(covers(grant, place), false, JSON.stringify({ grant, place }));
      for (const permission of permissions) assert.equal(allows(holder, permission, place), false);
    }
    assert.equal(mayManageAccess({ isRootAdmin: true, isOwner: true, grants: [] }, grant), false, 'not even a root admin changes a grant at no place');
  }
  assert.equal(grantKind({ projectId: null, environmentId: null, environmentSlug: null }), 'every-project');
  // A slug not read matches no grant on a slug.
  const dev = { projectId: null, environmentId: null, environmentSlug: 'dev' };
  assert.equal(covers(dev, { projectId: 'market', environmentId: 'market/dev', environmentSlug: null }), false);
});
