import assert from 'node:assert/strict';
import test from 'node:test';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';

import { allows, assignableToEnvironment, mayManageAccess, roleGrants, type Holdings, type Permission, type Place, type Role } from '../src/access.ts';
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
const grant = gs.record({
  projectId: gs.sampledFrom(['market', 'ops']),
  environmentId: gs.sampledFrom([null, 'dev', 'prod']),
  role: gs.sampledFrom(roles),
}).map((held) => ({
  ...held,
  environmentId: rights[held.role].some((permission) => management.includes(permission)) ? null : held.environmentId,
}));
const holder = gs.record({ isRootAdmin: gs.booleans(), isOwner: gs.booleans(), grants: gs.arrays(grant, { maxSize: 8 }).map((held) => [...new Map(held.map((item) => [JSON.stringify([item.projectId, item.environmentId]), item])).values()]) });

function modelAllows(member: Holdings, permission: Permission, place: Place): boolean {
  if (member.isRootAdmin) return true;
  if (place.environmentId == null && member.isOwner && management.includes(permission)) return true;
  for (const held of member.grants) {
    if (held.projectId !== place.projectId) continue;
    if (held.environmentId !== null && held.environmentId !== place.environmentId) continue;
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
      for (const environmentId of [undefined, null, 'dev', 'prod', 'other']) {
        const place = { projectId, environmentId };
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
    const place = { projectId: change.projectId, environmentId: change.environmentId, role };
    const canManage = modelAllows(actor, 'grant.manage', { projectId: place.projectId });
    assert.equal(mayManageAccess(actor, place), canManage, JSON.stringify({ actor, place }));
  }
}, settings));
