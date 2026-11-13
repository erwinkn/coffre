import test from 'node:test';
import assert from 'node:assert/strict';

import { allows, DEFAULT_POLICY, EVERYWHERE, givesService, isCredentialScope, protectedWithin, readScope, readsWholeLog, ROLES, scopeDefinition, type Holdings, type Policy } from '../src/access.ts';

const market = '11111111-1111-4111-8111-111111111111';
const dev = '22222222-2222-4222-8222-222222222222';

test("a scope kept before 0.10, its role's name alone, holds the role as it ships, whatever an Owner makes of it", () => {
  const kept = [{ projectId: market, environmentId: null, role: 'viewer' }];
  assert.equal(isCredentialScope(kept), true);
  assert.deepEqual(scopeDefinition(kept[0]!), ROLES.viewer);
  // Not a name no built-in role has: that holds nothing, and is no scope.
  assert.equal(isCredentialScope([{ projectId: market, environmentId: null, role: 'release-manager' }]), false);
  // Viewer widened to write: the holder writes, the credential does not.
  const widened: Policy = { ...DEFAULT_POLICY, roles: { ...DEFAULT_POLICY.roles, viewer: { ...ROLES.viewer, permissions: ['secret.read', 'secret.use', 'secret.write'] } } };
  const holder: Holdings = { role: 'member', scope: { projects: 'all', environments: 'all' }, grants: [{ projectId: market, environmentId: null, role: 'viewer' }], policy: widened };
  const place = { projectId: market, environmentId: dev, environmentSlug: 'dev' };
  assert.equal(allows(holder, 'secret.write', place), true);
  assert.equal(allows({ ...holder, credentialScope: kept }, 'secret.write', place), false);
  assert.equal(allows({ ...holder, credentialScope: kept }, 'secret.read', place), true);
});

test("a stored scope that is missing, unreadable, or a service's without saying where it reads sensitive values, reaches nothing", () => {
  const grant = { projectId: market, environmentId: null, role: 'viewer', permissions: { normal: [...ROLES.viewer.permissions], protected: [...ROLES.viewer.protected] } };
  const sealed = JSON.stringify([{ ...grant, sensitive: false }]);
  const old = JSON.stringify([grant]);
  for (const service of [true, false]) {
    // 0.4's, with none, and one the MAC checked that is no scope.
    assert.deepEqual(readScope(null, { service }), []);
    assert.deepEqual(readScope('{"not": "a scope"}', { service }), []);
    assert.deepEqual(readScope(sealed, { service }), JSON.parse(sealed));
  }
  // A release before 0.11 stored a service's without `sensitive`, which 0.15.0 sealed and 0.16 does not: it reaches
  // nothing, nor does a scope one such grant is part of. A person's never says, and reaches what it names.
  assert.deepEqual(readScope(old, { service: true }), []);
  assert.deepEqual(readScope(JSON.stringify([{ ...grant, sensitive: true }, { ...grant, environmentId: dev }]), { service: true }), []);
  assert.deepEqual(readScope(old, { service: false }), [grant]);
  const holder: Holdings = { role: 'member', scope: { projects: 'all', environments: 'all' }, grants: [{ projectId: market, environmentId: null, role: 'viewer' }], service: true };
  const place = { projectId: market, environmentId: dev, environmentSlug: 'dev' };
  assert.equal(allows({ ...holder, credentialScope: readScope(sealed, { service: true }) }, 'secret.read', place), true);
  assert.equal(allows({ ...holder, credentialScope: readScope(old, { service: true }) }, 'secret.read', place), false);
});

test('a name a plain object holds already names no role and no project of the policy', () => {
  // `formal-lean.ts` found these: `instanceRoles['constructor']` is Object, which made `allows` throw.
  for (const name of ['constructor', '__proto__', 'toString']) {
    const odd: Holdings = { role: name as Holdings['role'], scope: EVERYWHERE, grants: [], policy: DEFAULT_POLICY };
    assert.equal(allows(odd, 'secret.read', { projectId: 'market' }), false);
    assert.equal(readsWholeLog(odd), false);
    assert.deepEqual(protectedWithin(DEFAULT_POLICY, { projectId: name }), []);
    const developer: Holdings = { role: 'developer', scope: EVERYWHERE, grants: [], policy: DEFAULT_POLICY };
    assert.equal(givesService(developer, EVERYWHERE, 'viewer', { projectId: name }), true);
  }
});
