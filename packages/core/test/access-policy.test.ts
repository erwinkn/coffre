import test from 'node:test';
import assert from 'node:assert/strict';

import { allows, DEFAULT_POLICY, EVERYWHERE, givesService, isCredentialScope, protectedWithin, readsWholeLog, ROLES, scopeDefinition, type Holdings, type Policy } from '../src/access.ts';

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
