import test from 'node:test';
import assert from 'node:assert/strict';

import { allows, DEFAULT_POLICY, EVERYWHERE, givesService, grantDefinition, heldColumns, isCredentialScope, issuedGrant, issuesCredential, protectedWithin, readsWholeLog, ROLES, scopeDefinition, type Holdings, type Policy } from '../src/access.ts';

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
    // On a whole project, what they hold in its protected environments, whichever those are: use and write, not read.
    assert.equal(givesService(developer, EVERYWHERE, 'contributor', { projectId: name }), true);
    assert.equal(givesService(developer, EVERYWHERE, 'viewer', { projectId: name }), false);
  }
});

test('a grant on an environment gives nothing while its role holds a permission only a project takes', () => {
  // Eve's editor grant on market/dev, the role widened with grant.manage behind it: no grant on an environment takes that.
  const editor = { name: 'Editor', description: '', permissions: ['secret.read', 'secret.use', 'secret.write'], protected: ['secret.use', 'secret.write'] } as const;
  const narrow: Policy = { ...DEFAULT_POLICY, roles: { ...DEFAULT_POLICY.roles, editor } };
  const wide: Policy = { ...narrow, roles: { ...narrow.roles, editor: { ...editor, permissions: [...editor.permissions, 'grant.manage'] } } };
  const onDev = { projectId: market, environmentId: dev, role: 'editor' };
  const place = { projectId: market, environmentId: dev, environmentSlug: 'dev' };
  const eve = (policy: Policy): Holdings => ({ role: 'member', scope: EVERYWHERE, grants: [onDev], policy });
  assert.deepEqual(grantDefinition(narrow, onDev), narrow.roles.editor);
  assert.equal(grantDefinition(wide, onDev), undefined);
  for (const permission of ['secret.read', 'secret.write', 'grant.manage'] as const) assert.equal(allows(eve(wide), permission, place), false, permission);
  assert.deepEqual(heldColumns(eve(wide), place), { normal: [], protected: [] });
  assert.deepEqual(issuedGrant(onDev, wide).permissions, { normal: [], protected: [] });
  assert.equal(givesService(eve(wide), EVERYWHERE, 'editor', place), false);
  // Narrowed back, it gives what it did; on the project, the widened role gives everything it holds.
  assert.equal(allows(eve(narrow), 'secret.read', place), true);
  assert.equal(givesService(eve(narrow), EVERYWHERE, 'editor', place), true);
  const onMarket: Holdings = { ...eve(wide), grants: [{ ...onDev, environmentId: null }] };
  assert.equal(allows(onMarket, 'grant.manage', place), true);
  assert.equal(allows(onMarket, 'secret.read', place), true);
  // Nor is one given at an environment, to a service account or on its credential: a Keeper of market, who holds
  // environment.manage at market/dev, gives no keeper there; an Owner issues none there for an account that holds it on market.
  const keeper = { name: 'Keeper', description: '', permissions: ['secret.use', 'secret.write', 'environment.manage'], protected: ['secret.use', 'secret.write'] } as const;
  const kept: Policy = { ...DEFAULT_POLICY, roles: { ...DEFAULT_POLICY.roles, keeper } };
  const holding = (role: string, policy: Policy): Holdings => ({ role: 'member', scope: EVERYWHERE, grants: [{ projectId: market, environmentId: null, role }], policy });
  assert.equal(givesService(holding('keeper', kept), EVERYWHERE, 'keeper', place), false);
  assert.equal(givesService(holding('keeper', kept), EVERYWHERE, 'keeper', { projectId: market }), true);
  // A Maintainer of market gives no maintainer on market either, for another reason: a grant on a whole project takes
  // holding the role in the protected column, and a Maintainer reads no protected value (D241).
  assert.equal(givesService(holding('maintainer', DEFAULT_POLICY), EVERYWHERE, 'maintainer', place), false);
  assert.equal(givesService(holding('maintainer', DEFAULT_POLICY), EVERYWHERE, 'maintainer', { projectId: market }), false);
  const owner: Holdings = { role: 'owner', scope: EVERYWHERE, grants: [], policy: DEFAULT_POLICY };
  const account = { grants: [{ role: 'maintainer', place: { projectId: market } }], admittedBy: null };
  assert.equal(issuesCredential(owner, EVERYWHERE, 'user:ada', account, [{ role: 'maintainer', place }]), false);
  assert.equal(issuesCredential(owner, EVERYWHERE, 'user:ada', account, [{ role: 'maintainer', place: { projectId: market } }]), true);
});
