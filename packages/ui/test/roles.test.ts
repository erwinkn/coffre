import test from 'node:test';
import assert from 'node:assert/strict';

import { definitionProblem, PERMISSIONS, ROLES, type Permission } from '@coffre/core/access';

import {
  columnInWords,
  GRID_PERMISSIONS,
  impactInWords,
  protectionInWords,
  roleIdFrom,
  roleIdProblem,
  sameDefinition,
  SHIPPED_ROLES,
  toggle,
  type Columns,
} from '../src/lib/roles.ts';

const grid = (permissions: Permission[], guarded: Permission[] = []): Columns => ({ permissions, protected: guarded });

test('checking Read checks Use, and unchecking Use unchecks Read, in each column', () => {
  assert.deepEqual(toggle(grid([]), 'secret.read', 'normal', true), grid(['secret.read', 'secret.use']));
  assert.deepEqual(toggle(grid(['secret.read', 'secret.use']), 'secret.use', 'normal', false), grid([]));
  // Unchecking Read leaves Use.
  assert.deepEqual(toggle(grid(['secret.read', 'secret.use']), 'secret.read', 'normal', false), grid(['secret.use']));
  assert.deepEqual(
    toggle(grid(['secret.read', 'secret.use'], ['secret.read', 'secret.use']), 'secret.use', 'protected', false),
    grid(['secret.read', 'secret.use']),
  );
});

test('the protected column holds no more than the other: checking one checks both, unchecking the other unchecks both', () => {
  assert.deepEqual(toggle(grid([]), 'secret.write', 'protected', true), grid(['secret.write'], ['secret.write']));
  assert.deepEqual(toggle(grid([]), 'secret.read', 'protected', true), grid(['secret.read', 'secret.use'], ['secret.read', 'secret.use']));
  assert.deepEqual(toggle(grid(['secret.write'], ['secret.write']), 'secret.write', 'normal', false), grid([]));
  // Unchecking a protected box leaves the other.
  assert.deepEqual(toggle(grid(['secret.write'], ['secret.write']), 'secret.write', 'protected', false), grid(['secret.write']));
});

test('a project-wide permission has one column: its protected box changes nothing', () => {
  assert.deepEqual(toggle(grid([]), 'grant.manage', 'protected', true), grid([]));
  assert.deepEqual(toggle(grid([]), 'grant.manage', 'normal', true), grid(['grant.manage']));
});

test('whatever is clicked, in any order, the grid holds a role the vault accepts', () => {
  // Every two clicks in a row, from every built-in role: the rules hold after each.
  const clicks = GRID_PERMISSIONS.flatMap((permission) =>
    (['normal', 'protected'] as const).flatMap((column) => [true, false].map((on) => [permission, column, on] as const)));
  for (const start of Object.values(ROLES)) {
    let frontier: Columns[] = [grid([...start.permissions], [...start.protected])];
    for (let step = 0; step < 2; step++) {
      frontier = frontier.flatMap((columns) => clicks.map(([permission, column, on]) => toggle(columns, permission, column, on)));
      for (const columns of frontier) {
        assert.equal(definitionProblem({ name: 'Role', description: '', ...columns }), null, JSON.stringify(columns));
        assert.deepEqual(columns.permissions, PERMISSIONS.filter((permission) => columns.permissions.includes(permission)));
      }
    }
  }
});

test('a definition is the same whatever order its columns are in', () => {
  const developer = { ...ROLES.developer, permissions: [...ROLES.developer.permissions], protected: [...ROLES.developer.protected] };
  assert.equal(sameDefinition(developer, { ...developer, permissions: [...developer.permissions].reverse() }), true);
  assert.equal(sameDefinition(developer, { ...developer, protected: ['secret.use'] }), false);
  assert.equal(sameDefinition(developer, { ...developer, name: 'Developer ' }), true);
});

test('a column reads as a sentence', () => {
  assert.equal(columnInWords(ROLES.developer.permissions), 'read, use and write values');
  assert.equal(columnInWords(ROLES.developer.protected), 'use and write values');
  assert.equal(columnInWords(ROLES.maintainer.permissions), 'read, use, write and retire values and manage environments');
  assert.equal(columnInWords(ROLES['access-manager'].protected), 'nothing');
  assert.equal(columnInWords(ROLES.auditor.permissions), 'read the log');
});

test("a new role's id follows its name, and is checked as the server checks it", () => {
  assert.equal(roleIdFrom('Release manager'), 'release-manager');
  assert.equal(roleIdFrom('  2nd Line — Support!  '), 'nd-line-support');
  assert.equal(roleIdFrom('Équipe'), 'equipe');
  assert.equal(roleIdProblem('release-manager', ['viewer']), null);
  assert.equal(roleIdProblem('viewer', ['viewer']), 'There is a role viewer already.');
  assert.match(roleIdProblem('Release', [])!, /lowercase/);
  assert.match(roleIdProblem('2nd', [])!, /starts with a letter/);
  assert.match(roleIdProblem('r', [])!, /2 to 32/);
});

test('an impact reads in words, a single place by its path', () => {
  const line = { change: 'widens', permission: 'secret.read', protected: true, people: 6, services: 0, environments: 4, projects: 2, examples: ['ada@acme.example on market/prod'] } as const;
  assert.equal(impactInWords(line), '6 people can now read values in 4 protected environments');
  assert.equal(
    impactInWords({ ...line, change: 'narrows', permission: 'secret.write', protected: false, people: 1, environments: 1, examples: ['ada@acme.example on market/dev'] }),
    '1 person can no longer write values in market/dev',
  );
  assert.equal(
    impactInWords({ ...line, permission: 'grant.manage', protected: false, people: 2, environments: 0, projects: 1, examples: ['bo@acme.example on market'] }),
    '2 people can now manage access on market',
  );
  assert.equal(impactInWords({ ...line, permission: 'environment.manage', protected: false, environments: 0, projects: 3 }), '6 people can now manage environments on 3 projects');
  assert.equal(impactInWords({ ...line, people: 0, services: 1 }), '1 service account can now read values in 4 protected environments');
  assert.equal(impactInWords({ ...line, services: 2 }), '6 people and 2 service accounts can now read values in 4 protected environments');
});

test('protecting is said by what a Developer keeps, or by any role whose columns differ', () => {
  assert.equal(protectionInWords(SHIPPED_ROLES.roles), 'Developers use and write values, and read none');
  const same = SHIPPED_ROLES.roles.map((role) => ({ ...role, protected: role.permissions.filter((permission) => !['environment.manage', 'grant.manage', 'project.manage'].includes(permission)) }));
  assert.equal(protectionInWords(same), null);
  const onlyViewer = same.map((role) => (role.id === 'viewer' ? { ...role, protected: ['secret.use' as const] } : role));
  assert.equal(protectionInWords(onlyViewer), 'Viewers use values, and read none');
});

test('the roles as they ship stand in for the policy until it is read: Owner and Member fixed', () => {
  assert.deepEqual(SHIPPED_ROLES.roles.map((role) => role.id), Object.keys(ROLES));
  assert.deepEqual(SHIPPED_ROLES.roles.filter((role) => role.fixed).map((role) => role.id), ['owner']);
  assert.deepEqual(SHIPPED_ROLES.instanceRoles.filter((role) => role.fixed).map((role) => role.id), ['member', 'owner']);
  assert.deepEqual(SHIPPED_ROLES.roles.filter((role) => !role.assignableToEnvironment).map((role) => role.id), ['maintainer', 'access-manager', 'owner']);
  assert.equal(SHIPPED_ROLES.editable, false);
});
