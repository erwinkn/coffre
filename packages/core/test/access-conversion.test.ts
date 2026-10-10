import assert from 'node:assert/strict';
import test from 'node:test';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';

import {
  allows,
  assignableToEnvironment,
  convertEveryProjectGrants,
  EVERYWHERE,
  PERMISSIONS,
  PROJECT_ONLY_PERMISSIONS,
  ROLES,
  type ConversionInput,
  type EveryProjectGrant,
  type Holdings,
  type Permission,
  type Place,
  type Role,
} from '../src/access.ts';
import { propertySettings } from './properties.ts';

const projects = [
  { id: 'market', environments: [{ id: 'market/dev', slug: 'dev' }, { id: 'market/prod', slug: 'prod' }] },
  { id: 'billing', environments: [{ id: 'billing/dev', slug: 'dev' }] },
];

const person = (everyProject: EveryProjectGrant[], more: Partial<ConversionInput> = {}): ConversionInput =>
  ({ person: true, role: 'member', everyProject, grants: [], projects, ...more });
const all = (role: Role, expiresAt: number | null = null): EveryProjectGrant => ({ environmentSlug: null, role, expiresAt });
const on = (environmentSlug: string, role: Role, expiresAt: number | null = null): EveryProjectGrant => ({ environmentSlug, role, expiresAt });

test('the common cases convert as the design says', () => {
  const cases: [string, ConversionInput, Pick<ReturnType<typeof convertEveryProjectGrants>, 'role' | 'scope'>, string[]][] = [
    ['developer on every project', person([all('developer')]), { role: 'developer', scope: EVERYWHERE }, []],
    ['developer on dev in each', person([on('dev', 'developer')]), { role: 'developer', scope: { projects: 'all', environments: { only: ['dev'] } } }, []],
    ['developer on dev and on staging', person([on('staging', 'developer'), on('dev', 'developer')]), { role: 'developer', scope: { projects: 'all', environments: { only: ['dev', 'staging'] } } }, []],
    ['auditor on every project', person([all('auditor')]), { role: 'auditor', scope: EVERYWHERE }, []],
    ['viewer on every project', person([all('viewer')]), { role: 'member', scope: EVERYWHERE }, ['viewer market', 'viewer billing']],
    ['viewer on dev in each', person([on('dev', 'viewer')]), { role: 'member', scope: EVERYWHERE }, ['viewer market/dev', 'viewer billing/dev']],
    ['maintainer on every project', person([all('maintainer')]), { role: 'developer', scope: EVERYWHERE }, ['maintainer market', 'maintainer billing']],
    ['owner on every project', person([all('owner')]), { role: 'developer', scope: EVERYWHERE }, ['owner market', 'owner billing']],
    ['an owner of 0.4', person([], { role: 'admin' }), { role: 'admin', scope: EVERYWHERE }, []],
    ['an owner of 0.4, owner on every project', person([all('owner')], { role: 'admin' }), { role: 'owner', scope: EVERYWHERE }, []],
    ['an owner of 0.4, maintainer on every project', person([all('maintainer')], { role: 'admin' }), { role: 'owner', scope: EVERYWHERE }, []],
    ['an owner of 0.4, developer on every project', person([all('developer')], { role: 'admin' }), { role: 'admin', scope: EVERYWHERE }, ['developer market', 'developer billing']],
    ['developer on every project, until a date', person([all('developer', 2_000)]), { role: 'member', scope: EVERYWHERE }, ['developer market', 'developer billing']],
    ['a service account, developer on dev in each', { ...person([on('dev', 'developer')]), person: false }, { role: 'member', scope: EVERYWHERE }, ['developer market/dev', 'developer billing/dev']],
  ];
  for (const [name, input, expected, grants] of cases) {
    const conversion = convertEveryProjectGrants(input);
    assert.deepEqual({ role: conversion.role, scope: conversion.scope }, expected, name);
    assert.deepEqual(conversion.grants.map((grant) => `${grant.role} ${grant.environmentId ?? grant.projectId}`), grants, name);
    // Whatever goes to project grants reaches no project made later.
    assert.equal(conversion.narrowed.some((loss) => loss.kind === 'later-projects'), grants.length > 0, name);
  }
});

const held = (place: string, role: Role, expiresAt: number | null = null) => {
  const [projectId, environment] = place.split('/');
  return { projectId: projectId!, environmentId: environment === undefined ? null : place, role, expiresAt };
};
const given = (conversion: ReturnType<typeof convertEveryProjectGrants>) =>
  conversion.grants.map((grant) => `${grant.role} ${grant.environmentId ?? grant.projectId}${grant.expiresAt === null ? '' : ` until ${grant.expiresAt}`}`);
const losses = (conversion: ReturnType<typeof convertEveryProjectGrants>) =>
  conversion.narrowed.flatMap((loss) => {
    if (loss.kind === 'environments') return [`${loss.role} on ${loss.projectId}'s environments`];
    if (loss.kind === 'lost') return [`lost ${loss.lost} on ${loss.environmentId ?? loss.projectId}, kept ${loss.kept}`];
    return [];
  });

test('a project grant they hold stays when the new one would not hold all it does, for as long', () => {
  const replaced = convertEveryProjectGrants(person([all('maintainer')], { grants: [held('market', 'viewer')] }));
  assert.deepEqual(replaced.grants.find((grant) => grant.projectId === 'market')?.replaces, 'viewer');
  // Where they hold it all already, nothing is added.
  const covered = convertEveryProjectGrants(person([all('viewer')], { grants: [held('market', 'owner')] }));
  assert.deepEqual(given(covered), ['viewer billing']);
});

test('where one grant cannot hold both, a project\'s goes on to its environments, and nothing is lost', () => {
  // W59's case: viewer on every project and auditor on billing kept auditor alone, and billing's values were lost.
  const auditor = convertEveryProjectGrants(person([all('viewer')], { grants: [held('billing', 'auditor')] }));
  assert.deepEqual(given(auditor), ['viewer market', 'viewer billing/dev']);
  assert.deepEqual(losses(auditor), ["viewer on billing's environments"]);
  assert.ok(allows({ isRootAdmin: false, role: auditor.role, scope: auditor.scope, grants: [held('billing', 'auditor'), ...auditor.grants] }, 'secret.read', { projectId: 'billing', environmentId: 'billing/dev', environmentSlug: 'dev' }));
  // The other way round, the auditor's goes down instead, and billing reads on.
  const service = convertEveryProjectGrants({ ...person([all('auditor')], { grants: [held('billing', 'viewer')] }), person: false });
  assert.deepEqual(given(service), ['auditor market', 'auditor billing', 'viewer billing/dev']);
  // A project grant that holds all of the new one but ends sooner stays, and the new one goes on to the environments, for good.
  const sooner = convertEveryProjectGrants(person([all('viewer')], { grants: [held('market', 'developer', 5_000)] }));
  assert.deepEqual(given(sooner), ['viewer market/dev', 'viewer market/prod', 'viewer billing']);
  assert.deepEqual(losses(sooner), ["viewer on market's environments"]);
  // A grant held for good is not given up for one that ends: the one that ends goes on to the environments.
  const lasting = convertEveryProjectGrants(person([all('maintainer', 5_000)], { grants: [held('market', 'viewer')] }));
  assert.deepEqual(given(lasting), ['maintainer market until 5000', 'viewer market/dev', 'viewer market/prod', 'maintainer billing until 5000']);
  // An environment where they read already needs nothing more.
  const below = convertEveryProjectGrants(person([all('viewer')], { grants: [held('billing', 'auditor'), held('billing/dev', 'developer')] }));
  assert.deepEqual(given(below), ['viewer market']);
});

test('where no grant can hold both, the one that reads stays and the loss is named', () => {
  // Neither maintainer nor access-manager goes on an environment.
  const service = convertEveryProjectGrants({ ...person([all('maintainer')], { grants: [held('market', 'access-manager')] }), person: false });
  assert.deepEqual(given(service), ['maintainer market', 'maintainer billing']);
  assert.equal(service.grants[0]?.replaces, 'access-manager');
  assert.deepEqual(losses(service), ['lost access-manager on market, kept maintainer']);
  // On an environment there is nowhere further to go.
  const environment = convertEveryProjectGrants(person([on('dev', 'viewer')], { grants: [held('market/dev', 'auditor')] }));
  assert.deepEqual(given(environment), ['viewer market/dev', 'viewer billing/dev']);
  assert.deepEqual(losses(environment), ['lost auditor on market/dev, kept viewer']);
  // Of two that read, the one they had stays.
  const both = convertEveryProjectGrants({ ...person([on('dev', 'developer', 5_000)], { grants: [held('market/dev', 'viewer')] }), person: false });
  assert.deepEqual(losses(both), ['lost developer on market/dev, kept viewer']);
});

// What a member held in 0.4, independently of the conversion: a grant on
// every project reached every project, those made later too, and one on a
// slug each environment of that slug; an owner managed every project and
// read the whole log.
type Before = { admin: boolean; everyProject: readonly EveryProjectGrant[]; grants: ConversionInput['grants'] };
function heldBefore(before: Before, permission: Permission, place: Place, at: number): boolean {
  const live = (expiresAt: number | null) => expiresAt === null || expiresAt > at;
  if (before.admin && (permission === 'audit.read' || (place.environmentId == null && PROJECT_ONLY_PERMISSIONS.includes(permission)))) return true;
  for (const grant of before.everyProject) {
    if (!live(grant.expiresAt) || !(ROLES[grant.role].permissions as readonly Permission[]).includes(permission)) continue;
    if (grant.environmentSlug === null || (place.environmentId != null && place.environmentSlug === grant.environmentSlug)) return true;
  }
  return before.grants.some((grant) =>
    live(grant.expiresAt)
    && grant.projectId === place.projectId
    && (grant.environmentId === null || grant.environmentId === place.environmentId)
    && (ROLES[grant.role].permissions as readonly Permission[]).includes(permission));
}

const roles = Object.keys(ROLES) as Role[];
const environmentRoles: Role[] = ['viewer', 'developer', 'auditor'];
const expiry = gs.sampledFrom([null, 1_000, 2_000]);
const everyProjectGrants = gs.record({
  all: gs.oneOf(gs.just(null), gs.record({ role: gs.sampledFrom(roles), expiresAt: expiry })),
  dev: gs.oneOf(gs.just(null), gs.record({ role: gs.sampledFrom(environmentRoles), expiresAt: expiry })),
  prod: gs.oneOf(gs.just(null), gs.record({ role: gs.sampledFrom(environmentRoles), expiresAt: expiry })),
}).map(({ all, dev, prod }) => [
  ...(all === null ? [] : [{ environmentSlug: null, ...all }]),
  ...(dev === null ? [] : [{ environmentSlug: 'dev', ...dev }]),
  ...(prod === null ? [] : [{ environmentSlug: 'prod', ...prod }]),
]);
const projectGrants = gs.arrays(
  gs.record({ place: gs.sampledFrom(['market', 'market/dev', 'market/prod', 'billing', 'billing/dev']), role: gs.sampledFrom(roles), expiresAt: expiry }),
  { maxSize: 4 },
).map((grants) => [...new Map(grants.map((grant) => [grant.place, grant])).values()].flatMap(({ place, role, expiresAt }) => {
  const [projectId, environment] = place.split('/');
  if (environment !== undefined && !environmentRoles.includes(role)) return [];
  return [{ projectId: projectId!, environmentId: environment === undefined ? null : place, role, expiresAt }];
}));

// A project made after the conversion, with an environment of each slug.
const later = { id: 'later', environments: [{ id: 'later/dev', slug: 'dev' }, { id: 'later/prod', slug: 'prod' }, { id: 'later/other', slug: 'other' }] };

const settings = propertySettings(128);
test(`nobody holds more after the conversion than before, nor less than it names, anywhere, at any time, seed ${settings.seed}`, () => hegel.test((tc) => {
  const input: ConversionInput = {
    person: tc.draw(gs.booleans()),
    role: 'member',
    everyProject: tc.draw(everyProjectGrants),
    grants: tc.draw(projectGrants),
    projects,
  };
  const admin = input.person && tc.draw(gs.booleans());
  if (admin) input.role = 'admin';
  const conversion = convertEveryProjectGrants(input);
  if (!input.person) assert.equal(conversion.role, 'member');
  // The grants they end with: those they held, but where one replaced it.
  const given = new Map(conversion.grants.map((grant) => [grant.environmentId ?? grant.projectId, grant]));
  const grants = [...input.grants.filter((grant) => !given.has(grant.environmentId ?? grant.projectId!)), ...given.values()];
  for (const at of [0, 1_500, 2_500]) {
    const after: Holdings = { isRootAdmin: false, role: conversion.role, scope: conversion.scope, grants: grants.filter((grant) => grant.expiresAt === null || grant.expiresAt > at) };
    for (const project of [...projects, later]) {
      const places: Place[] = [{ projectId: project.id }, ...project.environments.map((environment) => ({ projectId: project.id, environmentId: environment.id, environmentSlug: environment.slug }))];
      for (const place of places) {
        for (const permission of PERMISSIONS) {
          // Managing a project is asked of the project: on an environment it says nothing of its own.
          if (place.environmentId != null && PROJECT_ONLY_PERMISSIONS.includes(permission)) continue;
          if (allows(after, permission, place)) {
            assert.ok(heldBefore({ admin, ...input }, permission, place, at), JSON.stringify({ input, conversion, permission, place, at }));
          }
        }
      }
    }
  }
  // What they held in the projects there are now, they hold still, at any
  // time, but for what the conversion names: a role that went on to a
  // project's environments, on the project itself, and a role lost there.
  const exempt = (permission: Permission, place: Place) => conversion.narrowed.some((loss) =>
    (loss.kind === 'environments' && place.environmentId == null && loss.projectId === place.projectId && (ROLES[loss.role].permissions as readonly Permission[]).includes(permission))
    || (loss.kind === 'lost' && loss.projectId === place.projectId && (loss.environmentId === null || loss.environmentId === place.environmentId) && (ROLES[loss.lost].permissions as readonly Permission[]).includes(permission)));
  for (const at of [0, 1_500, 2_500]) {
    const after: Holdings = { isRootAdmin: false, role: conversion.role, scope: conversion.scope, grants: grants.filter((grant) => grant.expiresAt === null || grant.expiresAt > at) };
    for (const project of projects) {
      const places: Place[] = [{ projectId: project.id }, ...project.environments.map((environment) => ({ projectId: project.id, environmentId: environment.id, environmentSlug: environment.slug }))];
      for (const place of places) {
        for (const permission of PERMISSIONS) {
          if (place.environmentId != null && PROJECT_ONLY_PERMISSIONS.includes(permission)) continue;
          if (heldBefore({ admin, ...input }, permission, place, at) && !exempt(permission, place)) {
            assert.ok(allows(after, permission, place), JSON.stringify({ input, conversion, permission, place, at }));
          }
        }
      }
    }
  }
  // One grant to a place, and only roles an environment takes on one.
  assert.equal(given.size, conversion.grants.length);
  for (const grant of conversion.grants) assert.ok(grant.environmentId === null || assignableToEnvironment(grant.role), JSON.stringify(grant));
}, settings));
