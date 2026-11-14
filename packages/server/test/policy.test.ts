// The instance's roles and settings over HTTP on the 0.16 contract
// (docs/design/0.16.md, "The server"), in 0.14.7's shapes: the list, a
// change, and a change weighed first and made as weighed. What each costs,
// request-cost.test.ts holds. Cases from 0.14.7's roles-api and
// instance-roles tests where they still hold.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { INSTANCE_ROLES, normalDefinition, ROLES, type RoleDefinition } from '@coffre/core/access';
import { roleRevision } from '@coffre/core/vault';
import { credential, emptyDatabase, environment, grant, instance, principal, project, rows, user, write } from '@coffre/vault/testing';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { WEIGHED_MOST } from '../src/api/routes/roles.ts';
import { openApp } from './app-fixture.ts';

const app = await openApp();
const { world } = app;
after(() => app.close());

const [bo, cy, eve, fay, al] = ['bo', 'cy', 'eve', 'fay', 'al'].map(user) as [string, string, string, string, string];
const ci = 'token:ci';
const release: RoleDefinition = { name: 'Release', description: 'Ships.', permissions: ['secret.use', 'secret.write'], protected: ['secret.use'] };

/** A role's row as `definition` says it. */
const roleRow = (instance: boolean, id: string, definition: RoleDefinition) => ({ instance, id, ...normalDefinition(definition), permissions: [...definition.permissions], protected: [...definition.protected] });

/**
 * market: dev, prod (protected). billing: prod.
 *
 * Cy owns the instance, Fay runs it as its Admin, Al is an Admin scoped to
 * market. Bo develops market, as does ci, a service account; Eve views
 * market/prod. Every role is as it ships.
 */
let market: ReturnType<typeof project>;
let prod: ReturnType<typeof environment>;
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  const billing = project('billing');
  market = project('market');
  prod = environment(market, 'prod', { protected: true });
  const dev = environment(market, 'dev');
  await write(
    world,
    ...rows('projects', market, billing),
    // Bo's personal config of dev: his alone, which no change to a role reaches.
    ...rows('environments', dev, environment(market, 'dev-bo', { parentId: dev.id, owner: bo }), prod, environment(billing, 'prod')),
    ...rows('roles', ...Object.entries(ROLES).map(([id, definition]) => roleRow(false, id, definition)), ...Object.entries(INSTANCE_ROLES).map(([id, definition]) => roleRow(true, id, definition))),
    ...rows('principals', principal(cy, { role: 'owner' }), principal(fay, { role: 'admin' }), principal(al, { role: 'admin', scope: JSON.stringify({ projects: { only: [market.id] }, environments: 'all' }) }), principal(bo), principal(eve), principal(ci)),
    ...rows('policy', instance()),
    ...rows('grants', grant(bo, 'developer', { project: market }), grant(ci, 'developer', { project: market }), grant(eve, 'viewer', { environment: prod })),
    ...rows('credentials',
      ...[cy, fay, al, bo, eve].map((who) => credential(`${who.slice(5, who.indexOf('@'))}-cli`, who)),
      // Cy's token, scoped to own market: it holds nothing of the instance's own.
      credential('cy-token', cy, { kind: 'personal', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'owner' }]) })),
  );
  await app.request('/livez');
  await app.request('/api/me', { headers: { authorization: 'Bearer nobody' } });
  app.calls.length = 0;
});

type Body = { error?: string; reason?: string; message?: string } & Record<string, unknown>;
const call = async (label: string, method: string, path: string, body?: unknown): Promise<[number, Body]> => {
  const got = await app.request(`/api${path}`, { method, headers: { authorization: `Bearer ${label}` }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  return [got.status, (await got.json()) as Body];
};
/** What `run` answered, the vault's calls it made and the app's statements it ran. */
async function cost<T>(run: () => Promise<T>): Promise<[T, string[], number]> {
  const [calls, statements] = [app.calls.length, app.statements];
  const result = await run();
  return [result, app.calls.slice(calls), app.statements - statements];
}
const refused = (answer: [number, Body]) => [answer[0], answer[1].error, answer[1].reason];
const NO_ACCESS = [403, 'vault_refused', 'no_access'];
const BAD = [400, 'bad_request', undefined];

type RoleView = RoleDefinition & { id: string; builtin: boolean; edited: boolean; fixed: boolean; default: RoleDefinition | null; assignableToEnvironment: boolean; grants: number | null };
type Roles = { roles: RoleView[]; instanceRoles: RoleView[]; editable: boolean };
const roles = async (label: string): Promise<Roles> => {
  const [status, body] = await call(label, 'GET', '/roles');
  assert.equal(status, 200, JSON.stringify(body));
  return body as unknown as Roles;
};
/** What the instance's roles say now, as the vault's rows hold them. */
const stored = async () => JSON.stringify(await world.owner.execute(sql`SELECT instance, id, name, description, permissions, protected FROM roles ORDER BY instance, id`));

const developer = normalDefinition(ROLES.developer);
const narrowed: RoleDefinition = { ...developer, permissions: ['secret.use', 'secret.write'] };

test('every role, as the instance defines it, for any member', async () => {
  const listed = await roles('bo-cli');
  // Those that ship, in the order they ship, each with the grants that name it; the instance's, with the people who hold them.
  assert.deepEqual(listed.roles.map((role) => `${role.id} ${role.grants}`), ['viewer 1', 'contributor 0', 'developer 2', 'maintainer 0', 'access-manager 0', 'auditor 0', 'owner 0']);
  assert.deepEqual(listed.instanceRoles.map((role) => `${role.id} ${role.grants}`), ['member 2', 'auditor 0', 'developer 0', 'admin 2', 'owner 1']);
  assert.deepEqual(listed.roles[2], { id: 'developer', ...developer, builtin: true, edited: false, fixed: false, default: developer, assignableToEnvironment: true, grants: 2 });
  assert.deepEqual([listed.roles[3]!.assignableToEnvironment, listed.roles[6]!.fixed, listed.instanceRoles[0]!.fixed, listed.instanceRoles[3]!.assignableToEnvironment, listed.editable], [false, true, true, false, false]);

  // Editable to an Owner of the whole instance on their own session, and to no one else.
  assert.deepEqual(await Promise.all(['cy-cli', 'cy-token', 'fay-cli', 'al-cli'].map(async (label) => (await roles(label)).editable)), [true, false, false, false]);

  // A role edited, one an Owner made after those that ship, and a lapsed grant, which still names its role; a role with no row is no role.
  await write(world, ...rows('roles', roleRow(false, 'a-team', release), roleRow(false, 'release', release)),
    ...rows('grants', grant(eve, 'release', { project: market }, { expiresAt: new Date('2020-01-01T00:00:00Z') })));
  await world.owner.execute(sql`UPDATE roles SET permissions = '{secret.read}', protected = '{}' WHERE NOT instance AND id = 'viewer'`);
  await world.owner.execute(sql`DELETE FROM roles WHERE NOT instance AND id = 'contributor'`);
  const now = await roles('cy-cli');
  assert.deepEqual(now.roles.map((role) => `${role.id} ${role.grants}`), ['viewer 1', 'developer 2', 'maintainer 0', 'access-manager 0', 'auditor 0', 'owner 0', 'a-team 0', 'release 1']);
  assert.deepEqual(now.roles[0]!.edited, true);
  assert.deepEqual(now.roles[7], { id: 'release', ...release, builtin: false, edited: false, fixed: false, default: null, assignableToEnvironment: true, grants: 1 });
});

test('a change weighed says who would gain or lose what, and changes nothing; made with the revision that answered, it is made', async () => {
  const before = await stored();
  const [status, impact] = await call('cy-cli', 'PUT', '/roles/developer?dryRun=1', narrowed);
  assert.equal(status, 200, JSON.stringify(impact));
  // Bo loses reading where nothing is protected, and ci, a service account, which holds the first column everywhere, at prod too.
  assert.deepEqual(impact, {
    impact: [
      { change: 'narrows', permission: 'secret.read', protected: false, people: 1, services: 1, environments: 1, projects: 1, examples: ['ci on market/dev', 'bo@acme.example on market/dev'] },
      { change: 'narrows', permission: 'secret.read', protected: true, people: 0, services: 1, environments: 1, projects: 1, examples: ['ci on market/prod'] },
    ],
    sentence: 'Narrows secret.read for 1 person and 1 service account on market/dev; narrows secret.read for 1 service account on market/prod, protected',
    revision: roleRevision(developer),
  });
  assert.equal(await stored(), before);
  assert.deepEqual(app.calls.slice(-1), ['caller'], 'nothing asked of the vault but who calls');

  assert.deepEqual(await call('cy-cli', 'PUT', `/roles/developer?revision=${roleRevision(developer)}`, narrowed), [200, { role: { id: 'developer', ...narrowed, builtin: true, edited: true, fixed: false, default: developer, assignableToEnvironment: true, grants: null } }]);
  // Weighed from the role as it was: it changed since, so it is weighed again.
  assert.deepEqual(refused(await call('cy-cli', 'DELETE', `/roles/developer?revision=${roleRevision(developer)}`)), [409, 'conflict', 'policy_changed']);
  // With no revision, made from the role as it is: put back as it ships.
  assert.deepEqual(await call('cy-cli', 'DELETE', '/roles/developer'), [200, { role: { id: 'developer', ...developer, builtin: true, edited: false, fixed: false, default: developer, assignableToEnvironment: true, grants: null } }]);

  // An instance role weighed: the Admin's, without managing access, reaches Fay and Al, Al in market alone.
  const admin = normalDefinition(INSTANCE_ROLES.admin);
  const [, weighed] = await call('cy-cli', 'PUT', '/instance-roles/admin?dryRun=1', { ...admin, permissions: admin.permissions.filter((permission) => permission !== 'grant.manage') });
  assert.deepEqual(weighed.impact, [{ change: 'narrows', permission: 'grant.manage', protected: false, people: 2, services: 0, environments: 0, projects: 2, examples: ['al@acme.example on market', 'fay@acme.example on billing', 'fay@acme.example on market'] }]);
  assert.equal(weighed.revision, roleRevision(admin));
  // Nothing changes for anyone: said so.
  const [, idle] = await call('cy-cli', 'PUT', '/roles/auditor?dryRun=1', { ...normalDefinition(ROLES.auditor), name: 'Inspector' });
  assert.deepEqual([idle.impact, idle.sentence], [[], 'Changes what nobody holds']);
});

test(`a change is weighed across at most ${WEIGHED_MOST} roles, members, grants of one and environments: past any, refused, named, and made unweighed`, async () => {
  const [most, auditor, viewer] = [WEIGHED_MOST, normalDefinition(INSTANCE_ROLES.auditor), normalDefinition(ROLES.viewer)];
  // Each read the three; one past the most roles, the first alone. `took`: the rows each of them answered.
  const took = (read: number) => app.answered.slice(-read) as [[{ roles: unknown[]; granted: number | string }], { grants: unknown[] | null }[]?, unknown[]?];
  const weighed = async (path: string, definition: unknown, read = 3) => {
    const [[status, body], calls, statements] = await cost(() => call('cy-cli', 'PUT', `${path}?dryRun=1`, definition));
    assert.deepEqual([calls, statements], [['caller'], read]);
    return status === 200 ? [200] : [...refused([status, body]), body.message];
  };
  const counted = async (query: ReturnType<typeof sql>) => Number((await rowsOf<{ n: number | string }>(world.owner, query))[0]!.n);
  const tooMany = (what: string) => [409, 'conflict', 'too_many_to_weigh', `too much to weigh: more than 1,000 ${what}. Make the change without weighing it first`];
  // Copies of Bo's row, of market/dev's and of Eve's grant on market/prod: the rows a weighing reads as they are.
  const members = (from: number, to: number, role: string) => world.owner.execute(sql`INSERT INTO principals (id, status, role, scope, generation, created_at, created_by, status_changed_at, status_changed_by, mac)
    SELECT 'user:m' || i || '@acme.example', 'active', ${role}, NULL, generation, created_at, created_by, status_changed_at, status_changed_by, mac FROM principals, generate_series(${from}::int, ${to}::int) i WHERE id = ${bo}`);
  const environments = (from: number, to: number) => world.owner.execute(sql`INSERT INTO environments (id, project_id, slug, name, created_at, protected, frozen_credentials, mac)
    SELECT gen_random_uuid(), project_id, 'e' || i, 'e' || i, created_at, false, '{}', mac FROM environments, generate_series(${from}::int, ${to}::int) i WHERE id = ${prod.id}`);

  // The instance's Auditors: as many as it weighs, then two more, of which it reads one.
  const existing = await counted(sql`SELECT count(*) AS n FROM principals WHERE role = 'auditor'`);
  await members(1, most - existing, 'auditor');
  assert.deepEqual(await weighed('/instance-roles/auditor', { ...auditor, name: 'Inspector' }), [200]);
  await members(most - existing + 1, most - existing + 2, 'auditor');
  assert.deepEqual(await weighed('/instance-roles/auditor', { ...auditor, name: 'Inspector' }), tooMany('members it reaches'));
  assert.equal(took(3)[1]!.length, most + 1);
  // Made unweighed, it is made.
  assert.equal((await call('cy-cli', 'PUT', '/instance-roles/auditor', { ...auditor, name: 'Inspector' }))[0], 200);

  // Eve views market/prod: market's environments, as many as it weighs, then two more, of which it reads one.
  const places = await counted(sql`SELECT count(*) AS n FROM environments WHERE project_id = ${market.id}`);
  await environments(1, most - places);
  assert.deepEqual(await weighed('/roles/viewer', { ...viewer, name: 'Reader' }), [200]);
  await environments(most - places + 1, most - places + 2);
  assert.deepEqual(await weighed('/roles/viewer', { ...viewer, name: 'Reader' }), tooMany('environments where it reaches'));
  assert.equal(took(3)[2]!.length, most + 1);

  // Eve given a release grant on more environments than it weighs: one member's grants, and its deletion counts them.
  await environments(most - places + 3, most - places + 3);
  await write(world, ...rows('roles', roleRow(false, 'release', release)));
  await world.owner.execute(sql`INSERT INTO grants (id, principal, generation, environment_id, role, granted_at, granted_by, mac)
    SELECT gen_random_uuid(), g.principal, g.generation, e.id, 'release', g.granted_at, g.granted_by, g.mac FROM grants g, environments e WHERE g.principal = ${eve} AND e.project_id = ${market.id} AND e.id <> ${prod.id}`);
  assert.deepEqual(await weighed('/roles/release', { ...release, name: 'Shipper' }), tooMany('grants of one member it reaches'));
  assert.deepEqual(took(3)[1]!.map((member) => member.grants?.length), [most + 1]);
  const [[status, body], calls, statements] = await cost(() => call('cy-cli', 'DELETE', '/roles/release?dryRun=1'));
  assert.deepEqual([...refused([status, body]), body.message, calls, statements], [409, 'conflict', 'role_granted', 'more than 1,000 grants name release: revoke them first', ['caller'], 1]);
  assert.equal(Number(took(1)[0][0].granted), most + 1);

  // Roles: as many as it weighs, then two more, of which it reads one.
  const roles = await counted(sql`SELECT count(*) AS n FROM roles`);
  const made = (from: number, to: number) => world.owner.execute(sql`INSERT INTO roles (instance, id, name, description, permissions, protected, mac)
    SELECT false, 'r-' || i, 'R', '', permissions, protected, mac FROM roles, generate_series(${from}::int, ${to}::int) i WHERE NOT instance AND id = 'auditor'`);
  await made(1, most - roles);
  assert.deepEqual(await weighed('/roles/auditor', { ...normalDefinition(ROLES.auditor), name: 'Inspector' }), [200]);
  await made(most - roles + 1, most - roles + 2);
  assert.deepEqual(await weighed('/roles/auditor', { ...normalDefinition(ROLES.auditor), name: 'Inspector' }, 1), tooMany('roles'));
  assert.equal(took(1)[0][0].roles.length, most + 1);
});

test('roles defined, put back and deleted: a grant naming one an Owner made refuses its deletion, and one not there is not found', async () => {
  const change = (label: string, method: string, path: string, body?: unknown) => cost(() => call(label, method, path, body));
  assert.deepEqual((await change('cy-cli', 'PUT', '/roles/release', release))[0], [200, { role: { id: 'release', ...release, builtin: false, edited: false, fixed: false, default: null, assignableToEnvironment: true, grants: null } }]);
  assert.deepEqual((await call('cy-cli', 'PATCH', `/access/${eve}`, { market: 'release' }))[0], 200);
  assert.deepEqual(refused((await change('cy-cli', 'DELETE', '/roles/release'))[0]), [409, 'conflict', 'role_granted']);
  // Weighing it says the same, with how many.
  const [weighedDeletion] = await change('cy-cli', 'DELETE', '/roles/release?dryRun=1');
  assert.deepEqual([...refused(weighedDeletion), weighedDeletion[1].message], [409, 'conflict', 'role_granted', '1 grant names release: revoke it first']);
  assert.deepEqual((await call('cy-cli', 'PATCH', `/access/${eve}`, { market: null }))[0], 200);
  assert.deepEqual((await change('cy-cli', 'DELETE', '/roles/release'))[0], [200, { role: null }]);
  assert.deepEqual(refused((await change('cy-cli', 'DELETE', '/roles/release'))[0]), [404, 'not_found', undefined]);
  assert.deepEqual(refused((await change('cy-cli', 'DELETE', '/roles/release?dryRun=1'))[0]), [404, 'not_found', undefined]);
  // A role that ships takes nothing only a project has while a grant on an environment names it: Eve views market/prod.
  const wide = { ...normalDefinition(ROLES.viewer), permissions: ['secret.read', 'secret.use', 'environment.manage'] };
  assert.deepEqual(refused((await change('cy-cli', 'PUT', '/roles/viewer', wide))[0]), [409, 'conflict', 'invalid']);

  // An Admin's role edited and put back; an Auditor's.
  const admin = normalDefinition(INSTANCE_ROLES.admin);
  const lesser = { ...admin, permissions: ['audit.read', 'grant.manage'], protected: ['audit.read'] };
  assert.deepEqual((await change('cy-cli', 'PUT', '/instance-roles/admin', lesser))[0][1], { role: { id: 'admin', ...lesser, builtin: true, edited: true, fixed: false, default: admin, assignableToEnvironment: false, grants: null } });
  assert.deepEqual((await change('cy-cli', 'DELETE', `/instance-roles/admin?revision=${roleRevision(lesser as RoleDefinition)}`))[0][1], { role: { id: 'admin', ...admin, builtin: true, edited: false, fixed: false, default: admin, assignableToEnvironment: false, grants: null } });
  assert.deepEqual((await roles('cy-cli')).instanceRoles.find((role) => role.id === 'admin')!.edited, false);
});

test('only an Owner of the whole instance changes or weighs a role; what the vault would take as a fault is told before any call', async () => {
  const before = await stored();
  for (const label of ['fay-cli', 'al-cli', 'bo-cli', 'cy-token']) {
    assert.deepEqual(refused((await cost(() => call(label, 'PUT', '/roles/developer', narrowed)))[0]), NO_ACCESS, label);
    const [weighed, calls, statements] = await cost(() => call(label, 'PUT', '/roles/developer?dryRun=1', narrowed));
    assert.deepEqual([...refused(weighed), calls, statements], [...NO_ACCESS, ['caller'], 0], label);
  }
  assert.deepEqual(refused(await call('nobody', 'DELETE', '/instance-roles/auditor')), [401, 'unauthenticated', 'unauthenticated']);
  assert.equal(await stored(), before);

  const asked = app.calls.length;
  const bads: [string, string, unknown, number][] = [
    ['PUT', '/roles/owner', developer, 400], ['DELETE', '/roles/owner', undefined, 400], ['PUT', '/instance-roles/owner', developer, 400], ['DELETE', '/instance-roles/member', undefined, 400],
    ['PUT', '/instance-roles/boss', developer, 404], ['PUT', '/roles/Release', release, 400], ['PUT', '/roles/r', release, 400],
    ['PUT', '/roles/release', { ...release, name: ' ' }, 400], ['PUT', '/roles/release', { ...release, protected: ['secret.read'] }, 400], ['PUT', '/roles/release', { ...release, permissions: ['secret.fly'] }, 400],
    ['PUT', '/roles/release', { ...release, extra: 1 }, 400], ['PUT', '/roles/release?revision=57.3f9a0c2e81b4d7a6', release, 400], ['PUT', '/roles/release?force=1', release, 400],
  ];
  for (const [method, path, body, status] of bads) assert.equal((await call('cy-cli', method, path, body))[0], status, `${method} ${path} ${JSON.stringify(body)}`);
  assert.equal(app.calls.length, asked);
});

test('an instance role whose row is gone, or not the vault\'s, is none: its holder runs nothing, reads no settings and edits no role', async () => {
  // Fay's Admin row edited around the vault, then deleted; Cy's Owner row the same.
  for (const change of [sql`UPDATE roles SET description = 'Runs it.' WHERE instance AND id = 'admin'`, sql`DELETE FROM roles WHERE instance AND id = 'admin'`]) {
    await world.owner.execute(change);
    world.memory.callers.clear();
    assert.deepEqual(refused(await call('fay-cli', 'GET', '/settings')), NO_ACCESS);
  }
  for (const change of [sql`UPDATE roles SET description = 'Everything.' WHERE instance AND id = 'owner'`, sql`DELETE FROM roles WHERE instance AND id = 'owner'`]) {
    await world.owner.execute(change);
    world.memory.callers.clear();
    assert.deepEqual([(await roles('cy-cli')).editable, refused(await call('cy-cli', 'GET', '/settings'))], [false, NO_ACCESS]);
    assert.deepEqual(refused(await call('cy-cli', 'PUT', '/roles/developer?dryRun=1', narrowed)), NO_ACCESS);
  }
});

test("the instance's settings: read by whoever runs it, and set in one change", async () => {
  const everywhere = { projects: 'all', environments: 'all' };
  assert.deepEqual(await call('fay-cli', 'GET', '/settings'), [200, { serviceAccounts: everywhere }]);
  for (const label of ['al-cli', 'bo-cli', 'cy-token']) assert.deepEqual(refused((await cost(() => call(label, 'GET', '/settings')))[0]), NO_ACCESS, label);

  // Set by slug, either filter left out is all, and answered as the row now holds it.
  const asked = { projects: { only: ['market', 'billing', 'market'] }, environments: { except: ['prod'] } };
  const set = { projects: { only: ['billing', 'market'] }, environments: { except: ['prod'] } };
  assert.deepEqual(await call('fay-cli', 'PUT', '/settings', { serviceAccounts: asked }), [200, { serviceAccounts: set }]);
  assert.deepEqual((await call('cy-cli', 'GET', '/settings'))[1], { serviceAccounts: set });
  assert.deepEqual((await call('cy-cli', 'PUT', '/settings', { serviceAccounts: { environments: { only: ['dev'] } } }))[1], { serviceAccounts: { projects: 'all', environments: { only: ['dev'] } } });
  // A project renamed is shown by its slug now; one deleted, not at all.
  await call('cy-cli', 'PUT', '/settings', { serviceAccounts: { projects: { except: ['market', 'billing'] } } });
  await world.owner.execute(sql`UPDATE projects SET slug = 'shop' WHERE id = ${market.id}`);
  await world.owner.execute(sql`UPDATE projects SET slug = 'billing~1' WHERE slug = 'billing'`);
  assert.deepEqual((await call('cy-cli', 'GET', '/settings'))[1], { serviceAccounts: { projects: { except: ['shop'] }, environments: 'all' } });

  // The vault refuses: whoever does not run the instance, a project not there.
  assert.deepEqual(refused(await call('al-cli', 'PUT', '/settings', { serviceAccounts: everywhere })), NO_ACCESS);
  assert.deepEqual(refused(await call('cy-cli', 'PUT', '/settings', { serviceAccounts: { projects: { only: ['nope'] } } })), NO_ACCESS);
  // A policy row gone is the vault's to say, and the read says it too.
  await world.owner.execute(sql`DELETE FROM policy`);
  assert.deepEqual(refused(await call('cy-cli', 'GET', '/settings')), [500, 'tampered', 'tampered']);
  assert.deepEqual(refused(await call('cy-cli', 'PUT', '/settings', { serviceAccounts: everywhere })), [500, 'tampered', 'tampered']);

  const before = app.calls.length;
  for (const bad of [{}, { serviceAccounts: { projects: 'some' } }, { serviceAccounts: everywhere, extra: 1 }, { serviceAccounts: { projects: { only: ['Market'] } } }]) {
    assert.deepEqual(refused(await call('cy-cli', 'PUT', '/settings', bad)), BAD, JSON.stringify(bad));
  }
  assert.equal(app.calls.length, before);
});
