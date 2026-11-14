// The instance's policy (src/ops/access.ts): roles defined, edited, put back or
// deleted (`policy.change`), and where people set up service accounts
// (`settings.change`), through the contract as the app calls it: who may, what
// is written, what its entry names, what a use right after is answered, each
// refusal writing nothing, and two changes side by side.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { INSTANCE_ROLES, normalDefinition, ROLES, type RoleDefinition } from '@coffre/core/access';
import { roleRevision, type Change, type Presented } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { commit, prepare } from '../src/change.ts';
import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { OPERATIONS } from '../src/ops/index.ts';
import { emptyDatabase, openTestVault } from './database.ts';
import { amend, binding, credential, environment, grant, instance, principal, project, rows, secret, session, tokenOf, user, value, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
after(() => world.close());
const deciding = { workloads: world.workloads, owners: world.owners };

const [ada, fay, sam, bo, eve] = ['ada', 'fay', 'sam', 'bo', 'eve'].map(user) as [string, string, string, string, string];
const api = 'token:api';
const release: RoleDefinition = { name: 'Release', description: 'Ships.', permissions: ['secret.use', 'secret.write'], protected: ['secret.use'] };
const frozenAt = new Date(Date.UTC(2026, 0, 2));
let market: ReturnType<typeof project>;
let billing: ReturnType<typeof project>;
let prod: ReturnType<typeof environment>;

/** A role's row as it ships, or as `definition` says. */
const roleRow = (instance: boolean, id: string, definition: RoleDefinition) => ({ instance, id, ...normalDefinition(definition), permissions: [...definition.permissions], protected: [...definition.protected] });

beforeEach(async () => {
  await emptyDatabase(world.owner);
  world.memory.reads.clear();
  world.memory.logged.clear();
  world.refused.clear();
  market = project('market');
  billing = project('billing');
  prod = environment(market, 'prod');
  const scoped = JSON.stringify({ projects: { only: [market.id] }, environments: 'all' });
  await write(world, ...rows('projects', market, billing), ...rows('environments', prod, environment(billing, 'prod')),
    ...rows('secrets', value(world, secret(prod, 'DATABASE_URL'), 'postgres://market')),
    ...rows('roles', ...Object.entries(ROLES).map(([id, definition]) => roleRow(false, id, definition)), ...Object.entries(INSTANCE_ROLES).map(([id, definition]) => roleRow(true, id, definition))),
    // Ada owns the instance; Fay runs it as its Admin; Sam is an Owner of market alone; Bo develops market; Eve views market's prod.
    ...rows('principals', principal(ada, { role: 'owner' }), principal(fay, { role: 'admin' }), principal(sam, { role: 'owner', scope: scoped }), principal(bo), principal(eve), principal(api)),
    ...rows('policy', instance()),
    ...rows('grants', grant(bo, 'developer', { project: market }), grant(eve, 'viewer', { environment: prod })),
    ...rows('credentials', ...[ada, fay, sam, bo, eve].map((who) => credential(`${who.slice(5, who.indexOf('@'))}-cli`, who)),
      credential('ada-pat', ada, { kind: 'personal', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'owner' }]) })));
  world.woken.length = 0;
});

const shown = (label: string): Presented => ({ token: tokenOf(label).toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7' });
/** A role's change, `was` the role as its preview weighed it (none, null), sent as its revision; left out, none is sent. */
type RoleAsk = { instance?: boolean; role: string; definition: RoleDefinition | null; was?: RoleDefinition | null };
const asked = (label: string, { was, ...ask }: RoleAsk): Presented & Extract<Change, { op: 'policy.change' }> =>
  ({ ...shown(label), op: 'policy.change', instance: false, ...ask, ...(was === undefined ? {} : { revision: roleRevision(was) }) });
const edit = (label: string, ask: RoleAsk) => vault.change<'policy.change'>(asked(label, ask));
type Filters = { projects: unknown; environments: unknown };
const settingAsked = (label: string, serviceAccounts: Filters): Presented & Extract<Change, { op: 'settings.change' }> => ({ ...shown(label), op: 'settings.change', serviceAccounts: serviceAccounts as never });
const setting = (label: string, serviceAccounts: Filters) => vault.change<'settings.change'>(settingAsked(label, serviceAccounts));

/** What a reveal of market/prod's `DATABASE_URL` by `label` is answered: the value, or why not. */
const reveals = async (label: string) => {
  const answer = await vault.use({ ...shown(label), project: 'market', environment: 'prod', mine: false, keys: ['DATABASE_URL'], purpose: 'reveal', upstream: null });
  return 'refused' in answer ? answer.refused : answer.values.map((item) => ('refused' in item ? item.refused : item.value))[0];
};
const roleOf = async (instance: boolean, id: string) =>
  (await rowsOf<{ name: string; description: string; permissions: string[]; protected: string[] }>(world.owner, sql`SELECT name, description, permissions, protected FROM roles WHERE instance = ${instance} AND id = ${id}`))[0];
const policyRow = async () => (await rowsOf<{ service_accounts: string; workloads_frozen_at: Date | null; changed_by: string }>(world.owner, sql`SELECT service_accounts, workloads_frozen_at, changed_by FROM policy`))[0];
const state = async () => JSON.stringify([await rowsOf(world.owner, sql`SELECT * FROM roles ORDER BY instance, id`), await rowsOf(world.owner, sql`SELECT * FROM policy`)]);
const kept = async () => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM log_pending WHERE kept`))[0]!.n;
const refusals = async () =>
  (await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE NOT kept ORDER BY id`)).map((found) => entryOf(world.keys, found)!);
const written = async () => {
  const [found] = await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE kept ORDER BY id DESC LIMIT 1`);
  return entryOf(world.keys, found!)!;
};
const named = (entry: Awaited<ReturnType<typeof written>>) =>
  entry.rows.map(({ row: name, was, now }) => `${(JSON.parse(name) as string[])[0]} ${was === null ? 'made' : now === null ? 'dropped' : was === now ? 'read' : 'replaced'}`).sort();
/** Nothing written by `run`: no change's entry, no role or policy moved. Its refusal may be logged. */
async function nothingWritten(run: () => Promise<void>) {
  const before = [await kept(), await state()];
  await run();
  assert.deepEqual([await kept(), await state()], before);
}

const developer = normalDefinition(ROLES.developer);
const narrowed: RoleDefinition = { ...developer, permissions: ['secret.use', 'secret.write'] };

test('an Owner of the whole instance edits a role, and a use by whoever holds it is answered as it says right after; put back, it is as it ships', async () => {
  assert.equal(await reveals('bo-cli'), 'postgres://market');
  world.woken.length = 0;
  assert.deepEqual(await edit('ada-cli', { role: 'developer', definition: narrowed, was: developer }), { answer: { role: narrowed } });
  assert.deepEqual(await roleOf(false, 'developer'), { ...narrowed, permissions: ['secret.use', 'secret.write'], protected: ['secret.use', 'secret.write'] });
  const entry = await written();
  assert.deepEqual([entry.action, entry.actor, entry.detail], ['policy.change', ada, { role: 'developer', instance: false, definition: narrowed, was: developer }]);
  assert.ok(entry.objects.includes('role:developer'), entry.objects.join());
  // Who asked and what lets them, and the role: no grant, no other role.
  assert.deepEqual(named(entry), ['credentials read', 'principals read', 'roles read', 'roles replaced']);
  assert.equal(world.woken.length, 1);
  world.tick(2000);
  assert.equal(await reveals('bo-cli'), 'no_access');

  // Put back, as it ships.
  assert.deepEqual(await edit('ada-cli', { role: 'developer', definition: null, was: narrowed }), { answer: { role: developer } });
  assert.deepEqual(await roleOf(false, 'developer'), developer);
  world.tick(2000);
  assert.equal(await reveals('bo-cli'), 'postgres://market');

  // Asked as it is, it changes nothing, and says so.
  const before = await state();
  assert.deepEqual(await edit('ada-cli', { role: 'developer', definition: developer, was: developer }), { answer: { role: developer } });
  assert.equal(await state(), before);
  assert.deepEqual((await written()).detail, { role: 'developer', instance: false, definition: developer, was: developer, unchanged: true });
});

test('a role an Owner makes, granted, refused deletion while any grant names it, lapsed or not, and deleted once none does', async () => {
  assert.deepEqual(await edit('ada-cli', { role: 'release', definition: release, was: null }), { answer: { role: release } });
  assert.ok(named(await written()).includes('roles made'));
  assert.deepEqual(await vault.change<'access.grant'>({ ...shown('fay-cli'), op: 'access.grant', principal: eve, changes: [{ project: 'billing', environment: null, role: 'release', expiresAt: null }] }), { answer: { changes: ['created'] } });
  // Lapsed, it names the role all the same.
  await write(world, ...rows('grants', grant(bo, 'release', { project: billing }, { expiresAt: new Date(world.now() - 1000) })));
  await nothingWritten(async () => assert.deepEqual(await edit('ada-cli', { role: 'release', definition: null, was: release }), { refused: 'role_granted' }));
  const [refused] = await refusals();
  assert.deepEqual([refused!.action, refused!.actor, refused!.detail, refused!.objects.includes('role:release')], ['policy.change', ada, { refused: 'role_granted' }, true]);

  await world.owner.execute(sql`DELETE FROM grants WHERE role = 'release' AND principal = ${bo}`);
  await nothingWritten(async () => assert.deepEqual(await edit('ada-cli', { role: 'release', definition: null, was: release }), { refused: 'role_granted' }));
  assert.deepEqual(await vault.change<'access.grant'>({ ...shown('fay-cli'), op: 'access.grant', principal: eve, changes: [{ project: 'billing', environment: null, role: null, expiresAt: null }] }), { answer: { changes: ['revoked'] } });
  assert.deepEqual(await edit('ada-cli', { role: 'release', definition: null, was: release }), { answer: { role: null } });
  assert.equal(await roleOf(false, 'release'), undefined);
  const deleted = await written();
  // The one grant read to refuse is none: the role, dropped.
  assert.deepEqual([deleted.detail, named(deleted)], [{ role: 'release', instance: false, definition: null, was: release }, ['credentials read', 'principals read', 'roles dropped', 'roles read']]);
  // Nothing left to delete; and seen as there, it is not.
  await nothingWritten(async () => assert.deepEqual(await edit('ada-cli', { role: 'release', definition: null, was: null }), { refused: 'invalid' }));
  await nothingWritten(async () => assert.deepEqual(await edit('ada-cli', { role: 'release', definition: null, was: release }), { refused: 'policy_changed' }));
  // Gone, it is given no more.
  await nothingWritten(async () => assert.deepEqual(await vault.change<'access.grant'>({ ...shown('fay-cli'), op: 'access.grant', principal: eve, changes: [{ project: 'billing', environment: null, role: 'release', expiresAt: null }] }), { refused: 'invalid' }));
});

test('a role that does not ship is defined only while no grant names it: one hidden from its deletion and put back refuses it, and gives nothing meanwhile', async () => {
  assert.deepEqual(await edit('ada-cli', { role: 'release', definition: release, was: null }), { answer: { role: release } });
  assert.deepEqual(await vault.change<'access.grant'>({ ...shown('fay-cli'), op: 'access.grant', principal: bo, changes: [{ project: 'billing', environment: null, role: 'release', expiresAt: null }] }), { answer: { changes: ['created'] } });
  // A writer hides Bo's grant, Ada deletes the role, and the writer puts the grant back.
  await world.owner.execute(sql`DELETE FROM grants WHERE principal = ${bo} AND role = 'release'`);
  assert.deepEqual(await edit('ada-cli', { role: 'release', definition: null, was: release }), { answer: { role: null } });
  await write(world, ...rows('grants', grant(bo, 'release', { project: billing })));
  // Defining the role again would give it back to Bo: refused, as a deletion is.
  await nothingWritten(async () => assert.deepEqual(await edit('ada-cli', { role: 'release', definition: release, was: null }), { refused: 'role_granted' }));
  const [refused] = await refusals();
  assert.deepEqual([refused!.action, refused!.detail], ['policy.change', { refused: 'role_granted' }]);
  // Meanwhile it names no role, gives nothing and breaks nothing: Bo reads market's prod by his grant on market.
  assert.equal(await reveals('bo-cli'), 'postgres://market');
  // With no grant naming it, it is defined; and a role that ships, put back, never asks.
  await world.owner.execute(sql`DELETE FROM grants WHERE principal = ${bo} AND role = 'release'`);
  assert.deepEqual(await edit('ada-cli', { role: 'release', definition: release, was: null }), { answer: { role: release } });
  await world.owner.execute(sql`DELETE FROM roles WHERE NOT instance AND id = 'viewer'`);
  assert.deepEqual(await edit('ada-cli', { role: 'viewer', definition: null, was: null }), { answer: { role: normalDefinition(ROLES.viewer) } });
});

test('a role granted on an environment takes nothing only a project has; one granted on projects alone does', async () => {
  const wider: RoleDefinition = { ...normalDefinition(ROLES.viewer), permissions: ['secret.read', 'secret.use', 'environment.manage'] };
  await nothingWritten(async () => assert.deepEqual(await edit('ada-cli', { role: 'viewer', definition: wider, was: normalDefinition(ROLES.viewer) }), { refused: 'invalid' }));
  // Developer is granted on market alone.
  const managing: RoleDefinition = { ...developer, permissions: [...developer.permissions, 'environment.manage'] };
  assert.deepEqual(await edit('ada-cli', { role: 'developer', definition: managing, was: developer }), { answer: { role: managing } });
  // Put back as it ships is held to the same: Owner, as it ships, holds project-wide permissions.
  await write(world, ...rows('grants', grant(fay, 'maintainer', { environment: prod })));
  const maintainer = normalDefinition(ROLES.maintainer);
  await nothingWritten(async () => assert.deepEqual(await edit('ada-cli', { role: 'maintainer', definition: maintainer, was: maintainer }), { refused: 'invalid' }));
});

test('a grant naming a role, edited around the vault, refuses its deletion and its widening as tampered, though a genuine one stands behind it', async () => {
  assert.deepEqual(await edit('ada-cli', { role: 'release', definition: release, was: null }), { answer: { role: release } });
  // A genuine grant on an environment, and in front of it, the first by id, one whose row the vault did not write.
  await write(world, ...rows('grants', grant(fay, 'release', { environment: prod }), grant(bo, 'release', { environment: prod })));
  await world.owner.execute(sql`UPDATE grants SET id = '00000000-0000-0000-0000-000000000000' WHERE principal = ${bo} AND role = 'release'`);
  await nothingWritten(async () => assert.deepEqual(await edit('ada-cli', { role: 'release', definition: null, was: release }), { refused: 'tampered' }));
  const wider: RoleDefinition = { ...release, permissions: [...release.permissions, 'environment.manage'] };
  await nothingWritten(async () => assert.deepEqual(await edit('ada-cli', { role: 'release', definition: wider, was: release }), { refused: 'tampered' }));
});

test('a role that ships, its row deleted around the vault, is put back; an edited one is not written over; one changed since it was seen is refused', async () => {
  await world.owner.execute(sql`DELETE FROM roles WHERE NOT instance AND id = 'viewer'`);
  world.tick(2000);
  assert.equal(await reveals('eve-cli'), 'no_access', 'a role with no row is no role');
  await nothingWritten(async () => assert.deepEqual(await edit('ada-cli', { role: 'viewer', definition: null, was: normalDefinition(ROLES.viewer) }), { refused: 'policy_changed' }));
  assert.deepEqual(await edit('ada-cli', { role: 'viewer', definition: null, was: null }), { answer: { role: normalDefinition(ROLES.viewer) } });
  assert.ok(named(await written()).includes('roles made'));
  world.tick(2000);
  assert.equal(await reveals('eve-cli'), 'postgres://market');

  await world.owner.execute(sql`UPDATE roles SET permissions = '{secret.read,secret.use,secret.write}' WHERE NOT instance AND id = 'viewer'`);
  await nothingWritten(async () => assert.deepEqual(await edit('ada-cli', { role: 'viewer', definition: null, was: normalDefinition(ROLES.viewer) }), { refused: 'tampered' }));
  await nothingWritten(async () => assert.deepEqual(await edit('ada-cli', { role: 'viewer', definition: null, was: null }), { refused: 'tampered' }));
});

test('instance roles: an Admin\'s and an Auditor\'s edited and put back; two Owners editing one role at once, the second is refused', async () => {
  const admin = normalDefinition(INSTANCE_ROLES.admin);
  const lesser: RoleDefinition = { ...admin, permissions: ['audit.read', 'grant.manage'], protected: ['audit.read'] };
  assert.deepEqual(await edit('ada-cli', { instance: true, role: 'admin', definition: lesser, was: admin }), { answer: { role: lesser } });
  assert.deepEqual(await roleOf(true, 'admin'), lesser);
  assert.deepEqual(await roleOf(false, 'admin'), undefined, 'a project role of that id is another role');
  assert.ok((await written()).objects.includes('instance-role:admin'));
  assert.deepEqual(await edit('ada-cli', { instance: true, role: 'admin', definition: null, was: lesser }), { answer: { role: admin } });

  // Both decide from the role as it was: the one that commits second reads another row, starts over, and is refused.
  await write(world, ...rows('principals', principal(user('oz'), { role: 'owner' })), ...rows('credentials', credential('oz-cli', user('oz'))));
  const auditor = normalDefinition(INSTANCE_ROLES.auditor);
  const first = OPERATIONS['policy.change'](asked('ada-cli', { instance: true, role: 'auditor', definition: { ...auditor, description: 'One.' }, was: auditor }), deciding);
  const second = OPERATIONS['policy.change'](asked('oz-cli', { instance: true, role: 'auditor', definition: { ...auditor, description: 'Two.' }, was: auditor }), deciding);
  const [one, two] = await Promise.all([prepare(world, first), prepare(world, second)]);
  assert.ok(!('refused' in one!) && !('refused' in two!), 'each decided alone');
  assert.equal(await commit(world, one), true);
  assert.equal(await commit(world, two), false);
  assert.deepEqual(await vault.change<'policy.change'>(asked('oz-cli', { instance: true, role: 'auditor', definition: { ...auditor, description: 'Two.' }, was: auditor })), { refused: 'policy_changed' });
  assert.equal((await roleOf(true, 'auditor'))!.description, 'One.');
});

test('a deletion beside a grant of the role: the one that commits second starts over, and the deletion is refused', async () => {
  assert.deepEqual(await edit('ada-cli', { role: 'release', definition: release, was: null }), { answer: { role: release } });
  const deleting = OPERATIONS['policy.change'](asked('ada-cli', { role: 'release', definition: null, was: release }), deciding);
  const granting = OPERATIONS['access.grant']({ ...shown('fay-cli'), op: 'access.grant', principal: eve, changes: [{ project: 'billing', environment: null, role: 'release', expiresAt: null }] }, deciding);
  const [deletion, grantMade] = await Promise.all([prepare(world, deleting), prepare(world, granting)]);
  assert.ok(!('refused' in deletion!) && !('refused' in grantMade!));
  assert.equal(await commit(world, grantMade), true);
  assert.equal(await commit(world, deletion), false, 'a grant naming it is there now');
  assert.deepEqual(await edit('ada-cli', { role: 'release', definition: null, was: release }), { refused: 'role_granted' });
});

test('roles are edited only by an Owner of the whole instance, on a session: refused to anyone else, writing nothing, and logged', async () => {
  const bound = binding(api, { profile: 'kubernetes', policy: '{}' });
  await write(world, ...rows('grants', grant(api, 'owner', { project: market })), ...rows('bindings', bound), ...rows('credentials', session('pod', bound), credential('api-token', api, { scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'owner' }]) })));
  const ask = { role: 'developer', definition: narrowed, was: developer };
  for (const [label, refused] of [['fay-cli', 'no_access'], ['sam-cli', 'no_access'], ['bo-cli', 'no_access'], ['ada-pat', 'no_access'], ['api-token', 'no_access'], ['nobody', 'unauthenticated']] as const) {
    await nothingWritten(async () => assert.deepEqual(await edit(label, ask), { refused }, label));
  }
  await nothingWritten(async () => assert.deepEqual(await vault.change<'policy.change'>({ ...asked('pod', ask), proof: 'pod' }), { refused: 'workload_cannot_issue' }));
  // Ada's own role row gone: she holds nothing by it.
  await world.owner.execute(sql`DELETE FROM roles WHERE instance AND id = 'owner'`);
  await nothingWritten(async () => assert.deepEqual(await edit('ada-cli', ask), { refused: 'no_access' }));
  assert.deepEqual((await refusals()).map((entry) => [entry.actor, entry.detail.refused]), [[fay, 'no_access'], [sam, 'no_access'], [bo, 'no_access'], [ada, 'no_access'], [api, 'no_access']], 'once a minute for who asked and what');
});

test('a change with no revision is made from the role as it is: a grant naming one that does not ship refuses it only where no row is', async () => {
  assert.deepEqual(await edit('ada-cli', { role: 'developer', definition: narrowed }), { answer: { role: narrowed } });
  assert.deepEqual((await written()).detail, { role: 'developer', instance: false, definition: narrowed, was: developer });
  await nothingWritten(async () => assert.deepEqual(await edit('ada-cli', { role: 'release', definition: null }), { refused: 'invalid' }));
  assert.deepEqual(await edit('ada-cli', { role: 'release', definition: release }), { answer: { role: release } });
  await write(world, ...rows('grants', grant(eve, 'release', { project: billing })));
  // There, it is an edit, whatever a grant says; deleted around the vault, defining it again is refused while the grant names it.
  const steady: RoleDefinition = { ...release, description: 'Ships, steadily.' };
  assert.deepEqual(await edit('ada-cli', { role: 'release', definition: steady }), { answer: { role: steady } });
  await world.owner.execute(sql`DELETE FROM roles WHERE NOT instance AND id = 'release'`);
  await nothingWritten(async () => assert.deepEqual(await edit('ada-cli', { role: 'release', definition: steady }), { refused: 'role_granted' }));
  // A revision of the role as it was weighed, which it no longer is.
  await nothingWritten(async () => assert.deepEqual(await edit('ada-cli', { role: 'developer', definition: developer, was: developer }), { refused: 'policy_changed' }));
});

test('a role\'s change that is not what the contract says is a fault, before any read', () => {
  const fault = (ask: Record<string, unknown>) => assert.throws(() => OPERATIONS['policy.change']({ ...asked('ada-cli', { role: 'developer', definition: narrowed, was: developer }), ...ask } as never, deciding), TypeError, JSON.stringify(ask));
  fault({ role: 'owner' });
  fault({ role: 'owner', instance: true });
  fault({ role: 'member', instance: true });
  fault({ role: 'release', instance: true });
  fault({ role: 'Release' });
  fault({ role: 'r' });
  fault({ instance: 'no' });
  fault({ definition: { ...narrowed, name: '' } });
  fault({ definition: { ...narrowed, permissions: ['secret.fly'] } });
  fault({ definition: { ...narrowed, permissions: ['secret.read'], protected: [] } });
  fault({ definition: { ...narrowed, protected: ['secret.read'] } });
  // An array with a hole, as another isolate may send one.
  const holed: unknown[] = ['secret.use'];
  holed[2] = 'secret.write';
  fault({ definition: { ...narrowed, permissions: holed } });
  fault({ definition: 'developer' });
  fault({ revision: null });
  fault({ revision: 'policy-57' });
  fault({ revision: roleRevision(developer).toUpperCase() });
  assert.doesNotThrow(() => OPERATIONS['policy.change'](asked('ada-cli', { role: 'release-2', definition: release, was: null }), deciding));
  assert.doesNotThrow(() => OPERATIONS['policy.change'](asked('ada-cli', { role: 'release-2', definition: release }), deciding), 'no revision: made from the role as it is');
});

test('whoever runs the instance sets where people set up service accounts, projects by id, and the policy row keeps the rest', async () => {
  await amend(world, 'policy', sql`true`, { workloadsFrozenAt: frozenAt });
  assert.deepEqual(await setting('fay-cli', { projects: { only: ['market'] }, environments: { except: ['prod'] } }), { answer: { serviceAccounts: { projects: { only: [market.id] }, environments: { except: ['prod'] } } } });
  const row = await policyRow();
  assert.deepEqual([JSON.parse(row!.service_accounts), new Date(row!.workloads_frozen_at!).getTime(), row!.changed_by], [{ projects: { only: [market.id] }, environments: { except: ['prod'] } }, frozenAt.getTime(), fay], 'the freeze the row held, kept');
  const entry = await written();
  assert.deepEqual([entry.action, entry.actor, entry.detail], ['settings.change', fay, { serviceAccounts: { projects: { only: [market.id] }, environments: { except: ['prod'] } }, was: { projects: 'all', environments: 'all' } }]);
  assert.ok(entry.objects.includes(`project:${market.id}`));
  assert.deepEqual(named(entry), ['credentials read', 'policy replaced', 'principals read', 'projects read', 'roles read']);

  const before = await state();
  assert.deepEqual(await setting('ada-cli', { projects: { only: ['market'] }, environments: { except: ['prod'] } }), { answer: { serviceAccounts: { projects: { only: [market.id] }, environments: { except: ['prod'] } } } });
  assert.equal(await state(), before);
  assert.equal((await written()).detail.unchanged, true);

  // Two at once: the second reads the first's row, and starts over.
  const one = OPERATIONS['settings.change'](settingAsked('fay-cli', { projects: 'all', environments: 'all' }), deciding);
  const two = OPERATIONS['settings.change'](settingAsked('ada-cli', { projects: { except: ['billing'] }, environments: 'all' }), deciding);
  const [first, second] = await Promise.all([prepare(world, one), prepare(world, two)]);
  assert.ok(!('refused' in first!) && !('refused' in second!));
  assert.equal(await commit(world, first), true);
  assert.equal(await commit(world, second), false);
});

test('the settings are set by no one else, and not on a policy row that is gone or edited around the vault', async () => {
  const bound = binding(api, { profile: 'kubernetes', policy: '{}' });
  await write(world, ...rows('bindings', bound), ...rows('credentials', session('pod', bound)));
  const all = { projects: 'all', environments: { except: ['prod'] } };
  for (const [label, refused] of [['sam-cli', 'no_access'], ['bo-cli', 'no_access'], ['ada-pat', 'no_access'], ['nobody', 'unauthenticated']] as const) {
    await nothingWritten(async () => assert.deepEqual(await setting(label, all), { refused }, label));
  }
  await nothingWritten(async () => assert.deepEqual(await vault.change<'settings.change'>({ ...settingAsked('pod', all), proof: 'pod' }), { refused: 'workload_cannot_issue' }));
  // Its freeze lifted around the vault, the row is none.
  await amend(world, 'policy', sql`true`, { workloadsFrozenAt: frozenAt });
  await world.owner.execute(sql`UPDATE policy SET workloads_frozen_at = NULL`);
  await nothingWritten(async () => assert.deepEqual(await setting('fay-cli', all), { refused: 'tampered' }));
  await world.owner.execute(sql`DELETE FROM policy`);
  await nothingWritten(async () => assert.deepEqual(await setting('fay-cli', all), { refused: 'tampered' }));
  await write(world, ...rows('policy', instance()));
  // A project there is not, to whoever runs the instance as to anyone.
  await nothingWritten(async () => assert.deepEqual(await setting('fay-cli', { projects: { only: ['nowhere'] }, environments: 'all' }), { refused: 'no_access' }));
  // Once a minute for who asked and what.
  assert.deepEqual((await refusals()).map((entry) => [entry.actor, entry.detail.refused]), [[sam, 'no_access'], [bo, 'no_access'], [ada, 'no_access'], [api, 'workload_cannot_issue'], [fay, 'tampered']]);
});

test('settings that are not what the contract says are a fault, before any read', () => {
  const fault = (serviceAccounts: unknown) => assert.throws(() => OPERATIONS['settings.change'](settingAsked('fay-cli', serviceAccounts as Filters), deciding), TypeError, JSON.stringify(serviceAccounts));
  fault(null);
  fault('all');
  fault({ projects: 'all' });
  fault({ projects: 'all', environments: 'all', more: 'all' });
  fault({ projects: { only: ['Market'] }, environments: 'all' });
  fault({ projects: { only: ['market'], except: [] }, environments: 'all' });
  fault({ projects: 'all', environments: { only: Array.from({ length: 1001 }, (_, i) => `e${i}`) } });
  assert.doesNotThrow(() => OPERATIONS['settings.change'](settingAsked('fay-cli', { projects: 'all', environments: { only: Array.from({ length: 1000 }, (_, i) => `e${i}`) } }), deciding));
});
