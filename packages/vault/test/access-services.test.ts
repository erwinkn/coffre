// A service account set up, given grants and removed by a person who does not
// run the instance (src/ops/access.ts: `member.put`, `access.grant`,
// `member.remove`), as 0.14.7 let them, by core's rules: where they could give
// it something (`setsUpServices`), what they hold (`givesService`), of an
// account they manage (`managesService`); and a row of what those weigh that
// the vault did not write, refused `tampered`.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import type { Change, Presented } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { commit, prepare } from '../src/change.ts';
import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { OPERATIONS } from '../src/ops/index.ts';
import { emptyDatabase, openTestVault } from './database.ts';
import { credential, environment, grant, instance, principal, project, role, rows, tokenOf, user, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
after(() => world.close());

const [ada, fay, sam, dv, mk, bo] = ['ada', 'fay', 'sam', 'dv', 'mk', 'bo'].map(user) as [string, string, string, string, string, string];
const [ci, prodOnly, empty, gone, theirs, both, ops] = ['ci', 'prod', 'empty', 'gone', 'theirs', 'both', 'ops'].map((name) => `token:${name}`) as [string, string, string, string, string, string, string];
let market: ReturnType<typeof project>;
let dev: ReturnType<typeof environment>;
let prod: ReturnType<typeof environment>;
beforeEach(async () => {
  await emptyDatabase(world.owner);
  world.memory.reads.clear();
  world.memory.logged.clear();
  world.refused.clear();
  market = project('market');
  const billing = project('billing');
  dev = environment(market, 'dev');
  prod = environment(market, 'prod', { protected: true });
  const billingProd = environment(billing, 'prod');
  await write(world, ...rows('projects', market, billing), ...rows('environments', dev, prod, billingProd),
    ...rows('roles', role(true, 'owner', ['grant.manage']), role(true, 'admin', ['grant.manage']), role(true, 'member', []),
      role(false, 'viewer', ['secret.read']), role(false, 'contributor', ['secret.use']), role(false, 'admin', ['grant.manage', 'project.manage']),
      // A Developer only uses a protected environment's values.
      role(false, 'developer', ['secret.read', 'secret.use', 'secret.write'], ['secret.use'])),
    // Ada and Fay run the instance, Sam is an Admin of market alone; Dv is a Developer of market/dev and a Viewer of billing/prod, Mk a Developer of all of market; Bo holds nothing.
    ...rows('principals', principal(ada, { role: 'owner' }), principal(fay, { role: 'admin' }),
      principal(sam, { role: 'admin', scope: JSON.stringify({ projects: { only: [market.id] }, environments: 'all' }) }), principal(dv), principal(mk), principal(bo),
      // CI holds developer on market/dev and Dv set it up; another holds viewer on market/prod; Dv set up one that holds nothing yet,
      // and removed another; Fay removed the last. Dv set up one more, which holds something in both projects.
      principal(ci, { statusChangedBy: dv }), principal(prodOnly, { statusChangedBy: fay }), principal(empty, { statusChangedBy: dv }),
      principal(gone, { status: 'removed', generation: 1, statusChangedBy: dv }), principal(theirs, { status: 'removed', generation: 1, statusChangedBy: fay }),
      principal(both, { statusChangedBy: dv }), principal(ops, { statusChangedBy: fay })),
    ...rows('policy', instance()),
    ...rows('grants', grant(dv, 'developer', { environment: dev }), grant(dv, 'viewer', { environment: billingProd }), grant(mk, 'developer', { project: market }),
      grant(ci, 'developer', { environment: dev }), grant(prodOnly, 'viewer', { environment: prod }), grant(both, 'developer', { environment: dev }), grant(both, 'viewer', { environment: billingProd }),
      // Ops, a service account, manages access on market.
      grant(ops, 'admin', { project: market })),
    ...rows('credentials', ...[ada, fay, sam, dv, mk, bo].map((who) => credential(`${who.slice(5, who.indexOf('@'))}-cli`, who)),
      // A personal token of Dv's, scoped as tokens are: what it sets up would outlive it.
      credential('dv-pat', dv, { kind: 'personal', scope: JSON.stringify([{ projectId: market.id, environmentId: dev.id, role: 'developer' }]) }),
      credential('ops-token', ops, { scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'admin', permissions: { normal: ['grant.manage', 'project.manage'], protected: ['grant.manage', 'project.manage'] } }]) })));
  world.woken.length = 0;
});

type Place = { project: string; environment?: string; role: string | null };
const shown = (label: string): Presented => ({ token: tokenOf(label).toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7' });
const asked = <O extends Change['op']>(label: string, change: Extract<Change, { op: O }>) => vault.change<O>({ ...shown(label), ...change } as never);
const put = (label: string, who: string, role: string | null = null) => asked(label, { op: 'member.put', principal: who, role, scope: null } as never);
const remove = (label: string, who: string) => asked(label, { op: 'member.remove', principal: who } as never);
const granting = (label: string, who: string, places: Place[], admit?: boolean) =>
  ({ ...shown(label), op: 'access.grant', principal: who, changes: places.map((place) => ({ environment: null, expiresAt: null, ...place })), ...(admit === undefined ? {} : { admit }) }) as never;
const set = (label: string, who: string, ...places: Place[]) => vault.change<'access.grant'>(granting(label, who, places));
const admit = (label: string, who: string, ...places: Place[]) => vault.change<'access.grant'>(granting(label, who, places, true));
const onDev = (role: string | null): Place => ({ project: 'market', environment: 'dev', role });

const members = async () => rowsOf<{ id: string; status: string; role: string; generation: number; status_changed_by: string }>(world.owner, sql`SELECT id, status, role, generation, status_changed_by FROM principals ORDER BY id`);
const row = async (id: string) => (await members()).find((member) => member.id === id);
const held = async (who: string) =>
  rowsOf<{ generation: number; project_id: string | null; environment_id: string | null; role: string; granted_by: string }>(world.owner,
    sql`SELECT generation, project_id, environment_id, role, granted_by FROM grants WHERE principal = ${who} ORDER BY role`);
const kept = async () => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM log_pending WHERE kept`))[0]!.n;
const allGrants = async () => JSON.stringify(await rowsOf(world.owner, sql`SELECT * FROM grants ORDER BY id`));
const written = async () => {
  const [found] = await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE kept ORDER BY id DESC LIMIT 1`);
  return entryOf(world.keys, found!)!;
};
/** Nothing written by `run`: no change's entry, no grant, no member's row moved. */
async function nothingWritten(run: () => Promise<void>) {
  const before = [await kept(), await allGrants(), JSON.stringify(await members())];
  await run();
  assert.deepEqual([await kept(), await allGrants(), JSON.stringify(await members())], before);
}

test('a person who does not run the instance sets up a service account where they could give it something, as member, and it is theirs to give', async () => {
  const fresh = 'token:fresh';
  assert.deepEqual(await put('dv-cli', fresh), { answer: { role: 'member', scope: null, created: true } });
  assert.deepEqual(await row(fresh), { id: fresh, status: 'active', role: 'member', generation: 0, status_changed_by: dv });
  const entry = await written();
  assert.deepEqual([entry.action, entry.actor, entry.detail], ['member.add', dv, { member: fresh, role: 'member', scope: null, generation: 0 }]);
  // It holds nothing, and Dv set it up: theirs to give what they hold, and nobody else's but whoever runs the instance.
  assert.deepEqual(await set('dv-cli', fresh, onDev('viewer')), { answer: { changes: ['created'] } });
  assert.deepEqual(await put('dv-cli', fresh, 'member'), { answer: { role: 'member', scope: null, created: false } }, 'asked again, it changes nothing');
  // Mk, a Developer of all of market, gives developer on market/dev, so sets one up too.
  assert.deepEqual(await put('mk-cli', 'token:mine'), { answer: { role: 'member', scope: null, created: true } });

  await nothingWritten(async () => {
    assert.deepEqual(await put('bo-cli', 'token:other'), { refused: 'no_access' }, 'who holds nothing gives nothing');
    assert.deepEqual(await put('dv-cli', 'token:other', 'admin'), { refused: 'no_access' }, 'a service account holds no instance role, and one who does not run the instance gives none');
    assert.deepEqual(await put('dv-cli', user('new')), { refused: 'no_access' }, 'nor admits a person');
    assert.deepEqual(await put('dv-pat', 'token:other'), { refused: 'no_access' }, 'nor sets one up on a token: it would outlive it');
  });

  // The instance's setting narrows where people set them up: not in dev or prod. Whoever manages access somewhere still does.
  assert.ok('answer' in await asked('fay-cli', { op: 'settings.change', serviceAccounts: { projects: 'all', environments: { except: ['dev', 'prod'] } } } as never));
  await nothingWritten(async () => {
    assert.deepEqual(await put('dv-cli', 'token:other'), { refused: 'no_access' });
    assert.deepEqual(await set('dv-cli', fresh, onDev('developer')), { refused: 'no_access' }, 'nor gives one anything there');
  });
  assert.deepEqual(await put('sam-cli', 'token:other'), { answer: { role: 'member', scope: null, created: true } });
});

test('a service account removed comes back by whoever removed it, or runs the instance, never by anyone else', async () => {
  assert.deepEqual(await put('dv-cli', gone), { answer: { role: 'member', scope: null, created: true } });
  assert.deepEqual(await row(gone), { id: gone, status: 'active', role: 'member', generation: 1, status_changed_by: dv }, 'in the generation its removal moved on to');
  assert.equal((await written()).action, 'member.restore');
  await nothingWritten(async () => {
    assert.deepEqual(await put('dv-cli', theirs), { refused: 'no_access' }, 'Fay removed it');
    assert.deepEqual(await admit('dv-cli', theirs, onDev('viewer')), { refused: 'no_access' }, 'nor with grants');
    assert.deepEqual(await put('sam-cli', theirs), { refused: 'no_access' }, 'nor by whoever manages access on part of the instance');
  });
  assert.deepEqual(await put('ada-cli', theirs), { answer: { role: 'member', scope: null, created: true } });
});

test('a person gives a service account they manage what they hold, takes it away, and their next change follows what it holds', async () => {
  assert.deepEqual(await set('dv-cli', ci, onDev('viewer')), { answer: { changes: ['updated'] } });
  const entry = await written();
  assert.deepEqual([entry.action, entry.actor, entry.detail], ['access.grant', dv, { member: ci, changes: [{ environment: dev.id, role: 'viewer', expiresAt: null, was: 'developer' }] }]);
  // A Developer of all of market manages it too, and gives it what they hold on all of market, prod included, where they only use.
  assert.deepEqual(await set('mk-cli', ci, { project: 'market', role: 'contributor' }), { answer: { changes: ['created'] } });
  assert.deepEqual((await held(ci)).map((grant) => [grant.role, grant.project_id ?? grant.environment_id, grant.granted_by]), [['contributor', market.id, mk], ['viewer', dev.id, dv]]);

  await nothingWritten(async () => {
    // Dv holds nothing on all of market, nor in prod: it now holds contributor on market, so it is not Dv's any more.
    assert.deepEqual(await set('dv-cli', ci, onDev('developer')), { refused: 'no_access' }, 'it holds what Dv does not');
    assert.deepEqual(await set('mk-cli', ci, { project: 'market', role: 'developer' }), { refused: 'no_access' }, 'on a whole project, its protected environments weigh: Mk only uses prod (D241)');
    assert.deepEqual(await set('mk-cli', ci, { project: 'market', environment: 'prod', role: 'viewer' }), { refused: 'no_access' }, 'nor reads it');
    assert.deepEqual(await set('mk-cli', prodOnly, onDev('viewer')), { refused: 'no_access' }, 'it reads prod, which Mk does not');
    assert.deepEqual(await set('mk-cli', empty, onDev('viewer')), { refused: 'no_access' }, 'one that holds nothing is its maker\'s');
    assert.deepEqual(await set('mk-cli', 'token:nobody', onDev('viewer')), { refused: 'no_access' }, 'not a member: nothing said to one who manages no access');
    assert.deepEqual(await set('mk-cli', gone, onDev('viewer')), { refused: 'no_access' }, 'removed: the same');
    assert.deepEqual(await set('mk-cli', bo, onDev('viewer')), { refused: 'no_access' }, 'a person\'s grants, whoever manages access there gives');
    assert.deepEqual(await set('dv-pat', empty, onDev('viewer')), { refused: 'no_access' }, 'nor on a token');
  });
  assert.deepEqual(await set('mk-cli', ci, { project: 'market', role: null }, onDev(null)), { answer: { changes: ['revoked', 'revoked'] } });
  assert.equal((await written()).action, 'access.revoke');
  // Holding nothing now, it is Dv's again, who set it up.
  assert.deepEqual(await set('dv-cli', ci, onDev('developer')), { answer: { changes: ['created'] } });
  assert.deepEqual(await set('dv-cli', empty, onDev('viewer')), { answer: { changes: ['created'] } });
  // What it holds in another project weighs too: Dv holds that, and Mk does not.
  assert.deepEqual(await set('dv-cli', both, onDev('viewer')), { answer: { changes: ['updated'] } });
  await nothingWritten(async () => assert.deepEqual(await set('mk-cli', both, onDev('developer')), { refused: 'no_access' }));
  // Whoever manages access everywhere asked gives a service account anything there, as a person.
  assert.deepEqual(await set('fay-cli', prodOnly, onDev('developer')), { answer: { changes: ['created'] } });
  assert.deepEqual(await set('sam-cli', prodOnly, { project: 'market', role: 'developer' }), { answer: { changes: ['created'] } });
});

test('a service account admitted with its first grants in one change, all or none', async () => {
  const fresh = 'token:fresh';
  assert.deepEqual(await admit('dv-cli', fresh, onDev('viewer')), { answer: { changes: ['created'], created: true } });
  assert.deepEqual(await row(fresh), { id: fresh, status: 'active', role: 'member', generation: 0, status_changed_by: dv });
  assert.deepEqual((await held(fresh)).map((grant) => [grant.generation, grant.environment_id, grant.role]), [[0, dev.id, 'viewer']]);
  const entry = await written();
  assert.deepEqual([entry.action, entry.actor, entry.detail], ['access.grant', dv, { member: fresh, changes: [{ environment: dev.id, role: 'viewer', expiresAt: null, was: null }], admitted: 'member.add', generation: 0 }]);
  assert.ok(entry.objects.includes(`principal:${fresh}`), entry.objects.join());

  // Brought back by its remover, in the generation its removal moved on to.
  assert.deepEqual(await admit('dv-cli', gone, onDev('developer')), { answer: { changes: ['created'], created: true } });
  assert.deepEqual([(await row(gone))!.status, (await held(gone)).map((grant) => grant.generation)], ['active', [1]]);
  assert.deepEqual((await written()).detail, { member: gone, changes: [{ environment: dev.id, role: 'developer', expiresAt: null, was: null }], admitted: 'member.restore', generation: 1 });
  // Asked of a member, it admits nobody, and says so.
  assert.deepEqual(await admit('dv-cli', ci, onDev('viewer')), { answer: { changes: ['updated'], created: false } });

  await nothingWritten(async () => {
    assert.deepEqual(await admit('dv-cli', 'token:other', onDev('viewer'), { project: 'market', environment: 'prod', role: 'viewer' }), { refused: 'no_access' }, 'one place Dv does not hold refuses all');
    assert.deepEqual(await admit('bo-cli', 'token:other', onDev('viewer')), { refused: 'no_access' });
    assert.deepEqual(await admit('bo-cli', 'token:other', onDev(null)), { refused: 'no_access' }, 'nor sets one up by taking nothing away');
    assert.deepEqual(await admit('dv-pat', 'token:other', onDev('viewer')), { refused: 'no_access' });
    assert.deepEqual(await set('sam-cli', 'token:other', onDev('viewer')), { refused: 'not_a_member' }, 'without admit, to whoever manages access there, what 0.14 said');
    assert.deepEqual(await admit('sam-cli', theirs, onDev('viewer')), { refused: 'no_access' }, 'one Fay removed, whoever manages access there but does not run the instance does not bring back');
    // A service account's token that manages access gives grants, but sets up no service account: it would outlive it.
    assert.deepEqual(await admit('ops-token', 'token:child', { project: 'market', role: 'viewer' }), { refused: 'no_access' });
    assert.deepEqual(await put('ops-token', 'token:child'), { refused: 'no_access' });
  });
  assert.deepEqual(await set('ops-token', ci, { project: 'market', role: 'viewer' }), { answer: { changes: ['created'] } }, 'but gives one that is a member what it may');
  await assert.rejects(admit('fay-cli', bo, onDev('viewer')), TypeError, 'a person is admitted by an instance role, never with grants');
  assert.deepEqual(await admit('fay-cli', theirs, { project: 'market', environment: 'prod', role: 'viewer' }), { answer: { changes: ['created'], created: true } }, 'whoever runs the instance brings back any');
});

test('a person removes a service account they manage, and no other member', async () => {
  await nothingWritten(async () => {
    assert.deepEqual(await remove('dv-cli', prodOnly), { refused: 'no_access' }, 'it reads prod');
    assert.deepEqual(await remove('dv-cli', 'token:nobody'), { refused: 'no_access' }, 'not a member: nothing said');
    assert.deepEqual(await remove('dv-cli', theirs), { refused: 'no_access' }, 'removed: the same');
    assert.deepEqual(await remove('dv-cli', bo), { refused: 'no_access' }, 'a person');
    assert.deepEqual(await remove('mk-cli', empty), { refused: 'no_access' }, 'one that holds nothing is its maker\'s');
    assert.deepEqual(await remove('dv-pat', ci), { refused: 'no_access' }, 'nor on a token');
  });
  assert.deepEqual(await remove('dv-cli', ci), { answer: { revoked: 1 } });
  assert.deepEqual(await row(ci), { id: ci, status: 'removed', role: 'member', generation: 1, status_changed_by: dv });
  assert.deepEqual(await held(ci), []);
  assert.deepEqual([(await written()).action, (await written()).actor], ['member.remove', dv]);
  assert.deepEqual(await remove('dv-cli', empty), { answer: { revoked: 0 } });
  // Its remover brings it back.
  assert.deepEqual(await put('dv-cli', ci), { answer: { role: 'member', scope: null, created: true } });
});

test('a row of what these weigh, written behind the vault, refuses them, tampered', async () => {
  // A grant of the service's edited: it might hold more than it says, which would make Dv manage it more easily.
  await world.owner.execute(sql`UPDATE grants SET role = 'viewer' WHERE principal = ${ci}`);
  await nothingWritten(async () => {
    assert.deepEqual(await remove('dv-cli', ci), { refused: 'tampered' });
    assert.deepEqual(await set('dv-cli', ci, onDev('developer')), { refused: 'tampered' });
    // Told only to whoever could make the change: not on a token, nor to Bo, who holds nothing.
    assert.deepEqual(await remove('dv-pat', ci), { refused: 'no_access' });
    assert.deepEqual(await set('dv-pat', ci, onDev('developer')), { refused: 'no_access' });
    assert.deepEqual(await remove('bo-cli', ci), { refused: 'no_access' });
    assert.deepEqual(await set('bo-cli', ci, onDev('developer')), { refused: 'no_access' });
  });
  assert.deepEqual(await set('dv-cli', empty, onDev('viewer')), { answer: { changes: ['created'] } }, 'another service account\'s rows weigh nothing here');

  // Prod unprotected behind the vault: its row, whatever it says, is read and found unsealed.
  await world.owner.execute(sql`UPDATE environments SET protected = false WHERE id = ${prod.id}`);
  await nothingWritten(async () => {
    // Dv's own, which holds dev alone: the project asked weighs, whatever else the service holds.
    assert.deepEqual(await set('dv-cli', empty, onDev('developer')), { refused: 'tampered' });
    assert.deepEqual(await set('mk-cli', prodOnly, onDev('viewer')), { refused: 'no_access' }, 'not Mk\'s: told nothing');
    assert.deepEqual(await put('dv-cli', 'token:other'), { refused: 'tampered' });
    assert.deepEqual(await admit('dv-cli', 'token:other', onDev('viewer')), { refused: 'tampered' });
    assert.deepEqual(await put('dv-pat', 'token:other'), { refused: 'no_access' }, 'not on a token');
    assert.deepEqual(await put('bo-cli', 'token:other'), { refused: 'no_access' }, 'nor to whoever holds nothing');
  });
  await world.owner.execute(sql`UPDATE environments SET protected = true WHERE id = ${prod.id}`);
  assert.ok('answer' in await put('dv-cli', 'token:other'), 'as it was, it is the vault\'s again');

  // The setting edited behind the vault: it may say more than it said. Without it, nobody sets one up by it, and is told
  // no more; whoever manages access somewhere needs none, and is told.
  await world.owner.execute(sql`UPDATE policy SET service_accounts = '{"projects":"all","environments":{"except":["prod"]}}'`);
  await nothingWritten(async () => {
    assert.deepEqual(await put('dv-cli', 'token:third'), { refused: 'no_access' });
    assert.deepEqual(await put('sam-cli', 'token:third'), { refused: 'tampered' });
  });
  assert.ok('answer' in await put('fay-cli', 'token:third'), 'whoever runs the instance weighs none of it');

  // A person's row edited: whoever does not run the instance removes no person, and is told nothing of their row.
  await world.owner.execute(sql`UPDATE principals SET created_by = ${dv} WHERE id = ${bo}`);
  await nothingWritten(async () => assert.deepEqual(await remove('dv-cli', bo), { refused: 'no_access' }));
});

test('a grant beside another that takes the service account out of their hands: the one that commits second starts over, and is refused', async () => {
  const deciding = { workloads: world.workloads, owners: world.owners };
  const mine = OPERATIONS['access.grant'](granting('dv-cli', ci, [onDev('viewer')]), deciding);
  const widening = OPERATIONS['access.grant'](granting('fay-cli', ci, [{ project: 'market', environment: 'prod', role: 'viewer' }]), deciding);
  const [first, second] = await Promise.all([prepare(world, mine), prepare(world, widening)]);
  assert.ok(!('refused' in first!) && !('refused' in second!));
  assert.equal(await commit(world, second), true);
  assert.equal(await commit(world, first), false, 'the grants it read are no longer the account\'s');
  assert.deepEqual(await set('dv-cli', ci, onDev('viewer')), { refused: 'no_access' });
  // The same beside its removal: Dv no longer manages it.
  const removing = OPERATIONS['member.remove']({ ...shown('dv-cli'), op: 'member.remove', principal: empty }, deciding);
  const giving = OPERATIONS['access.grant'](granting('fay-cli', empty, [{ project: 'market', environment: 'prod', role: 'viewer' }]), deciding);
  const [removal, given] = await Promise.all([prepare(world, removing), prepare(world, giving)]);
  assert.ok(!('refused' in removal!) && !('refused' in given!));
  assert.equal(await commit(world, given), true);
  assert.equal(await commit(world, removal), false);
  assert.deepEqual(await remove('dv-cli', empty), { refused: 'no_access' });
});
