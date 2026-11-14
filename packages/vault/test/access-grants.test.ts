// A person's grants set, changed, given an end or taken away (src/ops/access.ts,
// `access.grant`), through the contract as the app calls it: who may, at which
// places, what is written in which generation, what its entry names, what a use
// by the member does right after, and a grant beside a removal.
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
import { credential, environment, grant, instance, principal, project, role, rows, secret, tokenOf, user, value, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
after(() => world.close());

const [ada, fay, sam, dv, bo, eve, ex, old] = ['ada', 'fay', 'sam', 'dv', 'bo', 'eve', 'ex', 'old'].map(user) as [string, string, string, string, string, string, string, string];
const api = 'token:api';
let market: ReturnType<typeof project>;
let billing: ReturnType<typeof project>;
let prod: ReturnType<typeof environment>;
let dev: ReturnType<typeof environment>;
let lapsed: ReturnType<typeof grant>;
let stale: ReturnType<typeof grant>;
beforeEach(async () => {
  await emptyDatabase(world.owner);
  world.memory.reads.clear();
  world.memory.logged.clear();
  world.refused.clear();
  market = project('market');
  billing = project('billing');
  prod = environment(market, 'prod');
  dev = environment(market, 'dev');
  const billingProd = environment(billing, 'prod');
  const scoped = (scope: object) => JSON.stringify(scope);
  // Old was removed once and is back, in generation 1, with a grant from generation 0 put back; Eve's grant on billing has lapsed.
  stale = grant(old, 'developer', { project: market });
  lapsed = grant(eve, 'viewer', { project: billing }, { expiresAt: new Date(world.now() - 1000) });
  await write(world, ...rows('projects', market, billing), ...rows('environments', prod, dev, billingProd, environment(market, 'ada-dev', { parentId: dev.id, owner: ada })),
    ...rows('secrets', value(world, secret(prod, 'DATABASE_URL'), 'postgres://market')),
    ...rows('roles', role(true, 'owner', ['grant.manage']), role(true, 'admin', ['grant.manage']), role(true, 'member', []),
      role(false, 'viewer', ['secret.read']), role(false, 'developer', ['secret.read', 'secret.use', 'secret.write']), role(false, 'admin', ['grant.manage', 'project.manage'])),
    // Ada owns the instance and Fay runs it as its Admin; Sam is an Admin of market alone, Dv of every project's dev alone.
    ...rows('principals', principal(ada, { role: 'owner' }), principal(fay, { role: 'admin' }), principal(sam, { role: 'admin', scope: scoped({ projects: { only: [market.id] }, environments: 'all' }) }),
      principal(dv, { role: 'admin', scope: scoped({ projects: 'all', environments: { only: ['dev'] } }) }), principal(bo), principal(eve), principal(ex, { status: 'removed', generation: 1 }),
      principal(old, { generation: 1 }), principal(api)),
    ...rows('policy', instance()),
    ...rows('grants', grant(bo, 'developer', { project: market }), stale, lapsed),
    ...rows('credentials', ...[ada, fay, sam, dv, bo, eve].map((who) => credential(`${who.slice(5, who.indexOf('@'))}-cli`, who)), credential('old-cli', old, { generation: 1 }),
      credential('ada-pat', ada, { kind: 'personal', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'developer' }]) })));
  world.woken.length = 0;
});

type Place = { project: string; environment?: string; role: string | null; expiresAt?: string | null };
const shown = (label: string): Presented => ({ token: tokenOf(label).toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7' });
const change = (label: string, who: string, places: Place[]): Presented & Extract<Change, { op: 'access.grant' }> =>
  ({ ...shown(label), op: 'access.grant', principal: who, changes: places.map((place) => ({ environment: null, expiresAt: null, ...place })) }) as never;
const set = (label: string, who: string, ...places: Place[]) => vault.change<'access.grant'>(change(label, who, places));

/** What a use of market/prod's `DATABASE_URL` by `label` is answered: the value, or why not. */
const uses = async (label: string) => {
  const answer = await vault.use({ ...shown(label), project: 'market', environment: 'prod', mine: false, keys: ['DATABASE_URL'], purpose: 'reveal', upstream: null });
  return 'refused' in answer ? answer.refused : answer.values.map((item) => ('refused' in item ? item.refused : item.value))[0];
};
const held = async (who: string) =>
  rowsOf<{ id: string; generation: number; project_id: string | null; environment_id: string | null; role: string; expires_at: Date | null; granted_by: string }>(world.owner,
    sql`SELECT id, generation, project_id, environment_id, role, expires_at, granted_by FROM grants WHERE principal = ${who} ORDER BY role, id`);
const allGrants = async () => JSON.stringify(await rowsOf(world.owner, sql`SELECT * FROM grants ORDER BY id`));
const kept = async () => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM log_pending WHERE kept`))[0]!.n;
const refusals = async () =>
  (await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE NOT kept ORDER BY id`)).map((found) => entryOf(world.keys, found)!);
const written = async () => {
  const [found] = await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE kept ORDER BY id DESC LIMIT 1`);
  return entryOf(world.keys, found!)!;
};
const named = (entry: Awaited<ReturnType<typeof written>>) =>
  entry.rows.map(({ row: name, was, now }) => `${(JSON.parse(name) as string[])[0]} ${was === null ? 'made' : now === null ? 'dropped' : was === now ? 'read' : 'replaced'}`).sort();
/** Nothing written by `run`: no change's entry, no grant moved. Its refusal may be logged. */
async function nothingWritten(run: () => Promise<void>) {
  const before = [await kept(), await allGrants()];
  await run();
  assert.deepEqual([await kept(), await allGrants()], before);
}

test('whoever manages access gives a person a role, changes it and takes it away, and their next use follows at once', async () => {
  assert.equal(await uses('eve-cli'), 'no_access');
  const end = new Date(world.now() + 86_400_000).toISOString();
  assert.deepEqual(await set('fay-cli', eve, { project: 'market', environment: 'prod', role: 'viewer', expiresAt: end }), { answer: { changes: ['created'] } });
  const [made] = (await held(eve)).filter((row) => row.environment_id === prod.id);
  assert.deepEqual({ ...made, id: undefined, expires_at: new Date(made!.expires_at!).toISOString() }, { id: undefined, generation: 0, project_id: null, environment_id: prod.id, role: 'viewer', expires_at: end, granted_by: fay });
  const entry = await written();
  assert.deepEqual([entry.action, entry.actor, entry.detail], ['access.grant', fay, { member: eve, changes: [{ environment: prod.id, role: 'viewer', expiresAt: end, was: null }] }]);
  assert.ok(entry.objects.includes(`principal:${eve}`) && entry.objects.includes(`environment:${prod.id}`), entry.objects.join());
  // Who asked and what lets them, the member's row, the place, the role given and the grant made: no other member's grants.
  assert.deepEqual(named(entry), ['credentials read', 'environments read', 'grants made', 'principals read', 'principals read', 'projects read', 'roles read', 'roles read']);
  assert.equal(world.woken.length, 1);
  world.tick(2000);
  assert.equal(await uses('eve-cli'), 'postgres://market');

  assert.deepEqual(await set('fay-cli', eve, { project: 'market', environment: 'prod', role: 'developer' }), { answer: { changes: ['updated'] } });
  const [updated] = (await held(eve)).filter((row) => row.environment_id === prod.id);
  assert.deepEqual([updated!.id, updated!.role, updated!.expires_at], [made!.id, 'developer', null], 'the same row, its end gone');
  assert.deepEqual((await written()).detail, { member: eve, changes: [{ environment: prod.id, role: 'developer', expiresAt: null, was: 'viewer' }] });

  // An end given is a change of its own.
  const later = new Date(world.now() + 2 * 86_400_000).toISOString();
  assert.deepEqual(await set('fay-cli', eve, { project: 'market', environment: 'prod', role: 'developer', expiresAt: later }), { answer: { changes: ['updated'] } });
  assert.deepEqual(await set('fay-cli', eve, { project: 'market', environment: 'prod', role: 'developer' }), { answer: { changes: ['updated'] } });
  // Asked as it is, it changes nothing, and is logged all the same.
  const before = await allGrants();
  assert.deepEqual(await set('fay-cli', eve, { project: 'market', environment: 'prod', role: 'developer' }), { answer: { changes: ['unchanged'] } });
  assert.equal(await allGrants(), before);
  assert.deepEqual((await written()).detail, { member: eve, changes: [] });

  assert.deepEqual(await set('fay-cli', eve, { project: 'market', environment: 'prod', role: null }), { answer: { changes: ['revoked'] } });
  const revoking = await written();
  assert.deepEqual([revoking.action, revoking.detail], ['access.revoke', { member: eve, changes: [{ environment: prod.id, role: null, was: 'developer' }] }]);
  assert.ok(named(revoking).includes('grants dropped'));
  world.tick(2000);
  assert.equal(await uses('eve-cli'), 'no_access');
  assert.deepEqual(await set('fay-cli', eve, { project: 'market', environment: 'prod', role: null }), { answer: { changes: ['unchanged'] } }, 'nothing there to take');
});

test('several places in one change, all of them or none', async () => {
  await nothingWritten(async () => {
    assert.deepEqual(await set('fay-cli', eve, { project: 'market', role: 'developer' }, { project: 'market', environment: 'dev', role: 'viewer' }, { project: 'nowhere', role: 'viewer' }), { refused: 'no_access' });
    assert.deepEqual(await set('fay-cli', eve, { project: 'market', role: 'developer' }, { project: 'market', environment: 'nowhere', role: 'viewer' }), { refused: 'no_access' });
    assert.deepEqual(await set('fay-cli', eve, { project: 'market', role: 'developer' }, { project: 'market', environment: 'dev', role: 'nope' }), { refused: 'invalid' });
    assert.deepEqual(await set('sam-cli', eve, { project: 'market', role: 'developer' }, { project: 'billing', role: 'viewer' }), { refused: 'no_access' }, 'Sam manages market, not billing');
  });
  assert.deepEqual(await set('fay-cli', eve, { project: 'market', role: 'developer' }, { project: 'market', environment: 'dev', role: 'viewer' }, { project: 'billing', role: 'viewer' }),
    { answer: { changes: ['created', 'created', 'created'] } });
  assert.deepEqual((await held(eve)).map((row) => [row.role, row.project_id ?? row.environment_id]).sort(), [['developer', market.id], ['viewer', billing.id], ['viewer', dev.id]].sort());
  assert.equal((await held(eve)).find((row) => row.project_id === billing.id)!.id, lapsed.id, 'the lapsed grant on billing, replaced in place');
  // Given and taken in one change: logged as a grant.
  assert.deepEqual(await set('fay-cli', eve, { project: 'market', role: null }, { project: 'market', environment: 'prod', role: 'viewer' }), { answer: { changes: ['revoked', 'created'] } });
  assert.equal((await written()).action, 'access.grant');
});

test('only who manages access at each place changes grants there, and nobody gives themselves a role', async () => {
  await nothingWritten(async () => {
    assert.deepEqual(await set('bo-cli', eve, { project: 'market', role: 'viewer' }), { refused: 'no_access' }, 'a Developer manages no access');
    assert.deepEqual(await set('sam-cli', eve, { project: 'billing', role: 'viewer' }), { refused: 'no_access' }, 'an Admin of market alone');
    assert.deepEqual(await set('dv-cli', eve, { project: 'market', role: 'viewer' }), { refused: 'no_access' }, 'an Admin of dev alone holds no project');
    assert.deepEqual(await set('dv-cli', eve, { project: 'market', environment: 'prod', role: 'viewer' }), { refused: 'no_access' });
    assert.deepEqual(await set('ada-pat', eve, { project: 'market', role: 'viewer' }), { refused: 'no_access' }, 'a token scoped to developer manages nothing');
    assert.deepEqual(await set('fay-cli', fay, { project: 'market', role: 'viewer' }), { refused: 'no_access' }, 'a role given to oneself');
    assert.deepEqual(await set('ada-cli', ada, { project: 'market', role: 'viewer' }, { project: 'billing', role: null }), { refused: 'no_access' }, 'an Owner\'s too');
    assert.deepEqual(await set('bo-cli', bo, { project: 'market', role: 'admin' }), { refused: 'no_access' });
  });
  assert.deepEqual(await set('sam-cli', eve, { project: 'market', role: 'viewer' }), { answer: { changes: ['created'] } });
  assert.deepEqual(await set('dv-cli', eve, { project: 'market', environment: 'dev', role: 'viewer' }), { answer: { changes: ['created'] } });
  assert.deepEqual(await set('ada-cli', eve, { project: 'market', role: 'admin' }), { answer: { changes: ['updated'] } }, 'a project Admin, who manages access there');
  assert.deepEqual(await set('eve-cli', bo, { project: 'market', environment: 'prod', role: 'viewer' }), { answer: { changes: ['created'] } }, 'by their grant on market');
  // A role is given up by whoever manages access there, themselves included.
  assert.deepEqual(await set('eve-cli', eve, { project: 'market', role: null }), { answer: { changes: ['revoked'] } });
  assert.deepEqual(await set('eve-cli', bo, { project: 'market', role: 'viewer' }), { refused: 'no_access' }, 'and with it the access they managed');
});

test('a grant asked of a place it cannot be: no role by that id, a project\'s on an environment, an end gone, a personal config, a place of another project', async () => {
  await nothingWritten(async () => {
    assert.deepEqual(await set('fay-cli', eve, { project: 'market', role: 'nope' }), { refused: 'invalid' });
    assert.deepEqual(await set('fay-cli', eve, { project: 'market', environment: 'prod', role: 'admin' }), { refused: 'invalid' }, 'grant.manage holds on a project alone');
    assert.deepEqual(await set('fay-cli', eve, { project: 'market', role: 'viewer', expiresAt: new Date(world.now()).toISOString() }), { refused: 'invalid' });
    assert.deepEqual(await set('fay-cli', eve, { project: 'market', environment: 'ada-dev', role: 'viewer' }), { refused: 'no_access' }, 'Ada\'s personal config');
    assert.deepEqual(await set('fay-cli', eve, { project: 'billing', environment: 'dev', role: 'viewer' }), { refused: 'no_access' }, 'dev is market\'s');
    // What 0.14 told whoever manages access there of the member.
    assert.deepEqual(await set('fay-cli', ex, { project: 'market', role: 'viewer' }), { refused: 'removed' });
    assert.deepEqual(await set('fay-cli', user('new'), { project: 'market', role: 'viewer' }), { refused: 'not_a_member' });
    assert.deepEqual(await set('bo-cli', user('new'), { project: 'market', role: 'viewer' }), { refused: 'no_access' }, 'and to nobody else');
    // A service account's grants are not given here yet, by anyone.
    assert.deepEqual(await set('ada-cli', api, { project: 'market', environment: 'dev', role: 'viewer' }), { refused: 'no_access' });
  });
  assert.deepEqual(await set('fay-cli', eve, { project: 'market', role: 'admin' }), { answer: { changes: ['created'] } });
  // A role whose row is gone is no role: it is given by nobody.
  await world.owner.execute(sql`DELETE FROM roles WHERE NOT instance AND id = 'viewer'`);
  await nothingWritten(async () => assert.deepEqual(await set('fay-cli', bo, { project: 'market', environment: 'dev', role: 'viewer' }), { refused: 'invalid' }));
});

test('a grant left from before a removal is replaced in place, in the member\'s generation, and reaches nothing until then', async () => {
  world.tick(2000);
  assert.equal(await uses('old-cli'), 'no_access', 'a grant of generation 0 reaches nothing in generation 1');
  assert.deepEqual(await set('fay-cli', old, { project: 'market', role: 'developer' }), { answer: { changes: ['created'] } }, 'as it reads, it holds nothing there');
  assert.deepEqual((await held(old)).map((row) => [row.id, row.generation, row.role]), [[stale.id, 1, 'developer']]);
  assert.ok(named(await written()).includes('grants replaced'));
  world.tick(2000);
  assert.equal(await uses('old-cli'), 'postgres://market');

  // A row of an earlier generation taken away: nothing was held, and the row goes.
  await world.owner.execute(sql`DELETE FROM grants WHERE id = ${stale.id}`);
  await write(world, ...rows('grants', grant(old, 'developer', { project: market })));
  assert.deepEqual(await set('fay-cli', old, { project: 'market', role: null }), { answer: { changes: ['unchanged'] } });
  assert.deepEqual(await held(old), []);
  assert.ok(named(await written()).includes('grants dropped'));

  assert.deepEqual(await set('fay-cli', eve, { project: 'billing', role: null }), { answer: { changes: ['unchanged'] } }, 'a lapsed grant: nothing held, its row cleared');
  assert.deepEqual(await held(eve), []);
});

test('a change of grants shaped otherwise than the contract says is a fault, before any read', async () => {
  const bad: unknown[] = [
    [],
    [{ project: 'market', role: 'viewer' }, { project: 'market', role: 'developer' }],
    [{ project: 'Market', role: 'viewer' }],
    [{ project: 'market', environment: 'prod~x', role: 'viewer' }],
    [{ project: 'market', role: 'Viewer' }],
    [{ project: 'market', role: 'viewer', expiresAt: 'tomorrow' }],
    [{ project: 'market', role: 'viewer', expiresAt: '2026-02-30T00:00:00Z' }],
    Array.from({ length: 1001 }, (_, i) => ({ project: `p${i}`, role: 'viewer' })),
  ];
  for (const places of bad) {
    // Each place whole but for what it is wrong in.
    const whole = (places as object[]).map((place) => ({ environment: null, expiresAt: null, ...place }));
    assert.throws(() => OPERATIONS['access.grant']({ ...change('fay-cli', eve, []), changes: whole as never }, { workloads: world.workloads, owners: world.owners }), TypeError, JSON.stringify(places).slice(0, 80));
  }
  assert.throws(() => OPERATIONS['access.grant'](change('fay-cli', 'user:Eve@acme.example', [{ project: 'market', role: 'viewer' }]), { workloads: world.workloads, owners: world.owners }), TypeError);
  assert.throws(() => OPERATIONS['access.grant']({ ...change('fay-cli', eve, []), changes: 'market' as never }, { workloads: world.workloads, owners: world.owners }), TypeError);
  assert.throws(() => OPERATIONS['access.grant']({ ...change('fay-cli', eve, []), changes: [{ project: 'market', role: 'viewer' }] as never }, { workloads: world.workloads, owners: world.owners }), TypeError, 'a place says its environment, or null');
  // The same places, well formed, are not.
  assert.doesNotThrow(() => OPERATIONS['access.grant'](change('fay-cli', eve, Array.from({ length: 1000 }, (_, i) => ({ project: `p${i}`, environment: 'dev', role: 'viewer', expiresAt: '2028-02-29T00:00:00Z' }))), { workloads: world.workloads, owners: world.owners }));
  assert.equal(world.woken.length, 0);
});

test('a refused change of grants is logged once, with why and what it was about', async () => {
  assert.deepEqual(await set('bo-cli', eve, { project: 'market', role: 'viewer' }), { refused: 'no_access' });
  assert.deepEqual(await set('bo-cli', eve, { project: 'market', role: 'viewer' }), { refused: 'no_access' });
  assert.deepEqual(await set('fay-cli', eve, { project: 'market', role: null }), { answer: { changes: ['unchanged'] } });
  const [refused, ...more] = await refusals();
  assert.equal(more.length, 0, 'once a minute for who asked and what');
  assert.deepEqual([refused!.action, refused!.actor, refused!.detail], ['access.grant', bo, { refused: 'no_access' }]);
  assert.ok(refused!.objects.includes(`principal:${eve}`) && refused!.objects.includes(`project:${market.id}`), refused!.objects.join());
});

test('a grant beside the member\'s removal: the one that commits second starts over, and finds them removed', async () => {
  const deciding = { workloads: world.workloads, owners: world.owners };
  const granting = OPERATIONS['access.grant'](change('fay-cli', bo, [{ project: 'market', environment: 'prod', role: 'viewer' }]), deciding);
  const removing = OPERATIONS['member.remove']({ ...shown('ada-cli'), op: 'member.remove', principal: bo }, deciding);
  const [grant, removal] = await Promise.all([prepare(world, granting), prepare(world, removing)]);
  assert.ok(!('refused' in grant!) && !('refused' in removal!));
  assert.equal(await commit(world, removal), true);
  assert.equal(await commit(world, grant), false, 'the member it read is no longer the one it would grant');
  assert.deepEqual(await set('fay-cli', bo, { project: 'market', environment: 'prod', role: 'viewer' }), { refused: 'removed' });
  assert.deepEqual(await held(bo), []);

  // Two grants to one place side by side: the second reads the first's row and starts over.
  const twice = () => OPERATIONS['access.grant'](change('fay-cli', eve, [{ project: 'market', role: 'viewer' }]), deciding);
  const [first, second] = await Promise.all([prepare(world, twice()), prepare(world, twice())]);
  assert.ok(!('refused' in first!) && !('refused' in second!), 'each decided alone');
  assert.equal(await commit(world, first), true);
  assert.equal(await commit(world, second), false);
  assert.equal((await held(eve)).filter((row) => row.project_id === market.id).length, 1);
});
