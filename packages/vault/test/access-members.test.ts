// A member admitted, brought back, given a role or removed (src/ops/access.ts),
// through the contract as the app calls it: who may, what is written, what its
// entry names, what a use by the member does right after, and the instance
// keeping an Owner of all of it, alone and side by side.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import type { Change, Presented, UseInput } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { bindings } from '@coffre/db/schema';
import { eq, sql } from 'drizzle-orm';

import { commit, prepare } from '../src/change.ts';
import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { OPERATIONS } from '../src/ops/index.ts';
import { Signer } from '../src/signer.ts';
import { emptyDatabase, memoryStore, openTestVault } from './database.ts';
import { amend, binding, credential, environment, grant, instance, principal, project, role, rows, secret, session, tokenOf, user, value, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
after(() => world.close());

const [ada, cy, dee, fay, sam, bo, eve, ex] = ['ada', 'cy', 'dee', 'fay', 'sam', 'bo', 'eve', 'ex'].map(user) as [string, string, string, string, string, string, string, string];
const api = 'token:api';
let market: ReturnType<typeof project>;
let billing: ReturnType<typeof project>;
beforeEach(async () => {
  await emptyDatabase(world.owner);
  world.memory.reads.clear();
  world.memory.logged.clear();
  world.refused.clear();
  market = project('market');
  billing = project('billing');
  const prod = environment(market, 'prod');
  const onMarket = () => JSON.stringify({ projects: { only: [market.id] }, environments: 'all' });
  await write(world, ...rows('projects', market, billing, project('gone~deleted-2026-11-01')), ...rows('environments', prod),
    ...rows('secrets', value(world, secret(prod, 'DATABASE_URL'), 'postgres://market')),
    ...rows('roles', role(true, 'owner', ['secret.read', 'secret.use', 'secret.write', 'grant.manage']), role(true, 'admin', ['grant.manage']), role(true, 'developer', ['secret.read', 'secret.use', 'secret.write']), role(true, 'member', []),
      role(false, 'developer', ['secret.read', 'secret.use', 'secret.write'])),
    // Ada and Cy own the whole instance, Dee owns market alone; Fay runs the instance as its Admin, Sam is an Admin of market alone.
    ...rows('principals', principal(ada, { role: 'owner' }), principal(cy, { role: 'owner' }), principal(dee, { role: 'owner', scope: onMarket() }), principal(fay, { role: 'admin' }),
      principal(sam, { role: 'admin', scope: onMarket() }), principal(bo), principal(eve), principal(ex, { status: 'removed', generation: 1 }), principal(api)),
    ...rows('policy', instance()),
    ...rows('grants', grant(bo, 'developer', { project: market }), grant(bo, 'developer', { environment: prod })),
    ...rows('credentials', ...[ada, cy, dee, fay, sam, bo, eve].map((who) => credential(`${who.slice(5, who.indexOf('@'))}-cli`, who)),
      // Ex's session from before their removal; a personal token of Ada's, scoped as tokens are.
      credential('ex-cli', ex), credential('ada-pat', ada, { kind: 'personal', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'developer' }]) })));
  world.woken.length = 0;
});

const shown = (label: string): Presented => ({ token: tokenOf(label).toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7' });
const asked = <O extends Change['op']>(label: string, change: Extract<Change, { op: O }>) => vault.change<O>({ ...shown(label), ...change } as never);
const add = (label: string, who: string, role = 'member', scope: unknown = null) => asked(label, { op: 'member.add', principal: who, role, scope } as never);
const restore = (label: string, who: string, role = 'member', scope: unknown = null) => asked(label, { op: 'member.restore', principal: who, role, scope } as never);
const setRole = (label: string, who: string, role: string, scope: unknown = null) => asked(label, { op: 'member.role', principal: who, role, scope } as never);
const remove = (label: string, who: string) => asked(label, { op: 'member.remove', principal: who } as never);

const reveal = (label: string): UseInput => ({ ...shown(label), project: 'market', environment: 'prod', mine: false, keys: ['DATABASE_URL'], purpose: 'reveal', upstream: null });
/** What a use by `label` is answered: the value, or why not. */
const uses = async (label: string) => {
  const answer = await vault.use(reveal(label));
  return 'refused' in answer ? answer.refused : answer.values.map((item) => ('refused' in item ? item.refused : item.value))[0];
};
const count = async (table: 'log_pending' | 'grants') => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM ${sql.identifier(table)}`))[0]!.n;
/** The entries kept: a change's, never a refusal's (D236), which `refusals` reads. */
const kept = async () => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM log_pending WHERE kept`))[0]!.n;
/** The refusals logged, oldest first. */
const refusals = async () =>
  (await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE NOT kept ORDER BY id`)).map((found) => entryOf(world.keys, found)!);
const members = async () => rowsOf<{ id: string; status: string; role: string; scope: string | null; generation: number }>(world.owner, sql`SELECT id, status, role, scope, generation FROM principals ORDER BY id`);
const row = async (id: string) => (await members()).find((member) => member.id === id);
/** The newest change's entry, as the signer will read it. */
const written = async () => {
  const [found] = await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE kept ORDER BY id DESC LIMIT 1`);
  return entryOf(world.keys, found!)!;
};
/** The rows an entry names, by table, as made, replaced, dropped or only read. */
const named = (entry: Awaited<ReturnType<typeof written>>) =>
  entry.rows.map(({ row: name, was, now }) => `${(JSON.parse(name) as string[])[0]} ${was === null ? 'made' : now === null ? 'dropped' : was === now ? 'read' : 'replaced'}`).sort();
/** Nothing written by `run`: no change's entry, no grant, no member's row moved. Its refusal may be logged, as `refusals` reads. */
async function nothingWritten(run: () => Promise<void>) {
  const before = [await kept(), await count('grants'), JSON.stringify(await members())];
  await run();
  assert.deepEqual([await kept(), await count('grants'), JSON.stringify(await members())], before);
}

test('whoever runs the instance admits a member, with any role but Owner, which only an Owner of the whole instance gives, its scope kept by project id', async () => {
  const fresh = user('new');
  assert.deepEqual(await add('fay-cli', fresh), { answer: { role: 'member', scope: null } });
  assert.deepEqual(await row(fresh), { id: fresh, status: 'active', role: 'member', scope: null, generation: 0 });
  const entry = await written();
  assert.deepEqual([entry.action, entry.actor, (entry.detail as { member: string }).member], ['member.add', fay, fresh]);
  // Who asked and what makes them run the instance, and the member's row, made: none of anyone's grants, nor any Owner.
  assert.deepEqual(named(entry), ['credentials read', 'principals made', 'principals read', 'roles read']);
  assert.ok(entry.objects.includes(`principal:${fresh}`), entry.objects.join());
  assert.equal(world.woken.length, 1);

  const scope = { projects: { only: ['market'] }, environments: { only: ['prod', 'dev', 'dev'] } };
  const stored = { projects: { only: [market.id] }, environments: { only: ['dev', 'prod'] } };
  assert.deepEqual(await add('ada-cli', user('dev'), 'developer', scope), { answer: { role: 'developer', scope: stored } });
  assert.deepEqual(JSON.parse((await row(user('dev')))!.scope!), stored);
  assert.ok(named(await written()).includes('projects read'), 'the project its scope names, by the slug it was named by');
  // A scope that narrows nothing is no scope; an Owner of the whole instance makes another.
  assert.deepEqual(await add('ada-cli', user('own'), 'owner', { projects: { except: [] }, environments: 'all' }), { answer: { role: 'owner', scope: null } });
  assert.deepEqual(await add('fay-cli', api.replace('api', 'ci')), { answer: { role: 'member', scope: null } }, 'a service account');
  // An Admin gives any role but Owner, Admin included, as 0.14 did.
  assert.deepEqual(await add('fay-cli', user('ops'), 'admin'), { answer: { role: 'admin', scope: null } });
  assert.deepEqual(await add('fay-cli', user('mo'), 'developer', { projects: { only: ['market'] }, environments: 'all' }), { answer: { role: 'developer', scope: { projects: { only: [market.id] }, environments: 'all' } } });
});

test('an admission is refused to whoever may not make it, and of someone the instance has, and writes nothing', async () => {
  await nothingWritten(async () => {
    assert.deepEqual(await add('fay-cli', user('new'), 'owner'), { refused: 'no_access' }, 'an Admin makes no Owner');
    assert.deepEqual(await add('fay-cli', user('new'), 'owner', { projects: { only: ['market'] }, environments: 'all' }), { refused: 'no_access' }, 'nor an Owner of one project');
    assert.deepEqual(await add('sam-cli', user('new')), { refused: 'no_access' }, 'an Admin of one project runs no instance');
    assert.deepEqual(await add('dee-cli', user('new'), 'owner'), { refused: 'no_access' }, 'nor does an Owner of one project');
    assert.deepEqual(await add('ada-pat', user('new')), { refused: 'no_access' }, 'a token runs no instance, whoever made it');
    assert.deepEqual(await add('bo-cli', 'token:mine'), { refused: 'no_access' }, 'a person who does not run the instance sets up no service account yet');
    assert.deepEqual(await add('nobody', user('new')), { refused: 'unauthenticated' });
    assert.deepEqual(await add('ex-cli', user('new')), { refused: 'unauthenticated' });
    assert.deepEqual(await add('fay-cli', bo), { refused: 'exists' });
    assert.deepEqual(await add('fay-cli', ex), { refused: 'removed' });
    assert.deepEqual(await add('ada-cli', user('new'), 'developer', { projects: { only: ['nowhere'] }, environments: 'all' }), { refused: 'no_access' }, 'a scope naming no project there is');
    assert.deepEqual(await add('ada-cli', user('new'), 'developer', { projects: { except: ['gone~deleted-2026-11-01'] }, environments: 'all' }), { refused: 'no_access' }, 'nor one deleted');
    assert.deepEqual(await restore('fay-cli', bo), { refused: 'exists' });
    assert.deepEqual(await restore('fay-cli', user('new')), { refused: 'not_a_member' });
    assert.deepEqual(await restore('fay-cli', ex, 'owner'), { refused: 'no_access' }, 'an Admin brings back no Owner');
    assert.deepEqual(await restore('bo-cli', ex), { refused: 'no_access' });
  });
  assert.deepEqual(await restore('fay-cli', ex, 'admin'), { answer: { role: 'admin', scope: null } }, 'but any other role');
});

test('a service account holds no instance role but member, and one removed comes back by whoever runs the whole instance, whoever removed it', async () => {
  assert.deepEqual(await remove('ada-cli', api), { answer: { revoked: 0 } });
  await nothingWritten(async () => {
    assert.deepEqual(await restore('bo-cli', api), { refused: 'no_access' }, 'one who does not run the instance');
    assert.deepEqual(await restore('sam-cli', api), { refused: 'no_access' }, 'nor one who runs part of it');
    for (const role of ['admin', 'owner', 'developer']) await assert.rejects(restore('ada-cli', api, role), TypeError, role);
    await assert.rejects(setRole('ada-cli', api, 'member'), TypeError);
  });
  assert.deepEqual(await restore('fay-cli', api), { answer: { role: 'member', scope: null } }, 'Ada removed it; Fay runs the instance');
  assert.deepEqual(await row(api), { id: api, status: 'active', role: 'member', scope: null, generation: 1 });
});

test('a member brought back starts with no grant, in the generation their removal moved on to: what they held before stays dead', async () => {
  assert.equal(await uses('ex-cli'), 'unauthenticated');
  assert.deepEqual(await restore('fay-cli', ex), { answer: { role: 'member', scope: null } });
  assert.deepEqual(await row(ex), { id: ex, status: 'active', role: 'member', scope: null, generation: 1 });
  assert.equal((await written()).action, 'member.restore');
  world.tick(2000);
  assert.equal(await uses('ex-cli'), 'unauthenticated', 'a session of the membership before');
  await write(world, ...rows('credentials', credential('ex-new', ex, { generation: 1 })));
  assert.equal(await uses('ex-new'), 'no_access', 'one of this membership, which holds nothing yet');
});

test('an Owner of the whole instance sets a person\'s role and its scope, and a use by them holds it within the vault\'s memory', async () => {
  assert.equal(await uses('eve-cli'), 'no_access');
  assert.deepEqual(await setRole('ada-cli', eve, 'developer'), { answer: { role: 'developer', scope: null } });
  const entry = await written();
  assert.equal(entry.action, 'member.role');
  // It counts the Owners, every one of them, as it may have to keep one: their rows are named with the caller's and the member's.
  assert.deepEqual(named(entry), ['credentials read', 'principals read', 'principals read', 'principals read', 'principals replaced', 'roles read']);
  world.tick(2000);
  assert.equal(await uses('eve-cli'), 'postgres://market');
  assert.deepEqual(await setRole('ada-cli', eve, 'developer', { projects: { only: ['billing'] }, environments: 'all' }), { answer: { role: 'developer', scope: { projects: { only: [billing.id] }, environments: 'all' } } });
  assert.equal(await uses('eve-cli'), 'postgres://market', 'within the memory, the read before');
  world.tick(2000);
  assert.equal(await uses('eve-cli'), 'no_access');
  // An Owner steps down while another owns the whole instance.
  assert.deepEqual(await setRole('cy-cli', cy, 'admin'), { answer: { role: 'admin', scope: null } });
});

test('an Admin sets any role but an Owner\'s, Admin included, never their own', async () => {
  assert.deepEqual(await setRole('fay-cli', eve, 'admin'), { answer: { role: 'admin', scope: null } }, 'an Admin makes another');
  assert.deepEqual(await setRole('fay-cli', eve, 'developer', { projects: { only: ['market'] }, environments: 'all' }), { answer: { role: 'developer', scope: { projects: { only: [market.id] }, environments: 'all' } } });
  assert.deepEqual(await setRole('fay-cli', sam, 'admin'), { answer: { role: 'admin', scope: null } }, 'and widens another Admin\'s scope');
  await nothingWritten(async () => {
    assert.deepEqual(await setRole('fay-cli', eve, 'owner'), { refused: 'no_access' }, 'makes no Owner');
    assert.deepEqual(await setRole('fay-cli', eve, 'owner', { projects: { only: ['market'] }, environments: 'all' }), { refused: 'no_access' }, 'not even of one project');
    assert.deepEqual(await setRole('fay-cli', ada, 'admin'), { refused: 'no_access' }, 'changes no Owner of the whole instance');
    assert.deepEqual(await setRole('fay-cli', dee, 'admin'), { refused: 'no_access' }, 'nor of one project');
    assert.deepEqual(await setRole('fay-cli', fay, 'owner'), { refused: 'no_access' }, 'their own, up');
    assert.deepEqual(await setRole('fay-cli', fay, 'developer'), { refused: 'no_access' }, 'their own, down');
    assert.deepEqual(await setRole('fay-cli', fay, 'admin'), { refused: 'no_access' }, 'their own, as it is');
    assert.deepEqual(await setRole('dee-cli', dee, 'owner'), { refused: 'no_access' }, 'an Owner of one project runs no instance');
  });
});

test('an Owner\'s role is set by an Owner of the whole instance alone, never the last one\'s away, and never a named Owner\'s, and a refusal writes nothing', async () => {
  await nothingWritten(async () => {
    assert.deepEqual(await setRole('sam-cli', eve, 'developer'), { refused: 'no_access' }, 'an Admin of one project');
    assert.deepEqual(await setRole('dee-cli', eve, 'developer'), { refused: 'no_access' }, 'an Owner of one project');
    assert.deepEqual(await setRole('ada-pat', eve, 'developer'), { refused: 'no_access' }, 'an Owner\'s token');
    assert.deepEqual(await setRole('ada-cli', user('new'), 'developer'), { refused: 'not_a_member' });
    assert.deepEqual(await setRole('ada-cli', ex, 'developer'), { refused: 'removed' });
    assert.deepEqual(await setRole('ada-cli', eve, 'developer', { projects: { except: ['nowhere'] }, environments: 'all' }), { refused: 'no_access' });
  });
  assert.ok('answer' in (await setRole('ada-cli', cy, 'owner', { projects: { only: ['market'] }, environments: 'all' })), 'Cy, an Owner of market alone from now');
  await nothingWritten(async () => {
    assert.deepEqual(await setRole('ada-cli', ada, 'admin'), { refused: 'last_owner' });
    assert.deepEqual(await setRole('ada-cli', ada, 'owner', { projects: 'all', environments: { only: ['prod'] } }), { refused: 'last_owner' }, 'narrowed, she would own no whole instance');
  });
  assert.deepEqual(await setRole('ada-cli', ada, 'owner'), { answer: { role: 'owner', scope: null } }, 'as she is: she stays the Owner');

  const named = openLocalVault(world.db, { ...world, owners: ['cy@acme.example'] }, { wake: world.wake, now: world.now });
  const cyBack = await named.change({ ...shown('ada-cli'), op: 'member.role', principal: cy, role: 'owner', scope: null });
  assert.deepEqual(cyBack, { answer: { role: 'owner', scope: null } });
  await nothingWritten(async () => {
    assert.deepEqual(await named.change({ ...shown('cy-cli'), op: 'member.role', principal: cy, role: 'admin', scope: null }), { refused: 'configured_owner' });
    assert.deepEqual(await named.change({ ...shown('ada-cli'), op: 'member.remove', principal: cy }), { refused: 'configured_owner' });
  });
});

test('a person the deployment names an Owner is admitted as one, or not at all', async () => {
  const named = openLocalVault(world.db, { ...world, owners: ['boss@acme.example'] }, { wake: world.wake, now: world.now });
  const boss = user('boss');
  await nothingWritten(async () => {
    assert.deepEqual(await named.change({ ...shown('fay-cli'), op: 'member.add', principal: boss, role: 'member', scope: null }), { refused: 'configured_owner' });
    assert.deepEqual(await named.change({ ...shown('ada-cli'), op: 'member.add', principal: boss, role: 'owner', scope: { projects: { only: ['market'] }, environments: 'all' } }), { refused: 'configured_owner' });
  });
  assert.deepEqual(await named.change({ ...shown('ada-cli'), op: 'member.add', principal: boss, role: 'owner', scope: null }), { answer: { role: 'owner', scope: null } });
});

test('a removed person the deployment names an Owner comes back as one, which only an Owner of the whole instance gives', async () => {
  const named = openLocalVault(world.db, { ...world, owners: ['ex@acme.example'] }, { wake: world.wake, now: world.now });
  const back = (label: string, role: string, scope: unknown = null) => named.change({ ...shown(label), op: 'member.restore', principal: ex, role, scope } as never);
  await nothingWritten(async () => {
    assert.deepEqual(await back('fay-cli', 'member'), { refused: 'configured_owner' }, 'an Admin, as anything but an Owner');
    assert.deepEqual(await back('fay-cli', 'admin'), { refused: 'configured_owner' });
    assert.deepEqual(await back('fay-cli', 'owner'), { refused: 'no_access' }, 'an Admin makes no Owner');
    assert.deepEqual(await back('ada-cli', 'admin'), { refused: 'configured_owner' });
    assert.deepEqual(await back('ada-cli', 'owner', { projects: { only: ['market'] }, environments: 'all' }), { refused: 'configured_owner' }, 'an Owner of one project');
  });
  assert.deepEqual(await back('ada-cli', 'owner'), { answer: { role: 'owner', scope: null } });
  assert.deepEqual(await row(ex), { id: ex, status: 'active', role: 'owner', scope: null, generation: 1 });
});

test('a removal deletes the member\'s grants and moves their generation on, which ends their session within the vault\'s memory', async () => {
  assert.equal(await uses('bo-cli'), 'postgres://market');
  assert.deepEqual(await remove('fay-cli', bo), { answer: { revoked: 2 } });
  assert.deepEqual(await row(bo), { id: bo, status: 'removed', role: 'member', scope: null, generation: 1 });
  assert.equal(await count('grants'), 0);
  const entry = await written();
  assert.equal(entry.action, 'member.remove');
  assert.deepEqual(named(entry), ['credentials read', 'grants dropped', 'grants dropped', 'principals read', 'principals read', 'principals read', 'principals read', 'principals replaced', 'roles read']);
  assert.deepEqual((entry.detail as { revoked: { role: string }[] }).revoked.map((grant) => grant.role), ['developer', 'developer']);
  assert.ok(entry.objects.includes(`project:${market.id}`), 'each project\'s log shows it');
  assert.equal(await uses('bo-cli'), 'postgres://market', 'within the memory, the read before');
  world.tick(2000);
  assert.equal(await uses('bo-cli'), 'unauthenticated');
  // An Owner of the whole instance removes another, and anyone who runs it removes themselves.
  assert.deepEqual(await remove('ada-cli', cy), { answer: { revoked: 0 } });
  assert.deepEqual(await remove('fay-cli', fay), { answer: { revoked: 0 } });
});

test('a removed member whose rows are deleted around the vault is admitted anew in generation 0, their old session put back stands for it, and the signer finds the entry false history', async () => {
  // The design's adversary deletes rows (docs/design/0.16.md, "What it promises"): the decision cannot tell
  // such a member from a newcomer, but its entry says the row it made replaced none, and the signer's
  // mirror holds Bo's removed row. Its credential would have to be put back too, a row put back.
  const signer = await Signer.open({ db: world.db, keys: world.keys, now: world.now, store: memoryStore() });
  assert.deepEqual(await remove('fay-cli', bo), { answer: { revoked: 2 } });
  for (const hash of world.woken.splice(0)) await signer.wake(hash);
  await signer.run(true);
  assert.deepEqual(await signer.take(), []);
  // Bo's session row, kept as it was, MAC and all, to put back once the vault has made Bo anew.
  const [{ saved }] = await rowsOf<{ saved: unknown }>(world.owner, sql`SELECT to_jsonb(c) AS saved FROM credentials c WHERE principal = ${bo}`) as [{ saved: unknown }];
  await world.owner.execute(sql`DELETE FROM credentials WHERE principal = ${bo}`);
  await world.owner.execute(sql`DELETE FROM principals WHERE id = ${bo}`);
  assert.deepEqual(await add('fay-cli', bo), { answer: { role: 'member', scope: null } });
  assert.equal((await row(bo))!.generation, 0);
  await world.owner.execute(sql`INSERT INTO credentials SELECT * FROM jsonb_populate_record(NULL::credentials, ${JSON.stringify(saved)}::jsonb)`);
  world.tick(2000);
  // The genuine old session stands again, for the membership made anew: it holds what that holds, no grant of before.
  assert.equal(await uses('bo-cli'), 'no_access');
  for (const hash of world.woken.splice(0)) await signer.wake(hash);
  await signer.run(false);
  assert.deepEqual(await signer.take(), [{ found: 'rewritten', of: JSON.stringify(['principals', bo]) }]);
});

test('a removal is refused to whoever may not make it, of an Owner but by an Owner of the whole instance, and of the last one, and writes nothing', async () => {
  await nothingWritten(async () => {
    assert.deepEqual(await remove('sam-cli', bo), { refused: 'no_access' });
    assert.deepEqual(await remove('dee-cli', bo), { refused: 'no_access' });
    assert.deepEqual(await remove('ada-pat', bo), { refused: 'no_access' });
    assert.deepEqual(await remove('bo-cli', api), { refused: 'no_access' }, 'a person who does not run the instance removes no service account yet');
    assert.deepEqual(await remove('fay-cli', ada), { refused: 'no_access' }, 'an Admin removes no Owner');
    assert.deepEqual(await remove('fay-cli', dee), { refused: 'no_access' }, 'nor an Owner of one project');
    assert.deepEqual(await remove('fay-cli', ex), { refused: 'removed' });
    assert.deepEqual(await remove('fay-cli', user('new')), { refused: 'not_a_member' });
  });
  assert.ok('answer' in (await remove('ada-cli', cy)));
  await nothingWritten(async () => assert.deepEqual(await remove('ada-cli', ada), { refused: 'last_owner' }));
});

test('two Owners demoting each other side by side: the second starts over, finds itself no Owner, and one stays', async () => {
  const deciding = { workloads: world.workloads, owners: world.owners };
  const op = (label: string, who: string) => OPERATIONS['member.role']({ ...shown(label), op: 'member.role', principal: who, role: 'admin', scope: null }, deciding);
  const [first, second] = await Promise.all([prepare(world, op('ada-cli', cy)), prepare(world, op('cy-cli', ada))]);
  assert.ok(!('refused' in first!) && !('refused' in second!), 'each decided alone, with another Owner left');
  assert.equal(await commit(world, first), true);
  assert.equal(await commit(world, second), false, 'the Owners it counted are no longer the ones it read');
  assert.deepEqual(await setRole('cy-cli', ada, 'admin'), { refused: 'no_access' });
  assert.deepEqual((await members()).filter((member) => member.role === 'owner' && member.scope === null).map((member) => member.id), [ada]);
});

test('a removal and a demotion side by side, each counting on the other Owner: the second starts over and keeps the last one', async () => {
  const deciding = { workloads: world.workloads, owners: world.owners };
  const removing = OPERATIONS['member.remove']({ ...shown('ada-cli'), op: 'member.remove', principal: cy }, deciding);
  const stepping = OPERATIONS['member.role']({ ...shown('cy-cli'), op: 'member.role', principal: ada, role: 'admin', scope: null }, deciding);
  const [first, second] = await Promise.all([prepare(world, removing), prepare(world, stepping)]);
  assert.ok(!('refused' in first!) && !('refused' in second!), 'Ada counts on herself staying, Cy\'s demotion of her on Cy');
  assert.equal(await commit(world, first), true);
  assert.equal(await commit(world, second), false, 'Cy\'s row, and the Owners it counted, are not the ones it read');
  assert.deepEqual(await setRole('cy-cli', ada, 'admin'), { refused: 'unauthenticated' }, 'Cy, removed, asks nothing');
  assert.deepEqual(await setRole('ada-cli', ada, 'admin'), { refused: 'last_owner' });
  assert.deepEqual((await members()).filter((member) => member.status === 'active' && member.role === 'owner' && member.scope === null).map((member) => member.id), [ada]);
});

test('three Owners stepping down at once: each decided alone, and the last one is refused', async () => {
  assert.ok('answer' in (await setRole('ada-cli', fay, 'owner')));
  const results = await Promise.all(['ada-cli', 'cy-cli', 'fay-cli'].map((label) => setRole(label, user(label.slice(0, -4)), 'admin')));
  assert.deepEqual(results.filter((result) => 'refused' in result), [{ refused: 'last_owner' }]);
  assert.equal((await members()).filter((member) => member.role === 'owner' && member.scope === null).length, 1);
});

test('a removal beside a new grant of the member\'s starts over, and takes that grant too', async () => {
  const deciding = { workloads: world.workloads, owners: world.owners };
  const prepared = await prepare(world, OPERATIONS['member.remove']({ ...shown('fay-cli'), op: 'member.remove', principal: bo }, deciding));
  assert.ok(!('refused' in prepared));
  await write(world, ...rows('grants', grant(bo, 'developer', { project: billing })));
  assert.equal(await commit(world, prepared), false, 'a grant came since its read');
  assert.deepEqual(await remove('fay-cli', bo), { answer: { revoked: 3 } });
  assert.equal(await count('grants'), 0);
});

test('a row written around the vault is no row: an Owner edited in place or forged counts for nothing, and a scope\'s project edited names none', async () => {
  // Cy's row, edited: no MAC of the vault's, so no Owner to keep, and no caller either.
  await world.owner.execute(sql`UPDATE principals SET created_by = 'user:mallory@acme.example' WHERE id = ${cy}`);
  await nothingWritten(async () => {
    assert.deepEqual(await setRole('ada-cli', ada, 'admin'), { refused: 'last_owner' });
    assert.deepEqual(await remove('ada-cli', ada), { refused: 'last_owner' });
    assert.deepEqual(await setRole('cy-cli', eve, 'developer'), { refused: 'unauthenticated' });
    assert.deepEqual(await setRole('ada-cli', cy, 'admin'), { refused: 'not_a_member' });
  });
  // A forged Owner, with a MAC that is not the vault's.
  await world.owner.execute(sql`INSERT INTO principals (id, status, role, generation, created_at, created_by, status_changed_at, status_changed_by, mac) VALUES (${user('mallory')}, 'active', 'owner', 0, now(), 'x', now(), 'x', decode(repeat('00', 36), 'hex'))`);
  await nothingWritten(async () => assert.deepEqual(await setRole('ada-cli', ada, 'admin'), { refused: 'last_owner' }));
  // A project edited around the vault is no project for a scope to name.
  await world.owner.execute(sql`UPDATE projects SET name = 'Billing!' WHERE id = ${billing.id}`);
  await nothingWritten(async () => assert.deepEqual(await setRole('ada-cli', eve, 'developer', { projects: { only: ['billing'] }, environments: 'all' }), { refused: 'no_access' }));
  // Admitting someone whose row someone edited is a fault, not a refusal: the engine replaces no row it cannot read.
  await assert.rejects(add('fay-cli', cy), /principals_pkey|duplicate key/);
});

test('a workload\'s session that is stopped or narrowed is told so, as for any change, and runs no instance', async () => {
  const bound = binding(api, { profile: 'kubernetes', scope: '[]', policy: '{}' });
  const pod = session('pod', bound);
  await write(world, ...rows('bindings', bound), ...rows('credentials', pod, session('tool', bound, { ancestors: JSON.stringify([pod.id]) })));
  const by = (label: string) => vault.change({ ...shown(label), proof: label, op: 'member.add', principal: user('new'), role: 'member', scope: null });
  await nothingWritten(async () => {
    assert.deepEqual(await by('pod'), { refused: 'no_access' });
    assert.deepEqual(await by('tool'), { refused: 'narrowed' });
  });
  await amend(world, 'bindings', eq(bindings.id, bound.id), { frozenAt: new Date(world.now()) });
  await nothingWritten(async () => assert.deepEqual(await by('pod'), { refused: 'frozen' }));
});

test('a member change that is not what the contract says is a fault, before any read', async () => {
  const bad: unknown[] = [
    { op: 'member.add', principal: 'ada@acme.example', role: 'member', scope: null },
    { op: 'member.add', principal: 'user:Ada@acme.example', role: 'member', scope: null },
    { op: 'member.add', principal: 'user: ada', role: 'member', scope: null },
    { op: 'member.add', principal: `user:${'a'.repeat(260)}`, role: 'member', scope: null },
    { op: 'member.add', principal: user('new'), role: 'boss', scope: null },
    { op: 'member.add', principal: user('new'), role: 'toString', scope: null },
    { op: 'member.add', principal: user('new'), role: 'member', scope: { projects: 'all', environments: 'all' } },
    { op: 'member.add', principal: user('new'), role: 'developer', scope: { projects: 'all' } },
    { op: 'member.add', principal: user('new'), role: 'developer', scope: { projects: 'all', environments: 'all', more: 1 } },
    { op: 'member.add', principal: user('new'), role: 'developer', scope: { projects: { only: 'market' }, environments: 'all' } },
    { op: 'member.add', principal: user('new'), role: 'developer', scope: { projects: { only: [''] }, environments: 'all' } },
    { op: 'member.add', principal: user('new'), role: 'developer', scope: { projects: { only: ['a'], except: ['b'] }, environments: 'all' } },
    { op: 'member.add', principal: user('new'), role: 'developer', scope: { projects: { only: Array.from({ length: 1001 }, (_, i) => `p${i}`) }, environments: 'all' } },
    { op: 'member.add', principal: 'token:ci', role: 'developer', scope: null },
    { op: 'member.add', principal: user('new'), role: 'member' },
    { op: 'member.role', principal: api, role: 'member', scope: null },
    { op: 'member.restore', principal: 7, role: 'member', scope: null },
    { op: 'member.remove', principal: 'nobody' },
  ];
  for (const change of bad) await assert.rejects(vault.change({ ...shown('ada-cli'), ...(change as object) } as never), TypeError, JSON.stringify(change).slice(0, 80));
  assert.equal(world.woken.length, 0);
});

test('a refusal is logged once a minute for who asked and what, naming the member only by a row the read found', async () => {
  const fresh = user('new');
  const onMarket = { projects: { only: ['market'] }, environments: 'all' };
  assert.deepEqual(await add('bo-cli', fresh), { refused: 'no_access' }, 'a member admits nobody');
  assert.deepEqual(await add('bo-cli', user('other')), { refused: 'no_access' }, 'again in the minute');
  assert.deepEqual(await remove('bo-cli', eve), { refused: 'no_access' });
  assert.deepEqual(await add('fay-cli', fresh, 'owner', onMarket), { refused: 'no_access' }, 'an Admin makes no Owner');
  assert.deepEqual(await setRole('sam-cli', bo, 'developer'), { refused: 'no_access' });
  assert.deepEqual(await restore('ada-cli', 'user:rotate-now@evil.example'), { refused: 'not_a_member' }, 'someone the instance never had');
  assert.deepEqual(await remove('nobody', bo), { refused: 'unauthenticated' });
  const denied = await refusals();
  assert.deepEqual(denied.map((entry) => [entry.action, entry.actor, entry.detail, entry.objects.slice(2)]), [
    ['member.add', bo, { refused: 'no_access' }, []],
    ['member.remove', bo, { refused: 'no_access' }, [`principal:${eve}`]],
    ['member.add', fay, { refused: 'no_access' }, [`project:${market.id}`]],
    ['member.role', sam, { refused: 'no_access' }, [`principal:${bo}`]],
    ['member.restore', ada, { refused: 'not_a_member' }, []],
  ]);
  assert.deepEqual(denied.map((entry) => entry.objects.slice(0, 2)), denied.map((entry) => [`principal:${entry.actor}`, `credential:${entry.credential}`]));
  assert.ok(denied.every((entry) => entry.rows.length === 0 && !JSON.stringify(entry).includes('evil')));
});
