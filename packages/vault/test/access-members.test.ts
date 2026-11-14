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
import { amend, binding, credential, environment, grant, identity, instance, principal, project, role, rows, secret, session, tokenOf, user, value, write } from './world.ts';

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
const put = (label: string, who: string, role: string | null = null, scope: unknown = null) => asked(label, { op: 'member.put', principal: who, role, scope } as never);
/** A put's answer: the standing it leaves, and whether it admitted or brought back the member (`created`), or set their role. */
const as = (created: boolean, role: string, scope: unknown = null) => ({ answer: { role, scope, created } });
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
  assert.deepEqual(await put('fay-cli', fresh), as(true, 'member'));
  assert.deepEqual(await row(fresh), { id: fresh, status: 'active', role: 'member', scope: null, generation: 0 });
  const entry = await written();
  assert.deepEqual([entry.action, entry.actor, (entry.detail as { member: string }).member], ['member.add', fay, fresh]);
  // Who asked and what makes them run the instance, the Owners (Ada, Cy, Dee) a put of an active member would count, and the member's row, made: none of anyone's grants.
  assert.deepEqual(named(entry), ['credentials read', 'principals made', 'principals read', 'principals read', 'principals read', 'principals read', 'roles read']);
  assert.ok(entry.objects.includes(`principal:${fresh}`), entry.objects.join());
  assert.equal(world.woken.length, 1);

  const scope = { projects: { only: ['market'] }, environments: { only: ['prod', 'dev', 'dev'] } };
  const stored = { projects: { only: [market.id] }, environments: { only: ['dev', 'prod'] } };
  assert.deepEqual(await put('ada-cli', user('dev'), 'developer', scope), as(true, 'developer', stored));
  assert.deepEqual(JSON.parse((await row(user('dev')))!.scope!), stored);
  assert.ok(named(await written()).includes('projects read'), 'the project its scope names, by the slug it was named by');
  // A scope that narrows nothing is no scope; an Owner of the whole instance makes another.
  assert.deepEqual(await put('ada-cli', user('own'), 'owner', { projects: { except: [] }, environments: 'all' }), as(true, 'owner'));
  assert.deepEqual(await put('fay-cli', api.replace('api', 'ci')), as(true, 'member'), 'a service account');
  // An Admin gives any role but Owner, Admin included, as 0.14 did.
  assert.deepEqual(await put('fay-cli', user('ops'), 'admin'), as(true, 'admin'));
  assert.deepEqual(await put('fay-cli', user('mo'), 'developer', { projects: { only: ['market'] }, environments: 'all' }), as(true, 'developer', { projects: { only: [market.id] }, environments: 'all' }));
});

test('an admission is refused to whoever may not make it, and writes nothing', async () => {
  await nothingWritten(async () => {
    assert.deepEqual(await put('fay-cli', user('new'), 'owner'), { refused: 'no_access' }, 'an Admin makes no Owner');
    assert.deepEqual(await put('fay-cli', user('new'), 'owner', { projects: { only: ['market'] }, environments: 'all' }), { refused: 'no_access' }, 'nor an Owner of one project');
    assert.deepEqual(await put('sam-cli', user('new')), { refused: 'no_access' }, 'an Admin of one project runs no instance');
    assert.deepEqual(await put('dee-cli', user('new'), 'owner'), { refused: 'no_access' }, 'nor does an Owner of one project');
    assert.deepEqual(await put('ada-pat', user('new')), { refused: 'no_access' }, 'a token runs no instance, whoever made it');
    assert.deepEqual(await put('eve-cli', 'token:mine'), { refused: 'no_access' }, 'a person who holds nothing sets up no service account (access-services.test.ts)');
    assert.deepEqual(await put('nobody', user('new')), { refused: 'unauthenticated' });
    assert.deepEqual(await put('ex-cli', user('new')), { refused: 'unauthenticated' });
    assert.deepEqual(await put('ada-cli', user('new'), 'developer', { projects: { only: ['nowhere'] }, environments: 'all' }), { refused: 'no_access' }, 'a scope naming no project there is');
    await assert.rejects(put('ada-cli', user('new'), 'developer', { projects: { except: ['gone~deleted-2026-11-01'] }, environments: 'all' }), TypeError, 'nor one deleted, by its tombstone');
    assert.deepEqual(await put('fay-cli', ex, 'owner'), { refused: 'no_access' }, 'an Admin brings back no Owner');
    assert.deepEqual(await put('bo-cli', ex), { refused: 'no_access' });
  });
  assert.deepEqual(await put('fay-cli', ex, 'admin'), as(true, 'admin'), 'but any other role');
});

test('a service account holds no instance role but member, and one removed comes back by whoever runs the whole instance, whoever removed it', async () => {
  assert.deepEqual(await remove('ada-cli', api), { answer: { revoked: 0 } });
  await nothingWritten(async () => {
    assert.deepEqual(await put('bo-cli', api), { refused: 'no_access' }, 'one who does not run the instance');
    assert.deepEqual(await put('sam-cli', api), { refused: 'no_access' }, 'nor one who runs part of it');
    // Refused, not a fault: the route answers it as 0.14.7 did (`service_cannot_hold_role`).
    for (const role of ['admin', 'owner', 'developer']) assert.deepEqual(await put('ada-cli', api, role), { refused: 'invalid' }, role);
  });
  assert.deepEqual(await put('fay-cli', api), as(true, 'member'), 'Ada removed it; Fay runs the instance');
  assert.deepEqual(await row(api), { id: api, status: 'active', role: 'member', scope: null, generation: 1 });
});

test('a member brought back starts with no grant, in the generation their removal moved on to: what they held before stays dead', async () => {
  assert.equal(await uses('ex-cli'), 'unauthenticated');
  assert.deepEqual(await put('fay-cli', ex), as(true, 'member'));
  assert.deepEqual(await row(ex), { id: ex, status: 'active', role: 'member', scope: null, generation: 1 });
  assert.equal((await written()).action, 'member.restore');
  world.tick(2000);
  assert.equal(await uses('ex-cli'), 'unauthenticated', 'a session of the membership before');
  await write(world, ...rows('credentials', credential('ex-new', ex, { generation: 1 })));
  assert.equal(await uses('ex-new'), 'no_access', 'one of this membership, which holds nothing yet');
});

test('an Owner of the whole instance sets a person\'s role and its scope, and a use by them holds it at once: a person\'s read is never remembered', async () => {
  assert.equal(await uses('eve-cli'), 'no_access');
  assert.deepEqual(await put('ada-cli', eve, 'developer'), as(false, 'developer'));
  const entry = await written();
  assert.equal(entry.action, 'member.role');
  // It counts the Owners, every one of them, as it may have to keep one: their rows are named with the caller's and the member's.
  assert.deepEqual(named(entry), ['credentials read', 'principals read', 'principals read', 'principals read', 'principals replaced', 'roles read']);
  world.tick(2000);
  assert.equal(await uses('eve-cli'), 'postgres://market');
  assert.deepEqual(await put('ada-cli', eve, 'developer', { projects: { only: ['billing'] }, environments: 'all' }), as(false, 'developer', { projects: { only: [billing.id] }, environments: 'all' }));
  assert.equal(await uses('eve-cli'), 'no_access', 'at once, within what would be the memory');
  // An Owner steps down while another owns the whole instance.
  assert.deepEqual(await put('cy-cli', cy, 'admin'), as(false, 'admin'));
});

test('an Admin sets any role but an Owner\'s, Admin included, never their own', async () => {
  assert.deepEqual(await put('fay-cli', eve, 'admin'), as(false, 'admin'), 'an Admin makes another');
  assert.deepEqual(await put('fay-cli', eve, 'developer', { projects: { only: ['market'] }, environments: 'all' }), as(false, 'developer', { projects: { only: [market.id] }, environments: 'all' }));
  assert.deepEqual(await put('fay-cli', sam, 'admin'), as(false, 'admin'), 'and widens another Admin\'s scope');
  await nothingWritten(async () => {
    assert.deepEqual(await put('fay-cli', eve, 'owner'), { refused: 'no_access' }, 'makes no Owner');
    assert.deepEqual(await put('fay-cli', eve, 'owner', { projects: { only: ['market'] }, environments: 'all' }), { refused: 'no_access' }, 'not even of one project');
    assert.deepEqual(await put('fay-cli', ada, 'admin'), { refused: 'no_access' }, 'changes no Owner of the whole instance');
    assert.deepEqual(await put('fay-cli', dee, 'admin'), { refused: 'no_access' }, 'nor of one project');
    assert.deepEqual(await put('fay-cli', fay, 'owner'), { refused: 'no_access' }, 'their own, up');
    assert.deepEqual(await put('fay-cli', fay, 'developer'), { refused: 'no_access' }, 'their own, down');
    assert.deepEqual(await put('dee-cli', dee, 'owner'), { refused: 'no_access' }, 'an Owner of one project runs no instance');
  });
});

test('a role asked as it is changes nothing, and whoever runs the instance may ask it, their own or an Owner\'s', async () => {
  const before = JSON.stringify(await members());
  assert.deepEqual(await put('fay-cli', fay, 'admin'), as(false, 'admin'), 'an Admin, their own');
  assert.deepEqual(await put('fay-cli', ada, 'owner'), as(false, 'owner'), 'an Owner\'s, by an Admin');
  assert.equal(JSON.stringify(await members()), before, 'no member\'s row moved');
  const entry = await written();
  assert.deepEqual([entry.action, entry.detail], ['member.role', { member: ada, role: 'owner', scope: null, unchanged: true }], 'its entry says nothing changed, and reads as no promotion');
  assert.ok(named(entry).every((name) => name.endsWith(' read')), 'and wrote no row');
  assert.deepEqual(await put('fay-cli', ada, 'owner', { projects: { only: ['market'] }, environments: 'all' }), { refused: 'no_access' }, 'but not narrowed');
});

test('an Owner\'s role is set by an Owner of the whole instance alone, never the last one\'s away, and never a named Owner\'s, and a refusal writes nothing', async () => {
  await nothingWritten(async () => {
    assert.deepEqual(await put('sam-cli', eve, 'developer'), { refused: 'no_access' }, 'an Admin of one project');
    assert.deepEqual(await put('dee-cli', eve, 'developer'), { refused: 'no_access' }, 'an Owner of one project');
    assert.deepEqual(await put('ada-pat', eve, 'developer'), { refused: 'no_access' }, 'an Owner\'s token');
    assert.deepEqual(await put('ada-cli', eve, 'developer', { projects: { except: ['nowhere'] }, environments: 'all' }), { refused: 'no_access' });
  });
  assert.ok('answer' in (await put('ada-cli', cy, 'owner', { projects: { only: ['market'] }, environments: 'all' })), 'Cy, an Owner of market alone from now');
  await nothingWritten(async () => {
    assert.deepEqual(await put('ada-cli', ada, 'admin'), { refused: 'last_owner' });
    assert.deepEqual(await put('ada-cli', ada, 'owner', { projects: 'all', environments: { only: ['prod'] } }), { refused: 'last_owner' }, 'narrowed, she would own no whole instance');
  });
  assert.deepEqual(await put('ada-cli', ada, 'owner'), as(false, 'owner'), 'as she is: she stays the Owner');

  const named = openLocalVault(world.db, { ...world, owners: ['cy@acme.example'] }, { wake: world.wake, now: world.now });
  const cyBack = await named.change({ ...shown('ada-cli'), op: 'member.put', principal: cy, role: 'owner', scope: null });
  assert.deepEqual(cyBack, as(false, 'owner'));
  await nothingWritten(async () => {
    assert.deepEqual(await named.change({ ...shown('cy-cli'), op: 'member.put', principal: cy, role: 'admin', scope: null }), { refused: 'configured_owner' });
    assert.deepEqual(await named.change({ ...shown('ada-cli'), op: 'member.remove', principal: cy }), { refused: 'configured_owner' });
  });
});

test('a person the deployment names an Owner is admitted as one, or not at all', async () => {
  const named = openLocalVault(world.db, { ...world, owners: ['boss@acme.example'] }, { wake: world.wake, now: world.now });
  const boss = user('boss');
  await nothingWritten(async () => {
    assert.deepEqual(await named.change({ ...shown('fay-cli'), op: 'member.put', principal: boss, role: 'member', scope: null }), { refused: 'configured_owner' });
    assert.deepEqual(await named.change({ ...shown('ada-cli'), op: 'member.put', principal: boss, role: 'owner', scope: { projects: { only: ['market'] }, environments: 'all' } }), { refused: 'configured_owner' });
  });
  assert.deepEqual(await named.change({ ...shown('ada-cli'), op: 'member.put', principal: boss, role: 'owner', scope: null }), as(true, 'owner'));
});

test('a removed person the deployment names an Owner comes back as one, which only an Owner of the whole instance gives', async () => {
  const named = openLocalVault(world.db, { ...world, owners: ['ex@acme.example'] }, { wake: world.wake, now: world.now });
  const back = (label: string, role: string, scope: unknown = null) => named.change({ ...shown(label), op: 'member.put', principal: ex, role, scope } as never);
  await nothingWritten(async () => {
    assert.deepEqual(await back('fay-cli', 'member'), { refused: 'configured_owner' }, 'an Admin, as anything but an Owner');
    assert.deepEqual(await back('fay-cli', 'admin'), { refused: 'configured_owner' });
    assert.deepEqual(await back('fay-cli', 'owner'), { refused: 'no_access' }, 'an Admin makes no Owner');
    assert.deepEqual(await back('ada-cli', 'admin'), { refused: 'configured_owner' });
    assert.deepEqual(await back('ada-cli', 'owner', { projects: { only: ['market'] }, environments: 'all' }), { refused: 'configured_owner' }, 'an Owner of one project');
  });
  assert.deepEqual(await back('ada-cli', 'owner'), as(true, 'owner'));
  assert.deepEqual(await row(ex), { id: ex, status: 'active', role: 'owner', scope: null, generation: 1 });
});

test('a removal deletes the member\'s grants and moves their generation on, which ends their session at once', async () => {
  assert.equal(await uses('bo-cli'), 'postgres://market');
  assert.deepEqual(await remove('fay-cli', bo), { answer: { revoked: 2 } });
  assert.deepEqual(await row(bo), { id: bo, status: 'removed', role: 'member', scope: null, generation: 1 });
  assert.equal(await count('grants'), 0);
  const entry = await written();
  assert.equal(entry.action, 'member.remove');
  assert.deepEqual(named(entry), ['credentials read', 'grants dropped', 'grants dropped', 'principals read', 'principals read', 'principals read', 'principals read', 'principals replaced', 'roles read']);
  assert.deepEqual((entry.detail as { revoked: { role: string }[] }).revoked.map((grant) => grant.role), ['developer', 'developer']);
  assert.ok(entry.objects.includes(`project:${market.id}`), 'each project\'s log shows it');
  assert.equal(await uses('bo-cli'), 'unauthenticated', 'a person\'s read is never remembered: at once');
  // An Owner of the whole instance removes another, and anyone who runs it removes themselves.
  assert.deepEqual(await remove('ada-cli', cy), { answer: { revoked: 0 } });
  assert.deepEqual(await remove('fay-cli', fay), { answer: { revoked: 0 } });
});

test('a removal revokes the member\'s sign-in accounts, so that back in, they bind them anew: one revoked before is left as it is', async () => {
  const account = identity(bo, { email: 'bo@acme.example' });
  const before = identity(bo, { revokedAt: new Date(world.now() - 60_000), revokedBy: bo });
  const others = identity(eve);
  await write(world, ...rows('identities', account, before, others));
  const accounts = async () => rowsOf<{ id: string; generation: number; revoked_by: string | null; revoked: boolean }>(world.owner, sql`SELECT id, generation, revoked_by, revoked_at IS NOT NULL AS revoked FROM identities ORDER BY id`);
  const untouched = (await accounts()).find((found) => found.id === before.id);

  assert.ok('answer' in (await remove('fay-cli', bo)));
  const entry = await written();
  assert.ok(entry.objects.includes(`identity:${account.id}`) && !entry.objects.includes(`identity:${before.id}`), entry.objects.join());
  assert.deepEqual(named(entry).filter((name) => name.startsWith('identities')), ['identities read', 'identities replaced'], 'the one revoked before is read, by the member alone, and left');
  assert.ok('answer' in (await put('fay-cli', bo)));
  const now = await accounts();
  assert.deepEqual(now.find((found) => found.id === account.id), { id: account.id, generation: 0, revoked_by: fay, revoked: true }, 'revoked, of the generation before');
  assert.deepEqual(now.find((found) => found.id === before.id), untouched);
  assert.deepEqual(now.find((found) => found.id === others.id), { id: others.id, generation: 0, revoked_by: null, revoked: false }, 'another member\'s, untouched');
  assert.equal((await row(bo))!.generation, 1);
});

test('a removal that finds an account of the member\'s it cannot read refuses, and removes nothing', async () => {
  await write(world, ...rows('identities', identity(bo, { email: 'bo@acme.example' })));
  const before = [await members(), await count('grants'), await kept()];
  // Marked revoked behind the vault, as one that would hide it from a read of live accounts; then edited: neither is taken as it says.
  for (const edit of [sql`UPDATE identities SET revoked_at = now() WHERE principal = ${bo}`, sql`UPDATE identities SET revoked_at = NULL, email = 'eve@acme.example' WHERE principal = ${bo}`]) {
    await world.owner.execute(edit);
    assert.deepEqual(await remove('fay-cli', bo), { refused: 'tampered' });
    assert.deepEqual([await members(), await count('grants'), await kept()], before);
  }
  // Another member's account, edited, is not this removal's to refuse.
  await world.owner.execute(sql`DELETE FROM identities WHERE principal = ${bo}`);
  await write(world, ...rows('identities', identity(eve)));
  await world.owner.execute(sql`UPDATE identities SET email = 'x@acme.example' WHERE principal = ${eve}`);
  assert.ok('answer' in (await remove('fay-cli', bo)));
});

test('a grant hidden from a removal and put back once the member is brought back reaches nothing: it is of the generation the removal ended', async () => {
  // The writer the design assumes deletes Bo's grants before the removal, which finds none to drop, and puts them back, MACs and all, after.
  const [{ hidden }] = (await rowsOf<{ hidden: string }>(world.owner, sql`WITH gone AS (DELETE FROM grants WHERE principal = ${bo} RETURNING *) SELECT json_agg(gone)::text AS hidden FROM gone`)) as [{ hidden: string }];
  assert.deepEqual(await remove('fay-cli', bo), { answer: { revoked: 0 } });
  await world.owner.execute(sql`INSERT INTO grants SELECT * FROM json_populate_recordset(NULL::grants, ${hidden}::json)`);
  assert.deepEqual(await put('fay-cli', bo), as(true, 'member'));
  assert.deepEqual(await row(bo), { id: bo, status: 'active', role: 'member', scope: null, generation: 1 });
  assert.deepEqual(await rowsOf(world.owner, sql`SELECT generation FROM grants WHERE principal = ${bo}`), [{ generation: 0 }, { generation: 0 }]);
  await write(world, ...rows('credentials', credential('bo-again', bo, { generation: 1 })));
  world.tick(2000);
  assert.equal(await uses('bo-again'), 'no_access', 'a session of this membership holds none of the grants of the one before');
  assert.equal(await uses('bo-cli'), 'unauthenticated', 'nor does the session of the one before stand');
});

test('grants of two memberships before, kept and put back after the second return, reach nothing; one of this membership does', async () => {
  const saved = async () => (await rowsOf<{ kept: string }>(world.owner, sql`SELECT json_agg(g)::text AS kept FROM grants g WHERE principal = ${bo}`))[0]!.kept;
  const [prod] = await rowsOf<{ id: string }>(world.owner, sql`SELECT id FROM environments`) as [{ id: string }];
  const putBack = (kept: string) => world.owner.execute(sql`INSERT INTO grants SELECT * FROM json_populate_recordset(NULL::grants, ${kept}::json)`);
  // Generation 0's grants on market and on prod; the writer keeps the one on market.
  const [{ first }] = (await rowsOf<{ first: string }>(world.owner, sql`SELECT json_agg(g)::text AS first FROM grants g WHERE principal = ${bo} AND project_id IS NOT NULL`)) as [{ first: string }];
  assert.deepEqual(await remove('fay-cli', bo), { answer: { revoked: 2 } });
  assert.deepEqual(await put('fay-cli', bo), as(true, 'member'));
  // Generation 1 is given prod, genuinely, and the writer keeps that too.
  await write(world, ...rows('grants', grant(bo, 'developer', { environment: prod }, { generation: 1 })));
  const second = await saved();
  assert.deepEqual(await remove('fay-cli', bo), { answer: { revoked: 1 } });
  assert.deepEqual(await put('fay-cli', bo), as(true, 'member'));
  assert.equal((await row(bo))!.generation, 2);
  await putBack(first);
  await putBack(second);
  assert.deepEqual((await rowsOf<{ generation: number }>(world.owner, sql`SELECT generation FROM grants WHERE principal = ${bo} ORDER BY generation`)).map((found) => found.generation), [0, 1]);
  await write(world, ...rows('credentials', credential('bo-third', bo, { generation: 2 })));
  world.tick(2000);
  assert.equal(await uses('bo-third'), 'no_access', 'neither membership before reaches this one');
  // The same place given to generation 2 reaches it: the test sees a grant that counts.
  await world.owner.execute(sql`DELETE FROM grants WHERE principal = ${bo} AND generation = 1`);
  await write(world, ...rows('grants', grant(bo, 'developer', { environment: prod }, { generation: 2 })));
  world.tick(2000);
  assert.equal(await uses('bo-third'), 'postgres://market');
});

test('a removed member whose rows are deleted around the vault is admitted anew in generation 0, their old session put back stands for it, and the signer finds the entry false history', async () => {
  // The design's adversary deletes rows (docs/design/0.16.md, "What it promises"): the decision cannot tell
  // such a member from a newcomer, but its entry says the row it made replaced none, and the signer's
  // mirror holds Bo's removed row. Its credential would have to be put back too, a row put back.
  const signer = await Signer.open({ db: world.db, keys: world.keys, now: world.now, store: memoryStore(), keepUsesDays: 90 });
  assert.deepEqual(await remove('fay-cli', bo), { answer: { revoked: 2 } });
  for (const hash of world.woken.splice(0)) await signer.wake(hash);
  await signer.run(true);
  assert.deepEqual(await signer.take(), []);
  // Bo's session row, kept as it was, MAC and all, to put back once the vault has made Bo anew.
  const [{ saved }] = await rowsOf<{ saved: unknown }>(world.owner, sql`SELECT to_jsonb(c) AS saved FROM credentials c WHERE principal = ${bo}`) as [{ saved: unknown }];
  await world.owner.execute(sql`DELETE FROM credentials WHERE principal = ${bo}`);
  await world.owner.execute(sql`DELETE FROM principals WHERE id = ${bo}`);
  assert.deepEqual(await put('fay-cli', bo), as(true, 'member'));
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

test('a put does what the member\'s row calls for: of an active member with no role, nothing; of one removed and given a role, it brings them back with it', async () => {
  const onMarket = { projects: { only: [market.id] }, environments: 'all' };
  assert.deepEqual(await put('ada-cli', eve, 'developer', { projects: { only: ['market'] }, environments: 'all' }), as(false, 'developer', onMarket));
  // Eve, asked with no role: her role and scope kept, no row written, and the entry says so.
  const before = JSON.stringify(await members());
  assert.deepEqual(await put('fay-cli', eve), as(false, 'developer', onMarket));
  assert.equal(JSON.stringify(await members()), before);
  const entry = await written();
  assert.deepEqual([entry.action, entry.detail], ['member.role', { member: eve, role: 'developer', scope: onMarket, unchanged: true }]);
  assert.ok(named(entry).every((name) => name.endsWith(' read')), 'and wrote no row');
  // An Admin asking it of themselves changes nothing, so nothing is refused.
  assert.deepEqual(await put('fay-cli', fay), as(false, 'admin'));
  // Ex, removed, given a role: brought back with it, in the generation the removal moved on to, as 0.14.7 did.
  assert.deepEqual(await put('fay-cli', ex, 'developer'), as(true, 'developer'));
  assert.deepEqual(await row(ex), { id: ex, status: 'active', role: 'developer', scope: null, generation: 1 });
  assert.equal((await written()).action, 'member.restore');
  // Someone the instance never had, given a role: added with it; asked again, they are active, and nothing moves.
  const fresh = user('new');
  assert.deepEqual(await put('fay-cli', fresh, 'developer'), as(true, 'developer'));
  assert.equal((await written()).action, 'member.add');
  assert.deepEqual(await put('fay-cli', fresh, 'developer'), as(false, 'developer'));
  assert.deepEqual((await written()).detail, { member: fresh, role: 'developer', scope: null, unchanged: true });
});

test('two puts of one new member side by side: one adds them, the other starts over and finds them active', async () => {
  const deciding = { workloads: world.workloads, owners: world.owners };
  const fresh = user('new');
  const op = (label: string, role: 'developer' | null) => OPERATIONS['member.put']({ ...shown(label), op: 'member.put', principal: fresh, role, scope: null }, deciding);
  const [first, second] = await Promise.all([prepare(world, op('fay-cli', null)), prepare(world, op('ada-cli', 'developer'))]);
  assert.ok(!('refused' in first!) && !('refused' in second!), 'each decided alone, on no row: two admissions');
  assert.equal(await commit(world, first), true);
  assert.equal(await commit(world, second), false, 'the member\'s row is not the none it read');
  assert.deepEqual(await put('ada-cli', fresh, 'developer'), as(false, 'developer'), 'again, a role set');
  assert.equal((await written()).action, 'member.role');
  assert.deepEqual(await row(fresh), { id: fresh, status: 'active', role: 'developer', scope: null, generation: 0 });
});

test('two Owners demoting each other side by side: the second starts over, finds itself no Owner, and one stays', async () => {
  const deciding = { workloads: world.workloads, owners: world.owners };
  const op = (label: string, who: string) => OPERATIONS['member.put']({ ...shown(label), op: 'member.put', principal: who, role: 'admin', scope: null }, deciding);
  const [first, second] = await Promise.all([prepare(world, op('ada-cli', cy)), prepare(world, op('cy-cli', ada))]);
  assert.ok(!('refused' in first!) && !('refused' in second!), 'each decided alone, with another Owner left');
  assert.equal(await commit(world, first), true);
  assert.equal(await commit(world, second), false, 'the Owners it counted are no longer the ones it read');
  assert.deepEqual(await put('cy-cli', ada, 'admin'), { refused: 'no_access' });
  assert.deepEqual((await members()).filter((member) => member.role === 'owner' && member.scope === null).map((member) => member.id), [ada]);
});

test('a caller whose instance role has no row runs no instance, as `project.create` takes it', async () => {
  await world.owner.execute(sql`DELETE FROM roles WHERE instance AND id = 'admin'`);
  await nothingWritten(async () => {
    assert.deepEqual(await put('fay-cli', user('new')), { refused: 'no_access' });
    assert.deepEqual(await put('fay-cli', ex), { refused: 'no_access' });
    assert.deepEqual(await put('fay-cli', eve, 'developer'), { refused: 'no_access' });
    assert.deepEqual(await remove('fay-cli', eve), { refused: 'no_access' });
  });
  assert.deepEqual(await put('ada-cli', eve, 'developer'), as(false, 'developer'), 'an Owner, whose row is there, still does');
});

test('a service account\'s row that reads Owner keeps no Owner of the whole instance: the last person who owns it stays', async () => {
  await write(world, ...rows('principals', principal('token:x', { role: 'owner' })));
  assert.ok('answer' in (await remove('ada-cli', cy)));
  await nothingWritten(async () => {
    assert.deepEqual(await put('ada-cli', ada, 'admin'), { refused: 'last_owner' }, 'token:x is counted for no one');
    assert.deepEqual(await remove('ada-cli', ada), { refused: 'last_owner' });
  });
});

test('a removal and a demotion side by side, each counting on the other Owner: the second starts over and keeps the last one', async () => {
  const deciding = { workloads: world.workloads, owners: world.owners };
  const removing = OPERATIONS['member.remove']({ ...shown('ada-cli'), op: 'member.remove', principal: cy }, deciding);
  const stepping = OPERATIONS['member.put']({ ...shown('cy-cli'), op: 'member.put', principal: ada, role: 'admin', scope: null }, deciding);
  const [first, second] = await Promise.all([prepare(world, removing), prepare(world, stepping)]);
  assert.ok(!('refused' in first!) && !('refused' in second!), 'Ada counts on herself staying, Cy\'s demotion of her on Cy');
  assert.equal(await commit(world, first), true);
  assert.equal(await commit(world, second), false, 'Cy\'s row, and the Owners it counted, are not the ones it read');
  assert.deepEqual(await put('cy-cli', ada, 'admin'), { refused: 'unauthenticated' }, 'Cy, removed, asks nothing');
  assert.deepEqual(await put('ada-cli', ada, 'admin'), { refused: 'last_owner' });
  assert.deepEqual((await members()).filter((member) => member.status === 'active' && member.role === 'owner' && member.scope === null).map((member) => member.id), [ada]);
});

test('three Owners stepping down at once: each decided alone, and the last one is refused', async () => {
  assert.ok('answer' in (await put('ada-cli', fay, 'owner')));
  const results = await Promise.all(['ada-cli', 'cy-cli', 'fay-cli'].map((label) => put(label, user(label.slice(0, -4)), 'admin')));
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

test('a removal beside a sign-in that binds an account of the member\'s starts over, and revokes that account too', async () => {
  const deciding = { workloads: world.workloads, owners: world.owners };
  const prepared = await prepare(world, OPERATIONS['member.remove']({ ...shown('fay-cli'), op: 'member.remove', principal: bo }, deciding));
  assert.ok(!('refused' in prepared));
  const bound = identity(bo, { email: 'bo@acme.example' });
  await write(world, ...rows('identities', bound));
  assert.equal(await commit(world, prepared), false, 'an account came since its read');
  assert.ok('answer' in (await remove('fay-cli', bo)));
  assert.deepEqual(await rowsOf(world.owner, sql`SELECT revoked_by FROM identities WHERE id = ${bound.id}`), [{ revoked_by: fay }]);
});

test('a row written around the vault is no row: an Owner edited in place or forged counts for nothing, and a scope\'s project edited names none', async () => {
  // Cy's row, edited: no MAC of the vault's, so no Owner to keep, and no caller either.
  await world.owner.execute(sql`UPDATE principals SET created_by = 'user:mallory@acme.example' WHERE id = ${cy}`);
  await nothingWritten(async () => {
    assert.deepEqual(await put('ada-cli', ada, 'admin'), { refused: 'last_owner' });
    assert.deepEqual(await remove('ada-cli', ada), { refused: 'last_owner' });
    assert.deepEqual(await put('cy-cli', eve, 'developer'), { refused: 'unauthenticated' });
    // Nor someone new: admitted over it, the write would fail.
    assert.deepEqual(await put('ada-cli', cy, 'admin'), { refused: 'tampered' });
    assert.deepEqual(await put('fay-cli', cy), { refused: 'tampered' });
  });
  // A forged Owner, with a MAC that is not the vault's.
  await world.owner.execute(sql`INSERT INTO principals (id, status, role, generation, created_at, created_by, status_changed_at, status_changed_by, mac) VALUES (${user('mallory')}, 'active', 'owner', 0, now(), 'x', now(), 'x', decode(repeat('00', 36), 'hex'))`);
  await nothingWritten(async () => assert.deepEqual(await put('ada-cli', ada, 'admin'), { refused: 'last_owner' }));
  // A project edited around the vault is no project for a scope to name.
  await world.owner.execute(sql`UPDATE projects SET name = 'Billing!' WHERE id = ${billing.id}`);
  await nothingWritten(async () => assert.deepEqual(await put('ada-cli', eve, 'developer', { projects: { only: ['billing'] }, environments: 'all' }), { refused: 'no_access' }));
});

test('a workload\'s session that is stopped or narrowed is told so, as for any change, and changes no member', async () => {
  const bound = binding(api, { profile: 'kubernetes', scope: '[]', policy: '{}' });
  const pod = session('pod', bound);
  await write(world, ...rows('bindings', bound), ...rows('credentials', pod, session('tool', bound, { ancestors: JSON.stringify([pod.id]) })));
  const by = (label: string) => vault.change({ ...shown(label), proof: label, op: 'member.put', principal: user('new'), role: 'member', scope: null });
  await nothingWritten(async () => {
    assert.deepEqual(await by('pod'), { refused: 'workload_cannot_issue' });
    assert.deepEqual(await by('tool'), { refused: 'narrowed' });
  });
  await amend(world, 'bindings', eq(bindings.id, bound.id), { frozenAt: new Date(world.now()) });
  await nothingWritten(async () => assert.deepEqual(await by('pod'), { refused: 'frozen' }));
});

test('a member change that is not what the contract says is a fault, before any read', async () => {
  const bad: unknown[] = [
    { op: 'member.put', principal: 'ada@acme.example', role: 'member', scope: null },
    { op: 'member.put', principal: 'user:Ada@acme.example', role: 'member', scope: null },
    { op: 'member.put', principal: 'user: ada', role: 'member', scope: null },
    { op: 'member.put', principal: `user:${'a'.repeat(260)}`, role: 'member', scope: null },
    { op: 'member.put', principal: user('new'), role: 'boss', scope: null },
    { op: 'member.put', principal: user('new'), role: 'toString', scope: null },
    { op: 'member.put', principal: user('new'), role: 'member', scope: { projects: 'all', environments: 'all' } },
    { op: 'member.put', principal: user('new'), role: 'developer', scope: { projects: 'all' } },
    { op: 'member.put', principal: user('new'), role: 'developer', scope: { projects: 'all', environments: 'all', more: 1 } },
    { op: 'member.put', principal: user('new'), role: 'developer', scope: { projects: { only: 'market' }, environments: 'all' } },
    { op: 'member.put', principal: user('new'), role: 'developer', scope: { projects: { only: [''] }, environments: 'all' } },
    { op: 'member.put', principal: user('new'), role: 'developer', scope: { projects: 'all', environments: { except: ['Prod'] } } },
    { op: 'member.put', principal: user('new'), role: 'developer', scope: { projects: 'all', environments: { only: ['URGENT rotate at https://evil.example'] } } },
    { op: 'member.put', principal: user('new'), role: 'developer', scope: { projects: { only: ['a'], except: ['b'] }, environments: 'all' } },
    { op: 'member.put', principal: user('new'), role: 'developer', scope: { projects: { only: Array.from({ length: 1001 }, (_, i) => `p${i}`) }, environments: 'all' } },
    { op: 'member.put', principal: user('new'), role: 'member' },
    { op: 'member.put', principal: user('new'), role: null, scope: { projects: 'all', environments: 'all' } },
    { op: 'member.put', principal: 7, role: 'member', scope: null },
    // The three it replaced are no operations.
    { op: 'member.add', principal: user('new'), role: 'member', scope: null },
    { op: 'member.restore', principal: ex, role: 'member', scope: null },
    { op: 'member.role', principal: eve, role: 'developer', scope: null },
    { op: 'member.remove', principal: 'nobody' },
  ];
  for (const change of bad) await assert.rejects(vault.change({ ...shown('ada-cli'), ...(change as object) } as never), TypeError, JSON.stringify(change).slice(0, 80));
  assert.equal(world.woken.length, 0);
});

test('a refusal is logged once a minute for who asked and what, naming the member only by a row the read found', async () => {
  const fresh = user('new');
  const onMarket = { projects: { only: ['market'] }, environments: 'all' };
  assert.deepEqual(await put('bo-cli', fresh), { refused: 'no_access' }, 'a member admits nobody');
  assert.deepEqual(await put('bo-cli', user('other')), { refused: 'no_access' }, 'again in the minute');
  assert.deepEqual(await remove('bo-cli', eve), { refused: 'no_access' });
  assert.deepEqual(await put('fay-cli', fresh, 'owner', onMarket), { refused: 'no_access' }, 'an Admin makes no Owner');
  assert.deepEqual(await put('sam-cli', bo, 'developer'), { refused: 'no_access' });
  assert.deepEqual(await put('dee-cli', 'user:rotate-now@evil.example'), { refused: 'no_access' }, 'someone the instance never had, by an Owner of one project');
  assert.deepEqual(await remove('nobody', bo), { refused: 'unauthenticated' });
  const denied = await refusals();
  assert.deepEqual(denied.map((entry) => [entry.action, entry.actor, entry.detail, entry.objects.slice(2)]), [
    ['member.add', bo, { refused: 'no_access' }, []],
    ['member.remove', bo, { refused: 'no_access' }, [`principal:${eve}`]],
    ['member.add', fay, { refused: 'no_access' }, [`project:${market.id}`]],
    // Every refused put is logged as an admission, whatever the row, as 0.14.7 logged it.
    ['member.add', sam, { refused: 'no_access' }, [`principal:${bo}`]],
    ['member.add', dee, { refused: 'no_access' }, []],
  ]);
  assert.deepEqual(denied.map((entry) => entry.objects.slice(0, 2)), denied.map((entry) => [`principal:${entry.actor}`, `credential:${entry.credential}`]));
  assert.ok(denied.every((entry) => entry.rows.length === 0 && !JSON.stringify(entry).includes('evil')));
});
