// `caller` (src/caller.ts): who a request's credential is and all it holds,
// for the app to scope a page's queries with. use.test.ts holds what a use
// decides of its caller; this holds the call's own read, memory and answer.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { allows, runsInstance } from '@coffre/core/access';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import type { Called } from '@coffre/core/vault';

import { caller } from '../src/caller.ts';
import { memoryOf } from '../src/use.ts';
import { emptyDatabase, openTestVault } from './database.ts';
import { amend, binding, credential, environment, grant, instance, principal, project, role, rows, session, tokenOf, user, write } from './world.ts';

const vault = await openTestVault();
after(() => vault.close());

/** The round trips the vault's own connection made: a statement, or a transaction sent as one. */
let statements = 0;
for (const name of ['execute', 'transaction'] as const) {
  const run = (vault.db[name] as (...args: unknown[]) => unknown).bind(vault.db);
  (vault.db as unknown as Record<string, unknown>)[name] = (...args: unknown[]) => {
    statements += 1;
    return run(...args);
  };
}

const [ada, bo, cy, dee, api] = [user('ada'), user('bo'), user('cy'), user('dee'), 'token:api'];
const far = new Date(Date.UTC(2027, 0, 1));

/**
 * market: prod, staging, and vault, protected. billing: prod, protected,
 * and one deleted, which was. Ada views market; Bo, staging alone; Cy owns
 * the instance; Dee was removed. Every session was used a moment ago, so
 * that a call is its read and nothing else.
 */
async function world() {
  const [market, billing] = [project('market'), project('billing')];
  const [prod, staging, guarded] = [environment(market, 'prod'), environment(market, 'staging'), environment(market, 'vault', { protected: true })];
  const [billed, gone] = [environment(billing, 'prod', { protected: true }), environment(billing, 'old~1', { protected: true })];
  const used = { lastUsedAt: new Date(vault.now()) };
  const capped = JSON.stringify([{ projectId: market.id, environmentId: prod.id, role: 'viewer' }]);
  await write(
    vault,
    ...rows('projects', market, billing),
    ...rows('environments', prod, staging, guarded, billed, gone),
    ...rows('roles', role(false, 'viewer', ['secret.read'], []), role(false, 'unused', ['secret.write']), role(true, 'owner', ['secret.read', 'grant.manage']), role(true, 'member', [])),
    ...rows('principals', principal(ada), principal(bo), principal(cy, { role: 'owner' }), principal(dee, { status: 'removed', generation: 1 })),
    ...rows('grants', grant(ada, 'viewer', { project: market }), grant(bo, 'viewer', { environment: staging }), grant(bo, 'viewer', { project: billing }, { expiresAt: new Date(vault.now() - 1) }), grant(bo, 'unused', { environment: prod })),
    ...rows(
      'credentials',
      credential('ada', ada, used), credential('bo', bo, used), credential('cy', cy, used), credential('dee', dee, used),
      credential('cy-token', cy, { ...used, kind: 'personal', scope: capped }),
      credential('ada-handle', ada, { ...used, kind: 'handle', scope: capped }),
      credential('revoked', ada, { ...used, revokedAt: new Date(0) }),
      credential('expired', ada, { ...used, expiresAt: new Date(vault.now()) }),
      credential('soon', ada, used),
    ),
  );
  return { market, billing, prod, staging, guarded, billed, gone };
}

let w: Awaited<ReturnType<typeof world>>;
beforeEach(async () => {
  await emptyDatabase(vault.owner);
  vault.memory = memoryOf(2);
  w = await world();
  statements = 0;
});

const shown = (label: string, more: { proof?: string | null; ip?: string | null } = {}) => ({ token: tokenOf(label), proof: null, ip: '192.0.2.7', ...more });
const who = async (label: string): Promise<Called> => {
  const answer = await caller(vault, shown(label));
  assert.ok(!('refused' in answer), `${label}: ${JSON.stringify(answer)}`);
  return answer;
};
const refused = async (label: string, more: Parameters<typeof shown>[1] = {}) => {
  const answer = await caller(vault, shown(label, more));
  return 'refused' in answer ? answer.refused : 'answered';
};
const at = (environment: { id: string; projectId: string; slug: string }) => ({ projectId: environment.projectId, environmentId: environment.id, environmentSlug: environment.slug });

test('who a request is, in one statement: its principal, its credential, and what it holds wherever it holds it', async () => {
  const answer = await who('ada');
  assert.equal(statements, 1, 'one read');
  assert.equal(answer.principal, ada);
  assert.deepEqual({ ...answer.credential, id: 'x' }, { id: 'x', kind: 'cli', expiresAt: far.toISOString() });
  assert.deepEqual([answer.holds.role, answer.holds.service, answer.holds.kind, answer.holds.credentialScope], ['member', false, 'person', null]);
  assert.deepEqual(answer.holds.grants, [{ projectId: w.market.id, environmentId: null, role: 'viewer' }]);
  // Only the roles her rows name, her grants' and her own in the instance: not `unused`, which only Bo holds.
  assert.deepEqual([Object.keys(answer.holds.policy.roles), Object.keys(answer.holds.policy.instanceRoles)], [['viewer'], ['member']]);
  // What the app asks of the answer is what the vault asks of its rows.
  assert.equal(allows(answer.holds, 'secret.read', at(w.prod)), true);
  assert.equal(allows(answer.holds, 'secret.read', at(w.guarded)), false, 'a viewer holds nothing in a protected environment');
  assert.equal(allows(answer.holds, 'secret.read', at(w.billed)), false);
  assert.equal(allows(answer.holds, 'secret.write', at(w.prod)), false);

  // A grant on an environment says its project, from the environment's row; one that lapsed is none.
  const bos = await who('bo');
  const byPlace = (a: { environmentId?: string | null }, b: { environmentId?: string | null }) => String(a.environmentId).localeCompare(String(b.environmentId));
  assert.deepEqual([...bos.holds.grants].sort(byPlace), [{ projectId: w.market.id, environmentId: w.staging.id, role: 'viewer' }, { projectId: w.market.id, environmentId: w.prod.id, role: 'unused' }].sort(byPlace));
  assert.deepEqual(Object.keys(bos.holds.policy.roles).sort(), ['unused', 'viewer']);
  assert.deepEqual([allows(bos.holds, 'secret.read', at(w.staging)), allows(bos.holds, 'secret.read', at(w.prod)), allows(bos.holds, 'secret.write', at(w.prod))], [true, false, true]);
});

test('every environment the instance protects is in the answer, in a project the caller holds nothing in too; a deleted one protects nothing', async () => {
  for (const label of ['ada', 'cy']) {
    const { policy } = (await who(label)).holds;
    assert.deepEqual([...policy.protected].sort(), [w.guarded.id, w.billed.id].sort(), label);
    assert.deepEqual(policy.protectedIn, { [w.market.id]: [{ environmentId: w.guarded.id, slug: 'vault' }], [w.billing.id]: [{ environmentId: w.billed.id, slug: 'prod' }] }, label);
  }
  // An Owner of the instance reads a protected environment: their role's protected column holds it.
  const owner = (await who('cy')).holds;
  assert.equal(allows(owner, 'secret.read', at(w.billed)), true);
  assert.equal(runsInstance(owner), true);
});

test('a token holds no more than its scope, and nothing of the instance: an Owner on a personal token runs nothing', async () => {
  const { holds, credential: on } = await who('cy-token');
  assert.equal(on.kind, 'personal');
  assert.deepEqual(holds.credentialScope, [{ projectId: w.market.id, environmentId: w.prod.id, role: 'viewer' }]);
  assert.deepEqual([allows(holds, 'secret.read', at(w.prod)), allows(holds, 'secret.read', at(w.staging)), allows(holds, 'grant.manage', { projectId: w.market.id })], [true, false, false]);
  assert.equal(runsInstance(holds), false);
});

test('one answer for a token that is unknown, revoked, expired, a removed member\'s, or a handle; none is remembered', async () => {
  for (const label of ['nobody', 'revoked', 'expired', 'dee', 'ada-handle']) assert.equal(await refused(label), 'unauthenticated', label);
  assert.equal(vault.memory.callers.size, 0);
  // Each asked again reads again: what has changed since is what it is given.
  statements = 0;
  assert.equal(await refused('dee'), 'unauthenticated');
  assert.equal(statements, 1);
  await amend(vault, 'principals', sql`id = ${dee}`, { status: 'active' });
  await amend(vault, 'credentials', sql`label = 'dee'`, { generation: 1 });
  assert.equal((await who('dee')).principal, dee);
});

test('within the memory a call reads nothing again, counted from the read; a session that ends within it stops at once', async () => {
  await who('ada');
  // Her session's row deleted behind the vault: what was read still answers, for two seconds from the read.
  await vault.owner.execute(sql`DELETE FROM credentials WHERE label = 'ada'`);
  statements = 0;
  vault.tick(1999);
  assert.equal((await who('ada')).principal, ada);
  assert.equal(statements, 0);
  vault.tick(1);
  assert.equal(await refused('ada'), 'unauthenticated');
  assert.equal(statements, 1);

  // Decided again at each call, on the rows remembered: no read tells it the session ended.
  await amend(vault, 'credentials', sql`label = 'soon'`, { expiresAt: new Date(vault.now() + 1000) });
  await who('soon');
  statements = 0;
  vault.tick(999);
  assert.equal((await who('soon')).principal, ada);
  vault.tick(1);
  assert.equal(await refused('soon'), 'unauthenticated');
  assert.equal(statements, 0);
  // Refused, it is forgotten: the next call reads again, though the memory has not run out.
  assert.equal(await refused('soon'), 'unauthenticated');
  assert.equal(statements, 1);

  // A vault told to remember nothing reads at every call.
  vault.memory = memoryOf(0);
  statements = 0;
  await who('bo');
  await who('bo');
  assert.equal(statements, 2);
  assert.equal(vault.memory.callers.size, 0, 'and keeps nothing');

  // A clock set back makes nothing fresher: what was read later than now is read again.
  vault.memory = memoryOf(2);
  await who('cy');
  vault.tick(-1);
  statements = 0;
  await who('cy');
  assert.equal(statements, 1);
});

test('a row written behind the vault is no row: a grant made up holds nothing, and an edited session is nobody', async () => {
  // A grant inserted with no MAC of the vault's, and one of hers given another role.
  await vault.owner.execute(sql`INSERT INTO grants (id, principal, project_id, role, generation, granted_at, granted_by, mac) VALUES (gen_random_uuid(), ${ada}, ${w.billing.id}, 'viewer', 0, now(), ${ada}, decode(repeat('00', 36), 'hex'))`);
  assert.deepEqual((await who('ada')).holds.grants, [{ projectId: w.market.id, environmentId: null, role: 'viewer' }]);
  vault.memory = memoryOf(2);
  await vault.owner.execute(sql`UPDATE grants SET role = 'unused' WHERE principal = ${ada} AND project_id = ${w.market.id}`);
  assert.deepEqual((await who('ada')).holds.grants, []);
  // A grant from before a removal is of another generation than its member: genuine, and dead.
  await amend(vault, 'principals', sql`id = ${bo}`, { generation: 1 });
  await amend(vault, 'credentials', sql`label = 'bo'`, { generation: 1 });
  vault.memory = memoryOf(2);
  assert.deepEqual((await who('bo')).holds.grants, []);
  // A session moved to another member: its MAC is not the vault's.
  await vault.owner.execute(sql`UPDATE credentials SET principal = ${cy} WHERE label = 'bo'`);
  vault.memory = memoryOf(2);
  assert.equal(await refused('bo'), 'unauthenticated');
});

test("a credential's last use is moved on by the call, every five minutes at most", async () => {
  const last = async () => (await rowsOf<{ at: number; ip: string | null }>(vault.owner, sql`SELECT (extract(epoch FROM last_used_at) * 1000)::float8 AS at, last_used_ip AS ip FROM credentials WHERE label = 'ada'`))[0]!;
  const before = await last();
  vault.tick(5 * 60_000 - 1);
  await who('ada');
  assert.deepEqual(await last(), before);
  vault.tick(2000);
  statements = 0;
  await who('ada');
  assert.equal(statements, 2, 'the read, and the touch');
  assert.deepEqual(await last(), { at: vault.now(), ip: '192.0.2.7' });
});

test("a workload's session is who it is with its key alone; stopped, it is told why, and a narrowed one reaches no page", async () => {
  vault.workloads = { noReads: false, useOnly: false };
  const scope = JSON.stringify([{ projectId: w.market.id, environmentId: null, role: 'viewer' }]);
  const bound = binding(api, { profile: 'kubernetes', scope, policy: '{}' });
  const pod = session('pod', bound);
  await write(vault, ...rows('principals', principal(api)), ...rows('grants', grant(api, 'viewer', { project: w.market })), ...rows('policy', instance()), ...rows('bindings', bound),
    ...rows('credentials', pod, session('child', bound, { ancestors: JSON.stringify([pod.id]) })));
  for (const proof of [null, 'another']) assert.equal(await refused('pod', { proof }), 'unauthenticated');
  const answer = await caller(vault, shown('pod', { proof: 'pod' }));
  assert.ok(!('refused' in answer) && answer.holds.kind === 'workload' && answer.principal === api, JSON.stringify(answer));
  assert.equal(await refused('child', { proof: 'child' }), 'narrowed');
  await amend(vault, 'bindings', sql`id = ${bound.id}`, { frozenAt: new Date(vault.now()) });
  vault.memory = memoryOf(2);
  assert.equal(await refused('pod', { proof: 'pod' }), 'frozen');
});
