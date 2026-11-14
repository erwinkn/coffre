// A workload's use frozen and the freeze lifted (src/ops/freezes.ts,
// `workload.freeze`, `workload.unfreeze`): who may, for the instance, a service
// account, a binding and a session; what a workload's next request is told;
// that lifting restores it with no new sign-in; and a row written behind the
// vault, told only to whoever may.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import type { Presented } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { commit, prepare } from '../src/change.ts';
import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { OPERATIONS } from '../src/ops/index.ts';
import { emptyDatabase, openTestVault } from './database.ts';
import { binding, credential, environment, grant, instance, principal, project, role, rows, session, tokenOf, user, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
after(() => world.close());

const [ada, cy, fay, dv, bo] = ['ada', 'cy', 'fay', 'dv', 'bo'].map(user) as [string, string, string, string, string];
const [ci, prodOnly] = ['token:ci', 'token:prod'];
let bound: ReturnType<typeof binding>;
let revoked: ReturnType<typeof binding>;
let pod: ReturnType<typeof session>;
let ppod: ReturnType<typeof session>;
let stale: ReturnType<typeof binding>;
let ended: ReturnType<typeof session>;
let cut: ReturnType<typeof session>;
beforeEach(async () => {
  await emptyDatabase(world.owner);
  world.memory.reads.clear();
  world.memory.logged.clear();
  world.refused.clear();
  const market = project('market');
  const dev = environment(market, 'dev');
  const prod = environment(market, 'prod', { protected: true });
  bound = binding(ci!, { profile: 'kubernetes', scope: '[]', policy: '{}' });
  revoked = binding(ci!, { profile: 'kubernetes', scope: '[]', policy: '{}', revokedAt: new Date(0), revokedBy: dv });
  const prodBound = binding(prodOnly!, { profile: 'kubernetes', scope: '[]', policy: '{}' });
  // Back was removed and let back in, in generation 1: its binding from before binds nothing.
  stale = binding('token:back', { profile: 'kubernetes', scope: '[]', policy: '{}' });
  pod = session('pod', bound);
  ppod = session('ppod', prodBound);
  // Two of CI's sessions over: one past its expiry, one past its hard end.
  ended = session('ended', bound, { expiresAt: new Date(Date.UTC(2026, 10, 13, 11)) });
  cut = session('cut', bound, { notAfter: new Date(Date.UTC(2026, 10, 13, 11)) });
  await write(world, ...rows('projects', market), ...rows('environments', dev, prod),
    ...rows('roles', role(true, 'owner', ['grant.manage']), role(true, 'admin', ['grant.manage']), role(true, 'member', []),
      role(false, 'viewer', ['secret.read']), role(false, 'developer', ['secret.read', 'secret.use', 'secret.write'], ['secret.use'])),
    // Ada owns the instance, Cy owns market alone, Fay runs the instance as its Admin; Dv is a Developer of market/dev; Bo holds nothing.
    ...rows('principals', principal(ada, { role: 'owner' }), principal(cy, { role: 'owner', scope: JSON.stringify({ projects: { only: [market.id] }, environments: 'all' }) }),
      principal(fay, { role: 'admin' }), principal(dv), principal(bo),
      // Dv set CI up, which holds developer on market/dev; the other reads market/prod.
      principal(ci!, { statusChangedBy: dv }), principal(prodOnly!, { statusChangedBy: fay }),
      principal('token:gone', { status: 'removed', generation: 1 }), principal('token:back', { generation: 1 })),
    ...rows('policy', instance()),
    ...rows('grants', grant(dv, 'developer', { environment: dev }), grant(ci!, 'developer', { environment: dev }), grant(prodOnly!, 'viewer', { environment: prod })),
    ...rows('bindings', bound, revoked, prodBound, stale),
    ...rows('credentials', ...[ada, cy, fay, dv, bo].map((who) => credential(`${who.slice(5, who.indexOf('@'))}-cli`, who)), pod, ppod, ended, cut,
      credential('ci-token', ci!, { scope: '[]' }), credential('ci-ending', ci!, { scope: '[]', notAfter: new Date(Date.UTC(2027, 0, 1)) }), credential('ada-pat', ada, { kind: 'personal', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'developer' }]) })));
  world.woken.length = 0;
});

const shown = (label: string): Presented => ({ token: tokenOf(label).toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7' });
const freezing = (label: string, target: string, reason = 'leaked in a build log') => ({ ...shown(label), op: 'workload.freeze', target, reason }) as never;
const freeze = (label: string, target: string, reason?: string) => vault.change<'workload.freeze'>(freezing(label, target, reason));
const unfreeze = (label: string, target: string) => vault.change<'workload.unfreeze'>({ ...shown(label), op: 'workload.unfreeze', target } as never);
/** What a workload's session is told when it asks anything: `frozen` while a freeze stops it, else what any change is told by a workload. */
const told = async (label: string) => {
  const answer = await vault.change({ ...shown(label), proof: label, op: 'member.put', principal: user('new'), role: 'member', scope: null } as never);
  return 'refused' in answer ? answer.refused : 'answered';
};
const kept = async () => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM log_pending WHERE kept`))[0]!.n;
const frozenRows = async () => JSON.stringify(await rowsOf(world.owner, sql`
  SELECT 'policy' AS t, workloads_frozen_at AS at FROM policy UNION ALL SELECT id, frozen_at FROM principals UNION ALL SELECT id::text, frozen_at FROM bindings UNION ALL SELECT id::text, frozen_at FROM credentials ORDER BY 1`));
const written = async () => {
  const [found] = await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE kept ORDER BY id DESC LIMIT 1`);
  return entryOf(world.keys, found!)!;
};
/** Nothing written by `run`: no change's entry, no freeze moved. */
async function nothingWritten(run: () => Promise<void>) {
  const before = [await kept(), await frozenRows()];
  await run();
  assert.deepEqual([await kept(), await frozenRows()], before);
}

test('an Owner of the whole instance freezes every workload, and lifting it restores them with no new sign-in', async () => {
  assert.deepEqual([await told('pod'), await told('ppod')], ['workload_cannot_issue', 'workload_cannot_issue']);
  const since = new Date(world.now()).toISOString();
  assert.deepEqual(await freeze('ada-cli', 'instance'), { answer: { target: 'instance', frozenAt: since } });
  assert.deepEqual([await told('pod'), await told('ppod')], ['frozen', 'frozen']);
  const entry = await written();
  assert.deepEqual([entry.action, entry.actor, entry.detail], ['workload.freeze', ada, { target: 'instance', reason: 'leaked in a build log' }]);
  // Frozen already, it keeps its time.
  world.tick(5000);
  assert.deepEqual(await freeze('ada-cli', 'instance', 'again'), { answer: { target: 'instance', frozenAt: since } });
  assert.deepEqual((await written()).detail, { target: 'instance', reason: 'again', unchanged: true });

  await nothingWritten(async () => {
    assert.deepEqual(await unfreeze('fay-cli', 'instance'), { refused: 'no_access' }, 'an Admin runs the instance, and owns it not');
    assert.deepEqual(await unfreeze('cy-cli', 'instance'), { refused: 'no_access' }, 'nor an Owner of one project');
    assert.deepEqual(await unfreeze('ada-pat', 'instance'), { refused: 'no_access' }, 'nor a token');
    assert.deepEqual(await unfreeze('dv-cli', 'instance'), { refused: 'no_access' });
  });
  assert.deepEqual(await unfreeze('ada-cli', 'instance'), { answer: { target: 'instance', frozenAt: null } });
  assert.equal((await written()).action, 'workload.unfreeze');
  assert.deepEqual([await told('pod'), await told('ppod')], ['workload_cannot_issue', 'workload_cannot_issue']);
  assert.deepEqual(await unfreeze('ada-cli', 'instance'), { answer: { target: 'instance', frozenAt: null } }, 'lifted already, nothing moves');
  assert.equal((await written()).detail.unchanged, true);

  // The policy row gone: every workload is frozen, and the row a lift would write is not there to write.
  await world.owner.execute(sql`DELETE FROM policy`);
  assert.equal(await told('pod'), 'frozen');
  await nothingWritten(async () => assert.deepEqual(await unfreeze('ada-cli', 'instance'), { refused: 'tampered' }));
});

test('whoever manages a service account freezes it, one of its bindings or one of its sessions, and lifts it; nobody else', async () => {
  const since = new Date(world.now()).toISOString();
  assert.deepEqual(await freeze('dv-cli', ci!), { answer: { target: ci, frozenAt: since } });
  assert.deepEqual([await told('pod'), await told('ppod')], ['frozen', 'workload_cannot_issue']);
  const entry = await written();
  assert.deepEqual([entry.action, entry.actor], ['workload.freeze', dv]);
  assert.ok(entry.objects.includes(`principal:${ci}`), entry.objects.join());
  assert.deepEqual(await unfreeze('dv-cli', ci!), { answer: { target: ci, frozenAt: null } });
  assert.equal(await told('pod'), 'workload_cannot_issue');

  assert.deepEqual(await freeze('dv-cli', `binding:${bound.id}`), { answer: { target: `binding:${bound.id}`, frozenAt: since } });
  assert.equal(await told('pod'), 'frozen');
  assert.ok((await written()).objects.includes(`binding:${bound.id}`));
  assert.deepEqual(await unfreeze('dv-cli', `binding:${bound.id}`), { answer: { target: `binding:${bound.id}`, frozenAt: null } });
  assert.deepEqual(await freeze('dv-cli', `session:${pod.id}`), { answer: { target: `session:${pod.id}`, frozenAt: since } });
  assert.equal(await told('pod'), 'frozen');
  assert.ok((await written()).objects.includes(`credential:${pod.id}`));
  assert.deepEqual(await unfreeze('dv-cli', `session:${pod.id}`), { answer: { target: `session:${pod.id}`, frozenAt: null } });
  assert.equal(await told('pod'), 'workload_cannot_issue');

  await nothingWritten(async () => {
    assert.deepEqual(await freeze('dv-cli', prodOnly!), { refused: 'no_access' }, 'it reads prod, which Dv does not');
    assert.deepEqual(await freeze('dv-cli', `session:${ppod.id}`), { refused: 'no_access' });
    assert.deepEqual(await freeze('bo-cli', ci!), { refused: 'no_access' });
    assert.deepEqual(await freeze('fay-cli', `binding:${revoked.id}`), { refused: 'no_access' }, 'a binding revoked is not there to freeze');
    assert.deepEqual(await freeze('fay-cli', 'token:nobody'), { refused: 'no_access' });
    assert.deepEqual(await freeze('fay-cli', 'token:gone'), { refused: 'no_access' }, 'a service account removed');
    assert.deepEqual(await freeze('fay-cli', `binding:${stale.id}`), { refused: 'no_access' }, 'a binding of a generation before');
    assert.deepEqual(await freeze('dv-cli', `session:${ended.id}`), { refused: 'no_access' }, 'a session past its expiry');
    assert.deepEqual(await freeze('fay-cli', `session:${ended.id}`), { refused: 'no_access' });
    assert.deepEqual(await freeze('fay-cli', `session:${(await rowsOf<{ id: string }>(world.owner, sql`SELECT id::text FROM credentials WHERE label = 'ci-ending'`))[0]!.id}`), { refused: 'no_access' }, 'a service account\'s token, even with a hard end');
    assert.deepEqual(await unfreeze('dv-cli', `session:${ended.id}`), { refused: 'no_access' });
    assert.deepEqual(await freeze('dv-cli', `session:${cut.id}`), { refused: 'no_access' }, 'a session past its hard end');
    assert.deepEqual(await unfreeze('fay-cli', `session:${cut.id}`), { refused: 'no_access' });
    assert.deepEqual(await freeze('fay-cli', 'binding:00000000-0000-4000-8000-000000000000'), { refused: 'no_access' });
    assert.deepEqual(await freeze('fay-cli', `session:${(await rowsOf<{ id: string }>(world.owner, sql`SELECT id::text FROM credentials WHERE principal = ${dv}`))[0]!.id}`), { refused: 'no_access' }, 'a person\'s session is no workload\'s');
    assert.deepEqual(await freeze('fay-cli', `session:${(await rowsOf<{ id: string }>(world.owner, sql`SELECT id::text FROM credentials WHERE principal = ${ci} AND kind = 'service'`))[0]!.id}`), { refused: 'no_access' }, 'nor a service account\'s token');
    assert.deepEqual(await vault.change<'workload.freeze'>({ ...(freezing('pod', ci!) as object), proof: 'pod' } as never), { refused: 'workload_cannot_issue' }, 'a workload freezes nothing');
  });
  // An Owner of market manages access there, and so every service account that holds nothing elsewhere.
  assert.deepEqual(await freeze('cy-cli', ci!), { answer: { target: ci, frozenAt: since } });
  // Whoever runs the instance manages every service account.
  assert.deepEqual(await freeze('fay-cli', prodOnly!), { answer: { target: prodOnly, frozenAt: since } });
  assert.equal(await told('ppod'), 'frozen');
});

test('a row of what a freeze weighs, written behind the vault, refuses it, tampered, told only to whoever may', async () => {
  // CI's grant edited: it may hold more than it says, which would let Dv manage it.
  await world.owner.execute(sql`UPDATE grants SET role = 'viewer' WHERE principal = ${ci}`);
  await nothingWritten(async () => {
    assert.deepEqual(await freeze('dv-cli', ci!), { refused: 'tampered' });
    assert.deepEqual(await freeze('fay-cli', ci!), { refused: 'tampered' });
    assert.deepEqual(await freeze('bo-cli', ci!), { refused: 'no_access' });
  });
  await world.owner.execute(sql`UPDATE grants SET role = 'developer' WHERE principal = ${ci}`);
  // The binding itself edited: it is no binding Dv may be told of; whoever runs the instance is.
  await world.owner.execute(sql`UPDATE bindings SET label = 'edited' WHERE id = ${bound.id}`);
  await nothingWritten(async () => {
    assert.deepEqual(await freeze('dv-cli', `binding:${bound.id}`), { refused: 'no_access' });
    assert.deepEqual(await freeze('fay-cli', `binding:${bound.id}`), { refused: 'tampered' });
  });
  // The policy row edited: the instance's freeze is not the vault's to say.
  await world.owner.execute(sql`UPDATE policy SET changed_by = 'x'`);
  await nothingWritten(async () => assert.deepEqual(await freeze('ada-cli', 'instance'), { refused: 'tampered' }));
});

test('a freeze beside a grant that takes the service account out of their hands: the one that commits second starts over, and is refused', async () => {
  const deciding = { workloads: world.workloads, owners: world.owners };
  const freezingIt = OPERATIONS['workload.freeze'](freezing('dv-cli', ci!), deciding);
  const widening = OPERATIONS['access.grant']({ ...shown('fay-cli'), op: 'access.grant', principal: ci!, changes: [{ project: 'market', environment: 'prod', role: 'viewer', expiresAt: null }] } as never, deciding);
  const [first, second] = await Promise.all([prepare(world, freezingIt), prepare(world, widening)]);
  assert.ok(!('refused' in first!) && !('refused' in second!));
  assert.equal(await commit(world, second), true);
  assert.equal(await commit(world, first), false, 'the grants it read are no longer the account\'s');
  assert.deepEqual(await freeze('dv-cli', ci!), { refused: 'no_access' });
});

test('a freeze that is not what the contract says is a fault, before any read', async () => {
  for (const target of ['Instance', 'binding:NOT-A-UUID', `Binding:${'0'.repeat(8)}-0000-4000-8000-000000000000`, `credential:${'0'.repeat(8)}-0000-4000-8000-000000000000/stripe`, 'service:ci', 7]) {
    await assert.rejects(freeze('ada-cli', target as string), TypeError, String(target));
  }
  for (const reason of ['', ' padded', 'x'.repeat(401), 'nul\0', 7]) await assert.rejects(freeze('ada-cli', 'instance', reason as string), TypeError, JSON.stringify(reason));
  await assert.rejects(vault.change({ ...shown('ada-cli'), op: 'workload.freeze', target: 'instance' } as never), TypeError, 'a freeze says why');
});
