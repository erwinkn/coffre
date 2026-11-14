// Freezes over HTTP on the 0.16 contract (docs/design/workload-access.md,
// section 8.2; docs/design/0.16.md, "The server"): a workload's use frozen
// and the freeze lifted, each one change of the vault's and no statement,
// the target in any spelling `freezeTarget` takes and answered in its one.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { binding, credential, emptyDatabase, environment, grant, instance, principal, project, rows, session, user, write } from '@coffre/vault/testing';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { openApp } from './app-fixture.ts';

const app = await openApp();
const { world } = app;
after(() => app.close());

const [bo, cy, eve] = ['bo', 'cy', 'eve'].map(user) as [string, string, string];
const ci = 'token:ci';
let bound: ReturnType<typeof binding>;
let pod: ReturnType<typeof session>;

/** Cy owns the instance; Bo manages market, which ci, a service account, maintains through a binding and a workload's session; Eve views market. */
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  const market = project('market');
  bound = binding(ci, { profile: 'kubernetes', policy: '{}' });
  pod = session('pod', bound);
  await write(
    world,
    ...rows('projects', market),
    ...rows('environments', environment(market, 'dev')),
    ...rows('roles', ...[['viewer', ['secret.read']], ['maintainer', ['secret.read', 'secret.write', 'environment.manage']], ['manager', ['secret.read', 'grant.manage']]].map(([id, permissions]) => ({ instance: false, id: id as string, name: id as string, description: '', permissions: permissions as string[], protected: [] })),
      ...[['owner', ['secret.read', 'secret.write', 'grant.manage', 'project.manage', 'environment.manage', 'audit.read']], ['member', []]].map(([id, permissions]) => ({ instance: true, id: id as string, name: id as string, description: '', permissions: permissions as string[], protected: [] }))),
    ...rows('principals', principal(cy, { role: 'owner' }), principal(bo), principal(eve), principal(ci)),
    ...rows('policy', instance()),
    ...rows('grants', grant(bo, 'manager', { project: market }), grant(eve, 'viewer', { project: market }), grant(ci, 'maintainer', { project: market })),
    ...rows('bindings', bound),
    ...rows('credentials', ...[cy, bo, eve].map((who) => credential(`${who.slice(5, who.indexOf('@'))}-cli`, who)), pod),
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
async function cost<T>(run: () => Promise<T>): Promise<[T, string[], number]> {
  const [calls, statements] = [app.calls.length, app.statements];
  const result = await run();
  return [result, app.calls.slice(calls), app.statements - statements];
}
const refused = (answer: [number, Body]) => [answer[0], answer[1].error, answer[1].reason];
const NO_ACCESS = [403, 'vault_refused', 'no_access'];
const freeze = (label: string, target: string, reason = 'the key leaked in a build log') => cost(() => call(label, 'POST', '/freezes', { target, reason }));
const lift = (label: string, target: string) => cost(() => call(label, 'DELETE', `/freezes/${encodeURIComponent(target)}`));
const frozenAt = async (table: 'principals' | 'bindings' | 'credentials', id: string) =>
  (await rowsOf<{ frozen_at: Date | null }>(world.owner, sql`SELECT frozen_at FROM ${sql.identifier(table)} WHERE id::text = ${id}`))[0]?.frozen_at ?? null;

test("a service account's manager freezes it, and lifts the freeze: one change and no statement each, the target in its one spelling", async () => {
  const [[status, body], calls, statements] = await freeze('bo-cli', 'service:ci');
  assert.deepEqual([status, body.target, calls, statements], [200, ci, ['change'], 0]);
  assert.equal(typeof body.frozenAt, 'string');
  assert.ok((await frozenAt('principals', ci)) !== null);
  // Frozen again, it keeps its time.
  assert.deepEqual((await freeze('bo-cli', ci, 'again'))[0], [200, body]);
  assert.deepEqual(await lift('bo-cli', 'token:ci'), [[200, { target: ci, frozenAt: null }], ['change'], 0]);
  assert.equal(await frozenAt('principals', ci), null);
  assert.deepEqual((await lift('bo-cli', 'token:ci'))[0], [200, { target: ci, frozenAt: null }]);

  // One of its bindings, named in capitals, and one of its workloads' sessions.
  const [[, onBinding]] = await freeze('bo-cli', `binding:${bound.id.toUpperCase()}`);
  assert.equal(onBinding.target, `binding:${bound.id}`);
  assert.ok((await frozenAt('bindings', bound.id)) !== null);
  assert.deepEqual((await lift('bo-cli', `binding:${bound.id}`))[0], [200, { target: `binding:${bound.id}`, frozenAt: null }]);
  const [[, onSession]] = await freeze('bo-cli', `session:${pod.id}`);
  assert.deepEqual([onSession.target, (await frozenAt('credentials', pod.id!)) !== null], [`session:${pod.id}`, true]);
});

test('every workload frozen by an Owner of the whole instance alone; anyone else, or a target not there, is refused and nothing moves', async () => {
  assert.deepEqual(refused((await freeze('bo-cli', 'instance'))[0]), NO_ACCESS);
  const [[status, body]] = await freeze('cy-cli', 'instance');
  assert.deepEqual([status, body.target, typeof body.frozenAt], [200, 'instance', 'string']);
  assert.deepEqual((await lift('cy-cli', 'instance'))[0], [200, { target: 'instance', frozenAt: null }]);

  // Eve views market: she manages no service. A service account, binding or session not there is the same answer.
  for (const target of [ci, `binding:${bound.id}`, `session:${pod.id}`]) assert.deepEqual(refused((await freeze('eve-cli', target))[0]), NO_ACCESS, target);
  for (const target of ['token:gone', 'binding:00000000-0000-4000-8000-000000000000', 'session:00000000-0000-4000-8000-000000000000']) {
    assert.deepEqual(refused((await freeze('cy-cli', target))[0]), NO_ACCESS, target);
  }
  assert.deepEqual(refused((await lift('eve-cli', ci))[0]), NO_ACCESS);
  assert.equal(await frozenAt('principals', ci), null);
  assert.deepEqual(refused(await call('nobody', 'POST', '/freezes', { target: ci, reason: 'x' })), [401, 'unauthenticated', 'unauthenticated']);
});

test('what the vault would take as a fault is told before any call; an upstream credential is not frozen here', async () => {
  const before = app.calls.length;
  for (const bad of [
    { target: 'Token:ci', reason: 'x' }, { target: 'binding:not-a-uuid', reason: 'x' }, { target: 'everything', reason: 'x' }, { target: ci, reason: '  ' }, { target: ci },
    { target: ci, reason: 'x'.repeat(401) }, { target: ci, reason: 'x', extra: 1 },
    // What Postgres keeps no part of: a NUL, half of a surrogate pair.
    { target: ci, reason: 'leaked\u0000' }, { target: ci, reason: 'leaked \ud800' }, { target: 'instance', reason: '\udc00' },
  ]) assert.deepEqual(refused(await call('cy-cli', 'POST', '/freezes', bad)), [400, 'bad_request', undefined], JSON.stringify(bad));
  assert.deepEqual(refused(await call('cy-cli', 'DELETE', '/freezes/nothing')), [400, 'bad_request', undefined]);
  assert.deepEqual(refused(await call('cy-cli', 'POST', '/freezes', { target: 'credential:00000000-0000-4000-8000-000000000000/stripe', reason: 'x' })), [501, 'not_implemented', undefined]);
  assert.deepEqual(refused(await call('cy-cli', 'GET', '/freezes')), [501, 'not_implemented', undefined]);
  assert.equal(app.calls.length, before);
});
