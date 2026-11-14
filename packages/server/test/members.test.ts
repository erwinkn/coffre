// Members and their access over HTTP on the 0.16 contract (docs/design/0.16.md,
// "The server"): the directory and one member's access, scoped by the vault's
// answer about its caller, in 0.14.7's shapes; and the changes of members and
// grants, each one of the vault's. What each costs, request-cost.test.ts
// holds. Cases from 0.14.7's admin-api, owner-powers and one-access tests
// where they still hold.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { rowsOf } from '@coffre/db/dialect';
import { secrets } from '@coffre/db/schema';
import { eq, sql } from 'drizzle-orm';

import { amend, credential, emptyDatabase, environment, grant, instance, principal, project, role, rows, secret, user, write } from '@coffre/vault/testing';

import { openApp } from './app-fixture.ts';

const app = await openApp();
const { world } = app;
after(() => app.close());

const [ada, al, aud, bo, cy, dee, ed, fin, gus, ivy, rex] = ['ada', 'al', 'aud', 'bo', 'cy', 'dee', 'ed', 'fin', 'gus', 'ivy', 'rex'].map(user) as [string, string, string, string, string, string, string, string, string, string, string];
const ci = 'token:ci';

/**
 * market: prod, staging (protected), dev, prod-ada (Ada's personal config of prod). billing: prod. gone~1: a deletion's tombstone.
 *
 * Cy owns the instance. Al is an Admin scoped to market. Bo manages market
 * (`manager`, which holds `grant.manage`). Ada views market and billing/prod.
 * Ed views market/dev, and viewed billing until his grant ended. Dee is a
 * Developer everywhere, by her instance role alone; Aud an Auditor, a role
 * that holds nothing here. Fin manages billing and views market/dev. Gus
 * holds nothing but a grant on a deleted project. Ivy was removed and let
 * back in, and her grant of before stays as a row; Rex was removed, and his
 * row still says Admin, with a grant in his generation, as no removal leaves
 * them. ci, a
 * service account, maintains market.
 */
let ids: Record<string, string> = {};
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  const [market, billing, gone] = [project('market'), project('billing'), project('gone~1')];
  const prod = environment(market, 'prod');
  const staging = environment(market, 'staging', { protected: true });
  const dev = environment(market, 'dev');
  const adas = environment(market, 'prod-ada', { parentId: prod.id, owner: ada });
  const billed = environment(billing, 'prod');
  ids = { market: market.id, billing: billing.id, prod: prod.id, dev: dev.id };
  await write(
    world,
    ...rows('projects', market, billing, gone),
    ...rows('environments', prod, staging, dev, adas, billed),
    ...rows('roles',
      role(false, 'viewer', ['secret.read'], []),
      role(false, 'maintainer', ['secret.read', 'secret.write', 'environment.manage', 'project.manage']),
      role(false, 'manager', ['secret.read', 'grant.manage'], ['grant.manage']),
      role(true, 'owner', ['secret.read', 'secret.write', 'environment.manage', 'project.manage', 'grant.manage', 'audit.read']),
      role(true, 'admin', ['secret.read', 'secret.write', 'environment.manage', 'project.manage', 'grant.manage', 'audit.read']),
      role(true, 'developer', ['secret.read', 'secret.write'], []),
      role(true, 'auditor', [], []),
      role(true, 'member', [])),
    ...rows('principals',
      principal(ada), principal(al, { role: 'admin', scope: JSON.stringify({ projects: { only: [market.id] }, environments: 'all' }) }), principal(bo), principal(cy, { role: 'owner' }),
      principal(dee, { role: 'developer' }), principal(aud, { role: 'auditor' }), principal(ed), principal(fin), principal(gus), principal(ivy, { generation: 1 }), principal(rex, { status: 'removed', role: 'admin', generation: 1 }), principal(ci)),
    ...rows('policy', instance()),
    ...rows('grants',
      grant(ada, 'viewer', { project: market }), grant(ada, 'viewer', { environment: billed }), grant(bo, 'manager', { project: market }),
      grant(ed, 'viewer', { environment: dev }), grant(ed, 'viewer', { project: billing }, { expiresAt: new Date('2020-01-01T00:00:00Z') }),
      grant(fin, 'manager', { project: billing }), grant(fin, 'viewer', { environment: dev }),
      grant(ci, 'maintainer', { project: market }), grant(ivy, 'viewer', { project: market }), grant(rex, 'viewer', { project: market }, { generation: 1 }), grant(gus, 'viewer', { project: gone })),
    ...rows('credentials',
      ...[ada, al, bo, cy, dee, ed, fin, gus].map((who) => credential(`${who.slice(5, who.indexOf('@'))}-cli`, who)),
      // Cy's token, scoped to maintain market: it holds nothing of the instance's own.
      credential('cy-token', cy, { kind: 'personal', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'maintainer' }]) })),
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

type Grant = { id: string; project: string; environment: string | null; role: string; roleName: string; permissions: string[]; expiresAt: string | null };
type Member = { member: string; principalType: string; principalId: string; instanceRole: string; scope: unknown; reachesByRole: boolean; managed: boolean; tampered: boolean; declared: boolean; grants: Grant[] };
type Directory = { members: Member[]; removed: { principalType: string; principalId: string; toRotate: number | null }[] };
const directory = async (label: string, path?: string): Promise<[Directory, string[], number]> => {
  const [[status, body], calls, statements] = await cost(() => call(label, 'GET', `/members${path === undefined ? '' : `?path=${encodeURIComponent(path)}`}`));
  assert.equal(status, 200, JSON.stringify(body));
  return [body as unknown as Directory, calls, statements];
};
/** Each member as `member: role, grants by place`. */
const brief = (listed: Directory) => listed.members.map((member) => `${member.member}: ${member.instanceRole}${member.reachesByRole ? ' (by role)' : ''}${member.managed ? ' (managed)' : ''}, ${member.grants.map((held) => `${held.project}${held.environment === null ? '' : `/${held.environment}`}=${held.role}`).join(' ')}`.trimEnd().replace(/,$/, ''));

test('an Owner of the instance lists everyone and every live grant, with scopes and who was removed', async () => {
  const [listed] = await directory('cy-cli');
  // Service accounts first, as 0.14 sorted them; a lapsed grant, one on a deleted place and one of a membership before a removal are no grants.
  assert.deepEqual(brief(listed), [
    'token:ci: member (managed), market=maintainer',
    `${ada}: member, billing/prod=viewer market=viewer`,
    `${al}: admin`,
    `${aud}: auditor`,
    `${bo}: member, market=manager`,
    `${cy}: owner`,
    `${dee}: developer`,
    `${ed}: member, market/dev=viewer`,
    `${fin}: member, billing=manager market/dev=viewer`,
    `${gus}: member`,
    `${ivy}: member`,
  ]);
  const [service, adas, als] = listed.members;
  assert.deepEqual(adas!.grants[1], { id: `${ada}/market`, project: 'market', environment: null, role: 'viewer', roleName: 'viewer', permissions: ['secret.read'], expiresAt: null });
  assert.deepEqual([service!.principalType, service!.principalId, adas!.principalType, adas!.principalId], ['service', 'ci', 'user', 'ada@acme.example']);
  // Where a role applies, projects by slug, to whoever runs the instance.
  assert.deepEqual([als!.scope, adas!.scope], [{ projects: { only: ['market'] }, environments: 'all' }, { projects: 'all', environments: 'all' }]);
  assert.deepEqual([adas!.tampered, adas!.declared], [false, false]);
  // Rex was removed: listed apart, so he can be let back in, with how many keys he still knows the value of.
  assert.deepEqual(listed.removed, [{ principalType: 'user', principalId: 'rex@acme.example', toRotate: 0 }]);
});

test('a manager of a project lists the grants they manage and their members, and no scope; anyone else is refused', async () => {
  const [listed] = await directory('bo-cli');
  // Ada's grant on billing is not Bo's to see, nor is Dee, who holds market by her role alone, without a path. Bo manages
  // access to market, which is all ci holds: he manages ci (`managesService`).
  assert.deepEqual(brief(listed), ['token:ci: member (managed), market=maintainer', `${ada}: member, market=viewer`, `${bo}: member, market=manager`, `${ed}: member, market/dev=viewer`, `${fin}: member, market/dev=viewer`]);
  assert.deepEqual([listed.members.every((member) => member.scope === null && member.managed === (member.member === ci)), listed.removed], [true, []]);

  // Ada manages no access, and no service account: a person who may set some up lists those she manages, none.
  assert.deepEqual((await directory('ada-cli'))[0], { members: [], removed: [] });
  // Cy's token holds nothing of the instance's own, manages no grant and sets up no service account: refused, with no statement.
  const [answer, refusedCalls, refusedStatements] = await cost(() => call('cy-token', 'GET', '/members'));
  assert.deepEqual([...refused(answer), refusedCalls, refusedStatements], [...NO_ACCESS, ['caller'], 0]);
});

test('an Admin scoped to a project lists everyone, with the grants inside their scope, and no scope or removed member', async () => {
  const [listed] = await directory('al-cli');
  assert.deepEqual(brief(listed), [
    'token:ci: member (managed), market=maintainer',
    `${ada}: member, market=viewer`,
    `${al}: admin`,
    `${aud}: auditor`,
    `${bo}: member, market=manager`,
    `${cy}: owner`,
    `${dee}: developer`,
    `${ed}: member, market/dev=viewer`,
    `${fin}: member, market/dev=viewer`,
    `${gus}: member`,
    `${ivy}: member`,
  ]);
  assert.deepEqual([listed.members.every((member) => member.scope === null), listed.removed], [true, []]);
});

test("a project's access list: its grants, and, to whoever manages access there, who reaches it by their instance role", async () => {
  const [market] = await directory('bo-cli', 'market');
  assert.deepEqual(brief(market), [
    'token:ci: member (managed), market=maintainer',
    `${ada}: member, market=viewer`,
    `${al}: admin (by role)`,
    `${bo}: member, market=manager`,
    `${cy}: owner (by role)`,
    `${dee}: developer (by role)`,
    `${ed}: member, market/dev=viewer`,
    `${fin}: member, market/dev=viewer`,
  ]);
  // Fin reaches market and manages access in billing alone: none of market's grants, and nobody by their role.
  assert.deepEqual(brief((await directory('fin-cli', 'market'))[0]), []);
  // One environment: its own grants, not the project's, and the roles that reach it.
  assert.deepEqual(brief((await directory('bo-cli', 'market/dev'))[0]), [`${al}: admin (by role)`, `${cy}: owner (by role)`, `${dee}: developer (by role)`, `${ed}: member, market/dev=viewer`, `${fin}: member, market/dev=viewer`]);
  // Ed manages no access there, and no service account: none.
  assert.deepEqual(brief((await directory('ed-cli', 'market'))[0]), []);
  // A project Bo holds nothing in, and one not there, are one answer; to an Owner too.
  for (const [label, path] of [['bo-cli', 'billing'], ['bo-cli', 'nope'], ['cy-cli', 'nope'], ['cy-cli', 'gone~1']] as const) {
    assert.deepEqual(refused(await call(label, 'GET', `/members?path=${encodeURIComponent(path)}`)), NO_ACCESS, `${label} ${path}`);
  }
  // An Owner sees billing's, with Ada's grant on its prod, and no one past its lapsed grant.
  // An Owner sees billing's: Ada's grant on its prod, and those whose role reaches it, not Al, whose scope is market; no one by a lapsed grant.
  assert.deepEqual(brief((await directory('cy-cli', 'billing'))[0]), [`${ada}: member, billing/prod=viewer`, `${cy}: owner (by role)`, `${dee}: developer (by role)`, `${fin}: member, billing=manager`]);
  // Max, an Admin scoped to every project but billing: billing is as absent to him as one not there, its environments too.
  const max = user('max');
  await write(world, ...rows('principals', principal(max, { role: 'admin', scope: JSON.stringify({ projects: { except: [ids.billing] }, environments: 'all' }) })), ...rows('credentials', credential('max-cli', max)));
  for (const path of ['billing', 'billing/prod', 'nope']) assert.deepEqual(refused(await call('max-cli', 'GET', `/members?path=${encodeURIComponent(path)}`)), NO_ACCESS, `max ${path}`);
  assert.deepEqual(brief((await directory('max-cli', 'market/dev'))[0]), [`${al}: admin (by role)`, `${cy}: owner (by role)`, `${dee}: developer (by role)`, `${ed}: member, market/dev=viewer`, `${fin}: member, market/dev=viewer`, `${max}: admin (by role)`]);
  // A path no slug can be is told before any statement: a NUL, which Postgres refuses in text.
  for (const bad of ['market%00', 'market%2Fdev%00']) {
    const [answer, , statements] = await cost(() => call('cy-cli', 'GET', `/members?path=${bad}`));
    assert.deepEqual([...refused(answer), statements], [400, 'bad_request', undefined, 0], bad);
  }
});

test("one member's access: the grants the caller manages, their role, and their scope to whoever runs the instance", async () => {
  type Access = { member: string; principalType: string; principalId: string; status: string; instanceRole: string; scope: unknown; managed: boolean; grants: Grant[] };
  const access = async (label: string, member: string): Promise<[Access, string[], number]> => {
    const [[status, body], calls, statements] = await cost(() => call(label, 'GET', `/members/${encodeURIComponent(member)}/access`));
    assert.equal(status, 200, JSON.stringify(body));
    return [body as unknown as Access, calls, statements];
  };
  const [adas] = await access('cy-cli', ada);
  assert.deepEqual({ ...adas, grants: adas.grants.map((held) => held.id) }, {
    member: ada, principalType: 'user', principalId: 'ada@acme.example', status: 'active', instanceRole: 'member', scope: { projects: 'all', environments: 'all' }, managed: false,
    grants: [`${ada}/billing/prod`, `${ada}/market`],
  });
  // Bo sees what he manages of hers, and no scope; a person's email is one however it is cased. Fin reaches market, and manages billing alone.
  const [seen] = await access('bo-cli', 'user:ADA@Acme.example');
  assert.deepEqual([seen.member, seen.scope, seen.grants.map((held) => held.id)], [ada, null, [`${ada}/market`]]);
  assert.deepEqual((await access('fin-cli', ada))[0].grants.map((held) => held.id), [`${ada}/billing/prod`]);
  // Al's scope, by slug; a service account, managed by whoever runs the instance, and by Al, who manages access to market,
  // all it holds; not by Fin, who lists members but holds market/dev alone.
  assert.deepEqual([(await access('cy-cli', al))[0].scope, (await access('cy-cli', ci))[0].managed, (await access('al-cli', ci))[0].managed, (await access('fin-cli', ci))[0].managed], [{ projects: { only: ['market'] }, environments: 'all' }, true, true, false]);
  // Rex was removed: he holds nothing, whatever his rows say.
  const [rexs] = await access('cy-cli', rex);
  assert.deepEqual([rexs.status, rexs.instanceRole, rexs.grants], ['removed', 'member', []]);

  assert.deepEqual(refused(await call('ada-cli', 'GET', `/members/${bo}/access`)), NO_ACCESS);
  assert.deepEqual(refused(await call('cy-cli', 'GET', '/members/user:nobody@acme.example/access')), [404, 'not_found', undefined]);
  for (const bad of ['ada', 'user:', 'token::b', 'user:a b', 'group:x', `token:${'x'.repeat(260)}`]) {
    assert.deepEqual(refused(await call('cy-cli', 'GET', `/members/${encodeURIComponent(bad)}/access`)), [400, 'bad_request', undefined], bad);
  }
});

test('removing a member: their grants go, and their sessions end', async () => {
  // What went, as the vault's one change counted it: her two grants and her CLI session.
  assert.deepEqual(await call('cy-cli', 'DELETE', `/members/${ada}`), [200, { revoked: { grants: 2, sessions: 1, tokens: 0, identities: 0, apps: 0 }, report: null }]);
  assert.deepEqual(refused(await call('ada-cli', 'GET', '/me')), [401, 'unauthenticated', 'unauthenticated']);
  const [listed] = await directory('cy-cli');
  assert.deepEqual(listed.removed.map((member) => member.principalId), ['ada@acme.example', 'rex@acme.example']);

  // Bo runs nothing; one removed, and one never a member, are no such member; the last Owner of the instance stays.
  assert.deepEqual(refused(await call('bo-cli', 'DELETE', `/members/${ed}`)), NO_ACCESS);
  assert.deepEqual(refused(await call('cy-cli', 'DELETE', `/members/${rex}`)), [409, 'conflict', 'removed']);
  assert.deepEqual(refused(await call('cy-cli', 'DELETE', '/members/user:nobody@acme.example')), [404, 'not_found', 'not_a_member']);
  assert.deepEqual(refused(await call('cy-cli', 'DELETE', `/members/${cy}`)), [409, 'conflict', 'last_owner']);
  assert.deepEqual(refused(await call('cy-cli', 'DELETE', '/members/user:a%20b')), [400, 'bad_request', undefined]);
});

test('a person who sets up service accounts lists those they manage, reads their access and removes them, and no one else (0.14.7, D241)', async () => {
  // Ed views market/dev. Ada views all of market, whose staging is protected: as a person she reads nothing there.
  await write(world, ...rows('principals', principal('token:dev-reader'), principal('token:prod-reader'), principal('token:market-reader'), principal('token:eds', { statusChangedBy: ed })),
    ...rows('grants', grant('token:dev-reader', 'viewer', { environment: { id: ids.dev! } }), grant('token:prod-reader', 'viewer', { environment: { id: ids.prod! } }),
      grant('token:market-reader', 'viewer', { project: { id: ids.market! } })),
    ...rows('credentials', credential('dev-reader-1', 'token:dev-reader')));
  const managedBy = async (label: string) => (await directory(label))[0].members.map((member) => `${member.member}${member.managed ? ' (managed)' : ''}: ${member.grants.map((held) => held.id).join(' ')}`.trimEnd());
  // Ed holds all dev-reader holds, and admitted eds, which holds nothing: his two, and no person.
  assert.deepEqual(await managedBy('ed-cli'), ['token:dev-reader (managed): token:dev-reader/market/dev', 'token:eds (managed):']);
  // Ada holds viewer on dev and prod, but not in staging, which a grant on all of market reaches: she does not manage
  // market-reader, as 0.14.7 weighed it (D241).
  assert.deepEqual(await managedBy('ada-cli'), ['token:dev-reader (managed): token:dev-reader/market/dev', 'token:prod-reader (managed): token:prod-reader/market/prod']);

  const access = async (label: string, member: string) => call(label, 'GET', `/members/${member}/access`);
  const [status, seen] = await access('ed-cli', 'token:dev-reader');
  assert.deepEqual([status, seen.managed, (seen.grants as Grant[]).map((held) => held.id)], [200, true, ['token:dev-reader/market/dev']]);
  // Not his: another account, a person, one not there, one removed. The same refusal for each.
  for (const other of ['token:prod-reader', 'token:market-reader', ada, 'token:nobody', rex]) assert.deepEqual(refused(await access('ed-cli', other)), NO_ACCESS, other);
  assert.deepEqual(refused(await access('ada-cli', 'token:market-reader')), NO_ACCESS);
  // On a token, nobody manages a service account.
  assert.deepEqual(refused(await call('cy-token', 'GET', '/members/token:dev-reader/access')), NO_ACCESS);

  // He removes his, which ends its token, and the vault refuses him another.
  assert.deepEqual(await call('ed-cli', 'DELETE', '/members/token:dev-reader'), [200, { revoked: { grants: 1, sessions: 0, tokens: 1, identities: 0, apps: 0 }, report: null }]);
  assert.deepEqual(refused(await call('ed-cli', 'DELETE', '/members/token:prod-reader')), NO_ACCESS);
  assert.deepEqual(refused(await call('ada-cli', 'DELETE', '/members/token:market-reader')), NO_ACCESS);
  assert.deepEqual(await managedBy('ed-cli'), ['token:eds (managed):']);
});

test("a person's grants set in one change, each place by path, all or none", async () => {
  const patch = (label: string, member: string, body: unknown) => cost(() => call(label, 'PATCH', `/access/${member}`, body));
  assert.deepEqual((await patch('bo-cli', gus, { market: 'viewer', 'market/prod/': { role: 'viewer', until: '2030-12-31' } }))[0], [200, { changes: { market: 'created', 'market/prod': 'created' } }]);
  const [access] = await cost(() => call('cy-cli', 'GET', `/members/${gus}/access`));
  assert.deepEqual((access[1].grants as Grant[]).map((held) => [held.id, held.expiresAt]), [[`${gus}/market/prod`, '2030-12-31T23:59:59.999Z'], [`${gus}/market`, null]]);
  // As they are, unchanged; taken away, revoked; another role, updated.
  assert.deepEqual((await call('bo-cli', 'PATCH', `/access/${gus}`, { market: 'viewer', 'market/prod': null }))[1], { changes: { market: 'unchanged', 'market/prod': 'revoked' } });
  assert.deepEqual((await call('cy-cli', 'PATCH', `/access/${gus}`, { market: 'maintainer' }))[1], { changes: { market: 'updated' } });
  assert.deepEqual((await call('cy-cli', 'PATCH', `/access/${gus}`, { market: 'viewer' }))[1], { changes: { market: 'updated' } });
  // One place refused refuses them all: a role the instance lacks beside one it has.
  assert.deepEqual(refused(await call('cy-cli', 'PATCH', `/access/${gus}`, { 'market/dev': 'viewer', 'market/prod': 'owner' })), [409, 'conflict', 'invalid']);

  // A place Bo does not manage refuses the whole change; nobody gives themselves a role.
  assert.deepEqual(refused(await call('bo-cli', 'PATCH', `/access/${gus}`, { 'market/dev': 'viewer', billing: 'viewer' })), NO_ACCESS);
  assert.deepEqual((await call('cy-cli', 'GET', `/members/${gus}/access`))[1].grants, [{ id: `${gus}/market`, project: 'market', environment: null, role: 'viewer', roleName: 'viewer', permissions: ['secret.read'], expiresAt: null }]);
  assert.deepEqual(refused(await call('bo-cli', 'PATCH', `/access/${bo}`, { 'market/dev': 'viewer' })), NO_ACCESS);
  // To whoever manages the place: a role the instance lacks, a project's on an environment, someone removed or never a member.
  assert.deepEqual(refused(await call('bo-cli', 'PATCH', `/access/${gus}`, { market: 'nope' })), [409, 'conflict', 'invalid']);
  assert.deepEqual(refused(await call('cy-cli', 'PATCH', `/access/${gus}`, { 'market/dev': 'maintainer' })), [409, 'conflict', 'invalid']);
  assert.deepEqual(refused(await call('bo-cli', 'PATCH', `/access/${rex}`, { market: 'viewer' })), [409, 'conflict', 'removed']);
  assert.deepEqual(refused(await call('bo-cli', 'PATCH', '/access/user:nobody@acme.example', { market: 'viewer' })), [404, 'not_found', 'not_a_member']);

  // What the app tells before any call.
  const before = app.calls.length;
  for (const bad of [{ market: 'viewer', 'market/': 'viewer' }, { market: { role: 'viewer', until: '2020-01-01' } }, { market: { role: 'viewer', until: '+010000-01-01T00:00:00Z' } }, { market: { role: 'viewer', until: 'soon' } }, { Market: 'viewer' }, { 'market/prod@me': 'viewer' }, { 'market/prod/KEY': 'viewer' }]) {
    assert.deepEqual(refused(await call('bo-cli', 'PATCH', `/access/${gus}`, bad)), [400, 'bad_request', undefined], JSON.stringify(bad));
  }
  assert.deepEqual([await call('bo-cli', 'PATCH', `/access/${gus}`, {}), app.calls.length], [[200, { changes: {} }], before]);
});

test('a member put: admitted, brought back or given a role, as their row calls for', async () => {
  const put = (label: string, member: string, body: unknown) => cost(() => call(label, 'PUT', `/members/${member}`, body));
  const everywhere = { projects: 'all', environments: 'all' };
  const nobody = 'user:new@acme.example';

  // No row: admitted, as member when no role is asked.
  assert.deepEqual((await put('cy-cli', 'user:New@Acme.example', {}))[0], [200, { member: nobody, instanceRole: 'member', scope: everywhere, created: true }]);
  // Active, a role and a scope set, by slug; asked again, nothing moves.
  const admin = { role: 'admin', scope: { projects: { only: ['market', 'billing', 'market'] } } };
  const scoped = { projects: { only: ['billing', 'market'] }, environments: 'all' };
  assert.deepEqual((await put('cy-cli', nobody, admin))[0], [200, { member: nobody, instanceRole: 'admin', scope: scoped, created: false }]);
  assert.deepEqual((await put('cy-cli', nobody, admin))[0][1], { member: nobody, instanceRole: 'admin', scope: scoped, created: false });
  // No role keeps theirs, and its scope, which names projects by id, is worded by slug.
  assert.deepEqual((await put('cy-cli', nobody, {}))[0], [200, { member: nobody, instanceRole: 'admin', scope: scoped, created: false }]);
  assert.deepEqual((await put('cy-cli', dee, {}))[0], [200, { member: dee, instanceRole: 'developer', scope: everywhere, created: false }]);
  // A role with no scope is everywhere; one with an environments' filter alone names no project.
  assert.deepEqual((await put('cy-cli', ada, { role: 'auditor' }))[0][1], { member: ada, instanceRole: 'auditor', scope: everywhere, created: false });
  assert.deepEqual((await put('cy-cli', ada, { role: 'developer', scope: { environments: { except: ['prod'] } } }))[0][1], { member: ada, instanceRole: 'developer', scope: { projects: 'all', environments: { except: ['prod'] } }, created: false });
  assert.deepEqual((await put('cy-cli', ada, {}))[0].slice(0, 2), [200, { member: ada, instanceRole: 'developer', scope: { projects: 'all', environments: { except: ['prod'] } }, created: false }]);
  // Removed: brought back, as asked, with none of the grants they held before.
  assert.deepEqual((await call('cy-cli', 'DELETE', `/members/${ed}`))[0], 200);
  assert.deepEqual((await put('cy-cli', ed, { role: 'developer' }))[0], [200, { member: ed, instanceRole: 'developer', scope: everywhere, created: true }]);
  assert.deepEqual((await call('cy-cli', 'GET', `/members/${ed}/access`))[1].grants, []);
  assert.deepEqual((await put('cy-cli', rex, {}))[0], [200, { member: rex, instanceRole: 'member', scope: everywhere, created: true }]);
  // A service account is put as a member, and holds no instance role.
  assert.deepEqual((await put('cy-cli', ci, {}))[0][1], { member: ci, instanceRole: 'member', scope: everywhere, created: false });
  assert.deepEqual((await put('cy-cli', 'token:deploy', {}))[0][1], { member: 'token:deploy', instanceRole: 'member', scope: everywhere, created: true });
  const [[serviceStatus, serviceBody]] = await put('cy-cli', ci, { role: 'admin' });
  assert.deepEqual([serviceStatus, serviceBody.reason, serviceBody.message], [409, 'invalid', `${ci}: a service account holds project grants only, never an instance role`]);

  // The vault refuses: whoever does not run the instance, an Admin scoped to market included; an Admin who makes an Owner, or changes their own role; a
  // project that is not there; the last Owner; a token, whatever its scope.
  assert.deepEqual(refused((await put('bo-cli', 'user:other@acme.example', {}))[0]), NO_ACCESS);
  assert.deepEqual(refused((await put('al-cli', gus, { role: 'developer', scope: { projects: { only: ['market'] } } }))[0]), NO_ACCESS);
  assert.deepEqual((await put('cy-cli', dee, { role: 'admin' }))[0][0], 200);
  assert.deepEqual(refused((await put('dee-cli', gus, { role: 'owner' }))[0]), NO_ACCESS);
  assert.deepEqual(refused((await put('dee-cli', dee, { role: 'developer' }))[0]), NO_ACCESS);
  assert.deepEqual((await put('dee-cli', gus, { role: 'developer', scope: { projects: { only: ['market'] } } }))[0][1], { member: gus, instanceRole: 'developer', scope: { projects: { only: ['market'] }, environments: 'all' }, created: false });
  assert.deepEqual(refused((await put('cy-cli', gus, { role: 'admin', scope: { projects: { only: ['nope'] } } }))[0]), NO_ACCESS);
  assert.deepEqual(refused((await put('cy-cli', cy, { role: 'admin' }))[0]), [409, 'conflict', 'last_owner']);
  assert.deepEqual(refused((await put('cy-token', ed, { role: 'admin' }))[0]), NO_ACCESS);

  // What the app tells before any call.
  const before = app.calls.length;
  const bads: [string, unknown][] = [
    [gus, { scope: { projects: 'all' } }], [gus, { role: 'member', scope: { projects: 'all' } }], [gus, { role: 'boss' }], [gus, { role: 'admin', scope: { projects: { only: ['Market'] } } }],
    [gus, { role: 'admin', extra: 1 }], [gus, { access: { market: 'viewer' } }], [ci, { access: { market: 'viewer' }, role: 'member' }], [ci, { access: {} }],
  ];
  for (const [member, bad] of bads) assert.deepEqual(refused(await call('cy-cli', 'PUT', `/members/${member}`, bad)), [400, 'bad_request', undefined], JSON.stringify(bad));
  assert.deepEqual(refused(await call('cy-cli', 'PUT', '/members/user:a%20b', {})), [400, 'bad_request', undefined]);
  assert.equal(app.calls.length, before);
});

test("a service account made with its grants, and given more, each in one change, by whoever may set it up or manages it", async () => {
  const put = (label: string, member: string, body: unknown) => cost(() => call(label, 'PUT', `/members/${member}`, body));
  const everywhere = { projects: 'all', environments: 'all' };
  const deploy = 'token:deploy';
  // Made with its grants by whoever runs the instance; asked again, it is there, and so are they.
  assert.deepEqual((await put('cy-cli', deploy, { access: { 'market/dev': 'viewer', billing: { role: 'viewer', until: '2030-12-31' } } }))[0],
    [200, { member: deploy, instanceRole: 'member', scope: everywhere, created: true, changes: { 'market/dev': 'created', billing: 'created' } }]);
  assert.deepEqual((await put('cy-cli', deploy, { access: { 'market/dev': 'viewer' } }))[0][1], { member: deploy, instanceRole: 'member', scope: everywhere, created: false, changes: { 'market/dev': 'unchanged' } });
  assert.deepEqual(((await call('cy-cli', 'GET', `/members/${deploy}/access`))[1].grants as Grant[]).map((held) => [held.id, held.expiresAt]), [[`${deploy}/billing`, '2030-12-31T23:59:59.999Z'], [`${deploy}/market/dev`, null]]);

  // Bo manages market's access: he gives ci, which holds grants on market alone, more there, and takes them away; Ada, who views it, does not.
  assert.deepEqual(await call('bo-cli', 'PATCH', `/access/${ci}`, { 'market/dev': 'viewer' }), [200, { changes: { 'market/dev': 'created' } }]);
  assert.deepEqual((await call('bo-cli', 'PATCH', `/access/${ci}`, { 'market/dev': null }))[1], { changes: { 'market/dev': 'revoked' } });
  assert.deepEqual(refused(await call('ada-cli', 'PATCH', `/access/${ci}`, { 'market/dev': 'viewer' })), NO_ACCESS);
  // Where he manages access he grants any member, deploy too, which he does not manage: it holds a grant on billing.
  assert.deepEqual((await call('bo-cli', 'PATCH', `/access/${deploy}`, { market: 'viewer' }))[1], { changes: { market: 'created' } });
  assert.deepEqual((await call('bo-cli', 'PATCH', `/access/${deploy}`, { market: null }))[1], { changes: { market: 'revoked' } });
  // A service account never set up is not given grants on their own; one removed is brought back with its new ones, and none of its old.
  assert.deepEqual(refused(await call('cy-cli', 'PATCH', '/access/token:never', { market: 'viewer' })), [404, 'not_found', 'not_a_member']);
  assert.deepEqual((await call('cy-cli', 'DELETE', `/members/${deploy}`))[0], 200);
  assert.deepEqual((await put('cy-cli', deploy, { access: { market: 'viewer' } }))[0][1], { member: deploy, instanceRole: 'member', scope: everywhere, created: true, changes: { market: 'created' } });
  assert.deepEqual(((await call('cy-cli', 'GET', `/members/${deploy}/access`))[1].grants as Grant[]).map((held) => held.id), [`${deploy}/market`]);

  // Set up by someone who does not run the instance, of a role they hold all of where the instance lets them: Bo, viewer on market/dev.
  assert.deepEqual((await put('bo-cli', 'token:bots', { access: { 'market/dev': 'viewer' } }))[0][1], { member: 'token:bots', instanceRole: 'member', scope: everywhere, created: true, changes: { 'market/dev': 'created' } });
  // Not where it does not: billing is Fin's, whom the setting does not stop either, but Bo holds nothing there. One place refused refuses it all, the setting up included.
  assert.deepEqual(refused(await call('bo-cli', 'PUT', '/members/token:more', { access: { 'market/dev': 'viewer', billing: 'viewer' } })), NO_ACCESS);
  assert.equal((await call('cy-cli', 'GET', '/members/token:more/access'))[0], 404);
  // A token, whatever its scope, sets up nothing; nor does anyone outside the setting.
  await world.owner.execute(sql`UPDATE policy SET service_accounts = '{"projects":{"only":[]},"environments":"all"}'`);
  assert.deepEqual(refused(await call('cy-token', 'PUT', '/members/token:pat', { access: { 'market/dev': 'viewer' } })), NO_ACCESS);
});

test('what is not served yet answers 501', async () => {
  for (const [method, path] of [['GET', `/members/${ci}/bindings/${crypto.randomUUID()}/enrollments`], ['POST', `/members/${ci}/bindings/${crypto.randomUUID()}/enrollments`]] as const) {
    assert.deepEqual(refused(await call('cy-cli', method, path, method === 'GET' ? undefined : {})), [501, 'not_implemented', undefined], `${method} ${path}`);
  }
});

type Exposed = { project: string; environment: string; key: string; version: number; how: 'read' | 'wrote'; at: string };
type Report = Record<string, unknown> & { status: string; exposed: Exposed[]; rotated: number; live: Record<string, number> };
const report = async (member: string): Promise<[Report, string[], number]> => {
  const [[status, body], calls, statements] = await cost(() => call('cy-cli', 'GET', `/members/${member}`));
  assert.equal(status, 200, JSON.stringify(body));
  return [body as unknown as Report, calls, statements];
};
/** What a report says to rotate, `path vN how`, and how many keys it counts rotated. */
const toRotate = async (member: string) => {
  const [body] = await report(member);
  return [body.exposed.map((key) => `${key.project}/${key.environment}/${key.key} v${key.version} ${key.how}`), body.rotated];
};
const ok = async (answer: Promise<[number, Body]>) => {
  const [status, body] = await answer;
  assert.equal(status, 200, JSON.stringify(body));
};

test("a member's report: the keys whose current value they read or wrote, a restore's value counted from its first write; one call to the vault and one statement", async () => {
  // Dee writes two keys; Ada reads them.
  await ok(call('dee-cli', 'PATCH', '/secrets/market/prod', { STRIPE_KEY: 'sk_1', DATABASE_URL: 'pg://1' }));
  await ok(call('ada-cli', 'POST', '/reveals', { path: 'market/prod' }));
  assert.deepEqual(await toRotate(ada), [['market/prod/DATABASE_URL v1 read', 'market/prod/STRIPE_KEY v1 read'], 0]);
  assert.deepEqual(await toRotate(dee), [['market/prod/DATABASE_URL v1 wrote', 'market/prod/STRIPE_KEY v1 wrote'], 0]);

  // Al writes a new STRIPE_KEY: rotated for both, and his to rotate, though he never read it.
  await ok(call('al-cli', 'PATCH', '/secrets/market/prod', { STRIPE_KEY: 'sk_2' }));
  assert.deepEqual(await toRotate(ada), [['market/prod/DATABASE_URL v1 read'], 1]);
  assert.deepEqual(await toRotate(dee), [['market/prod/DATABASE_URL v1 wrote'], 1]);
  assert.deepEqual(await toRotate(al), [['market/prod/STRIPE_KEY v2 wrote'], 0]);

  // Al restores version 1 as version 3: Dee's value is back, and Ada saw it; Al restored a value he never knew, which is
  // no write of his, and his own is gone.
  await ok(call('al-cli', 'POST', '/secrets/market/prod/STRIPE_KEY/restore', { version: 1 }));
  assert.deepEqual(await toRotate(ada), [['market/prod/DATABASE_URL v1 read', 'market/prod/STRIPE_KEY v3 read'], 0]);
  assert.deepEqual(await toRotate(dee), [['market/prod/DATABASE_URL v1 wrote', 'market/prod/STRIPE_KEY v3 wrote'], 0]);
  assert.deepEqual(await toRotate(al), [[], 1]);

  // Fin reads billing/prod, whose LINK refers to market's DATABASE_URL: what he saw is the source's value, named as the source.
  await ok(call('cy-cli', 'PATCH', '/secrets/billing/prod', { LINK: { ref: 'market/prod/DATABASE_URL' } }));
  await ok(call('fin-cli', 'POST', '/reveals', { path: 'billing/prod' }));
  assert.deepEqual(await toRotate(fin), [['market/prod/DATABASE_URL v1 read'], 0]);

  // The whole report, at one call to the vault and one statement. Ada's sign-in and grants, her personal config; what
  // 0.16 does not serve yet is null.
  const [adas, calls, statements] = await report(ada);
  assert.deepEqual([calls, statements], [['caller'], 1]);
  const { exposed, ...rest } = adas;
  assert.ok(exposed.every((key) => !Number.isNaN(Date.parse(key.at))));
  assert.deepEqual(rest, {
    principalType: 'user', principalId: 'ada@acme.example', status: 'active', instanceRole: 'member', scope: { projects: 'all', environments: 'all' }, declared: false,
    removedAt: null, removedBy: null, live: { grants: 2, sessions: 1, tokens: 0, identities: 0, apps: 0 }, rotated: 0,
    issuedTokens: [], apps: [], personalTokens: [], references: [], totals: { issuedTokens: 0, personalTokens: 0, references: 0 }, personal: [{ project: 'market', of: 'prod', slug: 'prod-ada' }],
  });
  // Al's scope, by slug. Cy's token is a token, an app connected through MCP an app, listed as Connected apps lists it:
  // its access token is no app of its own, nor is a connection whose code waits. He has no personal config.
  assert.deepEqual((await report(al))[0].scope, { projects: { only: ['market'] }, environments: 'all' });
  const client = JSON.stringify({ id: 'https://claude.ai/client.json', host: 'claude.ai', registration: 'cimd', redirectUri: 'https://claude.ai/callback', scopes: 'read' });
  const connection = credential('cy-app', cy, { kind: 'mcp', label: 'Claude', client });
  await write(world, ...rows('credentials', connection, credential('cy-app-access', cy, { kind: 'mcp', client, ancestors: JSON.stringify([connection.id]) }), credential('cy-app-waiting', cy, { kind: 'mcp', client, challenge: 'x' })));
  const [cys] = await report(cy);
  assert.deepEqual([cys.live, cys.personal], [{ grants: 0, sessions: 1, tokens: 1, identities: 0, apps: 1 }, []]);
  assert.deepEqual(cys.apps.map(({ id, name, host, registration, scopes, lastUsedAt }) => ({ id, name, host, registration, scopes, lastUsedAt })), [
    { id: connection.id, name: 'Claude', host: 'claude.ai', registration: 'cimd', scopes: ['read'], lastUsedAt: null },
  ]);

  // Dee leaves: what lets her in is gone, what she knows is not. The directory counts it for everyone removed, still in one statement.
  await ok(call('cy-cli', 'DELETE', `/members/${dee}`));
  const [dees] = await report(dee);
  assert.deepEqual([dees.status, typeof dees.removedAt, dees.removedBy, dees.live, dees.exposed.length], ['removed', 'string', 'cy@acme.example', { grants: 0, sessions: 0, tokens: 0, identities: 0, apps: 0 }, 2]);
  // A new DATABASE_URL takes one key off her list, which the directory counts too.
  await ok(call('al-cli', 'PATCH', '/secrets/market/prod', { DATABASE_URL: 'pg://2' }));
  assert.deepEqual(await toRotate(dee), [['market/prod/STRIPE_KEY v3 wrote'], 1]);
  const [listed, listCalls, listStatements] = await directory('cy-cli');
  assert.deepEqual([listed.removed, listCalls, listStatements], [[{ principalType: 'user', principalId: 'dee@acme.example', toRotate: 1 }, { principalType: 'user', principalId: 'rex@acme.example', toRotate: 0 }], ['caller'], 1]);
});

test("a member's report holds a read to the date the value was first written, to the millisecond, and leaves out what is archived", async () => {
  await ok(call('dee-cli', 'PATCH', '/secrets/market/prod', { A: 'a', B: 'b', C: 'c' }));
  await ok(call('dee-cli', 'PATCH', '/secrets/market/dev', { D: 'd' }));
  const secrets = await rowsOf<{ key: string; id: string; first: string }>(world.owner, sql`
    SELECT s.key, s.id, v.first_written_at::text AS first FROM secrets s JOIN secret_versions v ON v.secret_id = s.id AND v.version = s.current_version`);
  const of = (key: string) => secrets.find((row) => row.key === key)!;
  // Ed saw A as it was written, and B a millisecond before: A's value is his to rotate, B's not, though he saw the key.
  await world.owner.execute(sql`INSERT INTO exposures (principal, secret_id, seen_at) VALUES
    (${ed}, ${of('A').id}, ${of('A').first}::timestamptz), (${ed}, ${of('B').id}, ${of('B').first}::timestamptz - interval '1 millisecond'),
    (${ed}, ${of('C').id}, ${of('C').first}::timestamptz), (${ed}, ${of('D').id}, ${of('D').first}::timestamptz)`);
  assert.deepEqual(await toRotate(ed), [['market/dev/D v1 read', 'market/prod/A v1 read', 'market/prod/C v1 read'], 1]);
  const [eds] = await report(ed);
  assert.equal(Date.parse(eds.exposed[1]!.at), Date.parse(of('A').first));
  // Dee wrote B and never read it: hers is the date she wrote it.
  const [dees] = await report(dee);
  assert.equal(Date.parse(dees.exposed.find((key) => key.key === 'B')!.at), Date.parse(of('B').first));
  // Cy restores A's first value as version 2: it is the value Ed saw and Dee wrote, and Cy, who never knew it, has nothing to rotate.
  await ok(call('cy-cli', 'POST', '/secrets/market/prod/A/restore', { version: 1 }));
  assert.deepEqual(await toRotate(cy), [[], 0]);
  assert.deepEqual(await toRotate(ed), [['market/dev/D v1 read', 'market/prod/A v2 read', 'market/prod/C v1 read'], 1]);
  // An archived key, and every key of an archived environment, are none: they are listed again once they are back.
  await world.owner.execute(sql`UPDATE secrets SET archived_at = now() WHERE id = ${of('C').id}`);
  await world.owner.execute(sql`UPDATE environments SET archived_at = now() WHERE id = ${ids.dev}`);
  assert.deepEqual(await toRotate(ed), [['market/prod/A v2 read'], 1]);
  // A deleted environment's keys are none either: its slug carries the deletion's mark.
  await world.owner.execute(sql`UPDATE environments SET archived_at = NULL, slug = 'dev~1' WHERE id = ${ids.dev}`);
  assert.deepEqual(await toRotate(ed), [['market/prod/A v2 read'], 1]);
  assert.deepEqual(await toRotate(dee), [['market/prod/A v2 wrote', 'market/prod/B v1 wrote'], 0]);
  // Al writes B again, and Dee reads it: she knows its value by a read, not as its writer.
  await ok(call('al-cli', 'PATCH', '/secrets/market/prod', { B: 'b2' }));
  await ok(call('dee-cli', 'POST', '/reveals', { path: 'market/prod/B' }));
  assert.deepEqual(await toRotate(dee), [['market/prod/A v2 wrote', 'market/prod/B v2 read'], 0]);
});

test("a member's report lists the service tokens they issued that still work, and a person's own tokens, in its one statement", async () => {
  const scoped = (...places: [string, string | null, string][]) => JSON.stringify(places.map(([projectId, environmentId, role]) => ({ projectId, environmentId, role })));
  const [old, gone] = ['token:old', (await rowsOf<{ id: string }>(world.owner, sql`SELECT id FROM projects WHERE slug = 'gone~1'`))[0]!.id];
  const day = (n: number) => new Date(Date.UTC(2026, 0, n));
  await write(
    world,
    ...rows('principals', principal(old, { status: 'removed', generation: 1 })),
    ...rows('credentials',
      // Ada made two of ci's tokens that still work: one reaching market/dev and a place since deleted, one reaching market.
      credential('ci-1', ci, { createdBy: ada, createdAt: day(2), tokenHint: 'cof_…a1', scope: scoped([ids.market, ids.dev, 'viewer'], [gone, null, 'viewer']), lastUsedAt: day(3) }),
      credential('ci-2', ci, { createdBy: ada, createdAt: day(1), tokenHint: 'cof_…a2', label: null, scope: scoped([ids.market, null, 'maintainer']) }),
      // Not hers to list: revoked, expired, of an earlier generation of ci, of an account since removed, or Cy's.
      credential('ci-3', ci, { createdBy: ada, revokedAt: day(4), revokedBy: cy }),
      credential('ci-4', ci, { createdBy: ada, expiresAt: day(5) }),
      credential('ci-5', ci, { createdBy: ada, generation: 1 }),
      credential('old-1', old, { createdBy: ada, generation: 1 }),
      credential('ci-6', ci, { createdBy: cy }),
      // Her own: a personal token and a handle, newest first; not one revoked, nor her session.
      credential('ada-token', ada, { kind: 'personal', createdAt: day(6), tokenHint: 'cof_…p1', scope: scoped([ids.market, ids.prod, 'viewer']) }),
      credential('ada-handle', ada, { kind: 'handle', createdAt: day(7), tokenHint: 'cof_…h1', scope: scoped([ids.billing, null, 'viewer']) }),
      credential('ada-gone', ada, { kind: 'personal', revokedAt: day(8), revokedBy: ada })),
  );
  const [adas, calls, statements] = await report(ada);
  assert.deepEqual([calls, statements], [['caller'], 1]);
  // By account, oldest first; each scope by path, the deleted place left out.
  const issued = adas.issuedTokens as { id: string }[];
  assert.deepEqual(issued.map(({ id: _, ...token }) => token), [
    { service: 'ci', label: null, hint: 'cof_…a2', expiresAt: '2027-01-01T00:00:00.000Z', lastUsedAt: null, scope: { market: 'maintainer' } },
    { service: 'ci', label: 'ci-1', hint: 'cof_…a1', expiresAt: '2027-01-01T00:00:00.000Z', lastUsedAt: '2026-01-03T00:00:00.000Z', scope: { 'market/dev': 'viewer' } },
  ]);
  const own = adas.personalTokens as { label: string; hint: string; createdBy: string; scope: Record<string, string> }[];
  assert.deepEqual(own.map(({ label, hint, createdBy, scope }) => [label, hint, createdBy, scope]), [
    ['ada-handle', 'cof_…h1', ada, { billing: 'viewer' }],
    ['ada-token', 'cof_…p1', ada, { 'market/prod': 'viewer' }],
  ]);
  assert.equal((adas.live as { tokens: number }).tokens, own.length);
  // ci's report: none it issued, and its own tokens are on its page.
  const [cis] = await report(ci);
  assert.deepEqual([cis.issuedTokens, cis.personalTokens], [[], []]);
  // Ada leaves: her own tokens end with her; those she issued still work, and are listed.
  await ok(call('cy-cli', 'DELETE', `/members/${ada}`));
  const [left] = await report(ada);
  assert.deepEqual([(left.issuedTokens as unknown[]).length, left.personalTokens], [2, []]);
});

test("a member's report lists the references they made that still stand, by their row, in its one statement", async () => {
  await ok(call('dee-cli', 'PATCH', '/secrets/market/prod', { SRC: 'v', OTHER: 'w', GONE: 'g' }));
  // Dee points six keys at market/prod: then breaks one, writes a value over another, archives a third's key, and Cy
  // points a fourth elsewhere; GONE, a fifth's source, is archived. Cy makes one of his own.
  await ok(call('dee-cli', 'PATCH', '/secrets/market/dev', { KEPT: { ref: 'market/prod/SRC' }, BROKEN: { ref: 'market/prod/SRC' }, OVER: { ref: 'market/prod/SRC' },
    SHUT: { ref: 'market/prod/SRC' }, TAKEN: { ref: 'market/prod/SRC' }, DIM: { ref: 'market/prod/GONE' } }));
  await ok(call('cy-cli', 'PATCH', '/secrets/billing/prod', { CYS: { ref: 'market/prod/SRC' } }));
  await ok(call('dee-cli', 'DELETE', '/secrets/market/dev/BROKEN/reference'));
  await ok(call('dee-cli', 'PATCH', '/secrets/market/dev', { OVER: 'own' }));
  await amend(world, 'secrets', eq(secrets.key, 'SHUT'), { archivedAt: new Date() });
  await ok(call('cy-cli', 'PATCH', '/secrets/market/dev', { TAKEN: { ref: 'market/prod/OTHER' } }));
  await amend(world, 'secrets', eq(secrets.key, 'GONE'), { archivedAt: new Date() });
  const made = await rowsOf<{ key: string; at: string }>(world.owner, sql`SELECT key, source_set_at AS at FROM secrets WHERE source_set_by = ${dee}`);
  const at = (key: string) => new Date(made.find((row) => row.key === key)!.at).toISOString();

  const [dees, calls, statements] = await report(dee);
  assert.deepEqual([calls, statements], [['caller'], 1]);
  type Made = { id: string; holder: string; source: string; state: string; version: number | null; createdBy: string; createdAt: string; endedBy: null; endedAt: null };
  assert.deepEqual((dees.references as Made[]).map(({ id: _, ...reference }) => reference), [
    { holder: 'market/dev/KEPT', source: 'market/prod/SRC', state: 'live', version: 1, createdBy: dee, createdAt: at('KEPT'), endedBy: null, endedAt: null },
    { holder: 'market/dev/DIM', source: 'market/prod/GONE', state: 'source_archived', version: null, createdBy: dee, createdAt: at('DIM'), endedBy: null, endedAt: null },
  ]);
  assert.deepEqual(dees.totals, { issuedTokens: 0, personalTokens: 0, references: 2 });
  const [cys] = await report(cy);
  assert.deepEqual((cys.references as Made[]).map((reference) => [reference.holder, reference.source]), [['billing/prod/CYS', 'market/prod/SRC'], ['market/dev/TAKEN', 'market/prod/OTHER']]);
  // The keys' own lists say who made each, and when.
  const [, listed] = await call('cy-cli', 'GET', '/secrets/market/dev');
  const views = Object.fromEntries((listed.keys as { key: string; reference: { createdBy: string | null } | null }[]).map((key) => [key.key, key.reference?.createdBy ?? null]));
  assert.deepEqual([views.KEPT, views.TAKEN, views.BROKEN, views.OVER], [dee, cy, null, null]);

  // Dee leaves: what she lent goes on lending, and her report still says so.
  await ok(call('cy-cli', 'DELETE', `/members/${dee}`));
  assert.deepEqual(((await report(dee))[0].references as Made[]).map((reference) => reference.holder), ['market/dev/KEPT', 'market/dev/DIM']);
});

test("a member's report lists 200 of each list at most, and counts them all", async () => {
  const day = (n: number) => new Date(Date.UTC(2026, 0, 1, 0, n));
  await ok(call('dee-cli', 'PATCH', '/secrets/market/prod', { SRC: 'v' }));
  const [src] = await rowsOf<{ id: string }>(world.owner, sql`SELECT id FROM secrets WHERE key = 'SRC'`);
  const dev = { id: ids.dev!, projectId: ids.market! };
  await write(world,
    ...rows('credentials', ...Array.from({ length: 201 }, (_, n) => credential(`ada-${n}`, ada, { kind: 'personal', createdAt: day(n) })),
      ...Array.from({ length: 202 }, (_, n) => credential(`ci-${n}`, ci, { createdBy: ada, createdAt: day(n) }))),
    ...rows('secrets', ...Array.from({ length: 203 }, (_, n) => secret(dev, `REF_${n}`, { sourceId: src!.id, sourceSetBy: ada, sourceSetAt: day(n) }))));
  const [adas, calls, statements] = await report(ada);
  assert.deepEqual([calls, statements], [['caller'], 1]);
  assert.deepEqual([(adas.personalTokens as unknown[]).length, (adas.issuedTokens as unknown[]).length, (adas.references as unknown[]).length], [200, 200, 200]);
  assert.deepEqual(adas.totals, { issuedTokens: 202, personalTokens: 201, references: 203 });
  // Each the first 200 in its order: own tokens newest first, issued and references oldest first.
  assert.equal((adas.personalTokens as { label: string }[])[0]!.label, 'ada-200');
  assert.equal((adas.issuedTokens as { label: string }[]).at(-1)!.label, 'ci-199');
  assert.equal((adas.references as { holder: string }[]).at(-1)!.holder, 'market/dev/REF_199');
});

test("a member's report is for whoever runs the instance: anyone else is refused before any statement", async () => {
  for (const label of ['al-cli', 'bo-cli', 'cy-token', 'ada-cli']) {
    const [answer, calls, statements] = await cost(() => call(label, 'GET', `/members/${ada}`));
    assert.deepEqual([...refused(answer), calls, statements], [...NO_ACCESS, ['caller'], 0], label);
  }
  assert.deepEqual(refused(await call('cy-cli', 'GET', '/members/user:nobody@acme.example')), [404, 'not_found', undefined]);
  assert.deepEqual(refused(await call('cy-cli', 'GET', '/members/user:a%20b')), [400, 'bad_request', undefined]);
  // Rex, removed, has his report, and his grant is none; so is Ivy's of before she was let back in. ci's is a service account's.
  const [[rexs], [ivys], [cis]] = [await report(rex), await report(ivy), await report(ci)];
  assert.deepEqual([rexs.status, rexs.live.grants, ivys.live.grants, cis.principalType, cis.live.grants], ['removed', 0, 0, 'service', 1]);
});
