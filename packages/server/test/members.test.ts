// Members and their access over HTTP on the 0.16 contract (docs/design/0.16.md,
// "The server"): the directory and one member's access, each one call to the
// vault (`caller`) and fixed statements, scoped by its answer, in 0.14.7's
// shapes; and the changes of members and grants, each one `change` and no
// statement. Cases from 0.14.7's admin-api, owner-powers and one-access tests
// where they still hold.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { credential, emptyDatabase, environment, grant, principal, project, role, rows, user, write } from '@coffre/vault/testing';

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

test('an Owner of the instance lists everyone and every live grant, with scopes and who was removed: one call to the vault and one statement', async () => {
  const [listed, calls, statements] = await directory('cy-cli');
  assert.deepEqual([calls, statements], [['caller'], 1]);
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
  // Rex was removed: listed apart, so he can be let back in. What he saw comes with the member report.
  assert.deepEqual(listed.removed, [{ principalType: 'user', principalId: 'rex@acme.example', toRotate: null }]);
});

test('a manager of a project lists the grants they manage and their members, and no scope; anyone else is refused', async () => {
  const [listed, calls, statements] = await directory('bo-cli');
  assert.deepEqual([calls, statements], [['caller'], 1]);
  // Ada's grant on billing is not Bo's to see, nor is Dee, who holds market by her role alone, without a path.
  assert.deepEqual(brief(listed), ['token:ci: member, market=maintainer', `${ada}: member, market=viewer`, `${bo}: member, market=manager`, `${ed}: member, market/dev=viewer`, `${fin}: member, market/dev=viewer`]);
  assert.deepEqual([listed.members.every((member) => member.scope === null && !member.managed), listed.removed], [true, []]);

  // Ada manages nothing: refused, with no statement.
  const [answer, refusedCalls, refusedStatements] = await cost(() => call('ada-cli', 'GET', '/members'));
  assert.deepEqual([...refused(answer), refusedCalls, refusedStatements], [...NO_ACCESS, ['caller'], 0]);
  // Cy's token holds nothing of the instance's own, and manages no grant: refused too.
  assert.deepEqual(refused(await call('cy-token', 'GET', '/members')), NO_ACCESS);
});

test('an Admin scoped to a project lists everyone, with the grants inside their scope, and no scope or removed member', async () => {
  const [listed] = await directory('al-cli');
  assert.deepEqual(brief(listed), [
    'token:ci: member, market=maintainer',
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
  const [market, calls, statements] = await directory('bo-cli', 'market');
  assert.deepEqual([calls, statements], [['caller'], 2]);
  assert.deepEqual(brief(market), [
    'token:ci: member, market=maintainer',
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
  // Ed manages nothing there.
  assert.deepEqual(refused(await call('ed-cli', 'GET', '/members?path=market')), NO_ACCESS);
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

test("one member's access: the grants the caller manages, their role, and their scope to whoever runs the instance; one call to the vault and one statement", async () => {
  type Access = { member: string; principalType: string; principalId: string; status: string; instanceRole: string; scope: unknown; managed: boolean; grants: Grant[] };
  const access = async (label: string, member: string): Promise<[Access, string[], number]> => {
    const [[status, body], calls, statements] = await cost(() => call(label, 'GET', `/members/${encodeURIComponent(member)}/access`));
    assert.equal(status, 200, JSON.stringify(body));
    return [body as unknown as Access, calls, statements];
  };
  const [adas, calls, statements] = await access('cy-cli', ada);
  assert.deepEqual([calls, statements], [['caller'], 1]);
  assert.deepEqual({ ...adas, grants: adas.grants.map((held) => held.id) }, {
    member: ada, principalType: 'user', principalId: 'ada@acme.example', status: 'active', instanceRole: 'member', scope: { projects: 'all', environments: 'all' }, managed: false,
    grants: [`${ada}/billing/prod`, `${ada}/market`],
  });
  // Bo sees what he manages of hers, and no scope; a person's email is one however it is cased. Fin reaches market, and manages billing alone.
  const [seen] = await access('bo-cli', 'user:ADA@Acme.example');
  assert.deepEqual([seen.member, seen.scope, seen.grants.map((held) => held.id)], [ada, null, [`${ada}/market`]]);
  assert.deepEqual((await access('fin-cli', ada))[0].grants.map((held) => held.id), [`${ada}/billing/prod`]);
  // Al's scope, by slug; a service account, managed by whoever runs the instance.
  assert.deepEqual([(await access('cy-cli', al))[0].scope, (await access('cy-cli', ci))[0].managed, (await access('al-cli', ci))[0].managed], [{ projects: { only: ['market'] }, environments: 'all' }, true, false]);
  // Rex was removed: he holds nothing, whatever his rows say.
  const [rexs] = await access('cy-cli', rex);
  assert.deepEqual([rexs.status, rexs.instanceRole, rexs.grants], ['removed', 'member', []]);

  assert.deepEqual(refused(await call('ada-cli', 'GET', `/members/${bo}/access`)), NO_ACCESS);
  assert.deepEqual(refused(await call('cy-cli', 'GET', '/members/user:nobody@acme.example/access')), [404, 'not_found', undefined]);
  for (const bad of ['ada', 'user:', 'token::b', 'user:a b', 'group:x', `token:${'x'.repeat(260)}`]) {
    assert.deepEqual(refused(await call('cy-cli', 'GET', `/members/${encodeURIComponent(bad)}/access`)), [400, 'bad_request', undefined], bad);
  }
});

test('removing a member is one change and no statement: their grants go, and their sessions end', async () => {
  const [[status, body], calls, statements] = await cost(() => call('cy-cli', 'DELETE', `/members/${ada}`));
  assert.deepEqual([status, body, calls, statements], [200, { revoked: { grants: 2, sessions: null, tokens: null, identities: null, apps: null }, report: null }, ['change'], 0]);
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

test("a person's grants set in one change and no statement, each place by path, all or none", async () => {
  const patch = (label: string, member: string, body: unknown) => cost(() => call(label, 'PATCH', `/access/${member}`, body));
  const [[status, body], calls, statements] = await patch('bo-cli', gus, { market: 'viewer', 'market/prod/': { role: 'viewer', until: '2030-12-31' } });
  assert.deepEqual([status, body, calls, statements], [200, { changes: { market: 'created', 'market/prod': 'created' } }, ['change'], 0]);
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
  // A service account's grants wait on who manages one (D239).
  assert.deepEqual(refused(await call('cy-cli', 'PATCH', `/access/${ci}`, { market: 'viewer' })), [501, 'not_implemented', undefined]);
});

test('a member put is one change and no statement: admitted, brought back or given a role, as their row calls for', async () => {
  const put = (label: string, member: string, body: unknown) => cost(() => call(label, 'PUT', `/members/${member}`, body));
  const everywhere = { projects: 'all', environments: 'all' };
  const nobody = 'user:new@acme.example';

  // No row: admitted, as member when no role is asked.
  const [[status, body], calls, statements] = await put('cy-cli', 'user:New@Acme.example', {});
  assert.deepEqual([status, body, calls, statements], [200, { member: nobody, instanceRole: 'member', scope: everywhere, created: true }, ['change'], 0]);
  // Active, a role and a scope set, by slug; asked again, nothing moves.
  const admin = { role: 'admin', scope: { projects: { only: ['market', 'billing', 'market'] } } };
  const scoped = { projects: { only: ['billing', 'market'] }, environments: 'all' };
  assert.deepEqual((await put('cy-cli', nobody, admin)).slice(0, 3), [[200, { member: nobody, instanceRole: 'admin', scope: scoped, created: false }], ['change'], 0]);
  assert.deepEqual((await put('cy-cli', nobody, admin))[0][1], { member: nobody, instanceRole: 'admin', scope: scoped, created: false });
  // No role keeps theirs: its scope names projects by id, which one statement words.
  assert.deepEqual((await put('cy-cli', nobody, {})).slice(0, 3), [[200, { member: nobody, instanceRole: 'admin', scope: scoped, created: false }], ['change'], 1]);
  assert.deepEqual((await put('cy-cli', dee, {})).slice(0, 3), [[200, { member: dee, instanceRole: 'developer', scope: everywhere, created: false }], ['change'], 0]);
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

  // What the app tells before any call; a service account made with its grants waits on who manages one (D239).
  const before = app.calls.length;
  const bads: [string, unknown][] = [
    [gus, { scope: { projects: 'all' } }], [gus, { role: 'member', scope: { projects: 'all' } }], [gus, { role: 'boss' }], [gus, { role: 'admin', scope: { projects: { only: ['Market'] } } }],
    [gus, { role: 'admin', extra: 1 }], [gus, { access: { market: 'viewer' } }], [ci, { access: { market: 'viewer' }, role: 'member' }], [ci, { access: {} }],
  ];
  for (const [member, bad] of bads) assert.deepEqual(refused(await call('cy-cli', 'PUT', `/members/${member}`, bad)), [400, 'bad_request', undefined], JSON.stringify(bad));
  assert.deepEqual(refused(await call('cy-cli', 'PUT', '/members/user:a%20b', {})), [400, 'bad_request', undefined]);
  assert.equal(app.calls.length, before);
  assert.deepEqual(refused(await call('cy-cli', 'PUT', `/members/${ci}`, { access: { market: 'viewer' } })), [501, 'not_implemented', undefined]);
});

test('what is not served yet answers 501', async () => {
  for (const [method, path] of [['GET', `/members/${ada}`], ['GET', `/members/${ci}/tokens`], ['POST', `/members/${ci}/bindings`]] as const) {
    assert.deepEqual(refused(await call('cy-cli', method, path, method === 'GET' ? undefined : {})), [501, 'not_implemented', undefined], `${method} ${path}`);
  }
});
