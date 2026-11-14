// A member's tokens, handles and ending a session over HTTP on the 0.16
// contract (docs/design/0.16.md, "Signing in from the server"): making or
// ending one is one `change` and no statement; a member's list is one call
// to the vault (`caller`) and one statement, in 0.14.7's shapes. Cases from
// 0.14.7's signin-service and personal-tokens tests where they still hold.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { INSTANCE_ROLES, ROLES } from '@coffre/core/access';
import { tokenHint } from '@coffre/core/identity';
import { binding, credential, emptyDatabase, environment, grant, instance, principal, project, role, rows, session, user, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

import type { ApiContext } from '../src/api/context.ts';
import type { ApiError } from '../src/api/errors.ts';
import { tokenRoutes } from '../src/api/routes/tokens.ts';
import { openApp } from './app-fixture.ts';

const app = await openApp();
const { world } = app;
after(() => app.close());

const [root, al, bo, cy, dee] = ['root', 'al', 'bo', 'cy', 'dee'].map(user) as [string, string, string, string, string];
const [ci, ops, bare, old, reader, left] = ['token:ci', 'token:ops', 'token:bare', 'token:old', 'token:reader', 'token:left'];
/** The instance's setting as it ships: anyone sets service accounts up, anywhere. */
const EVERYWHERE = '{"projects":"all","environments":"all"}';

/**
 * market: dev, and prod, protected; gone~1, a deletion's tombstone. Root
 * owns the instance, whose setting lets anyone set service accounts up
 * everywhere. Bo is a Developer of market/dev, Cy a Viewer of market/prod,
 * Dee holds nothing. ci, a service account, holds Developer on market/dev,
 * so Bo manages it; ops a Viewer of market/prod, which Bo does not hold;
 * bare nothing, admitted by Bo, so Bo manages it too; old Developer on
 * market/dev and a Viewer of gone~1, a grant that reaches nothing, so Bo
 * manages it as ci; reader a Viewer of market/dev, a role Bo does not
 * hold and holds all of, so Bo manages it. bare also has a grant that
 * ended and one of before it was let back in, which count for nothing.
 * left was removed, its token still a row. Al owns market by a grant. Dee
 * was removed and let back in: generation 1, a personal token of each.
 *
 * ci has a token (`ci-token`), one revoked, one expired, one a trust
 * binding issued a CI run (`ci-run`) and a workload's session through that
 * binding (`ci-pod`). Bo has a personal token and a handle.
 */
let ids: Record<string, string> = {};
let patEnds: Date;
beforeEach(() => instanceOf(EVERYWHERE));
async function instanceOf(setting: string) {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  const [market, gone] = [project('market'), project('gone~1')];
  const [dev, prod] = [environment(market, 'dev'), environment(market, 'prod', { protected: true })];
  const trusted = binding(ci, { profile: 'kubernetes', policy: '{}' });
  const deleted = environment(market, 'old~2');
  // A scope's places that were deleted since are not shown.
  const developer = (more: object = {}) => JSON.stringify([{ projectId: market.id, environmentId: dev.id, role: 'developer', ...more }, { projectId: gone.id, environmentId: null, role: 'viewer' }, { projectId: market.id, environmentId: deleted.id, role: 'viewer' }]);
  // Bo's personal token ends in a day: a handle made on it never outlasts it.
  patEnds = new Date(Math.floor(Date.now() / 1000) * 1000 + 86_400_000);
  const made = {
    ciToken: credential('ci-token', ci, { scope: developer(), tokenHint: 'coffre_svc_…ci01', label: 'deploy', lastUsedIp: '192.0.2.9', createdAt: new Date('2026-11-01T00:00:00Z') }),
    ciPod: session('ci-pod', trusted, { scope: developer(), createdAt: new Date('2026-11-02T00:00:00Z') }),
    boPat: credential('bo-pat', bo, { kind: 'personal', scope: JSON.stringify([{ projectId: market.id, environmentId: dev.id, role: 'viewer' }]), tokenHint: 'coffre_pat_…bo01', expiresAt: patEnds }),
    boHandle: credential('bo-handle', bo, { kind: 'handle', scope: '[]', places: '[]', expiresAt: new Date('2026-12-31T00:00:00Z') }),
    cyCli: credential('cy-cli', cy),
    boCli: credential('bo-cli', bo),
  };
  ids = { market: market.id, dev: dev.id, binding: trusted.id, ...Object.fromEntries(Object.entries(made).map(([name, row]) => [name, row.id])) };
  await write(
    world,
    ...rows('projects', market, gone),
    ...rows('environments', dev, prod, deleted),
    ...rows('policy', instance({ serviceAccounts: setting })),
    // Every role as it ships.
    ...rows('roles', ...Object.entries(ROLES).map(([id, held]) => role(false, id, [...held.permissions], [...held.protected])), ...Object.entries(INSTANCE_ROLES).map(([id, held]) => role(true, id, [...held.permissions], [...held.protected]))),
    ...rows('principals', principal(root, { role: 'owner' }), principal(bo), principal(cy), principal(dee, { generation: 1 }), principal(ci), principal(ops), principal(bare, { statusChangedBy: bo, generation: 1 }), principal(old), principal(reader), principal(left, { status: 'removed' }), principal(al)),
    ...rows('grants', grant(bo, 'developer', { environment: dev }), grant(cy, 'viewer', { environment: prod }), grant(ci, 'developer', { environment: dev }), grant(ops, 'viewer', { environment: prod }),
      grant(old, 'developer', { environment: dev }), grant(old, 'viewer', { project: gone }), grant(reader, 'viewer', { environment: dev }), grant(al, 'owner', { project: market }),
      grant(bare, 'viewer', { environment: prod }, { generation: 1, expiresAt: new Date('2020-01-01T00:00:00Z') }), grant(bare, 'viewer', { project: market })),
    ...rows('bindings', trusted),
    ...rows('credentials',
      credential('root-cli', root), credential('al-cli', al), credential('left-token', left, { scope: developer() }), credential('dee-cli', dee, { generation: 1 }), credential('bo-cli2', bo),
      credential('dee-was', dee, { kind: 'personal', scope: '[]' }), credential('dee-pat', dee, { kind: 'personal', scope: '[]', generation: 1, label: 'now' }),
      ...Object.values(made),
      credential('ci-ended', ci, { scope: developer(), revokedAt: new Date('2026-11-03T00:00:00Z'), revokedBy: root }),
      credential('ci-lapsed', ci, { scope: developer(), expiresAt: new Date('2020-01-01T00:00:00Z') }),
      credential('ci-run', ci, { scope: developer(), createdBy: `binding:${trusted.id}` }),
      credential('ops-token', ops, { scope: JSON.stringify([{ projectId: market.id, environmentId: prod.id, role: 'viewer' }]) })),
  );
  await app.request('/livez');
  await app.request('/api/me', { headers: { authorization: 'Bearer nobody' } });
  app.calls.length = 0;
}

type Body = { error?: string; reason?: string; message?: string } & Record<string, unknown>;
const call = async (bearer: string, method: string, path: string, body?: unknown): Promise<[number, Body]> => {
  const got = await app.request(`/api${path}`, { method, headers: { authorization: `Bearer ${bearer}` }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  return [got.status, (await got.json()) as Body];
};
async function cost<T>(run: () => Promise<T>): Promise<[T, string[], number]> {
  const [calls, statements] = [app.calls.length, app.statements];
  const result = await run();
  return [result, app.calls.slice(calls), app.statements - statements];
}
const refused = (answer: [number, Body]) => [answer[0], answer[1].error, answer[1].reason];

type Listed = { id: string; label: string | null; hint: string; scope: Record<string, string> | null; createdBy: string; lastUsedIp: string | null; session?: { bindingId: string | null } };
const listed = async (bearer: string, member: string): Promise<[Listed[], string[], number]> => {
  const [[status, body], calls, statements] = await cost(() => call(bearer, 'GET', `/members/${member}/tokens`));
  assert.equal(status, 200, JSON.stringify(body));
  return [body.tokens as Listed[], calls, statements];
};

test("a service account's live tokens and its workloads' sessions, newest first, to whoever manages it and to itself: one call to the vault and one statement", async () => {
  for (const bearer of ['root-cli', 'bo-cli', 'ci-token']) {
    const [tokens, calls, statements] = await listed(bearer, ci);
    assert.deepEqual([calls, statements], [['caller'], 1], bearer);
    // Never one revoked, expired, or a CI run's from its binding; each place of a scope by path, those still there.
    assert.deepEqual(tokens.map((token) => token.id), [ids.ciPod, ids.ciToken], bearer);
    // As stored, but for its own use, which a request on it records.
    if (bearer !== 'ci-token') assert.deepEqual(tokens[1], { id: ids.ciToken, label: 'deploy', hint: 'coffre_svc_…ci01', createdAt: '2026-11-01T00:00:00.000Z', createdBy: ci, expiresAt: '2027-01-01T00:00:00.000Z', lastUsedAt: null, lastUsedIp: '192.0.2.9', scope: { 'market/dev': 'developer' } });
    assert.deepEqual(tokens[0]!.session, { bindingId: ids.binding });
  }
  // Bo manages bare, which holds nothing and which he admitted: none of its tokens yet; and old, whose grant on a deleted project reaches nothing.
  assert.deepEqual((await listed('bo-cli', bare))[0], []);
  assert.deepEqual((await listed('bo-cli', old))[0], []);
  assert.deepEqual((await listed('bo-cli', reader))[0], []);
  // A removed account's tokens are no longer any, whatever their rows say; an account that is not there has none.
  assert.deepEqual((await listed('root-cli', left))[0], []);
  assert.deepEqual((await listed('root-cli', 'token:nobody'))[0], []);
  // Bo's personal token manages nothing, not even the account he admitted.
  assert.deepEqual(refused(await call('bo-pat', 'GET', `/members/${bare}/tokens`)), [403, 'forbidden', undefined]);
  // Not ops, whose grant he does not hold; not anyone's to Cy or Dee; not ci's to another service's token.
  for (const [bearer, member] of [['bo-cli', ops], ['cy-cli', ci], ['dee-cli', ci], ['ops-token', ci]] as const) {
    assert.deepEqual(refused(await call(bearer, 'GET', `/members/${member}/tokens`)), [403, 'forbidden', undefined], `${bearer} ${member}`);
  }
  // A token of Bo's own, which holds a scope, manages nothing: no service's list.
  assert.deepEqual(refused(await call('bo-pat', 'GET', `/members/${ci}/tokens`)), [403, 'forbidden', undefined]);
});

test("who manages a service account is weighed inside the instance's setting: outside it, Bo lists none but bare's, which he admitted", async () => {
  await instanceOf('{"projects":{"only":[]},"environments":"all"}');
  assert.deepEqual(refused(await call('bo-cli', 'GET', `/members/${ci}/tokens`)), [403, 'forbidden', undefined]);
  assert.deepEqual((await listed('root-cli', ci))[0].length, 2);
  assert.deepEqual((await listed('bo-cli', bare))[0], []);
  // A setting that does not read as one lets nobody but whoever runs the instance, as the vault reads it: not even an Owner of the project.
  await instanceOf('[]');
  assert.deepEqual(refused(await call('bo-cli', 'GET', `/members/${bare}/tokens`)), [403, 'forbidden', undefined]);
  assert.deepEqual(refused(await call('al-cli', 'GET', `/members/${ci}/tokens`)), [403, 'forbidden', undefined]);
  assert.deepEqual((await listed('root-cli', ci))[0].length, 2);
});

test("a person's personal tokens and handles, to them on a session of theirs and to whoever runs the instance; a personal token lists none", async () => {
  for (const bearer of ['bo-cli', 'root-cli']) {
    const [tokens, calls, statements] = await listed(bearer, bo);
    assert.deepEqual([calls, statements], [['caller'], 1]);
    // Made at the same instant: by id after.
    assert.deepEqual(tokens.map((token) => [token.id, token.scope]), [[ids.boPat, { 'market/dev': 'viewer' }], [ids.boHandle, {}]].sort(([a], [b]) => ((a as string) < (b as string) ? -1 : 1)));
  }
  // Only a token of the generation they are in: Dee's of before she was removed is none.
  assert.deepEqual((await listed('root-cli', dee))[0].map((token) => token.label), ['now']);
  // Bo's sessions are no tokens; one cased otherwise is the same person.
  assert.deepEqual((await listed('bo-cli', 'user:BO@acme.example'))[0].length, 2);
  for (const [bearer, member] of [['bo-pat', bo], ['cy-cli', bo], ['bo-cli', cy]] as const) {
    assert.deepEqual(refused(await call(bearer, 'GET', `/members/${member}/tokens`)), [403, 'forbidden', undefined], `${bearer} ${member}`);
  }
});

test("an instance role with no row, or one written behind the vault, is no role: an Owner by it lists no one else's tokens, as the vault would let them end none", async () => {
  for (const [how, behind] of [['missing', sql`DELETE FROM roles WHERE instance AND id = 'owner'`], ['forged', sql`UPDATE roles SET mac = '\\x'::bytea WHERE instance AND id = 'owner'`]] as const) {
    await instanceOf(EVERYWHERE);
    await world.owner.execute(behind);
    for (const member of [bo, ci]) {
      assert.deepEqual(refused(await call('root-cli', 'GET', `/members/${member}/tokens`)), [403, 'forbidden', undefined], `${how} ${member}`);
    }
    // Their own, on a session, as anyone's.
    assert.deepEqual((await listed('root-cli', root))[0], [], how);
  }
});

test('a personal token made by its person on a session: drawn by the app, one change and no statement, and it signs in', async () => {
  const [[status, body], calls, statements] = await cost(() => call('bo-cli', 'POST', `/members/${bo}/tokens`, { label: ' script ', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } }));
  assert.equal(status, 200, JSON.stringify(body));
  assert.deepEqual([calls, statements], [['change'], 0]);
  const { id, token, expiresAt, scope } = body as { id: string; token: string; expiresAt: string; scope: Record<string, string> };
  assert.match(token, /^coffre_pat_[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(scope, { 'market/dev': 'viewer' });
  assert.ok(Math.abs(Date.parse(expiresAt) - Date.now() - 3_600_000) < 60_000);
  // It is Bo, within its scope, and listed by its hint and trimmed label, never its value.
  const [me] = await call(token, 'GET', '/me');
  assert.equal(me, 200);
  const [tokens] = await listed('bo-cli', bo);
  const made = tokens.find((listedToken) => listedToken.id === id)!;
  assert.deepEqual([made.label, made.hint, made.createdBy], ['script', tokenHint(token), bo]);
  assert.ok(!JSON.stringify(tokens).includes(token));
});

test("a personal token is its person's own, made on a session, with a label, minutes and a scope; what does not parse asks nothing", async () => {
  const scope = { 'market/dev': 'viewer' };
  // Another person's, and one made on a token: as the vault refuses anything beyond the caller.
  assert.deepEqual(refused(await call('bo-cli', 'POST', `/members/${cy}/tokens`, { label: 'x', expiresInMinutes: 60, scope })), [403, 'vault_refused', 'no_access']);
  assert.deepEqual(refused(await call('bo-pat', 'POST', `/members/${bo}/tokens`, { label: 'x', expiresInMinutes: 60, scope })), [403, 'vault_refused', 'no_access']);
  // A service's token names no person's.
  const service = await call('ci-token', 'POST', '/members/user:ci@acme.example/tokens', { label: 'x', expiresInMinutes: 60, scope });
  assert.deepEqual(refused(service), [403, 'forbidden', 'not_a_person']);
  assert.match(service[1].message!, /only a person makes a personal token/);
  app.calls.length = 0;
  const bads: unknown[] = [
    { expiresInMinutes: 60, scope },
    { label: 'x', expiresInDays: 1, scope },
    { label: 'x', expiresInMinutes: 60, expiresInDays: 1, scope },
    { label: 'x', expiresInMinutes: 60 },
    { label: 'x', expiresInMinutes: 7 * 24 * 60 + 1, scope },
    { label: 'x', expiresInMinutes: 60, scope: {} },
    { label: 'x', expiresInMinutes: 60, scope: { 'market/dev/x': 'viewer' } },
    { label: 'x', expiresInMinutes: 60, scope: { 'Market/dev': 'viewer' } },
    { label: 'x', expiresInMinutes: 60, scope: { 'market/dev': 'Viewer' } },
    { label: 'a\u0007b', expiresInMinutes: 60, scope },
    { label: 'a\ud800b', expiresInMinutes: 60, scope },
    { label: 'x'.repeat(121), expiresInMinutes: 60, scope },
    { label: '   ', expiresInMinutes: 60, scope },
  ];
  for (const bad of bads) assert.deepEqual(refused(await call('bo-cli', 'POST', `/members/${bo}/tokens`, bad)), [400, 'bad_request', undefined], JSON.stringify(bad));
  assert.deepEqual(refused(await call('bo-cli', 'POST', '/members/bo/tokens', { label: 'x', expiresInMinutes: 60, scope })), [400, 'bad_request', undefined]);
  assert.deepEqual(app.calls, []);
});

test("0.14.7's preview of a token (`?dryRun=1`) is not served yet, and makes nothing", async () => {
  const before = (await listed('root-cli', ci))[0].length;
  app.calls.length = 0;
  assert.deepEqual(refused(await call('bo-cli', 'POST', `/members/${ci}/tokens?dryRun=1`, { label: null, expiresInDays: 1 })), [501, 'not_implemented', undefined]);
  assert.deepEqual(refused(await call('bo-cli', 'POST', `/members/${bo}/tokens?dryRun=1`, { label: 'x', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } })), [501, 'not_implemented', undefined]);
  assert.deepEqual(app.calls, []);
  assert.equal((await listed('root-cli', ci))[0].length, before);
});

test("a service's token, made by whoever manages it: its scope, or every grant it holds; one change and no statement", async () => {
  const [[status, body], calls, statements] = await cost(() => call('bo-cli', 'POST', `/members/${ci}/tokens`, { label: null, expiresInDays: 30 }));
  assert.equal(status, 200, JSON.stringify(body));
  assert.deepEqual([calls, statements], [['change'], 0]);
  assert.match(body.token as string, /^coffre_svc_[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(body.scope, { 'market/dev': 'developer' });
  assert.ok(Math.abs(Date.parse(body.expiresAt as string) - Date.now() - 30 * 86_400_000) < 60_000);
  assert.deepEqual((await call('bo-cli', 'POST', `/members/${ci}/tokens`, { label: 'read', expiresInDays: 1, scope: { 'market/dev': 'viewer' } }))[1].scope, { 'market/dev': 'viewer' });
  // Not ops, whose grant Bo does not hold; not a place beyond the account.
  assert.deepEqual(refused(await call('bo-cli', 'POST', `/members/${ops}/tokens`, { label: null, expiresInDays: 1 })), [403, 'vault_refused', 'no_access']);
  assert.deepEqual(refused(await call('bo-cli', 'POST', `/members/${ci}/tokens`, { label: null, expiresInDays: 1, scope: { 'market/prod': 'viewer' } })), [403, 'vault_refused', 'no_access']);
  // An account with nothing to reach needs a grant first, as 0.14.7 said; one that is not there is refused as any place beyond the caller.
  assert.deepEqual(refused(await call('bo-cli', 'POST', `/members/${bare}/tokens`, { label: null, expiresInDays: 1 })), [400, 'bad_request', 'no_grants']);
  assert.deepEqual(refused(await call('root-cli', 'POST', '/members/token:nobody/tokens', { label: null, expiresInDays: 1 })), [404, 'not_found', 'unknown_principal']);
  app.calls.length = 0;
  for (const bad of [{ label: null }, { label: null, expiresInDays: 367 }, { label: null, expiresInDays: 1, expiresInMinutes: 60 }, { label: null, expiresInDays: 1, scope: {} }]) {
    assert.deepEqual(refused(await call('bo-cli', 'POST', `/members/${ci}/tokens`, bad)), [400, 'bad_request', undefined], JSON.stringify(bad));
  }
  assert.deepEqual(app.calls, []);
});

test("ending a member's token: theirs, by whoever manages the account or runs the instance, and once; one change and no statement", async () => {
  const [answer, calls, statements] = await cost(() => call('bo-cli', 'DELETE', `/members/${ci}/tokens/${ids.ciToken}`));
  assert.deepEqual([answer, calls, statements], [[200, { revoked: true }], ['change'], 0]);
  assert.equal((await call('ci-token', 'GET', '/me'))[0], 401);
  // Ended already, not ci's, not Bo's to end, or no credential at all: one answer.
  for (const [bearer, member, id] of [['bo-cli', ci, ids.ciToken], ['bo-cli', ops, ids.ciPod], ['cy-cli', ci, ids.ciPod], ['bo-cli', ci, ids.boPat], ['root-cli', ci, '00000000-0000-4000-8000-000000000000']] as const) {
    assert.deepEqual(refused(await call(bearer, 'DELETE', `/members/${member}/tokens/${id}`)), [404, 'not_found', 'unknown_credential'], `${bearer} ${member} ${id}`);
  }
  // A workload's session, by whoever manages its account; a person's token by whoever runs the instance.
  assert.deepEqual(await call('bo-cli', 'DELETE', `/members/${ci}/tokens/${ids.ciPod}`), [200, { revoked: true }]);
  // An id in capitals is the same id, as the vault takes it.
  assert.deepEqual(await call('root-cli', 'DELETE', `/members/${bo}/tokens/${ids.boPat!.toUpperCase()}`), [200, { revoked: true }]);
  assert.deepEqual(refused(await call('bo-cli', 'DELETE', `/members/${ci}/tokens/not-an-id`)), [400, 'bad_request', undefined]);
});

test('a handle: made by a person on a session or a personal token of theirs, for the proxy, and ended by them; one change each', async () => {
  const [[status, body], calls, statements] = await cost(() => call('bo-cli', 'POST', '/handles', { label: 'run', paths: ['market/dev'] }));
  assert.equal(status, 200, JSON.stringify(body));
  assert.deepEqual([calls, statements], [['change'], 0]);
  assert.match(body.token as string, /^coffre_use_[A-Za-z0-9_-]{43}$/);
  // Bo reads dev: viewer there, which reads and uses, and writes nothing.
  assert.deepEqual(body.scope, { 'market/dev': 'viewer' });
  // Twelve hours unless told.
  assert.ok(Math.abs(Date.parse(body.expiresAt as string) - Date.now() - 12 * 3_600_000) < 60_000);
  // On his personal token, never past it.
  const onToken = await call('bo-pat', 'POST', '/handles', { label: 'run', expiresInMinutes: 7 * 24 * 60, paths: ['market/dev'] });
  assert.equal(onToken[0], 200, JSON.stringify(onToken[1]));
  assert.equal(onToken[1].expiresAt, patEnds.toISOString());
  // A service reads its values: it needs no placeholder.
  assert.deepEqual(refused(await call('ci-token', 'POST', '/handles', { label: 'run', paths: ['market/dev'] })), [403, 'forbidden', 'not_a_person']);
  assert.deepEqual(refused(await call('dee-cli', 'POST', '/handles', { label: 'run', paths: ['market/dev'] })), [403, 'vault_refused', 'no_access']);
  // Ended by its person, a handle alone; anyone else's, or a token that is no handle, is unknown.
  assert.deepEqual(refused(await call('cy-cli', 'DELETE', `/handles/${body.id as string}`)), [404, 'not_found', 'unknown_credential']);
  assert.deepEqual(refused(await call('bo-cli', 'DELETE', `/handles/${ids.boPat}`)), [404, 'not_found', 'unknown_credential']);
  assert.deepEqual(await call('bo-pat', 'DELETE', `/handles/${(body.id as string).toUpperCase()}`), [200, { revoked: true }]);
  app.calls.length = 0;
  for (const bad of [{ paths: ['market/dev'] }, { label: 'run', paths: [] }, { label: 'run', paths: ['market'] }, { label: 'run', paths: ['market/dev@you'] }, { label: 'run', paths: ['market/dev'], expiresInMinutes: 0 }]) {
    assert.deepEqual(refused(await call('bo-cli', 'POST', '/handles', bad)), [400, 'bad_request', undefined], JSON.stringify(bad));
  }
  assert.deepEqual(app.calls, []);
});

test("ending a session: the caller's own, or anyone's to whoever runs the instance; one change and no statement", async () => {
  const [answer, calls, statements] = await cost(() => call('bo-cli', 'DELETE', `/sessions/${ids.cyCli}`));
  assert.deepEqual([refused(answer), calls, statements], [[404, 'not_found', 'unknown_credential'], ['change'], 0]);
  // An id in capitals is the same id.
  assert.deepEqual(await call('root-cli', 'DELETE', `/sessions/${ids.cyCli!.toUpperCase()}`), [200, { revoked: true }]);
  assert.equal((await call('cy-cli', 'GET', '/me'))[0], 401);
  // Bo's own, from another of his sessions, and once.
  assert.deepEqual(await call('bo-cli2', 'DELETE', `/sessions/${ids.boCli}`), [200, { revoked: true }]);
  assert.equal((await call('bo-cli', 'GET', '/me'))[0], 401);
  assert.deepEqual(refused(await call('bo-cli2', 'DELETE', `/sessions/${ids.boCli}`)), [404, 'not_found', 'unknown_credential']);
});

test("behind Cloudflare Access there are no tokens, handles or sessions of coffre's: 404, before the vault is asked", async () => {
  // The API behind Access answers 501 at its door until it is served; each of these routes says 404 of its own then, as 0.14.7 did.
  const asked: string[] = [];
  const ctx = { auth: { mode: 'cloudflare' }, vault: new Proxy({}, { get: (_, name) => () => asked.push(String(name)) }), caller: async () => asked.push('caller') } as unknown as ApiContext;
  for (const [key, def] of Object.entries(tokenRoutes)) {
    await assert.rejects((def.run as (ctx: ApiContext, call: unknown) => Promise<unknown>)(ctx, { params: { member: ci, id: ids.ciToken }, input: { label: 'run', paths: ['market/dev'], expiresInDays: 1 }, query: {} }), (error: ApiError) => error.code === 'not_found', key);
  }
  assert.deepEqual(asked, []);
});

test('approving a workload\'s session and trust bindings are not served yet', async () => {
  assert.deepEqual(refused(await call('root-cli', 'POST', `/members/${ci}/tokens/${ids.ciPod}/approve`, {})), [501, 'not_implemented', undefined]);
});
