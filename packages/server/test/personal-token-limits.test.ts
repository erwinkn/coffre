// A personal token's limits over HTTP on the 0.16 contract
// (docs/design/personal-tokens.md): it makes nothing that outlives it, no
// service's token and no trust binding, whoever its person is; it signs
// itself out, and the log names it by its label; and a handle made on it
// takes its person as they are now. Cases from 0.14.7's personal-tokens
// and secret-use tests, against the real vault.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { INSTANCE_ROLES, ROLES } from '@coffre/core/access';
import { github, signin } from '@coffre/core/identity';
import { rowsOf } from '@coffre/db/dialect';
import { credential, emptyDatabase, environment, grant, instance, principal, project, role, rows, signerOf, user, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

import { processLimits } from '../src/workloads/limits.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { openApp } from './app-fixture.ts';

const KUBE = 'https://kubernetes.acme.example';
const transport: WorkloadTransport = {
  json: async (url) => {
    if (url.href === `${KUBE}/.well-known/openid-configuration`) return { issuer: KUBE, jwks_uri: `${KUBE}/openid/v1/jwks` };
    throw FetchRefused.answered(url, 404);
  },
};
const app = await openApp({ auth: signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], workloads: { limits: processLimits() } }), transport, workloads: {} });
const { world } = app;
after(() => app.close());

const [root, ada] = [user('root'), user('ada')];
const [ci, ops] = ['token:ci', 'token:ops'];
const ids: Record<string, string> = {};
let sign: () => Promise<void>;

/**
 * market: dev. Root owns the instance, whose setting lets anyone set
 * service accounts up; Ada is a Developer of market/dev. ci, a service,
 * is a Developer of market/dev, which both manage. Each has a CLI session
 * (`<name>-cli`) and a personal token (`<name>-pat`): Root's a Maintainer
 * of all of market, Ada's a Developer of market/dev, labelled `agent`. ops,
 * another service, manages access to market, with a token, `ops-token`.
 */
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  ({ sign } = await signerOf(world));
  const market = project('market');
  const dev = environment(market, 'dev');
  const scoped = (role: string, place: { environmentId: string | null }) => JSON.stringify([{ projectId: market.id, ...place, role }]);
  const pats = [
    credential('root-pat', root, { kind: 'personal', scope: scoped('maintainer', { environmentId: null }), label: 'root-agent' }),
    credential('ada-pat', ada, { kind: 'personal', scope: scoped('developer', { environmentId: dev.id }), label: 'agent', expiresAt: new Date(Date.now() + 3_600_000) }),
  ];
  Object.assign(ids, { market: market.id, dev: dev.id, rootPat: pats[0]!.id, adaPat: pats[1]!.id });
  await write(
    world,
    ...rows('policy', instance({ serviceAccounts: '{"projects":"all","environments":"all"}' })),
    ...rows('roles', ...Object.entries(ROLES).map(([id, held]) => role(false, id, [...held.permissions], [...held.protected])), ...Object.entries(INSTANCE_ROLES).map(([id, held]) => role(true, id, [...held.permissions], [...held.protected]))),
    ...rows('projects', market),
    ...rows('environments', dev),
    ...rows('principals', principal(root, { role: 'owner' }), principal(ada), principal(ci), principal(ops)),
    ...rows('grants', grant(ada, 'developer', { environment: dev }), grant(ci, 'developer', { environment: dev }), grant(ops, 'access-manager', { project: market })),
    ...rows('credentials', credential('root-cli', root), credential('ada-cli', ada), credential('ops-token', ops, { scope: scoped('access-manager', { environmentId: null }) }), ...pats),
  );
  await app.request('/livez');
  await app.request('/api/me', { headers: { authorization: 'Bearer nobody' } });
  app.calls.length = 0;
});

type Body = { error?: string; reason?: string; message?: string } & Record<string, unknown>;
const call = async (bearer: string, method: string, path: string, body?: unknown): Promise<[number, Body]> => {
  const got = await app.request(`/api${path}`, { method, headers: { authorization: `Bearer ${bearer}` }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  return [got.status, (await got.json()) as Body];
};
const refused = ([status, body]: [number, Body]) => [status, body.error, body.reason];
/** What the vault holds of ci: its live tokens and bindings. */
const held = async () => [
  (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM credentials WHERE principal = ${ci}`))[0]!.n,
  (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM bindings`))[0]!.n,
];
const BINDING = { profile: 'custom', issuer: KUBE, claims: { sub: 'system:serviceaccount:ci:runner' }, scope: { 'market/dev': 'developer' } };

test("a personal token makes no service's token and no trust binding, nor previews one, though its person may: the vault refuses, and nothing is written", async () => {
  for (const pat of ['root-pat', 'ada-pat']) {
    for (const query of ['', '?dryRun=1']) {
      assert.deepEqual(refused(await call(pat, 'POST', `/members/${ci}/tokens${query}`, { label: null, expiresInDays: 1 })), [403, 'vault_refused', 'no_access'], `${pat} token${query}`);
      assert.deepEqual(refused(await call(pat, 'POST', `/members/${ci}/bindings${query}`, BINDING)), [403, 'vault_refused', 'no_access'], `${pat} binding${query}`);
    }
  }
  assert.deepEqual(await held(), [0, 0]);
  // Their sessions make both: the refusal is the token's, not its person's.
  for (const session of ['root-cli', 'ada-cli']) {
    assert.equal((await call(session, 'POST', `/members/${ci}/tokens`, { label: null, expiresInDays: 1 }))[0], 200, session);
    assert.equal((await call(session, 'POST', `/members/${ci}/bindings`, BINDING))[0], 200, session);
  }
  assert.deepEqual(await held(), [2, 2]);
});

// 0.14.7 gave a non-person no service setting (`serviceSettingFor`): a service's token holding `grant.manage` would make
// another's tokens, or a new one of its own past its revocation.
test("a service's token manages no service, though its service manages access where ci holds its grant: it makes ci no token and no binding", async () => {
  for (const query of ['', '?dryRun=1']) {
    assert.deepEqual(refused(await call('ops-token', 'POST', `/members/${ci}/tokens${query}`, { label: null, expiresInDays: 1 })), [403, 'vault_refused', 'no_access'], `token${query}`);
    assert.deepEqual(refused(await call('ops-token', 'POST', `/members/${ci}/bindings${query}`, BINDING)), [403, 'vault_refused', 'no_access'], `binding${query}`);
  }
  assert.deepEqual(await held(), [0, 0]);
});

test("a personal token signs itself out, as `coffre logout` does: it is dead after, and the log names it by its label", async () => {
  const out = await app.request('/api/auth/logout', { method: 'POST', headers: { authorization: 'Bearer ada-pat' } });
  assert.equal(out.status, 200, await out.clone().text());
  assert.equal((await call('ada-pat', 'GET', '/me'))[0], 401);
  assert.equal((await call('ada-cli', 'GET', '/me'))[0], 200, 'her session stands');
  // A sign-out is a sign-in's kind of entry: the page shows it with `?detail=1`.
  await sign();
  const [status, page] = await call('root-cli', 'GET', '/audit?detail=1');
  assert.equal(status, 200, JSON.stringify(page));
  const entries = page.entries as { action: string; actorId: string; token: { id: string; label: string } | null }[];
  const ended = entries.find((entry) => entry.action === 'sign_out')!;
  assert.deepEqual([ended.actorId, ended.token], ['ada@acme.example', { id: ids.adaPat, label: 'agent' }]);
});

test("a handle made on a personal token takes its person as they are now: narrowed from Developer to Contributor since, the handle still reaches the place, as a contributor", async () => {
  assert.equal((await call('root-cli', 'PATCH', `/access/${ada}`, { 'market/dev': 'contributor' }))[0], 200);
  // The token reads no more: its person does not.
  assert.deepEqual(refused(await call('ada-pat', 'POST', '/reveals', { path: 'market/dev' })), [403, 'vault_refused', 'no_access']);
  const [status, handle] = await call('ada-pat', 'POST', '/handles', { label: 'coffre run market/dev', paths: ['market/dev'] });
  assert.equal(status, 200, JSON.stringify(handle));
  assert.deepEqual(handle.scope, { 'market/dev': 'contributor' });
  // Taken away, it makes none.
  assert.equal((await call('root-cli', 'PATCH', `/access/${ada}`, { 'market/dev': null }))[0], 200);
  assert.deepEqual(refused(await call('ada-pat', 'POST', '/handles', { label: 'coffre run market/dev', paths: ['market/dev'] })), [403, 'vault_refused', 'no_access']);
});
