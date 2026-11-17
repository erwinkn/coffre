// What a service's token or binding will not read, and says so (R32,
// `withheld`), and the personal token `GET /me` names, over HTTP on the 0.16
// contract: decided in the vault, beside the rows the change reads, at no
// call or statement more (request-cost.test.ts). Cases from 0.14.7's
// service-sensitive, credential-scopes and personal-tokens tests.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { INSTANCE_ROLES, ROLES } from '@coffre/core/access';
import { github, signin } from '@coffre/core/identity';
import { credential, emptyDatabase, environment, grant, instance, principal, project, role, rows, secret, user, value, write } from '@coffre/vault/testing';

import { processLimits } from '../src/workloads/limits.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { openApp } from './app-fixture.ts';

const KUBE = 'https://kubernetes.acme.example';
const transport: WorkloadTransport = {
  async json(url) {
    if (url.href === `${KUBE}/.well-known/openid-configuration`) return { issuer: KUBE, jwks_uri: `${KUBE}/openid/v1/jwks` };
    throw FetchRefused.answered(url, 404);
  },
};
const app = await openApp({ auth: signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], workloads: { limits: processLimits() } }), transport, workloads: {} });
const { world } = app;
after(() => app.close());

const [root, ada, owen, bo] = ['root', 'ada', 'owen', 'bo'].map(user) as [string, string, string, string];
const [ci, boCi] = ['token:ci', 'token:bo-ci'];

/**
 * backend: dev, which holds API_URL and STRIPE, sensitive; staging, with
 * API_URL and OLD, sensitive and archived; dev-eu, a fork that inherits
 * from dev and holds nothing of its own. billing: dev, with BILLING_KEY,
 * sensitive, and LEAK, a reference to backend/dev's STRIPE; ops, with
 * BILLING_KEY alone. Ada is a Developer of backend, Owen its Owner; Bo
 * owns billing and is a Developer of backend. ci holds Viewer on each of
 * backend's three, which Ada and Owen manage; bo-ci Viewer on billing,
 * which Bo manages. `ada-pat` is Ada's personal token.
 */
let patEnds: string;
let patId: string;
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  const [backend, billing] = [project('backend'), project('billing')];
  const [dev, staging] = [environment(backend, 'dev'), environment(backend, 'staging')];
  const devEu = environment(backend, 'dev-eu', { parentId: dev.id });
  const [billingDev, ops] = [environment(billing, 'dev'), environment(billing, 'ops')];
  const stripe = value(world, secret(dev, 'STRIPE'), 'sk_live_0123', { sensitive: true });
  const pat = credential('ada-pat', ada, { kind: 'personal', label: 'cursor-agent', scope: JSON.stringify([{ projectId: backend.id, environmentId: dev.id, role: 'viewer' }]) });
  [patEnds, patId] = [pat.expiresAt.toISOString(), pat.id];
  await write(
    world,
    ...rows('roles', ...Object.entries(ROLES).map(([id, held]) => role(false, id, [...held.permissions], [...held.protected])), ...Object.entries(INSTANCE_ROLES).map(([id, held]) => role(true, id, [...held.permissions], [...held.protected]))),
    ...rows('principals', principal(root, { role: 'owner' }), principal(ada), principal(owen), principal(bo), principal(ci), principal(boCi)),
    ...rows('projects', backend, billing),
    ...rows('environments', dev, staging, devEu, billingDev, ops),
    ...rows('secrets',
      value(world, secret(dev, 'API_URL'), 'https://api.dev.acme.example'), stripe,
      value(world, secret(staging, 'API_URL'), 'https://api.staging.acme.example'), { ...value(world, secret(staging, 'OLD'), 'sk_old', { sensitive: true }), archivedAt: new Date('2026-11-01T00:00:00Z') },
      value(world, secret(billingDev, 'BILLING_KEY'), 'bk_0123', { sensitive: true }), secret(billingDev, 'LEAK', { sourceId: stripe.id }),
      value(world, secret(ops, 'BILLING_KEY'), 'bk_4567', { sensitive: true })),
    ...rows('grants', grant(ada, 'developer', { project: backend }), grant(owen, 'owner', { project: backend }), grant(bo, 'owner', { project: billing }), grant(bo, 'developer', { project: backend }),
      grant(ci, 'viewer', { environment: dev }), grant(ci, 'viewer', { environment: staging }), grant(ci, 'viewer', { environment: devEu }), grant(boCi, 'viewer', { project: billing })),
    ...rows('policy', instance()),
    ...rows('credentials', credential('root-cli', root), credential('ada-cli', ada), credential('owen-cli', owen), credential('bo-cli', bo), pat),
  );
  await app.request('/livez');
  await app.request('/api/me', { headers: { authorization: 'Bearer nobody' } });
  app.calls.length = 0;
});

type Body = Record<string, unknown>;
/** A request's answer, and what it cost: the vault's calls and the app's statements. */
async function call(bearer: string, method: string, path: string, body?: unknown): Promise<[number, Body, string[], number]> {
  const [calls, statements] = [app.calls.length, app.statements];
  const got = await app.request(`/api${path}`, { method, headers: { authorization: `Bearer ${bearer}` }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  return [got.status, (await got.json()) as Body, app.calls.slice(calls), app.statements - statements];
}
/** A service's token, issued or previewed: its answer's scope and `withheld`. */
async function token(bearer: string, member: string, scope?: Record<string, string>, query = ''): Promise<{ scope: unknown; withheld: unknown }> {
  const [status, body] = await call(bearer, 'POST', `/members/${member}/tokens${query}`, { label: null, expiresInDays: 30, ...(scope === undefined ? {} : { scope }) });
  assert.equal(status, 200, JSON.stringify(body));
  return { scope: body.scope, withheld: body.withheld };
}

test("a Developer's token names the place whose sensitive value it will not read, previewed and issued; an Owner's names none", async () => {
  const dev = { 'backend/dev': 'viewer' };
  assert.deepEqual(await token('ada-cli', ci, dev, '?dryRun=1'), { scope: dev, withheld: ['backend/dev'] });
  assert.deepEqual(await token('ada-cli', ci, dev), { scope: dev, withheld: ['backend/dev'] });
  for (const owner of ['owen-cli', 'root-cli']) assert.deepEqual(await token(owner, ci, dev), { scope: dev, withheld: [] }, owner);
  // At what each cost before: a preview is one weigh, an issue one change, and neither a statement.
  const [, , previewed, previewStatements] = await call('ada-cli', 'POST', `/members/${ci}/tokens?dryRun=1`, { label: null, expiresInDays: 30, scope: dev });
  const [, , issued, issueStatements] = await call('ada-cli', 'POST', `/members/${ci}/tokens`, { label: null, expiresInDays: 30, scope: dev });
  assert.deepEqual([previewed, previewStatements, issued, issueStatements], [['weigh'], 0, ['change'], 0]);
});

test("a fork's inherited sensitive value counts where it is read; a place with none, or only an archived one, is not named", async () => {
  // All ci holds: dev, staging and dev-eu, which holds no value of its own.
  const all = { 'backend/dev': 'viewer', 'backend/dev-eu': 'viewer', 'backend/staging': 'viewer' };
  assert.deepEqual(await token('ada-cli', ci), { scope: all, withheld: ['backend/dev', 'backend/dev-eu'] });
  assert.deepEqual(await token('owen-cli', ci), { scope: all, withheld: [] });
});

test("a reference lends its source's sensitive value, read where the reference lives: withheld from no token an Owner of the holder's project issues", async () => {
  // Bo owns billing: its own sensitive values and LEAK, held there though backend's value, are his to give.
  assert.deepEqual(await token('bo-cli', boCi, { billing: 'viewer' }), { scope: { billing: 'viewer' }, withheld: [] });
  assert.deepEqual(await token('bo-cli', boCi, { 'billing/dev': 'viewer', 'billing/ops': 'viewer' }), { scope: { 'billing/dev': 'viewer', 'billing/ops': 'viewer' }, withheld: [] });
  assert.deepEqual(await token('root-cli', boCi), { scope: { billing: 'viewer' }, withheld: [] });
});

test('a personal token and its preview name no `withheld`: a person reads no sensitive value, whoever made the token', async () => {
  const asked = { label: 'script', expiresInMinutes: 60, scope: { 'backend/dev': 'viewer' } };
  const [, planned] = await call('ada-cli', 'POST', `/members/${ada}/tokens?dryRun=1`, asked);
  assert.deepEqual(planned, { scope: { 'backend/dev': 'viewer' } });
  const [status, made] = await call('ada-cli', 'POST', `/members/${ada}/tokens`, asked);
  assert.equal(status, 200, JSON.stringify(made));
  assert.deepEqual(Object.keys(made).sort(), ['expiresAt', 'id', 'scope', 'token']);
});

test("a binding's preview names what its runs will not read, by the same rule; a binding made answers as before", async () => {
  const asked = { profile: 'custom', issuer: KUBE, claims: { sub: 'system:serviceaccount:ci:runner' }, scope: { 'backend/dev': 'viewer', 'backend/staging': 'viewer' } };
  const [, theirs, calls, statements] = await call('ada-cli', 'POST', `/members/${ci}/bindings?dryRun=1`, asked);
  assert.deepEqual([theirs.withheld, calls, statements], [['backend/dev'], ['caller', 'weigh'], 1]);
  const [, owners] = await call('owen-cli', 'POST', `/members/${ci}/bindings?dryRun=1`, asked);
  assert.deepEqual(owners.withheld, []);
  const [status, made] = await call('ada-cli', 'POST', `/members/${ci}/bindings`, asked);
  assert.equal(status, 200, JSON.stringify(made));
  assert.deepEqual([Object.keys(made).sort(), Object.keys(made.binding as Body).sort()], [['binding', 'replaced'], ['id', 'scope']]);
});

test('`GET /me` names the personal token a request came in on, its label and scope by path, and nothing for a session; at one call and one statement', async () => {
  const [, me, calls, statements] = await call('ada-pat', 'GET', '/me');
  assert.deepEqual([me.personalToken, calls, statements], [{ id: patId, label: 'cursor-agent', expiresAt: patEnds, scope: { 'backend/dev': 'viewer' } }, ['caller'], 1]);
  const [, session] = await call('ada-cli', 'GET', '/me');
  assert.equal(session.personalToken, null);
});
