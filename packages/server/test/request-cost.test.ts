// What a request costs, exactly, and that it does not grow with the
// instance. On Workers' Free plan an invocation has 10 ms of CPU; each of
// the app's statements is a round trip through Hyperdrive, and each call to
// the vault an invocation of its own. So each route the API serves has a
// budget it meets exactly: the vault's calls, by name, and the app's
// statements (docs/design/0.16.md, "The server"). The app keeps no answer of
// the vault's between requests and writes nothing: a use or a change is one
// call and no statement, a page's read one `caller` and its own statements.
// And each runs the same statements, the same rows for a caller's own
// view, among a handful of members or hundreds, after one change to the
// policy or many. The budgets live here, not beside each route's tests.
// What the vault runs for each call is held by its own tests
// (packages/vault/test/caller.test.ts, use.test.ts, change.test.ts).
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { after, before, test } from 'node:test';

import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';

import { signin, SigninError, type SigninProvider } from '@coffre/core/identity';
import { rowsOf } from '@coffre/db/dialect';
import { credential, emptyDatabase, environment, grant, identity, instance, principal, project, role, rows, secret, user, value, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

import { propertySettings } from '../../../scripts/property-settings.ts';
// The router before its table: the table's modules import it back (mcp/tools.ts), so the table loads through it.
import '../src/api/router.ts';
import { routes } from '../src/api/routes.ts';
import { unservedRoutes } from '../src/api/routes/unserved.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { openApp, PUBLIC_URL, SESSION } from './app-fixture.ts';

const ISSUER = 'https://sso.acme.example';
/** The account Acme vouches for next: each round, one of Eve's she signs in with, and another she links. */
let account = { subject: '', email: '' };
/** A provider of the test's own, whose callback vouches for `account` whenever its state matches. */
const acme: SigninProvider = {
  id: 'acme',
  issuer: ISSUER,
  label: 'Acme SSO',
  brand: 'oidc',
  async start(redirectUri) {
    const state = randomUUID();
    return { url: new URL(`${ISSUER}/authorize?${new URLSearchParams({ state, redirect_uri: redirectUri })}`), pending: { state, codeVerifier: 'verifier', nonce: null } };
  },
  async finish(callback, _redirectUri, pending) {
    if (callback.searchParams.get('state') !== pending.state) throw new SigninError('state_mismatch', 'the state does not match');
    return { subject: account.subject, emails: [account.email], name: null };
  },
};

const KUBE = 'https://kubernetes.acme.example';
const POD = { sub: 'system:serviceaccount:ci:runner' };
/** The key the cluster publishes, the same every round, which an exchange fetches for a binding that carries none. */
const published = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const jwksOf = (pair: typeof published) => ({ keys: [{ ...pair.publicKey.export({ format: 'jwk' }), kid: 'pod', alg: 'ES256', use: 'sig' }] });
/** What a cluster publishes: its discovery document, which a binding's making asks, and its keys. */
const transport: WorkloadTransport = {
  async json(url) {
    if (url.href === `${KUBE}/.well-known/openid-configuration`) return { issuer: KUBE, jwks_uri: `${KUBE}/openid/v1/jwks` };
    if (url.href === `${KUBE}/openid/v1/jwks`) return jwksOf(published);
    throw FetchRefused.answered(url, 404);
  },
};
// Admission wide enough for every round's exchange: what is counted here is a request's cost, not its limit.
const workloads = { limits: processLimits({ perSource: 100_000, total: 100_000 }) };
// And for MCP's OAuth endpoints, which anyone may call.
const mcp = { limits: processLimits({ perSource: 100_000, perConnection: 100_000, total: 100_000 }) };
const app = await openApp({ auth: signin({ providers: [acme], workloads, mcp }), transport, workloads: {} });
const { world } = app;

const [ada, bo, cy, dee, eve] = [user('ada'), user('bo'), user('cy'), user('dee'), user('eve')];
const ci = 'token:ci';
/** What a CI job reveals: seven keys of the environment it reads. */
const SEVEN = ['CLOUDFLARE_API_TOKEN', 'SCALEWAY_SECRET_KEY', 'R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY', 'SOURCE_REGISTRY_KEY', 'GITHUB_RELEASE_APP_CLIENT_ID', 'GITHUB_RELEASE_APP_PRIVATE_KEY'];
const PENDING = '__Host-coffre_signin';

/**
 * market: dev (API_KEY, DATABASE_URL and the seven keys), dev-fork, which
 * inherits from dev, prod (protected), busy (KEY, and MIRROR, a reference
 * to dev's API_KEY), and Ada's personal config of dev.
 *
 * Cy owns the instance, and has a browser session and a personal token
 * scoped to market/dev. Ada views market/dev
 * alone, so that nothing grown elsewhere is hers to read; ci, a service
 * account, views market. Bo leads market: he reads, writes, manages
 * its environments, the project and its access. Dee holds nothing. Eve
 * signs in with Acme: each round binds an account of hers by her email,
 * links a second on that session, and unlinks both. busy's KEY has more
 * versions than a page of its history, and each round writes more.
 */
before(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  const market = project('market');
  const dev = environment(market, 'dev');
  const fork = environment(market, 'dev-fork', { parentId: dev.id });
  const busy = environment(market, 'busy');
  const adas = environment(market, 'dev-ada', { parentId: dev.id, owner: ada });
  const apiKey = value(world, secret(dev, 'API_KEY'), 'fake-api-key');
  const cys = identity(cy);
  await write(
    world,
    ...rows('projects', market),
    ...rows('environments', dev, fork, environment(market, 'prod', { protected: true }), busy, adas),
    ...rows('secrets',
      apiKey, value(world, secret(dev, 'DATABASE_URL'), 'postgres://fake'), ...SEVEN.map((key) => value(world, secret(dev, key), `fake-${key.toLowerCase()}`)),
      value(world, secret(fork, 'OWN'), 'fake-own'), value(world, secret(busy, 'KEY'), 'fake-0'), secret(busy, 'MIRROR', { sourceId: apiKey.id }), value(world, secret(adas, 'LOCAL'), 'fake-local')),
    ...rows('roles',
      role(false, 'viewer', ['secret.read', 'secret.use'], []),
      role(false, 'developer', ['secret.read', 'secret.use', 'secret.write'], []),
      role(false, 'lead', ['secret.read', 'secret.use', 'secret.write', 'environment.manage', 'project.manage', 'grant.manage']),
      role(true, 'owner', ['secret.read', 'secret.use', 'secret.write', 'environment.manage', 'project.manage', 'grant.manage', 'audit.read']),
      role(true, 'auditor', ['audit.read'], []),
      role(true, 'member', [])),
    ...rows('principals', principal(ada), principal(bo), principal(cy, { role: 'owner' }), principal(dee), principal(eve), principal(ci)),
    ...rows('policy', instance()),
    ...rows('grants', grant(ada, 'viewer', { environment: dev }), grant(ci, 'viewer', { project: market }), grant(bo, 'lead', { project: market })),
    ...rows('identities', cys),
    ...rows('credentials',
      ...[ada, bo, cy, dee, eve].map((who) => credential(`${who.slice(5, who.indexOf('@'))}-cli`, who)), credential('ci-token', ci, { scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'viewer' }]) }),
      credential('cy-web', cy, { kind: 'browser', identityId: cys.id }),
      credential('cy-dev', cy, { kind: 'personal', scope: JSON.stringify([{ projectId: market.id, environmentId: dev.id, role: 'viewer' }]) })),
  );
  for (let i = 0; i < 21; i++) await api('bo-cli', 'PATCH', '/secrets/market/busy', { KEY: `fake-history-${i}` });
  // A round first, unmeasured: the database's migrations, which the app asks once, are no request's cost.
  await costs();
});
after(async () => {
  await emptyDatabase(world.owner);
  await app.close();
});

const api = (label: string, method: string, path: string, body?: unknown) =>
  app.request(`/api${path}`, { method, headers: { authorization: `Bearer ${label}` }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
const reveal = (label: string, path: string, keys?: string[]) => api(label, 'POST', '/reveals', keys === undefined ? { path } : { path, keys });
/** Cy's browser, on one of coffre's own pages. */
const asCy = { cookie: `${SESSION}=cy-web`, 'sec-fetch-site': 'same-origin' };

/** What one round of the table made, for the entries after it to end: each round ends all it made but places and versions. */
let round = 0;
let device = { device_code: '', user_code: '' };
let collected = '';
let leaving = { state: '', pending: '' };
let browser = '';
let personal = '';
let serviceToken = '';
let handle = '';
let bound = '';
/** The round's MCP client, as it registered, its PKCE verifier, and what it holds. */
let oauth = { client: '', verifier: '', code: '', access: '', refresh: '', connection: '' };
const MCP_REDIRECT = 'http://127.0.0.1/callback';
const consent = () => {
  const challenge = createHash('sha256').update(oauth.verifier).digest('base64url');
  return { client_id: oauth.client, redirect_uri: MCP_REDIRECT, response_type: 'code', code_challenge: challenge, code_challenge_method: 'S256', state: 's', scope: 'read reveal' };
};
/** A 2026-07-28 request to `/mcp` on the round's access token. */
const mcpCall = (method: string, params: Record<string, unknown> = {}) =>
  app.request('/mcp', {
    method: 'POST',
    headers: { authorization: `Bearer ${oauth.access}`, 'content-type': 'application/json', 'mcp-protocol-version': '2026-07-28', 'mcp-method': method, ...(typeof params.name === 'string' ? { 'mcp-name': params.name } : {}) },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: { ...params, _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {} } } }),
  });
const oauthForm = (path: string, fields: Record<string, string>) =>
  app.request(path, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(fields).toString() });
/** The key a binding's re-keying carries, a new one each round. */
let cluster = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
/** A pod's ID token from the cluster, for ci, signed by `key`. */
function podToken(key = cluster): string {
  const now = Math.floor(Date.now() / 1000);
  const input = `${b64({ alg: 'ES256', kid: 'pod', typ: 'JWT' })}.${b64({ iss: KUBE, ...POD, aud: PUBLIC_URL, iat: now - 10, exp: now + 290, jti: randomUUID() })}`;
  return `${input}.${sign('sha256', Buffer.from(input), { key: key.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
}

/** A route's budget: the vault's calls, by name, and the app's statements, a transaction one. */
type Budget = { calls: string[]; statements: number };
type Entry = Budget & {
  request: () => Promise<Response>;
  /** Its rows are the caller's own view, which no growth elsewhere changes: the same however the instance grows. */
  fixed?: true;
};
const take = async <T>(response: Promise<Response>, keep: (body: T, answered: Response) => void) => {
  const answered = await response;
  keep((await answered.clone().json()) as T, answered);
  return answered;
};
const cookieOf = (response: Response, name: string) => response.headers.getSetCookie().find((line) => line.startsWith(`${name}=`))!.slice(name.length + 1).split(';')[0]!;
const unlink = async (subject: string) => {
  const [bound] = await rowsOf<{ id: string }>(world.owner, sql`SELECT id FROM identities WHERE subject = ${subject}`);
  return api('eve-cli', 'DELETE', `/identities/${bound!.id}`);
};
const release = { name: 'Release', description: 'Ships.', permissions: ['secret.use', 'secret.write'], protected: ['secret.use'] };

/**
 * Every route coffre serves, its health and sign-in with the API's, in an
 * order that runs as a cycle: what an entry makes, one after it ends, so
 * that a round leaves the instance as it found it, but for the places it
 * made and the versions it wrote.
 *
 * Not served yet, and priced here once they are: a workload's session
 * approved, a binding's enrollments, a workload's own exchange
 * (`POST /api/auth/workload`), and the credential proxy.
 */
const requests: Record<string, Entry> = {
  // A caller's own view: one `caller`, then the page's statements, scoped by its answer.
  'GET /me': { request: () => api('ada-cli', 'GET', '/me'), calls: ['caller'], statements: 1, fixed: true },
  // Whoever runs the instance reads every project, in the same statements.
  'GET /me, by whoever runs the instance': { request: () => api('cy-cli', 'GET', '/me'), calls: ['caller'], statements: 1 },
  'GET /projects': { request: () => api('ada-cli', 'GET', '/projects'), calls: ['caller'], statements: 2, fixed: true },
  'GET /projects, by whoever runs the instance': { request: () => api('cy-cli', 'GET', '/projects'), calls: ['caller'], statements: 2 },
  // Whoever runs it, on a token scoped to one environment: what the scope reaches, in the same statements.
  'GET /projects, on a scoped token': { request: () => api('cy-dev', 'GET', '/projects'), calls: ['caller'], statements: 2, fixed: true },
  // A caller who reaches no project: no count of their keys to read.
  'GET /projects, reaching nothing': { request: () => api('dee-cli', 'GET', '/projects'), calls: ['caller'], statements: 1, fixed: true },
  'GET /personal/:project': { request: () => api('bo-cli', 'GET', '/personal/market'), calls: ['caller'], statements: 1, fixed: true },
  'GET /secrets/:project/:environment': { request: () => api('ada-cli', 'GET', '/secrets/market/dev'), calls: ['caller'], statements: 1, fixed: true },
  'GET /secrets/:project/:environment, a fork': { request: () => api('bo-cli', 'GET', '/secrets/market/dev-fork'), calls: ['caller'], statements: 1, fixed: true },
  // A page of a key's history, 20 versions of the more it has, which each round grows; and one shorter than a page.
  'GET /secrets/:project/:environment/:key/versions': { request: () => api('bo-cli', 'GET', '/secrets/market/busy/KEY/versions'), calls: ['caller'], statements: 1, fixed: true },
  'GET /secrets/:project/:environment/:key/versions, a short history': { request: () => api('ada-cli', 'GET', '/secrets/market/dev/API_KEY/versions'), calls: ['caller'], statements: 1, fixed: true },
  'GET /projects/:project/:environment/missing': { request: () => api('ada-cli', 'GET', '/projects/market/dev/missing'), calls: ['caller'], statements: 1 },
  'GET /references': { request: () => api('ada-cli', 'GET', `/references?path=${encodeURIComponent('market/dev/API_KEY')}`), calls: ['caller'], statements: 1 },
  // Its readers, for whoever manages either end's access: one more statement for them all.
  'GET /references, by a manager': { request: () => api('bo-cli', 'GET', `/references?path=${encodeURIComponent('market/dev/API_KEY')}`), calls: ['caller'], statements: 2 },
  'GET /members': { request: () => api('cy-cli', 'GET', '/members'), calls: ['caller'], statements: 1 },
  'GET /members, by a project manager': { request: () => api('bo-cli', 'GET', '/members'), calls: ['caller'], statements: 1 },
  'GET /members?path=': { request: () => api('bo-cli', 'GET', '/members?path=market'), calls: ['caller'], statements: 2 },
  'GET /members/:member/access': { request: () => api('cy-cli', 'GET', `/members/${ada}/access`), calls: ['caller'], statements: 1, fixed: true },
  // A member's report, in one statement: what lets them in, what they know, the tokens they issued and their own.
  'GET /members/:member': { request: () => api('cy-cli', 'GET', `/members/${ada}`), calls: ['caller'], statements: 1, fixed: true },
  // Cy's, whose personal tokens and ci's tokens of his grow with the instance below: still one statement and one row.
  'GET /members/:member, of who issued tokens': { request: () => api('cy-cli', 'GET', `/members/${cy}`), calls: ['caller'], statements: 1, fixed: true },
  'GET /members/:member, a service account': { request: () => api('cy-cli', 'GET', `/members/${ci}`), calls: ['caller'], statements: 1, fixed: true },
  'GET /roles': { request: () => api('cy-cli', 'GET', '/roles'), calls: ['caller'], statements: 1 },
  // The roles, the members the role reaches, and the places they reach it in (`WEIGHED_MOST`).
  'PUT /roles/:role?dryRun=1': { request: () => api('cy-cli', 'PUT', '/roles/viewer?dryRun=1', { name: 'Viewer', description: '', permissions: [], protected: [] }), calls: ['caller'], statements: 3 },
  // A write weighed and not made: one `weigh`, then one `use` to compare every value it would replace, and none when
  // it replaces none.
  'PATCH /secrets/:project/:environment?dryRun=1': { request: () => api('bo-cli', 'PATCH', '/secrets/market/dev?dryRun=1', { API_KEY: 'fake-guess', DATABASE_URL: 'postgres://fake', NEW: 'fake-new' }), calls: ['weigh', 'use'], statements: 0 },
  'PATCH /secrets/:project/:environment?dryRun=1, new keys only': { request: () => api('bo-cli', 'PATCH', '/secrets/market/busy?dryRun=1', { NEW: 'fake-new' }), calls: ['weigh'], statements: 0 },
  'GET /settings': { request: () => api('cy-cli', 'GET', '/settings'), calls: ['caller'], statements: 1, fixed: true },

  // Values: one call to the vault and no statement, the token hashed, never looked up.
  'POST /reveals, one key': { request: () => reveal('ada-cli', 'market/dev/API_KEY'), calls: ['use'], statements: 0 },
  'POST /reveals, an environment': { request: () => reveal('ada-cli', 'market/dev'), calls: ['use'], statements: 0 },
  'POST /reveals, an export as a service': { request: () => reveal('ci-token', 'market/dev'), calls: ['use'], statements: 0 },
  "POST /reveals, a CI run's seven keys": { request: () => reveal('ci-token', 'market/dev', SEVEN), calls: ['use'], statements: 0 },
  'GET /projects/:project/:environment/version': { request: () => api('ada-cli', 'GET', '/projects/market/dev/version'), calls: ['peek'], statements: 0 },

  // Health: liveness asks nothing; readiness, whether the database has this release's migrations, two statements.
  'GET /livez': { request: () => app.request('/livez'), calls: [], statements: 0 },
  'GET /readyz': { request: () => app.request('/readyz'), calls: [], statements: 2, fixed: true },

  // Signing in: the sign-in page asks nothing; a device login's start reads its cap, one statement of one row however many wait.
  'GET /api/auth': { request: () => app.request('/api/auth'), calls: [], statements: 0 },
  'POST /api/auth/device': { request: () => take<typeof device>(app.request('/api/auth/device', { method: 'POST', body: '{}' }), (body) => (device = body)), calls: ['change'], statements: 1, fixed: true },
  'GET /device-logins/:code': { request: () => app.request(`/api/device-logins/${device.user_code}`, { headers: asCy }), calls: ['caller'], statements: 1, fixed: true },
  'POST /device-logins/:code': { request: () => app.request(`/api/device-logins/${device.user_code}`, { method: 'POST', headers: asCy, body: JSON.stringify({ approve: true }) }), calls: ['change'], statements: 0 },
  'POST /api/auth/device/token': {
    request: () => take<{ access_token: string }>(app.request('/api/auth/device/token', { method: 'POST', body: JSON.stringify({ device_code: device.device_code }) }), (body) => (collected = body.access_token)),
    calls: ['change'], statements: 0,
  },
  'POST /api/auth/logout': { request: () => app.request('/api/auth/logout', { method: 'POST', headers: { authorization: `Bearer ${collected}` } }), calls: ['change'], statements: 0 },
  'GET /auth/signin/:provider': {
    request: async () => {
      account = { subject: `acme-eve-${round}`, email: 'eve@acme.example' };
      const left = await app.request('/auth/signin/acme');
      leaving = { state: new URL(left.headers.get('location')!).searchParams.get('state')!, pending: cookieOf(left, PENDING) };
      return left;
    },
    calls: [], statements: 0,
  },
  'GET /auth/callback/:provider': {
    request: async () => {
      const back = await app.request(`/auth/callback/acme?${new URLSearchParams({ state: leaving.state, code: 'c' })}`, { headers: { cookie: `${PENDING}=${leaving.pending}` } });
      browser = cookieOf(back, SESSION);
      return back;
    },
    calls: ['change'], statements: 0,
  },
  // A second account linked on the session that asked: leaving for the provider asks nothing, and coming back is one change.
  'GET /auth/signin/:provider?link=1': {
    request: async () => {
      account = { subject: `acme-eve-work-${round}`, email: 'eve@work.example' };
      const left = await app.request('/auth/signin/acme?link=1', { headers: { cookie: `${SESSION}=${browser}` } });
      leaving = { state: new URL(left.headers.get('location')!).searchParams.get('state')!, pending: cookieOf(left, PENDING) };
      return left;
    },
    calls: [], statements: 0,
  },
  'GET /auth/callback/:provider, linking': {
    request: () => app.request(`/auth/callback/acme?${new URLSearchParams({ state: leaving.state, code: 'c' })}`, { headers: { cookie: `${PENDING}=${leaving.pending}; ${SESSION}=${browser}` } }),
    calls: ['change'], statements: 0,
  },
  // The browser's person lists their own sessions and accounts: `caller` and one statement each, the rows theirs alone.
  'GET /sessions': { request: () => app.request('/api/sessions', { headers: { cookie: `${SESSION}=${browser}` } }), calls: ['caller'], statements: 1, fixed: true },
  'GET /identities': { request: () => app.request('/api/identities', { headers: { cookie: `${SESSION}=${browser}` } }), calls: ['caller'], statements: 1, fixed: true },
  'POST /auth/signout': { request: () => app.request('/auth/signout', { method: 'POST', headers: { cookie: `${SESSION}=${browser}`, 'sec-fetch-site': 'same-origin' } }), calls: ['change'], statements: 0 },
  // The accounts the round's sign-in bound and linked, found as the test's owner, which no request's count sees.
  'DELETE /identities/:id': { request: () => unlink(`acme-eve-${round}`), calls: ['change'], statements: 0 },
  'DELETE /identities/:id, the linked one': { request: () => unlink(`acme-eve-work-${round}`), calls: ['change'], statements: 0 },

  // MCP's OAuth: the metadata asks nothing; the endpoints a client calls are one change each, and no statement. The consent
  // page reads its request with `caller` and one statement, a registration's row and the person's connections of it; its
  // Approve asks `caller`, reads the registration again, then makes the connection. Connected apps lists in one statement.
  'GET /.well-known/oauth-authorization-server': { request: () => app.request('/.well-known/oauth-authorization-server'), calls: [], statements: 0 },
  'POST /api/oauth/register': {
    request: () => take<{ client_id: string }>(app.request('/api/oauth/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ client_name: `Zed ${round}`, redirect_uris: [MCP_REDIRECT] }) }), (body) => {
      oauth = { client: body.client_id, verifier: randomBytes(32).toString('base64url'), code: '', access: '', refresh: '', connection: '' };
    }),
    calls: ['change'], statements: 0,
  },
  'GET /oauth/authorizations': { request: () => app.request(`/api/oauth/authorizations?${new URLSearchParams(consent())}`, { headers: asCy }), calls: ['caller'], statements: 1, fixed: true },
  'POST /oauth/authorizations': {
    request: () => take<{ redirect: string }>(app.request('/api/oauth/authorizations', { method: 'POST', headers: asCy, body: JSON.stringify({ request: consent(), approve: true, scopes: ['read', 'reveal'] }) }), (body) => (oauth.code = new URL(body.redirect).searchParams.get('code')!)),
    calls: ['caller', 'change'], statements: 1,
  },
  'POST /api/oauth/token': {
    request: () => take<{ access_token: string; refresh_token: string }>(oauthForm('/api/oauth/token', { grant_type: 'authorization_code', code: oauth.code, code_verifier: oauth.verifier, redirect_uri: MCP_REDIRECT, client_id: oauth.client }), (body) => {
      oauth.access = body.access_token;
      oauth.refresh = body.refresh_token;
    }),
    calls: ['change'], statements: 0,
  },
  'POST /api/oauth/token, a refresh': {
    request: () => take<{ access_token: string; refresh_token: string }>(oauthForm('/api/oauth/token', { grant_type: 'refresh_token', refresh_token: oauth.refresh, client_id: oauth.client }), (body) => {
      oauth.access = body.access_token;
      oauth.refresh = body.refresh_token;
    }),
    calls: ['change'], statements: 0,
  },
  // `/mcp` on the access token: one `caller`, which answers who it is and its scopes; a read tool then costs what its
  // route does, on that answer; a reveal is the route's `use`.
  'POST /mcp, tools/list': { request: () => mcpCall('tools/list'), calls: ['caller'], statements: 0 },
  'POST /mcp, a read tool': { request: () => mcpCall('tools/call', { name: 'list_secrets', arguments: { environment: 'market/dev' } }), calls: ['caller'], statements: 1, fixed: true },
  'POST /mcp, reveal_secret_values': { request: () => mcpCall('tools/call', { name: 'reveal_secret_values', arguments: { path: 'market/dev/API_KEY' } }), calls: ['caller', 'use'], statements: 0 },
  'GET /apps': { request: () => take<{ apps: { id: string }[] }>(app.request('/api/apps', { headers: asCy }), (body) => (oauth.connection = body.apps[0]!.id)), calls: ['caller'], statements: 1, fixed: true },
  'POST /api/oauth/revoke': { request: () => oauthForm('/api/oauth/revoke', { token: oauth.access, client_id: oauth.client }), calls: ['change'], statements: 0 },
  // The round's connection ended by its client just now: its person's Disconnect needs another, made as above.
  'POST /oauth/authorizations, again': {
    request: () => take<{ redirect: string }>(app.request('/api/oauth/authorizations', { method: 'POST', headers: asCy, body: JSON.stringify({ request: consent(), approve: true, scopes: ['read', 'reveal'] }) }), (body) => (oauth.code = new URL(body.redirect).searchParams.get('code')!)),
    calls: ['caller', 'change'], statements: 1,
  },
  'POST /api/oauth/token, again': {
    request: () => oauthForm('/api/oauth/token', { grant_type: 'authorization_code', code: oauth.code, code_verifier: oauth.verifier, redirect_uri: MCP_REDIRECT, client_id: oauth.client }),
    calls: ['change'], statements: 0,
  },
  'GET /apps, again': { request: () => take<{ apps: { id: string }[] }>(app.request('/api/apps', { headers: asCy }), (body) => (oauth.connection = body.apps[0]!.id)), calls: ['caller'], statements: 1, fixed: true },
  'DELETE /apps/:id': { request: () => app.request(`/api/apps/${oauth.connection}`, { method: 'DELETE', headers: asCy }), calls: ['change'], statements: 0 },
  // The audit page: the caller with the log's head, then the stretch and its tiles; by a path, its place first.
  'GET /audit': { request: () => api('cy-cli', 'GET', '/audit'), calls: ['caller'], statements: 2 },
  'GET /audit?path=': { request: () => api('cy-cli', 'GET', '/audit?path=market/dev'), calls: ['caller'], statements: 3 },

  // Every change: one call to the vault, `change`, and no statement.
  'PATCH /secrets/:project/:environment': { request: () => api('bo-cli', 'PATCH', '/secrets/market/busy', { KEY: `fake-${round}` }), calls: ['change'], statements: 0 },
  'PATCH /secrets/:project/:environment@me': { request: () => api('ada-cli', 'PATCH', '/secrets/market/dev@me', { LOCAL: `fake-${round}` }), calls: ['change'], statements: 0 },
  // A fork's own value over the one it inherits, then inherited again.
  "PATCH /secrets/:project/:environment, a fork's own": { request: () => api('bo-cli', 'PATCH', '/secrets/market/dev-fork', { API_KEY: `fake-${round}` }), calls: ['change'], statements: 0 },
  'PATCH /secrets/:project/:environment/:key, inherited': { request: () => api('bo-cli', 'PATCH', '/secrets/market/dev-fork/API_KEY', { inherit: true }), calls: ['change'], statements: 0 },
  'POST /secrets/:project/:environment/:key/restore': { request: () => api('bo-cli', 'POST', '/secrets/market/busy/KEY/restore', { version: 1 }), calls: ['change'], statements: 0 },
  'PATCH /secrets/:project/:environment/:key': { request: () => api('bo-cli', 'PATCH', '/secrets/market/busy/KEY', { folder: 'kept' }), calls: ['change'], statements: 0 },
  'PATCH /folders/:project/:environment/:folder': { request: () => api('bo-cli', 'PATCH', '/folders/market/busy/kept', { name: 'filed' }), calls: ['change'], statements: 0 },
  'DELETE /folders/:project/:environment/:folder': { request: () => api('bo-cli', 'DELETE', '/folders/market/busy/filed'), calls: ['change'], statements: 0 },
  'PATCH /secrets/:project/:environment/:key, renamed': { request: () => api('bo-cli', 'PATCH', '/secrets/market/busy/KEY', { key: 'RENAMED' }), calls: ['change'], statements: 0 },
  'PATCH /secrets/:project/:environment/:key, renamed back': { request: () => api('bo-cli', 'PATCH', '/secrets/market/busy/RENAMED', { key: 'KEY' }), calls: ['change'], statements: 0 },
  'PATCH /secrets/:project/:environment, a reference': { request: () => api('bo-cli', 'PATCH', '/secrets/market/busy', { LINK: { ref: 'market/dev/DATABASE_URL' } }), calls: ['change'], statements: 0 },
  'DELETE /secrets/:project/:environment/:key/reference': { request: () => api('bo-cli', 'DELETE', '/secrets/market/busy/LINK/reference'), calls: ['change'], statements: 0 },
  // A project of each round's own, since one that is there is refused: no caller above reaches it.
  'PUT /projects/:project': { request: () => api('cy-cli', 'PUT', `/projects/shop-${round}`, {}), calls: ['change'], statements: 0 },
  'PUT /projects/:project/:environment': { request: () => api('cy-cli', 'PUT', `/projects/shop-${round}/qa`, {}), calls: ['change'], statements: 0 },
  'PUT /projects/:project/:environment, a fork': { request: () => api('cy-cli', 'PUT', `/projects/shop-${round}/qa-fork`, { from: 'qa', inherit: true }), calls: ['change'], statements: 0 },
  'PATCH /projects/:project/:environment': { request: () => api('cy-cli', 'PATCH', `/projects/shop-${round}/qa`, { protected: true }), calls: ['change'], statements: 0 },
  'PATCH /projects/:project': { request: () => api('cy-cli', 'PATCH', `/projects/shop-${round}`, { folder: 'Payments' }), calls: ['change'], statements: 0 },
  'PATCH /folders/:folder': { request: () => api('cy-cli', 'PATCH', '/folders/Payments', { name: 'Shops' }), calls: ['change'], statements: 0 },
  'DELETE /folders/:folder': { request: () => api('cy-cli', 'DELETE', '/folders/Shops'), calls: ['change'], statements: 0 },
  // The round's places deleted for good, once archived: a preview is one `weigh`, a deletion one change, however much each erases.
  'PATCH /projects/:project/:environment, archived': { request: () => api('cy-cli', 'PATCH', `/projects/shop-${round}/qa-fork`, { archived: true }), calls: ['change'], statements: 0 },
  'DELETE /projects/:project/:environment?dryRun=1': { request: () => api('cy-cli', 'DELETE', `/projects/shop-${round}/qa-fork?dryRun=1`), calls: ['weigh'], statements: 0 },
  'DELETE /projects/:project/:environment': { request: () => api('cy-cli', 'DELETE', `/projects/shop-${round}/qa-fork`), calls: ['change'], statements: 0 },
  'PATCH /projects/:project, archived': { request: () => api('cy-cli', 'PATCH', `/projects/shop-${round}`, { archived: true }), calls: ['change'], statements: 0 },
  'DELETE /projects/:project?dryRun=1': { request: () => api('cy-cli', 'DELETE', `/projects/shop-${round}?dryRun=1`), calls: ['weigh'], statements: 0 },
  'DELETE /projects/:project': { request: () => api('cy-cli', 'DELETE', `/projects/shop-${round}`), calls: ['change'], statements: 0 },
  'PUT /members/:member': { request: () => api('cy-cli', 'PUT', '/members/user:temp@acme.example', {}), calls: ['change'], statements: 0 },
  'PUT /members/:member, a role and a scope': { request: () => api('cy-cli', 'PUT', '/members/user:temp@acme.example', { role: 'auditor', scope: { projects: { only: ['market'] } } }), calls: ['change'], statements: 0 },
  // No role keeps theirs, and its scope, which names projects by id, is worded by slug: one statement, after the change.
  'PUT /members/:member, its scope kept': { request: () => api('cy-cli', 'PUT', '/members/user:temp@acme.example', {}), calls: ['change'], statements: 1, fixed: true },
  'PATCH /access/:member': { request: () => api('bo-cli', 'PATCH', '/access/user:temp@acme.example', { 'market/busy': 'viewer' }), calls: ['change'], statements: 0 },
  'DELETE /members/:member': { request: () => api('cy-cli', 'DELETE', '/members/user:temp@acme.example'), calls: ['change'], statements: 0 },
  'PUT /members/:member, a service account with its grants': { request: () => api('cy-cli', 'PUT', '/members/token:deploy', { access: { 'market/busy': 'viewer' } }), calls: ['change'], statements: 0 },
  'DELETE /members/:member, a service account': { request: () => api('cy-cli', 'DELETE', '/members/token:deploy'), calls: ['change'], statements: 0 },
  // A member's tokens, handles and sessions: a list is `caller` and one statement; each made or ended, one change.
  'GET /members/:member/tokens': { request: () => api('bo-cli', 'GET', `/members/${ci}/tokens`), calls: ['caller'], statements: 1 },
  'GET /members/:member/tokens, by the service itself': { request: () => api('ci-token', 'GET', `/members/${ci}/tokens`), calls: ['caller'], statements: 1 },
  "GET /members/:member/tokens, a person's own": { request: () => api('bo-cli', 'GET', `/members/${bo}/tokens`), calls: ['caller'], statements: 1 },
  'POST /members/:member/tokens': {
    request: () => take<{ id: string }>(api('bo-cli', 'POST', `/members/${bo}/tokens`, { label: 'script', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } }), (body) => (personal = body.id)),
    calls: ['change'], statements: 0,
  },
  "POST /members/:member/tokens, a service's": {
    request: () => take<{ id: string }>(api('bo-cli', 'POST', `/members/${ci}/tokens`, { label: null, expiresInDays: 1 }), (body) => (serviceToken = body.id)),
    calls: ['change'], statements: 0,
  },
  'DELETE /members/:member/tokens/:id': { request: () => api('bo-cli', 'DELETE', `/members/${ci}/tokens/${serviceToken}`), calls: ['change'], statements: 0 },
  'DELETE /sessions/:id': { request: () => api('bo-cli', 'DELETE', `/sessions/${personal}`), calls: ['change'], statements: 0 },
  'POST /handles': { request: () => take<{ id: string }>(api('ada-cli', 'POST', '/handles', { label: 'run', paths: ['market/dev'] }), (body) => (handle = body.id)), calls: ['change'], statements: 0 },
  'DELETE /handles/:id': { request: () => api('ada-cli', 'DELETE', `/handles/${handle}`), calls: ['change'], statements: 0 },
  // A service account's trust bindings. Making one is weighed as the change first, `caller` and one statement, before its
  // issuer is asked where its keys are. A CI run's exchange is one statement, which bindings to verify under, and one
  // change: under the keys its issuer publishes, fetched, then under those the binding's re-keying carries.
  'POST /members/:member/bindings': {
    request: () => take<{ binding: { id: string } }>(api('bo-cli', 'POST', `/members/${ci}/bindings`, { profile: 'custom', issuer: KUBE, claims: POD, scope: { 'market/dev': 'viewer' } }), (body) => (bound = body.binding.id)),
    calls: ['caller', 'change'], statements: 1,
  },
  'GET /members/:member/bindings': { request: () => api('bo-cli', 'GET', `/members/${ci}/bindings`), calls: ['caller'], statements: 1 },
  'GET /members/:member/bindings, by the service itself': { request: () => api('ci-token', 'GET', `/members/${ci}/bindings`), calls: ['caller'], statements: 1 },
  'POST /api/auth/oidc, its keys fetched': {
    request: () => app.request('/api/auth/oidc', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ service: ci, token: podToken(published) }) }),
    calls: ['change'], statements: 1, fixed: true,
  },
  'POST /members/:member/bindings/keys': {
    request: () => {
      cluster = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const jwks = jwksOf(cluster);
      return take<{ bindings: { id: string }[] }>(api('bo-cli', 'POST', `/members/${ci}/bindings/keys`, { issuer: KUBE, jwks }), (body) => (bound = body.bindings[0]!.id));
    },
    calls: ['change'], statements: 0,
  },
  'POST /api/auth/oidc': {
    request: () => app.request('/api/auth/oidc', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ service: ci, token: podToken() }) }),
    calls: ['change'], statements: 1, fixed: true,
  },
  'DELETE /members/:member/bindings/:id': { request: () => api('bo-cli', 'DELETE', `/members/${ci}/bindings/${bound}`), calls: ['change'], statements: 0 },
  'PUT /roles/:role': { request: () => api('cy-cli', 'PUT', '/roles/release', release), calls: ['change'], statements: 0 },
  'DELETE /roles/:role': { request: () => api('cy-cli', 'DELETE', '/roles/release'), calls: ['change'], statements: 0 },
  'PUT /instance-roles/:role': { request: () => api('cy-cli', 'PUT', '/instance-roles/auditor', { name: 'Auditor', description: `Round ${round}.`, permissions: ['audit.read'], protected: [] }), calls: ['change'], statements: 0 },
  'DELETE /instance-roles/:role': { request: () => api('cy-cli', 'DELETE', '/instance-roles/auditor'), calls: ['change'], statements: 0 },
  'PUT /settings': { request: () => api('cy-cli', 'PUT', '/settings', { serviceAccounts: {} }), calls: ['change'], statements: 0 },
  'POST /freezes': { request: () => api('cy-cli', 'POST', '/freezes', { target: 'service:ci', reason: 'the key leaked in a build log' }), calls: ['change'], statements: 0 },
  // The freezes standing, ci's among them: whoever runs the instance sees each unweighed; a manager of ci, and someone
  // who manages nothing, read the services' grants by which each is weighed, in the same statement.
  'GET /freezes': { request: () => api('cy-cli', 'GET', '/freezes'), calls: ['caller'], statements: 1, fixed: true },
  'GET /freezes, by a manager of the service': { request: () => api('bo-cli', 'GET', '/freezes'), calls: ['caller'], statements: 1, fixed: true },
  'GET /freezes, by someone who manages nothing': { request: () => api('dee-cli', 'GET', '/freezes'), calls: ['caller'], statements: 1, fixed: true },
  'DELETE /freezes/:target': { request: () => api('cy-cli', 'DELETE', `/freezes/${encodeURIComponent(ci)}`), calls: ['change'], statements: 0 },
};

/** What a request ran: the vault's calls, the app's statements as `Budget` counts them, and every statement its connection sent with the rows they answered. */
type Cost = Budget & { sent: number; rows: number };

async function cost(name: string, request: () => Promise<Response>): Promise<Cost> {
  const [calls, statements, sent] = [app.calls.length, app.statements, { ...app.sent }];
  const answered = await request();
  if (answered.status >= 400) assert.fail(`${name} answered ${answered.status}: ${await answered.text()}`);
  return { calls: app.calls.slice(calls), statements: app.statements - statements, sent: app.sent.statements - sent.statements, rows: app.sent.rows - sent.rows };
}

/** One round of the table, each request's cost by name. */
async function costs(): Promise<Record<string, Cost>> {
  round += 1;
  const spent: Record<string, Cost> = {};
  for (const [name, { request }] of Object.entries(requests)) spent[name] = await cost(name, request);
  return spent;
}

/** What may not grow: every request's calls and statements, and the rows of a caller's own view. */
const held = (spent: Record<string, Cost>) =>
  Object.fromEntries(Object.entries(spent).map(([name, { calls, statements, sent, rows }]) => [name, { calls, statements, sent, ...(requests[name]!.fixed ? { rows } : {}) }]));

test('each route runs exactly its budget: the vault calls it makes, by name, and the app statements', async () => {
  const spent = await costs();
  for (const [name, budget] of Object.entries(requests)) assert.deepEqual({ calls: spent[name]!.calls, statements: spent[name]!.statements }, { calls: budget.calls, statements: budget.statements }, name);
});

test("every route the API serves has a budget above: an entry named by the route's key, before any `?` or `,`", () => {
  const priced = new Set(Object.keys(requests).map((name) => name.split(/[?,]/)[0]));
  // A route not served yet is unserved.ts's own, until an area lists its own under the same key.
  const served = Object.entries(routes).filter(([key, def]) => def !== unservedRoutes[key as keyof typeof unservedRoutes]).map(([key]) => key);
  assert.deepEqual(served.filter((key) => !priced.has(key)), []);
});

/** Cy, who may make every change growth asks. */
const asOwner = async (method: string, path: string, body?: unknown) => {
  const answered = await api('cy-cli', method, path, body);
  if (answered.status >= 400) assert.fail(`${method} ${path} answered ${answered.status}: ${await answered.text()}`);
};

test('a request runs the same statements, and a caller reads the same rows of their own, however large the log, the members and the policy grow', async () => {
  const small = held(await costs());
  // The log grown by writes elsewhere.
  for (let i = 0; i < 60; i++) await asOwner('PATCH', '/secrets/market/busy', { [`KEY_${i % 20}`]: `fake-${i}` });
  // Other projects, each with environments and keys, which none of the callers above reaches but Cy; and in each a
  // reference to the key Ada reads, which Bo, who manages its access, is shown with its readers.
  for (let i = 0; i < 10; i++) {
    await asOwner('PUT', `/projects/elsewhere-${i}`, {});
    for (const environment of ['dev', 'prod']) await asOwner('PUT', `/projects/elsewhere-${i}/${environment}`, {});
    await asOwner('PATCH', `/secrets/elsewhere-${i}/dev`, { A: 'fake-a', B: 'fake-b', REF: { ref: 'market/dev/API_KEY' } });
  }
  // Members, each with a grant, and Ada's own access changed back and forth.
  for (let i = 0; i < 30; i++) {
    await asOwner('PUT', `/members/user:member-${i}@acme.example`, {});
    await asOwner('PATCH', `/access/user:member-${i}@acme.example`, { 'market/dev': 'viewer' });
  }
  for (let i = 0; i < 20; i++) await asOwner('PATCH', `/access/${ada}`, { 'market/dev': i % 2 === 0 ? 'developer' : 'viewer' });
  // The policy changed, again and again: prod unprotected, then protected again; roles made.
  for (let i = 0; i < 20; i++) await asOwner('PATCH', '/projects/market/prod', { protected: i % 2 === 1 });
  for (let i = 0; i < 5; i++) await asOwner('PUT', `/roles/grown-${i}`, { ...release, name: `Grown ${i}` });
  // Tokens: ci's, and personal ones of Cy's scoped to one place each.
  for (let i = 0; i < 10; i++) {
    await asOwner('POST', `/members/${ci}/tokens`, { label: `grown-${i}`, expiresInDays: 1 });
    await asOwner('POST', `/members/${cy}/tokens`, { label: `grown-${i}`, expiresInMinutes: 60, scope: { 'market/busy': 'viewer' } });
  }
  assert.deepEqual(held(await costs()), small);
});

/**
 * The instance grown every way at once, in an order Hegel draws: other
 * environments written, other projects and their forks made, members
 * granted, Ada's own role flipped, environments protected and not, roles
 * edited and made, references made into the environment she reads, keys
 * made sensitive, tokens issued. Whatever it grew by, each request costs
 * what it did before.
 */
const growth = gs.record({
  kind: gs.sampledFrom(['write', 'project', 'fork', 'member', 'flip', 'protect', 'role', 'reference', 'sensitive', 'token'] as const),
  place: gs.integers({ minValue: 0, maxValue: 7 }),
  count: gs.integers({ minValue: 1, maxValue: 12 }),
  on: gs.booleans(),
});
const growthSettings = propertySettings(4, 10);

test(`a request costs the same after any growth of the instance, seed ${growthSettings.seed}`, async () => {
  const small = held(await costs());
  // Places made so far: names from a counter, since the instance keeps what every case made. So Hegel's replay of a
  // failing case runs on a larger instance, and may pass, which it reports as flaky: the first failure is printed whole.
  const made = { environments: ['market/busy', 'market/prod'], keys: [] as string[] };
  let n = 0;
  await hegel.testAsync(async (tc) => {
    const steps = tc.draw(gs.arrays(growth, { minSize: 1, maxSize: 8 }));
    for (const step of steps) {
      const at = made.environments[step.place % made.environments.length]!;
      const id = n++;
      switch (step.kind) {
        case 'write': {
          const keys = Object.fromEntries(Array.from({ length: step.count }, (_, i) => [`GROWN_${id}_${i}`, `fake-${id}-${i}`]));
          await asOwner('PATCH', `/secrets/${at}`, keys);
          made.keys.push(...Object.keys(keys).map((key) => `${at}/${key}`));
          break;
        }
        case 'project':
          await asOwner('PUT', `/projects/grown-${id}`, {});
          for (const environment of ['dev', 'prod']) await asOwner('PUT', `/projects/grown-${id}/${environment}`, {});
          made.environments.push(`grown-${id}/dev`, `grown-${id}/prod`);
          break;
        case 'fork': {
          // In another project than market: a caller reads the environments of the projects they reach, its forks among them.
          const [of, from] = at.split('/');
          if (of === 'market') break;
          await asOwner('PUT', `/projects/${of}/fork-${id}`, { from, inherit: true });
          made.environments.push(`${of}/fork-${id}`);
          break;
        }
        case 'member': {
          const member = `user:grown-${id}@acme.example`;
          await asOwner('PUT', `/members/${member}`, {});
          await asOwner('PATCH', `/access/${member}`, { [step.on ? 'market/dev' : at]: step.count % 2 === 0 ? 'viewer' : 'developer' });
          break;
        }
        case 'flip':
          await asOwner('PATCH', `/access/${ada}`, { 'market/dev': step.on ? 'developer' : 'viewer' });
          break;
        case 'protect':
          // Never market/dev, which Ada reads: protected, a viewer there holds nothing.
          await asOwner('PATCH', `/projects/${at}`, { protected: step.on });
          break;
        case 'role':
          await (step.on
            ? asOwner('PUT', `/roles/grown-${step.count % 3}`, { ...release, name: `Grown ${step.count}`, permissions: step.count % 2 === 0 ? ['secret.use'] : ['secret.read', 'secret.use', 'secret.write'] })
            : asOwner('PUT', '/instance-roles/auditor', { name: `Auditor ${step.count}`, description: '', permissions: ['audit.read'], protected: [] }));
          break;
        case 'reference':
          await asOwner('PATCH', `/secrets/${at}`, { [`REFERS_${id}`]: { ref: step.on ? 'market/dev/API_KEY' : 'market/dev/DATABASE_URL' } });
          break;
        case 'sensitive': {
          if (made.keys.length === 0) break;
          const path = made.keys[step.count % made.keys.length]!;
          const slash = path.lastIndexOf('/');
          await asOwner('PATCH', `/secrets/${path.slice(0, slash)}`, { [path.slice(slash + 1)]: { value: `fake-${id}`, sensitivity: step.on ? 'sensitive' : 'secret' } });
          break;
        }
        case 'token':
          await (step.on
            ? asOwner('POST', `/members/${ci}/tokens`, { label: `grown-${id}`, expiresInDays: 1 })
            : asOwner('POST', `/members/${cy}/tokens`, { label: `grown-${id}`, expiresInMinutes: 60, scope: { [at]: 'viewer' } }));
          break;
      }
    }
    const spent = held(await costs());
    for (const [name, then] of Object.entries(small)) {
      const why = `${name} ran more statements or read more rows once the instance grew by ${JSON.stringify(steps)}: ${JSON.stringify(spent[name])}, not ${JSON.stringify(then)}`;
      if (JSON.stringify(spent[name]) !== JSON.stringify(then)) console.error(why);
      assert.deepEqual(spent[name], then, why);
    }
  }, growthSettings);
});
