// coffre as MCP clients' OAuth authorization server (docs/design/mcp.md,
// section 4): its metadata, consent, codes, tokens, refresh and
// revocation, each over HTTP as a client and the consent page send them.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';

import { github, signin, type RateLimiter } from '@coffre/core/identity';
import { eq, inArray } from 'drizzle-orm';

import { SigninService } from '../src/api/signin.ts';
import { coffreRoute } from '../src/app.ts';
import { pageClient } from '../src/fetch-api.ts';
import { updateAuth } from '../src/db/queries.ts';
import { forgetDocuments } from '../src/mcp/clients.ts';
import { McpService } from '../src/mcp/service.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, testDeps, waitUntil, type FixtureDeps } from './api-fixture.ts';
import { auditLog, mcpConnections, oauthClients } from './db/tables.ts';

const ORIGIN = 'https://secrets.acme.example';
const RESOURCE = `${ORIGIN}/mcp`;
const ROOT = 'admin@acme.example';
const DEV = 'dev@acme.example';
const OTHER = 'other@acme.example';
const CLAUDE_CODE = 'https://claude.ai/oauth/claude-code-client-metadata';
const CLAUDE = 'https://claude.ai/oauth/mcp-oauth-client-metadata';

/** The documents the fake internet serves, by URL. */
const documents = new Map<string, unknown>([
  [CLAUDE_CODE, { client_id: CLAUDE_CODE, client_name: 'Claude Code', redirect_uris: ['http://localhost/callback', 'http://127.0.0.1/callback'], token_endpoint_auth_method: 'none' }],
  [CLAUDE, { client_id: CLAUDE, client_name: 'Claude', redirect_uris: ['https://claude.ai/api/mcp/auth_callback'], token_endpoint_auth_method: 'none' }],
]);
let fetched: string[] = [];
const transport: WorkloadTransport = {
  json: async (url) => {
    fetched.push(url.href);
    if (!documents.has(url.href)) throw new FetchRefused(url, 'answered 404');
    return documents.get(url.href);
  },
};

/** Limiters that let everything through, until a test closes one. */
const open = { source: true, total: true };
const limiter = (which: 'source' | 'total' | 'connection'): RateLimiter => ({
  limit: async () => ({ success: which === 'connection' ? true : open[which] }),
});
const auth = signin({
  providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })],
  mcp: { limits: { perSource: limiter('source'), perConnection: limiter('connection'), total: limiter('total') } },
}).resolve(ORIGIN);

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let runtime: CoffreRuntime;
let off: CoffreRuntime;

before(async () => {
  db = await openTestDatabase();
  deps = testDeps(db.runtime, [ROOT]);
  if (auth.mode !== 'signin') throw new Error('unreachable');
  const service = new SigninService({ ...deps, signin: auth.signin });
  const mcp = new McpService({ ...deps, config: auth.signin.mcp!, signin: auth.signin, publicUrl: ORIGIN, transport });
  runtime = { db: deps.db, vault: deps.vault, chainKey: deps.chainKey, signin: service, workloads: null, mcp, auth, publicUrl: ORIGIN, verifier: service, waitUntil, schema: { migrated: true } };
  off = { ...runtime, mcp: null };
});

after(async () => {
  await resetDatabase(db.owner);
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  forgetDocuments();
  fetched = [];
  open.source = true;
  open.total = true;
  const root = clientFor(deps, ROOT);
  for (const email of [DEV, OTHER]) await root.members.add(`user:${email}`);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/dev', { name: 'Development' });
  await root.access.set(`user:${DEV}`, { market: 'developer' });
});

function route(path: string, init: RequestInit = {}, on = runtime): Promise<Response> {
  return coffreRoute(new Request(`${ORIGIN}${path}`, init), on, '203.0.113.7').then((response) => response!);
}

/** A CLI session for `email`: how these tests stand in for the consent page's browser. */
async function session(email: string): Promise<string> {
  const service = runtime.signin!;
  const started = await service.startDevice({ clientLabel: 'laptop', sourceIp: null });
  await service.decideDevice(await contextFor(deps, email), started.userCode, true);
  const polled = await service.pollDevice(started.deviceCode, { requestId: randomUUID(), sourceIp: null });
  if (polled.status !== 'approved') throw new Error('the device login was not approved');
  return polled.credential.token;
}

function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}

type Ask = { client_id: string; redirect_uri: string; scope?: string; state?: string; resource?: string; code_challenge?: string; code_challenge_method?: string; response_type?: string };

function request(client: string, redirect: string, challenge: string, extra: Partial<Ask> = {}): Ask {
  return { client_id: client, redirect_uri: redirect, response_type: 'code', code_challenge: challenge, code_challenge_method: 'S256', state: 'st-1', resource: RESOURCE, ...extra };
}

async function describe(token: string, ask: Ask) {
  const response = await route(`/api/oauth/authorizations?${new URLSearchParams(ask)}`, { headers: { authorization: `Bearer ${token}` } });
  assert.equal(response.status, 200, await response.clone().text());
  return response.json() as Promise<Record<string, unknown>>;
}

async function decide(token: string, ask: Ask, answer: { approve: boolean; scopes?: string[] }): Promise<URL> {
  const response = await route('/api/oauth/authorizations', {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ request: ask, approve: answer.approve, scopes: answer.scopes ?? [] }),
  });
  assert.equal(response.status, 200, await response.clone().text());
  return new URL(((await response.json()) as { redirect: string }).redirect);
}

function tokenRequest(fields: Record<string, string>): RequestInit {
  return { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(fields).toString() };
}

/** Consent, then the code exchanged: what a client holds once its person approved. */
async function connect(email = DEV, client = CLAUDE_CODE, redirect = 'http://localhost:51234/callback', scope = 'read', ticked = scope.split(' ')) {
  const { verifier, challenge } = pkce();
  const ask = request(client, redirect, challenge, { scope });
  const back = await decide(await session(email), ask, { approve: true, scopes: ticked });
  const code = back.searchParams.get('code')!;
  const response = await route('/api/oauth/token', tokenRequest({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: redirect, client_id: client, resource: RESOURCE }));
  assert.equal(response.status, 200, await response.clone().text());
  return { ...((await response.json()) as { access_token: string; refresh_token: string; expires_in: number; scope: string }), code, verifier, redirect, client };
}

function discover(token: string | null, headers: Record<string, string> = {}): Promise<Response> {
  return route('/mcp', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'mcp-protocol-version': '2026-07-28',
      'mcp-method': 'server/discover',
      ...(token === null ? {} : { authorization: `Bearer ${token}` }),
      ...headers,
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'server/discover', params: { _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {} } } }),
  });
}

async function entries(action: string) {
  return (await db.owner.select().from(auditLog).where(eq(auditLog.action, action)).orderBy(auditLog.seq)).map((row) => ({ ...row, metadata: JSON.parse(row.metadata) as Record<string, unknown> }));
}

test('the metadata documents say where the authorization server is, and what it takes', async () => {
  const resource = await (await route('/.well-known/oauth-protected-resource/mcp')).json();
  assert.deepEqual(resource, {
    resource: RESOURCE,
    authorization_servers: [ORIGIN],
    scopes_supported: ['read'],
    bearer_methods_supported: ['header'],
    resource_name: 'coffre at secrets.acme.example',
  });
  assert.deepEqual(await (await route('/.well-known/oauth-protected-resource')).json(), resource, 'at the root as well');
  const server = (await (await route('/.well-known/oauth-authorization-server')).json()) as Record<string, unknown>;
  assert.equal(server.issuer, ORIGIN);
  assert.equal(server.token_endpoint, `${ORIGIN}/api/oauth/token`);
  assert.equal(server.authorization_endpoint, `${ORIGIN}/oauth/authorize`);
  // What Claude reads before it uses a metadata document rather than registering.
  assert.equal(server.client_id_metadata_document_supported, true);
  assert.deepEqual(server.token_endpoint_auth_methods_supported, ['none']);
  assert.deepEqual(server.code_challenge_methods_supported, ['S256']);
  assert.deepEqual(server.scopes_supported, ['read', 'write', 'reveal', 'manage-access', 'offline_access']);
  assert.equal(server.authorization_response_iss_parameter_supported, true);

  for (const path of ['/.well-known/oauth-authorization-server', '/.well-known/oauth-protected-resource/mcp', '/mcp']) {
    const response = await route(path, path === '/mcp' ? { method: 'POST' } : {}, off);
    assert.equal(response.status, 404, `${path} without signin({ mcp })`);
  }
});

test('/mcp answers 401, and where to sign in, without a good token; a request from another site, 403', async () => {
  const bare = await discover(null);
  assert.equal(bare.status, 401);
  assert.equal(bare.headers.get('www-authenticate'), `Bearer resource_metadata="${ORIGIN}/.well-known/oauth-protected-resource/mcp", scope="read"`);
  const wrong = await discover('coffre_mcp_nonsense');
  assert.equal(wrong.status, 401);
  assert.match(wrong.headers.get('www-authenticate')!, /^Bearer error="invalid_token"/);
  assert.equal((await route('/mcp')).status, 405, 'GET: no stream to open');

  const { access_token } = await connect();
  assert.equal((await discover(access_token)).status, 200);
  assert.equal((await discover(access_token, { origin: 'https://evil.example' })).status, 403);
});

test('Claude Code connects: its document fetched, any loopback port, consent, the code once, then /mcp', async () => {
  const token = await session(DEV);
  const { verifier, challenge } = pkce();
  const ask = request(CLAUDE_CODE, 'http://127.0.0.1:61001/callback', challenge);
  const view = await describe(token, ask);
  assert.deepEqual(view, {
    status: 'ready',
    client: { id: CLAUDE_CODE, name: 'Claude Code', host: 'claude.ai', registration: 'cimd' },
    redirectHost: 'localhost',
    loopbackOnly: true,
    scopes: ['read'],
    connections: [],
    days: 30,
  });
  assert.deepEqual(fetched, [CLAUDE_CODE]);

  const back = await decide(token, ask, { approve: true });
  assert.equal(`${back.origin}${back.pathname}`, 'http://127.0.0.1:61001/callback');
  assert.equal(back.searchParams.get('state'), 'st-1');
  assert.equal(back.searchParams.get('iss'), ORIGIN, 'RFC 9207: the issuer, against mix-ups');
  const code = back.searchParams.get('code')!;
  const [connected] = await entries('mcp.connect');
  assert.equal(connected?.actor, `user:${DEV}`);
  assert.deepEqual([connected?.decision, connected?.metadata.clientId, connected?.metadata.scopes, connected?.metadata.redirectHost], ['allow', CLAUDE_CODE, 'read', 'localhost']);

  const exchange = (fields: Record<string, string>) =>
    route('/api/oauth/token', tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: 'http://127.0.0.1:61001/callback', client_id: CLAUDE_CODE, ...fields }));
  assert.equal((await (await exchange({ code_verifier: pkce().verifier })).json() as { error: string }).error, 'invalid_grant', 'another verifier');
  const answered = await exchange({ code_verifier: verifier, resource: RESOURCE });
  assert.equal(answered.status, 200);
  assert.equal(answered.headers.get('cache-control'), 'no-store');
  const tokens = (await answered.json()) as { access_token: string; refresh_token: string; expires_in: number; scope: string; token_type: string };
  assert.match(tokens.access_token, /^coffre_mcp_/);
  assert.match(tokens.refresh_token, /^coffre_mcr_/);
  assert.deepEqual([tokens.token_type, tokens.expires_in, tokens.scope], ['Bearer', 3600, 'read']);

  const discovered = (await (await discover(tokens.access_token)).json()) as { result: { supportedVersions: string[] } };
  assert.deepEqual(discovered.result.supportedVersions, ['2026-07-28']);

  // The code again: whoever holds it is not who it was for, so the connection ends.
  const again = await exchange({ code_verifier: verifier });
  assert.equal(((await again.json()) as { error: string }).error, 'invalid_grant');
  assert.equal((await discover(tokens.access_token)).status, 401, 'its tokens die with it');
  const [ended] = await entries('mcp.disconnect');
  assert.deepEqual([ended?.actor, ended?.metadata.reason], [`user:${DEV}`, 'code_reused']);
});

test("Claude's hosted apps connect with their callback on claude.ai; a redirect elsewhere is never sent anything", async () => {
  const token = await session(DEV);
  const { challenge } = pkce();
  const view = await describe(token, request(CLAUDE, 'https://claude.ai/api/mcp/auth_callback', challenge));
  assert.deepEqual([view.status, view.redirectHost, view.loopbackOnly], ['ready', 'claude.ai', false]);

  for (const [redirect, why] of [
    ['https://evil.example/cb', /not one of its redirects/],
    ['https://claude.ai/api/mcp/other', /not one of its redirects/],
    ['cursor://anysphere.cursor-mcp/oauth/callback', /not one of its redirects/],
  ] as const) {
    const refused = await describe(token, request(CLAUDE, redirect, challenge));
    assert.equal(refused.status, 'invalid', redirect);
    assert.match(String(refused.message), why);
    assert.equal('redirect' in refused, false, 'shown on the page, never redirected to');
  }

  documents.set('https://evil.example/claude.json', {
    client_id: 'https://evil.example/claude.json', client_name: 'Claude', redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
  });
  const lookalike = await describe(token, request('https://evil.example/claude.json', 'https://claude.ai/api/mcp/auth_callback', challenge));
  assert.equal(lookalike.status, 'invalid');
  assert.match(String(lookalike.message), /not on evil\.example/, "a document can't send codes to another host");

  const missing = await describe(token, request('https://nowhere.example/client.json', 'https://nowhere.example/cb', challenge));
  assert.equal(missing.status, 'invalid');
  assert.match(String(missing.message), /answered 404/);
});

test('what is wrong past the client and its redirect goes back to the client, as OAuth says', async () => {
  const token = await session(DEV);
  const { challenge } = pkce();
  const redirect = 'http://localhost:5000/callback';
  for (const [extra, error] of [
    [{ response_type: 'token' }, 'unsupported_response_type'],
    [{ code_challenge_method: 'plain' }, 'invalid_request'],
    [{ code_challenge: undefined }, 'invalid_request'],
    [{ resource: 'https://other.example/mcp' }, 'invalid_target'],
    [{ scope: 'read admin' }, 'invalid_scope'],
  ] as const) {
    const view = await describe(token, request(CLAUDE_CODE, redirect, challenge, extra as Partial<Ask>));
    assert.equal(view.status, 'refused', JSON.stringify(extra));
    const back = new URL(String(view.redirect));
    assert.deepEqual([back.searchParams.get('error'), back.searchParams.get('state'), back.searchParams.get('iss')], [error, 'st-1', ORIGIN]);
  }
  // A resource with a trailing slash is the same resource.
  assert.equal((await describe(token, request(CLAUDE_CODE, redirect, challenge, { resource: `${RESOURCE}/` }))).status, 'ready');
});

test('a person who denies sends the client access_denied, and the refusal is logged', async () => {
  const back = await decide(await session(DEV), request(CLAUDE_CODE, 'http://localhost:5000/callback', pkce().challenge), { approve: false });
  assert.deepEqual([back.searchParams.get('error'), back.searchParams.get('code')], ['access_denied', null]);
  const [refused] = await entries('mcp.connect');
  assert.deepEqual([refused?.decision, refused?.metadata.reason], ['deny', 'person_denied']);
  assert.equal((await db.owner.select().from(mcpConnections)).length, 0);
});

test('scopes: Read always; the rest as the person ticked, asked for or not; the token says which', async () => {
  const token = await session(DEV);
  const { challenge } = pkce();
  const ask = request(CLAUDE_CODE, 'http://localhost:5000/callback', challenge, { scope: 'write reveal offline_access' });
  assert.deepEqual((await describe(token, ask)).scopes, ['read', 'write', 'reveal'], 'what starts ticked; offline_access is every connection');
  await decide(token, ask, { approve: true, scopes: ['write', 'manage-access'] });
  const [row] = await db.owner.select().from(mcpConnections);
  assert.equal(row?.scopes, 'read write manage-access', 'unticked Reveal values stays out; Manage access, never asked for, is in');
  const [connected] = await entries('mcp.connect');
  assert.deepEqual([connected?.metadata.asked, connected?.metadata.scopes], ['read write reveal', 'read write manage-access']);

  // Claude asks for what the resource metadata names, Read; its person ticks Write.
  const claude = await connect(DEV, CLAUDE, 'https://claude.ai/api/mcp/auth_callback', 'read', ['write']);
  assert.equal(claude.scope, 'read write', 'RFC 6749, section 3.3: the scope granted, which is not the one asked for');
  const refreshed = (await (await route('/api/oauth/token', tokenRequest({ grant_type: 'refresh_token', refresh_token: claude.refresh_token, client_id: CLAUDE }))).json()) as { scope: string };
  assert.equal(refreshed.scope, 'read write');
});

test('refresh tokens rotate, may narrow the scopes, and a replaced one presented again ends the connection', async () => {
  const first = await connect(DEV, CLAUDE_CODE, 'http://localhost:5000/callback', 'read write');
  const refresh = (refresh_token: string, extra: Record<string, string> = {}) =>
    route('/api/oauth/token', tokenRequest({ grant_type: 'refresh_token', refresh_token, client_id: CLAUDE_CODE, ...extra }));

  const wider = await refresh(first.refresh_token, { scope: 'read write manage-access' });
  assert.equal(((await wider.json()) as { error: string }).error, 'invalid_scope');
  const other = await refresh(first.refresh_token, { client_id: CLAUDE });
  assert.equal(((await other.json()) as { error: string }).error, 'invalid_grant');

  const second = (await (await refresh(first.refresh_token, { scope: 'read' })).json()) as { refresh_token: string; access_token: string; scope: string };
  assert.equal(second.scope, 'read');
  assert.notEqual(second.refresh_token, first.refresh_token);
  assert.equal((await discover(second.access_token)).status, 200);
  assert.equal((await discover(first.access_token)).status, 200, 'an earlier access token lives out its hour');

  // The first refresh token, replaced, comes back: one of its holders is not the client.
  const reused = await refresh(first.refresh_token);
  assert.equal(((await reused.json()) as { error: string }).error, 'invalid_grant');
  assert.equal((await discover(second.access_token)).status, 401);
  assert.equal(((await (await refresh(second.refresh_token)).json()) as { error: string }).error, 'invalid_grant', 'the current one is dead too');
  const ended = await entries('mcp.disconnect');
  assert.deepEqual(ended.map((entry) => entry.metadata.reason), ['refresh_reused']);
  const tokens = await entries('mcp.token');
  assert.deepEqual(tokens.map((entry) => entry.metadata.grant), ['authorization_code', 'refresh_token']);
});

test('revocation, by either token, ends the connection; and so does removing its person', async () => {
  const one = await connect();
  const revoke = await route('/api/oauth/revoke', tokenRequest({ token: one.refresh_token, client_id: CLAUDE_CODE }));
  assert.equal(revoke.status, 200);
  assert.equal((await discover(one.access_token)).status, 401);
  assert.equal((await route('/api/oauth/revoke', tokenRequest({ token: 'coffre_mcr_unknown' }))).status, 200, 'an unknown token: a quiet no-op');

  const two = await connect();
  assert.equal((await route('/api/oauth/revoke', tokenRequest({ token: two.access_token }))).status, 200);
  assert.equal((await discover(two.access_token)).status, 401);

  const three = await connect();
  await clientFor(deps, ROOT).members.remove(`user:${DEV}`);
  assert.equal((await discover(three.access_token)).status, 401, 'a removed member, whatever tokens are out');
});

test('an MCP token is good at /mcp only, and nothing else is good there', async () => {
  const { access_token } = await connect();
  const api = await route('/api/me', { headers: { authorization: `Bearer ${access_token}` } });
  assert.equal(api.status, 401, 'the API never takes one');
  const cli = await session(DEV);
  assert.equal((await discover(cli)).status, 401, 'nor /mcp a CLI session');
  const forged = access_token.slice(0, -4) + (access_token.endsWith('AAAA') ? 'BBBB' : 'AAAA');
  assert.equal((await discover(forged)).status, 401, 'a token whose MAC does not hold');
});

test('registration keeps the redirects coffre accepts and leaves out the rest, as Cursor needs', async () => {
  const response = await route('/api/oauth/register', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: 'Cursor',
      redirect_uris: ['http://localhost:8787/callback', 'cursor://anysphere.cursor-mcp/oauth/callback', 'https://www.cursor.com/agents/mcp/oauth/callback'],
      token_endpoint_auth_method: 'none',
    }),
  });
  assert.equal(response.status, 201);
  const registered = (await response.json()) as { client_id: string; redirect_uris: string[] };
  assert.deepEqual(registered.redirect_uris, ['http://localhost:8787/callback', 'https://www.cursor.com/agents/mcp/oauth/callback']);

  const token = await session(DEV);
  const { challenge } = pkce();
  const view = await describe(token, request(registered.client_id, 'http://localhost:8787/callback', challenge));
  assert.deepEqual(view.client, { id: registered.client_id, name: 'Cursor', host: null, registration: 'dcr' }, 'no host to vouch for it');
  assert.equal(view.loopbackOnly, false);
  assert.equal((await describe(token, request(registered.client_id, 'cursor://anysphere.cursor-mcp/oauth/callback', challenge))).status, 'invalid');
  const { access_token } = await connect(DEV, registered.client_id, 'https://www.cursor.com/agents/mcp/oauth/callback');
  assert.equal((await discover(access_token)).status, 200);

  for (const body of [
    { redirect_uris: ['cursor://only'] },
    { redirect_uris: ['https://app.example/cb'], token_endpoint_auth_method: 'client_secret_basic' },
    { redirect_uris: [] },
  ]) {
    const refused = await route('/api/oauth/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    assert.equal(refused.status, 400, JSON.stringify(body));
  }
});

test('the unauthenticated endpoints pass their limits first, and a JSON token request is refused', async () => {
  open.source = false;
  const limited = await route('/api/oauth/token', tokenRequest({ grant_type: 'refresh_token', refresh_token: 'x', client_id: CLAUDE_CODE }));
  assert.equal(limited.status, 429);
  assert.equal(limited.headers.get('retry-after'), '60');
  open.source = true;
  open.total = false;
  assert.equal((await route('/api/oauth/register', { method: 'POST', body: '{}' })).status, 429);
  open.total = true;
  const json = await route('/api/oauth/token', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  assert.equal(((await json.json()) as { error: string }).error, 'invalid_request');
  const twice = await route('/api/oauth/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'grant_type=a&grant_type=b' });
  assert.equal(((await twice.json()) as { error: string }).error, 'invalid_request');
});

test('a code lasts a minute, and is for its client and redirect only', async () => {
  const token = await session(DEV);
  const { verifier, challenge } = pkce();
  const redirect = 'http://localhost:5000/callback';
  const code = (await decide(token, request(CLAUDE_CODE, redirect, challenge), { approve: true })).searchParams.get('code')!;
  const exchange = (fields: Record<string, string>) =>
    route('/api/oauth/token', tokenRequest({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: redirect, client_id: CLAUDE_CODE, ...fields }));
  assert.equal(((await (await exchange({ client_id: CLAUDE })).json()) as { error: string }).error, 'invalid_grant');
  assert.equal(((await (await exchange({ redirect_uri: 'http://localhost:5001/callback' })).json()) as { error: string }).error, 'invalid_grant');
  assert.equal(((await (await exchange({ resource: 'https://other.example/mcp' })).json()) as { error: string }).error, 'invalid_target');
  await db.owner.update(mcpConnections).set({ codeExpiresAt: new Date(Date.now() - 1000) });
  assert.equal(((await (await exchange({})).json()) as { error: string }).error, 'invalid_grant', 'expired; and the MAC would refuse it anyway');
});

test("Connected apps lists a person's redeemed connections, and Disconnect ends one; an owner may end anyone's, no one else", async () => {
  const one = await connect();
  const two = await connect(DEV, CLAUDE, 'https://claude.ai/api/mcp/auth_callback');
  // A consent whose code was never redeemed is no connected app.
  const dev = await session(DEV);
  await decide(dev, request(CLAUDE_CODE, 'http://localhost:5000/callback', pkce().challenge), { approve: true });
  const as = (token: string, method = 'GET', path = '/api/apps') => route(path, { method, headers: { authorization: `Bearer ${token}` } });
  const listed = (await (await as(dev)).json()) as { apps: { id: string; name: string; host: string; registration: string; scopes: string[] }[] };
  assert.deepEqual(listed.apps.map((app) => [app.name, app.host, app.registration, app.scopes]), [
    ['Claude', 'claude.ai', 'cimd', ['read']],
    ['Claude Code', 'claude.ai', 'cimd', ['read']],
  ], 'newest first');
  const [claude, claudeCode] = listed.apps as [(typeof listed.apps)[0], (typeof listed.apps)[0]];

  assert.equal((await as(dev, 'DELETE', `/api/apps/${claudeCode.id}`)).status, 200);
  assert.equal((await discover(one.access_token)).status, 401, 'disconnected: its token stops at the next request');
  assert.equal((await discover(two.access_token)).status, 200, 'the other connection is untouched');

  const other = await session(OTHER);
  assert.deepEqual(((await (await as(other)).json()) as { apps: unknown[] }).apps, [], "someone else's apps are not listed");
  assert.equal((await as(other, 'DELETE', `/api/apps/${claude.id}`)).status, 403, "nor theirs to disconnect");
  assert.equal((await as(await session(ROOT), 'DELETE', `/api/apps/${claude.id}`)).status, 200, 'an owner may');
  assert.equal((await discover(two.access_token)).status, 401);
  assert.equal((await as(dev, 'DELETE', `/api/apps/${claude.id}`)).status, 404, 'ended already');
  assert.equal((await as(dev, 'DELETE', '/api/apps/not-a-connection')).status, 400, 'the router takes an ID only');

  const ended = await entries('mcp.disconnect');
  assert.deepEqual(ended.map((entry) => [entry.decision, entry.actor, entry.metadata.reason ?? entry.code, entry.metadata.principalId ?? null]), [
    ['allow', `user:${DEV}`, 'person', null],
    ['deny', `user:${OTHER}`, 'requires_instance_admin', null],
    ['allow', `user:${ROOT}`, 'owner', DEV],
    ['deny', `user:${DEV}`, 'unknown_connection', null],
  ]);
});

test("an owner reads a person's connected apps in their report; removal disconnects them, says how many, and re-admission brings none back", async () => {
  const app = await connect();
  // A consent whose code was never redeemed is no connected app, but removal ends it too.
  await decide(await session(DEV), request(CLAUDE_CODE, 'http://localhost:5000/callback', pkce().challenge), { approve: true });
  const root = await session(ROOT);
  const as = (method: string, path: string, token = root) => route(path, { method, headers: { authorization: `Bearer ${token}` } });
  type Report = { live: { apps: number }; apps: { name: string; host: string; scopes: string[] }[] };
  const before = (await (await as('GET', `/api/members/user:${DEV}`)).json()) as Report;
  assert.equal(before.live.apps, 1);
  assert.deepEqual(before.apps.map((listed) => [listed.name, listed.host, listed.scopes]), [['Claude Code', 'claude.ai', ['read']]]);
  assert.equal((await as('GET', `/api/members/user:${DEV}`, await session(OTHER))).status, 403, "only owners read someone's report");

  const removal = await as('DELETE', `/api/members/user:${DEV}`);
  assert.equal(removal.status, 200, await removal.clone().text());
  const { revoked, report } = (await removal.json()) as { revoked: { apps: number }; report: Report };
  assert.equal(revoked.apps, 1, 'the code never redeemed is no app, and is not counted');
  assert.deepEqual([report.live.apps, report.apps], [0, []]);
  assert.equal((await discover(app.access_token)).status, 401);
  const rows = await db.owner.select().from(mcpConnections).where(eq(mcpConnections.principal, `user:${DEV}`));
  assert.deepEqual(rows.map((row) => [row.revokedAt !== null, row.revokedBy]), [[true, ROOT], [true, ROOT]], 'revoked, not only dead by the generation');

  // As a removal before this release left them, dead by the generation alone: re-admission revokes them.
  await updateAuth(db.owner, deps.chainKey, mcpConnections, { principal: `user:${DEV}` }, { revokedAt: null, revokedBy: null });
  assert.equal((await as('PUT', `/api/members/user:${DEV}`)).status, 200);
  const readmitted = await db.owner.select().from(mcpConnections).where(eq(mcpConnections.principal, `user:${DEV}`));
  assert.deepEqual(readmitted.map((row) => row.revokedBy), [ROOT, ROOT]);
  const back = (await (await as('GET', `/api/members/user:${DEV}`)).json()) as Report;
  assert.deepEqual([back.live.apps, back.apps], [0, []], 'a fresh start');
  assert.equal((await route('/api/oauth/token', tokenRequest({ grant_type: 'refresh_token', refresh_token: app.refresh_token, client_id: CLAUDE_CODE }))).status, 400);
});

test("an instance that serves no MCP lists no one's apps", async () => {
  await connect();
  const response = await route(`/api/members/user:${DEV}`, { headers: { authorization: `Bearer ${await session(ROOT)}` } }, off);
  const report = (await response.json()) as { live: { apps: number }; apps: unknown[] };
  assert.deepEqual([report.live.apps, report.apps], [0, []]);
});

test('a consent abandoned before its code was redeemed does not count against the twenty', async () => {
  const dev = await session(DEV);
  const consent = () => decide(dev, request(CLAUDE_CODE, 'http://localhost:5000/callback', pkce().challenge), { approve: true });
  for (let i = 0; i < 20; i++) await consent();
  const refused = await route('/api/oauth/authorizations', {
    method: 'POST',
    headers: { authorization: `Bearer ${dev}`, 'content-type': 'application/json' },
    body: JSON.stringify({ request: request(CLAUDE_CODE, 'http://localhost:5000/callback', pkce().challenge), approve: true }),
  });
  assert.equal(refused.status, 409, 'twenty codes waiting count, as twenty connections would');
  // Their minute passes, each row signed again as coffre would sign it.
  for (const row of await db.owner.select().from(mcpConnections)) {
    await updateAuth(db.owner, deps.chainKey, mcpConnections, { id: row.id }, { codeExpiresAt: new Date(Date.now() - 1000) });
  }
  await consent();
});

test("the consent page's describe, asked with a cookie from another site, is refused before any client's document is fetched; the page's own render reads it", async () => {
  const token = await session(DEV);
  const { challenge } = pkce();
  const ask = request(CLAUDE_CODE, 'http://localhost:5000/callback', challenge);
  // The path as the router reads it: a trailing slash, a doubled one, a letter percent-encoded.
  for (const path of ['/api/oauth/authorizations', '/api/oauth/authorizations/', '/api//oauth/authorizations', '/api/%6Fauth/authorizations']) {
    const crossSite = await route(`${path}?${new URLSearchParams(ask)}`, {
      headers: { cookie: `__Host-coffre_session=${token}`, 'sec-fetch-site': 'cross-site' },
    });
    assert.equal(crossSite.status, 403, path);
    assert.equal(((await crossSite.json()) as { error: string }).error, 'cross_origin', path);
  }
  assert.deepEqual(fetched, [], "another site's page made coffre fetch nothing");
  // The consent page embedded in another site, as an iframe or an image, renders without describing.
  for (const dest of ['iframe', 'image']) {
    const embedded = pageClient(new Request(`${ORIGIN}/oauth/authorize`, { headers: { cookie: `__Host-coffre_session=${token}`, 'sec-fetch-dest': dest } }), runtime, null);
    await assert.rejects(embedded.oauth.describe(ask), (error: Error & { code?: string }) => error.code === 'cross_origin', dest);
  }
  assert.deepEqual(fetched, []);
  // The consent page's render, a top-level navigation in process with the cookie the browser sent it, is coffre itself.
  for (const headers of [{}, { 'sec-fetch-dest': 'document' }] as Record<string, string>[]) {
    const page = pageClient(new Request(`${ORIGIN}/oauth/authorize`, { headers: { cookie: `__Host-coffre_session=${token}`, ...headers } }), runtime, null);
    assert.equal((await page.oauth.describe(ask)).status, 'ready');
  }
  assert.deepEqual(fetched, [CLAUDE_CODE], 'fetched once, then kept');
});

test("a client's name, host and kind are under their rows' MACs: edited in the database, the row is refused", async () => {
  for (const [column, value] of [['client_name', 'Claude'], ['client_host', 'claude.ai'], ['registration', 'cimd']] as const) {
    await resetDatabase(db.owner);
    const root = clientFor(deps, ROOT);
    await root.members.add(`user:${DEV}`);
    const { access_token } = await connect();
    assert.equal((await discover(access_token)).status, 200);
    await db.owner.update(mcpConnections).set({ [column === 'client_name' ? 'clientName' : column === 'client_host' ? 'clientHost' : 'registration']: value === 'cimd' ? 'dcr' : `${value}-forged` });
    assert.equal((await discover(access_token)).status, 401, `${column} edited: the connection is refused`);
    const listed = await route('/api/apps', { headers: { authorization: `Bearer ${await session(DEV)}` } });
    assert.deepEqual(((await listed.json()) as { apps: unknown[] }).apps, [], `${column} edited: Connected apps does not show it`);
  }
  // A registration's name too.
  const registered = (await (await route('/api/oauth/register', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_name: 'Cursor', redirect_uris: ['http://localhost:4000/cb'] }),
  })).json()) as { client_id: string };
  const ask = request(registered.client_id, 'http://localhost:4000/cb', pkce().challenge);
  const token = await session(DEV);
  assert.equal((await describe(token, ask)).status, 'ready');
  await db.owner.update(oauthClients).set({ name: 'Claude' });
  assert.equal((await describe(token, ask)).status, 'invalid', 'a registration renamed in the database is no client');
});

test('GET /me says what the deployment turns on, read from its configuration, not from a route answering 404: MCP as its endpoint', async () => {
  const token = await session(DEV);
  const me = (on: CoffreRuntime) => route('/api/me', { headers: { authorization: `Bearer ${token}` } }, on).then((response) => response.json() as Promise<{ features: unknown }>);
  assert.deepEqual((await me(runtime)).features, { mcp: `${ORIGIN}/mcp`, workloads: false });
  assert.deepEqual((await me(off)).features, { mcp: null, workloads: false });
});

test("a step-up supersedes the client's narrower connection once its code is redeemed; one with the same scopes stays", async () => {
  const laptop = await connect(DEV, CLAUDE_CODE, 'http://localhost:51234/callback', 'read');
  const other = await connect(DEV, CLAUDE_CODE, 'http://localhost:51235/callback', 'read');
  assert.equal((await discover(laptop.access_token)).status, 200, 'a second laptop signs the first out of nothing');
  const claude = await connect(DEV, CLAUDE, 'https://claude.ai/api/mcp/auth_callback', 'read');

  // The consent page says what a step-up replaces: the two Read connections of Claude Code.
  const { challenge } = pkce();
  const shown = await describe(await session(DEV), request(CLAUDE_CODE, 'http://localhost:51236/callback', challenge, { scope: 'read write' }));
  assert.deepEqual(shown.connections, [['read'], ['read']]);

  const stepped = await connect(DEV, CLAUDE_CODE, 'http://localhost:51236/callback', 'read write');
  assert.equal((await discover(laptop.access_token)).status, 401, 'superseded');
  assert.equal((await discover(other.access_token)).status, 401, 'superseded');
  assert.equal((await discover(stepped.access_token)).status, 200);
  assert.equal((await discover(claude.access_token)).status, 200, "another client's connection is its own");
  const ended = (await entries('mcp.disconnect')).map((entry) => [entry.metadata.reason, entry.metadata.supersededBy !== undefined]);
  assert.deepEqual(ended, [['superseded', true], ['superseded', true]]);
});

test('a registration no connection names is revoked after a week, by a later registration; a used one stays', async () => {
  const register = async (name: string) => {
    const response = await route('/api/oauth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_name: name, redirect_uris: ['http://localhost:8787/callback'] }),
    });
    return ((await response.json()) as { client_id: string }).client_id;
  };
  const unused = await register('Never connected');
  const used = await register('Connected once');
  await connect(DEV, used, 'http://localhost:8787/callback');
  const recent = await register('Registered today');
  await db.owner.update(oauthClients).set({ createdAt: new Date(Date.now() - 8 * 86_400_000) }).where(inArray(oauthClients.id, [unused, used]));

  await register('A newcomer');
  const revoked = new Map((await db.owner.select().from(oauthClients)).map((row) => [row.id, row.revokedAt !== null]));
  assert.deepEqual([revoked.get(unused), revoked.get(used), revoked.get(recent)], [true, false, false], 'the unused week-old one revoked; a used one, and a recent one, stay');
  const { challenge } = pkce();
  assert.equal((await describe(await session(DEV), request(unused, 'http://localhost:8787/callback', challenge))).status, 'invalid', 'a revoked registration connects no more');
});
