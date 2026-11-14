// coffre as MCP clients' OAuth authorization server on the 0.16 contract
// (docs/design/0.16.md, "MCP connections"): its metadata, the consent page's
// two routes, codes, tokens, refresh, revocation, registration and
// Connected apps, each over HTTP as a client and the consent page send
// them, with the real vault. What each costs, request-cost.test.ts holds.
// Cases from 0.14.7's tests where they still hold; `/mcp` itself is
// another's.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { after, beforeEach, test } from 'node:test';

import { github, signin, type RateLimiter } from '@coffre/core/identity';
import { rowsOf } from '@coffre/db/dialect';
import { credential, emptyDatabase, identity, instance, principal, role, rows, user, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

import { forgetDocuments } from '../src/mcp/clients.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { openApp, PUBLIC_URL, SESSION } from './app-fixture.ts';

const RESOURCE = `${PUBLIC_URL}/mcp`;
const CLAUDE_CODE = 'https://claude.ai/oauth/claude-code-client-metadata';
const CLAUDE = 'https://claude.ai/oauth/mcp-oauth-client-metadata';
/** Documents the vault could not keep a connection of: a URL longer than it keeps, and a redirect longer than it keeps. */
const LONG_ID = `https://long.example/${'x'.repeat(250)}`;
const LONG_REDIRECT = `https://long.example/${'x'.repeat(400)}`;
const LONG_REDIRECTS = 'https://long.example/client.json';
/** A host of 119 characters, longer than a name the vault keeps; its documents give no name, or an empty one. */
const LONG_HOST = `${'a'.repeat(60)}.${'b'.repeat(50)}.example`;
const UNNAMED = `https://${LONG_HOST}/unnamed.json`;
const EMPTY_NAME = `https://${LONG_HOST}/empty.json`;

/** The documents the fake internet serves, by URL. */
const documents = new Map<string, unknown>([
  [CLAUDE_CODE, { client_id: CLAUDE_CODE, client_name: 'Claude Code', redirect_uris: ['http://localhost/callback', 'http://127.0.0.1/callback'], token_endpoint_auth_method: 'none' }],
  [CLAUDE, { client_id: CLAUDE, client_name: 'Claude', redirect_uris: ['https://claude.ai/api/mcp/auth_callback'], token_endpoint_auth_method: 'none' }],
  [LONG_ID, { client_id: LONG_ID, client_name: 'Long', redirect_uris: ['https://long.example/cb'] }],
  [LONG_REDIRECTS, { client_id: LONG_REDIRECTS, client_name: 'Long', redirect_uris: [LONG_REDIRECT] }],
  [UNNAMED, { client_id: UNNAMED, redirect_uris: [`https://${LONG_HOST}/cb`] }],
  [EMPTY_NAME, { client_id: EMPTY_NAME, client_name: ' ', redirect_uris: [`https://${LONG_HOST}/cb`] }],
]);
let fetched: string[] = [];
const transport: WorkloadTransport = {
  json: async (url) => {
    fetched.push(url.href);
    if (!documents.has(url.href)) throw FetchRefused.answered(url, 404);
    return documents.get(url.href);
  },
};

/** Limiters that let everything through, until a test closes one. */
const open = { source: true, total: true };
const limiter = (which: 'source' | 'total' | 'connection'): RateLimiter => ({ limit: async () => ({ success: which === 'connection' ? true : open[which] }) });
const mcp = { limits: { perSource: limiter('source'), perConnection: limiter('connection'), total: limiter('total') } };
const app = await openApp({ auth: signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], mcp }), transport });
const { world } = app;
after(() => app.close());

const [root, ada, bo] = [user('root'), user('ada'), user('bo')];
const ci = 'token:ci';

/** Root runs the instance. Ada and Bo are members, each on a browser session and a CLI's; Ada has a personal token. `ci` is a service account. */
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  forgetDocuments();
  fetched = [];
  open.source = true;
  open.total = true;
  const adas = identity(ada);
  const bos = identity(bo);
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', [])),
    ...rows('principals', principal(root, { role: 'owner' }), principal(ada), principal(bo), principal(ci)),
    ...rows('identities', adas, bos),
    ...rows('credentials',
      credential('root-cli', root), credential('ada-web', ada, { kind: 'browser', identityId: adas.id }), credential('ada-cli', ada),
      credential('ada-pat', ada, { kind: 'personal', scope: '[]' }), credential('bo-web', bo, { kind: 'browser', identityId: bos.id }), credential('bo-cli', bo),
      credential('ci-token', ci, { scope: '[]' })),
  );
  // The schema's question, asked once of a fresh app.
  await app.request('/api/auth');
  app.calls.length = 0;
});

/** What a request cost: the vault's calls and the app's statements. */
async function cost<T>(request: () => Promise<T>): Promise<[T, string[], number]> {
  app.calls.length = 0;
  const before = app.statements;
  const answer = await request();
  return [answer, [...app.calls], app.statements - before];
}

function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}

type Ask = { client_id: string; redirect_uri: string; scope?: string; state?: string; resource?: string; code_challenge?: string; code_challenge_method?: string; response_type?: string };

function request(client: string, redirect: string, challenge: string, extra: Partial<Ask> = {}): Ask {
  return { client_id: client, redirect_uri: redirect, response_type: 'code', code_challenge: challenge, code_challenge_method: 'S256', state: 'st-1', resource: RESOURCE, ...extra };
}

/** Ada's browser, on coffre's own consent page, or another credential by its label. */
const as = (label: string): Record<string, string> => (label.endsWith('-web') ? { cookie: `${SESSION}=${label}`, 'sec-fetch-site': 'same-origin' } : { authorization: `Bearer ${label}` });

async function describeAs(label: string, ask: Partial<Ask>): Promise<Response> {
  return app.request(`/api/oauth/authorizations?${new URLSearchParams(ask)}`, { headers: as(label) });
}

async function describe(ask: Partial<Ask>, label = 'ada-web') {
  const response = await describeAs(label, ask);
  assert.equal(response.status, 200, await response.clone().text());
  return response.json() as Promise<Record<string, unknown>>;
}

function decideAs(label: string, ask: Partial<Ask>, answer: { approve: boolean; scopes?: string[] }): Promise<Response> {
  return app.request('/api/oauth/authorizations', {
    method: 'POST',
    headers: { ...as(label), 'content-type': 'application/json' },
    body: JSON.stringify({ request: ask, approve: answer.approve, scopes: answer.scopes ?? [] }),
  });
}

async function decide(ask: Partial<Ask>, answer: { approve: boolean; scopes?: string[] }, label = 'ada-web'): Promise<URL> {
  const response = await decideAs(label, ask, answer);
  assert.equal(response.status, 200, await response.clone().text());
  return new URL(((await response.json()) as { redirect: string }).redirect);
}

function form(path: string, fields: Record<string, string>): Promise<Response> {
  return app.request(path, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(fields).toString() });
}

/** What the token endpoint answered: its status and body. */
async function token(fields: Record<string, string>): Promise<[number, Record<string, unknown>]> {
  const response = await form('/api/oauth/token', fields);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  return [response.status, (await response.json()) as Record<string, unknown>];
}

type Tokens = { access_token: string; refresh_token: string; expires_in: number; scope: string; token_type: string };

/** Consent, then the code exchanged: what a client holds once its person approved. */
async function connect({ label = 'ada-web', client = CLAUDE_CODE, redirect = 'http://localhost:51234/callback', scope = 'read', ticked }: { label?: string; client?: string; redirect?: string; scope?: string; ticked?: string[] } = {}) {
  const { verifier, challenge } = pkce();
  const back = await decide(request(client, redirect, challenge, { scope }), { approve: true, scopes: ticked ?? scope.split(' ') }, label);
  const code = back.searchParams.get('code')!;
  const [status, body] = await token({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: redirect, client_id: client, resource: RESOURCE });
  assert.equal(status, 200, JSON.stringify(body));
  return { ...(body as Tokens), code, verifier, redirect, client };
}

/** Who a token is at the API: their principal, or the error. */
async function whoIs(label: string): Promise<string> {
  const response = await app.request('/api/me', { headers: { authorization: `Bearer ${label}` } });
  const body = (await response.json()) as { principal?: { id: string }; error?: string };
  return body.principal?.id ?? `${response.status} ${body.error}`;
}

/** The MCP connections of a person, as stored: those standing. */
const standing = async (who: string) =>
  (await rowsOf<{ id: string }>(world.owner, sql`SELECT id::text FROM credentials WHERE principal = ${who} AND kind = 'mcp' AND ancestors IS NULL AND revoked_at IS NULL ORDER BY created_at`)).map((row) => row.id);

const refresh = (held: Tokens & { client: string }, more: Record<string, string> = {}) => token({ grant_type: 'refresh_token', refresh_token: held.refresh_token, client_id: held.client, ...more });

test('the metadata documents say where the authorization server is, and what it takes', async () => {
  for (const path of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']) {
    const [response, calls, statements] = await cost(() => app.request(path));
    assert.deepEqual([response.status, calls, statements], [200, [], 0]);
    assert.deepEqual(await response.json(), { resource: RESOURCE, authorization_servers: [PUBLIC_URL], scopes_supported: ['read'], bearer_methods_supported: ['header'], resource_name: 'coffre at secrets.acme.example' });
  }
  const server = (await (await app.request('/.well-known/oauth-authorization-server')).json()) as Record<string, unknown>;
  assert.deepEqual([server.issuer, server.authorization_endpoint, server.token_endpoint, server.registration_endpoint, server.revocation_endpoint], [
    PUBLIC_URL, `${PUBLIC_URL}/oauth/authorize`, `${PUBLIC_URL}/api/oauth/token`, `${PUBLIC_URL}/api/oauth/register`, `${PUBLIC_URL}/api/oauth/revoke`]);
  assert.deepEqual(server.code_challenge_methods_supported, ['S256']);
  assert.equal(server.client_id_metadata_document_supported, true);
  assert.equal((await app.request('/.well-known/oauth-authorization-server', { method: 'POST' })).status, 405);
});

test('Claude Code connects: its document fetched, any loopback port, consent, the code once; its tokens are good nowhere in the API', async () => {
  const { verifier, challenge } = pkce();
  const ask = request(CLAUDE_CODE, 'http://localhost:51234/callback', challenge);
  const [view, calls, statements] = await cost(() => describe(ask));
  assert.deepEqual(view, {
    status: 'ready', client: { id: CLAUDE_CODE, name: 'Claude Code', host: 'claude.ai', registration: 'cimd' }, redirectHost: 'localhost',
    loopbackOnly: true, scopes: ['read'], connections: [], days: 30,
  });
  assert.deepEqual([calls, statements], [['caller'], 1]);
  const back = await decide(ask, { approve: true, scopes: ['read'] });
  assert.equal(`${back.origin}${back.pathname}`, 'http://localhost:51234/callback');
  assert.deepEqual([back.searchParams.get('state'), back.searchParams.get('iss')], ['st-1', PUBLIC_URL]);
  const code = back.searchParams.get('code')!;
  assert.match(code, /^[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(fetched, [CLAUDE_CODE], 'fetched once, then kept');

  const redeem = { grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: 'http://localhost:51234/callback', client_id: CLAUDE_CODE, resource: RESOURCE };
  const [status, body] = await token(redeem);
  assert.equal(status, 200, JSON.stringify(body));
  const tokens = body as Tokens;
  assert.match(tokens.access_token, /^coffre_mcp_[A-Za-z0-9_-]{43}$/);
  assert.match(tokens.refresh_token, /^coffre_mcr_[A-Za-z0-9_-]{43}$/);
  assert.deepEqual([tokens.token_type, tokens.scope], ['Bearer', 'read']);
  assert.ok(tokens.expires_in > 3590 && tokens.expires_in <= 3600, String(tokens.expires_in));
  // An MCP client's tokens are good at /mcp and the token endpoint alone, as in 0.14.7.
  assert.equal(await whoIs(tokens.access_token), '401 unauthenticated');
  assert.equal(await whoIs(tokens.refresh_token), '401 unauthenticated');
  assert.equal((await app.vault.caller({ token: createHash('sha256').update(tokens.access_token).digest('hex'), proof: null, request: null, ip: null }) as { principal: string }).principal, ada);

  // The code again: whoever holds it now is not who it was for. The connection ends.
  const [again, replayed] = await token(redeem);
  assert.deepEqual([again, replayed.error], [400, 'invalid_grant']);
  assert.match(String(replayed.error_description), /used already; the connection it made is ended/);
  assert.deepEqual(await standing(ada), []);
  assert.deepEqual((await refresh({ ...tokens, client: CLAUDE_CODE }))[1].error, 'invalid_grant');
});

test("Claude's hosted app connects with its callback on claude.ai; a redirect elsewhere is never sent anything", async () => {
  const { challenge } = pkce();
  const view = await describe(request(CLAUDE, 'https://claude.ai/api/mcp/auth_callback', challenge));
  assert.deepEqual([view.status, view.redirectHost, view.loopbackOnly], ['ready', 'claude.ai', false]);
  for (const redirect of ['https://evil.example/callback', 'https://claude.ai/api/mcp/other', `https://claude.ai/${'x'.repeat(400)}`]) {
    const refused = await describe(request(CLAUDE, redirect, challenge));
    assert.deepEqual(Object.keys(refused).sort(), ['message', 'status']);
    assert.equal(refused.status, 'invalid');
    const decided = await decideAs('ada-web', request(CLAUDE, redirect, challenge), { approve: true });
    assert.equal(decided.status, 400);
  }
  for (const client of ['', 'https://unknown.example/client.json', 'not-a-client', '00000000-0000-4000-8000-000000000000', `https://claude.ai/${'x'.repeat(300)}`]) {
    assert.equal((await describe(request(client, 'https://claude.ai/api/mcp/auth_callback', challenge))).status, 'invalid', client);
  }
  // A client the vault could not keep is refused on the page, its document unfetched for an id longer than the vault keeps.
  assert.equal((await describe(request(LONG_ID, 'https://long.example/cb', challenge))).status, 'invalid');
  assert.equal((await describe(request(LONG_REDIRECTS, LONG_REDIRECT, challenge))).status, 'invalid');
  assert.deepEqual(fetched.filter((url) => url.startsWith('https://long.example/')), [LONG_REDIRECTS]);
  // An id Postgres would not take is no client's: said on the page, and refused on Approve, with nothing read.
  // Half of a surrogate pair reaches only Approve: a URL's query carries it as U+FFFD.
  for (const client of ['\0', 'https://claude.ai/oauth/x\0']) {
    const [view, , statements] = await cost(() => describe(request(client, 'https://claude.ai/api/mcp/auth_callback', challenge)));
    assert.deepEqual([view.status, statements], ['invalid', 0], JSON.stringify(client));
  }
  for (const client of ['\0', 'https://claude.ai/oauth/x\0', '\ud800', 'https://claude.ai/oauth/x\udc00']) {
    const [decided, , statements] = await cost(() => decideAs('ada-web', request(client, 'https://claude.ai/api/mcp/auth_callback', challenge), { approve: true }));
    assert.deepEqual([decided.status, statements], [400, 0], JSON.stringify(client));
  }
  assert.deepEqual(await standing(ada), []);
});

test("a client that names itself nothing is shown by its host, cut to the name the vault keeps, and connects", async () => {
  const { challenge } = pkce();
  const name = LONG_HOST.slice(0, 100);
  for (const client of [UNNAMED, EMPTY_NAME]) {
    const ask = request(client, `https://${LONG_HOST}/cb`, challenge);
    const view = await describe(ask);
    assert.deepEqual([view.status, (view.client as { name: string }).name], ['ready', name], client);
    assert.equal((await decide(ask, { approve: true })).searchParams.has('code'), true, client);
  }
  assert.equal((await standing(ada)).length, 2);
});

test('what is wrong past the client and its redirect goes back to the client, as OAuth says', async () => {
  const { challenge } = pkce();
  const redirect = 'http://127.0.0.1:4000/callback';
  const cases: [Partial<Ask>, string][] = [
    [{ response_type: 'token' }, 'unsupported_response_type'],
    [{ code_challenge_method: 'plain' }, 'invalid_request'],
    [{ code_challenge: 'short' }, 'invalid_request'],
    [{ state: 'x'.repeat(1025) }, 'invalid_request'],
    [{ resource: 'https://elsewhere.example/mcp' }, 'invalid_target'],
    [{ scope: 'read admin' }, 'invalid_scope'],
  ];
  for (const [wrong, error] of cases) {
    const ask = request(CLAUDE_CODE, redirect, challenge, wrong);
    const view = await describe(ask);
    assert.equal(view.status, 'refused', error);
    const back = new URL(view.redirect as string);
    assert.deepEqual([`${back.origin}${back.pathname}`, back.searchParams.get('error'), back.searchParams.get('iss')], [redirect, error, PUBLIC_URL]);
    // Approve on a request that cannot be approved sends the same, and makes nothing.
    assert.equal((await decide(ask, { approve: true })).searchParams.get('error'), error);
  }
  // A resource with a trailing slash is the MCP endpoint all the same.
  assert.equal((await describe(request(CLAUDE_CODE, redirect, challenge, { resource: `${RESOURCE}/` }))).status, 'ready');
  assert.deepEqual(await standing(ada), []);
});

test('a person who denies sends the client access_denied, and nothing is written', async () => {
  const { challenge } = pkce();
  const [back, calls, statements] = await cost(() => decide(request(CLAUDE_CODE, 'http://localhost/callback', challenge), { approve: false }));
  assert.deepEqual([back.searchParams.get('error'), back.searchParams.get('state'), back.searchParams.get('code')], ['access_denied', 'st-1', null]);
  assert.deepEqual([calls, statements], [['caller'], 0]);
  assert.deepEqual(await rowsOf(world.owner, sql`SELECT id FROM credentials WHERE kind = 'mcp'`), []);
});

test('only a person, on a session of theirs, connects an app: a personal token or a service account is refused before anything is fetched', async () => {
  const { challenge } = pkce();
  const ask = request(CLAUDE_CODE, 'http://localhost/callback', challenge);
  for (const label of ['ada-pat', 'ci-token']) {
    for (const response of [await describeAs(label, ask), await decideAs(label, ask, { approve: true })]) {
      assert.equal(response.status, 403, label);
      assert.equal(((await response.json()) as { reason: string }).reason, 'no_access');
    }
  }
  assert.deepEqual(fetched, []);
  // A CLI session is a session of theirs.
  assert.equal((await describe(ask, 'ada-cli')).status, 'ready');
});

test('scopes: read always; the rest as the person ticked, asked for or not; the token says which', async () => {
  const tokens = await connect({ scope: 'read', ticked: ['reveal', 'write', 'nonsense'] });
  assert.equal(tokens.scope, 'read write reveal');
  const narrow = await connect({ scope: 'read write', ticked: [] });
  assert.equal(narrow.scope, 'read');
});

test('refresh tokens rotate, may narrow the scopes, never widen them, and a replaced one presented again ends the connection', async () => {
  const first = await connect({ scope: 'read reveal' });
  const [status, body] = await refresh(first, { scope: 'read' });
  assert.equal(status, 200, JSON.stringify(body));
  const second = { ...(body as Tokens), client: first.client };
  assert.equal(second.scope, 'read');
  assert.notEqual(second.refresh_token, first.refresh_token);
  // Narrowed to reveal, `read` comes with it, as with every connection.
  assert.equal((await refresh(second, { scope: 'reveal' }))[1].scope, 'read reveal');
  // The refresh token before the one replaced last is unknown, and ends nothing (0.14.7); the one replaced last is a copy someone else holds.
  assert.deepEqual((await refresh(first))[1].error, 'invalid_grant');
  assert.equal((await standing(ada)).length, 1);
  const [reused, again] = await refresh(second);
  assert.deepEqual([reused, again.error], [400, 'invalid_grant']);
  assert.match(String(again.error_description), /used already; the connection it made is ended/);
  assert.deepEqual(await standing(ada), [], 'and so the connection ended');

  const other = await connect({ scope: 'read' });
  const [widened, wide] = await refresh(other, { scope: 'read write' });
  assert.deepEqual([widened, wide.error], [400, 'invalid_scope']);
  assert.deepEqual([(await refresh(other, { scope: 'read bogus' }))[1].error, (await refresh(other, { client_id: CLAUDE }))[1].error, (await refresh(other, { client_id: '\0' }))[1].error], ['invalid_scope', 'invalid_grant', 'invalid_grant']);
  assert.equal((await standing(ada)).length, 1, 'a refused refresh ends nothing');
});

test('a code is for its client, its redirect and its verifier only (its minute, the vault holds: packages/vault/test/mcp.test.ts)', async () => {
  const { verifier, challenge } = pkce();
  const redirect = 'http://localhost:7000/callback';
  const code = (await decide(request(CLAUDE_CODE, redirect, challenge), { approve: true })).searchParams.get('code')!;
  const redeem = { grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: redirect, client_id: CLAUDE_CODE };
  for (const [wrong, words] of [
    [{ client_id: CLAUDE }, 'another client'], [{ redirect_uri: 'http://localhost:7001/callback' }, 'not the one the code was sent to'],
    [{ redirect_uri: 'ftp://localhost/callback' }, 'not the one the code was sent to'], [{ code_verifier: pkce().verifier }, 'does not match'],
    [{ code_verifier: 'short' }, 'does not match'], [{ resource: 'https://elsewhere.example/mcp' }, 'issues tokens for'], [{ code: 'unknown' }, 'unknown code'],
    // Text the vault cannot take is refused here, not left to fault there.
    [{ client_id: '\0' }, 'another client'], [{ redirect_uri: `${redirect}\0` }, 'not the one the code was sent to'],
  ] as const) {
    const [status, body] = await token({ ...redeem, ...wrong });
    assert.equal(status, 400, JSON.stringify(wrong));
    assert.match(String(body.error_description), new RegExp(words), JSON.stringify(wrong));
  }
  assert.deepEqual((await token({ ...redeem, grant_type: 'password' }))[1].error, 'unsupported_grant_type');
  assert.deepEqual((await token({ grant_type: 'authorization_code', code })).slice(0, 1), [400]);
  // Refused, each wrote nothing: the code is good still.
  assert.equal((await token(redeem))[0], 200);
});

test('revocation, by either token, ends the connection; anything else is answered the same, and a stranger\'s string asks the vault nothing', async () => {
  const first = await connect();
  // Another client's token, or one that is not coffre's, ends nothing.
  for (const fields of [{ token: first.refresh_token, client_id: CLAUDE }, { token: first.refresh_token, client_id: '\0' }, { token: 'coffre_mcp_nonsense' }, { token: 'whatever' }] as Record<string, string>[]) {
    const [response, calls] = await cost(() => form('/api/oauth/revoke', fields));
    assert.equal(response.status, 200);
    assert.deepEqual(calls, fields.client_id === CLAUDE ? ['change'] : [], JSON.stringify(fields));
  }
  assert.equal((await standing(ada)).length, 1);
  const [revoked, calls, statements] = await cost(() => form('/api/oauth/revoke', { token: first.access_token, client_id: CLAUDE_CODE }));
  assert.deepEqual([revoked.status, revoked.headers.get('cache-control'), calls, statements], [200, 'no-store', ['change'], 0]);
  assert.deepEqual(await standing(ada), []);
  assert.deepEqual((await refresh(first))[1].error, 'invalid_grant');

  const second = await connect();
  assert.equal((await form('/api/oauth/revoke', { token: second.refresh_token })).status, 200);
  assert.deepEqual(await standing(ada), []);
  assert.equal((await form('/api/oauth/revoke', { token: second.refresh_token })).status, 200, 'ended once, answered the same');
  assert.equal((await form('/api/oauth/revoke', {})).status, 400);
});

test('registration keeps the redirects coffre accepts and leaves out the rest, as Cursor needs; its app connects by its row', async () => {
  const register = (body: unknown) => app.request('/api/oauth/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const [response, calls, statements] = await cost(() => register({ client_name: 'Cursor', redirect_uris: ['cursor://anysphere.cursor-retrieval/oauth/callback', 'http://127.0.0.1/callback', 'https://cursor.example/cb'], token_endpoint_auth_method: 'none' }));
  assert.deepEqual([response.status, calls, statements], [201, ['change'], 0]);
  const registered = (await response.json()) as Record<string, unknown>;
  assert.match(String(registered.client_id), /^[0-9a-f-]{36}$/);
  assert.deepEqual([registered.client_name, registered.redirect_uris, registered.token_endpoint_auth_method], ['Cursor', ['http://127.0.0.1/callback', 'https://cursor.example/cb'], 'none']);
  assert.equal(typeof registered.client_id_issued_at, 'number');

  const client = String(registered.client_id);
  const { challenge } = pkce();
  const view = await describe(request(client, 'http://127.0.0.1:9999/callback', challenge));
  assert.deepEqual([view.status, view.client, view.loopbackOnly], ['ready', { id: client, name: 'Cursor', host: null, registration: 'dcr' }, false]);
  assert.equal((await describe(request(client, 'https://cursor.example/other', challenge))).status, 'invalid');
  const tokens = await connect({ client, redirect: 'http://127.0.0.1:9999/callback' });
  assert.equal(tokens.scope, 'read');
  assert.deepEqual(fetched, [], 'a registration is its row, never fetched');

  for (const [body, error] of [
    [{ client_name: 'Secretive', redirect_uris: ['https://x.example/cb'], token_endpoint_auth_method: 'client_secret_basic' }, 'invalid_client_metadata'],
    [{ client_name: 'Nowhere', redirect_uris: ['cursor://only'] }, 'invalid_redirect_uri'],
    [{ client_name: 'Nul', redirect_uris: ['https://x.example/cb\0'] }, 'invalid_redirect_uri'],
    [{ client_name: 'Half', redirect_uris: ['https://x.example/\udc00'] }, 'invalid_redirect_uri'],
    [{ client_name: 'Many', redirect_uris: Array.from({ length: 11 }, (_, i) => `https://x.example/${i}`) }, 'invalid_redirect_uri'],
    [['not', 'an', 'object'], 'invalid_client_metadata'],
  ] as const) {
    const refused = await register(body);
    assert.deepEqual([refused.status, ((await refused.json()) as { error: string }).error], [400, error]);
  }
  // A name that is all control characters, or none: called what it is.
  const unnamed = (await (await register({ client_name: '\u0007​', redirect_uris: ['https://x.example/cb'] })).json()) as Record<string, unknown>;
  assert.equal(unnamed.client_name, 'Unnamed app');
  const half = (await (await register({ client_name: '\udc00', redirect_uris: ['https://x.example/cb'] })).json()) as Record<string, unknown>;
  assert.equal(half.client_name, 'Unnamed app', 'half of a surrogate pair is no text');
  const long = (await (await register({ client_name: `${'a'.repeat(99)} b`, redirect_uris: ['https://x.example/cb'] })).json()) as Record<string, unknown>;
  assert.equal(long.client_name, 'a'.repeat(99), 'cut, then trimmed');
});

test('the endpoints anyone may call pass their limits first, and a JSON token request is refused', async () => {
  open.source = false;
  for (const path of ['/api/oauth/token', '/api/oauth/register', '/api/oauth/revoke']) {
    const [response, calls] = await cost(() => app.request(path, { method: 'POST', body: '{}' }));
    assert.deepEqual([response.status, response.headers.get('retry-after'), ((await response.json()) as { error: string }).error, calls], [429, '60', 'slow_down', []], path);
  }
  open.source = true;
  open.total = false;
  assert.equal((await form('/api/oauth/token', { grant_type: 'refresh_token' })).status, 429);
  open.total = true;
  const json = await app.request('/api/oauth/token', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ grant_type: 'refresh_token' }) });
  assert.deepEqual([json.status, ((await json.json()) as { error: string }).error], [400, 'invalid_request']);
  const twice = await app.request('/api/oauth/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'client_id=a&client_id=b' });
  assert.equal(twice.status, 400);
  // The consent page fetches a document within the same limits.
  open.total = false;
  const { challenge } = pkce();
  assert.deepEqual([(await describe(request(CLAUDE, 'https://claude.ai/api/mcp/auth_callback', challenge))).status, fetched], ['invalid', []]);
});

test("Connected apps lists a person's redeemed connections, and Disconnect ends one; an owner may end anyone's, no one else", async () => {
  const first = await connect({ scope: 'read reveal' });
  await connect({ client: CLAUDE, redirect: 'https://claude.ai/api/mcp/auth_callback' });
  // A consent whose code waits is no app yet.
  await decide(request(CLAUDE_CODE, 'http://localhost/callback', pkce().challenge), { approve: true });
  const list = async (label: string) => {
    const response = await app.request('/api/apps', { headers: as(label) });
    assert.equal(response.status, 200);
    return ((await response.json()) as { apps: Record<string, unknown>[] }).apps;
  };
  const [apps, calls, statements] = await cost(() => list('ada-web'));
  assert.deepEqual([calls, statements], [['caller'], 1]);
  assert.deepEqual(apps.map((one) => [one.name, one.host, one.registration, one.scopes]), [['Claude', 'claude.ai', 'cimd', ['read']], ['Claude Code', 'claude.ai', 'cimd', ['read', 'reveal']]]);
  for (const one of apps) assert.deepEqual(Object.keys(one).sort(), ['createdAt', 'expiresAt', 'host', 'id', 'lastUsedAt', 'lastUsedIp', 'name', 'registration', 'scopes']);
  assert.deepEqual(await list('bo-web'), []);

  const [newest, oldest] = apps.map((one) => String(one.id));
  // Bo may not end Ada's; told it is not there, as for any credential.
  const refused = await app.request(`/api/apps/${newest}`, { method: 'DELETE', headers: as('bo-web') });
  assert.deepEqual([refused.status, ((await refused.json()) as { error: string }).error], [404, 'not_found']);
  const [ended, endCalls, endStatements] = await cost(() => app.request(`/api/apps/${newest!.toUpperCase()}`, { method: 'DELETE', headers: as('ada-web') }));
  assert.deepEqual([ended.status, await ended.json(), endCalls, endStatements], [200, { disconnected: true }, ['change'], 0]);
  assert.equal((await app.request(`/api/apps/${oldest}`, { method: 'DELETE', headers: as('root-cli') })).status, 200, 'an owner ends anyone\'s');
  assert.deepEqual(await list('ada-web'), []);
  assert.deepEqual((await refresh(first))[1].error, 'invalid_grant');
});

test("the consent page's describe, asked with a cookie from another site, is refused before any client's document is fetched; the page's own render reads it", async () => {
  const { challenge } = pkce();
  const ask = request(CLAUDE_CODE, 'http://localhost:5000/callback', challenge);
  for (const headers of [{ cookie: `${SESSION}=ada-web`, 'sec-fetch-site': 'cross-site' }, { cookie: `${SESSION}=ada-web` }] as Record<string, string>[]) {
    const [response, calls] = await cost(() => app.request(`/api/oauth/authorizations?${new URLSearchParams(ask)}`, { headers }));
    assert.deepEqual([response.status, ((await response.json()) as { error: string }).error, calls], [403, 'cross_origin', []]);
  }
  assert.deepEqual(fetched, [], "another site's page made coffre fetch nothing");
  // The consent page embedded in another site, as a frame or an image, renders without describing.
  for (const dest of ['iframe', 'image']) {
    const embedded = await app.render({ headers: { cookie: `${SESSION}=ada-web`, 'sec-fetch-dest': dest } }, ({ client }) => client.oauth.describe(ask).catch((error: Error & { code?: string }) => error.code));
    assert.equal(await embedded.json(), 'cross_origin', dest);
  }
  assert.deepEqual(fetched, []);
  // The consent page's render, a top-level navigation in process with the cookie the browser sent it, is coffre itself.
  for (const headers of [{}, { 'sec-fetch-dest': 'document' }] as Record<string, string>[]) {
    const page = await app.render({ headers: { cookie: `${SESSION}=ada-web`, ...headers } }, ({ client }) => client.oauth.describe(ask));
    assert.equal(((await page.json()) as { status: string }).status, 'ready');
  }
  // A bearer token is no browser's, from any site.
  assert.equal((await describe(ask, 'ada-cli')).status, 'ready');
  assert.deepEqual(fetched, [CLAUDE_CODE]);
});

test('a step-up says which connections it ends: the client\'s narrower ones, once its code is redeemed', async () => {
  await connect({ scope: 'read' });
  await connect({ scope: 'read reveal' });
  const view = await describe(request(CLAUDE_CODE, 'http://localhost/callback', pkce().challenge, { scope: 'read reveal write' }));
  assert.deepEqual(view.connections, [['read', 'reveal']], 'the narrower one ended when the wider one was redeemed');
  await connect({ scope: 'read reveal write' });
  assert.equal((await standing(ada)).length, 1);
});

test("a registration written behind the vault connects nothing, and the person is told what any request is told of such a row", async () => {
  const response = await app.request('/api/oauth/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ client_name: 'Zed', redirect_uris: ['http://127.0.0.1/callback'] }) });
  const { client_id: client } = (await response.json()) as { client_id: string };
  await world.owner.execute(sql`UPDATE oauth_clients SET redirect_uris = '["https://evil.example/cb"]' WHERE id = ${client}::uuid`);
  // The page reads the row as it is; the vault, approving it, finds it is not its own.
  const ask = request(client, 'https://evil.example/cb', pkce().challenge);
  assert.equal((await describe(ask)).status, 'ready');
  const refused = await decideAs('ada-web', ask, { approve: true });
  assert.deepEqual([refused.status, ((await refused.json()) as { error: string }).error], [500, 'tampered']);
  assert.deepEqual(await standing(ada), []);
});
