// Placeholders (docs/design/credential-proxy.md, R13): a sensitive value is
// handed back to no person, on any credential of theirs, while a service
// account reads it as any other. A person's app holds handles for what the
// proxy covers, and the values its person reads as they are; only the
// credential proxy takes a handle:
// it opens the credential's values for them and injects them into the
// request, for the credential's upstream alone. Here Schumann's client, as
// Equisafe's backend has it, reaches a fake Schumann through the proxy with
// no change but its base URL, the proxy's stable URL in the app's own
// config, and its key, and the fake checks it got the real key.
import test, { after, before, mock } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { createClient, type CoffreClient } from '@coffre/client';
import { credential } from '@coffre/client/credential';
import { eq } from 'drizzle-orm';

import { clientFor, contextFor } from './api-fixture.ts';
import { callRaw, connect, db, deps, DEV, entries, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { credentials, environments } from './db/tables.ts';
import { coffreRoute } from '../src/app.ts';
import { authMac } from '../src/auth-rows.ts';
import { checkPlugins } from '../src/plugins.ts';
import { setSecurityHeaders } from '../src/security-headers.ts';
import { basic, credentialProxy, header, jwt, query, type CredentialProxyOptions, type Egress } from '../src/plugins/credential-proxy.ts';
import { vaultKv } from '../src/plugins/vault-kv.ts';

const KEY = 'sk_schumann_real_0123456789abcdef';
const WEBHOOK = 'whsec_local_only_0123456789';
/** A key with a Latin-1 letter, and a password with one past Latin-1. */
const ACCENT_KEY = 'clé-0123456789';
const U_PASS = 'pāssword-0123456789';
/** A user name the password begins with. */
const P_USER = 'acct_one';
const P_PASS = 'acct_one_unknownabcdefgh0123456789';
/** A key a JSON echo escapes. */
const QUOTED = 'q"uo\\te/d<&>0123';
/** A reader of a fork of dev, and never of dev. */
const FORKER = 'fork@acme.example';

/** The fake Schumann: what it received, and an answer that echoes the key when asked to. */
let upstream: Server;
let upstreamUrl: string;
const received: { method: string; url: string; headers: IncomingMessage['headers']; body: string }[] = [];

before(async () => {
  upstream = createServer((request, response) => {
    let body = '';
    request.on('data', (chunk: Buffer) => (body += chunk.toString()));
    request.on('end', () => {
      received.push({ method: request.method!, url: request.url!, headers: request.headers, body });
      if (![KEY, QUOTED, ACCENT_KEY].includes(String(request.headers['x-api-key'])) && request.headers.authorization === undefined && !request.url!.includes('key=')) {
        response.writeHead(401, { 'content-type': 'application/json' }).end('{"error":"bad key"}');
        return;
      }
      if (request.url!.includes('/echo')) {
        response.writeHead(200, { 'content-type': 'application/json', 'x-echo': String(request.headers['x-api-key']), 'set-cookie': 'upstream=1' });
        response.end(JSON.stringify({ youSent: request.headers['x-api-key'], authorization: request.headers.authorization, url: request.url }));
        return;
      }
      const key = String(request.headers['x-api-key']);
      if (request.url!.includes('/xml')) {
        // An XML error quoting the key, entities and all.
        const escaped = key.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        response.writeHead(400, { 'content-type': 'application/xml' }).end(`<Error><Message>bad key ${escaped}</Message></Error>`);
        return;
      }
      if (request.url!.includes('/python')) {
        // As Python's json.dumps writes it: every non-ASCII character escaped.
        response.writeHead(400, { 'content-type': 'application/json' }).end(JSON.stringify({ key }).replace(/[\u0080-\uffff]/g, (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`));
        return;
      }
      if (request.url!.includes('/utf8-header')) {
        // The key, as UTF-8 bytes in a header: the header arrived as Latin-1, one byte a character.
        response.writeHead(400, { 'content-type': 'text/plain', 'x-error-key': Buffer.from(Buffer.from(key, 'latin1').toString('latin1'), 'utf8').toString('latin1') }).end('no');
        return;
      }
      if (request.url!.includes('/utf8-location')) {
        // A redirect under the upstream, the key in its path as UTF-8 bytes.
        response.writeHead(302, { location: Buffer.from(`/accented/moved/${Buffer.from(key, 'latin1').toString('latin1')}`, 'utf8').toString('latin1') }).end();
        return;
      }
      if (request.url!.includes('/sse')) {
        // A heartbeat, then a pause before anything else: it must reach the client while the stream is still open.
        response.writeHead(200, { 'content-type': 'text/event-stream' });
        response.write(': heartbeat\n\n');
        setTimeout(() => response.end(`data: ${key}\n\n`), 300);
        return;
      }
      if (request.url!.includes('/reason')) {
        response.writeHead(401, `Invalid API key ${key}`, { 'content-type': 'text/plain' }).end('no');
        return;
      }
      if (request.url!.includes('/latin1')) {
        response.writeHead(200, { 'content-type': 'text/csv; charset=iso-8859-1' }).end(Buffer.from([0x63, 0x61, 0x66, 0xe9, 0x2c, 0xff, 0x0a]));
        return;
      }
      if (request.url!.includes('/echo-escaped')) {
        // As PHP's json_encode writes it: every slash escaped.
        response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ authorization: request.headers.authorization }).replaceAll('/', '\\/'));
        return;
      }
      if (request.url!.includes('/split')) {
        // The password, which begins with the user name, split after that much, the second part a moment later.
        response.writeHead(200, { 'content-type': 'text/plain' });
        response.write(`user ${P_USER} password acct_one`);
        setTimeout(() => response.end(`${P_PASS.slice('acct_one'.length)} end`), 30);
        return;
      }
      if (request.url!.includes('/geocode/bare')) {
        // A trailing-slash redirect that drops the query.
        response.writeHead(301, { location: `${upstreamUrl}/maps/geocode/` }).end();
        return;
      }
      if (request.url === '/token/' || request.url === '/token') {
        // An upstream at a path of its own, which canonicalizes away a trailing slash.
        if (request.url === '/token/') response.writeHead(308, { location: `${upstreamUrl}/token` }).end();
        else response.writeHead(200, { 'content-type': 'application/json' }).end('{"token":"t"}');
        return;
      }
      if (request.url!.includes('/geocode/redirect')) {
        // A trailing-slash redirect that keeps the query, key and all.
        response.writeHead(301, { location: `${upstreamUrl}/maps/geocode/?${request.url!.split('?')[1]}` }).end();
        return;
      }
      if (request.url!.includes('/redirect-key')) {
        response.writeHead(302, { location: `https://evil.example/${KEY}` }).end();
        return;
      }
      if (request.url!.includes('/cached')) {
        response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'public, max-age=3600', expires: 'Thu, 01 Jan 2099 00:00:00 GMT' }).end('{}');
        return;
      }
      if (request.url!.includes('/redirect-collide')) {
        // Under the upstream, at a path that begins with an environment's name, then a credential's.
        response.writeHead(307, { location: `${upstreamUrl}/v1/dev/maps/companies` }).end();
        return;
      }
      if (request.url!.includes('/redirect-inside')) {
        response.writeHead(302, { location: `${upstreamUrl}/v1/companies?page=2` }).end();
        return;
      }
      if (request.url!.includes('/redirect')) {
        response.writeHead(302, { location: 'https://evil.example/steal' }).end();
        return;
      }
      if (request.url!.includes('/emoji')) {
        // Split mid-pair, and a short multi-byte answer around it.
        response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
        const bytes = Buffer.from('😀xxxxxx héllo wörld 😀');
        response.write(bytes.subarray(0, 2));
        response.end(bytes.subarray(2));
        return;
      }
      response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ companies: [{ siren: '123' }], path: request.url, body }));
    });
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  upstreamUrl = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
});

after(() => new Promise<void>((resolve) => upstream.close(() => resolve())));

function proxyOptions(overrides: Partial<CredentialProxyOptions> = {}): CredentialProxyOptions {
  return {
    credentials: {
      schumann: { upstream: `${upstreamUrl}/v1`, inject: header('x-api-key', '{SCHUMANN_API_KEY}') },
      maps: { upstream: `${upstreamUrl}/maps`, inject: query('key', '{MAPS_KEY}'), methods: ['GET'] },
      twilio: { upstream: `${upstreamUrl}/twilio`, inject: basic('{TWILIO_SID}', '{TWILIO_TOKEN}'), paths: ['/Accounts'] },
      padded: { upstream: `${upstreamUrl}/padded`, inject: header('x-api-key', '{PADDED_KEY}') },
      quoted: { upstream: `${upstreamUrl}/quoted`, inject: header('x-api-key', '{QUOTED_KEY}') },
      prefixed: { upstream: `${upstreamUrl}/prefixed`, inject: basic('{P_USER}', '{P_PASS}') },
      accented: { upstream: `${upstreamUrl}/accented`, inject: header('x-api-key', '{ACCENT_KEY}') },
      broken: { upstream: `${upstreamUrl}/v1`, inject: header('x-api-key', '{BROKEN_KEY}') },
      token: { upstream: `${upstreamUrl}/token`, inject: header('x-api-key', '{SCHUMANN_API_KEY}') },
    },
    insecureUpstreams: true,
    ...overrides,
  };
}

useMcp(
  async () => {
    runtime.plugins = checkPlugins([credentialProxy(proxyOptions()), vaultKv()]);
    received.length = 0;
    const root = clientFor(deps, ROOT);
    await root.members.add(`user:${DEV}`);
    await root.members.add('token:ci');
    await root.projects.create('market');
    await root.environments.create('market/dev');
    await root.secrets.set('market/dev', {
      SCHUMANN_API_KEY: { value: KEY, sensitivity: 'sensitive' },
      MAPS_KEY: 'maps+real/key=0123456789',
      TWILIO_SID: { value: 'AC0123456789', plain: true },
      TWILIO_TOKEN: 'twilio_real_token_0??0123456789',
      WEBHOOK_SECRET: WEBHOOK,
      QUOTED_KEY: QUOTED,
      PADDED_KEY: `${KEY}\n`,
      BROKEN_KEY: 'sk_broken_0123\n456789',
      P_USER,
      P_PASS,
      ACCENT_KEY,
      U_PASS: { value: U_PASS, sensitivity: 'sensitive' },
      DATABASE_URL: { value: 'postgres://dev-db/market', sensitivity: 'sensitive' },
    });
    await root.access.set(`user:${DEV}`, { market: 'developer' });
    await root.access.set('token:ci', { 'market/dev': 'viewer' });
  },
);

/** The API as whoever `token` is, over coffre's own routes. */
function bearer(token: string): CoffreClient {
  return createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${token}` }), transport: (request) => coffreRoute(request, runtime, '203.0.113.7').then((response) => response!) });
}

async function refusal(promise: Promise<unknown>): Promise<{ status: number; reason: string | null }> {
  try {
    await promise;
  } catch (error) {
    const { status, reason } = error as { status: number; reason?: string };
    return { status, reason: reason ?? null };
  }
  throw new Error('it was not refused');
}

/** A handle for DEV on market/dev, as `coffre run` makes one with their session. */
async function handleFor(paths = ['market/dev']): Promise<string> {
  return (await bearer(await sessionFor(DEV)).handles.create({ label: 'coffre run market/dev', paths })).token;
}

/** Schumann's client as Equisafe's backend has it (`providers/schumann/client/api-client.ts`): a base URL, paths appended, `x-api-key`. */
class SchumannApiClient {
  readonly config: { baseUrl: string; apiKey: string };
  constructor(config: { baseUrl: string; apiKey: string }) {
    this.config = config;
  }
  async get<T>(path: string): Promise<T> {
    const response = await fetchThrough(`${this.config.baseUrl}${path}`, { headers: { 'x-api-key': this.config.apiKey, accept: 'application/json' } });
    if (!response.ok) throw new Error(`Schumann answered ${response.status}: ${await response.text()}`);
    return (await response.json()) as T;
  }
}

/** The app's fetch, where it reaches coffre: in process here. */
function fetchThrough(input: string | URL | Request, init?: RequestInit): Promise<Response> {
  const request = new Request(input, init);
  if (!request.url.startsWith(ORIGIN)) return fetch(request);
  return coffreRoute(request, runtime, '203.0.113.7').then((response) => response!);
}

test('a sensitive value opens for no person, on any credential of theirs nor through MCP; a service account reads it', async () => {
  const session = await sessionFor(DEV);
  const sensitive = ['DATABASE_URL', 'SCHUMANN_API_KEY', 'U_PASS'];
  // A whole environment's read leaves them out, by name; a read of one is refused.
  const whole = await bearer(session).secrets.reveal('market/dev');
  assert.deepEqual([...whole.sensitive].sort(), sensitive);
  assert.equal(whole.values.SCHUMANN_API_KEY, undefined);
  assert.equal(whole.values.WEBHOOK_SECRET, WEBHOOK);
  assert.deepEqual(await refusal(bearer(session).secrets.reveal('market/dev/SCHUMANN_API_KEY')), { status: 403, reason: 'sensitive' });
  const pat = await bearer(session).tokens.issue(`user:${DEV}`, { label: 'agent', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  assert.deepEqual([...(await bearer(pat.token).secrets.reveal('market/dev')).sensitive].sort(), sensitive);
  assert.deepEqual(await refusal(bearer(pat.token).secrets.reveal('market/dev/U_PASS')), { status: 403, reason: 'sensitive' });
  // The Owner too: no person's credential is an exception.
  assert.deepEqual(await refusal(bearer(await sessionFor(ROOT)).secrets.reveal('market/dev/SCHUMANN_API_KEY')), { status: 403, reason: 'sensitive' });
  // Nor does a dry run say whether a guess was right: the right one is `changed` too.
  assert.deepEqual({ ...(await bearer(session).secrets.dryRun('market/dev', { SCHUMANN_API_KEY: KEY })).keys }, { SCHUMANN_API_KEY: 'changed' });
  const mcp = await connect(DEV, 'read reveal');
  const revealed = await callRaw(mcp, 'reveal_secret_values', { path: 'market/dev' });
  const { values, sensitive: left } = revealed.body.result!.structuredContent! as { values: Record<string, string>; sensitive: string[] };
  assert.equal(values.SCHUMANN_API_KEY, undefined);
  assert.deepEqual([...left].sort(), sensitive);
  const one = await callRaw(mcp, 'reveal_secret_values', { path: 'market/dev/SCHUMANN_API_KEY' });
  assert.equal(one.body.result!.isError, true);
  assert.equal(JSON.stringify(one.body).includes(KEY), false);
  assert.match(JSON.stringify(one.body), /sensitive/);

  // The vault refused each read of one, and logged it: the app's API holds no rule of its own for this.
  const refused = (await entries('secret.read')).filter((entry) => entry.decision === 'deny' && entry.author === 'vault');
  assert.ok(refused.length >= 4);
  assert.ok(refused.every((entry) => entry.code === 'sensitive'));

  // A service account's reads are values, as in CI.
  const ci = (await runtime.signin!.issueServiceToken(await contextFor(deps, ROOT), 'ci', { label: 'ci', expiresInDays: 1 })).token;
  assert.equal((await bearer(ci).secrets.reveal('market/dev')).values.SCHUMANN_API_KEY, KEY);
});

test('a handle stands in for its environment and reaches nothing but the proxy; minting it is logged, and it is revoked as a token is', async () => {
  const session = await sessionFor(DEV);
  const made = await bearer(session).handles.create({ label: 'coffre run market/dev', paths: ['market/dev'] });
  assert.match(made.token, /^coffre_use_[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(made.scope, { 'market/dev': 'viewer' });
  assert.ok(Math.abs(Date.parse(made.expiresAt) - Date.now() - 12 * 3_600_000) < 60_000, 'twelve hours unless told');
  const [created] = (await entries('token.create')).filter((entry) => entry.metadata.kind === 'handle');
  assert.equal(created!.actor, `user:${DEV}`);

  // Not the API, not a plugin's API: a handle is no bearer token.
  assert.deepEqual(await refusal(bearer(made.token).me()), { status: 403, reason: 'handle' });
  assert.equal((await route('/v1/secret/data/market/dev', { headers: { 'x-vault-token': made.token } })).status, 403);
  // Nor a handle making a service token, a binding, or another handle: it can make nothing.
  assert.equal((await refusal(bearer(made.token).tokens.issue('token:ci', { label: 'x', expiresInDays: 1 }))).status, 403);
  assert.equal((await refusal(bearer(made.token).handles.create({ label: 'x', paths: ['market/dev'] }))).status, 403);

  // Revoked as a personal token is: by its person, from the list of their tokens.
  const listed = await bearer(session).tokens.list(`user:${DEV}`);
  assert.ok(listed.tokens.some((token) => token.id === made.id));
  const schumann = new SchumannApiClient({ baseUrl: `${ORIGIN}/use/market/dev/schumann`, apiKey: made.token });
  runtime.plugins = checkPlugins([credentialProxy(proxyOptions({ cacheSeconds: 0 }))]);
  await schumann.get('/companies');
  // A request whose body is still coming when the handle is revoked sends nothing: the handle is checked as it goes out.
  let finish!: () => void;
  const slow = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode('{"a":'));
      finish = () => {
        controller.enqueue(new TextEncoder().encode('1}'));
        controller.close();
      };
    },
  });
  const pending = route('/use/market/dev/schumann/companies', { method: 'POST', headers: { 'x-api-key': made.token, 'content-type': 'application/json' }, body: slow, duplex: 'half' } as RequestInit);
  await new Promise((resolve) => setTimeout(resolve, 20));
  await bearer(session).tokens.revoke(`user:${DEV}`, made.id);
  const before = received.length;
  finish();
  assert.equal((await pending).status, 401);
  assert.equal(received.length, before, 'nothing reached Schumann');
  await assert.rejects(schumann.get('/companies'), /Schumann answered 401/);
});

test("a personal token makes handles within its scope and its end, and never a service token or a binding: the Owner's escape is a service token", async () => {
  const session = await sessionFor(DEV);
  const pat = await bearer(session).tokens.issue(`user:${DEV}`, { label: 'agent', expiresInMinutes: 30, scope: { 'market/dev': 'viewer' } });
  const handle = await bearer(pat.token).handles.create({ label: 'agent run', paths: ['market/dev'] });
  assert.ok(Date.parse(handle.expiresAt) <= Date.parse(pat.expiresAt), 'it ends no later than the token that made it');
  await clientFor(deps, ROOT).environments.create('market/prod');
  assert.equal((await refusal(bearer(pat.token).handles.create({ label: 'x', paths: ['market/prod'] }))).status, 403, 'nothing past its scope');
  // The service-token route is the escape hatch, and a person's token, which gets placeholders, does not reach it.
  assert.equal((await refusal(bearer(pat.token).tokens.issue('token:ci', { label: 'x', expiresInDays: 1 }))).status, 403);
  assert.equal((await refusal(bearer(pat.token).bindings.create('token:ci', { profile: 'github', claims: { repository: 'acme/market' } } as never))).status, 403);
  // A service account holds no handle: it reads its values.
  const ci = (await runtime.signin!.issueServiceToken(await contextFor(deps, ROOT), 'ci', { label: 'ci', expiresInDays: 1 })).token;
  assert.equal((await refusal(bearer(ci).handles.create({ label: 'x', paths: ['market/dev'] }))).status, 403);
});

test("Schumann's own client, its base URL the proxy's stable URL and its key from `coffre run`, reaches the fake Schumann with the real key, and nothing else does", async () => {
  const handle = await handleFor();
  const plan = (await (await route('/use/market/dev', { headers: { authorization: `Bearer ${handle}` } })).json()) as { env: Record<string, string>; credentials: Record<string, string>; left: string[] };
  assert.equal(plan.env.SCHUMANN_API_KEY, handle);
  assert.equal(Object.keys(plan.env).some((key) => key.endsWith('_BASE_URL')), false, 'the app sets its base URLs itself');
  assert.equal(plan.credentials.schumann, `${ORIGIN}/use/market/dev/schumann`, "the helper's: the environment's URL");

  // The app's own config, the same for every environment: `local` maps to the stable URL.
  const schumann = new SchumannApiClient({ baseUrl: `${ORIGIN}/use/schumann`, apiKey: plan.env.SCHUMANN_API_KEY! });
  const answer = await schumann.get<{ companies: unknown[]; path: string }>('/companies?q=acme');
  assert.deepEqual(answer.companies, [{ siren: '123' }]);
  assert.equal(answer.path, '/v1/companies?q=acme');
  const [sent] = received;
  assert.equal(sent!.headers['x-api-key'], KEY, 'the real key, at the edge');
  assert.equal(JSON.stringify(sent!.headers).includes(handle), false, 'and never the handle');
  assert.equal(sent!.headers.cookie, undefined);

  // The same through the helper, which sends the handle as x-coffre-handle.
  const helper = credential('schumann', { COFFRE_CREDENTIALS: JSON.stringify(plan.credentials), COFFRE_HANDLE: handle }, fetchThrough);
  assert.equal((await helper.fetch('/companies')).status, 200);
  assert.equal(received[1]!.headers['x-api-key'], KEY);

  // One opening of the credential's keys for the minute, however many calls: the vault's read, and the proxy's entry naming it.
  await schumann.get('/companies');
  const uses = (await entries('credential.use')).filter((entry) => entry.metadata.credential === 'schumann');
  assert.equal(uses.length, 1);
  assert.deepEqual(uses[0]!.metadata.keys, ['SCHUMANN_API_KEY']);
  assert.equal(uses[0]!.metadata.host, new URL(upstreamUrl).host);
  const reads = (await entries('secret.read')).filter((entry) => entry.author === 'vault' && entry.decision === 'allow' && entry.metadata.purpose === 'use');
  assert.equal(reads.length, 1);
  assert.equal(reads[0]!.operationId, uses[0]!.operationId);
});

test("a credential with an egress leaves through it, never the global fetch, as the proxy made the request: the real key in, the same checks, the log saying so", async () => {
  // Schuman's allowlist sees one address: the request leaves through the deployment's binding, a fake here, which answers itself.
  const sent: { input: URL; init: RequestInit; body: string }[] = [];
  let answer = (input: URL) => Response.json({ path: input.pathname + input.search });
  const egress: Egress = {
    async fetch(input, init) {
      sent.push({ input, init, body: init.body === undefined ? '' : new TextDecoder().decode(init.body as Uint8Array) });
      return answer(input);
    },
  };
  const options = proxyOptions();
  options.credentials.schumann = { ...options.credentials.schumann!, egress };
  runtime.plugins = checkPlugins([credentialProxy(options)]);
  const global = mock.method(globalThis, 'fetch');
  try {
    const handle = await handleFor();
    const call = (path: string, init: RequestInit = {}) => route(`/use/schumann${path}`, { ...init, headers: { 'x-api-key': handle, ...(init.headers as Record<string, string> | undefined) } });

    const got = await call('/companies?q=acme', { method: 'POST', headers: { 'content-type': 'application/json', cookie: 'coffre=1' }, body: '{"siren":"123"}' });
    assert.equal(got.status, 200);
    assert.deepEqual(await got.json(), { path: '/v1/companies?q=acme' });
    assert.equal(sent.length, 1);
    const [one] = sent;
    assert.equal(one!.input.href, `${upstreamUrl}/v1/companies?q=acme`, 'the upstream URL, its host the one the binding reaches');
    assert.equal(one!.init.method, 'POST');
    assert.equal(one!.init.redirect, 'manual');
    assert.equal(one!.body, '{"siren":"123"}');
    const headers = new Headers(one!.init.headers);
    assert.equal(headers.get('x-api-key'), KEY, 'the real key, injected before it leaves');
    assert.equal(headers.get('content-type'), 'application/json');
    assert.equal(headers.get('cookie'), null);
    assert.equal([...headers].some(([, value]) => value.includes(handle)), false);
    assert.equal(received.length, 0, 'the fake Schumann, which the global fetch reaches, got nothing');
    assert.equal(global.mock.callCount(), 0);

    // The answer is the upstream's as the proxy hands any back: redacted, no-store, its redirects kept on the proxy.
    answer = () => new Response(JSON.stringify({ youSent: KEY }), { headers: { 'content-type': 'application/json', 'cache-control': 'max-age=60' } });
    const echoed = await call('/echo');
    assert.equal((await echoed.text()).includes(KEY), false);
    assert.equal(echoed.headers.get('cache-control'), 'no-store');
    answer = () => new Response(null, { status: 302, headers: { location: 'https://evil.example/steal' } });
    assert.equal((await call('/redirect')).status, 502);

    // Refused before it leaves, as without an egress: the handle in the body, a path out of the upstream.
    const before = sent.length;
    assert.equal((await call('/companies', { method: 'POST', body: JSON.stringify({ token: handle }) })).status, 400);
    assert.equal((await call('/a%2Fb')).status, 400);
    assert.equal(sent.length, before);

    // A binding that fails is the upstream not answering, said as the egress.
    answer = () => {
      throw new Error('tunnel down');
    };
    const down = await call('/companies');
    assert.equal(down.status, 502);
    assert.match((await down.json()).message, /did not answer through schumann's egress: tunnel down/);
    // One that quotes the request it failed on says nothing of the key.
    answer = (input) => {
      throw new Error(`could not send ${input.href} with x-api-key: ${KEY}`);
    };
    const quoted = (await (await call('/companies')).json()) as { message: string };
    assert.equal(quoted.message.includes(KEY), false, quoted.message);
    assert.match(quoted.message, /x-api-key: \[redacted by coffre\]/);

    // A credential without one still leaves through the global fetch.
    assert.equal((await route('/use/market/dev/maps/geocode?key=' + handle)).status, 200);
    assert.equal(global.mock.callCount(), 1);
    assert.equal(received.length, 1);

    // The log says which credentials' openings went out through their egress, and nothing of the binding.
    const uses = (await entries('credential.use')).filter((entry) => entry.metadata.plan !== true);
    assert.deepEqual(uses.map((entry) => [entry.metadata.credential, entry.metadata.host, entry.metadata.egress]), [
      ['schumann', new URL(upstreamUrl).host, true],
      ['maps', new URL(upstreamUrl).host, undefined],
    ]);
  } finally {
    global.mock.restore();
  }
});

test('the proxy sends nothing outside the upstream, follows no redirect, redacts an echoed key, and keeps the handle and cookies from the upstream', async () => {
  const handle = await handleFor();
  const call = (path: string, init: RequestInit = {}) =>
    route(`/use/market/dev/schumann${path}`, { ...init, headers: { 'x-api-key': handle, ...(init.headers as Record<string, string> | undefined) } });

  const echoed = await call('/echo');
  assert.equal(echoed.status, 200);
  const text = await echoed.text();
  assert.equal(text.includes(KEY), false);
  assert.match(text, /redacted by coffre/);
  assert.equal(echoed.headers.get('x-echo'), '[redacted by coffre]');
  assert.equal(echoed.headers.get('set-cookie'), null);

  // A redirect elsewhere never reaches the app, which would follow it with the handle; one under the upstream is the proxy's URL for it.
  const redirect = await call('/redirect');
  assert.equal(redirect.status, 502);
  assert.equal(redirect.headers.get('location'), null);
  assert.equal(received.filter((request) => request.url.includes('steal')).length, 0);
  const told = await call('/redirect-key');
  assert.equal(told.status, 502);
  assert.equal((await told.text()).includes(KEY), false, 'the refusal names no destination');
  const cached = await call('/cached');
  assert.equal(cached.headers.get('cache-control'), 'no-store', 'no cache on the way keeps an answer for the next caller');
  assert.equal(cached.headers.get('expires'), null);
  const quoted = await route('/use/market/dev/quoted/echo', { headers: { 'x-api-key': handle } });
  const echoedJson = await quoted.text();
  assert.equal(JSON.stringify(JSON.parse(echoedJson)).includes(JSON.stringify(QUOTED).slice(1, -1)), false, echoedJson);
  assert.equal(JSON.parse(echoedJson).youSent, '[redacted by coffre]');
  const inside = await call('/redirect-inside');
  assert.equal(inside.status, 302);
  assert.equal(inside.headers.get('location'), `${ORIGIN}/use/market/dev/schumann/companies?page=2`);

  // The handle goes nowhere else: not in a body, not inside another header's Basic authentication.
  assert.equal((await call('/companies', { method: 'POST', body: JSON.stringify({ token: handle }) })).status, 400);
  assert.equal((await call('/companies', { headers: { 'x-coffre-handle': handle, 'x-api-key': '', authorization: `Basic ${btoa(`client:${handle}`)}` } })).status, 400);

  // A body is read no further than the limit, whatever it declares.
  let sent = 0;
  const endless = new ReadableStream<Uint8Array>({
    pull(controller) {
      sent += 1024 * 1024;
      controller.enqueue(new Uint8Array(1024 * 1024));
      if (sent > 64 * 1024 * 1024) controller.close();
    },
  });
  const big = await route('/use/market/dev/schumann/upload', { method: 'POST', headers: { 'x-api-key': handle }, body: endless, duplex: 'half' } as RequestInit);
  assert.equal(big.status, 413);
  assert.ok(sent <= 20 * 1024 * 1024, `read ${sent} bytes`);

  // Redaction keeps text whole: a pair split across chunks, multi-byte letters.
  const emoji = await call('/emoji');
  assert.equal(await emoji.text(), '😀xxxxxx héllo wörld 😀');
  // On coffre's origin, an upstream's document runs nothing: sandboxed, an origin of its own, which coffre's headers keep.
  assert.equal(emoji.headers.get('content-security-policy'), "sandbox; default-src 'none'; frame-ancestors 'none'");
  const page = setSecurityHeaders(new Response('<script>fetch("/api/me")</script>', { headers: emoji.headers }), { nonce: 'n', publicUrl: ORIGIN });
  assert.match(page.headers.get('content-security-policy')!, /^sandbox; default-src 'none'/);
  assert.match(setSecurityHeaders(new Response('x', { headers: { 'content-security-policy': 'sandbox allow-scripts allow-same-origin' } }), { nonce: 'n', publicUrl: ORIGIN }).headers.get('content-security-policy')!, /^default-src 'self'/, 'a sandbox that allows anything back is replaced');

  // A dot segment, encoded or not, is resolved before coffre sees it, out of the credential's path altogether; an encoded slash is refused.
  for (const path of ['/../admin', '/%2e%2e/admin', '/.%2E/admin']) assert.equal((await call(path)).headers.get('coffre-proxy'), 'refused', path);
  for (const path of ['/a%2Fb', '/a%5Cb', '/a%2fb%2f..%2f..']) {
    const climbed = await call(path);
    assert.equal(climbed.status, 400, path);
    assert.equal(climbed.headers.get('coffre-proxy'), 'refused');
  }
  assert.equal((await call('/companies', { headers: { 'x-other': handle } })).status, 400, 'the handle goes nowhere but where the key goes');
  assert.equal((await call('/companies?token=' + handle)).status, 400);
  assert.equal((await call(`/%FF/${handle.replace('_', '%5F')}`)).status, 400, 'encoded, beside a byte that is no UTF-8');
  assert.equal((await route('/use/market/dev/schumann/companies')).status, 401, 'no handle, no request');
  assert.equal((await route('/use/market/dev/nope/companies', { headers: { 'x-api-key': handle } })).status, 404);
  assert.equal(received.every((request) => request.url.startsWith('/v1/') || request.url.startsWith('/quoted/')), true);
});

test('query and Basic credentials, with their methods and paths', async () => {
  // A Basic password past Latin-1, here only, its user Twilio's plain account id.
  const options = proxyOptions();
  runtime.plugins = checkPlugins([credentialProxy({ ...options, credentials: { ...options.credentials, ubasic: { upstream: `${upstreamUrl}/ubasic`, inject: basic('{TWILIO_SID}', '{U_PASS}') } } })]);
  const handle = await handleFor();
  const maps = await route(`/use/market/dev/maps/geocode?address=paris&key=${handle}`);
  assert.equal(maps.status, 200);
  assert.equal(new URL(received.at(-1)!.url, 'http://x').searchParams.get('key'), 'maps+real/key=0123456789');
  assert.equal((await route(`/use/market/dev/maps/geocode?key=${handle}`, { method: 'POST' })).status, 405);

  // Twilio as its client calls it, from the plan: the account's id in the path and as the user, the handle as the token.
  const plan = (await (await route('/use/market/dev', { headers: { authorization: `Bearer ${handle}` } })).json()) as { env: Record<string, string> };
  assert.equal(plan.env.TWILIO_SID, 'AC0123456789', 'plain, as it is');
  assert.equal(plan.env.TWILIO_TOKEN, handle);
  const basicAuth = `Basic ${btoa(`${plan.env.TWILIO_SID}:${plan.env.TWILIO_TOKEN}`)}`;
  const twilio = await route(`/use/market/dev/twilio/Accounts/${plan.env.TWILIO_SID}/Messages.json`, { method: 'POST', headers: { authorization: basicAuth, 'content-type': 'application/x-www-form-urlencoded' }, body: 'To=%2B33600000000&Body=hi' });
  assert.equal(twilio.status, 200);
  const sent = received.at(-1)!;
  assert.equal(sent.headers.authorization, `Basic ${btoa('AC0123456789:twilio_real_token_0??0123456789')}`);
  assert.equal(sent.body, 'To=%2B33600000000&Body=hi');
  assert.equal((await route('/use/market/dev/twilio/Other', { headers: { authorization: basicAuth } })).status, 403);

  // Basic's base64 echoed as PHP writes JSON, slashes escaped, is no way back to the token either.
  const precondition = btoa('AC0123456789:twilio_real_token_0??0123456789');
  assert.ok(precondition.includes('/'), 'a base64 with a slash in it');
  const escaped = (await (await route('/use/market/dev/twilio/Accounts/echo-escaped', { headers: { authorization: basicAuth } })).json()) as { authorization: string };
  assert.equal(escaped.authorization, 'Basic [redacted by coffre]');

  // A password that begins with the user name, split right after it: neither shows, nor any of the rest.
  const prefixed = await (await route('/use/market/dev/prefixed/split', { headers: { authorization: `Basic ${btoa(`${handle}:${handle}`)}` } })).text();
  assert.equal(prefixed, 'user [redacted by coffre] password [redacted by coffre] end');

  // The encodings an honest upstream quotes a key in: XML's entities, Python's \u escapes, a reason phrase.
  // A key Headers trims on the way out is redacted as it went out.
  const padded = await (await route('/use/market/dev/padded/echo', { headers: { 'x-api-key': handle } })).text();
  assert.equal(padded.includes(KEY), false, padded);
  const xml = await (await route('/use/market/dev/quoted/xml', { headers: { 'x-api-key': handle } })).text();
  assert.equal(xml, '<Error><Message>bad key [redacted by coffre]</Message></Error>');
  const python = await (await route('/use/market/dev/accented/python', { headers: { 'x-api-key': handle } })).text();
  assert.equal(python, '{"key":"[redacted by coffre]"}');
  const header = await route('/use/market/dev/accented/utf8-header', { headers: { 'x-api-key': handle } });
  assert.equal(header.headers.get('x-error-key'), '[redacted by coffre]');
  const relocated = await route('/use/market/dev/accented/utf8-location', { headers: { 'x-api-key': handle } });
  assert.equal(relocated.status, 302);
  assert.equal(decodeURIComponent(relocated.headers.get('location')!).includes('0123456789'), false, relocated.headers.get('location')!);
  // An event stream's heartbeat comes through at once, and its end still redacted.
  const stream = (await route('/use/market/dev/schumann/sse', { headers: { 'x-api-key': handle } })).body!.getReader();
  const started = Date.now();
  const first = new TextDecoder().decode((await stream.read()).value);
  assert.equal(first, ': heartbeat\n\n');
  assert.ok(Date.now() - started < 250, 'before the upstream says more');
  let restOfStream = '';
  for (let part = await stream.read(); !part.done; part = await stream.read()) restOfStream += new TextDecoder().decode(part.value);
  assert.equal(restOfStream, 'data: [redacted by coffre]\n\n');

  // A value no header can carry is refused, and quoted nowhere: not in the answer, not in a log.
  const logged: unknown[] = [];
  const error = console.error;
  console.error = (...args: unknown[]) => void logged.push(...args);
  let broken: Response;
  try {
    broken = await route('/use/market/dev/broken/companies', { headers: { 'x-api-key': handle } });
  } finally {
    console.error = error;
  }
  assert.equal(broken.status, 409);
  assert.equal(JSON.stringify([await broken.text(), logged.map(String)]).includes('456789'), false);
  const reason = await route('/use/market/dev/schumann/reason', { headers: { 'x-api-key': handle } });
  assert.equal(reason.statusText.includes(KEY), false, reason.statusText);
  // A body in another charset passes byte for byte.
  assert.deepEqual([...new Uint8Array(await (await route('/use/market/dev/schumann/latin1', { headers: { 'x-api-key': handle } })).arrayBuffer())], [0x63, 0x61, 0x66, 0xe9, 0x2c, 0xff, 0x0a]);
  // Basic takes a password past Latin-1, as UTF-8.
  assert.equal((await route('/use/market/dev/ubasic/Accounts', { headers: { authorization: basicAuth } })).status, 200);
  assert.equal(received.at(-1)!.headers.authorization, `Basic ${Buffer.from(`AC0123456789:${U_PASS}`).toString('base64')}`);

  // A redirect under the upstream that keeps the key's parameter keeps the handle there, for an unchanged client to follow.
  const moved = await route(`/use/market/dev/maps/geocode/redirect?address=paris&key=${handle}`);
  assert.equal(moved.status, 301);
  const to = new URL(moved.headers.get('location')!);
  assert.equal(to.origin + to.pathname, `${ORIGIN}/use/market/dev/maps/geocode/`);
  assert.equal(to.searchParams.get('key'), handle);
  assert.equal(to.searchParams.get('address'), 'paris');
  const helped = await route('/use/market/dev/maps/geocode/redirect?key=unused', { headers: { 'x-coffre-handle': handle } });
  assert.equal(new URL(helped.headers.get('location')!).searchParams.get('key'), handle, 'a parameter that stands in for no handle gets the handle instead');
  const bare = await route(`/use/market/dev/maps/geocode/bare?key=${handle}`);
  assert.equal(new URL(bare.headers.get('location')!).searchParams.get('key'), handle, 'a query the redirect dropped gets the handle back');

  // The credential's own URL is its upstream's, with no slash added: no loop with an upstream that drops one.
  const own = await route('/use/market/dev/token', { headers: { 'x-api-key': handle } });
  assert.equal(own.status, 200);
  assert.equal(received.at(-1)!.url, '/token');
  const slashed = await route('/use/market/dev/token/', { headers: { 'x-api-key': handle } });
  assert.equal(slashed.status, 308);
  assert.equal(slashed.headers.get('location'), `${ORIGIN}/use/market/dev/token`);

  // An upstream echoing what it got gives back neither form of the keys: Basic's base64, the query's encoding.
  const echoedBasic = await (await route('/use/market/dev/twilio/Accounts/echo', { headers: { authorization: basicAuth } })).text();
  assert.equal(echoedBasic.includes(btoa('AC0123456789:twilio_real_token_0??0123456789')), false, echoedBasic);
  assert.equal(echoedBasic.includes('twilio_real_token'), false);
  const echoedQuery = await (await route(`/use/market/dev/maps/echo?key=${handle}`)).text();
  assert.equal(echoedQuery.includes(encodeURIComponent('maps+real/key=0123456789')) || echoedQuery.includes('maps%2Breal%2Fkey%3D0123456789') || echoedQuery.includes('maps+real'), false, echoedQuery);
});

test('a handle for a fork reads what it inherits, and one for dev@me stands in for the personal config', async () => {
  const root = clientFor(deps, ROOT);
  await root.environments.create('market/dev-eu', { from: 'dev', inherit: true });
  const session = await sessionFor(DEV);
  const fork = await bearer(session).handles.create({ label: 'run', paths: ['market/dev-eu'] });
  assert.deepEqual(fork.scope, { 'market/dev-eu': 'viewer', 'market/dev': 'viewer' }, 'and the parent it inherits from, which DEV reads');
  const inherited = await route('/use/market/dev-eu/schumann/companies', { headers: { 'x-api-key': fork.token } });
  assert.equal(inherited.status, 200, await inherited.clone().text());
  assert.equal(received.at(-1)!.headers['x-api-key'], KEY);

  // A local database the app is given, said a secret: saying nothing, it would be as sensitive as dev's (decision 27).
  await clientFor(deps, DEV).secrets.set('market/dev@me', { DATABASE_URL: { value: 'postgres://localhost/dev', sensitivity: 'secret' } });
  const mine = await bearer(session).handles.create({ label: 'run', paths: ['market/dev@me'] });
  assert.deepEqual(mine.scope, { 'market/dev': 'viewer' });
  const plan = (await (await route('/use/market/dev@me', { headers: { authorization: `Bearer ${mine.token}` } })).json()) as { env: Record<string, string> };
  assert.equal(plan.env.DATABASE_URL, 'postgres://localhost/dev', "the personal config's own value, not dev's");
  assert.equal(plan.env.WEBHOOK_SECRET, WEBHOOK, "dev's secret, which its owner reads through dev anyway");
});

test("the stable URL, /use/<credential>, is the handle's environment's: a fork's, a personal config's, or a refusal that names the environment's", async () => {
  const handle = await handleFor();
  const stable = (path: string, token = handle, init: RequestInit = {}) => route(`/use/schumann${path}`, { ...init, headers: { 'x-api-key': token, ...(init.headers as Record<string, string> | undefined) } });
  const root = await stable('');
  assert.equal(((await root.json()) as { path: string }).path, '/v1', 'the credential itself is its upstream');
  // One opening for the environment, whichever URL names it.
  assert.equal((await route('/use/market/dev/schumann/companies', { headers: { 'x-api-key': handle } })).status, 200);
  assert.equal((await entries('credential.use')).filter((entry) => entry.metadata.credential === 'schumann').length, 1);
  // A redirect under the upstream stays on the proxy, at the environment's URL, which nothing else can mean.
  assert.equal((await stable('/redirect-inside')).headers.get('location'), `${ORIGIN}/use/market/dev/schumann/companies?page=2`);

  // No handle where Schumann takes its key, nor as x-coffre-handle, and nothing goes: a bearer is the plan's.
  const sent = received.length;
  for (const headers of [{}, { authorization: `Bearer ${handle}` }, { 'x-api-key': 'sk_guess' }] as Record<string, string>[]) {
    const refused = await route('/use/schumann/companies', { headers });
    assert.equal(refused.status, 401, JSON.stringify(headers));
    assert.equal(refused.headers.get('coffre-proxy'), 'refused');
  }
  assert.equal(received.length, sent);

  // A fork's handle reads what it inherits; a personal config's, its own value over dev's.
  const session = await sessionFor(DEV);
  await clientFor(deps, ROOT).environments.create('market/dev-eu', { from: 'dev', inherit: true });
  const fork = await bearer(session).handles.create({ label: 'run', paths: ['market/dev-eu'] });
  assert.equal((await stable('/companies', fork.token)).status, 200);
  assert.equal(received.at(-1)!.headers['x-api-key'], KEY);
  await clientFor(deps, DEV).secrets.set('market/dev@me', { SCHUMANN_API_KEY: QUOTED });
  const mine = await bearer(session).handles.create({ label: 'run', paths: ['market/dev@me'] });
  assert.equal((await stable('/companies', mine.token)).status, 200);
  assert.equal(received.at(-1)!.headers['x-api-key'], QUOTED, "the personal config's");
  assert.equal((await stable('/companies', await handleFor())).status, 200);
  assert.equal(received.at(-1)!.headers['x-api-key'], KEY, "dev's, for a run of dev");

  // A handle for several environments names none: the environment's URL does, and still works.
  const both = await bearer(session).handles.create({ label: 'run', paths: ['market/dev', 'market/dev-eu'] });
  const ambiguous = await stable('/companies', both.token);
  assert.equal(ambiguous.status, 409);
  assert.match(((await ambiguous.json()) as { message: string }).message, new RegExp(`2 environments.*${ORIGIN}/use/market/dev/schumann or ${ORIGIN}/use/market/dev-eu/schumann`));
  assert.equal((await route('/use/market/dev-eu/schumann/companies', { headers: { 'x-api-key': both.token } })).status, 200);

  // Renamed, it is the same environment: the handle keeps it by id, and the stable URL follows within the cache's minute.
  runtime.plugins = checkPlugins([credentialProxy(proxyOptions({ cacheSeconds: 0 }))]);
  await clientFor(deps, ROOT).environments.update('market/dev-eu', { slug: 'europe' });
  assert.equal((await stable('/companies', fork.token)).status, 200);
  const moved = await stable('/companies', both.token);
  assert.match(((await moved.json()) as { message: string }).message, new RegExp(`${ORIGIN}/use/market/europe/schumann`));
  // Deleted, it still counts: the handle was made for two, and the stable URL picks neither.
  await clientFor(deps, ROOT).environments.update('market/europe', { archived: true });
  await clientFor(deps, ROOT).environments.delete('market/europe');
  assert.equal((await stable('/companies', both.token)).status, 409);
  assert.equal((await stable('/companies', fork.token)).status, 409, 'nor any, for a handle whose one environment is gone');
});

test('/use/<a>/<b>/… names an environment exactly when <a>/<b> is one the handle was made for, a project named like a credential included', async () => {
  const root = clientFor(deps, ROOT);
  await root.projects.create('schumann');
  await root.environments.create('schumann/dev');
  await root.secrets.set('schumann/dev', { SCHUMANN_API_KEY: KEY, MAPS_KEY: 'maps_of_schumann_0123456789' });
  await root.access.set(`user:${DEV}`, { market: 'developer', schumann: 'developer' });
  const session = await sessionFor(DEV);
  const handle = (await bearer(session).handles.create({ label: 'run', paths: ['schumann/dev'] })).token;
  const path = async (url: string, headers: Record<string, string>) => {
    const response = await route(url, { headers });
    assert.equal(response.status, 200, `${url}: ${await response.clone().text()}`);
    return received.at(-1)!.url;
  };
  assert.equal(await path('/use/schumann/dev/schumann/companies', { 'x-api-key': handle }), '/v1/companies', "the environment's");
  assert.equal(await path('/use/schumann/companies', { 'x-api-key': handle }), '/v1/companies', 'the stable URL');
  assert.equal(await path(`/use/schumann/dev/maps/geocode?key=${handle}`, {}), '/maps/geocode?key=maps_of_schumann_0123456789', 'another credential of the environment, its key where that one takes it');
  const plan = await route('/use/schumann/dev', { headers: { authorization: `Bearer ${handle}` } });
  assert.equal(((await plan.json()) as { environment: string }).environment, 'schumann/dev', 'and its plan');
  // For a run of market/dev, schumann/dev is no environment of the handle's: it is a path under Schumann's upstream.
  assert.equal(await path('/use/schumann/dev/companies', { 'x-api-key': await handleFor() }), '/v1/dev/companies');
  // A redirect from the stable URL to Schumann's /v1/dev/maps/… keeps to Schumann: on the stable URL it would read as schumann/dev's maps.
  const moved = await route('/use/schumann/redirect-collide', { method: 'POST', headers: { 'x-api-key': handle }, body: '{}' });
  const location = moved.headers.get('location')!;
  assert.equal(location, `${ORIGIN}/use/schumann/dev/schumann/dev/maps/companies`);
  assert.equal(await path(location.slice(ORIGIN.length), { 'x-api-key': handle }), '/v1/dev/maps/companies');
});

test("a handle keeps the environments it was made for under its row's MAC; one of 0.8, which has none, gets no stable URL rather than a guess", async () => {
  const made = await bearer(await sessionFor(DEV)).handles.create({ label: 'run', paths: ['market/dev@me', 'market/dev@me'] });
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.id, made.id));
  const [dev] = await db.owner.select({ id: environments.id }).from(environments).where(eq(environments.slug, 'dev'));
  assert.deepEqual(JSON.parse(row!.places!), [{ environmentId: dev!.id, personal: true }], 'by id, as asked, once each');
  const at = (token: string) => route('/use/schumann/companies', { headers: { 'x-api-key': token } });
  assert.equal((await at(made.token)).status, 200);

  // Edited around the app, it is refused: the places are the MAC's.
  const report = mock.method(console, 'error', () => {});
  try {
    runtime.plugins = checkPlugins([credentialProxy(proxyOptions())]);
    await db.owner.update(credentials).set({ places: JSON.stringify([{ environmentId: dev!.id, personal: false }]) }).where(eq(credentials.id, made.id));
    assert.equal((await at(made.token)).status, 401);
    assert.ok(report.mock.calls.some((call) => (call.arguments[0] as { event?: string } | undefined)?.event === 'auth_row_tampered'));
  } finally {
    report.mock.restore();
  }

  // As 0.8 made it: no paths, its MAC over 0.8's tuple. It works where it names its environment, and nowhere else.
  runtime.plugins = checkPlugins([credentialProxy(proxyOptions())]);
  const old = { ...row!, places: null };
  await db.owner.update(credentials).set({ places: null, authMac: authMac(deps.chainKey, 'credentials', old) }).where(eq(credentials.id, made.id));
  assert.equal((await route('/use/market/dev@me/schumann/companies', { headers: { 'x-api-key': made.token } })).status, 200);
  const refused = await at(made.token);
  assert.equal(refused.status, 409);
  assert.match(((await refused.json()) as { message: string }).message, /before coffre 0\.9.*coffre run/);
});

test('the plan: placeholders for what the proxy covers, and as they are the values its person reads where they are held, never a sensitive one', async () => {
  const root = clientFor(deps, ROOT);
  await root.environments.create('market/dev-eu', { from: 'dev', inherit: true });
  await root.members.add(`user:${FORKER}`);
  await root.access.set(`user:${FORKER}`, { 'market/dev-eu': 'viewer' });
  await root.secrets.set('market/dev@me', { EXTRA: 'mine' }).catch(() => undefined);
  await clientFor(deps, DEV).secrets.set('market/dev@me', { LOCAL_ONLY: 'x' });
  const plan = async (path: string, paths = [path.replace('@me', '')], who = DEV) => {
    const handle = (await bearer(await sessionFor(who)).handles.create({ label: 'run', paths: [path.includes('@me') ? 'market/dev' : paths[0]!] })).token;
    const response = await route(`/use/${path}`, { headers: { authorization: `Bearer ${handle}` } });
    assert.equal(response.status, 200, await response.clone().text());
    return (await response.json()) as { environment: string; env: Record<string, string>; left: string[] };
  };

  const dev = await plan('market/dev');
  assert.equal(dev.env.WEBHOOK_SECRET, WEBHOOK, 'a secret its person reads, and no credential');
  assert.equal(dev.env.MAPS_KEY?.startsWith('coffre_use_'), true, "a credential's secret is a placeholder");
  assert.equal(dev.env.SCHUMANN_API_KEY?.startsWith('coffre_use_'), true, "and a credential's sensitive one");
  assert.equal(dev.env.TWILIO_SID, 'AC0123456789', 'a plain value its credential names');
  assert.equal(dev.env.TWILIO_TOKEN?.startsWith('coffre_use_'), true);
  assert.deepEqual(dev.left, ['DATABASE_URL', 'U_PASS'], 'sensitive, and no credential: the app does without');
  assert.equal(JSON.stringify(dev).includes(KEY), false);

  // A fork's inherited values reach the app of whoever reads them where they are held: dev's reader, not the fork's alone.
  const fork = await plan('market/dev-eu');
  assert.equal(fork.env.WEBHOOK_SECRET, WEBHOOK);
  assert.equal(fork.env.SCHUMANN_API_KEY?.startsWith('coffre_use_'), true, 'its inherited keys are still placeholders');
  assert.deepEqual(fork.left, ['DATABASE_URL', 'U_PASS']);
  const forker = await plan('market/dev-eu', ['market/dev-eu'], FORKER);
  assert.equal(forker.env.WEBHOOK_SECRET, undefined, 'a reader of the fork alone, never of dev');
  assert.ok(forker.left.includes('WEBHOOK_SECRET'));

  const mine = await plan('market/dev@me');
  assert.equal(mine.environment, 'market/dev@me');
  assert.equal(mine.env.WEBHOOK_SECRET, WEBHOOK, "dev's, which its owner reads through dev");
  assert.equal(mine.env.LOCAL_ONLY, 'x', "and its own values, which only its owner wrote");
  assert.equal(mine.env.TWILIO_SID, 'AC0123456789', "dev's plain value");
  assert.deepEqual(mine.left, ['DATABASE_URL', 'U_PASS']);

  // Each value given is logged as the vault's read to expose, one entry per environment it opens in.
  const exposed = (await entries('secret.read')).filter((entry) => entry.author === 'vault' && entry.decision === 'allow' && entry.metadata.purpose === 'expose');
  assert.equal(exposed.length, 4);
});

test("a handle keeps what its person reads and uses at each place, both columns: an Owner's reads a protected prod as they do, a Developer's only uses it", async () => {
  const root = clientFor(deps, ROOT);
  await root.environments.create('market/prod');
  await root.secrets.set('market/prod', { WEBHOOK_SECRET: 'whsec_prod_0123456789' });
  await root.environments.protect('market/prod');
  const plan = async (who: string) => {
    const made = await bearer(await sessionFor(who)).handles.create({ label: 'run', paths: ['market/prod'] });
    const response = await route('/use/market/prod', { headers: { authorization: `Bearer ${made.token}` } });
    assert.equal(response.status, 200, await response.clone().text());
    return { made, plan: (await response.json()) as { env: Record<string, string>; left: string[] } };
  };
  const owner = await plan(ROOT);
  assert.deepEqual(owner.made.scope, { 'market/prod': 'viewer' });
  assert.equal(owner.plan.env.WEBHOOK_SECRET, 'whsec_prod_0123456789', 'the Owner reads prod, and so does their handle');
  const [stored] = await db.owner.select({ scope: credentials.scope }).from(credentials).where(eq(credentials.label, 'run'));
  assert.deepEqual((JSON.parse(stored!.scope!) as { permissions: unknown }[])[0]!.permissions, { normal: ['secret.read', 'secret.use'], protected: ['secret.read', 'secret.use'] });
  const developer = await plan(DEV);
  assert.deepEqual(developer.made.scope, { 'market/prod': 'contributor' });
  assert.equal(developer.plan.env.WEBHOOK_SECRET, undefined, 'a Developer only uses a protected prod');
  assert.deepEqual(developer.plan.left, ['WEBHOOK_SECRET']);
});

test("a handle made for dev reads its reference into a protected prod through dev, and reaches nothing else of prod", async () => {
  const root = clientFor(deps, ROOT);
  await root.environments.create('market/prod');
  await root.secrets.set('market/prod', { WEBHOOK_SECRET: 'whsec_prod_0123456789', MAPS_KEY: 'maps+prod/key=0123456789' });
  await root.secrets.set('market/dev', { WEBHOOK_SECRET: { ref: 'market/prod/WEBHOOK_SECRET' } });
  await root.environments.protect('market/prod');
  const made = await bearer(await sessionFor(ROOT)).handles.create({ label: 'run', paths: ['market/dev'] });
  // Made for dev, it holds dev alone: a reference's permissions are where it lives.
  assert.deepEqual(made.scope, { 'market/dev': 'viewer' });
  const response = await route('/use/market/dev', { headers: { authorization: `Bearer ${made.token}` } });
  assert.equal(response.status, 200, await response.clone().text());
  assert.equal(((await response.json()) as { env: Record<string, string> }).env.WEBHOOK_SECRET, 'whsec_prod_0123456789');
  // Prod itself, its plan or a credential of it, is no place the handle was made for.
  const sent = received.length;
  assert.equal((await route('/use/market/prod', { headers: { authorization: `Bearer ${made.token}` } })).status, 403);
  assert.equal((await route(`/use/market/prod/maps/geocode?address=paris&key=${made.token}`)).status, 403);
  assert.equal(received.length, sent, 'nothing reached an upstream');
});

test("a reference into a protected prod is handed to whoever reads dev, holding nothing in prod: its permissions are dev's", async () => {
  const root = clientFor(deps, ROOT);
  await root.environments.create('market/prod');
  await root.secrets.set('market/prod', { WEBHOOK_SECRET: 'whsec_prod_0123456789' });
  await root.secrets.set('market/dev', { WEBHOOK_SECRET: { ref: 'market/prod/WEBHOOK_SECRET' } });
  await root.environments.protect('market/prod');
  await root.members.add('user:dee@acme.example');
  await root.access.set('user:dee@acme.example', { 'market/dev': 'viewer' });
  const made = await bearer(await sessionFor('dee@acme.example')).handles.create({ label: 'run', paths: ['market/dev'] });
  const response = await route('/use/market/dev', { headers: { authorization: `Bearer ${made.token}` } });
  assert.equal(response.status, 200, await response.clone().text());
  assert.equal(((await response.json()) as { env: Record<string, string> }).env.WEBHOOK_SECRET, 'whsec_prod_0123456789');
  assert.equal((await route('/use/market/prod', { headers: { authorization: `Bearer ${made.token}` } })).status, 403);
});

test("a key named as an object's own property is still missing when the environment lacks it", async () => {
  runtime.plugins = checkPlugins([credentialProxy({ credentials: { odd: { upstream: `${upstreamUrl}/v1`, inject: header('x-api-key', '{constructor}') } }, insecureUpstreams: true })]);
  const handle = await handleFor();
  const missing = await route('/use/market/dev/odd/companies', { headers: { 'x-api-key': handle } });
  assert.equal(missing.status, 409);
  assert.equal(received.length, 0);
});

test("the configuration is checked: HTTPS upstreams, no private address, rules that name keys, and 0.9's expose and identifiers refused", () => {
  const make = (credentials: CredentialProxyOptions['credentials'], more: Partial<CredentialProxyOptions> = {}) => () => credentialProxy({ credentials, ...more });
  assert.throws(make({ a: { upstream: 'http://api.example.com', inject: header('x', '{K}') } }), /HTTPS/);
  assert.throws(make({ a: { upstream: 'https://10.0.0.8', inject: header('x', '{K}') } }), /private address/);
  assert.throws(make({ a: { upstream: 'https://169.254.169.254/latest', inject: header('x', '{K}') } }), /private address/);
  assert.throws(make({ a: { upstream: 'https://[::1]', inject: header('x', '{K}') } }), /private address/);
  assert.throws(make({ a: { upstream: 'https://localhost', inject: header('x', '{K}') } }), /private address/);
  // However it is written: a trailing dot, any case, IPv4 inside IPv6.
  for (const host of ['localhost.', 'LOCALHOST', 'api.localhost.', '127.0.0.1.', '[::ffff:10.0.0.8]', '[::7f00:1]', '[fe80::1]', '[64:ff9b::a00:8]']) {
    assert.throws(make({ a: { upstream: `https://${host}/v1`, inject: header('x', '{K}') } }), /private address/, host);
  }
  assert.throws(make({ a: { upstream: 'https://api.example.com', inject: header('x', 'static') } }), /names no key/);
  assert.throws(make({ A: { upstream: 'https://api.example.com', inject: header('x', '{K}') } }), /lowercase/);
  // `expose` and a credential's `identifiers` are gone in 0.10: refused at typecheck and at startup, saying what to do instead.
  // @ts-expect-error -- the type says each key says who sees it now
  assert.throws(make({}, { expose: { 'market/dev': ['WEBHOOK_SECRET'] } }), /expose is gone in 0\.10.*mark sensitive the keys no person may read/);
  // @ts-expect-error -- the type says to mark the key plain
  assert.throws(make({ twilio: { upstream: 'https://api.twilio.com', inject: basic('{SID}', '{TOKEN}'), identifiers: ['SID'] } }), /twilio's identifiers are gone in 0\.10: mark each key plain/);
  // `baseUrl` is gone in 0.9: refused at typecheck and at startup, naming the URL the app's config points at instead.
  // @ts-expect-error -- the type says where the URL goes now
  assert.throws(make({ schumann: { upstream: 'https://api.example.com', inject: header('x', '{K}'), baseUrl: 'SCHUMANN_BASE_URL' } }), /schumann's baseUrl is gone in 0\.9.*SCHUMANN_BASE_URL.*<publicUrl>\/use\/schumann/);
  // `standIn` is `placeholder` in 0.10: refused at typecheck and at startup, saying so.
  // @ts-expect-error -- the type says to rename it
  assert.throws(make({ dfns: { upstream: 'https://api.example.com', inject: header('authorization', 'Bearer {K}'), standIn: jwt() } }), /dfns's standIn is called placeholder in 0\.10: rename it/);
  // An egress named is one that fetches: a binding the Worker lacks, `undefined` with its key still there, fails the configuration.
  const env: { SCHUMANN_EGRESS?: Egress } = {};
  assert.throws(make({ schumann: { upstream: 'https://api.example.com', inject: header('x', '{K}'), egress: env.SCHUMANN_EGRESS } }), /schumann's egress is undefined, as a Worker's binding is when wrangler\.jsonc lacks it: add the binding, or remove egress/);
  // @ts-expect-error -- an egress has a fetch method
  assert.throws(make({ schumann: { upstream: 'https://api.example.com', inject: header('x', '{K}'), egress: {} } }), /schumann's egress has no fetch method/);
  // @ts-expect-error -- and is no null
  assert.throws(make({ schumann: { upstream: 'https://api.example.com', inject: header('x', '{K}'), egress: null } }), /schumann's egress has no fetch method/);
  assert.doesNotThrow(make({ schumann: { upstream: 'https://api.example.com', inject: header('x', '{K}'), egress: { fetch: (input, init) => fetch(input, init) } } }));
  assert.doesNotThrow(make({ a: { upstream: 'https://api.example.com/v1', inject: header('authorization', 'Bearer {K}') } }));
  assert.doesNotThrow(make({ a: { upstream: 'http://127.0.0.1:9000', inject: header('x', '{K}') } }, { insecureUpstreams: true }));
});
