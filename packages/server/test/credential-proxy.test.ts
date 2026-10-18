// Stand-ins (docs/design/credential-proxy.md, R13): where the vault gives
// people stand-ins, a person opens no value to be handed back, on any
// credential of theirs, while a service account reads values as before. A
// person's app holds handles instead, which only the credential proxy takes:
// it opens the credential's values for them and injects them into the
// request, for the credential's upstream alone. Here Schumann's client, as
// Equisafe's backend has it, reaches a fake Schumann through the proxy with
// no change but its base URL and key, and the fake checks it got the real key.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { createClient, type CoffreClient } from '@coffre/client';
import { credential } from '@coffre/client/credential';

import { clientFor, contextFor } from './api-fixture.ts';
import { callRaw, connect, deps, DEV, entries, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { coffreRoute } from '../src/app.ts';
import { checkPlugins } from '../src/plugins.ts';
import { setSecurityHeaders } from '../src/security-headers.ts';
import { basic, credentialProxy, header, query, type CredentialProxyOptions } from '../src/plugins/credential-proxy.ts';
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
      schumann: { upstream: `${upstreamUrl}/v1`, inject: header('x-api-key', '{SCHUMANN_API_KEY}'), baseUrl: 'SCHUMANN_BASE_URL' },
      maps: { upstream: `${upstreamUrl}/maps`, inject: query('key', '{MAPS_KEY}'), methods: ['GET'] },
      twilio: { upstream: `${upstreamUrl}/twilio`, inject: basic('{TWILIO_SID}', '{TWILIO_TOKEN}'), paths: ['/Accounts'] },
      quoted: { upstream: `${upstreamUrl}/quoted`, inject: header('x-api-key', '{QUOTED_KEY}') },
      prefixed: { upstream: `${upstreamUrl}/prefixed`, inject: basic('{P_USER}', '{P_PASS}') },
      accented: { upstream: `${upstreamUrl}/accented`, inject: header('x-api-key', '{ACCENT_KEY}') },
      ubasic: { upstream: `${upstreamUrl}/ubasic`, inject: basic('{TWILIO_SID}', '{U_PASS}') },
    },
    expose: { 'market/dev': ['WEBHOOK_SECRET'] },
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
      SCHUMANN_API_KEY: KEY,
      SCHUMANN_BASE_URL: 'https://api.schumann.example/v1',
      MAPS_KEY: 'maps+real/key=0123456789',
      TWILIO_SID: 'AC0123456789',
      TWILIO_TOKEN: 'twilio_real_token_0??0123456789',
      WEBHOOK_SECRET: WEBHOOK,
      QUOTED_KEY: QUOTED,
      P_USER,
      P_PASS,
      ACCENT_KEY,
      U_PASS,
      DATABASE_URL: 'postgres://dev-db/market',
    });
    await root.access.set(`user:${DEV}`, { market: 'developer' });
    await root.access.set('token:ci', { 'market/dev': 'viewer' });
  },
  { people: 'stand-ins' },
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

test('where people get stand-ins, a person opens no value on any credential of theirs, nor through MCP; a service account reads them', async () => {
  const session = await sessionFor(DEV);
  assert.deepEqual(await refusal(bearer(session).secrets.reveal('market/dev')), { status: 403, reason: 'stand_ins' });
  assert.deepEqual(await refusal(bearer(session).secrets.reveal('market/dev/SCHUMANN_API_KEY')), { status: 403, reason: 'stand_ins' });
  const pat = await bearer(session).tokens.issue(`user:${DEV}`, { label: 'agent', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  assert.deepEqual(await refusal(bearer(pat.token).secrets.reveal('market/dev')), { status: 403, reason: 'stand_ins' });
  // The Owner too: no person's credential is an exception.
  assert.deepEqual(await refusal(bearer(await sessionFor(ROOT)).secrets.reveal('market/dev')), { status: 403, reason: 'stand_ins' });
  // Nor a dry run, whose `changed` or `unchanged` says whether a guess was right.
  assert.deepEqual(await refusal(bearer(session).secrets.dryRun('market/dev', { SCHUMANN_API_KEY: 'guess' })), { status: 403, reason: 'stand_ins' });
  const mcp = await connect(DEV, 'read reveal');
  const revealed = await callRaw(mcp, 'reveal_secret_values', { path: 'market/dev' });
  assert.equal(JSON.stringify(revealed.body).includes(KEY), false);
  assert.match(JSON.stringify(revealed.body), /stand-ins/);

  // The vault refused each, and logged it: the app's API holds no rule of its own for this.
  const refused = (await entries('secret.read')).filter((entry) => entry.decision === 'deny' && entry.author === 'vault');
  assert.ok(refused.length >= 5);
  assert.ok(refused.every((entry) => entry.code === 'stand_ins'));

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
  await bearer(session).tokens.revoke(`user:${DEV}`, made.id);
  await assert.rejects(schumann.get('/companies'), /Schumann answered 401/);
});

test("a personal token makes handles within its scope and its end, and never a service token or a binding: the Owner's escape is a service token", async () => {
  const session = await sessionFor(DEV);
  const pat = await bearer(session).tokens.issue(`user:${DEV}`, { label: 'agent', expiresInMinutes: 30, scope: { 'market/dev': 'viewer' } });
  const handle = await bearer(pat.token).handles.create({ label: 'agent run', paths: ['market/dev'] });
  assert.ok(Date.parse(handle.expiresAt) <= Date.parse(pat.expiresAt), 'it ends no later than the token that made it');
  await clientFor(deps, ROOT).environments.create('market/prod');
  assert.equal((await refusal(bearer(pat.token).handles.create({ label: 'x', paths: ['market/prod'] }))).status, 403, 'nothing past its scope');
  // The service-token route is the escape hatch, and a stand-in principal's token does not reach it.
  assert.equal((await refusal(bearer(pat.token).tokens.issue('token:ci', { label: 'x', expiresInDays: 1 }))).status, 403);
  assert.equal((await refusal(bearer(pat.token).bindings.create('token:ci', { profile: 'github', claims: { repository: 'acme/market' } } as never))).status, 403);
  // A service account holds no handle: it reads its values.
  const ci = (await runtime.signin!.issueServiceToken(await contextFor(deps, ROOT), 'ci', { label: 'ci', expiresInDays: 1 })).token;
  assert.equal((await refusal(bearer(ci).handles.create({ label: 'x', paths: ['market/dev'] }))).status, 403);
});

test("Schumann's own client, its base URL and key from `coffre run`, reaches the fake Schumann with the real key, and nothing else does", async () => {
  const handle = await handleFor();
  const plan = (await (await route('/use/market/dev', { headers: { authorization: `Bearer ${handle}` } })).json()) as { env: Record<string, string>; credentials: Record<string, string>; left: string[] };
  assert.equal(plan.env.SCHUMANN_API_KEY, handle);
  assert.equal(plan.env.SCHUMANN_BASE_URL, `${ORIGIN}/use/market/dev/schumann`);

  const schumann = new SchumannApiClient({ baseUrl: plan.env.SCHUMANN_BASE_URL!, apiKey: plan.env.SCHUMANN_API_KEY! });
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
  assert.equal((await route('/use/market/dev/schumann/companies')).status, 401, 'no handle, no request');
  assert.equal((await route('/use/market/dev/nope/companies', { headers: { 'x-api-key': handle } })).status, 404);
  assert.equal(received.every((request) => request.url.startsWith('/v1/') || request.url.startsWith('/quoted/')), true);
});

test('query and Basic credentials, with their methods and paths', async () => {
  const handle = await handleFor();
  const maps = await route(`/use/market/dev/maps/geocode?address=paris&key=${handle}`);
  assert.equal(maps.status, 200);
  assert.equal(new URL(received.at(-1)!.url, 'http://x').searchParams.get('key'), 'maps+real/key=0123456789');
  assert.equal((await route(`/use/market/dev/maps/geocode?key=${handle}`, { method: 'POST' })).status, 405);

  const basicAuth = `Basic ${btoa(`${handle}:${handle}`)}`;
  const twilio = await route('/use/market/dev/twilio/Accounts/AC1/Messages.json', { method: 'POST', headers: { authorization: basicAuth, 'content-type': 'application/x-www-form-urlencoded' }, body: 'To=%2B33600000000&Body=hi' });
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
  const xml = await (await route('/use/market/dev/quoted/xml', { headers: { 'x-api-key': handle } })).text();
  assert.equal(xml, '<Error><Message>bad key [redacted by coffre]</Message></Error>');
  const python = await (await route('/use/market/dev/accented/python', { headers: { 'x-api-key': handle } })).text();
  assert.equal(python, '{"key":"[redacted by coffre]"}');
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

  await clientFor(deps, DEV).secrets.set('market/dev@me', { DATABASE_URL: 'postgres://localhost/dev' });
  const mine = await bearer(session).handles.create({ label: 'run', paths: ['market/dev@me'] });
  assert.deepEqual(mine.scope, { 'market/dev': 'viewer' });
  const plan = (await (await route('/use/market/dev@me', { headers: { authorization: `Bearer ${mine.token}` } })).json()) as { env: Record<string, string> };
  assert.equal(plan.env.DATABASE_URL, 'postgres://localhost/dev', "the personal config's own value, not dev's");
  assert.equal(plan.env.WEBHOOK_SECRET, undefined);
});

test('the plan: stand-ins for what the proxy covers, values only for what the exact environment exposes, never a fork or a personal config of it', async () => {
  const root = clientFor(deps, ROOT);
  await root.environments.create('market/dev-eu', { from: 'dev', inherit: true });
  await root.secrets.set('market/dev@me', { EXTRA: 'mine' }).catch(() => undefined);
  await clientFor(deps, DEV).secrets.set('market/dev@me', { LOCAL_ONLY: 'x' });
  const plan = async (path: string, paths = [path.replace('@me', '')]) => {
    const handle = (await bearer(await sessionFor(DEV)).handles.create({ label: 'run', paths: [path.includes('@me') ? 'market/dev' : paths[0]!] })).token;
    const response = await route(`/use/${path}`, { headers: { authorization: `Bearer ${handle}` } });
    assert.equal(response.status, 200, await response.clone().text());
    return (await response.json()) as { environment: string; env: Record<string, string>; left: string[] };
  };

  const dev = await plan('market/dev');
  assert.equal(dev.env.WEBHOOK_SECRET, WEBHOOK, 'exposed by its exact path');
  assert.equal(dev.env.MAPS_KEY?.startsWith('coffre_use_'), true);
  assert.equal(dev.env.TWILIO_SID?.startsWith('coffre_use_'), true);
  assert.deepEqual(dev.left, ['DATABASE_URL'], 'neither proxied nor exposed: the app does without');
  assert.equal(JSON.stringify(dev).includes(KEY), false);

  const fork = await plan('market/dev-eu');
  assert.equal(fork.env.WEBHOOK_SECRET, undefined, "a fork inherits dev's value, not its exposure");
  assert.ok(fork.left.includes('WEBHOOK_SECRET'));
  assert.equal(fork.env.SCHUMANN_API_KEY?.startsWith('coffre_use_'), true, 'its inherited keys are still stand-ins');

  const mine = await plan('market/dev@me');
  assert.equal(mine.environment, 'market/dev@me');
  assert.equal(mine.env.WEBHOOK_SECRET, undefined, 'nor does a personal config of it');
  assert.ok(mine.left.includes('WEBHOOK_SECRET'));
  assert.equal(mine.env.LOCAL_ONLY, 'x', "but its own values, which only its owner wrote, are its owner's app's");

  // Each exposure is logged as the vault's read to expose, and the proxy's entry of it.
  const exposed = (await entries('secret.read')).filter((entry) => entry.author === 'vault' && entry.decision === 'allow' && entry.metadata.purpose === 'expose');
  assert.equal(exposed.length, 2);
});

test('the configuration is checked: HTTPS upstreams, no private address, rules that name keys, expose by exact path', () => {
  const make = (credentials: CredentialProxyOptions['credentials'], more: Partial<CredentialProxyOptions> = {}) => () => credentialProxy({ credentials, ...more });
  assert.throws(make({ a: { upstream: 'http://api.example.com', inject: header('x', '{K}') } }), /HTTPS/);
  assert.throws(make({ a: { upstream: 'https://10.0.0.8', inject: header('x', '{K}') } }), /private address/);
  assert.throws(make({ a: { upstream: 'https://169.254.169.254/latest', inject: header('x', '{K}') } }), /private address/);
  assert.throws(make({ a: { upstream: 'https://[::1]', inject: header('x', '{K}') } }), /private address/);
  assert.throws(make({ a: { upstream: 'https://localhost', inject: header('x', '{K}') } }), /private address/);
  assert.throws(make({ a: { upstream: 'https://api.example.com', inject: header('x', 'static') } }), /names no key/);
  assert.throws(make({ A: { upstream: 'https://api.example.com', inject: header('x', '{K}') } }), /lowercase/);
  assert.throws(make({}, { expose: { 'market/*': 'all' } }), /exact|by path/);
  assert.doesNotThrow(make({ a: { upstream: 'https://api.example.com/v1', inject: header('authorization', 'Bearer {K}') } }));
  assert.doesNotThrow(make({ a: { upstream: 'http://127.0.0.1:9000', inject: header('x', '{K}') } }, { insecureUpstreams: true }));
});
