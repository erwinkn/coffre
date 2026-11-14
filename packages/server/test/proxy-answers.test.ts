// What a request through the credential proxy sends, and what comes back
// (docs/design/credential-proxy.md, sections 3 and 4), on the 0.16 fixture:
// 0.14.7's assertions (credential-proxy.test.ts, -properties,
// -placeholders, -egress-workers and plain-values.test.ts) ported. A
// credential's egress is its only way out; a redirect stays on the proxy or
// goes nowhere; every form of a secret the request carried is redacted from
// the answer however it is split; nothing leaves the upstream, and the
// handle goes nowhere but where the key goes; the configuration is checked;
// and a placeholder fills exactly its slot, a plain key's included.
import assert from 'node:assert/strict';
import { after, beforeEach, mock, test } from 'node:test';

import { generateToken } from '@coffre/core/identity';
import { rowsOf } from '@coffre/db/dialect';
import { amend, credential, emptyDatabase, environment, grant, instance, principal, project, role, rows, secret, value, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

import { basic, credentialProxy, header, jwt, prefix, query, sigv4, type Credential, type CredentialProxyOptions, type Egress } from '../src/plugins/credential-proxy.ts';
import { setSecurityHeaders } from '../src/security-headers.ts';
import { openApp, PUBLIC_URL } from './app-fixture.ts';

const ADA = 'user:ada';
const KEY = 'sk_schumann_real_0123456789abcdef';
/** A key a JSON echo escapes; one with a Latin-1 letter; one Headers trims on the way out. */
const QUOTED = 'q"uo\\te/d<&>0123';
const ACCENT = 'clé-0123456789';
const PADDED = '  padded-key-0123456789  ';
/** Twilio's plain account id, and a token whose Basic base64 has a `/`; a password past Latin-1. */
const SID = 'AC0123456789';
const TOKEN = 'twilio_real_token_0??0123456789';
const U_PASS = 'pāssword-0123456789';
/** A user name the password begins with. */
const P_USER = 'acct_one';
const P_PASS = 'acct_one_unknownabcdefgh0123456789';
const STRIPE = 'sk_live_0123456789';
const b64 = (claims: object) => Buffer.from(JSON.stringify(claims)).toString('base64url');
const DFNS = `${b64({ alg: 'HS256' })}.${b64({ org: 'or-sandbox', sub: 'sa-1' })}.c2lnbmF0dXJl`;
const REDACTED = '[redacted by coffre]';

const sent: { url: URL; init: RequestInit; headers: Headers; body: Buffer }[] = [];
let answer: (url: URL) => Response | Promise<Response> = () => Response.json({ ok: true });
const egress: Egress = {
  async fetch(input, init) {
    sent.push({ url: new URL(input.href), init, headers: new Headers(init.headers), body: Buffer.from((init.body as Uint8Array | undefined) ?? new Uint8Array()) });
    return answer(input);
  },
};
const through = (host: string, inject: Credential['inject'], more: Partial<Credential> = {}): Credential => ({ upstream: `https://${host}.example/v1`, inject, egress, ...more });
const proxy = credentialProxy({
  credentials: {
    schumann: through('api.schumann', header('x-api-key', '{SCHUMANN_KEY}')),
    open: { upstream: 'https://open.schumann.example/v1', inject: header('x-api-key', '{SCHUMANN_KEY}') },
    quoted: through('quoted', header('x-api-key', '{QUOTED_KEY}')),
    accented: through('accented', header('x-api-key', '{ACCENT_KEY}')),
    padded: through('padded', header('x-api-key', '{PADDED_KEY}')),
    twilio: through('twilio', basic('{TWILIO_SID}', '{TWILIO_TOKEN}'), { paths: ['/Accounts'] }),
    ubasic: through('ubasic', basic('{TWILIO_SID}', '{U_PASS}')),
    prefixed: through('prefixed', basic('{P_USER}', '{P_PASS}')),
    broken: through('broken', header('x-api-key', '{BROKEN_KEY}')),
    odd: through('odd', header('x-api-key', '{constructor}')),
    account: through('account', header('x-account', '{ACCOUNT_ID}')),
    legacy: through('legacy', basic('{LEGACY_USER}', '{LEGACY_PASSWORD}')),
    stripe: through('stripe', header('authorization', 'Bearer {STRIPE_KEY}'), { placeholder: prefix('sk_test_') }),
    dfns: through('dfns', query('token', '{DFNS_TOKEN}'), { placeholder: jwt({ claims: ['org'] }) }),
    notjwt: through('notjwt', header('x-k', '{NOT_A_JWT}'), { placeholder: jwt() }),
  },
});
const app = await openApp({ plugins: [proxy] });
const { world } = app;
after(() => app.close());

const market = project('market');
const dev = environment(market, 'dev');
const staging = environment(market, 'staging');
const other = environment(market, 'other');
let handle: string;
let handleId: string;

/** A handle of ADA's for `places`, as `coffre run` makes one. */
async function handleFor(...places: { id: string; projectId: string }[]): Promise<string> {
  const token = generateToken('handle');
  const row = credential(token, ADA, { kind: 'handle', scope: JSON.stringify(places.map((place) => ({ projectId: place.projectId, environmentId: place.id, role: 'developer' }))), places: JSON.stringify(places.map((place) => ({ environmentId: place.id, personal: false }))), expiresAt: new Date(Date.now() + 3_600_000) });
  handleId = row.id;
  await write(world, ...rows('credentials', row));
  return token;
}

beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  sent.length = 0;
  answer = () => Response.json({ ok: true });
  const held: Record<string, [string, 'plain' | 'sensitive' | 'secret']> = {
    SCHUMANN_KEY: [KEY, 'secret'], QUOTED_KEY: [QUOTED, 'secret'], ACCENT_KEY: [ACCENT, 'secret'], PADDED_KEY: [PADDED, 'secret'], TWILIO_SID: [SID, 'plain'], TWILIO_TOKEN: [TOKEN, 'secret'], U_PASS: [U_PASS, 'sensitive'],
    P_USER: [P_USER, 'secret'], P_PASS: [P_PASS, 'secret'], BROKEN_KEY: ['broken\nvalue-456789', 'secret'], ACCOUNT_ID: ['acct_public_42', 'plain'], LEGACY_USER: ['legacy-user', 'plain'], LEGACY_PASSWORD: ['legacy-password', 'plain'], STRIPE_KEY: [STRIPE, 'sensitive'], DFNS_TOKEN: [DFNS, 'sensitive'],
  };
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', []), role(false, 'developer', ['secret.read', 'secret.use', 'secret.write'])),
    ...rows('projects', market),
    ...rows('environments', dev, staging, other),
    ...rows('principals', principal(ADA)),
    ...rows('grants', grant(ADA, 'developer', { project: market })),
    ...rows('secrets', ...Object.entries(held).map(([key, [text, nature]]) => value(world, secret(dev, key), text, { [nature]: true })), value(world, secret(staging, 'SCHUMANN_KEY'), KEY), value(world, secret(other, 'NOT_A_JWT'), 'opaque-secret-0123456789')),
  );
  handle = await handleFor(dev);
});

const call = (path: string, init: RequestInit = {}, token = handle) => app.request(`/use/market/dev/schumann${path}`, { ...init, headers: { 'x-api-key': token, ...(init.headers as Record<string, string> | undefined) } });
const message = async (response: Response) => ((await response.clone().json()) as { message: string }).message;
const redirect = (location: string) => new Response(null, { status: 302, headers: { location } });
const text = (body: string | ReadableStream<Uint8Array>, type = 'application/json', init: ResponseInit = {}) => new Response(body, { ...init, headers: { 'content-type': type, ...(init.headers as Record<string, string> | undefined) } });
/** `body` in parts of `size` bytes, as a network may hand it. */
const chunked = (body: string, size: number) => new ReadableStream<Uint8Array>({ start(out) { const bytes = Buffer.from(body); for (let at = 0; at < bytes.length; at += size) out.enqueue(bytes.subarray(at, at + size)); out.close(); } });
const basicOf = (user: string, password: string) => `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`;
/** What tells the upstream about coffre's caller, its cookies, its Access sign-in or this hop: none of it goes on. */
const CALLER = {
  cookie: 'coffre=1', 'x-forwarded-for': '198.51.100.1', 'x-forwarded-host': 'coffre.example', forwarded: 'for=198.51.100.1', 'x-real-ip': '198.51.100.1', 'true-client-ip': '198.51.100.1',
  'cf-access-jwt-assertion': 'eyJ.access.jwt', 'cf-connecting-ip': '198.51.100.1', 'cf-ray': '8a0b1c2d3e4f-CDG', 'cdn-loop': 'cloudflare', 'proxy-authorization': 'Basic cHJveHk6cGFzcw==', te: 'trailers',
};
const planOf = async (token: string, path = 'market/dev') => app.request(`/use/${path}`, { headers: { authorization: `Bearer ${token}` } });

test("a credential with an egress leaves through it and never the global fetch, as the proxy made the request; its failure is a 502, redacted", async () => {
  const global = mock.method(globalThis, 'fetch', async () => Response.json({ global: true }));
  try {
    const got = await call('/companies?q=acme', { method: 'POST', headers: { 'content-type': 'application/json', ...CALLER }, body: '{"siren":"123"}' });
    assert.equal(got.status, 200, await got.clone().text());
    const [one] = sent;
    assert.deepEqual([one!.url.href, one!.init.method, one!.init.redirect, one!.body.toString()], ['https://api.schumann.example/v1/companies?q=acme', 'POST', 'manual', '{"siren":"123"}']);
    assert.deepEqual([one!.headers.get('x-api-key'), one!.headers.get('content-type')], [KEY, 'application/json']);
    assert.deepEqual(Object.keys(CALLER).filter((name) => one!.headers.has(name)), [], "nothing about coffre's caller or the hop goes on");
    assert.ok(![...one!.headers].some(([, said]) => said.includes(handle)));
    assert.equal(global.mock.callCount(), 0);
    // A credential without one leaves through the global fetch, its redirects not followed either.
    assert.equal((await app.request('/use/open/companies', { headers: { 'x-api-key': handle } })).status, 200);
    assert.deepEqual([global.mock.callCount(), (global.mock.calls[0]!.arguments[1] as RequestInit).redirect], [1, 'manual']);
  } finally {
    global.mock.restore();
  }
  answer = () => Promise.reject(new Error('tunnel down'));
  const down = await call('/companies');
  assert.equal(down.status, 502);
  assert.match(await message(down), /did not answer through schumann's egress: tunnel down/);
  answer = (url) => Promise.reject(new Error(`could not send ${url.href} with x-api-key: ${KEY}`));
  const quoted = await message(await call('/companies'));
  assert.ok(!quoted.includes(KEY) && quoted.includes(`x-api-key: ${REDACTED}`), quoted);
});

test('a redirect under the upstream is the proxy\'s URL for it, the stable URL\'s too; one elsewhere, or that no URL reads, is a 502 naming no destination', async () => {
  answer = () => redirect('/v1/companies?page=2');
  assert.equal((await app.request('/use/schumann/x', { headers: { 'x-api-key': handle } })).headers.get('location'), `${PUBLIC_URL}/use/market/dev/schumann/companies?page=2`);
  for (const location of [`https://evil.example/steal?k=${KEY}`, '//', 'https://api.schumann.example/v2/']) {
    answer = () => redirect(location);
    const refused = await call('/redirect');
    const said = await refused.text();
    assert.deepEqual([refused.status, refused.headers.get('location')], [502, null], location);
    assert.ok(!said.includes('evil') && !said.includes(KEY), said);
  }
});

test("an answer comes back no-store, sandboxed, without cookies, its headers and reason phrase redacted, and a body in another charset byte for byte", async () => {
  answer = () => text(JSON.stringify({ youSent: KEY }), 'application/json', { statusText: `bad ${KEY}`, headers: { 'x-echo': KEY, 'set-cookie': 'upstream=1', 'cache-control': 'max-age=60', expires: 'Thu, 01 Jan 2099 00:00:00 GMT' } });
  const got = await call('/echo');
  assert.deepEqual(await got.json(), { youSent: REDACTED });
  assert.deepEqual([got.statusText, got.headers.get('x-echo'), got.headers.get('set-cookie'), got.headers.get('cache-control'), got.headers.get('expires')], [`bad ${REDACTED}`, REDACTED, null, 'no-store', null]);
  // On coffre's origin, an upstream's document runs nothing: sandboxed, which coffre's own headers keep, and one that allows anything back is replaced.
  assert.equal(got.headers.get('content-security-policy'), "sandbox; default-src 'none'; frame-ancestors 'none'");
  assert.match(setSecurityHeaders(new Response('x', { headers: got.headers }), { nonce: 'n', publicUrl: PUBLIC_URL }).headers.get('content-security-policy')!, /^sandbox; default-src 'none'/);
  assert.match(setSecurityHeaders(new Response('x', { headers: { 'content-security-policy': 'sandbox allow-scripts allow-same-origin' } }), { nonce: 'n', publicUrl: PUBLIC_URL }).headers.get('content-security-policy')!, /^default-src 'self'/);
  answer = () => text(new Uint8Array([0x63, 0x61, 0x66, 0xe9, 0x2c, 0xff, 0x0a]) as never, 'text/plain; charset=iso-8859-1');
  assert.deepEqual([...new Uint8Array(await (await call('/latin1')).arrayBuffer())], [0x63, 0x61, 0x66, 0xe9, 0x2c, 0xff, 0x0a]);
});

test('every form an honest upstream echoes a secret in is redacted: escapes, entities, Basic\'s base64, a trimmed key, a UTF-8 header and Location', async () => {
  const utf8 = (said: string) => Buffer.from(said).toString('latin1');
  const cases: [string, Record<string, string>, () => Response, string][] = [
    ['quoted', { 'x-api-key': handle }, () => text(JSON.stringify({ youSent: QUOTED }).replaceAll('/', '\\/')), `{"youSent":"${REDACTED}"}`],
    ['quoted', { 'x-api-key': handle }, () => text(`<Error><Message>bad key ${QUOTED.replace(/[&<>"]/g, (char) => `&${{ '&': 'amp', '<': 'lt', '>': 'gt', '"': 'quot' }[char]};`)}</Message></Error>`, 'application/xml'), `<Error><Message>bad key ${REDACTED}</Message></Error>`],
    ['accented', { 'x-api-key': handle }, () => text('{"key":"cl\\u00e9-0123456789"}'), `{"key":"${REDACTED}"}`],
    ['padded', { 'x-api-key': handle }, () => text(`key ${PADDED.trim()}`, 'text/plain'), `key ${REDACTED}`],
    ['twilio', { authorization: basicOf(SID, handle) }, () => text(JSON.stringify({ authorization: basicOf(SID, TOKEN) }).replaceAll('/', '\\/')), `{"authorization":"Basic ${REDACTED}"}`],
  ];
  assert.ok(basicOf(SID, TOKEN).includes('/'), "a base64 with a slash, which PHP's JSON escapes");
  for (const [name, headers, made, want] of cases) {
    answer = made;
    assert.equal(await (await app.request(`/use/market/dev/${name}/Accounts/x`, { headers })).text(), want, name);
  }
  answer = () => redirect(`/v1/x?k=${utf8(ACCENT)}`);
  const relocated = await app.request('/use/accented/x', { headers: { 'x-api-key': handle } });
  assert.deepEqual([relocated.status, relocated.headers.get('location')], [302, `${PUBLIC_URL}/use/market/dev/accented/x?k=[redacted%20by%20coffre]`]);
  answer = () => text('{}', 'application/json', { headers: { 'x-error-key': utf8(ACCENT) } });
  assert.equal((await app.request('/use/accented/x', { headers: { 'x-api-key': handle } })).headers.get('x-error-key'), REDACTED);
});

test("redaction is the same however the answer is split: a password that begins with the user name, cut anywhere, and an event stream's heartbeat at once", async () => {
  const said = `user ${P_USER} password ${P_PASS} end, ${P_USER.slice(0, 5)}`;
  for (let size = 1; size <= said.length; size += 1) {
    answer = () => text(chunked(said, size), 'text/plain');
    assert.equal(await (await app.request('/use/prefixed/x', { headers: { authorization: basicOf(handle, handle) } })).text(), `user ${REDACTED} password ${REDACTED} end, acct_`, `parts of ${size}`);
  }
  // Text past ASCII comes back whole, however its characters are cut.
  const intl = `café 🎉 ${KEY} ñandú`;
  for (let size = 1; size <= 5; size += 1) {
    answer = () => text(chunked(intl, size), 'text/plain; charset=utf-8');
    assert.equal(await (await call('/intl')).text(), `café 🎉 ${REDACTED} ñandú`, `parts of ${size}`);
  }
  let later!: (part: string) => void;
  answer = () => text(new ReadableStream<Uint8Array>({ start(out) { out.enqueue(Buffer.from(': heartbeat\n\n')); later = (part) => { out.enqueue(Buffer.from(part)); out.close(); }; } }), 'text/event-stream');
  const stream = (await call('/sse')).body!.getReader();
  assert.equal(new TextDecoder().decode((await stream.read()).value), ': heartbeat\n\n', 'before the upstream says more');
  later(`data: ${KEY}\n\n`);
  let rest = '';
  for (let part = await stream.read(); !part.done; part = await stream.read()) rest += new TextDecoder().decode(part.value);
  assert.equal(rest, `data: ${REDACTED}\n\n`);
});

test('nothing the app writes leaves the upstream, the handle goes nowhere but where the key goes, and a body is read no further than its limit', async () => {
  // A dot segment, encoded or not, is resolved before coffre sees it, out of the credential's path altogether.
  for (const path of ['/../admin', '/%2e%2e/admin', '/.%2E/admin']) assert.equal((await call(path)).headers.get('coffre-proxy'), 'refused', path);
  // One with parameters, encoded twice, a control byte, blanks or an overlong dot, and an encoded slash: refused as climbing.
  for (const path of ['/a%2Fb', '/a%5Cb', '/..;/admin', '/companies/%2e%2e;x/admin', '/companies/..%3B', '/companies/%252e%252e/admin', '/a%252Fb', '/companies/..%00/admin', '/companies/..%20/admin', '/companies/%c0%ae%c0%ae/admin']) {
    const climbed = await call(path);
    assert.deepEqual([climbed.status, climbed.headers.get('coffre-proxy')], [400, 'refused'], path);
  }
  for (const [path, init] of [['/companies', { method: 'POST', body: JSON.stringify({ token: handle }) }], ['/companies', { headers: { 'x-other': handle } }], [`/companies?token=${handle}`, {}], [`/%FF/${handle.replace('_', '%5F')}`, {}], ['/companies', { headers: { 'x-coffre-handle': handle, 'x-api-key': '', authorization: `Basic ${btoa(`client:${handle}`)}` } }]] as const) {
    assert.equal((await call(path, init)).status, 400, `${path} ${JSON.stringify(init)}`);
  }
  assert.equal((await app.request('/use/market/dev/schumann/companies')).status, 401, 'no handle, no request');
  assert.equal((await app.request('/use/market/dev/nope/companies', { headers: { 'x-api-key': handle } })).status, 404);
  let read = 0;
  const endless = new ReadableStream<Uint8Array>({ pull(out) { read += 1024 * 1024; out.enqueue(new Uint8Array(1024 * 1024)); if (read > 64 * 1024 * 1024) out.close(); } });
  assert.equal((await call('/upload', { method: 'POST', body: endless, duplex: 'half' } as RequestInit)).status, 413);
  assert.ok(read <= 20 * 1024 * 1024, `read ${read} bytes`);
  assert.equal(sent.length, 0);
  // Basic takes a password past Latin-1, as UTF-8.
  assert.equal((await app.request('/use/ubasic/x', { headers: { authorization: basicOf(SID, handle) } })).status, 200);
  assert.equal(sent.at(-1)!.headers.get('authorization'), basicOf(SID, U_PASS));
});

test("a value no header can carry is a 409 quoted nowhere, a log line included, and a key named as an object's own property is missing", async () => {
  const said: unknown[] = [];
  const error = mock.method(console, 'error', (...args: unknown[]) => void said.push(...args));
  try {
    const broken = await app.request('/use/broken/x', { headers: { 'x-api-key': handle } });
    assert.equal(broken.status, 409);
    assert.ok(!JSON.stringify([await broken.text(), said.map(String)]).includes('456789'));
  } finally {
    error.mock.restore();
  }
  assert.equal((await app.request('/use/odd/x', { headers: { 'x-api-key': handle } })).status, 409);
  assert.equal(sent.length, 0);
});

test('a handle revoked while its body is still streaming sends nothing upstream', async () => {
  let pulled = false;
  const body = new ReadableStream<Uint8Array>({
    async pull(out) {
      if (pulled) return out.close();
      pulled = true;
      await amend(world, 'credentials', sql`id = ${handleId}`, { revokedAt: new Date(), revokedBy: ADA });
      world.memory.reads.clear();
      world.memory.callers.clear();
      out.enqueue(Buffer.from('{"siren":"123"}'));
    },
  });
  assert.equal((await call('/companies', { method: 'POST', body, duplex: 'half' } as RequestInit)).status, 401);
  assert.equal(sent.length, 0);
});

test('a handle made for two environments: the stable URL names both and goes to neither, follows a rename, and an environment deleted still counts', async () => {
  const both = await handleFor(dev, staging);
  const one = await handleFor(staging);
  const ambiguous = await app.request('/use/schumann/companies', { headers: { 'x-api-key': both } });
  assert.equal(ambiguous.status, 409);
  assert.match(await message(ambiguous), new RegExp(`2 environments.*${PUBLIC_URL}/use/market/dev/schumann or ${PUBLIC_URL}/use/market/staging/schumann`));
  assert.equal((await app.request('/use/market/staging/schumann/companies', { headers: { 'x-api-key': both } })).status, 200);
  await amend(world, 'environments', sql`id = ${staging.id}`, { slug: 'europe' });
  assert.match(await message(await app.request('/use/schumann/companies', { headers: { 'x-api-key': both } })), new RegExp(`${PUBLIC_URL}/use/market/europe/schumann`));
  assert.equal((await app.request('/use/schumann/companies', { headers: { 'x-api-key': one } })).status, 200);
  await amend(world, 'environments', sql`id = ${staging.id}`, { slug: 'europe~deleted' });
  assert.equal((await app.request('/use/schumann/companies', { headers: { 'x-api-key': both } })).status, 409);
  const gone = await app.request('/use/schumann/companies', { headers: { 'x-api-key': one } });
  assert.deepEqual([gone.status, await message(gone)], [409, 'the environment this handle was made for is gone']);
});

test('/use/<a>/<b>/… names an environment exactly when <a>/<b> is one the handle was made for, a project named like a credential included', async () => {
  const named = project('schumann');
  const own = environment(named, 'dev');
  await write(world, ...rows('projects', named), ...rows('environments', own), ...rows('grants', grant(ADA, 'developer', { project: named })), ...rows('secrets', value(world, secret(own, 'SCHUMANN_KEY'), 'sk_schumann_own_0123456789')));
  const ours = await handleFor(own);
  for (const url of ['/use/schumann/dev/schumann/companies', '/use/schumann/companies']) {
    assert.equal((await app.request(url, { headers: { 'x-api-key': ours } })).status, 200, url);
    assert.deepEqual([sent.at(-1)!.url.pathname, sent.at(-1)!.headers.get('x-api-key')], ['/v1/companies', 'sk_schumann_own_0123456789']);
  }
  // For a run of market/dev, schumann/dev is no environment of the handle's: a path under Schumann's upstream.
  assert.equal((await app.request('/use/schumann/dev/companies', { headers: { 'x-api-key': handle } })).status, 200);
  assert.deepEqual([sent.at(-1)!.url.pathname, sent.at(-1)!.headers.get('x-api-key')], ['/v1/dev/companies', KEY]);
});

test('the configuration is checked: HTTPS, no private address however written, rules that name keys, lowercase names, the gone options, and an egress that fetches', () => {
  const make = (credentials: CredentialProxyOptions['credentials'], more: Partial<CredentialProxyOptions> = {}) => () => credentialProxy({ credentials, ...more });
  const at = (upstream: string, more: Partial<Credential> = {}) => make({ a: { upstream, inject: header('x', '{K}'), ...more } });
  assert.throws(at('http://api.example.com'), /HTTPS/);
  for (const host of ['10.0.0.8', '169.254.169.254', '[::1]', 'localhost', 'localhost.', 'LOCALHOST', 'api.localhost.', '127.0.0.1.', '[::ffff:10.0.0.8]', '[::7f00:1]', '[fe80::1]', '[fec0::1]', '[64:ff9b::a00:8]', '198.18.0.1', '[2002:a00:8::1]', '[2002:7f00:1::]', '[2002::]']) {
    assert.throws(at(`https://${host}/v1`), /private address/, host);
  }
  assert.doesNotThrow(at('https://[2002:808:808::1]/v1'), 'a 6to4 address of a public IPv4 is public');
  assert.doesNotThrow(make({ a: { upstream: 'http://127.0.0.1:9000', inject: header('x', '{K}') } }, { insecureUpstreams: true }));
  assert.throws(make({ a: { upstream: 'https://api.example.com', inject: header('x', 'static') } }), /names no key/);
  assert.throws(make({ A: { upstream: 'https://api.example.com', inject: header('x', '{K}') } }), /lowercase/);
  // @ts-expect-error -- gone in 0.10
  assert.throws(make({}, { expose: { 'market/dev': ['K'] } }), /expose is gone in 0\.10.*mark sensitive the keys no person may read/);
  // @ts-expect-error -- gone in 0.10
  assert.throws(at('https://api.example.com', { identifiers: ['SID'] }), /a's identifiers are gone in 0\.10: mark each key plain/);
  // @ts-expect-error -- gone in 0.9
  assert.throws(at('https://api.example.com', { baseUrl: 'SCHUMANN_BASE_URL' }), /a's baseUrl is gone in 0\.9.*SCHUMANN_BASE_URL.*<publicUrl>\/use\/a/);
  // @ts-expect-error -- renamed in 0.10
  assert.throws(at('https://api.example.com', { standIn: jwt() }), /a's standIn is called placeholder in 0\.10: rename it/);
  // An egress named is one that fetches: a binding the Worker lacks is `undefined`, its key still there.
  const env: { EGRESS?: Egress } = {};
  assert.throws(at('https://api.example.com', { egress: env.EGRESS }), /a's egress is undefined, as a Worker's binding is when wrangler\.jsonc lacks it: add the binding, or remove egress/);
  for (const given of [{}, null]) assert.throws(at('https://api.example.com', { egress: given as never }), /a's egress has no fetch method/);
});

test('a shaped placeholder fills exactly its slot, a query\'s and a header\'s: the handle anywhere else is refused, a redirect gets the shape back, and the real token echoed is redacted', async () => {
  const { env } = (await (await planOf(handle)).json()) as { env: Record<string, string> };
  assert.deepEqual([env.STRIPE_KEY, env.DFNS_TOKEN!.split('.')[2], JSON.parse(Buffer.from(env.DFNS_TOKEN!.split('.')[1]!, 'base64url').toString()).org], [`sk_test_${handle}`, handle, 'or-sandbox']);
  assert.equal((await app.request('/use/stripe/charges', { headers: { authorization: `Bearer ${env.STRIPE_KEY}` } })).status, 200);
  assert.equal(sent.at(-1)!.headers.get('authorization'), `Bearer ${STRIPE}`);
  // Any JWT header and payload, as the proxy reads neither: the handle in the third part is what lets it in.
  for (const token of [env.DFNS_TOKEN!, `e30.e30.${handle}`]) {
    assert.equal((await app.request(`/use/dfns/wallets?token=${token}`)).status, 200, token);
    assert.equal(sent.at(-1)!.url.searchParams.get('token'), DFNS);
  }
  for (const [url, headers] of [['/use/stripe/charges', { authorization: `Bearer ${handle}` }], [`/use/dfns/wallets?token=${handle}`, {}], [`/use/dfns/wallets?token=e30.${handle}`, {}], [`/use/dfns/wallets?token=${env.DFNS_TOKEN}.x`, {}]] as const) {
    assert.equal((await app.request(url, { headers })).status, 401, url);
  }
  assert.equal((await app.request('/use/stripe/charges', { method: 'POST', headers: { authorization: `Bearer ${env.STRIPE_KEY}` }, body: JSON.stringify({ token: env.STRIPE_KEY }) })).status, 400);
  answer = () => Response.json({ error: `token ${DFNS} is not allowed here` });
  assert.deepEqual(await (await app.request(`/use/dfns/echo?token=${env.DFNS_TOKEN}`)).json(), { error: `token ${REDACTED} is not allowed here` });
  // A redirect under a query rule's upstream gives back the app's placeholder, or one of the same shape where the app sent none.
  answer = () => redirect(`/v1/wallets?token=${DFNS}`);
  assert.equal(new URL((await app.request(`/use/dfns/moved?token=${env.DFNS_TOKEN}`)).headers.get('location')!).searchParams.get('token'), env.DFNS_TOKEN);
  const helped = await app.request('/use/market/dev/dfns/moved?token=unused', { headers: { 'x-coffre-handle': handle } });
  assert.match(new URL(helped.headers.get('location')!).searchParams.get('token')!, new RegExp(`^[\\w-]+\\.e30\\.${handle}$`));
});

test('a JWT placeholder for a key that holds no JWT fails the plan, quoting nothing; a shaped placeholder is for a rule that carries one key', async () => {
  const plan = await planOf(await handleFor(other), 'market/other');
  const said = await plan.text();
  assert.equal(plan.status, 409);
  assert.match(said, /market\/other's NOT_A_JWT is no JWT, which notjwt's placeholder copies its claims from/);
  assert.ok(!said.includes('opaque-secret'));
  const upstream = 'https://api.example.com';
  const make = (credentials: CredentialProxyOptions['credentials']) => () => credentialProxy({ credentials });
  assert.throws(make({ a: { upstream, inject: basic('{ID}', '{SECRET}'), placeholder: prefix('sk_') } }), /a's placeholder shapes the one key a header, query, form, JSON or path rule carries.*not a basic\(\) rule/);
  assert.throws(make({ a: { upstream, inject: sigv4({ accessKeyId: '{A}', secretAccessKey: '{B}', region: 'eu-west-3', service: 's3' }), placeholder: jwt() } }), /not a sigv4\(\) rule/);
  assert.throws(make({ a: { upstream, inject: header('x', '{K}{K}'), placeholder: prefix('a') } }), /several keys, or one twice/);
  assert.throws(make({ a: { upstream, inject: header('x', '{K}'), placeholder: prefix('has space') } }), /prefix\(\) is up to 64/);
  assert.throws(make({ a: { upstream, inject: header('x', '{K}'), placeholder: jwt({ claims: ['exp'] }) } }), /exp is the handle's end/);
  // The app holds one value for a key: two credentials that read it give it one placeholder.
  assert.throws(make({ a: { upstream, inject: header('authorization', 'Bearer {K}'), placeholder: jwt({ claims: ['org'] }) }, b: { upstream, inject: query('k', '{K}') } }), /a and b read K with different placeholders/);
});

test("a plain key stays a placeholder where the handle would go nowhere else, a header's only key and Basic's pair; the real value goes, and comes back as it is", async () => {
  const { env } = (await (await planOf(handle)).json()) as { env: Record<string, string> };
  assert.deepEqual([env.TWILIO_SID, env.ACCOUNT_ID, env.LEGACY_USER, env.LEGACY_PASSWORD], [SID, handle, handle, handle]);
  answer = () => Response.json({ account: 'acct_public_42' });
  const got = await app.request('/use/account/whoami', { headers: { 'x-account': env.ACCOUNT_ID! } });
  assert.deepEqual(await got.json(), { account: 'acct_public_42' }, 'no secret, not redacted');
  assert.equal(sent.at(-1)!.headers.get('x-account'), 'acct_public_42');
  assert.equal((await app.request('/use/legacy/x', { headers: { authorization: basicOf(env.LEGACY_USER!, env.LEGACY_PASSWORD!) } })).status, 200);
  assert.equal(sent.at(-1)!.headers.get('authorization'), basicOf('legacy-user', 'legacy-password'));
});

test("a use's log entry names the host the value went to and whether through the deployment's egress", { todo: '0.16 logs the credential alone (vault/src/use.ts detail: purpose, credential, keys); 0.14.7 logged host and egress, and docs/design/0.16.md, "The proxy", row `logged`, keeps them' }, async () => {
  assert.equal((await call('/companies')).status, 200);
  const entries = (await rowsOf<{ body: string }>(world.owner, sql`SELECT body FROM log_pending ORDER BY id`)).map((row) => JSON.parse(row.body) as { detail: Record<string, unknown> });
  const used = entries.find((entry) => entry.detail.credential === 'schumann')!;
  assert.deepEqual([used.detail.host, used.detail.egress], ['api.schumann.example', true]);
});
