// Shaped placeholders (docs/design/credential-proxy.md, section 5): a client
// that checks its key's shape before it sends it gets a placeholder in that
// shape, the handle inside. DFNS's SDK reads its organization out of the
// token's claims on every request (`extractTokenScope`), so an opaque handle
// throws before anything is sent; with `jwt({ claims })` it holds a JWT of
// those claims whose last part is the handle. Here the real `@dfns/sdk`
// calls a fake DFNS through the proxy, and the fake reads the token exactly
// as the SDK does, and checks it got the real one.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { DfnsApiClient } from '@dfns/sdk';
import { extractTokenScope } from '@dfns/sdk/utils/authToken.js';

import { clientFor, keyIds, LOG, watchUses } from './api-fixture.ts';
import { db, deps, DEV, entries, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { coffreRoute } from '../src/app.ts';
import { checkPlugins } from '../src/plugins.ts';
import { basic, credentialProxy, header, jwt, prefix, query, sigv4, type CredentialProxyOptions } from '../src/plugins/credential-proxy.ts';

const base64url = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const APP_METADATA = 'https://custom/app_metadata';
/** A service account's token, as DFNS issues one: its scope in a custom claim, beside claims the app has no need of. */
const TOKEN = `${base64url({ alg: 'EdDSA', typ: 'JWT' })}.${base64url({ [APP_METADATA]: { orgId: 'or-sandbox', tenantId: 'tn-sandbox', tokenKind: 'ServiceAccount' }, sub: 'to-secret-subject', iss: 'auth.dfns.io', exp: 4_102_444_800 })}.c2lnbmF0dXJlLW9mLXRoZS1yZWFsLXRva2Vu`;
const STRIPE = 'sk_test_real_0123456789abcdef';

let dfns: Server;
let dfnsUrl: string;
let coffre: Server;
let coffreUrl: string;
const received: { url: string; authorization: string; scope: unknown }[] = [];

before(async () => {
  // The fake DFNS: the token read as the SDK reads it, the real one required, and an error that quotes it when asked to.
  dfns = createServer((request, response) => {
    const authorization = request.headers.authorization ?? '';
    const token = authorization.replace(/^Bearer /, '') || (new URL(request.url!, dfnsUrl).searchParams.get('token') ?? '');
    let scope: unknown;
    try {
      scope = extractTokenScope({ authToken: token });
    } catch (error) {
      scope = (error as Error).message;
    }
    received.push({ url: request.url!, authorization, scope });
    const send = (status: number, body: unknown) => response.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(body));
    if (token !== TOKEN && authorization !== `Bearer ${STRIPE}`) return send(401, { error: { message: 'Unauthorized' } });
    // A redirect that drops the query, for a query rule's placeholder to be given back.
    if (request.url!.startsWith('/q/moved')) return response.writeHead(302, { location: `${dfnsUrl}/q/wallets` }).end();
    if (request.url!.startsWith('/echo')) return send(401, { error: { message: `token ${token} is not allowed here` } });
    send(200, { items: [{ id: 'wa-1', network: 'EthereumSepolia' }] });
  });
  await new Promise<void>((resolve) => dfns.listen(0, '127.0.0.1', resolve));
  dfnsUrl = `http://127.0.0.1:${(dfns.address() as AddressInfo).port}`;
  // coffre over HTTP, as the SDK's fetch (cross-fetch, node-fetch 2) reaches it.
  coffre = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk as Buffer);
    const headers = new Headers();
    for (const [name, value] of Object.entries(request.headers)) if (typeof value === 'string') headers.set(name, value);
    const body = chunks.length === 0 ? undefined : Buffer.concat(chunks);
    const answer = (await coffreRoute(new Request(`${ORIGIN}${request.url}`, { method: request.method, headers, body }), runtime, '127.0.0.1'))!;
    response.writeHead(answer.status, Object.fromEntries(answer.headers));
    response.end(Buffer.from(await answer.arrayBuffer()));
  });
  await new Promise<void>((resolve) => coffre.listen(0, '127.0.0.1', resolve));
  coffreUrl = `http://127.0.0.1:${(coffre.address() as AddressInfo).port}`;
});

after(async () => {
  await new Promise<void>((resolve) => dfns.close(() => resolve()));
  await new Promise<void>((resolve) => coffre.close(() => resolve()));
});

function proxyOptions(): CredentialProxyOptions {
  return {
    credentials: {
      dfns: { upstream: dfnsUrl, inject: header('authorization', 'Bearer {DFNS_AUTH_TOKEN}'), placeholder: jwt({ claims: [APP_METADATA] }) },
      stripe: { upstream: `${dfnsUrl}/stripe`, inject: header('authorization', 'Bearer {STRIPE_SECRET_KEY}'), placeholder: prefix('sk_test_') },
      broken: { upstream: dfnsUrl, inject: query('token', '{NOT_A_JWT}'), placeholder: jwt() },
      // The same token in a query parameter: the same placeholder, which the app holds once.
      q: { upstream: `${dfnsUrl}/q`, inject: query('token', '{DFNS_AUTH_TOKEN}'), placeholder: jwt({ claims: [APP_METADATA] }) },
    },
    insecureUpstreams: true,
  };
}

useMcp(
  async () => {
    runtime.plugins = checkPlugins([credentialProxy(proxyOptions())]);
    received.length = 0;
    const root = clientFor(deps, ROOT);
    await root.members.add(`user:${DEV}`);
    await root.projects.create('market');
    await root.environments.create('market/dev');
    await root.secrets.set('market/dev', { DFNS_AUTH_TOKEN: { value: TOKEN, sensitivity: 'sensitive' }, STRIPE_SECRET_KEY: { value: STRIPE, sensitivity: 'sensitive' } });
    await root.access.set(`user:${DEV}`, { market: 'developer' });
  },
);

async function handleFor(): Promise<{ token: string; expiresAt: string }> {
  const made = await route('/api/handles', { method: 'POST', headers: { authorization: `Bearer ${await sessionFor(DEV)}`, 'content-type': 'application/json' }, body: JSON.stringify({ label: 'run', paths: ['market/dev'] }) });
  return (await made.json()) as { token: string; expiresAt: string };
}

async function planFor(handle: string): Promise<{ env: Record<string, string>; left: string[] }> {
  const plan = await route('/use/market/dev', { headers: { authorization: `Bearer ${handle}` } });
  assert.equal(plan.status, 200, await plan.clone().text());
  return (await plan.json()) as { env: Record<string, string>; left: string[] };
}

test("DFNS's own SDK, its token a JWT placeholder, reads its organization from it and reaches the fake DFNS with the real token", async () => {
  const { token: handle, expiresAt } = await handleFor();
  const watched = LOG === '0.15' ? watchUses(deps.vault) : null;
  const { env } = await planFor(handle);
  const [head, payload, last] = env.DFNS_AUTH_TOKEN!.split('.');
  assert.deepEqual(JSON.parse(Buffer.from(head!, 'base64url').toString()), { alg: 'none', typ: 'JWT' });
  const claims = JSON.parse(Buffer.from(payload!, 'base64url').toString()) as Record<string, unknown>;
  // The named claim and the handle's end, and nothing else of the real token's: no subject, no issuer.
  assert.deepEqual(Object.keys(claims).sort(), ['exp', APP_METADATA]);
  assert.deepEqual(claims[APP_METADATA], { orgId: 'or-sandbox', tenantId: 'tn-sandbox', tokenKind: 'ServiceAccount' });
  assert.equal(claims.exp, Math.floor(Date.parse(expiresAt) / 1000), "exp is the handle's end");
  assert.equal(last, handle);
  assert.equal(env.STRIPE_SECRET_KEY, `sk_test_${handle}`);

  // The SDK as Equisafe's backend makes it, the org it expects named: it checks the token's scope before every request.
  // Its base URL is the app's own config: the proxy's stable URL, which the test's coffre, on loopback, answers.
  const sdk = new DfnsApiClient({ baseUrl: `${coffreUrl}/use/dfns`, authToken: env.DFNS_AUTH_TOKEN!, orgId: 'or-sandbox' });
  const wallets = await sdk.wallets.listWallets();
  assert.deepEqual(wallets.items.map((wallet) => wallet.id), ['wa-1']);
  const [sent] = received;
  assert.equal(sent!.url, '/wallets');
  assert.equal(sent!.authorization, `Bearer ${TOKEN}`, 'the whole header replaced: the real token, and nothing of the placeholder');
  assert.deepEqual(sent!.scope, { orgId: 'or-sandbox', tenantId: 'tn-sandbox' });

  // An opaque handle is what the SDK refuses before it sends anything, as 0.8's placeholder was.
  await assert.rejects(new DfnsApiClient({ baseUrl: coffreUrl, authToken: handle }).wallets.listWallets(), /could not be properly parsed/);

  // The plan opened the real token for its claims, as a use of the credential, logged; the request opened it again.
  if (watched !== null) {
    watched.stop();
    // 0.15: the token used for each placeholder that copies its claims (dfns's, and q's), then for the request, the
    // repeats riding the first's cover. Its row is slim (R53), naming no credential, claim or host.
    const token = await keyIds(db.owner, 'DFNS_AUTH_TOKEN');
    assert.equal(watched.asked.filter((use) => token.includes(use.secretId) && use.purpose === 'use').length, 3);
    return;
  }
  const uses = (await entries('credential.use')).filter((entry) => entry.metadata.credential === 'dfns');
  assert.deepEqual(uses.map((entry) => entry.metadata.placeholder ?? entry.metadata.host), [{ claims: [APP_METADATA] }, new URL(dfnsUrl).host]);
});

test("a shaped placeholder's slot is that shape exactly; the handle goes nowhere else, and the real token echoed back is redacted", async () => {
  const { token: handle } = await handleFor();
  const { env } = await planFor(handle);
  const call = (path: string, authorization: string, init: RequestInit = {}) => route(`/use/market/dev/dfns${path}`, { ...init, headers: { authorization, ...(init.headers as Record<string, string> | undefined) } });

  assert.equal((await call('/wallets', `Bearer ${env.DFNS_AUTH_TOKEN}`)).status, 200);
  // Any header and payload, as the proxy reads neither: the handle in the third part is what lets it in.
  assert.equal((await call('/wallets', `Bearer e30.e30.${handle}`)).status, 200);
  // Not the bare handle, nor the placeholder out of its frame, nor a JWT with something after the handle.
  for (const slot of [`Bearer ${handle}`, env.DFNS_AUTH_TOKEN!, `Bearer x ${env.DFNS_AUTH_TOKEN}`, `Bearer ${env.DFNS_AUTH_TOKEN}.x`, `Bearer e30.${handle}`]) {
    const refused = await call('/wallets', slot);
    assert.equal(refused.status, 401, slot);
    assert.equal(refused.headers.get('coffre-proxy'), 'refused');
  }
  // The helper's way, the handle as x-coffre-handle, still holds.
  assert.equal((await route('/use/market/dev/dfns/wallets', { headers: { 'x-coffre-handle': handle } })).status, 200);

  // The handle anywhere but its slot is refused before it leaves, the placeholder in a body included.
  const leaked = await call('/wallets', `Bearer ${env.DFNS_AUTH_TOKEN}`, { method: 'POST', body: JSON.stringify({ token: env.DFNS_AUTH_TOKEN }) });
  assert.equal(leaked.status, 400);
  assert.equal((await call('/wallets', `Bearer ${env.DFNS_AUTH_TOKEN}`, { headers: { 'x-other': env.DFNS_AUTH_TOKEN! } })).status, 400);

  const echoed = await call('/echo', `Bearer ${env.DFNS_AUTH_TOKEN}`);
  const text = await echoed.text();
  assert.equal(text.includes(TOKEN), false, text);
  assert.match(text, /token \[redacted by coffre\] is not allowed/);
  assert.ok(received.every((request) => !request.authorization.includes(handle)), 'the handle never reaches DFNS');

  // A redirect under a query rule's upstream gives back the app's placeholder, or, where the app sent none that stands in for
  // this handle, one of the same shape: the app follows it with no header of coffre's and is let in.
  const follow = async (path: string, headers: Record<string, string> = {}) => {
    const moved = await route(`/use/market/dev/q${path}`, { headers });
    assert.equal(moved.status, 302, await moved.clone().text());
    const to = new URL(moved.headers.get('location')!);
    assert.equal((await route(`${to.pathname}${to.search}`)).status, 200, to.href);
    return to.searchParams.get('token')!;
  };
  assert.equal(await follow(`/moved?token=${env.DFNS_AUTH_TOKEN}`), env.DFNS_AUTH_TOKEN);
  assert.match(await follow('/moved?token=unused', { 'x-coffre-handle': handle }), new RegExp(`^[\\w-]+\\.e30\\.${handle}$`));
  assert.match(await follow('/moved', { 'x-coffre-handle': handle }), new RegExp(`\\.${handle}$`));

  // A prefix: the same, `sk_test_` before the handle.
  assert.equal((await route('/use/market/dev/stripe/v1/charges', { headers: { authorization: `Bearer ${env.STRIPE_SECRET_KEY}` } })).status, 200);
  assert.equal(received.at(-1)!.authorization, `Bearer ${STRIPE}`);
  assert.equal((await route('/use/market/dev/stripe/v1/charges', { headers: { authorization: `Bearer ${handle}` } })).status, 401);
});

test('a JWT placeholder for a key that holds no JWT fails the plan, saying so and quoting nothing', async () => {
  await clientFor(deps, ROOT).secrets.set('market/dev', { NOT_A_JWT: 'opaque-secret-0123456789' });
  const { token: handle } = await handleFor();
  const plan = await route('/use/market/dev', { headers: { authorization: `Bearer ${handle}` } });
  assert.equal(plan.status, 409);
  const text = await plan.text();
  assert.match(text, /market\/dev's NOT_A_JWT is no JWT, which broken's placeholder copies its claims from/);
  assert.equal(text.includes('opaque-secret'), false);
});

test('a shaped placeholder is for a header, query, form or JSON rule that carries one key: anything else is refused at configuration', () => {
  const make = (credential: CredentialProxyOptions['credentials'][string]) => () => credentialProxy({ credentials: { a: credential } });
  const upstream = 'https://api.example.com';
  assert.throws(make({ upstream, inject: basic('{ID}', '{SECRET}'), placeholder: prefix('sk_') }), /a's placeholder shapes the one key a header, query, form or JSON rule carries.*not a basic\(\) rule/);
  assert.throws(make({ upstream, inject: sigv4({ accessKeyId: '{A}', secretAccessKey: '{B}', region: 'eu-west-3', service: 's3' }), placeholder: jwt() }), /not a sigv4\(\) rule/);
  assert.throws(make({ upstream, inject: header('authorization', '{ID}:{TOKEN}'), placeholder: jwt() }), /several keys/);
  assert.throws(make({ upstream, inject: header('x', '{K}{K}'), placeholder: prefix('a') }), /several keys, or one twice/);
  assert.throws(make({ upstream, inject: header('x', '{K}'), placeholder: prefix('has space') }), /prefix\(\) is up to 64/);
  assert.throws(make({ upstream, inject: header('x', '{K}'), placeholder: jwt({ claims: ['exp'] }) }), /exp is the handle's end/);
  assert.throws(make({ upstream, inject: header('x', '{K}'), placeholder: { kind: 'other' } as never }), /jwt\(…\) or prefix\(…\)/);
  // The app holds one value for a key: two credentials that read it give it one placeholder.
  const two = (placeholder?: ReturnType<typeof jwt>) => () => credentialProxy({ credentials: { a: { upstream, inject: header('authorization', 'Bearer {K}'), placeholder: jwt({ claims: ['org'] }) }, b: { upstream, inject: query('k', '{K}'), ...(placeholder === undefined ? {} : { placeholder }) } } });
  assert.throws(two(), /a and b read K with different placeholders/);
  assert.throws(two(jwt({ claims: ['other'] })), /different placeholders/);
  assert.doesNotThrow(two(jwt({ claims: ['org'] })));
  assert.doesNotThrow(make({ upstream, inject: query('token', 'v1:{K}'), placeholder: jwt({ claims: ['org'] }) }));
});
