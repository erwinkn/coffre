// UI definitions served by the credential proxy (0.16, T186 PR C; docs/design/proxy-ui.md, sections 3, 4 and 6), end
// to end: coffre's own vault, a route saved in the Proxy tab, a handle as `coffre run` makes one, and a fake upstream
// over HTTP. The route use is the vault's one call, which reads the URL both ways; every request goes by the item the
// vault decided on (SentAsDecided), kept values by the item they were decided on (BoundToDefinition); code wins its
// names, reserved before an isolate's first proxy request (CodeGate, ClearSuperseded); an editor who no longer holds
// the key stops their route (EditorStillHolds).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, type Hash, type Hmac } from 'node:crypto';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { SignatureV4 } from '@smithy/signature-v4';

import { createClient, type CoffreClient } from '@coffre/client';
import { Deploying, USE_DEADLINE_MS, type ProxyDefinition, type Vault } from '@coffre/core/vault';

import { sql, type SQL } from 'drizzle-orm';

import { clientFor, LOG } from './api-fixture.ts';
import { TEST_ENGINE } from './db/engine.ts';
import { db, deps, DEV, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { coffreRoute } from '../src/app.ts';
import { bindingRoute, checkPlugins } from '../src/plugins.ts';
import { proxyCodeOf } from '../src/proxy-code.ts';
import { forgetProxyGates } from '../src/proxy-gate.ts';
import { credentialProxy, header, privateKey, type CredentialProxyOptions } from '../src/plugins/credential-proxy.ts';

const OPENAI = 'sk-openai-dev-0123456789abcdef';
const MAPS = 'maps-key-0123456789abcdef';
const LIN = 'lin@acme.example';
const AWS_ID = 'AKIAREALKEY000000001';
const AWS_SECRET = 'real/secret+access/key0123456789ABCDEFGH';
const ON_015 = { skip: LOG === '0.14' ? "proxy definitions are 0.15's log's objects" : false };

let upstream: Server;
let upstreamUrl: string;
const reached: { method: string; url: string; headers: IncomingMessage['headers']; body: string }[] = [];

before(async () => {
  upstream = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => {
      reached.push({ method: request.method!, url: request.url!, headers: request.headers, body: Buffer.concat(chunks).toString() });
      response.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}');
    });
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  upstreamUrl = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
});
after(() => new Promise<void>((resolve) => upstream.close(() => resolve())));

/** The deployment's proxy: code's `maps` (or none), the tab writing, local fakes allowed. */
function proxyOf(extra: Partial<CredentialProxyOptions> = {}, code = true) {
  return credentialProxy({
    credentials: code ? { maps: { upstream: `${upstreamUrl}/maps`, inject: header('x-api-key', '{MAPS_KEY}') } } : {},
    signers: { signing: privateKey('SIGNING_KEY') },
    editable: true, insecureUpstreams: true, ...extra,
  });
}

/** A route saved in the UI: `name` to `path` under the fake upstream, its key in Authorization, GET and POST as given. */
function uiRoute(name: string, path: string, key = 'OPENAI_API_KEY'): ProxyDefinition {
  return {
    kind: 'route', name, upstream: `${upstreamUrl}${path}`, inject: [{ kind: 'header', name: 'authorization', template: `Bearer {${key}}` }],
    allow: [{ methods: ['GET'], path: '/models/**' }, { methods: ['POST'], path: '/chat/completions' }], limit: { perMinute: null, perDay: null }, placeholder: null, egress: null,
  };
}

/** The deployment in front: its plugins, and the API's view of its proxy code. */
function deploy(plugin: ReturnType<typeof proxyOf>): void {
  runtime.plugins = checkPlugins([plugin]);
  deps.proxy = proxyCodeOf(runtime.plugins);
}

let root: CoffreClient;

useMcp(async () => {
  if (LOG === '0.14') return;
  deploy(proxyOf());
  reached.length = 0;
  root = clientFor(deps, ROOT);
  await root.members.add(`user:${DEV}`);
  await root.members.add(`user:${LIN}`);
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { OPENAI_API_KEY: OPENAI, MAPS_KEY: MAPS });
  await root.access.set(`user:${DEV}`, { market: 'developer' });
});

/** A save in `path`'s Proxy tab, market/dev's by default, on the seal it shows now, by `as`. */
async function save(items: Record<string, ProxyDefinition | null>, as: CoffreClient = root, path = 'market/dev'): Promise<void> {
  const page = await as.proxy.get(path);
  await as.proxy.save(path, { seal: page.seal, items });
}

/** A handle for DEV on `path`, market/dev by default, as `coffre run` makes one. */
async function handle(path = 'market/dev'): Promise<string> {
  const session = await sessionFor(DEV);
  const api = createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${session}` }), transport: (request) => coffreRoute(request, runtime, '203.0.113.7').then((response) => response!) });
  return (await api.handles.create({ label: 'coffre run market/dev', paths: [path] })).token;
}

/** Raw SQL as the owner, on either engine: a row changed around the vault. */
async function run(query: SQL): Promise<void> {
  if (TEST_ENGINE === 'sqlite') await (db.owner as unknown as { run: (q: SQL) => Promise<unknown> }).run(query);
  else await (db.owner as unknown as { execute: (q: SQL) => Promise<unknown> }).execute(query);
}

const as = (token: string, init: RequestInit = {}): RequestInit => ({ ...init, headers: { authorization: `Bearer ${token}`, ...(init.headers as Record<string, string> | undefined) } });

test('a UI route by its stable URL and by its place: sent to the item the vault decided on, its key injected, the handle going nowhere', ON_015, async () => {
  await save({ openai: uiRoute('openai', '/openai/v1') });
  const token = await handle();
  const stable = await route('/use/openai/models/gpt', as(token));
  assert.equal(stable.status, 200, await stable.clone().text());
  assert.equal(reached.at(-1)!.url, '/openai/v1/models/gpt');
  assert.equal(reached.at(-1)!.headers.authorization, `Bearer ${OPENAI}`);
  assert.ok(!JSON.stringify(reached.at(-1)!.headers).includes(token));
  const placed = await route('/use/market/dev/openai/chat/completions', as(token, { method: 'POST', body: '{}' }));
  assert.equal(placed.status, 200, await placed.clone().text());
  assert.deepEqual([reached.at(-1)!.method, reached.at(-1)!.url], ['POST', '/openai/v1/chat/completions']);
  // Its allow list, the decided item's: nothing sent.
  const before = reached.length;
  assert.equal((await route('/use/openai/chat/completions', as(token))).status, 405);
  assert.equal((await route('/use/openai/files', as(token))).status, 403);
  assert.equal(reached.length, before);
});

test('an edit reaches the next use; values kept for `cacheSeconds` go only where the item they were decided on says (BoundToDefinition)', ON_015, async () => {
  await save({ openai: uiRoute('openai', '/old') });
  const token = await handle();
  assert.equal((await route('/use/openai/models', as(token))).status, 200);
  assert.equal(reached.at(-1)!.url, '/old/models');
  await save({ openai: uiRoute('openai', '/new') });
  // Another handle on the same isolate brings the new item: the isolate's copy is now `/new`.
  assert.equal((await route('/use/openai/models', as(await handle()))).status, 200);
  assert.equal(reached.at(-1)!.url, '/new/models');
  // The first handle's values, kept (60 s by default), still go by the item they were decided on, never by the newer copy.
  assert.equal((await route('/use/openai/models', as(token))).status, 200);
  assert.equal(reached.at(-1)!.url, '/old/models');
  // An isolate that keeps nothing: each request decided on the newest version.
  deploy(proxyOf({ cacheSeconds: 0 }));
  assert.equal((await route('/use/openai/models', as(token))).status, 200);
  assert.equal(reached.at(-1)!.url, '/new/models');
});

test("EditorStillHolds: a route its editor saved stops once they no longer read its key, until someone who does saves it again", ON_015, async () => {
  deploy(proxyOf({ cacheSeconds: 0 }));
  await root.roles.set('router', { name: 'Router', description: 'routes keys', permissions: ['secret.read', 'secret.use', 'proxy.edit'], protected: ['secret.use'] });
  await root.access.set(`user:${LIN}`, { market: 'router' });
  const lin = clientFor(deps, LIN);
  await save({ openai: uiRoute('openai', '/lin') }, lin);
  const token = await handle();
  assert.equal((await route('/use/openai/models', as(token))).status, 200);
  // A contributor uses and writes keys, never reads them: the editor no longer holds what the route sends.
  await root.access.set(`user:${LIN}`, { market: 'contributor' });
  const stopped = await route('/use/openai/models', as(token));
  assert.equal(stopped.status, 403, await stopped.clone().text());
  assert.equal((await stopped.json() as { reason: string }).reason, 'route_not_cleared');
  // Saved again by an Owner, unchanged: cleared as theirs.
  await save({ openai: uiRoute('openai', '/lin') });
  assert.equal((await route('/use/openai/models', as(token))).status, 200);
});

test('code wins its names: reserved before an isolate first serves, the UI item of a name code adds deleted (CodeGate, ClearSuperseded)', ON_015, async () => {
  deploy(proxyOf({ cacheSeconds: 0 }, false));
  await save({ maps: uiRoute('maps', '/ui-maps', 'MAPS_KEY') });
  const token = await handle();
  assert.equal((await route('/use/maps/models', as(token))).status, 200);
  assert.equal(reached.at(-1)!.url, '/ui-maps/models');
  // A deploy adding code `maps`: its first request reserves the name, which deletes the UI item, before it serves.
  deploy(proxyOf({ cacheSeconds: 0 }, true));
  assert.equal((await route('/use/maps/geocode', { headers: { 'x-api-key': token } })).status, 200);
  assert.equal(reached.at(-1)!.url, '/maps/geocode');
  const page = await root.proxy.get('market/dev');
  assert.deepEqual(page.items.map((item) => item.definition.name), []);
  assert.ok(page.reserved.includes('maps'));
  // And when a later deployment drops `maps`, the UI item it hid does not come back (NoRevival).
  deploy(proxyOf({ cacheSeconds: 0 }, false));
  assert.equal((await route('/use/maps/models', as(token))).status, 404);
});

test('a name no definition holds is 404; a signer saved in the UI reaches no upstream; a personal config serves no UI route (409)', ON_015, async () => {
  const token = await handle();
  assert.equal((await route('/use/nothing/x', as(token))).status, 404);
  await save({ openai: uiRoute('openai', '/openai') });
  // A handle made for market/dev reads `/use/market/dev@me/openai/…` as the stable URL, a route `market` (section 6).
  const stable = await route('/use/market/dev@me/openai/models', as(token));
  assert.equal(stable.status, 404, await stable.clone().text());
  assert.match((await stable.json() as { message: string }).message, /no credential "market"/);
  // One made for market/dev@me reads the place, a personal config: 409 naming the base environment (decision 7).
  const personal = await route('/use/market/dev@me/openai/models', as(await handle('market/dev@me')));
  assert.equal(personal.status, 409, await personal.clone().text());
  assert.match((await personal.json() as { message: string }).message, /market\/dev\b(?!@)/);
  await save({ signer: { kind: 'signer', name: 'signer', signer: { kind: 'private-key', key: 'OPENAI_API_KEY' }, limit: { perMinute: null, perDay: null } } });
  assert.equal((await route('/use/signer/x', as(token))).status, 404);
});

test("the plan gives a UI route's key as the handle, never its value, and names its URL; one forged item answers 503 and no environment", ON_015, async () => {
  await save({ openai: uiRoute('openai', '/openai') });
  const token = await handle();
  const planned = await route('/use/market/dev', as(token));
  assert.equal(planned.status, 200, await planned.clone().text());
  const plan = await planned.json() as { env: Record<string, string>; credentials: Record<string, string>; left: string[] };
  assert.equal(plan.env.OPENAI_API_KEY, token);
  assert.equal(plan.env.MAPS_KEY, token);
  assert.equal(plan.credentials.openai, `${ORIGIN}/use/market/dev/openai`);
  assert.ok(!JSON.stringify(plan).includes(OPENAI));
  // Without the tab, no UI item serves: the key is the person's to read, as any uncovered key.
  deploy(proxyOf({ editable: false }));
  const plain = await (await route('/use/market/dev', as(token))).json() as { env: Record<string, string>; credentials: Record<string, string> };
  assert.equal(plain.env.OPENAI_API_KEY, OPENAI);
  assert.equal(plain.credentials.openai, undefined);
  // One item forged around the vault: no plan, rather than one shaped from code alone, which would hand the app its values.
  deploy(proxyOf());
  await run(TEST_ENGINE === 'postgres' ? sql`UPDATE proxy_definitions SET items = jsonb_set(items, '{openai,savedAt}', '1')` : sql`UPDATE proxy_definitions SET items = json_set(items, '$.openai.savedAt', 1)`);
  const forged = await route('/use/market/dev', as(token));
  assert.equal(forged.status, 503);
  assert.ok(!(await forged.text()).includes(OPENAI));
});

/** SHA-256 and its HMAC, as the SDK's signer takes a hash. */
type SourceData = string | ArrayBuffer | ArrayBufferView;
const bytes = (data: SourceData) => (typeof data === 'string' ? data : ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : new Uint8Array(data));
class Sha256 {
  readonly #hash: Hash | Hmac;
  constructor(secret?: SourceData) {
    this.#hash = secret === undefined ? createHash('sha256') : createHmac('sha256', bytes(secret));
  }
  update(data: SourceData): void {
    this.#hash.update(bytes(data));
  }
  async digest(): Promise<Uint8Array> {
    return new Uint8Array(this.#hash.digest());
  }
}

test('a UI route of three keys, a header and SigV4: one use decides them all, the request signed with the real pair, the handle going nowhere', ON_015, async () => {
  await root.secrets.set('market/dev', { AWS_ACCESS_KEY_ID: AWS_ID, AWS_SECRET_ACCESS_KEY: AWS_SECRET });
  await save({
    s3: {
      kind: 'route', name: 's3', upstream: `${upstreamUrl}/s3`,
      inject: [{ kind: 'header', name: 'x-tenant-key', template: '{OPENAI_API_KEY}' }, { kind: 'sigv4', accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', sessionToken: null, region: 'eu-west-3', service: 's3' }],
      allow: null, limit: { perMinute: null, perDay: null }, placeholder: null, egress: null,
    },
  });
  const token = await handle();
  const plan = await (await route('/use/market/dev', as(token))).json() as { env: Record<string, string> };
  assert.deepEqual([plan.env.AWS_ACCESS_KEY_ID, plan.env.AWS_SECRET_ACCESS_KEY, plan.env.OPENAI_API_KEY], [token, token, token]);
  // As the SDK signs it: the handle its access key, with any secret, which the proxy discards.
  const signer = new SignatureV4({ credentials: { accessKeyId: token, secretAccessKey: 'placeholder' }, region: 'eu-west-3', service: 's3', sha256: Sha256, uriEscapePath: false, applyChecksum: false });
  const target = new URL(`${ORIGIN}/use/s3/bucket/report.csv`);
  const signed = await signer.sign({ method: 'GET', protocol: 'https:', hostname: target.hostname, path: target.pathname, headers: { host: target.host, 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' } });
  const answer = await route('/use/s3/bucket/report.csv', { headers: signed.headers });
  assert.equal(answer.status, 200, await answer.clone().text());
  const sent = reached.at(-1)!;
  assert.equal(sent.url, '/s3/bucket/report.csv');
  assert.equal(sent.headers['x-tenant-key'], OPENAI);
  assert.match(String(sent.headers.authorization), new RegExp(`^AWS4-HMAC-SHA256 Credential=${AWS_ID}/`));
  assert.match(String(sent.headers.authorization), /SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-tenant-key,/);
  assert.ok(!JSON.stringify(sent.headers).includes(token));
});

test("a fork serves its parent's UI route, the item and its key found through the chain; the fork's own item overrides it", ON_015, async () => {
  deploy(proxyOf({ cacheSeconds: 0 }));
  await save({ openai: uiRoute('openai', '/parent') });
  await root.environments.create('market/dev-eu', { from: 'dev', inherit: true });
  const token = await handle('market/dev-eu');
  const inherited = await route('/use/openai/models', as(token));
  assert.equal(inherited.status, 200, await inherited.clone().text());
  assert.deepEqual([reached.at(-1)!.url, reached.at(-1)!.headers.authorization], ['/parent/models', `Bearer ${OPENAI}`]);
  const page = await root.proxy.get('market/dev-eu');
  await root.proxy.save('market/dev-eu', { seal: page.seal, items: { openai: uiRoute('openai', '/child') } });
  assert.equal((await route('/use/market/dev-eu/openai/models', as(token))).status, 200);
  assert.equal(reached.at(-1)!.url, '/child/models');
});

test("the gate: a vault that cannot reserve code's names, or one on another release, answers 503 and nothing is sent or kept; the next request asks again and is served", ON_015, async () => {
  await save({ openai: uiRoute('openai', '/openai') });
  const token = await handle();
  // An isolate that has not yet passed the gate, the save's API call having passed it in this one.
  forgetProxyGates();
  const vault = runtime.vault as unknown as { reserveProxy: Vault['reserveProxy'] };
  const real = vault.reserveProxy;
  let asked = 0;
  try {
    vault.reserveProxy = async () => {
      asked += 1;
      throw new Error('the vault is down');
    };
    const down = await route('/use/openai/models', as(token));
    assert.equal(down.status, 503, await down.clone().text());
    vault.reserveProxy = async () => {
      asked += 1;
      throw new Deploying('9.9.9', '9.9.9');
    };
    const deploying = await route('/use/openai/models', as(token));
    assert.equal(deploying.status, 503);
    assert.equal(deploying.headers.get('retry-after'), '1');
    assert.equal((await deploying.json() as { error: string }).error, 'deploying');
    assert.equal(asked, 2, 'a failed gate keeps nothing: each request asks again');
    assert.equal(reached.length, 0);
  } finally {
    vault.reserveProxy = real;
  }
  assert.equal((await route('/use/openai/models', as(token))).status, 200);
  assert.equal(reached.length, 1);
});

test("values go out within their window: a body that comes after the use's deadline is sent with none (review r1 of #467)", ON_015, async () => {
  deploy(proxyOf({ cacheSeconds: 0 }));
  await save({ openai: uiRoute('openai', '/openai') });
  const token = await handle();
  // The handle in a header, so the use is made at once; the body, read whole, comes 3.5 s later.
  const body = new ReadableStream<Uint8Array>({
    async start(controller) {
      controller.enqueue(new TextEncoder().encode('{"model":'));
      await new Promise((resolve) => setTimeout(resolve, USE_DEADLINE_MS + 500));
      controller.enqueue(new TextEncoder().encode('"gpt"}'));
      controller.close();
    },
  });
  const late = await route('/use/openai/chat/completions', as(token, { method: 'POST', body, duplex: 'half' } as RequestInit));
  assert.equal(late.status, 503, await late.clone().text());
  assert.equal((await late.json() as { reason: string }).reason, 'late');
  assert.equal(reached.length, 0);
  // In time, the same request goes.
  assert.equal((await route('/use/openai/chat/completions', as(token, { method: 'POST', body: '{"model":"gpt"}' }))).status, 200);
});

test("values go out within their window however long signing takes: a SigV4 request signed after the deadline is sent with none (review r3 of #467)", ON_015, async () => {
  deploy(proxyOf({ cacheSeconds: 0 }));
  await root.secrets.set('market/dev', { AWS_ACCESS_KEY_ID: AWS_ID, AWS_SECRET_ACCESS_KEY: AWS_SECRET });
  await save({
    s3: {
      kind: 'route', name: 's3', upstream: `${upstreamUrl}/s3`, inject: [{ kind: 'sigv4', accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', sessionToken: null, region: 'eu-west-3', service: 's3' }],
      allow: null, limit: { perMinute: null, perDay: null }, placeholder: null, egress: null,
    },
  });
  const token = await handle();
  const signer = new SignatureV4({ credentials: { accessKeyId: token, secretAccessKey: 'placeholder' }, region: 'eu-west-3', service: 's3', sha256: Sha256, uriEscapePath: false, applyChecksum: false });
  const target = new URL(`${ORIGIN}/use/s3/bucket/report.csv`);
  const signed = await signer.sign({ method: 'GET', protocol: 'https:', hostname: target.hostname, path: target.pathname, headers: { host: target.host, 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' } });
  // The proxy's own signature, its last HMAC (of the string to sign), made after the values' window closed.
  const real = crypto.subtle.sign.bind(crypto.subtle);
  let slowed = 0;
  crypto.subtle.sign = (async (algorithm: AlgorithmIdentifier, key: CryptoKey, data: BufferSource) => {
    if (new TextDecoder().decode(data as Uint8Array).startsWith('AWS4-HMAC-SHA256\n')) {
      slowed += 1;
      await new Promise((resolve) => setTimeout(resolve, USE_DEADLINE_MS + 500));
    }
    return real(algorithm, key, data);
  }) as typeof crypto.subtle.sign;
  try {
    const late = await route('/use/s3/bucket/report.csv', { headers: signed.headers });
    assert.equal(late.status, 503, await late.clone().text());
    assert.equal((await late.json() as { reason: string }).reason, 'late');
  } finally {
    crypto.subtle.sign = real;
  }
  assert.equal(slowed, 1);
  assert.equal(reached.length, 0);
  // Signed in time, the same request goes.
  assert.equal((await route('/use/s3/bucket/report.csv', { headers: signed.headers })).status, 200);
});

test("a personal config's plan: its UI items none, the plan given (review r1 of #467)", ON_015, async () => {
  await save({ openai: uiRoute('openai', '/openai') });
  const token = await handle('market/dev@me');
  const planned = await route('/use/market/dev@me', as(token));
  assert.equal(planned.status, 200, await planned.clone().text());
  const plan = await planned.json() as { environment: string; credentials: Record<string, string> };
  assert.equal(plan.credentials.openai, undefined);
});

test("the URL's reading decides before code's precedence: `/use/openai/models/maps` is route openai at /models/maps, code's `maps` at `openai/models` only for a handle made for it (review r1 of #467)", ON_015, async () => {
  deploy(proxyOf({ cacheSeconds: 0 }));
  await save({ openai: uiRoute('openai', '/openai') });
  const token = await handle();
  const answer = await route('/use/openai/models/maps', as(token));
  assert.equal(answer.status, 200, await answer.clone().text());
  assert.equal(reached.at(-1)!.url, '/openai/models/maps');
  // The place reading, a handle made for market/dev: code's `maps`, as before.
  assert.equal((await route('/use/market/dev/maps/geocode', { headers: { 'x-api-key': token } })).status, 200);
  assert.equal(reached.at(-1)!.url, '/maps/geocode');
});

test('a two-segment stable URL whose handle rides only in the body: the UI route, not compute (review r1 of #467)', ON_015, async () => {
  deploy(proxyOf({ cacheSeconds: 0 }));
  await save({
    login: {
      kind: 'route', name: 'login', upstream: `${upstreamUrl}/login`, inject: [{ kind: 'form', name: 'client_secret', template: '{OPENAI_API_KEY}' }],
      allow: [{ methods: ['POST'], path: '/token' }], limit: { perMinute: null, perDay: null }, placeholder: null, egress: null,
    },
  });
  const token = await handle();
  const answer = await route('/use/login/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: `grant_type=client_credentials&client_secret=${token}` });
  assert.equal(answer.status, 200, await answer.clone().text());
  assert.deepEqual([reached.at(-1)!.method, reached.at(-1)!.url], ['POST', '/login/token']);
});

test("a service binding's call is never served a handle's kept values: no UI route for it before C2b, the copy unread (review r2 of #467)", ON_015, async () => {
  await save({ openai: uiRoute('openai', '/openai') });
  const token = await handle();
  assert.equal((await route('/use/market/dev/openai/models', as(token))).status, 200);
  const before = reached.length;
  // The same URL and handle through a binding, on the same isolate, within cacheSeconds: nothing sent.
  const bound = await bindingRoute(new Request(`${ORIGIN}/use/market/dev/openai/models`, as(token)), runtime, 'token:svc')!;
  assert.equal(bound.status, 404, await bound.clone().text());
  assert.equal(reached.length, before);
});

test("a place copy's allow list refuses only a handle whose checked made-for list chose that place: a stranger's token is 401, never the copy's 403 (review r2 of #467)", ON_015, async () => {
  // `123` can be no route's name, so `/use/123/dev/openai/…` has the place reading alone.
  await root.projects.create('123');
  await root.environments.create('123/dev');
  await root.secrets.set('123/dev', { OPENAI_API_KEY: OPENAI });
  await root.access.set(`user:${DEV}`, { market: 'developer', 123: 'developer' });
  await save({ openai: uiRoute('openai', '/openai') }, root, '123/dev');
  const token = await handle('123/dev');
  assert.equal((await route('/use/123/dev/openai/models', as(token))).status, 200);
  assert.equal((await route('/use/123/dev/openai/files', as(token))).status, 403);
  const stranger = await route('/use/123/dev/openai/files', as(`coffre_use_${'A'.repeat(43)}`));
  assert.equal(stranger.status, 401, await stranger.clone().text());
});

for (const cacheSeconds of [60, 0]) {
  test(`a project named as code's credential is: its environment's UI route at the place URL, cacheSeconds ${cacheSeconds} (review r2 of #467)`, ON_015, async () => {
    deploy(proxyOf({ cacheSeconds }));
    await root.projects.create('maps');
    await root.environments.create('maps/dev');
    await root.secrets.set('maps/dev', { OPENAI_API_KEY: OPENAI });
    await root.access.set(`user:${DEV}`, { market: 'developer', maps: 'developer' });
    await save({ openai: uiRoute('openai', '/openai') }, root, 'maps/dev');
    const token = await handle('maps/dev');
    const plan = await (await route('/use/maps/dev', as(token))).json() as { credentials: Record<string, string> };
    assert.equal(plan.credentials.openai, `${ORIGIN}/use/maps/dev/openai`);
    const answer = await route('/use/maps/dev/openai/models', as(token));
    assert.equal(answer.status, 200, await answer.clone().text());
    assert.equal(reached.at(-1)!.url, '/openai/models');
    assert.equal(reached.at(-1)!.headers.authorization, `Bearer ${OPENAI}`);
  });
}

for (const cacheSeconds of [60, 0]) {
  test(`a project named as code's credential is: its UI route's handle wherever the item takes it, the body read once, cacheSeconds ${cacheSeconds} (review r3 of #467)`, ON_015, async () => {
    deploy(proxyOf({ cacheSeconds }));
    await root.projects.create('maps');
    await root.environments.create('maps/dev');
    await root.secrets.set('maps/dev', { OPENAI_API_KEY: OPENAI });
    await root.access.set(`user:${DEV}`, { market: 'developer', maps: 'developer' });
    const allow = [{ methods: ['POST'], path: '/chat/completions' }, { methods: ['POST'], path: '/token' }];
    await save({
      openai: { ...uiRoute('openai', '/openai'), inject: [{ kind: 'header', name: 'x-openai-key', template: '{OPENAI_API_KEY}' }], allow } as ProxyDefinition,
      login: { ...uiRoute('login', '/login'), inject: [{ kind: 'form', name: 'client_secret', template: '{OPENAI_API_KEY}' }], allow } as ProxyDefinition,
    }, root, 'maps/dev');
    const token = await handle('maps/dev');
    // Code's `maps` takes its handle in x-api-key: this one is in the route's own header, which code's reading never looks at.
    const body = '{"model":"gpt","messages":[]}';
    const custom = await route('/use/maps/dev/openai/chat/completions', { method: 'POST', headers: { 'x-openai-key': token, 'content-type': 'application/json' }, body });
    assert.equal(custom.status, 200, await custom.clone().text());
    assert.deepEqual([reached.at(-1)!.url, reached.at(-1)!.headers['x-openai-key'], reached.at(-1)!.body], ['/openai/chat/completions', OPENAI, body]);
    // Only in the body, as a form rule takes it.
    const form = await route('/use/maps/dev/login/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: `grant_type=client_credentials&client_secret=${token}` });
    assert.equal(form.status, 200, await form.clone().text());
    assert.deepEqual([reached.at(-1)!.url, reached.at(-1)!.body], ['/login/token', `grant_type=client_credentials&client_secret=${encodeURIComponent(OPENAI)}`]);
    // As x-coffre-handle, with a body: code's `maps` reads the body first, with no cache, and the route sends the same bytes.
    const coffre = await route('/use/maps/dev/openai/chat/completions', { method: 'POST', headers: { 'x-coffre-handle': token, 'content-type': 'application/json' }, body });
    assert.equal(coffre.status, 200, await coffre.clone().text());
    assert.deepEqual([reached.at(-1)!.url, reached.at(-1)!.headers['x-openai-key'], reached.at(-1)!.body], ['/openai/chat/completions', OPENAI, body]);
    // A handle made for another environment is code's `maps` at /dev/openai/…, which finds no handle where it takes its key.
    assert.equal((await route('/use/maps/dev/openai/chat/completions', { method: 'POST', headers: { 'x-openai-key': await handle() }, body })).status, 401);
    assert.equal(reached.length, 3);
  });
}

test('two routes reading one key with different placeholders: the plan refuses (409), as startup refuses it of code (review r2 of #467)', ON_015, async () => {
  const shaped = (name: string, prefix: string): ProxyDefinition => ({ ...uiRoute(name, `/${name}`), placeholder: { kind: 'prefix', prefix } } as ProxyDefinition);
  await save({ alpha: shaped('alpha', 'a_'), beta: shaped('beta', 'b_') });
  const planned = await route('/use/market/dev', as(await handle()));
  assert.equal(planned.status, 409, await planned.clone().text());
  assert.match((await planned.json() as { message: string }).message, /alpha and beta read OPENAI_API_KEY with different placeholders/);
});

test("a UI route shaping a code signer's key: the plan refuses (409), as startup refuses it of code's own (review r3 of #467)", ON_015, async () => {
  await root.secrets.set('market/dev', { SIGNING_KEY: 'a signing key' });
  await save({ tokens: { ...uiRoute('tokens', '/tokens', 'SIGNING_KEY'), placeholder: { kind: 'prefix', prefix: 'sk_test_' } } as ProxyDefinition });
  const token = await handle();
  const planned = await route('/use/market/dev', as(token));
  assert.equal(planned.status, 409, await planned.clone().text());
  assert.match((await planned.json() as { message: string }).message, /tokens and signing read SIGNING_KEY with different placeholders/);
  // Without the placeholder, both take the handle as it is: the plan is given.
  await save({ tokens: uiRoute('tokens', '/tokens', 'SIGNING_KEY') });
  const plan = await route('/use/market/dev', as(token));
  assert.equal(plan.status, 200, await plan.clone().text());
  assert.equal((await plan.json() as { env: Record<string, string> }).env.SIGNING_KEY, token);
});

test("a UI route's upstream goes out through the runtime's public fetch, and a runtime without one sends nothing (review r2 of #467)", ON_015, async () => {
  deploy(proxyOf({ insecureUpstreams: false, cacheSeconds: 0 }, false));
  await save({ openai: { ...uiRoute('openai', ''), upstream: 'https://api.openai.example/v1' } as ProxyDefinition });
  const token = await handle();
  const sent: { url: string; authorization: string | null }[] = [];
  const kept = runtime.publicFetch;
  try {
    runtime.publicFetch = async (url, init) => {
      sent.push({ url: url.href, authorization: new Headers(init.headers).get('authorization') });
      return new Response('{"ok":true}', { headers: { 'content-type': 'application/json' } });
    };
    const answer = await route('/use/openai/models', as(token));
    assert.equal(answer.status, 200, await answer.clone().text());
    assert.deepEqual(sent, [{ url: 'https://api.openai.example/v1/models', authorization: `Bearer ${OPENAI}` }]);
    delete runtime.publicFetch;
    const none = await route('/use/openai/models', as(token));
    assert.equal(none.status, 503, await none.clone().text());
    assert.equal(sent.length, 1);
  } finally {
    if (kept === undefined) delete runtime.publicFetch;
    else runtime.publicFetch = kept;
  }
});
