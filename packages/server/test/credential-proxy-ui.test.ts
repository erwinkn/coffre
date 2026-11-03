// UI definitions served by the credential proxy (0.16, T186 PR C; docs/design/proxy-ui.md, sections 3, 4 and 6), end
// to end: coffre's own vault, a route saved in the Proxy tab, a handle as `coffre run` makes one, and a fake upstream
// over HTTP. The route use is the vault's one call, which reads the URL both ways; every request goes by the item the
// vault decided on (SentAsDecided), kept values by the item they were decided on (BoundToDefinition); code wins its
// names, reserved before an isolate's first proxy request (CodeGate, ClearSuperseded); an editor who no longer holds
// the key stops their route (EditorStillHolds).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, type Hash, type Hmac } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import { createServer as createTlsServer } from 'node:https';
import type { AddressInfo, LookupFunction } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { SignatureV4 } from '@smithy/signature-v4';

import { createClient, type CoffreClient } from '@coffre/client';
import { bodyDigest, contentDigest } from '@coffre/client/dpop';
import { Deploying, USE_DEADLINE_MS, type ProxyDefinition, type Vault } from '@coffre/core/vault';

import { sql, type SQL } from 'drizzle-orm';

import { clientFor, LOG } from './api-fixture.ts';
import { TEST_ENGINE } from './db/engine.ts';
import { db, deps, DEV, entries, NO, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { coffreRoute } from '../src/app.ts';
import { bindingRoute, checkPlugins } from '../src/plugins.ts';
import { proxyCodeOf } from '../src/proxy-code.ts';
import { forgetProxyGates } from '../src/proxy-gate.ts';
import { credentialProxy, form, header, privateKey, type CredentialProxyOptions } from '../src/plugins/credential-proxy.ts';
import { publicFetch } from '../src/workloads/node-transport.ts';

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
  // 0.14's log included: no item is saved there, and its test below holds the plan to code's (review r5 of #467).
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

/** A handle for `who` (DEV by default) on `path`, market/dev by default, as `coffre run` makes one. */
async function handle(path = 'market/dev', who = DEV): Promise<string> {
  const session = await sessionFor(who);
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

test('a name no definition holds is 404; a signer saved in the UI reaches no upstream, its values neither read nor kept; a personal config serves no UI route (409)', ON_015, async () => {
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
  // Refused before the app reads the values the vault answered: none kept, so the next request asks the vault again
  // (Fable's review of #467).
  const vault = runtime.vault as unknown as { useRoute: Vault['useRoute'] };
  const real = vault.useRoute;
  let uses = 0;
  try {
    vault.useRoute = (async (...args: Parameters<Vault['useRoute']>) => {
      uses += 1;
      return real.apply(runtime.vault, args);
    }) as Vault['useRoute'];
    for (let round = 0; round < 2; round++) {
      const signer = await route('/use/signer/x', as(token));
      assert.equal(signer.status, 404, await signer.clone().text());
      assert.match((await signer.json() as { message: string }).message, /signer is a signer, which reaches no upstream/);
    }
    assert.equal(uses, 2);
  } finally {
    vault.useRoute = real;
  }
});

test("a UI signer whose inherited key its caller may not use answers that refusal, the one \"no\", never what kind the item is (review r10 of #467)", ON_015, async () => {
  deploy(proxyOf({ cacheSeconds: 0 }));
  await save({ signer: { kind: 'signer', name: 'signer', signer: { kind: 'private-key', key: 'OPENAI_API_KEY' }, limit: { perMinute: null, perDay: null } } });
  await root.environments.create('market/dev-eu', { from: 'dev', inherit: true });
  // LIN stands at the fork alone: its signer and its key are dev's, which LIN holds nothing of.
  await root.access.set(`user:${LIN}`, { 'market/dev-eu': 'developer' });
  const refused = await route('/use/market/dev-eu/signer/x', as(await handle('market/dev-eu', LIN)));
  assert.deepEqual([refused.status, await refused.json()], [404, NO]);
  // DEV may use it: the item's kind is the answer, the signer reaching no upstream.
  const served = await route('/use/market/dev-eu/signer/x', as(await handle('market/dev-eu')));
  assert.equal(served.status, 404, await served.clone().text());
  assert.match((await served.json() as { message: string }).message, /signer is a signer, which reaches no upstream/);
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

test("a handle escaped as its slot's own encoding allows: a query's or a form's percent escapes, a JSON string's \\u escapes, found with no other sign of it (review r7 of #467)", ON_015, async () => {
  deploy(proxyOf({ cacheSeconds: 0 }));
  const post = [{ methods: ['POST'], path: '/token' }];
  await save({
    search: { ...uiRoute('search', '/search'), inject: [{ kind: 'query', name: 'key', template: '{OPENAI_API_KEY}' }] } as ProxyDefinition,
    login: { ...uiRoute('login', '/login'), inject: [{ kind: 'form', name: 'client_secret', template: '{OPENAI_API_KEY}' }], allow: post } as ProxyDefinition,
    hook: { ...uiRoute('hook', '/hook'), inject: [{ kind: 'json', name: 'secret', template: '{OPENAI_API_KEY}' }], allow: post } as ProxyDefinition,
  });
  const token = await handle();
  const escaped = token.replace('_', '%5F');
  const query = await route(`/use/search/models/list?key=${escaped}`);
  assert.equal(query.status, 200, await query.clone().text());
  assert.equal(reached.at(-1)!.url, `/search/models/list?key=${encodeURIComponent(OPENAI)}`);
  const form = await route('/use/login/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: `grant_type=client_credentials&client_secret=${escaped}` });
  assert.equal(form.status, 200, await form.clone().text());
  assert.deepEqual([reached.at(-1)!.url, reached.at(-1)!.body], ['/login/token', `grant_type=client_credentials&client_secret=${encodeURIComponent(OPENAI)}`]);
  const json = await route('/use/hook/token', { method: 'POST', headers: { 'content-type': 'application/json' }, body: `{"secret":"${token.replace('_', '\\u005f')}"}` });
  assert.equal(json.status, 200, await json.clone().text());
  assert.deepEqual([reached.at(-1)!.url, JSON.parse(reached.at(-1)!.body)], ['/hook/token', { secret: OPENAI }]);
  // Two different handles, one escaped: still two.
  const other = await handle();
  assert.equal((await route(`/use/search/models/list?key=${escaped}&q=${other}`)).status, 400);
});

test("a body decoded only as its Content-Type reads it: a JSON note's percent escapes, a form value's backslashes, are text, no second handle (review r8 of #467)", ON_015, async () => {
  deploy(proxyOf({ cacheSeconds: 0 }));
  const post = [{ methods: ['POST'], path: '/token' }];
  await save({
    login: { ...uiRoute('login', '/login'), inject: [{ kind: 'form', name: 'client_secret', template: '{OPENAI_API_KEY}' }], allow: post } as ProxyDefinition,
    hook: { ...uiRoute('hook', '/hook'), inject: [{ kind: 'json', name: 'secret', template: '{OPENAI_API_KEY}' }], allow: post } as ProxyDefinition,
  });
  const token = await handle();
  const other = await handle();
  // JSON: `%5F` is three characters of a string, as the item's slot reads it; a form's decoding would make it `_`.
  const note = other.replace('_', '%5F');
  const json = await route('/use/hook/token', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ secret: token, note }) });
  assert.equal(json.status, 200, await json.clone().text());
  assert.deepEqual(JSON.parse(reached.at(-1)!.body), { secret: OPENAI, note });
  // A form: a quoted value whose `\u005f` is six characters; a JSON string's decoding would make it `_`.
  const slashed = `"${other.replace('_', '\\u005f')}"`;
  const form = await route('/use/login/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: `client_secret=${token}&note=${slashed}` });
  assert.equal(form.status, 200, await form.clone().text());
  assert.equal(reached.at(-1)!.body, `client_secret=${encodeURIComponent(OPENAI)}&note=${slashed}`);
});

test("64 KiB of escaped quotes that never close cost their length, not their square: found no handle in, read as no JSON (review r8 of #467)", ON_015, async () => {
  deploy(proxyOf({ cacheSeconds: 0 }));
  await save({ hook: { ...uiRoute('hook', '/hook'), inject: [{ kind: 'json', name: 'secret', template: '{OPENAI_API_KEY}' }], allow: [{ methods: ['POST'], path: '/v1/token' }] } as ProxyDefinition });
  const body = `"${'\\"'.repeat(32_000)}`;
  const sent = { method: 'POST', headers: { 'content-type': 'application/json' }, body };
  // A regex retried from each quote took seconds of CPU on this body; one pass takes a few milliseconds.
  let started = performance.now();
  const first = await route('/use/hook/v1/token', sent);
  assert.equal(first.status, 401, await first.clone().text());
  assert.ok(performance.now() - started < 1_000, `the handle's search took ${performance.now() - started} ms`);
  // With the handle beside it, the JSON rule's own read of its field: refused as no JSON, as fast.
  const token = await handle();
  started = performance.now();
  const answer = await route('/use/hook/v1/token', { ...sent, headers: { ...sent.headers, 'x-coffre-handle': token } });
  assert.equal(answer.status, 400, await answer.clone().text());
  assert.ok(performance.now() - started < 1_000, `the field's read took ${performance.now() - started} ms`);
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

test("a code credential's refusal of the body leaves it whole for the UI route the handle's place reading takes, with no cache (review r4 of #467)", ON_015, async () => {
  // Code's `maps` takes its key in a form's field: a JSON body is no form, and its refusal reads the body.
  deploy(proxyOf({ cacheSeconds: 0, credentials: { maps: { upstream: `${upstreamUrl}/maps`, inject: form('key', '{MAPS_KEY}') } } }));
  await root.projects.create('maps');
  await root.environments.create('maps/dev');
  await root.secrets.set('maps/dev', { OPENAI_API_KEY: OPENAI });
  await root.access.set(`user:${DEV}`, { market: 'developer', maps: 'developer' });
  await save({ openai: uiRoute('openai', '/openai') }, root, 'maps/dev');
  const token = await handle('maps/dev');
  const body = '{"model":"gpt","messages":[]}';
  const answer = await route('/use/maps/dev/openai/chat/completions', { method: 'POST', headers: { 'x-coffre-handle': token, 'content-type': 'application/json' }, body });
  assert.equal(answer.status, 200, await answer.clone().text());
  assert.deepEqual([reached.at(-1)!.url, reached.at(-1)!.headers.authorization, reached.at(-1)!.body], ['/openai/chat/completions', `Bearer ${OPENAI}`, body]);
});

test("values kept for a stable route serve every path under it: one use within cacheSeconds, whatever the URL's third segment, never the place reading's URL (review r4 of #467)", ON_015, async () => {
  // `market` too, named as the handle's project is: its stable copy must not answer `/use/market/dev/…`.
  await save({ openai: uiRoute('openai', '/openai'), market: uiRoute('market', '/market') });
  const token = await handle();
  const vault = runtime.vault as unknown as { useRoute: Vault['useRoute'] };
  const real = vault.useRoute;
  let uses = 0;
  try {
    vault.useRoute = (async (...args: Parameters<Vault['useRoute']>) => {
      uses += 1;
      return real.apply(runtime.vault, args);
    }) as Vault['useRoute'];
    for (const model of ['gpt-a', 'gpt-b', 'gpt-c']) {
      const answer = await route(`/use/openai/models/${model}`, as(token));
      assert.equal(answer.status, 200, await answer.clone().text());
      assert.equal(reached.at(-1)!.url, `/openai/models/${model}`);
    }
    assert.equal(uses, 1);
    // Route market's stable copy, kept for `/use/market/models/x`, whose `<a>/<b>` is no environment of the handle's.
    assert.equal((await route('/use/market/models/x', as(token))).status, 200);
    assert.equal(reached.at(-1)!.url, '/market/models/x');
    assert.equal(uses, 2);
    // `market/dev` is the handle's environment: the place reading of route openai, which that copy never answers.
    assert.equal((await route('/use/market/dev/openai/models/gpt-a', as(token))).status, 200);
    assert.equal(reached.at(-1)!.url, '/openai/models/gpt-a');
    assert.equal(uses, 3);
  } finally {
    vault.useRoute = real;
  }
});

test("a route of plain keys alone: the app's credential.use entry names the route the vault's reading took, not the URL's third segment (review r4 of #467)", ON_015, async () => {
  await root.secrets.set('market/dev', { OPENAI_ORG: { value: 'org-acme', sensitivity: 'plain' } });
  await save({ openai: uiRoute('openai', '/openai', 'OPENAI_ORG') });
  const token = await handle();
  const answer = await route('/use/openai/models/gpt', as(token));
  assert.equal(answer.status, 200, await answer.clone().text());
  assert.equal(reached.at(-1)!.headers.authorization, 'Bearer org-acme');
  const used = (await entries('credential.use')).filter((entry) => entry.metadata.ui === true);
  assert.deepEqual(used.map((entry) => entry.metadata.credential), ['openai']);
});

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

test("a UI route through undici's public fetch, as a Node deployment sends one: a TLS upstream by its name, a body, a streamed digested body, a redirect brought back to the proxy (Fable's review of #467)", ON_015, async () => {
  // The fake upstream is `api.openai.example` over TLS, its certificate from an authority of this test's own. The lookup
  // is the one seam: it resolves the name to the fake, as DNS resolves a public name to its server; the rest is the
  // production fetch, undici's, its Headers, bodies and Response wrapped by the proxy as they come.
  const dir = mkdtempSync(join(tmpdir(), 'coffre-tls-'));
  const kept = runtime.publicFetch;
  const seen: { method: string; url: string; authorization: string | undefined; digest: string | undefined; body: Buffer }[] = [];
  let port = 0;
  const tls = createTlsServer();
  try {
    // The name in a config file of its own, not `-addext`, which macOS's LibreSSL lacks (review r10 of #467).
    writeFileSync(join(dir, 'san.cnf'), '[req]\ndistinguished_name = dn\n[dn]\n[san]\nsubjectAltName = DNS:api.openai.example\n');
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=api.openai.example', '-config', join(dir, 'san.cnf'), '-extensions', 'san', '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem')], { stdio: 'ignore' });
    const cert = readFileSync(join(dir, 'cert.pem'), 'utf8');
    tls.setSecureContext({ key: readFileSync(join(dir, 'key.pem')), cert });
    tls.on('request', (request: IncomingMessage, response) => {
      const chunks: Buffer[] = [];
      request.on('data', (chunk: Buffer) => chunks.push(chunk));
      request.on('end', () => {
        const body = Buffer.concat(chunks);
        seen.push({ method: request.method!, url: request.url!, authorization: request.headers.authorization, digest: request.headers['content-digest'] as string | undefined, body });
        if (request.url === '/v1/models/moved') return void response.writeHead(302, { location: `https://api.openai.example:${port}/v1/models/next` }).end();
        response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ got: body.length }));
      });
    });
    await new Promise<void>((resolve) => tls.listen(0, '127.0.0.1', resolve));
    port = (tls.address() as AddressInfo).port;
    const lookup: LookupFunction = (_host, options, callback) => {
      if (options.all) (callback as unknown as (error: null, addresses: { address: string; family: number }[]) => void)(null, [{ address: '127.0.0.1', family: 4 }]);
      else callback(null, '127.0.0.1', 4);
    };
    runtime.publicFetch = publicFetch(lookup, { ca: cert });
    deploy(proxyOf({ insecureUpstreams: false, cacheSeconds: 0 }, false));
    await save({ openai: { ...uiRoute('openai', ''), upstream: `https://api.openai.example:${port}/v1` } as ProxyDefinition });
    const token = await handle();

    // A GET, its answer's body read through undici's Response.
    const models = await route('/use/openai/models', as(token));
    assert.equal(models.status, 200, await models.clone().text());
    assert.deepEqual(await models.json(), { got: 0 });
    // A body the proxy read whole.
    const chat = JSON.stringify({ model: 'gpt', messages: [{ role: 'user', content: 'hi' }] });
    const answered = await route('/use/openai/chat/completions', as(token, { method: 'POST', headers: { 'content-type': 'application/json' }, body: chat }));
    assert.equal(answered.status, 200, await answered.clone().text());
    assert.equal(seen.at(-1)!.body.toString(), chat);
    // A body streamed through as it comes, its digest declared and checked on the way: a ReadableStream, `duplex: 'half'`.
    const upload = new Uint8Array(100_000).map((_, i) => i % 251);
    const stream = new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(upload.slice(0, 40_000)); controller.enqueue(upload.slice(40_000)); controller.close(); } });
    const digest = contentDigest(await bodyDigest(upload));
    const streamed = await route('/use/openai/chat/completions', { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/octet-stream', 'content-length': String(upload.length), 'content-digest': digest }, body: stream, duplex: 'half' } as RequestInit);
    assert.equal(streamed.status, 200, await streamed.clone().text());
    assert.deepEqual([seen.at(-1)!.body.equals(Buffer.from(upload)), seen.at(-1)!.digest], [true, digest]);
    // A redirect under the upstream: the proxy's own URL for it, at the place the item was decided at, undici having followed nothing.
    const moved = await route('/use/openai/models/moved', as(token));
    assert.equal(moved.status, 302, await moved.clone().text());
    assert.equal(moved.headers.get('location'), `${ORIGIN}/use/market/dev/openai/models/next`);

    assert.deepEqual(seen.map((request) => `${request.method} ${request.url}`), ['GET /v1/models', 'POST /v1/chat/completions', 'POST /v1/chat/completions', 'GET /v1/models/moved']);
    assert.ok(seen.every((request) => request.authorization === `Bearer ${OPENAI}`));
  } finally {
    if (kept === undefined) delete runtime.publicFetch;
    else runtime.publicFetch = kept;
    await new Promise<void>((resolve) => (tls.listening ? tls.close(() => resolve()) : resolve()));
    rmSync(dir, { recursive: true, force: true });
  }
});

/** An unsigned JWT whose claims are `claims`: what a JWT placeholder copies its claims from. */
const jwtOf = (claims: Record<string, unknown>) => `${Buffer.from('{"alg":"HS256"}').toString('base64url')}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.c2lnbmF0dXJl`;
const ORG = 'org-hidden-7f3a';

test("a UI route's JWT placeholder copies only claims its caller may read: a Developer's secret yes, a sensitive value no, a Contributor's secret no (review r5 of #467)", ON_015, async () => {
  await root.secrets.set('market/dev', { ID_TOKEN: jwtOf({ org: ORG, sub: 'svc' }), SEALED_TOKEN: { value: jwtOf({ org: ORG }), sensitivity: 'sensitive' } });
  const shapedRoute = (name: string, key: string): ProxyDefinition => ({ ...uiRoute(name, `/${name}`, key), placeholder: { kind: 'jwt', claims: ['org'] } } as ProxyDefinition);
  await save({ ids: shapedRoute('ids', 'ID_TOKEN') });
  // A Developer reads secrets: the claim is theirs to see, copied, and nothing else of the token.
  const token = await handle();
  const planned = await route('/use/market/dev', as(token));
  assert.equal(planned.status, 200, await planned.clone().text());
  const placeholder = (await planned.json() as { env: Record<string, string> }).env.ID_TOKEN!;
  assert.deepEqual(Object.keys(JSON.parse(Buffer.from(placeholder.split('.')[1]!, 'base64url').toString()) as object).sort(), ['exp', 'org']);
  assert.ok(placeholder.endsWith(`.${token}`));
  // A Contributor uses keys and never reads them: 403, the claim nowhere in the answer.
  await root.access.set(`user:${LIN}`, { market: 'contributor' });
  const contributor = await route('/use/market/dev', as(await handle('market/dev', LIN)));
  assert.equal(contributor.status, 403, await contributor.clone().text());
  const refused = await contributor.text();
  assert.match(refused, /placeholder_unread/);
  assert.ok(!refused.includes(ORG));
  // A sensitive value no plan reads, whoever asks: the Developer's 403 too.
  await save({ ids: null, sealed: shapedRoute('sealed', 'SEALED_TOKEN') });
  const sensitive = await route('/use/market/dev', as(token));
  assert.equal(sensitive.status, 403, await sensitive.clone().text());
  assert.ok(!(await sensitive.text()).includes(ORG));
});

test("a generated environment's plan read from the person's personal config: no UI item of the base environment's shapes it, their own value given (review r5 of #467)", ON_015, async () => {
  deploy(proxyOf({ generate: { 'market/dev': 'all' } }));
  await save({ openai: uiRoute('openai', '/openai') });
  const token = await handle();
  // No personal config yet: the plan reads market/dev, whose route covers the key.
  const base = await (await route('/use/market/dev', as(token))).json() as { environment: string; env: Record<string, string>; credentials: Record<string, string> };
  assert.equal(base.env.OPENAI_API_KEY, token);
  assert.equal(base.credentials.openai, `${ORIGIN}/use/market/dev/openai`);
  // Their own key: the plan reads market/dev@me, which serves no UI route, and gives them their value, no handle, no route URL.
  const MINE = 'sk-openai-mine-0123456789';
  await clientFor(deps, DEV).secrets.set('market/dev@me', { OPENAI_API_KEY: MINE });
  const planned = await route('/use/market/dev', as(token));
  assert.equal(planned.status, 200, await planned.clone().text());
  const plan = await planned.json() as { environment: string; env: Record<string, string>; credentials: Record<string, string> };
  assert.equal(plan.environment, 'market/dev@me');
  assert.equal(plan.credentials.openai, undefined);
  assert.equal(plan.env.OPENAI_API_KEY, MINE);
});

test("a plan read the vault retries: a first attempt that read the personal config, the retry the base environment, whose UI items shape it again (review r6 of #467)", ON_015, async () => {
  // `use` retries a read whose kept answer changed (`AccessChanged`), and the pick runs again on the retry's answer. A
  // personal config deleted between the two: the first attempt resolved market/dev@me, the retry market/dev. Each plan
  // read below plays that first attempt to the proxy's pick before the vault's own, on the same rows.
  const plugin = proxyOf({ generate: { 'market/dev': 'all' } });
  const fetch = plugin.routes!.fetch;
  let replayed = 0;
  plugin.routes!.fetch = (request, coffre) => fetch(request, {
    ...coffre,
    use: (handle, asked) => {
      const pick = asked.keys;
      if (asked.logged.plan !== true || typeof pick !== 'function') return coffre.use(handle, asked);
      return coffre.use(handle, { ...asked, keys: (environment, rows) => {
        replayed += 1;
        pick({ ...environment, path: `${environment.path}@me`, personal: true }, rows);
        return pick(environment, rows);
      } });
    },
  });
  deploy(plugin);
  await save({ openai: uiRoute('openai', '/openai') });
  const token = await handle();
  const planned = await route('/use/market/dev', as(token));
  assert.equal(planned.status, 200, await planned.clone().text());
  assert.equal(replayed, 1);
  const plan = await planned.json() as { environment: string; env: Record<string, string>; credentials: Record<string, string> };
  assert.equal(plan.environment, 'market/dev');
  // The base environment's route covers the key: the handle and its URL, never the value.
  assert.equal(plan.env.OPENAI_API_KEY, token);
  assert.equal(plan.credentials.openai, `${ORIGIN}/use/market/dev/openai`);
  assert.ok(!JSON.stringify(plan).includes(OPENAI));
});

test("0.14's log too: an editable proxy's plan is code's, the vault asked for no UI item (review r5 of #467)", async () => {
  const token = await handle();
  const planned = await route('/use/market/dev', as(token));
  assert.equal(planned.status, 200, await planned.clone().text());
  const plan = await planned.json() as { env: Record<string, string>; credentials: Record<string, string> };
  assert.equal(plan.env.MAPS_KEY, token);
  assert.equal(plan.credentials.maps, `${ORIGIN}/use/market/dev/maps`);
  // The UI route's stable URL is no credential either: 404, never the vault's throw.
  if (LOG === '0.14') assert.equal((await route('/use/openai/models', as(token))).status, 404);
});
