// UI definitions served by the credential proxy (0.16, T186 PR C; docs/design/proxy-ui.md, sections 3, 4 and 6), end
// to end: coffre's own vault, a route saved in the Proxy tab, a handle as `coffre run` makes one, and a fake upstream
// over HTTP. The route use is the vault's one call, which reads the URL both ways; every request goes by the item the
// vault decided on (SentAsDecided), kept values by the item they were decided on (BoundToDefinition); code wins its
// names, reserved before an isolate's first proxy request (CodeGate, ClearSuperseded); an editor who no longer holds
// the key stops their route (EditorStillHolds).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { createClient, type CoffreClient } from '@coffre/client';
import type { ProxyDefinition } from '@coffre/core/vault';

import { clientFor, LOG } from './api-fixture.ts';
import { deps, DEV, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { coffreRoute } from '../src/app.ts';
import { checkPlugins } from '../src/plugins.ts';
import { proxyCodeOf } from '../src/proxy-code.ts';
import { credentialProxy, header, privateKey, type CredentialProxyOptions } from '../src/plugins/credential-proxy.ts';

const OPENAI = 'sk-openai-dev-0123456789abcdef';
const MAPS = 'maps-key-0123456789abcdef';
const LIN = 'lin@acme.example';
const ON_015 = { skip: LOG === '0.14' ? "proxy definitions are 0.15's log's objects" : false };

let upstream: Server;
let upstreamUrl: string;
const reached: { method: string; url: string; headers: IncomingMessage['headers'] }[] = [];

before(async () => {
  upstream = createServer((request, response) => {
    request.resume();
    request.on('end', () => {
      reached.push({ method: request.method!, url: request.url!, headers: request.headers });
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

/** A save in market/dev's Proxy tab, on the seal it shows now, by `as`. */
async function save(items: Record<string, ProxyDefinition | null>, as: CoffreClient = root): Promise<void> {
  const page = await as.proxy.get('market/dev');
  await as.proxy.save('market/dev', { seal: page.seal, items });
}

/** A handle for DEV on `path`, market/dev by default, as `coffre run` makes one. */
async function handle(path = 'market/dev'): Promise<string> {
  const session = await sessionFor(DEV);
  const api = createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${session}` }), transport: (request) => coffreRoute(request, runtime, '203.0.113.7').then((response) => response!) });
  return (await api.handles.create({ label: 'coffre run market/dev', paths: [path] })).token;
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
  // Kept (60 s by default): still the old item's upstream, never the new one with values decided on the old.
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
