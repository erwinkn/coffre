// A database saved in the Proxy tab, tunnelled to (0.16, T186 PR C2b3; docs/design/proxy-ui.md, section 3, "Tunnels";
// formal/Tunnel.tla): `coffre run`'s listener, a handle as its password, coffre's own vault deciding the item by name,
// and the suite's Postgres as the database. The open dials the decided item's hosts; each recheck is the same use,
// passing only on the item dialled, by its own digest (DigestRecheck), so an Owner who narrows `hosts` mid-session ends
// it within a recheck, and another item's edit ends nothing (ItemDigest). Postgres only, 0.15's log.
import test, { after, afterEach, before } from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttp, type Server } from 'node:http';
import { createServer as createTcp, type AddressInfo, type Server as TcpServer, type Socket } from 'node:net';
import { once } from 'node:events';

import { WebSocket } from 'ws';

import type { CoffreClient } from '@coffre/client';
import type { ProxyDefinition } from '@coffre/core/vault';

import { clientFor, LOG } from './api-fixture.ts';
import { trackBackgroundTask } from './background-tasks.ts';
import { TEST_RUNTIME_DATABASE_URL } from './db/connections.ts';
import { TEST_ENGINE } from './db/engine.ts';
import { deps, DEV, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { upgrade } from '../src/node-sockets.ts';
import { checkPlugins, pluginSocket, type CoffrePlugin } from '../src/plugins.ts';
import { proxyCodeOf } from '../src/proxy-code.ts';
import { credentialProxy } from '../src/plugins/credential-proxy.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { appClient, type AppClient } from './tunnel-listener.ts';

const ON = { skip: TEST_ENGINE !== 'postgres' ? 'the tunnel reaches a Postgres database' : LOG === '0.14' ? "proxy definitions are 0.15's log's objects" : false };
const REAL = `${TEST_RUNTIME_DATABASE_URL}?sslmode=disable`;
const OPENAI = 'sk-openai-dev-0123456789abcdef';

let coffre: Server;
let listener: TcpServer;
let listenerPort: number;
let handle: string;
/** Where the listener's WebSocket goes: market/dev's `db` unless a case says otherwise. */
let target = '/use/market/dev/db';
const carried: Socket[] = [];
let root: CoffreClient;

before(async () => {
  coffre = createHttp((_, response) => response.writeHead(404).end());
  coffre.on('upgrade', (request, socket, head) => void upgrade(tracked(runtime), request, socket, head));
  coffre.listen(0, '127.0.0.1');
  await once(coffre, 'listening');
  const at = `ws://127.0.0.1:${(coffre.address() as AddressInfo).port}`;
  // `coffre run`'s listener, as it is: each connection, a WebSocket to the tunnel with the handle, bytes both ways.
  listener = createTcp((socket) => {
    carried.push(socket);
    const ws = new WebSocket(`${at}${target}`, { headers: { authorization: `Bearer ${handle}` } });
    const early: Buffer[] = [];
    socket.on('data', (chunk: Buffer) => (ws.readyState === WebSocket.OPEN ? ws.send(chunk) : early.push(chunk)));
    ws.on('open', () => early.splice(0).forEach((chunk) => ws.send(chunk)));
    ws.on('message', (data: Buffer) => socket.write(data));
    ws.on('close', () => socket.destroy());
    ws.on('error', () => socket.destroy());
    socket.on('close', () => ws.close());
    socket.on('error', () => ws.terminate());
  });
  listener.listen(0, '127.0.0.1');
  await once(listener, 'listening');
  listenerPort = (listener.address() as AddressInfo).port;
});

after(async () => {
  for (const socket of carried) socket.destroy();
  await new Promise<void>((resolve) => listener.close(() => resolve()));
  coffre.closeAllConnections();
  await new Promise<void>((resolve) => coffre.close(() => resolve()));
});

afterEach(async () => {
  target = '/use/market/dev/db';
  assert.equal(await sessionsEnded(), true, 'every session the case opened has ended');
});

async function sessionsEnded(): Promise<boolean> {
  const open = () => new Promise<number>((resolve) => coffre.getConnections((_, count) => resolve(count)));
  for (let waited = 0; (await open()) > 0 && waited < 5000; waited += 20) await new Promise((resolve) => setTimeout(resolve, 20));
  return (await open()) === 0;
}

/** `runtime`, each use its sockets make the case's own work, which the next case's reset waits for (as the code tunnel's suite). */
function tracked(runtime: CoffreRuntime): CoffreRuntime {
  const plugins = runtime.plugins.map((plugin): CoffrePlugin => {
    const socket = plugin.routes?.socket;
    if (socket === undefined) return plugin;
    return {
      ...plugin,
      routes: {
        ...plugin.routes!,
        socket: (request, context) => socket(request, {
          ...context,
          ...(context.useRoute === undefined ? {} : {
            useRoute: (caller, asked) => {
              const using = context.useRoute!(caller, asked);
              trackBackgroundTask(using);
              return using;
            },
          }),
        }),
      },
    };
  });
  return { ...runtime, plugins };
}

/** market/dev's database, saved in the Proxy tab: its URL in DATABASE_URL, dialled only to `hosts`. */
const database = (hosts: string[] = ['127.0.0.1']): ProxyDefinition => ({ kind: 'tunnel', name: 'db', key: 'DATABASE_URL', hosts, network: null });

/** A save in `path`'s Proxy tab, on the seal it shows now, by the Owner. */
async function save(items: Record<string, ProxyDefinition | null>, path = 'market/dev'): Promise<void> {
  const page = await root.proxy.get(path);
  await root.proxy.save(path, { seal: page.seal, items });
}

async function handleFor(path: string): Promise<string> {
  const made = await route('/api/handles', { method: 'POST', headers: { authorization: `Bearer ${await sessionFor(DEV)}`, 'content-type': 'application/json' }, body: JSON.stringify({ label: 'run', paths: [path] }) });
  return ((await made.json()) as { token: string }).token;
}

useMcp(async () => {
  runtime.plugins = checkPlugins([credentialProxy({ credentials: {}, editable: true, insecureUpstreams: true, recheckSeconds: 0.2 })]);
  deps.proxy = proxyCodeOf(runtime.plugins);
  root = clientFor(deps, ROOT);
  await root.members.add(`user:${DEV}`);
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { DATABASE_URL: { value: REAL, sensitivity: 'sensitive' }, OPENAI_API_KEY: OPENAI });
  await root.access.set(`user:${DEV}`, { market: 'developer' });
  if (TEST_ENGINE === 'postgres' && LOG !== '0.14') await save({ db: database() });
  handle = await handleFor('market/dev');
});

const appClientOf = (password = handle): AppClient => appClient(listenerPort, password);

const endsWithin = (client: AppClient, ms: number): Promise<boolean> =>
  Promise.race([client.ended.then(() => true), new Promise<boolean>((resolve) => setTimeout(resolve, ms, false))]);

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** The tunnel's answer to an upgrade at `path` by `token`: the session, or the refusal's status and message. */
async function upgraded(path = '/use/market/dev/db', token = handle): Promise<'session' | { status: number; message: string }> {
  const answer = await pluginSocket(new Request(`${ORIGIN}${path}`, { headers: { authorization: `Bearer ${token}` } }), runtime, null);
  if (typeof answer === 'function') return 'session';
  assert.ok(answer instanceof Response);
  return { status: answer.status, message: ((await answer.json()) as { message: string }).message };
}

test("the plan names the UI's database as code's, and gives the app no URL of its own; queries run as the real login", ON, async () => {
  const plan = (await (await route('/use/market/dev', { headers: { authorization: `Bearer ${handle}` } })).json()) as { env: Record<string, string>; tunnels: Record<string, { key: string; url: string }> };
  assert.deepEqual(plan.tunnels, { db: { key: 'DATABASE_URL', url: `${ORIGIN.replace('https', 'wss')}/use/market/dev/db` } });
  assert.equal(plan.env.DATABASE_URL, undefined);
  assert.equal(JSON.stringify(plan).includes('local-runtime-only'), false, 'never the real password');
  const client = appClientOf();
  try {
    assert.deepEqual([...await client.unsafe('SELECT current_user AS who')], [{ who: 'coffre_runtime' }]);
    // Rechecks a fifth of a second apart, on an item nobody edits: the session stands.
    await sleep(1000);
    assert.deepEqual([...await client.unsafe('SELECT 2 AS two')], [{ two: 2 }]);
  } finally {
    await client.end();
  }
});

test('the decided item says where the tunnel dials: a host it does not list is refused before any login', ON, async () => {
  await save({ db: database(['db.acme.example']) });
  const refused = await upgraded();
  assert.notEqual(refused, 'session');
  assert.deepEqual(refused, { status: 403, message: "market/dev's DATABASE_URL names a host the tunnel db does not reach" });
  await save({ db: database(['db.acme.example', '127.0.0.1']) });
  assert.equal(await upgraded(), 'session');
});

test('an Owner who narrows the hosts mid-session ends it within a recheck; the reconnect dials by the new item', ON, async () => {
  const client = appClientOf();
  assert.deepEqual([...await client.unsafe('SELECT 1 AS one')], [{ one: 1 }]);
  // Saved anew, still reaching 127.0.0.1: a session dialled now is the new item's, and the old item's checks end only theirs.
  await save({ db: database(['127.0.0.1', 'db.acme.example']) });
  const newer = appClientOf();
  assert.deepEqual([...await newer.unsafe('SELECT 1 AS one')], [{ one: 1 }]);
  assert.equal(await endsWithin(client, 600), true, 'the session dialled by the old item ended');
  await assert.rejects(client.unsafe('SELECT 1'));
  await client.end();
  await sleep(600);
  assert.deepEqual([...await newer.unsafe('SELECT 3 AS three')], [{ three: 3 }], "the new item's session stands");
  // Narrowed off 127.0.0.1: the newer session ends too, and no connection dials there again.
  await save({ db: database(['db.acme.example']) });
  assert.equal(await endsWithin(newer, 600), true, 'the session ended');
  await newer.end();
  const again = appClientOf();
  await assert.rejects(again.unsafe('SELECT 1'));
  await again.end();
  assert.equal((await upgraded() as { status: number }).status, 403);
});

test("another item of the environment saved mid-session ends nothing: the check compares the item's own digest", ON, async () => {
  const client = appClientOf();
  try {
    assert.deepEqual([...await client.unsafe('SELECT 1 AS one')], [{ one: 1 }]);
    await save({ openai: { kind: 'route', name: 'openai', upstream: 'https://api.openai.example/v1', inject: [{ kind: 'header', name: 'authorization', template: 'Bearer {OPENAI_API_KEY}' }], allow: [{ methods: ['GET'], path: '/**' }], limit: { perMinute: null, perDay: null }, placeholder: null, egress: null } });
    await sleep(1000);
    assert.equal(await endsWithin(client, 0), false, 'still open');
    assert.deepEqual([...await client.unsafe('SELECT 2 AS two')], [{ two: 2 }]);
  } finally {
    await client.end();
  }
});

test("a person whose grant ends loses their UI tunnel's sessions at the next check, and opens no other", ON, async () => {
  const client = appClientOf();
  assert.deepEqual([...await client.unsafe('SELECT 1 AS one')], [{ one: 1 }]);
  await root.access.set(`user:${DEV}`, { market: null });
  assert.equal(await endsWithin(client, 600), true, 'the open session ended');
  await client.end();
  const another = appClientOf();
  await assert.rejects(another.unsafe('SELECT 1'));
  await another.end();
});

test('an item deleted mid-session ends it; a name of no database is no tunnel', ON, async () => {
  const client = appClientOf();
  assert.deepEqual([...await client.unsafe('SELECT 1 AS one')], [{ one: 1 }]);
  await save({ db: null, openai: { kind: 'route', name: 'openai', upstream: 'https://api.openai.example/v1', inject: [{ kind: 'header', name: 'authorization', template: 'Bearer {OPENAI_API_KEY}' }], allow: [{ methods: ['GET'], path: '/**' }], limit: { perMinute: null, perDay: null }, placeholder: null, egress: null } });
  assert.equal(await endsWithin(client, 600), true, 'the session ended');
  await client.end();
  assert.equal((await upgraded() as { status: number }).status, 404);
  // A route is no database: nothing of it opened.
  const route = await upgraded('/use/market/dev/openai');
  assert.notEqual(route, 'session');
  assert.deepEqual(route, { status: 404, message: 'openai is a route, which is no database: a tunnel saved in the Proxy tab, or the deployment\'s code, names one' });
});

test("a fork's tunnel is its parent's item and key, found through the chain", ON, async () => {
  await root.environments.create('market/dev-eu', { from: 'dev', inherit: true });
  handle = await handleFor('market/dev-eu');
  target = '/use/market/dev-eu/db';
  const plan = (await (await route('/use/market/dev-eu', { headers: { authorization: `Bearer ${handle}` } })).json()) as { tunnels: Record<string, { key: string; url: string }> };
  assert.deepEqual(plan.tunnels, { db: { key: 'DATABASE_URL', url: `${ORIGIN.replace('https', 'wss')}/use/market/dev-eu/db` } });
  const client = appClientOf();
  try {
    assert.deepEqual([...await client.unsafe('SELECT current_user AS who')], [{ who: 'coffre_runtime' }]);
  } finally {
    await client.end();
  }
  // The parent's item narrowed: the fork's sessions dial by it too.
  await save({ db: database(['db.acme.example']) });
  assert.equal((await upgraded('/use/market/dev-eu/db') as { status: number }).status, 403);
});
