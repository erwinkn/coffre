// A database saved in the Proxy tab, tunnelled to (docs/design/proxy-ui.md, section 3, "Tunnels";
// formal/Tunnel.tla): `coffre run`'s listener, a handle as its password, coffre's own vault deciding the item by name,
// and the suite's Postgres as the database. The open dials the decided item's hosts; each recheck is the same use,
// passing only on the item dialled, by its own digest (DigestRecheck), so an Owner who narrows `hosts` mid-session ends
// it within a recheck, and another item's edit ends nothing (ItemDigest). 0.15's log only.
import test, { after, afterEach, before } from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttp, type Server } from 'node:http';
import { createServer as createTcp, type AddressInfo, type Server as TcpServer, type Socket } from 'node:net';
import { once } from 'node:events';

import { WebSocket } from 'ws';

import type { CoffreClient } from '@coffre/client';
import { defineDeployment, type Deployment } from '@coffre/core/deployment';
import { github, signin } from '@coffre/core/identity';
import type { ProxyDefinition } from '@coffre/core/vault';

import { clientFor } from './api-fixture.ts';
import { trackBackgroundTask } from './background-tasks.ts';
import { TEST_RUNTIME_DATABASE_URL } from './db/connections.ts';
import { deps, DEV, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { createCoffre as nodeCoffre } from '../src/node.ts';
import { publicConnect, upgrade } from '../src/node-sockets.ts';
import { checkPlugins, pluginSocket, type CoffrePlugin } from '../src/plugins.ts';
import { proxyCodeWith } from '../src/proxy-code.ts';
import { credentialProxy, forgetUiItems } from '../src/plugins/credential-proxy.ts';
import { publicLookup } from '../src/workloads/node-transport.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { appClient, type AppClient } from './tunnel-listener.ts';

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
  holding = null;
  stalling = 0;
  assert.equal(await sessionsEnded(), true, 'every session the case opened has ended');
});

async function sessionsEnded(): Promise<boolean> {
  const open = () => new Promise<number>((resolve) => coffre.getConnections((_, count) => resolve(count)));
  for (let waited = 0; (await open()) > 0 && waited < 5000; waited += 20) await new Promise((resolve) => setTimeout(resolve, 20));
  return (await open()) === 0;
}

/** What a case does once an admission's use has answered, before the proxy reads the answer, given when the use started: once, then gone. */
let holding: ((started: number) => Promise<void>) | null = null;
/** How long a recheck's answer is held, as a vault that does not answer in time. */
let stalling = 0;

/**
 * `runtime`, each use its sockets make the case's own work, which the next case's reset waits for (as the code tunnel's
 * suite); an admission's answer held by `holding`, as a slow event loop or network would hold it.
 */
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
            useRoute: async (caller, asked) => {
              const started = Date.now();
              const using = context.useRoute!(caller, asked);
              trackBackgroundTask(using);
              const used = await using;
              // A recheck's use logs `recheck`, an admission's does not.
              const recheck = typeof asked.logged === 'object' && asked.logged.recheck === true;
              const hold = recheck ? null : holding;
              if (hold !== null) {
                holding = null;
                await hold(started);
              }
              if (recheck && stalling > 0) await sleep(stalling);
              return used;
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

/**
 * A deployment whose Proxy tab writes, its R `seconds`, below its 3 s floor where a case needs a tunnel's checks in
 * milliseconds: a test's own object, which `defineDeployment` refuses. Checks every R − d, each given d = min(R ÷ 2,
 * 10 s), a bound of R.
 */
const within = (seconds: number): Deployment => ({ ...defineDeployment(), proxy: { revokedWithinSeconds: seconds, cacheValues: true, editable: true } });

useMcp(async () => {
  runtime.plugins = checkPlugins([credentialProxy({ credentials: {}, insecureUpstreams: true })]);
  // Checks every 200 ms, each given 200 ms: a bound of 400 ms.
  runtime.deployment = within(0.4);
  deps.proxy = proxyCodeWith(runtime.plugins, runtime.deployment);
  root = clientFor(deps, ROOT);
  await root.members.add(`user:${DEV}`);
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { DATABASE_URL: { value: REAL, sensitivity: 'sensitive' }, OPENAI_API_KEY: OPENAI });
  await root.access.set(`user:${DEV}`, { market: 'developer' });
  await save({ db: database() });
  handle = await handleFor('market/dev');
});

const appClientOf = (password = handle): AppClient => appClient(listenerPort, password);

const endsWithin = (client: AppClient, ms: number): Promise<boolean> =>
  Promise.race([client.ended.then(() => true), new Promise<boolean>((resolve) => setTimeout(resolve, ms, false))]);

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** The tunnel's answer to an upgrade at `path` by `token`: the session, or the refusal's status and message. */
async function upgraded(path = '/use/market/dev/db', token = handle): Promise<'session' | { status: number; message: string }> {
  const answer = await pluginSocket(new Request(`${ORIGIN}${path}`, { headers: { authorization: `Bearer ${token}` } }), tracked(runtime), null);
  if (typeof answer === 'function') return 'session';
  assert.ok(answer instanceof Response);
  return { status: answer.status, message: ((await answer.json()) as { message: string }).message };
}

test("the plan names the UI's database as code's, and gives the app no URL of its own; queries run as the real login", async () => {
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

test('the decided item says where the tunnel dials: a host it does not list is refused before any login', async () => {
  await save({ db: database(['db.acme.example']) });
  const refused = await upgraded();
  assert.notEqual(refused, 'session');
  assert.deepEqual(refused, { status: 403, message: "market/dev's DATABASE_URL names a host the tunnel db does not reach" });
  await save({ db: database(['db.acme.example', '127.0.0.1']) });
  assert.equal(await upgraded(), 'session');
});

test('an Owner who narrows the hosts mid-session ends it within a recheck; the reconnect dials by the new item', async () => {
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

test("another item of the environment saved mid-session ends nothing: the check compares the item's own digest", async () => {
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

test("a person whose grant ends loses their UI tunnel's sessions at the next check, and opens no other", async () => {
  const client = appClientOf();
  assert.deepEqual([...await client.unsafe('SELECT 1 AS one')], [{ one: 1 }]);
  await root.access.set(`user:${DEV}`, { market: null });
  assert.equal(await endsWithin(client, 600), true, 'the open session ended');
  await client.end();
  const another = appClientOf();
  await assert.rejects(another.unsafe('SELECT 1'));
  await another.end();
});

test('an item deleted mid-session ends it; a name of no database is no tunnel', async () => {
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

test("a fork's tunnel is its parent's item and key, found through the chain", async () => {
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

/** The case's proxy, as `useMcp` made it but for `options` and its R, `seconds`, its own until the case ends. */
async function withProxy(options: Partial<Parameters<typeof credentialProxy>[0]>, seconds: number, body: () => Promise<void>): Promise<void> {
  const kept = { plugins: runtime.plugins, deployment: runtime.deployment };
  runtime.plugins = checkPlugins([credentialProxy({ credentials: {}, insecureUpstreams: true, ...options })]);
  runtime.deployment = within(seconds);
  try {
    await body();
  } finally {
    Object.assign(runtime, kept);
  }
}

test('a host an Owner typed is dialled only where it resolves to a public address: a name that resolves to a private one gets no connection (review r1 of #485)', async () => {
  // Where `db.attacker.example` resolves, as the Owner who typed it would have it: an address on the server's own network.
  let reached = 0;
  const trap = createTcp((socket) => {
    reached += 1;
    socket.destroy();
  });
  trap.listen(0, '127.0.0.1');
  await once(trap, 'listening');
  const port = (trap.address() as AddressInfo).port;
  const kept = runtime.publicConnect;
  try {
    await withProxy({ insecureUpstreams: false }, 0.4, async () => {
      await root.secrets.set('market/dev', { DATABASE_URL: { value: `postgres://coffre_runtime:pw@db.attacker.example:${port}/coffre?sslmode=require`, sensitivity: 'sensitive' } });
      await save({ db: database(['db.attacker.example']) });
      // A runtime with no connect that checks where a name resolves dials none, refused before the use.
      delete runtime.publicConnect;
      assert.deepEqual(await upgraded(), { status: 503, message: 'db: this runtime has no connect that checks where a database resolves, which a tunnel saved in the Proxy tab dials through' });
      // Node's: the name resolves to loopback, refused as the connection opens, before any byte.
      let asked = 0;
      runtime.publicConnect = publicConnect((hostname, options, callback) => {
        asked += 1;
        publicLookup('localhost', options, callback);
      });
      const client = appClientOf();
      await assert.rejects(client.unsafe('SELECT 1'));
      await client.end();
      assert.ok(asked >= 1, 'the name was resolved through the checked lookup, never the platform\'s');
      assert.equal(reached, 0, 'nothing reached the address the name resolves to');
    });
  } finally {
    if (kept === undefined) delete runtime.publicConnect;
    else runtime.publicConnect = kept;
    await new Promise<void>((resolve) => trap.close(() => resolve()));
  }
});

test('the public connect dials no address written as one that is not public, nor a name whose answer is not (review r1 of #485)', async () => {
  let reached = 0;
  const trap = createTcp((socket) => {
    reached += 1;
    socket.destroy();
  });
  trap.listen(0, '127.0.0.1');
  await once(trap, 'listening');
  const port = (trap.address() as AddressInfo).port;
  try {
    const dial = publicConnect();
    for (const host of ['127.0.0.1', '[::1]', '::ffff:7f00:1', '10.0.1.5', '169.254.169.254', 'localhost']) {
      await assert.rejects(dial(host, port), (error: NodeJS.ErrnoException) => error.code === 'ENOTPUBLIC', host);
    }
    assert.equal(reached, 0);
    // The lookup's answer is what it dials: one that answers loopback unchecked reaches the trap, by name.
    const socket = await publicConnect((hostname, options, callback) => {
      if (options.all) (callback as unknown as (error: null, addresses: { address: string; family: number }[]) => void)(null, [{ address: '127.0.0.1', family: 4 }]);
      else callback(null, '127.0.0.1', 4);
    })('db.acme.example', port);
    socket.close();
    for (let waited = 0; reached === 0 && waited < 2000; waited += 20) await sleep(20);
    assert.equal(reached, 1);
  } finally {
    await new Promise<void>((resolve) => trap.close(() => resolve()));
  }
});

test("an admission answered after its whole bound lets nothing in: the item may have been narrowed since it was decided (review r1 of #485)", async () => {
  // R 0.4 s: a bound of 400 ms. The vault decides the old item, the Owner narrows it, and the answer comes 600 ms on.
  holding = async () => {
    await save({ db: database(['127.0.0.1', 'db.acme.example']) });
    await sleep(600);
  };
  assert.deepEqual(await upgraded(), { status: 503, message: 'db: its use answered too late to dial by; ask again' });
  assert.equal(holding, null, 'the admission was held');
  // Asked again, by the new item.
  assert.equal(await upgraded(), 'session');
});

test("a group's watchdog counts from its admission: one answered late, its first check stalled, ends by the admission's bound (review r1 of #485)", { timeout: 20_000 }, async () => {
  await withProxy({}, 2, async () => {
    // A bound of 2 s. The answer comes 1.7 s after the use started, and the check due at once does not answer: the
    // watchdog, armed from the admission, ends the session 0.3 s on, before that check's deadline a second on.
    let answeredAt = 0;
    holding = async (started) => {
      await sleep(started + 1700 - Date.now());
      answeredAt = Date.now();
    };
    stalling = 3000;
    const client = appClientOf();
    const endedAt = client.ended.then(() => Date.now());
    void client.unsafe('SELECT 1').catch(() => undefined);
    assert.equal(await endsWithin(client, 5000), true, 'the session ended');
    await client.end();
    assert.ok(answeredAt > 0, 'the admission was held');
    const after = (await endedAt) - answeredAt;
    assert.ok(after < 700, `ended ${after} ms after its admission answered, by the watchdog armed 2 s after the use started`);
  });
});

test("a group's clock starts from its admission: one answered late is checked at once, not a whole recheck after (review r1 of #485)", { timeout: 20_000 }, async () => {
  await withProxy({}, 2, async () => {
    // A bound of 2 s. The vault decides the old item, the Owner saves it anew, and the answer comes 1.3 s after the use
    // started: past the admission's first recheck, inside its bound.
    let answeredAt = 0;
    holding = async () => {
      await save({ db: database(['127.0.0.1', 'db.acme.example']) });
      await sleep(1300);
      answeredAt = Date.now();
    };
    const client = appClientOf();
    const endedAt = client.ended.then(() => Date.now());
    void client.unsafe('SELECT 1').catch(() => undefined);
    assert.equal(await endsWithin(client, 5000), true, 'the session dialled by the old item ended');
    await client.end();
    assert.ok(answeredAt > 0, 'the admission was held');
    const after = (await endedAt) - answeredAt;
    assert.ok(after < 600, `ended ${after} ms after its admission answered, by the check due a second after the use started`);
  });
});

test("an isolate whose copy of the item's definition turned over claims no digest it lacks, and dials (review r1 of #485)", async () => {
  assert.equal(await upgraded(), 'session');
  // The copies of definitions turned over, the reading's last digest kept: a claim of it would have the vault leave the
  // definition out, and every open answer 503 `moved`.
  forgetUiItems(runtime.plugins[0]!);
  assert.equal(await upgraded(), 'session');
  // Turned over while the use is under way: the copy it claimed, kept through the use, is the definition.
  holding = async () => forgetUiItems(runtime.plugins[0]!);
  assert.equal(await upgraded(), 'session');
  assert.equal(holding, null, 'the admission was held');
});

test("Node's coffre hands its plugins the connect that dials only public addresses, which a UI tunnel needs (review r2 of #485)", async () => {
  // A plugin of its own, under `createCoffre` as a deployment calls it: what its context's `publicConnect` does with
  // loopback. Without one installed (node.ts), every UI tunnel on Node would answer 503, these cases all passing.
  const probe: CoffrePlugin = {
    name: 'probe',
    routes: {
      prefix: '/probe',
      fetch: async (_, context) => {
        if (context.publicConnect === undefined) return Response.json({ connect: null });
        try {
          (await context.publicConnect('127.0.0.1', 9, AbortSignal.timeout(2000))).close();
          return Response.json({ connect: 'dialled' });
        } catch (error) {
          return Response.json({ connect: (error as NodeJS.ErrnoException).code ?? String(error) });
        }
      },
    },
  };
  const node = nodeCoffre({ publicUrl: ORIGIN, database: TEST_RUNTIME_DATABASE_URL, vault: deps.vault, auth: signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })] }), auditChainKey: deps.chainKey.toString('base64'), plugins: [probe] });
  const request = new Request(`${ORIGIN}/probe`);
  const answered = await node.request(request).coffre.route(request);
  assert.deepEqual(await answered.json(), { connect: 'ENOTPUBLIC' });
});
