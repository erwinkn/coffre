import test from 'node:test';
import assert from 'node:assert/strict';

import { signin, github } from '@coffre/core/identity';

import { createCoffre, postgres, type CoffreContext, type SocketsNamespace } from '../src/cloudflare.ts';
import { credentialProxy, postgres as tunnel } from '../src/plugins/credential-proxy.ts';
import { api, auth, livez, readyz } from '../src/routes.ts';
import { NO_COFFRE, NO_MIDDLEWARE } from '../src/wiring.ts';
import { testVault } from './api-fixture.ts';

const worker = createCoffre(() => ({
  publicUrl: 'https://coffre.test',
  database: postgres({ connectionString: 'postgres://nobody@127.0.0.1:1/none' }),
  vault: testVault(['admin@acme.example']),
  auth: signin({ providers: [github({ clientId: 'id', clientSecret: 'secret' })] }),
  auditChainKey: Buffer.alloc(32, 1).toString('base64'),
}));

/** Start, as far as these need it: coffre's middleware, then coffre's routes. */
const start = (request: Request, { coffre }: CoffreContext) => coffre.respond(request, () => coffre.route(request));

test('a refusal answers at once, though its body never ends: nothing waits on what a caller still sends', async () => {
  const neverEnds = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array([1]));
    },
  });
  const request = new Request('https://coffre.test/livez', { method: 'POST', body: neverEnds, duplex: 'half' } as RequestInit);
  const answered = await Promise.race([
    start(request, worker.request({}, { waitUntil: () => {} })),
    new Promise<'waiting'>((resolve) => setTimeout(() => resolve('waiting'), 250)),
  ]);
  assert.notEqual(answered, 'waiting');
  assert.equal((answered as Response).status, 405);
  assert.match((answered as Response).headers.get('content-security-policy') ?? '', /script-src 'self' 'nonce-/);
});

test("a request's database is closed once coffre's work for it is done, and not before it begins", async () => {
  const left: Promise<unknown>[] = [];
  const context = worker.request({}, { waitUntil: (promise) => void left.push(promise) });
  assert.equal(left.length, 0);
  const response = await start(new Request('https://coffre.test/livez'), context);
  assert.equal(response.status, 200);
  assert.ok(left.length > 0, 'nothing was left to close the database');
  await Promise.all(left);
});

test("coffre's server routes, without its middleware or without coffre in the context, say which is missing", async () => {
  for (const route of [api, auth, livez, readyz]) {
    const handler = route.server.handlers.ANY;
    const request = new Request('https://coffre.test/livez');
    assert.throws(() => handler({ request, context: {} }), (error: Error) => error.message === NO_MIDDLEWARE);
    assert.throws(() => handler({ request, context: { coffreMiddleware: true } }), (error: Error) => error.message === NO_COFFRE);
  }
});

test("a plugin's WebSocket goes to the Durable Object its path and bearer name; any other request to Start", async () => {
  // The objects asked for, by name, and the requests each was sent.
  const sent: [string, Request][] = [];
  const sockets: SocketsNamespace = {
    idFromName: (name) => name,
    get: (id) => ({ fetch: async (request) => (sent.push([id as string, request]), new Response('from the object')) }),
  };
  const config = (withSockets: boolean) => () => ({
    publicUrl: 'https://coffre.test',
    database: postgres({ connectionString: 'postgres://nobody@127.0.0.1:1/none' }),
    vault: testVault(['admin@acme.example']),
    auth: signin({ providers: [github({ clientId: 'id', clientSecret: 'secret' })] }),
    auditChainKey: Buffer.alloc(32, 1).toString('base64'),
    plugins: [credentialProxy({ credentials: {}, tunnels: { db: tunnel('DATABASE_URL') } })],
    ...(withSockets ? { sockets } : {}),
  });
  const hosted = createCoffre(config(true));
  const socket = (path: string, handle: string, flow = 'credit') => new Request(`https://coffre.test${path}`, { headers: { upgrade: 'websocket', authorization: `Bearer ${handle}`, 'coffre-tunnel-flow': flow } });

  // Not a WebSocket, or one no plugin takes: Start's.
  assert.equal(hosted.upgrade(new Request('https://coffre.test/use/market/dev/db'), {}), null);
  assert.equal(hosted.upgrade(socket('/api/projects', 'a'), {}), null);
  // A client that does not pace its bytes, an older CLI's: refused by the Worker, no object made for it.
  assert.equal((await hosted.upgrade(socket('/use/market/dev/db', 'a', 'none'), {}))!.status, 426);
  assert.equal(sent.length, 0);

  // One object per run and database: the same handle and path, the same object; another handle or another path, another.
  for (const [path, handle] of [['/use/market/dev/db', 'a'], ['/use/market/dev/db', 'a'], ['/use/market/dev/db', 'b'], ['/use/market/prod/db', 'a']] as const) {
    assert.equal(await (await hosted.upgrade(socket(path, handle), {}))!.text(), 'from the object');
  }
  const names = sent.map(([name]) => name);
  assert.equal(names[0], names[1]);
  assert.equal(new Set(names).size, 3);
  // A digest: the handle names no object anyone can read.
  assert.ok(names.every((name) => /^[0-9a-f]{64}$/.test(name)));
  // The object is sent the request as it came, its bearer included, and decides on it: the Worker checks nothing.
  assert.equal(sent[0]![1].headers.get('authorization'), 'Bearer a');

  // A deployment that adds no sockets binding refuses, and says why.
  const refused = await createCoffre(config(false)).upgrade(socket('/use/market/dev/db', 'a'), {})!;
  assert.equal(refused.status, 501);
  assert.match(await refused.text(), /sockets binding/);
});
