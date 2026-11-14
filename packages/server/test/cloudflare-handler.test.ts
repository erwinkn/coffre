// The app Worker's `createCoffre(…)` (src/cloudflare-handler.ts), run on Node with
// stand-ins for its bindings, 0.14.7's cloudflare-handler.test.ts on 0.16: a refusal
// answers without waiting on the body; a request's Hyperdrive client closes through
// `waitUntil` once coffre's work is done; coffre's server routes say what the app left out
// of the request's context; and `upgrade` names the Durable Object a plugin's WebSocket
// goes to. `app-workers.test.ts` holds the same Worker in workerd, against a database.
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { github, signin } from '@coffre/core/identity';
import { HyperdrivePool } from '@coffre/db/hyperdrive';

import { createCoffre, postgres, type CoffreContext, type SocketsNamespace, type WorkersConfig } from '../src/cloudflare.ts';
import { credentialProxy, postgres as tunnel } from '../src/plugins/credential-proxy.ts';
import { api, auth, livez, readyz } from '../src/routes.ts';
import { NO_COFFRE, NO_MIDDLEWARE } from '../src/wiring.ts';

/** A deployment's configuration: a database no one listens at, which these never reach, and a vault never asked. */
const config = (more: Partial<WorkersConfig> = {}) => (): WorkersConfig => ({
  publicUrl: 'https://coffre.test',
  database: postgres({ connectionString: 'postgres://nobody@127.0.0.1:1/none' } as never),
  vault: {} as never,
  auth: signin({ providers: [github({ clientId: 'id', clientSecret: 'secret' })] }),
  auditChainKey: Buffer.alloc(32, 1).toString('base64'),
  ...more,
});
const worker = createCoffre(config());

/** Start, as far as these need it: coffre's middleware, then coffre's routes. */
const start = (request: Request, { coffre }: CoffreContext) => coffre.respond(request, () => coffre.route(request));

test('a refusal answers at once, though its body never ends: nothing waits on what a caller still sends', async () => {
  const neverEnds = new ReadableStream<Uint8Array>({ start: (controller) => controller.enqueue(new Uint8Array([1])) });
  const request = new Request('https://coffre.test/livez', { method: 'POST', body: neverEnds, duplex: 'half' } as RequestInit);
  const answered = await Promise.race([start(request, worker.request({}, { waitUntil: () => undefined })), new Promise<'waiting'>((resolve) => setTimeout(() => resolve('waiting'), 250))]);
  assert.notEqual(answered, 'waiting');
  assert.equal((answered as Response).status, 405);
  assert.match((answered as Response).headers.get('content-security-policy') ?? '', /script-src 'self' 'nonce-/);
});

test("a request's database client is closed through waitUntil once coffre's work for it is done, and not before", async (t) => {
  // Each `end` asked of a request's pool, in turn: no database answers here, so none has a connection to close.
  const ended: string[] = [];
  t.mock.method(HyperdrivePool.prototype, 'end', async () => void ended.push('end'));
  const left: Promise<unknown>[] = [];
  const context = worker.request({}, { waitUntil: (promise) => void left.push(promise) });
  assert.equal(left.length, 0);
  // The page's render, held: coffre's work for the request is not done until it answers.
  let render!: (response: Response) => void;
  const rendered = new Promise<Response>((resolve) => (render = resolve));
  const answer = context.coffre.respond(new Request('https://coffre.test/livez'), () => rendered);
  assert.ok(left.length > 0, 'nothing was left to close the database');
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.deepEqual(ended, [], 'closed while the render was still under way');
  render(new Response('rendered'));
  assert.equal(await (await answer).text(), 'rendered');
  await Promise.all(left);
  assert.deepEqual(ended, ['end']);
});

test("coffre's server routes, without its middleware or without coffre in the context, say which is missing", () => {
  for (const route of [api, auth, livez, readyz]) {
    const handler = route.server.handlers.ANY;
    const request = new Request('https://coffre.test/livez');
    assert.throws(() => handler({ request, context: {} }), (error: Error) => error.message === NO_MIDDLEWARE);
    assert.throws(() => handler({ request, context: { coffreMiddleware: true } }), (error: Error) => error.message === NO_COFFRE);
  }
});

test("a plugin's WebSocket goes to the Durable Object its path and credential name; any other request to Start", async () => {
  // The objects asked for, by name, and the requests each was sent.
  const sent: [string, Request][] = [];
  const sockets: SocketsNamespace = {
    idFromName: (name) => name,
    get: (id) => ({ fetch: async (request) => (sent.push([id as string, request]), new Response('from the object')) }),
  };
  const plugins = [credentialProxy({ credentials: {}, tunnels: { db: tunnel('DATABASE_URL') } })];
  const hosted = createCoffre(config({ plugins, sockets }));
  const socket = (path: string, credential: string, flow = 'credit') => new Request(`https://coffre.test${path}`, { headers: { upgrade: 'websocket', authorization: credential, 'coffre-tunnel-flow': flow } });

  // Not a WebSocket, or one no plugin takes: Start's.
  assert.equal(hosted.upgrade(new Request('https://coffre.test/use/market/dev/db'), {}), null);
  assert.equal(hosted.upgrade(socket('/api/projects', 'Bearer a'), {}), null);
  // A client that does not pace its bytes, an older CLI's: refused by the Worker, no object made for it.
  assert.equal((await hosted.upgrade(socket('/use/market/dev/db', 'Bearer a', 'none'), {}))!.status, 426);
  assert.equal(sent.length, 0);

  // One object per run and database: the same handle and path, the same object; another handle, another path, or the same
  // token as a workload's session, another.
  for (const [path, credential] of [['/use/market/dev/db', 'Bearer a'], ['/use/market/dev/db', 'Bearer a'], ['/use/market/dev/db', 'Bearer b'], ['/use/market/prod/db', 'Bearer a'], ['/use/market/dev/db', 'DPoP a']] as const) {
    assert.equal(await (await hosted.upgrade(socket(path, credential), {}))!.text(), 'from the object');
  }
  const names = sent.map(([name]) => name);
  assert.equal(names[0], names[1]);
  assert.equal(new Set(names).size, 4);
  // Another spelling of the same bearer and path, as admission reads them: the same object.
  await hosted.upgrade(socket('/use/market/dev/%64b', 'bearer   a'), {});
  assert.equal(sent.at(-1)![0], names[0]);
  // A digest: the handle names no object anyone can read.
  assert.ok(names.every((name) => /^[0-9a-f]{64}$/.test(name)), names.join());
  // The object is sent the request as it came, its bearer included, and decides on it: the Worker checks nothing.
  assert.equal(sent[0]![1].headers.get('authorization'), 'Bearer a');

  // A deployment that adds no sockets binding refuses, and says why.
  const refused = await createCoffre(config({ plugins })).upgrade(socket('/use/market/dev/db', 'Bearer a'), {})!;
  assert.equal(refused.status, 501);
  assert.match(await refused.text(), /sockets binding/);
});
