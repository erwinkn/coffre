import test from 'node:test';
import assert from 'node:assert/strict';

import { signin, github } from '@coffre/core/identity';

import { coffre, createCoffre, postgres, type CoffreContext } from '../src/cloudflare.ts';
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

test("0.1's coffre(env => …) says how to move, the moment it runs", () => {
  assert.throws(() => coffre(), /since 0\.2 the app is a TanStack Start app of its own.*npx @coffre\/cli@latest update/);
});

test("coffre's server routes, without its middleware or without coffre in the context, say which is missing", async () => {
  for (const route of [api, auth, livez, readyz]) {
    const handler = route.server.handlers.ANY;
    const request = new Request('https://coffre.test/livez');
    assert.throws(() => handler({ request, context: {} }), (error: Error) => error.message === NO_MIDDLEWARE);
    assert.throws(() => handler({ request, context: { coffreMiddleware: true } }), (error: Error) => error.message === NO_COFFRE);
  }
});
