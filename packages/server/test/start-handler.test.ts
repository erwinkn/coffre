// Start's own handler, as a deployment's server entry runs it, with the
// middleware coffre init's src/start.ts gives it: what Start does after the middleware has answered (resolving
// a redirect, serialising it for a server function) still works on what
// the middleware hands back. Start's entries, which its Vite plugin
// provides in a build, are the fixtures in fixtures/start/.
import test from 'node:test';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';

import { signin, github } from '@coffre/core/identity';

import { createCoffre, postgres } from '../src/cloudflare.ts';
import { testVault } from './api-fixture.ts';

const entries: Record<string, string> = {
  '#tanstack-router-entry': './fixtures/start/router.ts',
  '#tanstack-start-entry': './fixtures/start/start.ts',
  '#tanstack-start-server-fn-resolver': './fixtures/start/server-fns.ts',
};
registerHooks({
  resolve: (specifier, context, next) =>
    specifier in entries ? { url: new URL(entries[specifier]!, import.meta.url).href, shortCircuit: true } : next(specifier, context),
});
// As Vite's dev server sets them: no prebuilt manifest to warm up, and where server functions are.
process.env.TSS_DEV_SERVER = 'true';
process.env.TSS_SERVER_FN_BASE = '/_serverFn/';
const { createStartHandler, defaultStreamHandler } = await import('@tanstack/react-start/server');

const coffre = createCoffre(() => ({
  publicUrl: 'https://coffre.test',
  database: postgres({ connectionString: 'postgres://nobody@127.0.0.1:1/none' }),
  vault: testVault(['admin@acme.example']),
  auth: signin({ providers: [github({ clientId: 'id', clientSecret: 'secret' })] }),
  auditChainKey: Buffer.alloc(32, 1).toString('base64'),
}));
const handler = createStartHandler(defaultStreamHandler);
const fetchApp = (request: Request) => handler(request, { context: coffre.request({}, { waitUntil: () => {} }) } as never);

test("a server route's redirect, through coffre's middleware, is resolved by Start, with coffre's headers", async () => {
  const response = await fetchApp(new Request('https://coffre.test/hooks/deployed', { method: 'POST' }));
  assert.equal(response.status, 307);
  assert.equal(response.headers.get('location'), '/done');
  assert.match(response.headers.get('content-security-policy') ?? '', /'nonce-/);
});

test("a server function's redirect, through coffre's middleware, is serialised for its caller", async () => {
  const response = await fetchApp(
    new Request('https://coffre.test/_serverFn/redirects', {
      headers: { 'x-tsr-serverFn': 'true', origin: 'https://coffre.test', 'sec-fetch-site': 'same-origin' },
    }),
  );
  assert.match(response.headers.get('content-security-policy') ?? '', /'nonce-/);
  const body = (await response.json()) as { isSerializedRedirect?: boolean; to?: string };
  assert.equal(body.isSerializedRedirect, true, JSON.stringify(body));
  assert.equal(body.to, '/done');
});

test("a server function called from another site is refused by Start's CSRF check, with coffre's headers; coffre's routes are not its to refuse", async () => {
  const crossSite = { origin: 'https://evil.example', 'sec-fetch-site': 'cross-site' };
  const refused = await fetchApp(new Request('https://coffre.test/_serverFn/redirects', { headers: { 'x-tsr-serverFn': 'true', ...crossSite } }));
  assert.equal(refused.status, 403);
  assert.match(refused.headers.get('content-security-policy') ?? '', /'nonce-/);
  // A server route, as /api and /auth are: CSRF there is coffre's own to judge, by route.
  const route = await fetchApp(new Request('https://coffre.test/hooks/deployed', { method: 'POST', headers: crossSite }));
  assert.equal(route.status, 307);
});
