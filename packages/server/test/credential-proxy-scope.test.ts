// What PR B's first review found, each through the plugin's route with a fake
// coffre and an egress for the upstream: a code item's `environments` on the
// stable URL when the vault's one call finds nothing by name, a presigned
// URL's path held to a request's refusals, and rules a later step drops a
// header of. No database: what is checked is the plugin's own work.
import assert from 'node:assert/strict';
import test from 'node:test';

import type { PluginContext, UseAsked, WorkloadUse } from '../src/plugins.ts';
import { credentialProxy, form, header, hmac, postgres, privateKey, sigv4, type Credential } from '../src/plugins/credential-proxy.ts';

const PUBLIC = 'https://coffre.example';
const HANDLE = `coffre_use_${'h'.repeat(43)}`;
const LATER = new Date(Date.now() + 3_600_000).toISOString();
const SECRET = 'sk_live_0123456789abcdef';

/** coffre, as a plugin sees it: the handle stands for `market/dev`, whose keys each hold SECRET. `madeFor` plays the vault's one call. */
function fake(madeFor?: 'found' | 'none'): PluginContext {
  const used = (keys: readonly string[]) => ({
    values: Object.fromEntries(keys.map((key) => [key, SECRET])),
    plain: [],
    keys,
    environment: { path: 'market/dev', personal: false },
    expiresAt: LATER,
  });
  return {
    publicUrl: PUBLIC,
    workload: async () => null,
    handle: async () => ({ expiresAt: LATER, paths: ['market/dev'] }),
    use: async (_handle: string | WorkloadUse, asked: UseAsked) => used(asked.keys as readonly string[]),
    ...(madeFor === undefined ? {} : { useMadeFor: async (_handle: string, asked: { keys: readonly [string] }) => (madeFor === 'found' ? used(asked.keys) : null) }),
  } as unknown as PluginContext;
}

/** A proxy of one credential, `api`, and what reached its upstream. */
function proxy(credential: Partial<Credential>, coffre = fake()) {
  const reached: { url: URL; headers: Headers }[] = [];
  const egress = { fetch: async (url: URL, init: RequestInit) => {
    reached.push({ url, headers: new Headers(init.headers) });
    return new Response('ok');
  } };
  const plugin = credentialProxy({ cacheSeconds: 0, credentials: { api: { upstream: 'https://api.example/v1', inject: header('x-api-key', '{KEY}'), egress, ...credential } } });
  const ask = async (path: string, init: RequestInit = {}) => {
    const answer = await plugin.routes!.fetch(new Request(`${PUBLIC}/use${path}`, { ...init, headers: { 'x-coffre-handle': HANDLE, ...init.headers } }), coffre);
    return { status: answer.status, body: answer.status === 200 ? '' : await answer.text() };
  };
  return { reached, ask };
}

test('a credential scoped to market/prod: the stable URL refuses a market/dev handle, whether the vault finds it by name, finds nothing, or has no such call', async () => {
  for (const madeFor of ['found', 'none', undefined] as const) {
    const { reached, ask } = proxy({ environments: ['market/prod'] }, fake(madeFor));
    const answer = await ask('/api/x/y');
    assert.equal(answer.status, 404, String(madeFor));
    assert.match(answer.body, /api does not serve market\/dev/);
    assert.equal(reached.length, 0, String(madeFor));
  }
  // Served where it is scoped: the same stable URL, the vault's call finding nothing by name, goes on.
  const served = proxy({ environments: ['market/dev'] }, fake('none'));
  assert.equal((await served.ask('/api/x/y')).status, 200);
  assert.equal(served.reached[0]!.url.pathname, '/v1/x/y');
});

test('a presigned URL is refused for a path a request would be, at every decoding depth, before its allow list', async () => {
  const s3 = sigv4({ accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', region: 'eu-west-3', service: 's3' });
  const { ask } = proxy({ upstream: 'https://s3.eu-west-3.amazonaws.com', inject: s3, allow: [{ path: '/bucket/public/**' }] });
  const presign = (path: string) => ask('/market/dev', { method: 'POST', headers: { authorization: `Bearer ${HANDLE}`, 'content-type': 'application/json' }, body: JSON.stringify({ presign: { credential: 'api', path } }) });
  assert.equal((await presign('/bucket/public/k')).status, 200);
  for (const path of ['/bucket/public/%252e%252e/private/k', '/bucket/public/..;/private/k', '/bucket/public/..%20/private/k', '/bucket/public/%00/k', '/bucket/public/a%252fb/k']) {
    const answer = await presign(path);
    assert.equal(answer.status, 400, path);
    assert.match(answer.body, /may not climb out/, path);
  }
  assert.equal((await presign('/bucket/private/k')).status, 403);
  // A segment of `;` parameters alone, past `**`: under /bucket/public/ whether Tomcat drops it or not.
  assert.equal((await presign('/bucket/public/;/k')).status, 200);
  // Encoded deeper than anything sends, 40 KB of `%2525…`: refused, in 8 decodings, never a stack overflow.
  const deep = await presign(`/bucket/public/%${'25'.repeat(20_000)}2e/k`);
  assert.equal(deep.status, 400);
  assert.match(deep.body, /may not climb out/);
  assert.equal((await presign(`/bucket/public/%${'25'.repeat(7)}41/k`)).status, 200, 'eight decodings, the cap, read as A');
  assert.equal((await presign(`/bucket/public/%${'25'.repeat(8)}41/k`)).status, 400, 'nine, refused');
});

test('a segment of ; parameters alone fills no `*`, which a server may read as none; a prefix and a list of methods alone take it', async () => {
  const { reached, ask } = proxy({ allow: [{ path: '/companies/*/documents' }, { path: '/kyc' }] });
  // And spaces or dots alone, which Windows drops from a segment's end: `/companies/%20/documents` is `/companies//documents` to it.
  for (const path of ['/companies//documents', '/companies/;/documents', '/companies/;x/documents', '/companies/%3Bx/documents', '/companies/%253Bx/documents', '/companies/%20/documents', '/companies/%20%20/documents', '/companies/.../documents', '/companies/....;x/documents', '/companies/%2520/documents']) {
    const answer = await ask(`/market/dev/api${path}`);
    assert.equal(answer.status, 403, path);
    assert.match(answer.body, /api is not for/, path);
  }
  assert.equal((await ask('/market/dev/api/companies/a%20b/documents')).status, 200, 'a space inside a segment is a byte of it');
  assert.equal((await ask('/market/dev/api/companies/a;b/documents')).status, 200, 'a segment with bytes before its parameters is one');
  // Past a prefix: /kyc/ to a server that drops it, still under /kyc.
  for (const path of ['/kyc/;', '/kyc/%20', '/kyc//a']) assert.equal((await ask(`/market/dev/api${path}`)).status, 200, path);
  assert.equal(reached.length, 5);
  const methods = proxy({ methods: ['GET'] });
  for (const path of ['/bucket//key', '/bucket/;/key']) assert.equal((await methods.ask(`/market/dev/api${path}`)).status, 200, path);
  assert.equal((await methods.ask('/market/dev/api/bucket//key', { method: 'PUT' })).status, 405);
  // Beside an entry that names a path, an entry of methods alone still takes them: it counts no segment, whatever the others name.
  const mixed = proxy({ allow: [{ methods: ['GET'] }, { methods: ['POST'], path: '/x' }] });
  for (const path of ['/bucket//key', '/bucket/%20/key', '/bucket/;x/key']) assert.equal((await mixed.ask(`/market/dev/api${path}`)).status, 200, path);
  assert.equal((await mixed.ask('/market/dev/api/bucket//key', { method: 'POST' })).status, 405, 'POST is the path entry\'s, for /x only: GET\'s entry takes every path');
  assert.equal((await mixed.ask('/market/dev/api/x', { method: 'POST' })).status, 200);
  assert.equal(mixed.reached.length, 4);
});

test('an allow entry of any method on any path is refused at startup, however it says so: {} and { methods: [] } alike', () => {
  for (const entry of [{}, { methods: [] }]) {
    assert.throws(() => proxy({ allow: [{ path: '/a' }, entry] }), /allow entry .* takes every request: give it methods or a path, or leave allow out/, JSON.stringify(entry));
  }
  // With a path, `methods: []` is any method on it, and starts.
  const { ask } = proxy({ allow: [{ methods: [], path: '/health' }] });
  return Promise.all([ask('/market/dev/api/health', { method: 'DELETE' }), ask('/market/dev/api/other')]).then(([health, other]) => {
    assert.equal(health.status, 200);
    assert.equal(other.status, 403);
  });
});

test('environments on a signer, a verifier and a tunnel: each is refused, 404, in an environment it does not serve, before anything opens', async () => {
  const opened: string[] = [];
  const coffre = { ...fake(), use: async (_handle: unknown, asked: UseAsked) => { opened.push(...(asked.keys as readonly string[])); return { values: {}, plain: [], keys: asked.keys, environment: { path: 'market/dev', personal: false }, expiresAt: LATER }; } } as unknown as PluginContext;
  const plugin = credentialProxy({
    credentials: {},
    signers: { 'ed-key': privateKey('ED_KEY', { environments: ['market/prod'] }) },
    verifiers: { hook: hmac('HOOK_SECRET', { encoding: 'hex', environments: ['market/prod'] }) },
    tunnels: { db: postgres('DATABASE_URL', { environments: ['market/prod'] }) },
  });
  const post = (body: unknown) => plugin.routes!.fetch(new Request(`${PUBLIC}/use/market/dev`, { method: 'POST', headers: { authorization: `Bearer ${HANDLE}`, 'content-type': 'application/json' }, body: JSON.stringify(body) }), coffre);
  for (const [what, body] of [['sign', { sign: { credential: 'ed-key', message: 'aGk' } }], ['verify', { verify: { credential: 'hook', message: 'aGk', signature: '00' } }]] as const) {
    const answer = await post(body);
    assert.equal(answer.status, 404, what);
    assert.match(await answer.text(), /does not serve market\/dev/, what);
  }
  const tunnel = await plugin.routes!.socket!(new Request(`${PUBLIC}/use/market/dev/db`, { headers: { authorization: `Bearer ${HANDLE}`, upgrade: 'websocket' } }), coffre);
  assert.ok(tunnel instanceof Response);
  assert.equal(tunnel.status, 404);
  assert.match(await tunnel.text(), /db does not serve market\/dev/);
  assert.deepEqual(opened, []);
});

test('an empty allow list, or paths: [], takes nothing, and says so; methods: [] takes no method, and says so', async () => {
  for (const credential of [{ allow: [] }, { paths: [] }]) {
    const answer = await proxy(credential).ask('/market/dev/api/a');
    assert.equal(answer.status, 403);
    assert.match(answer.body, /api's allow list is empty: it takes no request/);
  }
  const none = await proxy({ methods: [] }).ask('/market/dev/api/a');
  assert.equal(none.status, 405);
  assert.match(none.body, /api takes no method/);
});

test('a * in code\'s paths is itself, as before 0.16, with a warning: never a glob, and no path of old fails to start', async (t) => {
  const warned = t.mock.method(console, 'warn', () => undefined);
  const { ask } = proxy({ paths: ['/files/*', '/a/**/b'] });
  assert.match(String(warned.mock.calls[0]?.arguments[0]), /api's path \/files\/\* takes \* as itself, as before 0\.16/);
  assert.equal((await ask('/market/dev/api/files/*/x')).status, 200);
  assert.equal((await ask('/market/dev/api/files/%2A')).status, 403, 'compared as written, as on 0.15: `%2A` is not `*`');
  assert.equal((await ask('/market/dev/api/files/anything')).status, 403);
  assert.equal((await ask('/market/dev/api/a/**/b/c')).status, 200);
  assert.equal((await ask('/market/dev/api/a/x/b')).status, 403);
});

test('a header a later step drops is still redacted, and the request goes: host before SigV4, content-md5 before a form field', async () => {
  const s3 = sigv4({ accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', region: 'eu-west-3', service: 's3' });
  const signed = proxy({ upstream: 'https://s3.eu-west-3.amazonaws.com', inject: [header('x-host', 'h-{HOST_KEY}'), header('host', '{HOST_KEY}'), s3] });
  assert.equal((await signed.ask('/market/dev/api/bucket/k')).status, 200);
  const filled = proxy({ inject: [header('content-md5', 'm-{MD5_KEY}'), form('secret', '{KEY}')] });
  const body = new URLSearchParams({ secret: HANDLE, other: 'x' }).toString();
  const answer = await filled.ask('/market/dev/api/verify', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
  assert.equal(answer.status, 200);
  assert.equal(filled.reached[0]!.headers.get('content-md5'), null, 'the body changed: its digest is dropped');
});
