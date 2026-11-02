// A route's allow list (docs/design/proxy-ui.md, section 7, "The path" and
// "The allow list"): section 7's table through the proxy, as a request
// reaches it, then each form of pattern, the methods beside them, and code's
// `methods` and `paths` read as entries. A fake coffre opens the values and
// an egress plays the upstream, so what is checked is the plugin's own work.
import assert from 'node:assert/strict';
import test from 'node:test';

import type { PluginContext, UseAsked, WorkloadUse } from '../src/plugins.ts';
import { credentialProxy, header, type Credential } from '../src/plugins/credential-proxy.ts';
import { allows, readPattern, requestSegments, type AllowEntry } from '../src/plugins/proxy-match.ts';

const PUBLIC = 'https://coffre.example';
const HANDLE = `coffre_use_${'h'.repeat(43)}`;
const LATER = new Date(Date.now() + 3_600_000).toISOString();

/** coffre, as a plugin sees it: the handle stands for `market/dev`, whose one key is KEY. */
const coffre = {
  publicUrl: PUBLIC,
  workload: async () => null,
  handle: async () => ({ expiresAt: LATER, paths: ['market/dev'] }),
  use: async (_handle: string | WorkloadUse, asked: UseAsked) => ({
    values: Object.fromEntries((asked.keys as readonly string[]).map((key) => [key, 'sk_live_0123456789abcdef'])),
    plain: [],
    keys: ['KEY'],
    environment: { path: 'market/dev', personal: false },
    expiresAt: LATER,
  }),
} as unknown as PluginContext;

/** The upstream's path for each request the proxy sent on: what it was asked, and nothing else. */
function proxy(credential: Partial<Credential>) {
  const reached: string[] = [];
  const egress = { fetch: async (url: URL) => {
    reached.push(url.pathname);
    return new Response('ok');
  } };
  const plugin = credentialProxy({ cacheSeconds: 0, credentials: { api: { upstream: 'https://api.example/v1', inject: header('x-api-key', '{KEY}'), egress, ...credential } } });
  const ask = async (path: string, method = 'GET') => {
    const answer = await plugin.routes!.fetch(new Request(`${PUBLIC}/use/market/dev/api${path}`, { method, headers: { 'x-coffre-handle': HANDLE } }), coffre);
    return { status: answer.status, message: answer.status === 200 ? '' : ((await answer.json()) as { message: string }).message };
  };
  return { reached, ask };
}

test("section 7's table: each segment decoded once and matched; a dot segment, an encoded slash or a control byte refused, and `//` fills no `*`", async () => {
  const { reached, ask } = proxy({ allow: [{ path: '/companies/*/documents/**' }, { path: '/kyc' }] });
  assert.equal((await ask('/companies/42/documents/a%20b.pdf')).status, 200);
  // Matched as `documents`, never missed for its spelling.
  assert.equal((await ask('/companies/42/docu%6Dents')).status, 200);
  assert.deepEqual(reached, ['/v1/companies/42/documents/a%20b.pdf', '/v1/companies/42/docu%6Dents'], 'the path goes on as the app encoded it');
  for (const path of ['/kyc/..%2fadmin', '/kyc/%25252e%25252e/admin', '/kyc/..%20/admin', '/kyc/..%00/admin', '/kyc/..;/admin']) {
    assert.deepEqual(await ask(path), { status: 400, message: "the path may not climb out of the credential's upstream" }, path);
  }
  assert.deepEqual(await ask('/companies//documents'), { status: 403, message: 'api is not for /companies//documents' });
  // `%2e%2e` is `..` to a URL parser, which resolves it before any server code runs: the request is for /admin, outside the list.
  assert.deepEqual(await ask('/kyc/%2e%2e/admin'), { status: 403, message: 'api is not for /admin' });
  assert.equal(reached.length, 2);
});

test('a plain path is a prefix by segments; code\'s trailing slash takes what is below it, a segment a server reads as one for allow; / takes every path', async () => {
  const plain = proxy({ allow: [{ path: '/companies' }] });
  for (const path of ['/companies', '/companies/', '/companies/42', '/companies/42/documents']) assert.equal((await plain.ask(path)).status, 200, path);
  for (const path of ['/companiesX', '/compan', '', '/', '/users/companies']) assert.equal((await plain.ask(path)).status, 403, path);
  // Legacy: what is below as written, as on 0.15, `/companies/` and `/companies/...` included.
  const below = proxy({ paths: ['/companies/'] });
  for (const path of ['/companies/', '/companies/42', '/companies/...']) assert.equal((await below.ask(path)).status, 200, path);
  assert.equal((await below.ask('/companies')).status, 403);
  // `allow`: a segment below that a server reads as one. `/bucket/a/...`, `/bucket/a/;x` and `/bucket/a/` are
  // `/bucket/a` to a server that drops what vanishes, or a trailing slash: which `/bucket/*/` leaves out.
  for (const pattern of ['/companies/', '/bucket/*/']) {
    const base = pattern === '/companies/' ? '/companies' : '/bucket/a';
    const { reached, ask } = proxy({ allow: [{ path: pattern }] });
    const taken = ['/42', '/42/', '//42', '/;x/42', '/.../42'].map((rest) => `${base}${rest}`);
    for (const path of taken) assert.equal((await ask(path)).status, 200, `${pattern} ${path}`);
    for (const rest of ['', '/', '//', '/...', '/;x', '/%20', '/%3Bx', '/.../;x/']) assert.equal((await ask(`${base}${rest}`)).status, 403, `${pattern} ${base}${rest}`);
    assert.deepEqual(reached, taken.map((path) => `/v1${path}`));
  }
  const all = proxy({ paths: ['/'] });
  for (const path of ['', '/', '/a', '/a/b/c']) assert.equal((await all.ask(path)).status, 200, path);
});

test('past a prefix, `//` and a segment a server may read as none go on as on 0.15: an S3 key under a bucket\'s path', async () => {
  for (const credential of [{ paths: ['/bucket'] }, { methods: ['GET'], paths: ['/bucket'] }, { allow: [{ path: '/bucket' }] }, { allow: [{ path: '/bucket/**' }] }, { paths: ['/bucket/'] }]) {
    const { reached, ask } = proxy(credential);
    for (const path of ['/bucket/a//b', '/bucket/%20/b', '/bucket/a//', '/bucket/;x', '/bucket/...']) assert.equal((await ask(path)).status, 200, `${JSON.stringify(credential)} ${path}`);
    assert.deepEqual(reached, ['/v1/bucket/a//b', '/v1/bucket/%20/b', '/v1/bucket/a//', '/v1/bucket/;x', '/v1/bucket/...']);
  }
});

test("a legacy path takes `//`, `;x`, `%20` and `...` in its own segments, as written, as on 0.15: an S3 key prefix may hold them", async () => {
  const { reached, ask } = proxy({ paths: ['/bucket//prefix', '/b/;x', '/c/...', '/d/%20', '/e/a;v1'] });
  const taken = ['/bucket//prefix/file', '/b/;x/k', '/c/.../k', '/d/%20/k', '/e/a;v1/k'];
  for (const path of taken) assert.equal((await ask(path)).status, 200, path);
  assert.deepEqual(reached, taken.map((path) => `/v1${path}`), 'as the app wrote it');
  for (const path of ['/bucket/prefix/file', '/b/k', '/c/k', '/e/a/k']) assert.equal((await ask(path)).status, 403, path);
});

test('`*` is one non-empty segment and the pattern is matched exactly; `**`, last, is the rest, none included', async () => {
  const { ask } = proxy({ allow: [{ path: '/companies/*/documents' }, { path: '/models/**' }] });
  assert.equal((await ask('/companies/42/documents')).status, 200);
  for (const path of ['/companies/42/documents/7', '/companies/documents', '/companies/42/documents/', '/companies/4/2/documents']) assert.equal((await ask(path)).status, 403, path);
  for (const path of ['/models', '/models/', '/models/gpt', '/models/gpt/versions/1']) assert.equal((await ask(path)).status, 200, path);
  assert.equal((await ask('/modelsX')).status, 403);
});

test('a pattern is decoded once: `/a%20b` matches `/a%20b` and `/a b`, never `/a%2520b`; bytes, not text', async () => {
  const { ask } = proxy({ paths: ['/files/a%20b', '/café'] });
  assert.equal((await ask('/files/a%20b')).status, 200);
  assert.equal((await ask('/files/a b')).status, 200);
  assert.equal((await ask('/files/a%2520b')).status, 403);
  assert.equal((await ask('/caf%C3%A9')).status, 200);
  // Decomposed, an e and a combining accent: another segment, as it is to the upstream.
  assert.equal((await ask('/cafe%CC%81')).status, 403);
  assert.equal((await ask('/CAF%C3%A9')).status, 403, 'no case folding');
});

test('methods per entry: a request any entry takes goes; 405 names the methods its path takes, 403 a path none takes', async () => {
  const { ask } = proxy({ allow: [{ methods: ['POST'], path: '/chat/completions' }, { methods: ['GET'], path: '/models/**' }, { methods: [], path: '/health' }] });
  assert.equal((await ask('/chat/completions', 'POST')).status, 200);
  assert.equal((await ask('/models/gpt', 'GET')).status, 200);
  assert.equal((await ask('/health', 'DELETE')).status, 200, 'no methods: any');
  assert.deepEqual(await ask('/chat/completions', 'GET'), { status: 405, message: 'api takes POST on /chat/completions' });
  assert.deepEqual(await ask('/models/gpt', 'PUT'), { status: 405, message: 'api takes GET on /models/gpt' });
  assert.deepEqual(await ask('/users', 'GET'), { status: 403, message: 'api is not for /users' });
});

test("code's methods and paths read as one entry per path, as before 0.16: the method first, then the path", async () => {
  const { ask } = proxy({ methods: ['get'], paths: ['/companies', '/x/y'] });
  assert.equal((await ask('/companies/1')).status, 200);
  assert.equal((await ask('/x/y/z')).status, 200);
  assert.deepEqual(await ask('/companies', 'POST'), { status: 405, message: 'api takes GET' });
  assert.deepEqual(await ask('/elsewhere', 'POST'), { status: 405, message: 'api takes GET' });
  assert.deepEqual(await ask('/elsewhere'), { status: 403, message: 'api is not for /elsewhere' });
  // `methods: []`, as before, takes none.
  assert.equal((await proxy({ methods: [] }).ask('/a')).status, 405);
  // No list: everything, `//` included, which S3's keys may hold.
  assert.equal((await proxy({}).ask('/bucket//key', 'DELETE')).status, 200);
});

test('the configuration: allow or methods and paths, `**` last, whole-segment globs, a path from /; a dead legacy path warns and matches nothing, an allow pattern a server may read as another is refused', async (t) => {
  const make = (credential: Partial<Credential>) => () => proxy(credential);
  assert.throws(make({ allow: [{ path: '/a' }], methods: ['GET'] }), /api says which requests it takes in allow, or in methods and paths, not both/);
  assert.throws(make({ allow: [{ path: '/a/**/b' }] }), /\*\* stands for the rest of the path: last only/);
  assert.throws(make({ allow: [{ path: '/doc*' }] }), /\* and \*\* stand for whole segments/);
  assert.throws(make({ paths: ['companies'] }), /api's path "companies": a path starts with \//);
  assert.throws(make({ allow: [{ path: '/a', method: 'GET' } as never] }), /allow entries are \{ methods, path \}/);
  assert.throws(make({ allow: [{ methods: ['GET POST'] }] }), /methods are a list of methods/);
  assert.throws(make({ allow: [{ path: '/a' }, {}] }), /api's allow entry \{\} takes every request: give it methods or a path, or leave allow out/);
  const warned = t.mock.method(console, 'warn', () => undefined);
  const dead = proxy({ paths: ['/kyc/%2e%2e', '/ok'] });
  assert.match(String(warned.mock.calls[0]?.arguments[0]), /api's path \/kyc\/%2e%2e has "%2e%2e", a segment no request reaches the upstream with: it matches nothing/);
  assert.equal((await dead.ask('/kyc')).status, 403);
  assert.equal((await dead.ask('/ok')).status, 200);
  // An allow pattern's literal a server behind may read as another segment: refused, since a request matching it as
  // written would reach a path the list does not take. `/tenants/%2561/*` takes `/tenants/%2561/x`, `/tenants/a/x` to a
  // server that decodes twice; `/a;v1/*` takes `/a;v1/x`, `/a/x` to Tomcat; `/a%20/*` and `/a./*`, `/a/x` to Windows.
  const refusals: [string, RegExp][] = [
    ['/tenants/%2561/*', /"%2561" is still percent-encoded once decoded/],
    ['/a/%253Bx', /"%253Bx" is still percent-encoded once decoded/],
    ['/a;v1/*', /"a;v1" has ; parameters/],
    ['/a/%3Bx', /"%3Bx" has ; parameters/],
    ['/a%20/*', /"a%20" ends in a space or a dot/],
    ['/a./*', /"a\." ends in a space or a dot/],
    ['/a/...', /"\.\.\." ends in a space or a dot/],
    ['/a//b', /a segment is empty/],
    ['/kyc/%2e%2e', /"%2e%2e" decodes to a slash, a control byte or a dot segment/],
    ['/a/%2F', /"%2F" decodes to a slash/],
  ];
  for (const [path, why] of refusals) {
    assert.throws(make({ allow: [{ path }] }), why, path);
    assert.throws(make({ allow: [{ path }] }), /a server behind may read the path as another than the one matched/, path);
  }
});

test('a pattern from the Proxy tab takes no trailing slash, nor a segment a server may read as another, as code\'s allow', () => {
  assert.deepEqual(readPattern('/companies/', 'ui'), { problem: 'a path ends in no slash: /companies/** for everything below it' });
  assert.match((readPattern('/a/%2F', 'ui') as { problem: string }).problem, /"%2F" decodes to a slash/);
  assert.match((readPattern('/a//b', 'ui') as { problem: string }).problem, /a segment is empty/);
  assert.match((readPattern('/tenants/%2561/*', 'ui') as { problem: string }).problem, /still percent-encoded once decoded/);
  assert.deepEqual(readPattern('/a/*/b/**', 'ui'), { pattern: { segments: ['a', null, 'b'], tail: 'rest' } });
});

test('matching reads the request once per entry, never more than its segments', () => {
  const pattern = (path: string) => (readPattern(path, 'code') as { pattern: NonNullable<AllowEntry['path']> }).pattern;
  const entries: AllowEntry[] = ['/a/*/*/*/*/*/*/*/*/x', '/a/**', '/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/y'].map((path) => ({ methods: new Set(['POST']), path: pattern(path) }));
  const path = requestSegments(`/${'a/'.repeat(1000)}z`)!;
  let reads = 0;
  const counted = new Proxy(path, { get: (target, key, receiver) => (typeof key === 'string' && /^\d+$/.test(key) && reads++, Reflect.get(target, key, receiver)) });
  assert.equal(allows(entries, 'GET', counted), 'method');
  assert.ok(reads <= 10 + 1 + 16, `${reads} reads`);
});
