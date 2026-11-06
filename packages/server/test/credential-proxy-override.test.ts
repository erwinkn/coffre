// T189: a method override in a header or the query never takes a request past its allow list. Many upstreams act on
// a POST that says `X-HTTP-Method-Override: DELETE`, or `?_method=DELETE`, as on a DELETE (Rails, Laravel and Symfony,
// Spring, Express's method-override, Google's and Azure's APIs), so an allow list that takes POST and not DELETE
// refuses such a POST; one whose override it takes goes on as it came. A `_method` in a body is not read (D179): the
// last test pins that, so that a change to it is deliberate. Each through the plugin's route with a fake coffre and an
// egress for the upstream, as credential-proxy-scope.test.ts: no database, what is checked is the plugin's own work,
// before anything opens.
import assert from 'node:assert/strict';
import test from 'node:test';

import { bodyDigest, contentDigest } from '@coffre/client/dpop';

import type { PluginContext, UseAsked, WorkloadUse } from '../src/plugins.ts';
import { credentialProxy, header, type Credential } from '../src/plugins/credential-proxy.ts';

const PUBLIC = 'https://coffre.example';
const HANDLE = `coffre_use_${'h'.repeat(43)}`;
const SESSION = `coffre_wl_${'w'.repeat(43)}`;
const LATER = new Date(Date.now() + 3_600_000).toISOString();
const SECRET = 'sk_live_0123456789abcdef';

/** coffre, as a plugin sees it: the handle, or a workload's session narrowed to `constraints` (its proof signing `hdr`), stands for `market/dev`. */
function fake(opened: string[], constraints: WorkloadUse['constraints'] = null, hdr = ['content-type', 'x-http-method-override']): PluginContext {
  const workload = { path: 'market/dev', place: 'market/dev', places: ['market/dev'], nonce: null, constraints, hdr, credentialId: 'c', principal: 'service:api' };
  return {
    publicUrl: PUBLIC,
    workload: async (request: Request) => (request.headers.get('authorization')?.startsWith('DPoP ') ? workload : null),
    handle: async () => ({ expiresAt: LATER, paths: ['market/dev'] }),
    use: async (_handle: unknown, asked: UseAsked) => {
      opened.push(...(asked.keys as readonly string[]));
      return { values: { KEY: SECRET }, plain: [], keys: asked.keys, environment: { path: 'market/dev', personal: false }, expiresAt: LATER };
    },
  } as unknown as PluginContext;
}

/** A proxy of one credential, `api`, at https://api.example/v1: what reached its upstream, and how many times values opened. */
function proxy(credential: Partial<Credential>, constraints: WorkloadUse['constraints'] = null, hdr?: string[]) {
  const reached: { method: string; url: URL; headers: Headers; body: string }[] = [];
  const opened: string[] = [];
  const egress = { fetch: async (url: URL, init: RequestInit) => {
    reached.push({ method: init.method!, url, headers: new Headers(init.headers), body: init.body == null ? '' : await new Response(init.body).text() });
    return new Response('ok');
  } };
  const plugin = credentialProxy({ cacheSeconds: 0, credentials: { api: { upstream: 'https://api.example/v1', inject: header('x-api-key', '{KEY}'), egress, ...credential } } });
  const coffre = fake(opened, constraints, hdr);
  const ask = async (path: string, init: RequestInit & { as?: 'handle' | 'workload' } = {}) => {
    const headers = new Headers(init.headers);
    if (init.as === 'workload') headers.set('authorization', `DPoP ${SESSION}`);
    else headers.set('x-coffre-handle', HANDLE);
    const answer = await plugin.routes!.fetch(new Request(`${PUBLIC}/use${path}`, { ...init, headers }), coffre);
    return { status: answer.status, body: await answer.text() };
  };
  return { reached, opened, ask };
}

const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
const JSON_TYPE = { 'content-type': 'application/json' };

/** A multipart body of `parts`, each a Content-Disposition's parameters and the part's value. */
function multipart(parts: [disposition: string, value: string][]): { headers: Record<string, string>; body: string } {
  const boundary = 'b0undary';
  const body = `${parts.map(([disposition, value]) => `--${boundary}\r\nContent-Disposition: form-data; ${disposition}\r\n\r\n${value}\r\n`).join('')}--${boundary}--\r\n`;
  return { headers: { 'content-type': `multipart/form-data; boundary=${boundary}` }, body };
}

test('a request whose override asks for a method the allow list does not take on its path is refused, 405, before anything opens, however it asks', async () => {
  const { reached, opened, ask } = proxy({ allow: [{ methods: ['GET', 'POST'], path: '/items/**' }, { methods: ['DELETE'], path: '/trash/**' }] });
  const asks: [string, RequestInit][] = [
    // Each header, in any case, a list's each, and as a CGI-style server reads one written with `_` or, PHP, `.`.
    ['/items/1', { headers: { 'x-http-method-override': 'DELETE' } }],
    ['/items/1', { headers: { 'X.HTTP.Method.Override': 'DELETE' } }],
    ['/items/1', { headers: { 'X-HTTP-Method': 'delete' } }],
    ['/items/1', { headers: { 'x-method-override': ' Delete ' } }],
    ['/items/1', { headers: { x_http_method_override: 'DELETE' } }],
    ['/items/1', { headers: { 'x-http-method-override': 'GET, DELETE' } }],
    ['/items/1', { headers: { 'x-http-method-override': 'PATCH' } }],
    // A name no entry's methods hold.
    ['/items/1', { headers: { 'x-http-method-override': 'PURGE' } }],
    // The query, as each framework reads a name: PHP's `.` and `[`, Rack's `;`, encoded, upper case.
    ['/items/1?_method=DELETE', {}],
    ['/items/1?_METHOD=delete', {}],
    ['/items/1?.method=DELETE', {}],
    ['/items/1?%20_method=DELETE', {}],
    ['/items/1?_method[]=DELETE', {}],
    ['/items/1?_method%00x=DELETE', {}],
    ['/items/1?a=1;_method=DELETE', {}],
    ['/items/1?%5Fmethod=DELETE', {}],
    ['/items/1?_method=DEL%45TE', {}],
    ['/items/1?_method%20=DELETE', {}],
    // ServiceStack and ASP.NET MVC read an override header's name from a query too; ASP.NET decodes `%uXXXX`.
    ['/items/1?X-HTTP-Method-Override=DELETE', {}],
    ['/items/1?%u0058-HTTP-Method-Override=DELETE', {}],
    ['/items/1?%u005Fmethod=DELETE', {}],
    ['/items/1?_method=%u0044ELETE', {}],
    // DELETE is the list's on /trash alone, never on /items.
    ['/items/1', { headers: { 'x-http-method-override': 'DELETE' }, body: '' }],
  ];
  for (const [path, init] of asks) {
    const answer = await ask(`/market/dev/api${path}`, { method: 'POST', ...init });
    assert.equal(answer.status, 405, `${path} ${JSON.stringify(init)}: ${answer.body}`);
    assert.match(answer.body, /api does not take [^ ]+ on \/items\/1, which this request asks for in (its [^ ]+ header|a method query parameter): an upstream may act on it as that method/);
  }
  const said = await ask('/market/dev/api/items/1', { method: 'POST', headers: { 'x-http-method-override': 'delete' } });
  assert.match(said.body, /api does not take DELETE on \/items\/1, which this request asks for in its x-http-method-override header/);
  // On a GET too: coffre does not guess which of its methods an upstream lets an override replace.
  assert.equal((await ask('/market/dev/api/items/1?_method=DELETE')).status, 405);
  assert.equal(reached.length, 0);
  assert.deepEqual(opened, [], 'refused before any value opens');
});

test('an override the allow list takes goes on as it came; nothing is looked for where the list takes any method on the path, or there is no list', async () => {
  const { reached, ask } = proxy({ allow: [{ methods: ['GET', 'POST', 'PATCH'], path: '/items/**' }, { path: '/open/**' }] });
  // Google's PATCH through a POST, and a GET named as itself.
  assert.equal((await ask('/market/dev/api/items/1', { method: 'POST', headers: { 'x-http-method-override': 'PATCH' } })).status, 200);
  assert.equal(reached.at(-1)!.headers.get('x-http-method-override'), 'PATCH');
  assert.equal((await ask('/market/dev/api/items/1?_method=PATCH', { method: 'POST', headers: { 'x-method-override': 'get' } })).status, 200);
  assert.equal(reached.at(-1)!.url.search, '?_method=PATCH');
  // An entry of any method on the path: an override of any.
  assert.equal((await ask('/market/dev/api/open/1?_method=DELETE', { method: 'POST', headers: { 'x-http-method-override': 'DELETE' } })).status, 200);
  // An empty override names no method: the request's own stands, as Express's method-override leaves it.
  for (const path of ['/items/1?_method=', '/items/1?_method=+', '/items/1?X-HTTP-Method-Override=&_method']) {
    assert.equal((await ask(`/market/dev/api${path}`, { method: 'POST', headers: { 'x-http-method-override': '' } })).status, 200, path);
    assert.equal(reached.at(-1)!.url.search, path.slice('/items/1'.length));
  }
  const unlisted = proxy({});
  assert.equal((await unlisted.ask('/market/dev/api/x?_method=DELETE', { method: 'POST', headers: { 'x-http-method-override': 'DELETE' } })).status, 200);
  assert.equal(unlisted.reached.length, 1);
});

test('what is no override goes on: a parameter named otherwise, a JSON-RPC method', async () => {
  const { reached, ask } = proxy({ allow: [{ methods: ['POST', 'PUT'], path: '/rpc/**' }] });
  const asks: [string, RequestInit][] = [
    ['/rpc/1?method=getMe', { method: 'POST' }],
    ['/rpc/1?methods=x&my_method=DELETE&_methodx=DELETE', { method: 'POST' }],
    ['/rpc/1', { method: 'POST', headers: { ...JSON_TYPE, 'x-method': 'DELETE' }, body: '{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1}' }],
  ];
  for (const [path, init] of asks) assert.equal((await ask(`/market/dev/api${path}`, init)).status, 200, `${path} ${JSON.stringify(init)}`);
  assert.equal(reached.length, asks.length);
});

test('a query name of a long run of spaces is read in linear time, before a handle is checked', async () => {
  const { ask } = proxy({ allow: [{ methods: ['POST'], path: '/items/**' }] });
  // Trimming such a name with a regular expression retried the run from each of its spaces: 14,000 took 180 ms.
  const started = performance.now();
  const answer = await ask(`/market/dev/api/items/1?x${'+'.repeat(200_000)}z=method`, { method: 'POST' });
  assert.equal(answer.status, 200, answer.body);
  assert.ok(performance.now() - started < 1_000, `${Math.round(performance.now() - started)} ms`);
});

test('a POST that streams, its digest declared, is refused for its override header before its body is read, and streams as before without one', async () => {
  const { reached, ask } = proxy({ allow: [{ methods: ['POST'], path: '/items/**' }] });
  const body = JSON.stringify({ text: 'x'.repeat(100_000) });
  const streaming = async (extra: Record<string, string> = {}) => ({
    method: 'POST', body, headers: { ...JSON_TYPE, ...extra, 'content-length': String(Buffer.byteLength(body)), 'content-digest': contentDigest(await bodyDigest(body)) },
  });
  const refused = await ask('/market/dev/api/items/1', await streaming({ 'x-http-method-override': 'DELETE' }));
  assert.equal(refused.status, 405, refused.body);
  assert.equal((await ask('/market/dev/api/items/1', await streaming())).status, 200);
  assert.equal(reached.length, 1);
  assert.equal(reached[0]!.body, body);
});

test("a narrowed session's methods hold an override too, with no allow list; a workload's is read from what goes upstream", async () => {
  const { reached, opened, ask } = proxy({}, { methods: ['POST'] });
  const refusals: [string, RequestInit][] = [
    ['/items/1', { headers: { 'x-http-method-override': 'DELETE' } }],
    ['/items/1?_method=DELETE', {}],
    ['/items/1?%u0058-HTTP-Method-Override=DELETE', {}],
  ];
  for (const [path, init] of refusals) {
    const answer = await ask(`/market/dev/api${path}`, { method: 'POST', as: 'workload', ...init });
    assert.equal(answer.status, 403, `${path}: ${answer.body}`);
    assert.match(answer.body, /this narrowed session may not DELETE \/items\/1 through api, which this request asks for in/);
    assert.match(answer.body, /narrowed/);
  }
  const through = await ask('/market/dev/api/items/1', { method: 'POST', as: 'workload', headers: { 'x-http-method-override': 'POST' } });
  assert.equal(through.status, 200, through.body);
  assert.equal(reached.length, 1);
  assert.deepEqual(opened, ['KEY'], 'the one request let through opened its values; the refusals, none');
  // Through the allow list, for a workload as for a handle.
  const listed = proxy({ allow: [{ methods: ['POST'], path: '/**' }] });
  assert.equal((await listed.ask('/market/dev/api/items/1', { method: 'POST', as: 'workload', headers: { 'x-http-method-override': 'DELETE' } })).status, 405);
  assert.deepEqual(listed.opened, []);
  // An override header its proof does not sign never gets there: nothing to refuse.
  const unsigned = proxy({ allow: [{ methods: ['POST'], path: '/**' }] }, null, ['content-type']);
  assert.equal((await unsigned.ask('/market/dev/api/items/1', { method: 'POST', as: 'workload', headers: { 'x-method-override': 'DELETE' } })).status, 200);
  assert.equal(unsigned.reached[0]!.headers.get('x-method-override'), null);
});

// ASP.NET Core's middleware sets `Request.Method` to the override as it came, and its routing reads `pAtCh` as PATCH:
// coffre holds that spelling as it would a request's own method, which a list or session taking `PATCH` does not take
// (review r4 of #526). `delete` is DELETE either way, as fetch reads one.
test('an override is held as it came as well as uppercased: a session or list taking PATCH takes no pAtCh', async () => {
  const session = proxy({}, { methods: ['POST', 'PATCH'] });
  const narrowed = await session.ask('/market/dev/api/items/1', { method: 'POST', as: 'workload', headers: { 'x-http-method-override': 'pAtCh' } });
  assert.equal(narrowed.status, 403, narrowed.body);
  assert.match(narrowed.body, /may not pAtCh \/items\/1/);
  assert.deepEqual(session.opened, []);
  assert.equal((await session.ask('/market/dev/api/items/1', { method: 'POST', as: 'workload', headers: { 'x-http-method-override': 'PATCH' } })).status, 200);
  const listed = proxy({ allow: [{ methods: ['POST', 'PATCH', 'DELETE'], path: '/items/**' }] });
  const refused = await listed.ask('/market/dev/api/items/1', { method: 'POST', headers: { 'x-http-method-override': 'pAtCh' } });
  assert.equal(refused.status, 405, refused.body);
  assert.match(refused.body, /does not take pAtCh/);
  for (const each of ['PATCH', 'delete']) {
    assert.equal((await listed.ask('/market/dev/api/items/1', { method: 'POST', headers: { 'x-http-method-override': each } })).status, 200, each);
  }
  assert.equal(listed.reached.length, 2);
  assert.deepEqual(listed.reached.map((each) => each.headers.get('x-http-method-override')), ['PATCH', 'delete'], 'what goes on goes as it came');
});

// ASP.NET MVC and ServiceStack read `?X-HTTP-Method-Override=` as they read the header, its case kept (review r5 of
// #526), and Hono's method-override middleware reissues `?_method=pAtCh` as `pAtCh` (review r6): every override in a
// query is held as it came as well as uppercased, whatever its name. So a list taking PATCH refuses Rails' lowercase
// `_method=patch` too, where an upstream that uppercases would have taken it: `PATCH` is what to send.
test('an override in a query is held as it came as well as uppercased, whatever its name', async () => {
  const session = proxy({}, { methods: ['POST', 'PATCH'] });
  for (const query of ['X-HTTP-Method-Override=pAtCh', '_method=pAtCh']) {
    const narrowed = await session.ask(`/market/dev/api/items/1?${query}`, { method: 'POST', as: 'workload' });
    assert.equal(narrowed.status, 403, `${query}: ${narrowed.body}`);
    assert.match(narrowed.body, /may not pAtCh \/items\/1/);
  }
  assert.deepEqual(session.opened, []);
  assert.equal((await session.ask('/market/dev/api/items/1?_method=PATCH', { method: 'POST', as: 'workload' })).status, 200);
  const listed = proxy({ allow: [{ methods: ['POST', 'PATCH', 'DELETE'], path: '/items/**' }] });
  for (const query of ['X-HTTP-Method-Override=pAtCh', 'x_http_method=pAtCh', 'X-Method-Override=pAtCh', '_method=pAtCh', '_method=patch', '_me%74hod=Patch']) {
    const refused = await listed.ask(`/market/dev/api/items/1?${query}`, { method: 'POST' });
    assert.equal(refused.status, 405, `${query}: ${refused.body}`);
    assert.match(refused.body, /does not take (pAtCh|patch|Patch)/);
  }
  assert.deepEqual(listed.opened, []);
  // `delete` is DELETE either way, as fetch reads a request's own `delete`.
  for (const query of ['X-HTTP-Method-Override=PATCH', '_method=PATCH', '_method=delete']) {
    assert.equal((await listed.ask(`/market/dev/api/items/1?${query}`, { method: 'POST' })).status, 200, query);
  }
  assert.deepEqual(listed.reached.map((each) => each.url.search), ['?X-HTTP-Method-Override=PATCH', '?_method=PATCH', '?_method=delete']);
});

// D179 (Erwin's choice): coffre reads no body for an override. A `_method` field of a POST's form, multipart or JSON
// body, which Rails, Laravel and Spring honour, goes on through a list that takes POST alone, as it came
// (docs/design/credential-proxy.md, section 3, `allow`). Should coffre ever read bodies for one, this test changes
// with it, on purpose.
test('a _method field in a body is not read: it goes on as it came, even where the list does not take the method it names', async () => {
  const { reached, opened, ask } = proxy({ allow: [{ methods: ['POST'], path: '/items/**' }] });
  const bodies: RequestInit[] = [
    { headers: FORM, body: 'name=x&_method=DELETE' },
    multipart([['name="_method"', 'DELETE']]),
    { headers: JSON_TYPE, body: '{"_method":"DELETE"}' },
  ];
  for (const init of bodies) {
    const answer = await ask('/market/dev/api/items/1', { method: 'POST', ...init });
    assert.equal(answer.status, 200, `${JSON.stringify(init)}: ${answer.body}`);
    assert.equal(reached.at(-1)!.method, 'POST');
    assert.equal(reached.at(-1)!.body, init.body);
  }
  assert.equal(reached.length, bodies.length);
  assert.equal(opened.length, bodies.length);
});
