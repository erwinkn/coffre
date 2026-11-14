// `/mcp` itself on the 0.16 contract (docs/design/0.16.md, "`/mcp`"): the
// official client connects in both eras and calls the Read tools, which run
// the API's handlers as the connection and no further; the access token as
// the vault answers it; the wire's checks; the scope gate, and the vault's
// own behind it. Cases from 0.14.7's suite where they still hold.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { beforeEach, test } from 'node:test';

import { hashToken } from '@coffre/core/identity';
import { rowsOf } from '@coffre/db/dialect';
import { credential, emptyDatabase, environment, grant, identity, instance, principal, project, role, rows, secret, user, value, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';
import { z } from 'zod';

import { ApiError, UNAVAILABLE } from '../src/api/errors.ts';
import { TOOL_BY_NAME, type Tool } from '../src/mcp/tools.ts';
import { app, callRaw, calls, client, connect, envelope, fromPage, raw, RESOURCE, sent, type Result } from './mcp-fixture.ts';

const { world } = app;
const [root, dev, lead, plain] = [user('root'), user('dev'), user('lead'), user('plain')];
const VALUE = `value-${randomBytes(6).toString('hex')}`;

/**
 * market and billing, each with prod and its API_KEY. Root owns the
 * instance; dev views market/prod; lead leads billing; plain holds
 * nothing. Each has a browser session, `<name>-web`, which connects apps.
 */
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  calls.open = true;
  const [market, billing] = [project('market'), project('billing')];
  const [marketProd, billingProd] = [environment(market, 'prod'), environment(billing, 'prod')];
  const people = [root, dev, lead, plain].map((who) => [who, identity(who)] as const);
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('projects', market, billing),
    ...rows('environments', marketProd, billingProd),
    ...rows('secrets', value(world, secret(marketProd, 'API_KEY'), VALUE), value(world, secret(billingProd, 'API_KEY'), 'billing-value')),
    ...rows('roles',
      role(false, 'viewer', ['secret.read', 'secret.use'], []),
      role(false, 'lead', ['secret.read', 'secret.use', 'secret.write', 'environment.manage', 'project.manage', 'grant.manage', 'audit.read']),
      role(true, 'owner', ['secret.read', 'secret.use', 'secret.write', 'environment.manage', 'project.manage', 'grant.manage', 'audit.read']),
      role(true, 'member', [])),
    ...rows('principals', principal(root, { role: 'owner' }), principal(dev), principal(lead), principal(plain)),
    ...rows('grants', grant(dev, 'viewer', { environment: marketProd }), grant(lead, 'lead', { project: billing })),
    ...rows('identities', ...people.map(([, id]) => id)),
    ...rows('credentials', ...people.map(([who, id]) => credential(`${who.slice(5, who.indexOf('@'))}-web`, who, { kind: 'browser', identityId: id.id }))),
  );
  sent.length = 0;
  app.calls.length = 0;
});

/** What a request cost: the vault's calls and the app's statements. */
async function cost<T>(request: () => Promise<T>): Promise<[T, string[], number]> {
  app.calls.length = 0;
  const before = app.statements;
  const answer = await request();
  return [answer, [...app.calls], app.statements - before];
}

for (const mode of ['modern', 'legacy'] as const) {
  test(`the official client connects on ${mode === 'modern' ? '2026-07-28' : '2025-11-25'}, lists the Read tools and calls them as its person`, async () => {
    const mcp = await client(await connect('dev-web'), mode);
    try {
      const { tools } = await mcp.listTools();
      // A viewer's: the tools their role reaches somewhere, the one that reveals values among them, though this
      // connection holds Read alone, so that a client steps up for it; and those for the service accounts they may set up.
      assert.deepEqual(tools.map((tool) => tool.name), ['whoami', 'list_projects', 'list_secrets', 'secret_history', 'list_access', 'describe_member', 'reveal_secret_values']);
      assert.ok(tools.every((tool) => tool.annotations?.readOnlyHint === true && tool.annotations.openWorldHint === false));
      // No tool takes a value: an agent cannot supply one.
      assert.ok(tools.every((tool) => !JSON.stringify(tool.inputSchema).includes('"value"')), 'no input named value');

      const projects = (await mcp.callTool({ name: 'list_projects', arguments: {} })) as Result;
      assert.deepEqual((projects.structuredContent!.projects as { slug: string }[]).map((entry) => entry.slug), ['market'], 'only what the person reaches');
      const keys = (await mcp.callTool({ name: 'list_secrets', arguments: { environment: 'market/prod' } })) as Result;
      assert.deepEqual((keys.structuredContent!.keys as { key: string }[]).map((key) => key.key), ['API_KEY']);
      const history = (await mcp.callTool({ name: 'secret_history', arguments: { secret: 'market/prod/API_KEY' } })) as Result;
      assert.equal((history.structuredContent!.versions as unknown[]).length, 1);
      assert.ok(!JSON.stringify([keys, history]).includes(VALUE), 'never a value');

      // The API's own refusal is the tool's result, which the model reads.
      const refused = (await mcp.callTool({ name: 'list_secrets', arguments: { environment: 'billing/prod' } })) as Result;
      assert.equal(refused.isError, true);
      assert.match(refused.content[0]!.text!, /billing\/prod/);

      const whoami = (await mcp.callTool({ name: 'whoami', arguments: {} })) as Result;
      const { me, connection } = whoami.structuredContent as { me: { principal: { id: string } }; connection: { id: string; scopes: string[] } };
      assert.equal(me.principal.id, 'dev@acme.example');
      assert.deepEqual(connection.scopes, ['read']);
      const [app0] = ((await (await app.request('/api/apps', { headers: fromPage('dev-web') })).json()) as { apps: { id: string }[] }).apps;
      assert.equal(connection.id, app0!.id, 'the connection Connected apps lists');
    } finally {
      await mcp.close();
    }
    if (mode === 'modern') {
      assert.ok(sent.every((line) => line.startsWith('POST ') && line.endsWith(' 2026-07-28') && !line.includes('initialize')), sent.join('\n'));
    } else {
      assert.equal(sent[0], 'POST initialize -', sent.join('\n'));
      assert.ok(sent.slice(1).every((line) => line.endsWith(' 2025-11-25')), sent.join('\n'));
    }
  });
}

test('each request asks the vault once who its token is, and a read tool then costs what its route does, its caller shared', async () => {
  const token = await connect('dev-web');
  const [listed, listCalls, listStatements] = await cost(() => raw(token, { method: 'tools/list', params: { _meta: envelope() } }));
  assert.equal(listed.status, 200);
  assert.deepEqual([listCalls, listStatements], [['caller'], 0]);
  const [called, toolCalls, toolStatements] = await cost(() => callRaw(token, 'list_secrets', { environment: 'market/prod' }));
  assert.equal(called.body.result!.isError, undefined);
  const [, routeCalls, routeStatements] = await cost(() => app.request('/api/secrets/market/prod', { headers: fromPage('dev-web') }));
  assert.deepEqual([toolCalls, toolStatements], [routeCalls, routeStatements]);
  assert.deepEqual(toolCalls, ['caller']);
});

test('a request without an access token is told where to get one; one that does not stand is invalid_token, the vault asked only of an access token', async () => {
  const challenge = /^Bearer (error="invalid_token", error_description="[^"]+", )?resource_metadata="https:\/\/secrets\.acme\.example\/\.well-known\/oauth-protected-resource\/mcp", scope="read"$/;
  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
  const ask = (headers: Record<string, string>) => app.request('/mcp', { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body });

  const [none, noneCalls] = await cost(() => ask({}));
  assert.equal(none.status, 401);
  assert.match(none.headers.get('www-authenticate')!, challenge);
  assert.doesNotMatch(none.headers.get('www-authenticate')!, /invalid_token/);
  assert.deepEqual(noneCalls, []);

  // A session's token, a CLI's, or the connection's own refresh token: no access token's shape, and the vault is not asked.
  const [session, sessionCalls] = await cost(() => ask({ authorization: 'Bearer dev-web' }));
  assert.equal(session.status, 401);
  assert.match(session.headers.get('www-authenticate')!, /error="invalid_token"/);
  assert.deepEqual(sessionCalls, []);

  // An access token's shape the vault knows nothing of.
  const [unknown, unknownCalls] = await cost(() => ask({ authorization: `Bearer coffre_mcp_${randomBytes(32).toString('base64url')}` }));
  assert.equal(unknown.status, 401);
  assert.match(unknown.headers.get('www-authenticate')!, challenge);
  assert.deepEqual(unknownCalls, ['caller']);

  // A connection disconnected on Connected apps ends its access tokens with it.
  const token = await connect('dev-web');
  assert.equal((await ask({ authorization: `Bearer ${token}` })).status, 200);
  const [app0] = ((await (await app.request('/api/apps', { headers: fromPage('dev-web') })).json()) as { apps: { id: string }[] }).apps;
  assert.equal((await app.request(`/api/apps/${app0!.id}`, { method: 'DELETE', headers: fromPage('dev-web') })).status, 200);
  // Past what the vault remembers of who a token is, two seconds, as for any credential.
  world.memory.callers.clear();
  assert.equal((await ask({ authorization: `Bearer ${token}` })).status, 401);
});

test('an access token is good at /mcp alone, and /mcp takes no request from a web page', async () => {
  const token = await connect('dev-web');
  const api = await app.request('/api/me', { headers: { authorization: `Bearer ${token}` } });
  assert.equal(api.status, 401);
  const [fromSite, siteCalls] = await cost(() => raw(token, { method: 'tools/list', params: { _meta: envelope() } }, { origin: 'https://evil.example' }));
  assert.equal(fromSite.status, 403);
  assert.deepEqual(siteCalls, []);
  assert.equal((await app.request('/mcp', { headers: { authorization: `Bearer ${token}` } })).status, 405, 'no stream to open');
  // Where to connect, for the pages and `coffre mcp`.
  const me = (await (await app.request('/api/me', { headers: fromPage('dev-web') })).json()) as { features: { mcp: string | null } };
  assert.equal(me.features.mcp, RESOURCE);
});

test('an access token whose row the vault did not write lets nobody in', async () => {
  const token = await connect('dev-web');
  await world.owner.execute(sql`UPDATE credentials SET expires_at = expires_at + interval '1 day' WHERE token_hash = ${hashToken(token)}`);
  const response = await raw(token, { method: 'tools/list', params: { _meta: envelope() } });
  assert.equal(response.status, 401);
  assert.match(response.headers.get('www-authenticate')!, /error="invalid_token"/);
});

test('the headers must say what the body does, or -32020; an unknown revision -32022; another method 404', async () => {
  const token = await connect('dev-web');
  const code = async (response: Response) => [response.status, ((await response.json()) as { error?: { code: number } }).error?.code];
  const call = { method: 'tools/call', params: { name: 'whoami', arguments: {}, _meta: envelope() } };
  assert.deepEqual(await code(await raw(token, call, { 'mcp-name': 'whoami' })), [200, undefined]);
  assert.deepEqual(await code(await raw(token, call, { 'mcp-name': '=?base64?d2hvYW1p?=' })), [200, undefined], 'Mcp-Name in its base64 form');
  assert.deepEqual(await code(await raw(token, call, { 'mcp-name': 'list_projects' })), [400, -32020]);
  assert.deepEqual(await code(await raw(token, call, {})), [400, -32020], 'Mcp-Name is required for tools/call');
  assert.deepEqual(await code(await raw(token, call, { 'mcp-name': 'whoami', 'mcp-method': 'tools/list' })), [400, -32020]);
  assert.deepEqual(await code(await raw(token, call, { 'mcp-name': 'whoami', 'mcp-protocol-version': null })), [400, -32020]);
  const later = { method: 'server/discover', params: { _meta: { ...envelope(), 'io.modelcontextprotocol/protocolVersion': '2027-01-01' } } };
  assert.deepEqual(await code(await raw(token, later, { 'mcp-protocol-version': '2027-01-01' })), [400, -32022]);
  const noCapabilities = { method: 'server/discover', params: { _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28' } } };
  assert.deepEqual(await code(await raw(token, noCapabilities)), [400, -32602]);
  assert.deepEqual(await code(await raw(token, { method: 'resources/list', params: { _meta: envelope() } })), [404, -32601]);
  // A notification is answered with nothing.
  const note = await app.request('/mcp', { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) });
  assert.equal(note.status, 202);
  // An older client, without its version header after initialize, is refused.
  const bare = await app.request('/mcp', { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) });
  assert.equal(bare.status, 400);
});

test("a connection's calls pass its own limit; listing is not a call; a limiter that fails refuses, and the log says so", async (t) => {
  const token = await connect('dev-web');
  calls.open = false;
  const limited = await callRaw(token, 'whoami', {});
  assert.equal(limited.status, 429);
  assert.equal(limited.headers.get('retry-after'), '60');
  assert.equal((await raw(token, { method: 'tools/list', params: { _meta: envelope() } })).status, 200, 'listing is not a call');
  const report = t.mock.method(console, 'error', () => {});
  calls.open = 'broken';
  assert.equal((await callRaw(token, 'whoami', {})).status, 429);
  const [message, detail] = report.mock.calls.at(-1)!.arguments as [string, { request: string; connection: string; error: { message: string } }];
  assert.equal(message, 'mcp limiter failed');
  assert.match(detail.request, /^[0-9a-f-]{36}$/);
  assert.match(detail.error.message, /rate limiter unreachable/);
});

test("bad arguments, or a path of the wrong shape, are the tool's error, not a crash; an unknown tool is invalid params", async () => {
  const token = await connect('dev-web');
  for (const [name, args, pattern] of [
    ['list_secrets', { environment: 42 }, /environment/],
    ['list_secrets', { environment: 'market' }, /market is no project\/environment/],
    ['secret_history', { secret: 'market/prod' }, /market\/prod is no project\/environment\/KEY/],
    ['list_secrets', { environment: 'Market!/prod' }, /is not a valid project/],
  ] as const) {
    const { status, body } = await callRaw(token, name, args);
    assert.equal(status, 200);
    assert.equal(body.result!.isError, true, JSON.stringify(args));
    assert.match(body.result!.content[0]!.text!, pattern);
  }
  const unknown = await callRaw(token, 'drop_everything', {});
  assert.equal(unknown.body.error!.code, -32602);
});

test("a tool beyond the connection's scopes answers 403 insufficient_scope, naming what it holds and lacks, and the vault refuses a value all the same", async () => {
  const token = await connect('dev-web');
  // A tool of the test's own that claims Read and reveals: the vault holds the use to Reveal values whatever the tool says.
  const sneaky: Tool = {
    name: 'test_sneaky', title: 'sneaky', description: 'sneaky', scope: 'read', needs: 'anyone', readOnly: true, idempotent: true, destructive: false,
    input: z.object({}).strict(), output: { type: 'object' },
    run: async ({ ctx }) => ({ structured: await (await import('../src/api/router.ts')).runRoute('POST /reveals', {}, { path: 'market/prod' }, ctx) }),
  };
  TOOL_BY_NAME.set('test_sneaky', sneaky);
  try {
    for (const name of ['reveal_secret_values', 'test_sneaky']) {
      const [response, asked] = await cost(() => raw(token, { method: 'tools/call', params: { name, arguments: name === 'test_sneaky' ? {} : { path: 'market/prod' }, _meta: envelope() } }, { 'mcp-name': name }));
      assert.equal(response.status, 403, name);
      // The endpoint asks for the scope a tool names before running it; the vault refuses the one that claims less.
      assert.deepEqual(asked, name === 'test_sneaky' ? ['caller', 'use'] : ['caller'], name);
      assert.match(response.headers.get('www-authenticate') ?? '', /^Bearer error="insufficient_scope", scope="read reveal", resource_metadata="https:\/\/secrets\.acme\.example\/\.well-known\/oauth-protected-resource\/mcp"/, name);
      // For a client that does not step up, as Claude Desktop did not: the tool's result, which the model reads.
      const { result } = (await response.json()) as { result: Result };
      assert.equal(result.isError, true, name);
      assert.match(result.content[0]!.text!, new RegExp(`^${name} needs coffre's Reveal values scope, which this connection was not given\\. Nothing was done\\.`), name);
      assert.ok(!JSON.stringify(result).includes(VALUE));
    }
    // The official client reads the challenge, not the body: with an auth provider, it would step up to these scopes.
    const official = await client(token, 'modern');
    try {
      await assert.rejects(official.callTool({ name: 'reveal_secret_values', arguments: { path: 'market/prod' } }), { name: 'InsufficientScopeError', message: /"read reveal"/ });
    } finally {
      await official.close();
    }
  } finally {
    TOOL_BY_NAME.delete('test_sneaky');
  }
});

test("a fault in a tool is JSON-RPC's internal error, with the details in the server log alone; a refusal is the tool's", async (t) => {
  const token = await connect('dev-web');
  const report = t.mock.method(console, 'error', () => {});
  const throwing = (name: string, error: Error): Tool => ({
    name, title: name, description: name, scope: 'read', needs: 'anyone', readOnly: true, idempotent: true, destructive: false,
    input: z.object({}).strict(), output: { type: 'object' },
    run: async () => {
      throw error;
    },
  });
  // A connection lost mid-call, as node-postgres throws it: what the API answers 503 `unavailable`.
  const lost = Object.assign(new Error('terminating connection due to administrator command'), { code: '08006' });
  const tools = {
    test_tampered: new ApiError('tampered', 'a row of market/prod failed'),
    test_bug: new Error('market/prod exploded'),
    test_refused: new ApiError('conflict', 'not now'),
    test_outage: lost,
  };
  for (const [name, error] of Object.entries(tools)) TOOL_BY_NAME.set(name, throwing(name, error));
  try {
    for (const name of ['test_tampered', 'test_bug']) {
      const { status, body } = await callRaw(token, name, {});
      assert.deepEqual([status, body.error?.code, body.error?.message], [500, -32603, 'Internal error: see the server log'], name);
    }
    assert.equal(report.mock.callCount(), 2);
    const refused = await callRaw(token, 'test_refused', {});
    assert.deepEqual([refused.status, refused.body.result!.isError, refused.body.result!.content[0]!.text], [200, true, 'not now']);
    // An outage is no fault of coffre's: the tool's error, to try again in a moment, as v0.14.7 answered it.
    const outage = await callRaw(token, 'test_outage', {});
    assert.deepEqual([outage.status, outage.body.result!.isError, outage.body.result!.content[0]!.text], [200, true, UNAVAILABLE]);
  } finally {
    for (const name of Object.keys(tools)) TOOL_BY_NAME.delete(name);
  }
});

test('values reach the model only with Reveal values, with a warning first, in one use', async () => {
  const token = await connect('dev-web', 'read reveal');
  const [revealed, used] = await cost(() => callRaw(token, 'reveal_secret_values', { path: 'market/prod' }));
  assert.deepEqual(revealed.body.result!.structuredContent!.values, { API_KEY: VALUE });
  assert.match(revealed.body.result!.content[0]!.text!, /^These values are now part of this conversation and its history\./);
  assert.deepEqual(used, ['caller', 'use']);
  // The vault logs the read as any, on the access token (packages/vault/test/mcp.test.ts).
  // One key, and one the person may not read: the API's refusal, and no value.
  assert.deepEqual((await callRaw(token, 'reveal_secret_values', { path: 'market/prod/API_KEY' })).body.result!.structuredContent!.values, { API_KEY: VALUE });
  const refused = await callRaw(token, 'reveal_secret_values', { path: 'billing/prod' });
  assert.equal(refused.body.result!.isError, true);
  assert.ok(!JSON.stringify(refused.body).includes('billing-value'));
});

/** A person's tool list, as each era asks for it: the names, and the cache hints a 2026-07-28 answer carries. */
async function listFor(token: string): Promise<{ names: string[]; legacy: string[]; ttlMs: unknown; cacheScope: unknown }> {
  const modern = (await (await raw(token, { method: 'tools/list', params: { _meta: envelope() } })).json()) as { result: { tools: { name: string }[]; ttlMs: unknown; cacheScope: unknown } };
  const legacy = (await (await raw(token, { method: 'tools/list' }, { 'mcp-protocol-version': '2025-11-25', 'mcp-method': null })).json()) as { result: { tools: { name: string }[] } };
  return { names: modern.result.tools.map((tool) => tool.name), legacy: legacy.result.tools.map((tool) => tool.name), ttlMs: modern.result.ttlMs, cacheScope: modern.result.cacheScope };
}

const ANYONE = ['whoami', 'list_projects'];
const READS = ['list_secrets', 'secret_history', 'reveal_secret_values'];
const SERVICES = ['list_access', 'describe_member'];
const sorted = (...names: string[][]) => names.flat().sort();

test("each person's tools/list is what their roles reach somewhere, whatever the connection's scopes, cached for them alone, a few minutes", async () => {
  const viewer = await listFor(await connect('dev-web'));
  assert.deepEqual(viewer.names.sort(), sorted(ANYONE, READS, SERVICES));
  assert.deepEqual(viewer.legacy.sort(), viewer.names, 'the same in either era');
  assert.deepEqual([viewer.ttlMs, viewer.cacheScope], [300_000, 'private']);
  // Nothing held: who they are, and the projects they see, none.
  assert.deepEqual((await listFor(await connect('plain-web'))).names.sort(), sorted(ANYONE));
  // A project's lead, and the instance's Owner: every tool.
  assert.deepEqual((await listFor(await connect('lead-web'))).names.sort(), sorted(ANYONE, READS, SERVICES));
  assert.deepEqual((await listFor(await connect('root-web', 'read'))).names, [...TOOL_BY_NAME.keys()]);
});

test("a role granted shows in the person's next list, and one taken is gone from it; a tool they cannot see, called by name, is refused as ever", async () => {
  const token = await connect('plain-web');
  assert.deepEqual((await listFor(token)).names.sort(), sorted(ANYONE));
  const [market] = await rowsOf<{ id: string }>(world.owner, sql`SELECT id::text FROM projects WHERE slug = 'market'`);
  await write(world, ...rows('grants', grant(plain, 'viewer', { project: { id: market!.id } })));
  world.memory.callers.clear();
  assert.deepEqual((await listFor(token)).names.sort(), sorted(ANYONE, READS, SERVICES));

  // Hidden from the list, not a lock: the call is the API's to refuse.
  const { status, body } = await callRaw(await connect('dev-web'), 'describe_member', { member: root });
  assert.equal(status, 200);
  assert.equal(body.result!.isError, true);
});
