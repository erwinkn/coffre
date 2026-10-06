// `/mcp` itself (docs/design/mcp.md, sections 2, 5 and 6): the official
// client connects in both eras and calls the Read tools, which act as
// their person and no further; the wire's checks, the scope gates in the
// endpoint and in the API, and every call's entry in the log.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { z } from 'zod';

import { serveApi } from '../src/api/router.ts';
import { decodeHeaderValue } from '../src/mcp/endpoint.ts';
import { TOOL_BY_NAME, type Tool } from '../src/mcp/tools.ts';
import { clientFor, contextFor } from './api-fixture.ts';
import { auditLog } from './db/tables.ts';
import { callRaw, calls, CLAUDE_CODE, client, connect, db, deps, DEV, entries, envelope, ORIGIN, raw, type Result, ROOT, route, sent, useMcp } from './mcp-fixture.ts';

useMcp(async () => {
  const root = clientFor(deps, ROOT);
  await root.members.add(`user:${DEV}`);
  for (const project of ['market', 'billing']) {
    await root.projects.create(project, { name: project });
    await root.environments.create(`${project}/prod`, { name: 'Production' });
    await root.secrets.set(`${project}/prod`, { API_KEY: `value-${randomBytes(6).toString('hex')}` });
  }
  await root.access.set(`user:${DEV}`, { 'market/prod': 'viewer' });
});

for (const mode of ['modern', 'legacy'] as const) {
  test(`the official client connects on ${mode === 'modern' ? '2026-07-28' : '2025-11-25'}, lists the Read tools and calls them as its person`, async () => {
    sent.length = 0;
    const mcp = await client(await connect(), mode);
    try {
      const { tools } = await mcp.listTools();
      // A viewer's: the tools their role reaches somewhere, the one that reveals values among them, though
      // this connection holds Read alone, so that a client steps up for it. Not the access or the log's,
      // which no role of theirs reaches.
      const readTools = ['whoami', 'list_projects', 'list_secrets', 'secret_history', 'show_secret_value', 'reveal_secret_values'];
      assert.deepEqual(tools.map((tool) => tool.name), readTools);
      assert.ok(tools.every((tool) => tool.annotations?.readOnlyHint === true));
      assert.ok(tools.every((tool) => tool.annotations?.openWorldHint === false));
      // No tool takes a value: an agent cannot supply one.
      assert.ok(tools.every((tool) => !JSON.stringify(tool.inputSchema).includes('"value"')), 'no input named value');

      const projects = (await mcp.callTool({ name: 'list_projects', arguments: {} })) as Result;
      assert.deepEqual((projects.structuredContent!.projects as { slug: string }[]).map((project) => project.slug), ['market'], 'only what the person reaches');
      const keys = (await mcp.callTool({ name: 'list_secrets', arguments: { environment: 'market/prod' } })) as Result;
      assert.deepEqual((keys.structuredContent!.keys as { key: string }[]).map((key) => key.key), ['API_KEY']);
      assert.ok(!JSON.stringify(keys).includes('value-'), 'never a value');

      // The API's own refusal is the tool's result, which the model reads.
      const refused = (await mcp.callTool({ name: 'list_secrets', arguments: { environment: 'billing/prod' } })) as Result;
      assert.equal(refused.isError, true);
      assert.match(refused.content[0]!.text!, /billing/);

      const whoami = (await mcp.callTool({ name: 'whoami', arguments: {} })) as Result;
      assert.deepEqual(whoami.structuredContent!.connection, { client: 'Claude Code', scopes: ['read'] });
    } finally {
      await mcp.close();
    }
    if (mode === 'modern') {
      assert.ok(sent.every((line) => line.startsWith('POST ') && line.endsWith(' 2026-07-28') && !line.includes('initialize')), sent.join('\n'));
    } else {
      assert.equal(sent[0], 'POST initialize -', sent.join('\n'));
      assert.ok(sent.slice(1).every((line) => line.endsWith(' 2025-11-25')), sent.join('\n'));
    }
    // Each call in the log, under the client: the reads as detail, the refusal shown, and the API's own entries name the connection.
    const reads = await entries('mcp.read');
    assert.deepEqual(reads.map((entry) => entry.metadata.tool), ['list_projects', 'list_secrets', 'whoami']);
    assert.ok(reads.every((entry) => entry.actor === `user:${DEV}` && (entry.metadata.via as { clientName: string }).clientName === 'Claude Code'));
    const refusal = await entries('mcp.call');
    assert.deepEqual(refusal.map((entry) => [entry.decision, entry.metadata.tool, entry.metadata.names]), [['deny', 'list_secrets', ['billing/prod']]]);
    // The API's own entry for that refusal names the connection too, as every entry a call writes does.
    const connection = (refusal[0]!.metadata.via as { connectionId: string }).connectionId;
    const all = (await db.owner.select().from(auditLog).orderBy(auditLog.seq)).map((row) => ({ action: row.action, metadata: JSON.parse(row.metadata) as Record<string, unknown> }));
    const api = all.filter((entry) => !entry.action.startsWith('mcp.') && entry.metadata.credentialId === connection);
    assert.ok(api.length > 0, 'the API wrote no entry naming the connection');
    assert.ok(api.every((entry) => (entry.metadata.via as { clientName: string }).clientName === 'Claude Code'), JSON.stringify(api));
  });
}

test('a tool beyond the API scope table is refused by the API itself, whatever the person may do', async () => {
  // The root admin may reveal; a connection with only Read may not, even if a tool asked.
  const ctx = { ...(await contextFor(deps, ROOT)), via: { connectionId: randomUUID(), clientId: CLAUDE_CODE, clientName: 'Claude Code', scopes: ['read'] as const } };
  const reveal = await serveApi(new Request(`${ORIGIN}/api/reveals`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ path: 'market/prod' }) }), ctx);
  assert.equal(reveal.status, 403);
  assert.equal(((await reveal.json()) as { error: string }).error, 'insufficient_scope');
  const sessions = await serveApi(new Request(`${ORIGIN}/api/sessions`), ctx);
  assert.equal(sessions.status, 403, 'nor a person-only route, whatever the scopes');
  const listed = await serveApi(new Request(`${ORIGIN}/api/projects`), ctx);
  assert.equal(listed.status, 200);
});

test('the headers must say what the body does, or -32020; an unknown revision -32022; another method 404', async () => {
  const token = await connect();
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
  const note = await route('/mcp', { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) });
  assert.equal(note.status, 202);
  // An older client, without its version header after initialize, is refused.
  const bare = await route('/mcp', { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) });
  assert.equal(bare.status, 400);
  assert.equal(decodeHeaderValue('=?base64?w6l0w6k=?='), 'été');
  assert.equal(decodeHeaderValue('café'), null, 'a raw non-ASCII value is no header value');
});

test("a connection's calls pass its own limit", async () => {
  const token = await connect();
  calls.open = false;
  const limited = await raw(token, { method: 'tools/call', params: { name: 'whoami', arguments: {}, _meta: envelope() } }, { 'mcp-name': 'whoami' });
  assert.equal(limited.status, 429);
  assert.equal(limited.headers.get('retry-after'), '60');
  assert.equal((await raw(token, { method: 'tools/list', params: { _meta: envelope() } })).status, 200, 'listing is not a call');
});

test("a connection's limiter that fails refuses the call, and the log says so with the request's id", async (t) => {
  const token = await connect();
  const report = t.mock.method(console, 'error', () => {});
  calls.open = 'broken';
  const refused = await raw(token, { method: 'tools/call', params: { name: 'whoami', arguments: {}, _meta: envelope() } }, { 'mcp-name': 'whoami' });
  assert.equal(refused.status, 429);
  const [message, detail] = report.mock.calls.at(-1)!.arguments as [string, { requestId: string; connectionId: string; error: { message: string } }];
  assert.equal(message, 'mcp limiter failed');
  assert.match(detail.requestId, /^[0-9a-f-]{36}$/);
  assert.match(detail.error.message, /rate limiter unreachable/);
});

test("bad arguments are the tool's error, not a crash; an unknown tool is invalid params", async () => {
  const token = await connect();
  const bad = await raw(token, { method: 'tools/call', params: { name: 'list_secrets', arguments: { environment: 42 }, _meta: envelope() } }, { 'mcp-name': 'list_secrets' });
  const body = (await bad.json()) as { result: Result };
  assert.equal(body.result.isError, true);
  assert.match(body.result.content[0]!.text!, /environment/);
  const unknown = await raw(token, { method: 'tools/call', params: { name: 'drop_everything', arguments: {}, _meta: envelope() } }, { 'mcp-name': 'drop_everything' });
  assert.equal(((await unknown.json()) as { error: { code: number } }).error.code, -32602);
});

test("a tool beyond the connection's scopes answers 403 insufficient_scope, naming what it holds and lacks, and says in plain words how to grant it; so does one whose API call is", async () => {
  const token = await connect();
  // Tools of the tests' own: one that declares a scope Read lacks, one that claims Read and reaches past it.
  const reveal = (name: string, scope: Tool['scope']): Tool => ({
    name, title: name, description: name, scope, needs: 'anyone', readOnly: true, idempotent: true, destructive: false,
    input: z.object({}).strict(), output: { type: 'object' }, names: () => ['market/prod'],
    run: async ({ api }) => ({ structured: await api.secrets.reveal('market/prod') }),
  });
  TOOL_BY_NAME.set('test_reveal', reveal('test_reveal', 'reveal'));
  TOOL_BY_NAME.set('test_sneaky', reveal('test_sneaky', 'read'));
  try {
    for (const name of ['test_reveal', 'test_sneaky']) {
      const response = await raw(token, { method: 'tools/call', params: { name, arguments: {}, _meta: envelope() } }, { 'mcp-name': name });
      assert.equal(response.status, 403, name);
      const challenge = response.headers.get('www-authenticate') ?? '';
      assert.match(challenge, /^Bearer error="insufficient_scope", scope="read reveal", resource_metadata="https:\/\/secrets\.acme\.example\/\.well-known\/oauth-protected-resource\/mcp"/, name);
      // For a client that does not step up, as Claude Desktop did not: the tool's result, which the model reads.
      const { result } = (await response.json()) as { result: Result };
      assert.equal(result.isError, true, name);
      assert.match(result.content[0]!.text!, new RegExp(`^${name} needs coffre's Reveal values scope, which this connection was not given\\. Nothing was done\\.`), name);
      assert.match(result.content[0]!.text!, /disconnect coffre in this app and connect it again, ticking Reveal values on coffre's consent page/, name);
    }
    // The official client reads the challenge, not the body: with an auth provider, it would step up to these scopes.
    const official = await client(token, 'modern');
    try {
      await assert.rejects(official.callTool({ name: 'test_reveal', arguments: {} }), { name: 'InsufficientScopeError', message: /"read reveal"/ });
    } finally {
      await official.close();
    }
  } finally {
    TOOL_BY_NAME.delete('test_reveal');
    TOOL_BY_NAME.delete('test_sneaky');
  }
  const refused = await entries('mcp.call');
  assert.deepEqual(refused.map((entry) => [entry.metadata.tool, entry.code ?? entry.metadata.reason]), [['test_reveal', 'insufficient_scope'], ['test_sneaky', 'insufficient_scope'], ['test_reveal', 'insufficient_scope']]);
  assert.deepEqual(await entries('secret.read'), [], 'no value was read');
});

/** A person's tool list, as each era asks for it: the names, and the cache hints a 2026-07-28 answer carries. */
async function listFor(token: string): Promise<{ names: string[]; legacy: string[]; ttlMs: unknown; cacheScope: unknown }> {
  const modern = (await (await raw(token, { method: 'tools/list', params: { _meta: envelope() } })).json()) as { result: { tools: { name: string }[]; ttlMs: unknown; cacheScope: unknown } };
  const legacy = (await (await raw(token, { method: 'tools/list' }, { 'mcp-protocol-version': '2025-11-25', 'mcp-method': null })).json()) as { result: { tools: { name: string }[] } };
  return { names: modern.result.tools.map((tool) => tool.name), legacy: legacy.result.tools.map((tool) => tool.name), ttlMs: modern.result.ttlMs, cacheScope: modern.result.cacheScope };
}

const ANYONE = ['whoami', 'list_projects'];
const READS = ['list_secrets', 'secret_history', 'show_secret_value', 'reveal_secret_values'];
const WRITES = ['request_secret_value', 'generate_secret_value', 'rename_secret', 'restore_secret_version'];
const ARCHIVES = ['archive_secret', 'unarchive_secret'];
const OWNERS = ['describe_member', 'create_project', 'admit_member', 'offboard_member', 'issue_service_token', 'revoke_service_token', 'trust_workload', 'untrust_workload'];
const sorted = (...names: string[][]) => names.flat().sort();

test("each person's tools/list is what their roles reach somewhere, whatever the connection's scopes, cached for them alone, a few minutes", async () => {
  const root = clientFor(deps, ROOT);
  await root.members.add('user:access@acme.example');
  await root.access.set('user:access@acme.example', { market: 'access-manager' });
  await root.members.add('user:owner@acme.example', { owner: true });
  await root.members.add('user:lead@acme.example');
  await root.access.set('user:lead@acme.example', { billing: 'owner' });

  // A viewer, connected with Read alone: Reveal values stays listed, for the client to step up to.
  const viewer = await listFor(await connect(DEV, 'read'));
  assert.deepEqual(viewer.names.sort(), sorted(ANYONE, READS));
  assert.deepEqual(viewer.legacy.sort(), viewer.names, 'the same in either era');
  assert.deepEqual([viewer.ttlMs, viewer.cacheScope], [300_000, 'private']);

  // An access manager: who has access, and changing it; no value, nor the log.
  assert.deepEqual((await listFor(await connect('access@acme.example'))).names.sort(), sorted(ANYONE, ['list_access', 'set_access']));
  // An instance owner with no grant: the instance's own tools, and every project's management, not a value.
  assert.deepEqual(
    (await listFor(await connect('owner@acme.example'))).names.sort(),
    sorted(ANYONE, OWNERS, ['list_access', 'set_access', 'read_audit_log', 'create_environment']),
  );
  // A project's owner: everything a role gives there, nothing that is the instance's.
  assert.deepEqual(
    (await listFor(await connect('lead@acme.example'))).names.sort(),
    sorted(ANYONE, READS, WRITES, ARCHIVES, ['list_access', 'set_access', 'read_audit_log', 'create_environment']),
  );
  // A root admin: every tool, whatever the connection holds.
  const everything = await listFor(await connect(ROOT, 'read'));
  assert.deepEqual(everything.names, [...TOOL_BY_NAME.keys()]);
  // No tool takes a value: an agent cannot supply one. Only reads say they are.
  const { result } = (await (await raw(await connect(ROOT, 'read'), { method: 'tools/list', params: { _meta: envelope() } })).json()) as {
    result: { tools: { name: string; inputSchema: unknown; annotations: { readOnlyHint: boolean; openWorldHint: boolean } }[] };
  };
  assert.ok(result.tools.every((tool) => !JSON.stringify(tool.inputSchema).includes('"value"')), 'no input named value');
  assert.ok(result.tools.every((tool) => tool.annotations.openWorldHint === false));
  assert.deepEqual(result.tools.filter((tool) => tool.annotations.readOnlyHint).map((tool) => tool.name).sort(), sorted(ANYONE, READS, ['list_access', 'describe_member', 'read_audit_log']));
});

test("a role granted shows in the person's next list, and one taken is gone from it; a tool they cannot see, called by name, is refused as ever", async () => {
  const token = await connect(DEV, 'read write');
  const root = clientFor(deps, ROOT);
  assert.deepEqual((await listFor(token)).names.sort(), sorted(ANYONE, READS));
  await root.access.set(`user:${DEV}`, { market: 'maintainer' });
  assert.deepEqual((await listFor(token)).names.sort(), sorted(ANYONE, READS, WRITES, ARCHIVES, ['create_environment']));
  await root.access.set(`user:${DEV}`, { market: null, 'market/prod': null });
  assert.deepEqual((await listFor(token)).names.sort(), sorted(ANYONE));

  // Hidden from the list, not a lock: the call is the API's to refuse, as it was.
  const { status, body } = await callRaw(token, 'describe_member', { member: `user:${ROOT}` });
  assert.equal(status, 200);
  assert.equal(body.result!.isError, true);
  assert.match(body.result!.content[0]!.text!, /only owners may see what someone has access to/);
  const listed = await callRaw(token, 'list_secrets', { environment: 'market/prod' });
  assert.equal(listed.body.result!.isError, true, 'nor does a role taken leave anything behind');
});
