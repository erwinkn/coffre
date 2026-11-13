// The app's entry points on a stack of half a megabyte, run by
// `deep-bodies.test.ts`: each sent a body nested as deep as its value count
// allows, which some walk of it on the way overflows here, as it may on a
// platform whose stack is smaller than Node's. What each answered goes back
// to the test. The bodies are written as text: a `JSON.stringify` of them
// would overflow this side first.
import { defineDeployment } from '@coffre/core/deployment';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { parentPort } from 'node:worker_threads';

import { github, signin, type RateLimiter } from '@coffre/core/identity';

import { SigninService } from '../src/api/signin.ts';
import { coffreRoute } from '../src/app.ts';
import { MAX_BODY_NODES } from '../src/http.ts';
import { McpService } from '../src/mcp/service.ts';
import { TOOL_BY_NAME } from '../src/mcp/tools.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';

import { clientFor, contextFor, openTestDatabase, resetDatabase, testDeps, waitUntil } from './api-fixture.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const CLAUDE_CODE = 'https://claude.ai/oauth/claude-code-client-metadata';
const REDIRECT = 'http://localhost:51234/callback';

const transport: WorkloadTransport = {
  json: async (url) => {
    if (url.href !== CLAUDE_CODE) throw FetchRefused.answered(url, 404);
    return { client_id: CLAUDE_CODE, client_name: 'Claude Code', redirect_uris: ['http://localhost/callback'], token_endpoint_auth_method: 'none' };
  },
};
const open: RateLimiter = { limit: async () => ({ success: true }) };
const auth = signin({
  providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })],
  mcp: { limits: { perSource: open, perConnection: open, total: open } },
}).resolve(ORIGIN);
if (auth.mode !== 'signin') throw new Error('unreachable');

const db = await openTestDatabase();
await resetDatabase(db.owner);
const deps = testDeps(db.runtime, [ROOT]);
const service = new SigninService({ ...deps, signin: auth.signin });
const mcp = new McpService({ ...deps, config: auth.signin.mcp!, signin: auth.signin, publicUrl: ORIGIN, transport });
const runtime: CoffreRuntime = {
  db: deps.db, vault: deps.vault, chainKey: deps.chainKey, previousChainKeys: [], signin: service, workloads: null, mcp, auth,
  publicUrl: ORIGIN, verifier: service, waitUntil, schema: { migrated: true }, appKey: { settled: true }, rotateAfterDays: 365, deployment: defineDeployment(), plugins: [],
};
const route = (path: string, init: RequestInit) => coffreRoute(new Request(`${ORIGIN}${path}`, init), runtime, '203.0.113.7').then((response) => response!);

const root = clientFor(deps, ROOT);
await root.projects.create('market');
await root.environments.create('market/dev');

// The root's CLI session, and an MCP connection of theirs, as `mcp-fixture.ts` makes them.
const started = await service.startDevice({ clientLabel: 'laptop', sourceIp: null });
await service.decideDevice(await contextFor(deps, ROOT), started.userCode, true);
const polled = await service.pollDevice(started.deviceCode, { requestId: randomUUID(), sourceIp: null });
if (polled.status !== 'approved') throw new Error('not approved');
const session = polled.credential.token;
const verifier = randomBytes(32).toString('base64url');
const consent = {
  client_id: CLAUDE_CODE, redirect_uri: REDIRECT, response_type: 'code', scope: 'read', resource: `${ORIGIN}/mcp`,
  code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256',
};
const decided = await route('/api/oauth/authorizations', {
  method: 'POST',
  headers: { authorization: `Bearer ${session}`, 'content-type': 'application/json' },
  body: JSON.stringify({ request: consent, approve: true, scopes: ['read'] }),
});
const code = new URL(((await decided.json()) as { redirect: string }).redirect).searchParams.get('code')!;
const tokens = await route('/api/oauth/token', {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: REDIRECT, client_id: CLAUDE_CODE }).toString(),
});
const access = ((await tokens.json()) as { access_token: string }).access_token;

/** An object nested `depth` levels, `{"a":{"a":…0…}}`, as text. */
const nested = (depth: number) => `${'{"a":'.repeat(depth)}0${'}'.repeat(depth)}`;
// As deep as the count lets a body be, beside the few values around it.
const deep = nested(MAX_BODY_NODES - 20);

const json = { 'content-type': 'application/json' };
const asRoot = { ...json, authorization: `Bearer ${session}` };
const sent: [string, string, RequestInit][] = [
  ['the API, a proxy definition', '/api/projects/market/dev/proxy', { method: 'PUT', headers: asRoot, body: `{"seal":null,"items":{"api":${deep}}}` }],
  ['the API, a role', '/api/roles/release', { method: 'PUT', headers: asRoot, body: `{"name":"Release","description":${deep},"permissions":[],"protected":[]}` }],
  ['the API, a secret write', '/api/secrets/market/dev', { method: 'PATCH', headers: asRoot, body: `{"KEY":${deep}}` }],
  ["sign-in, a device login's start", '/api/auth/device', { method: 'POST', headers: json, body: `{"client_label":${deep}}` }],
  ["MCP's client registration", '/api/oauth/register', { method: 'POST', headers: json, body: `{"redirect_uris":["${REDIRECT}"],"client_name":${deep}}` }],
  ['MCP, a tool call', '/mcp', {
    method: 'POST',
    headers: { ...json, authorization: `Bearer ${access}`, accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2026-07-28', 'mcp-method': 'tools/call', 'mcp-name': 'list_secrets' },
    body: `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"list_secrets","arguments":{"environment":"market/dev"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"deep":${deep}}}}`,
  }],
];
type Answer = { what: string; status: number; text: string };
const answer = async (what: string, path: string, init: RequestInit): Promise<Answer> => {
  const response = await route(path, init);
  return { what, status: response.status, text: (await response.text()).slice(0, 300) };
};
const deepAnswers: Answer[] = [];
for (const [what, path, init] of sent) deepAnswers.push(await answer(what, path, init));

// Then a walk that does run out, had inside each entry point: a genuine stack overflow, as one of a value too deep for
// it throws, where the vault takes a value the API writes, where sign-in starts a device login, and where MCP runs a
// connection's call (its tool: a connection's calls have no rate of their own to admit).
function overflow(depth = 0): never {
  return overflow(depth + 1);
}
const vault = deps.vault as unknown as Record<string, unknown>;
const stubbed = <T extends Record<string, unknown>>(target: T, name: keyof T & string) => {
  const kept = target[name];
  (target as Record<string, unknown>)[name] = () => overflow();
  return () => ((target as Record<string, unknown>)[name] = kept);
};
const overflowAnswers: Answer[] = [];
// Every call of the vault's but the caller check, whichever a write makes.
const methods = new Set<string>();
for (let at: object | null = vault; at !== null && at !== Object.prototype; at = Object.getPrototypeOf(at) as object | null) {
  for (const name of Object.getOwnPropertyNames(at)) if (name !== 'constructor' && name !== 'access' && typeof vault[name] === 'function') methods.add(name);
}
const restores = [...methods].map((name) => stubbed(vault, name));
overflowAnswers.push(await answer('the API', '/api/secrets/market/dev', { method: 'PATCH', headers: asRoot, body: '{"KEY":"v2"}' }));
for (const each of restores) each();
let restore = stubbed(service as unknown as Record<string, unknown>, 'startDevice');
overflowAnswers.push(await answer('sign-in', '/api/auth/device', { method: 'POST', headers: json, body: '{"client_label":"laptop"}' }));
restore();
restore = stubbed(TOOL_BY_NAME.get('list_secrets')! as unknown as Record<string, unknown>, 'run');
overflowAnswers.push(await answer('MCP', '/mcp', {
  method: 'POST',
  headers: { ...json, authorization: `Bearer ${access}`, accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2026-07-28', 'mcp-method': 'tools/call', 'mcp-name': 'list_secrets' },
  body: '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"list_secrets","arguments":{"environment":"market/dev"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}',
}));
restore();

await resetDatabase(db.owner);
await db.close();
parentPort!.postMessage({ deep: deepAnswers, overflowed: overflowAnswers });
