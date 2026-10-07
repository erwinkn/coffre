// What the MCP suites share: an instance with MCP on, in process, a person
// connecting Claude Code to it as Claude Code does, the official client in
// either era, raw 2026-07-28 requests, and the log's entries by action.
import { after, before, beforeEach } from 'node:test';
import { createHash, randomBytes, randomUUID } from 'node:crypto';

import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { github, signin, type RateLimiter } from '@coffre/core/identity';
import { eq } from 'drizzle-orm';

import { SigninService } from '../src/api/signin.ts';
import { coffreRoute } from '../src/app.ts';
import { McpService } from '../src/mcp/service.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { contextFor, openTestDatabase, resetDatabase, testDeps, waitUntil, type FixtureDeps } from './api-fixture.ts';
import { auditLog } from './db/tables.ts';

export const ORIGIN = 'https://secrets.acme.example';
export const RESOURCE = `${ORIGIN}/mcp`;
export const ROOT = 'admin@acme.example';
export const DEV = 'dev@acme.example';
export const CLAUDE_CODE = 'https://claude.ai/oauth/claude-code-client-metadata';
const REDIRECT = 'http://localhost:51234/callback';

/** What the internet answers besides Claude Code's document, by URL: a test sets GitHub's or GitLab's answers here. */
export const documents = new Map<string, unknown>();

const transport: WorkloadTransport = {
  json: async (url) => {
    if (documents.has(url.href)) return documents.get(url.href);
    if (url.href !== CLAUDE_CODE) throw new FetchRefused(url, 'answered 404');
    return { client_id: CLAUDE_CODE, client_name: 'Claude Code', redirect_uris: ['http://localhost/callback'], token_endpoint_auth_method: 'none' };
  },
};

/** Whether a connection's calls pass its limit: a test closes it to see the 429, or breaks it to see a limiter fail. */
export const calls: { open: boolean | 'broken' } = { open: true };
const limiter = (which: 'other' | 'connection'): RateLimiter => ({
  limit: async () => {
    if (which === 'connection' && calls.open === 'broken') throw new Error('rate limiter unreachable');
    return { success: which === 'other' || calls.open === true };
  },
});
const auth = signin({
  providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })],
  mcp: { limits: { perSource: limiter('other'), perConnection: limiter('connection'), total: limiter('other') } },
}).resolve(ORIGIN);

export let db: Awaited<ReturnType<typeof openTestDatabase>>;
export let deps: FixtureDeps;
export let runtime: CoffreRuntime;

/**
 * The suite's hooks: the instance once, and a clean database before each
 * test, which `seed` then fills. `approvalWaitMs` is how long a call waits
 * on its approval before saying it still waits.
 */
export function useMcp(seed: () => Promise<void>, options: { approvalWaitMs?: number } = {}): void {
  before(async () => {
    db = await openTestDatabase();
    deps = testDeps(db.runtime, [ROOT]);
    if (auth.mode !== 'signin') throw new Error('unreachable');
    const service = new SigninService({ ...deps, signin: auth.signin });
    const mcp = new McpService({ ...deps, config: auth.signin.mcp!, signin: auth.signin, publicUrl: ORIGIN, transport, ...options });
    runtime = { db: deps.db, vault: deps.vault, chainKey: deps.chainKey, signin: service, workloads: null, mcp, auth, publicUrl: ORIGIN, verifier: service, waitUntil, schema: { migrated: true } };
  });
  after(async () => {
    await resetDatabase(db.owner);
    await db.close();
  });
  beforeEach(async () => {
    await resetDatabase(db.owner);
    calls.open = true;
    documents.clear();
    await seed();
  });
}

export function route(path: string, init: RequestInit = {}): Promise<Response> {
  return coffreRoute(new Request(`${ORIGIN}${path}`, init), runtime, '203.0.113.7').then((response) => response!);
}

/** A CLI session for a person: what calls the API as them, as their browser would. */
export async function sessionFor(email: string): Promise<string> {
  const service = runtime.signin!;
  const started = await service.startDevice({ clientLabel: 'laptop', sourceIp: null });
  await service.decideDevice(await contextFor(deps, email), started.userCode, true);
  const polled = await service.pollDevice(started.deviceCode, { requestId: randomUUID(), sourceIp: null });
  if (polled.status !== 'approved') throw new Error('not approved');
  return polled.credential.token;
}

/** A browser session for a person, as signing in on coffre's page leaves one: what decides approvals. */
export async function browserFor(email: string): Promise<string> {
  const signed = await runtime.signin!.completeSignin({ provider: 'github', subject: `gh-${email}`, emails: [email], name: null }, { requestId: randomUUID(), sourceIp: null, label: 'Firefox' });
  if (!signed.ok) throw new Error(`${email} was not let in`);
  return signed.credential.token;
}

/** What one of coffre's pages sends with its calls: the browser's session cookie, from coffre's own origin. */
export function fromPage(session: string, headers: Record<string, string> = {}): Record<string, string> {
  return { cookie: `__Host-coffre_session=${session}`, 'sec-fetch-site': 'same-origin', ...headers };
}

/** Consent and the code exchanged, as Claude Code does it: the access token. */
export async function connect(email = DEV, scope = 'read'): Promise<string> {
  const session = await sessionFor(email);
  const verifier = randomBytes(32).toString('base64url');
  const request = {
    client_id: CLAUDE_CODE, redirect_uri: REDIRECT, response_type: 'code', scope, resource: RESOURCE,
    code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256',
  };
  const decided = await route('/api/oauth/authorizations', {
    method: 'POST',
    headers: { authorization: `Bearer ${session}`, 'content-type': 'application/json' },
    body: JSON.stringify({ request, approve: true, scopes: scope.split(' ') }),
  });
  const code = new URL(((await decided.json()) as { redirect: string }).redirect).searchParams.get('code')!;
  const tokens = await route('/api/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: REDIRECT, client_id: CLAUDE_CODE }).toString(),
  });
  return ((await tokens.json()) as { access_token: string }).access_token;
}

/** What the official client sent, by method and version header, request by request. */
export const sent: string[] = [];

/** The official client, connected in an era, every request answered by coffre in process. */
export async function client(token: string, mode: 'modern' | 'legacy', options: { elicitsUrl?: boolean } = {}): Promise<Client> {
  const mcp = new Client(
    { name: 'coffre-tests', version: '1.0.0' },
    {
      ...(mode === 'modern' ? { versionNegotiation: { mode: { pin: '2026-07-28' } } } : {}),
      ...(options.elicitsUrl === true ? { capabilities: { elicitation: { url: {} } } } : {}),
    },
  );
  await mcp.connect(
    new StreamableHTTPClientTransport(new URL(RESOURCE), {
      requestInit: { headers: { authorization: `Bearer ${token}` } },
      fetch: async (input, init) => {
        const request = new Request(input, init);
        const body = request.method === 'POST' ? ((await request.clone().json()) as { method?: string }) : {};
        sent.push(`${request.method} ${body.method ?? '-'} ${request.headers.get('mcp-protocol-version') ?? '-'}`);
        return (await coffreRoute(request, runtime, '203.0.113.7'))!;
      },
    }),
  );
  return mcp;
}

export type Result = { structuredContent?: Record<string, unknown>; content: { type: string; text?: string }[]; isError?: boolean };

export async function entries(action: string) {
  const rows = await db.owner.select().from(auditLog).where(eq(auditLog.action, action)).orderBy(auditLog.seq);
  return rows.map((row) => ({ ...row, metadata: JSON.parse(row.metadata) as Record<string, unknown> }));
}

/** A raw 2026-07-28 request, with the headers the client would send, each overridable. */
export function raw(token: string, body: Record<string, unknown>, headers: Record<string, string | null> = {}) {
  const base: Record<string, string> = {
    authorization: `Bearer ${token}`,
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    'mcp-protocol-version': '2026-07-28',
    'mcp-method': String(body.method),
  };
  for (const [name, value] of Object.entries(headers)) {
    if (value === null) delete base[name];
    else base[name] = value;
  }
  return route('/mcp', { method: 'POST', headers: base, body: JSON.stringify({ jsonrpc: '2.0', id: 7, ...body }) });
}

/** The `_meta` a 2026-07-28 request carries; `capabilities` are the client's. */
export function envelope(capabilities: Record<string, unknown> = {}) {
  return { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': capabilities };
}

/** A raw 2026-07-28 tool call: the body, `requestState` and `inputResponses` among the params if given. */
export async function callRaw(token: string, name: string, args: Record<string, unknown>, more: Record<string, unknown> = {}, capabilities: Record<string, unknown> = {}) {
  const response = await raw(token, { method: 'tools/call', params: { name, arguments: args, ...more, _meta: envelope(capabilities) } }, { 'mcp-name': name });
  return { status: response.status, body: (await response.json()) as { result?: Record<string, unknown> & Result; error?: { code: number; message: string } } };
}
