// What the `/mcp` suites share, on the 0.16 contract: the app with MCP on, in
// process, over the real vault; a person connecting Claude Code to it as
// Claude Code does, through the consent page and the token endpoint; the
// official client in either era; and raw 2026-07-28 requests.
import { createHash, randomBytes } from 'node:crypto';
import { after } from 'node:test';

import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { github, signin, type RateLimiter } from '@coffre/core/identity';

import { processLimits } from '../src/workloads/limits.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { openApp, PUBLIC_URL, SESSION } from './app-fixture.ts';

export const RESOURCE = `${PUBLIC_URL}/mcp`;
export const CLAUDE_CODE = 'https://claude.ai/oauth/claude-code-client-metadata';
const REDIRECT = 'http://localhost:51234/callback';

/** A cluster whose workloads a service account may trust: its discovery document, which a binding's making asks. */
export const KUBE = 'https://kubernetes.acme.example';

const transport: WorkloadTransport = {
  json: async (url) => {
    if (url.href === `${KUBE}/.well-known/openid-configuration`) return { issuer: KUBE, jwks_uri: `${KUBE}/openid/v1/jwks` };
    if (url.href !== CLAUDE_CODE) throw FetchRefused.answered(url, 404);
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

export const app = await openApp({
  auth: signin({
    providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })],
    // Workloads trusted, for the tools that bind them.
    workloads: { limits: processLimits() },
    mcp: { limits: { perSource: limiter('other'), perConnection: limiter('connection'), total: limiter('other') } },
  }),
  transport,
  workloads: {},
});
after(() => app.close());

/** A person's browser on one of coffre's own pages: `<who>-web` is their session's token. */
export const fromPage = (session: string): Record<string, string> => ({ cookie: `${SESSION}=${session}`, 'sec-fetch-site': 'same-origin' });

/** Consent on `session`'s page and the code exchanged, as Claude Code does it: the access token. */
export async function connect(session: string, scope = 'read'): Promise<string> {
  const verifier = randomBytes(32).toString('base64url');
  const request = {
    client_id: CLAUDE_CODE, redirect_uri: REDIRECT, response_type: 'code', scope, resource: RESOURCE,
    code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256',
  };
  const decided = await app.request('/api/oauth/authorizations', {
    method: 'POST',
    headers: { ...fromPage(session), 'content-type': 'application/json' },
    body: JSON.stringify({ request, approve: true, scopes: scope.split(' ') }),
  });
  if (decided.status !== 200) throw new Error(`consent: ${decided.status} ${await decided.text()}`);
  const code = new URL(((await decided.json()) as { redirect: string }).redirect).searchParams.get('code')!;
  const tokens = await app.request('/api/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: REDIRECT, client_id: CLAUDE_CODE }).toString(),
  });
  if (tokens.status !== 200) throw new Error(`token: ${tokens.status} ${await tokens.text()}`);
  return ((await tokens.json()) as { access_token: string }).access_token;
}

/** What the official client sent, by method and version header, request by request. */
export const sent: string[] = [];

/** The official client, connected in an era, every request answered by coffre in process. */
export async function client(token: string, mode: 'modern' | 'legacy', options: { elicitsUrl?: boolean } = {}): Promise<Client> {
  const mcp = new Client(
    { name: 'coffre-tests', version: '1.0.0' },
    { ...(mode === 'modern' ? { versionNegotiation: { mode: { pin: '2026-07-28' } } } : {}), ...(options.elicitsUrl === true ? { capabilities: { elicitation: { url: {} } } } : {}) },
  );
  await mcp.connect(
    new StreamableHTTPClientTransport(new URL(RESOURCE), {
      requestInit: { headers: { authorization: `Bearer ${token}` } },
      fetch: async (input, init) => {
        const request = new Request(input, init);
        const body = request.method === 'POST' ? await request.text() : undefined;
        sent.push(`${request.method} ${body === undefined ? '-' : ((JSON.parse(body) as { method?: string }).method ?? '-')} ${request.headers.get('mcp-protocol-version') ?? '-'}`);
        return app.request(new URL(request.url).pathname, { method: request.method, headers: request.headers, ...(body === undefined ? {} : { body }) });
      },
    }),
  );
  return mcp;
}

export type Result = { structuredContent?: Record<string, unknown>; content: { type: string; text?: string }[]; isError?: boolean };

/** A raw 2026-07-28 request, with the headers the client would send, each overridable, or dropped as null. */
export function raw(token: string, body: Record<string, unknown>, headers: Record<string, string | null> = {}): Promise<Response> {
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
  return app.request('/mcp', { method: 'POST', headers: base, body: JSON.stringify({ jsonrpc: '2.0', id: 7, ...body }) });
}

/** The `_meta` a 2026-07-28 request carries; `capabilities` are the client's. */
export function envelope(capabilities: Record<string, unknown> = {}) {
  return { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': capabilities };
}

/** A raw 2026-07-28 tool call: `requestState` and `inputResponses` among its params if given, and the client's capabilities. */
export async function callRaw(token: string, name: string, args: Record<string, unknown>, more: Record<string, unknown> = {}, capabilities: Record<string, unknown> = {}) {
  const response = await raw(token, { method: 'tools/call', params: { name, arguments: args, ...more, _meta: envelope(capabilities) } }, { 'mcp-name': name });
  return { status: response.status, headers: response.headers, body: (await response.json()) as { result?: Result & Record<string, unknown>; error?: { code: number; message: string } } };
}
