// `POST /mcp`: the MCP endpoint (docs/design/mcp.md, section 2). One JSON
// answer per request, never a stream, and no session: the 2026-07-28
// revision, whose requests each carry their version and the client's
// capabilities in `_meta`, and the 2025 era's `initialize` beside it, which
// coffre answers without minting a session either. Both serve the same
// tools, with the same checks. The token is checked first (`mcpCaller`):
// nothing here runs for a request without a good one.
import { CoffreError, createClient, type CoffreClient } from '@coffre/client';
import { isMcpScope, MCP_SCOPE_INFO, scopeString, type McpScope } from '@coffre/core/mcp';
import { z } from 'zod';

import { allowed, audited, denied, type McpVia } from '../api/context.ts';
import type { AuditEntry } from '../db/audit.ts';
import type { AuthenticatedIdentity } from '../auth.ts';
import { fetchApi } from '../fetch-api.ts';
import { readLimitedJson } from '../http.ts';
import { logged } from '../logged.ts';
import type { CoffreRuntime } from '../runtime.ts';
import { COFFRE_VERSION } from '../version.ts';
import { mcpCaller, resourceMetadataUrl } from './http.ts';
import { challengeScopes } from './scopes.ts';
import type { ApprovalRow } from '../db/queries.ts';
import { callDigest, MAX_PENDING, OUTCOME_SECONDS, outcomeOf, statusOf, UNKNOWN_OUTCOME, type Outcome } from './approvals.ts';
import type { McpConnection } from './service.ts';
import { openState, sealState } from './tokens.ts';
import { INSTRUCTIONS, listed, TOOL_BY_NAME, TOOLS, type Tool, usable } from './tools.ts';

/** The revision coffre speaks, stateless. */
export const PROTOCOL_VERSION = '2026-07-28';
/** The 2025 era's, answered through `initialize`, without a session. */
export const LEGACY_VERSIONS = ['2025-11-25', '2025-06-18'] as const;
const BODY_BYTES = 256 * 1024;
/** How long a client may keep the server's description, which every token sees the same. */
const TTL_MS = 3_600_000;
/** How long a client may keep its person's tool list, theirs alone: a role granted or taken shows within it. */
const LIST_TTL_MS = 300_000;

const META = {
  protocolVersion: 'io.modelcontextprotocol/protocolVersion',
  clientCapabilities: 'io.modelcontextprotocol/clientCapabilities',
  serverInfo: 'io.modelcontextprotocol/serverInfo',
} as const;

/** JSON-RPC's codes, and MCP's own (`-32020` header mismatch, `-32022` unsupported version). */
const CODE = {
  parse: -32700,
  invalidRequest: -32600,
  methodNotFound: -32601,
  invalidParams: -32602,
  internal: -32603,
  headerMismatch: -32020,
  unsupportedVersion: -32022,
} as const;

type JsonRpcId = string | number;
type Message = { jsonrpc: '2.0'; id?: JsonRpcId; method: string; params?: Record<string, unknown> };
type RpcError = { code: number; message: string; data?: unknown };

const SERVER_INFO = { name: 'coffre', title: 'coffre', version: COFFRE_VERSION };

function rpc(id: JsonRpcId | null, body: { result: unknown } | { error: RpcError }, status = 200, headers: Record<string, string> = {}): Response {
  return Response.json({ jsonrpc: '2.0', id, ...body }, { status, headers: { 'cache-control': 'no-store', ...headers } });
}

const failure = (id: JsonRpcId | null, status: number, error: RpcError, headers?: Record<string, string>) => rpc(id, { error }, status, headers);

/** A request's `Mcp-Name`, as sent: plain ASCII, or `=?base64?…?=` around UTF-8. Null when it is neither. */
export function decodeHeaderValue(value: string): string | null {
  const wrapped = /^=\?base64\?([A-Za-z0-9+/]*={0,2})\?=$/.exec(value);
  if (wrapped === null) return /^[\t\x20-\x7e]*$/.test(value) ? value : null;
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(atob(wrapped[1]!), (c) => c.charCodeAt(0)));
  } catch {
    return null;
  }
}

/** A JSON-RPC message the endpoint can answer, or why not. */
function parseMessage(body: unknown): Message | RpcError {
  if (Array.isArray(body)) return { code: CODE.invalidRequest, message: 'Batches are not supported: send one message per request' };
  if (typeof body !== 'object' || body === null) return { code: CODE.invalidRequest, message: 'Invalid Request: not a JSON-RPC message' };
  const message = body as Record<string, unknown>;
  if (message.jsonrpc !== '2.0' || typeof message.method !== 'string') {
    return { code: CODE.invalidRequest, message: 'Invalid Request: a JSON-RPC 2.0 request or notification, with a method' };
  }
  if ('id' in message && typeof message.id !== 'string' && typeof message.id !== 'number') {
    return { code: CODE.invalidRequest, message: 'Invalid Request: an id is a string or a number' };
  }
  if (message.params !== undefined && (typeof message.params !== 'object' || message.params === null || Array.isArray(message.params))) {
    return { code: CODE.invalidRequest, message: 'Invalid Request: params is an object' };
  }
  return message as Message;
}

const errorOf = (value: Message | RpcError): value is RpcError => !('method' in value);

export async function mcpEndpoint(request: Request, runtime: CoffreRuntime, sourceIp: string | null): Promise<Response> {
  const caller = await mcpCaller(request, runtime, sourceIp);
  if (caller instanceof Response) return caller;
  let body: unknown;
  try {
    body = await readLimitedJson(request, BODY_BYTES);
  } catch {
    return failure(null, 400, { code: CODE.parse, message: 'Parse error: the body is not JSON' });
  }
  const message = parseMessage(body);
  if (errorOf(message)) return failure(null, 400, message);
  const id = message.id ?? null;
  // A notification gets no answer; nothing coffre is told needs one.
  if (id === null) return new Response(null, { status: 202 });

  const meta = (message.params?._meta ?? undefined) as Record<string, unknown> | undefined;
  const header = request.headers.get('mcp-protocol-version');
  const claimed = meta?.[META.protocolVersion];
  try {
    if (claimed !== undefined) return await modern(request, runtime, sourceIp, caller, message, id, claimed, header);
    return await legacy(request, runtime, sourceIp, caller, message, id, header);
  } catch (error) {
    console.error('mcp request failed', logged(error));
    return failure(id, 500, { code: CODE.internal, message: 'Internal error: see the server log' });
  }
}

// --- 2026-07-28 ---------------------------------------------------------------

async function modern(
  request: Request,
  runtime: CoffreRuntime,
  sourceIp: string | null,
  caller: McpConnection,
  message: Message,
  id: JsonRpcId,
  claimed: unknown,
  header: string | null,
): Promise<Response> {
  if (typeof claimed !== 'string' || claimed !== PROTOCOL_VERSION) {
    return failure(id, 400, {
      code: CODE.unsupportedVersion,
      message: `Unsupported protocol version: coffre speaks ${PROTOCOL_VERSION}`,
      data: { supported: [PROTOCOL_VERSION], requested: claimed },
    });
  }
  // The headers name what the body says, so that what routes a request cannot disagree with what it is.
  const mismatch = (detail: string) => failure(id, 400, { code: CODE.headerMismatch, message: `Header mismatch: ${detail}` });
  if (header === null) return mismatch('MCP-Protocol-Version is required');
  if (header !== claimed) return mismatch(`MCP-Protocol-Version is ${header}, the body ${claimed}`);
  const method = request.headers.get('mcp-method');
  if (method === null) return mismatch('Mcp-Method is required');
  if (method !== message.method) return mismatch(`Mcp-Method is ${method}, the body ${message.method}`);
  if (message.method === 'tools/call') {
    const sent = request.headers.get('mcp-name');
    const name = message.params?.name;
    if (typeof name === 'string') {
      if (sent === null) return mismatch('Mcp-Name is required for tools/call');
      if (decodeHeaderValue(sent) !== name) return mismatch('Mcp-Name does not name the tool the body calls');
    }
  }
  const meta = message.params!._meta as Record<string, unknown>;
  const capabilities = meta[META.clientCapabilities];
  if (typeof capabilities !== 'object' || capabilities === null || Array.isArray(capabilities)) {
    return failure(id, 400, { code: CODE.invalidParams, message: `Invalid params: _meta needs ${META.clientCapabilities}` });
  }

  const complete = (result: Record<string, unknown>) =>
    rpc(id, { result: { resultType: 'complete', ...result, _meta: { [META.serverInfo]: SERVER_INFO } } });
  switch (message.method) {
    case 'server/discover':
      return complete({
        supportedVersions: [PROTOCOL_VERSION],
        capabilities: { tools: {} },
        instructions: INSTRUCTIONS,
        ttlMs: TTL_MS,
        cacheScope: 'public',
      });
    case 'tools/list':
      return complete({ tools: toolsFor(caller), ttlMs: LIST_TTL_MS, cacheScope: 'private' });
    case 'tools/call':
      return call(request, runtime, sourceIp, caller, message, id, (result) => complete(result), { era: 'modern', elicitsUrl: elicitsUrl(capabilities as Record<string, unknown>) });
    default:
      return failure(id, 404, { code: CODE.methodNotFound, message: `Method not found: ${message.method}` });
  }
}

// --- 2025-11-25 and 2025-06-18 ----------------------------------------------

async function legacy(
  request: Request,
  runtime: CoffreRuntime,
  sourceIp: string | null,
  caller: McpConnection,
  message: Message,
  id: JsonRpcId,
  header: string | null,
): Promise<Response> {
  if (message.method === 'initialize') {
    const asked = message.params?.protocolVersion;
    const version = (LEGACY_VERSIONS as readonly unknown[]).includes(asked) ? (asked as string) : LEGACY_VERSIONS[0];
    // No session ID: every request stands alone, as on 2026-07-28.
    return rpc(id, { result: { protocolVersion: version, capabilities: { tools: {} }, serverInfo: SERVER_INFO, instructions: INSTRUCTIONS } });
  }
  if (header === PROTOCOL_VERSION) {
    return failure(id, 400, { code: CODE.invalidParams, message: `Invalid params: a ${PROTOCOL_VERSION} request carries its _meta envelope` });
  }
  if (header === null || !(LEGACY_VERSIONS as readonly string[]).includes(header)) {
    return failure(id, 400, {
      code: CODE.invalidRequest,
      message: `coffre needs MCP-Protocol-Version ${PROTOCOL_VERSION}, or ${LEGACY_VERSIONS.join(' or ')} after initialize`,
    });
  }
  switch (message.method) {
    case 'ping':
      return rpc(id, { result: {} });
    case 'tools/list':
      return rpc(id, { result: { tools: toolsFor(caller) } });
    case 'tools/call':
      return call(request, runtime, sourceIp, caller, message, id, (result) => rpc(id, { result }), { era: 'legacy', elicitsUrl: false });
    default:
      return rpc(id, { error: { code: CODE.methodNotFound, message: `Method not found: ${message.method}` } });
  }
}

/**
 * The tools a person's roles let them use somewhere, as they are on this
 * request: the vault's answer the token check already read, so listing
 * costs no read of its own. A tool only the connection's scopes withhold
 * stays listed: calling it asks for the scope.
 */
function toolsFor(connection: McpConnection): Record<string, unknown>[] {
  return TOOLS.filter((tool) => usable(connection.caller, tool)).map(listed);
}

// --- tools/call ---------------------------------------------------------------

const CallParams = z
  .object({ name: z.string().max(64), arguments: z.record(z.string(), z.unknown()).optional(), requestState: z.string().max(512).optional(), inputResponses: z.record(z.string(), z.unknown()).optional() })
  .passthrough();

/** What coffre knows of a client from its request: its era, and whether it can open a URL for its person. */
type ClientSays = { era: 'modern' | 'legacy'; elicitsUrl: boolean };

/** Whether a 2026-07-28 client declared URL-mode elicitation, which opens coffre's approval page for its person. */
function elicitsUrl(capabilities: Record<string, unknown>): boolean {
  const elicitation = capabilities.elicitation;
  return typeof elicitation === 'object' && elicitation !== null && typeof (elicitation as Record<string, unknown>).url === 'object';
}

/** How long a retry waits on its approval before answering that it still waits: well inside every client's timeout. */
const WAIT_MS = 25_000;

/**
 * One tool's call: admitted against its connection's limit, held to its
 * scopes, run as API calls in its person's name, and logged with the client.
 * A refusal the API gives is the tool's result, an error the model reads; a
 * scope the connection lacks is a 403 that starts the client's step-up,
 * whose body is such a result too, for a client that does not. A
 * change goes through its approval instead (`change`).
 */
async function call(
  request: Request,
  runtime: CoffreRuntime,
  sourceIp: string | null,
  connection: McpConnection,
  message: Message,
  id: JsonRpcId,
  answer: (result: Record<string, unknown>) => Response,
  client: ClientSays,
): Promise<Response> {
  const mcp = runtime.mcp!;
  const requestId = crypto.randomUUID();
  if (!(await mcp.admitCall(connection.id, requestId))) {
    return failure(id, 429, { code: CODE.internal, message: 'Too many calls: try again in a minute' }, { 'retry-after': '60' });
  }
  const params = CallParams.safeParse(message.params ?? {});
  if (!params.success) return rpc(id, { error: { code: CODE.invalidParams, message: 'Invalid params: tools/call takes a name and its arguments' } });
  const tool = TOOL_BY_NAME.get(params.data.name);
  if (tool === undefined) return rpc(id, { error: { code: CODE.invalidParams, message: `Unknown tool: ${params.data.name}` } });
  const args = tool.input.safeParse(params.data.arguments ?? {});
  if (!args.success) {
    return answer(toolError(`The arguments do not fit ${tool.name}: ${args.error.issues.map((issue) => `${issue.path.join('.') || 'arguments'}: ${issue.message}`).join('; ')}`));
  }

  const via: McpVia = { connectionId: connection.id, clientId: connection.clientId, clientName: connection.clientName, scopes: connection.scopes };
  const writer = { caller: connection.caller, requestId, sourceIp, provenance: connection.id, via };
  const names = tool.names(args.data as never);
  const log = (entry: AuditEntry) =>
    audited(runtime, async (_tx, entries) => {
      entries.push(entry);
    });
  const metadata = { tool: tool.name, names };
  const entry = (action: string, more: Record<string, unknown>) => allowed(writer, action, { metadata: { ...metadata, ...more } });
  // A read-only tool's call that went through is detail, as a sign-in is; everything else shows.
  const done = (decision: 'allow' | 'deny', reason?: string, more: Record<string, unknown> = {}) =>
    log(
      decision === 'allow'
        ? entry(tool.readOnly ? 'mcp.read' : 'mcp.call', more)
        : denied(writer, 'mcp.call', reason ?? 'refused', { metadata: { ...metadata, ...more } }),
    );

  if (!connection.scopes.includes(tool.scope)) {
    await done('deny', 'insufficient_scope');
    return insufficientScope(runtime, connection, tool, id, tool.scope);
  }

  const identity: AuthenticatedIdentity = {
    principal: { type: 'user', id: connection.principal.id, email: connection.principal.id, subject: connection.principal.id },
    registered: connection.caller.registered,
    caller: connection.caller,
    requestId,
    sourceIp,
    credentialId: null,
    provenance: connection.id,
    via,
  };
  // The API in process, as the connection's person: one token check for the whole call, the one already made.
  const api = createClient({
    url: runtime.publicUrl,
    headers: () => ({ authorization: 'Bearer mcp-connection' }),
    transport: (inner) => fetchApi(inner, runtime, { sourceIp, authenticate: async () => identity }),
  });
  try {
    if (tool.change !== undefined) {
      return await change(runtime, connection, tool, args.data, params.data, { api, answer, client, done, entry, id });
    }
    const result = await tool.run({ api, connection, publicUrl: runtime.publicUrl }, args.data as never);
    await done('allow');
    return answer({
      content: [{ type: 'text', text: result.text ?? JSON.stringify(result.structured, null, 2) }],
      structuredContent: result.structured,
    });
  } catch (error) {
    const refused = refusalOf(error);
    if (refused === null) throw error;
    await done('deny', refused.code);
    // The API's own table refused: the challenge names the scope its route needs, which its reason says.
    if (refused.code === 'insufficient_scope') return insufficientScope(runtime, connection, tool, id, refused.reason !== undefined && isMcpScope(refused.reason) ? refused.reason : tool.scope);
    return answer(toolError(refused.message));
  }
}

type ChangeCall = {
  api: CoffreClient;
  answer: (result: Record<string, unknown>) => Response;
  client: ClientSays;
  done: (decision: 'allow' | 'deny', reason?: string, more?: Record<string, unknown>) => Promise<void>;
  /** The call's entry, allowed, for what `approvals` writes with it. */
  entry: (action: string, more: Record<string, unknown>) => AuditEntry;
  id: JsonRpcId;
};

/**
 * A change's call (docs/design/mcp.md, section 7). Nothing changes here: the
 * first call opens an approval, or rejoins the one the same call opened, and
 * the person decides it on coffre's page, which makes the change. A client
 * that can open a URL is asked to, by an elicitation, and retries with the
 * `requestState` coffre gave it; any other gets the link in the result, to
 * show its person, and calls again with the same arguments. Either way the
 * retry only reads the outcome, waiting up to 25 seconds for it.
 */
async function change(
  runtime: CoffreRuntime,
  connection: McpConnection,
  tool: Tool,
  args: unknown,
  params: z.infer<typeof CallParams>,
  { api, answer, client, done, entry, id }: ChangeCall,
): Promise<Response> {
  const { approvals } = runtime.mcp!;
  const prompt = (row: ApprovalRow, ask: boolean) =>
    answer({
      resultType: 'input_required',
      ...(ask
        ? { inputRequests: { approve: { method: 'elicitation/create', params: { mode: 'url', url: approvals.url(row.id), message: `Approve on coffre: ${tool.change!.summary(args as never)}` } } } }
        : {}),
      requestState: sealState(runtime.chainKey, {
        approvalId: row.id,
        connectionId: connection.id,
        digest: row.digest.toString('hex'),
        expiresAt: new Date(row.createdAt.getTime() + OUTCOME_SECONDS * 1000),
      }),
    });

  let row: ApprovalRow & { now?: Date };
  if (params.requestState !== undefined) {
    const state = client.era === 'modern' ? openState(runtime.chainKey, params.requestState) : null;
    // The state names the approval, its connection and its call: another call, or another connection's, gets nothing from it.
    if (state === null || state.connectionId !== connection.id || state.digest !== callDigest(tool.name, args)) {
      await done('deny', 'request_state');
      return rpc(id, { error: { code: CODE.invalidParams, message: 'Invalid params: this requestState is not for this call' } });
    }
    const found = state.expiresAt.getTime() > Date.now() ? await approvals.find(state.approvalId) : null;
    if (found === null) return answer(toolError(`This approval has expired: call ${tool.name} again to ask the person anew.`));
    const response = params.inputResponses?.approve as { action?: unknown } | undefined;
    // Declined: the person said no to opening the page, and the approval ends. Cancelled: the prompt was
    // dismissed, or a client that cannot ask anyone (Claude Code with -p) answered it, so the link goes to the model instead.
    if (response?.action === 'decline') await approvals.cancel(found.id, entry('mcp.cancel', { approvalId: found.id }));
    if (response?.action === 'cancel' && found.status === 'pending') return answer(pending(approvals.url(found.id), found, tool, 'asked'));
    row = found;
  } else {
    await tool.change!.check?.({ api, connection, publicUrl: runtime.publicUrl }, args as never);
    // A new approval's call is logged with it; a call that rejoins one is not logged again.
    const asked = await approvals.ask(connection, tool, args, (approvalId) => entry('mcp.call', { approvalId }));
    if ('full' in asked) {
      await done('deny', 'too_many_approvals');
      return answer(toolError(`${MAX_PENDING} changes are waiting for the person already: ask them to decide those on coffre first.`));
    }
    row = asked.row;
    if (row.status === 'pending' && (!asked.joined || client.elicitsUrl)) {
      return client.elicitsUrl ? prompt(row, true) : answer(pending(approvals.url(row.id), row, tool, 'asked'));
    }
  }

  const settled = await approvals.settle(row.id, Date.now() + (runtime.mcp!.approvalWaitMs ?? WAIT_MS));
  const status = statusOf(settled, settled.now);
  if (status === 'pending' || (status === 'approved' && settled.outcome === null)) {
    return client.elicitsUrl ? prompt(settled, false) : answer(pending(approvals.url(settled.id), settled, tool, status === 'pending' ? 'waiting' : 'making'));
  }
  const known = outcomeOf(settled, settled.now);
  // An unknown outcome is no end the client heard: the same call rejoins it, and is told so again, while it may.
  if (known !== UNKNOWN_OUTCOME) await approvals.reported(settled.id);
  // Without an outcome, it ended before the person approved it: nothing changed.
  const outcome: Outcome = known ?? { text: `This approval ${status === 'expired' ? 'expired before the person decided it' : `is ${status}`}: nothing changed.` };
  const structured = {
    status,
    message: outcome.text,
    approval: { id: settled.id, url: approvals.url(settled.id), expiresAt: settled.expiresAt.toISOString() },
    ...(outcome.result === undefined ? {} : { result: outcome.result }),
  };
  return answer({ content: [{ type: 'text', text: outcome.text }], structuredContent: structured, ...(status === 'approved' ? {} : { isError: true }) });
}

/**
 * What a client that cannot open a URL is told while its change waits:
 * the link, for its person, once `asked`, and while it is `waiting` on
 * them. Once they approved it, while coffre is `making` it, only to call again.
 */
function pending(url: string, row: ApprovalRow, tool: Tool, state: 'asked' | 'waiting' | 'making'): Record<string, unknown> {
  const approval = { id: row.id, url, expiresAt: row.expiresAt.toISOString() };
  if (state === 'making') {
    const text = `The person approved this, and coffre is making the change. Call ${tool.name} again with the same arguments in a moment: it answers what became of it.`;
    return { content: [{ type: 'text', text }], structuredContent: { status: 'pending', message: text, approval } };
  }
  const expires = row.expiresAt.toISOString().replace(/\.\d+Z$/, 'Z');
  const lead = state === 'waiting' ? 'The person has not decided yet. Nothing has changed.' : 'Nothing has changed yet: coffre asks the person to approve this on its own page.';
  const next = `Once they have approved or denied it, call ${tool.name} again with the same arguments: it answers what became of it.`;
  return {
    content: [{ type: 'text', text: [lead, `Show them this link, to open signed in to coffre (it expires at ${expires}):`, '', `  ${url}`, '', next].join('\n') }],
    // Some clients give the model this rather than the text: it says the same.
    structuredContent: { status: 'pending', message: `${lead} Show the person the approval's url, to open signed in to coffre. ${next}`, approval },
  };
}

/** What the API answered a tool's call with, when it refused it, or could not answer; null for a bug. */
function refusalOf(error: unknown): { code: string; message: string; reason: string | undefined } | null {
  if (!(error instanceof CoffreError) || (error.status >= 500 && error.status !== 503)) return null;
  return { code: error.code, message: error.message, reason: error.reason };
}

function toolError(text: string): Record<string, unknown> {
  return { content: [{ type: 'text', text }], isError: true };
}

/**
 * A tool beyond the connection's scopes: 403, with what to ask for, which
 * is everything it holds and what it lacks (RFC 6750, section 3.1), for a
 * client that steps up, as Claude Code does. Not every one does, Claude
 * Desktop among them: the body is the tool's result, an error that tells
 * the model, in plain words, what its person does to grant the scope
 * (docs/design/mcp.md, section 5).
 */
function insufficientScope(runtime: CoffreRuntime, connection: McpConnection, tool: Tool, id: JsonRpcId, needed: McpScope): Response {
  const scope = scopeString(challengeScopes(connection.scopes, needed));
  return rpc(id, { result: toolError(missingScope(tool, needed)) }, 403, {
    'www-authenticate': `Bearer error="insufficient_scope", scope="${scope}", resource_metadata="${resourceMetadataUrl(runtime)}", error_description="${tool.name} needs ${needed}"`,
  });
}

/** What the model is told of a scope its connection lacks: only its person can grant it, by connecting again. */
function missingScope(tool: Tool, needed: McpScope): string {
  const { label } = MCP_SCOPE_INFO[needed];
  return [
    `${tool.name} needs coffre's ${label} scope, which this connection was not given. Nothing was done.`,
    `Only the person can grant it: they disconnect coffre in this app and connect it again, ticking ${label} on coffre's consent page. The new connection replaces this one.`,
    'In Claude (claude.ai, Desktop): disconnect coffre under Customize > Connectors, then connect it again. In Claude Code: /mcp, coffre, then Re-authenticate.',
  ].join('\n');
}
