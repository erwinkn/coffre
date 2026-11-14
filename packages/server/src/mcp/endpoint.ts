// `POST /mcp`: the MCP endpoint (docs/design/mcp.md, section 2; docs/design/0.16.md,
// "`/mcp`"). One JSON answer per request, never a stream, and no session: the
// 2026-07-28 revision, whose requests each carry their version and the
// client's capabilities in `_meta`, and the 2025 era's `initialize` beside
// it, which coffre answers without minting a session either. Both serve the
// same tools, with the same checks. The vault is asked who the access token
// is first (`caller`): nothing here runs for a request without a good one.
import { MCP_SCOPE_INFO, scopeString, type McpScope } from '@coffre/core/mcp';
import { tokenKind } from '@coffre/core/identity';
import { isUnavailable } from '@coffre/db/dialect';
import { z } from 'zod';

import type { ApiContext } from '../api/context.ts';
import { ApiError, keyServiceDown, toErrorBody } from '../api/errors.ts';
import { bearerToken, presented } from '../auth.ts';
import { errorResponse, jsonResponse, readLimitedJson } from '../http.ts';
import { logged } from '../logged.ts';
import type { CoffreRuntime } from '../runtime.ts';
import { COFFRE_VERSION } from '../version.ts';
import { resourceMetadataUrl } from './http.ts';
import { mcpOf } from './oauth.ts';
import { findApproval } from '../db/queries/approvals.ts';
import { approvalUrl, approvalWait, ask, MAX_PENDING, named, OUTCOME_SECONDS, outcomeOf, settle, statusOf } from './approvals.ts';
import { INSTRUCTIONS, listed, TOOL_BY_NAME, TOOLS, type Connection, type Tool, type ToolContext, usable } from './tools.ts';

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
  const caller = await connectionOf(request, runtime, sourceIp);
  if (caller instanceof Response) return caller;
  let body: unknown;
  try {
    body = await readLimitedJson(request, BODY_BYTES);
  } catch (error) {
    // A malformed body is a parse error; a well-formed one the guard refuses (too large, or a `__proto__` key) is an
    // invalid request, told as such rather than as broken JSON.
    return error instanceof ApiError && error.message !== 'the body is not JSON'
      ? failure(null, 400, { code: CODE.invalidRequest, message: `Invalid Request: ${error.message}` })
      : failure(null, 400, { code: CODE.parse, message: 'Parse error: the body is not JSON' });
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
  caller: Connection,
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
      return call(runtime, caller, message, id, (result) => complete(result), { era: 'modern', elicitsUrl: elicitsUrl(capabilities as Record<string, unknown>) });
    default:
      return failure(id, 404, { code: CODE.methodNotFound, message: `Method not found: ${message.method}` });
  }
}

// --- 2025-11-25 and 2025-06-18 ----------------------------------------------

async function legacy(
  request: Request,
  runtime: CoffreRuntime,
  sourceIp: string | null,
  caller: Connection,
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
      return call(runtime, caller, message, id, (result) => rpc(id, { result }), { era: 'legacy', elicitsUrl: false });
    default:
      return rpc(id, { error: { code: CODE.methodNotFound, message: `Method not found: ${message.method}` } });
  }
}

/**
 * The tools a person's roles let them use somewhere, as they are on this
 * request: the vault's answer about the token, so listing costs no read of
 * its own. A tool only the connection's scopes withhold
 * stays listed: calling it asks for the scope.
 */
function toolsFor(connection: Connection): Record<string, unknown>[] {
  return TOOLS.filter((tool) => usable(connection.called, tool)).map(listed);
}

// --- the access token ---------------------------------------------------------

/** No token, or one that does not stand: where to get one (RFC 9728, section 5.1), and the minimum to ask for. */
function unauthorized(runtime: CoffreRuntime, presented: boolean): Response {
  const challenge = [
    ...(presented ? ['error="invalid_token"', 'error_description="the token is unknown, expired or revoked"'] : []),
    `resource_metadata="${resourceMetadataUrl(runtime)}"`,
    'scope="read"',
  ];
  return jsonResponse(
    { error: presented ? 'invalid_token' : 'unauthorized', error_description: presented ? 'the token is unknown, expired or revoked' : 'connect with OAuth first' },
    401,
    { 'www-authenticate': `Bearer ${challenge.join(', ')}` },
  );
}

/**
 * The connection a request to `/mcp` comes on, or what to answer it: a
 * request from another site's page is refused before anything, and one
 * whose bearer is no access token's shape asks the vault nothing. Else the
 * vault's `caller` decides, on the token's hash: its connection must stand,
 * of the same person and generation (docs/design/0.16.md, "An MCP
 * connection"). It remembers its answer two seconds, as for any credential.
 */
async function connectionOf(request: Request, runtime: CoffreRuntime, sourceIp: string | null): Promise<Connection | Response> {
  if (mcpOf(runtime.auth) === null) return errorResponse(new ApiError('not_found', "this instance serves no MCP: the deployment's signin({ mcp }) turns it on"));
  const origin = request.headers.get('origin');
  if (origin !== null && origin !== runtime.publicUrl) {
    return errorResponse(new ApiError('cross_origin', 'MCP clients are not web pages: a request from another site is refused'));
  }
  const token = bearerToken(request);
  if (token === null) return unauthorized(runtime, false);
  if (tokenKind(token) !== 'mcp') return unauthorized(runtime, true);
  const shown = presented(token, sourceIp);
  let answer: Awaited<ReturnType<CoffreRuntime['vault']['caller']>>;
  try {
    answer = await runtime.vault.caller(shown);
  } catch (error) {
    return errorResponse(error);
  }
  // An access token's refusal is one: unknown, ended, expired, its connection's or its person's, or a row the vault did not write.
  if ('refused' in answer) return unauthorized(runtime, true);
  const { connection, scopes } = answer.credential;
  // Only an access token has both: the vault answers them for kind `mcp` alone.
  if (connection === undefined || scopes === undefined) return unauthorized(runtime, true);
  return { called: answer, id: connection, scopes, shown };
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

/** A connection's calls, against its own limit; a limiter that fails refuses, and is logged. */
async function admitCall(runtime: CoffreRuntime, connection: Connection): Promise<boolean> {
  try {
    return (await mcpOf(runtime.auth)!.mcp.limits.perConnection.limit({ key: `connection:${connection.id}` })).success;
  } catch (error) {
    console.error('mcp limiter failed', { request: connection.shown.request, connection: connection.id, error: logged(error) });
    return false;
  }
}

/**
 * One tool's call: admitted against its connection's limit, held to its
 * scopes, and run as the API's handlers in process, as the connection, on
 * the vault's answer about it. A refusal the API gives is the tool's
 * result, an error the model reads; a scope the connection lacks is a 403
 * that starts the client's step-up, whose body is such a result too, for a
 * client that does not. No entry of its own: the vault's `use` logs a
 * reveal, under the access token, as it logs any read of a value.
 */
async function call(runtime: CoffreRuntime, connection: Connection, message: Message, id: JsonRpcId, answer: (result: Record<string, unknown>) => Response, client: ClientSays): Promise<Response> {
  if (!(await admitCall(runtime, connection))) {
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
  if (!connection.scopes.includes(tool.scope)) return insufficientScope(runtime, connection, tool, id, tool.scope);

  // The API's context as the connection: its token's hash for every vault call, and the vault's answer about it, already asked.
  const ctx: ApiContext = {
    db: runtime.db,
    vault: runtime.vault,
    shown: connection.shown,
    caller: async () => connection.called,
    crossSite: false,
    auth: runtime.auth,
    rotateAfterDays: runtime.rotateAfterDays,
    transport: runtime.transport,
  };
  try {
    if (tool.change !== undefined) return await change(runtime, { ctx, connection }, tool, args.data, params.data, { answer, client, id });
    const result = await tool.run!({ ctx, connection }, args.data as never);
    return answer({
      content: [{ type: 'text', text: result.text ?? JSON.stringify(result.structured, null, 2) }],
      structuredContent: result.structured,
    });
  } catch (error) {
    const refused = refusalOf(error);
    if (refused === null) throw error;
    // The vault holds a value to `reveal` too: a connection whose scopes changed under the call is asked for it as ever.
    if (refused.reason === 'mcp_no_reveal') return insufficientScope(runtime, connection, tool, id, 'reveal');
    return answer(toolError(refused.message));
  }
}

/**
 * A change's call (docs/design/mcp.md, section 7). Nothing changes here: a
 * call that names no approval asks the vault for one (`mcp.ask`), or joins
 * the one the same call waits on, and the person decides it on coffre's
 * page, which makes the change. A client that can open a URL is asked to,
 * by an elicitation, and retries with the `requestState` coffre gave it,
 * the approval's id; any other gets the link in the result, to show its
 * person, and calls again with the same arguments and the approval's id
 * (`approval`). A call that names its approval, either way, only reads
 * how it ended, waiting a while for it (`approvalWait`): as often as it
 * likes, writing nothing. The id is no secret: the row says which
 * connection and which call it is for, and it serves no other.
 */
async function change(
  runtime: CoffreRuntime,
  { ctx, connection }: ToolContext,
  tool: Tool,
  input: unknown,
  params: z.infer<typeof CallParams>,
  { answer, client, id }: { answer: (result: Record<string, unknown>) => Response; client: ClientSays; id: JsonRpcId },
): Promise<Response> {
  // The call is its other arguments: the approval it names is how it asks, not what.
  const { approval: argued, ...args } = input as Record<string, unknown> & { approval?: string };
  const url = (approval: string) => approvalUrl(runtime.publicUrl, approval);
  const prompt = (approval: string, ask: boolean) =>
    answer({
      resultType: 'input_required',
      ...(ask ? { inputRequests: { approve: { method: 'elicitation/create', params: { mode: 'url', url: url(approval), message: `Approve on coffre: ${tool.change!.summary(args as never)}` } } } } : {}),
      requestState: approval,
    });

  let row;
  const naming = (client.era === 'modern' ? params.requestState : undefined) ?? argued;
  if (naming !== undefined) {
    const found = await named(ctx, connection.id, naming, tool, args);
    if (found === 'unknown') return rpc(id, { error: { code: CODE.invalidParams, message: 'Invalid params: no such approval' } });
    if (found === 'other_call') return rpc(id, { error: { code: CODE.invalidParams, message: 'Invalid params: this approval is not for this call' } });
    if (found.createdAt.getTime() + OUTCOME_SECONDS * 1000 <= found.now.getTime()) return answer(toolError(`This approval has expired: call ${tool.name} again without approval to ask the person anew.`));
    const response = params.inputResponses?.approve as { action?: unknown } | undefined;
    if (statusOf(found) === 'pending') {
      // Declined: the person said no to opening the page. The approval waits on, and holds its place among the five,
      // until they decide it or it expires: a client that asks and declines in a loop opens no more than five.
      if (response?.action === 'decline') return answer(toolError(`The person declined to open coffre's page: nothing changed. Don't ask again unless they want you to.`));
      // Cancelled: the prompt was dismissed, or a client that cannot ask anyone (Claude Code with -p) answered it, so the link goes to the model instead.
      if (response?.action === 'cancel') return answer(pending(url(found.id), found, tool, 'asked'));
    }
    row = found;
  } else {
    await tool.change!.check?.({ ctx, connection }, args as never);
    const asked = await ask(ctx, connection.id, tool, args);
    if ('full' in asked) return answer(toolError(`${MAX_PENDING} changes are waiting for the person already: ask them to decide those on coffre first.`));
    if (!asked.joined || client.elicitsUrl) return client.elicitsUrl ? prompt(asked.id, true) : answer(pending(url(asked.id), asked, tool, 'asked'));
    row = (await findApproval(ctx.db, asked.id, OUTCOME_SECONDS))!;
  }

  const settled = await settle(ctx, row, Date.now() + approvalWait.ms);
  const status = statusOf(settled);
  if (status === 'pending') return client.elicitsUrl ? prompt(settled.id, false) : answer(pending(url(settled.id), settled, tool, 'waiting'));
  const outcome = outcomeOf(settled, tool)!;
  const structured = {
    status,
    message: outcome.text,
    approval: { id: settled.id, url: url(settled.id), expiresAt: settled.expiresAt.toISOString() },
    ...(outcome.result === undefined ? {} : { result: outcome.result }),
  };
  return answer({ content: [{ type: 'text', text: outcome.text }], structuredContent: structured, ...(status === 'approved' ? {} : { isError: true }) });
}

/**
 * What a client that cannot open a URL is told while its change waits:
 * the link, for its person, once `asked`, and while it is `waiting` on
 * them, with the approval's id to call again with.
 */
function pending(url: string, approval: { id: string; expiresAt: Date }, tool: Tool, state: 'asked' | 'waiting'): Record<string, unknown> {
  const shown = { id: approval.id, url, expiresAt: approval.expiresAt.toISOString() };
  const expires = approval.expiresAt.toISOString().replace(/\.\d+Z$/, 'Z');
  const lead = state === 'waiting' ? 'The person has not decided yet. Nothing has changed.' : 'Nothing has changed yet: coffre asks the person to approve this on its own page.';
  const next = `Once they have approved or denied it, call ${tool.name} again with the same arguments and approval: "${approval.id}". It answers what became of it.`;
  return {
    content: [{ type: 'text', text: [lead, `Show them this link, to open signed in to coffre (it expires at ${expires}):`, '', `  ${url}`, '', next].join('\n') }],
    // Some clients give the model this rather than the text: it says the same.
    structuredContent: { status: 'pending', message: `${lead} Show the person the approval's url, to open signed in to coffre. ${next}`, approval: shown },
  };
}

/**
 * What the API answered a tool's call with, when it refused it or could not answer; null for a bug, or a row the vault
 * did not write. A handler called in-process throws what the router would have mapped: the database or the vault's
 * transport not answering among it, which is the tool's error, to try again, as the API's 503 `unavailable` is.
 */
function refusalOf(error: unknown): { message: string; reason: string | undefined } | null {
  if (!(error instanceof ApiError) && !(error instanceof z.ZodError) && !isUnavailable(error) && !keyServiceDown(error)) return null;
  const { status, body } = toErrorBody(error);
  if (status >= 500 && status !== 501 && status !== 503) return null;
  return { message: body.message, reason: body.reason };
}

function toolError(text: string): Record<string, unknown> {
  return { content: [{ type: 'text', text }], isError: true };
}

/**
 * A tool beyond the connection's scopes: 403, with what to ask for, which
 * is everything it holds and what it lacks (RFC 6750, section 3.1), for a
 * client that steps up, as Claude Code does; a client asks for exactly what
 * the challenge says. Not every one does, Claude Desktop among them: the
 * body is the tool's result, an error that tells the model, in plain
 * words, what its person does to grant the scope (docs/design/mcp.md,
 * section 5).
 */
function insufficientScope(runtime: CoffreRuntime, connection: Connection, tool: Tool, id: JsonRpcId, needed: McpScope): Response {
  const scope = scopeString(connection.scopes.includes(needed) ? connection.scopes : [...connection.scopes, needed]);
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
