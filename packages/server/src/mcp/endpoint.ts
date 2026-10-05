// `POST /mcp`: the MCP endpoint (docs/design/mcp.md, section 2). For now,
// a connection's token and what the server is: `server/discover`. The
// tools come next.
import { readLimitedJson } from '../http.ts';
import type { CoffreRuntime } from '../runtime.ts';
import { COFFRE_VERSION } from '../version.ts';
import { mcpCaller } from './http.ts';

/** The revision coffre speaks. */
export const PROTOCOL_VERSION = '2026-07-28';
const BODY_BYTES = 256 * 1024;

type JsonRpcId = string | number;

function rpc(id: JsonRpcId | null, body: { result: unknown } | { error: { code: number; message: string; data?: unknown } }, status = 200): Response {
  return Response.json({ jsonrpc: '2.0', ...(id === null ? {} : { id }), ...body }, { status, headers: { 'cache-control': 'no-store' } });
}

export async function mcpEndpoint(request: Request, runtime: CoffreRuntime, sourceIp: string | null): Promise<Response> {
  const caller = await mcpCaller(request, runtime, sourceIp);
  if (caller instanceof Response) return caller;
  let message: { id?: JsonRpcId; method?: unknown };
  try {
    message = (await readLimitedJson(request, BODY_BYTES)) as typeof message;
  } catch {
    return rpc(null, { error: { code: -32700, message: 'Parse error' } }, 400);
  }
  const id = typeof message?.id === 'string' || typeof message?.id === 'number' ? message.id : null;
  if (message?.method === 'server/discover') {
    return rpc(id, {
      result: {
        resultType: 'complete',
        supportedVersions: [PROTOCOL_VERSION],
        capabilities: { tools: {} },
        _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'coffre', version: COFFRE_VERSION } },
        ttlMs: 3_600_000,
        cacheScope: 'public',
      },
    });
  }
  return rpc(id, { error: { code: -32601, message: 'Method not found' } }, 404);
}
