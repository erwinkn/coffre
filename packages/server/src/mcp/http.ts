// MCP's OAuth over HTTP: the two metadata documents, the token,
// registration and revocation endpoints, and what `/mcp` answers a request
// without a good token (docs/design/mcp.md, section 4). `app.ts` routes to
// them and checks the method.
import { MCP_SCOPES } from '@coffre/core/mcp';

import { ApiError, notFound } from '../api/errors.ts';
import { bearerToken } from '../auth.ts';
import { errorResponse, jsonResponse, readLimitedJson, readLimitedText } from '../http.ts';
import { logged } from '../logged.ts';
import type { CoffreRuntime } from '../runtime.ts';
import { OAuthError, type McpConnection, type McpService } from './service.ts';

/** What any OAuth endpoint reads of a body: a few short fields. */
const BODY_BYTES = 16 * 1024;

const NO_STORE = { 'cache-control': 'no-store', pragma: 'no-cache' };

function mcpOf(runtime: CoffreRuntime): McpService | Response {
  return runtime.mcp ?? errorResponse(notFound("this instance serves no MCP: the deployment's signin({ mcp }) turns it on"));
}

/** Where the protected resource's metadata is: the path-suffixed form, which clients try first (RFC 9728, section 3.1). */
export function resourceMetadataUrl(runtime: CoffreRuntime): string {
  return `${runtime.publicUrl}/.well-known/oauth-protected-resource/mcp`;
}

/** `GET /.well-known/oauth-protected-resource[/mcp]`: the MCP endpoint, and who issues its tokens. */
export async function protectedResource(_request: Request, runtime: CoffreRuntime): Promise<Response> {
  const mcp = mcpOf(runtime);
  if (mcp instanceof Response) return mcp;
  return jsonResponse({
    resource: mcp.resource,
    authorization_servers: [mcp.issuer],
    // The minimum: the rest come one step-up at a time.
    scopes_supported: ['browse'],
    bearer_methods_supported: ['header'],
    resource_name: `coffre at ${new URL(runtime.publicUrl).host}`,
  });
}

/** `GET /.well-known/oauth-authorization-server` (RFC 8414). */
export async function authorizationServer(_request: Request, runtime: CoffreRuntime): Promise<Response> {
  const mcp = mcpOf(runtime);
  if (mcp instanceof Response) return mcp;
  const base = runtime.publicUrl;
  return jsonResponse({
    issuer: mcp.issuer,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/api/oauth/token`,
    registration_endpoint: `${base}/api/oauth/register`,
    revocation_endpoint: `${base}/api/oauth/revoke`,
    scopes_supported: [...MCP_SCOPES, 'offline_access'],
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    revocation_endpoint_auth_methods_supported: ['none'],
    // Claude uses a metadata document only when both this and `none` above are there.
    client_id_metadata_document_supported: true,
    authorization_response_iss_parameter_supported: true,
  });
}

function oauthError(error: unknown): Response {
  if (error instanceof OAuthError) {
    return jsonResponse({ error: error.error, error_description: error.message }, error.status, {
      ...NO_STORE,
      ...(error.status === 429 ? { 'retry-after': '60' } : {}),
    });
  }
  if (error instanceof ApiError && error.code === 'unavailable') {
    return jsonResponse({ error: 'temporarily_unavailable', error_description: error.message }, 503, NO_STORE);
  }
  if (error instanceof ApiError && error.code === 'bad_request') {
    return jsonResponse({ error: 'invalid_request', error_description: error.message }, 400, NO_STORE);
  }
  console.error('oauth endpoint failed', logged(error));
  return jsonResponse({ error: 'server_error', error_description: 'something went wrong; see the server log' }, 500, NO_STORE);
}

/** A form-encoded body, every field at most once (RFC 6749, section 3.2). */
async function form(request: Request): Promise<URLSearchParams> {
  const type = request.headers.get('content-type') ?? '';
  if (!/^application\/x-www-form-urlencoded\b/i.test(type)) {
    throw new OAuthError('invalid_request', 'send the request as application/x-www-form-urlencoded');
  }
  const params = new URLSearchParams(await readLimitedText(request, BODY_BYTES));
  for (const name of new Set(params.keys())) {
    if (params.getAll(name).length > 1) throw new OAuthError('invalid_request', `${name} appears more than once`);
  }
  return params;
}

/**
 * `POST /api/oauth/token`: a code, then refresh tokens, for access tokens.
 * Admission first, both limits, before the body or the database.
 */
export async function oauthToken(request: Request, runtime: CoffreRuntime, sourceIp: string | null): Promise<Response> {
  const mcp = mcpOf(runtime);
  if (mcp instanceof Response) return mcp;
  try {
    await mcp.admit(sourceIp);
    const answer = await mcp.token(await form(request), { requestId: crypto.randomUUID(), sourceIp });
    return jsonResponse(answer, 200, NO_STORE);
  } catch (error) {
    return oauthError(error);
  }
}

/** `POST /api/oauth/register` (RFC 7591): JSON, unlike the token endpoint. */
export async function oauthRegister(request: Request, runtime: CoffreRuntime, sourceIp: string | null): Promise<Response> {
  const mcp = mcpOf(runtime);
  if (mcp instanceof Response) return mcp;
  try {
    await mcp.admit(sourceIp);
    const body = await readLimitedJson(request, BODY_BYTES).catch((error: unknown) => {
      throw error instanceof ApiError ? new OAuthError('invalid_client_metadata', error.message) : error;
    });
    return jsonResponse(await mcp.register(body, { requestId: crypto.randomUUID(), sourceIp }), 201, NO_STORE);
  } catch (error) {
    return oauthError(error);
  }
}

/** `POST /api/oauth/revoke` (RFC 7009): 200 whatever the token, so it tells nobody which exist. */
export async function oauthRevoke(request: Request, runtime: CoffreRuntime, sourceIp: string | null): Promise<Response> {
  const mcp = mcpOf(runtime);
  if (mcp instanceof Response) return mcp;
  try {
    await mcp.admit(sourceIp);
    await mcp.revoke(await form(request), { requestId: crypto.randomUUID(), sourceIp });
    return new Response(null, { status: 200, headers: NO_STORE });
  } catch (error) {
    return oauthError(error);
  }
}

/**
 * What `/mcp` answers without a good token: 401, and where to find out how
 * to get one (RFC 9728, section 5.1), with the minimum scope to ask for.
 * Claude starts its sign-in on exactly this, and only on a 401.
 */
export function unauthorized(runtime: CoffreRuntime, presented: boolean): Response {
  const challenge = [
    ...(presented ? ['error="invalid_token"', 'error_description="the token is unknown, expired or revoked"'] : []),
    `resource_metadata="${resourceMetadataUrl(runtime)}"`,
    'scope="browse"',
  ];
  return jsonResponse(
    { error: presented ? 'invalid_token' : 'unauthorized', error_description: presented ? 'the token is unknown, expired or revoked' : 'connect with OAuth first' },
    401,
    { 'www-authenticate': `Bearer ${challenge.join(', ')}` },
  );
}

/**
 * The connection a request to `/mcp` comes from, or what to answer it:
 * a request from another site's page is refused before anything (the
 * spec's Origin check), and one without a good token is told how to get
 * one.
 */
export async function mcpCaller(request: Request, runtime: CoffreRuntime, sourceIp: string | null): Promise<McpConnection | Response> {
  const mcp = mcpOf(runtime);
  if (mcp instanceof Response) return mcp;
  const origin = request.headers.get('origin');
  if (origin !== null && origin !== runtime.publicUrl) {
    return errorResponse(new ApiError('cross_origin', 'MCP clients are not web pages: a request from another site is refused'));
  }
  const token = bearerToken(request);
  if (token === null) return unauthorized(runtime, false);
  try {
    return (await mcp.authenticate(token, { sourceIp })) ?? unauthorized(runtime, true);
  } catch (error) {
    if (error instanceof ApiError) return errorResponse(error);
    console.error('mcp token check failed', logged(error));
    return errorResponse(new ApiError('unavailable', 'coffre cannot check this token right now'));
  }
}
