// MCP's OAuth over HTTP (docs/design/0.16.md, "MCP connections"): the two
// metadata documents, and the token, registration and revocation endpoints,
// each one call to the vault and no statement of the app's. `app.ts` routes
// to them and checks the method.
import { generateToken, hashToken, tokenKind } from '@coffre/core/identity';
import { ClientInvalid, clientName, MCP_SCOPES, parseScopes, redirectKind, registrationRedirects, scopeString, type McpScope } from '@coffre/core/mcp';
import type { Asked } from '@coffre/core/vault';

import { ApiError, noteTampered, refusal, toErrorBody, UNAVAILABLE_RETRY_AFTER } from '../api/errors.ts';
import { errorResponse, jsonResponse, readLimitedJson, readLimitedText } from '../http.ts';
import { logged } from '../logged.ts';
import type { CoffreRuntime } from '../runtime.ts';
import { admit, isResource, mcpOf, OAuthError, resourceOf } from './oauth.ts';

type Path = (request: Request, runtime: CoffreRuntime, sourceIp: string | null) => Promise<Response>;

/** What any OAuth endpoint reads of a body: a few short fields. */
const BODY_BYTES = 16 * 1024;

const NO_STORE = { 'cache-control': 'no-store', pragma: 'no-cache' };

/** A PKCE verifier (RFC 7636, section 4.1). */
const VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;
/** The longest client id the vault keeps (`text` in its ops). */
const MOST_CLIENT_ID = 256;

const hashed = (token: string) => hashToken(token).toString('hex');

/** The deployment's MCP, or the 404 of one that serves none. */
function served(runtime: CoffreRuntime) {
  return mcpOf(runtime.auth) ?? errorResponse(new ApiError('not_found', "this instance serves no MCP: the deployment's signin({ mcp }) turns it on"));
}

/** Where the protected resource's metadata is: the path-suffixed form, which clients try first (RFC 9728, section 3.1). */
export const resourceMetadataUrl = (runtime: CoffreRuntime) => `${runtime.publicUrl}/.well-known/oauth-protected-resource/mcp`;

/** `GET /.well-known/oauth-protected-resource[/mcp]`: the MCP endpoint, and who issues its tokens. */
export const protectedResource: Path = async (_request, runtime) => {
  const mcp = served(runtime);
  if (mcp instanceof Response) return mcp;
  return jsonResponse({
    resource: resourceOf(runtime.publicUrl),
    authorization_servers: [runtime.publicUrl],
    // The minimum, which clients ask for: the person ticks the rest on the consent page.
    scopes_supported: ['read'],
    bearer_methods_supported: ['header'],
    resource_name: `coffre at ${new URL(runtime.publicUrl).host}`,
  });
};

/** `GET /.well-known/oauth-authorization-server` (RFC 8414). */
export const authorizationServer: Path = async (_request, runtime) => {
  const mcp = served(runtime);
  if (mcp instanceof Response) return mcp;
  const base = runtime.publicUrl;
  return jsonResponse({
    issuer: base,
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
};

function oauthError(error: unknown): Response {
  if (error instanceof OAuthError) {
    return jsonResponse({ error: error.error, error_description: error.message }, error.status, {
      ...NO_STORE,
      ...(error.status === 429 ? { 'retry-after': '60' } : error.status === 503 ? { 'retry-after': UNAVAILABLE_RETRY_AFTER } : {}),
    });
  }
  // Anything else as the API maps and logs it (`toErrorBody`): coffre not answering for a moment, a lock or a connection
  // that gave up included, is the client's to ask again; a request that is wrong is the client's to fix.
  const { status, body } = toErrorBody(error);
  if (status === 503) return jsonResponse({ error: 'temporarily_unavailable', error_description: body.message }, 503, { ...NO_STORE, 'retry-after': UNAVAILABLE_RETRY_AFTER });
  if (status === 400) return jsonResponse({ error: 'invalid_request', error_description: body.message }, 400, NO_STORE);
  // `toErrorBody` logged what it did not know, and `noteTampered` a row the vault did not write; a refusal of the API's has no place here.
  if (status !== 500) console.error('oauth endpoint failed', logged(error));
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

function required(form: URLSearchParams, name: string): string {
  const value = form.get(name);
  if (value === null || value === '') throw new OAuthError('invalid_request', `${name} is required`);
  return value;
}

/** A refusal no client's request words: a row written behind the vault (said once in the server's log), or the vault not yet in charge. */
function fault(route: string, request: string, code: string): ApiError {
  const error = refusal(code);
  noteTampered(error, route, request);
  return error;
}

/** The vault's refusals of a token request, as OAuth words them (RFC 6749, section 5.2). */
const GRANT_REFUSED: Record<string, [string, string]> = {
  unknown_grant: ['invalid_grant', 'unknown code or refresh token, or its connection has ended'],
  expired: ['invalid_grant', 'that code has expired, or its connection has ended: connect again'],
  wrong_client: ['invalid_grant', 'that code or refresh token is for another client'],
  wrong_redirect: ['invalid_grant', 'the redirect_uri is not the one the code was sent to'],
  wrong_verifier: ['invalid_grant', 'the code_verifier does not match the code_challenge'],
  deactivated: ['invalid_grant', 'the person who connected this app is no longer a member as they were'],
  invalid_scope: ['invalid_scope', 'a refresh may narrow the scopes, not widen them'],
};

/** Whether a redirect is one the vault keeps: HTTPS, or HTTP on loopback, of 400 characters at most. */
function keptRedirect(value: string): boolean {
  try {
    redirectKind(value);
    return value.length <= 400;
  } catch {
    return false;
  }
}

/**
 * `POST /api/oauth/token`: a code, then refresh tokens, for an access token
 * and the next refresh token, which the app draws and the vault keeps by
 * their SHA-256. Admission first, both limits, before the body. One
 * `change`, `mcp.token`; a code or a refresh token presented after it was
 * replaced ends the connection, and is answered `invalid_grant`.
 */
export const oauthToken: Path = async (request, runtime, sourceIp) => {
  const mcp = served(runtime);
  if (mcp instanceof Response) return mcp;
  try {
    await admit(mcp.mcp.limits, sourceIp);
    const params = await form(request);
    const resource = params.get('resource');
    if (resource !== null && !isResource(runtime.publicUrl, resource)) throw new OAuthError('invalid_target', `coffre issues tokens for ${resourceOf(runtime.publicUrl)} only`);
    const client = required(params, 'client_id');
    if (client.length > MOST_CLIENT_ID) throw new OAuthError('invalid_grant', GRANT_REFUSED.wrong_client![1]);
    const tokens = { access: generateToken('mcp'), refresh: generateToken('mcp-refresh') };
    const asked = { request: crypto.randomUUID(), ip: sourceIp, op: 'mcp.token' as const, client, tokens: { access: hashed(tokens.access), refresh: hashed(tokens.refresh) } };
    let change: Asked<'mcp.token'>;
    const grant = params.get('grant_type');
    if (grant === 'authorization_code') {
      const [code, verifier, redirectUri] = [required(params, 'code'), required(params, 'code_verifier'), required(params, 'redirect_uri')];
      if (!VERIFIER.test(verifier)) throw new OAuthError('invalid_grant', GRANT_REFUSED.wrong_verifier![1]);
      if (!keptRedirect(redirectUri)) throw new OAuthError('invalid_grant', GRANT_REFUSED.wrong_redirect![1]);
      // A CLI login's days, which the configuration holds to 365, the vault's ceiling, in whole minutes.
      const minutes = Math.max(1, Math.round(mcp.cliSessionDays * 24 * 60));
      change = { ...asked, grant, code: hashed(code), verifier, redirectUri, minutes };
    } else if (grant === 'refresh_token') {
      const refresh = required(params, 'refresh_token');
      const scope = params.get('scope');
      let scopes: McpScope[] | null = null;
      if (scope !== null) {
        const parsed = parseScopes(scope);
        if (parsed.unknown.length > 0) throw new OAuthError('invalid_scope', `unknown scopes: ${parsed.unknown.join(', ')}`);
        // `read` among them always, as every connection holds it.
        scopes = parsed.scopes;
      }
      change = { ...asked, grant, refresh: hashed(refresh), scopes };
    } else {
      throw new OAuthError('unsupported_grant_type', 'coffre takes authorization_code and refresh_token');
    }
    const at = Date.now();
    const answered = await runtime.vault.change<'mcp.token'>(change);
    if ('refused' in answered) {
      const worded = GRANT_REFUSED[answered.refused];
      throw worded === undefined ? fault('POST /api/oauth/token', asked.request, answered.refused) : new OAuthError(worded[0], worded[1]);
    }
    const { answer } = answered;
    if (answer.ended) {
      const what = grant === 'authorization_code' ? 'that code' : 'that refresh token';
      throw new OAuthError('invalid_grant', `${what} was used already; the connection it made is ended`);
    }
    return jsonResponse({
      access_token: tokens.access,
      token_type: 'Bearer',
      expires_in: Math.max(0, Math.floor((Date.parse(answer.expiresAt) - at) / 1000)),
      refresh_token: tokens.refresh,
      scope: scopeString(answer.scopes),
    }, 200, NO_STORE);
  } catch (error) {
    return oauthError(error);
  }
};

/**
 * `POST /api/oauth/register` (RFC 7591), the fallback to metadata
 * documents: public clients only, with the redirects coffre accepts and the
 * others left out. JSON, unlike the token endpoint. What bounds it: the
 * limits first, then the vault's ceiling on the table (`oauth.register`).
 */
export const oauthRegister: Path = async (request, runtime, sourceIp) => {
  const mcp = served(runtime);
  if (mcp instanceof Response) return mcp;
  try {
    await admit(mcp.mcp.limits, sourceIp);
    const body = await readLimitedJson(request, BODY_BYTES).catch((error: unknown) => {
      throw error instanceof ApiError ? new OAuthError('invalid_client_metadata', error.message) : error;
    });
    if (typeof body !== 'object' || body === null || Array.isArray(body)) throw new OAuthError('invalid_client_metadata', 'the registration is not a JSON object');
    const fields = body as Record<string, unknown>;
    const method = fields.token_endpoint_auth_method;
    if (method !== undefined && method !== 'none') {
      throw new OAuthError('invalid_client_metadata', 'coffre registers public clients only: token_endpoint_auth_method must be none');
    }
    let redirects: string[];
    try {
      redirects = registrationRedirects(fields.redirect_uris).kept;
    } catch (error) {
      if (error instanceof ClientInvalid) throw new OAuthError('invalid_redirect_uri', error.message);
      throw error;
    }
    const name = clientName(fields.client_name, 'Unnamed app');
    const trace = { request: crypto.randomUUID(), ip: sourceIp };
    const answered = await runtime.vault.change<'oauth.register'>({ ...trace, op: 'oauth.register', name, redirectUris: redirects });
    if ('refused' in answered) {
      if (answered.refused === 'full') throw new OAuthError('temporarily_unavailable', 'coffre holds as many registered apps as it takes: an app with a client metadata document connects without one', 503);
      throw fault('POST /api/oauth/register', trace.request, answered.refused);
    }
    return jsonResponse({
      client_id: answered.answer.client,
      client_id_issued_at: Math.floor(Date.parse(answered.answer.createdAt) / 1000),
      client_name: name,
      redirect_uris: redirects,
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    }, 201, NO_STORE);
  } catch (error) {
    return oauthError(error);
  }
};

/**
 * `POST /api/oauth/revoke` (RFC 7009): either token ends its connection,
 * `mcp.revoke`. 200 whatever the token, so it tells nobody which exist; one
 * that is not an MCP token's shape is not asked about.
 */
export const oauthRevoke: Path = async (request, runtime, sourceIp) => {
  const mcp = served(runtime);
  if (mcp instanceof Response) return mcp;
  try {
    await admit(mcp.mcp.limits, sourceIp);
    const params = await form(request);
    const token = required(params, 'token');
    const client = params.get('client_id') || null;
    const kind = tokenKind(token);
    if ((kind === 'mcp' || kind === 'mcp-refresh') && (client === null || client.length <= MOST_CLIENT_ID)) {
      const trace = { request: crypto.randomUUID(), ip: sourceIp };
      const answered = await runtime.vault.change<'mcp.revoke'>({ ...trace, op: 'mcp.revoke', token: hashed(token), client });
      if ('refused' in answered && answered.refused !== 'unknown_grant') throw fault('POST /api/oauth/revoke', trace.request, answered.refused);
    }
    return new Response(null, { status: 200, headers: NO_STORE });
  } catch (error) {
    return oauthError(error);
  }
};
