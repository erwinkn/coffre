// coffre as the OAuth 2.1 authorization server of MCP clients
// (docs/design/0.16.md, "MCP connections"), what its paths share: whether
// the deployment turns MCP on, the limits of the paths anyone may call, and
// an authorization request checked, which the consent page shows and its
// Approve sends again. Every write is the vault's: `mcp.connect`,
// `mcp.token`, `mcp.revoke`, `oauth.register`.
import type { AuthConfig, McpConfig, McpLimits, SigninConfig } from '@coffre/core/identity';
import { ClientInvalid, clientIdKept, MAX_CLIENT_ID, parseScopes, redirectHost, redirectKind, redirectMatches, type ClientMetadata, type McpScope } from '@coffre/core/mcp';

import type { RegisteredClient } from '../db/queries/mcp.ts';
import { resolveClient, wouldFetch, type Fetching } from './clients.ts';

/** The sign-in of a deployment that turns MCP on (`signin({ mcp })`); null for one that does not, or that signs in behind Cloudflare Access. */
export function mcpOf(auth: AuthConfig): (SigninConfig & { mcp: McpConfig }) | null {
  return auth.mode === 'signin' && auth.signin.mcp !== null ? (auth.signin as SigninConfig & { mcp: McpConfig }) : null;
}

/** The MCP endpoint, the protected resource its tokens are for (RFC 8707). */
export const resourceOf = (publicUrl: string) => `${publicUrl}/mcp`;

/** An OAuth error, as the token, registration and revocation endpoints answer it (RFC 6749, section 5.2). */
export class OAuthError extends Error {
  readonly error: string;
  readonly status: number;
  constructor(error: string, description: string, status = 400) {
    super(description);
    this.name = 'OAuthError';
    this.error = error;
    this.status = status;
  }
}

/** The limits of what anyone may call, per source and in total, before anything is read or fetched; a limiter that fails refuses. */
export async function admit(limits: McpLimits, sourceIp: string | null): Promise<void> {
  let passed: boolean;
  try {
    const [source, all] = await Promise.all([limits.perSource.limit({ key: `source:${sourceIp ?? 'unknown'}` }), limits.total.limit({ key: 'total' })]);
    passed = source.success && all.success;
  } catch {
    throw new OAuthError('temporarily_unavailable', 'coffre cannot count requests right now: try again shortly', 503);
  }
  if (!passed) throw new OAuthError('slow_down', 'too many requests: try again in a minute', 429);
}

/** Whether a `resource` names the MCP endpoint, with a trailing slash or capitals in its origin. */
export function isResource(publicUrl: string, value: string): boolean {
  try {
    const url = new URL(value);
    return url.search === '' && url.hash === '' && `${url.origin}${url.pathname.replace(/\/$/, '')}` === resourceOf(publicUrl);
  } catch {
    return false;
  }
}

/** An authorization request's parameters, as the consent page carries them. */
export type AuthorizationRequest = {
  client_id?: string;
  redirect_uri?: string;
  response_type?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  state?: string;
  scope?: string;
  resource?: string;
};

/** What the consent page shows for a request. */
export type AuthorizationView =
  /** The client or its redirect is wrong: said on the page, and never redirected to. */
  | { status: 'invalid'; message: string }
  /** The client and redirect hold, the rest does not: said, with where to send the client its error. */
  | { status: 'refused'; message: string; redirect: string }
  | {
      status: 'ready';
      client: { id: string; name: string; host: string | null; registration: 'cimd' | 'dcr' };
      /** Where the answer goes: a host, or `localhost` for a native client on this machine. */
      redirectHost: string;
      /** Every redirect the client has is loopback: any program on the machine could be it. */
      loopbackOnly: boolean;
      /** What the client asks for, `read` always among them: what the page starts with ticked, of all four. */
      scopes: McpScope[];
      /** The scopes of each of the person's live connections of this client: one the approval supersedes ends. */
      connections: McpScope[][];
      /** How long the connection lasts, unless disconnected: a CLI login's days. */
      days: number;
    };

/** A request that holds: its client, the redirect, the S256 challenge, and the scopes asked. */
export type Checked = { status: 'ready'; client: ClientMetadata; redirectUri: string; challenge: string; scopes: McpScope[] };

/** An S256 challenge (RFC 7636, section 4.2): a SHA-256, base64url with no padding. */
const S256_CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
/** The longest redirect the vault keeps (`MOST_URI` in its ops). */
const MOST_REDIRECT = 400;

/**
 * An authorization request, checked in the order OAuth answers it: the
 * client and its redirect first, and wrong there, never redirected to;
 * then the rest, whose errors go back to the client. A metadata document
 * not fetched in the last ten minutes is fetched, within the limits.
 */
export async function checkAuthorization(
  mcp: SigninConfig & { mcp: McpConfig },
  fetching: Pick<Fetching, 'transport'>,
  request: AuthorizationRequest,
  registered: RegisteredClient | null,
  sourceIp: string | null,
): Promise<{ status: 'invalid'; message: string } | { status: 'refused'; message: string; redirect: string } | Checked> {
  const clientId = request.client_id ?? '';
  const redirectUri = request.redirect_uri ?? '';
  if (clientId === '') return { status: 'invalid', message: 'The app sent no client_id.' };
  if (redirectUri === '') return { status: 'invalid', message: 'The app sent no redirect_uri.' };
  if (!clientIdKept(clientId)) return { status: 'invalid', message: `The client_id is longer than ${MAX_CLIENT_ID} characters, or holds a NUL or half of a surrogate pair.` };
  let client: ClientMetadata;
  try {
    const { allowLoopback, limits } = mcp.mcp;
    if (wouldFetch(clientId, allowLoopback)) await admit(limits, sourceIp);
    client = await resolveClient({ transport: fetching.transport, allowLoopback }, clientId, registered);
  } catch (error) {
    if (error instanceof ClientInvalid) return { status: 'invalid', message: `${error.message.charAt(0).toUpperCase()}${error.message.slice(1)}.` };
    if (error instanceof OAuthError) return { status: 'invalid', message: error.message };
    throw error;
  }
  if (redirectUri.length > MOST_REDIRECT || !client.redirectUris.some((uri) => redirectMatches(uri, redirectUri))) {
    return { status: 'invalid', message: `${redirectUri} is not one of its redirects.` };
  }
  const refuse = (error: string, message: string) => ({
    status: 'refused' as const,
    message,
    redirect: redirectTo(mcp.publicUrl, redirectUri, request.state, { error, error_description: message }),
  });
  if (request.response_type !== 'code') return refuse('unsupported_response_type', 'coffre answers response_type=code only');
  if (request.code_challenge_method !== 'S256' || !S256_CHALLENGE.test(request.code_challenge ?? '')) {
    return refuse('invalid_request', 'coffre requires PKCE with S256');
  }
  if ((request.state ?? '').length > 1024) return refuse('invalid_request', 'the state is longer than 1024 characters');
  if (request.resource !== undefined && !isResource(mcp.publicUrl, request.resource)) {
    return refuse('invalid_target', `coffre issues tokens for ${resourceOf(mcp.publicUrl)} only`);
  }
  const { scopes, unknown } = parseScopes(request.scope);
  if (unknown.length > 0) return refuse('invalid_scope', `unknown scopes: ${unknown.join(', ')}`);
  return { status: 'ready', client, redirectUri, challenge: request.code_challenge!, scopes };
}

/** What the consent page shows of a request that holds. */
export function readyView(mcp: SigninConfig, checked: Checked, connections: McpScope[][]): Extract<AuthorizationView, { status: 'ready' }> {
  const { client, redirectUri, scopes } = checked;
  return {
    status: 'ready',
    client: { id: client.clientId, name: client.name, host: client.host, registration: client.registration },
    redirectHost: redirectHost(redirectUri),
    loopbackOnly: client.redirectUris.every((uri) => redirectKind(uri) === 'loopback'),
    scopes,
    connections,
    days: mcp.cliSessionDays,
  };
}

/** The client's redirect, with OAuth's answer, its `state`, and the issuer (RFC 9207). */
export function redirectTo(publicUrl: string, redirectUri: string, state: string | undefined, params: Record<string, string>): string {
  const url = new URL(redirectUri);
  for (const [name, value] of Object.entries(params)) url.searchParams.append(name, value);
  if (state !== undefined && state !== '') url.searchParams.append('state', state);
  url.searchParams.append('iss', publicUrl);
  return url.href;
}
