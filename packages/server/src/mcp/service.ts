import { randomUUID } from 'node:crypto';

import type { McpConfig, SigninConfig } from '@coffre/core/identity';
import {
  ClientInvalid,
  parseScopes,
  redirectHost,
  redirectKind,
  redirectMatches,
  registrationRedirects,
  clientName,
  grantedScopes,
  scopeString,
  supersedes,
  type ClientMetadata,
  type McpScope,
} from '@coffre/core/mcp';
import type { Access, Vault } from '@coffre/core/vault';
import type { Database, Transaction } from '@coffre/db';
import { mcpConnections } from '@coffre/db/schema';

import { callerFrom, type Caller } from '../api/caller.ts';
import { allowed, audited, denied, Refusal, type ApiContext } from '../api/context.ts';
import { ApiError, conflict, forbidden, notFound } from '../api/errors.ts';
import { AuthRowTampered } from '../auth-rows.ts';
import type { AuditEntry } from '../db/audit.ts';
import {
  findConnection,
  insertConnection,
  insertOauthClient,
  liveConnections,
  sweepOauthClients,
  memberOf,
  memberStanding,
  principalOf,
  update,
  updateAuth,
  type ConnectionRow,
} from '../db/queries.ts';
import { logged } from '../logged.ts';
import type { WorkloadTransport } from '../workloads/transport.ts';
import { McpApprovals } from './approvals.ts';
import { resolveClient, wouldFetch } from './clients.ts';
import {
  ACCESS_TOKEN_SECONDS,
  hashSecret,
  mintAccessToken,
  pkceMatches,
  readAccessToken,
  REFRESH_PREFIX,
  S256_CHALLENGE,
  secret,
} from './tokens.ts';

/** How long a code waits for its client: long enough for a redirect, and no longer. */
const CODE_SECONDS = 60;
/** Connections a person may hold at once, before Connected apps has to lose one. */
export const MAX_CONNECTIONS = 20;
/** Last use is written once per this long at most, as for credentials. */
const TOUCH_INTERVAL_MS = 5 * 60 * 1000;
/** A registration no connection names is revoked after this long: a client that registers to connect does so within minutes. */
const UNUSED_REGISTRATION_MS = 7 * 86_400_000;
/** How many of those one registration revokes, at most: the work stays bounded, and keeps pace with registrations. */
const SWEEP_LIMIT = 10;

export type McpServiceDeps = {
  db: Database;
  chainKey: Buffer;
  vault: Vault;
  config: McpConfig;
  signin: SigninConfig;
  publicUrl: string;
  transport: WorkloadTransport;
  /** How long a call waits on its approval before answering that it still waits; 25 seconds unless a test says otherwise. */
  approvalWaitMs?: number;
};

/** Who is asking, for the consent page's calls. */
export type Asker = Pick<ApiContext, 'caller' | 'requestId' | 'sourceIp'>;

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

/** A connection, as Connected apps lists it. */
export type ConnectedApp = {
  id: string;
  /** The client's name and host, as the consent page showed them. */
  name: string;
  host: string | null;
  /** `dcr`: a registration, whose name is the app's own claim. */
  registration: 'cimd' | 'dcr';
  scopes: McpScope[];
  createdAt: string;
  lastUsedAt: string | null;
  lastUsedIp: string | null;
  expiresAt: string;
};

/** What a request on `/mcp` is, once its token holds. */
export type McpConnection = {
  id: string;
  clientId: string;
  clientName: string;
  /** The token's scopes, within the connection's. */
  scopes: McpScope[];
  principal: { type: 'user'; id: string };
  caller: Caller;
};

export type TokenAnswer = {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token: string;
  scope: string;
};

type Meta = { requestId: string; sourceIp: string | null };

/**
 * coffre as an OAuth 2.1 authorization server for MCP clients
 * (docs/design/mcp.md, section 4): consent, codes, tokens, refresh and
 * revocation, and what `/mcp` checks a token against.
 *
 * A connection is one approved authorization: one person, one client, its
 * scopes. Its code, then its refresh token, live in its row under its MAC;
 * access tokens are MACed claims naming it, checked against it on every
 * request. Every change to it takes the log's head and writes its entry.
 */
export class McpService {
  readonly #deps: McpServiceDeps;
  /** The changes clients asked for, waiting for their person on coffre's page. */
  readonly approvals: McpApprovals;

  constructor(deps: McpServiceDeps) {
    this.#deps = deps;
    this.approvals = new McpApprovals(deps);
  }

  get approvalWaitMs(): number | undefined {
    return this.#deps.approvalWaitMs;
  }

  get limits(): McpConfig['limits'] {
    return this.#deps.config.limits;
  }

  /** The MCP endpoint, the protected resource tokens are bound to (RFC 8707). */
  get resource(): string {
    return `${this.#deps.publicUrl}/mcp`;
  }

  get issuer(): string {
    return this.#deps.publicUrl;
  }

  // --- consent ----------------------------------------------------------------

  /** What the consent page shows for an authorization request, every parameter checked. */
  async describe(asker: Asker, request: AuthorizationRequest): Promise<AuthorizationView> {
    if (asker.caller.principal.type !== 'user') throw forbidden('only people connect apps');
    const checked = await this.#check(request, asker.sourceIp);
    if (checked.status !== 'ready') return checked;
    const { client, redirectUri, scopes } = checked;
    const connections = await this.#sameClient(asker, client.clientId);
    return {
      status: 'ready',
      client: { id: client.clientId, name: client.name, host: client.host, registration: client.registration },
      redirectHost: redirectHost(redirectUri),
      loopbackOnly: client.redirectUris.every((uri) => redirectKind(uri) === 'loopback'),
      scopes,
      connections,
      days: this.#deps.signin.cliSessionDays,
    };
  }

  /**
   * The person's answer. Approved: a connection with its code, logged as
   * `mcp.connect`, and the redirect that carries the code. Denied: the
   * refusal logged, and the redirect that says so. Every parameter is
   * checked again: nothing is kept between the page and this.
   */
  async decide(asker: Asker, request: AuthorizationRequest, answer: { approve: boolean; scopes: string[] }): Promise<{ redirect: string }> {
    const { principal } = asker.caller;
    if (principal.type !== 'user') throw forbidden('only people connect apps');
    const checked = await this.#check(request, asker.sourceIp);
    if (checked.status === 'invalid') throw new ApiError('bad_request', checked.message);
    if (checked.status === 'refused') return { redirect: checked.redirect };
    const { client, redirectUri, scopes: asked } = checked;
    const shown = { clientId: client.clientId, clientName: client.name, clientHost: client.host, registration: client.registration, redirectHost: redirectHost(redirectUri) };
    const back = (params: Record<string, string>) => ({ redirect: this.#redirect(redirectUri, request.state, params) });

    if (!answer.approve) {
      await audited(this.#deps, async (_tx, log) => {
        log.push(denied(asker, 'mcp.connect', 'person_denied', { metadata: { ...shown, asked: scopeString(asked) } }));
      });
      return back({ error: 'access_denied', error_description: 'the person did not approve the connection' });
    }

    const scopes = grantedScopes(answer.scopes);
    const member = `user:${principal.id}`;
    const code = secret();
    const id = randomUUID();
    await audited(this.#deps, async (tx, log) => {
      const now = new Date();
      const standing = await memberStanding(tx, member);
      if (standing?.status !== 'active' || standing.generation !== asker.caller.generation) {
        throw new Refusal(forbidden('that session has ended'), denied(asker, 'mcp.connect', 'session_ended', { metadata: shown }));
      }
      if ((await liveConnections(tx, this.#deps.chainKey, member, now)).filter((row) => holds(row, now)).length >= MAX_CONNECTIONS) {
        throw new Refusal(
          conflict(`you have ${MAX_CONNECTIONS} connected apps already: disconnect one on your account page first`),
          denied(asker, 'mcp.connect', 'too_many_connections', { metadata: shown }),
        );
      }
      await insertConnection(tx, this.#deps.chainKey, {
        id,
        principal: member,
        generation: standing.generation,
        clientId: client.clientId,
        clientName: client.name,
        clientHost: client.host,
        registration: client.registration,
        scopes: scopeString(scopes),
        redirectUri,
        codeHash: hashSecret(code),
        codeChallenge: request.code_challenge!,
        codeExpiresAt: new Date(now.getTime() + CODE_SECONDS * 1000),
        expiresAt: new Date(now.getTime() + this.#deps.signin.cliSessionDays * 86_400_000),
      });
      log.push(allowed(asker, 'mcp.connect', { metadata: { connectionId: id, ...shown, asked: scopeString(asked), scopes: scopeString(scopes) } }));
    });
    return back({ code });
  }

  /** The scopes of the person's own live connections of a client: the consent page says what the new one replaces. */
  async #sameClient(asker: Asker, clientId: string): Promise<McpScope[][]> {
    const live = await liveConnections(this.#deps.db, this.#deps.chainKey, `user:${asker.caller.principal.id}`, new Date());
    return live.filter((row) => row.clientId === clientId && row.refreshHash !== null).map((row) => parseScopes(row.scopes).scopes);
  }

  /**
   * An authorization request, checked in the order OAuth answers it: the
   * client and its redirect first, and wrong there, never redirected to;
   * then the rest, whose errors go back to the client.
   */
  async #check(
    request: AuthorizationRequest,
    sourceIp: string | null,
  ): Promise<{ status: 'invalid'; message: string } | { status: 'refused'; message: string; redirect: string } | { status: 'ready'; client: ClientMetadata; redirectUri: string; scopes: McpScope[] }> {
    const clientId = request.client_id ?? '';
    const redirectUri = request.redirect_uri ?? '';
    if (clientId === '') return { status: 'invalid', message: 'The app sent no client_id.' };
    if (redirectUri === '') return { status: 'invalid', message: 'The app sent no redirect_uri.' };
    let client: ClientMetadata;
    try {
      if (wouldFetch(clientId, this.#deps.config.allowLoopback)) await this.#admit(sourceIp);
      client = await resolveClient({ ...this.#deps, allowLoopback: this.#deps.config.allowLoopback }, clientId);
    } catch (error) {
      if (error instanceof ClientInvalid) return { status: 'invalid', message: `${error.message.charAt(0).toUpperCase()}${error.message.slice(1)}.` };
      if (error instanceof OAuthError) return { status: 'invalid', message: error.message };
      throw error;
    }
    if (!client.redirectUris.some((registered) => redirectMatches(registered, redirectUri))) {
      return { status: 'invalid', message: `${redirectUri} is not one of its redirects.` };
    }
    const refuse = (error: string, message: string) => ({
      status: 'refused' as const,
      message,
      redirect: this.#redirect(redirectUri, request.state, { error, error_description: message }),
    });
    if (request.response_type !== 'code') return refuse('unsupported_response_type', 'coffre answers response_type=code only');
    if (request.code_challenge_method !== 'S256' || !S256_CHALLENGE.test(request.code_challenge ?? '')) {
      return refuse('invalid_request', 'coffre requires PKCE with S256');
    }
    if ((request.state ?? '').length > 1024) return refuse('invalid_request', 'the state is longer than 1024 characters');
    if (request.resource !== undefined && !this.#isResource(request.resource)) {
      return refuse('invalid_target', `coffre issues tokens for ${this.resource} only`);
    }
    const { scopes, unknown } = parseScopes(request.scope);
    if (unknown.length > 0) return refuse('invalid_scope', `unknown scopes: ${unknown.join(', ')}`);
    return { status: 'ready', client, redirectUri, scopes };
  }

  /** The client's redirect, with OAuth's answer, its `state`, and the issuer (RFC 9207). */
  #redirect(redirectUri: string, state: string | undefined, params: Record<string, string>): string {
    const url = new URL(redirectUri);
    for (const [name, value] of Object.entries(params)) url.searchParams.append(name, value);
    if (state !== undefined && state !== '') url.searchParams.append('state', state);
    url.searchParams.append('iss', this.issuer);
    return url.href;
  }

  /** Whether a `resource` names the MCP endpoint, with a trailing slash or capitals in its origin. */
  #isResource(value: string): boolean {
    try {
      const url = new URL(value);
      return url.search === '' && url.hash === '' && `${url.origin}${url.pathname.replace(/\/$/, '')}` === this.resource;
    } catch {
      return false;
    }
  }

  // --- connected apps -----------------------------------------------------------

  /** Your connected apps: Connected apps on your account page. */
  async apps(asker: Asker): Promise<ConnectedApp[]> {
    return this.appsOf(principalOf(asker.caller.principal));
  }

  /**
   * A person's connected apps, `user:<email>`, newest first: those whose
   * client redeemed its code. Their member report lists them for owners.
   */
  async appsOf(principal: string): Promise<ConnectedApp[]> {
    const live = await liveConnections(this.#deps.db, this.#deps.chainKey, principal, new Date());
    return live
      .filter((row) => row.refreshHash !== null)
      .map((row) => ({
        id: row.id,
        name: row.clientName,
        host: row.clientHost,
        registration: row.registration as ConnectedApp['registration'],
        scopes: parseScopes(row.scopes).scopes,
        createdAt: row.createdAt.toISOString(),
        lastUsedAt: row.lastUsedAt?.toISOString() ?? null,
        lastUsedIp: row.lastUsedIp,
        expiresAt: row.expiresAt.toISOString(),
      }));
  }

  /**
   * Disconnect an app: your own, or anyone's as an owner, as with sessions.
   * Its refresh token and every access token under it stop at once.
   */
  async disconnect(asker: Asker, id: string): Promise<{ disconnected: true }> {
    const { principal } = asker.caller;
    const unknown = () =>
      new Refusal(notFound('unknown connected app'), denied(asker, 'mcp.disconnect', 'unknown_connection', { metadata: { connectionId: id } }));
    return audited(this.#deps, async (tx, log) => {
      let row: Awaited<ReturnType<typeof findConnection>>;
      try {
        row = await findConnection(tx, this.#deps.chainKey, { id });
      } catch (error) {
        // A row that fails its MAC is nobody's app: nothing it claims holds.
        if (!(error instanceof AuthRowTampered)) throw error;
        throw unknown();
      }
      if (row === null || row.revokedAt !== null || row.expiresAt <= row.now) throw unknown();
      const own = row.principal === principalOf(principal);
      if (!own && !asker.caller.isOwner) {
        throw new Refusal(
          forbidden("only owners may disconnect other people's apps"),
          denied(asker, 'mcp.disconnect', 'requires_instance_owner', { metadata: { connectionId: id } }),
        );
      }
      const ended = await updateAuth(tx, this.#deps.chainKey, mcpConnections, { id, revokedAt: null }, { revokedAt: new Date(), revokedBy: principal.id });
      if (ended === 0) throw unknown();
      const member = memberOf(row.principal);
      log.push(
        allowed(asker, 'mcp.disconnect', {
          metadata: {
            connectionId: id,
            clientId: row.clientId,
            clientName: row.clientName,
            reason: own ? 'person' : 'owner',
            ...(own ? {} : { principalType: member.type, principalId: member.id }),
          },
        }),
      );
      return { disconnected: true as const };
    });
  }

  // --- the token endpoint -----------------------------------------------------

  /** `POST /api/oauth/token`: a code for the connection's first tokens, or a refresh token for the next. */
  async token(form: URLSearchParams, meta: Meta): Promise<TokenAnswer> {
    const resource = form.get('resource');
    if (resource !== null && !this.#isResource(resource)) throw new OAuthError('invalid_target', `coffre issues tokens for ${this.resource} only`);
    const clientId = required(form, 'client_id');
    switch (form.get('grant_type')) {
      case 'authorization_code':
        return this.#redeem(form, clientId, meta);
      case 'refresh_token':
        return this.#refresh(form, clientId, meta);
      default:
        throw new OAuthError('unsupported_grant_type', 'coffre takes authorization_code and refresh_token');
    }
  }

  async #redeem(form: URLSearchParams, clientId: string, meta: Meta): Promise<TokenAnswer> {
    const code = required(form, 'code');
    const verifier = required(form, 'code_verifier');
    const redirectUri = required(form, 'redirect_uri');
    const row = await this.#find({ codeHash: hashSecret(code) });
    if (row === null) throw new OAuthError('invalid_grant', 'unknown code');
    // Redeemed already: whoever holds it now is not who it was for, or the
    // client sent it twice. Either way the connection ends (OAuth 2.1, 4.1.3).
    if (row.codeChallenge === null) {
      await this.#end(row, 'code_reused', meta);
      throw new OAuthError('invalid_grant', 'that code was used already; the connection it made is ended');
    }
    if (row.revokedAt !== null || row.codeExpiresAt === null || row.codeExpiresAt <= row.now) throw new OAuthError('invalid_grant', 'that code has expired');
    if (row.clientId !== clientId) throw new OAuthError('invalid_grant', 'that code is for another client');
    if (row.redirectUri !== redirectUri) throw new OAuthError('invalid_grant', 'the redirect_uri is not the one the code was sent to');
    if (!pkceMatches(row.codeChallenge, verifier)) throw new OAuthError('invalid_grant', 'the code_verifier does not match the code_challenge');
    await this.#stillMember(row);
    const refresh = secret(REFRESH_PREFIX);
    await audited(this.#deps, async (tx, log) => {
      await this.#standing(tx, row);
      // Only an unredeemed code: of two racing, one gets the tokens.
      const redeemed = await updateAuth(tx, this.#deps.chainKey, mcpConnections, { id: row.id, codeChallenge: row.codeChallenge }, {
        codeChallenge: null,
        codeExpiresAt: null,
        refreshHash: hashSecret(refresh),
      });
      if (redeemed === 0) throw new OAuthError('invalid_grant', 'that code was used already');
      log.push(this.#entry(row, 'mcp.token', 'allow', meta, { grant: 'authorization_code' }));
      // A step-up: the client's earlier connections that this one grants all of and more end now, as the consent page said.
      const granted = parseScopes(row.scopes).scopes;
      for (const earlier of await liveConnections(tx, this.#deps.chainKey, row.principal, row.now)) {
        if (earlier.id === row.id || earlier.clientId !== row.clientId || earlier.refreshHash === null || !supersedes(granted, parseScopes(earlier.scopes).scopes)) continue;
        const ended = await updateAuth(tx, this.#deps.chainKey, mcpConnections, { id: earlier.id, revokedAt: null }, { revokedAt: row.now, revokedBy: 'coffre' });
        if (ended > 0) log.push(this.#entry(earlier, 'mcp.disconnect', 'allow', meta, { reason: 'superseded', supersededBy: row.id }));
      }
    });
    return this.#answer(row, parseScopes(row.scopes).scopes, refresh, row.now);
  }

  async #refresh(form: URLSearchParams, clientId: string, meta: Meta): Promise<TokenAnswer> {
    const presented = required(form, 'refresh_token');
    const row = await this.#find({ refreshHash: hashSecret(presented) });
    if (row === null) throw new OAuthError('invalid_grant', 'unknown refresh token');
    // A refresh token replaced already, presented again: one of its two
    // holders is not the client. The connection ends (OAuth 2.1, 4.3.1).
    if (row.previous) {
      await this.#end(row, 'refresh_reused', meta);
      throw new OAuthError('invalid_grant', 'that refresh token was replaced already; the connection is ended');
    }
    if (row.revokedAt !== null || row.expiresAt <= row.now) throw new OAuthError('invalid_grant', 'the connection has ended: connect again');
    if (row.clientId !== clientId) throw new OAuthError('invalid_grant', 'that refresh token is for another client');
    const held = parseScopes(row.scopes).scopes;
    let scopes = held;
    const asked = form.get('scope');
    if (asked !== null) {
      const parsed = parseScopes(asked);
      if (parsed.unknown.length > 0 || parsed.scopes.some((scope) => !held.includes(scope))) {
        throw new OAuthError('invalid_scope', `a refresh may narrow the scopes, not widen them: the connection holds ${row.scopes}`);
      }
      scopes = parsed.scopes;
    }
    await this.#stillMember(row);
    const refresh = secret(REFRESH_PREFIX);
    await audited(this.#deps, async (tx, log) => {
      await this.#standing(tx, row);
      const rotated = await updateAuth(tx, this.#deps.chainKey, mcpConnections, { id: row.id, refreshHash: row.refreshHash, revokedAt: null }, {
        refreshPreviousHash: row.refreshHash,
        refreshHash: hashSecret(refresh),
      });
      if (rotated === 0) throw new OAuthError('invalid_grant', 'that refresh token was replaced already');
      log.push(this.#entry(row, 'mcp.token', 'allow', meta, { grant: 'refresh_token', scopes: scopeString(scopes) }));
    });
    return this.#answer(row, scopes, refresh, row.now);
  }

  #answer(row: ConnectionRow, scopes: McpScope[], refresh: string, now: Date): TokenAnswer {
    const expiresAt = new Date(Math.min(now.getTime() + ACCESS_TOKEN_SECONDS * 1000, row.expiresAt.getTime()));
    return {
      access_token: mintAccessToken(this.#deps.chainKey, { connectionId: row.id, scopes, issuedAt: now, expiresAt }),
      token_type: 'Bearer',
      expires_in: Math.max(0, Math.floor((expiresAt.getTime() - now.getTime()) / 1000)),
      refresh_token: refresh,
      scope: scopeString(scopes),
    };
  }

  // --- revocation ---------------------------------------------------------------

  /** `POST /api/oauth/revoke` (RFC 7009): either token ends its connection. Anything unknown is a quiet no-op. */
  async revoke(form: URLSearchParams, meta: Meta): Promise<void> {
    const token = required(form, 'token');
    const clientId = form.get('client_id');
    let row: Awaited<ReturnType<typeof findConnection>> = null;
    if (token.startsWith(REFRESH_PREFIX)) row = await this.#find({ refreshHash: hashSecret(token) });
    else {
      const claims = readAccessToken(this.#deps.chainKey, token);
      if (claims !== null) row = await this.#find({ id: claims.connectionId });
    }
    if (row === null || row.revokedAt !== null || (clientId !== null && clientId !== row.clientId)) return;
    await this.#end(row, 'revocation_endpoint', meta);
  }

  // --- what /mcp checks ---------------------------------------------------------

  /**
   * The connection an access token names, if the token's MAC and hour hold,
   * the connection is redeemed, unrevoked and unexpired, and its person is
   * still a member at its generation: one query and the request's one
   * `vault.access`. Null otherwise, which `/mcp` answers 401.
   */
  async authenticate(token: string, meta: { sourceIp: string | null }): Promise<McpConnection | null> {
    const claims = readAccessToken(this.#deps.chainKey, token);
    if (claims === null) return null;
    let row: Awaited<ReturnType<typeof findConnection>>;
    try {
      row = await findConnection(this.#deps.db, this.#deps.chainKey, { id: claims.connectionId });
    } catch (error) {
      if (error instanceof AuthRowTampered) return null;
      throw error;
    }
    if (row === null || claims.expiresAt <= row.now || row.revokedAt !== null || row.expiresAt <= row.now || row.refreshHash === null) return null;
    const access = await this.#deps.vault.access(row.principal);
    if (access.status !== 'active' || access.generation !== row.generation) return null;
    if (row.now.getTime() - (row.lastUsedAt?.getTime() ?? 0) > TOUCH_INTERVAL_MS) {
      // Coarse on purpose, and never at the request's cost.
      await update(this.#deps.db, mcpConnections, { id: row.id }, { lastUsedAt: row.now, lastUsedIp: meta.sourceIp }).catch(() => 0);
    }
    const held = parseScopes(row.scopes).scopes;
    const principal = memberOf(row.principal) as { type: 'user'; id: string };
    return {
      id: row.id,
      clientId: row.clientId,
      clientName: row.clientName,
      scopes: claims.scopes.filter((scope) => held.includes(scope)),
      principal,
      caller: callerFrom(principal, access),
    };
  }

  // --- registration -------------------------------------------------------------

  /**
   * `POST /api/oauth/register` (RFC 7591), the fallback to metadata
   * documents: public clients only, with the redirects coffre accepts and
   * the others left out.
   */
  async register(body: unknown, meta: Meta): Promise<Record<string, unknown>> {
    if (typeof body !== 'object' || body === null || Array.isArray(body)) throw new OAuthError('invalid_client_metadata', 'the registration is not a JSON object');
    const fields = body as Record<string, unknown>;
    const method = fields.token_endpoint_auth_method;
    if (method !== undefined && method !== 'none') {
      throw new OAuthError('invalid_client_metadata', 'coffre registers public clients only: token_endpoint_auth_method must be none');
    }
    let redirects: { kept: string[]; dropped: string[] };
    try {
      redirects = registrationRedirects(fields.redirect_uris);
    } catch (error) {
      if (error instanceof ClientInvalid) throw new OAuthError('invalid_redirect_uri', error.message);
      throw error;
    }
    const id = randomUUID();
    const name = clientName(fields.client_name, 'Unnamed app');
    // Each registration revokes a few that were never used, so live ones cannot pile up (W19's review, P3-4).
    await sweepOauthClients(this.#deps.db, this.#deps.chainKey, new Date(Date.now() - UNUSED_REGISTRATION_MS), SWEEP_LIMIT);
    await insertOauthClient(this.#deps.db, this.#deps.chainKey, { id, name, redirectUris: JSON.stringify(redirects.kept), createdIp: meta.sourceIp });
    return {
      client_id: id,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      client_name: name,
      redirect_uris: redirects.kept,
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    };
  }

  // --- shared -------------------------------------------------------------------

  /** The unauthenticated endpoints' limits, per source and in total; a limiter that fails refuses. */
  async admit(sourceIp: string | null): Promise<void> {
    return this.#admit(sourceIp);
  }

  async #admit(sourceIp: string | null): Promise<void> {
    const { perSource, total } = this.#deps.config.limits;
    let passed: boolean;
    try {
      const [source, all] = await Promise.all([perSource.limit({ key: `source:${sourceIp ?? 'unknown'}` }), total.limit({ key: 'total' })]);
      passed = source.success && all.success;
    } catch {
      throw new OAuthError('temporarily_unavailable', 'coffre cannot count requests right now: try again shortly', 503);
    }
    if (!passed) throw new OAuthError('slow_down', 'too many requests: try again in a minute', 429);
  }

  /** A connection's tool calls, against its own limit. */
  async admitCall(connectionId: string, requestId: string): Promise<boolean> {
    try {
      return (await this.#deps.config.limits.perConnection.limit({ key: `connection:${connectionId}` })).success;
    } catch (error) {
      // Refused all the same, and logged: a limiter that fails is not a client calling too often.
      console.error('mcp limiter failed', { requestId, connectionId, error: logged(error) });
      return false;
    }
  }

  async #find(by: Parameters<typeof findConnection>[2]) {
    try {
      return await findConnection(this.#deps.db, this.#deps.chainKey, by);
    } catch (error) {
      if (error instanceof AuthRowTampered) throw new OAuthError('invalid_grant', 'that connection failed its integrity check');
      throw error;
    }
  }

  /** Whether the connection's person is still a member, at its generation: the vault's answer, before any transaction. */
  async #stillMember(row: ConnectionRow): Promise<Access> {
    const access = await this.#deps.vault.access(row.principal);
    if (access.status !== 'active' || access.generation !== row.generation) {
      throw new OAuthError('invalid_grant', 'the person who connected this app is no longer a member as they were');
    }
    return access;
  }

  /** The same, again, under the log's head: a removal racing the token cannot slip past. */
  async #standing(tx: Transaction, row: ConnectionRow): Promise<void> {
    const standing = await memberStanding(tx, row.principal);
    if (standing?.status !== 'active' || standing.generation !== row.generation) {
      throw new OAuthError('invalid_grant', 'the person who connected this app is no longer a member as they were');
    }
  }

  /** End a connection, and log why: `mcp.disconnect`, in its person's name. */
  async #end(row: ConnectionRow, reason: string, meta: Meta, by = 'coffre'): Promise<void> {
    await audited(this.#deps, async (tx, log) => {
      const ended = await updateAuth(tx, this.#deps.chainKey, mcpConnections, { id: row.id, revokedAt: null }, { revokedAt: new Date(), revokedBy: by });
      if (ended > 0) log.push(this.#entry(row, 'mcp.disconnect', 'allow', meta, { reason }));
    });
  }

  #entry(row: ConnectionRow, action: string, decision: 'allow' | 'deny', meta: Meta, metadata: Record<string, unknown>): AuditEntry {
    const member = memberOf(row.principal);
    return {
      actorType: member.type,
      actorId: member.id,
      action,
      decision,
      requestId: meta.requestId,
      sourceIp: meta.sourceIp,
      metadata: { connectionId: row.id, clientId: row.clientId, clientName: row.clientName, ...metadata },
    };
  }
}

/** Whether a connection counts against the limit: redeemed, or its code still waiting. An abandoned consent does not. */
function holds(row: ConnectionRow, now: Date): boolean {
  return row.refreshHash !== null || (row.codeExpiresAt !== null && row.codeExpiresAt > now);
}

function required(form: URLSearchParams, name: string): string {
  const values = form.getAll(name);
  if (values.length !== 1 || values[0] === '') throw new OAuthError('invalid_request', `${name} is required, once`);
  return values[0]!;
}
