import type { IncomingMessage, ServerResponse } from 'node:http';

import type { AuthorizationServer, Flavor } from './authorize.ts';
import { authorizationToken, readParams, repeatedParam, sendJson, type Route } from './http.ts';
import type { DevIdp, RegisteredClient } from './idp.ts';
import { displayName } from './people.ts';

const ACCESS_TOKEN_TTL = 3600;

/**
 * A small OpenID Connect provider: authorization code flow with PKCE,
 * confidential clients, userinfo. Enough for a generic OIDC client to run
 * its real code path end to end.
 */
export class OidcProvider {
  #idp: DevIdp;
  #authz: AuthorizationServer;
  readonly flavor: Flavor;

  constructor(idp: DevIdp, authz: AuthorizationServer) {
    this.#idp = idp;
    this.#authz = authz;
    this.flavor = {
      name: 'oidc',
      path: '/oauth/authorize',
      label: 'coffre dev IdP · OpenID Connect',
      codeTtl: 60,
      issuer: () => idp.issuer,
      parse(params) {
        const responseType = params.get('response_type');
        if (!responseType) return { error: 'invalid_request', description: 'response_type is required' };
        if (responseType !== 'code') {
          return { error: 'unsupported_response_type', description: 'only response_type=code is supported' };
        }
        const scope = (params.get('scope') ?? '').split(' ').filter(Boolean);
        if (!scope.includes('openid')) return { error: 'invalid_scope', description: 'scope must include openid' };
        return {
          scope: [...new Set(scope)],
          nonce: params.get('nonce') ?? undefined,
          hint: params.get('login_hint') ?? undefined,
        };
      },
      denied: { error_description: 'The user denied the request' },
    };
  }

  routes(): Route[] {
    return [
      {
        method: 'GET',
        path: '/.well-known/openid-configuration',
        handler: async (_req, res) => sendJson(res, 200, this.#discovery()),
      },
      ...this.#authz.routes(this.flavor),
      { method: 'POST', path: '/oauth/token', handler: (req, res) => this.#token(req, res) },
      { method: 'GET', path: '/oauth/userinfo', handler: async (req, res) => this.#userinfo(req, res) },
    ];
  }

  #discovery() {
    const origin = this.#idp.origin;
    return {
      issuer: this.#idp.issuer,
      authorization_endpoint: `${origin}/oauth/authorize`,
      token_endpoint: `${origin}/oauth/token`,
      userinfo_endpoint: `${origin}/oauth/userinfo`,
      jwks_uri: this.#idp.jwksUrl,
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
      scopes_supported: ['openid', 'email', 'profile'],
      claims_supported: ['iss', 'sub', 'aud', 'iat', 'exp', 'auth_time', 'nonce', 'email', 'email_verified', 'name'],
      authorization_response_iss_parameter_supported: true,
    };
  }

  /** RFC 6749 §4.1.3, errors per §5.2. */
  async #token(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const fail = (status: number, error: string, description: string, headers: Record<string, string> = {}) =>
      sendJson(res, status, { error, error_description: description }, { 'cache-control': 'no-store', ...headers });

    const params = await readParams(req);
    if (params === null) return fail(400, 'invalid_request', 'expected an application/x-www-form-urlencoded body');
    const repeated = repeatedParam(params);
    if (repeated) return fail(400, 'invalid_request', `parameter ${repeated} is repeated`);

    const auth = this.#authenticate(req, params);
    if ('error' in auth) {
      if (auth.error !== 'invalid_client') return fail(400, auth.error, auth.description);
      return fail(401, auth.error, auth.description, { 'www-authenticate': 'Basic realm="dev-idp"' });
    }

    const grantType = params.get('grant_type');
    if (grantType !== 'authorization_code') {
      return fail(400, grantType ? 'unsupported_grant_type' : 'invalid_request', 'grant_type must be authorization_code');
    }
    const code = params.get('code');
    const redirectUri = params.get('redirect_uri');
    const codeVerifier = params.get('code_verifier');
    if (!code || !redirectUri || !codeVerifier) {
      return fail(400, 'invalid_request', 'code, redirect_uri and code_verifier are required');
    }

    const result = this.#authz.exchange('oidc', {
      client: auth.client,
      code,
      redirectUri,
      codeVerifier,
      accessTokenTtl: ACCESS_TOKEN_TTL,
    });
    if (!result.ok) {
      const description = {
        invalid_code: 'the code is invalid, expired, already used, or was issued to another client',
        redirect_uri_mismatch: 'redirect_uri does not match the authorization request',
        invalid_verifier: 'code_verifier does not match the code_challenge',
      }[result.error];
      return fail(400, 'invalid_grant', description);
    }

    const { grant } = result;
    const idToken = await this.#idp.mintIdToken({
      clientId: grant.clientId,
      email: grant.email,
      nonce: grant.nonce,
      authTime: grant.authTime,
    });
    sendJson(
      res,
      200,
      {
        access_token: result.accessToken,
        token_type: 'Bearer',
        expires_in: result.expiresIn,
        id_token: idToken,
        scope: grant.scope.join(' '),
      },
      { 'cache-control': 'no-store', pragma: 'no-cache' },
    );
  }

  /** client_secret_basic or client_secret_post, never both (RFC 6749 §2.3). */
  #authenticate(
    req: IncomingMessage,
    params: URLSearchParams,
  ): { client: RegisteredClient } | { error: string; description: string } {
    const basic = authorizationToken(req, ['basic']);
    let clientId: string | null;
    let clientSecret: string | null;

    if (basic !== undefined) {
      if (params.has('client_secret')) {
        return { error: 'invalid_request', description: 'use one client authentication method' };
      }
      // §2.3.1: both halves are form-encoded before base64.
      const decoded = Buffer.from(basic, 'base64').toString('utf8');
      const colon = decoded.indexOf(':');
      if (colon < 0) return { error: 'invalid_client', description: 'malformed Basic credentials' };
      try {
        const formDecode = (s: string) => decodeURIComponent(s.replaceAll('+', ' '));
        clientId = formDecode(decoded.slice(0, colon));
        clientSecret = formDecode(decoded.slice(colon + 1));
      } catch {
        return { error: 'invalid_client', description: 'malformed Basic credentials' };
      }
      const bodyId = params.get('client_id');
      if (bodyId !== null && bodyId !== clientId) {
        return { error: 'invalid_client', description: 'client_id does not match the credentials' };
      }
    } else {
      clientId = params.get('client_id');
      clientSecret = params.get('client_secret');
    }

    if (!clientId || !clientSecret) return { error: 'invalid_client', description: 'client authentication is required' };
    const client = this.#idp.client(clientId);
    if (!client || client.clientSecret !== clientSecret) {
      return { error: 'invalid_client', description: 'unknown client or wrong secret' };
    }
    return { client };
  }

  #userinfo(req: IncomingMessage, res: ServerResponse): void {
    const token = authorizationToken(req, ['bearer']);
    if (token === undefined) {
      return sendJson(res, 401, { error: 'invalid_request' }, { 'www-authenticate': 'Bearer realm="dev-idp"' });
    }
    const grant = this.#authz.grantFor('oidc', token);
    if (!grant) {
      return sendJson(res, 401, { error: 'invalid_token' }, {
        'www-authenticate': 'Bearer realm="dev-idp", error="invalid_token"',
      });
    }
    sendJson(
      res,
      200,
      {
        sub: this.#idp.subjectFor(grant.email),
        email: grant.email,
        email_verified: true,
        name: displayName(grant.email),
      },
      { 'cache-control': 'no-store' },
    );
  }
}
