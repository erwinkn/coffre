import { randomBytes } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';

import type { AuthorizationServer, Flavor, Grant } from './authorize.ts';
import { authorizationToken, readParams, sendJson, type Route } from './http.ts';
import type { DevIdp } from './idp.ts';
import { isEmail, normalizeEmail, sha256Hex, type GitHubAccount } from './people.ts';

// Coffre is configured with a web base URL (https://github.com in production)
// and an API base URL (https://api.github.com); locally these two prefixes.
const WEB = '/github';
const API = '/github/api';

const DOCS = 'https://docs.github.com/rest';
const TROUBLESHOOTING = 'https://docs.github.com/apps/managing-oauth-apps/troubleshooting-oauth-app-access-token-request-errors';

/**
 * Enough of GitHub's OAuth apps and REST API for coffre's GitHub sign-in:
 * the web flow, the authenticated user, their emails, and org membership.
 * GitHub is not an OIDC provider, and its token endpoint has quirks a
 * standard OAuth client trips on; this imitates them rather than smoothing
 * them over.
 */
export class FakeGitHub {
  #idp: DevIdp;
  #authz: AuthorizationServer;
  readonly flavor: Flavor;

  constructor(idp: DevIdp, authz: AuthorizationServer) {
    this.#idp = idp;
    this.#authz = authz;
    // https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
    this.flavor = {
      name: 'github',
      path: `${WEB}/login/oauth/authorize`,
      label: 'coffre dev IdP · fake GitHub',
      // "The code expires after 10 minutes."
      codeTtl: 600,
      issuer: null,
      parse(params) {
        // Requested space-delimited; commas have long been accepted too.
        const scope = (params.get('scope') ?? '').split(/[\s,]+/).filter(Boolean);
        // GitHub's own hint is `login`, a username; login_hint is ours, an email.
        const login = params.get('login') ?? undefined;
        const hint =
          params.get('login_hint') ??
          (login === undefined || isEmail(login) ? login : idp.emailForGitHubLogin(login));
        return { scope: [...new Set(scope)], hint };
      },
      denied: {
        error_description: 'The user has denied your application access.',
        error_uri: 'https://docs.github.com/apps/managing-oauth-apps/troubleshooting-authorization-request-errors/#access-denied',
      },
    };
  }

  routes(): Route[] {
    return [
      ...this.#authz.routes(this.flavor),
      { method: 'POST', path: `${WEB}/login/oauth/access_token`, handler: (req, res) => this.#accessToken(req, res) },
      { method: 'GET', path: `${API}/user`, handler: async (req, res) => this.#user(req, res) },
      { method: 'GET', path: `${API}/user/emails`, handler: async (req, res) => this.#emails(req, res) },
      {
        method: 'GET',
        path: new RegExp(`^${API}/user/memberships/orgs/[^/]+$`),
        handler: async (req, res, url) => this.#membership(req, res, decodeURIComponent(url.pathname.split('/').pop()!)),
      },
    ];
  }

  /**
   * The quirks: JSON only when asked for with `Accept`, form-encoded
   * otherwise; errors are HTTP 200 with an `error` field; scopes come back
   * comma-separated.
   * https://docs.github.com/en/apps/oauth-apps/maintaining-oauth-apps/troubleshooting-oauth-app-access-token-request-errors
   */
  async #accessToken(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Numbers stay numbers in JSON, and are strings in a form, as everything there is.
    const reply = (body: Record<string, string | number>) => {
      if ((req.headers.accept ?? '').includes('application/json')) return sendJson(res, 200, body);
      res.writeHead(200, { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' });
      res.end(new URLSearchParams(Object.entries(body).map(([key, value]) => [key, String(value)])).toString());
    };
    const fail = (error: string, description: string) =>
      reply({ error, error_description: description, error_uri: `${TROUBLESHOOTING}#${error.replaceAll('_', '-')}` });

    const params = (await readParams(req)) ?? new URLSearchParams();
    let clientId = params.get('client_id');
    let clientSecret = params.get('client_secret');
    const basic = authorizationToken(req, ['basic']);
    if (basic !== undefined && clientSecret === null) {
      const decoded = Buffer.from(basic, 'base64').toString('utf8');
      const colon = decoded.indexOf(':');
      clientId = decoded.slice(0, colon);
      clientSecret = decoded.slice(colon + 1);
    }
    const client = clientId ? this.#idp.client(clientId) : undefined;
    if (!client || client.clientSecret !== clientSecret) {
      return fail('incorrect_client_credentials', 'The client_id and/or client_secret passed are incorrect.');
    }

    // A GitHub App's user tokens expire in eight hours; an OAuth app's do not, unless it opts in.
    const app = this.#isApp(client.clientId);
    const result = this.#authz.exchange('github', {
      client,
      code: params.get('code') ?? '',
      redirectUri: params.get('redirect_uri') ?? undefined,
      codeVerifier: params.get('code_verifier') ?? '',
      accessTokenTtl: app ? 8 * 60 * 60 : Infinity,
      accessTokenPrefix: app ? 'ghu_' : 'gho_',
    });
    if (!result.ok) {
      if (result.error === 'redirect_uri_mismatch') {
        return fail('redirect_uri_mismatch', 'The redirect_uri MUST match the registered callback URL for this application.');
      }
      return fail('bad_verification_code', 'The code passed is incorrect or expired.');
    }
    // https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app
    // An expiring user token comes with a refresh token, for six months; coffre uses neither, and keeps no token.
    if (app) {
      return reply({
        access_token: result.accessToken,
        expires_in: 8 * 60 * 60,
        refresh_token: `ghr_${randomBytes(30).toString('hex')}`,
        refresh_token_expires_in: 15_897_600,
        token_type: 'bearer',
        scope: '',
      });
    }
    reply({ access_token: result.accessToken, token_type: 'bearer', scope: result.grant.scope.join(',') });
  }

  /** https://docs.github.com/en/rest/users/users#get-the-authenticated-user */
  #user(req: IncomingMessage, res: ServerResponse): void {
    const auth = this.#authenticate(req, res);
    if (!auth) return;
    const { account } = auth;
    const publicEmail = account.emails.find((e) => e.primary && e.visibility === 'public');
    this.#json(res, auth.grant, 200, {
      login: account.login,
      id: account.id,
      node_id: `U_dev${account.id}`,
      html_url: `${this.#idp.origin}${WEB}/${account.login}`,
      type: 'User',
      site_admin: false,
      name: account.name,
      email: publicEmail?.email ?? null,
    });
  }

  /**
   * Needs `user:email` (or `user`). Without it GitHub answers 404, not 403.
   * https://docs.github.com/en/rest/users/emails#list-email-addresses-for-the-authenticated-user
   */
  #emails(req: IncomingMessage, res: ServerResponse): void {
    const auth = this.#authenticate(req, res);
    if (!auth) return;
    // A GitHub App's user token carries the app's permissions, not scopes: "Email addresses", read.
    if (this.#isApp(auth.grant.clientId)) {
      if (this.#idp.githubApp.permissions.emails === undefined) return this.#notAccessible(res, auth.grant);
    } else if (!this.#hasScope(auth.grant, ['user:email', 'user'])) return this.#notFound(res, auth.grant);
    this.#json(res, auth.grant, 200, auth.account.emails);
  }

  /**
   * Needs `read:org` (implied by `write:org`, `admin:org` and `user`), else 403;
   * 404 when the user is not a member.
   * https://docs.github.com/en/rest/orgs/members#get-an-organization-membership-for-the-authenticated-user
   * https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps
   */
  #membership(req: IncomingMessage, res: ServerResponse, org: string): void {
    const auth = this.#authenticate(req, res);
    if (!auth) return;
    // A GitHub App's user token reaches an organization's members only with the app's "Members" permission, and only
    // where the app is installed: elsewhere, "Resource not accessible by integration".
    if (this.#isApp(auth.grant.clientId)) {
      if (this.#idp.githubApp.permissions.members === undefined || !this.#idp.githubApp.installedOn(org)) return this.#notAccessible(res, auth.grant);
    } else if (!this.#hasScope(auth.grant, ['read:org', 'write:org', 'admin:org', 'user'])) {
      return this.#json(res, auth.grant, 403, {
        message: 'You need at least read:org scope or user scope to read organization memberships.',
        documentation_url: DOCS,
      });
    }
    const login = auth.account.orgs.find((o) => o.toLowerCase() === org.toLowerCase());
    if (!login) return this.#notFound(res, auth.grant);

    const api = `${this.#idp.origin}${API}`;
    this.#json(res, auth.grant, 200, {
      url: `${api}/orgs/${login}/memberships/${auth.account.login}`,
      state: 'active',
      role: 'member',
      organization_url: `${api}/orgs/${login}`,
      organization: {
        login,
        id: 2_000_000 + Number.parseInt(sha256Hex(`github-org:${login.toLowerCase()}`).slice(0, 7), 16),
        url: `${api}/orgs/${login}`,
      },
      user: { login: auth.account.login, id: auth.account.id, type: 'User' },
    });
  }

  /** `Bearer` or GitHub's older `token` scheme; 401 otherwise. */
  #authenticate(req: IncomingMessage, res: ServerResponse): { grant: Grant; account: GitHubAccount } | undefined {
    const token = authorizationToken(req, ['bearer', 'token']);
    if (token === undefined) {
      sendJson(res, 401, { message: 'Requires authentication', documentation_url: DOCS });
      return undefined;
    }
    const grant = this.#authz.grantFor('github', token);
    if (!grant) {
      sendJson(res, 401, { message: 'Bad credentials', documentation_url: DOCS });
      return undefined;
    }
    return { grant, account: this.#idp.gitHubUserFor(normalizeEmail(grant.email)) };
  }

  /** The deployment's GitHub App's OAuth client, whose tokens are user tokens of the app's. */
  #isApp(clientId: string): boolean {
    return clientId === this.#idp.githubApp.clientId;
  }

  #notAccessible(res: ServerResponse, grant: Grant): void {
    this.#json(res, grant, 403, { message: 'Resource not accessible by integration', documentation_url: DOCS });
  }

  #hasScope(grant: Grant, accepted: readonly string[]): boolean {
    return grant.scope.some((s) => accepted.includes(s));
  }

  /** Every authenticated response lists the token's scopes, as GitHub's do. */
  #json(res: ServerResponse, grant: Grant, status: number, body: unknown): void {
    sendJson(res, status, body, { 'x-oauth-scopes': grant.scope.join(', ') });
  }

  #notFound(res: ServerResponse, grant: Grant): void {
    this.#json(res, grant, 404, { message: 'Not Found', documentation_url: DOCS });
  }
}
