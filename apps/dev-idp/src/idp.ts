import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { exportJWK, generateKeyPair, SignJWT, type JWK, type CryptoKey } from 'jose';

import { AuthorizationServer } from './authorize.ts';
import { FakeGitHub } from './github.ts';
import type { Route } from './http.ts';
import { OidcProvider } from './oidc.ts';
import {
  defaultGitHubAccount,
  defaultSubject,
  displayName,
  gitHubEmails,
  normalizeEmail,
  PERSONAS,
  type GitHubAccount,
  type GitHubAccountPatch,
} from './people.ts';

export interface DevIdpClient {
  clientId: string;
  clientSecret: string;
  /** Matched exactly. */
  redirectUris: readonly string[];
}

export interface RegisteredClient extends DevIdpClient {
  /** Accept any http://127.0.0.1 or http://localhost redirect URI, on any port. */
  anyLoopbackRedirect: boolean;
}

export interface DevIdpOptions {
  /** Registered alongside the built-in `coffre-local` client. */
  clients?: readonly DevIdpClient[];
  /** Skip the persona page when the request carries a login hint. For tests. */
  autoApprove?: boolean;
}

/** Built in, so local dev needs no registration step. */
export const DEFAULT_CLIENT = Object.freeze({
  clientId: 'coffre-local',
  clientSecret: 'coffre-local-secret',
});

/**
 * A local stand-in for the identity providers coffre trusts.
 *
 * For Cloudflare Access, it generates a keypair, serves a JWKS at the same
 * `cdn-cgi` path Access uses, and mints Access-shaped tokens. It is also an
 * OpenID Connect provider (under `/oauth`) signing with the same key, and an
 * imitation of GitHub's OAuth apps and REST API (under `/github`). The
 * point is that the code under test runs its real remote code paths against
 * real HTTP endpoints -- local mode is a different implementation of the same
 * interface, never a branch that skips verification.
 */
export class DevIdp {
  #server: Server | null = null;
  #port = 0;
  #clients = new Map<string, RegisteredClient>();
  #subjects = new Map<string, string>();
  #gitHubAccounts = new Map<string, GitHubAccount>();
  #routes: Route[];

  privateKey!: CryptoKey;
  publicJwk!: JWK;
  readonly kid = 'dev-idp-key-1';

  /** Used by the /dev/mint convenience endpoint when no aud is supplied. */
  defaultAudience = 'coffre-local-dev-aud';

  /** Fixed port for the standalone dev server; 0 (ephemeral) in tests. */
  listenPort = 0;

  /** See {@link DevIdpOptions.autoApprove}. */
  autoApprove: boolean;

  constructor(options: DevIdpOptions = {}) {
    this.autoApprove = options.autoApprove ?? false;
    this.#clients.set(DEFAULT_CLIENT.clientId, {
      ...DEFAULT_CLIENT,
      redirectUris: [],
      anyLoopbackRedirect: true,
    });
    for (const client of options.clients ?? []) this.registerClient(client);

    const authz = new AuthorizationServer(this);
    this.#routes = [...new OidcProvider(this, authz).routes(), ...new FakeGitHub(this, authz).routes()];
  }

  get origin(): string {
    if (this.#port === 0) throw new Error('DevIdp is not started');
    return `http://127.0.0.1:${this.#port}`;
  }

  /** Matches the Cloudflare Access team-domain issuer shape. */
  get issuer(): string {
    return this.origin;
  }

  /** Access publishes its keys under this exact path. */
  get jwksUrl(): string {
    return `${this.origin}/cdn-cgi/access/certs`;
  }

  async start(): Promise<void> {
    const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
    this.privateKey = privateKey;
    this.publicJwk = { ...(await exportJWK(publicKey)), kid: this.kid, alg: 'RS256', use: 'sig' };

    this.#server = createServer((req, res) => {
      // Dev-only: stands in for `cloudflared access login`. Cloudflare Access
      // has no equivalent endpoint -- in production the browser SSO flow issues
      // the token and the CLI reads it via cloudflared.
      if (req.url?.startsWith('/dev/mint')) {
        const url = new URL(req.url, this.origin);
        const audience = url.searchParams.get('aud') ?? this.defaultAudience;
        const email = url.searchParams.get('email');
        const commonName = url.searchParams.get('common_name');

        // Callers choose their own lifetime. The web UI asks for a working
        // day, because a token minted for the default 15 minutes turned every
        // local session into a sign-in every quarter of an hour. Left
        // unspecified so the default still applies to everything else.
        const requested = Number(url.searchParams.get('expires_in'));
        const expiresIn =
          Number.isInteger(requested) && requested > 0 ? requested : undefined;

        const minted = commonName
          ? this.mintServiceToken({ audience, commonName, expiresIn })
          : this.mintUserToken({ audience, email: email ?? 'erwin@equisafe.io', expiresIn });

        minted.then((token) => {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ token }));
        });
        return;
      }
      if (req.url === '/cdn-cgi/access/certs') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ keys: [this.publicJwk] }));
        return;
      }
      this.#dispatch(req, res);
    });

    await new Promise<void>((resolve) => {
      this.#server!.listen(this.listenPort, '127.0.0.1', () => {
        const address = this.#server!.address();
        if (address === null || typeof address === 'string') throw new Error('no port');
        this.#port = address.port;
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    if (!this.#server) return;
    await new Promise<void>((resolve) => this.#server!.close(() => resolve()));
    this.#server = null;
    this.#port = 0;
  }

  registerClient(client: DevIdpClient): void {
    this.#clients.set(client.clientId, {
      clientId: client.clientId,
      clientSecret: client.clientSecret,
      redirectUris: [...client.redirectUris],
      anyLoopbackRedirect: false,
    });
  }

  client(clientId: string): RegisteredClient | undefined {
    return this.#clients.get(clientId);
  }

  /** The OIDC `sub` for an email: derived, unless {@link setSubject} overrode it. */
  subjectFor(email: string): string {
    const normalized = normalizeEmail(email);
    return this.#subjects.get(normalized) ?? defaultSubject(normalized);
  }

  /**
   * From now on, whoever signs in with this email gets this subject. Simulates
   * an address being recycled to a new person: same email, different account.
   */
  setSubject(email: string, subject: string): void {
    this.#subjects.set(normalizeEmail(email), subject);
  }

  /** The fake GitHub account that signs in with this email. */
  gitHubUserFor(email: string): GitHubAccount {
    const normalized = normalizeEmail(email);
    return this.#gitHubAccounts.get(normalized) ?? defaultGitHubAccount(normalized);
  }

  /**
   * From now on, whoever picks this email on the fake GitHub gets this account,
   * patched over the current one. A new `id` simulates a recycled address;
   * `emails` can add several, unverified ones included; `orgs` sets memberships.
   */
  setGitHubUser(email: string, patch: GitHubAccountPatch): void {
    const current = this.gitHubUserFor(email);
    this.#gitHubAccounts.set(normalizeEmail(email), {
      id: patch.id ?? current.id,
      login: patch.login ?? current.login,
      name: patch.name ?? current.name,
      emails: patch.emails ? gitHubEmails(patch.emails) : current.emails,
      orgs: patch.orgs ? [...patch.orgs] : current.orgs,
    });
  }

  /** The email that signs in as a GitHub login, for GitHub's `login` hint. */
  emailForGitHubLogin(login: string): string | undefined {
    const wanted = login.toLowerCase();
    for (const [email, account] of this.#gitHubAccounts) {
      if (account.login.toLowerCase() === wanted) return email;
    }
    return PERSONAS.find((p) => this.gitHubUserFor(p.email).login.toLowerCase() === wanted)?.email;
  }

  /** An OIDC ID token, as the token endpoint issues it. */
  async mintIdToken(opts: {
    clientId: string;
    email: string;
    nonce?: string;
    authTime?: number;
    expiresIn?: number;
  }): Promise<string> {
    const email = normalizeEmail(opts.email);
    return this.#sign(
      {
        sub: this.subjectFor(email),
        auth_time: opts.authTime ?? Math.floor(Date.now() / 1000),
        ...(opts.nonce !== undefined && { nonce: opts.nonce }),
        email,
        email_verified: true,
        name: displayName(email),
      },
      { audience: opts.clientId, expiresIn: opts.expiresIn ?? 600 },
    );
  }

  /** Mint a token shaped like an Access identity (human) token. */
  async mintUserToken(opts: {
    audience: string;
    email?: string;
    sub?: string;
    issuer?: string;
    expiresIn?: number;
    notBefore?: number;
    key?: CryptoKey;
  }): Promise<string> {
    return this.#sign(
      {
        email: opts.email ?? 'erwin@equisafe.io',
        sub: opts.sub ?? '0f9a1c2e-1111-2222-3333-444455556666',
        identity_nonce: 'devnonce',
      },
      opts,
    );
  }

  /**
   * Mint a token shaped like an Access *service token*.
   *
   * Deliberately faithful to the real thing: no email claim at all, and an
   * empty sub. Code that reads `claims.email` to identify the caller produces
   * `undefined` here, which is how machine callers end up in the audit log
   * with no actor.
   */
  async mintServiceToken(opts: {
    audience: string;
    commonName?: string;
    issuer?: string;
    expiresIn?: number;
    key?: CryptoKey;
  }): Promise<string> {
    return this.#sign(
      {
        sub: '',
        common_name: opts.commonName ?? 'e367826f93b8d71185e03fe518aff3b4.access',
      },
      opts,
    );
  }

  #dispatch(req: IncomingMessage, res: ServerResponse): void {
    const url = new URL(req.url ?? '/', this.origin);
    const matches = this.#routes.filter((route) =>
      typeof route.path === 'string' ? route.path === url.pathname : route.path.test(url.pathname),
    );
    if (matches.length === 0) {
      res.writeHead(404).end();
      return;
    }
    const route = matches.find((r) => r.method === req.method);
    if (!route) {
      res.writeHead(405, { allow: matches.map((r) => r.method).join(', ') }).end();
      return;
    }
    route.handler(req, res, url).catch((error: unknown) => {
      console.error(error);
      if (!res.headersSent) res.writeHead(500);
      res.end();
    });
  }

  async #sign(
    claims: Record<string, unknown>,
    opts: {
      audience: string;
      issuer?: string;
      expiresIn?: number;
      notBefore?: number;
      key?: CryptoKey;
    },
  ): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = opts.expiresIn ?? 900;

    const jwt = new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: this.kid })
      .setIssuedAt(now)
      .setIssuer(opts.issuer ?? this.issuer)
      .setAudience(opts.audience)
      .setExpirationTime(now + expiresIn);

    if (opts.notBefore !== undefined) jwt.setNotBefore(now + opts.notBefore);

    return jwt.sign(opts.key ?? this.privateKey);
  }
}
