import { createServer, type Server } from 'node:http';
import { exportJWK, generateKeyPair, SignJWT, type JWK, type CryptoKey } from 'jose';

/**
 * A local stand-in for Cloudflare Access.
 *
 * It generates a keypair, serves a JWKS at the same `cdn-cgi` path Access uses,
 * and mints Access-shaped tokens. The point is that the verifier under test
 * runs its real remote-JWKS code path against a real HTTP endpoint -- local
 * mode is a different implementation of the same interface, never a branch
 * that skips verification.
 */
export class DevIdp {
  #server: Server | null = null;
  #port = 0;

  privateKey!: CryptoKey;
  publicJwk!: JWK;
  readonly kid = 'dev-idp-key-1';

  /** Used by the /dev/mint convenience endpoint when no aud is supplied. */
  defaultAudience = 'coffre-local-dev-aud';

  /** Fixed port for the standalone dev server; 0 (ephemeral) in tests. */
  listenPort = 0;

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

        // Callers choose their own lifetime. The admin UI asks for a working
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
      if (req.url === '/.well-known/openid-configuration') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ issuer: this.issuer, jwks_uri: this.jwksUrl }));
        return;
      }
      res.writeHead(404).end();
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
