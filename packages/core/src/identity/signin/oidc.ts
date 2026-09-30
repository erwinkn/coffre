import * as oauth from 'oauth4webapi';

import type { OidcProviderConfig } from './config.ts';
import {
  SigninError,
  type PendingSignin,
  type ProviderOptions,
  type SigninBrand,
  type SigninProfile,
  type SigninProvider,
} from './types.ts';

/** Discovery documents change rarely; an hour keeps one fetch off every sign-in. */
const DISCOVERY_TTL_MS = 60 * 60 * 1000;

type Discovered = { server: oauth.AuthorizationServer; fetchedAt: number };

/**
 * The authorization code flow with PKCE, against any OpenID Connect issuer.
 *
 * Protocol work is delegated to oauth4webapi: discovery with issuer
 * validation, the RFC 9207 `iss` check on the callback, the token request and
 * ID token claim validation (issuer, audience, expiry, nonce). The ID token is
 * received straight from the token endpoint over TLS with client
 * authentication, which OpenID Connect Core 3.1.3.7 accepts in place of
 * checking its signature.
 */
export class OidcSigninProvider implements SigninProvider {
  readonly id: string;
  readonly label: string;
  readonly brand: SigninBrand;
  /** What it was made from, as checked. */
  readonly config: OidcProviderConfig;
  readonly #fetch: typeof fetch | undefined;
  readonly #insecure: boolean;
  #discovered: Discovered | null = null;

  constructor(config: OidcProviderConfig, options: ProviderOptions = {}) {
    this.id = config.id;
    this.label = config.label;
    this.brand = config.brand;
    this.config = config;
    this.#fetch = options.fetch;
    // Only ever true for the dev IdP: config rejects plain HTTP off loopback.
    this.#insecure = new URL(config.issuer).protocol === 'http:';
  }

  #http<Method, Body = undefined>(): oauth.HttpRequestOptions<Method, Body> {
    const options: oauth.HttpRequestOptions<Method, Body> = {
      signal: () => AbortSignal.timeout(10_000),
    };
    if (this.#fetch !== undefined) {
      const fetchImpl = this.#fetch;
      options[oauth.customFetch] = (url, init) => fetchImpl(url, init as RequestInit);
    }
    if (this.#insecure) options[oauth.allowInsecureRequests] = true;
    return options;
  }

  get #client(): oauth.Client {
    return { client_id: this.config.clientId };
  }

  async #server(): Promise<oauth.AuthorizationServer> {
    if (this.#discovered !== null && Date.now() - this.#discovered.fetchedAt < DISCOVERY_TTL_MS) {
      return this.#discovered.server;
    }
    const issuer = new URL(this.config.issuer);
    let server: oauth.AuthorizationServer;
    try {
      const response = await oauth.discoveryRequest(issuer, { ...this.#http<'GET'>(), algorithm: 'oidc' });
      server = await oauth.processDiscoveryResponse(issuer, response);
    } catch (error) {
      throw unavailable(this.config.label, error);
    }
    this.#discovered = { server, fetchedAt: Date.now() };
    return server;
  }

  async start(redirectUri: string, options: { loginHint?: string } = {}) {
    const server = await this.#server();
    if (server.authorization_endpoint === undefined) {
      throw new SigninError(
        'invalid_response',
        `${this.config.label} publishes no authorization endpoint`,
      );
    }

    const pending: PendingSignin = {
      state: oauth.generateRandomState(),
      codeVerifier: oauth.generateRandomCodeVerifier(),
      nonce: oauth.generateRandomNonce(),
    };

    const url = new URL(server.authorization_endpoint);
    const params = url.searchParams;
    params.set('client_id', this.config.clientId);
    params.set('redirect_uri', redirectUri);
    params.set('response_type', 'code');
    params.set('scope', this.config.scopes.join(' '));
    params.set('state', pending.state);
    params.set('nonce', pending.nonce as string);
    params.set('code_challenge', await oauth.calculatePKCECodeChallenge(pending.codeVerifier));
    params.set('code_challenge_method', 'S256');
    for (const [name, value] of Object.entries(this.config.authorizationParams)) {
      params.set(name, value);
    }
    if (options.loginHint !== undefined) params.set('login_hint', options.loginHint);

    return { url, pending };
  }

  async finish(callbackUrl: URL, redirectUri: string, pending: PendingSignin): Promise<SigninProfile> {
    const server = await this.#server();
    const label = this.config.label;

    let params: URLSearchParams;
    try {
      params = oauth.validateAuthResponse(server, this.#client, callbackUrl, pending.state);
    } catch (error) {
      if (error instanceof oauth.AuthorizationResponseError) {
        throw new SigninError('provider_denied', `${label} refused the sign-in: ${error.error}`);
      }
      throw new SigninError('state_mismatch', `the ${label} callback does not match this sign-in`);
    }

    let claims: oauth.IDToken;
    try {
      const response = await oauth.authorizationCodeGrantRequest(
        server,
        this.#client,
        oauth.ClientSecretPost(this.config.clientSecret),
        params,
        redirectUri,
        pending.codeVerifier,
        this.#http<'POST', URLSearchParams>(),
      );
      const result = await oauth.processAuthorizationCodeResponse(server, this.#client, response, {
        expectedNonce: pending.nonce ?? oauth.expectNoNonce,
        requireIdToken: true,
      });
      claims = oauth.getValidatedIdTokenClaims(result) as oauth.IDToken;
    } catch (error) {
      if (error instanceof SigninError) throw error;
      if (error instanceof oauth.ResponseBodyError) {
        throw new SigninError('provider_denied', `${label} refused the code: ${error.error}`);
      }
      if (isNetworkError(error)) throw unavailable(label, error);
      throw new SigninError('invalid_response', `${label} returned a token coffre cannot trust`);
    }

    return this.#profile(claims);
  }

  #profile(claims: oauth.IDToken): SigninProfile {
    const label = this.config.label;

    if (this.config.hostedDomain !== null && claims.hd !== this.config.hostedDomain) {
      throw new SigninError(
        'wrong_domain',
        `only ${this.config.hostedDomain} accounts may sign in with ${label}`,
      );
    }

    // Providers that do not send `email_verified` at all (Entra among them)
    // are trusted to only assert addresses they manage; one that sends it as
    // false is believed.
    const email = typeof claims.email === 'string' ? claims.email.trim().toLowerCase() : '';
    const emails = email !== '' && claims.email_verified !== false ? [email] : [];

    return {
      subject: claims.sub,
      emails,
      name: typeof claims.name === 'string' ? claims.name : null,
    };
  }
}

function isNetworkError(error: unknown): boolean {
  return (
    error instanceof TypeError ||
    (error instanceof Error && (error.name === 'TimeoutError' || error.name === 'AbortError'))
  );
}

function unavailable(label: string, cause: unknown): SigninError {
  const error = new SigninError('provider_unavailable', `${label} could not be reached`);
  (error as Error & { cause?: unknown }).cause = cause;
  return error;
}
