import { createHash, randomBytes } from 'node:crypto';
import type { ServerResponse } from 'node:http';

import { readParams, redirect, repeatedParam, sendHtml, type Route } from './http.ts';
import type { DevIdp, RegisteredClient } from './idp.ts';
import { consentPage, errorPage } from './pages.ts';
import { isEmail, normalizeEmail } from './people.ts';

/**
 * What differs between the OIDC and GitHub authorization endpoints. The rest
 * -- client and redirect checks, PKCE, the persona page, codes and tokens --
 * is one implementation.
 */
export interface Flavor {
  name: 'oidc' | 'github';
  /** The authorization endpoint; the persona page posts back to it. */
  path: string;
  /** Shown above the page title. */
  label: string;
  /** Seconds a code stays redeemable. */
  codeTtl: number;
  /** Adds RFC 9207 `iss` to every response when set. GitHub sends none. */
  issuer: (() => string) | null;
  /** Checks the flavor's own parameters; returns an RFC 6749 error or what they ask for. */
  parse(params: URLSearchParams): FlavorRequest | { error: string; description: string };
  /** Extra response parameters when the person clicks "Deny". */
  denied: Record<string, string>;
}

export interface FlavorRequest {
  scope: string[];
  nonce?: string;
  /** Who the client suggests signing in; an email once resolved. */
  hint?: string;
}

/** An approved request: who signed in, for which client, with what. */
export interface Grant {
  flavor: Flavor['name'];
  clientId: string;
  redirectUri: string;
  scope: string[];
  nonce?: string;
  codeChallenge: string;
  email: string;
  /** Seconds since the epoch. */
  authTime: number;
}

interface CodeRecord {
  grant: Grant;
  expiresAt: number;
  used: boolean;
  accessToken?: string;
}

interface TokenRecord {
  grant: Grant;
  expiresAt: number;
}

type Parsed =
  | { kind: 'ok'; client: RegisteredClient; redirectUri: string; state: string; codeChallenge: string; request: FlavorRequest }
  // The client or its redirect URI is not trusted: say so on a page, never redirect.
  | { kind: 'untrusted'; message: string }
  // Trusted redirect URI, bad request: report it back to the client.
  | { kind: 'error'; redirectUri: string; state?: string; error: string; description: string };

export type ExchangeResult =
  | { ok: true; grant: Grant; accessToken: string; expiresIn: number }
  | { ok: false; error: 'invalid_code' | 'redirect_uri_mismatch' | 'invalid_verifier' };

export function randomToken(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * The built-in client accepts any loopback URI, because local dev ports vary;
 * every other redirect URI must match a registered one exactly.
 */
export function allowsRedirect(client: RegisteredClient, uri: string): boolean {
  if (client.redirectUris.includes(uri)) return true;
  if (!client.anyLoopbackRedirect) return false;
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return false;
  }
  return (
    url.protocol === 'http:' &&
    (url.hostname === '127.0.0.1' || url.hostname === 'localhost') &&
    url.username === '' &&
    url.password === '' &&
    !uri.includes('#')
  );
}

/** RFC 7636 §4.6, S256 only. */
function verifies(verifier: string, challenge: string): boolean {
  if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(verifier)) return false;
  return createHash('sha256').update(verifier).digest('base64url') === challenge;
}

/** Codes and the access tokens they turn into, for both flavors. In memory only. */
export class AuthorizationServer {
  #idp: DevIdp;
  #codes = new Map<string, CodeRecord>();
  #tokens = new Map<string, TokenRecord>();

  constructor(idp: DevIdp) {
    this.#idp = idp;
  }

  /** The GET (show the page, or auto-approve) and POST (the page's answer) routes. */
  routes(flavor: Flavor): Route[] {
    return [
      {
        method: 'GET',
        path: flavor.path,
        handler: async (_req, res, url) => {
          const parsed = this.#parse(flavor, url.searchParams);
          if (parsed.kind !== 'ok') return this.#fail(flavor, res, parsed);

          const hint = parsed.request.hint;
          if (this.#idp.autoApprove && hint !== undefined && isEmail(hint)) {
            return redirect(res, this.#approve(flavor, parsed, normalizeEmail(hint)));
          }
          this.#page(flavor, res, 200, parsed, url.searchParams);
        },
      },
      {
        method: 'POST',
        path: flavor.path,
        handler: async (req, res) => {
          const params = await readParams(req);
          if (params === null) {
            return sendHtml(res, 400, errorPage(flavor.label, 'The form could not be read.'));
          }
          const email = normalizeEmail(params.get('email') ?? '');
          const deny = params.has('deny');
          params.delete('email');
          params.delete('deny');

          // The carried parameters came back through the browser: check them again.
          const parsed = this.#parse(flavor, params);
          if (parsed.kind !== 'ok') return this.#fail(flavor, res, parsed);

          if (deny) {
            return redirect(
              res,
              this.#location(flavor, parsed.redirectUri, {
                error: 'access_denied',
                ...flavor.denied,
                state: parsed.state,
              }),
            );
          }
          if (!isEmail(email)) {
            return this.#page(flavor, res, 400, parsed, params, 'Pick a persona or enter an email address.');
          }
          redirect(res, this.#approve(flavor, parsed, email));
        },
      },
    ];
  }

  /**
   * Redeem a code. Codes are single-use even when the attempt fails, and
   * presenting a spent code revokes the token it produced (RFC 6749 §4.1.2).
   */
  exchange(
    flavor: Flavor['name'],
    opts: {
      client: RegisteredClient;
      code: string;
      /** Undefined skips the check (GitHub makes the parameter optional). */
      redirectUri: string | undefined;
      codeVerifier: string;
      accessTokenTtl: number;
      accessTokenPrefix?: string;
    },
  ): ExchangeResult {
    this.#sweep();
    const record = this.#codes.get(opts.code);
    if (!record || record.grant.flavor !== flavor) return { ok: false, error: 'invalid_code' };
    if (record.used) {
      if (record.accessToken) this.#tokens.delete(record.accessToken);
      this.#codes.delete(opts.code);
      return { ok: false, error: 'invalid_code' };
    }
    record.used = true;

    const { grant } = record;
    if (grant.clientId !== opts.client.clientId) return { ok: false, error: 'invalid_code' };
    if (opts.redirectUri !== undefined && opts.redirectUri !== grant.redirectUri) {
      return { ok: false, error: 'redirect_uri_mismatch' };
    }
    if (!verifies(opts.codeVerifier, grant.codeChallenge)) return { ok: false, error: 'invalid_verifier' };

    const accessToken = (opts.accessTokenPrefix ?? '') + randomToken();
    record.accessToken = accessToken;
    this.#tokens.set(accessToken, { grant, expiresAt: Date.now() + opts.accessTokenTtl * 1000 });
    return { ok: true, grant, accessToken, expiresIn: opts.accessTokenTtl };
  }

  /** The grant behind a live access token of this flavor. */
  grantFor(flavor: Flavor['name'], accessToken: string): Grant | undefined {
    const record = this.#tokens.get(accessToken);
    if (!record || record.grant.flavor !== flavor || record.expiresAt <= Date.now()) return undefined;
    return record.grant;
  }

  #parse(flavor: Flavor, params: URLSearchParams): Parsed {
    const repeated = repeatedParam(params);
    if (repeated) return { kind: 'untrusted', message: `Parameter ${repeated} is repeated.` };

    const clientId = params.get('client_id');
    if (!clientId) return { kind: 'untrusted', message: 'client_id is missing.' };
    const client = this.#idp.client(clientId);
    if (!client) return { kind: 'untrusted', message: `Unknown client ${clientId}.` };

    const redirectUri = params.get('redirect_uri');
    if (!redirectUri) return { kind: 'untrusted', message: 'redirect_uri is missing.' };
    if (!allowsRedirect(client, redirectUri)) {
      return { kind: 'untrusted', message: `${redirectUri} is not a redirect URI registered for ${clientId}.` };
    }

    const fail = (error: string, description: string): Parsed => ({
      kind: 'error',
      redirectUri,
      state: params.get('state') ?? undefined,
      error,
      description,
    });

    const request = flavor.parse(params);
    if ('error' in request) return fail(request.error, request.description);

    // Required here even where GitHub only recommends them, so a client that
    // drops CSRF or PKCE protection fails its tests rather than production.
    const state = params.get('state');
    if (!state) return fail('invalid_request', 'state is required');
    const method = params.get('code_challenge_method');
    const codeChallenge = params.get('code_challenge');
    if (!codeChallenge) return fail('invalid_request', 'code_challenge is required');
    if (method !== 'S256') return fail('invalid_request', 'code_challenge_method must be S256');
    if (!/^[A-Za-z0-9_-]{43}$/.test(codeChallenge)) {
      return fail('invalid_request', 'code_challenge must be a base64url SHA-256 digest');
    }

    return { kind: 'ok', client, redirectUri, state, codeChallenge, request };
  }

  #fail(flavor: Flavor, res: ServerResponse, parsed: Exclude<Parsed, { kind: 'ok' }>): void {
    if (parsed.kind === 'untrusted') return sendHtml(res, 400, errorPage(flavor.label, parsed.message));
    redirect(
      res,
      this.#location(flavor, parsed.redirectUri, {
        error: parsed.error,
        error_description: parsed.description,
        state: parsed.state,
      }),
    );
  }

  #page(
    flavor: Flavor,
    res: ServerResponse,
    status: number,
    parsed: Extract<Parsed, { kind: 'ok' }>,
    carry: URLSearchParams,
    message?: string,
  ): void {
    sendHtml(
      res,
      status,
      consentPage({
        label: flavor.label,
        action: flavor.path,
        clientId: parsed.client.clientId,
        redirectUri: parsed.redirectUri,
        scope: parsed.request.scope,
        carry,
        hint: parsed.request.hint,
        message,
      }),
    );
  }

  #approve(flavor: Flavor, parsed: Extract<Parsed, { kind: 'ok' }>, email: string): string {
    this.#sweep();
    const code = randomToken();
    this.#codes.set(code, {
      grant: {
        flavor: flavor.name,
        clientId: parsed.client.clientId,
        redirectUri: parsed.redirectUri,
        scope: parsed.request.scope,
        nonce: parsed.request.nonce,
        codeChallenge: parsed.codeChallenge,
        email,
        authTime: Math.floor(Date.now() / 1000),
      },
      expiresAt: Date.now() + flavor.codeTtl * 1000,
      used: false,
    });
    return this.#location(flavor, parsed.redirectUri, { code, state: parsed.state });
  }

  #location(flavor: Flavor, redirectUri: string, params: Record<string, string | undefined>): string {
    const url = new URL(redirectUri);
    for (const [name, value] of Object.entries(params)) {
      if (value !== undefined) url.searchParams.set(name, value);
    }
    if (flavor.issuer) url.searchParams.set('iss', flavor.issuer());
    return url.href;
  }

  #sweep(): void {
    const now = Date.now();
    for (const [code, record] of this.#codes) if (record.expiresAt <= now) this.#codes.delete(code);
    for (const [token, record] of this.#tokens) if (record.expiresAt <= now) this.#tokens.delete(token);
  }
}
