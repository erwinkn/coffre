import * as oauth from 'oauth4webapi';

import type { GitHubProviderConfig } from './config.ts';
import {
  SigninError,
  type PendingSignin,
  type ProviderOptions,
  type SigninProfile,
  type SigninProvider,
} from './types.ts';

type GitHubUser = { id: number; login: string; name: string | null };
type GitHubEmail = { email: string; primary: boolean; verified: boolean };

/**
 * GitHub's OAuth web flow, which is OAuth 2.0 without OpenID Connect: no ID
 * token, so the profile comes from the REST API with the access token the
 * code is exchanged for. That token is used for these two or three calls and
 * then dropped; coffre never stores it.
 *
 * Works with an OAuth App or a GitHub App's user authorization, on github.com
 * or GitHub Enterprise Server.
 */
export class GitHubSigninProvider implements SigninProvider {
  readonly id: string;
  readonly #config: GitHubProviderConfig;
  readonly #fetch: typeof fetch;

  constructor(config: GitHubProviderConfig, options: ProviderOptions = {}) {
    this.id = config.id;
    this.#config = config;
    this.#fetch = options.fetch ?? ((input, init) => fetch(input, init));
  }

  async start(redirectUri: string, options: { loginHint?: string } = {}) {
    const pending: PendingSignin = {
      provider: this.id,
      state: oauth.generateRandomState(),
      codeVerifier: oauth.generateRandomCodeVerifier(),
      nonce: null,
    };

    const url = new URL(`${this.#config.webUrl}/login/oauth/authorize`);
    const params = url.searchParams;
    params.set('client_id', this.#config.clientId);
    params.set('redirect_uri', redirectUri);
    // `read:org` lets the membership check see private memberships; without
    // it, GitHub only reports members who made theirs public.
    params.set('scope', this.#config.organization ? 'read:user user:email read:org' : 'read:user user:email');
    params.set('state', pending.state);
    params.set('code_challenge', await oauth.calculatePKCECodeChallenge(pending.codeVerifier));
    params.set('code_challenge_method', 'S256');
    params.set('allow_signup', 'false');
    if (options.loginHint !== undefined) params.set('login', options.loginHint);

    return { url, pending };
  }

  async finish(callbackUrl: URL, redirectUri: string, pending: PendingSignin): Promise<SigninProfile> {
    const label = this.#config.label;
    const query = callbackUrl.searchParams;

    if (query.get('state') !== pending.state) {
      throw new SigninError('state_mismatch', `the ${label} callback does not match this sign-in`);
    }
    const refused = query.get('error');
    if (refused !== null) {
      throw new SigninError('provider_denied', `${label} refused the sign-in: ${refused}`);
    }
    const code = query.get('code');
    if (code === null || code === '') {
      throw new SigninError('invalid_response', `the ${label} callback carries no code`);
    }

    const token = await this.#exchange(code, redirectUri, pending.codeVerifier);
    const user = await this.#api<GitHubUser>(token, '/user');
    if (typeof user?.id !== 'number') {
      throw new SigninError('invalid_response', `${label} did not say who signed in`);
    }

    const organization = this.#config.organization;
    if (organization !== null && !(await this.#isMember(token, organization))) {
      throw new SigninError(
        'not_in_organization',
        `only members of the ${organization} organization may sign in with ${label}`,
      );
    }

    const listed = await this.#api<GitHubEmail[]>(token, '/user/emails');
    const emails = (Array.isArray(listed) ? listed : [])
      .filter((entry) => entry.verified && typeof entry.email === 'string')
      .sort((a, b) => Number(b.primary) - Number(a.primary))
      .map((entry) => entry.email.trim().toLowerCase());

    return {
      provider: this.id,
      subject: String(user.id),
      emails: [...new Set(emails)],
      name: user.name ?? user.login,
    };
  }

  async #exchange(code: string, redirectUri: string, codeVerifier: string): Promise<string> {
    const label = this.#config.label;
    const response = await this.#send(`${this.#config.webUrl}/login/oauth/access_token`, {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: this.#config.clientId,
        client_secret: this.#config.clientSecret,
        code,
        redirect_uri: redirectUri,
        code_verifier: codeVerifier,
      }),
    });
    // GitHub reports a bad code with a 200 and an `error` field.
    const body = (await readJson(response)) as { access_token?: unknown; error?: unknown } | null;
    if (!response.ok || body === null) {
      throw new SigninError('invalid_response', `${label} answered the code exchange with ${response.status}`);
    }
    if (typeof body.error === 'string') {
      throw new SigninError('provider_denied', `${label} refused the code: ${body.error}`);
    }
    if (typeof body.access_token !== 'string' || body.access_token === '') {
      throw new SigninError('invalid_response', `${label} returned no access token`);
    }
    return body.access_token;
  }

  async #isMember(token: string, organization: string): Promise<boolean> {
    const response = await this.#send(
      `${this.#config.apiUrl}/user/memberships/orgs/${encodeURIComponent(organization)}`,
      { headers: apiHeaders(token) },
    );
    if (response.status === 404 || response.status === 403) return false;
    const body = (await readJson(response)) as { state?: unknown } | null;
    if (!response.ok || body === null) {
      throw new SigninError('invalid_response', `${this.#config.label} answered the membership check with ${response.status}`);
    }
    return body.state === 'active';
  }

  async #api<T>(token: string, path: string): Promise<T | null> {
    const response = await this.#send(`${this.#config.apiUrl}${path}`, {
      headers: apiHeaders(token),
    });
    if (!response.ok) {
      throw new SigninError('invalid_response', `${this.#config.label} answered ${path} with ${response.status}`);
    }
    return (await readJson(response)) as T | null;
  }

  // A redirect is never followed: callers treat any answer other than a 2xx,
  // a 3xx included, as one coffre cannot trust. Workers only offer 'follow'
  // and 'manual'; 'error' throws there before any request is made.
  async #send(url: string, init: RequestInit): Promise<Response> {
    try {
      return await this.#fetch(url, { ...init, redirect: 'manual', signal: AbortSignal.timeout(10_000) });
    } catch (cause) {
      const error = new SigninError('provider_unavailable', `${this.#config.label} could not be reached`);
      (error as Error & { cause?: unknown }).cause = cause;
      throw error;
    }
  }
}

function apiHeaders(token: string): Record<string, string> {
  return {
    accept: 'application/vnd.github+json',
    authorization: `Bearer ${token}`,
    'user-agent': 'coffre',
    'x-github-api-version': '2022-11-28',
  };
}

async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}
