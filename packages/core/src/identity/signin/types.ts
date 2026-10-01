/**
 * What a provider reports about the person who just signed in.
 *
 * `subject` is the provider's permanent id for the account: OIDC's `sub`,
 * GitHub's numeric user id. coffre binds to it and to nothing else, since a
 * login name can be renamed and an email address can be handed to someone new.
 */
export type SigninProfile = {
  subject: string;
  /** Verified addresses only, lowercased, the provider's primary first. */
  emails: string[];
  name: string | null;
};

/**
 * What must survive the round trip through the provider: the anti-CSRF
 * state, the PKCE verifier and, for OIDC, the nonce. coffre keeps it in an
 * encrypted, short-lived cookie rather than in the database, so an
 * unauthenticated visitor cannot make coffre write anything.
 */
export type PendingSignin = {
  state: string;
  codeVerifier: string;
  nonce: string | null;
};

export type SigninErrorCode =
  /** The person cancelled, or the provider refused them. */
  | 'provider_denied'
  /** The callback does not belong to the sign-in this browser started. */
  | 'state_mismatch'
  /** The provider answered, but not in a way that can be trusted. */
  | 'invalid_response'
  /** The provider could not be reached. */
  | 'provider_unavailable'
  /** The account has no verified email address to match an invitation with. */
  | 'no_verified_email'
  /** A Google account outside the configured Workspace domain. */
  | 'wrong_domain'
  /** A GitHub account outside the configured organization. */
  | 'not_in_organization';

export class SigninError extends Error {
  readonly code: SigninErrorCode;
  constructor(code: SigninErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

export type ProviderOptions = {
  /** Injected by tests; defaults to globalThis.fetch. */
  fetch?: typeof fetch;
};

/** Which mark the sign-in button carries: GitHub's, Google's, Microsoft's, or a plain key. */
export type SigninBrand = 'github' | 'google' | 'microsoft' | 'oidc';

/**
 * A way to sign in: send the browser to whoever knows the person, and take
 * back who they are. `github()`, `google()`, `microsoft()` and `oidc()` make
 * one; so can a deployment, for a provider that is none of those. coffre
 * does everything around it: the pending state, sealed in a cookie between
 * the two calls, binding the profile to a member, sessions, CLI logins and
 * service tokens.
 *
 *   const acme: SigninProvider = {
 *     id: 'acme',
 *     issuer: 'https://sso.acme.example',
 *     label: 'Acme SSO',
 *     brand: 'oidc',
 *     async start(redirectUri) { … return { url, pending: { state, codeVerifier, nonce: null } }; },
 *     async finish(callbackUrl, redirectUri, pending) { … return { subject, emails, name }; },
 *   };
 */
export interface SigninProvider {
  /** Stable: part of the callback URL, `/auth/callback/{id}`, and of every account bound through it. */
  readonly id: string;
  /** The authority whose subjects these are; changing it requires linking accounts again. */
  readonly issuer: string;
  /** Button text: "Continue with {label}". */
  readonly label: string;
  readonly brand: SigninBrand;
  /** Where to send the browser, and what to remember until it comes back. */
  start(redirectUri: string, options?: { loginHint?: string }): Promise<{
    url: URL;
    pending: PendingSignin;
  }>;
  /**
   * The person back from the provider, verified: check the callback against
   * `pending`, and throw a SigninError for anything that does not hold.
   */
  finish(callbackUrl: URL, redirectUri: string, pending: PendingSignin): Promise<SigninProfile>;
}
