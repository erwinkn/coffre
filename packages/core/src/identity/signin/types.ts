/**
 * What a provider reports about the person who just signed in.
 *
 * `subject` is the provider's permanent id for the account: OIDC's `sub`,
 * GitHub's numeric user id. coffre binds to it and to nothing else, since a
 * login name can be renamed and an email address can be handed to someone new.
 */
export type SigninProfile = {
  /** The configured provider id, e.g. "github". */
  provider: string;
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
  provider: string;
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

export interface SigninProvider {
  readonly id: string;
  /** Where to send the browser, and what to remember until it comes back. */
  start(redirectUri: string, options?: { loginHint?: string }): Promise<{
    url: URL;
    pending: PendingSignin;
  }>;
  /** Exchange the callback for a verified profile, or throw a SigninError. */
  finish(callbackUrl: URL, redirectUri: string, pending: PendingSignin): Promise<SigninProfile>;
}
