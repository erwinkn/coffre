/**
 * An authenticated caller.
 *
 * Modelled as a tagged union rather than "a user with an optional email",
 * because Cloudflare Access issues two structurally different tokens:
 *
 *   identity token  -> sub = user uuid, email = "erwin@equisafe.io"
 *   service token   -> sub = ""       , common_name = "<client-id>.access", NO email
 *
 * Machine callers (external-secrets, CI) are most of the real traffic, so the
 * shape that cannot represent them is the wrong shape.
 */
export type Principal =
  | {
      type: 'user';
      /** Stable identifier used in grants and in the audit log. */
      id: string;
      email: string;
      subject: string;
    }
  | {
      type: 'service';
      /** Stable identifier used in grants and in the audit log. */
      id: string;
      commonName: string;
    };

/**
 * Verifies a bearer token and returns the caller it identifies.
 *
 * Production points at the Cloudflare Access team domain; local development
 * points at the dev IdP. Same code, different configuration.
 */
export interface IdentityVerifier {
  verify(token: string): Promise<Principal>;
}

/** Access delivers the JWT to the origin in this header. */
export const ACCESS_JWT_HEADER = 'cf-access-jwt-assertion';
