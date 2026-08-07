import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import type { IdentityVerifier, Principal } from './types.ts';

export type AccessVerifierConfig = {
  /** Cloudflare Access team domain, e.g. https://equisafe.cloudflareaccess.com */
  issuer: string;
  /** Usually `${issuer}/cdn-cgi/access/certs`. */
  jwksUrl: string;
  /** The AUD tag of the specific Access application. */
  audience: string;
  /** Seconds of clock skew tolerated. Kept at 0 by default deliberately. */
  clockToleranceSeconds?: number;
};

/**
 * Signature algorithms we accept, as an explicit allowlist.
 *
 * Without this, the algorithm is taken from the attacker-controlled token
 * header, which is how `alg: none` and RS256->HS256 confusion work. jose
 * defaults to permitting whatever the key supports; we do not rely on that.
 */
const ALLOWED_ALGORITHMS = ['RS256', 'ES256'] as const;

type AccessClaims = JWTPayload & {
  email?: unknown;
  common_name?: unknown;
};

function asNonEmptyString(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/**
 * Verifies Cloudflare Access JWTs.
 *
 * Signature and claim verification for the TanStack request boundary. The
 * boundary also rejects `x-middleware-subrequest` before calling this verifier.
 */
export class AccessIdentityVerifier implements IdentityVerifier {
  readonly #config: AccessVerifierConfig;
  readonly #jwks: ReturnType<typeof createRemoteJWKSet>;

  constructor(config: AccessVerifierConfig) {
    this.#config = config;
    // jose handles JWKS fetching, caching and rotation-driven refetch. Not
    // something to hand-roll.
    this.#jwks = createRemoteJWKSet(new URL(config.jwksUrl), {
      cooldownDuration: 30_000,
      cacheMaxAge: 600_000,
    });
  }

  async verify(token: string): Promise<Principal> {
    if (typeof token !== 'string' || token.length === 0) {
      throw new Error('missing or empty Access token');
    }

    const { payload } = await jwtVerify<AccessClaims>(token, this.#jwks, {
      issuer: this.#config.issuer,
      audience: this.#config.audience,
      algorithms: [...ALLOWED_ALGORITHMS],
      clockTolerance: this.#config.clockToleranceSeconds ?? 0,
    });

    return toPrincipal(payload);
  }
}

/**
 * Derive the caller from verified claims.
 *
 * Order matters. A service token is identified by `common_name` and carries an
 * empty `sub`; an identity token carries both `sub` and `email`. Anything else
 * is rejected rather than being allowed through as an authenticated caller
 * with no name -- an audit row with a null actor answers no question worth
 * asking.
 */
export function toPrincipal(claims: AccessClaims): Principal {
  const commonName = asNonEmptyString(claims.common_name);
  if (commonName !== null) {
    return { type: 'service', id: commonName, commonName };
  }

  const email = asNonEmptyString(claims.email);
  const subject = asNonEmptyString(claims.sub);
  if (email !== null && subject !== null) {
    return { type: 'user', id: email, email, subject };
  }

  throw new Error(
    'token verified but carries no usable identity: expected common_name (service) or sub+email (user)',
  );
}
