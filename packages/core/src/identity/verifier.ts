import { createLocalJWKSet, decodeProtectedHeader, errors, jwtVerify, type JSONWebKeySet, type JWTPayload } from 'jose';
import type { AccessVerifierConfig, IdentityVerifier, Principal } from './types.ts';

export type { AccessVerifierConfig };

/**
 * Signature algorithms we accept, as an explicit allowlist.
 *
 * Without this, the algorithm is taken from the attacker-controlled token
 * header, which is how `alg: none` and RS256->HS256 confusion work. jose
 * defaults to permitting whatever the key supports; we do not rely on that.
 */
const ALLOWED_ALGORITHMS = ['RS256', 'ES256'] as const;

/** How long a key set is used before it is fetched again, and the least time between two fetches an unknown key asks for. */
const KEYS_MAX_AGE_MS = 10 * 60_000;
const REFETCH_COOLDOWN_MS = 30_000;

type AccessClaims = JWTPayload & {
  email?: unknown;
  common_name?: unknown;
};

function asNonEmptyString(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/** The team's keys could not be fetched, or are no key set: no assertion can be checked, which is not the caller's fault. */
export class AccessKeysUnavailable extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'AccessKeysUnavailable';
  }
}

/** How the verifier fetches the team's key set, and what time it is. */
export type AccessVerifierIo = {
  /** GET a JSON document; throws when it cannot. The global `fetch` unless given. */
  json?: (url: URL) => Promise<unknown>;
  now?: () => number;
};

async function fetchJson(url: URL): Promise<unknown> {
  const response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(5_000), headers: { accept: 'application/json' } });
  if (response.status !== 200) {
    await response.body?.cancel();
    throw new Error(`${url.href} answered ${response.status}`);
  }
  return response.json();
}

/**
 * Verifies Cloudflare Access JWTs.
 *
 * Signature and claim verification of the token Access sends with each
 * request. The team's keys are fetched when first needed, used for ten
 * minutes, and fetched again sooner for a key they lack, at most every 30
 * seconds. The verifier lives as long as its configuration (an isolate's,
 * on Workers) and keeps settled values only, never a fetch in flight
 * (AGENTS.md, "What an isolate keeps"): concurrent requests that find no
 * key set each fetch their own, and the last to land is kept. The 30
 * seconds count from the last refresh started, landed or not, and are
 * taken before it starts: of a burst of assertions naming a key the set
 * lacks, one fetches, and the others are refused as the key unknown.
 */
export class AccessIdentityVerifier implements IdentityVerifier {
  readonly #config: AccessVerifierConfig;
  readonly #url: URL;
  readonly #json: (url: URL) => Promise<unknown>;
  readonly #now: () => number;
  #keys: { set: ReturnType<typeof createLocalJWKSet>; at: number } | null = null;
  /** When a refresh for an unknown key last started: a number, settled the moment it starts. */
  #refreshed = Number.NEGATIVE_INFINITY;

  constructor(config: AccessVerifierConfig, io: AccessVerifierIo = {}) {
    this.#config = config;
    this.#url = new URL(config.jwksUrl);
    this.#json = io.json ?? fetchJson;
    this.#now = io.now ?? Date.now;
  }

  async verify(token: string): Promise<Principal> {
    if (typeof token !== 'string' || token.length === 0) {
      throw new Error('missing or empty Access token');
    }
    // Malformed, or signed with an algorithm we never take: refused before anything is fetched for it.
    const { alg } = decodeProtectedHeader(token);
    if (!(ALLOWED_ALGORITHMS as readonly unknown[]).includes(alg)) throw new errors.JOSEAlgNotAllowed(`"alg" (Algorithm) Header Parameter value not allowed`);
    const options = {
      issuer: this.#config.issuer,
      audience: this.#config.audience,
      algorithms: [...ALLOWED_ALGORITHMS],
      clockTolerance: this.#config.clockToleranceSeconds ?? 0,
    };
    let keys = this.#keys;
    if (keys === null || this.#now() - keys.at >= KEYS_MAX_AGE_MS) keys = await this.#fetch();
    try {
      return toPrincipal((await jwtVerify<AccessClaims>(token, keys.set, options)).payload);
    } catch (error) {
      // A key the set lacks may be one Access rotated in since: asked again, once, past the cooldown.
      const now = this.#now();
      if (!(error instanceof errors.JWKSNoMatchingKey) || now - Math.max(keys.at, this.#refreshed) < REFETCH_COOLDOWN_MS) throw error;
      this.#refreshed = now;
    }
    return toPrincipal((await jwtVerify<AccessClaims>(token, (await this.#fetch()).set, options)).payload);
  }

  async #fetch(): Promise<{ set: ReturnType<typeof createLocalJWKSet>; at: number }> {
    let set: ReturnType<typeof createLocalJWKSet>;
    try {
      set = createLocalJWKSet((await this.#json(this.#url)) as JSONWebKeySet);
    } catch (error) {
      throw new AccessKeysUnavailable(`Cloudflare Access's keys could not be fetched from ${this.#url.href}`, { cause: error });
    }
    return (this.#keys = { set, at: this.#now() });
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
    // People are stored by lowercased email; see principals_user_id_lowercase.
    const id = email.toLowerCase();
    return { type: 'user', id, email: id, subject };
  }

  throw new Error(
    'token verified but carries no usable identity: expected common_name (service) or sub+email (user)',
  );
}
