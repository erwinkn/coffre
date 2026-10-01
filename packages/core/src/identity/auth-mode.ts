import { defineSignin, type SigninConfig, type SigninProviderConfig } from './signin/config.ts';
import type { AccessVerifierConfig } from './types.ts';

/**
 * Who vouches for the person at the other end of a request.
 *
 * - `signin`: coffre itself, after the person signs in with one of the
 *   configured providers (GitHub, Google, Microsoft, any OIDC issuer).
 * - `cloudflare`: Cloudflare Access, in front of coffre.
 * - `dev`: the local dev IdP's persona picker. Never deployed.
 */
export type AuthMode = 'dev' | 'cloudflare' | 'signin';

export type AuthConfig =
  | {
      mode: 'dev';
      access: AccessVerifierConfig;
      devIdpUrl: string;
    }
  | {
      mode: 'cloudflare';
      access: AccessVerifierConfig;
    }
  | {
      mode: 'signin';
      signin: SigninConfig;
    };

/**
 * What a deployment writes as `auth`: `signin(…)`, `cloudflareAccess(…)` or
 * `devIdp(…)`. Each checks its own options when called; sign-in is finished
 * against the deployment's public URL, which its callbacks are built from.
 */
export type Auth = {
  readonly mode: AuthMode;
  resolve(publicUrl: string): AuthConfig;
};

function origin(what: string, value: string, protocol: 'https:' | 'http:'): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${what} must be an absolute URL`);
  }
  if (
    url.protocol !== protocol ||
    url.username !== '' ||
    url.password !== '' ||
    url.pathname !== '/' ||
    url.search !== '' ||
    url.hash !== ''
  ) {
    throw new Error(`${what} must be an ${protocol === 'https:' ? 'HTTPS' : 'HTTP'} origin, with no path, query or credentials`);
  }
  return url;
}

function checkAudience(audience: string, what: string): string {
  if (audience.length === 0 || audience.length > 64 || /\s/.test(audience)) {
    throw new Error(`${what} must be a non-whitespace Access AUD tag of at most 64 characters`);
  }
  return audience;
}

/**
 * Cloudflare Access in front of coffre: every request carries Access's
 * signed assertion, checked against the team's keys and the application's
 * AUD tag.
 *
 *   cloudflareAccess({ teamDomain: 'acme.cloudflareaccess.com', audience: env.ACCESS_AUD })
 */
export function cloudflareAccess(options: { teamDomain: string; audience: string }): Auth {
  const domain = options.teamDomain.trim();
  const issuerUrl = origin(
    'the Access team domain',
    domain.includes('://') ? domain : `https://${domain}`,
    'https:',
  );
  if (
    issuerUrl.port !== '' ||
    !issuerUrl.hostname.endsWith('.cloudflareaccess.com') ||
    issuerUrl.hostname === 'cloudflareaccess.com'
  ) {
    throw new Error('the Access team domain must be <team>.cloudflareaccess.com');
  }
  const issuer = issuerUrl.origin;
  const config: AuthConfig = {
    mode: 'cloudflare',
    access: {
      issuer,
      jwksUrl: `${issuer}/cdn-cgi/access/certs`,
      audience: checkAudience(options.audience.trim(), 'the Access audience'),
    },
  };
  return { mode: 'cloudflare', resolve: () => config };
}

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]']);

/**
 * The local dev IdP (`@coffre/conformance/idp`, run by `dev/idp`): a persona picker that mints
 * Access-shaped tokens for anyone. It is refused anywhere but on loopback,
 * so no deployment can end up trusting it.
 */
export function devIdp(options: { url: string; audience?: string }): Auth {
  const url = origin('the dev IdP URL', options.url.trim(), 'http:');
  if (!LOOPBACK.has(url.hostname)) {
    throw new Error('the dev IdP must run on loopback (127.0.0.1, localhost or [::1])');
  }
  const config: AuthConfig = {
    mode: 'dev',
    access: {
      issuer: url.origin,
      jwksUrl: `${url.origin}/cdn-cgi/access/certs`,
      audience: checkAudience(options.audience ?? 'coffre-local-dev-aud', 'the dev IdP audience'),
    },
    devIdpUrl: url.origin,
  };
  return { mode: 'dev', resolve: () => config };
}

export type SigninOptions = {
  /** At least one; see `github`, `google`, `microsoft` and `oidc`. */
  providers: SigninProviderConfig[];
  /** Heading on the sign-in page, e.g. "Acme secrets". */
  title?: string;
  /** One line under it, e.g. "Use your acme.example Google account." */
  note?: string;
  /** Absolute lifetime of a browser session; 12 hours unless set, at most a week. */
  browserSessionHours?: number;
  /** Absolute lifetime of a CLI session; 30 days unless set, at most a year. */
  cliSessionDays?: number;
};

/**
 * coffre's own sign-in page, with these providers:
 *
 *   signin({ providers: [github({ clientId, clientSecret, organization: 'acme' })] })
 */
export function signin(options: SigninOptions): Auth {
  // Checked now, where the deployment wrote it, and again with the URL.
  defineSignin({ ...toSignin(options), publicUrl: 'https://coffre.invalid' });
  return {
    mode: 'signin',
    resolve: (publicUrl) => ({ mode: 'signin', signin: defineSignin({ ...toSignin(options), publicUrl }) }),
  };
}

function toSignin(options: SigninOptions) {
  return {
    providers: options.providers,
    page: { title: options.title, note: options.note },
    browserSessionHours: options.browserSessionHours,
    cliSessionDays: options.cliSessionDays,
  };
}
