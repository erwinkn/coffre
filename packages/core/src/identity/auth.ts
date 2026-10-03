import { defineSignin, type SigninConfig, type WorkloadsOptions } from './signin/config.ts';
import type { SigninProvider } from './signin/types.ts';
import type { AccessVerifierConfig } from './types.ts';

/**
 * Who vouches for the person at the other end of a request.
 *
 * - `signin`: coffre itself, after the person signs in with one of the
 *   deployment's providers: GitHub, Google, Microsoft, any OIDC issuer, or
 *   one of its own.
 * - `cloudflare`: Cloudflare Access, in front of coffre.
 *
 * Either way, coffre decides who is a member, and issues its own sessions,
 * CLI logins and service tokens.
 */
export type AuthConfig =
  | {
      mode: 'signin';
      signin: SigninConfig;
    }
  | {
      mode: 'cloudflare';
      access: AccessVerifierConfig;
    };

/**
 * What a deployment writes as `auth`: `signin(…)` or `cloudflareAccess(…)`.
 * Each checks its own options when called; sign-in is finished against the
 * deployment's public URL, which its callbacks are built from.
 */
export type Auth = {
  resolve(publicUrl: string): AuthConfig;
};

function httpsOrigin(what: string, value: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${what} must be an absolute URL`);
  }
  if (
    url.protocol !== 'https:' ||
    url.username !== '' ||
    url.password !== '' ||
    url.pathname !== '/' ||
    url.search !== '' ||
    url.hash !== ''
  ) {
    throw new Error(`${what} must be an HTTPS origin, with no path, query or credentials`);
  }
  return url;
}

function checkAudience(audience: string): string {
  if (audience.length === 0 || audience.length > 64 || /\s/.test(audience)) {
    throw new Error('the Access audience must be a non-whitespace Access AUD tag of at most 64 characters');
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
  const issuerUrl = httpsOrigin('the Access team domain', domain.includes('://') ? domain : `https://${domain}`);
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
      audience: checkAudience(options.audience.trim()),
    },
  };
  return { resolve: () => config };
}

export type SigninOptions = {
  /** At least one: `github`, `google`, `microsoft`, `oidc`, or the deployment's own `SigninProvider`. */
  providers: SigninProvider[];
  /** Heading on the sign-in page, e.g. "Acme secrets". */
  title?: string;
  /** One line under it, e.g. "Use your acme.example Google account." */
  note?: string;
  /** Absolute lifetime of a browser session; 12 hours unless set, at most a week. */
  browserSessionHours?: number;
  /** Absolute lifetime of a CLI session; 30 days unless set, at most a year. */
  cliSessionDays?: number;
  /** Lets CI runs sign in as services with their platform's ID token: `{}` turns it on. */
  workloads?: WorkloadsOptions;
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
    resolve: (publicUrl) => ({ mode: 'signin', signin: defineSignin({ ...toSignin(options), publicUrl }) }),
  };
}

function toSignin(options: SigninOptions) {
  return {
    providers: options.providers,
    page: { title: options.title, note: options.note },
    browserSessionHours: options.browserSessionHours,
    cliSessionDays: options.cliSessionDays,
    workloads: options.workloads,
  };
}
