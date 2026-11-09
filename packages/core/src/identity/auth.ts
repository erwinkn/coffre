import { checkPasskeysOption, defineSignin, type McpOptions, type PasskeysOptions, type SigninConfig, type WorkloadsOptions } from './signin/config.ts';
import type { SigninProvider } from './signin/types.ts';
import type { AccessVerifierConfig } from './types.ts';
import type { Deployment, MovedSetting } from '../deployment.ts';

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
  /** Sign-in finished against the public URL, with what the deployment chose (`deployment.ts`): its people's and services' fields. */
  resolve(publicUrl: string, deployment?: Deployment): AuthConfig;
  /** What the deployment still writes here that 0.16 moved to `deployment.ts`: read until 0.17. */
  moved?: readonly MovedSetting[];
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
  /** @deprecated In `deployment.ts` since 0.16, `people.browserSessionHours`: read until 0.17, which refuses it here. */
  browserSessionHours?: number;
  /** @deprecated In `deployment.ts` since 0.16, `people.cliSessionDays`: read until 0.17, which refuses it here. */
  cliSessionDays?: number;
  /** @deprecated In `deployment.ts` since 0.16, `services.tokenMaxDays`: read until 0.17, which refuses it here. */
  serviceTokenMaxDays?: number;
  /** Lets CI runs sign in as services with their platform's ID token: `{}` turns it on. */
  workloads?: WorkloadsOptions;
  /** Lets MCP clients, Claude among them, act as the people who connect them (docs/mcp.md). */
  mcp?: McpOptions;
  /**
   * Whether people need a passkey after the provider: `'off'`, `'optional'` (unless set) or `'required'`, or
   * `{ policy, rpId }` to name a parent of the public URL's host as the relying party (docs/design/passkeys.md,
   * sections 2 and 7.1). Not `off`, the public URL's host must be a name: `http://localhost:3000`, not `127.0.0.1`.
   */
  passkeys?: PasskeysOptions;
};

/**
 * coffre's own sign-in page, with these providers:
 *
 *   signin({ providers: [github({ clientId, clientSecret, organization: 'acme' })] })
 */
export function signin(options: SigninOptions): Auth {
  // Checked now, where the deployment wrote it, and again with the URL. Now on
  // a loopback stand-in: what turns on the URL, such as loopback issuers, is
  // decided with the real one.
  // Passkeys are checked against the URL then; here, their option's shape alone.
  checkPasskeysOption(options.passkeys);
  defineSignin({ ...toSignin(options), passkeys: 'off', publicUrl: 'http://127.0.0.1' });
  return {
    resolve: (publicUrl, deployment) => ({ mode: 'signin', signin: defineSignin({ ...toSignin(options, deployment), publicUrl }) }),
    moved: movedSettings(options),
  };
}

/** The settings `signin` took in 0.15 that `deployment.ts` holds since 0.16, as this deployment still writes them. */
function movedSettings(options: SigninOptions): MovedSetting[] {
  const moved: MovedSetting[] = [];
  const one = (old: string, value: unknown, group: string, field: string) => {
    if (value !== undefined) moved.push({ old, options: { [group]: { [field]: value } } });
  };
  one('signin({ browserSessionHours })', options.browserSessionHours, 'people', 'browserSessionHours');
  one('signin({ cliSessionDays })', options.cliSessionDays, 'people', 'cliSessionDays');
  one('signin({ serviceTokenMaxDays })', options.serviceTokenMaxDays, 'services', 'tokenMaxDays');
  one('signin({ workloads: { useOnly } })', options.workloads?.useOnly, 'services', 'useOnly');
  one('signin({ workloads: { noReads } })', options.workloads?.noReads, 'services', 'noReads');
  return moved;
}

/** Sign-in's options, its lifetimes and services' switches the deployment's (`deployment.ts`) when given. */
function toSignin(options: SigninOptions, deployment?: Deployment) {
  const workloads = options.workloads === undefined || deployment === undefined
    ? options.workloads
    : { ...options.workloads, useOnly: deployment.services.useOnly, noReads: deployment.services.noReads };
  return {
    providers: options.providers,
    page: { title: options.title, note: options.note },
    browserSessionHours: deployment?.people.browserSessionHours ?? options.browserSessionHours,
    cliSessionDays: deployment?.people.cliSessionDays ?? options.cliSessionDays,
    serviceTokenMaxDays: deployment?.services.tokenMaxDays ?? options.serviceTokenMaxDays,
    workloads,
    mcp: options.mcp,
    passkeys: options.passkeys,
  };
}
