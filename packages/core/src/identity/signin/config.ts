/**
 * Sign-in providers, and the sign-in they make up.
 *
 * coffre speaks two protocols: OpenID Connect, which covers Google, Microsoft,
 * Okta, Auth0, Keycloak, Authentik, Clerk, WorkOS and nearly everyone else,
 * and GitHub's own OAuth, because GitHub is the one provider people want that
 * does not speak OIDC. Everything named here is a preset of one of those two:
 * `google()` is OIDC with Google's issuer and a Workspace-domain check,
 * `microsoft()` is OIDC with a tenant's issuer. A provider that is not listed
 * needs no code, only `oidc()` and its issuer URL.
 *
 * A deployment writes them in its own code, where a misspelt option fails
 * the typecheck:
 *
 *   signin({ providers: [github({ clientId, clientSecret: env.GITHUB_SECRET, organization: 'acme' })] })
 *
 * Each returns a `SigninProvider`, and a provider that speaks neither can be
 * one of the deployment's own, in the same list.
 */
import { GitHubSigninProvider } from './github.ts';
import { OidcSigninProvider } from './oidc.ts';
import type { SigninBrand, SigninProvider } from './types.ts';

type ProviderBase = {
  id: string;
  label: string;
  brand: SigninBrand;
  clientId: string;
  clientSecret: string;
};

export type OidcProviderConfig = ProviderBase & {
  /** Issuer identifier; discovery is fetched from `${issuer}/.well-known/openid-configuration`. */
  issuer: string;
  scopes: string[];
  /** Extra authorization request parameters, such as Google's `hd` hint. */
  authorizationParams: Record<string, string>;
  /**
   * The Google Workspace domain the ID token's `hd` claim must equal. The
   * `hd` request parameter only filters Google's account picker; the claim is
   * what proves membership.
   */
  hostedDomain: string | null;
};

export type GitHubProviderConfig = ProviderBase & {
  /** https://github.com, or a GitHub Enterprise Server host. */
  webUrl: string;
  /** https://api.github.com, or `${host}/api/v3` on Enterprise Server. */
  apiUrl: string;
  /** When set, only active members of this organization may sign in. */
  organization: string | null;
};

export type SigninPage = {
  /** Heading on the sign-in page, e.g. "Acme secrets". */
  title: string;
  /** One line under it, e.g. "Use your acme.example Google account." */
  note: string | null;
};

export type SigninConfig = {
  /** The origin people reach coffre at. Callback URLs are built from it, never from the Host header. */
  publicUrl: string;
  providers: SigninProvider[];
  page: SigninPage;
  /** Absolute lifetime of a browser session. */
  browserSessionHours: number;
  /** Absolute lifetime of a CLI session. */
  cliSessionDays: number;
  /** CI runs signing in as services with their platform's ID token, when on (`workloads.ts`). */
  workloads: WorkloadsConfig | null;
};

/**
 * Workload identity: CI runs that sign in as a service with the ID token
 * their platform signs for them, through the trust bindings an owner sets
 * on the service (docs/design/oidc.md). Off unless the deployment turns it on.
 */
export type WorkloadsOptions = {
  /** Lets a binding's issuer be plain HTTP on loopback: the dev IdP's, never production's. */
  allowLoopback?: boolean;
};

export type WorkloadsConfig = { allowLoopback: boolean };

const PROVIDER_ID = /^[a-z0-9][a-z0-9-]{0,31}$/;
const BRANDS: readonly SigninBrand[] = ['github', 'google', 'microsoft', 'oidc'];

type Credentials = { clientId: string; clientSecret: string };

function checkId(id: string): string {
  if (typeof id !== 'string' || !PROVIDER_ID.test(id)) {
    throw new Error(
      `sign-in provider id "${id}" must be 1-32 lowercase letters, digits or dashes`,
    );
  }
  return id;
}

function credentials(id: string, options: Credentials): Credentials {
  if (!options.clientId || !options.clientSecret) {
    throw new Error(`sign-in provider ${id} needs a client id and a client secret`);
  }
  return { clientId: options.clientId, clientSecret: options.clientSecret };
}

/**
 * Any OpenID Connect provider, by issuer URL.
 *
 * Okta, Auth0, Keycloak, Authentik, Zitadel, Clerk, WorkOS, Dex and the like
 * all live here; so does a broker, for providers that only speak SAML or LDAP.
 */
export function oidc(options: OidcOptions): OidcSigninProvider {
  return new OidcSigninProvider(oidcConfig(options));
}

type OidcOptions = Credentials & {
  id: string;
  label: string;
  issuer: string;
  scopes?: string[];
  authorizationParams?: Record<string, string>;
};

function oidcConfig(options: OidcOptions): OidcProviderConfig {
  const id = checkId(options.id);
  return {
    id,
    label: options.label,
    brand: 'oidc',
    ...credentials(id, options),
    issuer: issuerUrl(options.issuer, `sign-in provider ${id}`),
    scopes: options.scopes ?? ['openid', 'email', 'profile'],
    authorizationParams: options.authorizationParams ?? {},
    hostedDomain: null,
  };
}

/** Google accounts; with `domain`, only that Google Workspace's accounts. */
export function google(
  options: Credentials & { id?: string; label?: string; domain?: string },
): OidcSigninProvider {
  const domain = options.domain?.trim().toLowerCase() || null;
  return new OidcSigninProvider({
    ...oidcConfig({
      id: options.id ?? 'google',
      label: options.label ?? 'Google',
      issuer: 'https://accounts.google.com',
      clientId: options.clientId,
      clientSecret: options.clientSecret,
      // `select_account` stops Google from silently reusing whichever of
      // several signed-in accounts was used last.
      authorizationParams: domain
        ? { hd: domain, prompt: 'select_account' }
        : { prompt: 'select_account' },
    }),
    brand: 'google',
    hostedDomain: domain,
  });
}

const TENANT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Microsoft Entra ID, for one tenant.
 *
 * The tenant must be its GUID. Entra's multi-tenant endpoints (`common`,
 * `organizations`) publish an issuer template rather than an issuer, which
 * standard OIDC validation rejects, and "any work account in the world" is not
 * an audience a secrets manager wants anyway.
 *
 * Entra email claims do not prove address ownership. Sign in through another
 * provider and link the Microsoft account first; later sign-ins use its subject.
 */
export function microsoft(
  options: Credentials & { id?: string; label?: string; tenant: string },
): OidcSigninProvider {
  const tenant = options.tenant.trim();
  if (!TENANT_ID.test(tenant)) {
    throw new Error(
      'the Microsoft sign-in tenant must be the directory (tenant) ID, a GUID, not a domain or "common"',
    );
  }
  return new OidcSigninProvider({
    ...oidcConfig({
      id: options.id ?? 'microsoft',
      label: options.label ?? 'Microsoft',
      issuer: `https://login.microsoftonline.com/${tenant.toLowerCase()}/v2.0`,
      clientId: options.clientId,
      clientSecret: options.clientSecret,
      authorizationParams: { prompt: 'select_account' },
    }),
    brand: 'microsoft',
  });
}

/** GitHub accounts; with `organization`, only that organization's members. */
export function github(
  options: Credentials & {
    id?: string;
    label?: string;
    organization?: string;
    webUrl?: string;
    apiUrl?: string;
  },
): GitHubSigninProvider {
  const id = checkId(options.id ?? 'github');
  return new GitHubSigninProvider({
    id,
    label: options.label ?? 'GitHub',
    brand: 'github',
    ...credentials(id, options),
    webUrl: baseUrl(options.webUrl ?? 'https://github.com', `sign-in provider ${id} web URL`),
    apiUrl: baseUrl(options.apiUrl ?? 'https://api.github.com', `sign-in provider ${id} API URL`),
    organization: options.organization?.trim() || null,
  });
}

function isLoopback(url: URL): boolean {
  return url.hostname === '127.0.0.1' || url.hostname === 'localhost' || url.hostname === '[::1]';
}

/** HTTPS, except on loopback, where the dev IdP runs. */
function checkedUrl(value: string, what: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${what} must be an absolute URL`);
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopback(url))) {
    throw new Error(`${what} must use HTTPS`);
  }
  if (url.username !== '' || url.password !== '' || url.search !== '' || url.hash !== '') {
    throw new Error(`${what} must not carry credentials, a query or a fragment`);
  }
  return url;
}

/**
 * Issuers are compared byte for byte with the `iss` of every token, so the
 * configured value is kept as written, less a trailing slash nobody means.
 */
function issuerUrl(value: string, what: string): string {
  checkedUrl(value, `${what} issuer`);
  return value.endsWith('/') ? value.slice(0, -1) : value;
}

function baseUrl(value: string, what: string): string {
  const url = checkedUrl(value, what);
  return url.href.endsWith('/') ? url.href.slice(0, -1) : url.href;
}

export function publicOrigin(value: string): string {
  const url = checkedUrl(value, 'the public URL');
  if (url.pathname !== '/') {
    throw new Error('the public URL must be an origin, with no path');
  }
  return url.origin;
}

/** Sign-in configuration, checked: at least one provider, each whole, ids unique, lifetimes sane. */
export function defineSignin(options: {
  publicUrl: string;
  providers: SigninProvider[];
  page?: { title?: string; note?: string };
  browserSessionHours?: number;
  cliSessionDays?: number;
  workloads?: WorkloadsOptions;
}): SigninConfig {
  if (options.providers.length === 0) {
    throw new Error('sign-in needs at least one provider');
  }
  const seen = new Set<string>();
  for (const provider of options.providers) {
    checkProvider(provider);
    if (seen.has(provider.id)) throw new Error(`sign-in provider id "${provider.id}" is used twice`);
    seen.add(provider.id);
  }
  return {
    publicUrl: publicOrigin(options.publicUrl),
    providers: options.providers,
    page: {
      title: options.page?.title ?? 'Sign in to coffre',
      note: options.page?.note ?? null,
    },
    browserSessionHours: lifetime(options.browserSessionHours, 'browserSessionHours', 12, 24 * 7),
    cliSessionDays: lifetime(options.cliSessionDays, 'cliSessionDays', 30, 365),
    workloads: options.workloads === undefined ? null : { allowLoopback: options.workloads.allowLoopback === true },
  };
}

/** A deployment's own provider is checked like coffre's: it is only typed, not trusted. */
function checkProvider(provider: SigninProvider): void {
  checkId(provider?.id);
  if (typeof provider.issuer !== 'string' || provider.issuer.trim() === '') {
    throw new Error(`sign-in provider ${provider.id} needs a stable issuer`);
  }
  if (typeof provider.label !== 'string' || provider.label.trim() === '') {
    throw new Error(`sign-in provider ${provider.id} needs a label`);
  }
  if (!BRANDS.includes(provider.brand)) {
    throw new Error(`sign-in provider ${provider.id}'s brand must be one of ${BRANDS.join(', ')}`);
  }
  if (typeof provider.start !== 'function' || typeof provider.finish !== 'function') {
    throw new Error(`sign-in provider ${provider.id} needs start() and finish()`);
  }
}

function lifetime(value: number | undefined, name: string, fallback: number, max: number): number {
  if (value === undefined) return fallback;
  if (!Number.isFinite(value) || value <= 0 || value > max) {
    throw new Error(`${name} must be a number above 0 and at most ${max}`);
  }
  return value;
}
