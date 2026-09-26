/**
 * Sign-in providers as configuration.
 *
 * coffre speaks two protocols: OpenID Connect, which covers Google, Microsoft,
 * Okta, Auth0, Keycloak, Authentik, Clerk, WorkOS and nearly everyone else,
 * and GitHub's own OAuth, because GitHub is the one provider people want that
 * does not speak OIDC. Everything named here is a preset of one of those two:
 * `google()` is OIDC with Google's issuer and a Workspace-domain check,
 * `microsoft()` is OIDC with a tenant's issuer. A provider that is not listed
 * needs no code, only `oidc()` and its issuer URL.
 *
 * A deployment usually configures this through environment variables (see
 * `loadSigninConfig`), so a prebuilt Worker or container needs nothing but
 * vars and secrets:
 *
 *   COFFRE_SIGNIN_PROVIDERS=github,okta
 *   COFFRE_SIGNIN_GITHUB_CLIENT_ID=Iv23li...
 *   COFFRE_SIGNIN_GITHUB_CLIENT_SECRET=...        (a secret)
 *   COFFRE_SIGNIN_OKTA_TYPE=oidc
 *   COFFRE_SIGNIN_OKTA_ISSUER=https://equisafe.okta.com
 *   COFFRE_SIGNIN_OKTA_CLIENT_ID=...
 *   COFFRE_SIGNIN_OKTA_CLIENT_SECRET=...
 */

/** Which mark the sign-in button carries. */
export type SigninBrand = 'github' | 'google' | 'microsoft' | 'oidc';

type ProviderBase = {
  /** Stable id: part of the callback URL and of every identity bound through it. */
  id: string;
  /** Button text: "Continue with {label}". */
  label: string;
  brand: SigninBrand;
  clientId: string;
  clientSecret: string;
};

export type OidcProviderConfig = ProviderBase & {
  kind: 'oidc';
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
  kind: 'github';
  /** https://github.com, or a GitHub Enterprise Server host. */
  webUrl: string;
  /** https://api.github.com, or `${host}/api/v3` on Enterprise Server. */
  apiUrl: string;
  /** When set, only active members of this organization may sign in. */
  organization: string | null;
};

export type SigninProviderConfig = OidcProviderConfig | GitHubProviderConfig;

export type SigninPage = {
  /** Heading on the sign-in page, e.g. "Equisafe secrets". */
  title: string;
  /** One line under it, e.g. "Use your equisafe.io Google account." */
  note: string | null;
};

export type SigninConfig = {
  /** The origin people reach coffre at. Callback URLs are built from it, never from the Host header. */
  publicUrl: string;
  providers: SigninProviderConfig[];
  page: SigninPage;
  /** Absolute lifetime of a browser session. */
  browserSessionHours: number;
  /** Absolute lifetime of a CLI session. */
  cliSessionDays: number;
};

const PROVIDER_ID = /^[a-z0-9][a-z0-9-]{0,31}$/;

type Credentials = { clientId: string; clientSecret: string };

function checkId(id: string): string {
  if (!PROVIDER_ID.test(id)) {
    throw new Error(
      `sign-in provider id "${id}" must be 1-32 lowercase letters, digits or dashes`,
    );
  }
  return id;
}

/**
 * Any OpenID Connect provider, by issuer URL.
 *
 * Okta, Auth0, Keycloak, Authentik, Zitadel, Clerk, WorkOS, Dex and the like
 * all live here; so does a broker, for providers that only speak SAML or LDAP.
 */
export function oidc(
  options: Credentials & {
    id: string;
    label: string;
    issuer: string;
    scopes?: string[];
    authorizationParams?: Record<string, string>;
  },
): OidcProviderConfig {
  return {
    kind: 'oidc',
    id: checkId(options.id),
    label: options.label,
    brand: 'oidc',
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    issuer: issuerUrl(options.issuer, `sign-in provider ${options.id}`),
    scopes: options.scopes ?? ['openid', 'email', 'profile'],
    authorizationParams: options.authorizationParams ?? {},
    hostedDomain: null,
  };
}

/** Google accounts; with `domain`, only that Google Workspace's accounts. */
export function google(
  options: Credentials & { id?: string; label?: string; domain?: string },
): OidcProviderConfig {
  const domain = options.domain?.trim().toLowerCase() || null;
  return {
    ...oidc({
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
  };
}

const TENANT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Microsoft Entra ID, for one tenant.
 *
 * The tenant must be its GUID. Entra's multi-tenant endpoints (`common`,
 * `organizations`) publish an issuer template rather than an issuer, which
 * standard OIDC validation rejects, and "any work account in the world" is not
 * an audience a secrets manager wants anyway.
 */
export function microsoft(
  options: Credentials & { id?: string; label?: string; tenant: string },
): OidcProviderConfig {
  const tenant = options.tenant.trim();
  if (!TENANT_ID.test(tenant)) {
    throw new Error(
      'the Microsoft sign-in tenant must be the directory (tenant) ID, a GUID, not a domain or "common"',
    );
  }
  return {
    ...oidc({
      id: options.id ?? 'microsoft',
      label: options.label ?? 'Microsoft',
      issuer: `https://login.microsoftonline.com/${tenant.toLowerCase()}/v2.0`,
      clientId: options.clientId,
      clientSecret: options.clientSecret,
      authorizationParams: { prompt: 'select_account' },
    }),
    brand: 'microsoft',
  };
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
): GitHubProviderConfig {
  const id = checkId(options.id ?? 'github');
  return {
    kind: 'github',
    id,
    label: options.label ?? 'GitHub',
    brand: 'github',
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    webUrl: baseUrl(options.webUrl ?? 'https://github.com', `sign-in provider ${id} web URL`),
    apiUrl: baseUrl(options.apiUrl ?? 'https://api.github.com', `sign-in provider ${id} API URL`),
    organization: options.organization?.trim() || null,
  };
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
  const url = checkedUrl(value, 'COFFRE_PUBLIC_URL');
  if (url.pathname !== '/') {
    throw new Error('COFFRE_PUBLIC_URL must be an origin, with no path');
  }
  return url.origin;
}

type Environment = Readonly<Record<string, string | undefined>>;

function envName(id: string, field: string): string {
  return `COFFRE_SIGNIN_${id.toUpperCase().replaceAll('-', '_')}_${field}`;
}

function optional(env: Environment, name: string): string | undefined {
  const value = env[name]?.trim();
  return value ? value : undefined;
}

function required(env: Environment, name: string): string {
  const value = optional(env, name);
  if (value === undefined) throw new Error(`missing required environment variable: ${name}`);
  return value;
}

function positiveNumber(env: Environment, name: string, fallback: number, max: number): number {
  const raw = optional(env, name);
  if (raw === undefined) return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0 || value > max) {
    throw new Error(`${name} must be a number between 0 and ${max}`);
  }
  return value;
}

const PRESETS = new Set(['github', 'google', 'microsoft', 'oidc']);

function providerFromEnv(env: Environment, id: string): SigninProviderConfig {
  checkId(id);
  const type = optional(env, envName(id, 'TYPE')) ?? (PRESETS.has(id) ? id : undefined);
  if (type === undefined) {
    throw new Error(
      `${envName(id, 'TYPE')} is required: one of github, google, microsoft or oidc`,
    );
  }

  const credentials = {
    clientId: required(env, envName(id, 'CLIENT_ID')),
    clientSecret: required(env, envName(id, 'CLIENT_SECRET')),
  };
  const label = optional(env, envName(id, 'LABEL'));

  switch (type) {
    case 'github':
      return github({
        ...credentials,
        id,
        label,
        organization: optional(env, envName(id, 'ORGANIZATION')),
        webUrl: optional(env, envName(id, 'WEB_URL')),
        apiUrl: optional(env, envName(id, 'API_URL')),
      });
    case 'google':
      return google({ ...credentials, id, label, domain: optional(env, envName(id, 'DOMAIN')) });
    case 'microsoft':
      return microsoft({
        ...credentials,
        id,
        label,
        tenant: required(env, envName(id, 'TENANT')),
      });
    case 'oidc': {
      const scopes = optional(env, envName(id, 'SCOPES'));
      return oidc({
        ...credentials,
        id,
        label: label ?? id,
        issuer: required(env, envName(id, 'ISSUER')),
        scopes: scopes?.split(/[\s,]+/).filter(Boolean),
      });
    }
    default:
      throw new Error(`${envName(id, 'TYPE')} must be one of github, google, microsoft or oidc`);
  }
}

/** Read `COFFRE_SIGNIN_*` into a validated configuration, failing on the first problem. */
export function loadSigninConfig(env: Environment): SigninConfig {
  const publicUrl = publicOrigin(required(env, 'COFFRE_PUBLIC_URL'));

  const ids = required(env, 'COFFRE_SIGNIN_PROVIDERS')
    .split(/[\s,]+/)
    .filter(Boolean);
  if (new Set(ids).size !== ids.length) {
    throw new Error('COFFRE_SIGNIN_PROVIDERS names a provider twice');
  }

  return defineSignin({
    publicUrl,
    providers: ids.map((id) => providerFromEnv(env, id)),
    page: {
      title: optional(env, 'COFFRE_SIGNIN_TITLE'),
      note: optional(env, 'COFFRE_SIGNIN_NOTE'),
    },
    browserSessionHours: positiveNumber(env, 'COFFRE_SESSION_HOURS', 12, 24 * 7),
    cliSessionDays: positiveNumber(env, 'COFFRE_CLI_SESSION_DAYS', 30, 365),
  });
}

/** The same validation for configuration written as code. */
export function defineSignin(options: {
  publicUrl: string;
  providers: SigninProviderConfig[];
  page?: { title?: string; note?: string };
  browserSessionHours?: number;
  cliSessionDays?: number;
}): SigninConfig {
  if (options.providers.length === 0) {
    throw new Error('sign-in needs at least one provider');
  }
  const seen = new Set<string>();
  for (const provider of options.providers) {
    if (seen.has(provider.id)) throw new Error(`sign-in provider id "${provider.id}" is used twice`);
    seen.add(provider.id);
    if (provider.clientId === '' || provider.clientSecret === '') {
      throw new Error(`sign-in provider ${provider.id} needs a client id and a client secret`);
    }
  }
  return {
    publicUrl: publicOrigin(options.publicUrl),
    providers: options.providers,
    page: {
      title: options.page?.title ?? 'Sign in to coffre',
      note: options.page?.note ?? null,
    },
    browserSessionHours: options.browserSessionHours ?? 12,
    cliSessionDays: options.cliSessionDays ?? 30,
  };
}
