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
import { MAX_SERVICE_TOKEN_DAYS } from '../../access.ts';
import { GitHubApp, pkcs8Of, type GitHubAppOptions } from '../github-app.ts';
import type { WorkloadAlert } from '../workloads.ts';
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
  /** The longest a service account's token may last here, in whole days: `MAX_SERVICE_TOKEN_DAYS` unless set lower. */
  serviceTokenMaxDays: number;
  /**
   * No service token is issued or taken: services sign in only with a key,
   * through `workloads` (`deployment.ts`'s `services.useOnly`; section 6.3 of
   * docs/design/workload-access.md). It holds whether workloads are on or not.
   */
  useOnly: boolean;
  /** CI runs signing in as services with their platform's ID token, when on (`workloads.ts`). */
  workloads: WorkloadsConfig | null;
  /** MCP clients acting as the people who connect them, when on (docs/design/mcp.md). */
  mcp: McpConfig | null;
  /** Passkeys, a second factor after the provider (docs/design/passkeys.md): the policy, `optional` unless set. */
  passkeys: PasskeysConfig;
};

/**
 * Whether people need a passkey on top of the provider (docs/design/passkeys.md, section 2):
 *
 * - `off`: the provider alone, as before passkeys; the rows stay, and turning them back on restores everyone's.
 * - `optional`: the provider, then a passkey for whoever has one; the risky acts need one.
 * - `required`: the provider, then a passkey, for everyone.
 */
export type PasskeyPolicy = 'off' | 'optional' | 'required';

export const PASSKEY_POLICIES: readonly PasskeyPolicy[] = ['off', 'optional', 'required'];

/**
 * How a deployment sets passkeys up: the policy alone, or with the WebAuthn relying party's ID, which is `publicUrl`'s
 * host unless set, or a parent of it (section 7.1): `{ policy: 'required', rpId: 'acme.example' }`.
 */
export type PasskeysOptions = PasskeyPolicy | { policy?: PasskeyPolicy; rpId?: string };

/** Passkeys, checked: the policy, the RP ID every ceremony names, and the one origin a response may come from (section 7.1). */
export type PasskeysConfig = { policy: PasskeyPolicy; rpId: string; origin: string };

/**
 * Workload identity: CI runs that sign in as a service with the ID token
 * their platform signs for them, through the trust bindings an owner sets
 * on the service (docs/design/oidc.md). Off unless the deployment turns it on.
 */
export type WorkloadsOptions = {
  /**
   * The limit every sign-in passes before coffre does any work for it
   * (`/api/auth/oidc`, `/api/auth/workload`): requests one source address
   * may make to each, counted apart. On Workers, a rate-limiting binding
   * (`env.SIGN_IN_PER_SOURCE`, 10,000 per 10 s), which Cloudflare counts
   * per location; on Node, `processLimits()` from `@coffre/server/node`,
   * which counts per process. The same one may serve `mcp.limits`.
   * Required: a sign-in is never without it.
   */
  limits: WorkloadLimits;
  /**
   * Lets a binding's issuer be plain HTTP on loopback, as the dev IdP's is:
   * for local development and conformance. Refused unless the public URL is
   * loopback too, so no instance anyone else can reach ever trusts one.
   */
  allowLoopbackIssuersForDevelopment?: boolean;
  /**
   * The deployment's own GitHub App, `githubApp(…)`, installed on its
   * organizations: where an owner trusts a workflow, the pages list the
   * repositories it is installed on, private ones too, and a repository
   * typed by name resolves through it (docs/github-app.md). The same value
   * may sign people in, `github({ app })`. Left out, repositories are typed,
   * and only public ones' IDs are looked up.
   */
  github?: GitHubApp;
  /** @deprecated In `deployment.ts` since 0.16, `services.useOnly`: read until 0.17, which refuses it here. */
  useOnly?: boolean;
  /** @deprecated In `deployment.ts` since 0.16, `services.noReads`: read until 0.17, which refuses it here. */
  noReads?: boolean;
  /** The deployment's own delivery of a workload's alerts, called in the background after the response: a Slack webhook, a pager. */
  alert?: (alert: WorkloadAlert) => unknown;
};

/** Cloudflare's rate-limiting binding, as coffre calls it; `processLimits()` has the same shape. */
export type RateLimiter = { limit(options: { key: string }): Promise<{ success: boolean }> };

/**
 * `perSource`: what one address may ask of an entry point that takes
 * anyone, before coffre knows who: each entry point counted apart, as the
 * key names it (`exchange:<address>`, `oauth:token:<address>`, …), so one
 * limiter serves them all.
 */
export type WorkloadLimits = {
  perSource: RateLimiter;
  /** @deprecated 0.15's limit for all sources together, gone in 0.16: read no more, and refused in 0.17. Remove it. */
  total?: RateLimiter;
};

export type WorkloadsConfig = {
  allowLoopback: boolean;
  limits: { perSource: RateLimiter };
  github: GitHubApp | null;
  noReads: boolean;
  alert: ((alert: WorkloadAlert) => unknown) | null;
};

/**
 * MCP clients, Claude among them, acting as the people who connect them,
 * with coffre as their OAuth authorization server (docs/design/mcp.md). Off
 * unless the deployment turns it on.
 */
export type McpOptions = {
  /**
   * The limit every unauthenticated OAuth request passes before coffre does
   * any work for it: requests one source address may make to each OAuth
   * endpoint, counted apart. On Workers, a rate-limiting binding, the one
   * `workloads.limits` takes (`env.SIGN_IN_PER_SOURCE`); on Node,
   * `processLimits()` from `@coffre/server/node`. A connection's tool calls
   * pass none: they act as the person who approved it, whose own requests
   * have no rate either. Required.
   */
  limits: McpLimits;
  /**
   * Lets a client's metadata document be plain HTTP on loopback: for local
   * development and conformance. Refused unless the public URL is loopback
   * too.
   */
  allowLoopbackClientsForDevelopment?: boolean;
};

export type McpLimits = {
  perSource: RateLimiter;
  /** @deprecated 0.15's limit on a connection's tool calls, gone in 0.16: read no more, and refused in 0.17. Remove it. */
  perConnection?: RateLimiter;
  /** @deprecated 0.15's limit for all sources together, gone in 0.16: read no more, and refused in 0.17. Remove it. */
  total?: RateLimiter;
};

export type McpConfig = { allowLoopback: boolean; limits: { perSource: RateLimiter } };

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

/**
 * GitHub accounts; with `organization`, only that organization's members.
 * Through an OAuth app, or a GitHub App's OAuth client, by its credentials;
 * or the deployment's GitHub App, `github({ app })`, the same value its
 * `workloads.github` lists repositories with:
 *
 *   const app = githubApp({ appId, privateKey, clientId, clientSecret });
 *   signin({ providers: [github({ app, organization: 'acme' })], workloads: { limits, github: app } })
 */
export function github(
  options: { id?: string; label?: string; organization?: string } & (
    | (Credentials & { webUrl?: string; apiUrl?: string })
    | { app: GitHubApp }
  ),
): GitHubSigninProvider {
  const id = checkId(options.id ?? 'github');
  const how = ((): Credentials & { webUrl?: string; apiUrl?: string } => {
    if (!('app' in options)) return options;
    const client = options.app instanceof GitHubApp ? options.app.signinClient() : null;
    if (client === null) {
      throw new Error(`sign-in provider ${id} signs in with the GitHub App's OAuth client: githubApp({ appId, privateKey, clientId, clientSecret })`);
    }
    return { ...client, webUrl: options.app.webUrl, apiUrl: options.app.apiUrl };
  })();
  return new GitHubSigninProvider({
    id,
    label: options.label ?? 'GitHub',
    brand: 'github',
    ...credentials(id, how),
    webUrl: baseUrl(how.webUrl ?? 'https://github.com', `sign-in provider ${id} web URL`),
    apiUrl: baseUrl(how.apiUrl ?? 'https://api.github.com', `sign-in provider ${id} API URL`),
    organization: options.organization?.trim() || null,
  });
}

/**
 * The deployment's GitHub App, checked where it is written: its numeric ID
 * and private key, and its OAuth client when it signs people in too. One
 * value, passed to each side that uses it: `github({ app })` and
 * `workloads.github` (`../github-app.ts`).
 */
export function githubApp(options: GitHubAppOptions): GitHubApp {
  const appId = String(options.appId ?? '').trim();
  if (!/^[1-9][0-9]{0,19}$/.test(appId)) throw new Error('githubApp(…).appId must be the app\'s numeric ID (its settings page, "App ID"), not its client ID');
  const [clientId, clientSecret] = [options.clientId?.trim() || null, options.clientSecret || null];
  if ((clientId === null) !== (clientSecret === null)) {
    throw new Error('githubApp(…) takes its OAuth client whole, clientId and clientSecret, or neither');
  }
  return new GitHubApp({
    appId,
    pkcs8: pkcs8Of(options.privateKey),
    webUrl: baseUrl(options.webUrl ?? 'https://github.com', 'githubApp(…).webUrl'),
    apiUrl: baseUrl(options.apiUrl ?? 'https://api.github.com', 'githubApp(…).apiUrl'),
    ...(clientId === null || clientSecret === null ? {} : { client: { clientId, clientSecret } }),
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
  /** The longest a service token may last, in whole days, 1 to `MAX_SERVICE_TOKEN_DAYS` (a year), which it is unless set. */
  serviceTokenMaxDays?: number;
  /** No service token issued or taken (`SigninConfig.useOnly`); 0.15's `workloads.useOnly` when left out. */
  useOnly?: boolean;
  workloads?: WorkloadsOptions;
  mcp?: McpOptions;
  /** The passkey policy, `optional` unless set, and the RP ID (sections 2 and 7.1 of docs/design/passkeys.md). */
  passkeys?: PasskeysOptions;
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
  if (options.useOnly !== undefined && typeof options.useOnly !== 'boolean') throw new Error('useOnly is true or false');
  return {
    publicUrl: publicOrigin(options.publicUrl),
    providers: options.providers,
    page: {
      title: options.page?.title ?? 'Sign in to coffre',
      note: options.page?.note ?? null,
    },
    browserSessionHours: lifetime(options.browserSessionHours, 'browserSessionHours', 12, 24 * 7),
    cliSessionDays: lifetime(options.cliSessionDays, 'cliSessionDays', 30, 365),
    serviceTokenMaxDays: wholeDays(options.serviceTokenMaxDays, 'serviceTokenMaxDays', MAX_SERVICE_TOKEN_DAYS),
    useOnly: options.useOnly ?? options.workloads?.useOnly === true,
    workloads: options.workloads === undefined ? null : workloadsConfig(options.workloads, publicOrigin(options.publicUrl)),
    mcp: options.mcp === undefined ? null : mcpConfig(options.mcp, publicOrigin(options.publicUrl)),
    passkeys: passkeysConfig(options.passkeys, publicOrigin(options.publicUrl)),
  };
}

/**
 * The passkeys option, checked against the public URL (section 7.1): the RP ID is its host, or a parent of it on a label
 * boundary with at least two labels. A host no browser makes a passkey for, an IP address, fails unless passkeys are
 * `off`: every sign-in of a person who has one, and under `required` every sign-in, would be out of reach. Whether a
 * parent is registrable (`acme.co.uk`) or a public suffix (`co.uk`, `workers.dev`) is the browser's public suffix
 * list's to say, which changes weekly and which coffre does not ship: a parent the browser refuses fails the first
 * passkey asked for, the Owner's as the deployment is set up, and the page names `passkeys.rpId`.
 */
export function passkeysConfig(options: PasskeysOptions | undefined, origin: string): PasskeysConfig {
  const { policy: asked, rpId: named } = checkPasskeysOption(options);
  const policy = asked ?? 'optional';
  const host = new URL(origin).hostname;
  if (policy !== 'off' && !isDomainName(host)) {
    throw new Error(
      `passkeys need a public URL whose host is a name, and ${host} is not one: browsers make no passkey there. ` +
        "Locally, use http://localhost:<port>; or set passkeys: 'off'",
    );
  }
  if (named !== undefined && named !== host && !(named.includes('.') && host.endsWith(`.${named}`))) {
    throw new Error(`passkeys.rpId ${named} must be the public URL's host, ${host}, or a parent of it with at least two labels`);
  }
  return { policy, rpId: named ?? host, origin };
}

/** The option's shape alone, before any URL: a policy, and an RP ID that is a domain name. */
export function checkPasskeysOption(options: PasskeysOptions | undefined): { policy?: PasskeyPolicy; rpId?: string } {
  const { policy, rpId } = typeof options === 'string' || options === undefined ? { policy: options } : options;
  if (policy !== undefined && !PASSKEY_POLICIES.includes(policy)) {
    throw new Error(`passkeys is one of ${PASSKEY_POLICIES.map((value) => `'${value}'`).join(', ')}`);
  }
  if (rpId !== undefined && (typeof rpId !== 'string' || !isDomainName(rpId))) throw new Error('passkeys.rpId is a domain name, lowercase: acme.example');
  return { policy, rpId };
}

const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

/** A lowercase DNS name, `localhost` included; never an IP address, which URLs give bare (IPv4) or in brackets (IPv6). */
function isDomainName(host: string): boolean {
  if (host.length === 0 || host.length > 253 || /^[0-9.]+$/.test(host) || host.startsWith('[')) return false;
  return host.split('.').every((label) => LABEL.test(label));
}

/** MCP, checked: its limit per source given, a limiter; loopback clients only on a loopback instance. */
function mcpConfig(options: McpOptions, publicUrl: string): McpConfig {
  const limiter = (value: unknown) => typeof (value as RateLimiter | undefined)?.limit === 'function';
  if (!limiter(options.limits?.perSource)) {
    throw new Error('mcp needs its limit per source, limits: { perSource }: on Workers, a rate-limiting binding; on Node, processLimits()');
  }
  const loopback = options.allowLoopbackClientsForDevelopment === true;
  if (loopback && !isLoopback(new URL(publicUrl))) {
    throw new Error(
      `mcp.allowLoopbackClientsForDevelopment is for an instance on loopback, and ${publicUrl} is not one: turn it off`,
    );
  }
  return { allowLoopback: loopback, limits: { perSource: options.limits.perSource } };
}

/** Workloads, checked: the limit per source given, a limiter; loopback issuers only on a loopback instance. */
function workloadsConfig(options: WorkloadsOptions, publicUrl: string): WorkloadsConfig {
  const limiter = (value: unknown) => typeof (value as RateLimiter | undefined)?.limit === 'function';
  if (!limiter(options.limits?.perSource)) {
    throw new Error('workloads need their limit per source, limits: { perSource }: on Workers, a rate-limiting binding; on Node, processLimits()');
  }
  const loopback = options.allowLoopbackIssuersForDevelopment === true;
  if (loopback && !isLoopback(new URL(publicUrl))) {
    throw new Error(
      `workloads.allowLoopbackIssuersForDevelopment is for an instance on loopback, and ${publicUrl} is not one: turn it off`,
    );
  }
  const app = options.github;
  if (app !== undefined && !(app instanceof GitHubApp)) {
    throw new Error('workloads.github is the deployment\'s GitHub App: githubApp({ appId, privateKey })');
  }
  // Its repositories' IDs are trusted under github.com's issuer, the one the lookup and the pages bind to.
  if (app !== undefined && app.apiUrl !== 'https://api.github.com' && !isLoopback(new URL(app.apiUrl))) {
    throw new Error('workloads.github is for github.com: GitHub Enterprise Server is not supported yet; sign in with its app, and leave workloads.github out');
  }
  for (const flag of ['useOnly', 'noReads'] as const) {
    if (options[flag] !== undefined && typeof options[flag] !== 'boolean') throw new Error(`workloads.${flag} is true or false`);
  }
  if (options.alert !== undefined && typeof options.alert !== 'function') throw new Error('workloads.alert is a function, given each alert');
  return {
    allowLoopback: loopback,
    limits: { perSource: options.limits.perSource },
    github: app ?? null,
    noReads: options.noReads === true,
    alert: options.alert ?? null,
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

/** A whole number of days, 1 to `max`, which it is unless set. */
function wholeDays(value: number | undefined, name: string, max: number): number {
  if (value === undefined) return max;
  if (!Number.isInteger(value) || value < 1 || value > max) {
    throw new Error(`${name} must be a whole number of days, 1 to ${max}`);
  }
  return value;
}

function lifetime(value: number | undefined, name: string, fallback: number, max: number): number {
  if (value === undefined) return fallback;
  if (!Number.isFinite(value) || value <= 0 || value > max) {
    throw new Error(`${name} must be a number above 0 and at most ${max}`);
  }
  return value;
}
