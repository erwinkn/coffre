// Plugins (docs/design/plugins.md): what a deployment adds to coffre in its
// configuration, `plugins: [vaultKv({ mount: 'secret' })]`. A plugin holds no
// authority of its own. It answers paths of its own, and reaches coffre only
// as whoever a request's credential names, through the API: the same route
// table, checks, vault and audit log as the CLI.
import { CoffreError, createClient, type CoffreClient } from '@coffre/client';
import { ACCESS_JWT_HEADER } from '@coffre/core/identity';

import { authenticateRequest, type AuthenticatedIdentity } from './auth.ts';
import { exchangeWorkloadToken, logout } from './auth-routes.ts';
import { fetchApi } from './fetch-api.ts';
import type { CoffreRuntime } from './runtime.ts';

/** One plugin, as its constructor returns it: `vaultKv({ mount: 'secret' })`. */
export type CoffrePlugin = {
  /** What names it in errors: lowercase, `vault-kv`. Unique among a deployment's plugins. */
  name: string;
  /**
   * The paths it answers: `prefix`, `/v1`, and every path under it, whatever
   * the method. The deployment's app routes them to coffre with a file
   * route of their own, `routes/v1.$.ts` (`plugin`, in `@coffre/server/routes`).
   */
  routes?: { prefix: string; fetch: (request: Request, coffre: PluginContext) => Promise<Response> };
};

/** What a plugin's route answers with: where coffre is, and its API as a credential's holder. */
export type PluginContext = {
  publicUrl: string;
  /**
   * The API as whoever `token` names, which the plugin read from its
   * request: a service, personal or CLI token with coffre's sign-in, Access's
   * assertion behind Cloudflare Access; never a cookie, which coffre alone
   * reads. The token is checked at the first call, once for all of them; a
   * refusal, the token's included, throws a `CoffreError`.
   */
  api(token: string): CoffreClient;
  /**
   * The request as a workload's sign-in: its body, a workload's ID token,
   * for a credential of the service account it names that lasts five
   * minutes, through that account's trust bindings. This is `POST
   * /api/auth/oidc` on the plugin's own request, in process: its limits
   * first, then the body, read only to its limit, then the token spent so
   * that it signs in once, and its audit. `asked` says what the body asks
   * for, `{ service, token }`, in the plugin's words. A refusal throws a
   * `CoffreError`, a body that does not say 400.
   */
  exchange(asked: (body: unknown) => { service: unknown; token: unknown }): Promise<{ token: string; expiresAt: string }>;
  /** End the credential `token` is, as `POST /api/auth/logout` with it does. A refusal throws a `CoffreError`. */
  signOut(token: string): Promise<void>;
};

const NAME = /^[a-z][a-z0-9-]{0,31}$/;
const PREFIX = /^(\/[a-z0-9][a-z0-9._-]*)+$/;
/** What coffre answers itself, and no plugin may take. */
const COFFRE_PATHS = ['/api', '/auth', '/mcp', '/.well-known', '/livez', '/readyz'];

/** Whether `pathname` is `prefix` or under it. */
const under = (pathname: string, prefix: string) => pathname === prefix || pathname.startsWith(`${prefix}/`);

/** Check a deployment's plugins, failing on the first problem: a bad name, or paths two would answer. */
export function checkPlugins(plugins: readonly CoffrePlugin[]): readonly CoffrePlugin[] {
  const names = new Set<string>();
  const prefixes: string[] = [...COFFRE_PATHS];
  for (const plugin of plugins) {
    if (typeof plugin.name !== 'string' || !NAME.test(plugin.name)) throw new Error(`a plugin's name is lowercase letters, digits and dashes; got ${JSON.stringify(plugin.name)}`);
    if (names.has(plugin.name)) throw new Error(`two plugins are named ${plugin.name}`);
    names.add(plugin.name);
    if (plugin.routes === undefined) continue;
    const { prefix } = plugin.routes;
    if (!PREFIX.test(prefix)) throw new Error(`plugin ${plugin.name}: its prefix is a path such as /v1, without a trailing slash; got ${JSON.stringify(prefix)}`);
    const taken = prefixes.find((other) => under(prefix, other) || under(other, prefix));
    if (taken !== undefined) throw new Error(`plugin ${plugin.name}: ${prefix} overlaps ${taken}, which ${COFFRE_PATHS.includes(taken) ? 'coffre answers' : 'another plugin takes'}`);
    prefixes.push(prefix);
  }
  return plugins;
}

/** The plugin's answer to a request under its prefix; null when no plugin takes the path. */
export function pluginRoute(request: Request, runtime: CoffreRuntime, sourceIp: string | null): Promise<Response> | null {
  const { pathname } = new URL(request.url);
  const routes = runtime.plugins.find((plugin) => plugin.routes !== undefined && under(pathname, plugin.routes.prefix))?.routes;
  if (routes === undefined) return null;
  // The token where the API looks for it in this instance's mode: a header either way, so never ambient.
  const carrying = (token: string): Record<string, string> => (runtime.auth.mode === 'cloudflare' ? { [ACCESS_JWT_HEADER]: token } : { authorization: `Bearer ${token}` });
  // One of coffre's own routes outside the API's, in process: its answer, or its refusal as the client throws one.
  const answer = async (response: Response): Promise<unknown> => {
    const body = (await response.json()) as { error?: string; message?: string; reason?: string };
    if (!response.ok) throw new CoffreError(response.status, body.error ?? 'error', body.message ?? response.statusText, body.reason);
    return body;
  };
  return routes.fetch(request, {
    publicUrl: runtime.publicUrl,
    exchange: async (asked) => (await answer(await exchangeWorkloadToken(request, runtime, sourceIp, asked))) as { token: string; expiresAt: string },
    signOut: async (token) => {
      await answer(await logout(new Request(`${runtime.publicUrl}/api/auth/logout`, { method: 'POST', headers: carrying(token) }), runtime, sourceIp));
    },
    api: (token) => {
      let checked: Promise<AuthenticatedIdentity | Response> | undefined;
      return createClient({
        url: runtime.publicUrl,
        headers: () => carrying(token),
        // In process, as a page's render calls it (`pageClient`): one check of the token for every call.
        transport: (inner) =>
          fetchApi(inner, runtime, {
            sourceIp,
            authenticate: async () => {
              checked ??= authenticateRequest(request, runtime, crypto.randomUUID(), token, sourceIp);
              const identity = await checked;
              // A refusal's body is read once: each call answers with its own copy.
              return identity instanceof Response ? identity.clone() : identity;
            },
          }),
      });
    },
  });
}
