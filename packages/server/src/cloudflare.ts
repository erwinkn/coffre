/**
 * coffre's app Worker:
 *
 *   import { coffre, postgres, signin, github } from '@coffre/server/cloudflare';
 *
 *   import pages from '@tanstack/react-start/server-entry';
 *
 *   export default coffre((env: Env) => ({
 *     pages,
 *     publicUrl: 'https://secrets.acme.example',
 *     database: postgres(env.HYPERDRIVE),
 *     vault: env.VAULT,
 *     auth: signin({ providers: [github({ clientId: env.GITHUB_CLIENT_ID, clientSecret: env.GITHUB_CLIENT_SECRET })] }),
 *     auditChainKey: env.APP_KEY,
 *   }));
 *
 * This is the server entry of the deployment's own TanStack Start app,
 * built by Vite with `@cloudflare/vite-plugin`: `pages` is Start's handler,
 * whose router is `@coffre/ui`'s, and the client files Vite builds are the
 * Worker's static assets; see `coffre init --workers`.
 */
import { cloudflareHandler, type WorkerHandler, type WorkersConfig } from './cloudflare-handler.ts';

export { postgres, type PostgresDatabase, type WaitUntil, type WorkerHandler, type WorkersConfig } from './cloudflare-handler.ts';
export * from './index.ts';

/** The app Worker's default export: `{ fetch, scheduled }`, configured from its `env`. */
export function coffre<Env>(configure: (env: Env) => WorkersConfig): WorkerHandler<Env> {
  return cloudflareHandler(configure);
}
