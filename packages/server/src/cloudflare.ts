/**
 * coffre on Workers, in the deployment's own TanStack Start app, built by
 * Vite with `@cloudflare/vite-plugin`. The configuration, once:
 *
 *   // src/coffre.ts
 *   import { createCoffre, github, postgres, signin } from '@coffre/server/cloudflare';
 *
 *   export const coffre = createCoffre((env: Env) => ({
 *     publicUrl: 'https://secrets.acme.example',
 *     database: postgres(env.HYPERDRIVE),
 *     vault: env.VAULT,
 *     auth: signin({ providers: [github({ clientId: env.GITHUB_CLIENT_ID, clientSecret: env.GITHUB_CLIENT_SECRET })] }),
 *     auditChainKey: env.APP_KEY,
 *   }));
 *
 * and the Worker, Start's server entry, which hands Start coffre as each
 * request's context:
 *
 *   // src/server.ts
 *   import handler from '@tanstack/react-start/server-entry';
 *   import { coffre, type Env } from './coffre';
 *
 *   export default {
 *     fetch: (request: Request, env: Env, ctx: ExecutionContext) =>
 *       handler.fetch(request, { context: coffre.request(env, ctx) }),
 *     scheduled: coffre.scheduled,
 *   };
 *
 * coffre's server routes (`@coffre/server/routes`) and pages (`@coffre/ui`)
 * go in the app's route tree, and its middleware (`@coffre/server/start`) in
 * its src/start.ts; see `coffre init --workers`.
 */
export {
  createCoffre,
  postgres,
  type CoffreWorker,
  type PostgresDatabase,
  type WaitUntil,
  type WorkersConfig,
} from './cloudflare-handler.ts';
export type { CoffreContext, CoffreRequest, PageContext, Preferences } from './scope.ts';
export * from './index.ts';
