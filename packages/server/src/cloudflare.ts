/**
 * coffre's app Worker:
 *
 *   import { coffre, postgres, signin, github } from '@coffre/server/cloudflare';
 *
 *   export default coffre((env: Env) => ({
 *     publicUrl: 'https://secrets.acme.example',
 *     database: postgres(env.HYPERDRIVE),
 *     vault: env.VAULT,
 *     auth: signin({ providers: [github({ clientId: env.GITHUB_CLIENT_ID, clientSecret: env.GITHUB_CLIENT_SECRET })] }),
 *     auditChainKey: env.APP_KEY,
 *   }));
 *
 * Pages come from `@coffre/ui`, whose static files the Worker's `assets`
 * serve; see `coffre init --workers`.
 */
import { createUi } from '@coffre/ui';

import { cloudflareHandler, type WorkerHandler, type WorkersConfig } from './cloudflare-handler.ts';

export { postgres, type PostgresDatabase, type WaitUntil, type WorkerHandler, type WorkersConfig } from './cloudflare-handler.ts';
export * from './index.ts';

/** The app Worker's default export: `{ fetch, scheduled }`, configured from its `env`. */
export function coffre<Env>(configure: (env: Env) => WorkersConfig): WorkerHandler<Env> {
  return cloudflareHandler(configure, createUi());
}
