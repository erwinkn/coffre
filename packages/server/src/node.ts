/**
 * coffre on Node. The configuration, once, in plain Node:
 *
 *   // src/server.ts
 *   import { createCoffre, serve, signin, github } from '@coffre/server/node';
 *   import { connectVault } from '@coffre/vault/node';
 *
 *   const coffre = createCoffre({
 *     publicUrl: 'https://secrets.acme.example',
 *     database: process.env.DATABASE_URL,
 *     vault: connectVault('/run/coffre/vault.sock'),
 *     auth: signin({ providers: [github({ clientId: …, clientSecret: … })] }),
 *     auditChainKey: process.env.APP_KEY,
 *   });
 *   await serve({ app: new URL('../app/dist/', import.meta.url), coffre, port: 3000 });
 *
 * `app` is the deployment's own TanStack Start app, built by Vite: its route
 * tree holds coffre's pages (`@coffre/ui`) and server routes
 * (`@coffre/server/routes`), its src/start.ts coffre's middleware
 * (`@coffre/server/start`). `vite build` puts its handler in
 * `dist/server/server.js` and its static files in `dist/client`. One process
 * serves them all, and runs the scheduled job itself.
 */
import { fileURLToPath, pathToFileURL } from 'node:url';

import { migrateDatabase } from '@coffre/db/migrate';

import { checkNodeConfig, serveWith, type NodeConfig, type ServeOptions, type Server } from './node-server.ts';
import { requestScope, type CoffreContext } from './scope.ts';

export * from './index.ts';
export type { NodeConfig, ServeOptions, Server };
export type { CoffreContext, CoffreRequest, PageContext } from './scope.ts';
/** Limits for workload exchanges that count in this process: `signin({ workloads: { limits: processLimits() } })`. */
export { processLimits } from './workloads/limits.ts';

/** Bring the database up to date: what `coffre-server migrate` runs. */
export function migrate(database: string): Promise<void> {
  return migrateDatabase(database);
}

/** coffre on Node, as `serve` takes it: its configuration, checked now. */
export type CoffreNode = { readonly config: NodeConfig };

export function createCoffre(config: NodeConfig): CoffreNode {
  checkNodeConfig(config);
  return { config };
}

/** Start's handler, as `vite build` leaves it in the app's `dist/server/server.js`. */
type StartHandler = { fetch(request: Request, init: { context: CoffreContext }): Response | Promise<Response> };

/** Serve the deployment's Start app, with coffre in each request's context, until `close()`. */
export async function serve(options: ServeOptions & { app: URL | string; coffre: CoffreNode }): Promise<Server> {
  const { app, coffre, ...rest } = options;
  if (coffre === undefined || (typeof app !== 'string' && !(app instanceof URL))) {
    throw new Error(
      "serve needs the app and coffre: serve({ app: new URL('../app/dist/', import.meta.url), coffre: createCoffre({ … }) }). " +
        'A deployment from coffre 0.1 moves with `npx @coffre/cli@latest update`; see docs/deploy.md, "Upgrading to 0.2"',
    );
  }
  // The app's build: its handler in server/, its static files in client/.
  const built = new URL(app instanceof URL ? app.href : pathToFileURL(app).href);
  if (!built.pathname.endsWith('/')) built.pathname += '/';
  const entry = new URL('server/server.js', built);
  let handler: StartHandler;
  try {
    handler = ((await import(entry.href)) as { default: StartHandler }).default;
  } catch (error) {
    throw new Error(`no app at ${fileURLToPath(entry)}: build the deployment's app first, with vite build`, { cause: error });
  }
  return serveWith(
    coffre.config,
    rest,
    async (request, runtime, sourceIp) => handler.fetch(request, { context: { coffre: requestScope(runtime, () => sourceIp) } }),
    fileURLToPath(new URL('client/', built)),
  );
}
