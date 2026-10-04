/**
 * coffre as a Node server:
 *
 *   import { serve, signin, github } from '@coffre/server/node';
 *   import { connectVault } from '@coffre/vault/node';
 *
 *   await serve({
 *     pages: new URL('../app/dist/', import.meta.url),
 *     port: 3000,
 *     publicUrl: 'https://secrets.acme.example',
 *     database: process.env.DATABASE_URL,
 *     vault: connectVault('/run/coffre/vault.sock'),
 *     auth: signin({ providers: [github({ clientId: …, clientSecret: … })] }),
 *     auditChainKey: process.env.APP_KEY,
 *   });
 *
 * One process serves the API, the pages and their static files, and runs
 * the scheduled job itself. The pages are the deployment's own TanStack
 * Start app, whose router is `@coffre/ui`'s: `vite build` puts its handler
 * in `dist/server/server.js` and its static files in `dist/client`.
 */
import { fileURLToPath, pathToFileURL } from 'node:url';

import { migrateDatabase } from '@coffre/db/migrate';

import { serveWith, type ServeOptions, type Server } from './node-server.ts';
import type { Ui } from './ui.ts';

export * from './index.ts';
export type { ServeOptions, Server };
/** Limits for workload exchanges that count in this process: `signin({ workloads: { limits: processLimits() } })`. */
export { processLimits } from './workloads/limits.ts';

/** Bring the database up to date: what `coffre-server migrate` runs. */
export function migrate(database: string): Promise<void> {
  return migrateDatabase(database);
}

/** Serve coffre until `close()`. */
export async function serve(options: ServeOptions & { pages: URL | string }): Promise<Server> {
  const { pages, ...rest } = options;
  if (typeof pages !== 'string' && !(pages instanceof URL)) {
    throw new Error(
      "pages is missing: since coffre 0.2 the pages are a TanStack Start app of the deployment's own, app/, built by Vite: pass serve({ pages: new URL('../app/dist/', import.meta.url), … }). Run `npx @coffre/cli@latest update` in the deployment to move it",
    );
  }
  // The app's build: its handler in server/, its static files in client/.
  const built = new URL(pages instanceof URL ? pages.href : pathToFileURL(pages).href);
  if (!built.pathname.endsWith('/')) built.pathname += '/';
  const entry = new URL('server/server.js', built);
  let handler: Ui;
  try {
    handler = ((await import(entry.href)) as { default: Ui }).default;
  } catch (error) {
    throw new Error(`no pages at ${fileURLToPath(entry)}: build the deployment's app first, with vite build`, { cause: error });
  }
  return serveWith(rest, handler, fileURLToPath(new URL('client/', built)));
}
