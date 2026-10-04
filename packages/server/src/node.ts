/**
 * coffre on Node, in the deployment's own TanStack Start app, built by Vite
 * as on Workers. The configuration, once:
 *
 *   // app/src/coffre.ts
 *   import { createCoffre, github, signin } from '@coffre/server/node';
 *   import { connectVault } from '@coffre/vault/node';
 *
 *   export const coffre = createCoffre({
 *     publicUrl: 'https://secrets.acme.example',
 *     database: process.env.DATABASE_URL,
 *     vault: connectVault('/run/coffre/vault.sock'),
 *     auth: signin({ providers: [github({ clientId: …, clientSecret: … })] }),
 *     auditChainKey: process.env.APP_KEY,
 *   });
 *
 * and Start's server entry, which hands each request coffre and runs the
 * scheduled job:
 *
 *   // app/src/server.ts
 *   coffre.schedule();
 *   export default { fetch: (request: Request) => handler.fetch(request, { context: coffre.request(request) }) };
 *
 * `vite build app` puts the server in `app/dist/server/server.js` and the
 * static files in `app/dist/client`, which any server that calls the
 * entry's `fetch` runs: `srvx --prod -s ../client app/dist/server/server.js`,
 * as TanStack Start documents for Node.
 */
import { openDatabase } from '@coffre/db/connect';
import { migrateDatabase } from '@coffre/db/migrate';

import { runScheduled } from './app.ts';
import { resolveConfig, type CoffreConfig } from './config.ts';
import { logged } from './logged.ts';
import { createRuntime, type CoffreRuntime } from './runtime.ts';
import { requestScope, type CoffreContext } from './scope.ts';
import { nodeTransport } from './workloads/node-transport.ts';

export * from './index.ts';
export type { CoffreContext, CoffreRequest, PageContext, Preferences } from './scope.ts';
/** Limits for workload exchanges that count in this process: `signin({ workloads: { limits: processLimits() } })`. */
export { processLimits } from './workloads/limits.ts';

/** Bring the database up to date: what `coffre-server migrate` runs. */
export function migrate(database: string): Promise<void> {
  return migrateDatabase(database);
}

/** coffre on Node: what the deployment's server entry runs. */
export type CoffreNode = {
  /** This request's coffre, for Start's handler to carry as its context: `handler.fetch(request, { context: coffre.request(request) })`. */
  request(request: Request): CoffreContext;
  /** Run the scheduled job, the audit heartbeat and the vault's checkpoint of it: now, and every five minutes after. */
  schedule(): void;
};

const SCHEDULE_MINUTES = 5;

/**
 * coffre on Node, its configuration checked now. The database opens with
 * the first request or the first run of the scheduled job, and serves the
 * process's every request from then on.
 */
export function createCoffre(config: NodeConfig): CoffreNode {
  const resolved = checkNodeConfig(config);
  let runtime: Promise<CoffreRuntime> | undefined;
  const ready = () =>
    (runtime ??= openDatabase(config.database).then((database) => createRuntime(resolved, database.db, config.vault, nodeTransport())));
  let timer: NodeJS.Timeout | undefined;
  return {
    request(request) {
      // The caller's address, as srvx gives it on Node; behind a proxy, the proxy's.
      const sourceIp = (request as { ip?: string }).ip ?? null;
      const scope = ready().then((rt) => requestScope(rt, () => sourceIp));
      return {
        coffre: {
          route: async (req) => (await scope).route(req),
          respond: async (req, render) => (await scope).respond(req, render),
        },
      };
    },
    schedule() {
      if (timer !== undefined) return;
      const tick = () =>
        ready()
          .then(runScheduled)
          .catch((error: unknown) => console.error('scheduled job failed', logged(error)));
      void tick();
      timer = setInterval(tick, SCHEDULE_MINUTES * 60_000);
      timer.unref();
    },
  };
}

/** coffre's configuration on Node. */
export type NodeConfig = CoffreConfig & {
  /** `postgres://…`, or `file:coffre.db` for local SQLite. */
  database: string;
};

/** Check coffre's configuration on Node, failing on the first problem. */
function checkNodeConfig(options: NodeConfig) {
  const config = resolveConfig(options);
  if (typeof options.database !== 'string' || options.database.length === 0) {
    throw new Error('database must be a URL: postgres://… or file:…');
  }
  return config;
}

/**
 * 0.1's server, which served prebuilt pages. Since 0.2 the app is a Start
 * app of its own, coffre configured with `createCoffre({ … })` in its
 * `app/src/coffre.ts`: this says so, the moment a deployment that has not
 * moved starts.
 *
 * @deprecated Since 0.2, `createCoffre({ … })` in the app: run `npx @coffre/cli@latest update`, or see docs/deploy.md, "Upgrading to 0.2".
 */
export function serve(..._options: unknown[]): never {
  throw new Error(
    "serve({ … }) is from coffre 0.1: since 0.2 the app is a TanStack Start app of its own, configured with createCoffre({ … }) " +
      'in app/src/coffre.ts. Run `npx @coffre/cli@latest update` in the deployment to move it, or see docs/deploy.md, "Upgrading to 0.2"',
  );
}
