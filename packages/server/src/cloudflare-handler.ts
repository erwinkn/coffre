import { createDatabase } from '@coffre/db';
import { HyperdrivePool, type PostgresDatabase } from '@coffre/db/hyperdrive';

import { runScheduled } from './app.ts';
import { cloudflareSourceIp } from './auth.ts';
import { resolveConfig, type CoffreConfig, type ResolvedConfig } from './config.ts';
import { createRuntime } from './runtime.ts';
import { requestScope, type CoffreContext } from './scope.ts';
import { fetchTransport } from './workloads/transport.ts';

export { postgres, type PostgresDatabase } from '@coffre/db/hyperdrive';

/** What the app Worker's `createCoffre(env => …)` returns. */
export type WorkersConfig = CoffreConfig & { database: PostgresDatabase };

/** The part of the Workers `ExecutionContext` coffre uses. */
export type WaitUntil = { waitUntil(promise: Promise<unknown>): void };

/** coffre on Workers: what the deployment's server entry runs. */
export type CoffreWorker<Env> = {
  /**
   * This invocation's coffre, for Start's handler to carry as the request's
   * context: `handler.fetch(request, { context: coffre.request(env, ctx) })`.
   */
  request(env: Env, ctx: WaitUntil): CoffreContext;
  /** coffre's scheduled job, the Worker's `scheduled`. */
  scheduled(controller: unknown, env: Env, ctx: WaitUntil): Promise<void>;
};

/**
 * coffre on Workers, configured from the Worker's `env`. Configuration is
 * read and checked once per `env`, which the isolate keeps; the database
 * client is built per invocation, since a Worker's I/O objects belong to the
 * request that made them: one client its queries take turns on, closed once
 * the request and the work it left to finish are done.
 */
export function createCoffre<Env>(configure: (env: Env) => WorkersConfig): CoffreWorker<Env> {
  const configs = new WeakMap<object, { config: WorkersConfig; resolved: ResolvedConfig }>();

  function runtimeFor(env: Env, ctx: WaitUntil) {
    let entry = configs.get(env as object);
    if (entry === undefined) {
      const config = configure(env);
      entry = { config, resolved: resolveConfig(config) };
      configs.set(env as object, entry);
    }
    const pool = new HyperdrivePool(entry.config.database.hyperdrive.connectionString);
    const left: Promise<unknown>[] = [];
    const runtime = createRuntime(entry.resolved, createDatabase(pool), entry.config.vault, fetchTransport(), (promise) => {
      left.push(promise);
      ctx.waitUntil(promise);
    });
    let closing: Promise<void> | undefined;
    /**
     * Close the client once `work`, and whatever the invocation left to
     * finish, are: the work of its request, a page with the API calls
     * its render made inside it, or its scheduled job.
     */
    const close = (work: Promise<unknown>) => {
      left.push(work);
      closing ??= (async () => {
        while (left.length > 0) await Promise.allSettled(left.splice(0));
        await pool.end();
      })();
      ctx.waitUntil(closing);
    };
    return { runtime, close };
  }

  return {
    request(env, ctx) {
      const { runtime, close } = runtimeFor(env, ctx);
      return { coffre: requestScope(runtime, cloudflareSourceIp, close) };
    },
    async scheduled(_controller, env, ctx) {
      const { runtime, close } = runtimeFor(env, ctx);
      const ran = runScheduled(runtime);
      close(ran);
      await ran;
    },
  };
}
