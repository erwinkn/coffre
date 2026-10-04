import { createDatabase } from '@coffre/db';
import { HyperdrivePool, type PostgresDatabase } from '@coffre/db/hyperdrive';

import { handleRequest, runScheduled } from './app.ts';
import { cloudflareSourceIp } from './auth.ts';
import { resolveConfig, type CoffreConfig, type ResolvedConfig } from './config.ts';
import { createRuntime } from './runtime.ts';
import { fetchTransport } from './workloads/transport.ts';
import type { Ui } from './ui.ts';

export { postgres, type PostgresDatabase } from '@coffre/db/hyperdrive';

/** What the app Worker's `coffre(env => …)` returns. */
export type WorkersConfig = CoffreConfig & { database: PostgresDatabase };

/** The part of the Workers `ExecutionContext` coffre uses. */
export type WaitUntil = { waitUntil(promise: Promise<unknown>): void };

export type WorkerHandler<Env> = {
  fetch(request: Request, env: Env, ctx: WaitUntil): Promise<Response>;
  scheduled(controller: unknown, env: Env, ctx: WaitUntil): Promise<void>;
};

/**
 * The app Worker, for a UI. Configuration is read and checked once per
 * `env`, which the isolate keeps; the database client is built per
 * invocation, since a Worker's I/O objects belong to the request that made
 * them: one client its queries take turns on, closed once the request and
 * the work it left to finish are done.
 */
export function cloudflareHandler<Env>(configure: (env: Env) => WorkersConfig, ui: Ui): WorkerHandler<Env> {
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
    /** Close the client once `done`, and whatever the request left to finish, are. */
    const close = async (done: Promise<unknown>) => {
      await done.catch(() => {});
      while (left.length > 0) await Promise.allSettled(left.splice(0));
      await pool.end();
    };
    return { runtime, close };
  }

  return {
    fetch(request, env, ctx) {
      const { runtime, close } = runtimeFor(env, ctx);
      const response = handleRequest(request, runtime, ui, cloudflareSourceIp(request));
      ctx.waitUntil(close(response));
      return response;
    },
    async scheduled(_controller, env, ctx) {
      const { runtime, close } = runtimeFor(env, ctx);
      const ran = runScheduled(runtime);
      ctx.waitUntil(close(ran));
      await ran;
    },
  };
}
