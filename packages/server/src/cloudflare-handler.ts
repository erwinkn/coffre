import { createDatabase } from './db/database.ts';
import { handleRequest, runScheduled } from './app.ts';
import { cloudflareSourceIp } from './auth.ts';
import { resolveConfig, type CoffreConfig, type ResolvedConfig } from './config.ts';
import { HyperdrivePool } from './database.ts';
import { createRuntime } from './runtime.ts';
import type { Ui } from './ui.ts';

/** Postgres through a Hyperdrive binding: `postgres(env.HYPERDRIVE)`. */
export type PostgresDatabase = { readonly engine: 'postgres'; readonly hyperdrive: { readonly connectionString: string } };

/** Postgres through Hyperdrive, the one database the Worker runs on. */
export function postgres(hyperdrive: { readonly connectionString: string }): PostgresDatabase {
  if (typeof hyperdrive?.connectionString !== 'string') {
    throw new Error('postgres() takes the Hyperdrive binding, e.g. postgres(env.HYPERDRIVE)');
  }
  return { engine: 'postgres', hyperdrive };
}

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
 * them.
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
    const db = createDatabase(new HyperdrivePool(entry.config.database.hyperdrive.connectionString));
    return createRuntime(entry.resolved, db, entry.config.vault, (promise) => ctx.waitUntil(promise));
  }

  return {
    fetch(request, env, ctx) {
      const runtime = runtimeFor(env, ctx);
      return handleRequest(request, runtime, ui, cloudflareSourceIp(request, runtime.auth));
    },
    async scheduled(_controller, env, ctx) {
      await runScheduled(runtimeFor(env, ctx));
    },
  };
}
