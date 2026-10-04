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
export type WorkersConfig = CoffreConfig & {
  database: PostgresDatabase;
  /** The pages: the default export of `@tanstack/react-start/server-entry`, in the deployment's Start app. */
  pages: Ui;
};

/** The part of the Workers `ExecutionContext` coffre uses. */
export type WaitUntil = { waitUntil(promise: Promise<unknown>): void };

export type WorkerHandler<Env> = {
  fetch(request: Request, env: Env, ctx: WaitUntil): Promise<Response>;
  scheduled(controller: unknown, env: Env, ctx: WaitUntil): Promise<void>;
};

/** What a deployment's app says with no pages: one from before its app was a Start app of its own. */
export const PAGES_MISSING =
  "pages is missing: since coffre 0.2 the app is a TanStack Start app of its own, built by Vite, and its server entry gives coffre Start's handler (import pages from '@tanstack/react-start/server-entry'). Run `npx @coffre/cli@latest update` in the deployment to move it, then deploy";

/** The most of a body answered unread, a refusal's, that is read before it is let go. */
const DRAIN_LIMIT = 1 << 20;

/**
 * A body the answer did not read, a refusal's say, read to its end before
 * the answer goes, as wrangler's own middleware does for a Worker it
 * bundles, in development only. A Worker Vite built runs without it, and
 * locally the runtime's proxy, still writing the body to a request that is
 * over, fails, and takes every request after with it. Cancelling the body,
 * the stream's or its reader's, does not stop that; reading it does.
 *
 * This runs in production too, on requests nobody has authenticated yet,
 * which is why it stops at `DRAIN_LIMIT`: past it the rest is let go, so a
 * large body refused costs at most a mebibyte read.
 */
export async function drainUnread(request: Request): Promise<void> {
  if (request.body === null || request.bodyUsed) return;
  const reader = request.body.getReader();
  let read = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      read += value.byteLength;
      if (read > DRAIN_LIMIT) return void (await reader.cancel());
    }
  } catch {
    // Already gone: nothing left to drain.
  }
}

/**
 * The app Worker. Configuration is read and checked once per
 * `env`, which the isolate keeps; the database client is built per
 * invocation, since a Worker's I/O objects belong to the request that made
 * them: one client its queries take turns on, closed once the request and
 * the work it left to finish are done.
 */
export function cloudflareHandler<Env>(configure: (env: Env) => WorkersConfig): WorkerHandler<Env> {
  const configs = new WeakMap<object, { config: WorkersConfig; resolved: ResolvedConfig }>();

  function runtimeFor(env: Env, ctx: WaitUntil) {
    let entry = configs.get(env as object);
    if (entry === undefined) {
      const config = configure(env);
      if (typeof config.pages?.fetch !== 'function') throw new Error(PAGES_MISSING);
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
    return { runtime, close, pages: entry.config.pages };
  }

  return {
    async fetch(request, env, ctx) {
      const { runtime, close, pages } = runtimeFor(env, ctx);
      const response = handleRequest(request, runtime, pages, cloudflareSourceIp(request));
      ctx.waitUntil(close(response));
      const answered = await response;
      await drainUnread(request);
      return answered;
    },
    async scheduled(_controller, env, ctx) {
      const { runtime, close } = runtimeFor(env, ctx);
      const ran = runScheduled(runtime);
      ctx.waitUntil(close(ran));
      await ran;
    },
  };
}
