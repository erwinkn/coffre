import { createDatabase } from '@coffre/db';
import { HyperdrivePool, type PostgresDatabase } from '@coffre/db/hyperdrive';

import { runScheduled } from './app.ts';
import { cloudflareSourceIp } from './auth.ts';
import { resolveConfig, type CoffreConfig, type ResolvedConfig } from './config.ts';
import { CoffreGates, workersGates, type GatesNamespace } from './cloudflare-gates.ts';
import { forwardSocket, IDLE_DATABASE_MS, socketsObject, type SocketsNamespace } from './cloudflare-sockets.ts';
import { workloadEntrypoint, type CoffreWorkload } from './cloudflare-workload.ts';
import type { Gates } from './gate.ts';
import { takesSocket } from './plugins.ts';
import { createRuntime } from './runtime.ts';
import { requestScope, type CoffreContext } from './scope.ts';
import { admitSocket } from './socket-admission.ts';
import { fetchTransport } from './workloads/transport.ts';

export { postgres, type PostgresDatabase } from '@coffre/db/hyperdrive';

/**
 * What the app Worker's `createCoffre(env => …)` returns. `sockets`, the
 * Durable Object binding whose class is `coffre.Sockets`, hosts plugins'
 * WebSockets, the credential proxy's database tunnel: without it, they are
 * refused. `gates`, the one whose class is `coffre.Gates`, holds each
 * workload's gate (docs/design/workload-access.md, section 5.2): without
 * it, no key-bound session is taken, since nothing else on Workers can
 * hold a proof to one use.
 */
export type WorkersConfig = CoffreConfig & { database: PostgresDatabase; sockets?: SocketsNamespace; gates?: GatesNamespace };

export type { GatesNamespace, SocketsNamespace };

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
  /**
   * A WebSocket a plugin takes, sent on to its Durable Object; null for any
   * other request, which Start answers: `coffre.upgrade(request, env) ??
   * handler.fetch(…)`.
   */
  upgrade(request: Request, env: Env): Promise<Response> | null;
  /** The Durable Object class `sockets` binds, which the Worker exports: `export const CoffreSockets = coffre.Sockets`. */
  Sockets: ReturnType<typeof socketsObject<Env>>;
  /** The workloads' gates' Durable Object class, which `GATES` binds: `export const CoffreGates = coffre.Gates` (docs/design/workload-access.md, section 5.2). */
  Gates: typeof CoffreGates;
  /** The entrypoint another Worker binds with `props` naming its service: `export const CoffreWorkload = coffre.Workload` (section 9.2). */
  Workload: CoffreWorkload;
};

/**
 * coffre on Workers, configured from the Worker's `env`. Configuration is
 * read and checked once per `env`, which the isolate keeps; the database
 * client is built per invocation, since a Worker's I/O objects belong to the
 * request that made them: one client its queries take turns on, closed once
 * the request and the work it left to finish are done.
 */
export function createCoffre<Env>(configure: (env: Env) => WorkersConfig): CoffreWorker<Env> {
  const configs = new WeakMap<object, { config: WorkersConfig; resolved: ResolvedConfig; gates: Gates | undefined }>();

  function configured(env: Env) {
    let entry = configs.get(env as object);
    if (entry === undefined) {
      const config = configure(env);
      entry = { config, resolved: resolveConfig(config), gates: config.gates && workersGates(config.gates) };
      configs.set(env as object, entry);
    }
    return entry;
  }

  function runtimeFor(env: Env, ctx: WaitUntil) {
    const entry = configured(env);
    const pool = new HyperdrivePool(entry.config.database.hyperdrive.connectionString);
    const left: Promise<unknown>[] = [];
    const runtime = createRuntime(entry.resolved, createDatabase(pool), entry.config.vault, fetchTransport(), (promise) => {
      left.push(promise);
      ctx.waitUntil(promise);
    }, entry.gates);
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
    upgrade(request, env) {
      if (request.headers.get('upgrade')?.toLowerCase() !== 'websocket') return null;
      const { config, resolved } = configured(env);
      if (!takesSocket(request, resolved.plugins)) return null;
      if (config.sockets === undefined) return Promise.resolve(new Response('this deployment hosts no WebSockets: its configuration names no sockets binding', { status: 501 }));
      return forwardSocket(request, config.sockets);
    },
    // The object's coffre lasts as long as it does: its database client opens with a query and closes once idle.
    Sockets: socketsObject<Env>((env, state) => {
      const { config, resolved, gates } = configured(env);
      const pool = new HyperdrivePool(config.database.hyperdrive.connectionString, { closeIdleMs: IDLE_DATABASE_MS });
      const runtime = createRuntime(resolved, createDatabase(pool), config.vault, fetchTransport(), (promise) => state.waitUntil(promise), gates);
      return (request, sourceIp, hold) => admitSocket(request, runtime, sourceIp, hold);
    }),
    Gates: CoffreGates,
    Workload: workloadEntrypoint<Env>(runtimeFor),
  };
}
