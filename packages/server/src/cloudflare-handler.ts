import { createDatabase } from '@coffre/db';
import { HyperdrivePool, type PostgresDatabase } from '@coffre/db/hyperdrive';

import { cloudflareSourceIp } from './auth.ts';
import { CoffreGates, workersGates, type GatesNamespace } from './cloudflare-gates.ts';
import { forwardSocket, IDLE_DATABASE_MS, socketsObject, type SocketsNamespace } from './cloudflare-sockets.ts';
import { resolveConfig, type CoffreConfig, type ResolvedConfig } from './config.ts';
import type { Gates } from './gate.ts';
import { takesSocket } from './plugins.ts';
import { createRuntime } from './runtime.ts';
import { requestScope, type CoffreContext } from './scope.ts';
import { admitSocket } from './socket-admission.ts';
import { fetchTransport } from './workloads/transport.ts';

export { postgres, type PostgresDatabase } from '@coffre/db/hyperdrive';

/** What the app Worker's `createCoffre(env => …)` returns. */
export type WorkersConfig = CoffreConfig & {
  database: PostgresDatabase;
  /**
   * The Durable Object that holds each service's workload gate, `CoffreGates`
   * (`CoffreWorker.Gates`), bound as `GATES`: `gates: env.GATES`. Without it
   * the deployment takes no workload session.
   */
  gates?: GatesNamespace;
  /**
   * The Durable Object that hosts plugins' WebSockets, `CoffreSockets`
   * (`CoffreWorker.Sockets`), bound as `SOCKETS`: `sockets: env.SOCKETS`.
   * The credential proxy's database tunnel runs there, one object per
   * `coffre run` and database. Without it, a WebSocket is refused.
   */
  sockets?: SocketsNamespace;
};

/** The part of the Workers `ExecutionContext` coffre uses. */
export type WaitUntil = { waitUntil(promise: Promise<unknown>): void };

/** 0.14's audit anchor's Durable Object, with nothing left to answer (`CoffreWorker.Anchor`). */
class CoffreAnchor {}

/** coffre on Workers: what the deployment's server entry runs. */
export type CoffreWorker<Env> = {
  /**
   * This invocation's coffre, for Start's handler to carry as the request's
   * context: `handler.fetch(request, { context: coffre.request(env, ctx) })`.
   */
  request(env: Env, ctx: WaitUntil): CoffreContext;
  /**
   * The Worker's `scheduled`, which does nothing: the app has no scheduled
   * job left, the signer's minute does the upkeep. Kept through 0.16.0,
   * since a 0.14 deployment's Worker names it and its cron still fires.
   */
  scheduled(controller: unknown, env: Env, ctx: WaitUntil): Promise<void>;
  /**
   * A WebSocket a plugin takes, sent on to its Durable Object; null for any
   * other request, which Start answers: `coffre.upgrade(request, env) ??
   * handler.fetch(…)`.
   */
  upgrade(request: Request, env: Env): Promise<Response> | null;
  /** The Durable Object class `SOCKETS` binds, which the Worker exports: `export const CoffreSockets = coffre.Sockets`. */
  Sockets: ReturnType<typeof socketsObject<Env>>;
  /**
   * 0.14's audit anchor's Durable Object, inert: a 0.14 deployment's app still
   * binds and exports it (`export const CoffreAnchor = coffre.Anchor`), and
   * keeping the class keeps its storage for going back (docs/design/0.16.md,
   * "At Equisafe"). The release after 0.16.0 removes it, with the
   * `deleted_classes` migration the deployment then needs.
   */
  Anchor: typeof CoffreAnchor;
  /** The workload gates' Durable Object, which the deployment exports as bound: `export const CoffreGates = coffre.Gates`. */
  Gates: typeof CoffreGates;
};

/**
 * coffre on Workers, configured from the Worker's `env`. Configuration is
 * read and checked once per `env`, which the isolate keeps; the database
 * client is built per invocation, since a Worker's I/O objects belong to the
 * request that made them: one client its queries take turns on, closed once
 * the request and the work it left to finish are done.
 */
export function createCoffre<Env>(configure: (env: Env) => WorkersConfig): CoffreWorker<Env> {
  const configs = new WeakMap<object, { config: WorkersConfig; resolved: ResolvedConfig; gates: Gates | null }>();

  function configured(env: Env) {
    let entry = configs.get(env as object);
    if (entry === undefined) {
      const config = configure(env);
      entry = { config, resolved: resolveConfig(config), gates: config.gates === undefined ? null : workersGates(config.gates) };
      configs.set(env as object, entry);
    }
    return entry;
  }

  return {
    request(env, ctx) {
      const entry = configured(env);
      const pool = new HyperdrivePool(entry.config.database.hyperdrive.connectionString);
      const runtime = createRuntime(entry.resolved, createDatabase(pool), entry.config.vault, { transport: fetchTransport(), gates: entry.gates });
      const left: Promise<unknown>[] = [];
      let closing: Promise<void> | undefined;
      /**
       * Close the client once `work`, and whatever else the invocation is
       * told of meanwhile, are done: its middleware's answer, and the
       * route or the page with the API calls its render made inside it.
       */
      const close = (work: Promise<unknown>) => {
        left.push(work);
        closing ??= (async () => {
          while (left.length > 0) await Promise.allSettled(left.splice(0));
          await pool.end();
        })();
        ctx.waitUntil(closing);
      };
      return { coffre: requestScope(runtime, cloudflareSourceIp, close) };
    },
    async scheduled() {},
    upgrade(request, env) {
      if (request.headers.get('upgrade')?.toLowerCase() !== 'websocket') return null;
      const { config, resolved } = configured(env);
      if (!takesSocket(request, resolved.plugins)) return null;
      if (config.sockets === undefined) return Promise.resolve(new Response('this deployment hosts no WebSockets: its configuration names no sockets binding', { status: 501 }));
      return forwardSocket(request, config.sockets);
    },
    // The object's coffre lasts as long as it does: its database client, which only routes, opens with a query and closes once idle.
    Sockets: socketsObject<Env>((env) => {
      const { config, resolved, gates } = configured(env);
      const pool = new HyperdrivePool(config.database.hyperdrive.connectionString, { closeIdleMs: IDLE_DATABASE_MS });
      const runtime = createRuntime(resolved, createDatabase(pool), config.vault, { transport: fetchTransport(), gates });
      return (request, sourceIp, hold) => admitSocket(request, runtime, sourceIp, hold);
    }),
    Anchor: CoffreAnchor,
    Gates: CoffreGates,
  };
}
