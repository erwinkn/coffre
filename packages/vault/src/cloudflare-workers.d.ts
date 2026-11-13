/**
 * What the vault takes from the Workers runtime, declared here so
 * that its Worker typechecks with the rest of the package, under Node's
 * types, as the server's does. Workers' own types would shadow Node's
 * `Buffer` in every module the Worker imports: the store, the log, Drizzle.
 * A deployment that builds the Worker brings the real ones.
 */
declare module 'cloudflare:workers' {
  export abstract class WorkerEntrypoint<Env = unknown> {
    protected env: Env;
    protected ctx: { waitUntil(promise: Promise<unknown>): void };
    constructor(ctx: unknown, env: Env);
  }
  /** A Durable Object's state, the part the signer's uses (cloudflare-signer.ts). */
  export type DurableObjectState = {
    storage: import('./signer-host.ts').Storage;
    blockConcurrencyWhile<T>(run: () => Promise<T>): Promise<T>;
  };
  export abstract class DurableObject<Env = unknown> {
    protected env: Env;
    protected ctx: DurableObjectState;
    constructor(ctx: DurableObjectState, env: Env);
  }
}
