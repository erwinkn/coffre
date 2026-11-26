/**
 * What the vault takes from the Workers runtime, and the server's
 * `CoffreWorkload` (whose tsconfig includes this), declared here so that
 * its Worker typechecks with the rest of the package, under Node's types,
 * as the server's does. Workers' own types would shadow Node's
 * `Buffer` in every module the Worker imports: the store, the log, Drizzle.
 * A deployment that builds the Worker brings the real ones.
 */
declare module 'cloudflare:workers' {
  export abstract class WorkerEntrypoint<Env = unknown> {
    protected env: Env;
    /** `props`: what the caller's binding says, for a named entrypoint another Worker binds (the server's `CoffreWorkload`). */
    protected ctx: { readonly props?: unknown; waitUntil(promise: Promise<unknown>): void };
    constructor(ctx: unknown, env: Env);
  }
  /** A Durable Object's state, the part the signer's uses (cloudflare-signer.ts). */
  export type DurableObjectState = {
    /** `name`: the one it was got by, `idFromName`. */
    id: { readonly name?: string };
    storage: import('./signer-host.ts').Storage & { deleteAlarm(): Promise<void> };
    blockConcurrencyWhile<T>(run: () => Promise<T>): Promise<T>;
  };
  export abstract class DurableObject<Env = unknown> {
    protected env: Env;
    protected ctx: DurableObjectState;
    constructor(ctx: DurableObjectState, env: Env);
  }
}
