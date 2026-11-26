// `cloudflare:workers` on Node, which has none, for the tests that load coffre's Workers entry (src/cloudflare.ts)
// there: once this module is imported, that specifier resolves to it, so the entry is imported after it, dynamically.
// Its `WorkerEntrypoint` is the class `CoffreWorkload` extends, which these tests never call; workerd runs the real one
// (test/app-workers.test.ts).
import { registerHooks } from 'node:module';

registerHooks({
  resolve: (specifier, context, next) => (specifier === 'cloudflare:workers' ? { url: import.meta.url, shortCircuit: true } : next(specifier, context)),
});

export abstract class WorkerEntrypoint<Env = unknown> {
  protected ctx: unknown;
  protected env: Env;
  constructor(ctx: unknown, env: Env) {
    this.ctx = ctx;
    this.env = env;
  }
}
