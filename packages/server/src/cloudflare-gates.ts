// The workload gate on Workers (docs/design/workload-access.md, section
// 5.2): a Durable Object per workload, `gate:<principal>`, which holds its
// nonce epochs, the `jti`s seen under each, and its counts, and implements
// `Gate` from `@coffre/core/identity`. The deployment binds it as `GATES`
// and exports it, `export const CoffreGates = coffre.Gates`. Declared by
// that design's PR 0, so a Worker can name it; PR 1b builds it, here.

/** The Durable Object class `GATES` binds. */
export class CoffreGates {
  async fetch(_request: Request): Promise<Response> {
    return new Response('the workload gate is not built yet: docs/design/workload-access.md, PR 1b, brings it', { status: 501 });
  }
}
