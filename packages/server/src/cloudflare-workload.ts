// What another Worker of the account binds to use coffre with nothing to
// prove (docs/design/workload-access.md, section 9.2): an entrypoint whose
// caller's `props` name its service, `{ "entrypoint": "CoffreWorkload",
// "props": { "service": "edge-api" } }`, with the proxy as its `fetch` and
// `sign`, `verify` and `presign` over RPC. The deployment exports it,
// `export const CoffreWorkload = coffre.Workload`. Declared by that design's
// PR 0, so a Worker can name it; PR 6 builds it, here.

/** The entrypoint a `cloudflare` binding's Worker calls. */
export class CoffreWorkload {
  async fetch(_request: Request): Promise<Response> {
    return new Response("coffre's workload entrypoint is not built yet: docs/design/workload-access.md, PR 6, brings it", { status: 501 });
  }
}
