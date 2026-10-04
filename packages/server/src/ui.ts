import type { CoffreClient } from '@coffre/client';

/**
 * The pages: the deployment's TanStack Start handler, whose router is
 * `@coffre/ui`'s, or a stand-in in tests. It renders with the nonce its
 * scripts carry and a client that reaches the API in process, as the
 * visitor.
 */
export type Ui = {
  fetch(request: Request, init: { context: { cspNonce: string; client: CoffreClient } }): Response | Promise<Response>;
};
