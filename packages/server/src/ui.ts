import type { CoffreClient } from '@coffre/client';

/**
 * The pages: `@coffre/ui`'s handler, or a stand-in in tests. It renders with
 * the nonce its scripts carry and a client that reaches the API in process,
 * as the visitor.
 */
export type Ui = {
  fetch(request: Request, init: { context: { cspNonce: string; client: CoffreClient } }): Promise<Response>;
};
