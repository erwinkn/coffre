// `@coffre/ui`'s public types, which its `.d.ts` is built from. The package
// itself is the Start build of `entry.ts`.
import type { CoffreClient } from '../../client/src/index.ts';

export type { CoffreClient };

/** What each page request needs from the server around it. */
export type UiContext = {
  /** This response's Content-Security-Policy nonce, put on every script the page renders. */
  cspNonce: string;
  /** The API as the visitor, which every loader reads through; see `@coffre/server`. */
  client: CoffreClient;
};

/** coffre's pages: HTML for a GET or HEAD, with no API, database or configuration of its own. */
export type Ui = {
  fetch(request: Request, init: { context: UiContext }): Promise<Response>;
};

/** The pages' handler. Its static files are in `dist/client`, served under `/_coffre/`. */
export declare function createUi(): Ui;
