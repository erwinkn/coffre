// `@coffre/ui`'s public types, which its `.d.ts` is built from. The package
// itself is the Vite build of `index.ts`.
import type { CoffreClient } from '@coffre/client';
import type { AnyRouter } from '@tanstack/react-router';

export type { CoffreClient };

/** What each page request needs from the server around it. */
export type UiContext = {
  /** This response's Content-Security-Policy nonce, put on every script the page renders. */
  cspNonce: string;
  /** The API as the visitor, which every loader reads through; see `@coffre/server`. */
  client: CoffreClient;
};

/**
 * coffre's pages, as a TanStack Start router: a deployment's src/router.tsx
 * re-exports it, and Start calls it once per request and once in the browser.
 */
export declare function getRouter(): AnyRouter;

// What a deployment's Start app hands its handler, as `@coffre/server` does
// for every page: its server entry type-checks against this. Start's server
// entry reads the router's `Register`, and its context helpers Start's own.
declare module '@tanstack/react-router' {
  interface Register {
    server: { requestContext: UiContext };
  }
}

declare module '@tanstack/react-start' {
  interface Register {
    server: { requestContext: UiContext };
  }
}
