import handler from '@tanstack/react-start/server-entry';

import type { Ui } from './types.ts';

/**
 * `@coffre/ui`: Start's handler for the pages, nothing else. The server
 * around it answers `/api` and sign-in, and hands every other GET here with
 * the request's nonce and API client; see `router.tsx`.
 */
export function createUi(): Ui {
  return { fetch: async (request, init) => handler.fetch(request, init) };
}

// The build's Worker entry must have a default `fetch`. Nothing deploys the
// UI alone: without a client from the server a page has no API to ask.
export default {
  fetch: (request: Request) =>
    new Response('coffre/ui renders pages for @coffre/server; it does not run alone', { status: 501 }),
};
