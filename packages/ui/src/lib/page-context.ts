import type { CoffreClient } from '@coffre/client';
import { NO_MIDDLEWARE } from '@coffre/core/pages';
import { getGlobalStartContext } from '@tanstack/react-start';

import type { Preferences } from './preferences';

/** What coffre's middleware hands each request's render (`@coffre/server/start`). */
export type PageContext = { cspNonce: string; client: CoffreClient; preferences: Preferences };

export const DEFAULT_PREFERENCES: Preferences = { theme: 'system', sidebar: 'expanded' };


/**
 * On the server, the request's page context: the visitor's API client, an
 * in-process call with their credential, the response's nonce and their
 * preferences, which coffre's middleware hands each request. A request it
 * did not pass through fails here, saying so, rather than render a page
 * with neither the client nor the headers. Undefined outside a request,
 * where a router is built only to resolve a redirect, and renders nothing.
 */
export function requestPage(): PageContext | undefined {
  let context: Partial<PageContext> | undefined;
  try {
    context = getGlobalStartContext() as Partial<PageContext> | undefined;
  } catch {
    return undefined;
  }
  if (context === undefined) return undefined;
  if (context.client === undefined) throw new Error(NO_MIDDLEWARE);
  return context as PageContext;
}
