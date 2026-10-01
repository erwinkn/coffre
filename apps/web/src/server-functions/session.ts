import '@tanstack/react-start/server-only';

import { getRequest } from '@tanstack/react-start/server';

import { createClient, type CoffreClient } from '../../../../packages/client/src/index.ts';
import type { ApiContext } from '../server/api/context.ts';
import { serveApi } from '../server/api/router.ts';
import { requestIdentityContext, type AuthenticatedIdentity, type RequestIdentityContext } from '../server/auth.ts';
import { apiContext, getRuntime } from '../server/runtime.ts';

export function currentIdentity(): RequestIdentityContext | undefined {
  return requestIdentityContext(getRequest());
}

export function currentRequestContext(): AuthenticatedIdentity {
  const identity = currentIdentity();
  if (
    identity === undefined ||
    identity.principal === null ||
    !identity.registered
  ) {
    throw new Error('registered request context is unavailable');
  }
  return identity;
}

/** The caller's context for the API handlers, for what sits outside the route table. */
export function currentApiContext(): ApiContext {
  return apiContext(getRuntime(), currentRequestContext());
}

/**
 * The API, as the signed-in caller, without leaving the Worker: each call is
 * a Request handed straight to the router, so the UI goes through the same
 * checks, validation and audit as the CLI.
 */
export function api(): CoffreClient {
  const ctx = currentApiContext();
  return createClient({
    url: new URL(getRequest().url).origin,
    transport: (request) => serveApi(request, ctx),
  });
}
