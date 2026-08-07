import '@tanstack/react-start/server-only';

import { getRequest } from '@tanstack/react-start/server';

import { requestIdentityContext, type RequestIdentityContext } from '../server/auth.ts';
import type { RequestContext } from '../server/services/secrets.ts';

export function currentIdentity(): RequestIdentityContext | undefined {
  return requestIdentityContext(getRequest());
}

export function currentRequestContext(): RequestContext {
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
