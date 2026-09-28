import {
  createCsrfMiddleware,
  createStart,
} from '@tanstack/react-start';
import {
  isApiPath,
  requestIdentityMiddleware,
} from './server/auth.ts';

// Defining a startInstance replaces Start's implicit default middleware. Keep
// CSRF explicit so adding authentication does not silently remove it.
const csrfMiddleware = createCsrfMiddleware({
  filter: ({ handlerType, request }) => shouldValidateCsrf(handlerType, request),
});

/**
 * Start checks the origin of form posts to page routes, such as sign-out.
 * `/api` checks its own, where it knows how the caller signed in: a change
 * made with a browser cookie must come from coffre's own pages, and one made
 * with a token needs no such check (see `server/fetch-api.ts`).
 */
export function shouldValidateCsrf(
  handlerType: 'serverFn' | 'router',
  request: Request,
): boolean {
  if (handlerType === 'serverFn') return true;
  if (['GET', 'HEAD', 'OPTIONS'].includes(request.method)) return false;
  return !isApiPath(new URL(request.url).pathname);
}

export const startInstance = createStart(() => ({
  requestMiddleware: [csrfMiddleware, requestIdentityMiddleware],
}));
