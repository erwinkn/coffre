import {
  createCsrfMiddleware,
  createStart,
} from '@tanstack/react-start';
import {
  requestIdentityMiddleware,
} from './server/auth.ts';

// Defining a startInstance replaces Start's implicit default middleware. Keep
// CSRF explicit so adding authentication does not silently remove it.
const csrfMiddleware = createCsrfMiddleware({
  filter: ({ handlerType, request }) => shouldValidateCsrf(handlerType, request),
});

/**
 * Browser server functions use origin validation. Native API mutations may
 * skip it only when they use a non-simple JSON content type, which browsers
 * must preflight and HTML forms cannot send.
 */
export function shouldValidateCsrf(
  handlerType: 'serverFn' | 'router',
  request: Request,
): boolean {
  if (handlerType === 'serverFn') return true;
  if (['GET', 'HEAD', 'OPTIONS'].includes(request.method)) return false;

  const mediaType = request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase();
  return mediaType !== 'application/json' && !mediaType?.endsWith('+json');
}

export const startInstance = createStart(() => ({
  requestMiddleware: [csrfMiddleware, requestIdentityMiddleware],
}));
