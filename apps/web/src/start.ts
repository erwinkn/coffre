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
  filter: ({ handlerType }) => handlerType === 'serverFn',
});

export const startInstance = createStart(() => ({
  requestMiddleware: [csrfMiddleware, requestIdentityMiddleware],
}));
