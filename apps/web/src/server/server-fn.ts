import { createServerFn } from '@tanstack/react-start';

import { registeredIdentityMiddleware } from './auth.ts';

/** Registered-user functions are the default application boundary. */
export const registeredServerFn = createServerFn().middleware([
  registeredIdentityMiddleware,
]);

/** Login and shell functions may inspect an anonymous or unregistered session. */
export const sessionServerFn = createServerFn();
