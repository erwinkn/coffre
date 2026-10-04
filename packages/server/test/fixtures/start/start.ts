// The app's src/start.ts, as coffre init writes it.
import { createCsrfMiddleware, createStart } from '@tanstack/react-start';

import { coffreMiddleware } from '../../../src/start.ts';

export const startInstance = createStart(() => ({
  requestMiddleware: [coffreMiddleware, createCsrfMiddleware({ filter: (ctx) => ctx.handlerType === 'serverFn' })],
}));
