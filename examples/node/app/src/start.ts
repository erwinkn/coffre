// Every request Start answers goes through coffre's middleware: a fresh CSP
// nonce, the visitor's API client for the pages, and coffre's security
// headers on the response. Then Start's CSRF check for server functions,
// which Start applies only while an app sets no middleware of its own:
// coffre has none, this app's may. coffre's goes first, so a refusal
// carries its headers too.
import { createCsrfMiddleware, createStart } from '@tanstack/react-start';
import { coffreMiddleware } from '@coffre/server/start';

export const startInstance = createStart(() => ({
  requestMiddleware: [coffreMiddleware, createCsrfMiddleware({ filter: (ctx) => ctx.handlerType === 'serverFn' })],
}));
