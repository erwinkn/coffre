// Every request Start answers goes through coffre's middleware: a fresh CSP
// nonce, the visitor's API client for the pages, and coffre's security
// headers on the response.
import { createStart } from '@tanstack/react-start';
import { coffreMiddleware } from '@coffre/server/start';

export const startInstance = createStart(() => ({ requestMiddleware: [coffreMiddleware] }));
