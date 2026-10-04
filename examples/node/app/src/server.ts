// The server, which `pnpm start` runs under srvx: Start's handler, with
// coffre in each request's context; coffre's scheduled job, the heartbeat
// and audit checkpoints, every five minutes from the start; and the
// browser's files. `vite build app` builds it into
// app/dist/server/server.js.
import { fileURLToPath } from 'node:url';

import handler from '@tanstack/react-start/server-entry';
import type { ServerMiddleware } from 'srvx';
import { serveStatic } from 'srvx/static';

import { coffre } from './coffre';

coffre.schedule();

export default {
  fetch: (request: Request) => handler.fetch(request, { context: coffre.request(request) }),
};

// The browser's files, from app/dist/client: each name holds its content's
// hash, so a browser keeps it for good. Never sniffed, and for this origin's
// pages alone, as coffre's own responses are.
const files = serveStatic({ dir: fileURLToPath(new URL('../client', import.meta.url)) });

export const middleware: ServerMiddleware[] = [
  async (request, next) => {
    if (!new URL(request.url).pathname.startsWith('/_coffre/assets/')) return next();
    const response = await files(request, next);
    if (response.ok) {
      response.headers.set('cache-control', 'public, max-age=31536000, immutable');
      response.headers.set('x-content-type-options', 'nosniff');
      response.headers.set('cross-origin-resource-policy', 'same-origin');
    }
    return response;
  },
];
