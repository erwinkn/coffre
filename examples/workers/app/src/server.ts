// The app Worker, and its Start app's server entry: Start's handler, with
// coffre in each request's context, and coffre's scheduled job. A WebSocket
// one of coffre's plugins takes goes to its Durable Object instead.
import handler from '@tanstack/react-start/server-entry';

import { coffre, type Env } from './coffre';

export default {
  fetch: (request: Request, env: Env, ctx: ExecutionContext) => coffre.upgrade(request, env) ?? handler.fetch(request, { context: coffre.request(env, ctx) }),
  scheduled: coffre.scheduled,
};

/** The Durable Object `SOCKETS` binds (wrangler.jsonc). */
export const CoffreSockets = coffre.Sockets;
