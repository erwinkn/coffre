// The app Worker, and its Start app's server entry: Start's handler, with
// coffre in each request's context, and coffre's scheduled job. A WebSocket
// one of coffre's plugins takes goes to its Durable Object instead.
import handler from '@tanstack/react-start/server-entry';

import { coffre, type Env } from './coffre';

export default {
  fetch: (request: Request, env: Env, ctx: ExecutionContext) => coffre.upgrade(request, env) ?? handler.fetch(request, { context: coffre.request(env, ctx) }),
  scheduled: coffre.scheduled,
};

/** The Durable Objects `SOCKETS` and `GATES` bind (wrangler.jsonc). */
export const CoffreSockets = coffre.Sockets;
export const CoffreGates = coffre.Gates;

/**
 * What another Worker of the account binds to use the credential proxy as
 * the service its props name, with nothing to prove (docs/workloads.md,
 * "Cloudflare Workers"): `"services": [{ "binding": "COFFRE", "service":
 * "<this Worker>", "entrypoint": "CoffreWorkload", "props": { "service":
 * "edge-api" } }]` in that Worker's wrangler.jsonc. It calls
 * `env.COFFRE.fetch(…)`, and `env.COFFRE.sign(…)`, `verify(…)` and
 * `presign(…)` over RPC (`CoffreBinding`, from `@coffre/client/workload`).
 */
export const CoffreWorkload = coffre.Workload;
