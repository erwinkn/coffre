// What another Worker of the account binds to use coffre with nothing to
// prove (docs/design/workload-access.md, section 9.2): an entrypoint whose
// caller's `props` name its service,
//
//   "services": [{ "binding": "COFFRE", "service": "coffre", "entrypoint": "CoffreWorkload", "props": { "service": "edge-api" } }]
//
// and which the deployment's app Worker exports, `export const
// CoffreWorkload = coffre.Workload`. Its `fetch` is the credential proxy:
// `env.COFFRE.fetch('https://coffre/use/openai/v1/chat/completions', …)`,
// the host ignored, since the binding is the route. The call is
// `token:edge-api`'s, which the vault holds to that service's live
// `cloudflare` bindings and grants, and the credential's rules and limit
// hold as they hold a session's: the Worker never holds the credential's
// value, only what the upstream answers.
//
// What vouches for the service is Cloudflare's: `props` comes from the
// calling Worker's deploy configuration, which its code cannot change. So
// whoever may deploy Workers to the account may name any service, and could
// as well deploy coffre itself. `sign`, `verify` and `presign` over RPC
// come later; `POST /use/<project>/<env>` with `{ sign: … }` reaches them
// through `fetch` meanwhile.
import { migrating, schemaReady } from './app.ts';
import { errorResponse } from './http.ts';
import { bindingRoute } from './plugins.ts';
import type { CoffreRuntime } from './runtime.ts';

/** The part of a call's `ExecutionContext` the entrypoint reads: its binding's `props`, and the work the call leaves to finish. */
export type BoundContext = { readonly props?: unknown; waitUntil(promise: Promise<unknown>): void };

/** A service's name as a member names it, without `token:`: no space, no control character. */
const SERVICE = /^[^\s\p{Cc}]{1,249}$/u;

/** The service `props` name, `token:<name>`, as `{ "service": "edge-api" }` or `{ "service": "token:edge-api" }` says it; null for anything else. */
export function boundService(props: unknown): string | null {
  if (typeof props !== 'object' || props === null || Array.isArray(props)) return null;
  const { service } = props as { service?: unknown };
  if (typeof service !== 'string') return null;
  const name = service.startsWith('token:') ? service.slice('token:'.length) : service;
  return SERVICE.test(name) ? `token:${name}` : null;
}

const refusal = (status: number, message: string, reason: string) =>
  Response.json({ error: status === 404 ? 'not_found' : 'forbidden', reason, message }, { status, headers: { 'coffre-proxy': 'refused' } });

/**
 * The entrypoint, over the runtime `open` makes for each call: its database
 * client, which `end` closes once the answer and the work it left are done.
 * An object with a `fetch`, as workerd takes a named entrypoint, so the
 * server's modules load on Node, which has no `cloudflare:workers`.
 */
export function workloadEntrypoint<Env>(open: (env: Env) => { runtime: CoffreRuntime; end(): Promise<void> }) {
  return {
    async fetch(request: Request, env: Env, ctx: BoundContext): Promise<Response> {
      const service = boundService(ctx.props);
      if (service === null) return refusal(403, 'this binding names no service: its props say { "service": "<name>" }, the service account coffre holds it to', 'props');
      // A WebSocket, a tunnel's, comes from `coffre run`'s listener with a handle or a session, never over a binding.
      if (request.headers.get('upgrade') !== null) return refusal(403, 'a call over a service binding opens no WebSocket', 'bound');
      const { runtime, end } = open(env);
      const left: Promise<unknown>[] = [];
      const track = (work: Promise<unknown>) => void left.push(work);
      try {
        // Below this version's migrations, the answer every request gets at coffre's one door (`respond`).
        if (!(await schemaReady(runtime))) return migrating(request);
        const answer = bindingRoute(request, runtime, service, track);
        if (answer === null) return refusal(404, 'a Worker bound to coffre reaches its plugins alone: /use/<credential>/<path>', 'not_found');
        return await answer;
      } catch (error) {
        return errorResponse(error);
      } finally {
        // The upstream's body streams after this; nothing of it reads the database, which goes once the work left is done.
        ctx.waitUntil((async () => {
          while (left.length > 0) await Promise.allSettled(left.splice(0));
          await end();
        })());
      }
    },
  };
}
