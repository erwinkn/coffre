// What another Worker of the account binds to use coffre with nothing to
// prove (docs/design/workload-access.md, section 9.2): an entrypoint whose
// caller's `props` name its service,
//
//   "services": [{ "binding": "COFFRE", "service": "coffre", "entrypoint": "CoffreWorkload", "props": { "service": "edge-api" } }]
//
// with the credential proxy as its `fetch`, and `sign`, `verify` and
// `presign` over RPC. The deployment exports it, `export const
// CoffreWorkload = coffre.Workload`.
//
// Props are set by the caller's deploy configuration, which its code cannot
// change, so they are the proof: whoever may deploy Workers to the account
// is the trust root. They name a service and nothing else; the service must
// have a live binding of profile `cloudflare`, which the plugin's context
// checks, with the freezes, on each call. A caller without props, or with
// props of any other shape, gets nothing, before any database is opened.
//
// Each call is one request's coffre: a database client of its own, closed
// once the call and the work it left are done, as for a request
// (cloudflare-handler.ts), and the same door, so that a deployment below its
// migrations answers `migrating` here too.
import { CoffreError } from '@coffre/client';

import { respond } from './app.ts';
import { bindingRoute } from './plugins.ts';
import type { CoffreRuntime } from './runtime.ts';

/** The part of the Workers `ExecutionContext` an entrypoint uses: the props its caller's binding set, and `waitUntil`. */
type EntrypointContext = { readonly props?: unknown; waitUntil(promise: Promise<unknown>): void };

/** One call's coffre, as `createCoffre` makes it for each invocation: its runtime, and how to close its database once `work` is done. */
export type OpenCall<Env> = (env: Env, ctx: EntrypointContext) => { runtime: CoffreRuntime; close(work: Promise<unknown>): void };

/**
 * Workers' `WorkerEntrypoint`, which a class must extend for its methods to
 * be called over RPC. Node, where tests load this module, has no
 * `cloudflare:workers`: a plain class stands in, which nothing calls there.
 */
const { WorkerEntrypoint } = (await import('cloudflare:workers' as string).catch(() => ({
  WorkerEntrypoint: class {
    readonly ctx: EntrypointContext;
    readonly env: unknown;
    constructor(ctx: EntrypointContext, env: unknown) {
      this.ctx = ctx;
      this.env = env;
    }
  },
}))) as { WorkerEntrypoint: new (ctx: EntrypointContext, env: unknown) => { readonly ctx: EntrypointContext; readonly env: unknown } };

/** A service's name, as the workload exchange takes it: `edge-api`, or `token:edge-api`. */
const SERVICE = /^(?:token:)?([a-z0-9][a-z0-9._-]{0,99})$/;

/**
 * The service a caller's props name, `token:<name>`: props of exactly one
 * field, `service`. Null for anything else, no props included, so that a
 * typo or a field coffre does not know refuses rather than being ignored.
 */
export function propsService(props: unknown): string | null {
  if (typeof props !== 'object' || props === null || Array.isArray(props)) return null;
  const fields = Object.keys(props);
  if (fields.length !== 1 || fields[0] !== 'service') return null;
  const service = (props as { service: unknown }).service;
  const named = typeof service === 'string' ? SERVICE.exec(service) : null;
  return named === null ? null : `token:${named[1]}`;
}

const NO_PROPS =
  'this Worker binds coffre without props naming its service: its service binding says "props": { "service": "<name>" }, and the service has a cloudflare binding (coffre trust <name> --cloudflare)';

/** What a call through the binding answers, and what an RPC method throws. */
function refusal(status: number, message: string, reason: string): Response {
  return new Response(JSON.stringify({ error: status === 401 ? 'unauthorized' : 'credential_proxy', message, reason }), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
}

/** The message a signer signs, or a verifier checks, as the proxy takes it: base64url. */
function base64url(message: string | Uint8Array): string {
  if (typeof message !== 'string' && !(message instanceof Uint8Array)) throw new CoffreError(400, 'bad_request', 'a message is a string, signed as UTF-8, or a Uint8Array');
  const bytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Where a computation goes: the environment named, or the one the caller's binding is for. */
type Place = { place?: string };

/** The entrypoint's class, as `createCoffre(…).Workload` gives it: what the deployment exports, and its callers' binding types name. */
export type CoffreWorkload = ReturnType<typeof workloadEntrypoint>;

/**
 * The entrypoint, over `open`, which makes each call's coffre. The proxy
 * answers every call, as it answers a request to `/use`; only the caller's
 * authentication differs, from its binding rather than a proof (section
 * 9.2): no `hdr`, as nobody stands between the caller and coffre.
 */
export function workloadEntrypoint<Env>(open: OpenCall<Env>) {
  return class CoffreWorkload extends WorkerEntrypoint {
    /**
     * The credential proxy, for the caller's service: `env.COFFRE.fetch(new
     * Request('https://coffre/use/openai/v1/chat/completions', init))`. The
     * URL's host is ignored, as the binding is the route.
     */
    fetch(request: Request): Promise<Response> {
      return this.#call(request);
    }

    /** A signature by a signer's key, which never leaves coffre: `{ signature }`, base64url. */
    async sign(credential: string, message: string | Uint8Array, options: Place = {}): Promise<{ signature: string }> {
      return (await this.#compute(options.place, { sign: { credential, message: base64url(message) } })) as { signature: string };
    }

    /** Whether `signature` is a verifier's over `message`, compared in constant time: `{ valid }`. */
    async verify(credential: string, message: string | Uint8Array, signature: string, options: Place = {}): Promise<{ valid: boolean }> {
      return (await this.#compute(options.place, { verify: { credential, message: base64url(message), signature } })) as { valid: boolean };
    }

    /** A presigned URL for a GET or HEAD of `path` under a sigv4 credential: `{ url, expiresAt }`. */
    async presign(
      credential: string,
      path: string,
      options: Place & { method?: 'GET' | 'HEAD'; query?: Record<string, string>; expiresIn?: number } = {},
    ): Promise<{ url: string; expiresAt: string }> {
      const { place, ...rest } = options;
      return (await this.#compute(place, { presign: { credential, path, ...rest } })) as { url: string; expiresAt: string };
    }

    /** `POST /use/<project>/<env>`, or `/use` for the one environment the binding is for, through the proxy: its answer, or its refusal thrown. */
    async #compute(place: string | undefined, body: unknown): Promise<unknown> {
      if (place !== undefined && (typeof place !== 'string' || !/^[^/]+\/[^/]+$/.test(place))) throw new CoffreError(400, 'bad_request', 'place names an environment, <project>/<environment>');
      const path = place === undefined ? '/use' : `/use/${place.split('/').map(encodeURIComponent).join('/')}`;
      const response = await this.#call(new Request(`https://coffre${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }));
      const answered = (await response.json().catch(() => null)) as { error?: string; message?: string; reason?: string } | null;
      if (!response.ok) throw new CoffreError(response.status, answered?.error ?? 'error', answered?.message ?? response.statusText, answered?.reason);
      return answered;
    }

    /** One call: refused at once without props naming a service, else the proxy's answer on a database of the call's own. */
    #call(request: Request): Promise<Response> {
      const principal = propsService(this.ctx.props);
      if (principal === null) return Promise.resolve(refusal(401, NO_PROPS, 'props'));
      const { pathname, search } = new URL(request.url);
      // The proxy's paths only: the binding is no way into the API, sign-in or the pages.
      if (pathname !== '/use' && !pathname.startsWith('/use/')) return Promise.resolve(refusal(404, 'a Cloudflare binding reaches the credential proxy only, /use/…', 'not_found'));
      const { runtime, close } = open(this.env as Env, this.ctx);
      // On coffre's own URL, as a request to it comes: the host the caller wrote is any.
      const rebased = new Request(new URL(`${pathname}${search}`, new URL(runtime.publicUrl).origin), request);
      const answered = respond(rebased, runtime, null, async () => (await bindingRoute(rebased, runtime, principal)) ?? refusal(404, "this deployment has no credential proxy: its configuration's plugins name none", 'no_proxy'));
      close(answered);
      return answered;
    }
  };
}
