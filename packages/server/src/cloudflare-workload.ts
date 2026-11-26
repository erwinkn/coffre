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
// as well deploy coffre itself.
//
// Its RPC methods, `env.COFFRE.sign(…)`, `verify(…)` and `presign(…)`, are
// the same operations as `POST /use/<project>/<env>` with `{ sign: … }`:
// each builds that request and sends it through `fetch`'s own route, so the
// proxy decides, refuses and logs them as it does over HTTP, and answers
// what the operation makes, never a value. A refusal is thrown as a
// `CoffreError` with the status, code and reason the HTTP form answers.
import { CoffreError } from '@coffre/client';
import { slug } from '@coffre/core/schemas';
import { JSON_MESSAGE_BYTES } from '@coffre/client/dpop';
import type { CoffreBinding, PresignOptions } from '@coffre/client/workload';
import { WorkerEntrypoint } from 'cloudflare:workers';

import { migrating, schemaReady } from './app.ts';
import { errorResponse } from './http.ts';
import { bindingRoute, operation } from './plugins.ts';
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

/** The entrypoint's class, as the deployment exports it: workerd makes one for each call over a binding, with its `ctx` and `env`. */
export type WorkloadEntrypoint<Env> = new (ctx: BoundContext, env: Env) => Omit<CoffreBinding, 'fetch'> & { fetch(request: Request): Promise<Response> };

/** What a call over the binding is given to run on: its runtime, and `end`, which closes its database client. */
type Open<Env> = (env: Env) => { runtime: CoffreRuntime; end(): Promise<void> };

/**
 * The entrypoint, over the runtime `open` makes for each call: its database
 * client, which `end` closes once the answer and the work it left are done.
 * Its public methods are what a bound Worker may call: every one on the
 * prototype is callable over RPC, so what they share is private or the
 * module's.
 */
export function workloadEntrypoint<Env>(open: Open<Env>): WorkloadEntrypoint<Env> {
  return class CoffreWorkload extends WorkerEntrypoint<Env> implements Omit<CoffreBinding, 'fetch'> {
    fetch(request: Request): Promise<Response> {
      return served(request, this.env, this.ctx, open);
    }

    async sign(signer: string, message: string | Uint8Array, options: { place?: string } = {}): Promise<string> {
      const bytes = bytesOf(message, 'sign');
      // Past what JSON takes, raw, as the SDK sends it: an hmac() signer's whose maxBytes takes it, signed as it comes.
      const made = bytes.byteLength > JSON_MESSAGE_BYTES
        ? await this.#made(placed(options), { 'content-type': 'application/octet-stream', 'content-length': String(bytes.byteLength) }, bytes, `?sign=${encodeURIComponent(named(signer, 'sign'))}`)
        : await this.#made(placed(options), JSON_HEADERS, JSON.stringify({ sign: { credential: named(signer, 'sign'), message: base64url(bytes) } }));
      if (typeof made.signature !== 'string') throw new Error('coffre signed nothing');
      return made.signature;
    }

    async verify(verifier: string, message: string | Uint8Array, signature: string, options: { place?: string } = {}): Promise<boolean> {
      if (typeof signature !== 'string') throw argument('verify takes the signature as a string, as its header carried it');
      const asked = { verify: { credential: named(verifier, 'verify'), message: base64url(bytesOf(message, 'verify')), signature } };
      const made = await this.#made(placed(options), JSON_HEADERS, JSON.stringify(asked));
      if (typeof made.valid !== 'boolean') throw new Error('coffre verified nothing');
      return made.valid;
    }

    async presign(credential: string, path: string, options: PresignOptions & { place?: string } = {}): Promise<{ url: string; expiresAt: string }> {
      if (typeof path !== 'string') throw argument('presign takes the path under the credential as a string, /bucket/key');
      const { expiresIn, method, query } = plain(options, 'presign') as PresignOptions;
      if (expiresIn !== undefined && !Number.isFinite(expiresIn)) throw argument('presign takes expiresIn as a number of seconds');
      if (method !== undefined && typeof method !== 'string') throw argument('presign takes method as a string, GET or HEAD');
      if (query !== undefined && Object.values(plain(query, 'presign\'s query')).some((value) => typeof value !== 'string')) throw argument('presign takes query as an object of strings');
      // The operation checks the rest, as over HTTP: the method, how long, the path under the credential.
      const asked = { presign: { credential: named(credential, 'presign'), path, ...(method === undefined ? {} : { method }), ...(expiresIn === undefined ? {} : { expiresIn }), ...(query === undefined ? {} : { query }) } };
      const made = await this.#made(placed(options), JSON_HEADERS, JSON.stringify(asked));
      if (typeof made.url !== 'string' || typeof made.expiresAt !== 'string') throw new Error('coffre presigned nothing');
      return { url: made.url, expiresAt: made.expiresAt };
    }

    /**
     * What the operation made, `POST /use[/<project>/<env>]<query>` with
     * `body` through `fetch`'s route: its JSON answer, or its refusal
     * thrown as the `CoffreError` its status and body say.
     */
    async #made(place: string, headers: Record<string, string>, body: string | Uint8Array<ArrayBuffer>, query = ''): Promise<Record<string, unknown>> {
      // An operation's, whose path is a place even where its project shares a credential's name (`operation`).
      const request = operation(new Request(`https://coffre/use${place}${query}`, { method: 'POST', headers: { ...headers, accept: 'application/json' }, body }));
      const response = await served(request, this.env, this.ctx, open);
      const answer = (await response.json().catch(() => null)) as Record<string, unknown> | null;
      if (response.ok && typeof answer === 'object' && answer !== null) return answer;
      const said = (key: string) => (typeof answer?.[key] === 'string' ? (answer[key] as string) : undefined);
      throw new CoffreError(response.ok ? 502 : response.status, said('error') ?? 'refused', said('message') ?? `coffre answered ${response.status}`, said('reason'));
    }
  };
}

/** A call over the binding, by `fetch` or by a method: the service its props name, then the plugin whose route takes the path. */
async function served<Env>(request: Request, env: Env, ctx: BoundContext, open: Open<Env>): Promise<Response> {
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
    // A plugin's refusal, a `CoffreError` by contract (`PluginContext`), is the refusal it says, not a fault.
    if (error instanceof CoffreError) return Response.json({ error: error.code, reason: error.reason ?? error.code, message: error.message }, { status: error.status, headers: { 'coffre-proxy': 'refused' } });
    return errorResponse(error);
  } finally {
    // The upstream's body streams after this; nothing of it reads the database, which goes once the work left is done.
    ctx.waitUntil((async () => {
      while (left.length > 0) await Promise.allSettled(left.splice(0));
      await end();
    })());
  }
}

const JSON_HEADERS = { 'content-type': 'application/json' };

/** A bound Worker's argument coffre cannot take: refused as the HTTP form refuses a body it cannot read. */
const argument = (message: string) => new CoffreError(400, 'bad_request', message);

/** The URL path a call's `place` names, `/<project>/<env>`, or none, for the one the service's bindings name. */
function placed(options: unknown): string {
  const { place } = plain(options, 'a call') as { place?: unknown };
  if (place === undefined) return '';
  // Two slugs, never `.` or `..`, which the URL would resolve out of the place it names.
  const [project, environment, ...more] = typeof place === 'string' ? place.split('/') : [];
  if (!slug.safeParse(project).success || !slug.safeParse(environment).success || more.length > 0) throw argument('place names an environment as project/environment, market/prod');
  return `/${project}/${environment}`;
}

/** The signer, verifier or credential a call names, as a string. */
function named(name: unknown, what: string): string {
  if (typeof name !== 'string') throw argument(`${what} names its ${what === 'presign' ? 'credential' : what === 'sign' ? 'signer' : 'verifier'} as a string`);
  return name;
}

/** An options object as RPC carried it: a plain object, never a stub of the caller's that would answer each read. */
function plain(value: unknown, what: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Object.getPrototypeOf(value) !== Object.prototype) throw argument(`${what} takes its options as a plain object`);
  return value as Record<string, unknown>;
}

/** A message's bytes: a string's UTF-8, as the SDK sends it, or the bytes given. */
function bytesOf(message: unknown, what: string): Uint8Array<ArrayBuffer> {
  if (typeof message === 'string') return new TextEncoder().encode(message);
  if (message instanceof Uint8Array) return new Uint8Array(message);
  throw argument(`${what} takes the message as a string or a Uint8Array`);
}

const base64url = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
