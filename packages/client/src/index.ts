/**
 * The coffre API as function calls, typed from the server's route table.
 *
 *   const coffre = createClient({ url: 'https://coffre.acme.example' });
 *   await coffre.secrets.set('market/prod', { DATABASE_URL: '…', OLD_KEY: null });
 *
 * Every call is one `fetch`. Pass a `transport` to send requests somewhere
 * else: the web app hands requests straight to its router, and the CLI adds
 * its own handling of Cloudflare Access redirects.
 */
import type {
  Params,
  RouteInput,
  RouteKey,
  RouteOutput,
} from '../../../apps/web/src/server/api/routes.ts';

export type { RouteInput, RouteKey, RouteOutput };

export type Transport = (request: Request) => Promise<Response>;

export type ClientOptions = {
  /** The instance's origin, e.g. `https://coffre.acme.example`. */
  url: string;
  /** Sent with every request: a bearer token, a Cloudflare Access header. */
  headers?: () => HeadersInit | Promise<HeadersInit>;
  transport?: Transport;
};

/** The API's error shape, `{ error, message }`, with the HTTP status. */
export class CoffreError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'CoffreError';
    this.status = status;
    this.code = code;
  }
}

type Args<K extends RouteKey> =
  RouteInput<K> extends undefined
    ? [params: Params<K>, input?: undefined]
    : Partial<RouteInput<K>> extends RouteInput<K>
      ? [params: Params<K>, input?: RouteInput<K>]
      : [params: Params<K>, input: RouteInput<K>];

/** `market/prod/KEY` as route parameters. */
function place(path: string): { project: string; environment: string; key: string } {
  const [project = '', environment = '', key = ''] = path.replace(/^\/+|\/+$/g, '').split('/');
  return { project, environment, key };
}

export function createClient(options: ClientOptions) {
  const origin = options.url.replace(/\/+$/, '');
  const transport = options.transport ?? ((request: Request) => fetch(request));

  /** Any route by its key: `call('GET /secrets/:project/:environment', { project, environment })`. */
  async function call<K extends RouteKey>(key: K, ...[params, input]: Args<K>): Promise<RouteOutput<K>> {
    const [method, pattern] = key.split(' ') as [string, string];
    const path = pattern.replace(/:(\w+)/g, (_, name: string) =>
      encodeURIComponent((params as Record<string, string>)[name]),
    );
    const url = new URL(`${origin}/api${path}`);
    const headers = new Headers(await options.headers?.());
    let body: string | undefined;
    if (method === 'GET') {
      for (const [name, value] of Object.entries(input ?? {})) {
        if (value !== undefined && value !== null) url.searchParams.set(name, String(value));
      }
    } else if (input !== undefined) {
      headers.set('content-type', 'application/json');
      body = JSON.stringify(input);
    }

    const response = await transport(new Request(url, { method, headers, body }));
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      const error = payload as { error?: unknown; message?: unknown } | null;
      throw new CoffreError(
        response.status,
        typeof error?.error === 'string' ? error.error : 'http_error',
        typeof error?.message === 'string' ? error.message : `request failed with status ${response.status}`,
      );
    }
    return payload as RouteOutput<K>;
  }

  return {
    call,

    /** Who I am, and every place I can reach. */
    me: () => call('GET /me', {}),

    projects: {
      /** With their environments. */
      list: () => call('GET /projects', {}),
      create: (project: string, input: RouteInput<'PUT /projects/:project'>) =>
        call('PUT /projects/:project', { project }, input),
      update: (project: string, patch: RouteInput<'PATCH /projects/:project'>) =>
        call('PATCH /projects/:project', { project }, patch),
    },

    environments: {
      create: (path: string, input: RouteInput<'PUT /projects/:project/:environment'>) =>
        call('PUT /projects/:project/:environment', place(path), input),
      update: (path: string, patch: RouteInput<'PATCH /projects/:project/:environment'>) =>
        call('PATCH /projects/:project/:environment', place(path), patch),
    },

    secrets: {
      /** Keys, versions and who changed what; never values. */
      list: (path: string) => call('GET /secrets/:project/:environment', place(path)),
      /** Decrypts one secret, or every secret in an environment. Logged in your name. */
      reveal: (path: string) => call('POST /reveals', {}, { path }),
      /** One transaction, a version and an audit entry per key; `null` archives. */
      set: (path: string, values: RouteInput<'PATCH /secrets/:project/:environment'>) =>
        call('PATCH /secrets/:project/:environment', place(path), values),
      history: (path: string) => call('GET /secrets/:project/:environment/:key/versions', place(path)),
      /** A new version holding the old one's value. */
      restore: (path: string, version: number) =>
        call('POST /secrets/:project/:environment/:key/restore', place(path), { version }),
      rename: (path: string, key: string) =>
        call('PATCH /secrets/:project/:environment/:key', place(path), { key }),
      update: (path: string, patch: RouteInput<'PATCH /secrets/:project/:environment/:key'>) =>
        call('PATCH /secrets/:project/:environment/:key', place(path), patch),
    },

    members: {
      /** People and tokens, their role and their access; at a place, those who reach it. */
      list: (path?: string) => call('GET /members', {}, { path }),
      /** What they hold, and what to rotate if they leave. */
      get: (member: string) => call('GET /members/:member', { member }),
      add: (member: string, input: RouteInput<'PUT /members/:member'> = {}) =>
        call('PUT /members/:member', { member }, input),
      /** Offboards; returns what to rotate. */
      remove: (member: string) => call('DELETE /members/:member', { member }),
    },

    tokens: {
      list: (member: string) => call('GET /members/:member/tokens', { member }),
      /** The value is in the answer, and only there. */
      issue: (member: string, input: RouteInput<'POST /members/:member/tokens'>) =>
        call('POST /members/:member/tokens', { member }, input),
      revoke: (member: string, id: string) => call('DELETE /members/:member/tokens/:id', { member, id }),
    },

    access: {
      /** What they should hold at each place; the server applies the difference. `null` revokes. */
      set: (member: string, access: RouteInput<'PATCH /access/:member'>) =>
        call('PATCH /access/:member', { member }, access),
    },

    syncs: {
      list: (path: string) => call('GET /syncs/:project/:environment', place(path)),
      add: (path: string, input: RouteInput<'POST /syncs/:project/:environment'>) =>
        call('POST /syncs/:project/:environment', place(path), input),
      update: (id: string, patch: RouteInput<'PATCH /syncs/by-id/:id'>) =>
        call('PATCH /syncs/by-id/:id', { id }, patch),
      remove: (id: string) => call('DELETE /syncs/by-id/:id', { id }),
      run: (id: string) => call('POST /syncs/by-id/:id/runs', { id }),
    },

    audit: {
      list: (query: RouteInput<'GET /audit'> = {}) => call('GET /audit', {}, query),
      verify: () => call('GET /audit/verification', {}),
    },
  };
}

export type CoffreClient = ReturnType<typeof createClient>;
