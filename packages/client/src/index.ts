/**
 * The coffre API as function calls, typed from the server's route table
 * (`api.ts`, generated from it).
 *
 *   const coffre = createClient({ url: 'https://coffre.acme.example' });
 *   await coffre.secrets.set('market/prod', { DATABASE_URL: '…', OLD_KEY: null });
 *
 * Every call is one `fetch`. Pass a `transport` to send requests somewhere
 * else: the web app hands requests straight to its router, and the CLI adds
 * its own handling of Cloudflare Access redirects.
 */
import type { Api, AuthInfo, BindingPlan, BindingView, DeletionResult, DryRunOutcome, DryRunResult, SetResult } from './api.ts';

export type {
  AccessValue,
  Api,
  AuditEntryView,
  AuthInfo,
  BindingPlan,
  BindingView,
  Deletion,
  DeletionResult,
  DryRunOutcome,
  DryRunResult,
  IdentityRow,
  InheritedGrant,
  InstanceState,
  ListedReference,
  Me,
  Member,
  OffboardingReport,
  ProjectSummary,
  ReferenceView,
  RemovedMember,
  SecretKey,
  SecretVersion,
  ServiceTokenRow,
  SessionRow,
  SetResult,
  WorkloadIds,
} from './api.ts';

export { byFolder, foldersOf } from './folders.ts';
export { apiMember, serviceName, shownMember, shownText } from './members.ts';

export type RouteKey = keyof Api;
/** What a caller sends: the body, or the query string for a GET. */
export type RouteInput<K extends RouteKey> = Api[K]['input'];
/** What comes back, as JSON. */
export type RouteOutput<K extends RouteKey> = Api[K]['output'];

type ParamNames<Pattern> = Pattern extends `${string}:${infer Name}/${infer Rest}`
  ? Name | ParamNames<`/${Rest}`>
  : Pattern extends `${string}:${infer Name}`
    ? Name
    : never;

/** `GET /members/:member` takes `{ member }`. */
export type Params<Key> = { [Name in ParamNames<Key>]: string };

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
  /** The vault's own code when it refused: `no_grant`, `removed`, `bulk_limit`, ... */
  readonly reason: string | undefined;

  constructor(status: number, code: string, message: string, reason?: string) {
    super(message);
    this.name = 'CoffreError';
    this.status = status;
    this.code = code;
    this.reason = reason;
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

  async function send(method: string, path: string, input: unknown): Promise<unknown> {
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
      const error = payload as { error?: unknown; message?: unknown; reason?: unknown } | null;
      throw new CoffreError(
        response.status,
        typeof error?.error === 'string' ? error.error : 'http_error',
        typeof error?.message === 'string' ? error.message : `request failed with status ${response.status}`,
        typeof error?.reason === 'string' ? error.reason : undefined,
      );
    }
    return payload;
  }

  /** A route key and its parameters as a method and a path. */
  function address<K extends RouteKey>(key: K, params: Params<K>): [method: string, path: string] {
    const [method, pattern] = key.split(' ') as [string, string];
    const path = pattern.replace(/:(\w+)/g, (_, name: string) =>
      encodeURIComponent((params as Record<string, string>)[name]),
    );
    return [method, path];
  }

  /** Any route by its key: `call('GET /secrets/:project/:environment', { project, environment })`. */
  async function call<K extends RouteKey>(key: K, ...[params, input]: Args<K>): Promise<RouteOutput<K>> {
    const [method, path] = address(key, params);
    return (await send(method, path, input)) as RouteOutput<K>;
  }

  return {
    call,

    /** How this instance signs people in. Answers anyone, signed in or not. */
    auth: () => send('GET', '/auth', undefined) as Promise<AuthInfo>,

    /** Who I am, and every place I can reach. */
    me: () => call('GET /me', {}),

    projects: {
      /** With their environments. */
      list: () => call('GET /projects', {}),
      create: (project: string, input: RouteInput<'PUT /projects/:project'>) =>
        call('PUT /projects/:project', { project }, input),
      update: (project: string, patch: RouteInput<'PATCH /projects/:project'>) =>
        call('PATCH /projects/:project', { project }, patch),
      /** What deleting an archived project would erase and revoke; changes nothing. */
      previewDelete: (project: string) => {
        const [method, route] = address('DELETE /projects/:project', { project });
        return send(method, `${route}?dryRun=1`, undefined) as Promise<DeletionResult>;
      },
      /** Delete an archived project for good: its values erased, its grants revoked, its slug free. Owners only. */
      delete: (project: string) => call('DELETE /projects/:project', { project }),
    },

    environments: {
      create: (path: string, input: RouteInput<'PUT /projects/:project/:environment'>) =>
        call('PUT /projects/:project/:environment', place(path), input),
      update: (path: string, patch: RouteInput<'PATCH /projects/:project/:environment'>) =>
        call('PATCH /projects/:project/:environment', place(path), patch),
      /** What deleting an archived environment would erase and revoke; changes nothing. */
      previewDelete: (path: string) => {
        const [method, route] = address('DELETE /projects/:project/:environment', place(path));
        return send(method, `${route}?dryRun=1`, undefined) as Promise<DeletionResult>;
      },
      /** Delete an archived environment for good, as a project is. Owners only. */
      delete: (path: string) => call('DELETE /projects/:project/:environment', place(path)),
    },

    secrets: {
      /** Keys, versions and who changed what; never values. */
      list: (path: string) => call('GET /secrets/:project/:environment', place(path)),
      /** Decrypts one secret, or every secret in an environment. Logged in your name. */
      reveal: (path: string) => call('POST /reveals', {}, { path }),
      /** One transaction, a version and an audit entry per key; `null` archives. */
      set: (path: string, values: RouteInput<'PATCH /secrets/:project/:environment'>) =>
        call('PATCH /secrets/:project/:environment', place(path), values) as Promise<SetResult>,
      /**
       * What `set` would do to each key, `added`, `changed`, `unchanged` or
       * `archived`, and nothing else: no value comes back and nothing is
       * written. Comparing opens the current values, logged as reads.
       */
      dryRun: (path: string, values: RouteInput<'PATCH /secrets/:project/:environment'>) => {
        const [method, route] = address('PATCH /secrets/:project/:environment', place(path));
        return send(method, `${route}?dryRun=1`, values) as Promise<DryRunResult>;
      },
      history: (path: string) => call('GET /secrets/:project/:environment/:key/versions', place(path)),
      /** A new version holding the old one's value. */
      restore: (path: string, version: number) =>
        call('POST /secrets/:project/:environment/:key/restore', place(path), { version }),
      rename: (path: string, key: string) =>
        call('PATCH /secrets/:project/:environment/:key', place(path), { key }),
      update: (path: string, patch: RouteInput<'PATCH /secrets/:project/:environment/:key'>) =>
        call('PATCH /secrets/:project/:environment/:key', place(path), patch),
    },

    /**
     * References: secrets read through others (docs/design/environments.md).
     * A key becomes one with `secrets.set(path, { KEY: { ref: 'market/prod/KEY' } })`.
     */
    references: {
      /** The live references into and out of a place, `market`, `market/prod` or `market/prod/KEY`, and who reads through them. */
      list: (path: string) => call('GET /references', {}, { path }),
      /** Break the reference a secret is: its readers stop reading the source through it. */
      break: (path: string) => call('DELETE /secrets/:project/:environment/:key/reference', place(path)),
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

    /** Trust bindings: which CI runs may sign in as a service, by their platform's ID token. */
    bindings: {
      list: (member: string) => call('GET /members/:member/bindings', { member }),
      /** The binding as it would be saved, the keys its issuer names, and what it replaces; writes nothing. */
      preview: (member: string, input: RouteInput<'POST /members/:member/bindings'>) => {
        const [method, route] = address('POST /members/:member/bindings', { member });
        return send(method, `${route}?dryRun=1`, input) as Promise<BindingPlan>;
      },
      create: (member: string, input: RouteInput<'POST /members/:member/bindings'>) =>
        call('POST /members/:member/bindings', { member }, input) as Promise<{ binding: BindingView; replaced: string[] }>,
      remove: (member: string, id: string) => call('DELETE /members/:member/bindings/:id', { member, id }),
      /** A public GitHub repository's or GitLab project's IDs, which bindings name. */
      lookup: (input: RouteInput<'GET /workloads/lookup'>) => call('GET /workloads/lookup', {}, input),
    },

    access: {
      /** What they should hold at each place; the server applies the difference. `null` revokes. */
      set: (member: string, access: RouteInput<'PATCH /access/:member'>) =>
        call('PATCH /access/:member', { member }, access),
    },

    /** Where I am signed in. Only where coffre runs its own sign-in. */
    sessions: {
      list: () => call('GET /sessions', {}),
      revoke: (id: string) => call('DELETE /sessions/:id', { id }),
    },

    /** The accounts I sign in with. */
    identities: {
      list: () => call('GET /identities', {}),
      unlink: (id: string) => call('DELETE /identities/:id', { id }),
    },

    /** A `coffre login` waiting for someone to approve it, by the code it shows. */
    deviceLogins: {
      get: (code: string) => call('GET /device-logins/:code', { code }),
      decide: (code: string, approve: boolean) => call('POST /device-logins/:code', { code }, { approve }),
    },

    audit: {
      list: (query: RouteInput<'GET /audit'> = {}) => call('GET /audit', {}, query),
      verify: () => call('GET /audit/verification', {}),
      /** What an escrowed key is checked against: public material, owners and root admins only. */
      keys: () => call('GET /audit/keys', {}),
    },
  };
}

export type CoffreClient = ReturnType<typeof createClient>;

export type ImportAction = Exclude<DryRunOutcome, 'archived'>;

/**
 * What writing these entries (a parsed `.env` file) would do, from a dry run
 * of the write: the server compares, so no value leaves it, and the values it
 * opens to compare are logged as reads. `changes` is what to pass to
 * `secrets.set`: the keys that differ, so an unchanged value does not become
 * a new version.
 */
export async function planImport(
  coffre: CoffreClient,
  path: string,
  entries: readonly { key: string; value: string }[],
): Promise<{
  plan: { key: string; action: ImportAction; version: number | null }[];
  changes: Record<string, string>;
}> {
  // Null-prototype records: a key named __proto__ is a key like any other.
  const values: Record<string, string> = Object.create(null);
  for (const { key, value } of entries) values[key] = value;
  // Settle both before throwing, so a refusal leaves no call still in flight.
  const [listed, compared] = await Promise.allSettled([
    coffre.secrets.list(path),
    coffre.secrets.dryRun(path, { ...values }),
  ]);
  if (listed.status === 'rejected') throw listed.reason;
  if (compared.status === 'rejected') throw compared.reason;
  const [{ keys }, dryRun] = [listed.value, compared.value];
  const versions = new Map(keys.map((entry) => [entry.key, entry.version]));
  const plan: { key: string; action: ImportAction; version: number | null }[] = [];
  const changes: Record<string, string> = Object.create(null);
  for (const [key, value] of Object.entries(values)) {
    // A patch without nulls archives nothing, so every outcome is one of these.
    const action = dryRun.keys[key] as ImportAction;
    plan.push({ key, action, version: versions.get(key) ?? null });
    if (action !== 'unchanged') changes[key] = value;
  }
  return { plan, changes: { ...changes } };
}
