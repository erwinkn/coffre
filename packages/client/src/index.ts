/**
 * The coffre API as function calls, typed from the server's route table
 * (`api.ts`, generated from it).
 *
 *   const coffre = createClient({ url: 'https://coffre.acme.example' });
 *   await coffre.secrets.set('market/prod', { DATABASE_URL: '…', OLD_KEY: null });
 *
 * Every call is one `fetch`. Pass a `transport` to send requests somewhere
 * else: the web app hands requests straight to its router, and the CLI adds
 * its own handling of Cloudflare Access redirects. A request that never
 * reaches the instance throws `Unreachable`, which says why.
 */
import type { Api, AuthInfo, BindingPlan, BindingView, DeletionResult, DryRunOutcome, DryRunResult, InheritResult, KeysPlan, RoleImpact, SetResult, TokenPlan } from './api.ts';
import { Unreachable } from './reach.ts';

export type {
  AccessValue,
  Api,
  ApprovalView,
  AuditEntryView,
  AuthInfo,
  AuthorizationView,
  BindingPlan,
  BindingView,
  ConnectedApp,
  Decision,
  Deletion,
  DeletionResult,
  DismissedKey,
  DryRunOutcome,
  DryRunResult,
  EnvironmentView,
  IdentityRow,
  ImpactLine,
  InheritResult,
  KeysPlan,
  ListedReference,
  Me,
  Member,
  MemberAccess,
  MissingKey,
  OffboardingReport,
  PersonalConfig,
  ProjectSummary,
  ReferenceView,
  RemovedMember,
  RoleImpact,
  RolesView,
  RoleView,
  SecretKey,
  SecretVersion,
  SessionRow,
  SetResult,
  TokenPlan,
  TokenRow,
  WorkloadIds,
} from './api.ts';

export { ageInDays, olderThan } from './age.ts';
export { byFolder, foldersOf } from './folders.ts';
export { apiMember, serviceName, shownMember } from './members.ts';
export { unreachable, Unreachable } from './reach.ts';

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
  /** When to ask again, in seconds, when the answer says (`Retry-After`): a 503's, a 429's. */
  readonly retryAfter: string | undefined;

  constructor(status: number, code: string, message: string, reason?: string, retryAfter?: string) {
    super(message);
    this.name = 'CoffreError';
    this.status = status;
    this.code = code;
    this.reason = reason;
    this.retryAfter = retryAfter;
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

/** A role's change confirmed: an instance role's, and the `revision` of the policy its preview answered with. */
type Confirmed = { instance?: boolean; revision?: string };

/** `?revision=57.3f9a0c2e81b4d7a6`, or nothing for a change asked without its preview. */
function asPreviewed(revision: string | undefined): string {
  return revision === undefined ? '' : `?revision=${encodeURIComponent(revision)}`;
}

export function createClient(options: ClientOptions) {
  const origin = options.url.replace(/\/+$/, '');
  const transport =
    options.transport ??
    (async (request: Request) => {
      try {
        return await fetch(request);
      } catch (error) {
        throw new Unreachable(origin, error);
      }
    });

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
        response.headers.get('retry-after') ?? undefined,
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

  /** 0.15's log checked; a server older than 0.15 has no such route, and keeps 0.14's log alone (`kept` false). */
  const verifyTrees = (query: RouteInput<'GET /audit/trees'> = {}): Promise<RouteOutput<'GET /audit/trees'>> =>
    call('GET /audit/trees', {}, query).catch((error: unknown) => {
      if (error instanceof CoffreError && error.status === 404) return { kept: false as const };
      throw error;
    });

  return {
    call,

    /** How this instance signs people in. Answers anyone, signed in or not. */
    auth: () => send('GET', '/auth', undefined) as Promise<AuthInfo>,

    /** Who I am, and every place I can reach. */
    me: () => call('GET /me', {}),

    projects: {
      /** With their environments. */
      list: () => call('GET /projects', {}),
      /** Its `name`, which releases before 0.6.2 show, defaults to the slug. */
      create: (project: string, input: RouteInput<'PUT /projects/:project'> = {}) =>
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
      /** As a project's: its `name` defaults to the slug. `from` forks a sibling. */
      create: (path: string, input: RouteInput<'PUT /projects/:project/:environment'> = {}) =>
        call('PUT /projects/:project/:environment', place(path), input),
      update: (path: string, patch: RouteInput<'PATCH /projects/:project/:environment'>) =>
        call('PATCH /projects/:project/:environment', place(path), patch),
      /**
       * Protected, a person holds their role's protected column there
       * (docs/design/roles.md); whoever manages the project's environments
       * protects one, and only an Owner of its project, or of the whole instance, unprotects it.
       */
      protect: (path: string, on = true) => call('PATCH /projects/:project/:environment', place(path), { protected: on }),
      /** What deleting an archived environment would erase and revoke; changes nothing. */
      previewDelete: (path: string) => {
        const [method, route] = address('DELETE /projects/:project/:environment', place(path));
        return send(method, `${route}?dryRun=1`, undefined) as Promise<DeletionResult>;
      },
      /** Delete an archived environment for good, as a project is. Owners only. */
      delete: (path: string) => call('DELETE /projects/:project/:environment', place(path)),
      /** The keys its sibling environments have and it lacks, read or not, and those its team dismissed. */
      missing: (path: string) => call('GET /projects/:project/:environment/missing', place(path)),
      /** A project's personal configs, for whoever manages its environments: whose, of what, and their key names. */
      personal: (project: string) => call('GET /personal/:project', place(project)),
      /**
       * A version of what reading it would open: it changes whenever a read
       * would, and reads no value, so it is not logged. Poll it, and read
       * only when it changed.
       */
      version: (path: string) => call('GET /projects/:project/:environment/version', place(path)),
      /** Dismiss missing keys (`true`) or restore them (`null`). */
      dismiss: (path: string, patch: RouteInput<'PATCH /projects/:project/:environment/dismissals'>) =>
        call('PATCH /projects/:project/:environment/dismissals', place(path), patch),
    },

    secrets: {
      /** Keys, versions and who changed what; never values. */
      list: (path: string) => call('GET /secrets/:project/:environment', place(path)),
      /** Decrypts one secret, or every secret in an environment, or, `keys` named, those of it only. Logged in your name. */
      reveal: (path: string, keys?: string[]) => call('POST /reveals', {}, keys === undefined ? { path } : { path, keys }),
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
      /**
       * In a fork, a key back to its parent's value (`true`), its own kept,
       * or its own served again (`false`); `from` holds the parent's.
       */
      inherit: (path: string, inherit: boolean) =>
        call('PATCH /secrets/:project/:environment/:key', place(path), { inherit }) as Promise<InheritResult>,
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
      /** Their instance role and scope, and the grants you manage, in one read. */
      access: (member: string) => call('GET /members/:member/access', { member }),
      add: (member: string, input: RouteInput<'PUT /members/:member'> = {}) =>
        call('PUT /members/:member', { member }, input),
      /** Offboards; returns what to rotate. */
      remove: (member: string) => call('DELETE /members/:member', { member }),
    },

    /**
     * A member's tokens: a service account's bearer tokens, or a person's
     * personal tokens (`user:<email>`), which act as them within their scope.
     */
    tokens: {
      list: (member: string) => call('GET /members/:member/tokens', { member }),
      /** What the token would reach, as the server would issue it now; issues nothing. */
      preview: (member: string, input: RouteInput<'POST /members/:member/tokens'>) => {
        const [method, route] = address('POST /members/:member/tokens', { member });
        return send(method, `${route}?dryRun=1`, input) as Promise<TokenPlan>;
      },
      /** The value is in the answer, and only there. */
      issue: (member: string, input: RouteInput<'POST /members/:member/tokens'>) =>
        call('POST /members/:member/tokens', { member }, input) as Promise<Extract<RouteOutput<'POST /members/:member/tokens'>, { token: string }>>,
      revoke: (member: string, id: string) => call('DELETE /members/:member/tokens/:id', { member, id }),
    },

    /**
     * Handles: placeholders a person's app holds in place of an environment's
     * values, which only the credential proxy (`/use`) takes. The value is
     * in the answer, and only there; it is revoked as a token is.
     */
    handles: {
      create: (input: RouteInput<'POST /handles'>) => call('POST /handles', {}, input),
      /** Ends a handle of the caller's own, as `coffre run` does once its command ends. */
      revoke: (id: string) => call('DELETE /handles/:id', { id }),
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
      /** The service's bindings on an issuer that new keys would replace, and the keys as checked; writes nothing. */
      previewKeys: (member: string, input: RouteInput<'POST /members/:member/bindings/keys'>) => {
        const [method, route] = address('POST /members/:member/bindings/keys', { member });
        return send(method, `${route}?dryRun=1`, input) as Promise<KeysPlan>;
      },
      /** New keys, uploaded, for every binding of the service on the issuer: each replaced by one the same but for them. */
      replaceKeys: (member: string, input: RouteInput<'POST /members/:member/bindings/keys'>) =>
        call('POST /members/:member/bindings/keys', { member }, input) as Promise<{ bindings: BindingView[]; replaced: string[] }>,
      remove: (member: string, id: string) => call('DELETE /members/:member/bindings/:id', { member, id }),
      /** A GitHub repository's or GitLab project's IDs, which bindings name: a public one's, or one the deployment's GitHub App is installed on. */
      lookup: (input: RouteInput<'GET /workloads/lookup'>) => call('GET /workloads/lookup', {}, input),
      /** The repositories the deployment's GitHub App is installed on, private ones too; `{ app: null }` without one. */
      repositories: () => call('GET /workloads/repositories', {}),
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

    /**
     * Folders, which arrange lists and do nothing else: a folder exists while
     * something is filed in it. Renaming one re-files all of it, onto a folder
     * that exists merges the two; removing one takes all of it out, each item
     * staying where it is, in no folder. Moving one item is `projects.update`
     * or `secrets.update` with a `folder`.
     */
    folders: {
      /** A folder of projects, renamed. Takes managing every project in it. */
      rename: (folder: string, name: string) => call('PATCH /folders/:folder', { folder }, { name }),
      /** Every project out of a folder. */
      remove: (folder: string) => call('DELETE /folders/:folder', { folder }),
      /** One of an environment's key folders, `market/prod`, renamed. Takes writing there. */
      renameKeys: (environment: string, folder: string, name: string) => {
        const { project, environment: slug } = place(environment);
        return call('PATCH /folders/:project/:environment/:folder', { project, environment: slug, folder }, { name });
      },
      /** Every key out of one of an environment's folders. */
      removeKeys: (environment: string, folder: string) => {
        const { project, environment: slug } = place(environment);
        return call('DELETE /folders/:project/:environment/:folder', { project, environment: slug, folder });
      },
    },

    /**
     * An MCP client asking to connect, by its authorization request, and the
     * person's answer: where to send the browser next.
     */
    oauth: {
      describe: (request: RouteInput<'GET /oauth/authorizations'>) => call('GET /oauth/authorizations', {}, request),
      decide: (input: RouteInput<'POST /oauth/authorizations'>) => call('POST /oauth/authorizations', {}, input),
    },

    /** The MCP clients I connected. */
    /** A change an MCP client asked for: what it would do, and the person's decision, which makes it. */
    approvals: {
      get: (id: string) => call('GET /approvals/:id', { id }),
      decide: (id: string, input: RouteInput<'POST /approvals/:id'>) => call('POST /approvals/:id', { id }, input),
    },

    apps: {
      list: () => call('GET /apps', {}),
      disconnect: (id: string) => call('DELETE /apps/:id', { id }),
    },

    /**
     * The instance's roles, in two columns, an environment's that is not
     * protected and one's that is (docs/design/roles.md). Any member lists
     * them; an Owner of the whole instance edits them. `instance` is about
     * instance roles, a person's across every project in their scope.
     */
    roles: {
      list: () => call('GET /roles', {}),
      /** What defining the role so would do to everyone it reaches; changes nothing. */
      preview: (role: string, definition: RouteInput<'PUT /roles/:role'>, { instance = false } = {}) => {
        const [method, route] = instance ? address('PUT /instance-roles/:role', { role }) : address('PUT /roles/:role', { role });
        return send(method, `${route}?dryRun=1`, definition) as Promise<RoleImpact>;
      },
      /**
       * A built-in role edited, or one an Owner makes. With its preview's
       * `revision`, made as previewed, or refused (409 `policy_changed`)
       * if the policy changed since: preview it again.
       */
      set: (role: string, definition: RouteInput<'PUT /roles/:role'>, { instance = false, revision }: Confirmed = {}) => {
        const [method, route] = instance ? address('PUT /instance-roles/:role', { role }) : address('PUT /roles/:role', { role });
        return send(method, `${route}${asPreviewed(revision)}`, definition) as Promise<{ role: RouteOutput<'GET /roles'>['roles'][number] | null }>;
      },
      /** What putting it back as it ships, or deleting one an Owner made, would do; changes nothing. */
      previewReset: (role: string, { instance = false } = {}) => {
        const [method, route] = instance ? address('DELETE /instance-roles/:role', { role }) : address('DELETE /roles/:role', { role });
        return send(method, `${route}?dryRun=1`, undefined) as Promise<RoleImpact>;
      },
      /** A built-in role back as it ships; one an Owner made, deleted, while no grant names it. With its preview's `revision`, as `set`. */
      reset: (role: string, { instance = false, revision }: Confirmed = {}) => {
        const [method, route] = instance ? address('DELETE /instance-roles/:role', { role }) : address('DELETE /roles/:role', { role });
        return send(method, `${route}${asPreviewed(revision)}`, undefined) as Promise<{ role: RouteOutput<'GET /roles'>['roles'][number] | null }>;
      },
    },

    /** The instance's settings, for those who run it: where people set up service accounts themselves. */
    settings: {
      get: () => call('GET /settings', {}),
      set: (input: RouteInput<'PUT /settings'>) => call('PUT /settings', {}, input),
    },

    audit: {
      list: (query: RouteInput<'GET /audit'> = {}) => call('GET /audit', {}, query),
      /**
       * Whether the log holds, from the newest checkpoint; or, with `from`, a
       * stretch of the walk from the first entry: `start`, then each `next`
       * until it is null (`verifyWhole`).
       */
      verify: (query: RouteInput<'GET /audit/verification'> = {}) => call('GET /audit/verification', {}, query),
      /**
       * The walk from the first entry to the head, a stretch a request, each
       * as long as the server walks in one: the first stretch that fails, or
       * the last. `onStretch` sees each verdict as it comes.
       */
      verifyWhole: async (onStretch: (verdict: RouteOutput<'GET /audit/verification'>) => void = () => {}) => {
        for (let from = 'start'; ;) {
          const verdict: RouteOutput<'GET /audit/verification'> = await call('GET /audit/verification', {}, { from });
          onStretch(verdict);
          if (!verdict.ok || verdict.next === undefined || verdict.next === null) return verdict;
          from = verdict.next;
        }
      },
      /**
       * Whether 0.15's log holds (the vault's `verifyTrees`): a page's check,
       * the newest signed checkpoint and every entry since; or, with `whole`,
       * the walk from the first entry, its trees, every entry, the replay and
       * every row, in one request. `kept` false where the instance keeps
       * 0.14's log alone.
       */
      verifyTrees: (options: { whole?: boolean } = {}) => verifyTrees(options.whole === true ? { whole: '1' } : {}),
      /** What an escrowed key is checked against: public material, for admins and owners of the whole instance. */
      keys: () => call('GET /audit/keys', {}),
      /**
       * Accept that entries `from` to `to` are lost for good, as an Owner of
       * the whole instance: the audit watch's finding, inside the range, stays
       * in the log, and its anchor goes on past them.
       */
      acceptLoss: (range: RouteInput<'POST /audit/loss'>) => call('POST /audit/loss', {}, range),
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
