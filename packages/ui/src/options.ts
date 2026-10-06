// coffre's routes, as route options: what each layout and page does, its
// loader, search and redirects, but not where it goes. A deployment mounts
// them, as Start's file routes,
//
//   // src/routes/_coffre.tsx
//   export const Route = createFileRoute('/_coffre')({ ...shell });
//
//   // src/routes/_coffre/projects.index.tsx
//   import { ProjectsPage } from '@coffre/ui/pages/projects';
//   export const Route = createFileRoute('/_coffre/projects/')({ ...projects, component: ProjectsPage });
//
// or in code, with TanStack's own `createRoute({ getParentRoute, path,
// ...projects, component: ProjectsPage })`. A layout's options hold its
// component. A page's do not: the route file names it, from its own module,
// so that Start's splitter puts each page in a chunk of its own, with its
// preload hints. Each page goes at the path coffre's links name; one at
// another path is one the links do not reach.
import { redirect, type ParsedLocation } from '@tanstack/react-router';
import type { QueryClient } from '@tanstack/react-query';
import type { CoffreClient, RouteInput } from '@coffre/client';

import { ShellLayout, SoloLayout } from './layout';
import { memberRef, uiResult } from './lib/coffre';
import { stringsOf } from './lib/search';
import {
  loadAccess,
  loadDirectory,
  loadMember,
  loadProject,
  loadServiceDirectory,
  loadSettings,
  loadShell,
  projectOf,
  queries,
  signInWays,
  type AuditSearch,
} from './lib/queries';
import type { Permission } from './shared/models';
import { loginSearch } from './lib/signin-errors';

/**
 * What coffre's routes read through the router: the API as the visitor
 * (`coffre`), and the query cache the pages share. The deployment's root is
 * created with it, `createRootRouteWithContext<CoffreContext>()`, and
 * coffre's `createRouter` provides it.
 */
export type CoffreContext = { coffre: CoffreClient; queryClient: QueryClient };

/**
 * coffre's context, as a route's loader reads it. The options take any
 * parent, whose context the types cannot follow; the root's is coffre's.
 */
const coffreOf = (context: unknown) => context as CoffreContext;

type Loader<TParams = object> = { context: unknown; params: TParams; location: ParsedLocation };

// --- the layouts ------------------------------------------------------------------------

/** coffre's nav, around the signed-in pages: someone not signed in, or not yet registered, is sent to the page for it. */
export const shell = {
  loader: async ({ context, location }: Loader) => {
    const { coffre, queryClient } = coffreOf(context);
    const shell = await loadShell(queryClient, coffre);
    if (shell.registrationRequired) throw redirect({ to: '/unregistered' });
    if (shell.principal === null) throw redirect({ to: '/login', search: { next: location.href } });
  },
  component: ShellLayout,
};

/** The bare frame of the sign-in pages. Each sends on whoever does not belong there. */
export const solo = { component: SoloLayout };

// --- under the shell ------------------------------------------------------------------

/** `/`, which sends to the projects. */
export const home = {
  beforeLoad: () => {
    throw redirect({ to: '/projects' });
  },
};

/** `/projects`. */
export const projects = {
  loader: ({ context }: Loader) => {
    const { coffre, queryClient } = coffreOf(context);
    return queryClient.fetchQuery(queries.projects(coffre));
  },
};

/**
 * `/projects/$project`, the layout of a project's tabs: its header, and the
 * tabs its visitor may open. Each tab is a page under it that reads its own.
 */
export const project = {
  loader: ({ context }: Loader<{ project: string }>) => {
    const { coffre, queryClient } = coffreOf(context);
    return queryClient.fetchQuery(queries.projects(coffre));
  },
};

/** `/projects/$project/`, its environments, and who can open each when you manage its access. */
export const projectEnvironments = {
  loader: ({ context, params }: Loader<{ project: string }>) => {
    const { coffre, queryClient } = coffreOf(context);
    return loadProject(queryClient, coffre, params.project);
  },
};

/** `/projects/$project/users`: who holds access, and what others read of it through references. */
export const projectUsers = {
  loader: async ({ context, params }: Loader<{ project: string }>) => {
    const { coffre, queryClient } = coffreOf(context);
    if (!(await projectTab(context, params.project, 'grant.manage'))) return;
    await Promise.all([
      queryClient.fetchQuery(queries.grants(coffre, params.project)),
      queryClient.fetchQuery(queries.references(coffre, params.project)),
    ]);
  },
};

/** `/projects/$project/service-accounts`. */
export const projectServiceAccounts = {
  loader: async ({ context, params }: Loader<{ project: string }>) => {
    const { coffre, queryClient } = coffreOf(context);
    if (await projectTab(context, params.project, 'grant.manage')) await queryClient.fetchQuery(queries.grants(coffre, params.project));
  },
};

/** `/projects/$project/settings`: the project itself, which its layout read. */
export const projectSettings = {
  loader: async ({ context, params }: Loader<{ project: string }>) => {
    await projectTab(context, params.project, 'project.manage');
  },
};

/**
 * Whether a project's tab reads anything: not for a project its visitor
 * cannot see, whose layout shows a closed door instead; and a tab they may
 * not open sends them to the first, so a link someone shared still lands
 * somewhere useful.
 */
async function projectTab(context: unknown, slug: string, permission: Permission): Promise<boolean> {
  const { coffre, queryClient } = coffreOf(context);
  const found = projectOf(await queryClient.fetchQuery(queries.projects(coffre)), slug);
  if (!found.ok) return false;
  if (!found.project.permissions.includes(permission)) throw redirect({ to: '/projects/$project', params: { project: slug } });
  return true;
}

/** `/projects/$project/$environment`. */
export const environment = {
  // `?filter=KEY` opens the ledger narrowed to matching keys, for links to one secret.
  validateSearch: (search: Record<string, unknown>): { filter?: string } => ({
    filter: typeof search.filter === 'string' && search.filter !== '' ? search.filter : undefined,
  }),
  loader: async ({ context, params }: Loader<{ project: string; environment: string }>) => {
    const { coffre, queryClient } = coffreOf(context);
    const secrets = await queryClient.fetchQuery(queries.secrets(coffre, params));
    // Then, for whoever reads it, the references that read its secrets from
    // elsewhere and the keys it lacks, rendered with them. Asked only then,
    // so a refused visit is one refusal in the log, not three.
    if (secrets.ok) {
      await Promise.all([
        queryClient.fetchQuery(queries.references(coffre, `${params.project}/${params.environment}`)),
        queryClient.fetchQuery(queries.missing(coffre, params)),
      ]);
    }
    return secrets;
  },
};

/** `/audit`. */
export const audit = {
  // Filters live in the URL so a finding can cite the exact view it came from.
  validateSearch: (search: Record<string, unknown>): AuditSearch => ({
    decision: search.decision === 'deny' ? 'deny' : undefined,
    actorId: typeof search.actorId === 'string' && search.actorId !== '' ? search.actorId : undefined,
    detail: search.detail === '1' ? '1' : undefined,
  }),
  loaderDeps: ({ search }: { search: AuditSearch }) => search,
  // The entries only: the verification is asked for once the page is up
  // (`ChainStatus`), so the table never waits on it.
  loader: ({ context, deps }: Loader & { deps: AuditSearch }) => {
    const { coffre, queryClient } = coffreOf(context);
    return queryClient.fetchQuery(queries.auditEntries(coffre, deps));
  },
};

/** `/users`. */
export const users = {
  loader: ({ context }: Loader) => {
    const { coffre, queryClient } = coffreOf(context);
    return loadDirectory(queryClient, coffre);
  },
};

/** `/users/$user`, the layout of a user's tabs: who they are to the instance, for owners. */
export const user = {
  loader: ({ context, params }: Loader<{ user: string }>) => {
    const { coffre, queryClient } = coffreOf(context);
    return loadMember(queryClient, coffre, memberRef('user', params.user));
  },
};

/** `/users/$user/`, their access on every project where you manage it. */
export const userAccess = {
  loader: ({ context }: Loader) => {
    const { coffre, queryClient } = coffreOf(context);
    return loadAccess(queryClient, coffre);
  },
};

/** `/users/$user/activity`, for whoever reads the audit log; the others are sent to the first tab. */
export const userActivity = {
  loader: async ({ context, params }: Loader<{ user: string }>) => {
    const { coffre, queryClient } = coffreOf(context);
    const shell = await loadShell(queryClient, coffre);
    if (!shell.capabilities.canReadAudit) throw redirect({ to: '/users/$user', params });
  },
};

/** `/service-accounts`. */
export const serviceAccounts = {
  loader: ({ context }: Loader) => {
    const { coffre, queryClient } = coffreOf(context);
    return loadServiceDirectory(queryClient, coffre);
  },
};

/** `/service-accounts/$account`, the layout of a service account's tabs: who it is to the instance, for owners. */
export const serviceAccount = {
  loader: ({ context, params }: Loader<{ account: string }>) => {
    const { coffre, queryClient } = coffreOf(context);
    return loadMember(queryClient, coffre, memberRef('service', params.account));
  },
};

/**
 * `/service-accounts/$account/`, how it signs in: its trusted workloads and
 * bearer tokens. Only an owner manages them, and only while it is active;
 * anyone else is sent to its access.
 */
export const serviceAccountSignIn = {
  loader: async ({ context, params }: Loader<{ account: string }>) => {
    const { coffre, queryClient } = coffreOf(context);
    const member = memberRef('service', params.account);
    const [shell, report] = await Promise.all([loadShell(queryClient, coffre), loadMember(queryClient, coffre, member)]);
    const ways = signInWays(shell, report);
    if (ways === null) throw redirect({ to: '/service-accounts/$account/access', params });
    await Promise.all([
      queryClient.fetchQuery(queries.credentials(coffre, member, ways.tokens)),
      queryClient.fetchQuery(queries.bindings(coffre, member, ways.workloads)),
    ]);
  },
};

/** `/service-accounts/$account/access`. */
export const serviceAccountAccess = {
  loader: ({ context }: Loader) => {
    const { coffre, queryClient } = coffreOf(context);
    return loadAccess(queryClient, coffre);
  },
};

/** `/service-accounts/$account/activity`, as a user's. */
export const serviceAccountActivity = {
  loader: async ({ context, params }: Loader<{ account: string }>) => {
    const { coffre, queryClient } = coffreOf(context);
    const shell = await loadShell(queryClient, coffre);
    if (!shell.capabilities.canReadAudit) throw redirect({ to: '/service-accounts/$account', params });
  },
};

/** `/settings`. */
export const settings = {
  // Instance facts come from the directory and the key checks, which only
  // owners may read. Asking on everyone's behalf would write a refusal to the
  // audit log for every user who opens the page, so they are only asked for them.
  loader: ({ context }: Loader) => {
    const { coffre, queryClient } = coffreOf(context);
    return loadSettings(queryClient, coffre);
  },
};

type AccountSearch = { linked?: string; error?: string };

/** `/account`. */
export const account = {
  validateSearch: (search: Record<string, unknown>): AccountSearch => {
    const out: AccountSearch = {};
    for (const name of ['linked', 'error'] as const) {
      const value = search[name];
      if (typeof value === 'string' && /^[a-z0-9_-]{1,40}$/.test(value)) out[name] = value;
    }
    return out;
  },
  // The sign-in half: which accounts you sign in with and where you are
  // signed in. Absent behind Cloudflare Access, which owns sessions there.
  loader: async ({ context }: Loader) => {
    const { coffre, queryClient } = coffreOf(context);
    const shell = await loadShell(queryClient, coffre);
    if (shell.auth.signin === null || shell.principal?.type !== 'user') return;
    await Promise.all([queryClient.fetchQuery(queries.identities(coffre)), queryClient.fetchQuery(queries.sessions(coffre))]);
  },
};

// --- in the solo frame ----------------------------------------------------------------

/** `/login`. */
export const login = {
  // Where to resume after signing in, and the sign-in's error, shown once (`loginSearch`).
  validateSearch: loginSearch,
  loader: async ({ context }: Loader) => {
    const { coffre, queryClient } = coffreOf(context);
    const shell = await loadShell(queryClient, coffre);
    if (shell.registrationRequired) throw redirect({ to: '/unregistered' });
    if (shell.principal !== null) throw redirect({ to: '/projects' });
  },
};

/** `/unregistered`. */
export const unregistered = {
  loader: async ({ context, location }: Loader) => {
    const { coffre, queryClient } = coffreOf(context);
    const shell = await loadShell(queryClient, coffre);
    if (shell.registrationRequired) return;
    if (shell.principal === null) throw redirect({ to: '/login', search: { next: location.href } });
    throw redirect({ to: '/projects' });
  },
};

/** `/auth/device`. */
export const deviceLogin = {
  validateSearch: (search: Record<string, unknown>): { code?: string } => {
    const code = search.code;
    return typeof code === 'string' && code.length <= 16 ? { code } : {};
  },
  loaderDeps: ({ search }: { search: { code?: string } }) => ({ code: search.code }),
  // Its own read, not a query: it is asked once, and nothing here refreshes it.
  loader: async ({ context, deps, location }: Loader & { deps: { code?: string } }) => {
    const { coffre, queryClient } = coffreOf(context);
    const shell = await loadShell(queryClient, coffre);
    if (shell.registrationRequired) throw redirect({ to: '/unregistered' });
    if (shell.principal === null) throw redirect({ to: '/login', search: { next: location.href } });
    if (deps.code === undefined) return null;
    if (!shell.auth.signin) return { ok: false as const, error: 'This instance has no CLI sign-in.' };
    const code = deps.code;
    return uiResult(() => coffre.deviceLogins.get(code));
  },
};

/**
 * `/approvals/$approval`: a change an MCP client asked for, which its person
 * decides here. Its own read: the page shows what the change would do now.
 */
export const approval = {
  loader: async ({ context, params, location }: Loader<{ approval: string }>) => {
    const { coffre, queryClient } = coffreOf(context);
    const shell = await loadShell(queryClient, coffre);
    if (shell.registrationRequired) throw redirect({ to: '/unregistered' });
    if (shell.principal === null) throw redirect({ to: '/login', search: { next: location.href } });
    return uiResult(() => coffre.approvals.get(params.approval));
  },
};

type AuthorizationSearch = RouteInput<'GET /oauth/authorizations'>;

/**
 * `/oauth/authorize`: an MCP client asking to connect. Its parameters go to
 * the API as sent, which says which it takes; the router keeps them strings,
 * so a `state` of `1e5` goes back as `1e5`.
 */
export const oauthAuthorize = {
  validateSearch: (search: Record<string, unknown>): AuthorizationSearch => stringsOf(search),
  loaderDeps: ({ search }: { search: AuthorizationSearch }) => ({ request: search }),
  // Its own read, as the device login's: every authorization is checked afresh.
  loader: async ({ context, deps, location }: Loader & { deps: { request: AuthorizationSearch } }) => {
    const { coffre, queryClient } = coffreOf(context);
    const shell = await loadShell(queryClient, coffre);
    if (shell.registrationRequired) throw redirect({ to: '/unregistered' });
    if (shell.principal === null) throw redirect({ to: '/login', search: { next: location.href } });
    const { request } = deps;
    return { request, email: shell.principal.id, result: await uiResult(() => coffre.oauth.describe(request)) };
  },
};
