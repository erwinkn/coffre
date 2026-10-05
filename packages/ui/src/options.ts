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
import type { CoffreClient } from '@coffre/client';

import { ShellLayout, SoloLayout } from './layout';
import { uiResult } from './lib/coffre';
import {
  loadDirectory,
  loadPrincipal,
  loadProject,
  loadServiceDirectory,
  loadShell,
  queries,
  type AuditSearch,
} from './lib/queries';
import type { ProjectTab } from './pages/project';
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

/** `/projects/$project`. */
export const project = {
  // The tab lives in the URL so a link can land on a project's access list.
  // Environments is the default and so has no parameter.
  validateSearch: (search: Record<string, unknown>): { tab?: Exclude<ProjectTab, 'environments'> } => ({
    tab: search.tab === 'users' || search.tab === 'tokens' || search.tab === 'settings' ? search.tab : undefined,
  }),
  loader: ({ context, params }: Loader<{ project: string }>) => {
    const { coffre, queryClient } = coffreOf(context);
    return loadProject(queryClient, coffre, params.project);
  },
};

/** `/projects/$project/$environment`. */
export const environment = {
  // `?filter=KEY` opens the ledger narrowed to matching keys, for links to one secret.
  validateSearch: (search: Record<string, unknown>): { filter?: string } => ({
    filter: typeof search.filter === 'string' && search.filter !== '' ? search.filter : undefined,
  }),
  loader: ({ context, params }: Loader<{ project: string; environment: string }>) => {
    const { coffre, queryClient } = coffreOf(context);
    return queryClient.fetchQuery(queries.secrets(coffre, params));
  },
};

/** `/audit`. */
export const audit = {
  // Filters live in the URL so a finding can cite the exact view it came from.
  validateSearch: (search: Record<string, unknown>): AuditSearch => ({
    decision: search.decision === 'deny' ? 'deny' : undefined,
    actorId: typeof search.actorId === 'string' && search.actorId !== '' ? search.actorId : undefined,
    detail: search.detail === '1' || search.detail === 1 ? '1' : undefined,
  }),
  loaderDeps: ({ search }: { search: AuditSearch }) => search,
  // The entries only: the verification is asked for once the page is up
  // (`ChainStatus`), so the table never waits on it.
  loader: ({ context, deps }: Loader & { deps: AuditSearch }) => {
    const { coffre, queryClient } = coffreOf(context);
    return queryClient.fetchQuery(queries.auditEntries(coffre, deps));
  },
};

/** `/access`: the access page became the users page, and old links land there. */
export const access = {
  beforeLoad: () => {
    throw redirect({ to: '/users' });
  },
};

/** `/users`. */
export const users = {
  loader: ({ context }: Loader) => {
    const { coffre, queryClient } = coffreOf(context);
    return loadDirectory(queryClient, coffre);
  },
};

/** `/users/$user`. */
export const user = {
  // Access is the default tab, with no parameter.
  validateSearch: (search: Record<string, unknown>): { tab?: 'activity' } => ({
    tab: search.tab === 'activity' ? search.tab : undefined,
  }),
  loader: ({ context, params }: Loader<{ user: string }>) => {
    const { coffre, queryClient } = coffreOf(context);
    return loadPrincipal(queryClient, coffre, 'user', params.user);
  },
};

/** `/tokens`. */
export const tokens = {
  loader: ({ context }: Loader) => {
    const { coffre, queryClient } = coffreOf(context);
    return loadServiceDirectory(queryClient, coffre);
  },
};

/** `/tokens/$token`. */
export const token = {
  // Sign-in is the default tab, with no parameter.
  validateSearch: (search: Record<string, unknown>): { tab?: 'access' | 'activity' } => ({
    tab: search.tab === 'access' || search.tab === 'activity' ? search.tab : undefined,
  }),
  loader: ({ context, params }: Loader<{ token: string }>) => {
    const { coffre, queryClient } = coffreOf(context);
    return loadPrincipal(queryClient, coffre, 'service', params.token);
  },
};

/** `/settings`. */
export const settings = {
  // Instance facts come from the directory, which only owners may list.
  // Asking on everyone's behalf would write a refusal to the audit log for
  // every user who opens the page, so it is only asked for them.
  loader: ({ context }: Loader) => {
    const { coffre, queryClient } = coffreOf(context);
    return loadDirectory(queryClient, coffre);
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
