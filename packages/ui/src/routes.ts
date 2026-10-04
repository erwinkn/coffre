// coffre's routes, in code, for the deployment's route tree, under the root
// it owns. The whole of them, as `coffre init` writes it:
//
//   root.addChildren([...coffreServerRoutes(root), ...coffreRoutes(root)])
//
// or one at a time, which is all coffreRoutes does (at the end of this file):
// leave any out, or put a page of the deployment's own at a path in its place.
// Each takes its parent. `coffreShell` is coffre's nav, and lets in only
// signed-in, registered visitors; `coffreSolo` is the bare frame of the
// sign-in pages. A deployment's own page under its root has neither, and no
// sign-in check, unless it is put under them. Each page's component is a
// chunk of its own, loaded as the page is.
import { createRoute, lazyRouteComponent, redirect, type AnyRoute } from '@tanstack/react-router';
import type { QueryClient } from '@tanstack/react-query';
import type { CoffreClient } from '@coffre/client';

import { ShellLayout, SoloLayout } from './layout';
import { uiResult } from './lib/coffre';
import { preloads } from './preloads';
import { loadDirectory, loadPrincipal, loadProject, loadShell, queries, type AuditSearch } from './lib/queries';
import type { ProjectTab } from './pages/project';

/**
 * What coffre's routes read through the router: the API as the visitor
 * (`coffre`), and the query cache the pages share. The deployment's root is
 * created with it, `createRootRouteWithContext<CoffreContext>()`, and
 * coffre's `createRouter` provides it.
 */
export type CoffreContext = { coffre: CoffreClient; queryClient: QueryClient };

/** A route coffre's routes can go under: one whose context is coffre's. */
export type CoffreParent = AnyRoute & { types: { allContext: CoffreContext } };

/**
 * coffre's context, as a page's loader reads it. A page goes under one of
 * coffre's layouts, whose parent has it (`CoffreParent`); its own parent is
 * any route, which the types cannot follow there.
 */
const coffreOf = (context: unknown) => context as CoffreContext;

const page = <T extends string>(load: () => Promise<Record<T, () => unknown>>, name: T) =>
  lazyRouteComponent(load as () => Promise<Record<string, never>>, name);

// --- the layouts ------------------------------------------------------------------------

/** coffre's nav, around the signed-in pages: someone not signed in, or not yet registered, is sent to the page for it. */
export function coffreShell<TParent extends CoffreParent>(parent: TParent) {
  return createRoute({
    getParentRoute: () => parent,
    id: 'coffre-shell',
    loader: async ({ context: { coffre, queryClient }, location }) => {
      const shell = await loadShell(queryClient, coffre);
      if (shell.registrationRequired) throw redirect({ to: '/unregistered' });
      if (shell.principal === null) throw redirect({ to: '/login', search: { next: location.href } });
    },
    component: ShellLayout,
  });
}

/** The bare frame of the sign-in pages. Each sends on whoever does not belong there. */
export function coffreSolo<TParent extends CoffreParent>(parent: TParent) {
  return createRoute({ getParentRoute: () => parent, id: 'coffre-solo', component: SoloLayout });
}

/** `/`, which sends to the projects. */
export function home<TParent extends CoffreParent>(parent: TParent) {
  return createRoute({
    getParentRoute: () => parent,
    path: '/',
    beforeLoad: () => {
      throw redirect({ to: '/projects' });
    },
  });
}

// --- under the shell ------------------------------------------------------------------

export function projects<TParent extends AnyRoute>(parent: TParent) {
  return createRoute({
    getParentRoute: () => parent,
    path: '/projects',
    loader: ({ context }) => {
      const { coffre, queryClient } = coffreOf(context);
      return queryClient.fetchQuery(queries.projects(coffre));
    },
    head: () => preloads('projects'),
    component: page(() => import('./pages/projects'), 'ProjectsPage'),
  });
}

export function project<TParent extends AnyRoute>(parent: TParent) {
  return createRoute({
    getParentRoute: () => parent,
    path: '/projects/$project',
    // The tab lives in the URL so a link can land on a project's access list.
    // Environments is the default and so has no parameter.
    validateSearch: (search: Record<string, unknown>): { tab?: Exclude<ProjectTab, 'environments'> } => ({
      tab: search.tab === 'users' || search.tab === 'tokens' || search.tab === 'settings' ? search.tab : undefined,
    }),
    loader: ({ context, params }) => {
      const { coffre, queryClient } = coffreOf(context);
      return loadProject(queryClient, coffre, params.project);
    },
    head: () => preloads('project'),
    component: page(() => import('./pages/project'), 'ProjectPage'),
  });
}

export function environment<TParent extends AnyRoute>(parent: TParent) {
  return createRoute({
    getParentRoute: () => parent,
    path: '/projects/$project/$environment',
    // `?filter=KEY` opens the ledger narrowed to matching keys, for links to one secret.
    validateSearch: (search: Record<string, unknown>): { filter?: string } => ({
      filter: typeof search.filter === 'string' && search.filter !== '' ? search.filter : undefined,
    }),
    loader: ({ context, params }) => {
      const { coffre, queryClient } = coffreOf(context);
      return queryClient.fetchQuery(queries.secrets(coffre, params));
    },
    head: () => preloads('environment'),
    component: page(() => import('./pages/environment'), 'EnvironmentPage'),
  });
}

export function audit<TParent extends AnyRoute>(parent: TParent) {
  return createRoute({
    getParentRoute: () => parent,
    path: '/audit',
    // Filters live in the URL so a finding can cite the exact view it came from.
    validateSearch: (search: Record<string, unknown>): AuditSearch => ({
      decision: search.decision === 'deny' ? 'deny' : undefined,
      actorId: typeof search.actorId === 'string' && search.actorId !== '' ? search.actorId : undefined,
      detail: search.detail === '1' || search.detail === 1 ? '1' : undefined,
    }),
    loaderDeps: ({ search }) => search,
    // The entries only: the verification is asked for once the page is up
    // (`ChainStatus`), so the table never waits on it.
    loader: ({ context, deps }) => {
      const { coffre, queryClient } = coffreOf(context);
      return queryClient.fetchQuery(queries.auditEntries(coffre, deps));
    },
    head: () => preloads('audit'),
    component: page(() => import('./pages/audit'), 'AuditPage'),
  });
}

/** The access page became the users page: old links land there. */
export function access<TParent extends AnyRoute>(parent: TParent) {
  return createRoute({
    getParentRoute: () => parent,
    path: '/access',
    beforeLoad: () => {
      throw redirect({ to: '/users' });
    },
  });
}

export function users<TParent extends AnyRoute>(parent: TParent) {
  return createRoute({
    getParentRoute: () => parent,
    path: '/users',
    loader: ({ context }) => {
      const { coffre, queryClient } = coffreOf(context);
      return loadDirectory(queryClient, coffre);
    },
    head: () => preloads('users'),
    component: page(() => import('./pages/users'), 'UsersPage'),
  });
}

export function user<TParent extends AnyRoute>(parent: TParent) {
  return createRoute({
    getParentRoute: () => parent,
    path: '/users/$user',
    loader: ({ context, params }) => {
      const { coffre, queryClient } = coffreOf(context);
      return loadPrincipal(queryClient, coffre, 'user', params.user);
    },
    head: () => preloads('user'),
    component: page(() => import('./pages/user'), 'UserPage'),
  });
}

export function tokens<TParent extends AnyRoute>(parent: TParent) {
  return createRoute({
    getParentRoute: () => parent,
    path: '/tokens',
    loader: ({ context }) => {
      const { coffre, queryClient } = coffreOf(context);
      return loadDirectory(queryClient, coffre);
    },
    head: () => preloads('tokens'),
    component: page(() => import('./pages/tokens'), 'TokensPage'),
  });
}

export function token<TParent extends AnyRoute>(parent: TParent) {
  return createRoute({
    getParentRoute: () => parent,
    path: '/tokens/$token',
    loader: ({ context, params }) => {
      const { coffre, queryClient } = coffreOf(context);
      return loadPrincipal(queryClient, coffre, 'service', params.token);
    },
    head: () => preloads('token'),
    component: page(() => import('./pages/token'), 'TokenPage'),
  });
}

export function settings<TParent extends AnyRoute>(parent: TParent) {
  return createRoute({
    getParentRoute: () => parent,
    path: '/settings',
    // Instance facts come from the directory, which only owners may list.
    // Asking on everyone's behalf would write a refusal to the audit log for
    // every user who opens the page, so it is only asked for them.
    loader: ({ context }) => {
      const { coffre, queryClient } = coffreOf(context);
      return loadDirectory(queryClient, coffre);
    },
    head: () => preloads('settings'),
    component: page(() => import('./pages/settings'), 'SettingsPage'),
  });
}

type AccountSearch = { linked?: string; error?: string };

export function account<TParent extends AnyRoute>(parent: TParent) {
  return createRoute({
    getParentRoute: () => parent,
    path: '/account',
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
    loader: async ({ context }) => {
      const { coffre, queryClient } = coffreOf(context);
      const shell = await loadShell(queryClient, coffre);
      if (shell.auth.signin === null || shell.principal?.type !== 'user') return;
      await Promise.all([queryClient.fetchQuery(queries.identities(coffre)), queryClient.fetchQuery(queries.sessions(coffre))]);
    },
    head: () => preloads('account'),
    component: page(() => import('./pages/account'), 'AccountPage'),
  });
}

// --- in the solo frame ----------------------------------------------------------------

export function login<TParent extends AnyRoute>(parent: TParent) {
  return createRoute({
    getParentRoute: () => parent,
    path: '/login',
    // Where to resume after signing in. Same-origin paths only: an absolute URL
    // accepted here would make the sign-in page an open redirect.
    validateSearch: (search: Record<string, unknown>): { next?: string; error?: string } => {
      const out: { next?: string; error?: string } = {};
      const { next, error } = search;
      if (typeof next === 'string' && next.startsWith('/') && !next.startsWith('//')) out.next = next;
      if (typeof error === 'string' && /^[a-z_]{1,40}$/.test(error)) out.error = error;
      return out;
    },
    loader: async ({ context }) => {
      const { coffre, queryClient } = coffreOf(context);
      const shell = await loadShell(queryClient, coffre);
      if (shell.registrationRequired) throw redirect({ to: '/unregistered' });
      if (shell.principal !== null) throw redirect({ to: '/projects' });
    },
    head: () => preloads('login'),
    component: page(() => import('./pages/login'), 'LoginPage'),
  });
}

export function unregistered<TParent extends AnyRoute>(parent: TParent) {
  return createRoute({
    getParentRoute: () => parent,
    path: '/unregistered',
    loader: async ({ context, location }) => {
      const { coffre, queryClient } = coffreOf(context);
      const shell = await loadShell(queryClient, coffre);
      if (shell.registrationRequired) return;
      if (shell.principal === null) throw redirect({ to: '/login', search: { next: location.href } });
      throw redirect({ to: '/projects' });
    },
    head: () => preloads('unregistered'),
    component: page(() => import('./pages/unregistered'), 'UnregisteredPage'),
  });
}

export function deviceLogin<TParent extends AnyRoute>(parent: TParent) {
  return createRoute({
    getParentRoute: () => parent,
    path: '/auth/device',
    validateSearch: (search: Record<string, unknown>): { code?: string } => {
      const code = search.code;
      return typeof code === 'string' && code.length <= 16 ? { code } : {};
    },
    loaderDeps: ({ search }) => ({ code: search.code }),
    // Its own read, not a query: it is asked once, and nothing here refreshes it.
    loader: async ({ context, deps, location }) => {
      const { coffre, queryClient } = coffreOf(context);
      const shell = await loadShell(queryClient, coffre);
      if (shell.registrationRequired) throw redirect({ to: '/unregistered' });
      if (shell.principal === null) throw redirect({ to: '/login', search: { next: location.href } });
      if (deps.code === undefined) return null;
      if (!shell.auth.signin) return { ok: false as const, error: 'This instance has no CLI sign-in.' };
      const code = deps.code;
      return uiResult(() => coffre.deviceLogins.get(code));
    },
    head: () => preloads('device-login'),
    component: page(() => import('./pages/device-login'), 'DevicePage'),
  });
}

/**
 * All of coffre's routes but its server's, under `root`: exactly the pieces
 * above, as a deployment would put them together one by one.
 */
export function coffreRoutes<TRoot extends CoffreParent>(root: TRoot) {
  const shell = coffreShell(root);
  const solo = coffreSolo(root);
  return [
    home(root),
    solo.addChildren([login(solo), unregistered(solo), deviceLogin(solo)]),
    shell.addChildren([
      projects(shell),
      project(shell),
      environment(shell),
      audit(shell),
      access(shell),
      users(shell),
      user(shell),
      tokens(shell),
      token(shell),
      settings(shell),
      account(shell),
    ]),
  ] as const;
}
