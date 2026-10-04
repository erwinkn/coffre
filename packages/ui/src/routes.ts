// `@coffre/ui/routes`: coffre's routes in code, for a deployment that mounts
// them so rather than as Start's file routes. The whole of them,
//
//   root.addChildren([...coffreServerRoutes(root), ...coffreRoutes(root)])
//
// or one at a time, which is all coffreRoutes does (at the end of this file):
// leave any out, or put a page of the deployment's own at a path in its place.
// Each is a function of its parent, and the route options of the same name
// (`./options.ts`) at coffre's path, with its page. The pages come with
// this module, in the deployment's main bundle: Start splits only file
// routes.
import { createRoute, type AnyRoute } from '@tanstack/react-router';

import { access, account, audit, deviceLogin, environment, home, login, project, projects, settings, shell, solo, token, tokens, unregistered, user, users, type CoffreContext } from './options';
import { AccountPage } from './pages/account';
import { AuditPage } from './pages/audit';
import { DevicePage } from './pages/device-login';
import { EnvironmentPage } from './pages/environment';
import { LoginPage } from './pages/login';
import { ProjectPage } from './pages/project';
import { ProjectsPage } from './pages/projects';
import { SettingsPage } from './pages/settings';
import { TokenPage } from './pages/token';
import { TokensPage } from './pages/tokens';
import { UnregisteredPage } from './pages/unregistered';
import { UserPage } from './pages/user';
import { UsersPage } from './pages/users';

/** A route coffre's routes can go under: one whose context is coffre's. */
export type CoffreParent = AnyRoute & { types: { allContext: CoffreContext } };

/** coffre's nav, around the signed-in pages. */
export const shellRoute = <TParent extends CoffreParent>(parent: TParent) =>
  createRoute({ getParentRoute: () => parent, id: 'coffre', ...shell });

/** The bare frame of the sign-in pages. */
export const soloRoute = <TParent extends CoffreParent>(parent: TParent) =>
  createRoute({ getParentRoute: () => parent, id: 'coffre-solo', ...solo });

export const homeRoute = <TParent extends AnyRoute>(parent: TParent) => createRoute({ getParentRoute: () => parent, path: '/', ...home });

export const projectsRoute = <TParent extends AnyRoute>(parent: TParent) =>
  createRoute({ getParentRoute: () => parent, path: '/projects', ...projects, component: ProjectsPage });

export const projectRoute = <TParent extends AnyRoute>(parent: TParent) =>
  createRoute({ getParentRoute: () => parent, path: '/projects/$project', ...project, component: ProjectPage });

export const environmentRoute = <TParent extends AnyRoute>(parent: TParent) =>
  createRoute({ getParentRoute: () => parent, path: '/projects/$project/$environment', ...environment, component: EnvironmentPage });

export const auditRoute = <TParent extends AnyRoute>(parent: TParent) =>
  createRoute({ getParentRoute: () => parent, path: '/audit', ...audit, component: AuditPage });

export const accessRoute = <TParent extends AnyRoute>(parent: TParent) => createRoute({ getParentRoute: () => parent, path: '/access', ...access });

export const usersRoute = <TParent extends AnyRoute>(parent: TParent) =>
  createRoute({ getParentRoute: () => parent, path: '/users', ...users, component: UsersPage });

export const userRoute = <TParent extends AnyRoute>(parent: TParent) =>
  createRoute({ getParentRoute: () => parent, path: '/users/$user', ...user, component: UserPage });

export const tokensRoute = <TParent extends AnyRoute>(parent: TParent) =>
  createRoute({ getParentRoute: () => parent, path: '/tokens', ...tokens, component: TokensPage });

export const tokenRoute = <TParent extends AnyRoute>(parent: TParent) =>
  createRoute({ getParentRoute: () => parent, path: '/tokens/$token', ...token, component: TokenPage });

export const settingsRoute = <TParent extends AnyRoute>(parent: TParent) =>
  createRoute({ getParentRoute: () => parent, path: '/settings', ...settings, component: SettingsPage });

export const accountRoute = <TParent extends AnyRoute>(parent: TParent) =>
  createRoute({ getParentRoute: () => parent, path: '/account', ...account, component: AccountPage });

export const loginRoute = <TParent extends AnyRoute>(parent: TParent) =>
  createRoute({ getParentRoute: () => parent, path: '/login', ...login, component: LoginPage });

export const unregisteredRoute = <TParent extends AnyRoute>(parent: TParent) =>
  createRoute({ getParentRoute: () => parent, path: '/unregistered', ...unregistered, component: UnregisteredPage });

export const deviceLoginRoute = <TParent extends AnyRoute>(parent: TParent) =>
  createRoute({ getParentRoute: () => parent, path: '/auth/device', ...deviceLogin, component: DevicePage });

/**
 * All of coffre's routes but its server's, under `root`: exactly the pieces
 * above, as a deployment would put them together one by one.
 */
export function coffreRoutes<TRoot extends CoffreParent>(root: TRoot) {
  const shell = shellRoute(root);
  const solo = soloRoute(root);
  return [
    solo.addChildren([loginRoute(solo), unregisteredRoute(solo), deviceLoginRoute(solo)]),
    shell.addChildren([
      homeRoute(shell),
      projectsRoute(shell),
      projectRoute(shell),
      environmentRoute(shell),
      auditRoute(shell),
      accessRoute(shell),
      usersRoute(shell),
      userRoute(shell),
      tokensRoute(shell),
      tokenRoute(shell),
      settingsRoute(shell),
      accountRoute(shell),
    ]),
  ] as const;
}
