// coffre's whole route tree, mounted as a deployment mounts it, in plain
// TanStack, for this package's own typecheck: its links are checked against
// every route it defines. Nothing imports this file, so the build, and a
// deployment, never runs it: there the deployment's tree is the one
// registered.
import { createRootRouteWithContext, createRoute } from '@tanstack/react-router';

import type { createRouter } from './router';
import {
  account,
  audit,
  deviceLogin,
  environment,
  home,
  login,
  project,
  projectEnvironments,
  projects,
  projectServiceAccounts,
  projectSettings,
  projectUsers,
  serviceAccount,
  serviceAccountAccess,
  serviceAccountActivity,
  serviceAccounts,
  serviceAccountSignIn,
  settings,
  shell,
  solo,
  unregistered,
  user,
  userAccess,
  userActivity,
  users,
  type CoffreContext,
} from './options';
import { AccountPage } from './pages/account';
import { AuditPage } from './pages/audit';
import { DevicePage } from './pages/device-login';
import { EnvironmentPage } from './pages/environment';
import { LoginPage } from './pages/login';
import { ProjectLayout } from './pages/project';
import { ProjectServiceAccountsPage, ProjectUsersPage } from './pages/project-access';
import { ProjectEnvironmentsPage } from './pages/project-environments';
import { ProjectSettingsPage } from './pages/project-settings';
import { ProjectsPage } from './pages/projects';
import { ServiceAccountAccessPage, ServiceAccountActivityPage, ServiceAccountLayout, ServiceAccountSignInPage } from './pages/service-account';
import { ServiceAccountsPage } from './pages/service-accounts';
import { SettingsPage } from './pages/settings';
import { UnregisteredPage } from './pages/unregistered';
import { UserAccessPage, UserActivityPage, UserLayout } from './pages/user';
import { UsersPage } from './pages/users';

const root = createRootRouteWithContext<CoffreContext>()({});
const nav = createRoute({ getParentRoute: () => root, id: '_coffre', ...shell });
const frame = createRoute({ getParentRoute: () => root, id: '_solo', ...solo });
const under = <T extends string>(path: T) => ({ getParentRoute: () => nav, path });

// A page with tabs is a layout, each tab a route under it, the first its index.
const projectPage = createRoute({ ...under('/projects/$project'), ...project, component: ProjectLayout });
const userPage = createRoute({ ...under('/users/$user'), ...user, component: UserLayout });
const serviceAccountPage = createRoute({ ...under('/service-accounts/$account'), ...serviceAccount, component: ServiceAccountLayout });
const tab = <P extends typeof projectPage | typeof userPage | typeof serviceAccountPage, T extends string>(parent: P, path: T) => ({ getParentRoute: () => parent, path });

const routeTree = root.addChildren([
  frame.addChildren([
    createRoute({ getParentRoute: () => frame, path: '/login', ...login, component: LoginPage }),
    createRoute({ getParentRoute: () => frame, path: '/unregistered', ...unregistered, component: UnregisteredPage }),
    createRoute({ getParentRoute: () => frame, path: '/auth/device', ...deviceLogin, component: DevicePage }),
  ]),
  nav.addChildren([
    createRoute({ ...under('/'), ...home }),
    createRoute({ ...under('/projects'), ...projects, component: ProjectsPage }),
    projectPage.addChildren([
      createRoute({ ...tab(projectPage, '/'), ...projectEnvironments, component: ProjectEnvironmentsPage }),
      createRoute({ ...tab(projectPage, '/users'), ...projectUsers, component: ProjectUsersPage }),
      createRoute({ ...tab(projectPage, '/service-accounts'), ...projectServiceAccounts, component: ProjectServiceAccountsPage }),
      createRoute({ ...tab(projectPage, '/settings'), ...projectSettings, component: ProjectSettingsPage }),
    ]),
    createRoute({ ...under('/projects/$project/$environment'), ...environment, component: EnvironmentPage }),
    createRoute({ ...under('/audit'), ...audit, component: AuditPage }),
    createRoute({ ...under('/users'), ...users, component: UsersPage }),
    userPage.addChildren([
      createRoute({ ...tab(userPage, '/'), ...userAccess, component: UserAccessPage }),
      createRoute({ ...tab(userPage, '/activity'), ...userActivity, component: UserActivityPage }),
    ]),
    createRoute({ ...under('/service-accounts'), ...serviceAccounts, component: ServiceAccountsPage }),
    serviceAccountPage.addChildren([
      createRoute({ ...tab(serviceAccountPage, '/'), ...serviceAccountSignIn, component: ServiceAccountSignInPage }),
      createRoute({ ...tab(serviceAccountPage, '/access'), ...serviceAccountAccess, component: ServiceAccountAccessPage }),
      createRoute({ ...tab(serviceAccountPage, '/activity'), ...serviceAccountActivity, component: ServiceAccountActivityPage }),
    ]),
    createRoute({ ...under('/settings'), ...settings, component: SettingsPage }),
    createRoute({ ...under('/account'), ...account, component: AccountPage }),
  ]),
]);

declare module '@tanstack/react-router' {
  interface Register {
    router: ReturnType<typeof createRouter<typeof routeTree>>;
  }
}
