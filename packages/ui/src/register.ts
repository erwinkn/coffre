// coffre's whole route tree, mounted as a deployment mounts it, in plain
// TanStack, for this package's own typecheck: its links are checked against
// every route it defines. Nothing imports this file, so the build, and a
// deployment, never runs it: there the deployment's tree is the one
// registered.
import { createRootRouteWithContext, createRoute } from '@tanstack/react-router';

import type { createRouter } from './router';
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

const root = createRootRouteWithContext<CoffreContext>()({});
const nav = createRoute({ getParentRoute: () => root, id: '_coffre', ...shell });
const frame = createRoute({ getParentRoute: () => root, id: '_solo', ...solo });
const under = <T extends string>(path: T) => ({ getParentRoute: () => nav, path });

const routeTree = root.addChildren([
  frame.addChildren([
    createRoute({ getParentRoute: () => frame, path: '/login', ...login, component: LoginPage }),
    createRoute({ getParentRoute: () => frame, path: '/unregistered', ...unregistered, component: UnregisteredPage }),
    createRoute({ getParentRoute: () => frame, path: '/auth/device', ...deviceLogin, component: DevicePage }),
  ]),
  nav.addChildren([
    createRoute({ ...under('/'), ...home }),
    createRoute({ ...under('/projects'), ...projects, component: ProjectsPage }),
    createRoute({ ...under('/projects/$project'), ...project, component: ProjectPage }),
    createRoute({ ...under('/projects/$project/$environment'), ...environment, component: EnvironmentPage }),
    createRoute({ ...under('/audit'), ...audit, component: AuditPage }),
    createRoute({ ...under('/access'), ...access }),
    createRoute({ ...under('/users'), ...users, component: UsersPage }),
    createRoute({ ...under('/users/$user'), ...user, component: UserPage }),
    createRoute({ ...under('/tokens'), ...tokens, component: TokensPage }),
    createRoute({ ...under('/tokens/$token'), ...token, component: TokenPage }),
    createRoute({ ...under('/settings'), ...settings, component: SettingsPage }),
    createRoute({ ...under('/account'), ...account, component: AccountPage }),
  ]),
]);

declare module '@tanstack/react-router' {
  interface Register {
    router: ReturnType<typeof createRouter<typeof routeTree>>;
  }
}
