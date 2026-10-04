// `pnpm dev`'s routes, in code: coffre's server routes and pages under the
// root (src/routes/__root.tsx), with any page files beside it, as Start's
// generator found them.
import { coffreServerRoutes } from '@coffre/server/routes';
import { createRouter } from '@coffre/ui';
import { coffreRoutes } from '@coffre/ui/routes';

import { routeTree as files, type RootRouteChildren } from './routeTree.gen';
import { Route as root } from './routes/__root';

const pages = Object.values(files.children ?? {}) as RootRouteChildren[keyof RootRouteChildren][];

export const routeTree = root.addChildren([...pages, ...coffreServerRoutes(root), ...coffreRoutes(root)]);

export const getRouter = () => createRouter(routeTree);

declare module '@tanstack/react-router' {
  interface Register {
    router: ReturnType<typeof getRouter>;
  }
}
