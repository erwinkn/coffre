// coffre's whole route tree, under a root as a deployment makes one, for
// this package's own typecheck: its links are checked against every route it
// defines. Nothing imports this file, so the build, and a deployment, never
// runs it: there the deployment's tree is the one registered.
import { createRootRouteWithContext } from '@tanstack/react-router';

import type { createRouter } from './router';
import { coffreRoutes, type CoffreContext } from './routes';

const root = createRootRouteWithContext<CoffreContext>()({});
const routeTree = root.addChildren(coffreRoutes(root));

declare module '@tanstack/react-router' {
  interface Register {
    router: ReturnType<typeof createRouter<typeof routeTree>>;
  }
}
