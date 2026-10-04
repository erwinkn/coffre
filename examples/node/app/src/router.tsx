// The app's router, around the route tree Start generates from
// src/routes: coffre's server routes, layouts and pages, and this app's own.
// To leave one of coffre's pages out, delete its file; to put a page of this
// app's own at a path, add one: see coffre's docs/deploy.md, "Your own
// routes".
import { createRouter } from '@coffre/ui';

import { routeTree } from './routeTree.gen';

export const getRouter = () => createRouter(routeTree);

declare module '@tanstack/react-router' {
  interface Register {
    router: ReturnType<typeof getRouter>;
  }
}
