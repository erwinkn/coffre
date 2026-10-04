// The app Start runs in page-context.test.ts: a router that, as coffre's
// does, reads the request's page context first.
import { createRootRoute, createRoute, createRouter } from '@tanstack/react-router';

import { requestPage } from '../../../src/lib/page-context.ts';

const root = createRootRoute();
const page = createRoute({ getParentRoute: () => root, path: '/page' });

export const getRouter = () => {
  requestPage();
  return createRouter({ routeTree: root.addChildren([page]) });
};
