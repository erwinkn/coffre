// The app Start runs in start-handler.test.ts: a root, and a server route of
// the deployment's own that redirects, as docs/deploy.md's would.
import { createRootRoute, createRoute, createRouter, redirect } from '@tanstack/react-router';

const root = createRootRoute();
const hook = createRoute({
  getParentRoute: () => root,
  path: '/hooks/deployed',
  server: {
    handlers: {
      POST: () => {
        throw redirect({ to: '/done' });
      },
    },
  },
});

// One that answers with a response whose headers cannot change.
const elsewhere = createRoute({
  getParentRoute: () => root,
  path: '/hooks/elsewhere',
  server: { handlers: { GET: () => Response.redirect('https://elsewhere.example/', 302) } },
});

export const getRouter = () => createRouter({ routeTree: root.addChildren([hook, elsewhere]) });
