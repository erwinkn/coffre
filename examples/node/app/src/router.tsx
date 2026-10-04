// The app's routes. Its root is the document every page renders in, with
// coffre's head entries and the provider its pages need; under it, coffre's
// server routes (/api, /auth, /livez and /readyz) and coffre's pages. To
// leave one out, or put a page of this app's own at a path, mount them one
// by one: see coffre's docs/deploy.md, "Your own routes".
import { createRootRouteWithContext, HeadContent, Scripts } from '@tanstack/react-router';
import { coffreServerRoutes } from '@coffre/server/routes';
import { CoffreProvider, coffreHead, coffreRoutes, createRouter, type CoffreContext } from '@coffre/ui';

export const root = createRootRouteWithContext<CoffreContext>()({
  head: () => coffreHead(),
  shellComponent: ({ children }) => (
    <html lang="en" suppressHydrationWarning>
      <head>
        <HeadContent />
      </head>
      <body>
        <CoffreProvider>{children}</CoffreProvider>
        <Scripts />
      </body>
    </html>
  ),
});

export const routeTree = root.addChildren([...coffreServerRoutes(root), ...coffreRoutes(root)]);

export const getRouter = () => createRouter(routeTree);

declare module '@tanstack/react-router' {
  interface Register {
    router: ReturnType<typeof getRouter>;
  }
}
