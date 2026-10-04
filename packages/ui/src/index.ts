// `@coffre/ui`: coffre's pages, as routes in code for a deployment's own
// TanStack Start app, under the root it owns, and the router they render in.
// Its src/router.tsx, as `coffre init` writes it:
//
//   import { coffreServerRoutes } from '@coffre/server/routes';
//   import { CoffreProvider, coffreHead, coffreRoutes, createRouter, type CoffreContext } from '@coffre/ui';
//
//   export const root = createRootRouteWithContext<CoffreContext>()({
//     head: () => coffreHead(),
//     shellComponent: ({ children }) => (
//       <html lang="en" suppressHydrationWarning>
//         <head><HeadContent /></head>
//         <body><CoffreProvider>{children}</CoffreProvider><Scripts /></body>
//       </html>
//     ),
//   });
//   export const routeTree = root.addChildren([...coffreServerRoutes(root), ...coffreRoutes(root)]);
//   export const getRouter = () => createRouter(routeTree);
export { coffreHead } from './head.ts';
export { CoffreProvider } from './layout.tsx';
export { useCoffre } from './lib/coffre.ts';
export { createRouter } from './router.tsx';
export {
  access,
  account,
  audit,
  coffreRoutes,
  coffreShell,
  coffreSolo,
  deviceLogin,
  environment,
  home,
  login,
  project,
  projects,
  settings,
  token,
  tokens,
  unregistered,
  user,
  users,
  type CoffreContext,
  type CoffreParent,
} from './routes.ts';
