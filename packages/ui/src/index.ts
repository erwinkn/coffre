// `@coffre/ui`: coffre's pages, for a deployment's own TanStack Start app.
// Each page's and layout's route options, which the deployment's file
// routes mount (`./options.ts`); `<CoffreProvider>`, around them in its root
// document; and the router they render in. Each page's component is at
// `@coffre/ui/pages/<name>`, the same routes in code at `@coffre/ui/routes`,
// and the stylesheet and icons at `@coffre/ui/styles.css`, `icon.svg` and
// `apple-touch-icon.png`.
export { CoffreProvider } from './layout.tsx';
export { useCoffre } from './lib/coffre.ts';
export { createRouter } from './router.tsx';
export {
  access,
  account,
  audit,
  deviceLogin,
  environment,
  home,
  login,
  project,
  projects,
  settings,
  shell,
  solo,
  token,
  tokens,
  unregistered,
  user,
  users,
  type CoffreContext,
} from './options.ts';
