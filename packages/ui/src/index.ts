// `@coffre/ui`: coffre's pages, for a deployment's own TanStack Start app.
// Each page's and layout's route options, which the deployment's file
// routes mount (`./options.ts`); `<CoffreProvider>`, around them in its root
// document; and the router they render in. Each page's component is at
// `@coffre/ui/pages/<name>`, and the stylesheet and icons are
// `@coffre/ui/styles.css`, `icon.svg` and `apple-touch-icon.png`.
export { CoffreProvider } from './layout.tsx';
export { useCoffre } from './lib/coffre.ts';
export { createRouter } from './router.tsx';
export {
  account,
  approval,
  audit,
  deviceLogin,
  environment,
  home,
  login,
  oauthAuthorize,
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
} from './options.ts';
