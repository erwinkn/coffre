# @coffre/ui

coffre's web pages, for a deployment's own TanStack Start app, whose pages
read only through `@coffre/client`; and `@coffre/ui/vite`, the Vite plugin
the app's build adds. Each page and layout is route options the app mounts
as Start's file routes, which is what `coffre init` writes:

```tsx
// app/src/routes/_coffre.tsx: coffre's nav
export const Route = createFileRoute('/_coffre')({ ...shell });

// app/src/routes/_coffre/projects.index.tsx
import { projects } from '@coffre/ui';
import { ProjectsPage } from '@coffre/ui/pages/projects';

export const Route = createFileRoute('/_coffre/projects/')({ ...projects, component: ProjectsPage });
```

The app's root puts `<CoffreProvider>` around them, and links
`@coffre/ui/styles.css`, `icon.svg` and `apple-touch-icon.png`; its router
is `createRouter(routeTree)`. The same routes mount in code from
`@coffre/ui/routes`, all at once, `coffreRoutes(root)`, or one at a time.
`useCoffre()` gives an app's own page the API as the signed-in visitor.
React, TanStack Router, Start, Query and Vite are peers, pinned exactly:
the app has them at those versions, and its build stops when one differs.

Part of [coffre](https://github.com/erwinkn/coffre), a secrets manager you
deploy as a small project of your own. Its eight `@coffre/*` packages are
released together, at one version. MIT licensed.
