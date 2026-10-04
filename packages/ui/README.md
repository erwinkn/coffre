# @coffre/ui

coffre's web pages, for a deployment's own TanStack Start app: the router,
whose pages read only through `@coffre/client`, and `@coffre/ui/vite`, the
Vite plugin the app's build adds. `coffre init` writes such an app:

```ts
// app/src/router.tsx
export { getRouter } from '@coffre/ui';

// app/vite.config.ts
plugins: [cloudflare({ viteEnvironment: { name: 'ssr' } }), tanstackStart(), viteReact(), coffre()]
```

and `@coffre/server` wraps Start's handler, which renders them. React,
TanStack Router, Start, Query and Vite are peers, pinned exactly: the app
has them at those versions, and its build stops when one differs.

Part of [coffre](https://github.com/erwinkn/coffre), a secrets manager you
deploy as a small project of your own. Its eight `@coffre/*` packages are
released together, at one version. MIT licensed.
