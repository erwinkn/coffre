# @coffre/ui

coffre's web pages, as routes in code for a deployment's own TanStack Start
app, whose pages read only through `@coffre/client`; and `@coffre/ui/vite`,
the Vite plugin the app's build adds. `coffre init` writes such an app:

```tsx
// app/src/router.tsx
export const root = createRootRouteWithContext<CoffreContext>()({
  head: () => coffreHead(),
  shellComponent: ({ children }) => (
    <html lang="en" suppressHydrationWarning>
      <head><HeadContent /></head>
      <body><CoffreProvider>{children}</CoffreProvider><Scripts /></body>
    </html>
  ),
});
export const routeTree = root.addChildren([...coffreServerRoutes(root), ...coffreRoutes(root)]);
export const getRouter = () => createRouter(routeTree);

// app/vite.config.ts
plugins: [cloudflare({ viteEnvironment: { name: 'ssr' } }), tanstackStart({ router: { enableRouteGeneration: false } }), viteReact(), coffre()]
```

Each page and layout is also exported as a function of its parent, to mount
one by one, and `useCoffre()` gives an app's own page the API as the
signed-in visitor. React, TanStack Router, Start, Query and Vite are peers,
pinned exactly: the app has them at those versions, and its build stops
when one differs.

Part of [coffre](https://github.com/erwinkn/coffre), a secrets manager you
deploy as a small project of your own. Its eight `@coffre/*` packages are
released together, at one version. MIT licensed.
