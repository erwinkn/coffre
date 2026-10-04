// The app's root: the document every page renders in, with coffre's
// stylesheet and icons in its head and the provider coffre's pages need in
// its body. Under it, src/router.tsx puts coffre's routes, and Start this
// app's own pages, the other files in src/routes.
import { createRootRouteWithContext, HeadContent, Scripts } from '@tanstack/react-router';
import { CoffreProvider, type CoffreContext } from '@coffre/ui';
import touchIcon from '@coffre/ui/apple-touch-icon.png?url';
import icon from '@coffre/ui/icon.svg?url';
import styles from '@coffre/ui/styles.css?url';

export const Route = createRootRouteWithContext<CoffreContext>()({
  head: () => ({
    meta: [{ charSet: 'utf-8' }, { name: 'viewport', content: 'width=device-width, initial-scale=1' }, { title: 'coffre' }],
    links: [
      { rel: 'stylesheet', href: styles },
      { rel: 'icon', type: 'image/svg+xml', href: icon },
      { rel: 'apple-touch-icon', href: touchIcon },
    ],
  }),
  shellComponent: ({ children }) => (
    <html lang="en">
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
