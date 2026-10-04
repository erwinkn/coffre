// The root of `pnpm dev`'s app: examples/workers', and the Agentation
// toolbar, for annotating the pages in development.
import { createRootRouteWithContext, HeadContent, Scripts } from '@tanstack/react-router';
import { CoffreProvider, type CoffreContext } from '@coffre/ui';

import { Agentation } from '../agentation';
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
        <Agentation />
        <Scripts />
      </body>
    </html>
  ),
});
