import type { ReactNode } from 'react';
import {
  createRootRoute,
  HeadContent,
  Outlet,
  redirect,
  Scripts,
  useRouterState,
} from '@tanstack/react-router';
import { Toaster } from 'sonner';
import globalsCss from '../styles/globals.css?url';
import { getShell } from '../lib/server';
import { Sidebar } from '../components/sidebar';
import { Breadcrumbs } from '../components/breadcrumbs';
import { CommandPalette } from '../components/command-palette';
import { TooltipProvider } from '../components/ui';
import { themeBootScript } from '../components/theme';
import { Agentation } from '../components/agentation';
import { Vault } from '../components/icons';

export const Route = createRootRoute({
  head: () => ({
    meta: [
      { charSet: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { title: 'coffre' },
      { name: 'description', content: 'Secrets, with an audit log' },
    ],
    links: [{ rel: 'stylesheet', href: globalsCss }],
  }),

  // Identity and the project tree, which the shell needs on every screen.
  loader: async ({ location }) => {
    const shell = await getShell();

    // Signed out, the app has nothing to show. Letting it be browsed anyway
    // put a "you are not signed in" notice in the middle of every page, which
    // reads as a broken screen rather than as a closed door. Where they were
    // headed rides along so signing in resumes it.
    if (shell.principal === null && location.pathname !== '/login') {
      throw redirect({ to: '/login', search: { next: location.href } });
    }

    return shell;
  },

  shellComponent: RootDocument,
  component: RootComponent,
});

function RootDocument({ children }: { children: ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <HeadContent />
        {/* Must run before first paint; see the comment on themeBootScript. */}
        <script dangerouslySetInnerHTML={{ __html: themeBootScript }} />
      </head>
      <body>
        {children}
        <Scripts />
      </body>
    </html>
  );
}

function RootComponent() {
  const { principal, projects } = Route.useLoaderData();
  const pathname = useRouterState({ select: (state) => state.location.pathname });

  // Sign-in gets no shell. Every destination in the sidebar, the breadcrumbs
  // and the command palette bounces straight back here while you are signed
  // out, so offering them is a loop dressed up as navigation. The brand stays,
  // as a mark rather than a link, so the page is still recognisably this app.
  if (pathname === '/login') {
    return (
      <TooltipProvider>
        <div className="solo">
          <p className="brand solo-brand">
            <Vault size={20} className="brand-mark" />
            coffre
          </p>
          <main className="content" id="content">
            <Outlet />
          </main>
        </div>

        <Toaster
          position="bottom-right"
          gap={10}
          offset={16}
          toastOptions={{ duration: 4200 }}
        />

        <Agentation />
      </TooltipProvider>
    );
  }

  return (
    <TooltipProvider>
      <a className="skip-link" href="#content">
        Skip to content
      </a>

      <div className="app">
        <Sidebar projects={projects} principal={principal} />

        <div className="main">
          <header className="topbar">
            <Breadcrumbs />
            <div style={{ marginLeft: 'auto' }}>
              <CommandPalette projects={projects} />
            </div>
          </header>

          <main className="content" id="content">
            <Outlet />
          </main>
        </div>
      </div>

      <Toaster
        position="bottom-right"
        gap={10}
        offset={16}
        toastOptions={{ duration: 4200 }}
      />

      <Agentation />
    </TooltipProvider>
  );
}
