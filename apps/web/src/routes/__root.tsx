import type { ReactNode } from 'react';
import {
  createRootRoute,
  HeadContent,
  Outlet,
  redirect,
  ScriptOnce,
  Scripts,
  useRouterState,
} from '@tanstack/react-router';
import { Toaster } from 'sonner';
import globalsCss from '../styles/globals.css?url';
import { getShell } from '../server-functions/shell';
import { Brand, Shell, sidebarBootScript } from '../components/shell';
import { TooltipProvider } from '../components/ui';
import { ThemeToggle, themeBootScript } from '../components/theme';
import { Agentation } from '../components/agentation';
import { MARK_SVG } from '../components/icons';

export const Route = createRootRoute({
  head: () => ({
    meta: [
      { charSet: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { title: 'coffre' },
      { name: 'description', content: 'Secrets, with an audit log' },
    ],
    links: [
      { rel: 'stylesheet', href: globalsCss },
      // Inline, so the icon needs no route of its own: in Cloudflare mode
      // every path but the health checks is behind Access.
      { rel: 'icon', type: 'image/svg+xml', href: `data:image/svg+xml,${encodeURIComponent(MARK_SVG)}` },
    ],
  }),

  // Identity and the project tree, which the shell needs on every screen.
  loader: async ({ location }) => {
    const shell = await getShell();

    if (shell.registrationRequired && location.pathname !== '/unregistered') {
      throw redirect({ to: '/unregistered' });
    }

    // Signed out, the app has nothing to show. Letting it be browsed anyway
    // put a "you are not signed in" notice in the middle of every page, which
    // reads as a broken screen rather than as a closed door. Where they were
    // headed rides along so signing in resumes it.
    if (shell.principal === null && location.pathname !== '/login') {
      throw redirect({ to: '/login', search: { next: location.href } });
    }

    // `/login` is only an error boundary in Cloudflare mode and a persona
    // picker in dev mode. Once the API has authenticated the caller, neither
    // belongs on screen.
    if (shell.principal !== null && location.pathname === '/login') {
      throw redirect({ to: '/projects' });
    }
    if (
      shell.principal !== null &&
      !shell.registrationRequired &&
      location.pathname === '/unregistered'
    ) {
      throw redirect({ to: '/projects' });
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
        {/* Must run before first paint; see the comments on each script.
            ScriptOnce gives them the page's CSP nonce, and removes them
            once run so hydration finds nothing to reconcile. */}
        <ScriptOnce>{themeBootScript}</ScriptOnce>
        <ScriptOnce>{sidebarBootScript}</ScriptOnce>
      </head>
      <body>
        {children}
        <Scripts />
      </body>
    </html>
  );
}

function Toasts() {
  return (
    <Toaster
      position="bottom-right"
      gap={10}
      offset={20}
      toastOptions={{
        duration: 4200,
        unstyled: true,
        classNames: {
          toast: 'toast',
          title: 'toast-title',
          description: 'toast-description',
          actionButton: 'toast-action',
          success: 'toast-success',
          error: 'toast-error',
        },
      }}
    />
  );
}

function RootComponent() {
  const { principal, instanceRole, projects, capabilities } = Route.useLoaderData();
  const pathname = useRouterState({ select: (state) => state.location.pathname });

  // Sign-in gets no navigation. Every destination in the sidebar and the
  // command palette bounces straight back here while you are signed out, so
  // offering them is a loop dressed up as navigation. The brand stays, as a
  // mark rather than a link, so the page is still recognisably this app.
  // Approving a CLI sign-in is the same kind of single-purpose stop.
  if (pathname === '/login' || pathname === '/unregistered' || pathname === '/auth/device') {
    return (
      <TooltipProvider>
        <div className="solo">
          <div className="solo-top">
            <Brand />
            <ThemeToggle />
          </div>
          <main className="solo-main" id="content">
            <Outlet />
          </main>
        </div>
        <Toasts />
        <Agentation />
      </TooltipProvider>
    );
  }

  return (
    <TooltipProvider>
      <a className="skip-link" href="#content">
        Skip to content
      </a>

      <Shell
        projects={projects}
        principal={principal}
        instanceRole={instanceRole}
        capabilities={capabilities}
      >
        <Outlet />
      </Shell>

      <Toasts />
      <Agentation />
    </TooltipProvider>
  );
}
