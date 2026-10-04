// What coffre's pages render in: the provider the deployment's document puts
// them in; the shell, coffre's nav, for signed-in pages; and the solo frame
// of the sign-in pages. The routes that render the two are in routes.ts.
import type { ReactNode } from 'react';
import { Outlet, ScriptOnce } from '@tanstack/react-router';
import { Toaster } from 'sonner';
import { Brand, Shell, sidebarBootScript } from './components/shell';
import { TooltipProvider } from './components/ui';
import { ThemeToggle, themeBootScript } from './components/theme';
import { Agentation } from './components/agentation';
import { LiveRegion } from './components/row-state';
import { useShell } from './lib/use-shell';

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

/**
 * What coffre's pages need around them, for the deployment's document to put
 * in its body: `<body><CoffreProvider>{children}</CoffreProvider><Scripts /></body>`.
 * The theme and the sidebar's width, set before anything paints; tooltips,
 * toasts and the live region, which the deployment's own pages may use too.
 * The query client comes with the router (`createRouter`).
 */
export function CoffreProvider({ children }: { children: ReactNode }) {
  return (
    <>
      {/* First in the body, so they run before anything in it paints.
          ScriptOnce gives them the page's CSP nonce, and removes them once
          run, so hydration finds nothing to reconcile. They are not in
          coffreHead(): the router re-adds a head script it cannot find by its
          nonce, which browsers hide, and so without one, which the CSP refuses. */}
      <ScriptOnce>{themeBootScript}</ScriptOnce>
      <ScriptOnce>{sidebarBootScript}</ScriptOnce>
      <TooltipProvider>
        {children}
        <Toasts />
        <LiveRegion />
        <Agentation />
      </TooltipProvider>
    </>
  );
}

/** coffre's shell: the nav, around the signed-in pages. */
export function ShellLayout() {
  const { principal, instanceRole, projects, capabilities, instance } = useShell();
  return (
    <>
      <a className="skip-link" href="#content">
        Skip to content
      </a>
      <Shell projects={projects} principal={principal} instanceRole={instanceRole} capabilities={capabilities} instance={instance}>
        <Outlet />
      </Shell>
    </>
  );
}

/** The sign-in pages' frame: coffre's mark and the theme, nothing else. */
export function SoloLayout() {
  return (
    <div className="solo">
      <div className="solo-top">
        <Brand />
        <ThemeToggle />
      </div>
      <main className="solo-main" id="content">
        <Outlet />
      </main>
    </div>
  );
}
