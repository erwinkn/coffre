// What coffre's pages render in: the provider the deployment's document puts
// them in; the shell, coffre's nav, for signed-in pages; and the solo frame
// of the sign-in pages. The routes that render the two are in routes.ts.
import { useMemo, useRef, useState, type ReactNode } from 'react';
import { Outlet, useRouter } from '@tanstack/react-router';
import { Toaster } from 'sonner';
import { Brand, Shell } from './components/shell';
import { TooltipProvider } from './components/ui';
import { ThemeToggle } from './components/theme';
import { PreferencesContext, rememberSidebar, rememberTheme, type Preferences, type Theme } from './lib/preferences';
import type { RouterContext } from './router';
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
 * coffre's element, drawn in the visitor's theme, its sidebar folded or not,
 * as their cookies say, from the first byte: the server and the browser
 * both render it from them, so nothing waits for a script. Tooltips, toasts
 * and the live region, which the deployment's own pages may use too. The
 * query client comes with the router (`createRouter`).
 */
export function CoffreProvider({ children }: { children: ReactNode }) {
  const initial = (useRouter().options.context as RouterContext).preferences;
  const [theme, setThemeState] = useState(initial.theme);
  const [sidebar, setSidebarState] = useState(initial.sidebar);
  const portal = useRef<HTMLDivElement>(null);
  const preferences = useMemo(
    () => ({
      theme,
      sidebar,
      setTheme: (next: Theme) => {
        rememberTheme(next);
        setThemeState(next);
      },
      setSidebar: (next: Preferences['sidebar']) => {
        rememberSidebar(next);
        setSidebarState(next);
      },
      portal,
    }),
    [theme, sidebar],
  );
  return (
    <PreferencesContext.Provider value={preferences}>
      <div
        ref={portal}
        className="coffre"
        data-theme={theme === 'system' ? undefined : theme}
        data-sidebar={sidebar === 'collapsed' ? 'collapsed' : undefined}
      >
        <TooltipProvider>
          {children}
          <Toasts />
          <LiveRegion />
        </TooltipProvider>
      </div>
    </PreferencesContext.Provider>
  );
}

/** coffre's shell: the nav, around the signed-in pages. */
export function ShellLayout() {
  const { principal, instanceRole, projects, capabilities } = useShell();
  return (
    <>
      <a className="skip-link" href="#content">
        Skip to content
      </a>
      <Shell projects={projects} principal={principal} instanceRole={instanceRole} capabilities={capabilities}>
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
