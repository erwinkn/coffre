// What coffre's server and its pages agree on outside the API: the
// visitor's preferences, which the server reads from a request's cookies
// and the browser from its own, to draw the same page; the names a
// project's pages take, which no environment may; and what either says
// when coffre's request middleware is missing.

/**
 * How the visitor has coffre's pages drawn: the theme they chose, `system`
 * when none, and whether the sidebar is folded.
 */
export type Preferences = { theme: 'system' | 'light' | 'dark'; sidebar: 'expanded' | 'collapsed' };

/** The cookies that hold them. */
export const PREFERENCE_COOKIES = { theme: 'coffre-theme', sidebar: 'coffre-sidebar' } as const;

/**
 * A project's pages beside its environments': `/projects/market/settings`
 * sits where `/projects/market/prod` does, so no environment takes one of
 * these names (`environmentSlug` in `./schemas.ts`). A tab a project gains
 * adds its word here.
 */
export const PROJECT_PAGES = ['users', 'service-accounts', 'settings'] as const;

/** The preferences in a `Cookie` header, or in `document.cookie`, which reads the same. */
export function preferencesIn(cookies: string | null): Preferences {
  const value = (name: string) => {
    for (const pair of (cookies ?? '').split(';')) {
      const at = pair.indexOf('=');
      if (at !== -1 && pair.slice(0, at).trim() === name) return pair.slice(at + 1).trim();
    }
    return undefined;
  };
  const theme = value(PREFERENCE_COOKIES.theme);
  return {
    theme: theme === 'light' || theme === 'dark' ? theme : 'system',
    sidebar: value(PREFERENCE_COOKIES.sidebar) === 'collapsed' ? 'collapsed' : 'expanded',
  };
}

/** What a server route or a page says, rendered without coffre's request middleware. */
export const NO_MIDDLEWARE =
  "coffre's request middleware is not installed: add coffreMiddleware, from @coffre/server/start, to " +
  "createStart(() => ({ requestMiddleware: [coffreMiddleware] })) in the app's src/start.ts";
