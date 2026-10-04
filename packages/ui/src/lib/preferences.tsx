import { createContext, useContext, type RefObject } from 'react';

/**
 * How the visitor has coffre's pages drawn: the theme they chose, `system`
 * when none, which CSS follows (`prefers-color-scheme`), and whether the
 * sidebar is folded. Each is a cookie, so the server renders the page as
 * the visitor left it, from the first byte: coffre's middleware reads them
 * for each request, and the browser reads the same cookies to hydrate.
 */
export type Preferences = { theme: 'system' | 'light' | 'dark'; sidebar: 'expanded' | 'collapsed' };

export type Theme = Preferences['theme'];

const THEME = 'coffre-theme';
const SIDEBAR = 'coffre-sidebar';

/** The preferences in the browser's cookies, as the server read them in the request's. */
export function browserPreferences(): Preferences {
  const cookies = new Map(document.cookie.split('; ').map((pair) => [pair.slice(0, pair.indexOf('=')), pair.slice(pair.indexOf('=') + 1)]));
  const theme = cookies.get(THEME);
  return {
    theme: theme === 'light' || theme === 'dark' ? theme : 'system',
    sidebar: cookies.get(SIDEBAR) === 'collapsed' ? 'collapsed' : 'expanded',
  };
}

/** Keep a choice for a year; the default, by removing it. */
function remember(name: string, value: string | null) {
  document.cookie =
    value === null ? `${name}=; Path=/; SameSite=Lax; Max-Age=0` : `${name}=${value}; Path=/; SameSite=Lax; Max-Age=31536000`;
}

export function rememberTheme(theme: Theme) {
  remember(THEME, theme === 'system' ? null : theme);
}

export function rememberSidebar(sidebar: Preferences['sidebar']) {
  remember(SIDEBAR, sidebar === 'collapsed' ? 'collapsed' : null);
}

type PreferencesValue = Preferences & {
  setTheme(theme: Theme): void;
  setSidebar(sidebar: Preferences['sidebar']): void;
  /** coffre's element, which menus, dialogs and tooltips render into, so they are drawn in its theme. */
  portal: RefObject<HTMLDivElement | null>;
};

export const PreferencesContext = createContext<PreferencesValue | null>(null);

/** The visitor's preferences, and the switches, from `<CoffreProvider>`. */
export function usePreferences(): PreferencesValue {
  const value = useContext(PreferencesContext);
  if (value === null) throw new Error("coffre's pages render inside <CoffreProvider>, in the app's root document");
  return value;
}
