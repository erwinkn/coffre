import { createContext, useContext, type RefObject } from 'react';

import { PREFERENCE_COOKIES, preferencesIn, type Preferences } from '@coffre/core/pages';

export type { Preferences };

export type Theme = Preferences['theme'];

/**
 * The preferences in the browser's cookies, as the server read them in the
 * request's: each is a cookie, so the server renders the page as the
 * visitor left it, from the first byte, and the browser hydrates the same.
 */
export function browserPreferences(): Preferences {
  return preferencesIn(document.cookie);
}

/** Keep a choice for a year; the default, by removing it. */
function remember(name: string, value: string | null) {
  document.cookie =
    value === null ? `${name}=; Path=/; SameSite=Lax; Max-Age=0` : `${name}=${value}; Path=/; SameSite=Lax; Max-Age=31536000`;
}

export function rememberTheme(theme: Theme) {
  remember(PREFERENCE_COOKIES.theme, theme === 'system' ? null : theme);
}

export function rememberSidebar(sidebar: Preferences['sidebar']) {
  remember(PREFERENCE_COOKIES.sidebar, sidebar === 'collapsed' ? 'collapsed' : null);
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
