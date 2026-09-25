import { useEffect, useState } from 'react';
import { Monitor, Moon, Sun } from './icons';

export type Theme = 'system' | 'light' | 'dark';

const STORAGE_KEY = 'coffre-theme';
const CHANGE_EVENT = 'coffre-theme-change';

/**
 * Applied before first paint, inlined in <head>.
 *
 * Without this the page renders in the system palette and then snaps to the
 * stored choice once React hydrates -- a full-screen flash on every load for
 * anyone who overrode it. Kept as a string so it runs synchronously; there is
 * no way to do this correctly from a component.
 */
export const themeBootScript = `(function(){try{var t=localStorage.getItem(${JSON.stringify(
  STORAGE_KEY,
)});if(t==="light"||t==="dark"){document.documentElement.setAttribute("data-theme",t)}}catch(e){}})()`;

function stored(): Theme {
  try {
    const value = localStorage.getItem(STORAGE_KEY);
    return value === 'light' || value === 'dark' ? value : 'system';
  } catch {
    return 'system';
  }
}

function apply(theme: Theme) {
  const root = document.documentElement;
  try {
    if (theme === 'system') localStorage.removeItem(STORAGE_KEY);
    else localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // Storage refused (private mode); the choice still holds for this page.
  }
  if (theme === 'system') root.removeAttribute('data-theme');
  else root.setAttribute('data-theme', theme);
  window.dispatchEvent(new CustomEvent(CHANGE_EVENT));
}

const OPTIONS: { value: Theme; label: string; Icon: typeof Sun }[] = [
  { value: 'system', label: 'Match system', Icon: Monitor },
  { value: 'light', label: 'Light', Icon: Sun },
  { value: 'dark', label: 'Dark', Icon: Moon },
];

/**
 * Three glyphs, one of them pressed. A menu for a three-way choice costs a
 * click to find out what the current value is.
 */
export function ThemeToggle() {
  // Server-rendered markup cannot know the stored preference, so it starts on
  // "system" and corrects itself on mount. Any other approach
  // hydration-mismatches.
  const [theme, setThemeState] = useState<Theme>('system');

  useEffect(() => {
    const sync = () => setThemeState(stored());
    sync();
    window.addEventListener(CHANGE_EVENT, sync);
    window.addEventListener('storage', sync);
    return () => {
      window.removeEventListener(CHANGE_EVENT, sync);
      window.removeEventListener('storage', sync);
    };
  }, []);

  return (
    <div className="theme-choice" role="group" aria-label="Colour scheme">
      {OPTIONS.map(({ value, label, Icon }) => (
        <button
          key={value}
          type="button"
          aria-pressed={theme === value}
          aria-label={label}
          title={label}
          onClick={() => apply(value)}
        >
          <Icon size={14} />
        </button>
      ))}
    </div>
  );
}

/** Imperative theme setter, so the command palette can offer the same options. */
export function setTheme(theme: Theme) {
  apply(theme);
}
