import { useEffect, useState } from 'react';
import { DropdownMenu } from 'radix-ui';
import { Check, ChevronDown, Monitor, Moon, Sun } from './icons';

export type Theme = 'system' | 'light' | 'dark';

const STORAGE_KEY = 'coffre-theme';

/**
 * Applied before first paint, inlined in <head>.
 *
 * Without this the page renders in the default (dark) palette and then snaps to
 * light once React hydrates -- a full-screen flash on every navigation for
 * anyone who prefers light. Kept as a string so it runs synchronously; there is
 * no way to do this correctly from a component.
 */
export const themeBootScript = `(function(){try{var t=localStorage.getItem(${JSON.stringify(
  STORAGE_KEY,
)});if(t==="light"||t==="dark"){document.documentElement.setAttribute("data-theme",t)}}catch(e){}})()`;

function apply(theme: Theme) {
  const root = document.documentElement;
  if (theme === 'system') {
    root.removeAttribute('data-theme');
    localStorage.removeItem(STORAGE_KEY);
  } else {
    root.setAttribute('data-theme', theme);
    localStorage.setItem(STORAGE_KEY, theme);
  }
}

const OPTIONS: { value: Theme; label: string; Icon: typeof Sun }[] = [
  { value: 'system', label: 'System', Icon: Monitor },
  { value: 'light', label: 'Light', Icon: Sun },
  { value: 'dark', label: 'Dark', Icon: Moon },
];

export function ThemeToggle() {
  // Server-rendered markup cannot know the stored preference, so the trigger
  // starts on the neutral "system" icon and corrects itself on mount. Any other
  // approach hydration-mismatches.
  const [theme, setTheme] = useState<Theme>('system');

  useEffect(() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === 'light' || stored === 'dark') setTheme(stored);
  }, []);

  const current = OPTIONS.find((option) => option.value === theme) ?? OPTIONS[0];

  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button className="btn btn-quiet btn-sm" aria-label={`Theme: ${current.label}`}>
          <current.Icon size={15} />
          <ChevronDown size={12} />
        </button>
      </DropdownMenu.Trigger>

      <DropdownMenu.Portal>
        <DropdownMenu.Content className="menu" sideOffset={6} align="end">
          {OPTIONS.map(({ value, label, Icon }) => (
            <DropdownMenu.Item
              key={value}
              className="menu-item"
              onSelect={() => {
                setTheme(value);
                apply(value);
              }}
            >
              <Icon size={15} />
              {label}
              {theme === value && (
                <span className="menu-shortcut">
                  <Check size={13} />
                </span>
              )}
            </DropdownMenu.Item>
          ))}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

/** Imperative theme setter, so the command palette can offer the same options. */
export function setTheme(theme: Theme) {
  apply(theme);
}
