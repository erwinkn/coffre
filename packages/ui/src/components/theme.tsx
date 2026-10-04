import { Menu } from '@base-ui/react/menu';
import { usePreferences, type Theme } from '../lib/preferences';
import { Check, Monitor, Moon, Sun } from './icons';

const OPTIONS: { value: Theme; label: string; Icon: typeof Sun }[] = [
  { value: 'system', label: 'Match system', Icon: Monitor },
  { value: 'light', label: 'Light', Icon: Sun },
  { value: 'dark', label: 'Dark', Icon: Moon },
];

/** The theme as a radio group inside a dropdown menu (the account menu). */
export function ThemeMenuItems() {
  const { theme, setTheme } = usePreferences();
  return (
    <Menu.RadioGroup value={theme} onValueChange={(value: Theme) => setTheme(value)}>
      <Menu.GroupLabel className="menu-label">Theme</Menu.GroupLabel>
      {OPTIONS.map(({ value, label, Icon }) => (
        <Menu.RadioItem key={value} value={value} className="menu-item" closeOnClick>
          <Icon size={15} />
          {label}
          <Menu.RadioItemIndicator className="menu-check">
            <Check size={14} />
          </Menu.RadioItemIndicator>
        </Menu.RadioItem>
      ))}
    </Menu.RadioGroup>
  );
}

/**
 * Three glyphs, one of them pressed, for pages without the account menu.
 * A menu for a three-way choice costs a click to find out the current value.
 */
export function ThemeToggle() {
  const { theme, setTheme } = usePreferences();

  return (
    <div className="theme-choice" role="group" aria-label="Colour scheme">
      {OPTIONS.map(({ value, label, Icon }) => (
        <button
          key={value}
          type="button"
          aria-pressed={theme === value}
          aria-label={label}
          title={label}
          onClick={() => setTheme(value)}
        >
          <Icon size={14} />
        </button>
      ))}
    </div>
  );
}

/** The theme as three large choices, for the Settings page. */
export function ThemeCards() {
  const { theme, setTheme } = usePreferences();
  return (
    <div className="choice-grid" role="group" aria-label="Colour scheme">
      {OPTIONS.map(({ value, label, Icon }) => (
        <button
          key={value}
          type="button"
          className="choice"
          aria-pressed={theme === value}
          onClick={() => setTheme(value)}
        >
          <Icon size={16} />
          {label}
        </button>
      ))}
    </div>
  );
}
