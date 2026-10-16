import { Combobox } from '@base-ui/react/combobox';
import { useId, type ReactNode } from 'react';
import { usePreferences } from '../lib/preferences';
import { Check, X } from './icons';

/**
 * Several of a fixed list, chosen by typing: each chosen one a chip in the
 * field, the rest offered below as the text filters them. Base UI's
 * combobox does the keyboard and ARIA: arrows move through the options,
 * Enter takes one, Backspace in an empty field removes the last chip, and
 * Left Arrow from the start of the field walks the chips.
 *
 * The value keeps the options' order, whatever order they were chosen in.
 */
export function MultiCombobox({
  label,
  options,
  value,
  onChange,
  placeholder,
  hint,
  note,
  mono = false,
}: {
  label: ReactNode;
  options: readonly string[];
  value: string[];
  onChange: (value: string[]) => void;
  placeholder?: string;
  hint?: ReactNode;
  /** A word beside an option in the list, such as what choosing it exposes. */
  note?: (option: string) => ReactNode;
  mono?: boolean;
}) {
  const { portal } = usePreferences();
  const id = useId();
  const hintId = useId();
  return (
    <Combobox.Root items={options} multiple value={value} onValueChange={(next) => onChange(options.filter((option) => next.includes(option)))}>
      <div className="field">
        <label className="label" htmlFor={id}>
          {label}
        </label>
        <Combobox.InputGroup className={`combo${mono ? ' combo-mono' : ''}`}>
          <Combobox.Chips className="combo-chips" aria-label={value.length > 0 ? 'Chosen' : undefined}>
            {value.map((option) => (
              <Combobox.Chip key={option} className="combo-chip" aria-label={option} aria-description="Press Backspace or Delete to remove">
                {option}
                <Combobox.ChipRemove className="combo-chip-remove" aria-label={`Remove ${option}`}>
                  <X size={12} />
                </Combobox.ChipRemove>
              </Combobox.Chip>
            ))}
            <Combobox.Input
              id={id}
              className="combo-input"
              placeholder={value.length > 0 ? undefined : placeholder}
              aria-describedby={hint === undefined ? undefined : hintId}
              aria-description={value.length > 0 ? `${value.length} chosen. From the start of the field, press Left Arrow to reach them` : undefined}
            />
          </Combobox.Chips>
        </Combobox.InputGroup>
        {hint !== undefined && (
          <span className="hint" id={hintId}>
            {hint}
          </span>
        )}
      </div>
      <Combobox.Portal container={portal}>
        <Combobox.Positioner className="menu-positioner" sideOffset={4} align="start">
          <Combobox.Popup className="menu combo-popup">
            <Combobox.Empty className="combo-empty">Nothing matches.</Combobox.Empty>
            <Combobox.List>
              {(option: string) => (
                <Combobox.Item key={option} value={option} className={`menu-item${mono ? ' mono' : ''}`}>
                  <span className="combo-check">
                    <Combobox.ItemIndicator>
                      <Check size={14} />
                    </Combobox.ItemIndicator>
                  </span>
                  <span className="combo-option">{option}</span>
                  {note?.(option)}
                </Combobox.Item>
              )}
            </Combobox.List>
          </Combobox.Popup>
        </Combobox.Positioner>
      </Combobox.Portal>
    </Combobox.Root>
  );
}
