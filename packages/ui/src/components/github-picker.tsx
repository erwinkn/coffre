import { Autocomplete } from '@base-ui/react/autocomplete';
import { useId, useState } from 'react';
import { usePreferences } from '../lib/preferences';

/** The most the list shows at once: typing narrows it. */
const LIMIT = 50;

/** A name the deployment's GitHub App lists: a repository, `acme/api`, or an account it is installed on, `acme`. */
export type Listed = { name: string; private?: boolean };

/**
 * The Trust dialog's repository or organization field, offering what the
 * deployment's GitHub App is installed on as the name is typed. It stays a
 * text field: a name the list lacks is typed whole, and looked up as
 * without the app. With nothing to offer (`options` null: no app, or its
 * list not there yet) its list never opens, and it is the same input
 * either way, so that the list arriving mid-word moves neither focus nor
 * caret. Base UI's autocomplete does the keyboard and ARIA: Down Arrow
 * opens the list, arrows move through it, Enter takes one, Escape closes
 * it.
 */
export function GitHubPicker({
  label,
  value,
  onChange,
  onPick,
  onBlur,
  options,
  placeholder,
  empty,
}: {
  label: string;
  value: string;
  /** The name as typed. */
  onChange: (value: string) => void;
  /** A name taken from the list: its IDs are the list's. */
  onPick: (value: string) => void;
  onBlur: () => void;
  options: readonly Listed[] | null;
  placeholder?: string;
  /** Said in the list when nothing matches the name typed. */
  empty: string;
}) {
  const { portal } = usePreferences();
  const id = useId();
  const labelId = useId();
  const [open, setOpen] = useState(false);
  const hidden = new Set((options ?? []).filter((option) => option.private === true).map((option) => option.name));
  return (
    <Autocomplete.Root
      items={(options ?? []).map((option) => option.name)}
      value={value}
      onValueChange={(next, details) => (details.reason === 'item-press' ? onPick(next) : onChange(next))}
      open={open && options !== null}
      onOpenChange={setOpen}
      openOnInputClick
      limit={LIMIT}
    >
      <div className="field">
        {/* Named by id: Base UI hides what lies beside its input while the list is open. */}
        <label className="label" id={labelId} htmlFor={id}>
          {label}
        </label>
        <Autocomplete.Input id={id} aria-labelledby={labelId} className="input mono" placeholder={placeholder} spellCheck={false} onBlur={onBlur} />
      </div>
      <Autocomplete.Portal container={portal}>
        <Autocomplete.Positioner className="menu-positioner" sideOffset={4} align="start">
          <Autocomplete.Popup className="menu combo-popup">
            <Autocomplete.Empty className="combo-empty">{empty}</Autocomplete.Empty>
            <Autocomplete.List>
              {(name: string) => (
                <Autocomplete.Item key={name} value={name} className="menu-item mono">
                  <span className="combo-option">{name}</span>
                  {hidden.has(name) && <span className="tag">private</span>}
                </Autocomplete.Item>
              )}
            </Autocomplete.List>
          </Autocomplete.Popup>
        </Autocomplete.Positioner>
      </Autocomplete.Portal>
    </Autocomplete.Root>
  );
}
