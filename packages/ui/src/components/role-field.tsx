import { useId, useState } from 'react';
import { INSTANCE_ROLE_NAMES, INSTANCE_ROLES, type Filter, type InstanceRole, type Scope } from '@coffre/core/access';
import type { RoleVars } from '../lib/changes';
import { useShell } from '../lib/use-shell';
import { slugProblem } from '../lib/validation';
import { X } from './icons';

/**
 * A person's instance role, one dropdown, and under it, for every role but
 * Member, where it applies: projects and environments, each All, Only or
 * All except. Projects are picked from those there are; environments are
 * names, so any slug goes, the ones made later too.
 */
export function RoleField({ value, onChange }: { value: RoleVars; onChange: (value: RoleVars) => void }) {
  const { role, scope } = value;
  return (
    <>
      <label className="field">
        <span className="label">Instance role</span>
        <select
          className="select"
          value={role}
          onChange={(event) => onChange({ role: event.target.value as InstanceRole, scope })}
        >
          {INSTANCE_ROLE_NAMES.map((name) => (
            <option key={name} value={name}>
              {INSTANCE_ROLES[name].name}
            </option>
          ))}
        </select>
        <span className="hint">
          {INSTANCE_ROLES[role].description}
          {role === 'member' ? '' : ' Project grants add to it.'}
        </span>
      </label>
      {role !== 'member' && <ScopeField scope={scope} onChange={(next) => onChange({ role, scope: next })} />}
    </>
  );
}

function ScopeField({ scope, onChange }: { scope: Scope; onChange: (scope: Scope) => void }) {
  const { projects } = useShell();
  const slugs = [...new Set(projects.flatMap((project) => project.environments.map((environment) => environment.slug)))].sort();
  return (
    <fieldset className="field scope-field">
      <legend className="label">Where</legend>
      <FilterRow
        label="Projects"
        filter={scope.projects}
        options={projects.map((project) => project.slug)}
        onChange={(filter) => onChange({ ...scope, projects: filter })}
      />
      <FilterRow
        label="Environments"
        filter={scope.environments}
        options={slugs}
        free
        onChange={(filter) => onChange({ ...scope, environments: filter })}
      />
      {scope.environments !== 'all' && <span className="hint">Environments match by name in every project, new ones included.</span>}
    </fieldset>
  );
}

type Mode = 'all' | 'only' | 'except';

const namesOf = (filter: Filter): string[] => (filter === 'all' ? [] : 'only' in filter ? filter.only : filter.except);

function filterOf(mode: Mode, names: string[]): Filter {
  return mode === 'all' ? 'all' : mode === 'only' ? { only: names } : { except: names };
}

/** One filter: All, Only or All except, and the names it lists. */
function FilterRow({
  label,
  filter,
  options,
  free = false,
  onChange,
}: {
  label: string;
  filter: Filter;
  options: string[];
  /** Whether a name need not be among `options`: an environment's slug, which may come later. */
  free?: boolean;
  onChange: (filter: Filter) => void;
}) {
  const mode: Mode = filter === 'all' ? 'all' : 'only' in filter ? 'only' : 'except';
  const names = namesOf(filter);
  return (
    <div className="scope-row">
      <span className="scope-label">{label}</span>
      <select
        className="select select-sm"
        aria-label={`${label}: which`}
        value={mode}
        onChange={(event) => onChange(filterOf(event.target.value as Mode, names))}
      >
        <option value="all">All</option>
        <option value="only">Only</option>
        <option value="except">All except</option>
      </select>
      {mode !== 'all' && (
        <NamePicker label={label} names={names} options={options} free={free} onChange={(next) => onChange(filterOf(mode, next))} />
      )}
    </div>
  );
}

/** Names as chips, and a field to add one: picked from the list, or, where any name goes, typed and entered. */
function NamePicker({
  label,
  names,
  options,
  free,
  onChange,
}: {
  label: string;
  names: string[];
  options: string[];
  free: boolean;
  onChange: (names: string[]) => void;
}) {
  const [draft, setDraft] = useState('');
  const list = useId();
  const add = (raw: string) => {
    const name = raw.trim();
    setDraft('');
    if (name === '' || names.includes(name)) return;
    if (free ? slugProblem(name) !== null : !options.includes(name)) return;
    onChange([...names, name]);
  };
  const offered = options.filter((option) => !names.includes(option));
  return (
    <span className="scope-names">
      {names.map((name) => (
        <span key={name} className="tag scope-chip">
          <span className="mono">{name}</span>
          <button type="button" aria-label={`Remove ${name}`} onClick={() => onChange(names.filter((other) => other !== name))}>
            <X size={11} />
          </button>
        </span>
      ))}
      <input
        className="input input-mono scope-input"
        list={list}
        value={draft}
        spellCheck={false}
        autoComplete="off"
        placeholder={names.length === 0 ? (free ? 'dev' : 'Pick a project') : 'Add'}
        aria-label={`Add to ${label}`}
        aria-invalid={draft !== '' && free && slugProblem(draft.trim()) !== null}
        onChange={(event) => {
          // A name picked from the list goes in at once; one typed, on Enter.
          if ((event.nativeEvent as InputEvent).inputType === 'insertReplacementText' || (!free && options.includes(event.target.value))) {
            add(event.target.value);
          } else {
            setDraft(event.target.value);
          }
        }}
        onKeyDown={(event) => {
          if (event.key === 'Enter' || event.key === ',') {
            event.preventDefault();
            add(draft);
          } else if (event.key === 'Backspace' && draft === '' && names.length > 0) {
            onChange(names.slice(0, -1));
          }
        }}
        onBlur={() => add(draft)}
      />
      <datalist id={list}>
        {offered.map((option) => (
          <option key={option} value={option} />
        ))}
      </datalist>
    </span>
  );
}
