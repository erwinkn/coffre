// What the Proxy tab is made of (W260, a prototype, DO NOT MERGE): the
// page's pending edits, saved or discarded all at once; the fields, each
// folding its controls into one input; and the bar, the review and the copy
// dialogs. `lib/proxy-prototype.ts` holds the rules.
import { useRef, useState, type ReactNode } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Menu } from '@base-ui/react/menu';
import { toast } from 'sonner';

import {
  definitionOf,
  definitionProblems,
  diffOf,
  KIND_LABELS,
  keysOf,
  METHODS,
  normalized,
  proxyKey,
  proxyQuery,
  sameDefinition,
  templateParts,
  transportRefusal,
  unreadable,
  type ItemKind,
  type Problems,
  type ProxyChange,
  type ProxyConfig,
  type ProxyCredential,
  type ProxyDefinition,
  type ProxyPlace,
  type ProxyStore,
  type ProxyTransport,
} from '../lib/proxy-prototype';
import { isActiveAccessibleEnvironment } from '../lib/project-environments';
import { useShell } from '../lib/use-shell';
import type { SecretKey } from '../shared/models';
import { AlertCircle, Check, ChevronDown, CopyFrom, Lock, Plus } from './icons';
import { EmptyState, MenuPopup, Modal, Spinner, Toggletip } from './ui';

// --- the edits ---------------------------------------------------------------------------

export type RowState = 'same' | 'changed' | 'added' | 'deleted';

/** One item as the page shows it: as stored, or as edited and not yet saved. */
export type Row = {
  id: string;
  /** As stored; null for one added here. */
  credential: ProxyCredential | null;
  before: ProxyDefinition | null;
  definition: ProxyDefinition;
  state: RowState;
  /** Whether its fields take edits: the environment's own, for whoever holds `proxy.edit`. */
  editable: boolean;
  /** The keys it sends which the editor may not send elsewhere: where it sends them stays as it is. */
  locked: string[];
  /** The sensitive keys a change routes, which an Owner may, audited. */
  routed: string[];
  /** What is wrong with it, once a save was tried. */
  problems: Problems;
};

export type Edits = ReturnType<typeof useProxyEdits>;

export function useProxyEdits({
  store,
  place,
  config,
  keys,
  canEdit,
}: {
  store: ProxyStore;
  place: ProxyPlace;
  config: ProxyConfig;
  keys: readonly SecretKey[];
  /** `proxy.edit`, which the mock gives Owners covering the place, who also route sensitive keys. */
  canEdit: boolean;
}) {
  const queryClient = useQueryClient();
  // Each edited item, by id: a stored item's name (`:code` for the code's), or `new-N`; null marks one to delete.
  const [drafts, setDrafts] = useState<Record<string, ProxyDefinition | null>>({});
  const [added, setAdded] = useState<string[]>([]);
  const [tried, setTried] = useState(false);
  const [reviewing, setReviewing] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const next = useRef(0);

  const code = config.credentials.filter((one) => one.source === 'code').map((one) => one.name);
  const base = [
    ...config.credentials.map((credential) => {
      const id = credential.name + (credential.source === 'code' ? ':code' : '');
      const before = definitionOf(credential);
      const draft = drafts[id];
      const definition = draft ?? before;
      const own = credential.source === 'environment';
      // Locked: a key the editor cannot read, and may not route as an Owner routes a sensitive one.
      const locked = own ? unreadable(keysOf(before), keys).filter((one) => !(one.sensitive && canEdit)).map((one) => one.key) : [];
      const state: RowState = draft === null ? 'deleted' : draft !== undefined && !sameDefinition(draft, before) ? 'changed' : 'same';
      return { id, credential, before, definition, state, editable: own && canEdit, locked };
    }),
    ...added.map((id) => ({ id, credential: null, before: null, definition: drafts[id]!, state: 'added' as RowState, editable: true, locked: [] })),
  ];
  const checkOf = (row: (typeof base)[number]) => {
    const others = base.filter((one) => one.id !== row.id && one.state !== 'deleted' && one.credential?.source !== 'code').map((one) => one.definition.name.trim());
    return definitionProblems(row.definition, { place, keys, owner: canEdit, code, others, egresses: config.egresses, networks: config.networks, before: row.before });
  };
  const rows: Row[] = base.map((row) => {
    if (row.state !== 'changed' && row.state !== 'added') return { ...row, problems: {}, routed: [] };
    const { problems, routed } = checkOf(row);
    return { ...row, problems: tried ? problems : {}, routed };
  });

  const counts = {
    added: rows.filter((row) => row.state === 'added').length,
    updated: rows.filter((row) => row.state === 'changed').length,
    deleted: rows.filter((row) => row.state === 'deleted').length,
  };
  const changed = counts.added + counts.updated + counts.deleted;

  const reset = () => {
    setDrafts({});
    setAdded([]);
    setTried(false);
    setReviewing(false);
    setError(null);
  };

  /** The changes, deletions first: a name one frees is free for the next. */
  const changes = (): { change: ProxyChange; row: Row }[] =>
    (['deleted', 'changed', 'added'] as const).flatMap((state) =>
      rows
        .filter((row) => row.state === state)
        .map((row) => ({ row, change: { was: row.credential?.name ?? null, definition: state === 'deleted' ? null : normalized(row.definition) } })),
    );

  return {
    rows,
    counts,
    changed,
    tried,
    faulty: rows.filter((row) => Object.keys(row.problems).length > 0),
    reviewing,
    pending,
    error,
    changes,
    /** Change an item: the first change opens it. */
    patch: (row: Row, change: (definition: ProxyDefinition) => ProxyDefinition) =>
      setDrafts((current) => ({ ...current, [row.id]: change(current[row.id] ?? row.definition) })),
    add: (definitions: ProxyDefinition[]) => {
      const ids = definitions.map(() => `new-${next.current++}`);
      setDrafts((current) => ({ ...current, ...Object.fromEntries(ids.map((id, index) => [id, definitions[index]!])) }));
      setAdded((current) => [...current, ...ids]);
      return ids;
    },
    remove: (row: Row) => {
      if (row.state === 'added') {
        setAdded((current) => current.filter((id) => id !== row.id));
        setDrafts(({ [row.id]: _, ...rest }) => rest);
      } else setDrafts((current) => ({ ...current, [row.id]: null }));
    },
    restore: (row: Row) => setDrafts(({ [row.id]: _, ...rest }) => rest),
    discard: reset,
    /** Save: what is wrong shows now, under its fields; else the review. */
    save: () => {
      setTried(true);
      setError(null);
      const wrong = base.some((row) => (row.state === 'changed' || row.state === 'added') && Object.keys(checkOf(row).problems).length > 0);
      if (!wrong && changed > 0) setReviewing(true);
    },
    closeReview: () => setReviewing(false),
    confirm: async () => {
      setPending(true);
      setError(null);
      try {
        queryClient.setQueryData(proxyKey(place), await store.write(place, changes().map((one) => one.change)));
        toast.success(`Saved: ${countsInWords(counts)}`);
        reset();
      } catch (failure) {
        setError(failure instanceof Error ? failure.message : 'The changes could not be saved.');
      } finally {
        setPending(false);
      }
    },
  };
}

/** "2 added, 1 updated": the pending changes, counted. */
export function countsInWords(counts: { added: number; updated: number; deleted: number }): string {
  const parts = [counts.added > 0 && `${counts.added} added`, counts.updated > 0 && `${counts.updated} updated`, counts.deleted > 0 && `${counts.deleted} deleted`].filter(
    (part) => part !== false,
  );
  return parts.length === 0 ? 'No changes' : parts.join(', ');
}

/** The foot of the page while anything changed: the changes counted, Discard and Save, for all of them at once. */
export function PendingBar({ edits }: { edits: Edits }) {
  if (edits.changed === 0) return null;
  const faulty = edits.faulty.length;
  return (
    <div className="pending-bar proxy-bar" role="region" aria-label="Unsaved changes">
      <span className="pending-count">
        <span className="dot" aria-hidden />
        {countsInWords(edits.counts)}
      </span>
      <span className="pending-summary" />
      <div className="pending-actions">
        <button className="btn btn-sm" type="button" onClick={edits.discard}>
          Discard
        </button>
        <button className="btn btn-sm btn-primary" type="button" onClick={edits.save}>
          Save
        </button>
      </div>
      {edits.tried && faulty > 0 && (
        <p className="pending-error" role="alert">
          <AlertCircle size={14} />
          <span>{faulty === 1 ? `${edits.faulty[0]!.definition.name || 'A new item'} needs fixing.` : `${faulty} items need fixing.`}</span>
        </p>
      )}
    </div>
  );
}

/** A note under a field: a problem in red, or what a change does in amber. */
export function Note({ tone = 'error', children }: { tone?: 'error' | 'warn'; children: ReactNode }) {
  return (
    <p className={`proxy-note${tone === 'error' ? ' proxy-note-error' : ''}`}>
      {tone === 'error' ? <AlertCircle size={12} /> : <Lock size={12} />}
      <span>{children}</span>
    </p>
  );
}

/** What today's proxy cannot do, which 0.16's backend change brings. */
export function Needs016({ what }: { what: string }) {
  return (
    <Toggletip label={`${what} need a backend change, in 0.16.`}>
      <button type="button" className="tag tag-outline tag-button">
        0.16
      </button>
    </Toggletip>
  );
}

// --- showing ---------------------------------------------------------------------------------

export function KindTag({ kind }: { kind: ItemKind }) {
  return <span className={`tag proxy-kind proxy-kind-${kind}`}>{KIND_LABELS[kind]}</span>;
}

/** Where a code item serves: every environment, or those it names. */
export const scopeInWords = (credential: ProxyCredential) =>
  credential.environments === null ? 'code · every environment' : `code · ${credential.environments.join(', ')} only`;

/** What a code item's lock says: that the code defines it, and where it serves. */
export const lockedByCodeInWords = (credential: ProxyCredential) =>
  `Defined in code, ${credential.environments === null ? 'for every environment' : `for ${credential.environments.join(', ')} only`}. Change it there: its name hides any of this environment's own.`;

/** Fields folded into one: text, selects and buttons inside its border, which focus lights as a whole. */
export function Fold({ invalid, className, children }: { invalid?: boolean; className?: string; children: ReactNode }) {
  return <div className={`fold${invalid === true ? ' is-invalid' : ''}${className === undefined ? '' : ` ${className}`}`}>{children}</div>;
}

/**
 * A template's input: each `{KEY}` it names marked in place (one the
 * environment lacks in red, one the editor cannot read in amber), and
 * typing `{` lists the environment's keys, which arrows and Enter pick.
 */
export function TemplateInput({
  value,
  keys,
  label,
  placeholder,
  disabled,
  onChange,
}: {
  value: string;
  keys: readonly SecretKey[];
  label: string;
  placeholder?: string;
  disabled: boolean;
  onChange: (value: string) => void;
}) {
  const input = useRef<HTMLInputElement>(null);
  const [caret, setCaret] = useState<number | null>(null);
  const [scroll, setScroll] = useState(0);
  const [active, setActive] = useState(0);
  const typed = caret === null ? null : (/\{([A-Za-z0-9_]*)$/.exec(value.slice(0, caret))?.[1] ?? null);
  const options = typed === null ? [] : keys.filter((entry) => entry.key.toLowerCase().includes(typed.toLowerCase()));
  const open = !disabled && options.length > 0;

  const track = () => {
    const element = input.current;
    if (element === null) return;
    setCaret(element.selectionStart);
    setScroll(element.scrollLeft);
  };
  const pick = (key: string) => {
    if (caret === null || typed === null) return;
    const start = caret - typed.length;
    const rest = value.slice(caret).replace(/^[A-Za-z0-9_]*\}?/, '');
    const at = start + key.length + 1;
    onChange(`${value.slice(0, start)}${key}}${rest}`);
    setCaret(null);
    requestAnimationFrame(() => {
      input.current?.setSelectionRange(at, at);
      track();
    });
  };

  return (
    <div className="tpl">
      <div className="tpl-clip" aria-hidden>
        <div className="tpl-mirror mono" style={{ transform: `translateX(${-scroll}px)` }}>
          {value === '' ? (
            <span className="tpl-placeholder">{placeholder}</span>
          ) : (
            templateParts(value).map((part, index) => ('key' in part ? <Token key={index} name={part.key} keys={keys} /> : <span key={index}>{part.text}</span>))
          )}
        </div>
      </div>
      <input
        ref={input}
        className="fold-input tpl-input mono"
        aria-label={label}
        aria-autocomplete="list"
        aria-expanded={open}
        value={value}
        disabled={disabled}
        spellCheck={false}
        autoComplete="off"
        onChange={(event) => {
          onChange(event.target.value);
          setActive(0);
          requestAnimationFrame(track);
        }}
        onSelect={track}
        onScroll={track}
        onBlur={() => setCaret(null)}
        onKeyDown={(event) => {
          if (!open) return;
          if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
            event.preventDefault();
            setActive((current) => (current + (event.key === 'ArrowDown' ? 1 : options.length - 1)) % options.length);
          } else if (event.key === 'Enter' || event.key === 'Tab') {
            event.preventDefault();
            pick(options[Math.min(active, options.length - 1)]!.key);
          } else if (event.key === 'Escape') {
            event.preventDefault();
            setCaret(null);
          }
        }}
      />
      {open && (
        <ul className="menu tpl-options" role="listbox" aria-label="Keys">
          {options.map((entry, index) => (
            <li
              key={entry.key}
              role="option"
              aria-selected={index === active}
              className={`menu-item mono${index === active ? ' is-active' : ''}`}
              onMouseDown={(event) => {
                event.preventDefault();
                pick(entry.key);
              }}
            >
              {entry.key}
              {!entry.readable && (
                <span className="menu-hint">
                  <Lock size={11} />
                  {entry.sensitivity === 'sensitive' ? 'sensitive' : "can't read"}
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** A `{KEY}` inside a template's input, as wide as its text: the environment lacks it, or the editor cannot read it. */
function Token({ name, keys }: { name: string; keys: readonly SecretKey[] }) {
  const entry = keys.find((one) => one.key === name);
  const tone = entry === undefined ? 'tpl-missing' : !entry.readable ? 'tpl-locked' : 'tpl-key';
  return <span className={tone}>{`{${name}}`}</span>;
}

/** One of the environment's keys, for a field that names a key alone. */
export function KeySelect({
  value,
  keys,
  label,
  disabled,
  optional = false,
  className = 'fold-select mono',
  onChange,
}: {
  value: string;
  keys: readonly SecretKey[];
  label: string;
  disabled: boolean;
  optional?: boolean;
  className?: string;
  onChange: (key: string) => void;
}) {
  const known = value === '' || keys.some((entry) => entry.key === value);
  return (
    <select className={className} aria-label={label} value={value} disabled={disabled} onChange={(event) => onChange(event.target.value)}>
      <option value="">{optional ? 'None' : 'Pick a key'}</option>
      {!known && <option value={value}>{value} (not here)</option>}
      {keys.map((entry) => (
        <option key={entry.key} value={entry.key}>
          {entry.key}
          {entry.sensitivity === 'sensitive' ? ' (sensitive)' : !entry.readable ? " (can't read)" : ''}
        </option>
      ))}
    </select>
  );
}

/** Direct, or a transport the code declares: one that names hosts greys out for an address it does not reach. */
export function TransportSelect({
  value,
  transports,
  address,
  label,
  disabled,
  onChange,
}: {
  value: string | null;
  transports: readonly ProxyTransport[];
  address: string | null;
  label: string;
  disabled: boolean;
  onChange: (name: string | null) => void;
}) {
  return (
    <select className="fold-select fold-end" aria-label={label} value={value ?? ''} disabled={disabled} onChange={(event) => onChange(event.target.value === '' ? null : event.target.value)}>
      <option value="">Direct</option>
      {transports.map((transport) => (
        <option key={transport.name} value={transport.name} disabled={address !== null && transportRefusal(transport, address) !== null && transport.name !== value} title={transport.description ?? undefined}>
          {transport.name}
        </option>
      ))}
    </select>
  );
}

/** Methods, as a menu at the start of an allow entry: none picked takes any. */
export function MethodsMenu({ methods, disabled, onChange }: { methods: string[]; disabled: boolean; onChange: (methods: string[]) => void }) {
  const picked = METHODS.filter((method) => methods.includes(method));
  const all = picked.join(' ');
  // The trigger is one width: what does not fit becomes the first method and a count.
  const shown = picked.length === 0 ? 'Any' : all.length <= 9 ? all : `${picked[0]} +${picked.length - 1}`;
  return (
    <Menu.Root>
      <Menu.Trigger className="fold-select fold-lead fold-kind fold-menu" aria-label="Methods" title={all === '' ? undefined : all} disabled={disabled}>
        <span className="fold-menu-text">{shown}</span>
      </Menu.Trigger>
      <MenuPopup align="start">
        {METHODS.map((method) => (
          <Menu.CheckboxItem
            key={method}
            className="menu-item mono"
            checked={methods.includes(method)}
            closeOnClick={false}
            onCheckedChange={(on) => onChange(on ? [...methods, method] : methods.filter((one) => one !== method))}
          >
            <span className="menu-check">{methods.includes(method) && <Check size={13} />}</span>
            {method}
          </Menu.CheckboxItem>
        ))}
      </MenuPopup>
    </Menu.Root>
  );
}

/** A whole number or nothing: what isn't a digit never lands. */
export function NumberInput({ value, label, disabled, onChange }: { value: number | null; label: string; disabled: boolean; onChange: (value: number | null) => void }) {
  return (
    <input
      className="input proxy-number"
      aria-label={label}
      inputMode="numeric"
      value={value === null ? '' : String(value)}
      placeholder="–"
      disabled={disabled}
      onChange={(event) => {
        const digits = event.target.value.replace(/\D/g, '').slice(0, 9);
        onChange(digits === '' ? null : Number(digits));
      }}
    />
  );
}

// --- adding, copying, reviewing -----------------------------------------------------------------

/** Add route, the other kinds and Copy from environment in its chevron's menu; for whoever holds `proxy.edit`. */
export function AddItem({ canEdit, project, onAdd, onCopy }: { canEdit: boolean; project: string; onAdd: (kind: ItemKind) => void; onCopy: () => void }) {
  if (!canEdit) {
    return (
      <Toggletip label={`Needs proxy.edit: Owners of ${project} and of the instance`}>
        <button type="button" className="btn btn-primary" aria-disabled="true">
          <Plus size={14} />
          Add route
        </button>
      </Toggletip>
    );
  }
  return (
    <div className="split-button">
      <button className="btn btn-primary" type="button" onClick={() => onAdd('route')}>
        <Plus size={14} />
        Add route
      </button>
      <Menu.Root>
        <Menu.Trigger className="btn btn-primary btn-icon" aria-label="More to add">
          <ChevronDown size={14} />
        </Menu.Trigger>
        <MenuPopup align="start">
          {(['signer', 'verifier', 'tunnel'] as const).map((kind) => (
            <Menu.Item key={kind} className="menu-item" onClick={() => onAdd(kind)}>
              <Plus size={14} />
              Add {KIND_LABELS[kind].toLowerCase()}
            </Menu.Item>
          ))}
          <Menu.Separator className="menu-sep" />
          <Menu.Item className="menu-item" onClick={onCopy}>
            <CopyFrom size={14} />
            Copy from environment…
          </Menu.Item>
        </MenuPopup>
      </Menu.Root>
    </div>
  );
}

/** The pending changes, each field by field, before they are saved together. */
export function ReviewDialog({ edits, place }: { edits: Edits; place: ProxyPlace }) {
  if (!edits.reviewing) return null;
  return (
    <Modal open onOpenChange={(open) => !open && edits.closeReview()} wide title={`Save to ${place.project}/${place.environment}`}>
      <div className="form">
        {edits.changes().map(({ row, change }) => (
          <section key={row.id} className="proxy-change" aria-label={row.definition.name}>
            <h3 className="proxy-change-title">
              <span className={`tag ${row.state === 'deleted' ? 'tag-red' : row.state === 'added' ? 'tag-green' : 'tag-blue'}`}>
                {row.state === 'deleted' ? 'Delete' : row.state === 'added' ? 'Add' : 'Update'}
              </span>
              <KindTag kind={row.definition.kind} />
              <span className="mono">{row.state === 'deleted' ? row.before!.name : row.definition.name}</span>
            </h3>
            {change.definition !== null && <Diff rows={diffOf(row.before, change.definition).filter((line) => row.before !== null || line.label !== 'Name')} adding={row.before === null} />}
            {row.routed.length > 0 && <Note tone="warn">Routes sensitive {row.routed.join(', ')}: audited as an Owner&apos;s change.</Note>}
          </section>
        ))}
        {edits.error !== null && (
          <p className="error-line" role="alert">
            <AlertCircle size={14} />
            <span>{edits.error}</span>
          </p>
        )}
        <div className="dialog-actions">
          <button className="btn" type="button" onClick={edits.closeReview} disabled={edits.pending}>
            Back
          </button>
          <button className="btn btn-primary" type="button" onClick={() => void edits.confirm()} disabled={edits.pending}>
            {edits.pending && <Spinner />}
            Save
          </button>
        </div>
      </div>
    </Modal>
  );
}

function Diff({ rows, adding }: { rows: ReturnType<typeof diffOf>; adding: boolean }) {
  return (
    <table className="proxy-diff">
      <tbody>
        {rows.map((row) => (
          <tr key={row.label}>
            <th scope="row">{row.label}</th>
            {!adding && <td className="proxy-diff-before mono">{row.before ?? '–'}</td>}
            <td className={`mono${adding ? '' : ' proxy-diff-after'}`}>{row.after}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/**
 * Items from another of the project's environments, added here as pending,
 * every field as it is, a route's egress included: the review shows them
 * before they are saved. One this environment cannot take says why.
 */
export function CopyFromEnvironment({
  store,
  place,
  config,
  keys,
  canEdit,
  edits,
  onClose,
}: {
  store: ProxyStore;
  place: ProxyPlace;
  config: ProxyConfig;
  keys: readonly SecretKey[];
  canEdit: boolean;
  edits: Edits;
  onClose: () => void;
}) {
  const { projects } = useShell();
  const siblings = (projects.find((entry) => entry.slug === place.project)?.environments ?? []).filter(
    (one) => isActiveAccessibleEnvironment(one) && !one.personal && one.slug !== place.environment,
  );
  const [source, setSource] = useState(siblings[0]?.slug ?? '');
  const [picked, setPicked] = useState<ReadonlySet<string>>(() => new Set());
  const from = useQuery({ ...proxyQuery(store, { project: place.project, environment: source }), enabled: source !== '' });

  const code = config.credentials.filter((one) => one.source === 'code').map((one) => one.name);
  const here = edits.rows.filter((row) => row.state !== 'deleted' && row.credential?.source !== 'code').map((row) => row.definition.name);
  const checked = (from.data?.credentials ?? [])
    .filter((one) => one.source === 'environment')
    .map((credential) => {
      const definition = definitionOf(credential);
      const { problems } = definitionProblems(definition, { place, keys, owner: canEdit, code, others: here, egresses: config.egresses, networks: config.networks, before: null });
      const held = here.includes(definition.name) ? 'Here already' : code.includes(definition.name) ? 'The code takes it here' : null;
      const refusal = problems.keys ?? Object.entries(problems).find(([field]) => field !== 'name')?.[1] ?? null;
      return { definition, held, problem: held ?? refusal };
    });
  const chosen = checked.filter((one) => one.problem === null && picked.has(one.definition.name));

  return (
    <Modal open onOpenChange={(open) => !open && onClose()} wide title="Copy from environment">
      <div className="form">
        <select
          className="select proxy-select"
          style={{ width: '14rem' }}
          aria-label="From"
          value={source}
          onChange={(event) => {
            setSource(event.target.value);
            setPicked(new Set());
          }}
        >
          {siblings.map((one) => (
            <option key={one.slug} value={one.slug}>
              {place.project}/{one.slug}
            </option>
          ))}
        </select>
        {siblings.length === 0 ? (
          <EmptyState title="No other environment" />
        ) : from.isPending ? (
          <Spinner />
        ) : checked.length === 0 ? (
          <EmptyState title="Nothing to copy" />
        ) : (
          <ul className="proxy-copy-list">
            {checked.map(({ definition, held, problem }) => (
              <li key={definition.name}>
                <label className={`proxy-copy${problem === null ? '' : ' proxy-copy-blocked'}`}>
                  <input
                    type="checkbox"
                    disabled={problem !== null}
                    checked={problem === null && picked.has(definition.name)}
                    onChange={(event) =>
                      setPicked((current) => {
                        const next = new Set(current);
                        if (event.target.checked) next.add(definition.name);
                        else next.delete(definition.name);
                        return next;
                      })
                    }
                  />
                  <KindTag kind={definition.kind} />
                  <span className="mono proxy-copy-name">{definition.name}</span>
                  <span className={`proxy-copy-problem${problem !== null && held === null ? ' proxy-error' : ''}`}>{problem}</span>
                </label>
              </li>
            ))}
          </ul>
        )}
        <div className="dialog-actions">
          <button className="btn" type="button" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn-primary"
            type="button"
            disabled={chosen.length === 0}
            onClick={() => {
              edits.add(chosen.map((one) => one.definition));
              onClose();
            }}
          >
            Copy{chosen.length === 0 ? '' : chosen.length === 1 ? ` ${chosen[0]!.definition.name}` : ` ${chosen.length}`}
          </button>
        </div>
      </div>
    </Modal>
  );
}
