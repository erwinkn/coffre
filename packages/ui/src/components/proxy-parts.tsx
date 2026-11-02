// What the Proxy tab is made of (0.16, T186): the page's pending edits,
// saved or discarded all at once; the fields, each folding its controls into
// one input; and the bar, the review, the copy and the release dialogs.
// `lib/proxy.ts` holds the rules.
import { useRef, useState, type ReactNode } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Menu } from '@base-ui/react/menu';
import { toast } from 'sonner';
import { CoffreError, type ProxyPage, type SecretKey } from '@coffre/client';

import {
  blankDefinition,
  changedSince,
  copiedInWords,
  countsInWords,
  diffOf,
  KIND_LABELS,
  methodsLabel,
  NO_DRAFTS,
  pageState,
  PROXY_METHODS,
  redirects,
  routedInWords,
  saveOf,
  savedByInWords,
  templateParts,
  type Drafts,
  type ParentPage,
  type Place,
  type ProxyDefinition,
  type ProxyItem,
  type ProxyKind,
  type ProxyMethod,
  type Row,
} from '../lib/proxy';
import { failureMessage, useCoffre } from '../lib/coffre';
import { isActiveAccessibleEnvironment } from '../lib/project-environments';
import { affects, queries, refresh } from '../lib/queries';
import { useShell } from '../lib/use-shell';
import { AlertCircle, Check, ChevronDown, CopyFrom, Lock, Plus } from './icons';
import { EmptyState, MenuPopup, Modal, Spinner, Toggletip } from './ui';

// --- the edits ---------------------------------------------------------------------------

export type Edits = ReturnType<typeof useProxyEdits>;

/**
 * The page's pending edits, and what saving them does: a review of each
 * change, field by field, then one save, from the seal the page loaded.
 * Another person's save since is a 409 (`proxy_changed`): the page reads
 * the environment again, keeps the edits, and the review says what changed
 * first, so saving over it is a decision.
 */
export function useProxyEdits({ place, page, parents, keys }: { place: Place; page: ProxyPage; parents: readonly ParentPage[]; keys: readonly SecretKey[] }) {
  const coffre = useCoffre();
  const queryClient = useQueryClient();
  const [drafts, setDrafts] = useState<Drafts>(NO_DRAFTS);
  const [tried, setTried] = useState(false);
  const [reviewing, setReviewing] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The page as it was when a save found another came first: the review says what changed since.
  const [overtaken, setOvertaken] = useState<ProxyPage | null>(null);
  const next = useRef(0);
  /** A change to the drafts, which remember the page the first one found, and each row's item as its edit began. */
  const edit = (row: Row | null, change: (current: Drafts) => Drafts) =>
    setDrafts((current) => {
      const changed = change(current);
      const origins = row?.item == null || row.item.source === 'code' || current.origins[row.id] !== undefined ? changed.origins : { ...changed.origins, [row.id]: row.item };
      return { ...changed, origins, loaded: current.loaded ?? page };
    });

  const state = pageState({ page, place, parents, keys, drafts, tried });
  const { rows, counts, changed, replacing } = state;

  const reset = () => {
    setDrafts(NO_DRAFTS);
    setTried(false);
    setReviewing(false);
    setError(null);
    setOvertaken(null);
  };

  return {
    ...state,
    tried,
    reviewing,
    pending,
    error,
    overtaken: overtaken === null ? [] : changedSince(overtaken, page),
    replacing,
    /** Change a row: the first change opens it as an edit. */
    patch: (row: Row, change: (definition: ProxyDefinition) => ProxyDefinition) =>
      edit(row, (current) => ({ ...current, edits: { ...current.edits, [row.id]: change(current.edits[row.id] ?? row.definition) } })),
    /** Add items, new or copied from another environment: each a row of its own, its id returned. */
    add: (definitions: readonly ProxyDefinition[], copiedFrom: string | null = null) => {
      const ids = definitions.map(() => `new:${next.current++}`);
      edit(null, (current) => ({
        ...current,
        edits: { ...current.edits, ...Object.fromEntries(ids.map((id, index) => [id, definitions[index]!])) },
        added: [...current.added, ...ids.map((id) => ({ id, copiedFrom }))],
      }));
      return ids;
    },
    remove: (row: Row) =>
      edit(row, (current) => {
        if (row.state !== 'added') return { ...current, edits: { ...current.edits, [row.id]: null } };
        const { [row.id]: _, ...edits } = current.edits;
        return { ...current, edits, added: current.added.filter((one) => one.id !== row.id) };
      }),
    /** Undo a row's edits, or its deletion. */
    restore: (row: Row) =>
      setDrafts((current) => {
        const { [row.id]: _, ...edits } = current.edits;
        const { [row.id]: __, ...origins } = current.origins;
        return { ...current, edits, origins, resaved: current.resaved.filter((id) => id !== row.id) };
      }),
    /** Save a row again as it is, under this editor's standing: how an Owner clears a route its editor no longer can (decision 5). */
    // It keeps the definition as the editor saw it: a change read since, a parent's, shows as one to review, never adopted unseen.
    resave: (row: Row) => edit(row, (current) => ({ ...current, edits: { ...current.edits, [row.id]: current.edits[row.id] ?? row.definition }, resaved: [...current.resaved, row.id] })),
    discard: reset,
    /** Save: what is wrong shows now, under its fields; else the review. */
    save: () => {
      setTried(true);
      setError(null);
      if (state.sound && changed > 0) setReviewing(true);
    },
    closeReview: () => setReviewing(false),
    confirm: async () => {
      setPending(true);
      setError(null);
      try {
        // The seal of the page the edits began on: a save since, even one a background read already shows, is a 409.
        await coffre.proxy.save(`${place.project}/${place.environment}`, { seal: (drafts.loaded ?? page).seal, items: saveOf(rows), ...(replacing ? { replace: true } : {}) });
        // Read again, as the tab reads it: the save's answer leaves out whether each item routes now. Its forks inherit
        // what it holds, and the log has a new entry.
        await refresh(queryClient, affects.proxy(place.project));
        toast.success(`Saved: ${countsInWords(counts)}`);
        reset();
      } catch (failure) {
        if (failure instanceof CoffreError && failure.reason === 'proxy_changed') {
          // Someone saved first: read the environment again, keep the edits, and say what changed.
          setOvertaken(drafts.loaded ?? page);
          const now = await queryClient.fetchQuery({ ...queries.proxy(coffre, place), staleTime: 0 });
          // Saving again is over what it read now, which the review showed.
          if (now.ok) setDrafts((current) => ({ ...current, loaded: now }));
        } else setError(proxyFailure(failure));
      } finally {
        setPending(false);
      }
    },
  };
}

/** What to say when a save fails: the vault's own words for what it refused (a key its editor may not route, say), else the page's. */
function proxyFailure(failure: unknown): string {
  if (failure instanceof CoffreError && failure.code === 'vault_refused') return failure.message.replace(/^the vault refused: /, '');
  return failureMessage(failure);
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
      {faulty > 0 && (
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

// --- showing ---------------------------------------------------------------------------------

export function KindTag({ kind }: { kind: ProxyKind }) {
  return <span className={`tag proxy-kind proxy-kind-${kind}`}>{KIND_LABELS[kind]}</span>;
}

/** Where a code item serves: every environment, or those it names. */
export const scopeInWords = (item: ProxyItem) => (item.environments === null ? 'Defined in code, for every environment' : `Defined in code, for ${item.environments.join(', ')} only`);

/** What a code item's lock says: that code defines it, where it serves, and that its name hides any environment's own. */
export const lockedByCodeInWords = (item: ProxyItem) =>
  `${scopeInWords(item)}. Change it there: its name is code's in every environment${item.serves ? '' : ', and it serves none but those'}.`;

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
  const options = typed === null ? [] : keys.filter((entry) => !entry.archived && entry.key.toLowerCase().includes(typed.toLowerCase()));
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
  const entry = keys.find((one) => one.key === name && !one.archived);
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
  const listed = keys.filter((entry) => !entry.archived);
  const known = value === '' || listed.some((entry) => entry.key === value);
  return (
    <select className={className} aria-label={label} value={value} disabled={disabled} onChange={(event) => onChange(event.target.value)}>
      <option value="">{optional ? `No ${label.toLowerCase()}` : 'Pick a key'}</option>
      {!known && <option value={value}>{value} (not here yet)</option>}
      {listed.map((entry) => (
        <option key={entry.key} value={entry.key}>
          {entry.key}
          {entry.sensitivity === 'sensitive' ? ' (sensitive)' : !entry.readable ? " (can't read)" : ''}
        </option>
      ))}
    </select>
  );
}

/**
 * Methods, as a menu at the start of an allow entry: none picked takes any.
 * Code's item may name a method beyond the tab's seven (`PROPFIND`): it
 * shows as written, checked, and its row takes no edits.
 */
export function MethodsMenu({ methods, disabled, onChange }: { methods: readonly string[]; disabled: boolean; onChange: (methods: ProxyMethod[]) => void }) {
  const known = PROXY_METHODS.filter((method) => methods.includes(method));
  const others = methods.filter((method) => !(PROXY_METHODS as readonly string[]).includes(method));
  const { all, shown } = methodsLabel(methods);
  return (
    <Menu.Root>
      <Menu.Trigger className="fold-select fold-lead fold-kind fold-menu" aria-label="Methods" title={all === '' ? undefined : all} disabled={disabled}>
        <span className="fold-menu-text">{shown}</span>
      </Menu.Trigger>
      <MenuPopup align="start">
        {PROXY_METHODS.map((method) => (
          <Menu.CheckboxItem
            key={method}
            className="menu-item mono"
            checked={methods.includes(method)}
            closeOnClick={false}
            onCheckedChange={(on) => onChange(on ? [...known, method] : known.filter((one) => one !== method))}
          >
            <span className="menu-check">{methods.includes(method) && <Check size={13} />}</span>
            {method}
          </Menu.CheckboxItem>
        ))}
        {others.map((method) => (
          <Menu.CheckboxItem key={method} className="menu-item mono" checked disabled>
            <span className="menu-check">
              <Check size={13} />
            </span>
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

// --- adding, copying, reviewing, releasing ----------------------------------------------------------

/** Add route, the other kinds and Copy from environment in its chevron's menu; for whoever may save here. */
export function AddItem({ edits, onAdded, onCopy }: { edits: Edits; onAdded: (id: string) => void; onCopy: () => void }) {
  if (!edits.editor.editable) {
    return (
      <Toggletip label={edits.page.readOnly?.message ?? "You can't change this environment's proxy definitions."}>
        <button type="button" className="btn btn-primary" aria-disabled="true">
          <Plus size={14} />
          Add route
        </button>
      </Toggletip>
    );
  }
  const add = (kind: ProxyKind) => onAdded(edits.add([blankDefinition(kind)])[0]!);
  return (
    <div className="split-button">
      <button className="btn btn-primary" type="button" onClick={() => add('route')}>
        <Plus size={14} />
        Add route
      </button>
      <Menu.Root>
        <Menu.Trigger className="btn btn-primary btn-icon" aria-label="More to add">
          <ChevronDown size={14} />
        </Menu.Trigger>
        <MenuPopup align="start">
          {(['signer', 'verifier', 'tunnel'] as const).map((kind) => (
            <Menu.Item key={kind} className="menu-item" onClick={() => add(kind)}>
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

/**
 * The pending changes, each field by field, before they are saved together:
 * what changed first if another save came since; each copied item's keys
 * and destination here (decision 2); the sensitive keys an Owner routes
 * (R66); and how long a change of destination leaves the old one served
 * values decided before it (decision 4).
 */
export function ReviewDialog({ edits }: { edits: Edits }) {
  if (!edits.reviewing) return null;
  const { place, page } = edits;
  const changing = edits.rows.filter((row) => row.state !== 'same');
  const moving = changing.some((row) => row.before !== null && redirects(row.before, row.state === 'deleted' ? null : row.definition));
  return (
    <Modal open onOpenChange={(open) => !open && edits.closeReview()} wide title={`Save to ${place.project}/${place.environment}`}>
      <div className="form">
        {edits.overtaken.length > 0 && (
          <div className="proxy-overtaken" role="status">
            <p className="proxy-overtaken-title">
              <AlertCircle size={14} />
              Saved by someone else since you loaded this page
            </p>
            <ul>
              {edits.overtaken.map((change) => (
                <li key={change.name}>
                  <span className="mono">{change.name}</span> {change.what}
                  {change.by !== null && <> by {savedByInWords(change.by)}</>}
                </li>
              ))}
            </ul>
            <p className="hint">Your changes below still apply on top. Save to keep them, or go back to look first.</p>
          </div>
        )}
        {edits.replacing && (
          <Note tone="warn">This save replaces the environment's proxy definitions whole: whatever the failed object held is dropped, and the log names it.</Note>
        )}
        {changing.map((row) => (
          <section key={row.id} className="proxy-change" aria-label={row.definition.name}>
            <h3 className="proxy-change-title">
              <span className={`tag ${row.state === 'deleted' ? 'tag-red' : row.state === 'added' ? 'tag-green' : 'tag-blue'}`}>{changeLabel(row)}</span>
              <KindTag kind={row.definition.kind} />
              <span className="mono">{row.state === 'deleted' ? row.before!.name : row.definition.name}</span>
            </h3>
            {row.state !== 'deleted' && row.state !== 'resaved' && <Diff rows={diffOf(row.before, row.definition).filter((line) => row.before !== null || line.label !== 'Name')} adding={row.before === null} />}
            {row.state === 'resaved' && (
              <p className="hint">
                {row.item?.source === 'inherited'
                  ? `Saved here as it is, over ${row.item.from}'s, under your access: ${place.environment}'s own from now on, its keys cleared for you.`
                  : 'Saved again as it is, under your access: its keys are cleared for you from now on.'}
              </p>
            )}
            {row.state === 'deleted' && row.item?.from != null && <p className="hint">{place.environment} uses {row.item.from}&apos;s {row.before!.name} again.</p>}
            {row.copiedFrom !== null && <Note tone="warn">{copiedInWords(row.definition, place, row.copiedFrom)}</Note>}
            {row.state !== 'deleted' && row.keys.routed.length > 0 && <Note tone="warn">Routes sensitive {row.keys.routed.join(', ')}: audited as an Owner&apos;s change.</Note>}
          </section>
        ))}
        {moving && (
          <p className="hint proxy-window">
            Requests already decided may still reach the old destination for up to {windowInWords(page.windowSeconds)} after you save, as with a revoked handle.
          </p>
        )}
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
            {edits.overtaken.length > 0 ? 'Save anyway' : 'Save'}
          </button>
        </div>
      </div>
    </Modal>
  );
}

function changeLabel(row: Row): string {
  if (row.state === 'deleted') return row.item?.from != null ? 'Revert' : 'Delete';
  if (row.state === 'added') return row.copiedFrom !== null ? 'Copy' : 'Add';
  if (row.item?.source === 'inherited') return 'Override';
  return row.state === 'resaved' ? 'Save again' : 'Update';
}

/** 60 -> "a minute", 3 -> "3 seconds", 90 -> "90 seconds". */
export function windowInWords(seconds: number): string {
  if (seconds === 60) return 'a minute';
  if (seconds % 60 === 0) return `${seconds / 60} minutes`;
  return `${seconds} seconds`;
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
 * every field as it is, a route's egress included (R66): the review names
 * the keys each will send here, and where. One this environment cannot take
 * says why.
 */
export function CopyFromEnvironment({ edits, onClose }: { edits: Edits; onClose: () => void }) {
  const coffre = useCoffre();
  const { projects } = useShell();
  const { place } = edits;
  const siblings = (projects.find((entry) => entry.slug === place.project)?.environments ?? []).filter(
    (one) => isActiveAccessibleEnvironment(one) && !one.personal && one.slug !== place.environment,
  );
  const [source, setSource] = useState(siblings[0]?.slug ?? '');
  const [picked, setPicked] = useState<ReadonlySet<string>>(() => new Set());
  const from = useQuery({ ...queries.proxy(coffre, { project: place.project, environment: source }), enabled: source !== '' });

  const here = edits.rows.filter((row) => row.state !== 'deleted' && row.item?.source !== 'code').map((row) => row.definition.name);
  const code = edits.editor.code.map((item) => item.definition.name);
  const read = from.data?.ok === true ? from.data : null;
  // Its own items, as its tab shows them: none code shadows.
  const offered = read === null ? [] : read.items.filter((item) => !read.code.some((one) => one.definition.name === item.definition.name));
  const checked = offered.map(({ definition }) => {
    const problem = here.includes(definition.name)
      ? `${place.environment} has ${definition.name} already`
      : code.includes(definition.name)
        ? 'Code defines it'
        : edits.editor.reserved.includes(definition.name)
          ? 'Reserved by earlier code'
          : null;
    return { definition, problem };
  });
  const chosen = checked.filter((one) => one.problem === null && picked.has(one.definition.name));

  return (
    <Modal open onOpenChange={(open) => !open && onClose()} wide title="Copy from environment" description="Every field comes as it is, upstream and egress included. Review each before it is saved here.">
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
        ) : from.data?.ok === false ? (
          <p className="error-line" role="alert">
            <AlertCircle size={14} />
            <span>{from.data.error}</span>
          </p>
        ) : checked.length === 0 ? (
          <EmptyState title="Nothing to copy" />
        ) : (
          <ul className="proxy-copy-list">
            {checked.map(({ definition, problem }) => (
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
                  <span className="proxy-copy-problem">{problem ?? <span className="mono proxy-copy-target">{copyTarget(definition)}</span>}</span>
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
              edits.add(
                chosen.map((one) => one.definition),
                `${place.project}/${source}`,
              );
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

function copyTarget(definition: ProxyDefinition): string {
  switch (definition.kind) {
    case 'route':
      try {
        return new URL(definition.upstream).host;
      } catch {
        return definition.upstream;
      }
    case 'tunnel':
      return definition.hosts.join(', ');
    case 'signer':
      return definition.signer.key;
    case 'verifier':
      return definition.hmac.key;
  }
}

/**
 * The names code reserved that this deployment's code no longer defines
 * (section 6): no UI item takes one until an instance Owner releases it,
 * instance-wide, in a dialog that says what nothing can check.
 */
export function ReservedNames({ edits }: { edits: Edits }) {
  const coffre = useCoffre();
  const queryClient = useQueryClient();
  const [releasing, setReleasing] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const code = new Set(edits.editor.code.map((item) => item.definition.name));
  const stale = edits.page.reserved.filter((name) => !code.has(name));
  if (stale.length === 0) return null;
  return (
    <div className="proxy-reserved">
      <p className="hint">
        Reserved by an earlier deployment&apos;s code, so no environment&apos;s own item takes{' '}
        {stale.map((name, index) => (
          <span key={name}>
            {index > 0 && ', '}
            {edits.page.releases ? (
              <button type="button" className="proxy-reserved-name" onClick={() => setReleasing(name)}>
                {name}
              </button>
            ) : (
              <span className="mono">{name}</span>
            )}
          </span>
        ))}
        {edits.page.releases ? ': release one to free it.' : ': an Owner of the whole instance may release them.'}
      </p>
      {releasing !== null && (
        <Modal open onOpenChange={(open) => !open && setReleasing(null)} title={`Release ${releasing}?`}>
          <div className="form">
            <p className="dialog-body">
              <span className="mono">{releasing}</span> becomes free in every environment of every project. This deployment&apos;s code no longer defines it, but coffre can&apos;t
              tell whether an older deployment still serving does: release it once no deployment of that code runs.
            </p>
            {error !== null && (
              <p className="error-line" role="alert">
                <AlertCircle size={14} />
                <span>{error}</span>
              </p>
            )}
            <div className="dialog-actions">
              <button className="btn" type="button" onClick={() => setReleasing(null)} disabled={pending}>
                Cancel
              </button>
              <button
                className="btn btn-danger"
                type="button"
                disabled={pending}
                onClick={async () => {
                  setPending(true);
                  setError(null);
                  try {
                    await coffre.proxy.release(releasing);
                    toast.success(`Released ${releasing}`);
                    setReleasing(null);
                    await refresh(queryClient, [['proxy']]);
                  } catch (failure) {
                    setError(failureMessage(failure));
                  } finally {
                    setPending(false);
                  }
                }}
              >
                {pending && <Spinner />}
                Release {releasing}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}

export type { Row };
