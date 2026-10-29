// What the Proxy tab's three variants share (W260, a prototype, DO NOT
// MERGE): the page's pending edits, saved or discarded all at once; the
// fields, each folding its controls into one input; and the bar, the
// review and the copy dialogs. `lib/proxy-prototype.ts` holds the rules.
import { useRef, useState, type ReactNode } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Menu } from '@base-ui/react/menu';
import { Popover } from '@base-ui/react/popover';
import { toast } from 'sonner';

import {
  blankDefinition,
  blankInject,
  definitionFrom,
  definitionOf,
  definitionProblems,
  diffOf,
  egressRefusal,
  formOf,
  injectInWords,
  keysOf,
  METHODS,
  proxyKey,
  proxyQuery,
  sameDefinition,
  soleKey,
  templateParts,
  unreadable,
  unreadableInWords,
  type Form,
  type InjectKind,
  type Problems,
  type ProxyChange,
  type ProxyConfig,
  type ProxyCredential,
  type ProxyDefinition,
  type ProxyEgress,
  type ProxyInject,
  type ProxyPlace,
  type ProxyStore,
} from '../lib/proxy-prototype';
import { isActiveAccessibleEnvironment } from '../lib/project-environments';
import { usePreferences } from '../lib/preferences';
import { useShell } from '../lib/use-shell';
import type { SecretKey } from '../shared/models';
import { AlertCircle, Check, ChevronDown, CopyFrom, Key, Lock, Plus } from './icons';
import { EmptyState, MenuPopup, Modal, Spinner, Tip, Toggletip } from './ui';

// --- the edits ---------------------------------------------------------------------------

export type RowState = 'same' | 'changed' | 'added' | 'deleted';

/** One credential as the page shows it: as stored, or as edited and not yet saved. */
export type Row = {
  id: string;
  /** As stored; null for one added here. */
  credential: ProxyCredential | null;
  before: ProxyDefinition | null;
  form: Form;
  definition: ProxyDefinition;
  state: RowState;
  /** Open for editing: changed or not. */
  open: boolean;
  /** Whether its fields take edits: the environment's own, for whoever holds `proxy.edit`. */
  editable: boolean;
  /** The keys it sends which the editor cannot read: where it sends them stays as it is. */
  locked: { key: string; sensitive: boolean }[];
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
  canEdit: boolean;
}) {
  const queryClient = useQueryClient();
  // Each open row's form, by id: a stored credential's name, or `new-N`; null marks one to delete.
  const [drafts, setDrafts] = useState<Record<string, Form | null>>({});
  const [added, setAdded] = useState<string[]>([]);
  const [tried, setTried] = useState(false);
  const [reviewing, setReviewing] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const next = useRef(0);

  const code = config.credentials.filter((one) => one.source === 'code').map((one) => one.name);
  const base: Omit<Row, 'problems'>[] = [
    ...config.credentials.map((credential) => {
      const id = credential.name + (credential.source === 'code' ? ':code' : '');
      const before = definitionOf(credential);
      const draft = drafts[id];
      const form = draft ?? formOf(before);
      const definition = definitionFrom(form);
      const own = credential.source === 'environment';
      return {
        id,
        credential,
        before,
        form,
        definition,
        state: (draft === null ? 'deleted' : draft !== undefined && !sameDefinition(definition, before) ? 'changed' : 'same') as RowState,
        open: draft !== undefined && draft !== null,
        editable: own && canEdit,
        locked: own ? unreadable(keysOf(before.inject), keys) : [],
      };
    }),
    ...added.map((id) => {
      const form = drafts[id]!;
      return { id, credential: null, before: null, form, definition: definitionFrom(form), state: 'added' as RowState, open: true, editable: true, locked: [] };
    }),
  ];
  const rows: Row[] = base.map((row) => {
    if (!tried || (row.state !== 'changed' && row.state !== 'added')) return { ...row, problems: {} };
    const others = base.filter((one) => one.id !== row.id && one.state !== 'deleted' && one.credential?.source !== 'code').map((one) => one.definition.name);
    return { ...row, problems: definitionProblems(row.definition, { place, keys, code, others, egresses: config.egresses, before: row.before }) };
  });

  const counts = {
    added: rows.filter((row) => row.state === 'added').length,
    updated: rows.filter((row) => row.state === 'changed').length,
    deleted: rows.filter((row) => row.state === 'deleted').length,
  };
  const changed = counts.added + counts.updated + counts.deleted;
  const faulty = rows.filter((row) => Object.keys(row.problems).length > 0);

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
        .map((row) => ({ row, change: { was: row.credential?.name ?? null, definition: state === 'deleted' ? null : row.definition } })),
    );

  return {
    rows,
    counts,
    changed,
    /** Whether anything is open or changed, which the bar is for. */
    active: Object.keys(drafts).length > 0,
    tried,
    faulty,
    reviewing,
    pending,
    error,
    changes,
    open: (row: Row) => {
      if (!row.editable || row.id in drafts) return;
      setDrafts((current) => ({ ...current, [row.id]: formOf(row.before!) }));
    },
    patch: (id: string, patch: Partial<Form>) =>
      setDrafts((current) => {
        const row = base.find((one) => one.id === id);
        const form = current[id] ?? (row?.before ? formOf(row.before) : formOf(blankDefinition()));
        return { ...current, [id]: { ...form, ...patch } };
      }),
    add: (forms: Form[] = [formOf(blankDefinition())]) => {
      const ids = forms.map(() => `new-${next.current++}`);
      setDrafts((current) => ({ ...current, ...Object.fromEntries(ids.map((id, index) => [id, forms[index]!])) }));
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
    /** Save: what is wrong shows now, on its rows; else the review. */
    save: () => {
      setTried(true);
      setError(null);
      const problems = rows.filter((row) => row.state === 'changed' || row.state === 'added').some((row) => {
        const others = base.filter((one) => one.id !== row.id && one.state !== 'deleted' && one.credential?.source !== 'code').map((one) => one.definition.name);
        return Object.keys(definitionProblems(row.definition, { place, keys, code, others, egresses: config.egresses, before: row.before })).length > 0;
      });
      if (!problems && changed > 0) setReviewing(true);
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

/** The foot of the page while anything is open: the changes counted, Discard and Save, for all of them at once. */
export function PendingBar({ edits }: { edits: Edits }) {
  if (!edits.active) return null;
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
        <button className="btn btn-sm btn-primary" type="button" onClick={edits.save} disabled={edits.changed === 0}>
          Save
        </button>
      </div>
      {edits.tried && faulty > 0 && (
        <p className="pending-error" role="alert">
          <AlertCircle size={14} />
          <span>{faulty === 1 ? `${edits.faulty[0]!.definition.name || 'A new credential'} needs fixing.` : `${faulty} credentials need fixing.`}</span>
        </p>
      )}
    </div>
  );
}

/** What is wrong with a row, and why where it sends its keys stays: under its line. */
export function RowNotes({ row }: { row: Row }) {
  const messages = [...new Set(Object.values(row.problems))];
  const locked = row.open && row.locked.length > 0;
  if (messages.length === 0 && !locked) return null;
  return (
    <div className="proxy-notes">
      {locked && (
        <p className="proxy-note">
          <Lock size={12} />
          {unreadableInWords(row.locked)}
        </p>
      )}
      {messages.map((message) => (
        <p key={message} className="proxy-note proxy-note-error">
          <AlertCircle size={12} />
          {message}
        </p>
      ))}
    </div>
  );
}

// --- showing ---------------------------------------------------------------------------------

export function KeyChip({ name, keys }: { name: string; keys: readonly SecretKey[] }) {
  const entry = keys.find((one) => one.key === name);
  if (entry === undefined) {
    return (
      <Tip label="Not in this environment">
        <span className="proxy-key proxy-key-missing">{name}</span>
      </Tip>
    );
  }
  if (entry.sensitivity === 'sensitive') {
    return (
      <Tip label="Sensitive">
        <span className="proxy-key proxy-key-sensitive">
          <Lock size={10} />
          {name}
        </span>
      </Tip>
    );
  }
  return <span className="proxy-key">{name}</span>;
}

export function Template({ template, keys }: { template: string; keys: readonly SecretKey[] }) {
  return (
    <span className="mono proxy-template">
      {templateParts(template).map((part, index) => ('key' in part ? <KeyChip key={index} name={part.key} keys={keys} /> : <span key={index}>{part.text}</span>))}
    </span>
  );
}

/** How a credential sends its keys, on one line, each `{KEY}` a chip. */
export function InjectText({ inject, keys }: { inject: ProxyInject; keys: readonly SecretKey[] }) {
  if (inject.kind === 'sigv4') {
    return (
      <span className="proxy-template">
        <span className="proxy-how">SigV4</span>
        {[inject.accessKeyId, inject.secretAccessKey, inject.sessionToken].filter((one) => one !== '').map((template, index) => (
          <Template key={index} template={template} keys={keys} />
        ))}
        <span className="proxy-how">
          {inject.service}, {inject.region}
        </span>
      </span>
    );
  }
  return (
    <span className="proxy-template">
      <span className="proxy-how">{KIND_WORDS[inject.kind]}</span>
      <Template template={injectInWords(inject)} keys={keys} />
    </span>
  );
}

/** A credential's marks beside its name: defined in code, or shadowed by it. */
export function SourceMark({ credential }: { credential: ProxyCredential | null }) {
  if (credential?.source === 'code') {
    return (
      <Toggletip label="Defined in code, for every environment">
        <button type="button" className="proxy-mark" aria-label="Defined in code">
          <Lock size={12} />
        </button>
      </Toggletip>
    );
  }
  if (credential?.shadowedSince != null) {
    return (
      <Toggletip label={`Shadowed: the code defines ${credential.name} too, and code's is served`}>
        <button type="button" className="proxy-mark proxy-mark-warn" aria-label="Shadowed by code">
          <AlertCircle size={12} />
        </button>
      </Toggletip>
    );
  }
  return null;
}

export const KIND_WORDS: Record<InjectKind, string> = { header: 'Header', query: 'Query', form: 'Form', json: 'JSON', basic: 'Basic', sigv4: 'SigV4' };

export const methodsShort = (methods: readonly string[]) => (methods.length === 0 ? 'Any' : methods.join(' '));
export const pathsShort = (paths: readonly string[]) => (paths.length === 0 ? 'any path' : paths.join(', '));
export function limitShort(limit: ProxyDefinition['limit'], perService = false): string {
  if (perService) return 'Per service';
  const format = new Intl.NumberFormat('en', { notation: 'compact' });
  const parts = [limit.perMinute !== null && `${format.format(limit.perMinute)}/min`, limit.perDay !== null && `${format.format(limit.perDay)}/day`].filter((part) => part !== false);
  return parts.length === 0 ? '–' : parts.join(' · ');
}

// --- the fields, each one input -----------------------------------------------------------------

/** Controls folded into one field: text and selects inside its border, which focus lights as a whole. */
export function Fold({ invalid, disabled, className, children }: { invalid?: boolean; disabled?: boolean; className?: string; children: ReactNode }) {
  return (
    <div className={`fold${invalid === true ? ' is-invalid' : ''}${disabled === true ? ' is-disabled' : ''}${className === undefined ? '' : ` ${className}`}`}>
      {children}
    </div>
  );
}

type FieldProps = { row: Row; edits: Edits };

const any = (problems: Problems, ...fields: (keyof Problems)[]) => fields.some((field) => problems[field] !== undefined);

export function NameField({ row, edits }: FieldProps) {
  return (
    <Fold invalid={any(row.problems, 'name')}>
      <span className="fold-text">/use/</span>
      <input className="fold-input mono" aria-label="Name" value={row.form.name} spellCheck={false} autoComplete="off" placeholder="name" onChange={(event) => edits.patch(row.id, { name: event.target.value })} />
    </Fold>
  );
}

/** The upstream, and the egress it leaves through at its end. */
export function UpstreamField({ row, edits, egresses }: FieldProps & { egresses: readonly ProxyEgress[] }) {
  const disabled = row.locked.length > 0;
  return (
    <Fold invalid={any(row.problems, 'upstream', 'egress')} disabled={disabled}>
      <input className="fold-input mono" aria-label="Upstream" value={row.form.upstream} disabled={disabled} spellCheck={false} autoComplete="off" placeholder="https://api.example.com" onChange={(event) => edits.patch(row.id, { upstream: event.target.value })} />
      <EgressSelect row={row} edits={edits} egresses={egresses} disabled={disabled} />
    </Fold>
  );
}

export function EgressSelect({ row, edits, egresses, disabled, className = 'fold-select' }: FieldProps & { egresses: readonly ProxyEgress[]; disabled: boolean; className?: string }) {
  return (
    <select className={className} aria-label="Egress" value={row.form.egress ?? ''} disabled={disabled} onChange={(event) => edits.patch(row.id, { egress: event.target.value === '' ? null : event.target.value })}>
      <option value="">Direct</option>
      {egresses.map((egress) => {
        const refusal = egressRefusal(egress, row.form.upstream);
        return (
          <option key={egress.name} value={egress.name} disabled={refusal !== null && egress.name !== row.form.egress} title={egress.description ?? undefined}>
            {egress.name}
          </option>
        );
      })}
    </select>
  );
}

/**
 * How it sends its keys: the kind, its name, the template, and the
 * environment's keys a click away. `compact` folds the kind, the name and
 * the placeholder into one lead, which opens them: a ledger's cell has room
 * for the template alone.
 */
export function SendsField({ row, edits, keys, compact = false }: FieldProps & { keys: readonly SecretKey[]; compact?: boolean }) {
  const inject = row.form.inject;
  const disabled = row.locked.length > 0;
  const set = (next: ProxyInject) => edits.patch(row.id, { inject: next });
  const [into, setInto] = useState<'user' | 'password'>('user');
  const invalid = any(row.problems, 'injectName', 'template', 'user', 'password', 'accessKeyId', 'secretAccessKey', 'sessionToken', 'region', 'service', 'keys', 'placeholder');
  if (compact) return <CompactSends row={row} edits={edits} keys={keys} invalid={invalid} disabled={disabled} set={set} />;
  const kind = (
    <select className="fold-select fold-lead" aria-label="Sends as" value={inject.kind} disabled={disabled} onChange={(event) => set(blankInject(event.target.value as InjectKind))}>
      {(Object.keys(KIND_WORDS) as InjectKind[]).map((one) => (
        <option key={one} value={one}>
          {KIND_WORDS[one]}
        </option>
      ))}
    </select>
  );
  if (inject.kind === 'sigv4') {
    const pick = (field: 'accessKeyId' | 'secretAccessKey' | 'sessionToken', label: string) => (
      <select className="fold-select mono" aria-label={label} value={soleKey(inject[field])} disabled={disabled} onChange={(event) => set({ ...inject, [field]: event.target.value === '' ? '' : `{${event.target.value}}` })}>
        <option value="">{field === 'sessionToken' ? 'no token' : label}</option>
        {keys.map((entry) => (
          <option key={entry.key} value={entry.key}>
            {entry.key}
          </option>
        ))}
      </select>
    );
    return (
      <Fold invalid={invalid} disabled={disabled}>
        {kind}
        {pick('accessKeyId', 'Access key ID')}
        {pick('secretAccessKey', 'Secret access key')}
        <input className="fold-input fold-short mono" aria-label="Region" value={inject.region} disabled={disabled} placeholder="eu-west-3" onChange={(event) => set({ ...inject, region: event.target.value.trim() })} />
        <input className="fold-input fold-short mono" aria-label="Service" value={inject.service} disabled={disabled} placeholder="s3" onChange={(event) => set({ ...inject, service: event.target.value.trim() })} />
      </Fold>
    );
  }
  if (inject.kind === 'basic') {
    return (
      <Fold invalid={invalid} disabled={disabled}>
        {kind}
        <input className="fold-input mono" aria-label="User" value={inject.user} disabled={disabled} placeholder="user" onFocus={() => setInto('user')} onChange={(event) => set({ ...inject, user: event.target.value })} />
        <span className="fold-text">:</span>
        <input className="fold-input mono" aria-label="Password" value={inject.password} disabled={disabled} placeholder="empty" onFocus={() => setInto('password')} onChange={(event) => set({ ...inject, password: event.target.value })} />
        <KeyMenu keys={keys} disabled={disabled} onPick={(key) => set({ ...inject, [into]: `${inject[into]}{${key}}` })} />
      </Fold>
    );
  }
  return (
    <Fold invalid={invalid} disabled={disabled}>
      {kind}
      <input className="fold-input fold-name mono" aria-label={inject.kind === 'header' ? 'Header' : 'Field'} value={inject.name} disabled={disabled} spellCheck={false} placeholder={inject.kind === 'header' ? 'authorization' : 'key'} onChange={(event) => set({ ...inject, name: event.target.value })} />
      <span className="fold-text">{inject.kind === 'header' ? ':' : '='}</span>
      <input className="fold-input mono" aria-label="Value" value={inject.template} disabled={disabled} spellCheck={false} placeholder="Bearer {KEY}" onChange={(event) => set({ ...inject, template: event.target.value })} />
      <KeyMenu keys={keys} disabled={disabled} onPick={(key) => set({ ...inject, template: `${inject.template}{${key}}` })} />
    </Fold>
  );
}

function CompactSends({ row, edits, keys, invalid, disabled, set }: FieldProps & { keys: readonly SecretKey[]; invalid: boolean; disabled: boolean; set: (inject: ProxyInject) => void }) {
  const { portal } = usePreferences();
  const inject = row.form.inject;
  const named = inject.kind !== 'basic' && inject.kind !== 'sigv4';
  const lead = inject.kind === 'sigv4' ? `SigV4 ${inject.service}` : inject.kind === 'basic' ? 'Basic' : `${inject.kind === 'header' ? '' : `${KIND_WORDS[inject.kind]} `}${inject.name || 'name'}${inject.kind === 'header' ? ':' : '='}`;
  return (
    <Fold invalid={invalid} disabled={disabled}>
      <Popover.Root>
        <Popover.Trigger className="fold-select fold-lead fold-menu" disabled={disabled}>
          {lead}
          <ChevronDown size={12} />
        </Popover.Trigger>
        <Popover.Portal container={portal}>
          <Popover.Positioner className="menu-positioner" align="start" sideOffset={6}>
            <Popover.Popup className="menu proxy-popover">
              <SendsField row={row} edits={edits} keys={keys} />
              {named && <PlaceholderField row={row} edits={edits} />}
            </Popover.Popup>
          </Popover.Positioner>
        </Popover.Portal>
      </Popover.Root>
      {inject.kind === 'sigv4' ? (
        <>
          {(['accessKeyId', 'secretAccessKey'] as const).map((field) => (
            <select key={field} className="fold-select mono" aria-label={field === 'accessKeyId' ? 'Access key ID' : 'Secret access key'} value={soleKey(inject[field])} disabled={disabled} onChange={(event) => set({ ...inject, [field]: event.target.value === '' ? '' : `{${event.target.value}}` })}>
              <option value="">{field === 'accessKeyId' ? 'key ID' : 'secret'}</option>
              {keys.map((entry) => (
                <option key={entry.key} value={entry.key}>
                  {entry.key}
                </option>
              ))}
            </select>
          ))}
        </>
      ) : inject.kind === 'basic' ? (
        <>
          <input className="fold-input mono" aria-label="User" value={inject.user} disabled={disabled} placeholder="user" onChange={(event) => set({ ...inject, user: event.target.value })} />
          <span className="fold-text">:</span>
          <input className="fold-input mono" aria-label="Password" value={inject.password} disabled={disabled} placeholder="empty" onChange={(event) => set({ ...inject, password: event.target.value })} />
          <KeyMenu keys={keys} disabled={disabled} onPick={(key) => set({ ...inject, user: `${inject.user}{${key}}` })} />
        </>
      ) : (
        <>
          <input className="fold-input mono" aria-label="Value" value={inject.template} disabled={disabled} spellCheck={false} placeholder="{KEY}" onChange={(event) => set({ ...inject, template: event.target.value })} />
          <KeyMenu keys={keys} disabled={disabled} onPick={(key) => set({ ...inject, template: `${inject.template}{${key}}` })} />
        </>
      )}
    </Fold>
  );
}

/** The environment's keys, a menu at a field's end: a pick puts `{KEY}` in it. Those the editor cannot read carry a lock. */
export function KeyMenu({ keys, disabled, onPick, className = 'fold-button' }: { keys: readonly SecretKey[]; disabled: boolean; onPick: (key: string) => void; className?: string }) {
  return (
    <Menu.Root>
      <Menu.Trigger className={className} aria-label="Insert a key" disabled={disabled}>
        <Key size={13} />
      </Menu.Trigger>
      <MenuPopup align="end">
        {keys.map((entry) => (
          <Menu.Item key={entry.key} className="menu-item mono" onClick={() => onPick(entry.key)}>
            {entry.readable ? <Key size={13} /> : <Lock size={13} />}
            {entry.key}
          </Menu.Item>
        ))}
      </MenuPopup>
    </Menu.Root>
  );
}

/** Which methods and paths an app may ask: the methods a menu at the field's start, the paths typed after it. */
export function AllowsField({ row, edits }: FieldProps) {
  return (
    <Fold invalid={any(row.problems, 'paths')}>
      <MethodsMenu row={row} edits={edits} />
      <input className="fold-input mono" aria-label="Paths" value={row.form.paths} spellCheck={false} placeholder="any path" onChange={(event) => edits.patch(row.id, { paths: event.target.value })} />
    </Fold>
  );
}

export function MethodsMenu({ row, edits, className = 'fold-select fold-lead fold-menu', asCode = false }: FieldProps & { className?: string; asCode?: boolean }) {
  const methods = row.form.methods;
  const picked = METHODS.filter((method) => methods.includes(method));
  return (
    <Menu.Root>
      <Menu.Trigger className={className} aria-label="Methods">
        {asCode ? (picked.length === 0 ? 'any' : `[${picked.map((one) => `'${one}'`).join(', ')}]`) : methodsShort(picked)}
        <ChevronDown size={12} />
      </Menu.Trigger>
      <MenuPopup align="start">
        {METHODS.map((method) => (
          <Menu.CheckboxItem
            key={method}
            className="menu-item mono"
            checked={methods.includes(method)}
            closeOnClick={false}
            onCheckedChange={(on) => edits.patch(row.id, { methods: on ? [...methods, method] : methods.filter((one) => one !== method) })}
          >
            <span className="menu-check">{methods.includes(method) && <Check size={13} />}</span>
            {method}
          </Menu.CheckboxItem>
        ))}
      </MenuPopup>
    </Menu.Root>
  );
}

export function LimitField({ row, edits }: FieldProps) {
  return (
    <Fold invalid={any(row.problems, 'perMinute', 'perDay')}>
      <input className="fold-input fold-number" aria-label="A minute" inputMode="numeric" value={row.form.perMinute} placeholder="–" onChange={(event) => edits.patch(row.id, { perMinute: event.target.value })} />
      <span className="fold-text">/min</span>
      <input className="fold-input fold-number" aria-label="A day" inputMode="numeric" value={row.form.perDay} placeholder="–" onChange={(event) => edits.patch(row.id, { perDay: event.target.value })} />
      <span className="fold-text">/day</span>
    </Fold>
  );
}

/** What the app holds where the key was: the handle as it is, with a prefix, or a JWT carrying some claims. */
export function PlaceholderField({ row, edits }: FieldProps) {
  const form = row.form;
  return (
    <Fold invalid={any(row.problems, 'placeholder')} className={form.placeholder === 'none' ? 'is-short' : undefined}>
      <select className={`fold-select${form.placeholder === 'none' ? '' : ' fold-lead'}`} aria-label="Placeholder" value={form.placeholder} onChange={(event) => edits.patch(row.id, { placeholder: event.target.value as Form['placeholder'] })}>
        <option value="none">Handle</option>
        <option value="prefix">Prefix</option>
        <option value="jwt">JWT</option>
      </select>
      {form.placeholder !== 'none' && (
        <input className="fold-input mono" aria-label={form.placeholder === 'prefix' ? 'Prefix' : 'Claims'} value={form.shape} placeholder={form.placeholder === 'prefix' ? 'sk_test_' : 'claims'} onChange={(event) => edits.patch(row.id, { shape: event.target.value })} />
      )}
    </Fold>
  );
}

// --- adding, copying, reviewing -----------------------------------------------------------------

/** Add credential, and Copy from environment in its chevron's menu; for whoever holds `proxy.edit`. */
export function AddCredential({ canEdit, project, onAdd, onCopy }: { canEdit: boolean; project: string; onAdd: () => void; onCopy: () => void }) {
  if (!canEdit) {
    return (
      <Toggletip label={`Needs proxy.edit: Owners of ${project} and of the instance`}>
        <button type="button" className="btn btn-primary" aria-disabled="true">
          <Plus size={14} />
          Add credential
        </button>
      </Toggletip>
    );
  }
  return (
    <div className="split-button">
      <button className="btn btn-primary" type="button" onClick={onAdd}>
        <Plus size={14} />
        Add credential
      </button>
      <Menu.Root>
        <Menu.Trigger className="btn btn-primary btn-icon" aria-label="More to add">
          <ChevronDown size={14} />
        </Menu.Trigger>
        <MenuPopup align="start">
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
  const changes = edits.changes();
  return (
    <Modal open onOpenChange={(open) => !open && edits.closeReview()} wide title={`Save to ${place.project}/${place.environment}`}>
      <div className="form">
        {changes.map(({ row, change }) => (
          <section key={row.id} className="proxy-change" aria-label={row.definition.name}>
            <h3 className="proxy-change-title">
              <span className={`tag ${row.state === 'deleted' ? 'tag-red' : row.state === 'added' ? 'tag-green' : 'tag-blue'}`}>
                {row.state === 'deleted' ? 'Delete' : row.state === 'added' ? 'Add' : 'Update'}
              </span>
              <span className="mono">{row.state === 'deleted' ? row.before!.name : row.definition.name}</span>
            </h3>
            {change.definition !== null && <Diff rows={diffOf(row.before, change.definition).filter((line) => row.before !== null || line.label !== 'Name')} adding={row.before === null} />}
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
  // Words in the page's face; addresses, templates and paths as code.
  const code = (label: string) => (['Name', 'Upstream', 'Egress', 'Sends', 'Paths'].includes(label) ? ' mono' : '');
  return (
    <table className="proxy-diff">
      <tbody>
        {rows.map((row) => (
          <tr key={row.label}>
            <th scope="row">{row.label}</th>
            {!adding && <td className={`proxy-diff-before${code(row.label)}`}>{row.before ?? '–'}</td>}
            <td className={`${adding ? '' : 'proxy-diff-after'}${code(row.label)}`}>{row.after ?? '–'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/**
 * Definitions from another of the project's environments, added here as
 * pending, as they are: prod set up from staging, its upstreams edited
 * before the save. One this environment cannot take says why.
 */
export function CopyFromEnvironment({
  store,
  place,
  config,
  keys,
  edits,
  onClose,
}: {
  store: ProxyStore;
  place: ProxyPlace;
  config: ProxyConfig;
  keys: readonly SecretKey[];
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
    .filter((one) => one.source === 'environment' && one.shadowedSince === null)
    .map((credential) => {
      const definition = definitionOf(credential);
      const problems = definitionProblems(definition, { place, keys, code, others: here, egresses: config.egresses, before: null });
      const held = here.includes(definition.name) ? 'Here already' : null;
      const refusal = problems.keys ?? problems.template ?? problems.user ?? problems.accessKeyId ?? problems.secretAccessKey ?? problems.egress ?? null;
      return { definition, held, problem: held ?? refusal };
    });
  const chosen = checked.filter((one) => one.problem === null && picked.has(one.definition.name)).map((one) => one.definition);

  return (
    <Modal open onOpenChange={(open) => !open && onClose()} wide title="Copy from environment">
      <div className="form">
        <select className="select" style={{ width: '14rem' }} aria-label="From" value={source} onChange={(event) => {
          setSource(event.target.value);
          setPicked(new Set());
        }}>
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
                  <span className="mono proxy-copy-name">{definition.name}</span>
                  <span className="mono proxy-copy-upstream">{definition.upstream.replace(/^https:\/\//, '')}</span>
                  {problem !== null && <span className={`proxy-copy-problem${held === null ? ' proxy-error' : ''}`}>{problem}</span>}
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
              edits.add(chosen.map(formOf));
              onClose();
            }}
          >
            Copy {chosen.length === 0 ? '' : chosen.length === 1 ? chosen[0]!.name : `${chosen.length}`}
          </button>
        </div>
      </div>
    </Modal>
  );
}
