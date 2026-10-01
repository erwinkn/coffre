import { CoffreError, planImport, type CoffreClient } from '@coffre/client';
import { parseDotenv } from '@coffre/core/dotenv';
import {
  useEffect,
  useRef,
  useState,
  type ComponentProps,
  type InputHTMLAttributes,
} from 'react';
import { createFileRoute, Link, useLoaderData, useRouter } from '@tanstack/react-router';
import { DropdownMenu } from 'radix-ui';
import { toast } from 'sonner';
import { failureMessage, Refusal, uiResult, useCoffre } from '../lib/coffre';
import { useAction } from '../lib/use-action';
import type {
  ImportPlanEntry,
  ImportProblem,
  Permission,
  SecretKey,
  SecretVersion,
} from '../shared/models';
import { canRevealSecrets } from '../lib/capabilities';
import {
  applySecretEditBatch,
  hasSecretEditConflict,
  secretChangeFor,
  type SecretChange,
  type SecretDraft,
} from '../lib/secret-edit-batch';
import { revealIsCurrent, type Reveal } from '../lib/reveal';
import { secretKeyProblem } from '../lib/validation';
import {
  breakAfterUnderscores,
  ConfirmButton,
  CopyButton,
  EmptyState,
  ErrorLine,
  Modal,
  Notice,
  Spinner,
  Timestamp,
  Tip,
} from '../components/ui';
import { Card, ClosedDoor, PageHeader } from '../components/page';
import { SecretReadOnly } from '../components/affordances';
import { Syncs } from '../components/syncs';
import {
  AlertCircle,
  Archive,
  Clock,
  Eye,
  EyeOff,
  Hash,
  History,
  Key,
  Lock,
  MoreHorizontal,
  Pencil,
  Plus,
  RotateBack,
  Search,
  Terminal,
  Upload,
  X,
} from '../components/icons';

/**
 * How long a revealed value stays on screen.
 *
 * A revealed secret is live credential material sitting in a browser tab that
 * may well be shared on a call. Hiding it again costs nothing -- the read is
 * already logged, and re-revealing writes a second, honest audit row.
 */
const REVEAL_TTL_SECONDS = 45;

export const Route = createFileRoute('/projects/$project/$environment')({
  // `?filter=KEY` opens the ledger narrowed to matching keys, for links to one secret.
  validateSearch: (search: Record<string, unknown>): { filter?: string } => ({
    filter: typeof search.filter === 'string' && search.filter !== '' ? search.filter : undefined,
  }),
  loader: async ({ context: { client }, params }) => {
    const path = `${params.project}/${params.environment}`;
    const [keys, syncs] = await Promise.all([
      uiResult(() => client.secrets.list(path)),
      uiResult(() => client.syncs.list(path)),
    ]);
    return { keys, syncs };
  },
  component: EnvironmentPage,
});

function EnvironmentPage() {
  const { keys: result, syncs } = Route.useLoaderData();
  const { project, environment } = Route.useParams();

  if (!result.ok) {
    return (
      <ClosedDoor
        icon={<Lock size={18} />}
        label={
          <span className="mono">
            {project}/{environment}
          </span>
        }
        title="This environment is closed to you"
        actions={
          <Link className="btn" to="/projects/$project" params={{ project }}>
            Back to {project}
          </Link>
        }
      >
        {result.error}
      </ClosedDoor>
    );
  }

  // Keyed by location: pending edits belong to the environment they were
  // started in. The route component is reused across params, so without the
  // key they would follow you into the next environment and be written there.
  return (
    <EnvironmentLedger
      key={`${project}/${environment}`}
      project={project}
      environment={environment}
      permissions={result.permissions}
      keys={result.keys}
      syncs={syncs}
    />
  );
}

type Pending = { key: string; what: string };

function EnvironmentLedger({
  project,
  environment,
  permissions,
  keys,
  syncs,
}: {
  project: string;
  environment: string;
  permissions: Permission[];
  keys: SecretKey[];
  syncs: ComponentProps<typeof Syncs>['result'];
}) {
  const router = useRouter();
  const coffre = useCoffre();
  const place = `${project}/${environment}`;
  const [drafts, setDrafts] = useState<SecretDraft[]>([]);
  const [changes, setChanges] = useState<Record<string, SecretChange>>({});
  // Rows opened for editing that may not have changed yet. A row with a
  // pending change is in edit mode whether or not it is listed here.
  const [editing, setEditing] = useState<ReadonlySet<string>>(() => new Set());
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [query, setQuery] = useState(Route.useSearch().filter ?? '');
  const nextDraftId = useRef(0);

  const canWrite = permissions.includes('secret.write');
  const canArchive = permissions.includes('secret.archive');
  const canReveal = canRevealSecrets(permissions);

  const active = keys.filter((entry) => !entry.archived);
  const archived = keys.filter((entry) => entry.archived);
  const existing = new Set(keys.map((entry) => entry.key));

  const changedEntries = active.filter(
    (entry) => secretChangeFor(changes, entry.key) !== undefined,
  );
  const hasConflict = hasSecretEditConflict(active, drafts, changes);
  // Every name that will be written. Blank ones only hold the save back -- a
  // row you just added is not an error yet -- while malformed ones say why.
  const pendingNames = [
    ...drafts.map((row) => row.key.trim()),
    ...changedEntries.flatMap((entry) => {
      const change = secretChangeFor(changes, entry.key);
      return change === undefined || change.archived ? [] : [change.key.trim()];
    }),
  ];
  const unnamed = pendingNames.some((name) => name === '');
  const invalid = pendingNames.some((name) => name !== '' && secretKeyProblem(name) !== null);
  const pendingCount = drafts.length + changedEntries.length;
  const ready = pendingCount > 0 && !unnamed && !invalid && !hasConflict;

  function patchChange(entry: SecretKey, patch: Partial<SecretChange>) {
    setChanges((current) => {
      const next = {
        ...(secretChangeFor(current, entry.key) ?? {
          key: entry.key,
          value: null,
          archived: false,
        }),
        ...patch,
      };
      const dirty = next.key !== entry.key || next.value !== null || next.archived;
      if (dirty) return { ...current, [entry.key]: next };
      const { [entry.key]: _, ...rest } = current;
      return rest;
    });
  }

  function dropChange(key: string) {
    setChanges((current) => {
      const { [key]: _, ...rest } = current;
      return rest;
    });
    setEditing((current) => {
      const next = new Set(current);
      next.delete(key);
      return next;
    });
  }

  function addDraft() {
    // New rows go to the top, where the button that made them is, rather than
    // below a list that may be longer than the screen.
    setDrafts((rows) => [{ id: nextDraftId.current++, key: '', value: '' }, ...rows]);
  }

  function discardAll() {
    setDrafts([]);
    setChanges({});
    setEditing(new Set());
    setSaveError(null);
  }

  /**
   * Write every pending edit: renames one by one, then the rest as one patch
   * that lands whole or not at all (see `applySecretEditBatch`). Whatever did
   * not land stays pending, so pressing save again retries exactly that.
   */
  async function saveChanges() {
    if (!ready || saving) return;
    setSaving(true);
    setSaveError(null);
    const outcome = await applySecretEditBatch({
      active,
      drafts,
      changes,
      operations: {
        rename: async (key, nextKey) => {
          try {
            await coffre.secrets.rename(`${place}/${key}`, nextKey);
          } catch (error) {
            // A refused rename names the key it stopped at.
            throw new Refusal(`${key}: ${failureMessage(error)}`);
          }
        },
        write: async (patch) => {
          try {
            await coffre.secrets.set(place, patch);
          } catch (error) {
            throw new Refusal(failureMessage(error));
          }
        },
      },
    });

    setDrafts(outcome.drafts);
    setChanges(outcome.changes);
    setEditing(new Set());

    if (outcome.applied > 0) {
      try {
        await router.invalidate();
      } catch {
        setSaveError('Saved, but the page could not refresh. Reload before you retry.');
        setSaving(false);
        return;
      }
    }

    if (outcome.error === null) {
      // Counted as the save button counted them: a rename with a new value is one change.
      toast.success(`Saved ${pendingCount} change${pendingCount === 1 ? '' : 's'}`);
    } else {
      const message =
        outcome.error instanceof Error ? outcome.error.message : 'The request could not be sent.';
      // Only renames can have landed before a failure: the patch is all or nothing.
      setSaveError(
        outcome.applied === 0
          ? message
          : `${message} The renames before it were saved; nothing else was, and the rest is ready to retry.`,
      );
    }
    setSaving(false);
  }

  // Cmd/Ctrl+Enter saves from anywhere on the page while edits are pending.
  const saveRef = useRef(saveChanges);
  saveRef.current = saveChanges;
  useEffect(() => {
    if (pendingCount === 0) return;
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Enter' && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        void saveRef.current();
      }
    }
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [pendingCount]);

  const pending: Pending[] = [
    ...drafts.map((draft) => ({
      key: draft.key.trim() || 'unnamed',
      what: existing.has(draft.key.trim()) ? 'new version' : 'added',
    })),
    ...changedEntries.map((entry) => {
      const change = secretChangeFor(changes, entry.key)!;
      if (change.archived) return { key: entry.key, what: 'archived' };
      const renamed = change.key.trim() !== entry.key;
      if (renamed && change.value !== null) {
        return { key: entry.key, what: `→ ${change.key.trim()}, new value` };
      }
      if (renamed) return { key: entry.key, what: `→ ${change.key.trim()}` };
      return { key: entry.key, what: 'new value' };
    }),
  ];

  // Two rows that are both still blank "conflict" too, so say nothing until
  // every name is filled in; the blank row speaks for itself.
  const problem = unnamed
    ? null
    : hasConflict
      ? 'Two pending edits would end up with the same name. Secret names are unique in an environment.'
      : invalid
        ? 'Names are letters, digits and underscores, and cannot start with a digit.'
        : null;

  // Filtering narrows what is listed, never what is saved: a pending edit on
  // a row the filter hides still counts, and still shows in the save bar.
  const needle = query.trim().toLowerCase();
  const listed =
    needle === '' ? active : active.filter((entry) => entry.key.toLowerCase().includes(needle));
  const columns = 6;

  return (
    <>
      <PageHeader
        tile={project}
        title={environment}
        aside={<EnvironmentName project={project} environment={environment} />}
        actions={
          <>
            {canWrite && canReveal && <ImportEnv project={project} environment={environment} />}
            {canWrite && (
              <button className="btn btn-primary" onClick={addDraft} disabled={saving}>
                <Plus size={14} />
                New secret
              </button>
            )}
          </>
        }
      />

      {(active.length > 0 || drafts.length > 0) && (
        <div className="toolbar">
          <label className="filter input-group">
            <span className="visually-hidden">Filter secrets by name</span>
            <Search size={14} className="input-icon" />
            <input
              className="input"
              type="search"
              placeholder="Filter by name…"
              spellCheck={false}
              autoComplete="off"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </label>
          <div className="toolbar-meta">
            <span className="th" title="Run a process with these secrets in its environment">
              <Terminal size={14} />
              <code>
                coffre run {project}/{environment} -- …
              </code>
              <CopyButton
                value={`coffre run ${project}/${environment} -- `}
                label="Copy command"
              />
            </span>
          </div>
        </div>
      )}

      <section className="card" aria-label="Secrets">
        {active.length === 0 && drafts.length === 0 ? (
          <EmptyState
            title="No secrets yet"
            actions={
              canWrite ? (
                <>
                  <button className="btn btn-primary" onClick={addDraft}>
                    <Plus size={14} />
                    New secret
                  </button>
                  {canReveal && <ImportEnv project={project} environment={environment} />}
                </>
              ) : undefined
            }
          >
            {canWrite
              ? 'Add them one by one, or import an existing .env file. Nothing is written until you save, or until you have seen the import plan.'
              : 'Nothing has been written to this environment, and adding the first secret needs secret.write.'}
          </EmptyState>
        ) : (
          <div className="dt-wrap">
            <table className="dt secrets stacks">
              <thead>
                <tr>
                  <th className="n">#</th>
                  <th className="col-key">
                    <span className="th">
                      <Key size={14} />
                      Key
                    </span>
                  </th>
                  <th>
                    <span className="th">
                      <Lock size={14} />
                      Value
                      {!canReveal && <span className="th-note">hidden from you</span>}
                    </span>
                  </th>
                  <th className="col-version">
                    <span className="th">
                      <Hash size={14} />
                      Version
                    </span>
                  </th>
                  <th className="col-written col-hide-narrow">
                    <span className="th">
                      <Clock size={14} />
                      Last written
                    </span>
                  </th>
                  <th className="col-actions">
                    <span className="visually-hidden">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {drafts.map((draft) => (
                  <DraftRow
                    key={draft.id}
                    draft={draft}
                    existingVersion={
                      keys.find((entry) => entry.key === draft.key.trim())?.version ?? null
                    }
                    disabled={saving}
                    onChange={(patch) =>
                      setDrafts((rows) =>
                        rows.map((row) => (row.id === draft.id ? { ...row, ...patch } : row)),
                      )
                    }
                    onRemove={() => setDrafts((rows) => rows.filter((row) => row.id !== draft.id))}
                  />
                ))}

                {listed.map((entry) => {
                  const change = secretChangeFor(changes, entry.key);
                  return (
                    <SecretRow
                      key={entry.key}
                      number={active.indexOf(entry) + 1}
                      project={project}
                      environment={environment}
                      entry={entry}
                      change={change ?? { key: entry.key, value: null, archived: false }}
                      editing={
                        change?.archived !== true &&
                        (editing.has(entry.key) || change !== undefined)
                      }
                      canWrite={canWrite}
                      canArchive={canArchive}
                      canReveal={canReveal}
                      disabled={saving}
                      columns={columns}
                      onEdit={() => setEditing((current) => new Set(current).add(entry.key))}
                      onPatch={(patch) => patchChange(entry, patch)}
                      onUndo={() => dropChange(entry.key)}
                      onMarkArchive={() => {
                        setEditing((current) => {
                          const next = new Set(current);
                          next.delete(entry.key);
                          return next;
                        });
                        setChanges((current) => ({
                          ...current,
                          [entry.key]: { key: entry.key, value: null, archived: true },
                        }));
                      }}
                    />
                  );
                })}

                {listed.length === 0 && active.length > 0 && (
                  <tr>
                    <td colSpan={columns} className="cell-muted" style={{ padding: '1rem' }}>
                      No secret name contains “{query.trim()}”.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <Syncs
        project={project}
        environment={environment}
        result={syncs}
        canRun={canWrite || permissions.includes('environment.manage')}
      />

      {archived.length > 0 && (
        <Card
          labelledBy="archived-secrets"
          title="Archived"
          description={
            <>
              Retired, so no longer served or injected by <code>coffre run</code>. Their history
              and audit trail are intact, and restoring is immediate.
            </>
          }
        >
          <div className="dt-wrap">
            <table className="dt secrets secrets-archived stacks">
              <thead>
                <tr>
                  <th className="n">#</th>
                  <th className="col-key">
                    <span className="th">
                      <Key size={14} />
                      Key
                    </span>
                  </th>
                  <th className="col-version">
                    <span className="th">
                      <Hash size={14} />
                      Version
                    </span>
                  </th>
                  <th className="col-written col-hide-narrow">
                    <span className="th">
                      <Clock size={14} />
                      Last written
                    </span>
                  </th>
                  <th className="col-actions">
                    <span className="visually-hidden">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {archived.map((entry, index) => (
                  <ArchivedRow
                    key={entry.key}
                    number={index + 1}
                    project={project}
                    environment={environment}
                    entry={entry}
                    canArchive={canArchive}
                    canReveal={canReveal}
                  />
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {pendingCount > 0 && (
        <div className="savebar" role="region" aria-label="Unsaved changes">
          <div className="savebar-inner">
            <span className="savebar-count">
              <span className="dot" aria-hidden />
              {pendingCount} unsaved change{pendingCount === 1 ? '' : 's'}
            </span>
            <span className="savebar-summary">
              {pending.slice(0, 3).map((item, index) => (
                <span key={`${item.key}:${index}`}>
                  {index > 0 && ' · '}
                  <span className="mono">{item.key}</span> {item.what}
                </span>
              ))}
              {pending.length > 3 && ` · and ${pending.length - 3} more`}
            </span>
            <div className="savebar-actions">
              <button className="btn btn-sm" onClick={discardAll} disabled={saving}>
                Discard
              </button>
              <button
                className="btn btn-sm btn-primary"
                onClick={() => void saveChanges()}
                disabled={saving || !ready}
                title="Save (⌘ Enter or Ctrl Enter)"
                aria-keyshortcuts="Meta+Enter Control+Enter"
              >
                {saving && <Spinner size={13} />}
                Save {pendingCount === 1 ? 'change' : `${pendingCount} changes`}
              </button>
            </div>
            {(saveError ?? problem) !== null && (
              <p className="savebar-error" role="alert">
                <AlertCircle size={14} />
                <span>{saveError ?? problem}</span>
              </p>
            )}
          </div>
        </div>
      )}
    </>
  );
}

/** The display name sits beside the slug; it comes from the shell's project tree. */
function EnvironmentName({ project, environment }: { project: string; environment: string }) {
  const { projects } = useLoaderData({ from: '__root__' });
  const name = projects
    .find((entry) => entry.slug === project)
    ?.environments.find((entry) => entry.slug === environment)?.name;
  return name === undefined ? null : <>{name}</>;
}

/* -------------------------------------------------------------------------- */
/* Rows                                                                        */
/* -------------------------------------------------------------------------- */

/**
 * A text field whose contents are masked until asked, for secret values.
 *
 * Where the browser supports it, the mask is CSS on a text input rather than
 * `type="password"`: password fields invite password managers to offer to
 * save or fill them, and a secret being typed into coffre is neither.
 */
function MaskedInput({
  masked,
  className = '',
  ...props
}: Omit<InputHTMLAttributes<HTMLInputElement>, 'type'> & { masked: boolean }) {
  const [cssMask, setCssMask] = useState(false);
  useEffect(() => {
    setCssMask(typeof CSS !== 'undefined' && CSS.supports('-webkit-text-security', 'disc'));
  }, []);

  return (
    <input
      {...props}
      type={masked && !cssMask ? 'password' : 'text'}
      className={`${className}${masked && cssMask ? ' is-masked' : ''}`}
      autoComplete="off"
      spellCheck={false}
      data-1p-ignore
      data-lpignore="true"
      data-bwignore
    />
  );
}

function ValueField({
  label,
  value,
  onChange,
  placeholder,
  disabled,
  autoFocus,
  onEscape,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  disabled: boolean;
  autoFocus?: boolean;
  onEscape?: () => void;
}) {
  const [shown, setShown] = useState(false);
  return (
    <div className="input-group">
      <MaskedInput
        className="input input-mono"
        masked={!shown}
        aria-label={label}
        placeholder={placeholder}
        value={value}
        disabled={disabled}
        autoFocus={autoFocus}
        onChange={(event) => onChange(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === 'Escape' && onEscape !== undefined) onEscape();
        }}
      />
      <button
        type="button"
        className="btn btn-quiet btn-sm btn-icon input-addon"
        aria-label={shown ? 'Mask the value' : 'Show the value'}
        aria-pressed={shown}
        onClick={() => setShown((current) => !current)}
      >
        {shown ? <EyeOff size={14} /> : <Eye size={14} />}
      </button>
    </div>
  );
}

function useSecondsLeft(reveal: Reveal | null): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (reveal === null) return;
    setNow(Date.now());
    const tick = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(tick);
  }, [reveal]);
  if (reveal === null) return 0;
  return Math.max(0, Math.ceil(REVEAL_TTL_SECONDS - (now - reveal.at) / 1000));
}

function SecretRow({
  number,
  project,
  environment,
  entry,
  change,
  editing,
  canWrite,
  canArchive,
  canReveal,
  disabled,
  columns,
  onEdit,
  onPatch,
  onUndo,
  onMarkArchive,
}: {
  number: number;
  project: string;
  environment: string;
  entry: SecretKey;
  change: SecretChange;
  editing: boolean;
  canWrite: boolean;
  canArchive: boolean;
  canReveal: boolean;
  disabled: boolean;
  columns: number;
  onEdit: () => void;
  onPatch: (patch: Partial<SecretChange>) => void;
  onUndo: () => void;
  onMarkArchive: () => void;
}) {
  const [reveal, setReveal] = useState<Reveal | null>(null);
  const coffre = useCoffre();
  const [revealing, setRevealing] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The current value, loaded on request as the starting point for an edit.
  // It is not a change until it is edited: saving it untouched would append a
  // version identical to the one it came from.
  const [base, setBase] = useState<Reveal | null>(null);

  // A reveal belongs to the version it decrypted. The moment the row shows a
  // different version -- saved here, rolled back, or written by someone else
  // and picked up on refresh -- the old plaintext is not the value any more,
  // and must not stay on screen pretending to be.
  const shown = revealIsCurrent(reveal, entry.version) ? reveal : null;
  useEffect(() => {
    if (reveal !== null && !revealIsCurrent(reveal, entry.version)) setReveal(null);
  }, [reveal, entry.version]);

  useEffect(() => {
    if (reveal === null) return;
    const timer = setTimeout(() => setReveal(null), REVEAL_TTL_SECONDS * 1000);
    return () => clearTimeout(timer);
  }, [reveal]);

  const secondsLeft = useSecondsLeft(shown);

  const editBase = editing && revealIsCurrent(base, entry.version) ? base : null;
  useEffect(() => {
    if (!editing) setBase(null);
  }, [editing]);

  async function readValue(): Promise<string | null> {
    if (shown !== null) return shown.value;
    setRevealing(true);
    try {
      const { values } = await coffre.secrets.reveal(`${project}/${environment}/${entry.key}`);
      const value = values[entry.key];
      setError(null);
      setReveal({ value, version: entry.version, at: Date.now() });
      return value;
    } catch (failure) {
      setError(
        failure instanceof CoffreError
          ? failureMessage(failure)
          : 'The request could not be sent. Nothing was read.',
      );
      return null;
    } finally {
      setRevealing(false);
    }
  }

  function toggleReveal() {
    if (shown !== null) setReveal(null);
    else void readValue();
  }

  const leaving = change.archived;
  const renamed = change.key !== entry.key;
  const valueChanged = change.value !== null;
  const keyProblem = editing ? secretKeyProblem(change.key.trim()) : null;
  const state = leaving
    ? ' is-leaving'
    : editing && (renamed || valueChanged)
      ? ' is-changed'
      : shown !== null
        ? ' is-revealed'
        : '';
  const version = entry.version ?? 0;

  return (
    <>
      <tr className={`secret-row${state}`}>
        <td className="n">{number}</td>
        <td className="cell-key" data-label="Key">
          {editing && canWrite ? (
            <div className="edit-stack">
              <input
                className="input input-mono"
                aria-label={`Name for ${entry.key}`}
                aria-invalid={keyProblem !== null}
                spellCheck={false}
                autoComplete="off"
                value={change.key}
                disabled={disabled}
                onChange={(event) => onPatch({ key: event.target.value })}
                onKeyDown={(event) => {
                  if (event.key === 'Escape') onUndo();
                }}
              />
              {(keyProblem !== null || renamed) && (
                <span className={`edit-note${keyProblem !== null ? ' edit-note-error' : ''}`}>
                  {keyProblem ?? (
                    <>
                      Renamed from <span className="mono">{entry.key}</span>
                    </>
                  )}
                </span>
              )}
            </div>
          ) : (
            <div className="key-cell">
              <span>{breakAfterUnderscores(entry.key)}</span>
              {leaving && <span className="tag tag-red">will be archived</span>}
            </div>
          )}
        </td>

        <td data-label="Value">
          {editing && canWrite ? (
            <div className="edit-stack">
              <ValueField
                label={`New value for ${entry.key}`}
                value={change.value ?? editBase?.value ?? ''}
                placeholder="New value"
                disabled={disabled}
                autoFocus
                onChange={(value) =>
                  onPatch({ value: value === (editBase?.value ?? '') ? null : value })
                }
                onEscape={onUndo}
              />
              <span className="edit-note">
                <span>
                  {valueChanged
                    ? `Saving appends v${version + 1}; v${version} stays restorable.`
                    : editBase !== null
                      ? `This is v${version}. Change it to append v${version + 1}.`
                      : `Nothing is decrypted to edit. Left empty, v${version} stays current.`}
                </span>
                {canReveal && !valueChanged && editBase === null && (
                  <button
                    type="button"
                    className="act"
                    disabled={revealing}
                    onClick={async () => {
                      const value = await readValue();
                      if (value !== null) {
                        setBase({ value, version: entry.version, at: Date.now() });
                      }
                    }}
                  >
                    {revealing && <Spinner size={12} />}
                    Start from current value
                  </button>
                )}
              </span>
            </div>
          ) : shown !== null && !leaving ? (
            <div
              className="revealed"
              style={{ ['--reveal-ttl' as string]: `${REVEAL_TTL_SECONDS}s` }}
            >
              <span className="revealed-value">{shown.value === '' ? '(empty)' : shown.value}</span>
              <span className="revealed-note">
                Hides in {secondsLeft}s
              </span>
              <span className="revealed-meter" aria-hidden />
            </div>
          ) : (
            <span className="mask" aria-label="Hidden">
              ••••••••••••
            </span>
          )}
        </td>

        <td className="col-version" data-label="Version">
          {editing && valueChanged ? (
            <span className="version-shift">
              v{version} → <b>v{version + 1}</b>
            </span>
          ) : (
            <span className="version-shift">{entry.version === null ? '—' : `v${entry.version}`}</span>
          )}
        </td>

        <td className="col-written col-hide-narrow" data-label="Last written">
          <Written entry={entry} />
        </td>

        <td className="col-actions">
          <div className="acts">
            {leaving ? (
              <Tip label="Keep">
                <button
                  className="act act-icon act-quiet"
                  onClick={onUndo}
                  disabled={disabled}
                  aria-label={`Keep ${entry.key}`}
                >
                  <RotateBack size={14} />
                </button>
              </Tip>
            ) : editing ? (
              <Tip label={renamed || valueChanged ? 'Undo changes' : 'Cancel'}>
                <button
                  className="act act-icon act-quiet"
                  onClick={onUndo}
                  disabled={disabled}
                  aria-label={`${renamed || valueChanged ? 'Undo changes to' : 'Stop editing'} ${entry.key}`}
                >
                  {renamed || valueChanged ? <RotateBack size={14} /> : <X size={15} />}
                </button>
              </Tip>
            ) : (
              <>
                {/* Copy comes in to the left, so Hide stays where Reveal was clicked. */}
                {shown !== null && (
                  <CopyButton variant="act" value={shown.value} label={`Copy ${entry.key}`} />
                )}
                <SecretReadOnly canReveal={canReveal}>
                  <Tip label={shown === null ? 'Reveal' : 'Hide'}>
                    <button
                      className="act act-icon act-accent"
                      onClick={toggleReveal}
                      disabled={revealing}
                      aria-label={`${shown === null ? 'Reveal' : 'Hide'} ${entry.key}`}
                    >
                      {revealing ? (
                        <Spinner size={13} />
                      ) : shown === null ? (
                        <Eye size={15} />
                      ) : (
                        <EyeOff size={15} />
                      )}
                    </button>
                  </Tip>
                </SecretReadOnly>
                {canWrite && (
                  <Tip label="Edit">
                    <button
                      className="act act-icon"
                      onClick={() => {
                        // A value already revealed is already on the record, so
                        // it becomes the starting point instead of being thrown
                        // away and read again.
                        if (shown !== null) setBase(shown);
                        setReveal(null);
                        onEdit();
                      }}
                      disabled={disabled}
                      aria-label={`Edit ${entry.key}`}
                    >
                      <Pencil size={14} />
                    </button>
                  </Tip>
                )}
                {(canReveal || canArchive) && (
                  <DropdownMenu.Root>
                    <DropdownMenu.Trigger asChild>
                      <button
                        className="act act-icon act-quiet"
                        aria-label={`More for ${entry.key}`}
                        disabled={disabled}
                      >
                        <MoreHorizontal size={16} />
                      </button>
                    </DropdownMenu.Trigger>
                    <DropdownMenu.Portal>
                      <DropdownMenu.Content className="menu" sideOffset={6} align="end">
                        <SecretReadOnly canReveal={canReveal}>
                          <DropdownMenu.Item
                            className="menu-item"
                            onSelect={() => setHistoryOpen((open) => !open)}
                          >
                            <History size={14} />
                            {historyOpen ? 'Hide history' : 'Version history'}
                          </DropdownMenu.Item>
                        </SecretReadOnly>
                        {canArchive && (
                          <>
                            {canReveal && <DropdownMenu.Separator className="menu-sep" />}
                            <DropdownMenu.Item
                              className="menu-item menu-item-danger"
                              onSelect={() => {
                                setReveal(null);
                                onMarkArchive();
                              }}
                            >
                              <Archive size={14} />
                              Archive
                              <span className="menu-hint">on save</span>
                            </DropdownMenu.Item>
                          </>
                        )}
                      </DropdownMenu.Content>
                    </DropdownMenu.Portal>
                  </DropdownMenu.Root>
                )}
              </>
            )}
          </div>
        </td>
      </tr>

      {historyOpen && canReveal && (
        <tr className="detail-row">
          <td colSpan={columns}>
            <VersionHistory
              project={project}
              environment={environment}
              secretKey={entry.key}
              currentVersion={entry.version}
              canWrite={canWrite}
              onClose={() => setHistoryOpen(false)}
              onRolledBack={() => setReveal(null)}
            />
          </td>
        </tr>
      )}

      {error !== null && (
        <tr className="row-error">
          <td colSpan={columns}>
            <ErrorLine error={error} />
          </td>
        </tr>
      )}
    </>
  );
}

/**
 * Who wrote the current version and how long ago, on one line: the local part
 * of the email is enough to recognise a colleague, and the full address and
 * the exact time are a hover away.
 */
function Written({ entry }: { entry: SecretKey }) {
  if (entry.updatedBy === null && entry.updatedAt === null) {
    return <span className="cell-muted">—</span>;
  }
  const by = entry.updatedBy ?? 'unknown';
  return (
    <span className="written">
      <span className="written-by" title={by}>
        {by.split('@')[0]}
      </span>
      {entry.updatedAt !== null && (
        <>
          <span className="cell-muted" aria-hidden>
            ·
          </span>
          <span className="cell-muted">
            <Timestamp iso={entry.updatedAt} display="relative" />
          </span>
        </>
      )}
    </span>
  );
}

/**
 * A secret being typed, sitting in the table where it will end up.
 *
 * This replaced a separate "Add a secret" form. The form made you look away
 * from the list to add to it, and only ever accepted one key at a time; a row
 * in place accepts as many as you want to queue.
 */
function DraftRow({
  draft,
  existingVersion,
  disabled,
  onChange,
  onRemove,
}: {
  draft: SecretDraft;
  existingVersion: number | null;
  disabled: boolean;
  onChange: (patch: Partial<SecretDraft>) => void;
  onRemove: () => void;
}) {
  const [touched, setTouched] = useState(false);
  const trimmed = draft.key.trim();
  const keyProblem = trimmed === '' ? (touched ? 'Give it a name.' : null) : secretKeyProblem(trimmed);
  const isNewVersion = trimmed !== '' && existingVersion !== null;

  return (
    <tr className="secret-row is-draft">
      <td className="n" aria-label="New">
        +
      </td>
      <td className="cell-key" data-label="New secret">
        <div className="edit-stack">
          <input
            className="input input-mono"
            // Only the row that just mounted takes focus, which is the one the
            // New secret button created.
            autoFocus
            aria-label="Name of the new secret"
            aria-invalid={keyProblem !== null}
            placeholder="NAME_OF_SECRET"
            spellCheck={false}
            autoComplete="off"
            value={draft.key}
            disabled={disabled}
            onBlur={() => setTouched(true)}
            onChange={(event) => onChange({ key: event.target.value })}
            onKeyDown={(event) => {
              if (event.key === 'Escape') onRemove();
            }}
          />
          {(keyProblem !== null || isNewVersion) && (
            <span className={`edit-note${keyProblem !== null ? ' edit-note-error' : ''}`}>
              {keyProblem ??
                'This name already exists here. Saving appends a new version to it rather than creating a second secret.'}
            </span>
          )}
        </div>
      </td>
      <td data-label="Value">
        <div className="edit-stack">
          <ValueField
            label={`Value for ${trimmed === '' ? 'the new secret' : trimmed}`}
            value={draft.value}
            placeholder="Value"
            disabled={disabled}
            onChange={(value) => onChange({ value })}
            onEscape={onRemove}
          />
        </div>
      </td>
      <td className="col-version" data-label="Version">
        <span className="version-shift">
          {isNewVersion ? (
            <>
              v{existingVersion} → <b>v{existingVersion + 1}</b>
            </>
          ) : (
            <b>new</b>
          )}
        </span>
      </td>
      <td className="col-written col-hide-narrow">
        <span className="cell-muted">—</span>
      </td>
      <td className="col-actions">
        <div className="acts">
          <Tip label="Remove">
            <button
              className="act act-icon act-quiet"
              onClick={onRemove}
              disabled={disabled}
              aria-label={trimmed === '' ? 'Remove this new secret' : `Remove new secret ${trimmed}`}
            >
              <X size={15} />
            </button>
          </Tip>
        </div>
      </td>
    </tr>
  );
}

function ArchivedRow({
  number,
  project,
  environment,
  entry,
  canArchive,
  canReveal,
}: {
  number: number;
  project: string;
  environment: string;
  entry: SecretKey;
  canArchive: boolean;
  canReveal: boolean;
}) {
  const [historyOpen, setHistoryOpen] = useState(false);
  const coffre = useCoffre();
  const { pending, error, run } = useAction();

  function setArchived(archived: boolean) {
    run(
      () => coffre.secrets.update(`${project}/${environment}/${entry.key}`, { archived }),
      () =>
        // Restoring is fully reversible, so it gets an undo rather than a
        // confirmation dialog in front of it.
        toast.success(archived ? `${entry.key} archived` : `${entry.key} restored`, {
          action: { label: 'Undo', onClick: () => setArchived(!archived) },
        }),
    );
  }

  return (
    <>
      <tr className="secret-row is-archived">
        <td className="n">{number}</td>
        <td className="cell-key" data-label="Key">
          {breakAfterUnderscores(entry.key)}
        </td>
        <td className="col-version" data-label="Version">
          <span className="version-shift">{entry.version === null ? '—' : `v${entry.version}`}</span>
        </td>
        <td className="col-written col-hide-narrow" data-label="Last written">
          <Written entry={entry} />
        </td>
        <td className="col-actions">
          <div className="acts">
            <SecretReadOnly canReveal={canReveal}>
              <Tip label={historyOpen ? 'Hide history' : 'Version history'}>
                <button
                  className="act act-icon act-quiet"
                  onClick={() => setHistoryOpen((open) => !open)}
                  aria-label={`${historyOpen ? 'Hide history of' : 'Version history of'} ${entry.key}`}
                  aria-expanded={historyOpen}
                >
                  <History size={15} />
                </button>
              </Tip>
            </SecretReadOnly>
            {canArchive && (
              <Tip label="Restore">
                <button
                  className="act act-icon"
                  onClick={() => setArchived(false)}
                  disabled={pending}
                  aria-label={`Restore ${entry.key}`}
                >
                  {pending ? <Spinner size={13} /> : <RotateBack size={14} />}
                </button>
              </Tip>
            )}
          </div>
        </td>
      </tr>
      {historyOpen && (
        <tr className="detail-row">
          <td colSpan={5}>
            <VersionHistory
              project={project}
              environment={environment}
              secretKey={entry.key}
              currentVersion={entry.version}
              canWrite={false}
              onClose={() => setHistoryOpen(false)}
              onRolledBack={() => undefined}
            />
          </td>
        </tr>
      )}
      {error !== null && (
        <tr className="row-error">
          <td colSpan={5}>
            <ErrorLine error={error} />
          </td>
        </tr>
      )}
    </>
  );
}

/* -------------------------------------------------------------------------- */
/* History                                                                     */
/* -------------------------------------------------------------------------- */

function VersionHistory({
  project,
  environment,
  secretKey,
  currentVersion,
  canWrite,
  onClose,
  onRolledBack,
}: {
  project: string;
  environment: string;
  secretKey: string;
  currentVersion: number | null;
  canWrite: boolean;
  onClose: () => void;
  onRolledBack: () => void;
}) {
  const [versions, setVersions] = useState<SecretVersion[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const coffre = useCoffre();
  const { pending, error, run } = useAction();

  // Refetch whenever the current version moves, so a rollback -- here or by
  // anyone else -- is reflected in which row says "current".
  useEffect(() => {
    let cancelled = false;
    coffre.secrets
      .history(`${project}/${environment}/${secretKey}`)
      .then((result) => {
        if (cancelled) return;
        setVersions(result.versions);
        setLoadError(null);
      })
      .catch((failure: unknown) => {
        if (cancelled) return;
        setLoadError(
          failure instanceof CoffreError
            ? failureMessage(failure)
            : 'The version history could not be loaded.',
        );
      });
    return () => {
      cancelled = true;
    };
  }, [coffre, project, environment, secretKey, currentVersion]);

  return (
    <div className="history">
      <div className="history-head">
        <span className="history-title th">
          <History size={14} />
          Versions of <span className="mono">{secretKey}</span>
        </span>
        <button className="act" onClick={onClose}>
          Close
        </button>
      </div>

      {loadError !== null ? (
        <div className="history-body">
          <ErrorLine error={loadError} />
        </div>
      ) : versions === null ? (
        <p className="hint history-body">
          <Spinner size={13} /> Loading versions…
        </p>
      ) : (
        <div className="dt-wrap">
          <table className="dt">
            <thead>
              <tr>
                <th className="col-shrink">Version</th>
                <th className="col-shrink">Written (UTC)</th>
                <th>By</th>
                <th className="col-shrink">Key id</th>
                <th className="col-actions">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {versions.map((version) => (
                <tr key={version.version}>
                  <td className="cell-mono nowrap">
                    v{version.version}{' '}
                    {version.current && <span className="tag tag-blue">current</span>}
                  </td>
                  <td className="nowrap">
                    <Timestamp iso={version.createdAt} />
                  </td>
                  <td>{version.createdBy}</td>
                  <td className="cell-mono cell-muted nowrap">{version.kek}</td>
                  <td className="col-actions">
                    {canWrite && !version.current && (
                      <ConfirmButton
                        trigger={
                          <button className="act" disabled={pending}>
                            <RotateBack size={13} />
                            Roll back
                          </button>
                        }
                        title={
                          <>
                            Roll <span className="mono">{secretKey}</span> back to v
                            {version.version}?
                          </>
                        }
                        body={
                          <>
                            The current pointer moves to v{version.version}. Nothing is copied
                            or deleted, every version stays readable, and the next write
                            continues the numbering forward. Anything reading{' '}
                            <span className="mono">
                              {project}/{environment}
                            </span>{' '}
                            picks up the change immediately.
                          </>
                        }
                        confirmLabel={`Roll back to v${version.version}`}
                        destructive={false}
                        onConfirm={() =>
                          run(
                            () =>
                              coffre.secrets.restore(
                                `${project}/${environment}/${secretKey}`,
                                version.version,
                              ),
                            () => {
                              onRolledBack();
                              toast.success(`${secretKey} rolled back to v${version.version}`);
                            },
                          )
                        }
                      />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {error !== null && (
        <div className="history-body">
          <ErrorLine error={error} />
        </div>
      )}
      <p className="history-note">
        Metadata only. Listing versions decrypts nothing.
      </p>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Import                                                                      */
/* -------------------------------------------------------------------------- */

const PLAN_TAG: Record<ImportPlanEntry['action'], string> = {
  added: 'tag tag-green',
  changed: 'tag tag-blue',
  unchanged: 'tag',
};

/** Plan a .env import against what is stored, with a dry run of the write. */
async function planEnv(coffre: CoffreClient, path: string, content: string) {
  const parsed = parseDotenv(content);
  if (parsed.entries.length === 0) return { plan: [], changes: {}, problems: parsed.problems };
  return { ...(await planImport(coffre, path, parsed.entries)), problems: parsed.problems };
}

/**
 * Bulk import from a .env file.
 *
 * Always previews first, with a dry run of the write: the server compares
 * the file against the current values and answers per key, so no value
 * reaches this page. Comparing is still reading -- it needs secret.read as
 * well as secret.write, and the values it opens are logged as reads. Writing
 * then sends exactly the changes the preview showed, in one patch.
 */
function ImportEnv({ project, environment }: { project: string; environment: string }) {
  const [content, setContent] = useState('');
  const [plan, setPlan] = useState<{ entries: ImportPlanEntry[]; changes: Record<string, string> } | null>(
    null,
  );
  const [problems, setProblems] = useState<ImportProblem[]>([]);
  const [open, setOpen] = useState(false);
  const coffre = useCoffre();
  const { pending, error, setError, run } = useAction();
  const path = `${project}/${environment}`;

  function preview() {
    run(
      () => planEnv(coffre, path, content),
      (result) => {
        setProblems(result.problems);
        setPlan({ entries: result.plan, changes: result.changes });
      },
    );
  }

  function apply() {
    if (plan === null) return;
    const written = Object.keys(plan.changes).length;
    run(
      () => coffre.secrets.set(path, plan.changes),
      () => {
        toast.success(`Imported ${written} change${written === 1 ? '' : 's'}`);
        close();
      },
    );
  }

  function close() {
    setOpen(false);
    setPlan(null);
    setContent('');
    setProblems([]);
    setError(null);
  }

  const changes = plan?.entries.filter((entry) => entry.action !== 'unchanged') ?? [];

  return (
    <>
      <button className="btn" onClick={() => setOpen(true)}>
        <Upload size={14} />
        Import .env
      </button>

      <Modal
        open={open}
        onOpenChange={(next) => (next ? setOpen(true) : close())}
        title={
          <>
            Import into{' '}
            <span className="mono">
              {project}/{environment}
            </span>
          </>
        }
        wide
        description={
          <>
            Paste a .env file. It is read by the CLI’s own parser, so this page and the CLI
            cannot disagree about what it means, and malformed lines are reported rather
            than guessed at. coffre compares it with the current values without sending any
            to this page.
          </>
        }
      >
        <div className="form" style={{ marginTop: '1.25rem' }}>
          <label className="field">
            <span className="label">File contents</span>
            <textarea
              className="textarea"
              autoFocus
              spellCheck={false}
              placeholder={'DATABASE_URL=postgres://…\nSTRIPE_KEY="sk_live_…"'}
              value={content}
              onChange={(event) => {
                setContent(event.target.value);
                setPlan(null);
                setProblems([]);
              }}
            />
          </label>

          {plan !== null && plan.entries.length > 0 && (
            <div className="card dt-wrap">
              <table className="dt">
                <thead>
                  <tr>
                    <th>Key</th>
                    <th className="col-shrink">Plan</th>
                    <th className="col-shrink">Current</th>
                  </tr>
                </thead>
                <tbody>
                  {plan.entries.map((entry) => (
                    <tr key={entry.key}>
                      <td className="cell-key">{breakAfterUnderscores(entry.key)}</td>
                      <td className="col-shrink">
                        <span className={PLAN_TAG[entry.action]}>{entry.action}</span>
                      </td>
                      <td className="col-shrink cell-mono cell-muted">
                        {entry.version === null ? '—' : `v${entry.version}`}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {plan !== null && plan.entries.length > 0 && changes.length === 0 && (
            <Notice tone="good">Every key already has this value. There is nothing to write.</Notice>
          )}

          {problems.length > 0 && (
            <Notice tone="bad">
              <strong>
                {problems.length} line{problems.length === 1 ? '' : 's'} could not be parsed
              </strong>
              <ul style={{ margin: '0.375rem 0 0', paddingLeft: '1.1rem' }}>
                {problems.map((problem) => (
                  <li key={problem.line}>
                    Line {problem.line}: {problem.reason}{' '}
                    <span className="mono">({problem.text})</span>
                  </li>
                ))}
              </ul>
            </Notice>
          )}

          <ErrorLine error={error} />

          <div className="dialog-actions">
            <button className="btn" onClick={close}>
              Cancel
            </button>
            {plan === null ? (
              <button
                className="btn btn-primary"
                disabled={pending || content.trim() === ''}
                onClick={preview}
              >
                {pending && <Spinner />}
                Preview changes
              </button>
            ) : (
              <button
                className="btn btn-primary"
                disabled={pending || changes.length === 0}
                onClick={apply}
              >
                {pending && <Spinner />}
                Write {changes.length} change{changes.length === 1 ? '' : 's'}
              </button>
            )}
          </div>
        </div>
      </Modal>
    </>
  );
}

