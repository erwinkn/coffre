import { useEffect, useRef, useState, type InputHTMLAttributes } from 'react';
import { createFileRoute, Link, useLoaderData, useRouter } from '@tanstack/react-router';
import { DropdownMenu } from 'radix-ui';
import { toast } from 'sonner';
import {
  importEnv,
  listKeys,
  listVersions,
  renameSecret,
  revealSecret,
  rollbackSecret,
  saveSecret,
  setSecretArchived,
} from '../server-functions/secrets';
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
  ConfirmButton,
  CopyButton,
  EmptyState,
  ErrorLine,
  Modal,
  Notice,
  Spinner,
  Timestamp,
} from '../components/ui';
import { ClosedDoor, PageHeader, Section } from '../components/page';
import { PermissionSummary } from '../components/permissions';
import { SecretReadOnly } from '../components/affordances';
import {
  AlertCircle,
  Archive,
  Eye,
  EyeOff,
  History,
  MoreHorizontal,
  Plus,
  RotateBack,
  Upload,
} from '../components/icons';

/**
 * How long a revealed value stays on screen.
 *
 * A revealed secret is live credential material sitting in a browser tab that
 * may well be shared on a call. Hiding it again costs nothing -- the read is
 * already logged, and re-revealing writes a second, honest audit row.
 */
const REVEAL_TTL_SECONDS = 45;

/** Referenced by every Reveal control, so the cost is announced before the click. */
const REVEAL_COST_ID = 'reveal-cost';

export const Route = createFileRoute('/projects/$project/$environment')({
  loader: ({ params }) =>
    listKeys({ data: { project: params.project, environment: params.environment } }),
  component: EnvironmentPage,
});

function EnvironmentPage() {
  const result = Route.useLoaderData();
  const { project, environment } = Route.useParams();

  if (!result.ok) {
    return (
      <ClosedDoor
        eyebrow={
          <Link to="/projects/$project" params={{ project }}>
            {project}
          </Link>
        }
        title={environment}
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
    />
  );
}

type Pending = { key: string; what: string };

function EnvironmentLedger({
  project,
  environment,
  permissions,
  keys,
}: {
  project: string;
  environment: string;
  permissions: Permission[];
  keys: SecretKey[];
}) {
  const router = useRouter();
  const [drafts, setDrafts] = useState<SecretDraft[]>([]);
  const [changes, setChanges] = useState<Record<string, SecretChange>>({});
  // Rows opened for editing that may not have changed yet. A row with a
  // pending change is in edit mode whether or not it is listed here.
  const [editing, setEditing] = useState<ReadonlySet<string>>(() => new Set());
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
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
   * Write every pending edit, stopping at the first refusal.
   *
   * Edits already written are dropped and the rest are kept, so pressing save
   * again retries exactly what did not land rather than duplicating what did.
   * There is no batch endpoint and inventing one client-side would only hide
   * that this is several audited writes.
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
        archive: async (key) => {
          const result = await setSecretArchived({
            data: { project, environment, key, archived: true },
          });
          if (!result.ok) throw new Error(`${key}: ${result.error}`);
        },
        rename: async (key, nextKey) => {
          const result = await renameSecret({
            data: { project, environment, key, nextKey },
          });
          if (!result.ok) throw new Error(`${key}: ${result.error}`);
        },
        save: async (key, value) => {
          const result = await saveSecret({
            data: { project, environment, key, value },
          });
          if (!result.ok) throw new Error(`${key}: ${result.error}`);
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
      toast.success(`Saved ${outcome.applied} change${outcome.applied === 1 ? '' : 's'}`);
    } else {
      const message =
        outcome.error instanceof Error ? outcome.error.message : 'The request could not be sent.';
      setSaveError(
        outcome.applied === 0
          ? message
          : `${message} Earlier changes were saved; the failed one and any after it are ready to retry.`,
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

  const problem = hasConflict
    ? 'Two pending edits would end up with the same name. Secret names are unique in an environment.'
    : invalid
      ? 'Names are letters, digits and underscores, and cannot start with a digit.'
      : null;

  const columns = 5;

  return (
    <>
      <p id={REVEAL_COST_ID} className="visually-hidden">
        Revealing decrypts the value and records a read under your name in the audit log.
      </p>

      <PageHeader
        eyebrow={
          <Link to="/projects/$project" params={{ project }}>
            {project}
          </Link>
        }
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
        meta={
          <>
            <span>
              <strong>{active.length}</strong> secret{active.length === 1 ? '' : 's'}
              {archived.length > 0 && `, ${archived.length} archived`}
            </span>
            <PermissionSummary permissions={permissions} />
            {canReveal && <span>Every reveal is recorded under your name</span>}
            <span className="mono" title="Inject these into a process with the CLI">
              coffre run {project}/{environment} -- …
            </span>
          </>
        }
      />

      {active.length === 0 && drafts.length === 0 ? (
        <EmptyState
          title="No secrets here yet"
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
            ? 'Add them one by one, or paste an existing .env file to import several at once. Nothing is written until you save, or until you have seen the import plan.'
            : 'Nothing has been written to this environment, and adding the first secret needs secret.write.'}
        </EmptyState>
      ) : (
        <div className="ledger-wrap">
          <table className="ledger secrets stacks">
            <thead>
              <tr>
                <th className="caps col-key">Key</th>
                <th className="caps">
                  Value
                  {!canReveal && <span className="col-head-note">· hidden from you</span>}
                </th>
                <th className="caps col-version">Ver.</th>
                <th className="caps col-written col-hide-narrow">Last written</th>
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

              {active.map((entry) => {
                const change = secretChangeFor(changes, entry.key);
                return (
                  <SecretRow
                    key={entry.key}
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
            </tbody>
          </table>
        </div>
      )}

      {archived.length > 0 && (
        <Section
          labelledBy="archived-secrets"
          title="Archived"
          note={
            <>
              Retired, so no longer served or injected by <code>coffre run</code>. Their
              history and audit trail are intact, and restoring is immediate.
            </>
          }
        >
          <div className="ledger-wrap">
            <table className="ledger secrets secrets-archived stacks">
              <thead>
                <tr>
                  <th className="caps col-key">Key</th>
                  <th className="caps col-version">Ver.</th>
                  <th className="caps col-written col-hide-narrow">Last written</th>
                  <th className="col-actions">
                    <span className="visually-hidden">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {archived.map((entry) => (
                  <ArchivedRow
                    key={entry.key}
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
        </Section>
      )}

      {pendingCount > 0 && (
        <div className="savebar" role="region" aria-label="Unsaved changes">
          <div className="savebar-inner">
            <span className="savebar-count">
              {pendingCount} change{pendingCount === 1 ? '' : 's'}
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
              <button className="btn" onClick={discardAll} disabled={saving}>
                Discard
              </button>
              <button
                className="btn btn-primary"
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
      const result = await revealSecret({ data: { project, environment, key: entry.key } });
      if (!result.ok) {
        setError(result.error);
        return null;
      }
      setError(null);
      setReveal({ value: result.value, version: entry.version, at: Date.now() });
      return result.value;
    } catch {
      setError('The request could not be sent. Nothing was read.');
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
              <span>{entry.key}</span>
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
                    aria-describedby={REVEAL_COST_ID}
                    disabled={revealing}
                    onClick={async () => {
                      const value = await readValue();
                      if (value !== null) {
                        setBase({ value, version: entry.version, at: Date.now() });
                      }
                    }}
                  >
                    {revealing && <Spinner size={12} />}
                    Start from current value (logged)
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
                Read recorded under your name at {clock(shown.at)} · hides in {secondsLeft}s
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
              <button className="act act-quiet" onClick={onUndo} disabled={disabled}>
                <RotateBack size={13} />
                Keep
              </button>
            ) : editing ? (
              <button className="act act-quiet" onClick={onUndo} disabled={disabled}>
                {renamed || valueChanged ? 'Undo' : 'Cancel'}
              </button>
            ) : (
              <>
                <SecretReadOnly canReveal={canReveal}>
                  <button
                    className="act"
                    onClick={toggleReveal}
                    disabled={revealing}
                    aria-describedby={shown === null ? REVEAL_COST_ID : undefined}
                    aria-label={`${shown === null ? 'Reveal' : 'Hide'} ${entry.key}`}
                  >
                    {revealing ? (
                      <Spinner size={13} />
                    ) : shown === null ? (
                      <Eye size={14} />
                    ) : (
                      <EyeOff size={14} />
                    )}
                    {shown === null ? 'Reveal' : 'Hide'}
                  </button>
                </SecretReadOnly>
                {shown !== null && <CopyButton variant="text" value={shown.value} label={`Copy ${entry.key}`} />}
                {canWrite && (
                  <button
                    className="act"
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
                    Edit
                  </button>
                )}
                {(canReveal || canArchive) && (
                  <DropdownMenu.Root>
                    <DropdownMenu.Trigger asChild>
                      <button
                        className="act act-quiet"
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

function Written({ entry }: { entry: SecretKey }) {
  if (entry.updatedBy === null && entry.updatedAt === null) {
    return <span className="cell-muted">—</span>;
  }
  return (
    <div className="cell-stack">
      <span title={entry.updatedBy ?? undefined}>{entry.updatedBy ?? 'unknown'}</span>
      {entry.updatedAt !== null && (
        <small>
          <Timestamp iso={entry.updatedAt} display="relative" />
        </small>
      )}
    </div>
  );
}

function clock(at: number): string {
  return `${new Date(at).toISOString().slice(11, 19)} UTC`;
}

/**
 * A secret being typed, sitting in the ledger where it will end up.
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
        <button className="act act-quiet" onClick={onRemove} disabled={disabled}>
          Remove
        </button>
      </td>
    </tr>
  );
}

function ArchivedRow({
  project,
  environment,
  entry,
  canArchive,
  canReveal,
}: {
  project: string;
  environment: string;
  entry: SecretKey;
  canArchive: boolean;
  canReveal: boolean;
}) {
  const [historyOpen, setHistoryOpen] = useState(false);
  const { pending, error, run } = useAction();

  function setArchived(archived: boolean) {
    run(
      () => setSecretArchived({ data: { project, environment, key: entry.key, archived } }),
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
        <td className="cell-key" data-label="Key">
          {entry.key}
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
              <button className="act act-quiet" onClick={() => setHistoryOpen((open) => !open)}>
                <History size={14} />
                {historyOpen ? 'Hide history' : 'History'}
              </button>
            </SecretReadOnly>
            {canArchive && (
              <button className="act" onClick={() => setArchived(false)} disabled={pending}>
                {pending ? <Spinner size={13} /> : <RotateBack size={13} />}
                Restore
              </button>
            )}
          </div>
        </td>
      </tr>
      {historyOpen && (
        <tr className="detail-row">
          <td colSpan={4}>
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
          <td colSpan={4}>
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
  const { pending, error, run } = useAction();

  // Refetch whenever the current version moves, so a rollback -- here or by
  // anyone else -- is reflected in which row says "current".
  useEffect(() => {
    let cancelled = false;
    listVersions({ data: { project, environment, key: secretKey } })
      .then((result) => {
        if (cancelled) return;
        if (result.ok) {
          setVersions(result.versions);
          setLoadError(null);
        } else {
          setLoadError(result.error);
        }
      })
      .catch(() => {
        if (!cancelled) setLoadError('The version history could not be loaded.');
      });
    return () => {
      cancelled = true;
    };
  }, [project, environment, secretKey, currentVersion]);

  return (
    <div className="history">
      <div className="history-head">
        <span className="history-title">
          History of <span className="mono">{secretKey}</span>
        </span>
        <button className="act act-quiet" onClick={onClose}>
          Close
        </button>
      </div>

      {loadError !== null ? (
        <ErrorLine error={loadError} />
      ) : versions === null ? (
        <p className="hint" style={{ padding: '0.75rem 0' }}>
          <Spinner size={13} /> Loading versions…
        </p>
      ) : (
        <div className="ledger-wrap">
          <table className="ledger">
            <thead>
              <tr>
                <th className="caps col-shrink">Version</th>
                <th className="caps col-shrink">Written (UTC)</th>
                <th className="caps">By</th>
                <th className="caps col-shrink">Key id</th>
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
                    {version.current && <span className="tag tag-accent">current</span>}
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
                              rollbackSecret({
                                data: {
                                  project,
                                  environment,
                                  key: secretKey,
                                  version: version.version,
                                },
                              }),
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

      <ErrorLine error={error} />
      <p className="history-note">
        Metadata only. Listing versions decrypts nothing and is not recorded as a read.
      </p>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Import                                                                      */
/* -------------------------------------------------------------------------- */

const PLAN_TAG: Record<ImportPlanEntry['action'], string> = {
  create: 'tag tag-green',
  update: 'tag tag-accent',
  unchanged: 'tag tag-outline',
};

/**
 * Bulk import from a .env file.
 *
 * Always previews first. The preview compares against current values, which
 * means it reads them -- so it needs secret.read as well as secret.write, and
 * both the preview and the import are audited.
 */
function ImportEnv({ project, environment }: { project: string; environment: string }) {
  const [content, setContent] = useState('');
  const [plan, setPlan] = useState<ImportPlanEntry[] | null>(null);
  const [problems, setProblems] = useState<ImportProblem[]>([]);
  const [open, setOpen] = useState(false);
  const { pending, error, setError, run } = useAction();

  function preview() {
    run(
      () => importEnv({ data: { project, environment, content, dryRun: true } }),
      (result) => {
        setProblems(result.problems);
        setPlan(result.plan);
      },
    );
  }

  function apply() {
    run(
      () => importEnv({ data: { project, environment, content, dryRun: false } }),
      (result) => {
        const written = result.plan.filter((entry) => entry.action !== 'unchanged').length;
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

  const changes = plan?.filter((entry) => entry.action !== 'unchanged') ?? [];

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
            Paste a .env file. It is parsed on the server, so this page and the CLI cannot
            disagree about what it means, and malformed lines are reported rather than
            guessed at. The preview compares against current values, so both the preview and
            the import are recorded in the audit log.
          </>
        }
      >
        <div className="form" style={{ marginTop: '1.25rem' }}>
          <label className="field">
            <span className="caps">File contents</span>
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

          {plan !== null && plan.length > 0 && (
            <div className="ledger-wrap">
              <table className="ledger">
                <thead>
                  <tr>
                    <th className="caps">Key</th>
                    <th className="caps col-shrink">Plan</th>
                    <th className="caps col-shrink">Current</th>
                  </tr>
                </thead>
                <tbody>
                  {plan.map((entry) => (
                    <tr key={entry.key}>
                      <td className="cell-key">{entry.key}</td>
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

          {plan !== null && plan.length > 0 && changes.length === 0 && (
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

