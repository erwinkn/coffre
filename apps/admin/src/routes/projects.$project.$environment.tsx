import { useEffect, useRef, useState } from 'react';
import { createFileRoute, Link, useRouter } from '@tanstack/react-router';
import { DropdownMenu } from 'radix-ui';
import { toast } from 'sonner';
import {
  importEnv,
  listKeys,
  listVersions,
  revealSecret,
  rollbackSecret,
  saveSecret,
  setSecretArchived,
} from '../lib/server';
import { useAction } from '../lib/use-action';
import type {
  ImportPlanEntry,
  ImportProblem,
  Permission,
  SecretKey,
  SecretVersion,
} from '../lib/api';
import {
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
import { PermissionSummary } from '../components/permissions';
import {
  Archive,
  Eye,
  EyeOff,
  History,
  Key,
  MoreHorizontal,
  Pencil,
  Plus,
  RotateBack,
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
  loader: ({ params }) =>
    listKeys({ data: { project: params.project, environment: params.environment } }),
  component: EnvironmentPage,
});

/** A row you are filling in, not yet written to anything. */
type Draft = { id: number; key: string; value: string };

function EnvironmentPage() {
  const result = Route.useLoaderData();
  const { project, environment } = Route.useParams();
  const router = useRouter();

  const [drafts, setDrafts] = useState<Draft[]>([]);
  const [saving, setSaving] = useState(false);
  const [draftError, setDraftError] = useState<string | null>(null);
  const nextDraftId = useRef(0);

  // Drafts belong to the environment they were started in. The route component
  // is reused across params, so without this they would follow you into the
  // next environment and be written there.
  useEffect(() => {
    setDrafts([]);
    setDraftError(null);
  }, [project, environment]);

  function addDraft() {
    setDrafts((rows) => [...rows, { id: nextDraftId.current++, key: '', value: '' }]);
  }

  /**
   * Write every draft row, stopping at the first refusal.
   *
   * Rows already written are dropped and the rest are kept, so pressing save
   * again retries exactly what did not land rather than duplicating what did.
   * There is no batch endpoint and inventing one client-side would only hide
   * that this is several audited writes.
   */
  async function saveDrafts() {
    setSaving(true);
    setDraftError(null);
    const written: number[] = [];
    try {
      for (const draft of drafts) {
        const saved = await saveSecret({
          data: { project, environment, key: draft.key.trim(), value: draft.value },
        });
        if (!saved.ok) {
          setDraftError(`${draft.key.trim()}: ${saved.error}`);
          return;
        }
        written.push(draft.id);
      }
      toast.success(`Saved ${written.length} secret${written.length === 1 ? '' : 's'}`);
    } catch {
      setDraftError('The request could not be sent.');
    } finally {
      setDrafts((rows) => rows.filter((row) => !written.includes(row.id)));
      if (written.length > 0) await router.invalidate();
      setSaving(false);
    }
  }

  if (!result.ok) {
    return (
      <>
        <div className="page-head">
          <h1 className="mono">
            {project}/{environment}
          </h1>
        </div>
        <Notice tone="bad">{result.error}</Notice>
        <p style={{ marginTop: 'var(--space-5)' }}>
          <Link to="/projects">Back to projects</Link>
        </p>
      </>
    );
  }

  const { permissions, keys } = result;
  const canWrite = permissions.includes('secret.write');
  const canArchive = permissions.includes('secret.archive');
  const canReveal = permissions.includes('secret.read');

  const active = keys.filter((entry) => !entry.archived);
  const archived = keys.filter((entry) => entry.archived);
  const rowProps = { project, environment, canWrite, canArchive, canReveal };

  const existing = new Set(keys.map((entry) => entry.key));
  const ready =
    drafts.length > 0 && drafts.every((row) => row.key.trim() !== '' && row.value !== '');

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="mono">
            {project}/{environment}
          </h1>
          <p className="sub">
            {active.length} secret{active.length === 1 ? '' : 's'} in this environment
            {archived.length > 0 && `, ${archived.length} archived`}.
          </p>
        </div>
        <div className="cluster">
          <PermissionSummary permissions={permissions} />
          {canWrite && (
            <button className="btn btn-sm" onClick={addDraft} disabled={saving}>
              <Plus size={13} />
              Add secret
            </button>
          )}
          {canWrite && canReveal && (
            <ImportEnv project={project} environment={environment} />
          )}
        </div>
      </div>

      <div className="card">
        {active.length === 0 && drafts.length === 0 ? (
          <EmptyState icon={<Key size={26} />} title="No secrets here yet">
            {canWrite
              ? 'Add one with the button above, or paste an existing .env file to import several at once. Nothing is written until you have seen the plan.'
              : 'Nothing has been written to this environment. You would need secret.write to add the first one.'}
          </EmptyState>
        ) : (
          active.map((entry) => <SecretRow key={entry.key} entry={entry} {...rowProps} />)
        )}

        {drafts.map((draft) => (
          <DraftRow
            key={draft.id}
            draft={draft}
            newVersion={draft.key.trim() !== '' && existing.has(draft.key.trim())}
            disabled={saving}
            onChange={(patch) =>
              setDrafts((rows) =>
                rows.map((row) => (row.id === draft.id ? { ...row, ...patch } : row)),
              )
            }
            onRemove={() => setDrafts((rows) => rows.filter((row) => row.id !== draft.id))}
          />
        ))}

        {drafts.length > 0 && (
          <div className="row">
            <button className="btn btn-sm btn-quiet" onClick={addDraft} disabled={saving}>
              <Plus size={13} />
              Add another
            </button>
            <div className="row-actions">
              <button
                className="btn btn-sm"
                onClick={() => {
                  setDrafts([]);
                  setDraftError(null);
                }}
                disabled={saving}
              >
                Discard
              </button>
              <button
                className="btn btn-sm btn-primary"
                onClick={saveDrafts}
                disabled={saving || !ready}
              >
                {saving && <Spinner size={13} />}
                Save {drafts.length} secret{drafts.length === 1 ? '' : 's'}
              </button>
            </div>
          </div>
        )}

        {draftError !== null && (
          <div className="row">
            <ErrorLine error={draftError} />
          </div>
        )}
      </div>

      {archived.length > 0 && (
        <section className="section">
          <div className="section-head">
            <div>
              <h2>Archived</h2>
              <p className="sub">
                Retired, so no longer served or injected by <code>coffre run</code>. History
                and audit references are intact, and restoring is one click.
              </p>
            </div>
          </div>
          <div className="card">
            {archived.map((entry) => (
              <SecretRow key={entry.key} entry={entry} {...rowProps} />
            ))}
          </div>
        </section>
      )}
    </>
  );
}

function SecretRow({
  project,
  environment,
  entry,
  canWrite,
  canArchive,
  canReveal,
}: {
  project: string;
  environment: string;
  entry: SecretKey;
  canWrite: boolean;
  canArchive: boolean;
  canReveal: boolean;
}) {
  const [value, setValue] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState('');
  const [versions, setVersions] = useState<SecretVersion[] | null>(null);
  const [busy, setBusy] = useState(false);
  const { pending, error, setError, run } = useAction();

  // Hide the value again on a timer. Paired with the countdown bar in
  // `.secret-value`, so the disappearance is expected rather than startling.
  useEffect(() => {
    if (value === null) return;
    const timer = setTimeout(() => setValue(null), REVEAL_TTL_SECONDS * 1000);
    return () => clearTimeout(timer);
  }, [value]);

  async function onReveal() {
    if (value !== null) {
      setValue(null);
      return;
    }
    setBusy(true);
    try {
      const result = await revealSecret({ data: { project, environment, key: entry.key } });
      if (result.ok) {
        setValue(result.value);
        setError(null);
      } else {
        setError(result.error);
      }
    } finally {
      setBusy(false);
    }
  }

  async function onHistory() {
    if (versions !== null) {
      setVersions(null);
      return;
    }
    setBusy(true);
    try {
      const result = await listVersions({ data: { project, environment, key: entry.key } });
      if (result.ok) {
        setVersions(result.versions);
        setError(null);
      } else {
        setError(result.error);
      }
    } finally {
      setBusy(false);
    }
  }

  function setArchived(archived: boolean) {
    run(
      () => setSecretArchived({ data: { project, environment, key: entry.key, archived } }),
      () =>
        // Archiving is fully reversible, so it gets an undo rather than a
        // confirmation dialog in front of it.
        toast.success(archived ? `${entry.key} archived` : `${entry.key} restored`, {
          action: { label: 'Undo', onClick: () => setArchived(!archived) },
        }),
    );
  }

  const working = busy || pending;
  const hasSecondaryActions = canWrite || canArchive || canReveal;

  return (
    <div className="row-group">
      <div className="row row-interactive">
        <div className="row-title">
          <span className="row-key">{entry.key}</span>
          {entry.archived && <span className="pill pill-muted">archived</span>}
        </div>

        <span className="meta numeric" style={{ flex: 'none' }}>
          v{entry.version ?? 0}
        </span>
        {entry.updatedBy !== null && (
          <span className="meta" style={{ flex: 'none' }}>
            {entry.updatedBy}
          </span>
        )}

        <div className="row-actions">
          {canReveal && !entry.archived && (
            <button className="btn btn-sm" onClick={onReveal} disabled={working}>
              {working && value === null ? (
                <Spinner size={13} />
              ) : value !== null ? (
                <EyeOff size={13} />
              ) : (
                <Eye size={13} />
              )}
              {value !== null ? 'Hide' : 'Reveal'}
            </button>
          )}

          {hasSecondaryActions && (
            <DropdownMenu.Root>
              <DropdownMenu.Trigger asChild>
                <button
                  className="btn btn-sm btn-icon"
                  aria-label={`Actions for ${entry.key}`}
                >
                  <MoreHorizontal size={14} />
                </button>
              </DropdownMenu.Trigger>
              <DropdownMenu.Portal>
                <DropdownMenu.Content className="menu" sideOffset={6} align="end">
                  {canWrite && !entry.archived && (
                    <DropdownMenu.Item
                      className="menu-item"
                      onSelect={() => {
                        setEditing((open) => !open);
                        setDraft('');
                      }}
                    >
                      <Pencil size={14} />
                      {editing ? 'Cancel edit' : 'Set new value'}
                    </DropdownMenu.Item>
                  )}
                  {canReveal && (
                    <DropdownMenu.Item className="menu-item" onSelect={onHistory}>
                      <History size={14} />
                      {versions === null ? 'Version history' : 'Hide history'}
                    </DropdownMenu.Item>
                  )}
                  {canArchive && (
                    <>
                      <DropdownMenu.Separator className="menu-sep" />
                      <DropdownMenu.Item
                        className={`menu-item${entry.archived ? '' : ' menu-item-danger'}`}
                        onSelect={() => setArchived(!entry.archived)}
                      >
                        <Archive size={14} />
                        {entry.archived ? 'Restore' : 'Archive'}
                      </DropdownMenu.Item>
                    </>
                  )}
                </DropdownMenu.Content>
              </DropdownMenu.Portal>
            </DropdownMenu.Root>
          )}
        </div>
      </div>

      {value !== null && (
        <div className="row-detail">
          <div
            className="secret-value"
            style={{ ['--secret-ttl' as string]: `${REVEAL_TTL_SECONDS}s` }}
          >
            <span className="secret-text">{value}</span>
            <CopyButton value={value} label={`Copy ${entry.key}`} />
            <div className="secret-meter" />
          </div>
          <p className="meta" style={{ marginTop: 'var(--space-2)' }}>
            Logged as a read by you. Hides itself in {REVEAL_TTL_SECONDS} seconds.
          </p>
        </div>
      )}

      {editing && (
        <div className="row-detail">
          <form
            className="form-grid"
            onSubmit={(event) => {
              event.preventDefault();
              run(
                () =>
                  saveSecret({
                    data: { project, environment, key: entry.key, value: draft },
                  }),
                (result) => {
                  toast.success(`${entry.key} saved as v${result.version}`);
                  setEditing(false);
                  setValue(null);
                  setVersions(null);
                  setDraft('');
                },
              );
            }}
          >
            <label className="field grow">
              <span className="label">New value for {entry.key}</span>
              <input
                className="input"
                autoFocus
                value={draft}
                onChange={(event) => setDraft(event.target.value)}
              />
            </label>
            <button
              className="btn btn-primary"
              type="submit"
              disabled={working || draft === ''}
            >
              {working && <Spinner />}
              Save as v{(entry.version ?? 0) + 1}
            </button>
            <button className="btn" type="button" onClick={() => setEditing(false)}>
              Cancel
            </button>
          </form>
          <p className="meta" style={{ marginTop: 'var(--space-3)' }}>
            The current value is not replaced. A new version is appended and the pointer
            moves, so v{entry.version ?? 0} stays readable and restorable.
          </p>
        </div>
      )}

      {versions !== null && (
        <div className="row-detail">
          {/* No card wrapper: this table already sits inside one, and a card
              inside a card reads as a rendering accident. */}
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th className="shrink">Version</th>
                  <th>Written</th>
                  <th>By</th>
                  <th>KEK</th>
                  <th className="shrink" />
                </tr>
              </thead>
              <tbody>
                {versions.map((version) => (
                  <tr key={version.version}>
                    <td className="num">
                      v{version.version}
                      {version.current && (
                        <span className="pill pill-accent" style={{ marginLeft: 8 }}>
                          current
                        </span>
                      )}
                    </td>
                    <td className="num">
                      <Timestamp iso={version.createdAt} />
                    </td>
                    <td className="wrap">{version.createdBy}</td>
                    <td className="mono">{version.kek}</td>
                    <td className="shrink">
                      {canWrite && !version.current && (
                        <ConfirmButton
                          trigger={
                            <button className="btn btn-sm" disabled={working}>
                              <RotateBack size={13} />
                              Roll back
                            </button>
                          }
                          title={`Roll ${entry.key} back to v${version.version}?`}
                          body={
                            <>
                              The current pointer moves to v{version.version}. Nothing is
                              copied or deleted, every version stays readable, and the next
                              write continues the numbering forward. Anything reading this
                              environment picks up the change immediately.
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
                                    key: entry.key,
                                    version: version.version,
                                  },
                                }),
                              () => {
                                toast.success(
                                  `${entry.key} rolled back to v${version.version}`,
                                );
                                setVersions(null);
                                setValue(null);
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
          <p className="meta" style={{ marginTop: 'var(--space-3)' }}>
            Metadata only. Listing versions does not decrypt anything and is not recorded as
            a read.
          </p>
        </div>
      )}

      {error !== null && (
        <div className="row-detail">
          <ErrorLine error={error} />
        </div>
      )}
    </div>
  );
}

/**
 * A secret being typed, sitting in the list where it will end up.
 *
 * This replaced a separate "Add a secret" form below the table. The form made
 * you look away from the list to add to it, and only ever accepted one key at
 * a time; a row in place accepts as many as you want to queue and shows them
 * in the order they will be written.
 */
function DraftRow({
  draft,
  newVersion,
  disabled,
  onChange,
  onRemove,
}: {
  draft: Draft;
  newVersion: boolean;
  disabled: boolean;
  onChange: (patch: Partial<Draft>) => void;
  onRemove: () => void;
}) {
  return (
    <div className="row row-draft">
      <input
        className="input"
        style={{ flex: '0 1 17rem' }}
        // Only the row that just mounted takes focus, which is the one the
        // "Add" button created.
        autoFocus
        aria-label="Key"
        placeholder="DATABASE_URL"
        spellCheck={false}
        value={draft.key}
        disabled={disabled}
        onChange={(event) => onChange({ key: event.target.value })}
      />

      <input
        className="input grow"
        aria-label="Value"
        placeholder="postgres://..."
        spellCheck={false}
        value={draft.value}
        disabled={disabled}
        onChange={(event) => onChange({ value: event.target.value })}
      />

      {newVersion && (
        <Tip label="This key already exists here. Saving appends a new version to it rather than creating a second secret.">
          <span className="pill pill-muted" style={{ flex: 'none', cursor: 'help' }}>
            new version
          </span>
        </Tip>
      )}

      <div className="row-actions">
        <button
          className="btn btn-quiet btn-sm btn-icon"
          aria-label="Discard this row"
          onClick={onRemove}
          disabled={disabled}
        >
          <X size={14} />
        </button>
      </div>
    </div>
  );
}

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
      <button className="btn btn-sm" onClick={() => setOpen(true)}>
        <Upload size={13} />
        Import .env
      </button>

      <Modal
        open={open}
        onOpenChange={(next) => (next ? setOpen(true) : close())}
        title="Import .env"
        wide
        description={
          <>
            Parsed on the server, so the CLI and this page cannot disagree about what a file
            means. Malformed lines are reported, never guessed at.
          </>
        }
      >
        <div className="dialog-form stack">
          <label className="field">
            <span className="label">Paste file contents</span>
            <textarea
              className="textarea"
              autoFocus
              spellCheck={false}
              placeholder={'DATABASE_URL=postgres://...\nSTRIPE_KEY="sk_live_..."'}
              value={content}
              onChange={(event) => {
                setContent(event.target.value);
                setPlan(null);
              }}
            />
          </label>

          {plan !== null && (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Key</th>
                    <th className="shrink">Action</th>
                    <th className="shrink">Current</th>
                  </tr>
                </thead>
                <tbody>
                  {plan.map((entry) => (
                    <tr key={entry.key}>
                      <td className="mono">{entry.key}</td>
                      <td>
                        <span
                          className={`pill ${
                            entry.action === 'unchanged' ? 'pill-muted' : 'pill-allow'
                          }`}
                        >
                          {entry.action}
                        </span>
                      </td>
                      <td className="num">
                        {entry.version === null ? '--' : `v${entry.version}`}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {problems.length > 0 && (
            <Notice tone="bad">
              <strong>
                {problems.length} line{problems.length === 1 ? '' : 's'} could not be parsed
              </strong>
              <ul style={{ margin: 'var(--space-2) 0 0', paddingLeft: '1.1rem' }}>
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
            <button className="btn" disabled={pending || content === ''} onClick={preview}>
              {pending && <Spinner />}
              Preview changes
            </button>
            <button
              className="btn btn-primary"
              disabled={pending || plan === null || changes.length === 0}
              onClick={apply}
            >
              {plan === null
                ? 'Preview first'
                : `Apply ${changes.length} change${changes.length === 1 ? '' : 's'}`}
            </button>
          </div>
        </div>
      </Modal>
    </>
  );
}
