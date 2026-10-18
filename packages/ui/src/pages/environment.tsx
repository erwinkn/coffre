import { ageInDays, byFolder, CoffreError, foldersOf, olderThan, planImport, shownMember, type CoffreClient, type ListedReference } from '@coffre/client';
import { parseDotenv } from '@coffre/core/dotenv';
import type { Generation } from '@coffre/core/recipe';
import { useEffect, useId, useReducer, useRef, useState, type ReactNode } from 'react';
import { useQuery, useQueryClient, useSuspenseQuery } from '@tanstack/react-query';
import { Link, useNavigate } from '@tanstack/react-router';
import { useShell } from '../lib/use-shell';
import { Menu } from '@base-ui/react/menu';
import { toast } from 'sonner';
import { failureMessage, useCoffre } from '../lib/coffre';
import { archiveSecret, forkKey, moveSecret, regenerateSecret, restoreSecret, saveSecrets, UnsavedEdits, type ForkAction, type SaveSecretsVars } from '../lib/changes';
import { changeKey, type ItemStatus } from '../lib/optimistic';
import { affects, keys as queryKeys, queries } from '../lib/queries';
import { useChange, useChangeStatus } from '../lib/use-change';
import { RowFailure, RowPending, rowClass } from '../components/row-state';
import { useAction } from '../lib/use-action';
import type {
  ImportPlanEntry,
  ImportProblem,
  Permission,
  SecretKey,
  SecretVersion,
  Sensitivity,
} from '../shared/models';
import { canRevealSecrets } from '../lib/capabilities';
import { LEVELS, markable, SENSITIVITIES, stricter, waitsForValue } from '../lib/sensitivity';
import {
  companionsOf,
  hasSecretEditConflict,
  madeSensitive,
  secretChangeFor,
  valueEdit,
  type Companion,
  type SecretChange,
  type SecretDraft,
} from '../lib/secret-edit-batch';
import { createCopier } from '../lib/copy-attempts';
import { revealIsCurrent, type Reveal } from '../lib/reveal';
import { noReads, revealToggleDisabled, rowReads } from '../lib/row-reads';
import { sortKeys, type Sort } from '../lib/secret-order';
import { inDialog } from '../lib/shortcuts';
import { folderProblem, secretKeyProblem } from '../lib/validation';
import {
  breakAfterUnderscores,
  ConfirmButton,
  ConfirmDialog,
  CopyButton,
  EmptyState,
  ErrorLine,
  MenuPopup,
  Modal,
  Notice,
  Spinner,
  Timestamp,
  Tip,
} from '../components/ui';
import { Card, ClosedDoor, PageHeader } from '../components/page';
import { SecretReadOnly } from '../components/affordances';
import { GenerateValue, type GeneratedUse } from '../components/generate-value';
import { RecipeMark, RegenerateSecret } from '../components/regenerate';
import { liveGeneration, regeneratedKeys, regenerateWaits } from '../lib/recipes';
import { MaskedInput, MaskedTextarea } from '../components/masked';
import { FolderMenu, FolderRow, MoveToFolder } from '../components/folders';
import { MissingKeys } from '../components/missing';
import { MultiCombobox } from '../components/multi-combobox';
import { ArchiveBlocked, archiveBlockers, LentReferences, MakeReference, ReferenceValue } from '../components/references';
import { isActiveAccessibleEnvironment } from '../lib/project-environments';
import {
  AlertCircle,
  Archive,
  Check,
  Clock,
  Eye,
  ArrowRight,
  ChevronDown,
  ChevronsUpDown,
  EyeOff,
  Folder,
  Generate,
  Hash,
  History,
  Key,
  Lock,
  MoreHorizontal,
  Pencil,
  Plus,
  RotateBack,
  Search,
  SlashCircle,
  Terminal,
  Trash,
  Upload,
  X,
} from '../components/icons';
import { pageRoute } from '../lib/page-route';
import type { environment } from '../options';

const Route = pageRoute<typeof environment>();

/**
 * How long a revealed value stays on screen.
 *
 * A revealed secret is live credential material sitting in a browser tab that
 * may well be shared on a call. Hiding it again costs nothing -- the read is
 * already logged, and re-revealing writes a second, honest audit row.
 */
const REVEAL_TTL_SECONDS = 45;

/** Why a read of a secret's value failed, as the row says it. */
function readFailureMessage(failure: unknown): string {
  return failure instanceof CoffreError
    ? failureMessage(failure)
    : 'The request could not be sent. Nothing was read.';
}

export function EnvironmentPage() {
  const { project, environment } = Route.useParams();
  const { data: result } = useSuspenseQuery(queries.secrets(useCoffre(), { project, environment }));

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

  // `dev@me` while you have none: what one is, and making it, rather than dev's own keys under your name.
  if (result.personal?.fallback === true) return <NoPersonalConfig project={project} of={result.personal.of} />;

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
      parents={result.parents ?? []}
      personal={result.personal != null}
      rotateAfterDays={result.rotateAfterDays}
    />
  );
}

type Pending = { key: string; what: string };

function EnvironmentLedger({
  project,
  environment,
  permissions,
  keys,
  parents,
  personal,
  rotateAfterDays,
}: {
  project: string;
  environment: string;
  permissions: Permission[];
  keys: SecretKey[];
  /** The environments it inherits from, nearest first: a fork's (docs/design/forking.md). */
  parents: string[];
  /** Your personal config, `dev@me`: its values yours alone. */
  personal: boolean;
  /** Days a value may go unchanged before it is flagged for rotation; null for no flag. */
  rotateAfterDays: number | null;
}) {
  const coffre = useCoffre();
  const queryClient = useQueryClient();
  const { principal } = useShell();
  const save = useChange(saveSecrets(coffre, { project, environment }, principal?.id ?? null));
  const restore = useChange(restoreSecret(coffre, { project, environment }));
  const archive = useChange(archiveSecret(coffre, { project, environment }));
  const move = useChange(moveSecret(coffre, { project, environment }));
  const regenerate = useChange(regenerateSecret(coffre, { project, environment }, principal?.id ?? null));
  // A fork's keys, against its parent's: each action shows at once, with its opposite as Undo.
  const forkChanges = {
    remove: useChange(forkKey(coffre, { project, environment }, 'remove')),
    restore: useChange(forkKey(coffre, { project, environment }, 'restore')),
    reset: useChange(forkKey(coffre, { project, environment }, 'reset')),
    override: useChange(forkKey(coffre, { project, environment }, 'override')),
  };
  // The references that read this environment's secrets from elsewhere, and the environments you read.
  const { data: references } = useQuery(queries.references(coffre, `${project}/${environment}`));
  const lentBy = new Map<string, ListedReference[]>();
  for (const reference of references?.ok === true ? references.references : []) {
    const [sourceProject, sourceEnvironment, key] = reference.source.split('/') as [string, string, string];
    if (sourceProject !== project || sourceEnvironment !== environment) continue;
    lentBy.set(key, [...(lentBy.get(key) ?? []), reference]);
  }
  // A personal config is no reference's source: its values are its owner's alone.
  const readable = useShell().projects.flatMap((each) => each.environments
    .filter((one) => isActiveAccessibleEnvironment(one) && !one.personal)
    .map((one) => `${each.slug}/${one.slug}`));
  const { status, dismiss } = useChangeStatus(queryKeys.secrets({ project, environment }));
  const [drafts, setDrafts] = useState<SecretDraft[]>([]);
  const [changes, setChanges] = useState<Record<string, SecretChange>>({});
  // Rows opened for editing that may not have changed yet. A row with a
  // pending change is in edit mode whether or not it is listed here.
  const [editing, setEditing] = useState<ReadonlySet<string>>(() => new Set());
  const [saveError, setSaveError] = useState<string | null>(null);
  // A save that makes keys sensitive, waiting for its confirmation: nobody sees them again, which the row's menu asks too.
  const [hiding, setHiding] = useState<{ keys: string[]; go: () => void } | null>(null);
  // Every key the save writes counts, a key pair's public key included.
  function confirmingSensitive(drafts: readonly SecretDraft[], changes: Record<string, SecretChange>, go: () => void) {
    const keys = madeSensitive(active, drafts, changes);
    if (keys.length === 0) go();
    else setHiding({ keys, go });
  }
  const [query, setQuery] = useState(Route.useSearch().filter ?? '');
  const [sort, setSort] = useState<Sort>({ by: 'key', descending: false });
  // A column's first click sorts it ascending: names A to Z, the oldest values first.
  const sortBy = (by: Sort['by']) => setSort((current) => ({ by, descending: current.by === by && !current.descending }));
  const [addingFolder, setAddingFolder] = useState(false);
  const nextDraftId = useRef(0);

  const canWrite = permissions.includes('secret.write');
  const canArchive = permissions.includes('secret.archive');
  const canReveal = canRevealSecrets(permissions);
  // What a Contributor does without reading: lists the keys, their history, and keeps a personal config.
  const canList = canReveal || permissions.includes('secret.use');

  // Listed by folder: those in none first, then each folder by name.
  const active = byFolder(keys.filter((entry) => !entry.archived)).flatMap(([, entries]) => entries);
  const folders = foldersOf(active);
  // In a fork, an inherited key is filed where its parent files it: only the keys held here are filed here.
  const heldHere = (entry: SecretKey) => entry.parent === null || entry.parent.state === 'overridden';
  // What can be filed now: not a secret whose save is on its way, which may
  // not exist yet, nor one with an edit pending, as its menu offers no move
  // while it is edited.
  const settled = active.filter((entry) => heldHere(entry) && status(entry.key).state !== 'pending' && secretChangeFor(changes, entry.key) === undefined);
  // Renaming or removing a folder: everything in it at once, the keys staying where they are.
  const refile = useAction();
  const place = `${project}/${environment}`;
  const folderMenu = (folder: string, count: number) =>
    canWrite && count > 0 && (
      <FolderMenu
        folder={folder}
        count={count}
        what="key"
        folders={folders}
        onRename={(name) =>
          void refile.run(() => coffre.folders.renameKeys(place, folder, name), {
            affects: affects.secrets({ project, environment }),
            onSuccess: () => toast.success(`${folder}/ is ${name}/ now`),
          })}
        onRemove={() =>
          void refile.run(() => coffre.folders.removeKeys(place, folder), {
            affects: affects.secrets({ project, environment }),
            onSuccess: () => toast.success(`${folder}/ removed: its keys are in no folder`),
          })}
      />
    );
  const archived = keys.filter((entry) => entry.archived);
  const existing = new Set(keys.map((entry) => entry.key));
  const versionOf = (key: string) => keys.find((entry) => entry.key === key.trim())?.version ?? null;
  /** The listed version id of each key, those with one: what a regenerate replaces. */
  const versionIdOf = (name: string) => active.find((entry) => entry.key === name)?.versionId ?? null;
  const versionsOf = (names: readonly string[]) =>
    Object.fromEntries(names.flatMap((name) => {
      const version = versionIdOf(name);
      return version === null ? [] : [[name, version] as const];
    }));

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
    ...companionsOf(active, drafts, changes).map((companion) => companion.key.trim()),
  ];
  const unnamed = pendingNames.some((name) => name === '');
  const invalid = pendingNames.some((name) => name !== '' && secretKeyProblem(name) !== null);
  // A key made more visible, or marked where it holds no value of its own, waits for its value typed.
  const waiting = changedEntries.find((entry) => waitsForValue(entry, secretChangeFor(changes, entry.key)));
  const pendingCount = drafts.length + changedEntries.length;
  const ready = pendingCount > 0 && !unnamed && !invalid && !hasConflict && waiting === undefined;

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
      const dirty = next.key !== entry.key || next.value !== null || next.sensitivity !== undefined || next.archived;
      if (dirty) return { ...current, [entry.key]: next };
      const { [entry.key]: _, ...rest } = current;
      return rest;
    });
  }

  /**
   * One row's own Save: its change alone goes, and any other row's stays
   * pending. A row opened and left as it was just closes.
   */
  function saveRow(key: string) {
    const change = secretChangeFor(changes, key);
    if (change === undefined) return dropChange(key);
    confirmingSensitive([], { [key]: change }, () => {
      dropChange(key);
      sendAlone({ active, drafts: [], changes: { [key]: change } });
    });
  }

  function saveDraft(draft: SecretDraft) {
    confirmingSensitive([draft], {}, () => {
      setDrafts((rows) => rows.filter((row) => row.id !== draft.id));
      sendAlone({ active, drafts: [draft], changes: {} });
    });
  }

  /** Whether one row's change could go alone: named, well named, and clashing with nothing. */
  function readyAlone(drafts: SecretDraft[], changes: Record<string, SecretChange>): boolean {
    const names = [
      ...drafts.map((row) => row.key.trim()),
      ...Object.values(changes).flatMap((change) => (change.archived ? [] : [change.key.trim()])),
      ...companionsOf(active, drafts, changes).map((companion) => companion.key.trim()),
    ];
    return (
      (drafts.length > 0 || Object.keys(changes).length > 0) &&
      names.every((name) => name !== '' && secretKeyProblem(name) === null) &&
      !hasSecretEditConflict(active, drafts, changes) &&
      !active.some((entry) => waitsForValue(entry, secretChangeFor(changes, entry.key)))
    );
  }

  function sendAlone(batch: { active: SecretKey[]; drafts: SecretDraft[]; changes: Record<string, SecretChange> }) {
    setSaveError(null);
    save(batch, {
      // What did not go comes back as it was, beside the other pending rows.
      onError: (error) => {
        forgetRefusal(batch);
        const left = error instanceof UnsavedEdits ? error.outcome : batch;
        setDrafts((rows) => [...rows, ...left.drafts]);
        setChanges((current) => ({ ...current, ...left.changes }));
        setSaveError(failureMessage(error));
      },
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

  function addDraft(key = '') {
    // New rows go last, by the button that made them, in the order they were added.
    setDrafts((rows) => [...rows, { id: nextDraftId.current++, key, value: '', sensitivity: 'secret' }]);
  }

  function discardAll() {
    setDrafts([]);
    setChanges({});
    setEditing(new Set());
    setSaveError(null);
  }

  /**
   * A refused save leaves its rows no failure of their own: its edits come
   * back on them, and the bar under the table says why. Every other refused
   * change, a move for one, says why beneath its row.
   */
  function forgetRefusal(batch: SaveSecretsVars) {
    const saves = queryClient.getMutationCache().findAll({ mutationKey: changeKey(queryKeys.secrets({ project, environment })) });
    for (const each of saves) if (each.state.variables === batch) dismiss(each.mutationId);
  }

  /**
   * Write every pending edit (`saveSecrets`): renames one by one, then the
   * rest as one patch that lands whole or not at all. The edits show in the
   * list at once, each row marked as saving; whatever did not land comes
   * back as pending, so pressing save again retries exactly that, and the
   * bar under the table says why.
   */
  function saveChanges() {
    if (!ready) return;
    confirmingSensitive(drafts, changes, sendChanges);
  }

  function sendChanges() {
    const batch = { active, drafts, changes };
    setDrafts([]);
    setChanges({});
    setEditing(new Set());
    setSaveError(null);
    save(batch, {
      onError: (error) => {
        forgetRefusal(batch);
        const left = error instanceof UnsavedEdits ? error.outcome : batch;
        setDrafts(left.drafts);
        setChanges(left.changes);
        setSaveError(failureMessage(error));
      },
    });
  }

  /**
   * Bring an archived secret back: in the list at once, as saving. Restoring
   * is fully reversible, so it gets an undo rather than a confirmation
   * dialog in front of it. Asked here, not by its row, which leaves the
   * Archived list as soon as it is restored.
   */
  function restoreSecretKey(key: string) {
    restore(
      { key },
      {
        onSuccess: () =>
          toast.success(`${key} restored`, {
            action: { label: 'Undo', onClick: () => archive({ key }) },
          }),
      },
    );
  }

  /**
   * In a fork, a key against its parent's: removed, restored, reset to the
   * parent's value or overriding it again. Each is undone by its opposite,
   * so it gets an Undo rather than a confirmation dialog in front of it.
   */
  function forkAction(entry: SecretKey, action: ForkAction) {
    const from = entry.parent?.from ?? parents[0] ?? 'its parent';
    const undo: Record<ForkAction, ForkAction> = { remove: 'restore', restore: 'remove', reset: 'override', override: 'reset' };
    const said: Record<ForkAction, string> = {
      remove: `${entry.key} removed: ${environment} does without ${from}'s`,
      restore: `${entry.key} inherited from ${from} again`,
      reset: `${entry.key} reads ${from}'s value again; its own is kept`,
      override: `${entry.key} overrides ${from} again`,
    };
    forkChanges[action](
      { key: entry.key },
      {
        onSuccess: () =>
          toast.success(said[action], {
            action: { label: 'Undo', onClick: () => forkChanges[undo[action]]({ key: entry.key }) },
          }),
      },
    );
  }

  // Cmd/Ctrl+Enter saves from anywhere on the page while edits are pending,
  // but for an open dialog, such as Generate's.
  const saveRef = useRef(saveChanges);
  saveRef.current = saveChanges;
  useEffect(() => {
    if (pendingCount === 0) return;
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Enter' && (event.metaKey || event.ctrlKey) && !inDialog(event.target)) {
        event.preventDefault();
        saveRef.current();
      }
    }
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [pendingCount]);

  const withCompanion = (what: string, companion: Companion | undefined) =>
    companion === undefined ? what : `${what}, with ${companion.key.trim()}`;
  const pending: Pending[] = [
    ...drafts.map((draft) => ({
      key: draft.key.trim() || 'unnamed',
      what: withCompanion(existing.has(draft.key.trim()) ? 'new version' : 'added', draft.companion),
    })),
    ...changedEntries.map((entry) => {
      const change = secretChangeFor(changes, entry.key)!;
      if (change.archived) return { key: entry.key, what: 'archived' };
      const renamed = change.key.trim() !== entry.key;
      // Who sees it, where the edit changes that: beside a new value, or alone, a mark.
      const level = change.sensitivity === undefined || change.sensitivity === entry.sensitivity ? null : change.sensitivity;
      const written = change.value === null
        ? (level === null ? null : `made ${level}`)
        : withCompanion(level === null ? 'new value' : `new value, ${level}`, change.companion);
      if (renamed) return { key: entry.key, what: written === null ? `→ ${change.key.trim()}` : `→ ${change.key.trim()}, ${written}` };
      // In a fork, a value written over the parent's overrides it.
      if (entry.parent !== null && entry.parent.state !== 'overridden') return { key: entry.key, what: withCompanion(`overrides ${entry.parent.from}`, change.companion) };
      return { key: entry.key, what: written ?? 'new value' };
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
        : waiting !== undefined
          ? `${waiting.key} waits for its value: type it again.`
          : null;

  // Filtering narrows what is listed, never what is saved: a pending edit on
  // a row the filter hides still counts, and still shows in the bar under the table.
  const needle = query.trim().toLowerCase();
  const listed = sortKeys(
    needle === '' ? active : active.filter((entry) => entry.key.toLowerCase().includes(needle)),
    sort,
  );
  const columns = 6;

  return (
    <>
      <PageHeader
        tile={project}
        title={environment}
        actions={personal ? (
          <DeletePersonal project={project} environment={environment} of={parents[0]!} />
        ) : principal?.type === 'user' && canList && (
          <Link className="btn btn-sm" to="/projects/$project/$environment" params={{ project, environment: `${environment}@me` }}>
            <Key size={14} />
            My own {environment}
          </Link>
        )}
        description={personal ? (
          <span className="inherits">
            Your own{' '}
            <Link className="mono" to="/projects/$project/$environment" params={{ project, environment: parents[0]! }}>
              {project}/{parents[0]}
            </Link>
            : what you set here, only you read, while you read {parents[0]}; the rest is {parents[0]}'s, as it changes.
          </span>
        ) : parents.length > 0 && (
          <span className="inherits">
            Inherits from{' '}
            <Link className="mono" to="/projects/$project/$environment" params={{ project, environment: parents[0]! }}>
              {project}/{parents[0]}
            </Link>
            {parents.length > 1 && <>, which inherits from {parents.slice(1).map((parent) => `${project}/${parent}`).join(', then ')}</>}
            : its keys, as they change, but for those set or removed here.
          </span>
        )}
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

      <MissingKeys
        project={project}
        environment={environment}
        canWrite={canWrite}
        onAdd={addDraft}
      />

      {refile.error !== null && <ErrorLine error={refile.error} />}
      <section className="card card-wide" aria-label="Secrets">
        {active.length === 0 && drafts.length === 0 ? (
          <EmptyState title="No secrets yet">
            {canWrite
              ? 'Add them one by one, or import a .env file.'
              : 'Adding secrets here needs secret.write.'}
          </EmptyState>
        ) : (
          <div className="dt-wrap">
            <table className="dt secrets stacks sortable">
              <thead>
                <tr>
                  <th className="n">#</th>
                  <SortHeader className="col-key" by="key" sort={sort} onSort={sortBy}>
                    <Key size={14} />
                    Key
                  </SortHeader>
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
                  <SortHeader className="col-written" by="written" sort={sort} onSort={sortBy}>
                    <Clock size={14} />
                    Last written
                  </SortHeader>
                  <th className="col-actions">
                    <span className="visually-hidden">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {byFolder(listed).flatMap(([folder, entries]) => [
                  ...(folder === null ? [] : [<FolderRow key={`folder:${folder}`} folder={folder} count={entries.length} columns={columns} actions={folderMenu(folder, entries.filter(heldHere).length)} />]),
                  ...entries.map((entry) => {
                  const change = secretChangeFor(changes, entry.key);
                  const state = status(entry.key);
                  return (
                    <SecretRow
                      key={entry.key}
                      number={active.indexOf(entry) + 1}
                      project={project}
                      environment={environment}
                      entry={entry}
                      generated={liveGeneration(entry, active)}
                      // Being edited, written by a new row or its companion, or with a save on its way:
                      // a key pair's Regenerate waits for both halves.
                      busy={(key) =>
                        status(key).state === 'pending' ||
                        editing.has(key) ||
                        secretChangeFor(changes, key) !== undefined ||
                        drafts.some((draft) => draft.key.trim() === key || draft.companion?.key.trim() === key) ||
                        // Written here and not yet read back: no version to say it replaces.
                        versionIdOf(key) === null
                      }
                      onRegenerate={(generated) =>
                        regenerate(
                          { key: entry.key, generated, versions: versionsOf(regeneratedKeys(entry.key, generated)) },
                          { onSuccess: () => toast.success(`Regenerated ${regeneratedKeys(entry.key, generated).join(' and ')}`) },
                        )
                      }
                      rotateAfterDays={rotateAfterDays}
                      change={change ?? { key: entry.key, value: null, archived: false }}
                      editing={
                        change?.archived !== true &&
                        (editing.has(entry.key) || change !== undefined)
                      }
                      canWrite={canWrite}
                      canArchive={canArchive}
                      canReveal={canReveal}
                      canList={canList}
                      folders={folders}
                      onMove={(folder) => move({ key: entry.key, folder })}
                      lent={lentBy.get(entry.key) ?? []}
                      // A personal config holds values only: no reference.
                      environments={personal ? [] : readable}
                      personal={personal}
                      status={state}
                      // Not while its save is on its way.
                      disabled={state.state === 'pending'}
                      onDismiss={dismiss}
                      columns={columns}
                      onFork={(action) => forkAction(entry, action)}
                      onEdit={() => setEditing((current) => new Set(current).add(entry.key))}
                      onPatch={(patch) => patchChange(entry, patch)}
                      onUndo={() => dropChange(entry.key)}
                      onSave={() => saveRow(entry.key)}
                      versionOf={versionOf}
                      saveReady={
                        change === undefined || readyAlone([], { [entry.key]: change })
                      }
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
                  }),
                ])}

                {listed.length === 0 && active.length > 0 && (
                  <tr>
                    <td colSpan={columns} className="cell-muted" style={{ padding: '1rem' }}>
                      No secret name contains “{query.trim()}”.
                    </td>
                  </tr>
                )}

                {drafts.map((draft) => (
                  <DraftRow
                    key={draft.id}
                    draft={draft}
                    existingVersion={versionOf(draft.key)}
                    personal={personal}
                    disabled={false}
                    onChange={(patch) =>
                      setDrafts((rows) =>
                        rows.map((row) => (row.id === draft.id ? { ...row, ...patch } : row)),
                      )
                    }
                    onRemove={() => setDrafts((rows) => rows.filter((row) => row.id !== draft.id))}
                    onSave={() => saveDraft(draft)}
                    versionOf={versionOf}
                    saveReady={readyAlone([draft], {})}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
        {pendingCount > 0 && (
          <PendingBar
            pending={pending}
            ready={ready}
            error={saveError ?? problem}
            onDiscard={discardAll}
            onSave={saveChanges}
          />
        )}
      </section>

      <ConfirmDialog
        open={hiding !== null}
        onOpenChange={(open) => !open && setHiding(null)}
        title={hiding?.keys.length === 1 ? <>Make <span className="mono">{hiding.keys[0]}</span> sensitive?</> : `Make ${hiding?.keys.length ?? 0} keys sensitive?`}
        body={`${hiding !== null && hiding.keys.length > 1 ? `${hiding.keys.join(', ')}: n` : 'N'}obody, Owners included, will see ${hiding?.keys.length === 1 ? 'this value' : 'these values'} again. Apps use ${hiding?.keys.length === 1 ? 'it' : 'them'} through the proxy; service accounts still read ${hiding?.keys.length === 1 ? 'it' : 'them'}.`}
        confirmLabel="Make sensitive"
        destructive={false}
        onConfirm={() => {
          const go = hiding?.go;
          setHiding(null);
          go?.();
        }}
      />

      {canWrite && (
        <div className="table-actions">
          <AddButton onAddSecret={() => addDraft()} onAddFolder={() => setAddingFolder(true)} canAddFolder={settled.length > 0} />
          {canReveal && <ImportEnv project={project} environment={environment} />}
          <AddFolder
            open={addingFolder}
            onOpenChange={setAddingFolder}
            keys={settled.map((entry) => entry.key)}
            folders={folders}
            onAdd={(folder, keys) => {
              // As things stand on submit: a secret whose save started since the dialog opened is left out, not raced.
              for (const entry of settled) {
                if (keys.includes(entry.key) && entry.folder !== folder) move({ key: entry.key, folder });
              }
            }}
          />
        </div>
      )}

      {archived.length > 0 && (
        <Card
          wide
          labelledBy="archived-secrets"
          title="Archived"
          description="No longer served; restoring one brings it back with its history."
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
                    canList={canList}
                    status={status(entry.key)}
                    onRestore={() => restoreSecretKey(entry.key)}
                    onDismiss={dismiss}
                  />
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

    </>
  );
}

/**
 * The pending edits, at the foot of the table they are made in: what they
 * are, Discard and Save. It sticks to the bottom of the window while the
 * table runs past it, so Save stays in reach of any row.
 */
function PendingBar({
  pending,
  ready,
  error,
  onDiscard,
  onSave,
}: {
  pending: Pending[];
  ready: boolean;
  /** Why the last save failed, or why this one cannot go yet. */
  error: string | null;
  onDiscard: () => void;
  onSave: () => void;
}) {
  const count = pending.length;
  return (
    <div className="pending-bar" role="region" aria-label="Unsaved changes">
      <span className="pending-count">
        <span className="dot" aria-hidden />
        {count} unsaved change{count === 1 ? '' : 's'}
      </span>
      <span className="pending-summary">
        {pending.slice(0, 3).map((item, index) => (
          <span key={`${item.key}:${index}`}>
            {index > 0 && ' · '}
            <span className="mono">{item.key}</span> {item.what}
          </span>
        ))}
        {count > 3 && ` · and ${count - 3} more`}
      </span>
      <div className="pending-actions">
        <button className="btn btn-sm" onClick={onDiscard}>
          Discard
        </button>
        <button
          className="btn btn-sm btn-primary"
          onClick={onSave}
          disabled={!ready}
          title="Save (⌘ Enter or Ctrl Enter)"
          aria-keyshortcuts="Meta+Enter Control+Enter"
        >
          Save {count === 1 ? 'change' : `${count} changes`}
        </button>
      </div>
      {error !== null && (
        <p className="pending-error" role="alert">
          <AlertCircle size={14} />
          <span>{error}</span>
        </p>
      )}
    </div>
  );
}

/**
 * Add secret, and beside it a menu of the other things to add: a folder.
 * One button in look, two to the keyboard and to a screen reader, the
 * second a menu button.
 */
function AddButton({
  onAddSecret,
  onAddFolder,
  canAddFolder,
}: {
  onAddSecret: () => void;
  onAddFolder: () => void;
  /** Whether there is a secret to file in a new folder. */
  canAddFolder: boolean;
}) {
  return (
    <div className="split-button">
      <button className="btn btn-primary" onClick={onAddSecret}>
        <Plus size={14} />
        Add secret
      </button>
      <Menu.Root>
        <Menu.Trigger className="btn btn-primary btn-icon" aria-label="More to add">
          <ChevronDown size={14} />
        </Menu.Trigger>
        <MenuPopup align="start">
          <Menu.Item className="menu-item" onClick={onAddFolder} disabled={!canAddFolder}>
            <Folder size={14} />
            Add folder…
            {!canAddFolder && <span className="menu-hint">after a secret</span>}
          </Menu.Item>
        </MenuPopup>
      </Menu.Root>
    </div>
  );
}

/**
 * A new folder, and the secrets filed in it. A folder is a name on what it
 * holds (docs/design/environments.md), so it is made with its first
 * secrets: one with nothing in it would not be there to see.
 */
function AddFolder({
  open,
  onOpenChange,
  keys,
  folders,
  onAdd,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** The secrets that can be filed, by name. */
  keys: readonly string[];
  /** The folders in use, which a name already in use joins. */
  folders: readonly string[];
  onAdd: (folder: string, keys: string[]) => void;
}) {
  const [name, setName] = useState('');
  const [chosen, setChosen] = useState<string[]>([]);
  useEffect(() => {
    if (!open) return;
    setName('');
    setChosen([]);
  }, [open]);
  const problem = folderProblem(name);
  const joins = folders.includes(name);
  const ready = name !== '' && problem === null && chosen.length > 0;

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title="Add a folder"
      description="Folders only arrange the list: names, values and access stay as they are."
    >
      <form
        className="form"
        onSubmit={(event) => {
          event.preventDefault();
          if (!ready) return;
          onAdd(name, chosen);
          onOpenChange(false);
        }}
      >
        <label className="field">
          <span className="label">Name</span>
          <input
            className="input"
            autoFocus
            spellCheck={false}
            autoComplete="off"
            value={name}
            aria-invalid={problem !== null}
            onChange={(event) => setName(event.target.value)}
          />
          <span className={`hint${problem !== null ? ' edit-note-error' : ''}`}>
            {problem ?? (joins ? `${name} is in use: the secrets join it.` : 'One level: no slash.')}
          </span>
        </label>
        <MultiCombobox
          label="Secrets in it"
          options={keys}
          value={chosen}
          onChange={setChosen}
          placeholder="Pick one or more…"
          hint="A folder holds at least one secret."
          mono
        />
        <div className="dialog-actions">
          <button className="btn" type="button" onClick={() => onOpenChange(false)}>
            Cancel
          </button>
          <button className="btn btn-primary" type="submit" disabled={!ready}>
            Add folder
          </button>
        </div>
      </form>
    </Modal>
  );
}

/* -------------------------------------------------------------------------- */
/* Rows                                                                        */
/* -------------------------------------------------------------------------- */

const lineCount = (text: string) => text.split('\n').length;

function ValueField({
  label,
  value,
  start = '',
  onChange,
  placeholder,
  disabled,
  autoFocus,
  onEscape,
  generate,
  plain = false,
}: {
  label: string;
  value: string;
  /** The value the edit started from. */
  start?: string;
  onChange: (value: string) => void;
  placeholder: string;
  disabled: boolean;
  autoFocus?: boolean;
  onEscape?: () => void;
  /** The row Generate fills: its name, whether that can change, and what Use does. */
  generate: {
    name: string;
    renamable: boolean;
    /** The public key a pair generated here before writes with the row. */
    companion: Companion | undefined;
    onUse: (use: GeneratedUse) => void;
  };
  /** A plain value, no secret: shown as it is typed. */
  plain?: boolean;
}) {
  const [shown, setShown] = useState(false);
  const [generating, setGenerating] = useState(false);
  // A value with a line break is edited in a textarea, and stays in one to
  // the end of the edit: taking its last line break out moves no focus.
  const [lines, setLines] = useState(() => start.includes('\n') || value.includes('\n'));
  if (!lines && value.includes('\n')) setLines(true);
  // Where the caret goes in the textarea a paste or a typed line break opened.
  const caret = useRef<number | null>(null);
  // Text goes into the value of the single-line field in place of its
  // selection, and the field turns into a textarea, focused, its caret after it.
  const insert = (text: string, field: HTMLInputElement) => {
    const from = field.selectionStart ?? value.length;
    const to = field.selectionEnd ?? from;
    caret.current = from + text.length;
    onChange(value.slice(0, from) + text + value.slice(to));
  };
  const field = {
    className: 'input input-mono',
    masked: !shown && !plain,
    'aria-label': label,
    placeholder,
    value,
    disabled,
    autoFocus,
    onChange: (event: { target: { value: string } }) => onChange(event.target.value),
    onKeyDown: (event: { key: string }) => {
      if (event.key === 'Escape' && onEscape !== undefined) onEscape();
    },
  };
  return (
    <div className="input-group has-generate">
      {/* A value with line breaks opens one line tall, as tall as the row it
          replaces, and grows only by the lines typed or pasted into it. */}
      {lines ? (
        <MaskedTextarea
          {...field}
          ref={(node) => {
            if (node === null || caret.current === null) return;
            node.focus();
            node.setSelectionRange(caret.current, caret.current);
            caret.current = null;
          }}
          className="input input-mono value-lines"
          rows={Math.min(8, 1 + Math.max(0, lineCount(value) - lineCount(start)))}
        />
      ) : (
        <MaskedInput
          {...field}
          // A text input drops a pasted value's line breaks, a PEM key's
          // included. Such a paste goes into the value here instead, and the
          // field turns into a textarea, focused, its caret after the paste.
          // Line breaks are \n, as a textarea keeps them: \r\n is one \n.
          onPaste={(event) => {
            const pasted = event.clipboardData.getData('text/plain');
            if (!/[\r\n]/.test(pasted)) return;
            event.preventDefault();
            insert(pasted.replace(/\r\n?/g, '\n'), event.currentTarget);
          }}
          // Shift+Enter types a line break, the way a textarea's Enter does.
          // Enter alone stays as it was, and so does Cmd/Ctrl+Enter, which saves,
          // and so does Shift+Enter that confirms text an input method is composing.
          onKeyDown={(event) => {
            if (event.key === 'Enter' && event.shiftKey && !event.metaKey && !event.ctrlKey && !event.nativeEvent.isComposing) {
              event.preventDefault();
              insert('\n', event.currentTarget);
            } else field.onKeyDown(event);
          }}
        />
      )}
      <Tip label="Generate a value">
        <button
          type="button"
          className="btn btn-quiet btn-sm btn-icon input-addon input-addon-generate"
          aria-label={`Generate a value for ${generate.name.trim() === '' ? 'the new secret' : generate.name.trim()}`}
          disabled={disabled}
          onClick={() => setGenerating(true)}
        >
          <Generate size={14} />
        </button>
      </Tip>
      {/* A plain value shows as it is: nothing to mask. */}
      {!plain && (
        <button
          type="button"
          className="btn btn-quiet btn-sm btn-icon input-addon"
          aria-label={shown ? 'Mask the value' : 'Show the value'}
          aria-pressed={shown}
          onClick={() => setShown((current) => !current)}
        >
          {shown ? <EyeOff size={14} /> : <Eye size={14} />}
        </button>
      )}
      <GenerateValue
        open={generating}
        onOpenChange={setGenerating}
        name={generate.name}
        renamable={generate.renamable}
        companion={generate.companion}
        onUse={generate.onUse}
      />
    </div>
  );
}

/** Under a row's value: the public key that saves with it, and the version it makes. */
function CompanionNote({
  companion,
  versionOf,
}: {
  companion: Companion | undefined;
  versionOf: (key: string) => number | null;
}) {
  if (companion === undefined) return null;
  const version = versionOf(companion.key);
  return (
    <span className="edit-note">
      <span>
        Saves its public key as <span className="mono">{companion.key.trim()}</span>
        {version === null ? ', a new secret' : `, v${version} → v${version + 1}`}
      </span>
    </span>
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
  generated,
  busy,
  onRegenerate,
  rotateAfterDays,
  change,
  editing,
  canWrite,
  canArchive,
  canReveal,
  canList,
  folders,
  onMove,
  lent,
  environments,
  status,
  disabled,
  onDismiss,
  columns,
  onFork,
  onEdit,
  onPatch,
  onUndo,
  onSave,
  versionOf,
  saveReady,
  onMarkArchive,
  personal,
}: {
  number: number;
  project: string;
  environment: string;
  entry: SecretKey;
  /** Its recipe, as the page may regenerate it by: a key pair's while both halves are listed alike (`liveGeneration`). */
  generated: Generation | null;
  /** Whether a key in this environment is being edited, or has a save on its way. */
  busy: (key: string) => boolean;
  /** Regenerate it by its recipe, a tracked save of every key it writes. */
  onRegenerate: (generated: Generation) => void;
  rotateAfterDays: number | null;
  change: SecretChange;
  editing: boolean;
  canWrite: boolean;
  canArchive: boolean;
  canReveal: boolean;
  /** Whether the caller lists the environment: reads it, or uses it as a Contributor does. */
  canList: boolean;
  /** The folders in use in this environment, offered when moving it. */
  folders: readonly string[];
  onMove: (folder: string | null) => void;
  /** The references that read this secret from elsewhere. */
  lent: ListedReference[];
  /** The environments you read, offered when making this a reference. */
  environments: readonly string[];
  /** A save of this row on its way, or refused. */
  status: ItemStatus;
  disabled: boolean;
  /** Forget a refused change once its row has said so. */
  onDismiss: (mutationId: number) => void;
  columns: number;
  /** In a fork, the key against its parent's: removed, restored, reset or overriding it again. */
  onFork: (action: ForkAction) => void;
  onEdit: () => void;
  onPatch: (patch: Partial<SecretChange>) => void;
  onUndo: () => void;
  /** This row's change alone, saved now. */
  onSave: () => void;
  /** The current version of a key in this environment, for a companion's note. */
  versionOf: (key: string) => number | null;
  saveReady: boolean;
  onMarkArchive: () => void;
  /** In a personal config, whose values are its owner's alone: always a secret. */
  personal: boolean;
}) {
  const [reads, dispatch] = useReducer(rowReads, noReads);
  const { reveal, revealing, error, copyError } = reads;
  const setReveal = (next: Reveal | null) => dispatch({ type: 'set-reveal', reveal: next });
  const coffre = useCoffre();
  const [historyOpen, setHistoryOpen] = useState(false);
  const [moving, setMoving] = useState(false);
  const [referring, setReferring] = useState(false);
  const [breaking, setBreaking] = useState<string | null>(null);
  const [regenerating, setRegenerating] = useState(false);
  const [lentOpen, setLentOpen] = useState(false);
  // Archiving a key others read through references waits until they are broken (D41).
  const [archiveBlocked, setArchiveBlocked] = useState(false);
  const blockers = archiveBlockers(`${project}/${environment}/${entry.key}`, lent);
  // Making or breaking a reference, or marking it: its refusal shows under the row, as a reveal's does.
  const { run: act, error: actError } = useAction();
  // Made sensitive from the menu, once confirmed: nobody sees its value after.
  const [hiding, setHiding] = useState(false);
  const { reference, parent } = entry;
  // In a fork (docs/design/forking.md): a key it inherits has no row of its
  // own, one it overrides has, and one it removed is not served.
  const inherited = parent?.state === 'inherited';
  const removed = parent?.state === 'removed';
  const overridden = parent?.state === 'overridden';
  const own = !inherited && !removed;
  // Inherited from a parent you do not read: its name is yours to know, its value is not.
  const parentHidden = inherited && entry.version === null && reference === null;
  // A sensitive value is shown to nobody, its readers included: no Reveal, no Copy, and an edit starts empty.
  const sensitive = entry.sensitivity === 'sensitive';
  const canRead = canReveal && !removed && !parentHidden && !sensitive;
  // What a reveal shows: its own version, or, as a reference, its source's.
  const readVersion = reference === null ? entry.version : reference.version;
  // And where that version is held: a reset, an override or a new reference changes it under the same number.
  const readFrom = `${inherited ? parent!.from : '.'}:${reference?.source ?? ''}`;
  const holderPath = `${project}/${environment}/${entry.key}`;
  // A plain value is no secret: listed as it is, shown inline and copied with no read.
  const rowPlain = entry.value !== null;
  // Who sees its value now, and who will once the edit is saved; in a personal config, its owner alone, a secret.
  const rowLevel = personal ? 'secret' : entry.sensitivity;
  const level = change.sensitivity ?? rowLevel ?? 'secret';
  // More visible than it is: the value is typed again, never shown and kept.
  const loosening = rowLevel !== null && stricter(rowLevel, level);
  const from = () => ({ start: editBase?.value ?? '', level: rowLevel });
  // The current value, loaded on request as the starting point for an edit.
  // It is not a change until it is edited: saving it untouched would append a
  // version identical to the one it came from.
  const [base, setBase] = useState<Reveal | null>(null);

  // A reveal belongs to the version it decrypted. The moment the row shows a
  // different version -- saved here, rolled back, or written by someone else
  // and picked up on refresh -- the old plaintext is not the value any more,
  // and must not stay on screen pretending to be.
  const shown = revealIsCurrent(reveal, readVersion, readFrom) ? reveal : null;
  useEffect(() => {
    if (reveal !== null && !revealIsCurrent(reveal, readVersion, readFrom)) setReveal(null);
  }, [reveal, readVersion, readFrom]);

  useEffect(() => {
    if (reveal === null) return;
    const timer = setTimeout(() => setReveal(null), REVEAL_TTL_SECONDS * 1000);
    return () => clearTimeout(timer);
  }, [reveal]);

  const secondsLeft = useSecondsLeft(shown);

  const editBase = editing && revealIsCurrent(base, readVersion, readFrom) ? base : null;
  useEffect(() => {
    if (!editing) setBase(null);
  }, [editing]);

  async function readValue({ show = true } = {}): Promise<string | null> {
    if (shown !== null) return shown.value;
    dispatch({ type: 'read-started' });
    try {
      const value = await fetchValue();
      dispatch({
        type: 'read-succeeded',
        reveal: show ? { value, version: readVersion, from: readFrom, at: Date.now() } : null,
      });
      return value;
    } catch (failure) {
      dispatch({ type: 'read-failed', message: readFailureMessage(failure) });
      return null;
    }
  }

  async function fetchValue(): Promise<string> {
    if (entry.value !== null) return entry.value;
    const { values } = await coffre.secrets.reveal(`${project}/${environment}/${entry.key}`);
    return values[entry.key];
  }

  function toggleReveal() {
    if (shown !== null) setReveal(null);
    else void readValue();
  }

  // Copy reads a hidden value the way Reveal does (the same audited read) and hands
  // it to the clipboard, never to the screen or to the row's reveal state: it shares
  // nothing with Reveal but the endpoint, so neither can change whether a value is
  // shown or Hide can be pressed. Copies do not lock each other out; the latest one
  // wins. The row holds the copier, which a remount of the button does not reset,
  // and only the latest copy may set `copyError` or the button's feedback.
  const [copier] = useState(() => createCopier());
  function copyValue() {
    dispatch({ type: 'copy-started' });
    // What a failed read said, if the read is what failed rather than the clipboard.
    const read: { failed: boolean; failure?: unknown } = { failed: false };
    const text =
      shown !== null
        ? shown.value
        : fetchValue().catch((failure: unknown) => {
            read.failed = true;
            read.failure = failure;
            throw failure;
          });
    void copier.run(text).then((result) => {
      if (result.outcome === 'superseded') return;
      dispatch(
        result.outcome === 'copied'
          ? { type: 'copy-succeeded' }
          : {
              type: 'copy-failed',
              message: read.failed
                ? readFailureMessage(read.failure)
                : 'The browser did not allow copying to the clipboard. Reveal the value and copy it by hand.',
            },
      );
    });
  }

  // An edit starts from the current value, read the way Reveal reads it, so
  // the audit log shows who opened it. One that cannot be read starts empty.
  const [opening, setOpening] = useState(false);
  // Rename opens the same editor, its name field focused rather than its value.
  const [focusName, setFocusName] = useState(false);
  async function startEdit({ name = false } = {}) {
    setFocusName(name);
    if (entry.value !== null) setBase({ value: entry.value, version: readVersion, from: readFrom, at: Date.now() });
    else if (canRead) {
      setOpening(true);
      const value = await readValue({ show: false });
      setOpening(false);
      if (value === null) return;
      setBase({ value, version: readVersion, from: readFrom, at: Date.now() });
    }
    setReveal(null);
    onEdit();
  }

  // Who sees it, chosen from its menu: stricter at once, its value kept; more
  // visible in the editor, which asks for the value typed again.
  function chooseLevel(next: Sensitivity) {
    if (entry.sensitivity === null || next === entry.sensitivity) return;
    if (stricter(entry.sensitivity, next)) {
      setFocusName(false);
      setReveal(null);
      onEdit();
      onPatch({ sensitivity: next });
    } else if (next === 'sensitive') setHiding(true);
    else mark(next);
  }

  function mark(next: Sensitivity) {
    setReveal(null);
    act(() => coffre.secrets.set(`${project}/${environment}`, { [entry.key]: { sensitivity: next } }), {
      affects: affects.secrets({ project, environment }),
      onSuccess: () => toast.success(`Made ${entry.key} ${next}`),
    });
  }

  const leaving = change.archived;
  const renamed = change.key !== entry.key;
  // A new value, or a level alone, a mark: either makes a new version.
  const valueChanged = change.value !== null || change.sensitivity !== undefined;
  const keyProblem = editing ? secretKeyProblem(change.key.trim()) : null;
  const state = leaving
    ? ' is-leaving'
    : editing && (renamed || valueChanged)
      ? ' is-changed'
      : shown !== null
        ? ' is-revealed'
        : removed
          ? ' is-removed'
          : inherited
            ? ' is-inherited'
            : '';
  const version = entry.version ?? 0;

  return (
    <>
      <tr className={`secret-row${state} ${rowClass(status)}`}>
        <td className="n">{number}</td>
        <td className="cell-key" data-label="Key">
          {/* An inherited key has no row here to rename: overriding it keeps its name. */}
          {editing && canWrite && own ? (
            <div className="edit-stack">
              <input
                className="input input-mono"
                autoFocus={focusName}
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
              {generated !== null && <RecipeMark generated={generated} />}
              {rowPlain && <span className="tag" title={LEVELS.plain.hint}>Plain</span>}
              {sensitive && (
                <span className="tag" title={LEVELS.sensitive.hint}>
                  <Lock size={11} aria-hidden />
                  Sensitive
                </span>
              )}
              {leaving && <span className="tag tag-red">Will be archived</span>}
              {parent !== null && <Standing project={project} secretKey={entry.key} parent={parent} />}
              {lent.length > 0 && (
                <button
                  type="button"
                  className="tag tag-button tag-violet"
                  aria-expanded={lentOpen}
                  onClick={() => setLentOpen((open) => !open)}
                >
                  {lent.length} {lent.length === 1 ? 'reference' : 'references'}
                </button>
              )}
            </div>
          )}
        </td>

        <td data-label="Value">
          {/* What acts on the value sits beside it: reading, Copy, Reveal and Edit;
              editing or marked for archiving, Save and Cancel, in the same place. */}
          <div className="value-cell">
            <div className="value-content">
              {editing && canWrite ? (
                <div className="edit-stack">
                  <ValueField
                    label={`New value for ${entry.key}`}
                    // Made more visible, the field opens empty: the value is typed again.
                    value={change.value ?? (loosening ? '' : editBase?.value ?? '')}
                    start={loosening ? undefined : editBase?.value}
                    placeholder={
                      loosening ? 'Its value, typed again'
                        : editBase !== null ? 'Value'
                          : sensitive ? 'Type a new value'
                            : canReveal ? 'New value' : 'New value; the current one is hidden from you'
                    }
                    plain={level === 'plain'}
                    disabled={disabled}
                    autoFocus={!focusName}
                    // A value typed over a generated one has no recipe, and a private key's no longer matches its public key.
                    onChange={(value) =>
                      onPatch({ ...valueEdit(from(), { value, sensitivity: level }), companion: undefined, recipe: undefined })
                    }
                    onEscape={onUndo}
                    generate={{
                      // A pending rename is the name it saves under.
                      name: change.key,
                      renamable: false,
                      companion: change.companion,
                      // A generated value is never plain.
                      onUse: ({ value, companion, recipe }) => onPatch({ value, companion, recipe, sensitivity: level === 'plain' ? 'secret' : level }),
                    }}
                  />
                  {/* In a personal config, every value is its owner's secret. */}
                  {!personal && (
                    <SensitivityField
                      name={change.key.trim() === '' ? entry.key : change.key.trim()}
                      value={level}
                      disabled={disabled}
                      // A value made plain is typed by hand: it drops the recipe of one generated.
                      onChange={(next) => onPatch({
                        ...valueEdit(from(), { value: change.value, sensitivity: next }),
                        ...(next === 'plain' ? { companion: undefined, recipe: undefined } : {}),
                      })}
                    />
                  )}
                  {waitsForValue(entry, change) && (
                    <span className="edit-note">
                      {loosening ? 'Making it visible takes a new value: type it again.' : 'Type its value: only a value of its own here is marked.'}
                    </span>
                  )}
                  <CompanionNote companion={change.companion} versionOf={versionOf} />
                  {!overridden && parent !== null && (
                    <span className="edit-note">Saved here, over {parent.from}'s value</span>
                  )}
                  {reference !== null && reference.state === 'live' && (
                    <span className="edit-note">
                      Saving a value stops following <span className="mono">{reference.source}</span>
                    </span>
                  )}
                </div>
              ) : rowPlain && !leaving ? (
                <span className="revealed-value plain-value">{entry.value === '' ? '(empty)' : entry.value}</span>
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
              ) : removed ? (
                <span className="cell-muted">Not served here</span>
              ) : reference !== null ? (
                <ReferenceValue reference={reference} />
              ) : (
                <span className="mask" aria-label={sensitive ? 'Never shown' : 'Hidden'}>
                  ••••••••••••
                </span>
              )}
            </div>
            {status.state !== 'pending' && (
              <div className="acts value-acts">
                {editing || leaving ? (
                  <>
                    <Tip label={leaving ? 'Archive now' : 'Save'}>
                      <button
                        className="act act-icon act-accent"
                        onClick={onSave}
                        disabled={disabled || !saveReady}
                        aria-label={`${leaving ? 'Archive' : 'Save'} ${entry.key} now`}
                      >
                        <Check size={15} />
                      </button>
                    </Tip>
                    <Tip label={leaving ? 'Keep' : 'Cancel'}>
                      <button
                        className="act act-icon act-quiet"
                        onClick={onUndo}
                        disabled={disabled}
                        aria-label={leaving ? `Keep ${entry.key}` : `Cancel editing ${entry.key}`}
                      >
                        <X size={15} />
                      </button>
                    </Tip>
                  </>
                ) : removed ? (
                  canWrite && (
                    <button type="button" className="btn btn-sm" onClick={() => onFork('restore')} disabled={disabled}>
                      Restore
                    </button>
                  )
                ) : (
                  <>
                    {/* Copy sits left of Reveal, hidden or shown, so Hide stays where
                        Reveal was clicked. Hidden, it copies without showing the value;
                        as for Reveal, it takes secret.read, and a reference copies the
                        value it reads through; an inherited key, its parent's, which
                        takes read there too. */}
                    <SecretReadOnly canReveal={canRead}>
                      <CopyButton variant="act" copier={copier} onCopy={copyValue} label={`Copy ${entry.key}`} />
                      {!rowPlain && <Tip label={shown === null ? 'Reveal' : 'Hide'}>
                        <button
                          className="act act-icon act-accent"
                          onClick={toggleReveal}
                          disabled={revealToggleDisabled(reads, shown)}
                          aria-label={`${shown === null ? 'Reveal' : 'Hide'} ${entry.key}`}
                        >
                          {revealing && !opening ? (
                            <Spinner size={13} />
                          ) : shown === null ? (
                            <Eye size={15} />
                          ) : (
                            <EyeOff size={15} />
                          )}
                        </button>
                      </Tip>}
                    </SecretReadOnly>
                    {canWrite && (
                      <Tip label={inherited ? `Override ${parent!.from}'s` : 'Edit'}>
                        <button
                          className="act act-icon"
                          onClick={() => void startEdit()}
                          disabled={disabled || revealing}
                          aria-label={inherited ? `Override ${entry.key}` : `Edit ${entry.key}`}
                        >
                          {opening ? <Spinner size={13} /> : <Pencil size={14} />}
                        </button>
                      </Tip>
                    )}
                  </>
                )}
              </div>
            )}
          </div>
        </td>

        <td className="col-version" data-label="Version">
          {editing && valueChanged && !overridden && parent !== null ? (
            <span className="version-shift">
              <b>own</b>
            </span>
          ) : editing && valueChanged ? (
            <span className="version-shift">
              v{version} → <b>v{version + 1}</b>
            </span>
          ) : (
            <span
              className="version-shift"
              title={inherited ? `${parent!.from}'s version` : reference === null ? undefined : "The source's version"}
            >
              {readVersion === null ? '—' : `v${readVersion}`}
            </span>
          )}
        </td>

        <td className="col-written" data-label="Last written">
          {!removed && <Written entry={entry} rotateAfterDays={rotateAfterDays} />}
        </td>

        <td className="col-actions">
          {status.state === 'pending' ? (
            <RowPending status={status} />
          ) : (
            !removed && (canList || (canWrite && !editing && !leaving) || (canArchive && !leaving && own && !overridden)) && (
              <Menu.Root>
                <Menu.Trigger
                  className="act act-icon act-quiet"
                  aria-label={`More for ${entry.key}`}
                  disabled={disabled}
                >
                  <MoreHorizontal size={16} />
                </Menu.Trigger>
                <MenuPopup align="end">
                  <SecretReadOnly canReveal={canList && own}>
                    <Menu.Item className="menu-item" onClick={() => setHistoryOpen((open) => !open)}>
                      <History size={14} />
                      {historyOpen ? 'Hide history' : 'Version history'}
                    </Menu.Item>
                  </SecretReadOnly>
                  {canWrite && !editing && inherited && (
                    <>
                      <Menu.Item className="menu-item" onClick={() => void startEdit()}>
                        <Pencil size={14} />
                        Override…
                      </Menu.Item>
                      {parent!.reset && (
                        <Menu.Item className="menu-item" onClick={() => onFork('override')}>
                          <RotateBack size={14} />
                          Use its own value again
                        </Menu.Item>
                      )}
                      <Menu.Item className="menu-item" onClick={() => onFork('remove')}>
                        <SlashCircle size={14} />
                        Remove from {environment}
                      </Menu.Item>
                    </>
                  )}
                  {canWrite && !editing && !leaving && overridden && (
                    <Menu.Item className="menu-item" onClick={() => onFork('reset')}>
                      <RotateBack size={14} />
                      Reset to {parent!.from}
                    </Menu.Item>
                  )}
                  {canWrite && !editing && !leaving && own && (
                    <Menu.Item className="menu-item" onClick={() => void startEdit({ name: true })}>
                      <Pencil size={14} />
                      Rename
                    </Menu.Item>
                  )}
                  {canWrite && !editing && !leaving && generated !== null && (
                    <Menu.Item
                      className="menu-item"
                      disabled={regenerateWaits(entry.key, generated, busy)}
                      onClick={() => setRegenerating(true)}
                    >
                      <Generate size={14} />
                      Regenerate…
                    </Menu.Item>
                  )}
                  {canWrite && !editing && !leaving && own && (
                    <Menu.Item className="menu-item" onClick={() => setMoving(true)}>
                      <Folder size={14} />
                      Move to folder…
                    </Menu.Item>
                  )}
                  {canWrite && !editing && !leaving && own && environments.length > 0 && (
                    <Menu.Item className="menu-item" onClick={() => setReferring(true)}>
                      <ArrowRight size={14} />
                      {reference === null ? 'Make a reference…' : 'Point elsewhere…'}
                    </Menu.Item>
                  )}
                  {canWrite && !editing && !leaving && own && reference !== null && reference.state === 'live' && (
                    <Menu.Item className="menu-item" onClick={() => setBreaking(holderPath)}>
                      <SlashCircle size={14} />
                      Break reference…
                    </Menu.Item>
                  )}
                  {/* Its own value's level: a reference's is its source's, an inherited one's its parent's. */}
                  {canWrite && !editing && !leaving && !personal && markable(entry) && (
                    <>
                      <Menu.Separator className="menu-sep" />
                      <Menu.RadioGroup value={entry.sensitivity} onValueChange={(next: Sensitivity) => chooseLevel(next)}>
                        <Menu.GroupLabel className="menu-label">Who sees it</Menu.GroupLabel>
                        {SENSITIVITIES.map((each) => (
                          <Menu.RadioItem key={each} value={each} className="menu-item menu-item-level" closeOnClick>
                            <span className="menu-item-text">
                              {LEVELS[each].label}
                              <span className="menu-item-hint">{LEVELS[each].hint}</span>
                            </span>
                            <Menu.RadioItemIndicator className="menu-check">
                              <Check size={14} />
                            </Menu.RadioItemIndicator>
                          </Menu.RadioItem>
                        ))}
                      </Menu.RadioGroup>
                    </>
                  )}
                  {/* An override's way out is Reset, which keeps it; archiving there would be the same, by more. */}
                  {canArchive && !leaving && own && !overridden && (
                    <>
                      {(canReveal || canWrite) && <Menu.Separator className="menu-sep" />}
                      <Menu.Item
                        className="menu-item menu-item-danger"
                        onClick={() => {
                          setReveal(null);
                          if (blockers.length > 0) setArchiveBlocked(true);
                          else onMarkArchive();
                        }}
                      >
                        <Archive size={14} />
                        Archive
                        <span className="menu-hint">on save</span>
                      </Menu.Item>
                    </>
                  )}
                </MenuPopup>
              </Menu.Root>
            )
          )}
        </td>
      </tr>

      {canWrite && (
        <MakeReference
          open={referring}
          onOpenChange={setReferring}
          holder={holderPath}
          environments={environments}
          onMake={(source) =>
            act(() => coffre.secrets.set(`${project}/${environment}`, { [entry.key]: { ref: source } }), {
              affects: affects.secrets({ project, environment }),
              onSuccess: () => toast.success(`${entry.key} reads ${source}`),
            })
          }
        />
      )}

      {canWrite && generated !== null && (
        <RegenerateSecret
          open={regenerating}
          onOpenChange={setRegenerating}
          place={`${project}/${environment}`}
          entry={entry}
          generated={generated}
          onConfirm={() => {
            setReveal(null);
            onRegenerate(generated);
          }}
        />
      )}

      <ConfirmDialog
        open={archiveBlocked}
        onOpenChange={setArchiveBlocked}
        title={
          <>
            Archive <span className="mono">{entry.key}</span>?
          </>
        }
        body={`It is marked to archive when you save: ${project}/${environment} stops serving it, and its versions stay.`}
        detail={<ArchiveBlocked references={blockers} />}
        confirmLabel="Archive on save"
        confirmDisabled={blockers.length > 0}
        onConfirm={onMarkArchive}
      />

      <ConfirmDialog
        open={hiding}
        onOpenChange={setHiding}
        title={
          <>
            Make <span className="mono">{entry.key}</span> sensitive?
          </>
        }
        body="Nobody, Owners included, will see this value again. Apps use it through the proxy; service accounts still read it."
        confirmLabel="Make sensitive"
        destructive={false}
        onConfirm={() => mark('sensitive')}
      />

      <ConfirmDialog
        open={breaking !== null}
        onOpenChange={(open) => !open && setBreaking(null)}
        title="Break this reference?"
        body={
          breaking === holderPath
            ? `Whoever reads ${project}/${environment} stops reading ${reference?.source ?? 'its source'} through ${entry.key}, and a run of ${project}/${environment} refuses until ${entry.key} gets a value.`
            : `Whoever reads ${breaking ?? ''}'s environment stops reading ${project}/${environment}/${entry.key} through it, and a run there refuses until it gets a value.`
        }
        confirmLabel="Break"
        onConfirm={() => {
          const path = breaking!;
          act(() => coffre.references.break(path), {
            affects: affects.secrets({ project, environment }),
            onSuccess: () => toast.success(`Broke ${path}`),
          });
        }}
      />

      {lentOpen && lent.length > 0 && (
        <tr className="detail-row">
          <td colSpan={columns}>
            <LentReferences references={lent} onBreak={(each) => setBreaking(each.holder)} />
          </td>
        </tr>
      )}

      {canWrite && (
        <MoveToFolder
          open={moving}
          onOpenChange={setMoving}
          what={entry.key}
          current={entry.folder}
          folders={folders}
          onMove={onMove}
        />
      )}

      {historyOpen && canList && (
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

      {(error ?? actError) !== null || copyError !== null ? (
        <tr className="row-error">
          <td colSpan={columns}>
            {/* Reveal's refusal and Copy's are independent: neither hides the other. */}
            <ErrorLine error={error ?? actError} />
            <ErrorLine error={copyError} />
          </td>
        </tr>
      ) : null}

      <RowFailure
        status={status}
        columns={columns}
        onDismiss={() => status.state === 'failed' && onDismiss(status.mutationId)}
      />
    </>
  );
}

/** Delete your personal config, from its page: its values erased; dev itself untouched. */
function DeletePersonal({ project, environment, of }: { project: string; environment: string; of: string }) {
  const coffre = useCoffre();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const { error, run } = useAction();
  return (
    <>
      <button type="button" className="btn btn-sm" onClick={() => setOpen(true)}>
        <Trash size={14} />
        Delete…
      </button>
      {error !== null && <ErrorLine error={error} />}
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        title={<>Delete your own <span className="mono">{of}</span>?</>}
        body={`The values you set in ${project}/${environment} are erased for good. ${project}/${of} is untouched, and ${environment} reads it again.`}
        confirmLabel="Delete"
        onConfirm={() =>
          void run(() => coffre.environments.delete(`${project}/${environment}`), {
            affects: [...affects.secrets({ project, environment }), ...affects.places()],
            onSuccess: () => {
              toast.success(`Your own ${of} is deleted`);
              void navigate({ to: '/projects/$project/$environment', params: { project, environment: of } });
            },
          })}
      />
    </>
  );
}

/**
 * `dev@me` while you have no personal dev: what one is, and Make, which
 * makes it empty; your first write would make it too. A read of
 * `market/dev@me` meanwhile is dev's, so scripts can name it either way.
 */
function NoPersonalConfig({ project, of }: { project: string; of: string }) {
  const coffre = useCoffre();
  const { pending, error, run } = useAction();
  return (
    <>
      <PageHeader tile={project} title={`${of}@me`} />
      <Card labelledBy="no-personal-config" title={`You have no personal ${of} yet`}>
        <div className="card-row">
          <div>
            <p className="card-row-desc">
              A personal config is your own <span className="mono">{project}/{of}</span>: it reads {of}'s keys as they change,
              and the values you set or remove there are yours alone. No one else reads them, an Owner included, and you read
              them only while you read {of}. Until you make one, <span className="mono">{project}/{of}@me</span> reads {of} itself,
              so a script can name it either way.
            </p>
            {error !== null && <ErrorLine error={error} />}
          </div>
          <button
            type="button"
            className="btn btn-primary"
            disabled={pending}
            onClick={() => void run(() => coffre.environments.create(`${project}/${of}@me`), {
              affects: [...affects.secrets({ project, environment: `${of}@me` }), ...affects.places()],
              onSuccess: () => toast.success(`Your own ${of} is made: what you set there is yours alone`),
            })}
          >
            {pending ? <Spinner size={13} /> : <Plus size={14} />}
            Make my own {of}
          </button>
        </div>
      </Card>
    </>
  );
}

/**
 * Where a fork's key stands to its parent's (docs/design/forking.md):
 * inherited from it, overriding it, perhaps since it changed, or removed.
 * The parent links to its own row of the key.
 */
function Standing({ project, secretKey, parent }: { project: string; secretKey: string; parent: NonNullable<SecretKey['parent']> }) {
  const from = (
    <Link className="tag-link" to="/projects/$project/$environment" params={{ project, environment: parent.from }} search={{ filter: secretKey }}>
      {parent.from}
    </Link>
  );
  switch (parent.state) {
    case 'inherited':
      return <span className="tag tag-outline">from {from}</span>;
    case 'removed':
      return <span className="tag tag-outline">removed · {from} {parent.held ? 'has it' : 'dropped it'}</span>;
    case 'overridden':
      return (
        <>
          <span className="tag tag-outline">overrides {from}</span>
          {parent.changed && (
            <Tip label={`${parent.from} has written a newer value since this one: check the override still holds`}>
              <span className="tag tag-amber" tabIndex={0}>
                {parent.from} changed since
              </span>
            </Tip>
          )}
        </>
      );
  }
}

/**
 * A column header that orders the table: its first click ascending, the
 * next descending. Below the width where rows stack, the sortable headers
 * stay, a row of their own above the keys.
 */
function SortHeader({
  className,
  by,
  sort,
  onSort,
  children,
}: {
  className: string;
  by: Sort['by'];
  sort: Sort;
  onSort: (by: Sort['by']) => void;
  children: ReactNode;
}) {
  const sorted = sort.by === by;
  return (
    <th className={`${className} th-sortable`} aria-sort={sorted ? (sort.descending ? 'descending' : 'ascending') : undefined}>
      <button type="button" className="th th-sort" onClick={() => onSort(by)}>
        {children}
        {sorted ? (
          <ChevronDown size={13} className={sort.descending ? 'sort-mark' : 'sort-mark is-ascending'} />
        ) : (
          <ChevronsUpDown size={13} className="sort-mark is-idle" />
        )}
      </button>
    </th>
  );
}

/**
 * Who wrote the value a key reads and how long ago, on one line: the local
 * part of the email is enough to recognise a colleague, and the full address
 * and the exact time are a hover away. A reference's value is its source's,
 * as old as the version it reads, and who made the reference is a hover
 * away too. A value unchanged past the deployment's `rotateAfterDays` gets a
 * quiet tag, its age in days a hover away: it is due for rotation.
 */
function Written({ entry, rotateAfterDays }: { entry: SecretKey; rotateAfterDays: number | null }) {
  const { reference } = entry;
  const made = reference === null
    ? undefined
    : `Reference made by ${shownMember(reference.createdBy).replace(/^user:/, '')} on ${reference.createdAt.slice(0, 10)}`;
  if (entry.updatedAt === null) {
    return <span className="cell-muted" title={made}>—</span>;
  }
  const by = entry.updatedBy ?? 'unknown';
  const due = rotateAfterDays !== null && olderThan(entry, rotateAfterDays);
  const age = ageInDays(entry);
  return (
    <span className="written">
      {reference === null ? (
        <span className="written-by" title={by}>
          {by.split('@')[0]}
        </span>
      ) : (
        <span className="written-by cell-muted" title={`Its source's current version. ${made}`}>
          source
        </span>
      )}
      <span className="cell-muted" aria-hidden>
        ·
      </span>
      <span className="cell-muted">
        <Timestamp iso={entry.updatedAt} display="relative" />
      </span>
      {due && (
        <Tip label={`Unchanged for ${age} days, past the ${rotateAfterDays} this deployment allows: rotate it`}>
          <span className="tag tag-amber written-flag" tabIndex={0}>
            Rotate
          </span>
        </Tip>
      )}
    </span>
  );
}

/**
 * Who sees the value being written, loosest first, and beside it what the
 * level pointed at, or else the one chosen, means. Native radios: the arrow
 * keys move the choice, and a screen reader hears one group of three.
 */
function SensitivityField({
  name,
  value,
  disabled,
  onChange,
}: {
  /** The key it is for, naming the group. */
  name: string;
  value: Sensitivity;
  disabled: boolean;
  onChange: (level: Sensitivity) => void;
}) {
  const id = useId();
  const [pointed, setPointed] = useState<Sensitivity | null>(null);
  return (
    <div className="edit-note sensitivity-field">
      <div className="segmented segmented-sm" role="radiogroup" aria-label={`Who sees ${name}`} aria-describedby={`${id}-hint`}>
        {SENSITIVITIES.map((level) => (
          <label key={level} onPointerEnter={() => setPointed(level)} onPointerLeave={() => setPointed(null)}>
            <input
              type="radio"
              className="visually-hidden"
              name={id}
              value={level}
              checked={value === level}
              disabled={disabled}
              onChange={() => onChange(level)}
            />
            {LEVELS[level].label}
          </label>
        ))}
      </div>
      <span id={`${id}-hint`}>{LEVELS[pointed ?? value].hint}</span>
    </div>
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
  onSave,
  versionOf,
  saveReady,
  personal,
}: {
  draft: SecretDraft;
  existingVersion: number | null;
  disabled: boolean;
  onChange: (patch: Partial<SecretDraft>) => void;
  onRemove: () => void;
  /** This new secret alone, saved now. */
  onSave: () => void;
  /** The current version of a key in this environment, for a companion's note. */
  versionOf: (key: string) => number | null;
  saveReady: boolean;
  /** In a personal config, whose values are its owner's alone: always a secret. */
  personal: boolean;
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
            // Add secret button created.
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
                'This name exists here already. Saving adds a new version to it.'}
            </span>
          )}
        </div>
      </td>
      <td data-label="Value">
        <div className="value-cell">
          <div className="value-content">
            <div className="edit-stack">
              <ValueField
                label={`Value for ${trimmed === '' ? 'the new secret' : trimmed}`}
                value={draft.value}
                plain={draft.sensitivity === 'plain'}
                placeholder="Value"
                disabled={disabled}
                // A value typed over a generated one has no recipe, and a private key's no longer matches its public key.
                onChange={(value) => onChange({ value, companion: undefined, recipe: undefined })}
                onEscape={onRemove}
                generate={{
                  name: draft.key,
                  renamable: true,
                  companion: draft.companion,
                  // A generated value is never plain.
                  onUse: ({ value, name, companion, recipe }) =>
                    onChange({ key: name, value, companion, recipe, sensitivity: draft.sensitivity === 'plain' ? 'secret' : draft.sensitivity }),
                }}
              />
              {!personal && (
                <SensitivityField
                  name={trimmed === '' ? 'the new secret' : trimmed}
                  value={draft.sensitivity}
                  disabled={disabled}
                  // A value made plain is typed by hand: it drops the recipe of one generated.
                  onChange={(sensitivity) => onChange(sensitivity === 'plain' ? { sensitivity, companion: undefined, recipe: undefined } : { sensitivity })}
                />
              )}
              <CompanionNote companion={draft.companion} versionOf={versionOf} />
            </div>
          </div>
          <div className="acts value-acts">
            <Tip label="Save">
              <button
                className="act act-icon act-accent"
                onClick={onSave}
                disabled={disabled || !saveReady}
                aria-label={trimmed === '' ? 'Save this new secret now' : `Save ${trimmed} now`}
              >
                <Check size={15} />
              </button>
            </Tip>
            <Tip label="Cancel">
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
      <td className="col-actions" />
    </tr>
  );
}

function ArchivedRow({
  number,
  project,
  environment,
  entry,
  canArchive,
  canList,
  status: state,
  onRestore,
  onDismiss,
}: {
  number: number;
  project: string;
  environment: string;
  entry: SecretKey;
  canArchive: boolean;
  /** Whether the caller lists the environment, as its history takes. */
  canList: boolean;
  status: ItemStatus;
  onRestore: () => void;
  onDismiss: (mutationId: number) => void;
}) {
  const [historyOpen, setHistoryOpen] = useState(false);

  return (
    <>
      <tr className={`secret-row is-archived ${rowClass(state)}`}>
        <td className="n">{number}</td>
        <td className="cell-key" data-label="Key">
          {breakAfterUnderscores(entry.key)}
        </td>
        <td className="col-version" data-label="Version">
          <span className="version-shift">{entry.version === null ? '—' : `v${entry.version}`}</span>
        </td>
        <td className="col-written col-hide-narrow" data-label="Last written">
          <Written entry={entry} rotateAfterDays={null} />
        </td>
        <td className="col-actions">
          {state.state === 'pending' ? (
            <RowPending status={state} />
          ) : (
            (canList || canArchive) && (
              <div className="acts">
                <Menu.Root>
                  <Menu.Trigger
                    className="act act-icon act-quiet"
                    aria-label={`More for ${entry.key}`}
                  >
                    <MoreHorizontal size={16} />
                  </Menu.Trigger>
                  <MenuPopup align="end">
                    <SecretReadOnly canReveal={canList}>
                      <Menu.Item
                        className="menu-item"
                        onClick={() => setHistoryOpen((open) => !open)}
                      >
                        <History size={14} />
                        {historyOpen ? 'Hide history' : 'Version history'}
                      </Menu.Item>
                    </SecretReadOnly>
                    {canArchive && (
                      <>
                        {canList && <Menu.Separator className="menu-sep" />}
                        <Menu.Item className="menu-item" onClick={onRestore}>
                          <RotateBack size={14} />
                          Restore
                        </Menu.Item>
                      </>
                    )}
                  </MenuPopup>
                </Menu.Root>
              </div>
            )
          )}
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
      <RowFailure
        status={state}
        columns={5}
        onDismiss={() => state.state === 'failed' && onDismiss(state.mutationId)}
      />
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
                    {version.current && <span className="tag tag-blue">Current</span>}
                    {version.sensitivity !== 'secret' && (
                      <>
                        {' '}
                        <span className="tag" title={LEVELS[version.sensitivity].hint}>{LEVELS[version.sensitivity].label}</span>
                      </>
                    )}
                  </td>
                  <td className="nowrap">
                    <Timestamp iso={version.createdAt} />
                  </td>
                  <td>
                    {version.createdBy}
                    {version.recipe !== null && (
                      <span className="cell-muted">
                        {' '}· generated, <span className="mono">{version.recipe}</span>
                      </span>
                    )}
                  </td>
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
                            v{version.version} becomes current, and anything reading{' '}
                            <span className="mono">
                              {project}/{environment}
                            </span>{' '}
                            gets it at once. Every version stays.
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
                            {
                              affects: affects.secrets({ project, environment }),
                              onSuccess: () => {
                                onRolledBack();
                                toast.success(`${secretKey} rolled back to v${version.version}`);
                              },
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
      {
        // A dry run: nothing changes.
        affects: [],
        onSuccess: (result) => {
          setProblems(result.problems);
          setPlan({ entries: result.plan, changes: result.changes });
        },
      },
    );
  }

  function apply() {
    if (plan === null) return;
    const written = Object.keys(plan.changes).length;
    run(
      () => coffre.secrets.set(path, plan.changes),
      {
        affects: affects.secrets({ project, environment }),
        onSuccess: () => {
          toast.success(`Imported ${written} change${written === 1 ? '' : 's'}`);
          close();
        },
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
            Paste a .env file. coffre parses it as the CLI does and compares it with the current
            values, without sending them to this page.
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
            <Notice tone="good">Every key already has this value.</Notice>
          )}

          {problems.length > 0 && (
            <Notice tone="bad">
              <strong>
                {problems.length} line{problems.length === 1 ? '' : 's'} could not be parsed
              </strong>
              <ul style={{ margin: '0.375rem 0 0', paddingLeft: '1.1rem' }}>
                {problems.map((problem) => (
                  <li key={problem.line}>
                    Line {problem.line}: {problem.reason}
                    {problem.key !== undefined && <span className="mono"> ({problem.key})</span>}
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

