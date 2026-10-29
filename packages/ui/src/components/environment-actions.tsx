import { useEffect, useState } from 'react';
import { Menu } from '@base-ui/react/menu';
import { useQuery } from '@tanstack/react-query';
import { Link, useNavigate } from '@tanstack/react-router';
import { toast } from 'sonner';
import { archiveEnvironment, createEnvironment, renameEnvironment } from '../lib/changes';
import { useCoffre } from '../lib/coffre';
import { isActiveAccessibleEnvironment, type ProjectEnvironment } from '../lib/project-environments';
import { affects, queries } from '../lib/queries';
import { useAction } from '../lib/use-action';
import { useChange } from '../lib/use-change';
import { useShell } from '../lib/use-shell';
import { environmentSlugProblem } from '../lib/validation';
import { DeletePlaceDialog } from './delete-place';
import { Archive, Fork, Key, Lock, MoreHorizontal, Pencil, RotateBack, Trash } from './icons';
import { changesProtection, ProtectDialog } from './protected';
import { ArchiveBlocked, archiveBlockers } from './references';
import { ConfirmDialog, ErrorLine, MenuPopup, Modal, Notice } from './ui';

/**
 * Renaming an environment, `market/dev` to `market/develop`: shown at once
 * where it is listed, which says if the server refuses; `onRenamed` once it
 * has not.
 */
export function RenameEnvironment({
  project,
  environment,
  open,
  onOpenChange,
  onRenamed,
}: {
  project: string;
  environment: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onRenamed?: (slug: string) => void;
}) {
  const rename = useChange(renameEnvironment(useCoffre(), project));
  const [slug, setSlug] = useState(environment);
  useEffect(() => {
    if (open) setSlug(environment);
  }, [open, environment]);
  const slugError = slug === '' ? null : environmentSlugProblem(slug);
  // Scopes match environments by slug: a new one is said to move them before the rename is saved.
  const reslugged = slug !== environment && slug !== '' && slugError === null;
  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={
        <>
          Rename{' '}
          <span className="mono">
            {project}/{environment}
          </span>
        </>
      }
    >
      <form
        className="form"
        onSubmit={(event) => {
          event.preventDefault();
          rename({ from: environment, slug }, { onSuccess: () => onRenamed?.(slug) });
          onOpenChange(false);
        }}
      >
        <label className="field">
          <span className="label">Slug</span>
          <input
            className="input input-mono"
            autoFocus
            spellCheck={false}
            value={slug}
            aria-invalid={slugError !== null}
            onChange={(event) => setSlug(event.target.value)}
          />
          <span className={`hint${slugError !== null ? ' edit-note-error' : ''}`}>
            {slugError ?? `Anything running coffre run ${project}/${environment} will need the new path.`}
          </span>
        </label>
        {reslugged && (
          <Notice tone="info">
            Instance roles scoped to <span className="mono">{environment}</span> stop reaching it; those scoped
            to <span className="mono">{slug}</span> start.
          </Notice>
        )}

        <div className="dialog-actions">
          <button className="btn" type="button" onClick={() => onOpenChange(false)}>
            Cancel
          </button>
          <button
            className="btn btn-primary"
            type="submit"
            disabled={slug === environment || slug === '' || slugError !== null}
          >
            Save
          </button>
        </div>
      </form>
    </Modal>
  );
}

/**
 * Archiving an environment, or restoring an archived one. What archiving
 * would stop is asked once the dialog opens (D41), and Archive waits for
 * the answer; `onArchived` once the server has archived it.
 */
export function ArchiveEnvironment({
  project,
  environment,
  open,
  onOpenChange,
  onArchived,
}: {
  project: string;
  environment: ProjectEnvironment;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onArchived?: () => void;
}) {
  const coffre = useCoffre();
  const archive = useChange(archiveEnvironment(coffre, project));
  const place = `${project}/${environment.slug}`;
  const isArchived = environment.details !== null && environment.details.archivedAt !== null;
  const secretCount = environment.details?.secretCount ?? null;
  const archiving = open && !isArchived;
  const { data: lent } = useQuery({ ...queries.references(coffre, place), enabled: archiving });
  const blockers = archiving && lent?.ok === true ? archiveBlockers(place, lent.references) : [];
  const asking = archiving && lent === undefined;
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title={
        <>
          {isArchived ? 'Restore' : 'Archive'} <span className="mono">{place}</span>?
        </>
      }
      body={
        secretCount === null ? (
          <>This changes whether the environment serves its secrets. Values and history stay stored.</>
        ) : isArchived ? (
          <>
            It serves its {secretCount} secret{secretCount === 1 ? '' : 's'} again, to everyone with a grant on it.
          </>
        ) : (
          <>
            Its {secretCount} secret{secretCount === 1 ? '' : 's'} stop being served, so anything running{' '}
            <code>coffre run</code> against <span className="mono">{place}</span> loses them at its next start.
            Values and history survive, and restoring is one click.
          </>
        )
      }
      detail={<ArchiveBlocked references={blockers} />}
      confirmLabel={isArchived ? 'Restore environment' : 'Archive environment'}
      confirmDisabled={asking || blockers.length > 0}
      destructive={!isArchived}
      onConfirm={() => archive({ slug: environment.slug, archived: !isArchived }, { onSuccess: () => !isArchived && onArchived?.() })}
    />
  );
}

/**
 * A new environment, empty, or forked from one you can read: inheriting
 * its keys live (docs/design/forking.md), or each of them copied, value and
 * folder, without history, or a reference to it. Copying is a read, and
 * logged as one; inheriting reads nothing until the fork is read. `from`
 * starts it as a fork of that environment, inheriting.
 */
export function NewEnvironment({
  project,
  from: forked,
  open,
  onOpenChange,
  onCreated,
}: {
  project: string;
  from?: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated?: (slug: string) => void;
}) {
  const environments = useShell().projects.find((entry) => entry.slug === project)?.environments ?? [];
  // Your personal config is nobody's source: its values are yours alone.
  const sources = environments.filter((environment) => isActiveAccessibleEnvironment(environment) && !environment.personal).map((environment) => environment.slug);
  // The protected ones: a fork of one is protected too.
  const guarded = environments.filter((environment) => environment.protected).map((environment) => environment.slug);
  // '' for empty, 'inherit:prod' for a fork that inherits, 'copy:prod' for a copy, 'ref:prod' for references to prod.
  const initial = forked === undefined ? '' : `inherit:${forked}`;
  const [slug, setSlug] = useState('');
  const [start, setStart] = useState(initial);
  // Set back as it closes, not as it opens: opened again, it never starts, even for a render, from the last choice,
  // whose source it would read.
  const close = () => {
    setSlug('');
    setStart(initial);
    onOpenChange(false);
  };
  const [how, from] = start === '' ? ['', ''] : (start.split(':') as ['inherit' | 'copy' | 'ref', string]);
  const coffre = useCoffre();
  // A fork as references copies the keys whose source you read only through their parent: said before you confirm,
  // and read only while the dialog is open.
  const { data: parent } = useQuery({ ...queries.secrets(coffre, { project, environment: from }), enabled: open && how === 'ref' });
  const copied = how === 'ref' && parent?.ok === true
    ? parent.keys.filter((key) => !key.archived && key.reference !== null && !key.reference.canOpenSource).map((key) => key.key)
    : [];
  const create = useChange(createEnvironment(coffre, project));
  const slugError = slug === '' ? null : environmentSlugProblem(slug);

  return (
    <Modal
      open={open}
      onOpenChange={(next) => (next ? onOpenChange(true) : close())}
      title={
        forked === undefined ? (
          <>
            New environment in <span className="mono">{project}</span>
          </>
        ) : (
          <>
            Fork <span className="mono">{project}/{forked}</span>
          </>
        )
      }
    >
      <form
        className="form"
        onSubmit={(event) => {
          event.preventDefault();
          // Listed at once, as saving; the list says if the server refuses.
          const made = slug;
          create(
            { slug: made, ...(from === '' ? {} : { from }), ...(how === 'ref' ? { references: true } : {}), ...(how === 'inherit' ? { inherit: true } : {}) },
            { onSuccess: () => onCreated?.(made) },
          );
          close();
        }}
      >
        <label className="field">
          <span className="label">Slug</span>
          <input
            className="input input-mono"
            autoFocus
            spellCheck={false}
            autoComplete="off"
            placeholder="staging"
            value={slug}
            aria-invalid={slugError !== null}
            onChange={(event) => setSlug(event.target.value)}
          />
          <span className={`hint${slugError !== null ? ' edit-note-error' : ''}`}>
            {slugError ?? (
              <>
                The CLI will address it as{' '}
                <span className="mono">
                  {project}/{slug === '' ? 'staging' : slug}
                </span>
                .
              </>
            )}
          </span>
        </label>
        {sources.length > 0 && (
          <label className="field">
            <span className="label">Start from</span>
            <select className="select" value={start} onChange={(event) => setStart(event.target.value)}>
              <option value="">Empty</option>
              {sources.map((source) => (
                <option key={`inherit:${source}`} value={`inherit:${source}`}>
                  Inheriting from {source}
                </option>
              ))}
              {sources.map((source) => (
                <option key={`copy:${source}`} value={`copy:${source}`}>
                  A copy of {source}
                </option>
              ))}
              {sources.map((source) => (
                <option key={`ref:${source}`} value={`ref:${source}`}>
                  References to {source}
                </option>
              ))}
            </select>
            <span className="hint">
              {how === ''
                ? 'No secrets yet.'
                : how === 'inherit'
                  ? `Keeps reading ${from}'s keys, live, except those you set or remove here. Whoever reads ${slug === '' ? 'the new environment' : slug} needs read on ${from} too, for those.`
                  : how === 'copy'
                  ? `Each of ${from}'s keys, with its current value and folder, without history.`
                  : `Each key follows ${from}'s until it gets a value of its own. Whoever can read ${slug === '' ? 'the new environment' : slug} will read ${from}'s values through them, even without access to ${from}.`}
            </span>
            {from !== '' && guarded.includes(from) && (
              <span className="hint">
                <span className="mono">{from}</span> is protected, so the new environment is too, from its first moment.
              </span>
            )}
            {copied.length > 0 && (
              <span className="hint">
                Copied instead, since you read their source only through {from}: <span className="mono">{copied.join(', ')}</span>.
              </span>
            )}
          </label>
        )}

        <div className="dialog-actions">
          <button className="btn" type="button" onClick={close}>
            Cancel
          </button>
          <button className="btn btn-primary" type="submit" disabled={slug === '' || slugError !== null}>
            Add environment
          </button>
        </div>
      </form>
    </Modal>
  );
}

/**
 * What is done to an environment itself, in one menu, on its card and its
 * page alike: rename, protect, fork, your own config of it, archive or
 * restore, and delete once archived; in your own config, delete it. Each
 * shows only to whoever may do it, as the project tree says, so it asks
 * the server nothing more.
 */
export function EnvironmentMenu({
  project,
  environment,
  inProject,
  ownConfig,
  busy,
  follow,
  className,
}: {
  project: string;
  environment: string;
  /** It as the project tree has it. */
  inProject: ProjectEnvironment | undefined;
  /** Whether to offer your own config of it, `dev@me`. */
  ownConfig: boolean;
  /** Whether a change of it, a rename, its protection or its archiving, is on its way: another waits for its answer. */
  busy: boolean;
  /**
   * Whether it goes where a change leads, as its own page does: to its new
   * name, to its fork, back to the project once it is archived, and to the
   * environment your own config was of once you delete it.
   */
  follow: boolean;
  /** The trigger's look: the page header's button, or a card's quiet act. */
  className: string;
}) {
  const navigate = useNavigate();
  const { projects, capabilities } = useShell();
  const [open, setOpen] = useState<'rename' | 'protect' | 'fork' | 'archive' | 'delete' | null>(null);
  const dialog = (which: NonNullable<typeof open>) => ({
    open: open === which,
    onOpenChange: (next: boolean) => setOpen(next ? which : null),
  });
  const toEnvironment = follow ? (slug: string) => void navigate({ to: '/projects/$project/$environment', params: { project, environment: slug } }) : undefined;
  // Your own config, `dev@me`: deleted, nothing else; the environment it is yours of.
  const personalOf = inProject?.personal === true ? inProject.parent : null;
  // Its dialogs stay mounted by the project's permission, not by its entry in the tree: a rename moves that entry at
  // once, and a dialog gone with it would drop the rename's answer, and with it the move to its new address.
  const managesProject = personalOf === null && projects.find((entry) => entry.slug === project)?.permissions.includes('environment.manage') === true;
  const manages = managesProject && inProject !== undefined && inProject.details !== null;
  const archived = manages && inProject!.details!.archivedAt !== null;
  const protects = personalOf === null && inProject !== undefined && changesProtection(projects, project, inProject);
  const forks = manages && isActiveAccessibleEnvironment(inProject!);
  // Deleting is for those who run the instance, and only once the environment is archived.
  const deletes = archived && capabilities.runsInstance;
  const offers = personalOf !== null || manages || protects || ownConfig;
  return (
    <>
      {offers && (
        <Menu.Root>
          <Menu.Trigger className={className} aria-label={`Actions for ${project}/${environment}`}>
            <MoreHorizontal size={16} />
          </Menu.Trigger>
          <MenuPopup align="end">
            {personalOf !== null ? (
              <Menu.Item className="menu-item menu-item-danger" onClick={() => setOpen('delete')}>
                <Trash size={14} />
                Delete…
              </Menu.Item>
            ) : (
              <>
                {manages && (
                  <Menu.Item className="menu-item" disabled={busy} onClick={() => setOpen('rename')}>
                    <Pencil size={14} />
                    Rename…
                  </Menu.Item>
                )}
                {protects && (
                  <Menu.Item className="menu-item" disabled={busy} onClick={() => setOpen('protect')}>
                    <Lock size={14} />
                    {inProject!.protected ? 'Unprotect…' : 'Protect…'}
                  </Menu.Item>
                )}
                {forks && (
                  <Menu.Item className="menu-item" onClick={() => setOpen('fork')}>
                    <Fork size={14} />
                    Fork…
                  </Menu.Item>
                )}
                {ownConfig && (
                  <Menu.LinkItem
                    className="menu-item"
                    closeOnClick
                    render={<Link to="/projects/$project/$environment" params={{ project, environment: `${environment}@me` }} />}
                  >
                    <Key size={14} />
                    My own {environment}
                  </Menu.LinkItem>
                )}
                {manages && (
                  <>
                    <Menu.Separator className="menu-sep" />
                    <Menu.Item className={`menu-item${archived ? '' : ' menu-item-danger'}`} disabled={busy} onClick={() => setOpen('archive')}>
                      {archived ? <RotateBack size={14} /> : <Archive size={14} />}
                      {archived ? 'Restore…' : 'Archive…'}
                    </Menu.Item>
                  </>
                )}
                {deletes && (
                  <Menu.Item className="menu-item menu-item-danger" disabled={busy} onClick={() => setOpen('delete')}>
                    <Trash size={14} />
                    Delete…
                  </Menu.Item>
                )}
              </>
            )}
          </MenuPopup>
        </Menu.Root>
      )}
      {managesProject && (
        <>
          <RenameEnvironment project={project} environment={environment} {...dialog('rename')} onRenamed={toEnvironment} />
          <NewEnvironment project={project} from={environment} {...dialog('fork')} onCreated={toEnvironment} />
        </>
      )}
      {manages && (
        <ArchiveEnvironment
          project={project}
          environment={inProject!}
          {...dialog('archive')}
          onArchived={follow ? () => {
            toast.success(`${project}/${environment} archived`);
            void navigate({ to: '/projects/$project', params: { project } });
          } : undefined}
        />
      )}
      {protects && <ProtectDialog project={project} environment={inProject!} {...dialog('protect')} />}
      {deletes && (
        <DeletePlaceDialog
          path={`${project}/${environment}`}
          {...dialog('delete')}
          onDeleted={() => toast.success(`${project}/${environment} deleted`)}
        />
      )}
      {personalOf !== null && (
        <DeletePersonal project={project} environment={environment} of={personalOf} {...dialog('delete')} onDeleted={toEnvironment} />
      )}
    </>
  );
}

/** Delete your personal config: its values erased; the environment it is yours of untouched. */
function DeletePersonal({
  project,
  environment,
  of,
  open,
  onOpenChange,
  onDeleted,
}: {
  project: string;
  environment: string;
  of: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Once deleted, with the environment it was yours of. */
  onDeleted?: (of: string) => void;
}) {
  const coffre = useCoffre();
  const { error, run } = useAction();
  return (
    <>
      {error !== null && <ErrorLine error={error} />}
      <ConfirmDialog
        open={open}
        onOpenChange={onOpenChange}
        title={<>Delete your own <span className="mono">{of}</span>?</>}
        body={`The values you set in ${project}/${environment} are erased for good. ${project}/${of} is untouched, and ${environment} reads it again.`}
        confirmLabel="Delete"
        onConfirm={() =>
          void run(() => coffre.environments.delete(`${project}/${environment}`), {
            affects: [...affects.secrets({ project, environment }), ...affects.places()],
            onSuccess: () => {
              toast.success(`Your own ${of} is deleted`);
              onDeleted?.(of);
            },
          })}
      />
    </>
  );
}
