import { useState } from 'react';
import { useQuery, useSuspenseQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useShell } from '../lib/use-shell';
import { Menu } from '@base-ui/react/menu';
import { toast } from 'sonner';
import { useCoffre } from '../lib/coffre';
import { archiveEnvironment, createEnvironment, environmentId, renameEnvironment } from '../lib/changes';
import { keys, queries } from '../lib/queries';
import { useChange, useChangeStatus } from '../lib/use-change';
import { ItemFailure, RowPending, rowClass } from '../components/row-state';
import type { GrantRow, ProjectSummary } from '../shared/models';
import { ArchiveBlocked, archiveBlockers } from '../components/references';
import { hasEnvironmentDetails, isActiveAccessibleEnvironment, type ProjectEnvironment } from '../lib/project-environments';
import { environmentSlugProblem } from '../lib/validation';
import { ConfirmDialog, EmptyState, MenuPopup, Modal, Timestamp } from '../components/ui';
import { DeletePlaceDialog } from '../components/delete-place';
import { PrincipalAvatar } from '../components/principal';
import { ReachedBy, reaching, useEveryProject } from '../components/every-project';
import { Archive, ChevronRight, MoreHorizontal, Pencil, Plus, RotateBack, Trash } from '../components/icons';
import { pageRoute } from '../lib/page-route';
import { useProject } from '../lib/project-page';
import type { projectEnvironments } from '../options';

const Route = pageRoute<typeof projectEnvironments>();

/** A project's first tab: its environments, each opening its secrets. */
export function ProjectEnvironmentsPage() {
  const { project, managesAccess } = useProject(Route.useParams().project);
  const canManage = project.permissions.includes('environment.manage');
  return managesAccess ? (
    <ManagedEnvironments project={project} canManage={canManage} />
  ) : (
    <EnvironmentsPanel project={project} canManage={canManage} grants={[]} />
  );
}

/** The environments of a project whose access you manage, each with who can open it. */
function ManagedEnvironments({ project, canManage }: { project: ProjectSummary; canManage: boolean }) {
  const { data: result } = useSuspenseQuery(queries.grants(useCoffre(), project.slug));
  return <EnvironmentsPanel project={project} canManage={canManage} grants={result.ok ? result.grants : []} />;
}

function EnvironmentsPanel({
  project,
  canManage,
  grants,
}: {
  project: ProjectSummary;
  canManage: boolean;
  /** The project's grants, when you manage its access: who can open each environment. */
  grants: GrantRow[];
}) {
  const detailed = project.environments.filter(hasEnvironmentDetails);
  const archived = detailed.filter((environment) => environment.details.archivedAt !== null);
  // Environments you may know by name only sit with the active ones: no grant
  // you hold covers their contents, so they are muted and do not open.
  const current = project.environments.filter(
    (environment) => environment.details === null || environment.details.archivedAt === null,
  );
  const { failedAdds, dismiss } = useChangeStatus(keys.projects);
  const refused = failedAdds<{ slug: string; name: string }>(
    project.environments.map((environment) => environmentId(project.slug, environment.slug)),
  ).filter(({ ids }) => ids.every((id) => id.startsWith(`${project.slug}/`)));

  return (
    <>
      {current.length === 0 && refused.length === 0 ? (
        <div className="card">
          <EmptyState title="No environments yet">
            {canManage
              ? 'Add the first with Add environment.'
              : 'Creating environments needs environment.manage on this project.'}
          </EmptyState>
        </div>
      ) : (
        <ul className="env-grid" aria-label="Environments">
          {current.map((environment) => (
            <li key={`${project.slug}:${environment.slug}`}>
              <EnvironmentCard
                project={project.slug}
                environment={environment}
                isAdmin={canManage}
                grants={grants}
              />
            </li>
          ))}
          {refused.map(({ mutationId, vars, status }) => (
            <li key={mutationId}>
              <div className="env-card is-muted is-failed">
                <div className="env-card-text">
                  <span className="env-card-name">{vars.name}</span>
                  <span className="env-card-meta">
                    <span className="mono">{vars.slug}</span>
                  </span>
                </div>
                <ItemFailure status={status} onDismiss={() => dismiss(mutationId)}>
                  Not added.
                </ItemFailure>
              </div>
            </li>
          ))}
        </ul>
      )}

      {canManage && (
        <div className="table-actions">
          <NewEnvironment
            project={project.slug}
            sources={current.filter(isActiveAccessibleEnvironment).map((environment) => environment.slug)}
          />
        </div>
      )}

      {archived.length > 0 && (
        <section aria-labelledby="archived-environments">
          <h2 className="section-title" id="archived-environments">
            Archived
          </h2>
          <ul className="env-grid">
            {archived.map((environment) => (
              <li key={environment.slug}>
                <EnvironmentCard
                  project={project.slug}
                  environment={environment}
                  isAdmin={canManage}
                  grants={grants}
                />
              </li>
            ))}
          </ul>
        </section>
      )}
    </>
  );
}

/**
 * One environment. The whole card opens it when you can; its menu sits above
 * that link.
 */
/** Who can open an environment: a grant on it, or on the whole project. */
function holdersOf(grants: GrantRow[], environment: string) {
  const seen = new Set<string>();
  return grants.filter((grant) => {
    const id = `${grant.principalType}:${grant.principalId}`;
    if ((grant.environmentSlug !== null && grant.environmentSlug !== environment) || seen.has(id)) {
      return false;
    }
    seen.add(id);
    return true;
  });
}

/** The newest change among an environment's secrets, read when its card shows. */
function useLastChange(project: string, environment: string, enabled: boolean) {
  const { data } = useQuery({ ...queries.secrets(useCoffre(), { project, environment }), enabled });
  if (data === undefined || !data.ok) return null;
  let last: { at: string; by: string | null } | null = null;
  for (const key of data.keys) {
    if (!key.archived && key.updatedAt !== null && (last === null || key.updatedAt > last.at)) {
      last = { at: key.updatedAt, by: key.updatedBy };
    }
  }
  return last;
}

const SHOWN_HOLDERS = 4;

function EnvironmentCard({
  project,
  environment,
  isAdmin,
  grants,
}: {
  project: string;
  environment: ProjectEnvironment;
  isAdmin: boolean;
  grants: GrantRow[];
}) {
  const [renaming, setRenaming] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const { instanceRole } = useShell();
  const [slug, setSlug] = useState(environment.slug);
  const [name, setName] = useState(environment.name);
  const coffre = useCoffre();
  const rename = useChange(renameEnvironment(coffre, project));
  const archive = useChange(archiveEnvironment(coffre, project));
  // What archiving it would stop, asked once the dialog opens (D41); Archive waits for the answer.
  const place = `${project}/${environment.slug}`;
  const archiving = confirming && environment.details?.archivedAt == null;
  const { data: lent } = useQuery({ ...queries.references(coffre, place), enabled: archiving });
  const blockers = archiving && lent?.ok === true ? archiveBlockers(place, lent.references) : [];
  const asking = archiving && lent === undefined;
  const everyProject = useEveryProject();
  const { status, dismiss } = useChangeStatus(keys.projects);
  const state = status(environmentId(project, environment.slug));
  const pending = state.state === 'pending';
  const details = environment.details;
  const isArchived = details !== null && details.archivedAt !== null;
  const secretCount = details?.secretCount ?? null;
  const opens = details !== null && !isArchived && environment.accessible && !pending;
  const manageable = isAdmin && details !== null;
  // Deleting is for instance owners, and only once the environment is archived.
  const deletable = manageable && isArchived && instanceRole !== 'user';
  const slugError = slug === '' ? null : environmentSlugProblem(slug);
  const lastChange = useLastChange(project, environment.slug, opens);
  const holders = holdersOf(grants, environment.slug);
  // A new slug brings in whoever holds it in every project: said before the rename is saved.
  const gainedBy =
    slug === environment.slug || slugError !== null
      ? []
      : reaching(everyProject, slug).filter((grant) => grant.place !== '*');

  return (
    <div
      className={`env-card${opens ? ' is-link' : ' is-muted'} ${rowClass(state)}`}
    >
      <div className="env-card-text">
        <span className="env-card-head">
          {opens ? (
            <Link
              className="env-card-name stretch"
              to="/projects/$project/$environment"
              params={{ project, environment: environment.slug }}
            >
              {environment.name}
            </Link>
          ) : (
            <span className="env-card-name">{environment.name}</span>
          )}
          <span className="env-card-slug mono">{environment.slug}</span>
        </span>

        {isArchived ? (
          <span className="env-card-meta">
            <span className="tag tag-red">Archived</span>
          </span>
        ) : !environment.accessible && !pending ? (
          <span className="env-card-meta">
            <span className="tag tag-outline">No secret access</span>
          </span>
        ) : (
          secretCount !== null && (
            <span className="env-card-facts">
              <span className="env-card-count">
                <strong>{secretCount}</strong> secret{secretCount === 1 ? '' : 's'}
              </span>
              {lastChange !== null && (
                <span className="env-card-change">
                  Changed <Timestamp iso={lastChange.at} display="relative" />
                  {lastChange.by !== null && <> by {lastChange.by.split('@')[0]}</>}
                </span>
              )}
            </span>
          )
        )}

        {holders.length > 0 && !isArchived && (
          <span
            className="env-card-holders"
            title={holders.map((grant) => grant.principalId).join(', ')}
          >
            <span className="avatar-stack">
              {holders.slice(0, SHOWN_HOLDERS).map((grant) => (
                <PrincipalAvatar
                  key={`${grant.principalType}:${grant.principalId}`}
                  type={grant.principalType}
                  id={grant.principalId}
                />
              ))}
            </span>
            <span>{holders.length} with access</span>
          </span>
        )}
      </div>

      {opens && <ChevronRight size={16} className="env-card-go" aria-hidden />}

      {pending && <RowPending status={state} />}

      {manageable && !pending && (
        <Menu.Root>
          <Menu.Trigger
            className="act act-quiet env-card-menu"
            aria-label={`Actions for ${environment.slug}`}
          >
            <MoreHorizontal size={16} />
          </Menu.Trigger>
          <MenuPopup align="end">
            <Menu.Item
              className="menu-item"
              onClick={() => {
                setSlug(environment.slug);
                setName(environment.name);
                setRenaming(true);
              }}
            >
              <Pencil size={14} />
              Rename
            </Menu.Item>
            <Menu.Separator className="menu-sep" />
            <Menu.Item
              className={`menu-item${isArchived ? '' : ' menu-item-danger'}`}
              onClick={() => setConfirming(true)}
            >
              {isArchived ? <RotateBack size={14} /> : <Archive size={14} />}
              {isArchived ? 'Restore' : 'Archive…'}
            </Menu.Item>
            {deletable && (
              <Menu.Item className="menu-item menu-item-danger" onClick={() => setDeleting(true)}>
                <Trash size={14} />
                Delete…
              </Menu.Item>
            )}
          </MenuPopup>
        </Menu.Root>
      )}

      {manageable && (
        <>
          <Modal
            open={renaming}
            onOpenChange={setRenaming}
            title={
              <>
                Rename{' '}
                <span className="mono">
                  {project}/{environment.slug}
                </span>
              </>
            }
          >
            <form
              className="form"
              onSubmit={(event) => {
                event.preventDefault();
                // Shown on the card at once; the card says if the server refuses.
                rename({ from: environment.slug, slug, name: name.trim() });
                setRenaming(false);
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
                  {slugError ??
                    `Anything running coffre run ${project}/${environment.slug} will need the new path.`}
                </span>
              </label>
              <label className="field">
                <span className="label">Display name</span>
                <input
                  className="input"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                />
              </label>

              <ReachedBy grants={gainedBy} lead={`As ${project}/${slug}, it is reached by`} />

              <div className="dialog-actions">
                <button className="btn" type="button" onClick={() => setRenaming(false)}>
                  Cancel
                </button>
                <button
                  className="btn btn-primary"
                  type="submit"
                  disabled={slug === '' || slugError !== null || name.trim() === ''}
                >
                  Save
                </button>
              </div>
            </form>
          </Modal>

          <ConfirmDialog
            open={confirming}
            onOpenChange={setConfirming}
            title={
              <>
                {isArchived ? 'Restore' : 'Archive'}{' '}
                <span className="mono">
                  {project}/{environment.slug}
                </span>
                ?
              </>
            }
            body={
              secretCount === null ? (
                <>
                  This changes whether the environment serves its secrets. Values and history
                  stay stored.
                </>
              ) : isArchived ? (
                <>
                  It serves its {secretCount} secret{secretCount === 1 ? '' : 's'} again, to
                  everyone with a grant on it.
                </>
              ) : (
                <>
                  Its {secretCount} secret{secretCount === 1 ? '' : 's'} stop being served, so
                  anything running <code>coffre run</code> against{' '}
                  <span className="mono">
                    {project}/{environment.slug}
                  </span>{' '}
                  loses them at its next start. Values and history survive, and restoring is
                  one click.
                </>
              )
            }
            detail={<ArchiveBlocked references={blockers} />}
            confirmLabel={isArchived ? 'Restore environment' : 'Archive environment'}
            confirmDisabled={asking || blockers.length > 0}
            destructive={!isArchived}
            onConfirm={() => archive({ slug: environment.slug, archived: !isArchived })}
          />
        </>
      )}

      {deletable && (
        <DeletePlaceDialog
          path={`${project}/${environment.slug}`}
          open={deleting}
          onOpenChange={setDeleting}
          onDeleted={() => toast.success(`${project}/${environment.slug} deleted`)}
        />
      )}

      <ItemFailure
        status={state}
        onDismiss={() => state.state === 'failed' && dismiss(state.mutationId)}
      />
    </div>
  );
}

/**
 * A new environment, empty, or forked from one you can read: each of its
 * keys copied, value and folder, without history. Copying is a read, and
 * logged as one.
 */
function NewEnvironment({ project, sources }: { project: string; sources: string[] }) {
  const [open, setOpen] = useState(false);
  const [slug, setSlug] = useState('');
  const [name, setName] = useState('');
  // '' for empty, 'copy:prod' for a copy, 'ref:prod' for references to prod.
  const [start, setStart] = useState('');
  const [how, from] = start === '' ? ['', ''] : (start.split(':') as ['copy' | 'ref', string]);
  const coffre = useCoffre();
  // A fork as references copies the keys whose source you read only through their parent: said before you confirm.
  const { data: parent } = useQuery({ ...queries.secrets(coffre, { project, environment: from }), enabled: how === 'ref' });
  const copied = how === 'ref' && parent?.ok === true
    ? parent.keys.filter((key) => !key.archived && key.reference !== null && !key.reference.canOpenSource).map((key) => key.key)
    : [];
  const create = useChange(createEnvironment(coffre, project));
  const slugError = slug === '' ? null : environmentSlugProblem(slug);
  const reachedBy = reaching(useEveryProject(), slugError === null && slug !== '' ? slug : null);

  function close() {
    setOpen(false);
  }

  return (
    <>
      <button className="btn btn-primary" onClick={() => setOpen(true)}>
        <Plus size={14} />
        Add environment
      </button>

      <Modal
        open={open}
        onOpenChange={(next) => (next ? setOpen(true) : close())}
        title={
          <>
            New environment in <span className="mono">{project}</span>
          </>
        }
      >
        <form
          className="form"
          onSubmit={(event) => {
            event.preventDefault();
            // Listed at once, as saving; the list says if the server refuses.
            create({ slug, name: name.trim(), ...(from === '' ? {} : { from }), ...(how === 'ref' ? { references: true } : {}) });
            setSlug('');
            setName('');
            setStart('');
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
          <label className="field">
            <span className="label">Display name</span>
            <input
              className="input"
              placeholder="Staging"
              value={name}
              onChange={(event) => setName(event.target.value)}
            />
          </label>
          {sources.length > 0 && (
            <label className="field">
              <span className="label">Start from</span>
              <select className="select" value={start} onChange={(event) => setStart(event.target.value)}>
                <option value="">Empty</option>
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
                  : how === 'copy'
                    ? `Each of ${from}'s keys, with its current value and folder, without history.`
                    : `Each key follows ${from}'s until it gets a value of its own. Whoever can read ${slug === '' ? 'the new environment' : slug} will read ${from}'s values through them, even without access to ${from}.`}
              </span>
              {copied.length > 0 && (
                <span className="hint">
                  Copied instead, since you read their source only through {from}: <span className="mono">{copied.join(', ')}</span>.
                </span>
              )}
            </label>
          )}

          <ReachedBy grants={reachedBy} lead="As soon as it exists, it is reached by" />

          <div className="dialog-actions">
            <button className="btn" type="button" onClick={close}>
              Cancel
            </button>
            <button
              className="btn btn-primary"
              type="submit"
              disabled={slug === '' || slugError !== null || name.trim() === ''}
            >
              Add environment
            </button>
          </div>
        </form>
      </Modal>
    </>
  );
}
