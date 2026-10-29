import { useState } from 'react';
import type { PersonalConfig } from '@coffre/client';
import { useQuery, useSuspenseQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useShell } from '../lib/use-shell';
import { Menu } from '@base-ui/react/menu';
import { toast } from 'sonner';
import { useCoffre } from '../lib/coffre';
import { environmentId } from '../lib/changes';
import { affects, keys, queries } from '../lib/queries';
import { useChangeStatus } from '../lib/use-change';
import { ItemFailure, RowPending, rowClass } from '../components/row-state';
import type { GrantRow, ProjectSummary } from '../shared/models';
import { ArchiveEnvironment, NewEnvironment, RenameEnvironment } from '../components/environment-actions';
import { hasEnvironmentDetails, type ProjectEnvironment } from '../lib/project-environments';
import { ConfirmDialog, EmptyState, ErrorLine, MenuPopup, Timestamp } from '../components/ui';
import { Card } from '../components/page';
import { useAction } from '../lib/use-action';
import { DeletePlaceDialog } from '../components/delete-place';
import { PrincipalAvatar } from '../components/principal';
import { Archive, ChevronRight, MoreHorizontal, Pencil, Plus, RotateBack, Trash } from '../components/icons';
import { Protection } from '../components/protected';
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
  const refused = failedAdds<{ slug: string }>(
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
                  <span className="env-card-name">{vars.slug}</span>
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
          <AddEnvironment project={project.slug} />
        </div>
      )}

      {canManage && <PersonalConfigs project={project.slug} />}

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
  const { capabilities } = useShell();
  const { status, dismiss } = useChangeStatus(keys.projects);
  const state = status(environmentId(project, environment.slug));
  const pending = state.state === 'pending';
  const details = environment.details;
  const isArchived = details !== null && details.archivedAt !== null;
  const secretCount = details?.secretCount ?? null;
  const opens = details !== null && !isArchived && environment.accessible && !pending;
  const manageable = isAdmin && details !== null;
  // Deleting is for those who run the instance, and only once the environment is archived.
  const deletable = manageable && isArchived && capabilities.runsInstance;
  const lastChange = useLastChange(project, environment.slug, opens);
  // A personal config is its owner's alone: no grant reaches it, so none is shown on its card.
  const holders = environment.personal === true ? [] : holdersOf(grants, environment.slug);

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
              {environment.slug}
            </Link>
          ) : (
            <span className="env-card-name">{environment.slug}</span>
          )}
          <Protection project={project} environment={environment} />
          {/* A fork: its keys are its parent's, but for those it sets or removes. An instance before 0.7 says nothing. */}
          {environment.personal === true
            ? <span className="tag tag-blue">yours alone</span>
            : environment.parent != null && <span className="tag tag-outline">inherits {environment.parent}</span>}
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

      {/* Your personal config is deleted from its own page; it is no environment of the team's to rename or archive. */}
      {manageable && !pending && environment.personal !== true && (
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
              onClick={() => setRenaming(true)}
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
          <RenameEnvironment project={project} environment={environment.slug} open={renaming} onOpenChange={setRenaming} />
          <ArchiveEnvironment project={project} environment={environment} open={confirming} onOpenChange={setConfirming} />
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
 * The project's personal configs, `dev@me` (docs/design/forking.md), for
 * whoever manages its environments: that they exist, whose, of what, and
 * their key names, never a value, which only their owners read. Delete is
 * how offboarding cleans one up: its values are erased.
 */
function PersonalConfigs({ project }: { project: string }) {
  const coffre = useCoffre();
  const { data } = useQuery(queries.personal(coffre, project));
  const [deleting, setDeleting] = useState<PersonalConfig | null>(null);
  const { error, run } = useAction();
  if (data === undefined || !data.ok || data.configs.length === 0) return null;
  return (
    <Card
      labelledBy="personal-configs"
      title="Personal configs"
      description="Members' own forks of an environment, its keys and their values over it. Only their owner reads the values; you see whose they are and their key names."
    >
      {error !== null && <ErrorLine error={error} />}
      {data.configs.map((config) => (
        <div className="card-row" key={config.slug}>
          <div>
            <p className="card-row-title">
              <span className="mono">{config.of}</span> · {config.owner.replace(/^user:/, '')}
              {config.archived && <span className="tag tag-outline">archived</span>}
            </p>
            <p className="card-row-desc mono">{config.keys.length === 0 ? 'no keys of its own' : config.keys.join(', ')}</p>
          </div>
          <button type="button" className="btn btn-sm" onClick={() => setDeleting(config)}>
            <Trash size={14} />
            Delete…
          </button>
        </div>
      ))}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={<>Delete {deleting?.owner.replace(/^user:/, '')}'s <span className="mono">{deleting?.of}</span>?</>}
        body={`Its ${deleting?.keys.length ?? 0} ${deleting?.keys.length === 1 ? 'value is' : 'values are'} erased for good; ${project}/${deleting?.of} itself is untouched.`}
        confirmLabel="Delete"
        onConfirm={() => {
          const doomed = deleting!;
          void run(() => coffre.environments.delete(`${project}/${doomed.slug}`), {
            // The list, and the owner's own `dev@me` when it is theirs: its card and its keys go.
            affects: [...affects.places(), ...affects.secrets({ project, environment: `${doomed.of}@me` })],
            onSuccess: () => toast.success(`Deleted ${doomed.owner.replace(/^user:/, '')}'s ${doomed.of}`),
          });
        }}
      />
    </Card>
  );
}

/** Add environment, and the dialog it opens. */
function AddEnvironment({ project }: { project: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button className="btn btn-primary" onClick={() => setOpen(true)}>
        <Plus size={14} />
        Add environment
      </button>
      <NewEnvironment project={project} open={open} onOpenChange={setOpen} />
    </>
  );
}
