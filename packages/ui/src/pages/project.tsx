import { useEffect, useState, type ReactNode } from 'react';
import { useQuery, useSuspenseQuery } from '@tanstack/react-query';
import { Link, useRouter } from '@tanstack/react-router';
import { useShell } from '../lib/use-shell';
import { Menu } from '@base-ui/react/menu';
import { toast } from 'sonner';
import { useCoffre } from '../lib/coffre';
import {
  archiveEnvironment,
  createEnvironment,
  environmentId,
  grantAccess,
  grantId,
  renameEnvironment,
} from '../lib/changes';
import { affects, keys, projectOf, queries } from '../lib/queries';
import { useChange, useChangeStatus } from '../lib/use-change';
import { ItemFailure, RowPending, rowClass } from '../components/row-state';
import { useAction } from '../lib/use-action';
import type { GrantRow, ProjectSummary } from '../shared/models';
import {
  hasEnvironmentDetails,
  type ProjectEnvironment,
} from '../lib/project-environments';
import { slugProblem } from '../lib/validation';
import {
  ConfirmDialog,
  EmptyState,
  ErrorLine,
  MenuPopup,
  Modal,
  Notice,
  Spinner,
  Timestamp,
} from '../components/ui';
import { Card, ClosedDoor, PageHeader } from '../components/page';
import { PageTabs, type TabItem } from '../components/tabs';
import { DeletePlaceDialog } from '../components/delete-place';
import { GrantRowView, GrantsTable, RefusedGrants, useRefusedGrants } from '../components/grants';
import { KIND } from '../components/directory';
import { PrincipalAvatar, PrincipalLink } from '../components/principal';
import { ReachedBy, reaching, useEveryProject } from '../components/every-project';
import { PrincipalPicker } from '../components/principal-picker';
import {
  parseProjectAccess,
  projectAccessOptions,
} from '../lib/project-access';
import {
  Archive,
  ChevronRight,
  Folder,
  Key,
  Layers,
  MoreHorizontal,
  Pencil,
  Plus,
  RotateBack,
  Settings,
  Trash,
  User,
  Users,
} from '../components/icons';
import { pageRoute } from '../lib/page-route';
import type { project } from '../options';

const Route = pageRoute<typeof project>();

export type ProjectTab = 'environments' | 'users' | 'tokens' | 'settings';

const TABS: TabItem<ProjectTab>[] = [
  { key: 'environments', label: 'Environments', icon: <Layers size={15} /> },
  { key: 'users', label: 'Users', icon: <Users size={15} /> },
  { key: 'tokens', label: 'Service accounts', icon: <Key size={15} /> },
  { key: 'settings', label: 'Settings', icon: <Settings size={15} /> },
];

export function ProjectPage() {
  const { project: projectSlug } = Route.useParams();
  const { data: projects } = useSuspenseQuery(queries.projects(useCoffre()));
  const result = projectOf(projects, projectSlug);

  if (!result.ok) {
    return (
      <ClosedDoor
        icon={<Folder size={18} />}
        label={<span className="mono">{projectSlug}</span>}
        title="No project here for you"
        actions={
          <Link className="btn" to="/projects">
            All projects
          </Link>
        }
      >
        {result.error ??
          'There is no such project, or you hold no grant on it. The two look the same on purpose: an answer that told them apart would let anyone list project names.'}
      </ClosedDoor>
    );
  }

  return result.managesAccess ? (
    <ManagedProject project={result.project} />
  ) : (
    <ProjectView project={result.project} grants={[]} grantsError={null} />
  );
}

/** A project whose access you manage, with its grants. */
function ManagedProject({ project }: { project: ProjectSummary }) {
  const { data: result } = useSuspenseQuery(queries.grants(useCoffre(), project.slug));
  return result.ok ? (
    <ProjectView project={project} grants={result.grants} grantsError={null} />
  ) : (
    <ProjectView project={project} grants={[]} grantsError={result.error} />
  );
}

function ProjectView({
  project,
  grants,
  grantsError,
}: {
  project: ProjectSummary;
  grants: GrantRow[];
  grantsError: string | null;
}) {
  const search = Route.useSearch();

  // Each tab is gated on its own permission, not on one blanket "admin".
  // That is what lets an access manager administer grants without being able
  // to rename the project, and vice versa.
  const canManageProject = project.permissions.includes('project.manage');
  const canManageEnvironments = project.permissions.includes('environment.manage');
  const canManageGrants = project.permissions.includes('grant.manage');
  const allowed = TABS.filter(
    ({ key }) =>
      key === 'environments' ||
      ((key === 'users' || key === 'tokens') && canManageGrants) ||
      (key === 'settings' && canManageProject),
  );
  // A tab you may not open falls back to the default rather than to an error:
  // a link someone shared still lands somewhere useful.
  const tab = allowed.find(({ key }) => key === search.tab)?.key ?? 'environments';
  const principalType = tab === 'users' ? 'user' : 'service';

  return (
    <>
      <PageHeader
        tile={project.slug}
        title={project.name}
        aside={<span className="page-title-slug">{project.slug}</span>}
      />

      {project.archivedAt !== null && (
        <div style={{ marginBottom: '1.25rem' }}>
          <Notice tone="bad">
            <strong>This project is archived.</strong> Its environments serve no reads, to
            people or to machines, until it is restored.
          </Notice>
        </div>
      )}

      <PageTabs
        label="Project sections"
        tabs={allowed}
        current={tab}
        link={(key, props) => (
          <Link
            to="/projects/$project"
            params={{ project: project.slug }}
            search={{ tab: key === 'environments' ? undefined : key }}
            // Without these, Environments (no parameter) counts as a
            // prefix of every other tab and stays highlighted on all of them.
            activeOptions={{ exact: true, explicitUndefined: true }}
            {...props}
          />
        )}
      />

      {tab === 'environments' && (
        <EnvironmentsPanel project={project} canManage={canManageEnvironments} grants={grants} />
      )}

      {(tab === 'users' || tab === 'tokens') &&
        (grantsError !== null ? (
          <Notice tone="bad">{grantsError}</Notice>
        ) : (
          <AccessPanel
            principalType={principalType}
            project={project.slug}
            environments={project.environments}
            grants={grants}
          />
        ))}

      {tab === 'settings' && (
        <>
          <GeneralSettings project={project} />
          <DangerZone project={project} />
        </>
      )}
    </>
  );
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
          <NewEnvironment project={project.slug} />
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
  const slugError = slug === '' ? null : slugProblem(slug);
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
                  This changes whether the environment serves secrets to principals who have
                  access. Values and history remain stored.
                </>
              ) : isArchived ? (
                <>
                  The environment starts serving its {secretCount} secret
                  {secretCount === 1 ? '' : 's'} again, to everyone who holds a grant on it.
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
            confirmLabel={isArchived ? 'Restore environment' : 'Archive environment'}
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
          onDeleted={() => toast.success(`${project}/${environment.slug} deleted, and its name is free`)}
        />
      )}

      <ItemFailure
        status={state}
        onDismiss={() => state.state === 'failed' && dismiss(state.mutationId)}
      />
    </div>
  );
}

function NewEnvironment({ project }: { project: string }) {
  const [open, setOpen] = useState(false);
  const [slug, setSlug] = useState('');
  const [name, setName] = useState('');
  const create = useChange(createEnvironment(useCoffre(), project));
  const slugError = slug === '' ? null : slugProblem(slug);
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
            create({ slug, name: name.trim() });
            setSlug('');
            setName('');
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

/** One kind's grants on the project, and below them the way to add one. */
function AccessPanel({
  principalType,
  project,
  environments,
  grants: all,
}: {
  principalType: 'user' | 'service';
  project: string;
  environments: ProjectSummary['environments'];
  /** Every grant on the project: the picker shows what each candidate already holds. */
  grants: GrantRow[];
}) {
  const people = principalType === 'user';
  const kind = KIND[principalType];
  const grants = all.filter((grant) => grant.principalType === principalType);
  const refused = useRefusedGrants(project, grants, principalType);
  return (
    <>
      <section className="card" aria-label={people ? 'Users with access' : 'Service accounts with access'}>
        {grants.length === 0 && refused.length === 0 ? (
          <EmptyState title={`No ${kind} has access`}>
            Add a {kind} with permissions on the whole project or on one environment.
          </EmptyState>
        ) : (
          <GrantsTable
            lead={
              <span className="th">
                {people ? <User size={14} /> : <Key size={14} />}
                {people ? 'Email' : 'Name'}
              </span>
            }
          >
            {grants.map((grant, index) => (
              <GrantRowView
                key={grantId(grant)}
                number={index + 1}
                project={project}
                grant={grant}
                leadLabel={people ? 'Email' : 'Name'}
                lead={<PrincipalLink type={grant.principalType} id={grant.principalId} />}
              />
            ))}
            <RefusedGrants refused={refused} />
          </GrantsTable>
        )}
      </section>
      <div className="table-actions">
        <NewGrant
          principalType={principalType}
          project={project}
          environments={environments}
          grants={all}
        />
      </div>
    </>
  );
}

function NewGrant({
  principalType,
  project,
  environments,
  grants,
}: {
  principalType: 'user' | 'service';
  project: string;
  environments: ProjectSummary['environments'];
  grants: GrantRow[];
}) {
  const { capabilities } = useShell();
  const [open, setOpen] = useState(false);
  const [principalId, setPrincipalId] = useState('');
  const [permission, setPermission] = useState('viewer:');
  const [expiresAt, setExpiresAt] = useState('');
  const grant = useChange(grantAccess(useCoffre(), project));
  const permissionOptions = projectAccessOptions(environments);
  const kind = KIND[principalType];

  function close() {
    setOpen(false);
  }

  return (
    <>
      <button className="btn btn-primary" onClick={() => setOpen(true)}>
        <Plus size={14} />
        Add {kind}
      </button>

      <Modal
        open={open}
        onOpenChange={(next) => (next ? setOpen(true) : close())}
        title={
          <>
            Give a {kind} access to <span className="mono">{project}</span>
          </>
        }
        wide
        description="Owners manage the whole project and its access. Read and write can cover every environment, or one."
      >
        <form
          className="form"
          onSubmit={(event) => {
            event.preventDefault();
            const access = parseProjectAccess(permission);
            // Shown in the list at once, marked as saving; the list says if the server refuses.
            grant({
              principalType,
              principalId: principalId.trim(),
              role: access.role,
              roleName: permissionOptions.find((option) => option.value === permission)?.label ?? access.role,
              environmentSlug: access.environmentSlug,
              expiresAt: expiresAt === '' ? null : new Date(`${expiresAt}T23:59:59Z`).toISOString(),
            });
            setPrincipalId('');
            setExpiresAt('');
            setPermission('viewer:');
            close();
          }}
        >
          <PrincipalPicker
            principalType={principalType}
            canList={capabilities.canManageGrants}
            grants={grants}
            value={principalId}
            onChange={setPrincipalId}
          />

          <div className="form-row">
            <label className="field" style={{ flexGrow: 2 }}>
              <span className="label">Permissions</span>
              <select
                className="select"
                value={permission}
                onChange={(event) => setPermission(event.target.value)}
              >
                {permissionOptions.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>

            <label className="field">
              <span className="label">
                Expires <span className="hint">(optional)</span>
              </span>
              <input
                className="input"
                type="date"
                value={expiresAt}
                onChange={(event) => setExpiresAt(event.target.value)}
              />
            </label>
          </div>

          <div className="dialog-actions">
            <button className="btn" type="button" onClick={close}>
              Cancel
            </button>
            <button className="btn btn-primary" type="submit" disabled={principalId.trim() === ''}>
              Grant access
            </button>
          </div>
        </form>
      </Modal>
    </>
  );
}

/**
 * The project's name and slug, as a form on the page.
 *
 * Renaming changes paths other people and scripts use, so it is laid out in
 * plain sight with what it does and does not affect, rather than tucked
 * behind a menu.
 */
function GeneralSettings({ project }: { project: ProjectSummary }) {
  const router = useRouter();
  const [slug, setSlug] = useState(project.slug);
  const [name, setName] = useState(project.name);
  const coffre = useCoffre();
  const { pending, error, run } = useAction();
  const slugError = slug === '' ? null : slugProblem(slug);
  const dirty = slug !== project.slug || name.trim() !== project.name;

  // Follow a rename made elsewhere (another tab, another person) rather than
  // keep offering the old values back.
  useEffect(() => {
    setSlug(project.slug);
    setName(project.name);
  }, [project.slug, project.name]);

  // Two fields and their Save need no card: the tab already says what they are.
  return (
    <section className="plain-form" aria-label="General">
      <form
        onSubmit={(event) => {
          event.preventDefault();
          run(
            () => coffre.projects.update(project.slug, { slug, name }),
            {
              affects: affects.places(),
              onSuccess: async () => {
                toast.success('Project renamed');
                // The slug is part of the URL, so a rename has to navigate.
                if (slug !== project.slug) {
                  await router.navigate({
                    to: '/projects/$project',
                    params: { project: slug },
                    search: { tab: 'settings' },
                  });
                }
              },
            },
          );
        }}
      >
        <div className="form-row">
          <label className="field">
            <span className="label">Slug</span>
            <input
              className="input input-mono"
              spellCheck={false}
              value={slug}
              aria-invalid={slugError !== null}
              onChange={(event) => setSlug(event.target.value)}
            />
            <span className={`hint${slugError !== null ? ' edit-note-error' : ''}`}>
              {slugError ?? 'Scripts that name the old slug will need the new one.'}
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
        </div>
        <div className="form-actions">
          <button
            className="btn btn-primary"
            type="submit"
            disabled={!dirty || pending || slug === '' || slugError !== null || name.trim() === ''}
          >
            {pending && <Spinner />}
            Save
          </button>
          {error !== null && (
            <span className="hint">
              <ErrorLine error={error} />
            </span>
          )}
        </div>
      </form>
    </section>
  );
}

function DangerZone({ project }: { project: ProjectSummary }) {
  const [confirming, setConfirming] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const coffre = useCoffre();
  const router = useRouter();
  const { instanceRole } = useShell();
  const { pending, error, run } = useAction();
  const isArchived = project.archivedAt !== null;
  // Deleting is for instance owners, and only once the project is archived.
  const canDelete = isArchived && instanceRole !== 'user';

  return (
    <Card labelledBy="danger-zone" title="Danger zone" tone="danger">
      <div className="card-row">
        <div>
          <p className="card-row-title">{isArchived ? 'Restore project' : 'Archive project'}</p>
          {/* Restoring needs no warning: the button says what it does. */}
          {!isArchived && (
            <p className="card-row-desc">Stops every read until restored; nothing is deleted.</p>
          )}
          {error !== null && (
            <div style={{ marginTop: '0.5rem' }}>
              <ErrorLine error={error} />
            </div>
          )}
        </div>
        <button
          className={`btn ${isArchived ? '' : 'btn-danger-outline'}`}
          onClick={() => setConfirming(true)}
          disabled={pending}
        >
          {pending ? (
            <Spinner />
          ) : isArchived ? (
            <RotateBack size={14} />
          ) : (
            <Archive size={14} />
          )}
          {isArchived ? `Restore ${project.name}` : `Archive ${project.name}…`}
        </button>
      </div>

      {canDelete && (
        <div className="card-row">
          <div>
            <p className="card-row-title">Delete project</p>
            <p className="card-row-desc">
              Erases its values for good and frees its name; only names stay, for the audit log.
            </p>
          </div>
          <button className="btn btn-danger-outline" onClick={() => setDeleting(true)}>
            <Trash size={14} />
            {`Delete ${project.name}…`}
          </button>
        </div>
      )}
      {canDelete && (
        <DeletePlaceDialog
          path={project.slug}
          open={deleting}
          onOpenChange={setDeleting}
          onDeleted={async () => {
            toast.success(`${project.slug} deleted, and its name is free`);
            await router.navigate({ to: '/projects' });
          }}
        />
      )}

      <ConfirmDialog
        open={confirming}
        onOpenChange={setConfirming}
        title={
          <>
            {isArchived ? 'Restore' : 'Archive'} <span className="mono">{project.slug}</span>?
          </>
        }
        body={
          isArchived ? (
            <>
              The project reappears in listings and its environments start serving reads
              again, for everyone who holds a grant on it.
            </>
          ) : (
            <>
              Every environment in <span className="mono">{project.slug}</span> stops serving
              reads, including to machine callers already running. Nothing is deleted: values,
              versions and the audit trail over them stay intact, and you can restore it here
              at any time.
            </>
          )
        }
        confirmLabel={isArchived ? `Restore ${project.name}` : `Archive ${project.name}`}
        destructive={!isArchived}
        onConfirm={() =>
          run(
            () =>
              coffre.projects.update(project.slug, { archived: !isArchived }),
            {
              affects: affects.places(),
              onSuccess: () =>
                toast.success(
                  isArchived ? `${project.slug} restored` : `${project.slug} archived`,
                ),
            },
          )
        }
      />
    </Card>
  );
}
