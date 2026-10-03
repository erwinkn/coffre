import { useEffect, useState, type ReactNode } from 'react';
import { useSuspenseQuery } from '@tanstack/react-query';
import { createFileRoute, Link, useRouter } from '@tanstack/react-router';
import { useShell } from '../lib/use-shell';
import { DropdownMenu } from 'radix-ui';
import { toast } from 'sonner';
import { memberRef, Refusal, useCoffre } from '../lib/coffre';
import { affects, loadProject, projectOf, queries } from '../lib/queries';
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
  Modal,
  Notice,
  Spinner,
} from '../components/ui';
import { Card, ClosedDoor, PageHeader } from '../components/page';
import { ensureGrant, GrantRowView, GrantsTable } from '../components/grants';
import { PrincipalLink } from '../components/principal';
import { PrincipalPicker } from '../components/principal-picker';
import {
  parseProjectAccess,
  projectAccessOptions,
} from '../lib/project-access';
import {
  Archive,
  Folder,
  Key,
  Layers,
  MoreHorizontal,
  Pencil,
  Plus,
  RotateBack,
  Settings,
  User,
  Users,
} from '../components/icons';

type ProjectTab = 'environments' | 'users' | 'tokens' | 'settings';

export const Route = createFileRoute('/projects/$project/')({
  // The tab lives in the URL so a link can land on a project's access list.
  // Environments is the default and so has no parameter.
  validateSearch: (search: Record<string, unknown>): { tab?: Exclude<ProjectTab, 'environments'> } => ({
    tab:
      search.tab === 'users' || search.tab === 'tokens' || search.tab === 'settings'
        ? search.tab
        : undefined,
  }),
  loader: ({ context: { client, queryClient }, params }) => loadProject(queryClient, client, params.project),
  component: ProjectPage,
});

const TABS: { key: ProjectTab; label: string; icon: ReactNode }[] = [
  { key: 'environments', label: 'Environments', icon: <Layers size={15} /> },
  { key: 'users', label: 'Users', icon: <Users size={15} /> },
  { key: 'tokens', label: 'Tokens', icon: <Key size={15} /> },
  { key: 'settings', label: 'Settings', icon: <Settings size={15} /> },
];

function ProjectPage() {
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
        actions={
          tab === 'environments'
            ? canManageEnvironments && <NewEnvironment project={project.slug} />
            : (tab === 'users' || tab === 'tokens') &&
              grantsError === null && (
                <NewGrant
                  principalType={principalType}
                  project={project.slug}
                  environments={project.environments}
                  grants={grants}
                />
              )
        }
      />

      {project.archivedAt !== null && (
        <div style={{ marginBottom: '1.25rem' }}>
          <Notice tone="bad">
            <strong>This project is archived.</strong> Its environments serve no reads, to
            people or to machines, until it is restored.
          </Notice>
        </div>
      )}

      {/* One tab is no choice at all, so a reader-only project shows none. */}
      {allowed.length > 1 && (
        <nav className="tabs" aria-label="Project sections">
          {allowed.map(({ key, label, icon }) => (
            <Link
              key={key}
              to="/projects/$project"
              params={{ project: project.slug }}
              search={{ tab: key === 'environments' ? undefined : key }}
              // Without these, Environments (no parameter) counts as a
              // prefix of every other tab and stays highlighted on all of them.
              activeOptions={{ exact: true, explicitUndefined: true }}
              aria-current={key === tab ? 'page' : undefined}
            >
              {icon}
              {label}
            </Link>
          ))}
        </nav>
      )}

      {tab === 'environments' && (
        <EnvironmentsPanel project={project} canManage={canManageEnvironments} />
      )}

      {(tab === 'users' || tab === 'tokens') &&
        (grantsError !== null ? (
          <Notice tone="bad">{grantsError}</Notice>
        ) : (
          <AccessPanel
            principalType={principalType}
            project={project.slug}
            grants={grants.filter((grant) => grant.principalType === principalType)}
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
}: {
  project: ProjectSummary;
  canManage: boolean;
}) {
  const detailed = project.environments.filter(hasEnvironmentDetails);
  const archived = detailed.filter((environment) => environment.details.archivedAt !== null);
  // Environments you may know by name only sit with the active ones: no grant
  // you hold covers their contents, so they are muted and do not open.
  const current = project.environments.filter(
    (environment) => environment.details === null || environment.details.archivedAt === null,
  );

  return (
    <>
      {current.length === 0 ? (
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
              />
            </li>
          ))}
        </ul>
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
function EnvironmentCard({
  project,
  environment,
  isAdmin,
}: {
  project: string;
  environment: ProjectEnvironment;
  isAdmin: boolean;
}) {
  const [renaming, setRenaming] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [slug, setSlug] = useState(environment.slug);
  const [name, setName] = useState(environment.name);
  const coffre = useCoffre();
  const { pending, error, setError, run } = useAction();
  const details = environment.details;
  const isArchived = details !== null && details.archivedAt !== null;
  const secretCount = details?.secretCount ?? null;
  const opens = details !== null && !isArchived && environment.accessible;
  const manageable = isAdmin && details !== null;
  const slugError = slug === '' ? null : slugProblem(slug);

  useEffect(() => {
    if (error !== null && !renaming) toast.error(error);
  }, [error, renaming]);

  return (
    <div className={`env-card${opens ? ' is-link' : ' is-muted'}`}>
      <div className="env-card-text">
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
        <span className="env-card-meta">
          <span className="mono">{environment.slug}</span>
          {isArchived ? (
            <span className="tag tag-red">archived</span>
          ) : !environment.accessible ? (
            <span className="tag tag-outline">no secret access</span>
          ) : (
            secretCount !== null && (
              <span>
                {secretCount} secret{secretCount === 1 ? '' : 's'}
              </span>
            )
          )}
        </span>
      </div>

      {manageable && (
        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild>
            <button
              className="act act-quiet env-card-menu"
              aria-label={`Actions for ${environment.slug}`}
              disabled={pending}
            >
              {pending ? <Spinner size={14} /> : <MoreHorizontal size={16} />}
            </button>
          </DropdownMenu.Trigger>
          <DropdownMenu.Portal>
            <DropdownMenu.Content className="menu" sideOffset={6} align="end">
              <DropdownMenu.Item
                className="menu-item"
                onSelect={() => {
                  setSlug(environment.slug);
                  setName(environment.name);
                  setRenaming(true);
                }}
              >
                <Pencil size={14} />
                Rename
              </DropdownMenu.Item>
              <DropdownMenu.Separator className="menu-sep" />
              <DropdownMenu.Item
                className={`menu-item${isArchived ? '' : ' menu-item-danger'}`}
                onSelect={() => setConfirming(true)}
              >
                {isArchived ? <RotateBack size={14} /> : <Archive size={14} />}
                {isArchived ? 'Restore' : 'Archive…'}
              </DropdownMenu.Item>
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>
      )}

      {manageable && (
        <>
          <Modal
            open={renaming}
            onOpenChange={(open) => {
              setRenaming(open);
              if (!open) setError(null);
            }}
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
                run(
                  () =>
                    coffre.environments.update(`${project}/${environment.slug}`, { slug, name }),
                  {
                    affects: affects.places(),
                    onSuccess: () => {
                      setRenaming(false);
                      toast.success('Environment renamed');
                    },
                  },
                );
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

              <ErrorLine error={error} />

              <div className="dialog-actions">
                <button className="btn" type="button" onClick={() => setRenaming(false)}>
                  Cancel
                </button>
                <button
                  className="btn btn-primary"
                  type="submit"
                  disabled={pending || slug === '' || slugError !== null || name.trim() === ''}
                >
                  {pending && <Spinner />}
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
            onConfirm={() =>
              run(
                () =>
                  coffre.environments.update(`${project}/${environment.slug}`, { archived: !isArchived }),
                {
                  affects: affects.places(),
                  onSuccess: () =>
                    toast.success(
                      isArchived ? `${environment.slug} restored` : `${environment.slug} archived`,
                    ),
                },
              )
            }
          />
        </>
      )}
    </div>
  );
}

function NewEnvironment({ project }: { project: string }) {
  const [open, setOpen] = useState(false);
  const [slug, setSlug] = useState('');
  const [name, setName] = useState('');
  const coffre = useCoffre();
  const { pending, error, setError, run } = useAction();
  const slugError = slug === '' ? null : slugProblem(slug);

  function close() {
    setOpen(false);
    setError(null);
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
            run(
              async () => {
                const { created } = await coffre.environments.create(`${project}/${slug}`, { name });
                if (!created) throw new Refusal(`An environment named "${slug}" already exists.`);
              },
              {
                affects: affects.places(),
                onSuccess: () => {
                  toast.success(`Environment ${slug} added`);
                  setSlug('');
                  setName('');
                  close();
                },
              },
            );
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

          <ErrorLine error={error} />

          <div className="dialog-actions">
            <button className="btn" type="button" onClick={close}>
              Cancel
            </button>
            <button
              className="btn btn-primary"
              type="submit"
              disabled={pending || slug === '' || slugError !== null || name.trim() === ''}
            >
              {pending && <Spinner />}
              Add environment
            </button>
          </div>
        </form>
      </Modal>
    </>
  );
}

function AccessPanel({
  principalType,
  project,
  grants,
}: {
  principalType: 'user' | 'service';
  project: string;
  grants: GrantRow[];
}) {
  const people = principalType === 'user';
  return (
    <section className="card" aria-label={people ? 'Users with access' : 'Tokens with access'}>
      {grants.length === 0 ? (
        <EmptyState title={people ? 'No user has access' : 'No token has access'}>
          Add {people ? 'a user' : 'a token'} with permissions on the whole project or on one
          environment.
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
              key={grant.id}
              number={index + 1}
              project={project}
              grant={grant}
              leadLabel={people ? 'Email' : 'Name'}
              lead={<PrincipalLink type={grant.principalType} id={grant.principalId} />}
            />
          ))}
        </GrantsTable>
      )}
    </section>
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
  const coffre = useCoffre();
  const { pending, error, setError, run } = useAction();
  const permissionOptions = projectAccessOptions(environments);
  const kind = principalType === 'user' ? 'user' : 'token';

  function close() {
    setOpen(false);
    setError(null);
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
            run(
              () =>
                ensureGrant(coffre, {
                  project,
                  principalType,
                  principalId: principalId.trim(),
                  role: access.role,
                  environmentSlug: access.environmentSlug,
                  expiresAt:
                    expiresAt === '' ? null : new Date(`${expiresAt}T23:59:59Z`).toISOString(),
                }),
              {
                affects: affects.access(project, memberRef(principalType, principalId.trim())),
                onSuccess: ({ existed }) => {
                  const label =
                    permissionOptions.find((option) => option.value === permission)?.label ??
                    'access';
                  toast.success(
                    existed
                      ? `${principalId} already has ${label}`
                      : `${principalId} granted ${label.toLowerCase()}`,
                  );
                  setPrincipalId('');
                  setExpiresAt('');
                  setPermission('viewer:');
                  close();
                },
              },
            );
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

          <ErrorLine error={error} />

          <div className="dialog-actions">
            <button className="btn" type="button" onClick={close}>
              Cancel
            </button>
            <button
              className="btn btn-primary"
              type="submit"
              disabled={pending || principalId.trim() === ''}
            >
              {pending && <Spinner />}
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

  return (
    <section className="card" aria-labelledby="general-settings">
      <div className="card-head">
        <div>
          <h2 className="card-title" id="general-settings">
            General
          </h2>
        </div>
      </div>
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
        <div className="card-body form-row">
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
        <div className="card-foot">
          {error !== null && (
            <span className="hint">
              <ErrorLine error={error} />
            </span>
          )}
          <button
            className="btn btn-primary"
            type="submit"
            disabled={!dirty || pending || slug === '' || slugError !== null || name.trim() === ''}
          >
            {pending && <Spinner />}
            Save
          </button>
        </div>
      </form>
    </section>
  );
}

function DangerZone({ project }: { project: ProjectSummary }) {
  const [confirming, setConfirming] = useState(false);
  const coffre = useCoffre();
  const { pending, error, run } = useAction();
  const isArchived = project.archivedAt !== null;

  return (
    <Card labelledBy="danger-zone" title="Danger zone" tone="danger">
      <div className="card-row">
        <div>
          <p className="card-row-title">{isArchived ? 'Restore project' : 'Archive project'}</p>
          <p className="card-row-desc">
            {isArchived
              ? 'The project reappears in listings and its environments serve reads again, for everyone who holds a grant on it.'
              : 'Every environment stops serving reads, including to machine callers already running. Nothing is deleted, and you can restore it here at any time.'}
          </p>
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
          {isArchived ? 'Restore project' : 'Archive project…'}
        </button>
      </div>

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
        confirmLabel={isArchived ? 'Restore project' : 'Archive project'}
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
