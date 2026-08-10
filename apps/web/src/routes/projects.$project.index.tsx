import { useEffect, useState } from 'react';
import { createFileRoute, Link, useRouter } from '@tanstack/react-router';
import { DropdownMenu } from 'radix-ui';
import { toast } from 'sonner';
import {
  createEnvironment,
  getProject,
  setEnvironmentArchived,
  setProjectArchived,
  updateEnvironment,
  updateProject,
} from '../server-functions/projects';
import {
  createGrant,
  revokeGrant,
} from '../server-functions/access';
import { useAction } from '../lib/use-action';
import type { GrantRow, ProjectSummary } from '../shared/models';
import {
  hasEnvironmentDetails,
  type DetailedProjectEnvironment,
} from '../lib/project-environments';
import {
  ConfirmButton,
  ConfirmDialog,
  EmptyState,
  ErrorLine,
  Modal,
  Notice,
  Spinner,
} from '../components/ui';
import { PermissionSummary } from '../components/permissions';
import {
  parseProjectAccess,
  projectAccessLabel,
  projectAccessOptions,
} from '../lib/project-access';
import {
  Archive,
  Key,
  Layers,
  MoreHorizontal,
  Pencil,
  Plus,
  Settings,
  Users,
  X,
} from '../components/icons';

export const Route = createFileRoute('/projects/$project/')({
  loader: ({ params }) => getProject({ data: { project: params.project } }),
  component: ProjectPage,
});

function ProjectPage() {
  const result = Route.useLoaderData();
  const { project: projectSlug } = Route.useParams();

  if (!result.ok) {
    return (
      <>
        <div className="page-head">
          <h1 className="mono">{projectSlug}</h1>
        </div>
        <Notice tone="bad">
          {result.error ??
            'No such project, or you hold no grant on it. Those two cases look identical on purpose: an error that distinguished them would let anyone enumerate project names.'}
        </Notice>
        <p style={{ marginTop: 'var(--space-5)' }}>
          <Link to="/projects">Back to projects</Link>
        </p>
      </>
    );
  }

  const { project, grants, grantsError } = result;

  // Each section is gated on its own permission, not on one blanket "admin".
  // That is what lets an access manager administer grants without being able
  // to rename the project, and vice versa.
  const canManageProject = project.permissions.includes('project.manage');
  const canManageEnvironments = project.permissions.includes('environment.manage');
  const canManageGrants = project.permissions.includes('grant.manage');

  const detailed = project.environments.filter(hasEnvironmentDetails);
  const active = detailed.filter((environment) => environment.details.archivedAt === null);
  const archived = detailed.filter((environment) => environment.details.archivedAt !== null);
  const listedOnly = project.environments.filter((environment) => environment.details === null);

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="mono">
            {project.slug}
            {project.archivedAt !== null && (
              <span className="pill pill-deny" style={{ marginLeft: 'var(--space-3)' }}>
                archived
              </span>
            )}
          </h1>
          <p className="sub">{project.name}</p>
        </div>
        <div className="cluster">
          <PermissionSummary permissions={project.permissions} />
          {canManageProject && <ProjectSettings project={project} />}
        </div>
      </div>

      <section className="section">
        <div className="section-head">
          <h2>Environments</h2>
          {canManageEnvironments && <NewEnvironment project={project.slug} />}
        </div>

        <div className="card">
          {active.length === 0 ? (
            <EmptyState icon={<Layers size={26} />} title="No environments yet">
              {listedOnly.length > 0
                ? 'You can see the other environment names below, but you do not have access to their metadata.'
                : canManageEnvironments
                ? 'Add the first one above. Secrets live in environments, not in the project itself, and a grant can be scoped to exactly one of them.'
                : 'Nothing to show. Creating environments needs environment.manage on this project.'}
            </EmptyState>
          ) : (
            active.map((environment) => (
              <EnvironmentRow
                key={`${project.slug}:${environment.slug}`}
                project={project.slug}
                environment={environment}
                isAdmin={canManageEnvironments}
              />
            ))
          )}
        </div>
      </section>

      {listedOnly.length > 0 && (
        <section className="section">
          <div className="section-head">
            <h2>Other environments</h2>
          </div>
          <div className="card">
            {listedOnly.map((environment) => (
              <div className="row" key={environment.slug}>
                <div className="row-title">
                  <Layers size={15} style={{ color: 'var(--ink-3)', flex: 'none' }} />
                  <span className="row-key">{environment.slug}</span>
                  <span className="meta">{environment.name}</span>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {archived.length > 0 && (
        <section className="section">
          <div className="section-head">
            <h2>Archived environments</h2>
          </div>
          <div className="card">
            {archived.map((environment) => (
              <EnvironmentRow
                key={environment.slug}
                project={project.slug}
                environment={environment}
                isAdmin={canManageEnvironments}
              />
            ))}
          </div>
        </section>
      )}

      {canManageGrants && (
        <Grants
          project={project.slug}
          environments={project.environments}
          grants={grants}
          error={grantsError}
        />
      )}
    </>
  );
}

/**
 * Rename and archive, behind the gear in the page head.
 *
 * These settings change rarely, so they stay behind the page-head action.
 */
function ProjectSettings({ project }: { project: ProjectSummary }) {
  const router = useRouter();
  const [renaming, setRenaming] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [slug, setSlug] = useState(project.slug);
  const [name, setName] = useState(project.name);
  const { pending, error, setError, run } = useAction();
  const isArchived = project.archivedAt !== null;

  // Renaming prints its error inside the modal. Archiving has no surface of
  // its own now that the settings card is gone, so it says so in a toast --
  // otherwise a failed archive would look like nothing happening at all.
  useEffect(() => {
    if (error !== null && !renaming) toast.error(error);
  }, [error, renaming]);

  return (
    <>
      <DropdownMenu.Root>
        <DropdownMenu.Trigger asChild>
          <button
            className="btn btn-icon btn-head-action"
            aria-label={`Settings for ${project.slug}`}
            disabled={pending}
          >
            <Settings size={16} />
          </button>
        </DropdownMenu.Trigger>
        <DropdownMenu.Portal>
          <DropdownMenu.Content className="menu" sideOffset={6} align="end">
            <DropdownMenu.Item
              className="menu-item"
              onSelect={() => {
                setSlug(project.slug);
                setName(project.name);
                setRenaming(true);
              }}
            >
              <Pencil size={14} />
              Rename project
            </DropdownMenu.Item>
            <DropdownMenu.Separator className="menu-sep" />
            <DropdownMenu.Item
              className={`menu-item${isArchived ? '' : ' menu-item-danger'}`}
              onSelect={() => setConfirming(true)}
            >
              <Archive size={14} />
              {isArchived ? 'Restore project' : 'Archive project'}
            </DropdownMenu.Item>
          </DropdownMenu.Content>
        </DropdownMenu.Portal>
      </DropdownMenu.Root>

      <Modal
        open={renaming}
        // Clearing on close keeps a failed rename from re-surfacing as a toast
        // the moment the modal that already showed it goes away.
        onOpenChange={(open) => {
          setRenaming(open);
          if (!open) setError(null);
        }}
        title={`Rename ${project.slug}`}
      >
        <form
          className="dialog-form stack"
          onSubmit={(event) => {
            event.preventDefault();
            run(
              () => updateProject({ data: { project: project.slug, slug, name } }),
              async () => {
                setRenaming(false);
                toast.success('Project renamed');
                // The slug is part of the URL, so a rename has to navigate.
                if (slug !== project.slug) {
                  await router.navigate({ to: '/projects/$project', params: { project: slug } });
                }
              },
            );
          }}
        >
          <label className="field">
            <span className="label">Slug</span>
            <input
              className="input"
              autoFocus
              value={slug}
              onChange={(event) => setSlug(event.target.value)}
            />
          </label>
          <label className="field">
            <span className="label">Display name</span>
            <input
              className="input"
              value={name}
              onChange={(event) => setName(event.target.value)}
            />
          </label>

          <p className="meta">
            Renaming the slug is safe. Ciphertext is bound to immutable ids, never to names,
            so nothing needs re-encrypting and no history is orphaned.
          </p>

          <ErrorLine error={error} />

          <div className="dialog-actions">
            <button className="btn" type="button" onClick={() => setRenaming(false)}>
              Cancel
            </button>
            <button
              className="btn btn-primary"
              type="submit"
              disabled={pending || slug === '' || name === ''}
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
        title={isArchived ? `Restore ${project.slug}?` : `Archive ${project.slug}?`}
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
              setProjectArchived({
                data: { project: project.slug, archived: !isArchived },
              }),
            () =>
              toast.success(
                isArchived ? `${project.slug} restored` : `${project.slug} archived`,
              ),
          )
        }
      />
    </>
  );
}

function EnvironmentRow({
  project,
  environment,
  isAdmin,
}: {
  project: string;
  environment: DetailedProjectEnvironment;
  isAdmin: boolean;
}) {
  const [editing, setEditing] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [slug, setSlug] = useState(environment.slug);
  const [name, setName] = useState(environment.name);
  const { pending, error, run } = useAction();
  const isArchived = environment.details.archivedAt !== null;
  const secretCount = environment.details.secretCount;

  return (
    <div className="row-group">
      <div className="row row-interactive">
        <div className="row-title">
          <Layers size={15} style={{ color: 'var(--ink-3)', flex: 'none' }} />
          {isArchived || !environment.accessible ? (
            <span className="row-key">{environment.slug}</span>
          ) : (
            <Link
              className="row-key row-stretch-link"
              to="/projects/$project/$environment"
              params={{ project, environment: environment.slug }}
            >
              {environment.slug}
            </Link>
          )}
          <span className="meta">{environment.name}</span>
        </div>

        {secretCount !== null && (
          <span className="meta numeric" style={{ flex: 'none' }}>
            {secretCount} secret{secretCount === 1 ? '' : 's'}
          </span>
        )}

        {isAdmin && (
          <div className="row-actions">
            <DropdownMenu.Root>
              <DropdownMenu.Trigger asChild>
                <button
                  className="btn btn-sm btn-icon"
                  aria-label={`Actions for ${environment.slug}`}
                  disabled={pending}
                >
                  <MoreHorizontal size={14} />
                </button>
              </DropdownMenu.Trigger>
              <DropdownMenu.Portal>
                <DropdownMenu.Content className="menu" sideOffset={6} align="end">
                  <DropdownMenu.Item
                    className="menu-item"
                    onSelect={() => setEditing((open) => !open)}
                  >
                    <Pencil size={14} />
                    {editing ? 'Cancel rename' : 'Rename'}
                  </DropdownMenu.Item>
                  <DropdownMenu.Separator className="menu-sep" />
                  <DropdownMenu.Item
                    className={`menu-item${isArchived ? '' : ' menu-item-danger'}`}
                    onSelect={() => setConfirming(true)}
                  >
                    <Archive size={14} />
                    {isArchived ? 'Restore' : 'Archive'}
                  </DropdownMenu.Item>
                </DropdownMenu.Content>
              </DropdownMenu.Portal>
            </DropdownMenu.Root>

            <ConfirmDialog
              open={confirming}
              onOpenChange={setConfirming}
              title={
                isArchived
                  ? `Restore ${project}/${environment.slug}?`
                  : `Archive ${project}/${environment.slug}?`
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
                    {secretCount === 1 ? '' : 's'} again, to everyone who holds a
                    grant on it.
                  </>
                ) : (
                  <>
                    Its {secretCount} secret
                    {secretCount === 1 ? '' : 's'} stop being served, so anything
                    running <code>coffre run</code> against{' '}
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
                    setEnvironmentArchived({
                      data: { project, environment: environment.slug, archived: !isArchived },
                    }),
                  () =>
                    toast.success(
                      isArchived
                        ? `${environment.slug} restored`
                        : `${environment.slug} archived`,
                    ),
                )
              }
            />
          </div>
        )}
      </div>

      {editing && (
        <div className="row-detail" style={{ paddingTop: 'var(--space-4)' }}>
          <form
            className="form-grid"
            onSubmit={(event) => {
              event.preventDefault();
              run(
                () =>
                  updateEnvironment({
                    data: { project, environment: environment.slug, slug, name },
                  }),
                () => {
                  setEditing(false);
                  toast.success('Environment renamed');
                },
              );
            }}
          >
            <label className="field" style={{ maxWidth: '15rem' }}>
              <span className="label">Slug</span>
              <input
                className="input"
                value={slug}
                onChange={(event) => setSlug(event.target.value)}
              />
            </label>
            <label className="field grow">
              <span className="label">Display name</span>
              <input
                className="input"
                value={name}
                onChange={(event) => setName(event.target.value)}
              />
            </label>
            <button className="btn btn-primary" type="submit" disabled={pending}>
              {pending && <Spinner />}
              Save
            </button>
          </form>
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

function NewEnvironment({ project }: { project: string }) {
  const [open, setOpen] = useState(false);
  const [slug, setSlug] = useState('');
  const [name, setName] = useState('');
  const { pending, error, setError, run } = useAction();

  function close() {
    setOpen(false);
    setError(null);
  }

  return (
    <>
      <button className="btn btn-sm" onClick={() => setOpen(true)}>
        <Plus size={13} />
        Add environment
      </button>

      <Modal
        open={open}
        onOpenChange={(next) => (next ? setOpen(true) : close())}
        title="Add an environment"
      >
        <form
          className="dialog-form stack"
          onSubmit={(event) => {
            event.preventDefault();
            run(
              () => createEnvironment({ data: { project, slug, name } }),
              () => {
                toast.success(`Environment ${slug} added`);
                setSlug('');
                setName('');
                close();
              },
            );
          }}
        >
          <label className="field">
            <span className="label">Slug</span>
            <input
              className="input"
              autoFocus
              placeholder="staging"
              value={slug}
              onChange={(event) => setSlug(event.target.value)}
            />
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
              disabled={pending || slug === '' || name === ''}
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

function Grants({
  project,
  environments,
  grants,
  error: loadError,
}: {
  project: string;
  environments: ProjectSummary['environments'];
  grants: GrantRow[];
  error: string | null;
}) {
  const userGrants = grants.filter((grant) => grant.principalType === 'user');
  const serviceGrants = grants.filter((grant) => grant.principalType === 'service');

  return (
    <section className="section">
      <div className="section-head">
        <h2>Access</h2>
      </div>

      {loadError !== null ? (
        <Notice tone="bad">{loadError}</Notice>
      ) : (
        <div className="stack" style={{ gap: 'var(--space-6)' }}>
          <ProjectAccessTable
            title="Users"
            principalType="user"
            project={project}
            environments={environments}
            grants={userGrants}
          />
          <ProjectAccessTable
            title="Service accounts"
            principalType="service"
            project={project}
            environments={environments}
            grants={serviceGrants}
          />
        </div>
      )}
    </section>
  );
}

function ProjectAccessTable({
  title,
  principalType,
  project,
  environments,
  grants,
}: {
  title: string;
  principalType: 'user' | 'service';
  project: string;
  environments: ProjectSummary['environments'];
  grants: GrantRow[];
}) {
  return (
    <div>
      <div className="section-head">
        <h3>{title}</h3>
        <NewGrant
          principalType={principalType}
          project={project}
          environments={environments}
        />
      </div>
      <div className="card">
        {grants.length === 0 ? (
          <EmptyState
            icon={
              principalType === 'user' ? <Users size={26} /> : <Key size={26} />
            }
            title={`No ${title.toLowerCase()} have access`}
          >
            Add {principalType === 'user' ? 'a user' : 'a service account'} with
            permissions for the whole project or one environment.
          </EmptyState>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{principalType === 'user' ? 'Email' : 'Common name'}</th>
                  <th>Permissions</th>
                  <th className="shrink">Expires</th>
                  <th className="shrink" />
                </tr>
              </thead>
              <tbody>
                {grants.map((grant) => (
                  <GrantRowView key={grant.id} project={project} grant={grant} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function NewGrant({
  principalType,
  project,
  environments,
}: {
  principalType: 'user' | 'service';
  project: string;
  environments: ProjectSummary['environments'];
}) {
  const [open, setOpen] = useState(false);
  const [principalId, setPrincipalId] = useState('');
  const [permission, setPermission] = useState('viewer:');
  const [expiresAt, setExpiresAt] = useState('');
  const { pending, error, setError, run } = useAction();
  const permissionOptions = projectAccessOptions(environments);

  function close() {
    setOpen(false);
    setError(null);
  }

  return (
    <>
      <button className="btn btn-sm" onClick={() => setOpen(true)}>
        <Plus size={13} />
        Add
      </button>

      <Modal
        open={open}
        onOpenChange={(next) => (next ? setOpen(true) : close())}
        title={`Add ${principalType === 'user' ? 'user' : 'service-account'} access`}
        wide
        description={
          <>
            Owners can manage the whole project and its access. Read and write access can
            cover every environment or one specific environment.
          </>
        }
      >
        <form
          className="dialog-form stack"
          onSubmit={(event) => {
            event.preventDefault();
            const access = parseProjectAccess(permission);
            run(
              () =>
                createGrant({
                  data: {
                    project,
                    principalType,
                    principalId,
                    role: access.role,
                    environmentSlug: access.environmentSlug,
                    expiresAt:
                      expiresAt === ''
                        ? null
                        : new Date(`${expiresAt}T23:59:59Z`).toISOString(),
                  },
                }),
              () => {
                const label =
                  permissionOptions.find((option) => option.value === permission)?.label ??
                  'access';
                toast.success(`${principalId} granted ${label.toLowerCase()}`);
                setPrincipalId('');
                setExpiresAt('');
                setPermission('viewer:');
                close();
              },
            );
          }}
        >
          <label className="field">
            <span className="label">
              {principalType === 'user' ? 'Email' : 'Service token common name'}
            </span>
            <input
              className="input"
              autoFocus
              placeholder={
                principalType === 'user' ? 'someone@equisafe.io' : 'ci-deploy.access'
              }
              value={principalId}
              onChange={(event) => setPrincipalId(event.target.value)}
            />
          </label>

          <div className="form-grid">
            <label className="field grow">
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

            <label className="field" style={{ maxWidth: '10rem' }}>
              <span className="label">Expires</span>
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
              disabled={pending || principalId === ''}
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

function GrantRowView({ project, grant }: { project: string; grant: GrantRow }) {
  const { pending, error, run } = useAction();

  return (
    <tr>
      <td className="mono nowrap">{grant.principalId}</td>
      <td>
        <span className={`pill ${grant.role === 'owner' ? 'pill-accent' : ''}`}>
          {projectAccessLabel(grant)}
        </span>
      </td>
      <td className="num">{grant.expiresAt === null ? '--' : grant.expiresAt.slice(0, 10)}</td>
      <td className="shrink">
        <ConfirmButton
          trigger={
            <button className="btn btn-sm btn-danger" disabled={pending}>
              <X size={13} />
              Revoke
            </button>
          }
          title={`Revoke ${projectAccessLabel(grant)} from ${grant.principalId}?`}
          body={
            <>
              They lose <strong>{projectAccessLabel(grant)}</strong> on{' '}
              <span className="mono">{project}</span> immediately. Any other access they
              hold still applies.
            </>
          }
          confirmLabel="Revoke access"
          onConfirm={() =>
            run(
              () => revokeGrant({ data: { project, grantId: grant.id } }),
              () => toast.success(`Revoked access from ${grant.principalId}`),
            )
          }
        />
        {error !== null && (
          <span className="meta" style={{ color: 'var(--deny)' }}>
            {' '}
            {error}
          </span>
        )}
      </td>
    </tr>
  );
}
