import { useEffect, useState } from 'react';
import { createFileRoute, Link, useRouter } from '@tanstack/react-router';
import { DropdownMenu } from 'radix-ui';
import { toast } from 'sonner';
import {
  createEnvironment,
  createGrant,
  getProject,
  revokeGrant,
  setEnvironmentArchived,
  setProjectArchived,
  updateEnvironment,
  updateProject,
} from '../lib/server';
import { useAction } from '../lib/use-action';
import type { GrantRow, ProjectSummary } from '../lib/api';
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
  Layers,
  MoreHorizontal,
  Pencil,
  Plus,
  Settings,
  Users,
  X,
} from '../components/icons';

type Env = ProjectSummary['environments'][number];

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

  const active = project.environments.filter((e) => e.archivedAt === null);
  const archived = project.environments.filter((e) => e.archivedAt !== null);

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
              {canManageEnvironments
                ? 'Add the first one above. Secrets live in environments, not in the project itself, and a grant can be scoped to exactly one of them.'
                : 'Nothing to show. Creating environments needs environment.manage on this project.'}
            </EmptyState>
          ) : (
            active.map((environment) => (
              <EnvironmentRow
                key={environment.slug}
                project={project.slug}
                environment={environment}
                isAdmin={canManageEnvironments}
              />
            ))
          )}
        </div>
      </section>

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
 * These used to be a permanent "Project settings" card above the content --
 * two buttons and a heading occupying the top of the page to say what the page
 * already said. Settings that are read once and changed rarely do not earn
 * standing space.
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
  environment: Env;
  isAdmin: boolean;
}) {
  const [editing, setEditing] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [slug, setSlug] = useState(environment.slug);
  const [name, setName] = useState(environment.name);
  const { pending, error, run } = useAction();
  const isArchived = environment.archivedAt !== null;

  return (
    <div className="row-group">
      <div className="row row-interactive">
        <div className="row-title">
          <Layers size={15} style={{ color: 'var(--ink-3)', flex: 'none' }} />
          {isArchived ? (
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

        <span className="meta numeric" style={{ flex: 'none' }}>
          {environment.secretCount} secret{environment.secretCount === 1 ? '' : 's'}
        </span>

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
                isArchived ? (
                  <>
                    The environment starts serving its {environment.secretCount} secret
                    {environment.secretCount === 1 ? '' : 's'} again, to everyone who holds a
                    grant on it.
                  </>
                ) : (
                  <>
                    Its {environment.secretCount} secret
                    {environment.secretCount === 1 ? '' : 's'} stop being served, so anything
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
  environments: Env[];
  grants: GrantRow[];
  error: string | null;
}) {
  return (
    <section className="section">
      <div className="section-head">
        <h2>Access</h2>
        <NewGrant project={project} environments={environments} />
      </div>

      {loadError !== null ? (
        <Notice tone="bad">{loadError}</Notice>
      ) : (
        <div className="card">
          {grants.length === 0 ? (
            <EmptyState icon={<Users size={26} />} title="No grants on this project">
              Nobody but a root admin can reach it. Add the first grant above; scope it to one
              environment when someone only needs <span className="mono">dev</span>.
            </EmptyState>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Principal</th>
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
      )}
    </section>
  );
}

function NewGrant({
  project,
  environments,
}: {
  project: string;
  environments: Env[];
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
        Grant access
      </button>

      <Modal
        open={open}
        onOpenChange={(next) => (next ? setOpen(true) : close())}
        title="Grant access"
        wide
        description={
          <>
            Owners can manage the whole project and its access. Read and write access can
            cover every environment or one specific environment. Service accounts are
            managed from the Users page.
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
                    principalType: 'user',
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
            <span className="label">Email</span>
            <input
              className="input"
              autoFocus
              placeholder="someone@equisafe.io"
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
