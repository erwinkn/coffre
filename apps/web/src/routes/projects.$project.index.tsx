import { useEffect, useState, type ReactNode } from 'react';
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
import { slugProblem } from '../lib/validation';
import {
  ConfirmButton,
  ConfirmDialog,
  EmptyState,
  ErrorLine,
  Modal,
  Notice,
  Spinner,
} from '../components/ui';
import { Card, ClosedDoor, PageHeader } from '../components/page';
import { PermissionSummary } from '../components/permissions';
import {
  parseProjectAccess,
  projectAccessLabel,
  projectAccessOptions,
} from '../lib/project-access';
import {
  Archive,
  Clock,
  Folder,
  Hash,
  Key,
  Layers,
  MoreHorizontal,
  Pencil,
  Plus,
  RotateBack,
  ShieldCheck,
  User,
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
  const isArchived = project.archivedAt !== null;

  return (
    <>
      <PageHeader
        tile={project.slug}
        title={project.slug}
        aside={project.name}
        meta={
          <>
            {isArchived && <span className="tag tag-red">archived</span>}
            <span>
              <strong>{active.length + listedOnly.length}</strong> environment
              {active.length + listedOnly.length === 1 ? '' : 's'}
              {archived.length > 0 && `, ${archived.length} archived`}
            </span>
            <PermissionSummary permissions={project.permissions} />
          </>
        }
      />

      {isArchived && (
        <div style={{ marginBottom: '1.25rem' }}>
          <Notice tone="bad">
            <strong>This project is archived.</strong> Its environments serve no reads, to
            people or to machines, until it is restored.
          </Notice>
        </div>
      )}

      <Card
        labelledBy="environments"
        title="Environments"
        description="Secrets live in environments, and a grant can be scoped to exactly one of them."
        actions={canManageEnvironments && <NewEnvironment project={project.slug} />}
      >
        {active.length === 0 && listedOnly.length === 0 ? (
          <EmptyState title="No environments yet">
            {canManageEnvironments
              ? 'Add the first with Add environment.'
              : 'Creating environments needs environment.manage on this project.'}
          </EmptyState>
        ) : (
          <EnvironmentTable>
            {active.map((environment, index) => (
              <EnvironmentRow
                key={`${project.slug}:${environment.slug}`}
                number={index + 1}
                project={project.slug}
                environment={environment}
                isAdmin={canManageEnvironments}
              />
            ))}
            {/* Environments you may know by name only: no grant you hold covers
                their contents, so they are listed, muted, and do not open. */}
            {listedOnly.map((environment, index) => (
              <tr key={environment.slug}>
                <td className="n">{active.length + index + 1}</td>
                <td className="cell-mono cell-muted" data-label="Environment">
                  {environment.slug}
                </td>
                <td className="cell-muted" data-label="Name">
                  {environment.name}
                </td>
                <td data-label="Secrets">
                  <span className="tag tag-outline">no secret access</span>
                </td>
                <td className="col-actions" />
              </tr>
            ))}
          </EnvironmentTable>
        )}
      </Card>

      {archived.length > 0 && (
        <Card
          labelledBy="archived-environments"
          title="Archived environments"
          description="Not served to anyone. Values, versions and their audit trail are intact."
        >
          <EnvironmentTable>
            {archived.map((environment, index) => (
              <EnvironmentRow
                key={environment.slug}
                number={index + 1}
                project={project.slug}
                environment={environment}
                isAdmin={canManageEnvironments}
              />
            ))}
          </EnvironmentTable>
        </Card>
      )}

      {canManageGrants &&
        (grantsError !== null ? (
          <div style={{ marginTop: '1.25rem' }}>
            <Notice tone="bad">{grantsError}</Notice>
          </div>
        ) : (
          <>
            <ProjectAccessTable
              principalType="user"
              project={project.slug}
              environments={project.environments}
              grants={grants.filter((grant) => grant.principalType === 'user')}
            />
            <ProjectAccessTable
              principalType="service"
              project={project.slug}
              environments={project.environments}
              grants={grants.filter((grant) => grant.principalType === 'service')}
            />
          </>
        ))}

      {canManageProject && (
        <>
          <GeneralSettings project={project} />
          <DangerZone project={project} />
        </>
      )}
    </>
  );
}

function EnvironmentTable({ children }: { children: ReactNode }) {
  return (
    <div className="dt-wrap">
      <table className="dt stacks">
        <thead>
          <tr>
            <th className="n">#</th>
            <th>
              <span className="th">
                <Layers size={14} />
                Environment
              </span>
            </th>
            <th>Name</th>
            <th className="col-shrink">
              <span className="th">
                <Hash size={14} />
                Secrets
              </span>
            </th>
            <th className="col-actions">
              <span className="visually-hidden">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

function EnvironmentRow({
  number,
  project,
  environment,
  isAdmin,
}: {
  number: number;
  project: string;
  environment: DetailedProjectEnvironment;
  isAdmin: boolean;
}) {
  const [renaming, setRenaming] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [slug, setSlug] = useState(environment.slug);
  const [name, setName] = useState(environment.name);
  const { pending, error, setError, run } = useAction();
  const isArchived = environment.details.archivedAt !== null;
  const secretCount = environment.details.secretCount;
  const opens = !isArchived && environment.accessible;
  const slugError = slug === '' ? null : slugProblem(slug);

  useEffect(() => {
    if (error !== null && !renaming) toast.error(error);
  }, [error, renaming]);

  return (
    <tr>
      <td className="n">{number}</td>
      <td className="cell-mono" data-label="Environment">
        {opens ? (
          <Link
            className="cell-link"
            to="/projects/$project/$environment"
            params={{ project, environment: environment.slug }}
          >
            {environment.slug}
          </Link>
        ) : (
          <span className={isArchived ? 'cell-muted' : undefined}>{environment.slug}</span>
        )}
      </td>
      <td className={isArchived ? 'cell-muted' : undefined} data-label="Name">
        {environment.name}
      </td>
      <td className="num nowrap" data-label="Secrets">
        {isArchived ? (
          <span className="tag tag-red">archived</span>
        ) : !environment.accessible ? (
          <span className="tag tag-outline">no secret access</span>
        ) : (
          (secretCount ?? '—')
        )}
      </td>
      <td className="col-actions">
        {isAdmin && (
          <DropdownMenu.Root>
            <DropdownMenu.Trigger asChild>
              <button
                className="act act-quiet"
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

        {isAdmin && (
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
                      updateEnvironment({
                        data: { project, environment: environment.slug, slug, name },
                      }),
                    () => {
                      setRenaming(false);
                      toast.success('Environment renamed');
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
                    setEnvironmentArchived({
                      data: { project, environment: environment.slug, archived: !isArchived },
                    }),
                  () =>
                    toast.success(
                      isArchived ? `${environment.slug} restored` : `${environment.slug} archived`,
                    ),
                )
              }
            />
          </>
        )}
      </td>
    </tr>
  );
}

function NewEnvironment({ project }: { project: string }) {
  const [open, setOpen] = useState(false);
  const [slug, setSlug] = useState('');
  const [name, setName] = useState('');
  const { pending, error, setError, run } = useAction();
  const slugError = slug === '' ? null : slugProblem(slug);

  function close() {
    setOpen(false);
    setError(null);
  }

  return (
    <>
      <button className="btn btn-sm" onClick={() => setOpen(true)}>
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

function ProjectAccessTable({
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
  const people = principalType === 'user';
  return (
    <Card
      labelledBy={`access-${principalType}`}
      title={people ? 'Members with access' : 'Tokens with access'}
      description={
        people
          ? 'A grant covers the whole project or exactly one environment, and takes effect immediately.'
          : 'Machines such as CI and deploys, matched on their Access service-token common name.'
      }
      actions={
        <NewGrant principalType={principalType} project={project} environments={environments} />
      }
    >
      {grants.length === 0 ? (
        <EmptyState title={people ? 'No member has access' : 'No token has access'}>
          Add {people ? 'a member' : 'a token'} with permissions on the whole project
          or on one environment.
        </EmptyState>
      ) : (
        <div className="dt-wrap">
          <table className="dt grants stacks">
            <thead>
              <tr>
                <th className="n">#</th>
                <th className="col-principal">
                  <span className="th">
                    {people ? <User size={14} /> : <Key size={14} />}
                    {people ? 'Email' : 'Common name'}
                  </span>
                </th>
                <th>
                  <span className="th">
                    <ShieldCheck size={14} />
                    Permissions
                  </span>
                </th>
                <th className="col-expires">
                  <span className="th">
                    <Clock size={14} />
                    Expires
                  </span>
                </th>
                <th className="col-actions">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {grants.map((grant, index) => (
                <GrantRowView key={grant.id} number={index + 1} project={project} grant={grant} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
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
  const kind = principalType === 'user' ? 'member' : 'token';

  function close() {
    setOpen(false);
    setError(null);
  }

  return (
    <>
      <button className="btn btn-sm" onClick={() => setOpen(true)}>
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
        description={
          <>
            Owners manage the whole project and its access. Read and write can cover every
            environment, or one. The {kind} must already be registered under
            {principalType === 'user' ? ' Members' : ' Tokens'}.
          </>
        }
      >
        <form
          className="form"
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
              className="input input-mono"
              autoFocus
              spellCheck={false}
              autoComplete="off"
              placeholder={
                principalType === 'user' ? 'someone@equisafe.io' : 'ci-deploy.access'
              }
              value={principalId}
              onChange={(event) => setPrincipalId(event.target.value)}
            />
          </label>

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

function GrantRowView({
  number,
  project,
  grant,
}: {
  number: number;
  project: string;
  grant: GrantRow;
}) {
  const { pending, error, run } = useAction();
  const label = projectAccessLabel(grant);
  const expired = grant.expiresAt !== null && new Date(grant.expiresAt).getTime() < Date.now();

  return (
    <>
      <tr>
        <td className="n">{number}</td>
        <td
          className="cell-mono"
          data-label={grant.principalType === 'user' ? 'Email' : 'Common name'}
        >
          {grant.principalId}
        </td>
        <td data-label="Permissions">
          <span className={`tag${grant.role === 'owner' ? ' tag-violet' : ''}`}>{label}</span>
        </td>
        <td className="col-expires cell-mono cell-muted" data-label="Expires">
          {grant.expiresAt === null ? (
            'never'
          ) : (
            <>
              {grant.expiresAt.slice(0, 10)}
              {expired && (
                <>
                  {' '}
                  <span className="tag tag-red">expired</span>
                </>
              )}
            </>
          )}
        </td>
        <td className="col-actions">
          <ConfirmButton
            trigger={
              <button className="act act-danger" disabled={pending}>
                {pending && <Spinner size={13} />}
                Revoke
              </button>
            }
            title={
              <>
                Revoke {label} from <span className="mono">{grant.principalId}</span>?
              </>
            }
            body={
              <>
                They lose <strong>{label}</strong> on <span className="mono">{project}</span>{' '}
                immediately, including any process using it right now. Other grants they hold
                still apply.
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
        </td>
      </tr>
      {error !== null && (
        <tr className="row-error">
          <td colSpan={5}>
            <ErrorLine error={error} />
          </td>
        </tr>
      )}
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
          <p className="card-desc">
            Safe to rename: ciphertext is bound to ids, never names, so nothing is re-encrypted
            and no history is orphaned.
          </p>
        </div>
      </div>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          run(
            () => updateProject({ data: { project: project.slug, slug, name } }),
            async () => {
              toast.success('Project renamed');
              // The slug is part of the URL, so a rename has to navigate.
              if (slug !== project.slug) {
                await router.navigate({ to: '/projects/$project', params: { project: slug } });
              }
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
    </Card>
  );
}
