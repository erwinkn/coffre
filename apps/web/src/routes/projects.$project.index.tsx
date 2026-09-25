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
import { ClosedDoor, PageHeader, Section } from '../components/page';
import { PermissionSummary } from '../components/permissions';
import {
  parseProjectAccess,
  projectAccessLabel,
  projectAccessOptions,
} from '../lib/project-access';
import {
  Archive,
  ArrowRight,
  ChevronDown,
  MoreHorizontal,
  Pencil,
  Plus,
  RotateBack,
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
        eyebrow="Project"
        title={projectSlug}
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
        eyebrow={
          <>
            Project
            {isArchived && <span className="tag tag-red">archived</span>}
          </>
        }
        title={project.slug}
        aside={project.name}
        actions={canManageProject && <ProjectSettings project={project} />}
        meta={
          <>
            <span>
              <strong>{active.length}</strong> environment{active.length === 1 ? '' : 's'}
              {archived.length > 0 && `, ${archived.length} archived`}
            </span>
            <PermissionSummary permissions={project.permissions} />
          </>
        }
      />

      {isArchived && (
        <div style={{ marginTop: '1.25rem' }}>
          <Notice tone="bad">
            <strong>This project is archived.</strong> Its environments serve no reads, to
            people or to machines, until it is restored.
          </Notice>
        </div>
      )}

      <Section
        labelledBy="environments"
        title="Environments"
        actions={canManageEnvironments && <NewEnvironment project={project.slug} />}
      >
        {active.length === 0 ? (
          <EmptyState title="No environments yet">
            {listedOnly.length > 0
              ? 'You can see the names of other environments below, but not open them.'
              : canManageEnvironments
                ? 'Secrets live in environments, not in the project itself, and a grant can be scoped to exactly one of them. Add the first with Add environment.'
                : 'Creating environments needs environment.manage on this project.'}
          </EmptyState>
        ) : (
          <ul className="index">
            {active.map((environment) => (
              <EnvironmentRow
                key={`${project.slug}:${environment.slug}`}
                project={project.slug}
                environment={environment}
                isAdmin={canManageEnvironments}
              />
            ))}
          </ul>
        )}
      </Section>

      {listedOnly.length > 0 && (
        <Section
          labelledBy="other-environments"
          title="Other environments"
          note="They exist, and that is all you can see: no grant you hold covers their contents."
        >
          <ul className="index">
            {listedOnly.map((environment) => (
              <li className="index-row is-muted" key={environment.slug}>
                <div className="index-main">
                  <span className="index-title">{environment.slug}</span>
                  <span className="index-sub">{environment.name}</span>
                </div>
                <div className="index-side">
                  <span className="tag tag-outline">no access</span>
                </div>
              </li>
            ))}
          </ul>
        </Section>
      )}

      {archived.length > 0 && (
        <Section
          labelledBy="archived-environments"
          title="Archived environments"
          note="Not served to anyone. Values, versions and their audit trail are intact."
        >
          <ul className="index">
            {archived.map((environment) => (
              <EnvironmentRow
                key={environment.slug}
                project={project.slug}
                environment={environment}
                isAdmin={canManageEnvironments}
              />
            ))}
          </ul>
        </Section>
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
 * Rename and archive, behind one Settings menu in the page head.
 *
 * These change rarely and reach everyone on the project, so they are one
 * deliberate step away rather than laid out on the page.
 */
function ProjectSettings({ project }: { project: ProjectSummary }) {
  const router = useRouter();
  const [renaming, setRenaming] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [slug, setSlug] = useState(project.slug);
  const [name, setName] = useState(project.name);
  const { pending, error, setError, run } = useAction();
  const isArchived = project.archivedAt !== null;
  const slugError = slug === '' ? null : slugProblem(slug);

  // Renaming prints its error inside the modal. Archiving has no surface of
  // its own, so it says so in a toast -- otherwise a failed archive would look
  // like nothing happening at all.
  useEffect(() => {
    if (error !== null && !renaming) toast.error(error);
  }, [error, renaming]);

  return (
    <>
      <DropdownMenu.Root>
        <DropdownMenu.Trigger asChild>
          <button className="btn" disabled={pending}>
            Settings
            <ChevronDown size={13} />
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
              {isArchived ? <RotateBack size={14} /> : <Archive size={14} />}
              {isArchived ? 'Restore project' : 'Archive project…'}
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
        title={
          <>
            Rename <span className="mono">{project.slug}</span>
          </>
        }
      >
        <form
          className="form"
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
            <span className="caps">Slug</span>
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
                'Safe to change: ciphertext is bound to ids, never names, so nothing is re-encrypted and no history is orphaned. Scripts that name the old slug will need the new one.'}
            </span>
          </label>
          <label className="field">
            <span className="caps">Display name</span>
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
    <li className={`index-row${isArchived ? ' is-muted' : ''}`}>
      <div className="index-main">
        {opens ? (
          <Link
            className="index-title index-stretch"
            to="/projects/$project/$environment"
            params={{ project, environment: environment.slug }}
          >
            {environment.slug}
          </Link>
        ) : (
          <span className="index-title">{environment.slug}</span>
        )}
        <span className="index-sub">{environment.name}</span>
      </div>

      <div className="index-side">
        {secretCount !== null && (
          <span className="num nowrap">
            {secretCount} secret{secretCount === 1 ? '' : 's'}
          </span>
        )}
        {isArchived && <span className="tag tag-red">archived</span>}

        {isAdmin && (
          <DropdownMenu.Root>
            <DropdownMenu.Trigger asChild>
              <button
                className="btn btn-quiet btn-sm btn-icon"
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

        {opens && <ArrowRight size={16} className="index-arrow" />}
      </div>

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
                Rename <span className="mono">{project}/{environment.slug}</span>
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
                <span className="caps">Slug</span>
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
                <span className="caps">Display name</span>
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
    </li>
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
        <Plus size={13} />
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
            <span className="caps">Slug</span>
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
            <span className="caps">Display name</span>
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
    <Section
      labelledBy="access"
      title="Access"
      note="Who can do what in this project. A grant covers the whole project or exactly one environment, and takes effect immediately."
    >
      {loadError !== null ? (
        <div style={{ marginTop: '1rem' }}>
          <Notice tone="bad">{loadError}</Notice>
        </div>
      ) : (
        <>
          <ProjectAccessTable
            title="People"
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
        </>
      )}
    </Section>
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
    <div className="subsection">
      <div className="subsection-head">
        <h3 className="subsection-title">{title}</h3>
        <NewGrant principalType={principalType} project={project} environments={environments} />
      </div>
      {grants.length === 0 ? (
        <EmptyState
          title={principalType === 'user' ? 'Nobody has access' : 'No service account has access'}
        >
          Add {principalType === 'user' ? 'a person' : 'a service account'} with permissions
          on the whole project or on one environment.
        </EmptyState>
      ) : (
        <div className="ledger-wrap">
          <table className="ledger stacks">
            <thead>
              <tr>
                <th className="caps">{principalType === 'user' ? 'Email' : 'Common name'}</th>
                <th className="caps">Permissions</th>
                <th className="caps col-shrink">Expires</th>
                <th className="col-actions">
                  <span className="visually-hidden">Actions</span>
                </th>
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
  const kind = principalType === 'user' ? 'person' : 'service account';

  function close() {
    setOpen(false);
    setError(null);
  }

  return (
    <>
      <button className="btn btn-sm" onClick={() => setOpen(true)}>
        <Plus size={13} />
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
            environment, or one. The {kind} must already be in the directory.
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
            <span className="caps">
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
              <span className="caps">Permissions</span>
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
              <span className="caps">Expires (optional)</span>
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

function GrantRowView({ project, grant }: { project: string; grant: GrantRow }) {
  const { pending, error, run } = useAction();
  const label = projectAccessLabel(grant);
  const expired = grant.expiresAt !== null && new Date(grant.expiresAt).getTime() < Date.now();

  return (
    <>
      <tr>
        <td className="cell-mono" data-label={grant.principalType === 'user' ? 'Email' : 'Common name'}>
          {grant.principalId}
        </td>
        <td data-label="Permissions">
          <span className={`tag ${grant.role === 'owner' ? 'tag-accent' : ''}`}>{label}</span>
        </td>
        <td className="col-shrink cell-mono cell-muted" data-label="Expires">
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
          <td colSpan={4}>
            <ErrorLine error={error} />
          </td>
        </tr>
      )}
    </>
  );
}
