import { useState } from 'react';
import { Link, useLoaderData, useNavigate, useRouter } from '@tanstack/react-router';
import { toast } from 'sonner';
import { createGrant, listDirectoryPrincipals } from '../server-functions/access';
import { getProject } from '../server-functions/projects';
import { useAction } from '../lib/use-action';
import type { UiCapabilities } from '../lib/capabilities';
import { parseProjectAccess, projectAccessLabel } from '../lib/project-access';
import type { DirectoryPrincipal, GrantRow, ProjectSummary } from '../shared/models';
import { ClosedDoor, PageHeader } from './page';
import { EmptyState, ErrorLine, Modal, Notice, Spinner } from './ui';
import { GrantRowView, GrantsTable } from './grants';
import { InstanceRole, KIND, PrincipalActions } from './directory';
import { PrincipalAvatar } from './principal';
import { Tile } from './tile';
import { Folder, Key, Plus, Users } from './icons';

type PrincipalType = DirectoryPrincipal['principalType'];

type ProjectAccess = { project: ProjectSummary; grants: GrantRow[]; grantsError: string | null };

/**
 * Everything one user's or token's page shows: its directory entry, and its
 * grants on every project where you manage access.
 *
 * There is no "grants of this principal" call, so this asks each project you
 * manage for its grants and keeps this principal's. Projects where you do not
 * hold grant.manage are skipped rather than asked: the refusal would land in
 * the audit log as a denial in your name. The directory is only asked for
 * instance owners, for the same reason.
 */
export async function loadPrincipalPage(
  principalType: PrincipalType,
  principalId: string,
  root: { projects: ProjectSummary[]; capabilities: UiCapabilities } | undefined,
) {
  const managed = (root?.projects ?? []).filter((project) =>
    project.permissions.includes('grant.manage'),
  );
  const [directory, details] = await Promise.all([
    root?.capabilities.canManageGrants ? listDirectoryPrincipals() : Promise.resolve(null),
    Promise.all(managed.map((project) => getProject({ data: { project: project.slug } }))),
  ]);

  const access: ProjectAccess[] = details.flatMap((result) =>
    result.ok
      ? [
          {
            project: result.project,
            grants: result.grants.filter(
              (grant) =>
                grant.principalType === principalType && grant.principalId === principalId,
            ),
            grantsError: result.grantsError,
          },
        ]
      : [],
  );

  return { directory, access };
}

export function PrincipalPage({
  principalType,
  principalId,
  data,
}: {
  principalType: PrincipalType;
  principalId: string;
  data: Awaited<ReturnType<typeof loadPrincipalPage>>;
}) {
  const navigate = useNavigate();
  const { instanceRole } = useLoaderData({ from: '__root__' });
  const { directory, access } = data;
  const kind = KIND[principalType];
  const people = principalType === 'user';
  const list = people ? '/users' : '/tokens';
  const entry =
    directory?.ok === true
      ? directory.principals.find(
          (principal) =>
            principal.principalType === principalType && principal.principalId === principalId,
        )
      : undefined;

  // Owners see the whole directory, so a miss there means there is no such
  // user. Everyone else only reaches this page through projects they manage.
  const unknown = directory?.ok === true && entry === undefined;
  if (unknown || (directory === null && access.length === 0)) {
    return (
      <ClosedDoor
        icon={people ? <Users size={18} /> : <Key size={18} />}
        label={<span className="mono">{principalId}</span>}
        title={people ? 'No such user for you' : 'No such token for you'}
        actions={
          <Link className="btn" to={list}>
            All {people ? 'users' : 'tokens'}
          </Link>
        }
      >
        {directory === null
          ? `A ${kind}'s page lists its access to the projects where you manage access, and you manage none.`
          : `No ${kind} by that name is registered. It may have been removed.`}
      </ClosedDoor>
    );
  }

  const rows = access.flatMap(({ project, grants }) =>
    grants.map((grant) => ({ project, grant })),
  );
  const errors = access.filter((entry) => entry.grantsError !== null);
  const addable = access.filter(
    ({ project, grantsError }) => project.archivedAt === null && grantsError === null,
  );

  return (
    <>
      <PageHeader
        lead={<PrincipalAvatar type={principalType} id={principalId} size="lg" />}
        title={principalId}
        meta={entry !== undefined && <InstanceRole principal={entry} />}
        actions={
          (addable.length > 0 || entry !== undefined) && (
            <>
              {addable.length > 0 && (
                <AddToProjects
                  principalType={principalType}
                  principalId={principalId}
                  access={addable}
                />
              )}
              {entry !== undefined && (
                <PrincipalActions
                  principal={entry}
                  trigger="btn btn-icon"
                  onRemoved={() => navigate({ to: list })}
                />
              )}
            </>
          )
        }
      />

      <h2 className="section-title">Project access</h2>

      {errors.map(({ project, grantsError }) => (
        <div key={project.slug} style={{ marginBottom: '0.75rem' }}>
          <Notice tone="bad">
            <span className="mono">{project.slug}</span>: {grantsError}
          </Notice>
        </div>
      ))}

      <section className="card" aria-label="Project access">
        {rows.length === 0 ? (
          <EmptyState title="No project access yet">
            {addable.length > 0
              ? `Add to projects gives this ${kind} access to several projects at once.`
              : `None of the projects where you manage access has a grant for this ${kind}.`}
          </EmptyState>
        ) : (
          <GrantsTable
            lead={
              <span className="th">
                <Folder size={14} />
                Project
              </span>
            }
          >
            {rows.map(({ project, grant }, index) => (
              <GrantRowView
                key={grant.id}
                number={index + 1}
                project={project.slug}
                grant={grant}
                leadLabel="Project"
                lead={
                  <span className="cell-project">
                    <Tile name={project.slug} />
                    <Link
                      className="cell-link"
                      to="/projects/$project"
                      params={{ project: project.slug }}
                      search={{ tab: people ? 'users' : 'tokens' }}
                    >
                      {project.name}
                    </Link>
                    {project.archivedAt !== null && <span className="tag tag-red">archived</span>}
                  </span>
                }
              />
            ))}
          </GrantsTable>
        )}
      </section>

      {/* A root admin manages every project, so nothing is out of view. */}
      {instanceRole !== 'root-admin' && (
        <p className="hint section-foot">
          Only projects where you manage access are listed.
        </p>
      )}
    </>
  );
}

/** What one project's row of the dialog is set to. */
type Plan = {
  level: '' | 'owner' | 'viewer' | 'developer' | 'env';
  environments: Record<string, '' | 'viewer' | 'developer'>;
};

const NO_PLAN: Plan = { level: '', environments: {} };

/** One grant the dialog will create. */
type Planned = { project: string; environment: string | null; access: string };

/**
 * Grants on several projects in one go, for onboarding someone.
 *
 * Each project takes one project-wide level, or "per environment" to read or
 * write only some of them. Every choice becomes one grant, created in order;
 * if one fails, the ones before it stand and drop out of the form, so trying
 * again does not create them twice.
 */
function AddToProjects({
  principalType,
  principalId,
  access,
}: {
  principalType: PrincipalType;
  principalId: string;
  access: ProjectAccess[];
}) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [plans, setPlans] = useState<Record<string, Plan>>({});
  const [expiresAt, setExpiresAt] = useState('');
  const { pending, error, setError, run } = useAction();
  const kind = KIND[principalType];

  const planned = access.flatMap(({ project }): Planned[] => {
    const plan = plans[project.slug] ?? NO_PLAN;
    if (plan.level === '') return [];
    if (plan.level !== 'env') {
      return [{ project: project.slug, environment: null, access: `${plan.level}:` }];
    }
    return Object.entries(plan.environments).flatMap(([environment, role]) =>
      role === '' ? [] : [{ project: project.slug, environment, access: `${role}:${environment}` }],
    );
  });

  function setPlan(project: string, next: Partial<Plan>) {
    setPlans((current) => ({
      ...current,
      [project]: { ...(current[project] ?? NO_PLAN), ...next },
    }));
  }

  /** Drop grants that were created from the form, so a retry skips them. */
  function forget(done: Planned[]) {
    setPlans((current) => {
      const next = { ...current };
      for (const item of done) {
        const plan = next[item.project] ?? NO_PLAN;
        next[item.project] =
          item.environment === null
            ? NO_PLAN
            : { ...plan, environments: { ...plan.environments, [item.environment]: '' } };
      }
      return next;
    });
  }

  function close() {
    setOpen(false);
    setPlans({});
    setExpiresAt('');
    setError(null);
  }

  return (
    <>
      <button className="btn btn-primary" onClick={() => setOpen(true)}>
        <Plus size={14} />
        Add to projects
      </button>

      <Modal
        open={open}
        onOpenChange={(next) => (next ? setOpen(true) : close())}
        title={
          <>
            Add <span className="mono">{principalId}</span> to projects
          </>
        }
        description={`Pick a level on each project the ${kind} should reach. Per environment reads or writes only the environments you choose.`}
        wide
      >
        <form
          className="form"
          onSubmit={(event) => {
            event.preventDefault();
            const expiry =
              expiresAt === '' ? null : new Date(`${expiresAt}T23:59:59Z`).toISOString();
            run(
              async () => {
                for (const [index, item] of planned.entries()) {
                  const { role, environmentSlug } = parseProjectAccess(item.access);
                  const result = await createGrant({
                    data: {
                      project: item.project,
                      principalType,
                      principalId,
                      role,
                      environmentSlug,
                      expiresAt: expiry,
                    },
                  });
                  if (!result.ok) {
                    if (index > 0) {
                      forget(planned.slice(0, index));
                      await router.invalidate();
                    }
                    return { ok: false as const, error: `${item.project}: ${result.error}` };
                  }
                }
                return { ok: true as const };
              },
              () => {
                const projects = new Set(planned.map((item) => item.project)).size;
                toast.success(
                  `${principalId} added to ${projects} project${projects === 1 ? '' : 's'}`,
                );
                close();
              },
            );
          }}
        >
          <ul className="plan-list">
            {access.map(({ project, grants }) => {
              const plan = plans[project.slug] ?? NO_PLAN;
              const environments = project.environments.filter(
                (environment) =>
                  environment.details !== null && environment.details.archivedAt === null,
              );
              const id = `plan-${project.slug}`;
              return (
                <li key={project.slug} className="plan-row">
                  <label className="plan-project" htmlFor={id}>
                    <Tile name={project.slug} />
                    <span className="plan-project-text">
                      <span className="plan-project-name">{project.name}</span>
                      <span className="plan-project-held">
                        {grants.length === 0
                          ? 'No access yet'
                          : `Holds ${grants.map((grant) => projectAccessLabel(grant)).join(', ')}`}
                      </span>
                    </span>
                  </label>
                  <select
                    id={id}
                    className="select select-sm"
                    value={plan.level}
                    onChange={(event) =>
                      setPlan(project.slug, { level: event.target.value as Plan['level'] })
                    }
                  >
                    <option value="">Leave as is</option>
                    <option value="owner">Owner</option>
                    <option value="viewer">Read: all</option>
                    <option value="developer">Write: all</option>
                    {environments.length > 0 && <option value="env">Per environment…</option>}
                  </select>

                  {plan.level === 'env' && (
                    <ul className="plan-envs" aria-label={`Environments of ${project.name}`}>
                      {environments.map((environment) => (
                        <li key={environment.slug}>
                          <label className="plan-env">
                            <span className="mono">{environment.slug}</span>
                            <select
                              className="select select-sm"
                              value={plan.environments[environment.slug] ?? ''}
                              onChange={(event) =>
                                setPlan(project.slug, {
                                  environments: {
                                    ...plan.environments,
                                    [environment.slug]: event.target.value as
                                      | ''
                                      | 'viewer'
                                      | 'developer',
                                  },
                                })
                              }
                            >
                              <option value="">No access</option>
                              <option value="viewer">Read</option>
                              <option value="developer">Write</option>
                            </select>
                          </label>
                        </li>
                      ))}
                    </ul>
                  )}
                </li>
              );
            })}
          </ul>

          <label className="field">
            <span className="label">
              Expires <span className="hint">(optional, for every grant above)</span>
            </span>
            <input
              className="input"
              type="date"
              value={expiresAt}
              onChange={(event) => setExpiresAt(event.target.value)}
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
              disabled={pending || planned.length === 0}
            >
              {pending && <Spinner />}
              {planned.length > 1 ? `Add ${planned.length} grants` : 'Add grant'}
            </button>
          </div>
        </form>
      </Modal>
    </>
  );

}
