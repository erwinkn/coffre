import { useState } from 'react';
import { useSuspenseQueries, useSuspenseQuery } from '@tanstack/react-query';
import { Link, Outlet } from '@tanstack/react-router';
import { ROLES } from '@coffre/core/access';
import { useShell } from '../lib/use-shell';
import { toast } from 'sonner';
import { memberRef, useCoffre } from '../lib/coffre';
import { directoryList, disconnectMemberApp } from '../lib/changes';
import { affects, managedProjects, queries, signInWays } from '../lib/queries';
import { useChangeStatus } from '../lib/use-change';
import { useMounted } from '../lib/mounted';
import { ItemFailure } from './row-state';
import { useAction } from '../lib/use-action';
import { projectAccessLabel } from '../lib/project-access';
import {
  accessChanges,
  accessPatch,
  dateFromExpiry,
  environmentAccess,
  expiryFromDate,
  planFromGrants,
  withEnvironment,
  withLevel,
  type AccessChange,
  type AccessPlan,
} from '../lib/access-plan';
import type { DirectoryPrincipal, GrantRow, PrincipalReport, ProjectSummary } from '../shared/models';
import { ClosedDoor, PageHeader } from './page';
import { EmptyState, ErrorLine, Modal, Notice, Spinner } from './ui';
import { GrantRowView, GrantsTable } from './grants';
import { EveryProjectGrants } from './every-project';
import { ExpiryField } from './expiry-field';
import { InstanceRole, KIND, PrincipalActions } from './directory';
import { PrincipalReportCards, RemovedNotice } from './offboarding';
import { ConnectedAppsCard } from './connected-apps';
import { PrincipalAvatar } from './principal';
import { Tile } from './tile';
import { Activity, Archive, Clock, Folder, Key, Link as LinkIcon, Pencil, Users, X } from './icons';
import { PageTabs } from './tabs';

type PrincipalType = DirectoryPrincipal['principalType'];

type ProjectAccess = { project: ProjectSummary; grants: GrantRow[]; grantsError: string | null };

/** Who a user or service account is to the instance, as an owner reads it; null for anyone else. */
function useReport(principalType: PrincipalType, principalId: string) {
  const { capabilities } = useShell();
  return useSuspenseQuery(queries.report(useCoffre(), memberRef(principalType, principalId), capabilities.canManageGrants)).data;
}

/**
 * Its grants on every project where you manage access, which `loadAccess`
 * read: there is no call for one member's, so each project's are filtered.
 */
function useProjectAccess(principalType: PrincipalType, principalId: string): ProjectAccess[] {
  const client = useCoffre();
  const managed = managedProjects(useShell().projects);
  const grants = useSuspenseQueries({
    queries: managed.map((project) => queries.grants(client, project.slug)),
  });
  return managed.map((project, index) => {
    const result = grants[index]!.data;
    return {
      project,
      // Grants on every project show once, below: not again in each project they reach.
      grants: result.ok
        ? result.grants.filter(
            (grant) =>
              grant.principalType === principalType &&
              grant.principalId === principalId &&
              grant.scope !== 'every-project',
          )
        : [],
      grantsError: result.ok ? null : result.error,
    };
  });
}

/**
 * A user's or service account's page: who it is, its menu, and its tabs,
 * each a page of its own under this one. Access is a user's first tab; a
 * service account's is how it signs in, while it shows one. A tab the
 * deployment left out is not offered.
 */
export function PrincipalLayout({ principalType, principalId }: { principalType: PrincipalType; principalId: string }) {
  const shell = useShell();
  const mounted = useMounted();
  const { capabilities } = shell;
  const report = useReport(principalType, principalId);
  // A role change or removal made from this page's menu, refused.
  const { status, dismiss } = useChangeStatus(directoryList.queryKey);
  const change = status(memberRef(principalType, principalId));
  const kind = KIND[principalType];
  const people = principalType === 'user';
  const found = report?.ok === true ? report.report : null;
  const removed = found?.status === 'removed';
  const entry =
    found !== null && !removed
      ? {
          principalType,
          principalId,
          instanceRole: found.instanceRole,
          isRootAdmin: found.isRootAdmin,
          tampered: found.status === 'tampered',
        }
      : undefined;

  // Owners get a report about anyone ever registered, removed or not, so a
  // miss there means there is no such user. Everyone else only reaches this
  // page through projects they manage.
  const unknown = report?.ok === true && found === null;
  if (unknown || (report === null && managedProjects(shell.projects).length === 0)) {
    return (
      <ClosedDoor
        icon={people ? <Users size={18} /> : <Key size={18} />}
        label={<span className="mono">{people ? principalId : `service:${principalId}`}</span>}
        title={people ? 'No such user for you' : 'No such service account for you'}
        actions={
          <Link className="btn" to={people ? '/users' : '/service-accounts'}>
            All {people ? 'users' : 'service accounts'}
          </Link>
        }
      >
        {report === null
          ? `A ${kind}'s page lists its access to the projects where you manage access, and you manage none.`
          : `No ${kind} by that name has ever been registered here.`}
      </ClosedDoor>
    );
  }

  const access = (
    <>
      {removed ? <Archive size={15} /> : <Folder size={15} />}
      {removed ? 'Offboarding' : 'Access'}
    </>
  );
  const activity = (
    <>
      <Activity size={15} />
      Activity
    </>
  );
  const tabs = people
    ? [
        <Link key="access" to="/users/$user" params={{ user: principalId }} activeOptions={{ exact: true, includeSearch: false }}>
          {access}
        </Link>,
        capabilities.canReadAudit && mounted('/users/$user/activity') && (
          <Link key="activity" to="/users/$user/activity" params={{ user: principalId }}>
            {activity}
          </Link>
        ),
      ]
    : [
        signInWays(shell, report) !== null && (
          <Link key="sign-in" to="/service-accounts/$account" params={{ account: principalId }} activeOptions={{ exact: true, includeSearch: false }}>
            <LinkIcon size={15} />
            Sign-in
          </Link>
        ),
        mounted('/service-accounts/$account/access') && (
          <Link key="access" to="/service-accounts/$account/access" params={{ account: principalId }}>
            {access}
          </Link>
        ),
        capabilities.canReadAudit && mounted('/service-accounts/$account/activity') && (
          <Link key="activity" to="/service-accounts/$account/activity" params={{ account: principalId }}>
            {activity}
          </Link>
        ),
      ];

  return (
    <>
      <PageHeader
        lead={<PrincipalAvatar type={principalType} id={principalId} size="lg" />}
        title={principalType === 'service' ? `service:${principalId}` : principalId}
        description={
          principalType === 'service'
            ? 'A service account: an identity for CI and other automation.'
            : undefined
        }
        meta={
          removed ? (
            <span className="tag tag-red">Removed</span>
          ) : (
            entry?.principalType === 'user' && <InstanceRole principal={entry} />
          )
        }
        actions={entry !== undefined && <PrincipalActions principal={entry} trigger="btn btn-icon" />}
      />

      {change.state === 'failed' && (
        <div className="report-notice">
          <ItemFailure status={change} onDismiss={() => dismiss(change.mutationId)} />
        </div>
      )}
      {report?.ok === false && (
        <div className="report-notice">
          <Notice tone="bad">{report.error}</Notice>
        </div>
      )}
      <PageTabs label={people ? 'User sections' : 'Service account sections'}>{tabs}</PageTabs>

      <Outlet />
    </>
  );
}

/**
 * A user's or service account's Access tab: its grants on every project
 * where you manage access, and on every project; once it is removed, what
 * its offboarding did instead.
 */
export function PrincipalAccess({ principalType, principalId }: { principalType: PrincipalType; principalId: string }) {
  const { instanceRole, features } = useShell();
  const report = useReport(principalType, principalId);
  const access = useProjectAccess(principalType, principalId);
  const kind = KIND[principalType];
  const people = principalType === 'user';
  const found = report?.ok === true ? report.report : null;
  const removed = found?.status === 'removed';

  const rows = access.flatMap(({ project, grants }) =>
    grants.map((grant) => ({ project, grant })),
  );
  const errors = access.filter((entry) => entry.grantsError !== null);
  // Grants to someone removed are refused until they are added back.
  const editable = removed
    ? []
    : access.filter(
        ({ project, grantsError }) => project.archivedAt === null && grantsError === null,
      );

  return (
    <>
      {removed && found !== null && <RemovedNotice report={found} />}

      {/* Removal ends every grant, so there is no access left to show. */}
      {!removed && (
        <>
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
                {editable.length > 0
                  ? `Edit access gives this ${kind} access to several projects at once.`
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
                          to={people ? '/projects/$project/users' : '/projects/$project/service-accounts'}
                          params={{ project: project.slug }}
                        >
                          {project.name}
                        </Link>
                        {project.archivedAt !== null && <span className="tag tag-red">Archived</span>}
                      </span>
                    }
                  />
                ))}
              </GrantsTable>
            )}
          </section>

          {editable.length > 0 && (
            <div className="table-actions">
              <EditAccess principalType={principalType} principalId={principalId} access={editable} />
            </div>
          )}

          {/* A root admin manages every project, so nothing is out of view. */}
          {instanceRole !== 'root-admin' && (
            <p className="hint section-foot">
              Only projects where you manage access are listed.
            </p>
          )}

          <EveryProjectGrants principalType={principalType} principalId={principalId} />

          {/* Only an owner reads the report that lists them; removal disconnects them. */}
          {features.mcp && people && found !== null && <MemberApps principalId={principalId} apps={found.apps} />}
        </>
      )}

      {found !== null && <PrincipalReportCards report={found} />}
    </>
  );
}

/** A person's connected apps, for an owner, who may disconnect any of them. */
function MemberApps({ principalId, apps }: { principalId: string; apps: PrincipalReport['apps'] }) {
  return (
    <ConnectedAppsCard
      apps={apps}
      change={disconnectMemberApp(useCoffre(), memberRef('user', principalId))}
      description="AI assistants and other MCP clients they connected. Removing them disconnects every one."
      empty="They have connected none."
    />
  );
}

/**
 * One principal's access to every project you manage, edited in one place.
 *
 * Each project opens set to what the principal holds: a project-wide level,
 * or read or write per environment, each with its own expiry. Saving sends
 * only the difference, every project in one `access.set`: the server applies
 * all of it in one transaction, or none of it.
 */
function EditAccess({
  principalType,
  principalId,
  access,
}: {
  principalType: PrincipalType;
  principalId: string;
  access: ProjectAccess[];
}) {
  const coffre = useCoffre();
  const [open, setOpen] = useState(false);
  const [edits, setEdits] = useState<Record<string, AccessPlan>>({});
  const { pending, error, setError, run } = useAction();
  const kind = KIND[principalType];

  const rows = access.map(({ project, grants }) => {
    const environments = project.environments
      .filter(
        (environment) => environment.details !== null && environment.details.archivedAt === null,
      )
      .map((environment) => environment.slug);
    const held = planFromGrants(grants, environments);
    const plan = Object.hasOwn(edits, project.slug) ? edits[project.slug] : held;
    return { project, grants, environments, held, plan, changes: accessChanges(grants, plan) };
  });
  const changed = rows.filter((row) => row.changes.length > 0);

  function close() {
    setOpen(false);
    setEdits({});
    setError(null);
  }

  return (
    <>
      <button className="btn btn-primary" onClick={() => setOpen(true)}>
        <Pencil size={14} />
        Edit access
      </button>

      <Modal
        open={open}
        onOpenChange={(next) => (next ? setOpen(true) : close())}
        title={
          <>
            Edit access for <span className="mono">{principalId}</span>
          </>
        }
        description={`Set what this ${kind} can reach on each project you manage, and until when.`}
        wide
      >
        <form
          className="form"
          onSubmit={(event) => {
            event.preventDefault();
            run(
              () =>
                coffre.access.set(
                  memberRef(principalType, principalId),
                  Object.assign({}, ...changed.map(({ project, changes }) => accessPatch(project.slug, changes))),
                ),
              {
                affects: changed.flatMap(({ project }) =>
                  affects.access(project.slug, memberRef(principalType, principalId)),
                ),
                onSuccess: () => {
                  toast.success(
                    `Updated ${principalId}’s access on ${changed.length} project${changed.length === 1 ? '' : 's'}`,
                  );
                  close();
                },
              },
            );
          }}
        >
          <ul className="plan-list">
            <li className="plan-head" aria-hidden="true">
              <span>Project</span>
              <span>Access</span>
              <span>Expires</span>
            </li>
            {rows.map(({ project, grants, environments, held, plan, changes }) => {
              const id = `plan-${project.slug}`;
              const edit = (next: AccessPlan) =>
                setEdits((current) => ({ ...current, [project.slug]: next }));
              return (
                <li
                  key={project.slug}
                  className={`plan-row${changes.length > 0 ? ' is-changed' : ''}`}
                >
                  <label className="plan-project" htmlFor={id}>
                    <Tile name={project.slug} />
                    <span className="plan-project-text">
                      <span className="plan-project-name">{project.name}</span>
                      {held.level === 'custom' && (
                        <span className="plan-project-held">
                          Holds {grants.map((grant) => projectAccessLabel(grant)).join(', ')}
                        </span>
                      )}
                    </span>
                  </label>
                  <select
                    id={id}
                    className="select select-sm"
                    value={plan.level}
                    onChange={(event) =>
                      edit(
                        withLevel(plan, event.target.value as AccessPlan['level'], environments),
                      )
                    }
                  >
                    {held.level === 'custom' && <option value="custom">Keep as is</option>}
                    <option value="none">No access</option>
                    <option value="owner">{ROLES.owner.name}</option>
                    <option value="viewer">{ROLES.viewer.name}: all</option>
                    <option value="developer">{ROLES.developer.name}: all</option>
                    {environments.length > 0 && <option value="env">Per environment…</option>}
                  </select>
                  {(plan.level === 'owner' ||
                    plan.level === 'viewer' ||
                    plan.level === 'developer') && (
                    <ExpiryField
                      label={`${project.name} expires`}
                      expiresAt={plan.expiresAt}
                      onChange={(expiresAt) => edit({ ...plan, expiresAt })}
                    />
                  )}

                  {plan.level === 'env' && (
                    <ul className="plan-envs" aria-label={`Environments of ${project.name}`}>
                      {environments.map((slug) => {
                        const current = environmentAccess(plan, slug);
                        return (
                          <li key={slug} className="plan-env">
                            <label className="mono" htmlFor={`${id}-${slug}`}>
                              {slug}
                            </label>
                            <select
                              id={`${id}-${slug}`}
                              className="select select-sm"
                              value={current?.role ?? ''}
                              onChange={(event) => {
                                const role = event.target.value;
                                edit(
                                  withEnvironment(
                                    plan,
                                    slug,
                                    role === 'viewer' || role === 'developer'
                                      ? { role, expiresAt: current?.expiresAt ?? null }
                                      : null,
                                  ),
                                );
                              }}
                            >
                              <option value="">No access</option>
                              <option value="viewer">{ROLES.viewer.name}</option>
                              <option value="developer">{ROLES.developer.name}</option>
                            </select>
                            {current !== null && (
                              <ExpiryField
                                label={`${slug} of ${project.name} expires`}
                                expiresAt={current.expiresAt}
                                onChange={(expiresAt) =>
                                  edit(withEnvironment(plan, slug, { ...current, expiresAt }))
                                }
                              />
                            )}
                          </li>
                        );
                      })}
                    </ul>
                  )}

                  {changes.length > 0 && (
                    <ul className="plan-changes" aria-label={`Changes to ${project.name}`}>
                      {changes.map((change) => (
                        <li
                          key={
                            change.kind === 'create'
                              ? `+${change.role}@${change.environmentSlug ?? ''}`
                              : change.grant.id
                          }
                        >
                          <AccessChangeTag change={change} />
                        </li>
                      ))}
                    </ul>
                  )}
                </li>
              );
            })}
          </ul>

          <ErrorLine error={error} />

          <div className="dialog-actions">
            <button className="btn" type="button" onClick={close}>
              Cancel
            </button>
            <button
              className="btn btn-primary"
              type="submit"
              disabled={pending || changed.length === 0}
            >
              {pending && <Spinner />}
              Save changes
            </button>
          </div>
        </form>
      </Modal>
    </>
  );
}

function AccessChangeTag({ change }: { change: AccessChange }) {
  const until = (expiresAt: string | null) =>
    expiresAt === null ? '' : ` until ${dateFromExpiry(expiresAt)}`;
  switch (change.kind) {
    case 'create':
      return (
        <span className="tag tag-green">
          <span aria-hidden="true">+</span>
          <span className="visually-hidden">Adds</span>
          {projectAccessLabel({ ...change, roleName: change.role })}
          {until(change.expiresAt)}
        </span>
      );
    case 'expiry':
      return (
        <span className="tag tag-blue">
          <Clock size={12} />
          <span className="visually-hidden">Moves the expiry of</span>
          {projectAccessLabel(change.grant)}
          {change.expiresAt === null ? ', no expiry' : until(change.expiresAt)}
        </span>
      );
    case 'revoke':
      return (
        <span className="tag tag-red">
          <span aria-hidden="true">−</span>
          <span className="visually-hidden">Removes</span>
          {projectAccessLabel(change.grant)}
        </span>
      );
  }
}
