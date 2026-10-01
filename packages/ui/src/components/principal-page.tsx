import type { CoffreClient } from '@coffre/client';
import { useState } from 'react';
import { Link, useLoaderData, useRouter } from '@tanstack/react-router';
import { toast } from 'sonner';
import { memberRef, statusOf, uiResult, useCoffre } from '../lib/coffre';
import { useAction } from '../lib/use-action';
import type { UiCapabilities } from '../lib/capabilities';
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
import type { DirectoryPrincipal, GrantRow, ProjectSummary } from '../shared/models';
import { ClosedDoor, PageHeader } from './page';
import { EmptyState, ErrorLine, Modal, Notice, Spinner } from './ui';
import { GrantRowView, GrantsTable, loadProject } from './grants';
import { InstanceRole, KIND, PrincipalActions } from './directory';
import { PrincipalReportCards, RemovedNotice } from './offboarding';
import { PrincipalAvatar } from './principal';
import { Tile } from './tile';
import { Clock, Folder, Key, Pencil, Users, X } from './icons';

type PrincipalType = DirectoryPrincipal['principalType'];

type ProjectAccess = { project: ProjectSummary; grants: GrantRow[]; grantsError: string | null };

/**
 * Everything one user's or token's page shows: who it is to the instance and
 * what it has seen (owners only), and its grants on every project where you
 * manage access.
 *
 * There is no "grants of this principal" call, so this asks each project you
 * manage for its grants and keeps this principal's. Projects where you do not
 * hold grant.manage are skipped rather than asked: the refusal would land in
 * the audit log as a denial in your name. The report is only asked for
 * instance owners, for the same reason.
 */
export async function loadPrincipalPage(
  client: CoffreClient,
  principalType: PrincipalType,
  principalId: string,
  root: { projects: ProjectSummary[]; capabilities: UiCapabilities } | undefined,
) {
  const managed = (root?.projects ?? []).filter((project) =>
    project.permissions.includes('grant.manage'),
  );
  const [report, details] = await Promise.all([
    root?.capabilities.canManageGrants
      ? uiResult(async () => {
          try {
            return { report: await client.members.get(memberRef(principalType, principalId)) };
          } catch (error) {
            // No such principal is an answer, not a failure.
            if (statusOf(error) === 404) return { report: null };
            throw error;
          }
        })
      : Promise.resolve(null),
    Promise.all(managed.map((project) => loadProject(client, project.slug))),
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

  return { report, access };
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
  const router = useRouter();
  const { instanceRole } = useLoaderData({ from: '__root__' });
  const { report, access } = data;
  const kind = KIND[principalType];
  const people = principalType === 'user';
  const list = people ? '/users' : '/tokens';
  const found = report?.ok === true ? report.report : null;
  const removed = found?.status === 'removed';
  const entry =
    found !== null && !removed
      ? {
          principalType,
          principalId,
          instanceRole: found.instanceRole,
          isRootAdmin: found.isRootAdmin,
        }
      : undefined;

  // Owners get a report about anyone ever registered, removed or not, so a
  // miss there means there is no such user. Everyone else only reaches this
  // page through projects they manage.
  const unknown = report?.ok === true && found === null;
  if (unknown || (report === null && access.length === 0)) {
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
        {report === null
          ? `A ${kind}'s page lists its access to the projects where you manage access, and you manage none.`
          : `No ${kind} by that name has ever been registered here.`}
      </ClosedDoor>
    );
  }

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
      <PageHeader
        lead={<PrincipalAvatar type={principalType} id={principalId} size="lg" />}
        title={principalId}
        meta={
          removed ? (
            <span className="tag tag-red">Removed</span>
          ) : (
            entry?.principalType === 'user' && <InstanceRole principal={entry} />
          )
        }
        actions={
          (editable.length > 0 || entry !== undefined) && (
            <>
              {editable.length > 0 && (
                <EditAccess
                  principalType={principalType}
                  principalId={principalId}
                  access={editable}
                />
              )}
              {entry !== undefined && (
                <PrincipalActions
                  principal={entry}
                  trigger="btn btn-icon"
                  onRemoved={() => router.invalidate()}
                />
              )}
            </>
          )
        }
      />

      {report?.ok === false && (
        <div className="report-notice">
          <Notice tone="bad">{report.error}</Notice>
        </div>
      )}
      {removed && found !== null && <RemovedNotice report={found} />}

      {/* Removal ends every grant, so there is no access left to show. */}
      {!removed && (
        <>
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
      )}

      {found !== null && <PrincipalReportCards report={found} />}
    </>
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
        description={`Set what this ${kind} can reach on each project you manage, and until when. Saving applies only what you changed.`}
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
              () => {
                toast.success(
                  `Updated ${principalId}’s access on ${changed.length} project${changed.length === 1 ? '' : 's'}`,
                );
                close();
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
                    <option value="owner">Owner</option>
                    <option value="viewer">Read: all</option>
                    <option value="developer">Write: all</option>
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
                              <option value="viewer">Read</option>
                              <option value="developer">Write</option>
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

/**
 * When one grant ends, as a date: access lasts through that day, UTC. Blank
 * reads "Never" where the browser lets the empty field be restyled.
 */
function ExpiryField({
  label,
  expiresAt,
  onChange,
}: {
  label: string;
  expiresAt: string | null;
  onChange: (expiresAt: string | null) => void;
}) {
  const date = dateFromExpiry(expiresAt);
  return (
    <span className={`expiry${date === '' ? ' is-never' : ''}`}>
      <input
        className="input select-sm"
        type="date"
        aria-label={label}
        min={new Date().toISOString().slice(0, 10)}
        value={date}
        onChange={(event) => onChange(expiryFromDate(event.target.value))}
      />
      <span className="expiry-never" aria-hidden="true">
        Never
      </span>
      <button
        className="btn btn-quiet btn-sm btn-icon"
        type="button"
        aria-label={`${label}: never`}
        title="Never expires"
        onClick={() => onChange(null)}
      >
        <X size={12} />
      </button>
    </span>
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
