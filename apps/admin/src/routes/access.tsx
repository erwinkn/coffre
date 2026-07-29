import { useState } from 'react';
import { createFileRoute, Link } from '@tanstack/react-router';
import { toast } from 'sonner';
import {
  createGrant,
  listPrincipals,
  removePrincipal,
  updateGrant,
} from '../lib/server';
import { useAction } from '../lib/use-action';
import type { Principal, ProjectSummary, RoleRow } from '../lib/api';
import {
  parseProjectAccess,
  projectAccessLabel,
  projectAccessOptions,
  projectAccessRoles,
} from '../lib/project-access';
import {
  ConfirmButton,
  EmptyState,
  ErrorLine,
  Modal,
  Notice,
  Spinner,
  Tip,
} from '../components/ui';
import { Key, Plus, Users, X } from '../components/icons';

export const Route = createFileRoute('/access')({
  loader: () => listPrincipals(),
  component: AccessPage,
});

function AccessPage() {
  const result = Route.useLoaderData();

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Users</h1>
          <p className="sub">
            Human and machine access are managed separately. Permissions apply to a
            project or one environment; root admins remain global configuration.
          </p>
        </div>
      </div>

      {!result.ok ? (
        <Notice tone="bad">{result.error}</Notice>
      ) : (
        <>
          <PrincipalSection
            title="Users"
            description="People authenticated by Cloudflare Access email."
            principalType="user"
            principals={result.principals.filter(
              (principal) => principal.principalType === 'user',
            )}
            projects={result.projects}
            roles={result.roles}
          />
          <PrincipalSection
            title="Service accounts"
            description="Machine callers matched on their Access service-token common name."
            principalType="service"
            principals={result.principals.filter(
              (principal) => principal.principalType === 'service',
            )}
            projects={result.projects}
            roles={result.roles}
          />
        </>
      )}
    </>
  );
}

function PrincipalSection({
  title,
  description,
  principalType,
  principals,
  projects,
  roles,
}: {
  title: string;
  description: string;
  principalType: 'user' | 'service';
  principals: Principal[];
  projects: ProjectSummary[];
  roles: RoleRow[];
}) {
  return (
    <section className="section">
      <div className="section-head">
        <div>
          <h2>{title}</h2>
          <p className="sub">{description}</p>
        </div>
        <AddAccess
          principalType={principalType}
          projects={projects}
        />
      </div>

      <div className="card">
        {principals.length === 0 ? (
          <EmptyState
            icon={principalType === 'user' ? <Users size={26} /> : <Key size={26} />}
            title={`No ${title.toLowerCase()} visible`}
          >
            Add the first one with project permissions. A principal with no access does
            not appear here.
          </EmptyState>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{principalType === 'user' ? 'Email' : 'Common name'}</th>
                  <th>Project</th>
                  <th>Permissions</th>
                  <th className="shrink">Expires</th>
                  <th className="shrink" />
                </tr>
              </thead>
              {principals.map((principal) => (
                <PrincipalRows
                  key={principal.principalId}
                  principal={principal}
                  projects={projects}
                  roles={roles}
                />
              ))}
            </table>
          </div>
        )}
      </div>
    </section>
  );
}

function PrincipalRows({
  principal,
  projects,
  roles,
}: {
  principal: Principal;
  projects: ProjectSummary[];
  roles: RoleRow[];
}) {
  const { pending, error, run } = useAction();

  if (principal.isRootAdmin && principal.grants.length === 0) {
    return (
      <tbody>
        <tr>
          <td className="mono nowrap">
            {principal.principalId}{' '}
            <Tip label="Granted by COFFRE_ROOT_ADMINS, not by a database grant.">
              <span className="pill pill-accent">root admin</span>
            </Tip>
          </td>
          <td className="meta">Everything, from configuration.</td>
          <td>
            <span className="pill pill-accent">Root admin</span>
          </td>
          <td className="num">--</td>
          <td className="shrink">
            <Tip label="Remove this principal from COFFRE_ROOT_ADMINS to revoke it.">
              <span className="meta nowrap">Not editable here</span>
            </Tip>
          </td>
        </tr>
      </tbody>
    );
  }

  return (
    <tbody className="principal-group">
      {principal.grants.map((grant, index) => {
        const assignableRoles = projectAccessRoles(
          roles,
          grant.environmentSlug,
          grant.role,
        );

        return (
          <tr key={grant.id}>
            {index === 0 && (
              <td className="mono nowrap principal-name-cell" rowSpan={principal.grants.length}>
                <div className="stack">
                  <span>
                    {principal.principalId}{' '}
                    {principal.isRootAdmin && (
                      <Tip label="Global access from COFFRE_ROOT_ADMINS.">
                        <span className="pill pill-accent">root admin</span>
                      </Tip>
                    )}
                  </span>
                  <div className="cluster">
                    <AddAccess
                      compact
                      principalType={principal.principalType}
                      principalId={principal.principalId}
                      projects={projects}
                    />
                    {principal.isRootAdmin ? (
                      <Tip label="Remove this principal from COFFRE_ROOT_ADMINS to revoke global access.">
                        <span className="meta nowrap">Configured globally</span>
                      </Tip>
                    ) : (
                      <ConfirmButton
                        trigger={
                          <button className="btn btn-sm btn-danger" disabled={pending}>
                            <X size={13} />
                            Remove
                          </button>
                        }
                        title={`Remove ${principal.principalId}?`}
                        body="Every project and environment permission shown here is revoked immediately."
                        confirmLabel={`Remove ${principal.principalType}`}
                        onConfirm={() =>
                          run(
                            () =>
                              removePrincipal({
                                data: {
                                  principalType: principal.principalType,
                                  principalId: principal.principalId,
                                },
                              }),
                            () => toast.success(`${principal.principalId} removed`),
                          )
                        }
                      />
                    )}
                  </div>
                  <ErrorLine error={error} />
                </div>
              </td>
            )}
            <td>
              <Link
                className="mono"
                to="/projects/$project"
                params={{ project: grant.project }}
              >
                {grant.project}
              </Link>
            </td>
            <td>
              <select
                className="select access-role-select"
                aria-label={`Permissions for ${principal.principalId} on ${grant.project}`}
                value={grant.role}
                disabled={pending}
                onChange={(event) => {
                  const role = event.target.value;
                  void run(
                    () =>
                      updateGrant({
                        data: { project: grant.project, grantId: grant.id, role },
                      }),
                    () => toast.success(`${principal.principalId} is now ${role}`),
                  );
                }}
              >
                {assignableRoles.map((role) => (
                  <option key={role.slug} value={role.slug}>
                    {projectAccessLabel({
                      role: role.slug,
                      roleName: role.name,
                      environmentSlug: grant.environmentSlug,
                    })}
                  </option>
                ))}
              </select>
            </td>
            <td className="num">
              {grant.expiresAt === null ? '--' : grant.expiresAt.slice(0, 10)}
            </td>
            <td className="shrink" />
          </tr>
        );
      })}
    </tbody>
  );
}

function AddAccess({
  principalType,
  principalId: fixedPrincipalId,
  projects,
  compact = false,
}: {
  principalType: 'user' | 'service';
  principalId?: string;
  projects: ProjectSummary[];
  compact?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [principalId, setPrincipalId] = useState(fixedPrincipalId ?? '');
  const [project, setProject] = useState(projects[0]?.slug ?? '');
  const [permission, setPermission] = useState('viewer:');
  const { pending, error, setError, run } = useAction();

  const selectedProject = projects.find((entry) => entry.slug === project);
  const permissionOptions = projectAccessOptions(selectedProject?.environments ?? []);

  function close() {
    setOpen(false);
    setError(null);
    if (fixedPrincipalId === undefined) setPrincipalId('');
    setPermission('viewer:');
  }

  return (
    <>
      <button
        className={compact ? 'btn btn-sm btn-quiet' : 'btn btn-sm'}
        onClick={() => setOpen(true)}
        disabled={projects.length === 0}
      >
        <Plus size={13} />
        {compact
          ? 'Add access'
          : `Add ${principalType === 'user' ? 'user' : 'service account'}`}
      </button>

      <Modal
        open={open}
        onOpenChange={(next) => (next ? setOpen(true) : close())}
        title={`Add ${principalType === 'user' ? 'user' : 'service-account'} access`}
        wide
        description="Owner manages the whole project and its access. Read and write can cover every environment or one specific environment. Root admin remains global deployment configuration."
      >
        <form
          className="dialog-form stack"
          onSubmit={(event) => {
            event.preventDefault();
            const access = parseProjectAccess(permission);
            void run(
              () =>
                createGrant({
                  data: {
                    project,
                    principalType,
                    principalId,
                    role: access.role,
                    environmentSlug: access.environmentSlug,
                    expiresAt: null,
                  },
                }),
              () => {
                const label =
                  permissionOptions.find((option) => option.value === permission)?.label ??
                  'access';
                toast.success(`${principalId} granted ${label.toLowerCase()} on ${project}`);
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
              value={principalId}
              disabled={fixedPrincipalId !== undefined}
              placeholder={
                principalType === 'user' ? 'someone@equisafe.io' : 'ci-deploy.access'
              }
              onChange={(event) => setPrincipalId(event.target.value)}
            />
          </label>

          <div className="form-grid">
            <label className="field grow">
              <span className="label">Project</span>
              <select
                className="select"
                value={project}
                onChange={(event) => {
                  setProject(event.target.value);
                  setPermission('viewer:');
                }}
              >
                {projects.map((entry) => (
                  <option key={entry.slug} value={entry.slug}>
                    {entry.name}
                  </option>
                ))}
              </select>
            </label>

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
          </div>

          <p className="meta">
            Owner includes project settings and access management. Write includes read.
          </p>
          <ErrorLine error={error} />

          <div className="dialog-actions">
            <button className="btn" type="button" onClick={close}>
              Cancel
            </button>
            <button
              className="btn btn-primary"
              type="submit"
              disabled={pending || principalId.trim() === '' || project === ''}
            >
              {pending && <Spinner />}
              Add access
            </button>
          </div>
        </form>
      </Modal>
    </>
  );
}
