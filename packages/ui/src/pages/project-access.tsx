import { useState, type ReactNode } from 'react';
import { useSuspenseQuery } from '@tanstack/react-query';
import { useShell } from '../lib/use-shell';
import { useCoffre } from '../lib/coffre';
import { grantAccess, grantId } from '../lib/changes';
import { queries } from '../lib/queries';
import { useChange } from '../lib/use-change';
import type { GrantRow, ProjectSummary } from '../shared/models';
import { ReferencesInto } from '../components/references';
import { EmptyState, Modal, Notice } from '../components/ui';
import { GrantRowView, GrantsTable, RefusedGrants, useRefusedGrants } from '../components/grants';
import { KIND } from '../components/directory';
import { PrincipalLink } from '../components/principal';
import { PrincipalPicker } from '../components/principal-picker';
import { parseProjectAccess, projectAccessOptions } from '../lib/project-access';
import { Key, Plus, User } from '../components/icons';
import { pageRoute } from '../lib/page-route';
import { useProject } from '../lib/project-page';
import type { projectServiceAccounts, projectUsers } from '../options';

/** A project's users: who holds access, and what others read of it through references. */
export function ProjectUsersPage() {
  const { project: slug } = pageRoute<typeof projectUsers>().useParams();
  return (
    <ProjectAccess slug={slug} principalType="user">
      <ReferencesInto project={slug} />
    </ProjectAccess>
  );
}

/** A project's service accounts: which hold access. */
export function ProjectServiceAccountsPage() {
  const { project: slug } = pageRoute<typeof projectServiceAccounts>().useParams();
  return <ProjectAccess slug={slug} principalType="service" />;
}

function ProjectAccess({ slug, principalType, children }: { slug: string; principalType: 'user' | 'service'; children?: ReactNode }) {
  const { project } = useProject(slug);
  const { data: result } = useSuspenseQuery(queries.grants(useCoffre(), slug));
  if (!result.ok) return <Notice tone="bad">{result.error}</Notice>;
  return (
    <>
      <AccessPanel principalType={principalType} project={slug} environments={project.environments} grants={result.grants} />
      {children}
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
