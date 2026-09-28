import type { ReactNode } from 'react';
import { toast } from 'sonner';
import type { CoffreClient } from '../../../../packages/client/src/index.ts';
import type { Role } from '../../../../packages/core/src/access.ts';
import { failureMessage, memberRef, uiFailure, useCoffre } from '../lib/coffre';
import { useAction } from '../lib/use-action';
import { projectAccessLabel } from '../lib/project-access';
import type { GrantRow, ProjectSummary } from '../shared/models';
import { ConfirmButton, ErrorLine, Spinner } from './ui';
import { Clock, ShieldCheck } from './icons';

/**
 * One project and, when you manage its access, its grants. A project that is
 * not there for you fails with no message: the page words that itself.
 */
export async function loadProject(client: CoffreClient, slug: string) {
  let project: ProjectSummary | undefined;
  try {
    project = (await client.projects.list()).projects.find((entry) => entry.slug === slug);
  } catch (error) {
    return uiFailure(error);
  }
  if (project === undefined) return { ok: false as const, error: null };
  if (!project.permissions.includes('grant.manage')) {
    return { ok: true as const, project, grants: [] as GrantRow[], grantsError: null };
  }

  try {
    const { members } = await client.members.list(slug);
    const grants: GrantRow[] = members.flatMap((member) =>
      member.grants.map((grant) => ({
        id: grant.id,
        principalType: member.principalType,
        principalId: member.principalId,
        role: grant.role,
        roleName: grant.roleName,
        permissions: grant.permissions,
        scope: grant.environment === null ? ('project' as const) : ('environment' as const),
        environmentSlug: grant.environment,
        expiresAt: grant.expiresAt,
      })),
    );
    return { ok: true as const, project, grants, grantsError: null };
  } catch (error) {
    return { ok: true as const, project, grants: [] as GrantRow[], grantsError: failureMessage(error) };
  }
}

/** Where a grant applies, as the API names it: `market`, or `market/prod`. */
export function grantPlace(project: string, environmentSlug: string | null): string {
  return environmentSlug === null ? project : `${project}/${environmentSlug}`;
}

/**
 * Give someone a role at one place. Access is declarative, so asking for what
 * they already hold is not an error, whoever asked first: `existed` says so.
 */
export async function ensureGrant(
  coffre: CoffreClient,
  data: {
    project: string;
    principalType: GrantRow['principalType'];
    principalId: string;
    role: string;
    environmentSlug: string | null;
    expiresAt: string | null;
  },
): Promise<{ existed: boolean }> {
  const place = grantPlace(data.project, data.environmentSlug);
  const role = data.role as Role;
  const { changes } = await coffre.access.set(memberRef(data.principalType, data.principalId), {
    [place]: data.expiresAt === null ? role : { role, until: data.expiresAt },
  });
  return { existed: changes[place] === 'unchanged' };
}

/**
 * Grants as a table: who or where in the first column, then the access, when
 * it lapses, and a revoke.
 *
 * A project's page leads each row with the principal; a user's page leads with
 * the project. Everything after the first column is the same grant either way.
 */
export function GrantsTable({ lead, children }: { lead: ReactNode; children: ReactNode }) {
  return (
    <div className="dt-wrap">
      <table className="dt grants stacks">
        <thead>
          <tr>
            <th className="n">#</th>
            <th className="col-principal">{lead}</th>
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
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

export function GrantRowView({
  number,
  project,
  grant,
  lead,
  leadLabel,
}: {
  number: number;
  project: string;
  grant: GrantRow;
  lead: ReactNode;
  leadLabel: string;
}) {
  const coffre = useCoffre();
  const { pending, error, run } = useAction();
  const label = projectAccessLabel(grant);
  const expired = grant.expiresAt !== null && new Date(grant.expiresAt).getTime() < Date.now();

  return (
    <>
      <tr>
        <td className="n">{number}</td>
        <td className="col-lead" data-label={leadLabel}>
          {lead}
        </td>
        <td className="col-access" data-label="Permissions">
          <span className={`tag${grant.role === 'owner' ? ' tag-violet' : ''}`}>{label}</span>
        </td>
        <td
          className={`col-expires cell-mono cell-muted${grant.expiresAt === null ? ' is-never' : ''}`}
          data-label="Expires"
        >
          {grant.expiresAt === null ? (
            'never'
          ) : (
            <>
              <span className="narrow-only">expires </span>
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
                () =>
                  coffre.access.set(memberRef(grant.principalType, grant.principalId), {
                    [grantPlace(project, grant.environmentSlug)]: null,
                  }),
                () => toast.success(`Revoked ${label} on ${project} from ${grant.principalId}`),
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
