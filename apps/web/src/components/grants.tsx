import type { ReactNode } from 'react';
import { toast } from 'sonner';
import { revokeGrant } from '../server-functions/access';
import { useAction } from '../lib/use-action';
import { projectAccessLabel } from '../lib/project-access';
import type { GrantRow } from '../shared/models';
import { ConfirmButton, ErrorLine, Spinner } from './ui';
import { Clock, ShieldCheck } from './icons';

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
                () => revokeGrant({ data: { project, grantId: grant.id } }),
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
