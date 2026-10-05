import type { ReactNode } from 'react';
import { grantId, revokeGrant, type GrantVars } from '../lib/changes';
import type { FailedAdd } from '../lib/optimistic';
import { useCoffre } from '../lib/coffre';
import { projectAccessLabel } from '../lib/project-access';
import { everyProjectPlace } from './every-project';
import { keys } from '../lib/queries';
import { useChange, useChangeStatus } from '../lib/use-change';
import type { GrantRow } from '../shared/models';
import { RowFailure, RowPending, rowClass } from './row-state';
import { ConfirmButton } from './ui';
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
  const revoke = useChange(revokeGrant(useCoffre(), project));
  const { status, dismiss } = useChangeStatus(keys.grants(project));
  const state = status(grantId(grant));
  // A grant on every project is shown where it reaches, and changed only by owners, with the CLI.
  const everywhere = grant.scope === 'every-project';
  const label = everywhere ? `${everyProjectPlace(grant.environmentSlug)} · ${grant.roleName}` : projectAccessLabel(grant);
  const expired = grant.expiresAt !== null && new Date(grant.expiresAt).getTime() < Date.now();

  return (
    <>
      <tr className={rowClass(state)}>
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
            'Never'
          ) : (
            <>
              <span className="narrow-only">Expires </span>
              {grant.expiresAt.slice(0, 10)}
              {expired && (
                <>
                  {' '}
                  <span className="tag tag-red">Expired</span>
                </>
              )}
            </>
          )}
        </td>
        <td className="col-actions">
          {state.state === 'pending' ? (
            <RowPending status={state} />
          ) : everywhere ? (
            <span className="cell-muted" title="Owners change grants on every project with coffre grant '*' and coffre revoke '*'">
              every project
            </span>
          ) : (
            <ConfirmButton
              trigger={<button className="act act-danger">Revoke</button>}
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
              onConfirm={() => revoke(grant)}
            />
          )}
        </td>
      </tr>
      <RowFailure
        status={state}
        columns={5}
        onDismiss={() => state.state === 'failed' && dismiss(state.mutationId)}
      />
    </>
  );
}

/**
 * Grants the server refused to give: rolled back, so no row of theirs is
 * left, and listed here, after the table's rows, saying why.
 */
export function RefusedGrants({ refused }: { refused: RefusedGrant[] }) {
  return refused.map(({ mutationId, vars, status, dismiss }) => (
    <RowFailure key={mutationId} status={status} columns={5} onDismiss={dismiss}>
      {vars.principalId} was not given {vars.roleName.toLowerCase()}.
    </RowFailure>
  ));
}

type RefusedGrant = FailedAdd<GrantVars> & { dismiss: () => void };

/** The grants of one kind the server refused to give in a project, still to be said. */
export function useRefusedGrants(project: string, grants: GrantRow[], principalType?: GrantRow['principalType']): RefusedGrant[] {
  const { failedAdds, dismiss } = useChangeStatus(keys.grants(project));
  return failedAdds<GrantVars>(grants.map(grantId))
    .filter(({ vars }) => principalType === undefined || vars.principalType === principalType)
    .map((refused) => ({ ...refused, dismiss: () => dismiss(refused.mutationId) }));
}
