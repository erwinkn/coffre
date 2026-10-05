import { Link } from '@tanstack/react-router';
import type { PrincipalReport, RemovedPrincipal } from '../shared/models';
import { Card } from './page';
import { EmptyState, Notice, Timestamp } from './ui';
import { PrincipalLink } from './principal';
import { ChevronRight, Key, User } from './icons';
import { serviceName } from '@coffre/client';

/**
 * The part of a user's or token's page that answers "if they left, what would
 * we have to change?". Owners only, and most useful once someone is removed:
 * everything that let them in is gone by then, but what they saw is not.
 */
export function PrincipalReportCards({ report }: { report: PrincipalReport }) {
  const removed = report.status === 'removed';
  const person = report.principalType === 'user';
  return (
    <>
      <SeenValues report={report} removed={removed} person={person} />
      {report.issuedTokens.length > 0 && <IssuedTokens report={report} />}
    </>
  );
}

export function RemovedNotice({ report }: { report: PrincipalReport }) {
  const person = report.principalType === 'user';
  return (
    <div className="report-notice">
      <Notice>
        Removed
        {report.removedBy !== null && (
          <>
            {' '}by <span className="mono">{report.removedBy}</span>
          </>
        )}
        {report.removedAt !== null && (
          <>
            {' '}on <Timestamp iso={report.removedAt} />
          </>
        )}
        .{' '}
        {person
          ? 'Their project access, sessions, CLI logins and linked sign-in accounts were revoked at the same time, so adding them again starts from nothing.'
          : 'Its project access and every token issued to it were revoked at the same time, so adding it again starts from nothing.'}
      </Notice>
    </div>
  );
}

/**
 * The people or service accounts removed from the directory, under the live ones.
 * Removal ends their access but not the work it leaves, so they stay one click
 * away until every value they saw has been rotated.
 */
export function RemovedList({
  principalType,
  removed,
}: {
  principalType: RemovedPrincipal['principalType'];
  removed: RemovedPrincipal[];
}) {
  const users = principalType === 'user';
  const rows = removed.filter((principal) => principal.principalType === principalType);
  if (rows.length === 0) return null;
  return (
    <>
      <h2 className="section-title">Removed</h2>
      <section className="card" aria-label={users ? 'Removed users' : 'Removed service accounts'}>
        <div className="dt-wrap">
          <table className="dt directory stacks">
            <thead>
              <tr>
                <th className="n">#</th>
                <th className="col-principal">
                  <span className="th">
                    {users ? <User size={14} /> : <Key size={14} />}
                    {users ? 'Email' : 'Name'}
                  </span>
                </th>
                <th className="col-role">Still to rotate</th>
                <th className="col-actions">
                  <span className="visually-hidden">Report</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((principal, index) => (
                <tr key={principal.principalId} className="row-link">
                  <td className="n">{index + 1}</td>
                  <td className="col-lead" data-label={users ? 'Email' : 'Name'}>
                    <PrincipalLink type={principal.principalType} id={principal.principalId} stretch />
                  </td>
                  <td className="col-role" data-label="Still to rotate">
                    {principal.toRotate === 0 ? (
                      <span className="cell-muted">Nothing</span>
                    ) : (
                      `${principal.toRotate} ${principal.toRotate === 1 ? 'value' : 'values'}`
                    )}
                  </td>
                  {/* The row opens the report; the chevron says it does. */}
                  <td className="col-actions col-open cell-muted" aria-hidden="true">
                    <ChevronRight size={16} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <p className="hint section-foot">
        {users ? 'They' : 'These'} can no longer sign in. Each page lists the values{' '}
        {users ? 'they' : 'it'} saw that nobody has changed since.
      </p>
    </>
  );
}

function SeenValues({
  report,
  removed,
  person,
}: {
  report: PrincipalReport;
  removed: boolean;
  person: boolean;
}) {
  const they = person ? 'they' : 'it';
  const description = removed
    ? `Values ${they} read or wrote that nobody has changed since, so ${they} may still hold them. Rotate each where it comes from, such as a new API key or database password, then save the new value here and it leaves this list.`
    : `Current values ${they} ${person ? 'have' : 'has'} read or written: the ones to rotate if ${they} ${person ? 'leave' : 'is retired'}. Saving a new version takes a value off.`;

  return (
    <Card
      labelledBy="seen-values"
      title={removed ? 'Still to rotate' : 'Values seen'}
      description={description}
      actions={
        report.rotated > 0 && (
          <span className="card-aside">{report.rotated} already rotated</span>
        )
      }
    >
      {report.exposed.length === 0 ? (
        <EmptyState title={removed ? 'Nothing left to rotate' : 'No current values seen'}>
          {report.rotated > 0
            ? `Every value ${they} saw has had a new version since.`
            : `${person ? 'They have' : 'It has'} not read or written a value that is still current.`}
        </EmptyState>
      ) : (
        <div className="dt-wrap">
          <table className="dt report-values">
            <thead>
              <tr>
                <th>Secret</th>
                <th className="col-shrink">Version</th>
                <th className="col-shrink">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {report.exposed.map((secret) => (
                <tr key={`${secret.project}/${secret.environment}/${secret.key}`}>
                  <td>
                    <Link
                      className="cell-link mono"
                      to="/projects/$project/$environment"
                      params={{ project: secret.project, environment: secret.environment }}
                      search={{ filter: secret.key }}
                    >
                      <span className="report-path">
                        {secret.project}/{secret.environment}/
                      </span>
                      {secret.key}
                    </Link>
                  </td>
                  <td className="col-shrink cell-mono cell-muted">v{secret.version}</td>
                  <td className="col-shrink nowrap">
                    {secret.how === 'wrote' ? 'Wrote' : 'Read'}{' '}
                    <Timestamp iso={secret.at} display="relative" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function IssuedTokens({ report }: { report: PrincipalReport }) {
  return (
    <Card
      labelledBy="issued-tokens"
      title="Bearer tokens they issued"
      description="Bearer tokens they issued to service accounts that still work. Each was shown to them once, when it was made; revoke any they may have kept a copy of."
    >
      <div className="dt-wrap">
        <table className="dt report-tokens">
          <thead>
            <tr>
              <th>Token</th>
              <th className="col-shrink">Expires</th>
              <th className="col-shrink col-hide-narrow">Last used</th>
            </tr>
          </thead>
          <tbody>
            {report.issuedTokens.map((token) => (
              <tr key={token.id}>
                <td>
                  <span className="cell-stack">
                    <Link className="cell-link mono" to="/tokens/$token" params={{ token: serviceName(token.service) }}>
                      service:{serviceName(token.service)}
                    </Link>
                    <small>
                      {token.label ?? 'No label'} · <span className="mono">{token.hint}</span>
                    </small>
                  </span>
                </td>
                <td className="col-shrink nowrap">
                  <Timestamp iso={token.expiresAt} display="relative" />
                </td>
                <td className="col-shrink col-hide-narrow nowrap">
                  {token.lastUsedAt === null ? (
                    <span className="cell-muted">Never</span>
                  ) : (
                    <Timestamp iso={token.lastUsedAt} display="relative" />
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
