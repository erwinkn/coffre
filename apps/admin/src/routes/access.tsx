import { createFileRoute, Link } from '@tanstack/react-router';
import { listPrincipals } from '../lib/server';
import { EmptyState, Notice, Tip } from '../components/ui';
import { ChevronRight, Users } from '../components/icons';

/**
 * Who holds what, across every project you administer.
 *
 * The inverse of the per-project access table, and the query you actually want
 * when someone leaves: "what does this person still hold?" Root admins are
 * listed too -- they hold everything from configuration, and an access review
 * that silently omitted them would be worse than useless.
 */
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
            Every principal and what they can reach. The question you want when someone
            leaves, answered in one place rather than project by project.
          </p>
        </div>
      </div>

      {!result.ok ? (
        <Notice tone="bad">{result.error}</Notice>
      ) : (
        <div className="card">
          {result.principals.length === 0 ? (
            <EmptyState icon={<Users size={26} />} title="No principals visible">
              You see principals only on projects where you hold{' '}
              <span className="mono">grant.manage</span>. This list is empty because no
              project qualifies, not because nobody has access.
            </EmptyState>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Principal</th>
                    <th className="shrink">Type</th>
                    <th>Holds</th>
                  </tr>
                </thead>
                <tbody>
                  {result.principals.map((principal) => (
                    <tr key={`${principal.principalType}:${principal.principalId}`}>
                      <td className="wrap mono">
                        {principal.principalId}
                        {principal.isRootAdmin && (
                          <>
                            {' '}
                            <Tip label="Granted by COFFRE_ROOT_ADMINS, not by a row in the grants table.">
                              <span className="pill pill-accent">root admin</span>
                            </Tip>
                          </>
                        )}
                      </td>
                      <td>
                        <span className="pill pill-muted">{principal.principalType}</span>
                      </td>
                      <td className="wrap">
                        {principal.isRootAdmin && principal.grants.length === 0 ? (
                          <span className="meta">Everything, from configuration.</span>
                        ) : (
                          <div className="stack" style={{ gap: 'var(--space-2)' }}>
                            {principal.grants.map((grant, index) => (
                              <span
                                key={index}
                                className="cluster"
                                style={{ gap: 'var(--space-2)' }}
                              >
                                <Link
                                  className="mono"
                                  to="/projects/$project"
                                  params={{ project: grant.project }}
                                >
                                  {grant.project}
                                </Link>
                                <ChevronRight size={12} className="crumb-sep" />
                                <span className="mono meta">{grant.scope}</span>
                                <span className="pill">{grant.role}</span>
                                {grant.expiresAt !== null && (
                                  <span className="meta numeric">
                                    until {grant.expiresAt.slice(0, 10)}
                                  </span>
                                )}
                              </span>
                            ))}
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </>
  );
}
