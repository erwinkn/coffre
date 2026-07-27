import { coffreFetch } from '../../lib/api';

export const dynamic = 'force-dynamic';

type Principal = {
  principalType: 'user' | 'service';
  principalId: string;
  isRootAdmin: boolean;
  grants: { project: string; scope: string; role: string; expiresAt: string | null }[];
};

/**
 * Who holds what, across every project you administer.
 *
 * The inverse of the per-project access table, and the query you actually want
 * when someone leaves: "what does this person still hold?" Root admins are
 * listed too -- they hold everything from configuration, and an access review
 * that silently omitted them would be worse than useless.
 */
export default async function AccessPage() {
  const result = await coffreFetch<{ principals: Principal[] }>('/v1/admin/principals');

  return (
    <>
      <h1>Access</h1>
      <p className="sub">Every principal and what they can reach.</p>

      {!result.ok ? (
        <div className="notice bad">{result.error}</div>
      ) : result.data.principals.length === 0 ? (
        <div className="card">
          <div className="empty">No principals visible to you.</div>
        </div>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Principal</th>
                <th>Type</th>
                <th>Holds</th>
              </tr>
            </thead>
            <tbody>
              {result.data.principals.map((principal) => (
                <tr key={`${principal.principalType}:${principal.principalId}`}>
                  <td className="wrap">
                    {principal.principalId}
                    {principal.isRootAdmin && (
                      <span className="pill admin" style={{ marginLeft: 8 }}>
                        root admin
                      </span>
                    )}
                  </td>
                  <td>
                    <span className="pill">{principal.principalType}</span>
                  </td>
                  <td className="wrap">
                    {principal.isRootAdmin && principal.grants.length === 0 ? (
                      <span className="meta">everything, from configuration</span>
                    ) : (
                      principal.grants.map((grant, index) => (
                        <div key={index}>
                          <a href={`/${grant.project}`}>{grant.project}</a>
                          {' / '}
                          {grant.scope} — <strong>{grant.role}</strong>
                          {grant.expiresAt !== null && (
                            <span className="meta"> until {grant.expiresAt.slice(0, 10)}</span>
                          )}
                        </div>
                      ))
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
