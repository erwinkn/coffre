import { coffreFetch, type AuditEntry } from '../../lib/api';
import { VerifyButton } from './verify-button';

export const dynamic = 'force-dynamic';

type Search = Promise<{ decision?: string; actorId?: string }>;

export default async function AuditPage({ searchParams }: { searchParams: Search }) {
  const filters = await searchParams;

  const query = new URLSearchParams({ limit: '200' });
  if (filters.decision === 'deny') query.set('decision', 'deny');
  if (filters.actorId) query.set('actorId', filters.actorId);

  const result = await coffreFetch<{ entries: AuditEntry[] }>(`/v1/audit?${query}`);

  return (
    <>
      <h1>Audit log</h1>
      <p className="sub">Who read which secret, when. Append-only and hash-chained.</p>

      {!result.ok ? (
        <div className="notice bad">{result.error}</div>
      ) : (
        <>
          <VerifyButton />

          <div className="filters">
            <a className="btn" href="/audit">
              All
            </a>
            <a className="btn" href="/audit?decision=deny">
              Denials only
            </a>
          </div>

          <div className="card">
            {result.data.entries.length === 0 ? (
              <div className="empty">No entries.</div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Seq</th>
                    <th>When (UTC)</th>
                    <th>Actor</th>
                    <th>Action</th>
                    <th>Secret</th>
                    <th>Result</th>
                  </tr>
                </thead>
                <tbody>
                  {result.data.entries.map((entry) => (
                    <tr key={entry.seq}>
                      <td>{entry.seq}</td>
                      <td>{entry.occurredAt.replace('T', ' ').slice(0, 23)}</td>
                      <td>
                        {entry.actorId}
                        <span className="pill" style={{ marginLeft: 8 }}>
                          {entry.actorType}
                        </span>
                      </td>
                      <td>{entry.action}</td>
                      <td className="wrap">
                        {(entry.metadata.key as string) ??
                          (entry.metadata.reason as string) ??
                          '-'}
                      </td>
                      <td>
                        <span className={`pill ${entry.decision}`}>{entry.decision}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}
    </>
  );
}
