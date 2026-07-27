import { coffreFetch, type Me } from '../lib/api';

export const dynamic = 'force-dynamic';

export default async function ProjectsPage() {
  const me = await coffreFetch<Me>('/v1/me');

  if (!me.ok) {
    return (
      <>
        <h1>Projects</h1>
        <div className="notice bad">
          {me.error}. <a href="/login">Sign in</a> to continue.
        </div>
      </>
    );
  }

  const byProject = new Map<string, typeof me.data.environments>();
  for (const entry of me.data.environments) {
    byProject.set(entry.project, [...(byProject.get(entry.project) ?? []), entry]);
  }

  return (
    <>
      <h1>Projects</h1>
      <p className="sub">
        Environments you hold a grant for. Listing keys is not a read; revealing a value is,
        and is logged.
      </p>

      {byProject.size === 0 ? (
        <div className="card">
          <div className="empty">
            No environments granted to {me.data.principal.id}.
          </div>
        </div>
      ) : (
        [...byProject.entries()].map(([project, environments]) => (
          <section key={project}>
            <h2>{project}</h2>
            <div className="card">
              {environments.map((entry) => (
                <div className="row" key={entry.environment}>
                  <div className="key">
                    <a href={`/${project}/${entry.environment}`}>{entry.environment}</a>
                  </div>
                  <span className={`pill ${entry.capability === 'admin' ? 'admin' : ''}`}>
                    {entry.capability}
                  </span>
                </div>
              ))}
            </div>
          </section>
        ))
      )}
    </>
  );
}
