import { coffreFetch, type Me, type ProjectSummary } from '../lib/api';
import { NewProject } from './projects-client';

export const dynamic = 'force-dynamic';

export default async function ProjectsPage() {
  const me = await coffreFetch<Me>('/v1/me');
  const projects = await coffreFetch<{ projects: ProjectSummary[] }>('/v1/admin/projects');

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

  const rows = projects.ok ? projects.data.projects : [];
  const active = rows.filter((project) => project.archivedAt === null);
  const archived = rows.filter((project) => project.archivedAt !== null);

  return (
    <>
      <h1>Projects</h1>
      <p className="sub">
        Listing keys is not a read; revealing a value is, and is logged.
      </p>

      {rows.length === 0 ? (
        <div className="card">
          <div className="empty">No projects visible to {me.data.principal.id}.</div>
        </div>
      ) : (
        <div className="card">
          {active.map((project) => (
            <ProjectRow key={project.slug} project={project} />
          ))}
        </div>
      )}

      <NewProject />

      {archived.length > 0 && (
        <>
          <h2>Archived</h2>
          <div className="card">
            {archived.map((project) => (
              <ProjectRow key={project.slug} project={project} />
            ))}
          </div>
        </>
      )}
    </>
  );
}

function ProjectRow({ project }: { project: ProjectSummary }) {
  const environments = project.environments.filter((e) => e.archivedAt === null);

  return (
    <div className="row">
      <div className="key">
        <a href={`/${project.slug}`}>{project.slug}</a>
        <span className="meta" style={{ marginLeft: 10 }}>
          {project.name}
        </span>
      </div>
      <span className="meta">
        {environments.length} env{environments.length === 1 ? '' : 's'}
      </span>
      {environments.map((environment) => (
        <a
          key={environment.slug}
          className="btn"
          href={`/${project.slug}/${environment.slug}`}
        >
          {environment.slug}
        </a>
      ))}
      <span className={`pill ${project.capability === 'admin' ? 'admin' : ''}`}>
        {project.capability}
      </span>
    </div>
  );
}
