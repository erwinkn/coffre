import { coffreFetch, type GrantRow, type ProjectSummary } from '../../lib/api';
import { ProjectClient } from './project-client';

export const dynamic = 'force-dynamic';

type Params = Promise<{ project: string }>;

export default async function ProjectPage({ params }: { params: Params }) {
  const { project: projectSlug } = await params;

  const projects = await coffreFetch<{ projects: ProjectSummary[] }>('/v1/admin/projects');
  if (!projects.ok) {
    return (
      <>
        <h1>{projectSlug}</h1>
        <div className="notice bad">{projects.error}</div>
        <a href="/">Back to projects</a>
      </>
    );
  }

  const project = projects.data.projects.find((entry) => entry.slug === projectSlug);
  if (!project) {
    return (
      <>
        <h1>{projectSlug}</h1>
        <div className="notice bad">No such project, or you have no grant on it.</div>
        <a href="/">Back to projects</a>
      </>
    );
  }

  // Only project admins may see the grant list, so a non-admin viewer gets the
  // page without it rather than an error page.
  const grants =
    project.capability === 'admin'
      ? await coffreFetch<{ grants: GrantRow[] }>(
          `/v1/admin/projects/${projectSlug}/grants`,
        )
      : null;

  return (
    <>
      <div className="spread">
        <div>
          <h1>{project.slug}</h1>
          <p className="sub">{project.name}</p>
        </div>
        <span className={`pill ${project.capability === 'admin' ? 'admin' : ''}`}>
          {project.capability}
        </span>
      </div>

      <ProjectClient
        project={project}
        grants={grants?.ok ? grants.data.grants : []}
        grantsError={grants && !grants.ok ? grants.error : null}
      />
    </>
  );
}
