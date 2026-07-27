import { coffreFetch, type GrantRow, type ProjectSummary, type RoleRow } from '../../lib/api';
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

  // Only grant.manage holders may see the access list, so everyone else gets
  // the page without it rather than an error page.
  const canManageGrants = project.permissions.includes('grant.manage');
  const grants = canManageGrants
    ? await coffreFetch<{ grants: GrantRow[] }>(`/v1/admin/projects/${projectSlug}/grants`)
    : null;
  const roles = canManageGrants
    ? await coffreFetch<{ roles: RoleRow[] }>('/v1/admin/roles')
    : null;

  return (
    <>
      <div className="spread">
        <div>
          <h1>{project.slug}</h1>
          <p className="sub">{project.name}</p>
        </div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          {project.permissions.length === 0 ? (
            <span className="pill">no project-scope permissions</span>
          ) : (
            project.permissions.map((permission) => (
              <span className="pill" key={permission}>
                {permission}
              </span>
            ))
          )}
        </div>
      </div>

      <ProjectClient
        project={project}
        grants={grants?.ok ? grants.data.grants : []}
        roles={roles?.ok ? roles.data.roles : []}
        grantsError={grants && !grants.ok ? grants.error : null}
      />
    </>
  );
}
