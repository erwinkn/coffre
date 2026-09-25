import { useState } from 'react';
import { Link, useRouterState } from '@tanstack/react-router';
import type { ProjectSummary } from '../shared/models';
import type { UiCapabilities } from '../lib/capabilities';
import { isActiveAccessibleEnvironment } from '../lib/project-environments';
import { AdministrationNav } from './affordances';
import { ThemeToggle } from './theme';
import { ChevronRight, Mark } from './icons';

type Props = {
  projects: ProjectSummary[];
  principal: { type: 'user' | 'service'; id: string } | null;
  instanceRole: 'user' | 'owner' | 'root-admin' | null;
  capabilities: UiCapabilities;
};

/** Marks the current route without each link having to compare paths itself. */
const CURRENT = { 'aria-current': 'page' } as const;

export function Wordmark({ asLink = true }: { asLink?: boolean }) {
  const body = (
    <>
      <Mark size={20} className="wordmark-mark" />
      coffre
    </>
  );
  return asLink ? (
    <Link className="wordmark" to="/projects" aria-label="coffre, all projects">
      {body}
    </Link>
  ) : (
    <span className="wordmark">{body}</span>
  );
}

export function roleLabel(
  principal: Props['principal'],
  instanceRole: Props['instanceRole'],
): string {
  if (principal?.type === 'service') return 'Service account';
  if (instanceRole === 'root-admin') return 'Root admin';
  if (instanceRole === 'owner') return 'Owner';
  return 'User';
}

/**
 * Primary navigation.
 *
 * The project/environment tree lives here rather than only on the index,
 * because "jump from market/dev to market/prod" is the single most common
 * movement in the app, so it belongs in the persistent navigation.
 */
export function Sidebar({ projects, principal, instanceRole, capabilities }: Props) {
  const active = projects.filter((project) => project.archivedAt === null);

  // Which project you are inside, read off the path the way Breadcrumbs does
  // rather than from params, so this works from the root route.
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const segments = pathname.split('/').filter((segment) => segment !== '');
  const current = segments[0] === 'projects' ? decodeURIComponent(segments[1] ?? '') : '';

  // Only projects you have explicitly clicked open or shut live here. Anything
  // absent falls back to "expanded if it is the one you are in", so walking
  // into a project opens it and walking out closes it again without the tree
  // slowly accumulating every project you have ever visited.
  const [toggled, setToggled] = useState<Record<string, boolean>>({});

  return (
    <aside className="sidebar">
      <Wordmark />

      <nav className="nav-section" aria-label="Projects">
        <span className="caps" aria-hidden>
          Projects
        </span>

        {active.length === 0 ? (
          <span className="nav-empty">None visible to you</span>
        ) : (
          active.map((project) => {
            const environments = project.environments.filter(isActiveAccessibleEnvironment);
            const expanded = toggled[project.slug] ?? project.slug === current;
            const treeId = `nav-tree-${project.slug}`;

            return (
              <div key={project.slug}>
                <div className="nav-project">
                  <Link
                    className="nav-link"
                    to="/projects/$project"
                    params={{ project: project.slug }}
                    // Without `exact`, the project stays marked as current while
                    // you are inside one of its environments, and two things in
                    // the tree claim to be the page you are on.
                    activeOptions={{ exact: true }}
                    activeProps={CURRENT}
                  >
                    {project.slug}
                  </Link>

                  {environments.length > 0 && (
                    <button
                      type="button"
                      className="nav-toggle"
                      aria-expanded={expanded}
                      aria-controls={treeId}
                      aria-label={`${expanded ? 'Hide' : 'Show'} environments of ${project.slug}`}
                      onClick={() =>
                        setToggled((state) => ({ ...state, [project.slug]: !expanded }))
                      }
                    >
                      <ChevronRight size={12} />
                    </button>
                  )}
                </div>

                {environments.length > 0 && expanded && (
                  <div className="nav-tree" id={treeId}>
                    {environments.map((environment) => (
                      <Link
                        key={environment.slug}
                        className="nav-link"
                        to="/projects/$project/$environment"
                        params={{ project: project.slug, environment: environment.slug }}
                        activeProps={CURRENT}
                      >
                        {environment.slug}
                        <span className="count">{environment.details.secretCount}</span>
                      </Link>
                    ))}
                  </div>
                )}
              </div>
            );
          })
        )}
      </nav>

      <AdministrationNav
        capabilities={capabilities}
        users={
          <Link className="nav-link" to="/access" activeProps={CURRENT}>
            Directory
          </Link>
        }
        audit={
          <Link className="nav-link" to="/audit" activeProps={CURRENT}>
            Audit log
          </Link>
        }
      />

      <div className="sidebar-foot">
        {principal !== null && (
          <div className="identity">
            <span className="identity-name" title={principal.id}>
              {principal.id}
            </span>
            <span className="identity-role">{roleLabel(principal, instanceRole)}</span>
          </div>
        )}
        <div className="sidebar-row">
          <ThemeToggle />
        </div>
        <p className="demo-note">Demo instance. Do not store real secrets here.</p>
      </div>
    </aside>
  );
}
