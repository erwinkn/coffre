import { useState } from 'react';
import { Link, useRouterState } from '@tanstack/react-router';
import type { ProjectSummary } from '../lib/api';
import { ThemeToggle } from './theme';
import { ChevronRight, Folder, Ledger, Users, Vault } from './icons';

type Props = {
  projects: ProjectSummary[];
  principal: { type: 'user' | 'service'; id: string } | null;
  instanceRole: 'user' | 'owner' | 'root-admin' | null;
};

/** Marks the current route without each link having to compare paths itself. */
const CURRENT = { 'aria-current': 'page' } as const;

/**
 * Primary navigation.
 *
 * The project/environment tree lives here rather than only on the index,
 * because "jump from market/dev to market/prod" is the single most common
 * movement in the app and it used to cost two page loads.
 */
export function Sidebar({ projects, principal, instanceRole }: Props) {
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
      <div>
        <Link className="brand" to="/projects">
          <Vault size={20} className="brand-mark" />
          coffre
        </Link>
        <span className="brand-tag">Secrets, with an audit log</span>
      </div>

      <nav className="nav-group" aria-label="Sections">
        <span className="nav-label">Projects</span>

        {active.length === 0 ? (
          <span className="nav-sub" style={{ opacity: 0.7 }}>
            none visible
          </span>
        ) : (
          active.map((project) => {
            const environments = project.environments.filter((e) => e.archivedAt === null);
            const expanded = toggled[project.slug] ?? project.slug === current;
            const treeId = `nav-tree-${project.slug}`;

            return (
              <div key={project.slug}>
                <div className="nav-row">
                  {environments.length === 0 ? (
                    // Keeps the labels of childless projects on the same
                    // vertical line as everything else.
                    <span className="nav-toggle-space" aria-hidden />
                  ) : (
                    <button
                      type="button"
                      className="nav-toggle"
                      aria-expanded={expanded}
                      aria-controls={treeId}
                      aria-label={`${expanded ? 'Collapse' : 'Expand'} ${project.slug}`}
                      onClick={() =>
                        setToggled((state) => ({ ...state, [project.slug]: !expanded }))
                      }
                    >
                      <ChevronRight size={13} />
                    </button>
                  )}

                  <Link
                    className="nav-item grow"
                    to="/projects/$project"
                    params={{ project: project.slug }}
                    // Without `exact`, the project stays marked as current while
                    // you are inside one of its environments, and two things in
                    // the tree claim to be the page you are on.
                    activeOptions={{ exact: true }}
                    activeProps={CURRENT}
                  >
                    <Folder size={15} />
                    {project.slug}
                    <span className="nav-count">{environments.length}</span>
                  </Link>
                </div>

                {environments.length > 0 && expanded && (
                  <div className="nav-tree" id={treeId}>
                    {environments.map((environment) => (
                      <Link
                        key={environment.slug}
                        className="nav-sub"
                        to="/projects/$project/$environment"
                        params={{ project: project.slug, environment: environment.slug }}
                        activeProps={CURRENT}
                      >
                        {environment.slug}
                      </Link>
                    ))}
                  </div>
                )}
              </div>
            );
          })
        )}
      </nav>

      <nav className="nav-group" aria-label="Administration">
        <span className="nav-label">Admin</span>
        {(instanceRole === 'owner' || instanceRole === 'root-admin') && (
          <Link className="nav-item" to="/access" activeProps={CURRENT}>
            <Users size={15} />
            Users
          </Link>
        )}
        <Link className="nav-item" to="/audit" activeProps={CURRENT}>
          <Ledger size={15} />
          Audit log
        </Link>
      </nav>

      <div className="sidebar-foot">
        <div className="identity">
          {principal === null ? (
            <Link className="nav-item" to="/login" style={{ padding: 0 }}>
              Sign in
            </Link>
          ) : (
            <>
              <span className="identity-avatar" aria-hidden>
                {principal.id.slice(0, 1)}
              </span>
              <span className="identity-text">
                <span className="identity-name" title={principal.id}>
                  {principal.id}
                </span>
                <span className="identity-role">
                  {principal.type === 'service'
                    ? 'Service account'
                    : instanceRole === 'root-admin'
                      ? 'Root admin'
                      : instanceRole === 'owner'
                        ? 'Owner'
                        : 'User'}
                </span>
              </span>
            </>
          )}
          <span style={{ marginLeft: 'auto' }}>
            <ThemeToggle />
          </span>
        </div>
      </div>
    </aside>
  );
}
