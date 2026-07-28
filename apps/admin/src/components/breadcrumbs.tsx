import { Fragment } from 'react';
import { Link, useRouterState } from '@tanstack/react-router';
import { ChevronRight } from './icons';

const NAMED: Record<string, string> = {
  '/projects': 'Projects',
  '/access': 'Users',
  '/audit': 'Audit log',
  '/login': 'Sign in',
};

/**
 * Where you are, and one click back to everything above it.
 *
 * Derived from the path rather than passed down, so no page has to remember to
 * declare its own trail -- the failure mode being one route that silently
 * renders without breadcrumbs.
 */
export function Breadcrumbs() {
  const pathname = useRouterState({ select: (state) => state.location.pathname });

  const named = NAMED[pathname];
  if (named !== undefined) {
    return (
      <nav className="crumbs" aria-label="Breadcrumb">
        <span className="crumb-current">{named}</span>
      </nav>
    );
  }

  // Everything else is /projects/$project or /projects/$project/$environment.
  const segments = pathname.split('/').filter((segment) => segment !== '');
  const [, project, environment] =
    segments[0] === 'projects' ? segments.map(decodeURIComponent) : [];

  return (
    <nav className="crumbs" aria-label="Breadcrumb">
      <Link to="/projects">Projects</Link>

      {project !== undefined && (
        <Fragment key="project">
          <ChevronRight size={13} className="crumb-sep" />
          {environment === undefined ? (
            <span className="crumb-current mono" aria-current="page">
              {project}
            </span>
          ) : (
            <Link className="mono" to="/projects/$project" params={{ project }}>
              {project}
            </Link>
          )}
        </Fragment>
      )}

      {environment !== undefined && (
        <Fragment key="environment">
          <ChevronRight size={13} className="crumb-sep" />
          <span className="crumb-current mono" aria-current="page">
            {environment}
          </span>
        </Fragment>
      )}
    </nav>
  );
}
