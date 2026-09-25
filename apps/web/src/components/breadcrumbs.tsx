import { Fragment } from 'react';
import { Link, useRouterState } from '@tanstack/react-router';

const NAMED: Record<string, string> = {
  '/projects': 'Projects',
  '/access': 'Directory',
  '/audit': 'Audit log',
};

function Sep() {
  return (
    <span className="crumb-sep" aria-hidden>
      /
    </span>
  );
}

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
        <span className="crumb-current" aria-current="page">
          {named}
        </span>
      </nav>
    );
  }

  // Everything else is /projects/$project or /projects/$project/$environment.
  const segments = pathname.split('/').filter((segment) => segment !== '');
  if (segments[0] !== 'projects') {
    return <nav className="crumbs" aria-label="Breadcrumb" />;
  }
  const [, project, environment] = segments.map(decodeURIComponent);

  return (
    <nav className="crumbs" aria-label="Breadcrumb">
      <Link to="/projects">Projects</Link>

      {project !== undefined && (
        <Fragment key="project">
          <Sep />
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
          <Sep />
          <span className="crumb-current mono" aria-current="page">
            {environment}
          </span>
        </Fragment>
      )}
    </nav>
  );
}
