import { Link, useRouter, type ErrorComponentProps } from '@tanstack/react-router';
import { ClosedDoor } from './page';
import { AlertTriangle, Search } from './icons';

/** A path that matches no page. */
export function NotFound() {
  return (
    <ClosedDoor
      icon={<Search size={18} />}
      label="404"
      title="Nothing at this address"
      actions={
        <Link className="btn" to="/projects">
          All projects
        </Link>
      }
    >
      If you followed a link to a project or environment, it may have been renamed or
      archived.
    </ClosedDoor>
  );
}

/**
 * A loader or render failure the page itself did not anticipate.
 *
 * Deliberately says nothing about the error's contents: they can include
 * server detail that has no business on screen. Retrying re-runs the loaders.
 */
export function RouteError({ reset }: ErrorComponentProps) {
  const router = useRouter();
  return (
    <ClosedDoor
      icon={<AlertTriangle size={18} />}
      label="Something went wrong"
      title="This page could not be shown"
      actions={
        <>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => {
              reset();
              void router.invalidate();
            }}
          >
            Try again
          </button>
          <Link className="btn" to="/projects">
            All projects
          </Link>
        </>
      }
    >
      coffre could not load this page, and nothing was read or written. If it keeps
      happening, the service or its database may be down.
    </ClosedDoor>
  );
}
