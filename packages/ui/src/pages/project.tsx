import { Link, Outlet } from '@tanstack/react-router';
import { useSuspenseQuery } from '@tanstack/react-query';

import { useCoffre } from '../lib/coffre';
import { useMounted } from '../lib/mounted';
import { projectOf, queries } from '../lib/queries';
import { Notice } from '../components/ui';
import { ClosedDoor, PageHeader } from '../components/page';
import { PageTabs } from '../components/tabs';
import { Folder, Key, Layers, Settings, Users } from '../components/icons';
import { pageRoute } from '../lib/page-route';
import type { project } from '../options';

const Route = pageRoute<typeof project>();

/**
 * A project's page: its header, and its tabs, each a page of its own under
 * this one. Each tab is gated on its own permission, not on one blanket
 * "admin": an access manager can administer grants without being able to
 * rename the project, and the other way round. A tab the deployment left
 * out is not offered.
 */
export function ProjectLayout() {
  const { project: slug } = Route.useParams();
  const mounted = useMounted();
  const { data: projects } = useSuspenseQuery(queries.projects(useCoffre()));
  const result = projectOf(projects, slug);

  if (!result.ok) {
    return (
      <ClosedDoor
        icon={<Folder size={18} />}
        label={<span className="mono">{slug}</span>}
        title="No project here for you"
        actions={
          <Link className="btn" to="/projects">
            All projects
          </Link>
        }
      >
        {result.error ??
          'There is no such project, or you hold no grant on it. The two look the same on purpose: an answer that told them apart would let anyone list project names.'}
      </ClosedDoor>
    );
  }

  const { project: found, managesAccess } = result;
  const params = { project: found.slug };
  return (
    <>
      <PageHeader
        tile={found.slug}
        title={found.name}
        aside={<span className="page-title-slug">{found.slug}</span>}
      />

      {found.archivedAt !== null && (
        <div style={{ marginBottom: '1.25rem' }}>
          <Notice tone="bad">
            <strong>This project is archived.</strong> Its environments serve no reads, to
            people or to machines, until it is restored.
          </Notice>
        </div>
      )}

      <PageTabs label="Project sections">
        {[
          <Link key="environments" to="/projects/$project" params={params} activeOptions={{ exact: true, includeSearch: false }}>
            <Layers size={15} />
            Environments
          </Link>,
          managesAccess && mounted('/projects/$project/users') && (
            <Link key="users" to="/projects/$project/users" params={params}>
              <Users size={15} />
              Users
            </Link>
          ),
          managesAccess && mounted('/projects/$project/service-accounts') && (
            <Link key="service-accounts" to="/projects/$project/service-accounts" params={params}>
              <Key size={15} />
              Service accounts
            </Link>
          ),
          found.permissions.includes('project.manage') && mounted('/projects/$project/settings') && (
            <Link key="settings" to="/projects/$project/settings" params={params}>
              <Settings size={15} />
              Settings
            </Link>
          ),
        ]}
      </PageTabs>

      <Outlet />
    </>
  );
}
