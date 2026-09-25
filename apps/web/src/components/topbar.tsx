import { Link, useNavigate, useRouterState } from '@tanstack/react-router';
import { DropdownMenu } from 'radix-ui';
import type { ProjectSummary } from '../shared/models';
import type { UiCapabilities } from '../lib/capabilities';
import { isActiveAccessibleEnvironment } from '../lib/project-environments';
import { AdministrationItems, AdministrationNav, hasAdministrationItems } from './affordances';
import { CommandPalette } from './command-palette';
import { ThemeMenuItems } from './theme';
import { Tile } from './tile';
import { Check, ChevronsUpDown, Ledger, Mark, Users } from './icons';

type Principal = { type: 'user' | 'service'; id: string } | null;
type InstanceRole = 'user' | 'owner' | 'root-admin' | null;

/** Marks the current route without each link having to compare paths itself. */
const CURRENT = { 'aria-current': 'page' } as const;

const NAMED: Record<string, string> = {
  '/access': 'Directory',
  '/audit': 'Audit log',
};

export function roleLabel(principal: Principal, instanceRole: InstanceRole): string {
  if (principal?.type === 'service') return 'Service account';
  if (instanceRole === 'root-admin') return 'Root admin';
  if (instanceRole === 'owner') return 'Owner';
  return 'User';
}

export function Brand({ asLink = true }: { asLink?: boolean }) {
  const body = (
    <>
      <span className="brand-mark" aria-hidden>
        <Mark size={16} />
      </span>
      <span className="brand-name">coffre</span>
    </>
  );
  return asLink ? (
    <Link className="brand" to="/projects" aria-label="coffre, all projects">
      {body}
    </Link>
  ) : (
    <span className="brand">{body}</span>
  );
}

/**
 * The top bar: where you are, as a path you can switch at any step, and the
 * few places that are not inside a project.
 *
 * "Jump from market/dev to market/prod" is the most common movement in the
 * app, so the environment in the path is itself a switcher: one click lists
 * its siblings. The path is derived from the URL rather than passed down, so
 * no page has to remember to declare it.
 */
export function TopBar({
  projects,
  principal,
  instanceRole,
  capabilities,
}: {
  projects: ProjectSummary[];
  principal: Principal;
  instanceRole: InstanceRole;
  capabilities: UiCapabilities;
}) {
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const segments = pathname.split('/').filter((segment) => segment !== '');
  const [projectSlug, environmentSlug] =
    segments[0] === 'projects' ? segments.slice(1).map(decodeURIComponent) : [];

  const active = projects.filter((project) => project.archivedAt === null);
  const project = projects.find((entry) => entry.slug === projectSlug);
  const named = NAMED[pathname];

  return (
    <header className="topbar">
      <div className="topbar-inner">
        <Brand />

        <nav className="crumbs" aria-label="Breadcrumb">
          {projectSlug !== undefined && (
            <>
              <span className="crumb-sep" aria-hidden>
                /
              </span>
              <ProjectCrumb
                slug={projectSlug}
                current={environmentSlug === undefined}
                projects={active}
              />
            </>
          )}

          {projectSlug !== undefined && environmentSlug !== undefined && (
            <>
              <span className="crumb-sep" aria-hidden>
                /
              </span>
              <EnvironmentCrumb
                projectSlug={projectSlug}
                slug={environmentSlug}
                environments={project?.environments.filter(isActiveAccessibleEnvironment) ?? []}
              />
            </>
          )}

          {named !== undefined && (
            <>
              <span className="crumb-sep" aria-hidden>
                /
              </span>
              <span className="crumb-link" aria-current="page">
                <span>{named}</span>
              </span>
            </>
          )}
        </nav>

        <div className="topbar-end">
          <AdministrationNav
            capabilities={capabilities}
            users={
              <Link className="topnav-link" to="/access" activeProps={CURRENT}>
                Directory
              </Link>
            }
            audit={
              <Link className="topnav-link" to="/audit" activeProps={CURRENT}>
                Audit log
              </Link>
            }
          />
          <CommandPalette projects={projects} capabilities={capabilities} />
          <AccountMenu
            principal={principal}
            instanceRole={instanceRole}
            capabilities={capabilities}
          />
        </div>
      </div>
    </header>
  );
}

function ProjectCrumb({
  slug,
  current,
  projects,
}: {
  slug: string;
  current: boolean;
  projects: ProjectSummary[];
}) {
  const navigate = useNavigate();
  return (
    <span className="crumb">
      <Link
        className="crumb-link"
        to="/projects/$project"
        params={{ project: slug }}
        aria-current={current ? 'page' : undefined}
      >
        <Tile name={slug} />
        <span className="crumb-project-name">{slug}</span>
      </Link>
      <DropdownMenu.Root>
        <DropdownMenu.Trigger asChild>
          <button type="button" className="crumb-switch" aria-label="Switch project">
            <ChevronsUpDown size={14} />
          </button>
        </DropdownMenu.Trigger>
        <DropdownMenu.Portal>
          <DropdownMenu.Content className="menu" sideOffset={6} align="start">
            <DropdownMenu.Label className="menu-label">Projects</DropdownMenu.Label>
            {projects.map((project) => (
              <DropdownMenu.Item
                key={project.slug}
                className="menu-item"
                onSelect={() =>
                  navigate({ to: '/projects/$project', params: { project: project.slug } })
                }
              >
                <Tile name={project.slug} />
                {project.slug}
                <span className="menu-hint">{project.name}</span>
                {project.slug === slug && <Check size={14} className="menu-check" />}
              </DropdownMenu.Item>
            ))}
            <DropdownMenu.Separator className="menu-sep" />
            <DropdownMenu.Item className="menu-item" onSelect={() => navigate({ to: '/projects' })}>
              All projects
            </DropdownMenu.Item>
          </DropdownMenu.Content>
        </DropdownMenu.Portal>
      </DropdownMenu.Root>
    </span>
  );
}

function EnvironmentCrumb({
  projectSlug,
  slug,
  environments,
}: {
  projectSlug: string;
  slug: string;
  environments: ProjectSummary['environments'];
}) {
  const navigate = useNavigate();
  return (
    <span className="crumb">
      <span className="crumb-link" aria-current="page">
        <span>{slug}</span>
      </span>
      {environments.length > 0 && (
        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild>
            <button type="button" className="crumb-switch" aria-label="Switch environment">
              <ChevronsUpDown size={14} />
            </button>
          </DropdownMenu.Trigger>
          <DropdownMenu.Portal>
            <DropdownMenu.Content className="menu" sideOffset={6} align="start">
              <DropdownMenu.Label className="menu-label">
                Environments in {projectSlug}
              </DropdownMenu.Label>
              {environments.map((environment) => (
                <DropdownMenu.Item
                  key={environment.slug}
                  className="menu-item"
                  onSelect={() =>
                    navigate({
                      to: '/projects/$project/$environment',
                      params: { project: projectSlug, environment: environment.slug },
                    })
                  }
                >
                  <span className="mono">{environment.slug}</span>
                  <span className="menu-hint">
                    {environment.details?.secretCount ?? 0} secret
                    {environment.details?.secretCount === 1 ? '' : 's'}
                  </span>
                  {environment.slug === slug && <Check size={14} className="menu-check" />}
                </DropdownMenu.Item>
              ))}
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>
      )}
    </span>
  );
}

function AccountMenu({
  principal,
  instanceRole,
  capabilities,
}: {
  principal: Principal;
  instanceRole: InstanceRole;
  capabilities: UiCapabilities;
}) {
  const navigate = useNavigate();
  if (principal === null) return null;

  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button type="button" className="avatar" aria-label={`Account: ${principal.id}`}>
          {principal.id.slice(0, 1)}
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content className="menu" sideOffset={8} align="end" style={{ width: '16rem' }}>
          <div className="menu-identity">
            <strong title={principal.id}>{principal.id}</strong>
            <span>{roleLabel(principal, instanceRole)}</span>
          </div>

          {hasAdministrationItems(capabilities) && (
            <>
              <DropdownMenu.Separator className="menu-sep" />
              <AdministrationItems
                capabilities={capabilities}
                users={
                  <DropdownMenu.Item className="menu-item" onSelect={() => navigate({ to: '/access' })}>
                    <Users size={15} />
                    Directory
                  </DropdownMenu.Item>
                }
                audit={
                  <DropdownMenu.Item
                    className="menu-item"
                    onSelect={() => navigate({ to: '/audit', search: {} })}
                  >
                    <Ledger size={15} />
                    Audit log
                  </DropdownMenu.Item>
                }
              />
            </>
          )}

          <DropdownMenu.Separator className="menu-sep" />
          <DropdownMenu.Label className="menu-label">Theme</DropdownMenu.Label>
          <ThemeMenuItems />

          <DropdownMenu.Separator className="menu-sep" />
          <p className="menu-note">
            <span className="dot" aria-hidden />
            Demo instance. Do not store real secrets here.
          </p>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}
