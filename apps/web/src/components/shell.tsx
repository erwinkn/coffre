import { useEffect, useState, type ReactNode } from 'react';
import { Link, useNavigate, useRouterState } from '@tanstack/react-router';
import { Dialog, DropdownMenu } from 'radix-ui';
import type { ProjectSummary } from '../shared/models';
import type { UiCapabilities } from '../lib/capabilities';
import { isActiveAccessibleEnvironment } from '../lib/project-environments';
import { AdministrationItems } from './affordances';
import { CommandPalette } from './command-palette';
import { ThemeMenuItems } from './theme';
import { Tile } from './tile';
import { Tip } from './ui';
import {
  Check,
  ChevronsUpDown,
  Folder,
  GitHub,
  Key,
  Ledger,
  Mark,
  Menu,
  Settings,
  Users,
  X,
} from './icons';

type Principal = { type: 'user' | 'service'; id: string } | null;
type InstanceRole = 'user' | 'owner' | 'root-admin' | null;

type ShellProps = {
  projects: ProjectSummary[];
  principal: Principal;
  instanceRole: InstanceRole;
  capabilities: UiCapabilities;
  children: ReactNode;
};

const REPOSITORY = 'https://github.com/equisafe/coffre';

/** Marks the current route without each link having to compare paths itself. */
const CURRENT = { 'aria-current': 'page' } as const;

export function roleLabel(principal: Principal, instanceRole: InstanceRole): string {
  if (principal?.type === 'service') return 'Token';
  if (instanceRole === 'root-admin') return 'Root admin';
  if (instanceRole === 'owner') return 'Owner';
  return 'Member';
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
 * The application frame: a sidebar of sections with your account at its top,
 * and a bar across the content with search on the right.
 *
 * Inside a project, the left of that bar is the path to where you are, and
 * each step of it switches: that is the only place project and environment
 * navigation lives outside the pages themselves. Everywhere else the page's
 * own title says where you are, so the bar leaves it out rather than repeat it.
 */
export function Shell({ projects, principal, instanceRole, capabilities, children }: ShellProps) {
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const [drawerOpen, setDrawerOpen] = useState(false);

  // Following a link in the drawer should land on the page, not leave the
  // navigation covering it.
  useEffect(() => setDrawerOpen(false), [pathname]);

  return (
    <div className="shell">
      <aside className="sidebar">
        <Sidebar principal={principal} instanceRole={instanceRole} capabilities={capabilities} />
      </aside>

      <div className="main">
        <header className="header">
          <Dialog.Root open={drawerOpen} onOpenChange={setDrawerOpen}>
            <Dialog.Trigger asChild>
              <button
                type="button"
                className="btn btn-quiet btn-icon header-menu"
                aria-label="Open navigation"
              >
                <Menu size={18} />
              </button>
            </Dialog.Trigger>
            <Dialog.Portal>
              <Dialog.Overlay className="overlay" />
              <Dialog.Content className="drawer" aria-describedby={undefined}>
                <Dialog.Title className="visually-hidden">Navigation</Dialog.Title>
                <Sidebar
                  principal={principal}
                  instanceRole={instanceRole}
                  capabilities={capabilities}
                  close={
                    <Dialog.Close asChild>
                      <button
                        type="button"
                        className="btn btn-quiet btn-sm btn-icon"
                        aria-label="Close navigation"
                      >
                        <X size={16} />
                      </button>
                    </Dialog.Close>
                  }
                />
              </Dialog.Content>
            </Dialog.Portal>
          </Dialog.Root>

          <Breadcrumbs
            pathname={pathname}
            projects={projects}
            canListPrincipals={capabilities.canManageGrants}
          />

          <div className="header-end">
            <CommandPalette projects={projects} capabilities={capabilities} />
            <Tip label="coffre on GitHub">
              <a
                className="btn btn-quiet btn-icon"
                href={REPOSITORY}
                target="_blank"
                rel="noreferrer"
                aria-label="coffre on GitHub"
              >
                <GitHub size={16} />
              </a>
            </Tip>
          </div>
        </header>

        <main className="content" id="content">
          {children}
        </main>
      </div>
    </div>
  );
}

/** The sidebar's contents, shared by the wide layout and the narrow drawer. */
function Sidebar({
  principal,
  instanceRole,
  capabilities,
  close,
}: {
  principal: Principal;
  instanceRole: InstanceRole;
  capabilities: UiCapabilities;
  close?: ReactNode;
}) {
  return (
    <>
      <div className="sidebar-head">
        <AccountMenu principal={principal} instanceRole={instanceRole} />
        {close}
      </div>

      <nav className="sidebar-nav" aria-label="Sections">
        <NavLink to="/projects" label="Projects" icon={<Folder size={16} />} />
        <AdministrationItems
          capabilities={capabilities}
          users={
            <>
              <NavLink to="/users" label="Users" icon={<Users size={16} />} />
              <NavLink to="/tokens" label="Tokens" icon={<Key size={16} />} />
            </>
          }
          audit={<NavLink to="/audit" label="Audit" icon={<Ledger size={16} />} />}
        />
        <NavLink to="/settings" label="Settings" icon={<Settings size={16} />} />
      </nav>

      <div className="sidebar-foot">
        <Brand />
      </div>
    </>
  );
}

function NavLink({
  to,
  label,
  icon,
}: {
  to: '/projects' | '/users' | '/tokens' | '/audit' | '/settings';
  label: string;
  icon: ReactNode;
}) {
  // Matching is by prefix, so Projects stays current inside a project and
  // Audit stays current whatever its filters.
  return (
    <Link className="nav-link" to={to} activeProps={CURRENT}>
      {icon}
      {label}
    </Link>
  );
}

function AccountMenu({
  principal,
  instanceRole,
}: {
  principal: Principal;
  instanceRole: InstanceRole;
}) {
  const navigate = useNavigate();
  if (principal === null) return null;

  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button type="button" className="account" title={principal.id}>
          <span className="avatar" aria-hidden>
            {principal.id.slice(0, 1)}
          </span>
          <span className="account-text">
            <span className="account-name">{principal.id}</span>
            <span className="account-role">{roleLabel(principal, instanceRole)}</span>
          </span>
          <ChevronsUpDown size={14} className="account-chevron" />
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          className="menu menu-account"
          align="start"
          sideOffset={6}
        >
          <DropdownMenu.Item className="menu-item" onSelect={() => navigate({ to: '/settings' })}>
            <Settings size={15} />
            Settings
          </DropdownMenu.Item>

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

/**
 * The path to the project or environment you are in, where each step also
 * switches: one click on `prod` lists its siblings. Absent everywhere else.
 */
function Breadcrumbs({
  pathname,
  projects,
  canListPrincipals,
}: {
  pathname: string;
  projects: ProjectSummary[];
  canListPrincipals: boolean;
}) {
  const [section, projectSlug, environmentSlug] = pathname
    .split('/')
    .filter((segment) => segment !== '')
    .map(decodeURIComponent);

  // A user's or token's own page sits under its list, like an environment
  // under its project. Someone who manages one project's access reaches the
  // page without being able to open the list, so the root is then just a label.
  if ((section === 'users' || section === 'tokens') && projectSlug !== undefined) {
    const label = <span>{section === 'users' ? 'Users' : 'Tokens'}</span>;
    return (
      <nav className="crumbs" aria-label="Breadcrumb">
        {canListPrincipals ? (
          <Link className="crumb-link crumb-root" to={section === 'users' ? '/users' : '/tokens'}>
            {label}
          </Link>
        ) : (
          <span className="crumb-link crumb-root">{label}</span>
        )}
        <span className="crumb-sep" aria-hidden>
          /
        </span>
        <span className="crumb">
          <span className="crumb-link" aria-current="page">
            <span>{projectSlug}</span>
          </span>
        </span>
      </nav>
    );
  }

  if (section !== 'projects' || projectSlug === undefined) return null;

  const active = projects.filter((project) => project.archivedAt === null);
  const project = projects.find((entry) => entry.slug === projectSlug);

  return (
    <nav className="crumbs" aria-label="Breadcrumb">
      <Link className="crumb-link crumb-root" to="/projects">
        <span>Projects</span>
      </Link>

      <span className="crumb-sep" aria-hidden>
        /
      </span>
      <ProjectCrumb slug={projectSlug} current={environmentSlug === undefined} projects={active} />

      {environmentSlug !== undefined && (
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
    </nav>
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
