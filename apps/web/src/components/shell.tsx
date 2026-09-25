import { useEffect, useState, type ReactNode } from 'react';
import { Link, useNavigate, useRouterState } from '@tanstack/react-router';
import { Dialog, DropdownMenu } from 'radix-ui';
import type { ProjectSummary } from '../shared/models';
import type { UiCapabilities } from '../lib/capabilities';
import { isActiveAccessibleEnvironment } from '../lib/project-environments';
import { AdministrationNav } from './affordances';
import { CommandPalette } from './command-palette';
import { ThemeMenuItems } from './theme';
import { Tile } from './tile';
import { Tip } from './ui';
import {
  Check,
  ChevronRight,
  ChevronsUpDown,
  Folder,
  Key,
  Ledger,
  Mark,
  Menu,
  PanelLeft,
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

/** Marks the current route without each link having to compare paths itself. */
const CURRENT = { 'aria-current': 'page' } as const;

const SECTION_TITLE: Record<string, string> = {
  audit: 'Audit',
  members: 'Members',
  tokens: 'Tokens',
  settings: 'Settings',
};

const PANEL_KEY = 'coffre-sidebar';

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

/** Where the path puts you: the section, and inside Projects, which project and environment. */
function useLocationParts() {
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const segments = pathname.split('/').filter((segment) => segment !== '');
  const section = segments[0] ?? 'projects';
  const [projectSlug, environmentSlug] =
    section === 'projects' ? segments.slice(1).map(decodeURIComponent) : [];
  return { pathname, section, projectSlug, environmentSlug };
}

/**
 * The application frame: a rail of sections, the Projects section's own
 * sidebar, and a header whose path is also the way to switch.
 *
 * Only Projects has depth (project, then environment), so only Projects gets
 * a sidebar; Audit, Members, Tokens and Settings are single pages and take the
 * full width. The sidebar folds away for wide tables and remembers that.
 */
export function Shell({ projects, principal, instanceRole, capabilities, children }: ShellProps) {
  const { pathname, section } = useLocationParts();
  const [panelOpen, setPanelOpen] = useState(true);
  const [drawerOpen, setDrawerOpen] = useState(false);

  useEffect(() => {
    try {
      setPanelOpen(localStorage.getItem(PANEL_KEY) !== 'closed');
    } catch {
      // Storage refused; the sidebar simply starts open.
    }
  }, []);

  // Following a link in the drawer should land on the page, not leave the
  // navigation covering it.
  useEffect(() => setDrawerOpen(false), [pathname]);

  function togglePanel(open: boolean) {
    setPanelOpen(open);
    try {
      localStorage.setItem(PANEL_KEY, open ? 'open' : 'closed');
    } catch {
      // Remembering is a convenience, not a requirement.
    }
  }

  const inProjects = section === 'projects';

  return (
    <div className={`shell${inProjects && panelOpen ? ' has-panel' : ''}`}>
      <Rail capabilities={capabilities} principal={principal} instanceRole={instanceRole} />

      {inProjects && panelOpen && (
        <aside className="panel" aria-label="Projects">
          <div className="panel-head">
            <Link className="panel-title" to="/projects">
              Projects
            </Link>
            <Tip label="Hide sidebar" side="right">
              <button
                type="button"
                className="btn btn-quiet btn-sm btn-icon"
                aria-label="Hide sidebar"
                onClick={() => togglePanel(false)}
              >
                <PanelLeft size={15} />
              </button>
            </Tip>
          </div>
          <ProjectTree projects={projects} />
        </aside>
      )}

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
                <div className="panel-head">
                  <Brand />
                  <Dialog.Close asChild>
                    <button
                      type="button"
                      className="btn btn-quiet btn-sm btn-icon"
                      aria-label="Close navigation"
                    >
                      <X size={16} />
                    </button>
                  </Dialog.Close>
                </div>
                <SectionList capabilities={capabilities} />
                <p className="drawer-label">Projects</p>
                <ProjectTree projects={projects} />
              </Dialog.Content>
            </Dialog.Portal>
          </Dialog.Root>

          {inProjects && !panelOpen && (
            <Tip label="Show sidebar">
              <button
                type="button"
                className="btn btn-quiet btn-icon header-panel-toggle"
                aria-label="Show sidebar"
                onClick={() => togglePanel(true)}
              >
                <PanelLeft size={16} />
              </button>
            </Tip>
          )}

          <Breadcrumbs projects={projects} />

          <div className="header-end">
            <CommandPalette projects={projects} capabilities={capabilities} />
          </div>
        </header>

        <main className="content" id="content">
          {children}
        </main>
      </div>
    </div>
  );
}

function Rail({
  capabilities,
  principal,
  instanceRole,
}: {
  capabilities: UiCapabilities;
  principal: Principal;
  instanceRole: InstanceRole;
}) {
  return (
    <nav className="rail" aria-label="Sections">
      <Tip label="coffre" side="right">
        <Link className="rail-brand" to="/projects" aria-label="coffre, all projects">
          <span className="brand-mark" aria-hidden>
            <Mark size={16} />
          </span>
        </Link>
      </Tip>

      <div className="rail-group">
        <RailLink to="/projects" label="Projects" icon={<Folder size={18} />} />
      </div>

      <AdministrationNav
        capabilities={capabilities}
        audit={<RailLink to="/audit" label="Audit" icon={<Ledger size={18} />} />}
        users={
          <>
            <RailLink to="/members" label="Members" icon={<Users size={18} />} />
            <RailLink to="/tokens" label="Tokens" icon={<Key size={18} />} />
          </>
        }
      />

      <div className="rail-foot">
        <RailLink to="/settings" label="Settings" icon={<Settings size={18} />} />
        <AccountMenu principal={principal} instanceRole={instanceRole} />
      </div>
    </nav>
  );
}

function RailLink({
  to,
  label,
  icon,
}: {
  to: '/projects' | '/audit' | '/members' | '/tokens' | '/settings';
  label: string;
  icon: ReactNode;
}) {
  return (
    <Tip label={label} side="right">
      <Link className="rail-link" to={to} aria-label={label} activeProps={CURRENT}>
        {icon}
      </Link>
    </Tip>
  );
}

/** The rail's sections as a labelled list, for the narrow-screen drawer. */
function SectionList({ capabilities }: { capabilities: UiCapabilities }) {
  return (
    <nav className="section-list" aria-label="Sections">
      <Link className="section-link" to="/projects" activeProps={CURRENT}>
        <Folder size={16} />
        Projects
      </Link>
      {capabilities.canReadAudit && (
        <Link className="section-link" to="/audit" activeProps={CURRENT}>
          <Ledger size={16} />
          Audit
        </Link>
      )}
      {capabilities.canManageGrants && (
        <>
          <Link className="section-link" to="/members" activeProps={CURRENT}>
            <Users size={16} />
            Members
          </Link>
          <Link className="section-link" to="/tokens" activeProps={CURRENT}>
            <Key size={16} />
            Tokens
          </Link>
        </>
      )}
      <Link className="section-link" to="/settings" activeProps={CURRENT}>
        <Settings size={16} />
        Settings
      </Link>
    </nav>
  );
}

/**
 * Projects and their environments, as a tree.
 *
 * Only projects you have explicitly opened or shut live in state. Anything
 * absent falls back to "open if it is the one you are in", so walking into a
 * project opens it and walking out closes it again, without the tree slowly
 * accumulating every project you have ever visited.
 */
function ProjectTree({ projects }: { projects: ProjectSummary[] }) {
  const { projectSlug } = useLocationParts();
  const [toggled, setToggled] = useState<Record<string, boolean>>({});
  const active = projects.filter((project) => project.archivedAt === null);

  if (active.length === 0) {
    return <p className="tree-empty">No projects visible to you.</p>;
  }

  return (
    <ul className="tree">
      {active.map((project) => {
        const environments = project.environments.filter(isActiveAccessibleEnvironment);
        const expanded = toggled[project.slug] ?? project.slug === projectSlug;
        const branchId = `tree-${project.slug}`;

        return (
          <li key={project.slug}>
            <div className="tree-row">
              <Link
                className="tree-link"
                to="/projects/$project"
                params={{ project: project.slug }}
                // Without `exact`, the project stays marked as current while
                // you are inside one of its environments, and two rows in the
                // tree claim to be the page you are on.
                activeOptions={{ exact: true }}
                activeProps={CURRENT}
              >
                <Tile name={project.slug} />
                <span>{project.slug}</span>
              </Link>
              {environments.length > 0 && (
                <button
                  type="button"
                  className="tree-toggle"
                  aria-expanded={expanded}
                  aria-controls={branchId}
                  aria-label={`${expanded ? 'Hide' : 'Show'} environments of ${project.slug}`}
                  onClick={() =>
                    setToggled((state) => ({ ...state, [project.slug]: !expanded }))
                  }
                >
                  <ChevronRight size={14} />
                </button>
              )}
            </div>

            {environments.length > 0 && expanded && (
              <ul className="tree-branch" id={branchId}>
                {environments.map((environment) => (
                  <li key={environment.slug}>
                    <Link
                      className="tree-link tree-leaf"
                      to="/projects/$project/$environment"
                      params={{ project: project.slug, environment: environment.slug }}
                      activeProps={CURRENT}
                    >
                      <span>{environment.slug}</span>
                      <span className="tree-count">{environment.details.secretCount}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </li>
        );
      })}
    </ul>
  );
}

/**
 * The path to this page, where each project and environment step also
 * switches: one click on `prod` lists its siblings.
 */
function Breadcrumbs({ projects }: { projects: ProjectSummary[] }) {
  const { section, projectSlug, environmentSlug } = useLocationParts();
  const active = projects.filter((project) => project.archivedAt === null);
  const project = projects.find((entry) => entry.slug === projectSlug);

  if (section !== 'projects') {
    return (
      <nav className="crumbs" aria-label="Breadcrumb">
        <span className="crumb-link" aria-current="page">
          <span>{SECTION_TITLE[section] ?? ''}</span>
        </span>
      </nav>
    );
  }

  return (
    <nav className="crumbs" aria-label="Breadcrumb">
      {projectSlug === undefined ? (
        <span className="crumb-link" aria-current="page">
          <span>Projects</span>
        </span>
      ) : (
        <Link className="crumb-link crumb-root" to="/projects">
          <span>Projects</span>
        </Link>
      )}

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
        <button type="button" className="avatar" aria-label={`Account: ${principal.id}`}>
          {principal.id.slice(0, 1)}
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          className="menu"
          side="right"
          align="end"
          sideOffset={10}
          style={{ width: '16rem' }}
        >
          <div className="menu-identity">
            <strong title={principal.id}>{principal.id}</strong>
            <span>{roleLabel(principal, instanceRole)}</span>
          </div>

          <DropdownMenu.Separator className="menu-sep" />
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
