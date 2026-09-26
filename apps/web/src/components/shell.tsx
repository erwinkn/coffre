import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { Link, useLoaderData, useNavigate, useRouterState } from '@tanstack/react-router';
import { Dialog, DropdownMenu } from 'radix-ui';
import { toast } from 'sonner';
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
  PanelLeft,
  Plus,
  Settings,
  SignOut,
  UserCog,
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

/**
 * The workspace this deployment serves. The server has no such notion yet --
 * one deployment is one workspace -- so the name lives here until it does.
 */
const WORKSPACE = 'Equisafe';

const SIDEBAR_KEY = 'coffre-sidebar';

/** Wide enough for the sidebar to sit beside the page; narrower, it is a drawer. */
const WIDE = '(width > 60rem)';

/**
 * Collapses the sidebar before first paint, inlined in <head> like the
 * theme's script: drawn wide and then snapped narrow, the whole page would
 * lurch sideways on every load.
 */
export const sidebarBootScript = `(function(){try{if(localStorage.getItem(${JSON.stringify(
  SIDEBAR_KEY,
)})==="collapsed"){document.documentElement.setAttribute("data-sidebar","collapsed")}}catch(e){}})()`;

/**
 * Whether the sidebar is folded down to its icons, and the switch.
 *
 * The attribute on <html> is the truth and the stylesheet reads it, so the
 * boot script has already drawn the right width. Server-rendered markup
 * cannot know it, so this state starts expanded and catches up on mount.
 */
function useSidebarCollapsed(): [boolean, () => void] {
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => setCollapsed(document.documentElement.dataset.sidebar === 'collapsed'), []);

  const toggle = useCallback(() => {
    const root = document.documentElement;
    const next = root.dataset.sidebar !== 'collapsed';
    if (next) root.dataset.sidebar = 'collapsed';
    else delete root.dataset.sidebar;
    try {
      if (next) localStorage.setItem(SIDEBAR_KEY, 'collapsed');
      else localStorage.removeItem(SIDEBAR_KEY);
    } catch {
      // Storage refused (private mode); the choice still holds for this page.
    }
    setCollapsed(next);
  }, []);

  return [collapsed, toggle];
}

/** Marks the current route without each link having to compare paths itself. */
const CURRENT = { 'aria-current': 'page' } as const;

function roleLabel(principal: Principal, instanceRole: InstanceRole): string {
  if (principal?.type === 'service') return 'Token';
  if (instanceRole === 'root-admin') return 'Root admin';
  if (instanceRole === 'owner') return 'Owner';
  return 'Member';
}

/** The product's mark and name, for the pages you see before signing in. */
export function Brand() {
  return (
    <span className="brand">
      <span className="brand-mark" aria-hidden>
        <Mark size={16} />
      </span>
      <span className="brand-name">coffre</span>
    </span>
  );
}

/**
 * The application frame: a sidebar of sections, headed by the workspace and
 * footed by your account, and a bar across the content with search on the
 * right. The sidebar folds down to its icons (⌘B, or the button at the left
 * of the bar) and stays folded across visits.
 *
 * Inside a project, the left of that bar is the path to where you are, and
 * each step of it switches: that is the only place project and environment
 * navigation lives outside the pages themselves. Everywhere else the page's
 * own title says where you are, so the bar leaves it out rather than repeat it.
 */
export function Shell({ projects, principal, instanceRole, capabilities, children }: ShellProps) {
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [collapsed, toggleSidebar] = useSidebarCollapsed();

  // Following a link in the drawer should land on the page, not leave the
  // navigation covering it.
  useEffect(() => setDrawerOpen(false), [pathname]);

  // ⌘B, as in most editors, and only where there is a sidebar to fold.
  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'b' && (event.metaKey || event.ctrlKey) && matchMedia(WIDE).matches) {
        event.preventDefault();
        toggleSidebar();
      }
    }
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [toggleSidebar]);

  return (
    <div className="shell">
      <aside className="sidebar">
        <Sidebar
          principal={principal}
          instanceRole={instanceRole}
          capabilities={capabilities}
          collapsed={collapsed}
        />
      </aside>

      <div className="main">
        <header className="header">
          <Tip
            label={
              <>
                {collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
                <kbd>⌘B</kbd>
              </>
            }
          >
            <button
              type="button"
              className="btn btn-quiet btn-icon header-sidebar"
              aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
              aria-keyshortcuts="Meta+B Control+B"
              onClick={toggleSidebar}
            >
              <PanelLeft size={16} />
            </button>
          </Tip>

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
  collapsed = false,
  close,
}: {
  principal: Principal;
  instanceRole: InstanceRole;
  capabilities: UiCapabilities;
  /** Folded down to its icons: each then names itself on hover. */
  collapsed?: boolean;
  close?: ReactNode;
}) {
  return (
    <>
      <div className="sidebar-head">
        <WorkspaceMenu collapsed={collapsed} />
        {close}
      </div>

      <nav className="sidebar-nav" aria-label="Sections">
        <NavLink
          to="/projects"
          label="Projects"
          icon={<Folder size={16} />}
          collapsed={collapsed}
        />
        <AdministrationItems
          capabilities={capabilities}
          users={
            <>
              <NavLink to="/users" label="Users" icon={<Users size={16} />} collapsed={collapsed} />
              <NavLink to="/tokens" label="Tokens" icon={<Key size={16} />} collapsed={collapsed} />
            </>
          }
          audit={
            <NavLink to="/audit" label="Audit" icon={<Ledger size={16} />} collapsed={collapsed} />
          }
        />
        <NavLink
          to="/settings"
          label="Settings"
          icon={<Settings size={16} />}
          collapsed={collapsed}
        />
      </nav>

      {/* Settings above is the workspace's; yours are here, with you. */}
      {principal !== null && (
        <div className="sidebar-foot">
          <AccountMenu principal={principal} instanceRole={instanceRole} collapsed={collapsed} />
          <Tip label="Account settings" side={collapsed ? 'right' : undefined}>
            <Link
              className="btn btn-quiet btn-icon sidebar-foot-settings"
              to="/account"
              aria-label="Account settings"
              activeProps={CURRENT}
            >
              <UserCog size={16} />
            </Link>
          </Tip>
        </div>
      )}
    </>
  );
}

/** A folded sidebar's stand-in for the labels it hides. */
function CollapsedTip({
  collapsed,
  label,
  children,
}: {
  collapsed: boolean;
  label: string;
  children: ReactNode;
}) {
  return collapsed ? (
    <Tip label={label} side="right">
      {children}
    </Tip>
  ) : (
    children
  );
}

function NavLink({
  to,
  label,
  icon,
  collapsed,
}: {
  to: '/projects' | '/users' | '/tokens' | '/audit' | '/settings';
  label: string;
  icon: ReactNode;
  collapsed: boolean;
}) {
  // Matching is by prefix, so Projects stays current inside a project and
  // Audit stays current whatever its filters.
  return (
    <CollapsedTip collapsed={collapsed} label={label}>
      <Link className="nav-link" to={to} activeProps={CURRENT}>
        {icon}
        <span className="nav-label">{label}</span>
      </Link>
    </CollapsedTip>
  );
}

/**
 * The workspace you are in, and where the others would be.
 *
 * For now this lists the one there is, and creating another says why it
 * cannot yet rather than opening a form that goes nowhere.
 */
function WorkspaceMenu({ collapsed }: { collapsed: boolean }) {
  const navigate = useNavigate();
  return (
    <DropdownMenu.Root>
      <CollapsedTip collapsed={collapsed} label={WORKSPACE}>
        <DropdownMenu.Trigger asChild>
          <button type="button" className="workspace">
            <Tile name={WORKSPACE} />
            <span className="workspace-name">{WORKSPACE}</span>
            <ChevronsUpDown size={14} className="workspace-chevron" />
          </button>
        </DropdownMenu.Trigger>
      </CollapsedTip>
      <DropdownMenu.Portal>
        <DropdownMenu.Content className="menu menu-workspace" align="start" sideOffset={6}>
          <DropdownMenu.Label className="menu-label">Workspaces</DropdownMenu.Label>
          <DropdownMenu.Item className="menu-item" onSelect={() => navigate({ to: '/projects' })}>
            <Tile name={WORKSPACE} />
            {WORKSPACE}
            <Check size={14} className="menu-check" />
          </DropdownMenu.Item>
          <DropdownMenu.Separator className="menu-sep" />
          <DropdownMenu.Item
            className="menu-item"
            onSelect={() =>
              toast('One workspace per deployment, for now', {
                description: `Creating another needs server support coffre does not have yet. This deployment is ${WORKSPACE}.`,
              })
            }
          >
            <Plus size={14} />
            Create workspace
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

/**
 * Sign out with a real form post, built on the spot: the menu item unmounts
 * as the menu closes, so it cannot hold the form itself, and the response is
 * a redirect the browser should follow (to Access's logout, in Cloudflare
 * mode).
 */
function signOut() {
  const form = document.createElement('form');
  form.method = 'post';
  form.action = '/auth/signout';
  document.body.appendChild(form);
  form.submit();
}

function AccountMenu({
  principal,
  instanceRole,
  collapsed,
}: {
  principal: NonNullable<Principal>;
  instanceRole: InstanceRole;
  collapsed: boolean;
}) {
  const { authMode } = useLoaderData({ from: '__root__' });
  return (
    <DropdownMenu.Root>
      <CollapsedTip collapsed={collapsed} label={principal.id}>
        <DropdownMenu.Trigger asChild>
          <button
            type="button"
            className="account"
            title={collapsed ? undefined : principal.id}
          >
            <span className="avatar" aria-hidden>
              {principal.id.slice(0, 1)}
            </span>
            <span className="account-text">
              <span className="account-name">{principal.id}</span>
              <span className="account-role">{roleLabel(principal, instanceRole)}</span>
            </span>
          </button>
        </DropdownMenu.Trigger>
      </CollapsedTip>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          className="menu menu-account"
          side="top"
          align="start"
          sideOffset={6}
        >
          <DropdownMenu.Label className="menu-label">Theme</DropdownMenu.Label>
          <ThemeMenuItems />

          <DropdownMenu.Separator className="menu-sep" />
          <DropdownMenu.Item className="menu-item" onSelect={signOut}>
            <SignOut size={14} />
            Sign out
          </DropdownMenu.Item>

          {authMode === 'dev' && (
            <>
              <DropdownMenu.Separator className="menu-sep" />
              <p className="menu-note">
                <span className="dot" aria-hidden />
                Demo instance. Do not store real secrets here.
              </p>
            </>
          )}
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
