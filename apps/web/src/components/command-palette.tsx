import { useEffect, useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { Command } from 'cmdk';
import type { ProjectSummary } from '../shared/models';
import type { UiCapabilities } from '../lib/capabilities';
import { isActiveAccessibleEnvironment } from '../lib/project-environments';
import {
  AdministrationItems,
  hasAdministrationItems,
} from './affordances';
import { setTheme } from './theme';
import {
  Folder,
  Key,
  Layers,
  Ledger,
  Monitor,
  Moon,
  Search,
  Settings,
  SlashCircle,
  Sun,
  User,
  Users,
} from './icons';

/**
 * Command palette.
 *
 * The fast path, never the only path: everything reachable here is also
 * reachable by clicking.
 *
 * Selecting an item uses router navigation so the destination loader finishes
 * before the new screen replaces the current one.
 */
export function CommandPalette({
  projects,
  capabilities,
}: {
  projects: ProjectSummary[];
  capabilities: UiCapabilities;
}) {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'k' && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        setOpen((value) => !value);
      }
    }
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, []);

  const active = projects.filter((project) => project.archivedAt === null);

  return (
    <>
      <button
        type="button"
        className="search-trigger"
        onClick={() => setOpen(true)}
        aria-label="Search projects and environments"
        aria-keyshortcuts="Meta+K Control+K"
      >
        <Search size={14} />
        <span className="search-label">Search…</span>
        <kbd aria-hidden>⌘K</kbd>
      </button>

      <Command.Dialog
        open={open}
        onOpenChange={setOpen}
        label="Jump to a project, environment or page"
        overlayClassName="overlay"
        contentClassName="palette"
        loop
      >
        <Command.Input placeholder="Search projects, environments and pages…" />

        <Command.List>
          <Command.Empty>Nothing by that name.</Command.Empty>

          {active.length > 0 && (
            <Command.Group heading="Environments">
              {active.flatMap((project) =>
                project.environments
                  .filter(isActiveAccessibleEnvironment)
                  .map((environment) => (
                    <Command.Item
                      key={`${project.slug}/${environment.slug}`}
                      value={`${project.slug}/${environment.slug} ${environment.name}`}
                      onSelect={() => {
                        setOpen(false);
                        navigate({
                          to: '/projects/$project/$environment',
                          params: { project: project.slug, environment: environment.slug },
                        });
                      }}
                    >
                      <Layers size={15} />
                      <span className="mono">
                        {project.slug}/{environment.slug}
                      </span>
                      <span className="palette-hint">
                        {environment.details.secretCount} secret
                        {environment.details.secretCount === 1 ? '' : 's'}
                      </span>
                    </Command.Item>
                  )),
              )}
            </Command.Group>
          )}

          {active.length > 0 && (
            <Command.Group heading="Projects">
              {active.map((project) => (
                <Command.Item
                  key={project.slug}
                  value={`${project.slug} ${project.name}`}
                  onSelect={() => {
                    setOpen(false);
                    navigate({ to: '/projects/$project', params: { project: project.slug } });
                  }}
                >
                  <Folder size={15} />
                  <span className="mono">{project.slug}</span>
                  <span className="palette-hint">{project.name}</span>
                </Command.Item>
              ))}
            </Command.Group>
          )}

          <Command.Group heading="Pages">
            <Command.Item
              value="projects all"
              onSelect={() => {
                setOpen(false);
                navigate({ to: '/projects' });
              }}
            >
              <Folder size={15} />
              Projects
            </Command.Item>
            {hasAdministrationItems(capabilities) && (
              <AdministrationItems
                capabilities={capabilities}
                audit={
                  <>
                    <Command.Item
                      value="audit log history reads"
                      onSelect={() => {
                        setOpen(false);
                        navigate({ to: '/audit', search: {} });
                      }}
                    >
                      <Ledger size={15} />
                      Audit
                    </Command.Item>
                    <Command.Item
                      value="audit denials denied refused"
                      onSelect={() => {
                        setOpen(false);
                        navigate({ to: '/audit', search: { decision: 'deny' } });
                      }}
                    >
                      <SlashCircle size={15} />
                      Audit, denials only
                    </Command.Item>
                  </>
                }
                users={
                  <>
                    <Command.Item
                      value="users people members directory"
                      onSelect={() => {
                        setOpen(false);
                        navigate({ to: '/users' });
                      }}
                    >
                      <Users size={15} />
                      Users
                    </Command.Item>
                    <Command.Item
                      value="tokens service accounts machines ci directory"
                      onSelect={() => {
                        setOpen(false);
                        navigate({ to: '/tokens' });
                      }}
                    >
                      <Key size={15} />
                      Tokens
                    </Command.Item>
                  </>
                }
              />
            )}
            <Command.Item
              value="settings workspace instance sign-in"
              onSelect={() => {
                setOpen(false);
                navigate({ to: '/settings' });
              }}
            >
              <Settings size={15} />
              Settings
            </Command.Item>
            <Command.Item
              value="account preferences appearance identity profile me"
              onSelect={() => {
                setOpen(false);
                navigate({ to: '/account' });
              }}
            >
              <User size={15} />
              Account
            </Command.Item>
          </Command.Group>

          <Command.Group heading="Appearance">
            <Command.Item
              value="theme system automatic"
              onSelect={() => {
                setTheme('system');
                setOpen(false);
              }}
            >
              <Monitor size={15} />
              Match system colours
            </Command.Item>
            <Command.Item
              value="theme light paper"
              onSelect={() => {
                setTheme('light');
                setOpen(false);
              }}
            >
              <Sun size={15} />
              Light
            </Command.Item>
            <Command.Item
              value="theme dark night"
              onSelect={() => {
                setTheme('dark');
                setOpen(false);
              }}
            >
              <Moon size={15} />
              Dark
            </Command.Item>
          </Command.Group>
        </Command.List>

        <div className="palette-foot" aria-hidden>
          <span>
            <kbd>↑</kbd>
            <kbd>↓</kbd> move
          </span>
          <span>
            <kbd>↵</kbd> open
          </span>
          <span>
            <kbd>esc</kbd> close
          </span>
        </div>
      </Command.Dialog>
    </>
  );
}
