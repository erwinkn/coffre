import { useEffect, useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { Command } from 'cmdk';
import type { ProjectSummary } from '../lib/api';
import { setTheme } from './theme';
import {
  Folder,
  Layers,
  Ledger,
  Monitor,
  Moon,
  Search,
  SlashCircle,
  Sun,
  Users,
} from './icons';

/**
 * Command palette.
 *
 * The fast path, never the only path: everything reachable here is also
 * reachable by clicking.
 *
 * Selecting an item navigates through the router rather than assigning to
 * `location.href`. Under Next.js that shortcut was load-bearing -- every page
 * was `force-dynamic`, so a client transition would have shown the previous
 * screen's data while it refetched. Here the destination's loader runs as part
 * of the navigation and the router holds the old screen until it resolves,
 * which is both correct and considerably faster.
 */
export function CommandPalette({
  projects,
  canManageDirectory,
}: {
  projects: ProjectSummary[];
  canManageDirectory: boolean;
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
      <button className="kbd-trigger" onClick={() => setOpen(true)}>
        <Search size={14} />
        <span>Search</span>
        <span className="palette-hint">
          <kbd>⌘</kbd> <kbd>K</kbd>
        </span>
      </button>

      <Command.Dialog
        open={open}
        onOpenChange={setOpen}
        label="Command palette"
        overlayClassName="overlay"
        contentClassName="palette"
        loop
      >
        <Command.Input placeholder="Jump to a project, environment or view..." />

        <Command.List>
          <Command.Empty>Nothing matches that.</Command.Empty>

          {active.length > 0 && (
            <Command.Group heading="Environments">
              {active.flatMap((project) =>
                project.environments
                  .filter((environment) => environment.archivedAt === null)
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
                        {environment.secretCount} secret
                        {environment.secretCount === 1 ? '' : 's'}
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

          <Command.Group heading="Admin">
            {canManageDirectory && (
              <Command.Item
                value="users service accounts identity directory"
                onSelect={() => {
                  setOpen(false);
                  navigate({ to: '/access' });
                }}
              >
                <Users size={15} />
                Users
              </Command.Item>
            )}
            <Command.Item
              value="audit log history reads"
              onSelect={() => {
                setOpen(false);
                navigate({ to: '/audit', search: {} });
              }}
            >
              <Ledger size={15} />
              Audit log
            </Command.Item>
            <Command.Item
              value="denials denied refused audit"
              onSelect={() => {
                setOpen(false);
                navigate({ to: '/audit', search: { decision: 'deny' } });
              }}
            >
              <SlashCircle size={15} />
              Denials only
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
              Match system theme
            </Command.Item>
            <Command.Item
              value="theme light"
              onSelect={() => {
                setTheme('light');
                setOpen(false);
              }}
            >
              <Sun size={15} />
              Light theme
            </Command.Item>
            <Command.Item
              value="theme dark"
              onSelect={() => {
                setTheme('dark');
                setOpen(false);
              }}
            >
              <Moon size={15} />
              Dark theme
            </Command.Item>
          </Command.Group>
        </Command.List>
      </Command.Dialog>
    </>
  );
}
