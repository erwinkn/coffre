import { useEffect, useState, type ReactNode } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { Autocomplete } from '@base-ui/react/autocomplete';
import { Dialog } from '@base-ui/react/dialog';
import type { ProjectSummary } from '../shared/models';
import type { UiCapabilities } from '../lib/capabilities';
import { isActiveAccessibleEnvironment } from '../lib/project-environments';
import { useMounted } from '../lib/mounted';
import { usePreferences } from '../lib/preferences';
import { administrationEntries } from './affordances';
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
  UserCog,
  Users,
} from './icons';

/** One line of the palette. */
type Command = {
  /** What a query is matched against: the name, then words people may type for it. */
  value: string;
  icon: ReactNode;
  label: ReactNode;
  hint?: string;
  run: () => void;
  /** The page it opens, offered only if the deployment kept it. */
  path?: string;
};

type CommandGroup = { value: string; items: Command[] };

/**
 * Every word of the query appears somewhere in the command's value, so
 * `prod acme` finds `acme/prod` and `denied` finds "Audit, denials only".
 */
function matches(command: Command, query: string): boolean {
  const value = command.value.toLowerCase();
  return query
    .toLowerCase()
    .split(/\s+/)
    .every((word) => value.includes(word));
}

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
  const { portal, setTheme } = usePreferences();
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
  const closing = (action: () => unknown) => () => {
    setOpen(false);
    action();
  };

  const mounted = useMounted();
  const commands: CommandGroup[] = [
    {
      value: 'Environments',
      items: active.flatMap((project) =>
        project.environments.filter(isActiveAccessibleEnvironment).map((environment) => ({
          value: `${project.slug}/${environment.slug} ${environment.name}`,
          icon: <Layers size={15} />,
          label: (
            <span className="mono">
              {project.slug}/{environment.slug}
            </span>
          ),
          hint: `${environment.details.secretCount} secret${
            environment.details.secretCount === 1 ? '' : 's'
          }`,
          path: '/projects/$project/$environment',
          run: closing(() =>
            navigate({
              to: '/projects/$project/$environment',
              params: { project: project.slug, environment: environment.slug },
            }),
          ),
        })),
      ),
    },
    {
      value: 'Projects',
      items: active.map((project) => ({
        value: `${project.slug} ${project.name}`,
        icon: <Folder size={15} />,
        label: <span className="mono">{project.slug}</span>,
        hint: project.name,
        path: '/projects/$project',
        run: closing(() =>
          navigate({ to: '/projects/$project', params: { project: project.slug } }),
        ),
      })),
    },
    {
      value: 'Pages',
      items: [
        {
          value: 'projects all',
          icon: <Folder size={15} />,
          label: 'Projects',
          path: '/projects',
          run: closing(() => navigate({ to: '/projects' })),
        },
        ...administrationEntries<Command>(capabilities, {
          users: [
            {
              value: 'users people members directory',
              icon: <Users size={15} />,
              label: 'Users',
              path: '/users',
              run: closing(() => navigate({ to: '/users' })),
            },
          ],
          services: [
            {
              value: 'service accounts tokens machines ci oidc directory',
              icon: <Key size={15} />,
              label: 'Service accounts',
              path: '/service-accounts',
              run: closing(() => navigate({ to: '/service-accounts' })),
            },
          ],
          audit: [
            {
              value: 'audit log history reads',
              icon: <Ledger size={15} />,
              label: 'Audit',
              path: '/audit',
              run: closing(() => navigate({ to: '/audit', search: {} })),
            },
            {
              value: 'audit denials denied refused',
              icon: <SlashCircle size={15} />,
              label: 'Audit, denials only',
              path: '/audit',
              run: closing(() => navigate({ to: '/audit', search: { decision: 'deny' } })),
            },
          ],
        }),
        {
          value: 'settings instance sign-in',
          icon: <Settings size={15} />,
          label: 'Settings',
          path: '/settings',
          run: closing(() => navigate({ to: '/settings' })),
        },
        {
          value: 'account preferences appearance identity profile me',
          icon: <UserCog size={15} />,
          label: 'Account',
          path: '/account',
          run: closing(() => navigate({ to: '/account' })),
        },
      ],
    },
    {
      value: 'Appearance',
      items: [
        {
          value: 'theme system automatic',
          icon: <Monitor size={15} />,
          label: 'Match system colours',
          run: closing(() => setTheme('system')),
        },
        {
          value: 'theme light paper',
          icon: <Sun size={15} />,
          label: 'Light',
          run: closing(() => setTheme('light')),
        },
        {
          value: 'theme dark night',
          icon: <Moon size={15} />,
          label: 'Dark',
          run: closing(() => setTheme('dark')),
        },
      ],
    },
  ];
  const groups = commands
    .map((group) => ({ ...group, items: group.items.filter((item) => item.path === undefined || mounted(item.path)) }))
    .filter((group) => group.items.length > 0);

  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
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

      <Dialog.Portal container={portal}>
        <Dialog.Backdrop className="overlay" />
        <Dialog.Popup className="palette" aria-label="Jump to a project, environment or page">
          {/* `inline`: the list sits in the dialog, always shown, not in a popup of its own. */}
          <Autocomplete.Root
            items={groups}
            filter={matches}
            itemToStringValue={(command: Command) => command.value}
            open
            inline
            autoHighlight="always"
            keepHighlight
          >
            <Autocomplete.Input
              className="palette-input"
              placeholder="Search projects, environments and pages…"
              aria-label="Search projects, environments and pages"
            />

            <div className="palette-list">
              <Autocomplete.Empty className="palette-empty">
                Nothing by that name.
              </Autocomplete.Empty>
              <Autocomplete.List>
                {(group: CommandGroup) => (
                  <Autocomplete.Group key={group.value} items={group.items}>
                    <Autocomplete.GroupLabel className="palette-group-label">
                      {group.value}
                    </Autocomplete.GroupLabel>
                    <Autocomplete.Collection>
                      {(command: Command) => (
                        <Autocomplete.Item
                          key={command.value}
                          value={command}
                          className="palette-item"
                          onClick={command.run}
                        >
                          {command.icon}
                          {command.label}
                          {command.hint !== undefined && (
                            <span className="palette-hint">{command.hint}</span>
                          )}
                        </Autocomplete.Item>
                      )}
                    </Autocomplete.Collection>
                  </Autocomplete.Group>
                )}
              </Autocomplete.List>
            </div>

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
          </Autocomplete.Root>
        </Dialog.Popup>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
