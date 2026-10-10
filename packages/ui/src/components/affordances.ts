import {
  createElement,
  Fragment,
  type ReactElement,
  type ReactNode,
} from 'react';
import type { UiCapabilities } from '../lib/capabilities';

type AdministrationItemsProps = {
  capabilities: UiCapabilities;
  users: ReactNode;
  services: ReactNode;
  audit: ReactNode;
};

/** The shared ordering and visibility rule for administration destinations. */
export function AdministrationItems({
  capabilities,
  users,
  services,
  audit,
}: AdministrationItemsProps): ReactElement {
  return createElement(
    Fragment,
    null,
    ...administrationEntries(capabilities, { users: [users], services: [services], audit: [audit] }),
  );
}

/** The same rule, for destinations kept as data (the command palette's). */
export function administrationEntries<T>(
  capabilities: UiCapabilities,
  { users, services, audit }: { users: T[]; services: T[]; audit: T[] },
): T[] {
  return [
    ...(capabilities.canManageGrants ? users : []),
    // Service accounts, to whoever sets one up too: they see those they manage.
    ...(capabilities.canManageGrants || capabilities.setsUpServices ? services : []),
    ...(capabilities.canReadAudit ? audit : []),
  ];
}

/** Project creation exists before a grantable resource, so it follows the instance role and its scope (`makesProjects`). */
export function RootAdminOnly({
  capabilities,
  children,
}: {
  capabilities: UiCapabilities;
  children: ReactNode;
}): ReactNode {
  return capabilities.canCreateProject ? children : null;
}

/** Empty project copy must distinguish an empty instance from archived-only state. */
export function ProjectEmptyStateCopy({
  capabilities,
  hasArchivedProjects,
}: {
  capabilities: UiCapabilities;
  hasArchivedProjects: boolean;
}): ReactNode {
  if (hasArchivedProjects) {
    return capabilities.canCreateProject
      ? 'No active projects. Start a new one, or restore one from the archive below.'
      : 'No active projects. Your archived projects appear below.';
  }

  if (capabilities.canCreateProject) {
    return 'No projects exist yet. Start the first one with New project.';
  }

  return createElement(
    Fragment,
    null,
    'No project is visible to you. Someone holding ',
    createElement('span', { className: 'mono' }, 'grant.manage'),
    ' on a project can add you.',
  );
}

/** Reveal- and history-shaped controls require secret.read in this environment. */
export function SecretReadOnly({
  canReveal,
  children,
}: {
  canReveal: boolean;
  children: ReactNode;
}): ReactNode {
  return canReveal ? children : null;
}
