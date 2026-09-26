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
  audit: ReactNode;
};

/** The shared ordering and visibility rule for administration destinations. */
export function AdministrationItems({
  capabilities,
  users,
  audit,
}: AdministrationItemsProps): ReactElement {
  return createElement(
    Fragment,
    null,
    capabilities.canManageGrants ? users : null,
    capabilities.canReadAudit ? audit : null,
  );
}

export function hasAdministrationItems(capabilities: UiCapabilities): boolean {
  return capabilities.canManageGrants || capabilities.canReadAudit;
}

/** Project creation exists before a grantable resource, so it is owner-only. */
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
