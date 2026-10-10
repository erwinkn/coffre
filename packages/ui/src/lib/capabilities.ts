import { administers, makesProjects, type InstanceRole } from '@coffre/core/access';

import type { Me, Permission, ProjectSummary } from '../shared/models';

/**
 * The small set of instance-wide decisions the shell has to make.
 *
 * Resource-specific controls still use the permissions returned for that
 * project or environment. These are only the capabilities whose affordances
 * live outside one resource page.
 */
export type UiCapabilities = {
  /** Admins and owners, scoped or not, and root admins: the Users and Service accounts pages. */
  canManageGrants: boolean;
  /**
   * Admins and owners whose scope narrows nothing, and root admins: adding
   * and removing people and service accounts, instance roles, tokens and
   * trust bindings, offboarding reports, the instance's keys.
   */
  runsInstance: boolean;
  canReadAudit: boolean;
  canCreateProject: boolean;
};

const NONE: UiCapabilities = {
  canManageGrants: false,
  runsInstance: false,
  canReadAudit: false,
  canCreateProject: false,
};

export function deriveUiCapabilities(
  me: Me | null,
  projects: readonly ProjectSummary[],
): UiCapabilities {
  if (me === null) return NONE;

  const isRootAdmin = me.instanceRole === 'root-admin';
  const role: InstanceRole = me.instanceRole === 'root-admin' ? 'owner' : me.instanceRole;

  return {
    // Users and Service accounts list the instance's directory, for those
    // who manage access across projects. Project access managers keep their
    // grant controls on each project page.
    canManageGrants: isRootAdmin || administers(role),
    runsInstance: me.runsInstance,
    canReadAudit: me.canReadAudit,
    // A new project is one no `only` list names: as the server decides,
    // from the role and the scope, projects by slug.
    canCreateProject: makesProjects({ isRootAdmin, role, scope: me.scope, grants: [] }),
  };
}

/** Secret values are available only where the API reports secret.read. */
export function canRevealSecrets(permissions: readonly Permission[]): boolean {
  return permissions.includes('secret.read');
}
