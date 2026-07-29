import type { Me, Permission, ProjectSummary } from './api';

/**
 * The small set of instance-wide decisions the shell has to make.
 *
 * Resource-specific controls still use the permissions returned for that
 * project or environment. These are only the capabilities whose affordances
 * live outside one resource page.
 */
export type UiCapabilities = {
  canManageGrants: boolean;
  canReadAudit: boolean;
  canCreateProject: boolean;
};

const NONE: UiCapabilities = {
  canManageGrants: false,
  canReadAudit: false,
  canCreateProject: false,
};

export function deriveUiCapabilities(
  me: Me | null,
  projects: readonly ProjectSummary[],
): UiCapabilities {
  if (me === null) return NONE;

  const canManageInstance =
    me.instanceRole === 'owner' || me.instanceRole === 'root-admin';

  return {
    // The Users page manages the instance directory, not project grants.
    // Project access managers keep their grant controls on each project page.
    canManageGrants: canManageInstance,
    canReadAudit: me.canReadAudit,
    // Project creation has no resource on which to hold a grant, so it follows
    // the instance-wide owner role (including configured root admins).
    canCreateProject: canManageInstance,
  };
}

/** Secret values are available only where the API reports secret.read. */
export function canRevealSecrets(permissions: readonly Permission[]): boolean {
  return permissions.includes('secret.read');
}
