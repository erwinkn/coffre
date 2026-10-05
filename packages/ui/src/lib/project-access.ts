import { ROLES, type Role } from '@coffre/core/access';

import type { GrantRow, ProjectSummary, RoleRow } from '../shared/models';

/** The roles the project's access picker offers, a product choice; others show by their names. */
export type ProjectAccessRole = Extract<Role, 'owner' | 'viewer' | 'developer'>;

export type ProjectAccessOption = {
  value: string;
  role: ProjectAccessRole;
  environmentSlug: string | null;
  label: string;
};

export function projectAccessOptions(
  environments: ProjectSummary['environments'],
): ProjectAccessOption[] {
  const options: ProjectAccessOption[] = [
    {
      value: 'owner:',
      role: 'owner',
      environmentSlug: null,
      label: ROLES.owner.name,
    },
  ];

  for (const role of ['viewer', 'developer'] as const) {
    options.push({
      value: `${role}:`,
      role,
      environmentSlug: null,
      label: `${ROLES[role].name}: all`,
    });
  }

  for (const environment of environments) {
    if (environment.details === null || environment.details.archivedAt !== null) continue;
    for (const role of ['viewer', 'developer'] as const) {
      options.push({
        value: `${role}:${environment.slug}`,
        role,
        environmentSlug: environment.slug,
        label: `${ROLES[role].name}: ${environment.slug}`,
      });
    }
  }

  return options;
}

export function parseProjectAccess(value: string): {
  role: ProjectAccessRole;
  environmentSlug: string | null;
} {
  const [role, environmentSlug = ''] = value.split(':', 2);
  if (role !== 'owner' && role !== 'viewer' && role !== 'developer') {
    throw new Error('unknown project access level');
  }
  return { role, environmentSlug: environmentSlug || null };
}

/** "Owner", "Viewer: all" or "Developer: prod": a grant by its role's name, and where. */
export function projectAccessLabel(
  grant: Pick<GrantRow, 'role' | 'roleName' | 'environmentSlug'>,
): string {
  const name = Object.hasOwn(ROLES, grant.role) ? ROLES[grant.role as Role].name : grant.roleName;
  if (grant.role === 'owner') return name;
  return `${name}: ${grant.environmentSlug ?? 'all'}`;
}

export function projectAccessRoles(
  roles: RoleRow[],
  environmentSlug: string | null,
  currentRole?: string,
): RoleRow[] {
  const allowed = new Set(
    environmentSlug === null
      ? ['owner', 'viewer', 'developer']
      : ['viewer', 'developer'],
  );
  if (currentRole) allowed.add(currentRole);
  return roles.filter((role) => allowed.has(role.slug));
}
