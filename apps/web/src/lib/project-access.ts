import type { GrantRow, ProjectSummary, RoleRow } from '../shared/models';

export type ProjectAccessRole = 'owner' | 'viewer' | 'developer';

export type ProjectAccessOption = {
  value: string;
  role: ProjectAccessRole;
  environmentSlug: string | null;
  label: string;
};

const LEVEL_LABELS: Record<ProjectAccessRole, string> = {
  owner: 'Owner',
  viewer: 'Read',
  developer: 'Write',
};

export function projectAccessOptions(
  environments: ProjectSummary['environments'],
): ProjectAccessOption[] {
  const options: ProjectAccessOption[] = [
    {
      value: 'owner:',
      role: 'owner',
      environmentSlug: null,
      label: 'Owner',
    },
  ];

  for (const role of ['viewer', 'developer'] as const) {
    options.push({
      value: `${role}:`,
      role,
      environmentSlug: null,
      label: `${LEVEL_LABELS[role]}: all`,
    });
  }

  for (const environment of environments) {
    if (environment.details === null || environment.details.archivedAt !== null) continue;
    for (const role of ['viewer', 'developer'] as const) {
      options.push({
        value: `${role}:${environment.slug}`,
        role,
        environmentSlug: environment.slug,
        label: `${LEVEL_LABELS[role]}: ${environment.slug}`,
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

export function projectAccessLabel(
  grant: Pick<GrantRow, 'role' | 'roleName' | 'environmentSlug'>,
): string {
  const scope =
    grant.environmentSlug === null ? 'all environments' : grant.environmentSlug;

  if (grant.role === 'owner') return 'Owner';
  if (grant.role === 'viewer') {
    return grant.environmentSlug === null ? 'Read: all' : `Read: ${scope}`;
  }
  if (grant.role === 'developer') {
    return grant.environmentSlug === null ? 'Write: all' : `Write: ${scope}`;
  }
  // Specialised grants remain legible even though the common access controls
  // use owner/read/write.
  return `${grant.roleName}: ${scope}`;
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
