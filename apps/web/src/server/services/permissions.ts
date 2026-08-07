import type { PoolClient } from 'pg';

export type PrincipalRef = { type: 'user' | 'service'; id: string };

/**
 * The fixed permission catalogue. Mirrors the `permissions` table.
 *
 * Deliberately an enum and not a policy language. Roles are named bundles of
 * these; nothing composes predicates at runtime. Authorisation stays something
 * you can read end to end.
 */
export const PERMISSIONS = [
  'secret.read',
  'secret.write',
  'secret.archive',
  'audit.read',
  'environment.manage',
  'grant.manage',
  'project.manage',
] as const;

export type Permission = (typeof PERMISSIONS)[number];

/**
 * Permissions that only make sense at project scope.
 *
 * Granting `environment.manage` on a single environment would be incoherent --
 * the thing it authorises is creating siblings of that environment.
 */
export const PROJECT_ONLY_PERMISSIONS: readonly Permission[] = [
  'environment.manage',
  'grant.manage',
  'project.manage',
];

export type PermissionSet = ReadonlySet<Permission>;

const ALL: PermissionSet = new Set(PERMISSIONS);

export function isRootAdmin(principal: PrincipalRef, rootAdmins: readonly string[]): boolean {
  return principal.type === 'user' && rootAdmins.includes(principal.id);
}

/**
 * Everything the caller may do in one environment.
 *
 * The union of a grant on the environment itself and a grant on its project.
 * Expired grants are excluded here, which is the only place expiry needs to be
 * enforced -- every check goes through this function.
 */
export async function permissionsForEnvironment(
  tx: PoolClient,
  principal: PrincipalRef,
  environmentId: string,
  rootAdmins: readonly string[],
): Promise<PermissionSet> {
  if (isRootAdmin(principal, rootAdmins)) return ALL;

  const result = await tx.query<{ permission: Permission }>(
    `SELECT DISTINCT rp.permission
       FROM grants g
       JOIN role_permissions rp ON rp.role_id = g.role_id
      WHERE g.principal_type = $1
        AND g.principal_id = $2
        AND (g.expires_at IS NULL OR g.expires_at > now())
        AND (
              g.environment_id = $3
           OR g.project_id = (SELECT project_id FROM environments WHERE id = $3)
            )`,
    [principal.type, principal.id, environmentId],
  );

  return new Set(result.rows.map((row) => row.permission));
}

/**
 * Everything the caller may do at project scope.
 *
 * Only project-scoped grants count. An environment grant, however strong, does
 * not confer authority over the project's structure -- that separation is the
 * reason project-scoped grants exist.
 */
export async function permissionsForProject(
  tx: PoolClient,
  principal: PrincipalRef,
  projectId: string,
  rootAdmins: readonly string[],
): Promise<PermissionSet> {
  if (isRootAdmin(principal, rootAdmins)) return ALL;

  const result = await tx.query<{ permission: Permission }>(
    `SELECT DISTINCT rp.permission
       FROM grants g
       JOIN role_permissions rp ON rp.role_id = g.role_id
      WHERE g.principal_type = $1
        AND g.principal_id = $2
        AND g.project_id = $3
        AND (g.expires_at IS NULL OR g.expires_at > now())`,
    [principal.type, principal.id, projectId],
  );

  return new Set(result.rows.map((row) => row.permission));
}

/**
 * Permissions the caller holds anywhere inside a project, including via
 * environment-scoped grants. Used for visibility decisions ("may this person
 * see this project at all"), never for authorising a mutation.
 */
export async function permissionsAnywhereInProject(
  tx: PoolClient,
  principal: PrincipalRef,
  projectId: string,
  rootAdmins: readonly string[],
): Promise<PermissionSet> {
  if (isRootAdmin(principal, rootAdmins)) return ALL;

  const result = await tx.query<{ permission: Permission }>(
    `SELECT DISTINCT rp.permission
       FROM grants g
       JOIN role_permissions rp ON rp.role_id = g.role_id
       LEFT JOIN environments e ON e.id = g.environment_id
      WHERE g.principal_type = $1
        AND g.principal_id = $2
        AND (g.expires_at IS NULL OR g.expires_at > now())
        AND (g.project_id = $3 OR e.project_id = $3)`,
    [principal.type, principal.id, projectId],
  );

  return new Set(result.rows.map((row) => row.permission));
}

export function has(permissions: PermissionSet, permission: Permission): boolean {
  return permissions.has(permission);
}
