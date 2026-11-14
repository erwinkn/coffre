import { allows, instanceRoleGrants, PERMISSIONS, roleGrants, runsInstance, scopeDefinition, withinCredential, type Holdings, type Permission, type Place as CorePlace, type Policy } from '@coffre/core/access';
import type { Called } from '@coffre/core/vault';

/**
 * What a page may list, from the vault's answer about its caller
 * (`ApiContext.caller`). The rule is the vault's own, from core, on what
 * the vault said the caller holds. Nothing here opens a value or makes a
 * change: those the vault decides again, in its own call.
 */

/** A place as the app's own row says it is: protected or not, and a personal config with its owner and the environment it is a config of. */
export type Place = CorePlace & {
  /** The row's own flag, counted with the vault's list: a protected environment missing from that list is protected still. */
  protected?: boolean;
  personal?: { owner: string; parent: { environmentId: string; environmentSlug: string | null } };
};

/** A project, or one of its environments, as a permission check names it. */
export function placeOf(
  project: { id: string },
  environment: { id: string; slug: string; protected: boolean; owner: string | null; parentId: string | null; parentSlug: string | null } | null,
): Place {
  if (environment === null) return { projectId: project.id };
  const place = { projectId: project.id, environmentId: environment.id, environmentSlug: environment.slug, protected: environment.protected };
  if (environment.owner === null) return place;
  // A parent unknown here matches no grant: the owner's read of it is not assumed.
  return { ...place, personal: { owner: environment.owner, parent: { environmentId: environment.parentId ?? '', environmentSlug: environment.parentSlug } } };
}

const SECRET_PERMISSIONS: readonly Permission[] = ['secret.read', 'secret.use', 'secret.write', 'secret.archive'];

/**
 * Whether the caller may do `permission` at `place`, as the vault decides
 * it (`callerFrom` and `decide` in @coffre/vault).
 *
 *   on a project       its project grant, or their instance role, when its scope takes in all of the project
 *   on an environment  its environment grant, its project's grant, or their instance role, when its scope takes it in
 *   in a personal config, its values: its owner alone, while they read or use the environment it is a config of
 */
export function can(who: Called, permission: Permission, place: Place): boolean {
  const { holds } = who;
  const held: Holdings & { policy: Policy } =
    place.protected === true && place.environmentId != null ? { ...holds, policy: { ...holds.policy, protected: [...holds.policy.protected, place.environmentId] } } : holds;
  const { protected: _, personal, ...at } = place;
  if (personal === undefined) return allows(held, permission, at as CorePlace);
  const parent = { projectId: place.projectId, ...personal.parent };
  // A personal config's values: its owner's alone, no grant or role reaches them, an Owner's included (docs/design/forking.md, section 3).
  // A credential's scope caps it still, at what it must hold at the parent: as much, but for reading, which use there allows.
  if (SECRET_PERMISSIONS.includes(permission)) {
    return who.principal === personal.owner
      && (allows(held, 'secret.read', parent) || allows(held, 'secret.use', parent))
      && withinCredential(held, permission === 'secret.read' ? 'secret.use' : permission, parent);
  }
  // Anything else, as at its parent: its log, to whoever reads the parent's.
  return allows(held, permission, parent);
}

/** Everything the caller may do at `place`, in catalogue order. */
export function permissionsAt(who: Called, place: Place): Permission[] {
  return PERMISSIONS.filter((permission) => can(who, permission, place));
}

/**
 * The projects the caller may reach or name, by id, or null for any: every
 * one for whoever runs the instance; else those of their grants, their
 * credential's and their scope's lists, and, when their instance role holds
 * anything, every project its scope does not list alone. What a project the
 * caller can do nothing in holds, they need not read.
 */
export function projectsReached({ holds }: Called): string[] | null {
  if (runsInstance(holds)) return null;
  const { projects } = holds.scope;
  const role = holds.policy.instanceRoles[holds.role];
  const holdsAnything = role !== undefined && (role.permissions.length > 0 || role.protected.length > 0);
  if (holdsAnything && (projects === 'all' || 'except' in projects)) return null;
  const listed = projects === 'all' ? [] : 'only' in projects ? projects.only : projects.except;
  const ids = [...holds.grants, ...(holds.credentialScope ?? [])].flatMap((grant) => grant.projectId ?? []);
  return [...new Set([...ids, ...listed])];
}

/** Whether the caller holds `permission` anywhere at all: by a grant, or by their instance role; within their credential's scope. */
export function canAnywhere({ holds }: Called, permission: Permission): boolean {
  if (holds.credentialScope != null && !holds.credentialScope.some((grant) => scopeDefinition(grant).permissions.includes(permission))) return false;
  return instanceRoleGrants(holds.role, permission, holds.policy) || holds.grants.some((grant) => roleGrants(grant.role, permission, holds.policy));
}
