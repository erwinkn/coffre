import { allows, grantDefinition, instanceRoleGrants, isScope, PERMISSIONS, runsInstance, scopeDefinition, setsUpServices, withinCredential, type Holdings, type Permission, type Place as CorePlace, type Policy, type RoleDefinition, type ServiceSetting } from '@coffre/core/access';
import type { Called } from '@coffre/core/vault';

import type { PlaceRow } from '../db/queries/places.ts';
import type { RoleRow } from '../db/queries/policy.ts';

/**
 * What a page may list, from the vault's answer about its caller
 * (`ApiContext.caller`). The rule is the vault's own, from core, on what
 * the vault said the caller holds. Nothing here opens a value or makes a
 * change: those the vault decides again, in its own call.
 */

/**
 * A place as the app's own rows say it is. `protected` are the row's own
 * flags, counted with the vault's list: a protected environment missing
 * from that list is protected still. A personal config comes with its
 * owner and the environment it is a config of.
 */
export type Place = CorePlace & {
  protected?: readonly string[];
  personal?: { owner: string; parent: { environmentId: string; environmentSlug: string | null } };
};

type Row = { id: string; slug: string; protected: boolean };

/** A project, or one of its environments, as a permission check names it. */
export function placeOf(project: { id: string }, environment: (Row & { owner: string | null; parent: Row | null }) | null): Place {
  if (environment === null) return { projectId: project.id };
  const { parent } = environment;
  // A personal config holds what its parent does; a fork is protected by its own row alone.
  const place = { projectId: project.id, environmentId: environment.id, environmentSlug: environment.slug, protected: [environment, ...(environment.owner === null ? [] : [parent])].flatMap((row) => (row?.protected === true ? [row.id] : [])) };
  if (environment.owner === null) return place;
  // A parent unknown here matches no grant: the owner's read of it is not assumed.
  return { ...place, personal: { owner: environment.owner, parent: { environmentId: parent?.id ?? '', environmentSlug: parent?.slug ?? null } } };
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
export function can(who: Pick<Called, 'principal' | 'holds'>, permission: Permission, place: Place): boolean {
  const { holds } = who;
  const held: Holdings & { policy: Policy } =
    place.protected === undefined || place.protected.length === 0 ? holds : { ...holds, policy: { ...holds.policy, protected: [...holds.policy.protected, ...place.protected] } };
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
 * Whether the caller sees `project`, as `GET /projects` lists it: they hold
 * something in it, on it or in one of its environments, someone else's
 * personal config aside. What `projectsReached` reads may hold projects
 * they see nothing in (0.14.7's `seesProject`).
 */
export function seesProject(who: Called, project: PlaceRow): boolean {
  if (permissionsAt(who, placeOf(project, null)).length > 0) return true;
  return project.environments.some((environment) => (environment.owner === null || environment.owner === who.principal) && permissionsAt(who, placeOf(project, environment)).length > 0);
}

/**
 * The projects the caller may reach or name, by id, or null for any: those
 * their scope lists, which `GET /me` names by slug, with those they may do
 * something in. On a scoped credential, its scope's: it does nothing
 * anywhere else, whoever holds it. Otherwise every one for whoever runs
 * the instance; else those of their grants, and, when their instance role
 * holds anything, every project its scope does not list alone. What a
 * project the caller can do nothing in holds, they need not read.
 */
export function projectsReached({ holds }: Called): string[] | null {
  const { projects } = holds.scope;
  const listed = projects === 'all' ? [] : 'only' in projects ? projects.only : projects.except;
  const among = (grants: readonly { projectId?: string | null }[]) => [...new Set([...grants.flatMap((grant) => grant.projectId ?? []), ...listed])];
  if (holds.credentialScope != null) return among(holds.credentialScope);
  if (runsInstance(holds)) return null;
  const role = holds.policy.instanceRoles[holds.role];
  const holdsAnything = role !== undefined && (role.permissions.length > 0 || role.protected.length > 0);
  if (holdsAnything && (projects === 'all' || 'except' in projects)) return null;
  return among(holds.grants);
}

/** Whether the caller holds `permission` anywhere at all: by a grant, or by their instance role; within their credential's scope. */
export function canAnywhere({ holds }: Called, permission: Permission): boolean {
  if (holds.credentialScope != null && !holds.credentialScope.some((grant) => scopeDefinition(grant).permissions.includes(permission))) return false;
  return instanceRoleGrants(holds.role, permission, holds.policy) || holds.grants.some((grant) => grantDefinition(holds.policy, grant)?.permissions.includes(permission) ?? false);
}

/** The service-account setting as the policy row keeps it (JSON); none for one that does not read as a scope, as the vault takes it. */
export function settingOf(text: string | null): ServiceSetting | null {
  if (text === null) return null;
  try {
    const setting: unknown = JSON.parse(text);
    return isScope(setting) ? setting : null;
  } catch {
    return null;
  }
}

/**
 * Whether the caller sets up any service account, as 0.14.7 weighed it
 * and the vault weighs it when it admits one (`setsUpServices`,
 * `member.put`): whoever runs the instance; or a person on a credential
 * with no scope who could give one a grant somewhere `known` holds,
 * archived places too, inside the instance's `setting`. The vault names
 * only the roles the caller holds, and any role may be one they could give:
 * every one `roles` defines counts, under the vault's definitions of its
 * own. The rows are read as they are: they say what a page offers, and the
 * vault decides every service account set up.
 *
 *   setting everywhere, Ada a viewer of market    true: she gives viewer at market
 *   setting only [billing], the same Ada          false
 *   ci, a service account, or Ada on a token      false
 */
export function setsUpAnywhere(who: Called, setting: ServiceSetting | null, roles: readonly RoleRow[], known: readonly PlaceRow[]): boolean {
  if (runsInstance(who.holds)) return true;
  if (!who.principal.startsWith('user:') || who.holds.credentialScope != null) return false;
  const defined = Object.fromEntries(roles.map((row): [string, RoleDefinition] => [row.id, { name: row.name, description: row.description, permissions: row.permissions as Permission[], protected: row.protected as Permission[] }]));
  const holder = { ...who.holds, policy: { ...who.holds.policy, roles: { ...defined, ...who.holds.policy.roles } } };
  // A personal config is its owner's alone: no service account is given anything there.
  const reached = known.flatMap((project) => [placeOf(project, null), ...project.environments.filter((environment) => environment.owner === null).map((environment) => placeOf(project, environment))]);
  return setsUpServices(holder, setting, reached);
}
