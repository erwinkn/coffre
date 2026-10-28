import {
  allows,
  DEFAULT_POLICY,
  instanceRoleGrants,
  withinCredential,
  PERMISSIONS,
  roleGrants,
  runsInstance,
  scopeDefinition,
  type GrantPlace,
  type InstanceRole,
  type Permission,
  type Place as CorePlace,
  type CredentialScope,
  type Policy,
  type Role,
  type Scope,
} from '@coffre/core/access';
import type { Access, CallerKind, Settings, Vault } from '@coffre/core/vault';
import type { Queryable } from '@coffre/db';
import { newestVaultSeq } from '@coffre/db/log';

import type { Recalled } from '../accesses.ts';
import { formatMember } from './paths.ts';

/**
 * A place a permission is checked at. A personal config's names its owner
 * and the environment it is a config of: `can` decides it on them, never
 * on grants or roles at the personal config itself.
 */
export type Place = CorePlace | (Extract<CorePlace, { environmentSlug: string | null }> & {
  personal: { owner: string; parent: { environmentId: string; environmentSlug: string | null } };
});

export type PrincipalRef = { type: 'user' | 'service'; id: string };

/** A grant: `projectId` is the project it is in, also for a grant on one of its environments (`GrantPlace`). */
export type CallerGrant = GrantPlace & {
  role: Role;
  expiresAt: Date | null;
};

/**
 * Who is asking, and everything they hold. Loaded from the vault once per
 * request; every permission check after that is a plain function of this
 * value, `Holdings` in @coffre/core/access. The vault checks again
 * whatever touches a key or a grant.
 */
export type Caller = {
  principal: PrincipalRef;
  /** An active member. Everyone else only reaches sign-in. */
  registered: boolean;
  /** A member the vault refuses because their record failed its integrity check. */
  tampered: boolean;
  /** The membership this request authenticated, checked again before linking accounts. */
  generation: number;
  /** Their instance role and where it applies, projects by id; `member` everywhere for services and strangers. */
  role: InstanceRole;
  scope: Scope;
  /** Live grants only. */
  grants: CallerGrant[];
  /** The scope of the service token or binding the request came in on, past which nothing reaches; null for a session. */
  credentialScope: CredentialScope | null;
  /** The instance's roles and protected environments, as the vault told them with this access (docs/design/roles.md). */
  policy: Policy;
  /**
   * The newest `policy.change` the app saw before it asked the vault, by
   * its number; null for none. A transaction that commits a decision made
   * from `policy` checks, under the log's head, that none came since
   * (`policyStill`).
   */
  policySeq: bigint | null;
  /** A service account's: it holds each role's normal column, in a protected environment too. */
  service: boolean;
  /**
   * What the request came in on (`CallerKind`): a person's session or
   * token, a bearer service credential, or a workload's key-bound session,
   * which is handed back only plain values and those its scope lists
   * (`useOnly`, docs/design/workload-access.md, section 6.1). The vault is
   * told it with every call (`through`).
   */
  kind: CallerKind;
  /**
   * Set when this is the vault's answer kept from an earlier request, not
   * one asked for this one (`accessFor`): the request answers only once
   * the vault has vouched for it, or confirmed it (`Recalled`).
   */
  recalled?: Recalled;
  /**
   * Set when the app read this caller from the vault's rows itself, which
   * it cannot check, rather than asked the vault (`answerShown`): what
   * `GET /api/me` shows, and nothing else reads. Everything such a caller
   * then asks for, the vault decides.
   */
  unchecked?: true;
  /**
   * The instance's settings as the vault's newest entry says them, read by
   * the app with the credential, unchecked, for a request that shows them:
   * `me`, which shows what the caller may set up (`serviceSettingShown`).
   */
  settings?: Settings;
};

/** The principal and their live grants, in one vault call. */
export async function loadCaller(db: Queryable, vault: Vault, principal: PrincipalRef): Promise<Caller> {
  const seq = await newestPolicySeq(db);
  return callerFrom({ type: principal.type, id: principal.id }, await vault.access(formatMember(principal)), seq);
}

/**
 * The newest `policy.change` there is, by its number: read before the
 * vault is asked, whose answer's policy is then that one or newer, never older.
 */
export function newestPolicySeq(db: Queryable): Promise<bigint | null> {
  return newestVaultSeq(db, 'policy.change');
}

/**
 * A caller from what the vault said of its principal, and the credential it
 * came in on: its scope, and its kind, a person's or a bearer's by its
 * principal unless it says `workload`, whose scope lists what it reads
 * (`scopeWithReads`).
 */
export function callerFrom(
  principal: PrincipalRef,
  access: Access,
  policySeq: bigint | null,
  credentialScope: CredentialScope | null = null,
  kind: CallerKind = principal.type === 'user' ? 'person' : 'bearer',
): Caller {
  return {
    principal,
    registered: access.status === 'active',
    tampered: access.status === 'tampered',
    generation: access.generation,
    role: access.role,
    scope: access.scope,
    grants: access.grants.map((grant) => ({
      projectId: grant.projectId,
      environmentId: grant.environmentId,
      role: grant.role,
      expiresAt: grant.expiresAt === null ? null : new Date(grant.expiresAt),
    })),
    credentialScope,
    // A vault older than 0.10 tells none, and decides as the roles ship.
    policy: access.policy ?? DEFAULT_POLICY,
    policySeq,
    service: principal.type === 'service',
    kind,
  };
}

/** The caller, marked as built from a kept answer when it was (`Caller.recalled`). */
export function withRecalled(caller: Caller, recalled: Recalled | null): Caller {
  return recalled === null ? caller : { ...caller, recalled };
}

/** The caller, with what the app read of the vault's rows to show: the caller itself (`Caller.unchecked`), or the settings alone. */
export function withShown(caller: Caller, shown: { unchecked?: true; settings?: Settings }): Caller {
  return {
    ...caller,
    ...(shown.unchecked === undefined ? {} : { unchecked: shown.unchecked }),
    ...(shown.settings === undefined ? {} : { settings: shown.settings }),
  };
}

/**
 * Whether the caller may do `permission` at `place`: the rule the vault
 * applies too, from core.
 *
 *   on a project       its project grant, or their instance role, when its scope takes in all of the project
 *   on an environment  its environment grant, its project's grant, or their instance role, when its scope takes it in
 */
export function can(caller: Caller, permission: Permission, place: Place): boolean {
  if (!('personal' in place)) return allows(caller, permission, place);
  const parent = { projectId: place.projectId, ...place.personal.parent };
  // A personal config's values: its owner's alone, while they read or use its parent; no grant or role reaches them,
  // an Owner's included (docs/design/forking.md, section 3). The vault decides the same.
  // A credential's scope caps it still: an owner's viewer token on the parent reads their config, and writes nothing.
  if (SECRET_PERMISSIONS.includes(permission)) {
    return caller.principal.type === 'user' && formatMember(caller.principal) === place.personal.owner
      && (allows(caller, 'secret.read', parent) || allows(caller, 'secret.use', parent)) && withinCredential(caller, personalCap(permission), parent);
  }
  // Anything else, as at its parent: its log, to whoever reads the parent's.
  return allows(caller, permission, parent);
}

const SECRET_PERMISSIONS: readonly Permission[] = ['secret.read', 'secret.use', 'secret.write', 'secret.archive'];

/**
 * What a credential's scope must hold at a personal config's parent for
 * its owner to do `permission` in it: as much, but for reading, which use
 * there allows. Its values are its owner's own (R8), so a handle or a token
 * that uses the environment, a Contributor's, reads what its owner wrote
 * over it, and nothing of the environment's.
 */
export function personalCap(permission: Permission): Permission {
  return permission === 'secret.read' ? 'secret.use' : permission;
}

/** Whether the caller lists an environment's keys: reads its values, or uses them, as a Contributor does (R6). */
export function lists(caller: Caller, place: Place): boolean {
  return can(caller, 'secret.read', place) || can(caller, 'secret.use', place);
}

/** Everything the caller may do at `place`, in catalogue order. */
export function permissionsAt(caller: Caller, place: Place): Permission[] {
  return PERMISSIONS.filter((permission) => can(caller, permission, place));
}

/** A project, or one of its environments, as a permission check names it: a personal config with its owner and parent. */
export function placeOf(
  project: { id: string },
  environment: { id: string; slug: string; owner?: string | null; parentId?: string | null; parentSlug?: string | null } | null,
): Place {
  if (environment === null) return { projectId: project.id };
  const place = { projectId: project.id, environmentId: environment.id, environmentSlug: environment.slug };
  if (environment.owner == null) return place;
  // A parent unknown here matches no grant: the owner's read of it is not assumed.
  return { ...place, personal: { owner: environment.owner, parent: { environmentId: environment.parentId ?? '', environmentSlug: environment.parentSlug ?? null } } };
}

/**
 * Whether the caller holds anything anywhere in a project, which is what
 * lets them see it: a grant on it or in it, or an instance role whose
 * scope takes in it or one of its environments.
 */
export function seesProject(caller: Caller, project: { id: string; environments: { id: string; slug: string }[] }): boolean {
  const places = [placeOf(project, null), ...project.environments.map((environment) => placeOf(project, environment))];
  return places.some((place) => PERMISSIONS.some((permission) => can(caller, permission, place)));
}

/**
 * The projects the caller may reach or name, by id, or null for any: every
 * one for whoever runs the instance; else those of their grants, their
 * credential's and their scope's lists, and, when their instance role holds
 * anything, every project its scope does not list alone. What a project the caller can do nothing in holds, they need
 * not read.
 */
export function projectsReached(caller: Caller): string[] | null {
  // Whoever runs the instance names every project, its setting for service accounts too, whatever their role holds.
  if (runsInstance(caller)) return null;
  const { projects } = caller.scope;
  const role = caller.policy.instanceRoles[caller.role];
  const holdsAnything = role !== undefined && (role.permissions.length > 0 || role.protected.length > 0);
  if (holdsAnything && (projects === 'all' || 'except' in projects)) return null;
  const listed = projects === 'all' ? [] : 'only' in projects ? projects.only : projects.except;
  const ids = [...caller.grants, ...(caller.credentialScope ?? [])].flatMap((grant) => grant.projectId ?? []);
  return [...new Set([...ids, ...listed])];
}

/** Whether the caller holds `permission` anywhere at all: by a grant, or by their instance role; within their credential's scope. */
export function canAnywhere(caller: Caller, permission: Permission): boolean {
  // A role's normal column holds all its protected one does: what it holds anywhere.
  if (caller.credentialScope !== null && !caller.credentialScope.some((grant) => scopeDefinition(grant).permissions.includes(permission))) return false;
  return instanceRoleGrants(caller.role, permission, caller.policy) || caller.grants.some((grant) => roleGrants(grant.role, permission, caller.policy));
}
