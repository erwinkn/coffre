import type { Filter, InstanceRole, Role, RoleDefinition, Scope } from '../access.ts';
import type { AccessChange } from '../vault.ts';

/**
 * The changes of members, grants, roles and the instance's policy
 * (`packages/vault/src/ops/access.ts`). A workload's session makes none of
 * them, whatever its scope holds (`workload_cannot_issue`), as 0.14 refused.
 */
export type AccessChanges = MemberAdd | MemberRestore | MemberRole | MemberRemove | AccessGrant | RoleEdit | SettingsEdit;

export type AccessAnswers = {
  /** The role and scope written, the scope's projects by id as the row holds them: null is everywhere. */
  'member.add': Standing;
  'member.restore': Standing;
  'member.role': Standing;
  /** How many grants went with them. */
  'member.remove': { revoked: number };
  /** What became of each place, in the order asked. */
  'access.grant': { changes: AccessChange[] };
  /** The role as it is now: null once deleted. */
  'policy.change': { role: RoleDefinition | null };
  /** The setting as the row holds it, projects by id. */
  'settings.change': { serviceAccounts: Scope };
};

export type Standing = { role: InstanceRole; scope: Scope | null };

/**
 * Where a person's instance role applies, as the app names it: projects by
 * slug, which the vault keeps by id, so a rename keeps them; environments by
 * slug, those of every project. Each list holds 1,000 slugs at most. Null is
 * everywhere.
 */
export type ScopeInput = { projects: Filter; environments: Filter };

/**
 * A member, by principal: a person, `user:<email>` in lowercase, or a
 * service account, `token:<name>`, 256 characters at most. A service
 * account is admitted as a `member` with no scope, and holds what its
 * grants give: never an instance role. A `member` holds nothing by its
 * role, so it has no scope either. Past any of these the call is a fault,
 * not a refusal: the app checks them first.
 */
type Membership = { principal: string; role: InstanceRole; scope: ScopeInput | null };

/** Admit someone the instance has never had. */
export type MemberAdd = Membership & { op: 'member.add' };

/** Bring back a member who was removed: with no grant, and in the generation their removal moved on to. */
export type MemberRestore = Membership & { op: 'member.restore' };

/** Set a person's instance role and its scope: a service account has none. */
export type MemberRole = Membership & { op: 'member.role' };

/**
 * Remove a member: their grants go, their sign-in accounts are revoked, and
 * their generation moves on, which ends every session, token and binding
 * issued before.
 */
export type MemberRemove = { op: 'member.remove'; principal: string };

/**
 * A person's roles at projects and environments, set, changed, given an end
 * or taken away: all of the places or none, each once. A place is a
 * project's slug, or one of its environments' too, which takes a role that
 * holds nothing only a project has (`PROJECT_ONLY_PERMISSIONS`). A role is
 * a project role's id, or null to revoke; `expiresAt` an ISO 8601 time
 * after the change, or null for no end. Whoever manages access at each
 * place (`grant.manage`) gives anything there but to themselves; they may
 * give up their own. A grant is of the member's generation: one left from
 * before a removal is replaced in place. Refused `no_access` where a place
 * is not there or not theirs; to whoever manages every place asked,
 * `not_a_member`, `removed`, and `invalid` for a role there is not, a
 * project's on an environment or an end gone. A service account's grants
 * are not given here yet (`no_access`). 1 to 1,000 places; past the
 * shapes above the call is a fault, not a refusal: the app checks them
 * first.
 */
export type AccessGrant = {
  op: 'access.grant';
  principal: string;
  changes: { project: string; environment: string | null; role: Role | null; expiresAt: string | null }[];
};

/**
 * A role defined, edited, put back or deleted (`policy.change`), by an
 * Owner of the whole instance on a session, as 0.14 allowed: a project role
 * (`instance` false), one that ships or one an Owner makes, or one of the
 * instance's that ships (Admin, Auditor). Owner, and the instance's Member,
 * are never edited. `definition` null puts a role that ships back as it
 * ships, and deletes one an Owner made, refused `role_granted` while a
 * grant names it. A project role that holds what only a project has
 * (`PROJECT_ONLY_PERMISSIONS`) is refused `invalid` while a grant on an
 * environment names it. `was` is the role as the caller saw it, null for
 * none: one that changed since is refused `policy_changed`, so that a
 * change is made from the role its preview was. An id is a role's as
 * `ROLE_ID` has it; a definition one `definitionProblem` passes: past those
 * the call is a fault, not a refusal: the app checks them first.
 */
export type RoleEdit = { op: 'policy.change'; instance: boolean; role: Role; definition: RoleDefinition | null; was: RoleDefinition | null };

/**
 * Where people set up service accounts themselves (`settings.change`,
 * `ServiceSetting`): projects and environments by slug, 1,000 a list at
 * most. Whoever runs the instance sets it, as 0.14 allowed.
 */
export type SettingsEdit = { op: 'settings.change'; serviceAccounts: ScopeInput };
