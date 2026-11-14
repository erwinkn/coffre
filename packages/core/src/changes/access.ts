import type { Filter, InstanceRole, Role, RoleDefinition, Scope } from '../access.ts';
import type { AccessChange } from '../vault.ts';

/**
 * The changes of members, grants, roles and the instance's policy
 * (`packages/vault/src/ops/access.ts`). A workload's session makes none of
 * them, whatever its scope holds (`workload_cannot_issue`), as 0.14 refused.
 */
export type AccessChanges = MemberPut | MemberRemove | AccessGrant | RoleEdit | SettingsEdit;

export type AccessAnswers = {
  /** The role and scope they hold now, the scope's projects by id as the row holds them (null is everywhere), and whether they were admitted or brought back. */
  'member.put': Standing & { created: boolean };
  /** How many grants went with them. */
  'member.remove': { revoked: number };
  /** What became of each place, in the order asked; with `admit`, whether this change admitted the service account. */
  'access.grant': { changes: AccessChange[]; created?: boolean };
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
 * A member admitted, brought back or given an instance role
 * (`member.put`), whichever their row calls for, as 0.14.7's `admit` did:
 * the app cannot know which without reading the row, and only the vault's
 * read can. Its entry is the action that happened:
 *
 *   no row        `member.add`, as `role`, or `member` when null
 *   removed       `member.restore`, the same, in the generation their removal moved on to, with no grant
 *   active        `member.role`, `unchanged` when nothing moves; a null role keeps their role and scope
 *
 * Whoever runs the instance puts a member; only an Owner of the whole
 * instance makes an Owner, changes one, or changes their own role; the last
 * Owner of the whole instance stays one (`last_owner`), and one the
 * deployment names comes in and stays as one (`configured_owner`). A
 * service account holds no instance role but `member`: asked one, refused
 * `invalid`. A person who does not run the instance, on a session, sets up
 * a service account, as `member`, where they could give it something
 * (`setsUpServices`), and brings back one they removed. A refused put is
 * logged as `member.add`, as 0.14.7 logged it.
 *
 * A member, by principal: a person, `user:<email>` in lowercase, or a
 * service account, `token:<name>`, 256 characters at most. `scope` is where
 * the role applies, given only with a role but `member`, which holds
 * nothing. Past these the call is a fault, not a refusal: the app checks
 * them first.
 */
export type MemberPut = { op: 'member.put'; principal: string; role: InstanceRole | null; scope: ScopeInput | null };

/**
 * Remove a member: their grants go, their sign-in accounts are revoked, and
 * their generation moves on, which ends every session, token and binding
 * issued before. Whoever runs the instance removes a member; a person on a
 * session, a service account they manage (`managesService`).
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
 * project's on an environment or an end gone.
 *
 * A service account's grants, where the caller does not manage access: a
 * person on a session gives it what they could give it (`givesService`),
 * and takes away what it holds, if they manage it (`managesService`): they
 * could give it all it holds. `admit` admits it in the same change when
 * it is not a member, or brings it back, all or none, as 0.14.7's
 * `setAccess` did: by someone who could set one up (`setsUpServices`), it
 * holds nothing before and is theirs; one removed, only its remover or
 * whoever runs the instance brings back. A row these weigh that the vault
 * did not write refuses, `tampered`. 1 to 1,000 places; past the shapes
 * above, or `admit` of a person, the call is a fault, not a refusal: the
 * app checks them first.
 */
export type AccessGrant = {
  op: 'access.grant';
  principal: string;
  changes: { project: string; environment: string | null; role: Role | null; expiresAt: string | null }[];
  admit?: boolean;
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
