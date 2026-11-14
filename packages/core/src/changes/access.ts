import type { Filter, InstanceRole, Scope } from '../access.ts';

/** The changes of members, grants, roles and the instance's policy (`packages/vault/src/ops/access.ts`). */
export type AccessChanges = MemberAdd | MemberRestore | MemberRole | MemberRemove;

export type AccessAnswers = {
  /** The role and scope written, the scope's projects by id as the row holds them: null is everywhere. */
  'member.add': Standing;
  'member.restore': Standing;
  'member.role': Standing;
  /** How many grants went with them. */
  'member.remove': { revoked: number };
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
 * Remove a member: their grants go, and their generation moves on, which
 * ends every session, token and binding issued before.
 */
export type MemberRemove = { op: 'member.remove'; principal: string };
