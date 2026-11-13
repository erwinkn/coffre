import { EVERYWHERE, isInstanceRole, isScope, normalScope, ownsInstance, runsInstance, unscoped, type Filter, type InstanceRole, type Scope } from '@coffre/core/access';
import type { AccessAnswers, AccessChanges, MemberAdd, MemberRemove, MemberRestore, MemberRole, Presented, ScopeInput, Standing } from '@coffre/core/vault';
import { grants, principals, projects } from '@coffre/db/schema';
import { eq, sql } from 'drizzle-orm';

import { callerFrom, callerParts, type Asking, type Shown } from '../caller.ts';
import { drop, part, put, type Operation, type Parts, type Refusal, type Seen } from '../change.ts';
import type { Said } from '../entry.ts';
import type { Fresh, Row } from '../rows.ts';
import type { Deciding } from '../vault.ts';
import type { Operations } from './index.ts';
import { presented, text } from './input.ts';

/**
 * The changes of members, grants, roles and the instance's policy
 * (docs/design/0.16.md, "A change"). Who runs the instance, an Admin or an
 * Owner whose scope narrows nothing, adds and removes members; only an Owner
 * of the whole instance gives an instance role, or changes or removes an
 * Owner; and the instance always keeps one Owner of all of it.
 *
 * Not yet: a person who does not run the instance setting up or removing a
 * service account (`setsUpServices`, `managesService`). That weighs a
 * project's protected environments, which the engine settles first: those
 * paths are refused.
 */

/** A change about no project: the caller's instance role and its scope decide, and none of their grants. */
const NOWHERE = sql`(SELECT NULL::uuid WHERE false)`;

/** A member's id, as the table's checks have it (`principals_id_check`, `principals_user_lowercase`). */
const PRINCIPAL = /^(user|token):[^\s:]\S*$/;
const isMember = (value: unknown): value is string => text(value) && PRINCIPAL.test(value) && (!value.startsWith('user:') || value === value.toLowerCase());

/** The most slugs a scope's list names: as many as a credential's scope names places. */
const MOST_SLUGS = 1000;

/** A filter as the app names it, copied: an array from another isolate may have holes, which no check of its items sees. */
function filterOf(value: unknown): Filter | undefined {
  if (value === 'all') return 'all';
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const [kind, ...more] = Object.keys(value);
  const list: unknown = (value as Record<string, unknown>)[kind!];
  if (more.length > 0 || (kind !== 'only' && kind !== 'except') || !Array.isArray(list) || list.length > MOST_SLUGS) return undefined;
  const items = [...list];
  if (!items.every((item) => text(item) && item.length > 0)) return undefined;
  return kind === 'only' ? { only: items as string[] } : { except: items as string[] };
}

const listOf = (filter: Filter): string[] => (filter === 'all' ? [] : 'only' in filter ? filter.only : filter.except);

/** A row's scope: null, everywhere; one that does not read as a scope reaches nothing, as `callerOf` takes it. */
function scopeOf(row: Row<typeof principals>): Scope | null {
  if (row.scope === null) return EVERYWHERE;
  try {
    const scope: unknown = JSON.parse(row.scope);
    return isScope(scope) ? scope : null;
  } catch {
    return null;
  }
}

/** Whether an active member's row makes them an Owner of the whole instance: Owner, scoped nowhere. */
function ownsAll(row: Row<typeof principals>): boolean {
  const scope = scopeOf(row);
  return scope !== null && ownsInstance({ role: row.role as InstanceRole, scope });
}

/** Whether the caller is an Owner of the whole instance, on a credential no scope narrows. */
const ownsAllAsking = (caller: Asking) => caller.holds.credentialScope == null && ownsInstance(caller.holds);

/** Whether the deployment names this person an Owner (`owners`): no change demotes or removes them while it does. */
const named = (vault: Deciding, principal: string) => vault.owners.some((email) => principal === `user:${email}`);

/** Who asks, or why they are refused, as `secret.write` takes them: a narrowed session changes nothing. */
function asking(seen: Seen<ReturnType<typeof callerParts>>, shown: Shown, vault: Deciding, at: number): Asking | Refusal {
  const caller = callerFrom(seen, shown, vault.workloads, at);
  if (caller === null) return { refused: 'unauthenticated' };
  if (caller.workload?.stop != null) return { refused: caller.workload.stop };
  if (caller.workload?.narrowed === true) return { refused: 'narrowed' };
  return caller;
}

/** An entry of these changes: who asked, on what, and what it mentions. */
function said(action: string, caller: Asking, shown: { request: string | null; ip: string | null }, objects: string[], detail: Record<string, unknown>): Said {
  return {
    kept: true,
    action,
    actor: caller.principal,
    credential: caller.credential.id,
    request: shown.request,
    ip: shown.ip,
    objects: [`principal:${caller.principal}`, `credential:${caller.credential.id}`, ...objects],
    detail,
  };
}

/**
 * A member's role and scope as asked, checked before any read: a person's
 * role is one of the instance's, its scope's lists bounded; a service
 * account, and anyone admitted as a `member`, has no scope, and a service
 * account no role but `member`.
 */
function membership(input: MemberAdd | MemberRestore | MemberRole): { principal: string; role: InstanceRole; scope: ScopeInput | null } {
  const { principal, role, scope } = input;
  const asked = scope === null ? null : typeof scope === 'object' && scope !== null && !Array.isArray(scope) && Object.keys(scope).length === 2
    ? { projects: filterOf(scope.projects), environments: filterOf(scope.environments) } : undefined;
  const valid = isMember(principal) && typeof role === 'string' && isInstanceRole(role) && asked !== undefined
    && (asked === null || (asked.projects !== undefined && asked.environments !== undefined && role !== 'member'))
    && (principal.startsWith('user:') || (role === 'member' && asked === null));
  if (!valid) {
    throw new TypeError('a member is user:<email> in lowercase or token:<name>, with an instance role, and a scope of 1,000 slugs a list at most only with a role but member; a service account is a member, with no scope');
  }
  return { principal, role, scope: asked as ScopeInput | null };
}

/**
 * The scope as the row keeps it, its projects by id, from the projects the
 * read found by their slugs: null, everywhere. Undefined when a slug names
 * no project there is, or one deleted.
 */
function scopeWritten(asked: ScopeInput | null, found: readonly Row<typeof projects>[]): string | null | undefined {
  if (asked === null) return null;
  const ids = listOf(asked.projects).map((slug) => found.find((row) => row.slug === slug && !row.slug.includes('~'))?.id);
  if (ids.includes(undefined)) return undefined;
  const scope = normalScope({ projects: asked.projects === 'all' ? 'all' : 'only' in asked.projects ? { only: ids as string[] } : { except: ids as string[] }, environments: asked.environments });
  return unscoped(scope) ? null : JSON.stringify(scope);
}

const standing = (role: InstanceRole, scope: string | null): Standing => ({ role, scope: scope === null ? null : (JSON.parse(scope) as Scope) });

/**
 * Admit someone the instance has never had (`member.add`), or bring back
 * one removed (`member.restore`), in the generation their removal moved on
 * to and with no grant. Whoever runs the instance admits a member; only an
 * Owner of the whole instance gives an instance role. A person the
 * deployment names an Owner comes in as one, or not at all.
 */
const admit = (action: 'member.add' | 'member.restore') =>
  function admitting(input: Presented & (MemberAdd | MemberRestore), vault: Deciding): Operation<Parts, AccessAnswers[typeof action]> {
    const shown = presented(input);
    const { principal, role, scope } = membership(input);
    const read = {
      ...callerParts(shown.token, NOWHERE),
      member: part(principals, eq(principals.id, principal)),
      scoped: part(projects, sql`${projects.slug} = ANY(${sql.param(scope === null ? [] : listOf(scope.projects))}::text[])`),
    };
    return {
      read,
      decide(seen: Seen<typeof read>, at: number) {
        const caller = asking(seen, shown, vault, at);
        if ('refused' in caller) return caller;
        if (!runsInstance(caller.holds) || (role !== 'member' && !ownsAllAsking(caller))) return { refused: 'no_access' };
        const [was] = seen.member;
        if (action === 'member.add' ? was !== undefined : was?.status !== 'removed') {
          return { refused: was === undefined ? 'not_a_member' : was.status === 'removed' ? 'removed' : 'exists' };
        }
        const written = scopeWritten(scope, seen.scoped);
        if (written === undefined) return { refused: 'no_access' };
        if (named(vault, principal) && !(role === 'owner' && written === null)) return { refused: 'configured_owner' };

        const now = new Date(at);
        const row: Fresh<typeof principals> = was === undefined
          ? { id: principal, status: 'active', role, scope: written, generation: 0, createdAt: now, createdBy: caller.principal, statusChangedAt: now, statusChangedBy: caller.principal, frozenAt: null }
          : { ...withoutMac(was), status: 'active', role, scope: written, statusChangedAt: now, statusChangedBy: caller.principal };
        return {
          writes: [put(principals, row, was ?? null)],
          entry: said(action, caller, shown, [`principal:${principal}`, ...seen.scoped.map((project) => `project:${project.id}`)], { member: principal, role, scope: standing(role, written).scope, generation: row.generation }),
          answer: standing(role, written),
        };
      },
    };
  };

/** Every active Owner, whom a role's change or a removal counts, read with it: two changes side by side, each leaving one Owner, start over and the second is refused. */
const owners = () => part(principals, sql`${principals.status} = 'active' AND ${principals.role} = 'owner'`);

/** Whether an Owner of the whole instance stays once `principal` is not one. */
const anotherOwner = (seen: readonly Row<typeof principals>[], principal: string) => seen.some((row) => row.id !== principal && ownsAll(row));

/**
 * A person's instance role and its scope (`member.role`), which only an
 * Owner of the whole instance sets, their own included: an Owner may step
 * down, but not the last one, and not one the deployment names.
 */
function memberRole(input: Presented & MemberRole, vault: Deciding): Operation<Parts, AccessAnswers['member.role']> {
  const shown = presented(input);
  const { principal, role, scope } = membership(input);
  if (!principal.startsWith('user:')) throw new TypeError('a service account holds no instance role');
  const read = {
    ...callerParts(shown.token, NOWHERE),
    member: part(principals, eq(principals.id, principal)),
    owners: owners(),
    scoped: part(projects, sql`${projects.slug} = ANY(${sql.param(scope === null ? [] : listOf(scope.projects))}::text[])`),
  };
  return {
    read,
    decide(seen: Seen<typeof read>, at: number) {
      const caller = asking(seen, shown, vault, at);
      if ('refused' in caller) return caller;
      if (!ownsAllAsking(caller)) return { refused: 'no_access' };
      const [was] = seen.member;
      if (was === undefined || was.status !== 'active') return { refused: was === undefined ? 'not_a_member' : 'removed' };
      const written = scopeWritten(scope, seen.scoped);
      if (written === undefined) return { refused: 'no_access' };
      const ownsAfter = role === 'owner' && written === null;
      if (named(vault, principal) && !ownsAfter) return { refused: 'configured_owner' };
      if (ownsAll(was) && !ownsAfter && !anotherOwner(seen.owners, principal)) return { refused: 'last_owner' };
      return {
        writes: [put(principals, { ...withoutMac(was), role, scope: written }, was)],
        entry: said('member.role', caller, shown, [`principal:${principal}`, ...seen.scoped.map((project) => `project:${project.id}`)], { member: principal, role, scope: standing(role, written).scope }),
        answer: standing(role, written),
      };
    },
  };
}

/**
 * Remove a member (`member.remove`): their grants are deleted, and their
 * generation moves on, which ends every session, token and binding issued
 * in the one before (`callerOf`), with nothing revoked row by row. Whoever
 * runs the instance removes a member, and only an Owner of the whole
 * instance an Owner; never the last one, nor one the deployment names.
 */
function memberRemove(input: Presented & MemberRemove, vault: Deciding): Operation<Parts, AccessAnswers['member.remove']> {
  const shown = presented(input);
  const { principal } = input;
  if (!isMember(principal)) throw new TypeError('a member is user:<email> in lowercase or token:<name>');
  const read = {
    ...callerParts(shown.token, NOWHERE),
    member: part(principals, eq(principals.id, principal)),
    owners: owners(),
    held: part(grants, eq(grants.principal, principal)),
  };
  return {
    read,
    decide(seen: Seen<typeof read>, at: number) {
      const caller = asking(seen, shown, vault, at);
      if ('refused' in caller) return caller;
      if (!runsInstance(caller.holds)) return { refused: 'no_access' };
      const [was] = seen.member;
      if (was === undefined || was.status !== 'active') return { refused: was === undefined ? 'not_a_member' : 'removed' };
      if (was.role === 'owner' && !ownsAllAsking(caller)) return { refused: 'no_access' };
      if (named(vault, principal)) return { refused: 'configured_owner' };
      if (ownsAll(was) && !anotherOwner(seen.owners, principal)) return { refused: 'last_owner' };

      const now = new Date(at);
      const generation = was.generation + 1;
      const revoked = seen.held.map((grant) => ({ project: grant.projectId, environment: grant.environmentId, role: grant.role, expiresAt: grant.expiresAt?.toISOString() ?? null }));
      return {
        writes: [
          put(principals, { ...withoutMac(was), status: 'removed', role: 'member', scope: null, generation, statusChangedAt: now, statusChangedBy: caller.principal }, was),
          ...seen.held.map((grant) => drop(grants, grant)),
        ],
        entry: said('member.remove', caller, shown, [`principal:${principal}`, ...seen.held.map((grant) => (grant.projectId === null ? `environment:${grant.environmentId}` : `project:${grant.projectId}`))], { member: principal, generation, revoked }),
        answer: { revoked: revoked.length },
      };
    },
  };
}

/** A row as read, but for its MAC: the engine seals what a change writes. */
function withoutMac<T extends { mac: unknown }>(row: T): Omit<T, 'mac'> {
  const { mac: _, ...kept } = row;
  return kept;
}

/** The changes of members, grants, roles and the instance's policy. */
export const accessOperations: Operations<AccessChanges> = {
  'member.add': admit('member.add'),
  'member.restore': admit('member.restore'),
  'member.role': memberRole,
  'member.remove': memberRemove,
};
