import { randomUUID } from 'node:crypto';

import { allows, EVERYWHERE, isInstanceRole, isScope, normalScope, ownsInstance, PROJECT_ONLY_PERMISSIONS, ROLE_ID, runsInstance, unscoped, type Filter, type InstanceRole, type Permission, type Scope } from '@coffre/core/access';
import type { AccessAnswers, AccessChange, AccessChanges, AccessGrant, MemberAdd, MemberRemove, MemberRestore, MemberRole, Presented, ScopeInput, Standing } from '@coffre/core/vault';
import { environments, grants, identities, principals, projects, roles } from '@coffre/db/schema';
import { eq, sql } from 'drizzle-orm';

import { callerFrom, callerParts, refusedTo, type Asking, type Shown } from '../caller.ts';
import { amended, drop, part, put, type Operation, type Parts, type Refusal, type Seen, type Unsealed, type Write } from '../change.ts';
import type { Said } from '../entry.ts';
import type { Fresh, Row } from '../rows.ts';
import type { Deciding } from '../vault.ts';
import type { Operations } from './index.ts';
import { presented, text } from './input.ts';

/**
 * The changes of members, grants, roles and the instance's policy
 * (docs/design/0.16.md, "A change"). Who runs the instance, an Admin or an
 * Owner whose scope narrows nothing, adds and removes members and sets their
 * roles; only an Owner
 * of the whole instance makes an Owner, or changes or removes one; nobody
 * else changes their own role; and the instance always keeps one Owner of
 * all of it. These are 0.14's rules, as they were.
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

/** A place's slug as one is made (`SLUG` in places.ts): a scope names its projects and environments by theirs, so no other text reaches the row or the log. */
const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;

/** A filter as the app names it, copied: an array from another isolate may have holes, which no check of its items sees. */
function filterOf(value: unknown): Filter | undefined {
  if (value === 'all') return 'all';
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const [kind, ...more] = Object.keys(value);
  const list: unknown = (value as Record<string, unknown>)[kind!];
  if (more.length > 0 || (kind !== 'only' && kind !== 'except') || !Array.isArray(list) || list.length > MOST_SLUGS) return undefined;
  const items = [...list];
  if (!items.every((item) => typeof item === 'string' && SLUG.test(item))) return undefined;
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

/** Whether an active member's row makes them an Owner of the whole instance: a person, Owner, scoped nowhere. A service account owns nothing, as `callerOf` takes it. */
function ownsAll(row: Row<typeof principals>): boolean {
  const scope = scopeOf(row);
  return row.id.startsWith('user:') && scope !== null && ownsInstance({ role: row.role as InstanceRole, scope });
}

/** Whether the caller runs the instance by a role whose row was read: a role with no row is no role, as `project.create` takes it. */
const runs = (caller: Asking) => runsInstance(caller.holds) && Object.hasOwn(caller.holds.policy.instanceRoles, caller.holds.role);

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

/**
 * What the log says of one of these changes refused (D236): the member it was
 * about, by their row only when the read found one, and the scope's projects
 * found. No place: these changes name none, and a member's name as typed is
 * free text the log does not take.
 */
const deniedTo = <S extends Seen<ReturnType<typeof callerParts>> & { member: Row<typeof principals>[]; scoped?: Row<typeof projects>[] }>(action: string, shown: Shown & { request: string | null }, vault: Deciding) =>
  refusedTo<S>(action, shown, vault.workloads, {
    objects: (seen) => [...seen.member.map((row) => `principal:${row.id}`), ...(seen.scoped ?? []).map((project) => `project:${project.id}`)],
  });

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
 * no project there is (a deleted one's slug holds a `~`, which none asked does).
 */
function scopeWritten(asked: ScopeInput | null, found: readonly Row<typeof projects>[]): string | null | undefined {
  if (asked === null) return null;
  const ids = listOf(asked.projects).map((slug) => found.find((row) => row.slug === slug)?.id);
  if (ids.includes(undefined)) return undefined;
  const scope = normalScope({ projects: asked.projects === 'all' ? 'all' : 'only' in asked.projects ? { only: ids as string[] } : { except: ids as string[] }, environments: asked.environments });
  return unscoped(scope) ? null : JSON.stringify(scope);
}

const standing = (role: InstanceRole, scope: string | null): Standing => ({ role, scope: scope === null ? null : (JSON.parse(scope) as Scope) });

/**
 * Admit someone the instance has never had (`member.add`), or bring back
 * one removed (`member.restore`), in the generation their removal moved on
 * to and with no grant. Whoever runs the instance admits a member, with
 * any role but Owner, which only an Owner of the whole instance gives. A
 * removed service account comes back the same way: 0.14 let whoever
 * removed it bring it back too, but only those who run the instance remove
 * one yet. A person the
 * deployment names an Owner comes in as one, or not at all.
 *
 * A removed member whose row is deleted around the vault looks new, and comes
 * back in generation 0: no row the vault reads says otherwise. Its entry says
 * the row it made replaced none, which the signer's mirror finds false
 * history (`rewritten`), as it does any write over a deleted row.
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
      denied: deniedTo(action, shown, vault),
      decide(seen: Seen<typeof read>, at: number) {
        const caller = asking(seen, shown, vault, at);
        if ('refused' in caller) return caller;
        if (!runs(caller) || (role === 'owner' && !ownsAllAsking(caller))) return { refused: 'no_access' };
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
 * A person's instance role and its scope (`member.role`), which whoever runs
 * the instance sets; an Owner's, or Owner, only an Owner of the whole
 * instance, who alone also sets their own. So an Admin makes another Admin
 * but never widens what they hold themselves, and an Owner may step down,
 * but not the last one, and not one the deployment names.
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
    denied: deniedTo('member.role', shown, vault),
    decide(seen: Seen<typeof read>, at: number) {
      const caller = asking(seen, shown, vault, at);
      if ('refused' in caller) return caller;
      if (!runs(caller)) return { refused: 'no_access' };
      const [was] = seen.member;
      if (was === undefined || was.status !== 'active') return { refused: was === undefined ? 'not_a_member' : 'removed' };
      const written = scopeWritten(scope, seen.scoped);
      if (written === undefined) return { refused: 'no_access' };
      // A role asked as it is changes nothing, so whoever runs the instance may ask it, of anyone, themselves included, as 0.14 did. Its entry says so, as `secret.write`'s with no key does.
      if (was.role === role && was.scope === written) return { writes: [], entry: said('member.role', caller, shown, [`principal:${principal}`, ...seen.scoped.map((project) => `project:${project.id}`)], { member: principal, role, scope: standing(role, written).scope, unchanged: true }), answer: standing(role, written) };
      if ((was.role === 'owner' || role === 'owner' || principal === caller.principal) && !ownsAllAsking(caller)) return { refused: 'no_access' };
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
 * in the one before (`callerOf`), with nothing revoked row by row. Their
 * sign-in accounts are revoked: an account signs in as one member at a
 * time (`identities_active_subject`), and one bound in a generation before
 * signs in as nobody, so revoked, it is free to bind anew when they are
 * let back in. Whoever runs the instance removes a member, and only an
 * Owner of the whole instance an Owner; never the last one, nor one the
 * deployment names.
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
    // Every account of theirs, revoked or not and of any generation, by the member alone: one a sign-in binds between
    // this read and the write is found by the write's read again, and the removal starts over and revokes it too.
    accounts: part(identities, eq(identities.principal, principal)),
  };
  return {
    read,
    denied: deniedTo('member.remove', shown, vault),
    decide(seen: Seen<typeof read>, at: number, unsealed: Unsealed<typeof read>) {
      const caller = asking(seen, shown, vault, at);
      if ('refused' in caller) return caller;
      if (!runs(caller)) return { refused: 'no_access' };
      const [was] = seen.member;
      if (was === undefined || was.status !== 'active') return { refused: was === undefined ? 'not_a_member' : 'removed' };
      if (was.role === 'owner' && !ownsAllAsking(caller)) return { refused: 'no_access' };
      if (named(vault, principal)) return { refused: 'configured_owner' };
      if (ownsAll(was) && !anotherOwner(seen.owners, principal)) return { refused: 'last_owner' };
      // An account of theirs the vault cannot read may be one still live: removed, they would sign in with it once back.
      if (unsealed.accounts > 0) return { refused: 'tampered' };

      const now = new Date(at);
      const generation = was.generation + 1;
      // Those not revoked yet: one revoked before keeps when and by whom.
      const live = seen.accounts.filter((account) => account.revokedAt === null);
      const revoked = seen.held.map((grant) => ({ project: grant.projectId, environment: grant.environmentId, role: grant.role, expiresAt: grant.expiresAt?.toISOString() ?? null }));
      return {
        writes: [
          put(principals, { ...withoutMac(was), status: 'removed', role: 'member', scope: null, generation, statusChangedAt: now, statusChangedBy: caller.principal }, was),
          ...seen.held.map((grant) => drop(grants, grant)),
          ...live.map((account) => amended(identities, account, { revokedAt: now, revokedBy: caller.principal })),
        ],
        entry: said('member.remove', caller, shown, [
          `principal:${principal}`,
          ...seen.held.map((grant) => (grant.projectId === null ? `environment:${grant.environmentId}` : `project:${grant.projectId}`)),
          ...live.map((account) => `identity:${account.id}`),
        ], { member: principal, generation, revoked }),
        answer: { revoked: revoked.length },
      };
    },
  };
}

/** The most places one change of grants names: as many as a credential's scope does. */
const MOST_PLACES = 1000;

/** An end as the app sends one: an ISO 8601 time, which the row keeps to the millisecond. */
const ENDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})$/;

/** One place's change, as asked: a project's slug, an environment's within it, the role or null, the end or null. */
type Asked = AccessGrant['changes'][number];

function asked(value: unknown): value is Asked {
  if (typeof value !== 'object' || value === null) return false;
  const { project, environment, role, expiresAt } = value as Record<string, unknown>;
  return typeof project === 'string' && SLUG.test(project) && (environment === null || (typeof environment === 'string' && SLUG.test(environment)))
    && (role === null || (typeof role === 'string' && ROLE_ID.test(role)))
    && (expiresAt === null || (typeof expiresAt === 'string' && ENDS.test(expiresAt) && Number.isFinite(Date.parse(expiresAt)) && aDay(expiresAt)));
}

/** Whether an ISO 8601 time's date is one the calendar has: `Date.parse` reads February 30 as March 2. */
function aDay(time: string): boolean {
  const [year, month, day] = time.slice(0, 10).split('-').map(Number) as [number, number, number];
  return new Date(Date.UTC(year, month - 1, day)).getUTCDate() === day;
}

/**
 * A person's grants set at several places, all or none (`access.grant`; a
 * change that only takes roles away is logged `access.revoke`, as 0.14 did).
 * At each place the caller manages access (`grant.manage`), and gives no
 * role to themselves; a role is a project role there is, never one that
 * holds what only a project has on an environment; an end is after now. A
 * live grant asked as it is changes nothing; any other row at the place, a
 * lapsed grant or one of a membership before a removal, is replaced in
 * place, in the member's generation, or dropped.
 *
 * Not yet: a service account's grants, which weigh a project's protected
 * environments through `givesService`; refused.
 */
function accessGrant(input: Presented & AccessGrant, vault: Deciding): Operation<Parts, AccessAnswers['access.grant']> {
  const shown = presented(input);
  const { principal } = input;
  const changes = Array.isArray(input.changes) ? [...input.changes] : [];
  const path = (change: Asked) => (change.environment === null ? change.project : `${change.project}/${change.environment}`);
  if (!isMember(principal) || changes.length === 0 || changes.length > MOST_PLACES || !changes.every(asked) || new Set(changes.map(path)).size !== changes.length) {
    throw new TypeError('a change of grants names a member, and 1 to 1,000 places by slug, each once, with a project role or null and an ISO 8601 end or null');
  }
  // A place with no grant yet gets one under an id drawn here: a decision draws nothing.
  const ids = changes.map(() => randomUUID());
  const action = changes.every((change) => change.role === null) ? 'access.revoke' : 'access.grant';

  const named = sql`(SELECT p.id FROM projects p WHERE p.slug = ANY(${sql.param([...new Set(changes.map((change) => change.project))])}::text[]))`;
  const onProjects = sql`(SELECT p.id FROM projects p WHERE p.slug = ANY(${sql.param(changes.filter((change) => change.environment === null).map((change) => change.project))}::text[]))`;
  // Slugs hold no slash, so a path names one environment.
  const onEnvironments = sql`(SELECT e.id FROM environments e JOIN projects p ON p.id = e.project_id WHERE p.slug || '/' || e.slug = ANY(${sql.param(changes.filter((change) => change.environment !== null).map(path))}::text[]))`;
  const read = {
    ...callerParts(shown.token, named),
    member: part(principals, eq(principals.id, principal)),
    project: part(projects, sql`${projects.slug} = ANY(${sql.param([...new Set(changes.map((change) => change.project))])}::text[])`),
    environment: part(environments, sql`${environments.id} IN ${onEnvironments}`),
    // Every row at the places asked, whatever its generation: a place holds one grant a member, and a row left from before is replaced.
    held: part(grants, sql`${grants.principal} = ${principal} AND (${grants.projectId} IN ${onProjects} OR ${grants.environmentId} IN ${onEnvironments})`),
    given: part(roles, sql`NOT ${roles.instance} AND ${roles.id} = ANY(${sql.param([...new Set(changes.flatMap((change) => (change.role === null ? [] : [change.role])))])}::text[])`),
  };
  /** Each place asked, as far as it is there. */
  const placed = (seen: Seen<typeof read>) =>
    changes.map((change) => {
      const project = seen.project.find((row) => row.slug === change.project);
      const environment = change.environment === null ? null : seen.environment.find((row) => row.projectId === project?.id && row.slug === change.environment);
      return { project, environment };
    });
  return {
    read,
    denied: refusedTo(action, shown, vault.workloads, {
      objects: (seen: Seen<typeof read>) => [
        ...seen.member.map((row) => `principal:${row.id}`),
        ...placed(seen).flatMap(({ project, environment }) => (environment == null ? (project === undefined ? [] : [`project:${project.id}`]) : [`environment:${environment.id}`])),
      ],
    }),
    decide(seen: Seen<typeof read>, at: number) {
      const caller = asking(seen, shown, vault, at);
      if ('refused' in caller) return caller;
      const places = placed(seen);
      // One answer whether a place is not there or not theirs to manage, and for a service account's grants, not given here yet: none says which.
      if (!principal.startsWith('user:')) return { refused: 'no_access' };
      for (const [i, { project, environment }] of places.entries()) {
        // A personal config is its owner's alone: nobody is granted it.
        if (project === undefined || environment === undefined || environment?.owner != null) return { refused: 'no_access' };
        const manages = environment === null ? allows(caller.holds, 'grant.manage', { projectId: project.id }) : caller.may('grant.manage', environment);
        // Managing access never reads a value: nobody gives themselves a role, though they may give one up.
        if (!manages || (principal === caller.principal && changes[i]!.role !== null)) return { refused: 'no_access' };
      }
      // To whoever manages access at every place asked, what 0.14 told them of the member.
      const [member] = seen.member;
      if (member === undefined) return { refused: 'not_a_member' };
      if (member.status !== 'active') return { refused: 'removed' };
      // Asked of a place they manage, what 0.14 called invalid.
      for (const [i, { role, expiresAt }] of changes.entries()) {
        // An end gone is no end, on a role taken away too: 0.14 refused the whole change.
        if (expiresAt !== null && Date.parse(expiresAt) <= at) return { refused: 'invalid' };
        if (role === null) continue;
        const definition = seen.given.find((row) => !row.instance && row.id === role);
        if (definition === undefined || (places[i]!.environment !== null && definition.permissions.some((permission) => PROJECT_ONLY_PERMISSIONS.includes(permission as Permission)))) return { refused: 'invalid' };
      }

      const now = new Date(at);
      const writes: Write[] = [];
      const lines: Record<string, unknown>[] = [];
      const outcomes = changes.map(({ role, expiresAt }, i): AccessChange => {
        const { project, environment } = places[i] as { project: Row<typeof projects>; environment: Row<typeof environments> | null };
        const was = seen.held.find((row) => row.principal === principal && (environment === null ? row.projectId === project.id : row.environmentId === environment.id));
        // What the member holds there now: a grant of this membership, not lapsed.
        const current = was !== undefined && was.generation === member.generation && (was.expiresAt === null || was.expiresAt.getTime() > at) ? was : undefined;
        const ends = expiresAt === null ? null : new Date(Date.parse(expiresAt));
        const place = environment === null ? { project: project.id } : { environment: environment.id };
        if (role === null) {
          if (was !== undefined) writes.push(drop(grants, was));
          if (current === undefined) return 'unchanged';
          lines.push({ ...place, role: null, was: current.role });
          return 'revoked';
        }
        if (current !== undefined && current.role === role && current.expiresAt?.getTime() === ends?.getTime()) return 'unchanged';
        const grant: Fresh<typeof grants> = { id: was?.id ?? ids[i]!, principal, generation: member.generation, projectId: environment === null ? project.id : null, environmentId: environment?.id ?? null, role, expiresAt: ends, grantedAt: now, grantedBy: caller.principal };
        writes.push(put(grants, grant, was ?? null));
        lines.push({ ...place, role, expiresAt: ends?.toISOString() ?? null, was: current?.role ?? null });
        return current === undefined ? 'created' : 'updated';
      });
      return {
        writes,
        entry: said(action, caller, shown, [`principal:${principal}`, ...places.map(({ project, environment }) => (environment === null ? `project:${project!.id}` : `environment:${environment!.id}`))], { member: principal, changes: lines }),
        answer: { changes: outcomes },
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
  'access.grant': accessGrant,
};
