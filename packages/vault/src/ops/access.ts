import { randomUUID } from 'node:crypto';

import {
  allows, definitionProblem, EVERYWHERE, FIXED_ROLES, givesService, INSTANCE_ROLES, isBuiltinRole, isInstanceRole, isScope, managesService, normalDefinition, normalScope, ownsInstance, PROJECT_ONLY_PERMISSIONS,
  ROLE_ID, ROLES, setsUpServices, unscoped,
  type Filter, type Holdings, type InstanceRole, type Permission, type Place, type RoleDefinition, type Scope, type ServiceAccount,
} from '@coffre/core/access';
import { ROLE_REVISION, roleRevision, type AccessAnswers, type AccessChange, type AccessChanges, type AccessGrant, type MemberPut, type MemberRemove, type Presented, type RoleEdit, type ScopeInput, type SettingsEdit, type Standing } from '@coffre/core/vault';
import { environments, grants, identities, policy, principals, projects, roles } from '@coffre/db/schema';
import { and, eq, sql } from 'drizzle-orm';

import { callerParts, refusedTo, type Asking, type Shown } from '../caller.ts';
import { amended, drop, part, put, type Operation, type Parts, type Refusal, type Seen, type Unsealed, type Write } from '../change.ts';
import type { Said } from '../entry.ts';
import type { Fresh, Row } from '../rows.ts';
import type { Deciding } from '../vault.ts';
import { managing, NOWHERE, ownsAllAsking, said } from './asking.ts';
import type { Operations } from './index.ts';
import { presented, text } from './input.ts';
import { definitionsOf, managesSealed, onSession, projectsOf, runs, serviceOf, serviceParts, settingOf } from './services.ts';

/**
 * The changes of members, grants, roles and the instance's policy
 * (docs/design/0.16.md, "A change"). Who runs the instance, an Admin or an
 * Owner whose scope narrows nothing, adds and removes members and sets their
 * roles; only an Owner
 * of the whole instance makes an Owner, or changes or removes one; nobody
 * else changes their own role; and the instance always keeps one Owner of
 * all of it. Only an Owner of the whole instance edits roles, and whoever
 * runs the instance its settings. These are 0.14's rules, as they were.
 *
 * A person who does not run the instance sets up a service account where
 * they could give it something, gives it what they hold, and removes one
 * they manage (`setsUpServices`, `givesService`, `managesService`), as 0.14.7
 * let them: those rules are core's, and the vault adds none. What they weigh
 * is read with the change, and a row of it the vault did not write refuses
 * the change, `tampered`: a grant hidden, a role or a place edited, would let
 * them reach further.
 */

/** A member's id, as the table's checks have it (`principals_id_check`, `principals_user_lowercase`). */
const PRINCIPAL = /^(user|token):[^\s:]\S*$/;
const isMember = (value: unknown): value is string => text(value) && PRINCIPAL.test(value) && (!value.startsWith('user:') || value === value.toLowerCase());

/** Every project there is, for `callerParts`: a deleted one's slug holds a `~`. */
const LIVE_PROJECTS = sql`(SELECT p.id FROM projects p WHERE strpos(p.slug, '~') = 0)`;

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


/** Whether the deployment names this person an Owner (`owners`): no change demotes or removes them while it does. */
const named = (vault: Deciding, principal: string) => vault.owners.some((email) => principal === `user:${email}`);


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


/**
 * A member's role and scope as asked, checked before any read: a role is
 * one of the instance's, or null; a scope's lists are bounded, and a scope
 * is given only with a role but `member`. Whether a service account may
 * hold the role is the decision's (`invalid`), as 0.14.7 refused it.
 */
function membership(input: MemberPut): { principal: string; role: InstanceRole | null; scope: ScopeInput | null } {
  const { principal, role, scope } = input;
  const asked = scope === null ? null : scopeAsked(scope);
  const valid = isMember(principal) && (role === null || (typeof role === 'string' && isInstanceRole(role))) && asked !== undefined
    && (asked === null || (role !== null && role !== 'member'));
  if (!valid) {
    throw new TypeError('a member is user:<email> in lowercase or token:<name>, with an instance role or null, and a scope of 1,000 slugs a list at most only with a role but member');
  }
  return { principal, role, scope: asked };
}

/** A scope as asked, its projects by id, from the projects the read found by their slugs. Undefined when a slug names no project there is (a deleted one's slug holds a `~`, which none asked does). */
function scopeById(asked: ScopeInput, found: readonly Row<typeof projects>[]): Scope | undefined {
  const ids = listOf(asked.projects).map((slug) => found.find((row) => row.slug === slug)?.id);
  if (ids.includes(undefined)) return undefined;
  return normalScope({ projects: asked.projects === 'all' ? 'all' : 'only' in asked.projects ? { only: ids as string[] } : { except: ids as string[] }, environments: asked.environments });
}

/** The scope as a member's row keeps it: null, everywhere. Undefined when a slug names no project there is. */
function scopeWritten(asked: ScopeInput | null, found: readonly Row<typeof projects>[]): string | null | undefined {
  if (asked === null) return null;
  const scope = scopeById(asked, found);
  return scope === undefined ? undefined : unscoped(scope) ? null : JSON.stringify(scope);
}

/** A scope as the app names it, its two filters copied, or undefined for any other shape. */
function scopeAsked(value: unknown): ScopeInput | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value) || Object.keys(value).length !== 2) return undefined;
  const { projects: inProjects, environments: inEnvironments } = value as Record<string, unknown>;
  const asked = { projects: filterOf(inProjects), environments: filterOf(inEnvironments) };
  return asked.projects === undefined || asked.environments === undefined ? undefined : (asked as ScopeInput);
}

/** The projects a scope asked names by slug, read with the change. */
const projectsIn = (scope: ScopeInput | null) => part(projects, sql`${projects.slug} = ANY(${sql.param(scope === null ? [] : listOf(scope.projects))}::text[])`);

const standing = (role: InstanceRole, scope: string | null): Standing => ({ role, scope: scope === null ? null : (JSON.parse(scope) as Scope) });

/** Every active Owner, whom a role's change or a removal counts, read with it: two changes side by side, each leaving one Owner, start over and the second is refused. */
const owners = () => part(principals, sql`${principals.status} = 'active' AND ${principals.role} = 'owner'`);

/** Whether an Owner of the whole instance stays once `principal` is not one. */
const anotherOwner = (seen: readonly Row<typeof principals>[], principal: string) => seen.some((row) => row.id !== principal && ownsAll(row));

/**
 * A member admitted, brought back or given an instance role (`member.put`),
 * as their row calls for, which only this read knows, as 0.14.7's `admit`
 * did. Whoever runs the instance puts anyone, as any role but Owner, which
 * only an Owner of the whole instance gives, changes or takes. With no row,
 * they are added (`member.add`); removed, brought back (`member.restore`),
 * in the generation their removal moved on to and with no grant; either
 * way as `member` when no role is asked. Active, their role and scope are
 * set (`member.role`), and kept when no role is asked: nobody but an Owner
 * of the whole instance sets their own, so an Admin makes another Admin
 * but never widens what they hold themselves; an Owner may step down, but
 * not the last one. A person the deployment names an Owner comes in as
 * one and stays one. A service account holds no role but `member`.
 *
 * A person who does not run the instance, on a session, sets up a service
 * account, as `member`, where they could give it something
 * (`setsUpServices`): every place there is, and the instance's setting,
 * are read with the change. One removed only its remover brings back, or
 * whoever runs the instance, as 0.14.7 allowed.
 *
 * A removed member whose row is deleted around the vault looks new, and comes
 * back in generation 0: no row the vault reads says otherwise. Its entry says
 * the row it made replaced none, which the signer's mirror finds false
 * history (`rewritten`), as it does any write over a deleted row.
 */
function memberPut(input: Presented & MemberPut, vault: Deciding): Operation<Parts, AccessAnswers['member.put']> {
  const shown = presented(input);
  const { principal, role, scope } = membership(input);
  const service = principal.startsWith('token:');
  const read = {
    // For a service account, what the caller holds everywhere, and every place there is: where they could give it something.
    ...callerParts(shown.token, service ? LIVE_PROJECTS : NOWHERE),
    member: part(principals, eq(principals.id, principal)),
    owners: owners(),
    scoped: projectsIn(scope),
    everyProject: part(projects, service ? sql`strpos(${projects.slug}, '~') = 0` : sql`false`),
    // Every environment, whatever its row says: one whose protection was edited behind the vault is found unsealed.
    everyEnvironment: part(environments, service ? sql`strpos(${environments.slug}, '~') = 0` : sql`false`),
    setting: part(policy, service ? sql`${policy.onlyRow}` : sql`false`),
    // Every project role: any of them may be what they could give it.
    defined: part(roles, service ? sql`NOT ${roles.instance}` : sql`false`),
  };
  return {
    read,
    // Refused, it is logged as an admission, whatever the row: 0.14.7's `admit` logged it so.
    denied: deniedTo('member.add', shown, vault),
    decide(seen: Seen<typeof read>, at: number, unsealed: Unsealed<typeof read>) {
      const caller = managing(seen, shown, vault, at);
      if ('refused' in caller) return caller;
      if (!runs(caller)) {
        // Only a person, on a session (a service account's credentials always have a scope), sets up a service account, as
        // `member`: what they set up would outlive a credential with a scope.
        if (!service || (role !== null && role !== 'member') || scope !== null || !onSession(caller)) return { refused: 'no_access' };
        const places: Place[] = [
          ...seen.everyProject.map((row) => ({ projectId: row.id })),
          ...seen.everyEnvironment.map((row) => ({ projectId: row.projectId, environmentId: row.id, environmentSlug: row.slug })),
        ];
        if (!setsUpServices(withRoles(caller, seen.defined), settingOf(seen), places)) return { refused: 'no_access' };
        // One removed, only whoever removed it brings back: never past someone else's removal.
        const [removed] = seen.member;
        if (removed?.status === 'removed' && removed.statusChangedBy !== caller.principal) return { refused: 'no_access' };
        // A row written behind the vault is not a row that is absent: a place's protection edited, a role, the setting. Told
        // only to whoever may by the rows the vault wrote: anyone else is refused as they would be without it.
        if (Object.values(unsealed).some((count) => count > 0)) return { refused: 'tampered' };
      }
      // A row the vault did not write is neither someone new nor a member to change: added over it, the write would fail.
      if (unsealed.member > 0) return { refused: 'tampered' };
      if (!principal.startsWith('user:') && role !== null && role !== 'member') return { refused: 'invalid' };
      const written = scopeWritten(scope, seen.scoped);
      if (written === undefined) return { refused: 'no_access' };
      const objects = [`principal:${principal}`, ...seen.scoped.map((project) => `project:${project.id}`)];
      const [was] = seen.member;

      if (was === undefined || was.status === 'removed') {
        const given = role ?? 'member';
        if (given === 'owner' && !ownsAllAsking(caller)) return { refused: 'no_access' };
        if (named(vault, principal) && !(given === 'owner' && written === null)) return { refused: 'configured_owner' };
        const now = new Date(at);
        const row: Fresh<typeof principals> = was === undefined
          ? { id: principal, status: 'active', role: given, scope: written, generation: 0, createdAt: now, createdBy: caller.principal, statusChangedAt: now, statusChangedBy: caller.principal, frozenAt: null }
          : { ...withoutMac(was), status: 'active', role: given, scope: written, statusChangedAt: now, statusChangedBy: caller.principal };
        return {
          writes: [put(principals, row, was ?? null)],
          entry: said(was === undefined ? 'member.add' : 'member.restore', caller, shown, objects, { member: principal, role: given, scope: standing(given, written).scope, generation: row.generation }),
          answer: { ...standing(given, written), created: true },
        };
      }

      // Active: the role and scope asked, or theirs, kept.
      const next = role === null ? { role: was.role as InstanceRole, scope: was.scope } : { role, scope: written };
      const answer = { ...standing(next.role, next.scope), created: false };
      // Asked as it is, it changes nothing, so whoever runs the instance may ask it, of anyone, themselves included, as 0.14 did. Its entry says so, as `secret.write`'s with no key does.
      if (was.role === next.role && was.scope === next.scope) return { writes: [], entry: said('member.role', caller, shown, objects, { member: principal, role: next.role, scope: answer.scope, unchanged: true }), answer };
      if ((was.role === 'owner' || next.role === 'owner' || principal === caller.principal) && !ownsAllAsking(caller)) return { refused: 'no_access' };
      const ownsAfter = next.role === 'owner' && next.scope === null;
      if (named(vault, principal) && !ownsAfter) return { refused: 'configured_owner' };
      if (ownsAll(was) && !ownsAfter && !anotherOwner(seen.owners, principal)) return { refused: 'last_owner' };
      return {
        writes: [put(principals, { ...withoutMac(was), role: next.role, scope: next.scope }, was)],
        entry: said('member.role', caller, shown, objects, { member: principal, role: next.role, scope: answer.scope }),
        answer,
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
 * deployment names. A service account, whoever manages it too
 * (`managesService`), on a session, as 0.14.7 allowed: what it holds, the
 * places and roles it holds them as and the instance's setting are read
 * with the change. Beside the read, how many ways in the move ends, by
 * kind, which the answer says, as 0.14.7's did: a credential issued or
 * ended meanwhile starts the change over.
 */
function memberRemove(input: Presented & MemberRemove, vault: Deciding): Operation<Parts, AccessAnswers['member.remove']> {
  const shown = presented(input);
  const { principal } = input;
  if (!isMember(principal)) throw new TypeError('a member is user:<email> in lowercase or token:<name>');
  const read = {
    // For a service account, what the caller holds where it holds something, and what says who manages it.
    ...callerParts(shown.token, projectsOf(principal)),
    ...serviceParts(principal),
    member: part(principals, eq(principals.id, principal)),
    owners: owners(),
    held: part(grants, eq(grants.principal, principal)),
    // Every account of theirs, revoked or not and of any generation, by the member alone: one a sign-in binds between
    // this read and the write is found by the write's read again, and the removal starts over and revokes it too.
    accounts: part(identities, eq(identities.principal, principal)),
  };
  // Their live credentials at their generation, by kind, on `credentials_live_idx`: no decision goes by them.
  const beside = {
    ending: sql`SELECT jsonb_build_object(
      'sessions', count(*) FILTER (WHERE c.kind IN ('browser', 'cli')),
      'tokens', count(*) FILTER (WHERE c.kind NOT IN ('browser', 'cli', 'mcp')),
      'apps', count(*) FILTER (WHERE c.kind = 'mcp' AND c.ancestors IS NULL AND c.challenge IS NULL)) AS row
      FROM credentials c JOIN principals m ON m.id = c.principal AND m.generation = c.generation
      WHERE c.principal = ${principal} AND c.revoked_at IS NULL AND c.expires_at > now()`,
  };
  return {
    read,
    beside,
    denied: deniedTo('member.remove', shown, vault),
    decide(seen: Seen<typeof read>, at: number, unsealed: Unsealed<typeof read>, _checked, rode) {
      const caller = managing(seen, shown, vault, at);
      if ('refused' in caller) return caller;
      if (!runs(caller)) {
        if (!principal.startsWith('token:') || !managesSealed(caller, seen, principal, at)) return { refused: 'no_access' };
        // A row written behind the vault is not a row that is absent: a grant of the service's hidden, its place's protection
        // edited. Told only to whoever manages it by the rows the vault wrote (`managesSealed`).
        if (Object.values(unsealed).some((count) => count > 0)) return { refused: 'tampered' };
      }
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
        answer: { revoked: revoked.length, ...ending(rode?.ending?.[0]), identities: live.length },
      };
    },
  };
}

/** What a removal ends, as the count beside its read said it: one row, always, whose absence is a fault, never none. */
function ending(counted: unknown): { sessions: number; tokens: number; apps: number } {
  const { sessions, tokens, apps } = (counted ?? {}) as Record<string, unknown>;
  if (![sessions, tokens, apps].every((count) => typeof count === 'number' && Number.isSafeInteger(count))) throw new Error('a removal reads what it ends beside its rows, as one row of counts');
  return { sessions: sessions as number, tokens: tokens as number, apps: apps as number };
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
 * A member's grants set at several places, all or none (`access.grant`; a
 * change that only takes roles away is logged `access.revoke`, as 0.14 did).
 * At each place the caller manages access (`grant.manage`), and gives no
 * role to themselves; a role is a project role there is, never one that
 * holds what only a project has on an environment; an end is after now. A
 * live grant asked as it is changes nothing; any other row at the place, a
 * lapsed grant or one of a membership before a removal, is replaced in
 * place, in the member's generation, or dropped.
 *
 * A service account's, as 0.14.7's `setAccess` set them: where the caller
 * does not manage access, a person on a session gives it what they could
 * give it (`givesService`), and takes from it what it holds, of a service
 * account they manage (`managesService`): they could give it all it holds. With
 * `admit`, one that is not a member is admitted in the same change, holding
 * nothing before it, and the caller's to give what they could: by someone
 * who could set one up (`setsUpServices`), and one removed, by its remover
 * or whoever runs the instance alone. What these weigh is read with the
 * change: a row of it the vault did not write refuses it, `tampered`.
 */
function accessGrant(input: Presented & AccessGrant, vault: Deciding): Operation<Parts, AccessAnswers['access.grant']> {
  const shown = presented(input);
  const { principal } = input;
  const admit = input.admit ?? false;
  const changes = Array.isArray(input.changes) ? [...input.changes] : [];
  const path = (change: Asked) => (change.environment === null ? change.project : `${change.project}/${change.environment}`);
  if (!isMember(principal) || changes.length === 0 || changes.length > MOST_PLACES || !changes.every(asked) || new Set(changes.map(path)).size !== changes.length
    || typeof admit !== 'boolean' || (admit && !principal.startsWith('token:'))) {
    throw new TypeError('a change of grants names a member, and 1 to 1,000 places by slug, each once, with a project role or null and an ISO 8601 end or null; admit, of a service account alone');
  }
  const service = principal.startsWith('token:');
  // A place with no grant yet gets one under an id drawn here: a decision draws nothing.
  const ids = changes.map(() => randomUUID());
  const action = changes.every((change) => change.role === null) ? 'access.revoke' : 'access.grant';

  const named = sql`(SELECT p.id FROM projects p WHERE p.slug = ANY(${sql.param([...new Set(changes.map((change) => change.project))])}::text[]))`;
  const onProjects = sql`(SELECT p.id FROM projects p WHERE p.slug = ANY(${sql.param(changes.filter((change) => change.environment === null).map((change) => change.project))}::text[]))`;
  // Each project and environment pair through the two unique keys, so each is an index lookup.
  const pairs = changes.filter((change) => change.environment !== null);
  const onEnvironments = sql`(SELECT e.id FROM unnest(${sql.param(pairs.map((change) => change.project))}::text[], ${sql.param(pairs.map((change) => change.environment))}::text[]) AS a(project, environment) JOIN projects p ON p.slug = a.project JOIN environments e ON e.project_id = p.id AND e.slug = a.environment)`;
  // A service account's places weigh too: what the caller holds there says whether they manage it.
  const weighed = service ? sql`(${named} UNION ${projectsOf(principal)})` : named;
  const read = {
    ...callerParts(shown.token, weighed),
    // A service account's grants, their places and roles, and the instance's setting (`managesService`); nothing for a person.
    ...serviceParts(principal),
    member: part(principals, eq(principals.id, principal)),
    project: part(projects, sql`${projects.slug} = ANY(${sql.param([...new Set(changes.map((change) => change.project))])}::text[])`),
    environment: part(environments, sql`${environments.id} IN ${onEnvironments}`),
    // Every row at the places asked, whatever its generation: a place holds one grant a member, and a row left from before is replaced.
    // A service account's every grant, all of which `managesService` weighs, those at the places asked among them.
    held: part(grants, service
      ? sql`${grants.principal} = ${principal}`
      : sql`${grants.principal} = ${principal} AND (${grants.projectId} IN ${onProjects} OR ${grants.environmentId} IN ${onEnvironments})`),
    // Every environment of the projects weighed, whatever its row says: the caller's read takes those that say they are
    // protected, and one whose flag was edited behind the vault would be left unseen, where it is found unsealed.
    beside: part(environments, service ? sql`${environments.projectId} IN ${weighed}` : sql`false`),
    given: part(roles, sql`NOT ${roles.instance} AND ${roles.id} = ANY(${sql.param([...new Set(changes.flatMap((change) => (change.role === null ? [] : [change.role])))])}::text[])`),
    // For a service account, every project role: those asked, those its grants name, and any a caller who sets one up could give it.
    defined: part(roles, service ? sql`NOT ${roles.instance}` : sql`false`),
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
    decide(seen: Seen<typeof read>, at: number, unsealed: Unsealed<typeof read>) {
      const caller = managing(seen, shown, vault, at);
      if ('refused' in caller) return caller;
      const places = placed(seen);
      // Whether they manage access at every place asked: else only a person, on a session, gives a service account what they hold.
      let everywhere = true;
      for (const [i, { project, environment }] of places.entries()) {
        // A personal config is its owner's alone: nobody is granted it. One answer whether a place is not there or not theirs: none says which.
        if (project === undefined || environment === undefined || environment?.owner != null) return { refused: 'no_access' };
        // Managing access never reads a value: nobody gives themselves a role, though they may give one up.
        if (principal === caller.principal && changes[i]!.role !== null) return { refused: 'no_access' };
        if (!(environment === null ? allows(caller.holds, 'grant.manage', { projectId: project.id }) : caller.may('grant.manage', environment))) everywhere = false;
      }
      if (!everywhere && !(service && onSession(caller))) return { refused: 'no_access' };
      const [member] = seen.member;
      const admitting = admit && (member === undefined || member.status === 'removed');
      // The generation its grants are of: one admitted here is new, or in the one its removal moved on to.
      const generation = member?.generation ?? 0;

      if (service && (admitting || !everywhere)) {
        const setting = settingOf(seen);
        const runner = runs(caller);
        const holder = withRoles(caller, seen.defined);
        const where = places.map(({ project, environment }): Place => (environment == null ? { projectId: project!.id } : { projectId: project!.id, environmentId: environment.id, environmentSlug: environment.slug }));
        // Admitted by a person on a session, who could set one up here; brought back by whoever removed it: never past
        // someone else's removal. A service account's token that manages access sets up no other: it would outlive it.
        if (admitting && !runner && (!onSession(caller) || (member !== undefined && member.statusChangedBy !== caller.principal) || !setsUpServices(holder, setting, where))) {
          return { refused: 'no_access' };
        }
        if (!everywhere) {
          // They manage it: they could give it every grant it holds, the one at a place asked included, so taking one away is
          // theirs too. One admitted here holds nothing before, and is theirs; one that is not a member, or holds a grant on a
          // place not found, is nobody's here.
          const account: ServiceAccount | null = admitting ? { grants: [], admittedBy: caller.principal } : serviceOf(seen, principal, at);
          if (account === null || !managesService(holder, setting, caller.principal, account)) return { refused: 'no_access' };
          // And each role asked, where it is asked.
          if (!changes.every(({ role }, i) => role === null || givesService(holder, setting, role, where[i]!))) return { refused: 'no_access' };
        }
      }
      // A row written behind the vault is not a row that is absent: a grant of the service's hidden, a role or a place's
      // protection edited. Told only to whoever may by the rows the vault wrote: anyone else is refused as they would be without it.
      if (service && Object.values(unsealed).some((count) => count > 0)) return { refused: 'tampered' };
      // To whoever may change the member's grants at every place asked, what 0.14 told them of the member.
      if (!admitting) {
        if (member === undefined) return { refused: 'not_a_member' };
        if (member.status !== 'active') return { refused: 'removed' };
      }
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
      if (admitting) {
        const row: Fresh<typeof principals> = member === undefined
          ? { id: principal, status: 'active', role: 'member', scope: null, generation: 0, createdAt: now, createdBy: caller.principal, statusChangedAt: now, statusChangedBy: caller.principal, frozenAt: null }
          : { ...withoutMac(member), status: 'active', role: 'member', scope: null, statusChangedAt: now, statusChangedBy: caller.principal };
        writes.push(put(principals, row, member ?? null));
      }
      const lines: Record<string, unknown>[] = [];
      const outcomes = changes.map(({ role, expiresAt }, i): AccessChange => {
        const { project, environment } = places[i] as { project: Row<typeof projects>; environment: Row<typeof environments> | null };
        const was = seen.held.find((row) => row.principal === principal && (environment === null ? row.projectId === project.id : row.environmentId === environment.id));
        // What the member holds there now: a grant of this membership, not lapsed.
        const current = was !== undefined && was.generation === generation && (was.expiresAt === null || was.expiresAt.getTime() > at) ? was : undefined;
        const ends = expiresAt === null ? null : new Date(Date.parse(expiresAt));
        const place = environment === null ? { project: project.id } : { environment: environment.id };
        if (role === null) {
          if (was !== undefined) writes.push(drop(grants, was));
          if (current === undefined) return 'unchanged';
          lines.push({ ...place, role: null, was: current.role });
          return 'revoked';
        }
        if (current !== undefined && current.role === role && current.expiresAt?.getTime() === ends?.getTime()) return 'unchanged';
        const grant: Fresh<typeof grants> = { id: was?.id ?? ids[i]!, principal, generation, projectId: environment === null ? project.id : null, environmentId: environment?.id ?? null, role, expiresAt: ends, grantedAt: now, grantedBy: caller.principal };
        writes.push(put(grants, grant, was ?? null));
        lines.push({ ...place, role, expiresAt: ends?.toISOString() ?? null, was: current?.role ?? null });
        return current === undefined ? 'created' : 'updated';
      });
      return {
        writes,
        entry: said(action, caller, shown, [`principal:${principal}`, ...places.map(({ project, environment }) => (environment === null ? `project:${project!.id}` : `environment:${environment!.id}`))], {
          member: principal,
          changes: lines,
          // Admitted with it: the action 0.14.7 logged apart, in the generation it comes back in.
          ...(admitting ? { admitted: member === undefined ? 'member.add' : 'member.restore', generation } : {}),
        }),
        answer: { changes: outcomes, ...(admit ? { created: admitting } : {}) },
      };
    },
  };
}

/** A role's definition as a change asks it, copied and in order, or undefined for one `definitionProblem` refuses: an array from another isolate may have holes. */
function definitionAsked(value: unknown): RoleDefinition | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const { name, description, permissions, protected: guarded } = value as Record<string, unknown>;
  if (!text(name) || !text(description) || !Array.isArray(permissions) || !Array.isArray(guarded)) return undefined;
  const definition = { name, description, permissions: [...permissions], protected: [...guarded] } as RoleDefinition;
  return definitionProblem(definition) === null ? normalDefinition(definition) : undefined;
}

/** A role as its row says it. */
const definitionIn = (row: Row<typeof roles>): RoleDefinition => ({ name: row.name, description: row.description, permissions: row.permissions as Permission[], protected: row.protected as Permission[] });

/** Whether a role's row says `definition`, its permissions in any order; no row, none. */
function says(row: Row<typeof roles> | undefined, definition: RoleDefinition | null): boolean {
  if (row === undefined || definition === null) return row === undefined && definition === null;
  const same = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((item) => b.includes(item));
  return row.name === definition.name && row.description === definition.description && same(row.permissions, definition.permissions) && same(row.protected, definition.protected);
}

/**
 * A role defined, edited, put back as it ships or deleted
 * (`policy.change`), by an Owner of the whole instance on a session, as
 * 0.14 allowed. Roles are rows, and a role with no row is no role: one put
 * back is written as it ships, one deleted is dropped, and one that ships
 * whose row was deleted is written again.
 *
 * A grant is read only to refuse: deleting a role one names, defining one
 * that does not ship and has no row while one names it, or giving a role
 * one names on an environment what only a project has. The read takes the
 * first such grant, and one the vault did not write refuses as `tampered`:
 * it may stand in front of a genuine one. After a genuine deletion no grant
 * names the role, so defining it again refuses no honest caller; a grant
 * put back around the vault refuses it, and one kept hidden from the
 * deletion through the definition is the accepted "row taken away for one
 * decision" (docs/design/0.16.md). One on an environment put back after a
 * widening gives nothing (`grantDefinition`).
 */
function roleEdit(input: Presented & RoleEdit, vault: Deciding): Operation<Parts, AccessAnswers['policy.change']> {
  const shown = presented(input);
  const { instance, role, revision } = input;
  const definition = input.definition === null ? null : definitionAsked(input.definition);
  const fixed = (instance ? (FIXED_ROLES.instanceRoles as readonly string[]) : FIXED_ROLES.roles).includes(role);
  if (
    typeof instance !== 'boolean' || typeof role !== 'string' || !ROLE_ID.test(role) || (instance && !isInstanceRole(role)) || fixed || definition === undefined
    || (revision !== undefined && (typeof revision !== 'string' || !ROLE_REVISION.test(revision)))
  ) {
    throw new TypeError("a role's change names a project role or an Admin's or Auditor's, by id, never Owner's or the instance's Member's, with a definition as definitionProblem holds one or null, and the role's revision as its preview weighed it, or none");
  }
  // What it holds once changed: one that ships, put back, as it ships; one an Owner made, deleted, nothing.
  const shipped = instance ? INSTANCE_ROLES[role as InstanceRole] : isBuiltinRole(role) ? ROLES[role] : null;
  const next = definition ?? (shipped === null ? null : normalDefinition(shipped));
  // The first grant naming the role, which refuses deleting it, or defining one that does not ship where no row is (which
  // the row read beside it says); the first on an environment, which refuses giving it what only a project has.
  const wide = next !== null && next.permissions.some((permission) => PROJECT_ONLY_PERMISSIONS.includes(permission));
  const first = (onEnvironment: boolean) => sql`${grants.id} = (SELECT g.id FROM grants g WHERE g.role = ${role}${onEnvironment ? sql` AND g.environment_id IS NOT NULL` : sql``} ORDER BY g.id LIMIT 1)`;
  const read = {
    ...callerParts(shown.token, NOWHERE),
    edited: part(roles, and(eq(roles.instance, instance), eq(roles.id, role))),
    naming: part(grants, !instance && (next === null || shipped === null) ? first(false) : sql`false`),
    onEnvironment: part(grants, !instance && wide ? first(true) : sql`false`),
  };
  const object = `${instance ? 'instance-role' : 'role'}:${role}`;
  return {
    read,
    denied: refusedTo('policy.change', shown, vault.workloads, { objects: () => [object] }),
    decide(seen: Seen<typeof read>, at: number, unsealed: Unsealed<typeof read>) {
      const caller = managing(seen, shown, vault, at);
      if ('refused' in caller) return caller;
      if (!runs(caller) || !ownsAllAsking(caller)) return { refused: 'no_access' };
      // A row the vault did not write is neither the role the caller weighed nor one to write over.
      if (unsealed.edited > 0) return { refused: 'tampered' };
      const [row] = seen.edited;
      if (revision !== undefined && roleRevision(row === undefined ? null : definitionIn(row)) !== revision) return { refused: 'policy_changed' };
      if (row === undefined && next === null) return { refused: 'invalid' };
      // A grant naming it refuses its deletion, and defining one that does not ship and is not there; the first, unreadable,
      // may hide a genuine one behind it.
      if (next === null || (shipped === null && row === undefined)) {
        if (unsealed.naming > 0) return { refused: 'tampered' };
        if (seen.naming.length > 0) return { refused: 'role_granted' };
      }
      if (wide) {
        if (unsealed.onEnvironment > 0) return { refused: 'tampered' };
        if (seen.onEnvironment.length > 0) return { refused: 'invalid' };
      }
      const detail = { role, instance, definition: next, was: row === undefined ? null : definitionIn(row) };
      if (says(row, next)) return { writes: [], entry: said('policy.change', caller, shown, [object], { ...detail, unchanged: true }), answer: { role: next } };
      return {
        writes: [next === null ? drop(roles, row!) : put(roles, { instance, id: role, ...next, permissions: [...next.permissions], protected: [...next.protected] }, row ?? null)],
        entry: said('policy.change', caller, shown, [object], detail),
        answer: { role: next },
      };
    },
  };
}

/** The setting as the policy row holds it, or null for one that does not read as a scope. */
function settingIn(row: Row<typeof policy>): Scope | null {
  try {
    const setting: unknown = JSON.parse(row.serviceAccounts);
    return isScope(setting) ? normalScope(setting) : null;
  } catch {
    return null;
  }
}

/**
 * Where people set up service accounts themselves (`settings.change`):
 * whoever runs the instance sets it, as 0.14 allowed, in the instance's
 * policy row. That row is always there: without it the change would make
 * one, and lift a freeze of every workload that the row held, so a change
 * that does not find it refuses.
 */
function settingsEdit(input: Presented & SettingsEdit, vault: Deciding): Operation<Parts, AccessAnswers['settings.change']> {
  const shown = presented(input);
  const asked = scopeAsked(input.serviceAccounts);
  if (asked === undefined) throw new TypeError('who sets up service accounts is a scope: projects and environments, each all, or only or except 1,000 slugs at most');
  const read = {
    ...callerParts(shown.token, NOWHERE),
    instance: part(policy, eq(policy.onlyRow, true)),
    scoped: projectsIn(asked),
  };
  return {
    read,
    denied: refusedTo('settings.change', shown, vault.workloads, { objects: (seen: Seen<typeof read>) => seen.scoped.map((project) => `project:${project.id}`) }),
    decide(seen: Seen<typeof read>, at: number) {
      const caller = managing(seen, shown, vault, at);
      if ('refused' in caller) return caller;
      if (!runs(caller)) return { refused: 'no_access' };
      const [row] = seen.instance;
      if (row === undefined) return { refused: 'tampered' };
      const setting = scopeById(asked, seen.scoped);
      if (setting === undefined) return { refused: 'no_access' };
      const before = settingIn(row);
      const objects = seen.scoped.map((project) => `project:${project.id}`);
      const detail = { serviceAccounts: setting, was: before };
      if (JSON.stringify(before) === JSON.stringify(setting)) return { writes: [], entry: said('settings.change', caller, shown, objects, { ...detail, unchanged: true }), answer: { serviceAccounts: setting } };
      return {
        writes: [amended(policy, row, { serviceAccounts: JSON.stringify(setting), changedAt: new Date(at), changedBy: caller.principal })],
        entry: said('settings.change', caller, shown, objects, detail),
        answer: { serviceAccounts: setting },
      };
    },
  };
}

/** What the caller holds, every project role as its row says beside their own: whether they give a service account one weighs them all. */
function withRoles(caller: Asking, defined: readonly Row<typeof roles>[]): Holdings {
  const own = caller.holds;
  return { ...own, policy: { ...own.policy, roles: { ...definitionsOf(defined), ...own.policy.roles } } };
}

/** A row as read, but for its MAC: the engine seals what a change writes. */
function withoutMac<T extends { mac: unknown }>(row: T): Omit<T, 'mac'> {
  const { mac: _, ...kept } = row;
  return kept;
}

/** The changes of members, grants, roles and the instance's policy. */
export const accessOperations: Operations<AccessChanges> = {
  'member.put': memberPut,
  'member.remove': memberRemove,
  'access.grant': accessGrant,
  'policy.change': roleEdit,
  'settings.change': settingsEdit,
};
