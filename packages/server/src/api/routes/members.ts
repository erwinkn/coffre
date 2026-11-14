import type { Queryable } from '@coffre/db';
import { administers, EVERYWHERE, inScope, isScope, normalScope, runsInstance, type Filter, type InstanceRole, type Permission, type Policy, type Role, type RoleDefinition, type Scope } from '@coffre/core/access';
import { instanceRole, roleId, scopeInput, slug } from '@coffre/core/schemas';
import type { AccessChange, Called } from '@coffre/core/vault';
import { z } from 'zod';

import { members, projectNamed, projectSlugs, reportOf, type Definition, type GrantRow, type MemberRow } from '../../db/queries/members.ts';
import type { PlaceRow } from '../../db/queries/places.ts';
import { can, canAnywhere, permissionsAt, placeOf, projectsReached, type Place } from '../caller.ts';
import { changed } from '../change.ts';
import { ApiError, badRequest, refusal } from '../errors.ts';
import { formatPath, parsePath, type Path } from '../paths.ts';
import { route } from '../route.ts';

/**
 * Members and what they hold (docs/design/0.16.md, "The server"): the
 * directory, one member's access, and the changes of members and grants,
 * in 0.14.7's shapes. A list is one call to the vault, `caller`, and fixed
 * statements, scoped by its answer; what the caller is shown is worked out
 * from that answer as 0.14.7 worked it out from its own. A change is one
 * call to the vault, which decides it.
 */

/** A member as the vault takes one (`isMember` in its ops/access.ts): told before any call, so a fault never stands for a refusal. */
const PRINCIPAL = /^(user|token):[^\s:]\S*$/;

/** A member named in a path: `user:<email>`, which is one person however it is cased, or `token:<name>`. */
export function memberOf(raw: string): string {
  const member = raw.startsWith('user:') ? raw.toLowerCase() : raw;
  if (member.length > 256 || !PRINCIPAL.test(member) || member.includes('\0') || !wellFormed(member)) throw badRequest('name a member as user:<email> or token:<name>');
  return member;
}

/** Whether text holds no half of a surrogate pair, which Postgres refuses: `encodeURIComponent` throws on one. */
export function wellFormed(text: string): boolean {
  try {
    encodeURIComponent(text);
    return true;
  } catch {
    return false;
  }
}

export const typeOf = (member: string): 'user' | 'service' => (member.startsWith('user:') ? 'user' : 'service');
const idOf = (member: string) => member.slice(member.indexOf(':') + 1);

/** By code unit, as 0.14.7 sorted a report. */
const compare = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

const notServed = (what: string) => new ApiError('not_implemented', `${what} is not served yet`);

/** A grant as a member's lists show it. */
export type MemberGrant = {
  /** Its member and place, `user:ada@acme.example/market/prod`: one grant per member per place. */
  id: string;
  project: string;
  /** Null for a grant on the whole project. */
  environment: string | null;
  role: Role;
  /** Its name, and what it holds where nothing is protected, as the instance defines it: one it no longer defines goes by its id and holds nothing. */
  roleName: string;
  permissions: Permission[];
  expiresAt: string | null;
};

export type Member = {
  member: string;
  principalType: 'user' | 'service';
  principalId: string;
  /** `member` for every service account. */
  instanceRole: InstanceRole;
  /** Where their instance role applies, projects by slug; everywhere for a member. Null unless the caller runs the instance: a scope names projects the caller may not see. */
  scope: Scope | null;
  /** Asked of a place (`?path=`): whether their instance role reaches it, beside any grant there. */
  reachesByRole: boolean;
  /** A service account the caller manages: every one, to whoever runs the instance. */
  managed: boolean;
  /** 0.14's finding of the vault's, which no page reads now: the rows are shown as stored, and false. */
  tampered: boolean;
  /** Whether the deployment names them an Owner: the app is not told, and false (the vault refuses `configured_owner` all the same). */
  declared: boolean;
  grants: MemberGrant[];
};

/** What a member's row says of where they stand. */
type Standing = Pick<MemberRow, 'id' | 'status' | 'role' | 'scope'>;

/** Where an instance role applies, as the row keeps it: everywhere for none; one that does not read as a scope reaches nothing, as the vault takes it. */
function scopeOf(row: Standing): Scope {
  if (row.scope === null) return EVERYWHERE;
  try {
    const scope: unknown = JSON.parse(row.scope);
    if (isScope(scope)) return scope;
  } catch {
    // As below.
  }
  return { projects: { only: [] }, environments: { only: [] } };
}

/** Someone's instance role: a person's, while active. */
export const roleOf = (row: Standing): InstanceRole => (row.status === 'active' && typeOf(row.id) === 'user' ? (row.role as InstanceRole) : 'member');

/** Where their role applies: everywhere for a member, who holds nothing by it. */
export const standingOf = (row: Standing): Scope => (roleOf(row) === 'member' ? EVERYWHERE : scopeOf(row));

/** A scope as the API shows it: projects by slug, those still there, sorted. */
export function scopeView(scope: Scope, slugs: Record<string, string>): Scope {
  const named = (ids: string[]) => ids.flatMap((id) => (Object.hasOwn(slugs, id) ? [slugs[id]!] : [])).sort();
  const projects: Filter = scope.projects === 'all' ? 'all' : 'only' in scope.projects ? { only: named(scope.projects.only) } : { except: named(scope.projects.except) };
  return { projects, environments: scope.environments };
}

const placeOfGrant = (grant: GrantRow): Place => placeOf(grant.project, grant.environment);

/**
 * Who reads each of these places, by name: the active members whose grants
 * or instance role hold `secret.read` there, weighed by the rule the vault
 * decides by (`can`), on what each holds as the vault would read it: their
 * live grants, and the definitions of the roles they hold, from the rows,
 * unchecked. A person holds a protected environment's column of their
 * roles there, a service account the other one; a personal config is read
 * by its owner alone. What a reference's `readers` show: it decides
 * nothing, and no credential's scope narrows it. One statement, the grants
 * on these places' projects alone, however many places.
 */
const definitionOf = (row: Definition): RoleDefinition => ({ name: row.name, description: '', permissions: row.permissions as Permission[], protected: row.protected as Permission[] });

export async function readersAt(db: Queryable, who: Called, places: readonly Place[], now: Date): Promise<string[][]> {
  if (places.length === 0) return [];
  const rows = await members(db, { within: [...new Set(places.map((place) => place.projectId))], listed: 'held', roles: true, removed: false, scopes: false, now });
  const holders = rows.map((row) => ({
    principal: row.id,
    holds: {
      role: roleOf(row),
      scope: standingOf(row),
      grants: row.grants.map((grant) => ({ projectId: grant.project.id, environmentId: grant.environment?.id ?? null, role: grant.role as Role })),
      // As the vault's answer about them would carry it: the roles they hold, no other, and every environment the instance protects.
      policy: {
        ...who.holds.policy,
        roles: Object.fromEntries(row.grants.flatMap((grant) => (grant.definition === null ? [] : [[grant.role, definitionOf(grant.definition)]]))),
        instanceRoles: Object.fromEntries(row.roleDefinition === null ? [] : [[row.role, definitionOf(row.roleDefinition)]]) as Policy['instanceRoles'],
      },
      service: typeOf(row.id) === 'service',
    },
  }));
  return places.map((place) => holders.filter((holder) => can(holder, 'secret.read', place)).map((holder) => holder.principal));
}

/** By project, then environment, the project-wide grant after its environments. */
function byPlace(a: GrantRow, b: GrantRow): number {
  if (a.project.slug !== b.project.slug) return a.project.slug < b.project.slug ? -1 : 1;
  const [x, y] = [a.environment?.slug ?? null, b.environment?.slug ?? null];
  if (x === y) return 0;
  if (x === null) return 1;
  if (y === null) return -1;
  return x < y ? -1 : 1;
}

function grantView(member: string, grant: GrantRow): MemberGrant {
  const environment = grant.environment?.slug ?? null;
  return {
    id: `${member}/${grant.project.slug}${environment === null ? '' : `/${environment}`}`,
    project: grant.project.slug,
    environment,
    role: grant.role,
    roleName: grant.definition?.name ?? grant.role,
    permissions: (grant.definition?.permissions ?? []) as Permission[],
    expiresAt: grant.expiresAt,
  };
}

/**
 * Who lists members and reads what one holds: an Admin or Owner, scoped or
 * not, on no credential's scope, and whoever manages access somewhere.
 * 0.14 also let in whoever sets up service accounts, which waits on the
 * instance's setting (D239).
 */
const administrator = ({ holds }: Called) => holds.credentialScope == null && administers(holds.role);

/** The places of a path a project's access list asks about: the project and its environments, or the one environment. */
/** Whether the caller can do anything in the project or one of its environments: what `GET /projects` lists them. */
function reachesAny(who: Called, project: PlaceRow): boolean {
  return [placeOf(project, null), ...project.environments.map((environment) => placeOf(project, environment))].some((place) => permissionsAt(who, place).length > 0);
}

function placesIn(project: PlaceRow, environment: string | undefined): Place[] {
  return [
    ...(environment === undefined ? [placeOf(project, null)] : []),
    ...project.environments.filter((candidate) => environment === undefined || candidate.slug === environment).map((candidate) => placeOf(project, candidate)),
  ];
}

/** `2026-12-31` is the end of that day, UTC; a full time is itself. Past, or past what the vault's ISO 8601 writes (year 9999), is no end. */
function parseUntil(until: string, now: number): string {
  const time = /^\d{4}-\d{2}-\d{2}$/.test(until) ? Date.parse(`${until}T23:59:59.999Z`) : Date.parse(until);
  if (!Number.isFinite(time) || time >= Date.UTC(10000, 0, 1)) throw badRequest(`"${until}" is not a date`);
  if (time <= now) throw badRequest(`"${until}" is in the past`);
  return new Date(time).toISOString();
}

/** What a member should hold, each place by path: a role, a role until a date, or null for none. */
const accessPatch = z.record(z.string().max(200), z.union([roleId, z.object({ role: roleId, until: z.string().max(40).nullable() }).strict(), z.null()]));

/** The most places one change of grants names, as the vault takes them. */
const MOST_PLACES = 1000;

type Wanted = { path: string; project: string; environment: string | null; role: string | null; expiresAt: string | null };

/** The grants a body asks for, each place by its path, checked before any call: a place named once, by slug, an end to come. */
function grantsAsked(input: z.output<typeof accessPatch>): Wanted[] {
  const now = Date.now();
  const wanted = Object.entries(input).map(([raw, value]) => {
    const path = parsePath(raw, [1, 2]);
    if (!slug.safeParse(path.project).success || (path.environment !== undefined && !slug.safeParse(path.environment).success)) {
      throw badRequest(`${raw}: a grant names a project, or one of its environments, by slug`);
    }
    const role = value === null ? null : typeof value === 'string' ? value : value.role;
    const until = value !== null && typeof value === 'object' ? value.until : null;
    return { path: formatPath(path), project: path.project, environment: path.environment ?? null, role, expiresAt: until === null ? null : parseUntil(until, now) };
  });
  if (new Set(wanted.map((want) => want.path)).size !== wanted.length) throw badRequest('name each place once');
  if (wanted.length > MOST_PLACES) throw badRequest(`a change of grants names at most ${MOST_PLACES} places`);
  return wanted;
}

/** What became of each place, by its path, in the order asked. */
const byPath = (wanted: readonly Wanted[], changes: readonly AccessChange[]) => Object.fromEntries(wanted.map((want, i) => [want.path, changes[i]!])) as Record<string, AccessChange>;

export const memberRoutes = {
  /**
   * Members and their live grants. Admins and Owners see everyone, with the
   * grants they manage: all of them, or, scoped, those inside their scope.
   * Anyone else sees the grants in the places where they hold
   * `grant.manage`, and the members those grants belong to. `path` narrows
   * it to who reaches one project or environment: by a grant there, or, to
   * whoever manages access there, by an instance role whose scope takes it
   * in. Where a role applies (`scope`) only those who run the instance see,
   * and they alone see who was removed.
   *
   * One call to the vault and one statement; two with `path`, the project
   * first.
   */
  ...route('GET /members', {
    input: z.object({ path: z.string().max(200).refine((path) => !path.includes('\0') && wellFormed(path), 'a path is well-formed text, with no NUL').optional() }),
    run: async (ctx, { input }) => {
      const who = await ctx.caller();
      const path: Path | undefined = input.path === undefined ? undefined : parsePath(input.path, [1, 2]);
      if (!administrator(who) && !canAnywhere(who, 'grant.manage')) throw refusal('no_access');
      const runs = runsInstance(who.holds);
      const reached = projectsReached(who);
      const target = path === undefined ? undefined : await projectNamed(ctx.db, path.project);
      // A project not there and one the caller can do nothing in are one answer, as `GET /projects` tells them apart: the
      // filter above is broad (an Admin scoped to all but `hidden` gets null), so what they hold there decides.
      if (target === null || (target !== undefined && !runs && !reachesAny(who, target))) throw refusal('no_access', input.path);
      const everyone = path === undefined && administrator(who);
      const asked = target === undefined ? [] : placesIn(target, path?.environment);
      // Who reaches the path by their instance role is shown to whoever manages access there.
      const managesPath = target !== undefined && (runs || asked.some((place) => can(who, 'grant.manage', place)));
      const rows = await members(ctx.db, {
        within: runs ? null : reached,
        ...(target === undefined ? {} : { project: target.id }),
        listed: everyone ? 'all' : 'held',
        roles: managesPath,
        removed: everyone && runs,
        scopes: runs,
        now: new Date(),
      });
      const inPath = (grant: GrantRow) => path?.environment === undefined || grant.environment?.slug === path.environment;
      const listed: Member[] = [];
      for (const row of rows) {
        if (row.status === 'removed') continue;
        const service = typeOf(row.id) === 'service';
        const managed = service && runs;
        const visible = row.grants.filter((grant) => (runs || can(who, 'grant.manage', placeOfGrant(grant))) && inPath(grant)).sort(byPlace);
        const scope = standingOf(row);
        const reachesByRole = managesPath && row.roleHolds && roleOf(row) !== 'member' && asked.some((place) => inScope(scope, place));
        if (!everyone && visible.length === 0 && !reachesByRole && !(managed && path === undefined)) continue;
        listed.push({
          member: row.id,
          principalType: typeOf(row.id),
          principalId: idOf(row.id),
          instanceRole: roleOf(row),
          scope: runs ? scopeView(scope, row.scopeSlugs) : null,
          reachesByRole,
          managed,
          tampered: false,
          declared: false,
          grants: visible.map((grant) => grantView(row.id, grant)),
        });
      }
      listed.sort((a, b) => a.principalType.localeCompare(b.principalType) || a.principalId.localeCompare(b.principalId));
      // Those removed, so they can be found and let back in, each with how many keys they still know the value of (`seenBy`).
      const removed = rows.filter((row) => row.status === 'removed').map((row) => ({ principalType: typeOf(row.id), principalId: idOf(row.id), toRotate: row.toRotate ?? 0 }));
      return { members: listed, removed };
    },
  }),

  /**
   * Who someone is to the instance, what still lets them in, and the keys
   * whose current value they know, to rotate once they leave: 0.14.7's
   * member report, for whoever runs the instance, removed members
   * included. A key is to rotate when they saw it on or after its value was
   * first written, or wrote that value themselves (`seenBy`). One call to
   * the vault and one statement, from their own rows. The tokens they
   * issued, their personal tokens and connected apps are not read here yet,
   * and the references they made need who made a reference, which 0.16
   * keeps nowhere: each null, "not listed", which the client's type allows.
   */
  ...route('GET /members/:member', {
    run: async (ctx, { params }) => {
      const principal = memberOf(params.member);
      const who = await ctx.caller();
      if (!runsInstance(who.holds)) throw refusal('no_access');
      const row = await reportOf(ctx.db, principal, new Date());
      if (row === null) throw new ApiError('not_found', 'no such member');
      const exposed = row.keys.filter((key) => key.rotate)
        .sort((a, b) => compare(a.project, b.project) || compare(a.environment, b.environment) || compare(a.key, b.key))
        .map((key) => ({ project: key.project, environment: key.environment, key: key.key, version: key.version, how: key.wrote ? 'wrote' as const : 'read' as const, at: key.at! }));
      const removed = row.status === 'removed';
      return {
        principalType: typeOf(principal),
        principalId: idOf(principal),
        status: row.status,
        instanceRole: roleOf(row),
        scope: scopeView(standingOf(row), row.scopeSlugs),
        declared: false,
        removedAt: removed ? row.statusChangedAt : null,
        removedBy: removed ? idOf(row.statusChangedBy) : null,
        live: row.live,
        exposed,
        rotated: row.keys.length - exposed.length,
        issuedTokens: null,
        apps: null,
        personalTokens: null,
        references: null,
        personal: row.personal,
      };
    },
  }),

  /**
   * One member's access, for their page: their instance role and scope,
   * and the grants the caller manages, all of them to whoever runs the
   * instance. For whoever lists members. One call to the vault and one
   * statement.
   */
  ...route('GET /members/:member/access', {
    run: async (ctx, { params }) => {
      const principal = memberOf(params.member);
      const who = await ctx.caller();
      if (!administrator(who) && !canAnywhere(who, 'grant.manage')) throw refusal('no_access');
      const runs = runsInstance(who.holds);
      const [row] = await members(ctx.db, { member: principal, within: runs ? null : projectsReached(who), listed: 'all', removed: true, scopes: runs, now: new Date() });
      if (row === undefined) throw new ApiError('not_found', 'no such member');
      const managed = typeOf(principal) === 'service' && row.status === 'active' && runs;
      return {
        member: principal,
        principalType: typeOf(principal),
        principalId: idOf(principal),
        status: row.status,
        instanceRole: roleOf(row),
        scope: runs ? scopeView(standingOf(row), row.scopeSlugs) : null,
        managed,
        grants: row.grants.filter((grant) => runs || can(who, 'grant.manage', placeOfGrant(grant))).sort(byPlace).map((grant) => grantView(principal, grant)),
      };
    },
  }),

  /**
   * Admit a member, bring one back, or set their instance role, as their
   * row calls for: one change of the vault's (`member.put`), which reads the
   * row and does whichever it calls for, all under its head, and says which
   * (`created`). No role keeps an active member's, and admits anyone else as
   * `member`; a scope comes with a role but `member`, and either filter left
   * out is `all`. A service account holds no role but `member`, and is made
   * with its grants (`access`, as `PATCH /access` takes them), admitted or
   * brought back in the same change (`access.grant` with `admit`), by
   * whoever may set it up there; it answers what became of each place.
   *
   *   { "role": "admin", "scope": { "projects": { "only": ["market"] } } }
   *   { "access": { "market/dev": "developer" } }
   *
   * No statement, but one, after the change, when the answer keeps a scope
   * that names projects the body did not: their slugs.
   */
  ...route('PUT /members/:member', {
    input: z.object({ role: instanceRole.optional(), scope: scopeInput.optional(), access: accessPatch.refine((access) => Object.keys(access).length > 0, 'name a place to grant').optional() }).strict(),
    run: async (ctx, { params, input }) => {
      const principal = memberOf(params.member);
      const service = typeOf(principal) === 'service';
      if (input.access !== undefined) {
        if (!service || input.role !== undefined || input.scope !== undefined) throw badRequest('access comes with a service account, and no role: a person is given grants once a member');
        // Admitted, or brought back, with its grants, in one change of the vault's: all of it or none.
        const wanted = grantsAsked(input.access);
        const { changes, created } = await changed(ctx, { op: 'access.grant', principal, changes: wanted.map(({ path: _, ...change }) => change), admit: true }, principal);
        return { member: principal, instanceRole: 'member' as const, scope: EVERYWHERE, created: created ?? false, changes: byPath(wanted, changes) };
      }
      if (input.scope !== undefined && input.role === undefined) throw badRequest('a scope goes with a role: name the role too');
      if (input.scope !== undefined && input.role === 'member') throw badRequest('a member holds nothing by their role: it takes no scope');
      const asked = input.scope === undefined ? null : normalScope({ projects: input.scope.projects ?? 'all', environments: input.scope.environments ?? 'all' });
      let answer;
      try {
        answer = await changed(ctx, { op: 'member.put', principal, role: input.role ?? null, scope: asked }, principal);
      } catch (error) {
        // A service account asked a role the vault refuses as it refuses any shape it does not take: said as 0.14.7 said it.
        if (service && error instanceof ApiError && error.reason === 'invalid') throw new ApiError('conflict', `${principal}: a service account holds project grants only, never an instance role`, 'invalid');
        throw error;
      }
      const { role, scope, created } = answer;
      // The scope as asked, by slug, when the body named it; the one kept otherwise, whose projects only their ids name.
      const listed = scope === null || scope.projects === 'all' ? [] : 'only' in scope.projects ? scope.projects.only : scope.projects.except;
      const shown = role === 'member' || scope === null ? EVERYWHERE : input.role !== undefined ? (asked ?? EVERYWHERE) : scopeView(scope, listed.length === 0 ? {} : await projectSlugs(ctx.db, listed));
      return { member: principal, instanceRole: role, scope: shown, created };
    },
  }),

  /**
   * Remove a member: their grants go, their sign-in accounts are revoked,
   * and their generation moves on, which ends every session, token and
   * binding they hold. One change of the vault's. It says how many grants
   * went; the rest it ends without counting, and those are null. Their
   * report comes with the offboarding design: null until then.
   */
  ...route('DELETE /members/:member', {
    run: async (ctx, { params }) => {
      const principal = memberOf(params.member);
      const { revoked } = await changed(ctx, { op: 'member.remove', principal }, principal);
      return { revoked: { grants: revoked, sessions: null, tokens: null, identities: null, apps: null }, report: null };
    },
  }),

  /**
   * Set what one member holds, declaratively: each path names a project or
   * an environment, and the role they should have there, until a date, or
   * null for none. Places left out are left alone. One change of the
   * vault's: all of it or none. A service account's grants are given by
   * whoever manages it, or, of a role they hold all of, by whoever the
   * instance lets set one up there (`givesService`).
   *
   *   { "api": "developer", "api/prod": { "role": "viewer", "until": "2026-12-31" }, "web": null }
   */
  ...route('PATCH /access/:member', {
    input: accessPatch,
    run: async (ctx, { params, input }) => {
      const principal = memberOf(params.member);
      const wanted = grantsAsked(input);
      if (wanted.length === 0) return { changes: {} };
      const { changes } = await changed(ctx, { op: 'access.grant', principal, changes: wanted.map(({ path: _, ...change }) => change) }, principal);
      return { changes: byPath(wanted, changes) };
    },
  }),
};
