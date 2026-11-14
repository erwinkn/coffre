import {
  allows,
  definitionProblem,
  FIXED_ROLES,
  INSTANCE_ROLES,
  isBuiltinRole,
  isInstanceRole,
  normalDefinition,
  ownsInstance,
  PERMISSIONS,
  PROJECT_ONLY_PERMISSIONS,
  ROLE_ID,
  ROLES,
  runsInstance,
  type Holdings,
  type InstanceRole,
  type Permission,
  type Place,
  type Policy,
  type RoleDefinition,
} from '@coffre/core/access';
import { ROLE_REVISION, roleRevision, type Called } from '@coffre/core/vault';
import { z } from 'zod';

import { members } from '../../db/queries/members.ts';
import { places } from '../../db/queries/places.ts';
import { roleRows, rolesWeighed, type RoleRow } from '../../db/queries/policy.ts';
import { changed } from '../change.ts';
import type { ApiContext } from '../context.ts';
import { ApiError, badRequest, notFound, refusal } from '../errors.ts';
import { route } from '../route.ts';
import { roleOf, standingOf, typeOf } from './members.ts';

/**
 * The instance's roles (docs/design/roles.md, docs/design/0.16.md, "The
 * server"), in 0.14.7's shapes: every role as the instance defines it, for
 * any member; a change of one, weighed first (`?dryRun=1`), then made as
 * weighed (`?revision=`), by an Owner of the whole instance. The list is
 * one call to the vault, `caller`, and one statement; a change is one
 * `policy.change` and no statement; weighing one is `caller` and three.
 */

/** A role as `GET /roles` lists it: as the instance defines it now, beside how it ships. */
export type RoleView = RoleDefinition & {
  id: string;
  /** One coffre ships; false for one an Owner made. */
  builtin: boolean;
  /** A role that ships, which an Owner changed: Reset to default puts it back. */
  edited: boolean;
  /** Owner, and the instance's Member: nobody edits them. */
  fixed: boolean;
  /** How it ships; null for one an Owner made. */
  default: RoleDefinition | null;
  /** Whether a grant on an environment may name it: it holds nothing project-wide. Instance roles: false. */
  assignableToEnvironment: boolean;
  /** Grants that name it, lapsed ones too; for an instance role, the people who hold it. */
  grants: number;
};

/** A role as a change answers it: as `GET /roles` lists it, but its grants null, uncounted, since a change reads no row. */
export type ChangedRole = Omit<RoleView, 'grants'> & { grants: number | null };

/** Every role, as `GET /roles` lists them: project roles, instance roles, and whether the caller edits them. */
export type RolesView = { roles: RoleView[]; instanceRoles: RoleView[]; editable: boolean };

/** What a change to a role would do to one permission, one way, where it is protected or not (`impactOf`). */
export type ImpactLine = {
  change: 'widens' | 'narrows';
  permission: Permission;
  /** In protected environments; always false for a project-wide permission. */
  protected: boolean;
  people: number;
  /** Service accounts it reaches, which hold a role's first column, in a protected environment too. */
  services: number;
  /** Environments it changes at; 0 for a project-wide permission, which `projects` counts. */
  environments: number;
  projects: number;
  /** A few of them, `ada@acme.example on market/prod`, `ci on market/prod`. */
  examples: string[];
};

/**
 * What a change to a role would do, and the role it was weighed from, by
 * its revision (`roleRevision`): the change, confirmed with it, is made
 * from that role or refused `policy_changed`.
 */
export type RoleImpact = { impact: ImpactLine[]; sentence: string; revision: string };

type Kind = 'role' | 'instance-role';

/** A role's definition, both columns: checked whole (`definitionProblem`) before the vault is asked. */
const roleDefinition = z.object({
  name: z.string().max(40),
  description: z.string().max(200),
  permissions: z.array(z.enum(PERMISSIONS)).max(PERMISSIONS.length),
  protected: z.array(z.enum(PERMISSIONS)).max(PERMISSIONS.length),
}).strict();

/** `?dryRun=1` weighs a change and makes none; `?revision=` makes it from the role its preview weighed. */
const roleChange = z.object({ dryRun: z.enum(['1', 'true']).optional(), revision: z.string().regex(ROLE_REVISION, 'a revision is what a preview of the change answered').optional() }).strict();

/** Whether the caller edits roles: an Owner of the whole instance, signed in as themselves, on no credential's scope. */
const editsRoles = ({ principal, holds }: Called) => typeOf(principal) === 'user' && runsInstance(holds) && ownsInstance(holds);

/** A role as coffre ships it, or null for one an Owner made. */
function shippedAs(kind: Kind, id: string): RoleDefinition | null {
  if (kind === 'instance-role') return isInstanceRole(id) ? INSTANCE_ROLES[id] : null;
  return isBuiltinRole(id) ? ROLES[id] : null;
}

const fixedRole = (kind: Kind, id: string) => (kind === 'role' ? FIXED_ROLES.roles : (FIXED_ROLES.instanceRoles as readonly string[])).includes(id);
const definitionIn = (row: RoleRow): RoleDefinition => ({ name: row.name, description: row.description, permissions: row.permissions as Permission[], protected: row.protected as Permission[] });

function view<Grants extends number | null>(kind: Kind, id: string, definition: RoleDefinition, grants: Grants): Omit<RoleView, 'grants'> & { grants: Grants } {
  const shipped = shippedAs(kind, id);
  const current = normalDefinition(definition);
  return {
    id,
    ...current,
    builtin: shipped !== null,
    edited: shipped !== null && JSON.stringify(normalDefinition(shipped)) !== JSON.stringify(current),
    fixed: fixedRole(kind, id),
    default: shipped === null ? null : normalDefinition(shipped),
    assignableToEnvironment: kind === 'role' && !current.permissions.some((permission) => PROJECT_ONLY_PERMISSIONS.includes(permission)),
    grants,
  };
}

/** Those that ship first, in the order they ship, then those an Owner made, by id. */
function listed(kind: Kind, rows: readonly RoleRow[], counts: Record<string, number>): RoleView[] {
  const shipped = Object.keys(kind === 'role' ? ROLES : INSTANCE_ROLES);
  const rank = (id: string) => (shipped.includes(id) ? shipped.indexOf(id) : shipped.length);
  return rows
    .filter((row) => row.instance === (kind === 'instance-role'))
    .sort((a, b) => rank(a.id) - rank(b.id) || (a.id < b.id ? -1 : 1))
    .map((row) => view(kind, row.id, definitionIn(row), counts[row.id] ?? 0));
}

/**
 * The change asked, checked as the vault checks it, so that what it would
 * take as a fault is a bad request: a fixed role, an instance role that
 * does not ship, an id no role may have, a definition it refuses.
 */
function asked(kind: Kind, id: string, definition: RoleDefinition | null): RoleDefinition | null {
  if (kind === 'instance-role' && !isInstanceRole(id)) throw notFound(`no instance role ${id}: an Owner makes project roles`);
  if (kind === 'role' && !ROLE_ID.test(id)) throw badRequest('a role is named by lowercase letters, digits and dashes, 2 to 32, starting with a letter');
  if (fixedRole(kind, id)) throw badRequest(`${id} is not edited: it holds ${id === 'member' ? 'nothing' : 'everything'}, always`);
  if (definition === null) return null;
  const problem = definitionProblem(definition);
  if (problem !== null) throw badRequest(problem);
  return normalDefinition(definition);
}

/**
 * Define a role, one that ships edited or one an Owner makes, or with
 * `definition` null put one that ships back as it ships, or delete one an
 * Owner made, while no grant names it. With `dryRun`, what it would do to
 * everyone it reaches, and nothing changes; with the `revision` that
 * answered, made from the role as it was weighed, or refused, 409
 * `policy_changed`, to be weighed again.
 *
 *   PUT /api/roles/release-manager?revision=9c41e07b5d2a8f13
 *     { "name": "Release manager", "description": "…", "permissions": ["secret.use", "secret.write"], "protected": ["secret.use"] }
 */
async function changeRole(ctx: ApiContext, kind: Kind, id: string, definition: RoleDefinition | null, query: z.infer<typeof roleChange>): Promise<RoleImpact | { role: ChangedRole | null }> {
  const next = asked(kind, id, definition);
  if (query.dryRun !== undefined) return weigh(ctx, kind, id, next);
  const instance = kind === 'instance-role';
  let answer;
  try {
    answer = await changed(ctx, { op: 'policy.change', instance, role: id, definition: next, ...(query.revision === undefined ? {} : { revision: query.revision }) }, id);
  } catch (error) {
    // Deleting a role an Owner made that is not there: the vault's `invalid`, said as 0.14.7 said it.
    if (next === null && shippedAs(kind, id) === null && error instanceof ApiError && error.reason === 'invalid') throw notFound(`no role ${id}`);
    throw error;
  }
  return { role: answer.role === null ? null : view(kind, id, answer.role, null) };
}

/** How many examples an impact line names. */
const EXAMPLES = 3;

/**
 * The most of anything a change is weighed across: roles, members it
 * reaches, grants of one of them, environments where it reaches. Each read
 * takes one past it; past it, the change is refused 409
 * `too_many_to_weigh`, and is made without being weighed first.
 */
export const WEIGHED_MOST = 1000;

const tooMany = (what: string) =>
  new ApiError('conflict', `too much to weigh: more than ${WEIGHED_MOST.toLocaleString('en-US')} ${what}. Make the change without weighing it first`, 'too_many_to_weigh');

/**
 * What a change to a role would do, weighed from the rows as stored: the
 * roles (and whether a grant names one being deleted), the active members
 * the role reaches with their live grants, and the places it reaches:
 * for a project role, the projects a grant naming it is on; for an
 * instance role, every one. A display of the rules (`allows`); the vault
 * decides. For an Owner of the whole instance: `caller` and three
 * statements, each of at most `WEIGHED_MOST` and one.
 */
async function weigh(ctx: ApiContext, kind: Kind, id: string, next: RoleDefinition | null): Promise<RoleImpact> {
  const who = await ctx.caller();
  if (!editsRoles(who)) throw refusal('no_access', id);
  const instance = kind === 'instance-role';
  const { roles, granted } = await rolesWeighed(ctx.db, { instance, id }, WEIGHED_MOST);
  if (roles.length > WEIGHED_MOST) throw tooMany('roles');
  const row = roles.find((candidate) => candidate.instance === instance && candidate.id === id);
  const shipped = shippedAs(kind, id);
  if (next === null && shipped === null && row === undefined) throw notFound(`no role ${id}`);
  // Deleting one an Owner made, or defining one that is not there, while a grant names it: refused, as the vault refuses it.
  if (granted > 0 && shipped === null && (next === null || row === undefined)) {
    const count = granted > WEIGHED_MOST ? `more than ${WEIGHED_MOST.toLocaleString('en-US')} grants name` : granted === 1 ? '1 grant names' : `${granted.toLocaleString('en-US')} grants name`;
    throw new ApiError('conflict', `${count} ${id}: revoke ${granted === 1 ? 'it' : 'them'} first`, 'role_granted');
  }
  const [held, known] = await Promise.all([
    members(ctx.db, { within: null, listed: 'all', removed: false, scopes: false, reaching: { instance, role: id }, most: WEIGHED_MOST, now: new Date() }),
    places(ctx.db, null, { ...(instance ? {} : { granting: id }), most: WEIGHED_MOST }),
  ]);
  if (held.length > WEIGHED_MOST) throw tooMany('members it reaches');
  if (held.some((member) => member.grants.length > WEIGHED_MOST)) throw tooMany('grants of one member it reaches');
  if (known.reduce((sum, project) => sum + Math.max(project.environments.length, 1), 0) > WEIGHED_MOST) throw tooMany('environments where it reaches');
  const before = policyOf(roles, known);
  const after = changedPolicy(before, kind, id, next ?? (shipped === null ? null : normalDefinition(shipped)));
  return { ...impactOf(kind, id, before, after, held, known), revision: roleRevision(row === undefined ? null : definitionIn(row)) };
}

/** The policy as the rows say it: every role, and every protected environment, which a personal config is protected as. */
function policyOf(roles: readonly RoleRow[], known: Awaited<ReturnType<typeof places>>): Policy {
  const table = (instance: boolean) => Object.fromEntries(roles.filter((row) => row.instance === instance).map((row) => [row.id, definitionIn(row)]));
  const guarded = known.map((project) => ({ projectId: project.id, environments: project.environments.filter((environment) => environment.protected && environment.owner === null) }));
  return {
    roles: table(false),
    instanceRoles: table(true) as Policy['instanceRoles'],
    protected: guarded.flatMap(({ environments }) => environments.map((environment) => environment.id)),
    protectedIn: Object.fromEntries(guarded.filter(({ environments }) => environments.length > 0).map(({ projectId, environments }) => [projectId, environments.map((environment) => ({ environmentId: environment.id, slug: environment.slug }))])),
  };
}

/** The policy a change makes of `policy`: the role defined, put back as it ships, or gone. */
function changedPolicy(policy: Policy, kind: Kind, id: string, definition: RoleDefinition | null): Policy {
  const key = kind === 'role' ? 'roles' : 'instanceRoles';
  const table: Record<string, RoleDefinition> = { ...policy[key] };
  if (definition === null) delete table[id];
  else table[id] = definition;
  return { ...policy, [key]: table };
}

/**
 * For every active member the role reaches, by a grant naming it or as
 * their instance role, at every place they could hold it, what they hold
 * as the policy is and as it would be, summed by permission, direction,
 * and whether the environment is protected. Personal configs are their
 * owners', and left out.
 */
function impactOf(kind: Kind, id: string, before: Policy, after: Policy, held: Awaited<ReturnType<typeof members>>, known: Awaited<ReturnType<typeof places>>): Omit<RoleImpact, 'revision'> {
  type Lines = { line: Pick<ImpactLine, 'change' | 'permission' | 'protected'>; people: Set<string>; services: Set<string>; places: Set<string>; projects: Set<string>; examples: string[] };
  const lines = new Map<string, Lines>();
  const note = (change: ImpactLine['change'], permission: Permission, guarded: boolean, member: { principal: string; service: boolean }, path: string, project: string) => {
    const key = `${change} ${permission} ${guarded}`;
    const entry = lines.get(key) ?? { line: { change, permission, protected: guarded }, people: new Set(), services: new Set(), places: new Set(), projects: new Set(), examples: [] };
    lines.set(key, entry);
    (member.service ? entry.services : entry.people).add(member.principal);
    entry.places.add(path);
    entry.projects.add(project);
    if (entry.examples.length < EXAMPLES) entry.examples.push(`${member.principal.replace(/^(user|token):/, '')} on ${path}`);
  };
  for (const row of held) {
    const member = { principal: row.id, service: typeOf(row.id) === 'service' };
    const role = roleOf(row);
    const grants = row.grants.map((grant) => ({ projectId: grant.project.id, environmentId: grant.environment?.id ?? null, role: grant.role }));
    // A project role reaches only the projects its grants are on; an instance role, every one its scope may take in.
    const reached = kind === 'instance-role'
      ? (role === id ? known : [])
      : known.filter((project) => grants.some((grant) => grant.role === id && grant.projectId === project.id));
    if (reached.length === 0) continue;
    const holds: Holdings = { role, scope: standingOf(row), grants, credentialScope: null, service: member.service };
    const was = { ...holds, policy: before };
    const will = { ...holds, policy: after };
    const compare = (permissions: readonly Permission[], place: Place, path: string, project: string, guarded: boolean) => {
      for (const permission of permissions) {
        const [then, now] = [allows(was, permission, place), allows(will, permission, place)];
        if (then !== now) note(now ? 'widens' : 'narrows', permission, guarded, member, path, project);
      }
    };
    for (const project of reached) {
      compare(PROJECT_ONLY_PERMISSIONS, { projectId: project.id }, project.slug, project.slug, false);
      for (const environment of project.environments) {
        if (environment.owner !== null) continue;
        const place = { projectId: project.id, environmentId: environment.id, environmentSlug: environment.slug };
        compare(PERMISSIONS.filter((permission) => !PROJECT_ONLY_PERMISSIONS.includes(permission)), place, `${project.slug}/${environment.slug}`, project.slug, environment.protected);
      }
    }
  }
  const order = (line: ImpactLine) => [line.change === 'widens' ? 0 : 1, PERMISSIONS.indexOf(line.permission), Number(line.protected)] as const;
  const weighed = [...lines.values()]
    .map(({ line, people, services, places: where, projects, examples }) => {
      const wide = PROJECT_ONLY_PERMISSIONS.includes(line.permission);
      const impact: ImpactLine = { ...line, people: people.size, services: services.size, environments: wide ? 0 : where.size, projects: projects.size, examples };
      return { impact, only: where.size === 1 ? [...where][0]! : null };
    })
    .sort((a, b) => {
      const [x, y] = [order(a.impact), order(b.impact)];
      return x[0] - y[0] || x[1] - y[1] || x[2] - y[2];
    });
  return { impact: weighed.map(({ impact }) => impact), sentence: sentenceOf(weighed) };
}

/** Whom an impact line reaches: `6 people`, `1 service account`, `2 people and 1 service account`. */
function whoInWords({ people, services }: Pick<ImpactLine, 'people' | 'services'>): string {
  const named = [people > 0 ? `${people} ${people === 1 ? 'person' : 'people'}` : null, services > 0 ? `${services} service account${services === 1 ? '' : 's'}` : null];
  return named.filter((part) => part !== null).join(' and ');
}

/**
 * An impact in words: "Widens secret.read for 6 people on 4 protected
 * environments; narrows secret.write for 2 people on market/dev". One
 * place is named; more are counted.
 */
function sentenceOf(weighed: readonly { impact: ImpactLine; only: string | null }[]): string {
  if (weighed.length === 0) return 'Changes what nobody holds';
  const sentence = weighed.map(({ impact: line, only }) => {
    const wide = PROJECT_ONLY_PERMISSIONS.includes(line.permission);
    const count = wide ? line.projects : line.environments;
    const where = only !== null ? `${only}${line.protected ? ', protected' : ''}` : `${count} ${line.protected ? 'protected ' : ''}${wide ? 'projects' : 'environments'}`;
    return `${line.change} ${line.permission} for ${whoInWords(line)} on ${where}`;
  }).join('; ');
  return sentence.charAt(0).toUpperCase() + sentence.slice(1);
}

export const roleRoutes = {
  /** Every role, as the instance defines it, for any member: what a grant names, and what it holds. `caller` and one statement. */
  ...route('GET /roles', {
    run: async (ctx): Promise<RolesView> => {
      const who = await ctx.caller();
      const { roles, granted, people } = await roleRows(ctx.db);
      return { roles: listed('role', roles, granted), instanceRoles: listed('instance-role', roles, people), editable: editsRoles(who) };
    },
  }),
  ...route('PUT /roles/:role', {
    input: roleDefinition,
    query: roleChange,
    run: (ctx, { params, input, query }) => changeRole(ctx, 'role', params.role, input, query),
  }),
  /** A role that ships, back as it ships; one an Owner made, deleted, while no grant names it (409 `role_granted`). */
  ...route('DELETE /roles/:role', {
    query: roleChange,
    run: (ctx, { params, query }) => changeRole(ctx, 'role', params.role, null, query),
  }),
  /** An Admin's or an Auditor's role, edited; Owner and Member are fixed (400), and the instance makes no other (404). */
  ...route('PUT /instance-roles/:role', {
    input: roleDefinition,
    query: roleChange,
    run: (ctx, { params, input, query }) => changeRole(ctx, 'instance-role', params.role, input, query),
  }),
  ...route('DELETE /instance-roles/:role', {
    query: roleChange,
    run: (ctx, { params, query }) => changeRole(ctx, 'instance-role', params.role, null, query),
  }),
};
