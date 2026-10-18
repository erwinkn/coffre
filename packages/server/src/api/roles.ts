import { randomUUID } from 'node:crypto';

import {
  allows,
  assignableToEnvironment,
  definitionProblem,
  FIXED_ROLES,
  grantKind,
  INSTANCE_ROLES,
  isBuiltinRole,
  isInstanceRole,
  normalDefinition,
  ownsInstance,
  PERMISSIONS,
  PROJECT_ONLY_PERMISSIONS,
  protects,
  ROLE_ID,
  ROLES,
  type Holdings,
  type InstanceRole,
  type Permission,
  type Policy,
  type RoleDefinition,
} from '@coffre/core/access';
import type { PolicyChange } from '@coffre/core/vault';

import { peopleHoldings, places, roleHolders, type ResolvedPath } from '../db/queries.ts';
import type { Caller } from './caller.ts';
import { placeOf } from './caller.ts';
import { denied, Refusal, withRefusals, type ApiContext } from './context.ts';
import { badRequest, conflict, forbidden, notFound, vaultRefused } from './errors.ts';
import { formatMember } from './paths.ts';

// The role editor and protected environments (docs/design/roles.md): the
// vault keeps both in its newest `policy.change` entry and decides on them;
// the app lists them, weighs a change before it is made, and asks.

/** A role as `GET /api/roles` lists it: as the instance defines it now, beside how it ships. */
export type RoleView = RoleDefinition & {
  id: string;
  /** One coffre ships; false for one an Owner made. */
  builtin: boolean;
  /** A built-in role an Owner changed: Reset to default puts it back. */
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

export type RolesView = {
  roles: RoleView[];
  instanceRoles: RoleView[];
  /** Whether the caller edits them: an Owner of the whole instance, signed in as themselves. */
  editable: boolean;
};

/** What a change to a role would do to one permission, one way, where it is protected or not (`roleImpact`). */
export type ImpactLine = {
  change: 'widens' | 'narrows';
  permission: Permission;
  /** In protected environments; always false for a project-wide permission. */
  protected: boolean;
  people: number;
  /** Environments it changes at; 0 for a project-wide permission, which `projects` counts. */
  environments: number;
  projects: number;
  /** A few of them, `ada@acme.example on market/prod`. */
  examples: string[];
};

export type RoleImpact = { impact: ImpactLine[]; sentence: string };

/** What a role definition is sent as. */
export type RoleInput = { name: string; description: string; permissions: Permission[]; protected: Permission[] };

type Kind = 'role' | 'instance-role';

/** Whether the caller edits roles and unprotects environments: an Owner of the whole instance, on no credential's scope. */
export function editsRoles(caller: Caller): boolean {
  return caller.principal.type === 'user' && caller.credentialScope === null && ownsInstance(caller);
}

/** Whether an environment is protected for the caller: a personal config as the environment it is a config of. */
export function protectedFor(caller: Pick<Caller, 'policy'>, environment: { id: string; owner?: string | null; parentId?: string | null }): boolean {
  const id = environment.owner == null ? environment.id : environment.parentId;
  return id != null && protects(caller.policy, id);
}

/** Every role, as the instance defines it, for any member: what a grant names, and what it holds. */
export async function listRoles(ctx: ApiContext): Promise<RolesView> {
  const held = await roleHolders(ctx.db);
  return { ...views(ctx.caller.policy, held), editable: editsRoles(ctx.caller) };
}

function views(policy: Policy, held: Awaited<ReturnType<typeof roleHolders>>): Pick<RolesView, 'roles' | 'instanceRoles'> {
  return {
    roles: Object.keys(policy.roles).map((id) => view('role', id, policy, held.roles.get(id) ?? 0)),
    instanceRoles: Object.keys(policy.instanceRoles).map((id) => view('instance-role', id, policy, held.instanceRoles.get(id as InstanceRole) ?? 0)),
  };
}

function view(kind: Kind, id: string, policy: Policy, grants: number): RoleView {
  const definition = table(policy, kind)[id]!;
  const shipped = shippedAs(kind, id);
  const current = normalDefinition(definition);
  return {
    id,
    ...current,
    builtin: shipped !== null,
    edited: shipped !== null && JSON.stringify(normalDefinition(shipped)) !== JSON.stringify(current),
    fixed: (kind === 'role' ? FIXED_ROLES.roles : FIXED_ROLES.instanceRoles as readonly string[]).includes(id),
    default: shipped === null ? null : normalDefinition(shipped),
    assignableToEnvironment: kind === 'role' && assignableToEnvironment(id, policy),
    grants,
  };
}

function table(policy: Policy, kind: Kind): Readonly<Record<string, RoleDefinition>> {
  return kind === 'role' ? policy.roles : policy.instanceRoles;
}

/** A role as coffre ships it, or null for one an Owner made. */
function shippedAs(kind: Kind, id: string): RoleDefinition | null {
  if (kind === 'instance-role') return isInstanceRole(id) ? INSTANCE_ROLES[id] : null;
  return isBuiltinRole(id) ? ROLES[id] : null;
}

/**
 * Define a role, a built-in one edited or one an Owner makes, or with
 * `definition` null put a built-in one back as it ships, or delete one an
 * Owner made, while no grant names it. With `dryRun`, what it would do to
 * every person it reaches (`roleImpact`), and nothing is changed.
 *
 *   PUT /api/roles/release-manager  { "name": "Release manager", "description": "…",
 *                                     "permissions": ["secret.use", "secret.write"], "protected": ["secret.use"] }
 */
export async function changeRole(
  ctx: ApiContext,
  kind: Kind,
  id: string,
  definition: RoleInput | null,
  { dryRun }: { dryRun: boolean },
): Promise<RoleImpact | { role: RoleView | null }> {
  return withRefusals(ctx, async () => {
    const change = proposed(ctx, kind, id, definition);
    const before = ctx.caller.policy;
    if (definition === null && kind === 'role' && !isBuiltinRole(id)) {
      // Deleting one an Owner made: refused while a grant names it, which the vault refuses too.
      const granted = (await roleHolders(ctx.db)).roles.get(id) ?? 0;
      if (granted > 0) {
        throw new Refusal(
          conflict(`${granted === 1 ? '1 grant names' : `${granted} grants name`} ${id}: revoke ${granted === 1 ? 'it' : 'them'} first`),
          denied(ctx, 'policy.change', 'role_granted', { metadata: { role: id, grants: granted } }),
        );
      }
    }
    if (dryRun) return roleImpact(ctx, before, after(before, change), change);
    const result = await ctx.vault.changePolicy({
      actor: formatMember(ctx.caller.principal),
      change,
      requestId: ctx.requestId,
      operationId: randomUUID(),
      credentialId: ctx.provenance,
      credentialScope: ctx.caller.credentialScope,
    });
    if (!result.ok) throw vaultRefused(result.refusal);
    // The role as it is now; null for one deleted.
    if (!Object.hasOwn(table(result.policy, kind), id)) return { role: null };
    const held = await roleHolders(ctx.db);
    return { role: view(kind, id, result.policy, (kind === 'role' ? held.roles.get(id) : held.instanceRoles.get(id as InstanceRole)) ?? 0) };
  });
}

/** The change asked for, checked as the vault checks it, to answer in the app's words: the vault decides. */
function proposed(ctx: ApiContext, kind: Kind, id: string, definition: RoleInput | null): Extract<PolicyChange, { kind: 'role' | 'instance-role' }> {
  if (!editsRoles(ctx.caller)) {
    throw new Refusal(
      forbidden('only an Owner of the whole instance edits roles, signed in as themselves'),
      denied(ctx, 'policy.change', 'requires_instance_owner', { metadata: { role: id, kind } }),
    );
  }
  const fixed = kind === 'role' ? FIXED_ROLES.roles.includes(id) : (FIXED_ROLES.instanceRoles as readonly string[]).includes(id);
  if (fixed) throw badRequest(`${id} is not edited: it holds ${id === 'member' ? 'nothing' : 'everything'}, always`);
  if (kind === 'instance-role' && !isInstanceRole(id)) throw notFound(`no instance role ${id}: an Owner makes project roles`);
  if (kind === 'role' && !ROLE_ID.test(id)) throw badRequest('a role is named by lowercase letters, digits and dashes, 2 to 32, starting with a letter');
  if (definition === null) {
    if (kind === 'role' && !isBuiltinRole(id) && !Object.hasOwn(ctx.caller.policy.roles, id)) throw notFound(`no role ${id}`);
    return kind === 'role' ? { kind, role: id, definition: null } : { kind, role: id as InstanceRole, definition: null };
  }
  const problem = definitionProblem(definition);
  if (problem !== null) throw badRequest(problem);
  const normal = normalDefinition(definition);
  return kind === 'role' ? { kind, role: id, definition: normal } : { kind, role: id as InstanceRole, definition: normal };
}

/** The policy a change to a role makes of `policy`: the role defined, put back as it ships, or gone. */
function after(policy: Policy, change: Extract<PolicyChange, { kind: 'role' | 'instance-role' }>): Policy {
  if (change.kind === 'instance-role') {
    return { ...policy, instanceRoles: { ...policy.instanceRoles, [change.role]: change.definition ?? INSTANCE_ROLES[change.role] } };
  }
  const roles: Record<string, RoleDefinition> = { ...policy.roles };
  const shipped = shippedAs('role', change.role);
  if (change.definition !== null) roles[change.role] = change.definition;
  else if (shipped !== null) roles[change.role] = shipped;
  else delete roles[change.role];
  return { ...policy, roles };
}

/** How many examples an impact line names. */
const EXAMPLES = 3;

/**
 * What changing a role would do: for every person it reaches, by a grant
 * naming it or as their instance role, at every place they could hold it,
 * what they hold with the policy as it is and as it would be, summed by
 * permission, direction, and whether the environment is protected. A
 * display of the rules (`allows`), from the rows as stored; the vault
 * decides. Personal configs are their owners', and left out.
 */
async function roleImpact(ctx: ApiContext, before: Policy, next: Policy, change: Extract<PolicyChange, { kind: 'role' | 'instance-role' }>): Promise<RoleImpact> {
  const [people, known] = await Promise.all([peopleHoldings(ctx.db, new Date()), places(ctx.db)]);
  const lines = new Map<string, { line: Omit<ImpactLine, 'people' | 'environments' | 'projects' | 'examples'>; people: Set<string>; places: Set<string>; projects: Set<string>; examples: string[] }>();
  const note = (change: ImpactLine['change'], permission: Permission, guarded: boolean, person: string, path: string, project: string) => {
    const key = `${change} ${permission} ${guarded}`;
    const entry = lines.get(key) ?? { line: { change, permission, protected: guarded }, people: new Set(), places: new Set(), projects: new Set(), examples: [] };
    lines.set(key, entry);
    entry.people.add(person);
    entry.places.add(path);
    entry.projects.add(project);
    if (entry.examples.length < EXAMPLES) entry.examples.push(`${person.replace(/^user:/, '')} on ${path}`);
  };
  for (const person of people) {
    const grants = person.grants.filter((grant) => grantKind(grant) !== null).map(({ projectId, environmentId, role }) => ({ projectId: projectId!, environmentId, role }));
    // A project role reaches only the projects its grants are on; an instance role, every one its scope takes in.
    const reached = change.kind === 'instance-role'
      ? (person.role === change.role ? known : [])
      : known.filter((project) => grants.some((grant) => grant.role === change.role && grant.projectId === project.id));
    if (reached.length === 0) continue;
    const held: Holdings = { role: person.role, scope: person.scope, grants, credentialScope: null, service: false };
    const was = { ...held, policy: before };
    const will = { ...held, policy: next };
    const weigh = (permissions: readonly Permission[], place: ReturnType<typeof placeOf>, path: string, project: string, guarded: boolean) => {
      for (const permission of permissions) {
        const [then, now] = [allows(was, permission, place), allows(will, permission, place)];
        if (then !== now) note(now ? 'widens' : 'narrows', permission, guarded, person.principal, path, project);
      }
    };
    for (const project of reached) {
      weigh(PROJECT_ONLY_PERMISSIONS, placeOf(project, null), project.slug, project.slug, false);
      for (const environment of project.environments) {
        if (environment.owner !== null) continue;
        const place = placeOf(project, environment);
        weigh(PERMISSIONS.filter((permission) => !PROJECT_ONLY_PERMISSIONS.includes(permission)), place, `${project.slug}/${environment.slug}`, project.slug, protects(before, environment.id));
      }
    }
  }
  const order = (line: ImpactLine) => [line.change === 'widens' ? 0 : 1, PERMISSIONS.indexOf(line.permission), Number(line.protected)];
  const weighed = [...lines.values()]
    .map(({ line, people: who, places: where, projects, examples }) => {
      const wide = PROJECT_ONLY_PERMISSIONS.includes(line.permission);
      const impact: ImpactLine = { ...line, people: who.size, environments: wide ? 0 : where.size, projects: projects.size, examples };
      return { impact, only: where.size === 1 ? [...where][0]! : null };
    })
    .sort((a, b) => {
      const [x, y] = [order(a.impact), order(b.impact)];
      return x[0]! - y[0]! || x[1]! - y[1]! || x[2]! - y[2]!;
    });
  return { impact: weighed.map(({ impact }) => impact), sentence: impactSentence(weighed) };
}

/**
 * An impact in words: "Widens secret.read for 6 people on 4 protected
 * environments; narrows secret.write for 2 people on market/dev". One
 * place is named, with the one it is in; more are counted.
 */
function impactSentence(weighed: readonly { impact: ImpactLine; only: string | null }[]): string {
  if (weighed.length === 0) return 'Changes what nobody holds';
  const sentence = weighed.map(({ impact: line, only }) => {
    const people = `${line.people} ${line.people === 1 ? 'person' : 'people'}`;
    const wide = PROJECT_ONLY_PERMISSIONS.includes(line.permission);
    const count = wide ? line.projects : line.environments;
    const where = only !== null
      ? `${only}${line.protected ? ', protected' : ''}`
      : `${count} ${line.protected ? 'protected ' : ''}${wide ? 'projects' : 'environments'}`;
    return `${line.change} ${line.permission} for ${people} on ${where}`;
  }).join('; ');
  return sentence.charAt(0).toUpperCase() + sentence.slice(1);
}

/**
 * Protect an environment, or take its protection off: whoever manages its
 * project's environments protects it, and only an Owner of the whole
 * instance unprotects it (R15). The vault decides, and logs it as
 * `policy.change`. Before any app transaction: none stays open across a
 * vault call. Whether it is protected now.
 */
export async function protectEnvironment(ctx: ApiContext, place: ResolvedPath, on: boolean): Promise<boolean> {
  const { project, environment } = place;
  if (environment === null) throw notFound('no such environment');
  if (environment.owner !== null) throw badRequest('a personal config is protected as the environment it is a config of is');
  return (await protectIds(ctx, project.id, [environment.id], on)).includes(environment.id);
}

/**
 * Protect environments of a project by id, rows or not: a fork's, before
 * its row is written, so it is never readable unprotected. The ids the
 * vault's policy protects of them now.
 */
export async function protectIds(ctx: ApiContext, projectId: string, environmentIds: string[], on = true): Promise<string[]> {
  const result = await ctx.vault.changePolicy({
    actor: formatMember(ctx.caller.principal),
    change: { kind: 'protect', projectId, environmentIds, protected: on },
    requestId: ctx.requestId,
    operationId: randomUUID(),
    credentialId: ctx.provenance,
    credentialScope: ctx.caller.credentialScope,
  });
  if (!result.ok) throw vaultRefused(result.refusal);
  return environmentIds.filter((id) => protects(result.policy, id));
}
