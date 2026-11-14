// The tools that make places and change who holds what (docs/design/mcp.md,
// section 6): Write's projects and environments, then Manage access. Each
// waits for its person's approval, as every change does (changes.ts), and
// runs the API's own route on Approve, as the person, with the connection
// and the approval named.
import { apiMember, shownMember } from '@coffre/client';
import { INSTANCE_ROLE_NAMES, INSTANCE_ROLES, makesProjects, ownsInstance, ROLE_NAMES, runsInstance, scopeInWords, type InstanceRole, type Permission, type Role } from '@coffre/core/access';
import { instanceRole, roleId, scopeInput, slug } from '@coffre/core/schemas';
import { z } from 'zod';

import type { ApiContext } from '../api/context.ts';
import { changed } from '../api/change.ts';
import { ApiError, badRequest, conflict, forbidden, notFound } from '../api/errors.ts';
import { grantsAsked, memberOf } from '../api/routes/members.ts';
import { runRoute } from '../api/router.ts';
import { approved, changeTool, type Replaced } from './changes.ts';
import type { Tool, ToolContext } from './tools.ts';

export const member = z.string().min(1).max(320).describe('A member: user:ada@acme.example, or service:ci-deploy for a service account');
const environment = z.string().min(1).max(200).describe('An environment, as project/environment: market/prod');
// A project or environment goes by its slug since 0.6.2. A call made before
// takes a name still, so that it matches the approval it asked for.
const name = z.string().trim().min(1).max(100).optional().describe('Ignored: it goes by its slug');

/** `market/prod` as its project and environment, or why not. */
function splitEnvironment(path: string): { project: string; environment: string } {
  const parts = path.replace(/^\/+|\/+$/g, '').split('/');
  if (parts.length !== 2 || !slug.safeParse(parts[0]).success || !slug.safeParse(parts[1]).success) {
    throw badRequest(`"${path}" is not an environment: name one as project/environment`);
  }
  return { project: parts[0]!, environment: parts[1]! };
}

/** Refuse now, as the API would on Approve, when the person does not run the instance. */
export function instanceOnly({ connection }: ToolContext): void {
  if (!runsInstance(connection.called.holds)) throw forbidden('only an admin or owner of the whole instance can do this');
}

/**
 * Refuse now, as the vault would on Approve, what only an Owner of the
 * whole instance asks of a person's instance role (`member.role` and
 * `member.remove`): to make one an Owner, to change or remove an Owner, or
 * to change their own. Whether the member is an Owner now is read only when
 * nothing else said it: one statement, the member's access. A role asked
 * as it is already, which the vault lets any admin ask, is refused here
 * too.
 */
async function ownerOnly(tool: ToolContext, member: string, role: InstanceRole | 'removed'): Promise<void> {
  const { called } = tool.connection;
  if (called.holds.credentialScope == null && ownsInstance(called.holds)) return;
  const owner = async () => {
    try {
      return (await runRoute('GET /members/:member/access', { member }, undefined, tool.ctx)).instanceRole === 'owner';
    } catch (error) {
      // Someone not a member yet holds no role.
      if (error instanceof ApiError && error.code === 'not_found') return false;
      throw error;
    }
  };
  if (role === 'owner' || (role !== 'removed' && member === called.principal) || (await owner())) {
    throw forbidden('only an owner of the whole instance can make someone an owner, change or remove an owner, or change their own role');
  }
}

/**
 * Refuse now, as the API would on Approve, unless the person manages the
 * service account: who runs the instance, or a person who reaches every
 * grant it holds where the instance lets them (`managesService`), as its
 * tokens' list weighs it, and refuses anyone else.
 */
export async function manages({ ctx }: ToolContext, service: string): Promise<void> {
  try {
    await runRoute('GET /members/:member/tokens', { member: service }, undefined, ctx);
  } catch (error) {
    if (!(error instanceof ApiError) || (error.code !== 'forbidden' && error.code !== 'not_found')) throw error;
    throw forbidden(`you do not manage ${shownMember(service)}: it holds something you do not, or the instance keeps it to admins`);
  }
}

/** Refuse now, as the API would on Approve, when the person lacks a permission on each project, or at each environment. */
async function needsAt({ ctx }: ToolContext, places: readonly string[], permission: Permission): Promise<void> {
  const projects = places.filter((place) => !place.includes('/'));
  const environments = places.filter((place) => place.includes('/'));
  if (projects.length > 0) {
    const { projects: theirs } = await runRoute('GET /projects', {}, undefined, ctx);
    for (const project of new Set(projects)) {
      const here = theirs.find((entry) => entry.slug === project);
      if (here === undefined) throw notFound(`no project "${project}" that you can see`);
      if (!here.permissions.includes(permission)) throw forbidden(`you need ${permission} on ${project}`);
    }
  }
  if (environments.length > 0) {
    const me = await runRoute('GET /me', {}, undefined, ctx);
    for (const path of new Set(environments)) {
      const { project, environment } = splitEnvironment(path);
      const here = me.environments.find((entry) => entry.project === project && entry.environment === environment);
      if (here === undefined) throw notFound(`no environment "${path}" that you can see`);
      if (!here.permissions.includes(permission)) throw forbidden(`you need ${permission} on ${path}`);
    }
  }
}

/** An instance role as the instance defines it now, an Owner's edits included (docs/design/roles.md). */
async function instanceRoleOf(ctx: ApiContext, role: InstanceRole): Promise<{ name: string; description: string; permissions: readonly string[]; protected: readonly string[] }> {
  const defined = (await runRoute('GET /roles', {}, undefined, ctx)).instanceRoles.find((each) => each.id === role) ?? INSTANCE_ROLES[role];
  return { name: defined.name, description: defined.description, permissions: defined.permissions, protected: defined.protected };
}

/**
 * What an instance role holds, as an approval says it: its name and
 * description, and its two columns as they are now. "Auditor: Reads the
 * log … Holds audit.read; in a protected environment, audit.read."
 */
function instanceRoleInWords(defined: Awaited<ReturnType<typeof instanceRoleOf>>): string {
  const column = (permissions: readonly string[]) => (permissions.length === 0 ? 'nothing' : permissions.join(', '));
  return `${defined.name}: ${defined.description} Holds ${column(defined.permissions)}; in a protected environment, ${column(defined.protected)}.`;
}

/** A scope as the API takes it, with either filter left out as `all`. */
const fullScope = (scope: z.infer<typeof scopeInput> | undefined) => ({ projects: scope?.projects ?? 'all', environments: scope?.environments ?? 'all' });

const accessChange = z.union([roleId, z.object({ role: roleId, until: z.string().max(40).nullable() }).strict(), z.null()]);
type AccessChange = z.infer<typeof accessChange>;
const shownAccess = (to: AccessChange) => (to === null ? 'nothing' : typeof to === 'string' ? to : `${to.role}${to.until === null ? '' : ` until ${to.until}`}`);
const accessChanges = z.record(z.string().min(1).max(200), accessChange).refine((changes) => Object.keys(changes).length > 0 && Object.keys(changes).length <= 50, 'name from 1 to 50 places');

// A place as the API reads one, without spaces or slashes around it: market, or market/prod.
const placeOf = (raw: string) => raw.trim().replace(/^\/+|\/+$/g, '');

/** A grant at a place as the member list shows it, live and of the member's generation, or null for none. */
type Held = { role: Role; expiresAt: string | null } | null;

/** What `set_access` replaces: the role a member holds at each place, and until when, or nothing. */
async function heldAt(ctx: ApiContext, member: string, changes: Record<string, AccessChange>): Promise<Replaced> {
  const named = apiMember(member);
  const held = (await runRoute('GET /members', {}, {}, ctx)).members.find((entry) => entry.member === named)?.grants ?? [];
  const now = Object.keys(changes).map((place): [string, Held] => {
    const grant = held.find((entry) => (entry.environment === null ? entry.project : `${entry.project}/${entry.environment}`) === placeOf(place));
    return [place, grant === undefined ? null : { role: grant.role, expiresAt: grant.expiresAt }];
  });
  const said = (was: Held) => (was === null ? 'nothing' : `${was.role}${was.expiresAt === null ? '' : ` until ${was.expiresAt}`}`);
  return { state: Object.fromEntries(now), details: now.map(([place, was]) => ({ label: place, value: `${said(was)} → ${shownAccess(changes[place]!)}` })) };
}

/**
 * The grants changed over what Approve read (`heldAt`): the routes take no
 * `was`, so the change is made here, as `PATCH /access` and `PUT /members`
 * make theirs, in one call to the vault, which refuses `stale` a place
 * whose grant is no longer the one the page showed.
 */
async function granted(ctx: ApiContext, member: string, changes: Record<string, AccessChange>, replaced: Replaced | undefined, admit: boolean): Promise<void> {
  const held = replaced?.state as Record<string, Held> | undefined;
  const places = Object.keys(changes);
  if (held === undefined || !places.every((place) => Object.hasOwn(held, place))) throw conflict('coffre could not read what this replaces: open the approval again');
  const principal = memberOf(apiMember(member));
  const wanted = grantsAsked(changes).map(({ path: _, ...change }, i) => ({ ...change, was: held[places[i]!]! }));
  await changed(ctx, { op: 'access.grant', principal, changes: wanted, ...(admit ? { admit } : {}) }, principal);
}

const CREATE_PROJECT = changeTool({
  name: 'create_project',
  needs: 'new-project',
  title: 'Create a project',
  description: `Create a project, with no environments yet. Admins and owners only. ${approved}`,
  scope: 'write',
  idempotent: true,
  destructive: false,
  input: z.object({ project: slug.describe('The project slug: market'), name }).strict(),
  change: {
    summary: ({ project }) => `create the project ${project}`,
    place: ({ project }) => project,
    done: ({ project }) => ({ result: { project, created: true }, text: `The project ${project} is created, with no environments yet.` }),
    check: async ({ connection }) => {
      if (!makesProjects(connection.called.holds)) throw forbidden('only an admin or owner whose scope takes in new projects can do this');
    },
    preview: async (_ctx, { project }) => [{ label: 'Project', value: project, kind: 'mono' }],
    apply: async (ctx, { project }) => {
      await runRoute('PUT /projects/:project', { project }, {}, ctx);
      return {};
    },
  },
});

const CREATE_ENVIRONMENT = changeTool({
  name: 'create_environment',
  needs: 'environment.manage',
  title: 'Create an environment',
  description: `Create an environment in a project, with no secrets yet; or, with \`inherits\`, a fork that reads another environment's keys live, but for those it sets or removes. ${approved}`,
  scope: 'write',
  idempotent: true,
  destructive: false,
  input: z
    .object({
      environment,
      name,
      inherits: slug.optional().describe("An environment of the same project, by slug, whose keys it inherits: prod for market/prod-eu. Its readers need read on that one for those keys"),
    })
    .strict(),
  change: {
    summary: ({ environment, inherits }) => `create the environment ${environment}${inherits === undefined ? '' : `, inheriting ${splitEnvironment(environment).project}/${inherits}`}`,
    place: ({ environment }) => {
      const { project, environment: slug } = splitEnvironment(environment);
      return `${project}/${slug}`;
    },
    done: ({ environment, inherits }) => {
      const parent = inherits === undefined ? null : `${splitEnvironment(environment).project}/${inherits}`;
      return {
        result: { environment, created: true, ...(parent === null ? {} : { inherits: parent }) },
        text: parent === null ? `The environment ${environment} is created, with no secrets yet.` : `The environment ${environment} is created, inheriting ${parent}: it reads ${parent}'s keys as they change, but for those it sets or removes.`,
      };
    },
    check: async (tool, { environment }) => needsAt(tool, [splitEnvironment(environment).project], 'environment.manage'),
    preview: async (_ctx, { environment, inherits }) => [
      { label: 'Environment', value: environment, kind: 'mono' },
      ...(inherits === undefined ? [] : [{ label: 'Inherits from', value: `${splitEnvironment(environment).project}/${inherits}`, kind: 'mono' as const }]),
    ],
    apply: async (ctx, { environment, inherits }) => {
      await runRoute('PUT /projects/:project/:environment', splitEnvironment(environment), inherits === undefined ? {} : { from: inherits, inherit: true }, ctx);
      return {};
    },
  },
});

const SET_ACCESS = changeTool({
  name: 'set_access',
  needs: 'grant.manage',
  title: 'Change a member’s access',
  description: `Grant, change or revoke a member's roles at projects and environments; list_access shows what they hold. ${approved}`,
  scope: 'manage-access',
  idempotent: true,
  destructive: true,
  input: z
    .object({
      member,
      changes: accessChanges.describe(`Each place, a project or project/environment, with the role to hold there (${ROLE_NAMES.join(', ')}, or one the instance's Owners made; { role, until } for one that ends), or null to revoke it`),
    })
    .strict(),
  change: {
    summary: ({ member, changes }) => {
      const places = Object.keys(changes);
      return `change ${shownMember(apiMember(member))}'s access at ${places.length === 1 ? places[0] : `${places.length} places`}`;
    },
    place: () => null,
    done: ({ member, changes }) => ({ result: { member: shownMember(apiMember(member)), changes }, text: `${shownMember(apiMember(member))}'s access is changed.` }),
    // Each place needs grant.manage there, as the API checks: on a project, all of it; on an environment, that one.
    // A service account's manager gives it what they hold, which the vault decides on Approve.
    check: async (tool, { member, changes }) => {
      const places = Object.keys(changes).map(placeOf);
      if (places.some((place) => place.split('/')[0] === '*')) throw badRequest('grants are on a project or an environment: a person reaches every project by their instance role (admit_member)');
      if (apiMember(member).startsWith('token:') && !runsInstance(tool.connection.called.holds)) return manages(tool, apiMember(member));
      await needsAt(tool, places, 'grant.manage');
    },
    replaces: async (ctx, { member, changes }) => heldAt(ctx, member, changes),
    preview: async (_ctx, { member }, _viewing, replaced) => [{ label: 'Member', value: shownMember(apiMember(member)), kind: 'mono' }, ...replaced],
    apply: async (ctx, { member, changes }, { replaced }) => {
      await granted(ctx, member, changes, replaced, false);
      return {};
    },
  },
});

/**
 * Admitting a member. A service account is set up by whoever `GET /me`
 * says may (`setsUpServices`): until the instance's policy row is served,
 * that is whoever runs the instance alone, where 0.14.7 also let a person
 * the policy allowed (docs/mcp.md, "What 0.16 does not do yet").
 */
const ADMIT = changeTool({
  name: 'admit_member',
  needs: 'services',
  title: 'Admit a member, or set their role',
  description: `Admit a person, or a service account, as a member, with no access until granted some; or set a person's instance role and where it applies. A service account may come with its first grants (access), in one step: a grant refused admits nothing. A person who holds access may add a service account, where the instance lets them. A role's default permissions, before any project grant adds more: ${INSTANCE_ROLE_NAMES.map((role) => `${role}: ${INSTANCE_ROLES[role].description.toLowerCase()}`).join(' ')} ${approved}`,
  scope: 'manage-access',
  idempotent: true,
  destructive: false,
  input: z
    .object({
      member,
      role: instanceRole.optional().describe("A person's instance role; left out, a new member is a member and an existing one keeps theirs"),
      scope: scopeInput.optional().describe('Where the role applies: projects and environments (by slug), each "all", { only: [...] } or { except: [...] }; left out, everywhere'),
      access: accessChanges
        .optional()
        .describe(`A service account's first grants, as set_access takes them: each place, a project or project/environment, with its role (${ROLE_NAMES.join(', ')}, or one the instance's Owners made; { role, until } for one that ends)`),
    })
    .strict(),
  change: {
    summary: ({ member, role, scope, access }) =>
      `admit ${shownMember(apiMember(member))}${role === undefined ? '' : ` as ${role}, ${scopeInWords(fullScope(scope))}`}${access === undefined ? '' : `, with access at ${Object.keys(access).join(', ')}`}`,
    place: () => null,
    done: ({ member, role, access }) => ({
      result: { member: shownMember(apiMember(member)), ...(role === undefined ? {} : { instanceRole: role }), ...(access === undefined ? {} : { changes: access }) },
      text: `${shownMember(apiMember(member))} is a member${role === undefined ? '' : `, as ${role}`}${access === undefined ? '' : ', with its access set'}.`,
    }),
    // The grants are the vault's to decide on Approve, as set_access's for a service account are.
    check: async (tool, { member, role, scope, access }) => {
      const service = apiMember(member).startsWith('token:');
      if (access !== undefined && (!service || role !== undefined || scope !== undefined)) {
        throw badRequest('access comes with a service account, and no role or scope: a person is given grants once a member (set_access)');
      }
      // As PUT /members/:member refuses them, before anyone is asked: a scope said with no role would be dropped.
      if (scope !== undefined && role === undefined) throw badRequest('a scope goes with a role: name the role too');
      if (scope !== undefined && role === 'member') throw badRequest('a member holds nothing by their role: it takes no scope');
      if (!service || (role ?? 'member') !== 'member' || scope !== undefined) {
        instanceOnly(tool);
        // A person's role kept as it is (none asked) is no change of it.
        if (!service && role !== undefined) await ownerOnly(tool, apiMember(member), role);
        return;
      }
      if (!(await runRoute('GET /me', {}, undefined, tool.ctx)).setsUpServices) throw forbidden('you set up no service account: the instance keeps them to admins where you hold access');
    },
    // What it gives, as the page says it: the grants as they were, or the instance role as the instance defines it, which
    // Approve refuses once an Owner has edited it since.
    replaces: async (ctx, { member, role, access }) => {
      if (access !== undefined) return heldAt(ctx, member, access);
      if (role === undefined) return { details: [], state: null };
      return { details: [], state: { role, definition: await instanceRoleOf(ctx, role) } };
    },
    preview: async (ctx, { member, role, scope, access }, _viewing, replaced) => [
      { label: 'Member', value: shownMember(apiMember(member)), kind: 'mono' },
      role === undefined
        ? { label: 'As', value: access === undefined ? 'a member, with no access until granted some, or as they are' : 'a member, with this access' }
        : { label: 'As', value: instanceRoleInWords(await instanceRoleOf(ctx, role)) },
      ...(role === undefined || role === 'member' ? [] : [{ label: 'Where', value: scopeInWords(fullScope(scope)) }]),
      ...replaced,
    ],
    apply: async (ctx, { member, role, scope, access }, { replaced }) => {
      // Its first grants over what the page showed it holds, as set_access's; else the route's role, as Approve weighed it.
      if (access !== undefined) await granted(ctx, member, access, replaced, true);
      else await runRoute('PUT /members/:member', { member: apiMember(member) }, { ...(role === undefined ? {} : { role }), ...(scope === undefined ? {} : { scope }) }, ctx);
      return {};
    },
  },
});

const OFFBOARD = changeTool({
  name: 'offboard_member',
  needs: 'services',
  title: 'Offboard a member',
  description: `Remove a member: their grants, sessions, tokens and linked accounts end; describe_member then lists the secrets they read or wrote, to rotate. A service account's manager removes it too. ${approved}`,
  scope: 'manage-access',
  idempotent: true,
  destructive: true,
  input: z.object({ member }).strict(),
  change: {
    summary: ({ member }) => `offboard ${shownMember(apiMember(member))}`,
    place: () => null,
    done: ({ member }) => ({
      result: { member: shownMember(apiMember(member)), removed: true },
      text: `${shownMember(apiMember(member))} is offboarded. describe_member lists the secrets they read or wrote, to rotate.`,
    }),
    check: async (tool, { member }) => {
      const named = apiMember(member);
      if (named.startsWith('token:')) return runsInstance(tool.connection.called.holds) ? undefined : manages(tool, named);
      instanceOnly(tool);
      await ownerOnly(tool, named, 'removed');
    },
    preview: async (ctx, { member }) => {
      const named = apiMember(member);
      if (!(await runRoute('GET /me', {}, undefined, ctx)).runsInstance) {
        const access = await runRoute('GET /members/:member/access', { member: named }, undefined, ctx);
        return [
          { label: 'Service account', value: shownMember(named), kind: 'mono' },
          { label: 'Ends', value: `${access.grants.length} grants, and every token and trust binding` },
        ];
      }
      const report = await runRoute('GET /members/:member', { member: named }, undefined, ctx);
      return [
        { label: 'Member', value: shownMember(named), kind: 'mono' },
        { label: 'Ends', value: `${report.live.grants} grants, ${report.live.sessions} sessions, ${report.live.tokens} tokens, ${report.live.identities} linked accounts` },
        { label: 'To rotate after', value: `${report.exposed.length} secrets they read or wrote` },
      ];
    },
    apply: async (ctx, { member }) => {
      await runRoute('DELETE /members/:member', { member: apiMember(member) }, undefined, ctx);
      return {};
    },
  },
});

/** The tools that make places, then those that change who holds what. */
export const MEMBER_TOOLS: readonly Tool[] = [CREATE_PROJECT, CREATE_ENVIRONMENT, SET_ACCESS, ADMIT, OFFBOARD];
