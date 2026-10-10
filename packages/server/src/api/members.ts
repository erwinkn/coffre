import { randomUUID } from 'node:crypto';

import {
  administers,
  allows,
  EVERYWHERE,
  grantKind,
  INSTANCE_ROLES,
  inScope,
  mayManageAccess,
  normalScope,
  ROLES,
  runsInstance,
  type Filter,
  type InstanceRole,
  type Permission,
  type Place,
  type Role,
  type Scope,
} from '@coffre/core/access';
import { isTombstone } from '@coffre/core/schemas';
import type { Queryable } from '@coffre/db';
import { credentials, identities, mcpConnections } from '@coffre/db/schema';

import { actorParts } from '../db/audit.ts';
import {
  revokePriorMembership,
  liveConnections,
  memberAccess as readMemberAccess,
  memberActivity,
  members as loadMembers,
  missingMembers,
  places,
  updateAuth,
  type MemberRow,
  type PlaceRow,
  type StoredGrant,
} from '../db/queries.ts';
import { canAnywhere, instanceRoleOf, placeOf } from './caller.ts';
import { audited, denied, Refusal, requireInstance, withRefusals, type ApiContext } from './context.ts';
import { badRequest, conflict, forbidden, notFound, vaultRefused } from './errors.ts';
import type { ConnectedApp } from '../mcp/service.ts';
import { formatMember, parseGrantee, type MemberRef, type Path } from './paths.ts';
import { referencesBy, type ReferenceView } from './references.ts';

export type MemberGrant = {
  /** Its member and place, `user:ada@acme.example/market/prod`: one grant per member per place. */
  id: string;
  project: string;
  /** Null for a grant on the whole project. */
  environment: string | null;
  role: Role;
  roleName: string;
  permissions: Permission[];
  expiresAt: string | null;
};

export type Member = {
  /** `user:ada@acme.example` or `token:ci-deploy`. */
  member: string;
  principalType: 'user' | 'service';
  principalId: string;
  /** `member` for every service account. */
  instanceRole: InstanceRole | 'root-admin';
  /** Where their instance role applies, projects by slug; everywhere for a member or a root admin. */
  scope: Scope;
  /** Asked of a place (`?path=`): whether their instance role reaches it, beside any grant there. False otherwise. */
  reachesByRole: boolean;
  isRootAdmin: boolean;
  /**
   * The vault found their record changed around it, and refuses them: they
   * hold nothing until an owner removes them, which starts them over. A
   * change the vault has not met yet shows as stored; the vault refuses it
   * at its first use, and the scheduled checkpoint looks every few minutes.
   */
  tampered: boolean;
  grants: MemberGrant[];
};

/** A value someone saw that is still the current one: what to rotate. */
export type ExposedSecret = {
  project: string;
  environment: string;
  key: string;
  version: number;
  /** `wrote` when they set this value themselves. */
  how: 'read' | 'wrote';
  /** The last time they read or wrote it. */
  at: string;
};

export type IssuedToken = {
  id: string;
  service: string;
  label: string | null;
  hint: string;
  expiresAt: string;
  lastUsedAt: string | null;
};

/**
 * What one person or service can still reach, and what they have seen.
 *
 * Built from the audit log, which records the version of every value read or
 * written. A value they saw that is still current is one they could still use
 * somewhere, so it is listed to rotate; writing a new version takes it off.
 */
export type OffboardingReport = {
  principalType: 'user' | 'service';
  principalId: string;
  status: 'active' | 'removed' | 'tampered';
  instanceRole: Member['instanceRole'];
  scope: Scope;
  isRootAdmin: boolean;
  removedAt: string | null;
  removedBy: string | null;
  /** What still lets them in. All zero once removed. */
  live: WaysIn;
  /** Current values they read or wrote, by project, environment and key. */
  exposed: ExposedSecret[];
  /** Secrets they saw that have had a new version since. */
  rotated: number;
  /** Service tokens they issued that still work. */
  issuedTokens: IssuedToken[];
  /** A person's connected MCP apps, which removing them disconnects. */
  apps: ConnectedApp[];
  /**
   * References they made, live ones first, as the log's `reference.create`
   * entries name their actor: each belongs to the environment that holds
   * it, and their leaving ends none. Listed for review
   * (docs/design/environments.md, "Offboarding").
   */
  references: ReferenceView[];
};

/** What lets a member in, counted: what removing them revokes. */
export type WaysIn = { grants: number; sessions: number; tokens: number; identities: number; apps: number };

/** Someone no longer a member, and how many of their report's values are left. */
export type RemovedMember = {
  principalType: 'user' | 'service';
  principalId: string;
  /** The length of their report's `exposed`. */
  toRotate: number;
};

/** A stored grant, placed by slug, and as a permission check names its place. */
type PlacedGrant = { project: string; environment: string | null; place: Place; role: Role; expiresAt: string | null };

/** The slugs of every project and environment, by id: grants name places only by id. */
function slugs(known: PlaceRow[]): Map<string, string> {
  return new Map(
    known.flatMap((project) => [
      [project.id, project.slug] as const,
      ...project.environments.map((environment) => [environment.id, environment.slug] as const),
    ]),
  );
}

function placed(grants: StoredGrant[], known: PlaceRow[]): PlacedGrant[] {
  return grants.flatMap((grant): PlacedGrant[] => {
    // A grant whose fields name no coherent place reaches nothing, and is not listed.
    if (grantKind(grant) === null) return [];
    const project = known.find((candidate) => candidate.id === grant.projectId);
    const environment = grant.environmentId === null ? null : project?.environments.find((candidate) => candidate.id === grant.environmentId);
    // A grant on a place that is gone names nothing anyone can reach.
    if (project === undefined || environment === undefined) return [];
    return [{
      project: project.slug,
      environment: environment?.slug ?? null,
      place: placeOf(project, environment),
      role: grant.role as Role,
      expiresAt: grant.expiresAt === null ? null : new Date(grant.expiresAt).toISOString(),
    }];
  });
}

/**
 * A scope as the API shows it: projects by slug, those that are still
 * there. Its environments are slugs already.
 */
export function scopeView(scope: Scope, known: PlaceRow[]): Scope {
  const names = slugs(known);
  const named = (ids: string[]) => ids.flatMap((id) => names.get(id) ?? []).sort();
  const projects: Filter = scope.projects === 'all' ? 'all' : 'only' in scope.projects ? { only: named(scope.projects.only) } : { except: named(scope.projects.except) };
  return { projects, environments: scope.environments };
}

/**
 * Whether someone's instance role, in its scope, reaches a project, or one
 * environment of it: what a project's access list shows them for, beside
 * the grants it lists.
 */
function roleReaches(role: InstanceRole, scope: Scope, project: PlaceRow, environment: string | undefined): boolean {
  if (INSTANCE_ROLES[role].permissions.length === 0) return false;
  const places = [
    ...(environment === undefined ? [placeOf(project, null)] : []),
    ...project.environments.filter((candidate) => environment === undefined || candidate.slug === environment).map((candidate) => placeOf(project, candidate)),
  ];
  return places.some((place) => inScope(scope, place));
}

/** Someone in the directory, as the rows and the vault's findings say. */
type Listed = {
  member: MemberRef;
  /** Null for a missing row, or a root admin the vault has not met yet. */
  row: MemberRow | null;
  isRootAdmin: boolean;
  status: 'active' | 'removed' | 'tampered';
  /** What they hold as stored: nothing unless active. */
  grants: StoredGrant[];
};

/**
 * Everyone in the directory, or one member, read from the rows rather than
 * asked of the vault: a list is a display, not a decision. The root admins
 * are the vault's configuration, so it says who they are, rows or not.
 */
async function directory(ctx: ApiContext, now: Date, member?: MemberRef): Promise<Listed[]> {
  const [rows, missing, { rootAdmins }] = await Promise.all([
    loadMembers(ctx.db, ctx.chainKey, member === undefined ? {} : { member }, now),
    missingMembers(ctx.db, member),
    ctx.vault.about(),
  ]);
  const byPrincipal = new Map(rows.map((row) => [formatMember(row), row]));
  const roots = new Set(rootAdmins);
  const wanted = member === undefined ? null : formatMember(member);
  const principals = new Set([...byPrincipal.keys(), ...missing, ...rootAdmins.filter((root) => wanted === null || root === wanted)]);
  return [...principals].sort().map((principal) => {
    const row = byPrincipal.get(principal) ?? null;
    const isRootAdmin = roots.has(principal);
    const status = isRootAdmin ? 'active' : row === null || row.tampered ? 'tampered' : row.status;
    return { member: parseGrantee(principal) as MemberRef, row, isRootAdmin, status, grants: status === 'active' ? row?.grants ?? [] : [] };
  });
}

function instanceRole(listed: Listed): Member['instanceRole'] {
  if (listed.isRootAdmin) return 'root-admin';
  return listed.status === 'active' && listed.member.type === 'user' ? listed.row?.role ?? 'member' : 'member';
}

/** Where their instance role applies, as stored: everywhere for anyone without one. */
function scopeOf(listed: Listed): Scope {
  return instanceRole(listed) === 'member' || listed.isRootAdmin ? EVERYWHERE : listed.row?.scope ?? EVERYWHERE;
}

/** By project, then environment, with the project-wide grant after its environments. */
function byPlace(a: PlacedGrant, b: PlacedGrant): number {
  if (a.project !== b.project) return a.project < b.project ? -1 : 1;
  if (a.environment === b.environment) return 0;
  if (a.environment === null) return 1;
  if (b.environment === null) return -1;
  return a.environment < b.environment ? -1 : 1;
}

/**
 * Members and their live grants. Admins and owners see everyone, with the
 * grants they manage: all of them, or, scoped, those inside their scope.
 * Anyone else sees the grants in the places where they hold
 * `grant.manage`, and the members those grants belong to. `path` narrows
 * it to who reaches one project or environment: by a grant there, or by an
 * instance role whose scope takes it in, listed with no grant.
 */
export async function listMembers(
  ctx: ApiContext,
  query: { path?: Path },
): Promise<{ members: Member[]; removed: RemovedMember[] }> {
  const { caller } = ctx;
  const administrator = caller.isRootAdmin || administers(caller.role);
  if (!administrator && !canAnywhere(caller, 'grant.manage')) {
    throw forbidden('only admins, owners and members with grant.manage on a project can list members');
  }
  const everyone = query.path === undefined && administrator;
  const [all, known] = await Promise.all([directory(ctx, new Date()), places(ctx.db)]);
  const path = query.path;
  const target = path === undefined ? undefined : known.find((project) => project.slug === path.project);
  if (path !== undefined && target === undefined) throw notFound(`no project "${path.project}"`);
  const inPath = (grant: PlacedGrant): boolean =>
    path === undefined || (grant.project === path.project && (path.environment === undefined || grant.environment === path.environment));
  // Who reaches the path by their instance role is shown to whoever manages access there.
  const managesPath = target !== undefined && (runsInstance(caller) || [
    ...(path?.environment === undefined ? [placeOf(target, null)] : []),
    ...target.environments.filter((environment) => path?.environment === undefined || environment.slug === path.environment).map((environment) => placeOf(target, environment)),
  ].some((place) => mayManageAccess(caller, place)));

  const members: Member[] = [];
  for (const listed of all) {
    if (listed.status === 'removed') continue;
    const visible = placed(listed.grants, known)
      .filter((grant) => (runsInstance(caller) || mayManageAccess(caller, grant.place)) && inPath(grant))
      .sort(byPlace);
    const role = instanceRole(listed);
    const scope = scopeOf(listed);
    const byRole = target !== undefined && managesPath && role !== 'root-admin' && roleReaches(role, scope, target, path?.environment);
    if (!everyone && visible.length === 0 && !byRole) continue;
    const ref = listed.member;
    const member = formatMember(ref);
    members.push({
      member,
      principalType: ref.type,
      principalId: ref.id,
      instanceRole: role,
      scope: scopeView(scope, known),
      reachesByRole: byRole,
      isRootAdmin: listed.isRootAdmin,
      tampered: listed.status === 'tampered',
      grants: visible.map((grant) => ({
        id: `${member}/${grant.project}${grant.environment === null ? '' : `/${grant.environment}`}`,
        project: grant.project,
        environment: grant.environment,
        role: grant.role,
        roleName: ROLES[grant.role].name,
        permissions: [...ROLES[grant.role].permissions],
        expiresAt: grant.expiresAt,
      })),
    });
  }
  members.sort((a, b) => a.principalType.localeCompare(b.principalType) || a.principalId.localeCompare(b.principalId));
  // Those removed are the instance's to see: their reports name what they saw anywhere.
  if (!everyone || !runsInstance(caller)) return { members, removed: [] };

  // Everyone removed, so their reports stay reachable: removal ends access,
  // not the work of rotating what they saw.
  const removed = all.filter((listed) => listed.status === 'removed').map((listed) => listed.member);
  const exposed = exposure(removed, removed.length === 0 ? [] : await memberActivity(ctx.db, removed.map((m) => m.id)));
  return {
    members,
    removed: removed.map((member) => ({
      principalType: member.type,
      principalId: member.id,
      toRotate: exposed.get(formatMember(member))!.exposed.length,
    })),
  };
}

type Activity = Awaited<ReturnType<typeof memberActivity>>[number];
type Seen = { version: number; wrote: boolean; at: string };

/**
 * What each of these members read or wrote that is still a live secret's
 * current version: a value they saw that is still current is one to rotate.
 */
function exposure(
  members: MemberRef[],
  activity: Activity[],
): Map<string, { exposed: ExposedSecret[]; rotated: number }> {
  const result = new Map(members.map((member) => [formatMember(member), { exposed: [] as ExposedSecret[], rotated: 0 }]));

  // Per member, per secret, per version: whether they wrote it, and when they last saw it.
  const seen = new Map<string, Map<string, Map<number, Seen>>>();
  // A restore is a new version holding an older one's value, so whoever saw
  // that value has seen the restored version too.
  const restoredFrom = new Map<string, number>();
  const current = new Map<string, Activity>();
  for (const row of activity) {
    if (row.secretId === null) continue;
    const metadata = JSON.parse(row.metadata) as { version?: unknown; from?: unknown };
    if (row.action === 'secret.restore') {
      if (typeof metadata.version === 'number' && typeof metadata.from === 'number') {
        restoredFrom.set(`${row.secretId}:${metadata.version}`, metadata.from);
      }
      continue;
    }
    const { actorType, actorId } = actorParts(row.actor);
    const key = formatMember({ type: actorType as 'user' | 'service', id: actorId });
    if (!result.has(key)) continue;
    const version = metadata.version;
    if (typeof version !== 'number') continue;
    if (row.key !== null && !row.archived && row.currentVersion! > 0) current.set(row.secretId, row);
    const bySecret = seen.get(key) ?? new Map<string, Map<number, Seen>>();
    seen.set(key, bySecret);
    const byVersion = bySecret.get(row.secretId) ?? new Map<number, Seen>();
    bySecret.set(row.secretId, byVersion);
    const previous = byVersion.get(version);
    byVersion.set(version, {
      version,
      wrote: (previous?.wrote ?? false) || row.action !== 'secret.read',
      at: row.occurredAt,
    });
  }

  const secrets = [...current.values()].sort(
    (a, b) => compare(a.project!, b.project!) || compare(a.environment!, b.environment!) || compare(a.key!, b.key!),
  );
  for (const [key, bySecret] of seen) {
    const report = result.get(key)!;
    for (const secret of secrets) {
      const byVersion = bySecret.get(secret.secretId!);
      if (byVersion === undefined) continue;
      // Restores only point back, so this walk ends.
      let version: number | undefined = secret.currentVersion!;
      let hit: Seen | undefined;
      while (version !== undefined && (hit = byVersion.get(version)) === undefined) {
        version = restoredFrom.get(`${secret.secretId}:${version}`);
      }
      if (hit === undefined) {
        report.rotated += 1;
        continue;
      }
      report.exposed.push({
        project: secret.project!,
        environment: secret.environment!,
        key: secret.key!,
        version: secret.currentVersion!,
        how: hit.wrote ? 'wrote' : 'read',
        at: hit.at,
      });
    }
  }
  return result;
}

const compare = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * Who someone is to this instance and what to rotate if they leave, for
 * those who run the instance. Works for removed members too: that is when
 * it matters most.
 */
export async function memberReport(ctx: ApiContext, member: MemberRef): Promise<OffboardingReport> {
  if (!runsInstance(ctx.caller)) throw forbidden('only admins and owners of the whole instance may see what someone has access to');
  // Everyone, not just them: the service tokens they issued belong to others.
  const [everyone, known] = await Promise.all([directory(ctx, new Date()), places(ctx.db)]);
  const listed = everyone.find((entry) => formatMember(entry.member) === formatMember(member));
  if (listed === undefined) throw notFound('no such member');
  const { row, status } = listed;

  const held = row?.credentials ?? [];
  const issued = everyone
    .filter((entry) => entry.status === 'active')
    .flatMap((entry) => (entry.row?.credentials ?? []).map((credential) => ({ service: entry.member.id, ...credential })))
    .filter((credential) => credential.kind === 'service' && credential.createdBy === member.id)
    .sort((a, b) => compare(a.service, b.service) || a.createdAt.getTime() - b.createdAt.getTime());

  const activity = await memberActivity(ctx.db, [member.id]);
  const { exposed, rotated } = exposure([member], activity).get(formatMember(member))!;
  const made = (await referencesBy(ctx.db, formatMember(member))).map((reference) => reference.view);
  made.sort((a, b) => Number(b.state === 'live') - Number(a.state === 'live') || a.createdAt.localeCompare(b.createdAt));
  // Only people connect apps. Removal disconnects them, but 0.4.0's left
  // them to the generation alone: a removed member's are never listed.
  const apps = member.type === 'user' && status !== 'removed' && ctx.mcp !== null ? await ctx.mcp.appsOf(formatMember(member)) : [];
  return {
    principalType: member.type,
    principalId: member.id,
    status,
    instanceRole: instanceRole(listed),
    scope: scopeView(scopeOf(listed), known),
    isRootAdmin: listed.isRootAdmin,
    // When and by whom, as the vault wrote it: the removal is its decision.
    removedAt: status === 'removed' ? row!.statusChangedAt.toISOString() : null,
    removedBy: status === 'removed' ? parseGrantee(row!.statusChangedBy).id : null,
    live: {
      grants: listed.grants.length,
      sessions: held.filter((credential) => credential.kind !== 'service').length,
      tokens: held.filter((credential) => credential.kind === 'service').length,
      identities: row?.identities.length ?? 0,
      apps: apps.length,
    },
    exposed,
    rotated,
    issuedTokens: issued.map((token) => ({
      id: token.id,
      service: token.service,
      label: token.label,
      hint: token.tokenHint,
      expiresAt: token.expiresAt.toISOString(),
      lastUsedAt: token.lastUsedAt?.toISOString() ?? null,
    })),
    apps,
    references: made,
  };
}

/**
 * Who reads each of these environments, by a grant or their instance role,
 * as members: those a reference held there lets read its source. Root
 * admins read everything, and are not listed.
 */
export async function readersAt(ctx: ApiContext, places: readonly { projectId: string; environmentId: string; environmentSlug: string }[]): Promise<string[][]> {
  if (places.length === 0) return [];
  const all = await directory(ctx, new Date());
  return places.map((place) => all
    .filter((listed) => listed.status === 'active' && !listed.isRootAdmin && allows(
      { isRootAdmin: false, role: instanceRole(listed) as InstanceRole, scope: scopeOf(listed), grants: listed.grants.map((grant) => ({ ...grant, role: grant.role as Role })) },
      'secret.read',
      place,
    ))
    .map((listed) => formatMember(listed.member)));
}

function rootAdminRefusal(ctx: ApiContext, action: string, member: MemberRef): Refusal {
  return new Refusal(
    conflict("root admins are set by the vault's COFFRE_ROOT_ADMINS"),
    denied(ctx, action, 'configured_root_admin', {
      metadata: { principalType: member.type, principalId: member.id },
    }),
  );
}

/** One member's access, as a member page shows it: their instance role and scope, and the grants the caller sees. */
export type MemberAccess = {
  member: string;
  principalType: 'user' | 'service';
  principalId: string;
  status: 'active' | 'removed' | 'tampered';
  instanceRole: InstanceRole | 'root-admin';
  /** Projects by slug; everywhere for a member or a root admin. */
  scope: Scope;
  isRootAdmin: boolean;
  /** Their live grants the caller manages: all of them, for those who run the instance. None unless active. */
  grants: MemberGrant[];
};

/**
 * One member's access, for their page: one query (`memberAccess` in
 * db/queries.ts), however many projects they hold grants in, rather than
 * a project's list per project. For whoever may list members; the grants
 * are those the caller manages, as `listMembers` shows them.
 */
export async function memberAccess(ctx: ApiContext, member: MemberRef): Promise<MemberAccess> {
  const { caller } = ctx;
  const administrator = caller.isRootAdmin || administers(caller.role);
  if (!administrator && !canAnywhere(caller, 'grant.manage')) {
    throw forbidden('only admins, owners and members with grant.manage on a project can see what someone holds');
  }
  const principal = formatMember(member);
  const [stored, { rootAdmins }] = await Promise.all([readMemberAccess(ctx.db, principal, new Date()), ctx.vault.about()]);
  const isRootAdmin = rootAdmins.includes(principal);
  if (stored.member === null && !isRootAdmin) throw notFound('no such member');
  const status = isRootAdmin ? 'active' : stored.member!.tampered ? 'tampered' : stored.member!.status;
  const role: InstanceRole = status === 'active' && member.type === 'user' && !isRootAdmin ? stored.member!.role : 'member';
  const scope = role === 'member' ? EVERYWHERE : stored.member!.scope;
  // A scope names projects by id: by slug here, those still there, as `scopeView` names them.
  const named = (ids: string[]) => ids.flatMap((id) => stored.projectSlugs.get(id) ?? []).filter((slug) => !isTombstone(slug)).sort();
  const shown: Scope = {
    projects: scope.projects === 'all' ? 'all' : 'only' in scope.projects ? { only: named(scope.projects.only) } : { except: named(scope.projects.except) },
    environments: scope.environments,
  };
  const grants = status !== 'active' ? [] : stored.grants
    // A grant on a place that is gone names nothing anyone can reach.
    .filter((grant) => !isTombstone(grant.projectSlug) && (grant.environmentSlug === null || !isTombstone(grant.environmentSlug)))
    .filter((grant) => runsInstance(caller) || mayManageAccess(caller, grant.environmentId === null
      ? { projectId: grant.projectId }
      : { projectId: grant.projectId, environmentId: grant.environmentId, environmentSlug: grant.environmentSlug }))
    .map((grant) => {
      const held = grant.role as Role;
      return {
        id: `${principal}/${grant.projectSlug}${grant.environmentSlug === null ? '' : `/${grant.environmentSlug}`}`,
        project: grant.projectSlug,
        environment: grant.environmentSlug,
        role: held,
        roleName: ROLES[held].name,
        permissions: [...ROLES[held].permissions],
        expiresAt: grant.expiresAt === null ? null : new Date(grant.expiresAt).toISOString(),
      };
    })
    .sort((a, b) => compare(a.project, b.project) || (a.environment === null ? 1 : b.environment === null ? -1 : compare(a.environment, b.environment)));
  return {
    member: principal,
    principalType: member.type,
    principalId: member.id,
    status,
    instanceRole: isRootAdmin ? 'root-admin' : role,
    scope: shown,
    isRootAdmin,
    grants,
  };
}

/** A filter as the API takes one, projects by slug. */
type FilterInput = 'all' | { only: string[] } | { except: string[] };

/**
 * Add a member, bring back a removed one, or set a person's instance role
 * and its scope (left out, everywhere). Adding someone who is already a
 * member as they are changes nothing. Those who run the instance do it,
 * never about themselves; the vault decides and keeps who is in, in the
 * member row their sessions and tokens hang off.
 *
 *   { "role": "developer", "scope": { "projects": "all", "environments": { "only": ["dev"] } } }
 */
export async function putMember(
  ctx: ApiContext,
  member: MemberRef,
  input: { role?: InstanceRole; scope?: { projects?: FilterInput; environments?: FilterInput } },
): Promise<{ member: string; instanceRole: InstanceRole; scope: Scope; created: boolean }> {
  const principal = formatMember(member);
  const fields = { principalType: member.type, principalId: member.id, ...(input.role === undefined ? {} : { role: input.role }) };
  return withRefusals(ctx, async () => {
    requireInstance(ctx, 'member.add', { metadata: fields }, 'add members or set their roles');
    if ((await ctx.vault.about()).rootAdmins.includes(principal)) throw rootAdminRefusal(ctx, 'member.add', member);
    if (input.scope !== undefined && input.role === undefined) throw badRequest('a scope goes with a role: name the role too');
    if (member.type === 'service' && input.role !== undefined && input.role !== 'member') {
      throw new Refusal(
        conflict('service accounts hold project grants only, never an instance role'),
        denied(ctx, 'member.add', 'service_cannot_hold_role', { metadata: fields }),
      );
    }
    const known = await places(ctx.db);
    const scope = input.role === undefined ? undefined : scopeIds(input.scope ?? {}, known);
    const self = formatMember(ctx.caller.principal) === principal;
    if (self && input.role !== undefined && (input.role !== ctx.caller.role || JSON.stringify(scope) !== JSON.stringify(ctx.caller.scope))) {
      throw new Refusal(
        conflict('nobody changes their own instance role: ask another admin'),
        denied(ctx, 'member.add', 'own_role', { metadata: fields }),
      );
    }

    // The vault logs the change, as `member.add`, `member.restore` or `member.role`.
    const result = await ctx.vault.admit({
      actor: formatMember(ctx.caller.principal),
      principal,
      ...(input.role === undefined ? {} : { role: input.role, scope }),
      requestId: ctx.requestId,
      operationId: randomUUID(),
      credentialId: ctx.provenance,
    });
    if (!result.ok) throw vaultRefused(result.refusal);
    // Housekeeping: rows of an earlier membership are dead already, by their generation.
    await audited(ctx, (tx) => revokePriorMembership(tx, ctx.chainKey, member, result.generation, ctx.caller.principal.id));
    return { member: principal, instanceRole: result.role, scope: scopeView(result.scope, known), created: result.created };
  });
}

/** A scope as the vault keeps it, projects by id: a project the API names by slug must be there. */
function scopeIds(input: { projects?: FilterInput; environments?: FilterInput }, known: PlaceRow[]): Scope {
  const id = (slug: string) => {
    const project = known.find((candidate) => candidate.slug === slug);
    if (project === undefined) throw notFound(`no project "${slug}"`);
    return project.id;
  };
  const projects = input.projects ?? 'all';
  return normalScope({
    projects: projects === 'all' ? 'all' : 'only' in projects ? { only: projects.only.map(id) } : { except: projects.except.map(id) },
    environments: input.environments ?? 'all',
  });
}

/**
 * Offboard a member: the vault revokes every grant and refuses them from
 * then on, whatever sessions they still hold; the app signs out every
 * session and revokes their tokens, sign-in accounts and connected apps.
 * Re-adding them later is a fresh start. Returns their report, which is
 * what to rotate.
 */
export async function removeMember(
  ctx: ApiContext,
  member: MemberRef,
): Promise<{ revoked: WaysIn; report: OffboardingReport }> {
  const principal = formatMember(member);
  const fields = { principalType: member.type, principalId: member.id };
  const revoked = await withRefusals(ctx, async () => {
    requireInstance(ctx, 'member.remove', { metadata: fields }, 'remove members');
    if ((await ctx.vault.about()).rootAdmins.includes(principal)) throw rootAdminRefusal(ctx, 'member.remove', member);
    // The vault logs the removal, and one `access.revoke` per grant it took, so each project's log shows it.
    const result = await ctx.vault.remove({
      actor: formatMember(ctx.caller.principal),
      principal,
      requestId: ctx.requestId,
      operationId: randomUUID(),
      credentialId: ctx.provenance,
    });
    if (!result.ok) {
      if (result.refusal.code === 'not_a_member' || result.refusal.code === 'removed') {
        throw new Refusal(
          notFound('no such member'),
          denied(ctx, 'member.remove', 'unknown_principal', { metadata: fields }),
        );
      }
      throw vaultRefused(result.refusal);
    }
    const { generation } = result;
    return audited(ctx, async (tx) => {
      const now = new Date();
      const [held] = await loadMembers(tx, ctx.chainKey, { member }, now);
      const liveCredentials = (held?.credentials ?? []).filter((row) => row.generation < generation);
      const liveIdentities = (held?.identities ?? []).filter((row) => row.generation < generation);
      // The generation already ends them; revoked, Connected apps and their report say so.
      const liveApps =
        member.type === 'user' ? (await liveConnections(tx, ctx.chainKey, principal, now)).filter((row) => row.generation < generation) : [];
      const revokedBy = ctx.caller.principal.id;
      const ids = (rows: { id: string }[]) => rows.map((row) => row.id);
      if (liveCredentials.length > 0) {
        await updateAuth(tx, ctx.chainKey, credentials, { id: ids(liveCredentials) }, { revokedAt: now, revokedBy });
      }
      if (liveIdentities.length > 0) {
        await updateAuth(tx, ctx.chainKey, identities, { id: ids(liveIdentities) }, { revokedAt: now, revokedBy });
      }
      if (liveApps.length > 0) {
        await updateAuth(tx, ctx.chainKey, mcpConnections, { id: ids(liveApps) }, { revokedAt: now, revokedBy });
      }

      return {
        grants: result.revoked.length,
        sessions: liveCredentials.filter((row) => row.kind !== 'service').length,
        tokens: liveCredentials.filter((row) => row.kind === 'service').length,
        identities: liveIdentities.length,
        // As the report counts them: a code never redeemed was no app yet.
        apps: liveApps.filter((row) => row.refreshHash !== null).length,
      };
    });
  });
  return { revoked, report: await memberReport(ctx, member) };
}
