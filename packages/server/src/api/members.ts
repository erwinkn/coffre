import { ROLES, type Permission, type Role } from '../../../core/src/access.ts';
import type { Queryable } from '../../../db/src/database.ts';
import {
  insertIfAbsent,
  lock,
  memberActivity,
  members as loadMembers,
  places,
  update,
} from '../../../db/src/queries.ts';
import { credentials, identities, principals } from '../../../db/src/schema.ts';
import type { Access, Grant } from '../../../vault/src/types.ts';
import { can } from './caller.ts';
import { allowed, audited, denied, Refusal, requireOwner, vaultRefusal, type ApiContext } from './context.ts';
import { conflict, forbidden, notFound } from './errors.ts';
import { formatMember, parseGrantee, type MemberRef, type Path } from './paths.ts';
import { syncsCreatedBy, type PlacedSyncView } from './syncs.ts';

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
  instanceRole: 'user' | 'owner' | 'root-admin';
  isRootAdmin: boolean;
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
  status: 'active' | 'removed';
  instanceRole: Member['instanceRole'];
  isRootAdmin: boolean;
  removedAt: string | null;
  removedBy: string | null;
  /** What still lets them in. All zero once removed. */
  live: { grants: number; sessions: number; tokens: number; identities: number };
  /** Current values they read or wrote, by project, environment and key. */
  exposed: ExposedSecret[];
  /** Secrets they saw that have had a new version since. */
  rotated: number;
  /** Service tokens they issued that still work. */
  issuedTokens: IssuedToken[];
  /** Syncs they set up, which keep pushing after they leave. */
  syncs: PlacedSyncView[];
};

/** Someone no longer a member, and how many of their report's values are left. */
export type RemovedMember = {
  principalType: 'user' | 'service';
  principalId: string;
  /** The length of their report's `exposed`. */
  toRotate: number;
};

/** A vault grant, placed by slug. */
type PlacedGrant = Grant & { project: string; environment: string | null };

/** The slugs of every project and environment, by id: the vault knows places only by id. */
async function slugs(db: Queryable): Promise<Map<string, string>> {
  return new Map(
    (await places(db)).flatMap((project) => [
      [project.id, project.slug] as const,
      ...project.environments.map((environment) => [environment.id, environment.slug] as const),
    ]),
  );
}

function placed(grants: Grant[], names: Map<string, string>): PlacedGrant[] {
  return grants.flatMap((grant) => {
    const project = names.get(grant.projectId);
    const environment = grant.environmentId === null ? null : names.get(grant.environmentId);
    // A grant on a place that is gone names nothing anyone can reach.
    return project === undefined || environment === undefined ? [] : [{ ...grant, project, environment }];
  });
}

/** A vault principal as a member, or null for a sync, which is no one's to list. */
function memberOf(access: Access): MemberRef | null {
  const ref = parseGrantee(access.principal);
  return ref.type === 'sync' ? null : ref;
}

function instanceRole(access: Access): Member['instanceRole'] {
  return access.isRootAdmin ? 'root-admin' : access.isOwner ? 'owner' : 'user';
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
 * Members and their live grants. Owners see everyone; anyone else sees the
 * grants in the projects where they hold `grant.manage`, and the members
 * those grants belong to. `path` narrows it to one project or environment.
 */
export async function listMembers(
  ctx: ApiContext,
  query: { path?: Path },
): Promise<{ members: Member[]; removed: RemovedMember[] }> {
  const { caller } = ctx;
  const manages = (projectId: string) => can(caller, 'grant.manage', { projectId });
  if (!caller.isOwner && !caller.grants.some((grant) => manages(grant.projectId))) {
    throw forbidden('only owners, and members with grant.manage on a project, can list members');
  }
  const everyone = query.path === undefined && caller.isOwner;
  const inPath = (grant: PlacedGrant) =>
    query.path === undefined ||
    (grant.project === query.path.project &&
      (query.path.environment === undefined || grant.environment === query.path.environment));

  const [all, names] = await Promise.all([ctx.vault.members(), slugs(ctx.db)]);
  const members: Member[] = [];
  for (const access of all) {
    const ref = memberOf(access);
    if (ref === null || access.status !== 'active') continue;
    const visible = placed(access.grants, names)
      .filter((grant) => (caller.isOwner || manages(grant.projectId)) && inPath(grant))
      .sort(byPlace);
    if (!everyone && visible.length === 0) continue;
    const member = formatMember(ref);
    members.push({
      member,
      principalType: ref.type,
      principalId: ref.id,
      instanceRole: instanceRole(access),
      isRootAdmin: access.isRootAdmin,
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
  if (!everyone) return { members, removed: [] };

  // Everyone removed, so their reports stay reachable: removal ends access,
  // not the work of rotating what they saw.
  const removed = all
    .filter((access) => access.status === 'removed')
    .flatMap((access) => memberOf(access) ?? []);
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
    const metadata = JSON.parse(row.metadata) as { version?: unknown; toVersion?: unknown };
    if (row.action === 'secret.rollback') {
      if (typeof metadata.version === 'number' && typeof metadata.toVersion === 'number') {
        restoredFrom.set(`${row.secretId}:${metadata.version}`, metadata.toVersion);
      }
      continue;
    }
    const key = formatMember({ type: row.actorType as 'user' | 'service', id: row.actorId });
    if (row.action === 'directory.remove' || !result.has(key)) continue;
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
 * Who someone is to this instance and what to rotate if they leave. Owners
 * only. Works for removed members too: that is when it matters most.
 */
export async function memberReport(ctx: ApiContext, member: MemberRef): Promise<OffboardingReport> {
  if (!ctx.caller.isOwner) throw forbidden('only owners may see what someone has access to');
  const now = new Date();
  // Everyone, not just them: the service tokens they issued belong to others.
  const [everyone, directory] = await Promise.all([ctx.vault.members(), loadMembers(ctx.db, {}, now)]);
  const standing = new Map(everyone.map((access) => [access.principal, access]));
  const access = standing.get(formatMember(member));
  if (access === undefined || access.status === 'unknown') throw notFound('no such member');
  const active = access.status === 'active';
  const found = directory.find((row) => row.type === member.type && row.id === member.id);

  const held = found?.credentials ?? [];
  const issued = directory
    .filter((row) => standing.get(formatMember(row))?.status === 'active')
    .flatMap((row) => row.credentials.map((credential) => ({ service: row.id, ...credential })))
    .filter((credential) => credential.kind === 'service' && credential.createdBy === member.id)
    .sort((a, b) => compare(a.service, b.service) || a.createdAt.getTime() - b.createdAt.getTime());

  const activity = await memberActivity(ctx.db, [member.id]);
  const { exposed, rotated } = exposure([member], activity).get(formatMember(member))!;
  return {
    principalType: member.type,
    principalId: member.id,
    status: active ? 'active' : 'removed',
    instanceRole: instanceRole(access),
    isRootAdmin: access.isRootAdmin,
    // The vault knows when and by whom: the removal is its decision.
    removedAt: active ? null : access.since,
    removedBy: active || access.by === null ? null : parseGrantee(access.by).id,
    live: {
      grants: access.grants.length,
      sessions: held.filter((credential) => credential.kind !== 'service').length,
      tokens: held.filter((credential) => credential.kind === 'service').length,
      identities: found?.identities.length ?? 0,
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
    syncs: await syncsCreatedBy(ctx, member.id),
  };
}

function rootAdminRefusal(ctx: ApiContext, action: string, member: MemberRef): Refusal {
  return new Refusal(
    conflict("root admins are set by the vault's COFFRE_ROOT_ADMINS"),
    denied(ctx, action, 'configured_root_admin', {
      metadata: { principalType: member.type, principalId: member.id },
    }),
  );
}

/**
 * Add a member, bring back a removed one, or change whether they are an
 * owner. Adding someone who is already a member as they are changes nothing.
 * The vault decides and keeps who is in; the app keeps a directory row, which
 * their sessions and tokens hang off.
 */
export async function putMember(
  ctx: ApiContext,
  member: MemberRef,
  input: { owner?: boolean },
): Promise<{ member: string; instanceRole: 'user' | 'owner'; created: boolean }> {
  const principal = formatMember(member);
  const fields = { principalType: member.type, principalId: member.id, instanceRole: input.owner === true ? 'owner' : 'user' };
  return audited(ctx, async (tx, log) => {
    requireOwner(ctx, 'directory.create', { metadata: fields });
    const standing = await ctx.vault.access(principal);
    if (standing.isRootAdmin) throw rootAdminRefusal(ctx, 'directory.create', member);
    if (member.type === 'service' && input.owner === true) {
      throw new Refusal(
        conflict('service accounts cannot be instance owners'),
        denied(ctx, 'directory.create', 'service_cannot_be_owner', { metadata: fields }),
      );
    }

    const result = await ctx.vault.admit({
      actor: formatMember(ctx.caller.principal),
      principal,
      owner: input.owner,
      requestId: ctx.requestId,
    });
    if (!result.ok) throw vaultRefusal(ctx, result.refusal, 'directory.create', { metadata: fields });
    const role = result.owner ? 'owner' : 'user';
    await insertIfAbsent(tx, principals, {
      principalType: member.type,
      principalId: member.id,
      createdBy: ctx.caller.principal.id,
    });
    if (result.created) {
      log.push(allowed(ctx, 'directory.create', { metadata: { ...fields, instanceRole: role } }));
    } else if (result.owner !== standing.isOwner) {
      log.push(allowed(ctx, 'directory.update', { metadata: { ...fields, instanceRole: role } }));
    }
    return { member: principal, instanceRole: role, created: result.created };
  });
}

/**
 * Offboard a member: the vault revokes every grant and refuses them from
 * then on, whatever sessions they still hold; the app signs out every
 * session and revokes their tokens and sign-in accounts. Re-adding them
 * later is a fresh start. Returns their report, which is what to rotate.
 */
export async function removeMember(
  ctx: ApiContext,
  member: MemberRef,
): Promise<{ revoked: { grants: number; sessions: number; tokens: number; identities: number }; report: OffboardingReport }> {
  const principal = formatMember(member);
  const fields = { principalType: member.type, principalId: member.id };
  const revoked = await audited(ctx, async (tx, log) => {
    requireOwner(ctx, 'directory.remove', { metadata: fields });
    const standing = await ctx.vault.access(principal);
    if (standing.isRootAdmin) throw rootAdminRefusal(ctx, 'directory.remove', member);
    if (standing.status !== 'active') {
      throw new Refusal(
        notFound('no such member'),
        denied(ctx, 'directory.remove', 'unknown_principal', { metadata: fields }),
      );
    }

    const key = { principalType: member.type, principalId: member.id };
    // Locking the row makes a token issue that races this wait, then find its credentials revoked.
    await lock(tx, principals, key);
    const result = await ctx.vault.remove({
      actor: formatMember(ctx.caller.principal),
      principal,
      requestId: ctx.requestId,
    });
    if (!result.ok) throw vaultRefusal(ctx, result.refusal, 'directory.remove', { metadata: fields });

    const now = new Date();
    const [held] = await loadMembers(tx, { member }, now);
    const liveCredentials = held?.credentials ?? [];
    const liveIdentities = held?.identities ?? [];
    const revokedBy = ctx.caller.principal.id;
    const ids = (rows: { id: string }[]) => rows.map((row) => row.id);
    if (liveCredentials.length > 0) {
      await update(tx, credentials, { id: ids(liveCredentials) }, { revokedAt: now, revokedBy });
    }
    if (liveIdentities.length > 0) {
      await update(tx, identities, { id: ids(liveIdentities) }, { revokedAt: now, revokedBy });
    }

    const counts = {
      grants: result.revoked.length,
      sessions: liveCredentials.filter((row) => row.kind !== 'service').length,
      tokens: liveCredentials.filter((row) => row.kind === 'service').length,
      identities: liveIdentities.length,
    };
    const perProject = new Map<string, number>();
    for (const grant of result.revoked) {
      perProject.set(grant.projectId, (perProject.get(grant.projectId) ?? 0) + 1);
    }
    const { grants: revokedGrants, ...signedOut } = counts;
    log.push(allowed(ctx, 'directory.remove', { metadata: { ...fields, revoked: revokedGrants, ...signedOut } }));
    // One row per project too, so each project's own log shows who lost access to it.
    for (const [projectId, n] of [...perProject].sort(([a], [b]) => a.localeCompare(b))) {
      log.push(allowed(ctx, 'directory.remove', { projectId, metadata: { ...fields, revoked: n } }));
    }
    return counts;
  });
  return { revoked, report: await memberReport(ctx, member) };
}
