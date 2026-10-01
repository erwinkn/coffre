import { ROLES, type Permission, type Role } from '../../../../../packages/core/src/access.ts';
import type { Queryable } from '../../../../../packages/db/src/database.ts';
import {
  insertIfAbsent,
  lock,
  memberActivity,
  members as loadMembers,
  update,
  type MemberRow,
} from '../../../../../packages/db/src/queries.ts';
import { credentials, grants, identities, principals } from '../../../../../packages/db/src/schema.ts';
import { can, isConfiguredRootAdmin } from './caller.ts';
import { allowed, audited, denied, Refusal, requireOwner, type ApiContext } from './context.ts';
import { conflict, forbidden, notFound } from './errors.ts';
import { formatMember, type MemberRef, type Path } from './paths.ts';
import { syncsCreatedBy, type PlacedSyncView } from './syncs.ts';

export type MemberGrant = {
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

const isLive = (now: Date) => (grant: { expiresAt: Date | null }) =>
  grant.expiresAt === null || grant.expiresAt > now;

/** By project, then environment, with the project-wide grant after its environments. */
function byPlace(a: MemberRow['grants'][number], b: MemberRow['grants'][number]): number {
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
  const inPath = (grant: MemberRow['grants'][number]) =>
    query.path === undefined ||
    (grant.project === query.path.project &&
      (query.path.environment === undefined || grant.environment === query.path.environment));

  const all = await loadMembers(ctx.db, {}, new Date());
  const byMember = new Map<string, Member>();
  const entry = (type: 'user' | 'service', id: string, instanceRole: string): Member => {
    const ref = { type, id };
    const key = formatMember(ref);
    let member = byMember.get(key);
    if (member === undefined) {
      const isRootAdmin = isConfiguredRootAdmin(ref, ctx.rootAdmins);
      member = {
        member: key,
        principalType: type,
        principalId: id,
        instanceRole: isRootAdmin ? 'root-admin' : (instanceRole as 'user' | 'owner'),
        isRootAdmin,
        grants: [],
      };
      byMember.set(key, member);
    }
    return member;
  };

  // Owners see configured root admins even when they have no row.
  if (everyone) {
    for (const id of ctx.rootAdmins) entry('user', id, 'user');
  }
  const now = new Date();
  for (const row of all.filter((row) => row.active)) {
    if (everyone) entry(row.type, row.id, row.instanceRole);
    const visible = row.grants
      .filter(isLive(now))
      .filter((grant) => (caller.isOwner || manages(grant.projectId)) && inPath(grant))
      .sort(byPlace);
    for (const grant of visible) {
      const role = grant.role as Role;
      entry(row.type, row.id, row.instanceRole).grants.push({
        id: grant.id,
        project: grant.project,
        environment: grant.environment,
        role,
        roleName: ROLES[role].name,
        permissions: [...ROLES[role].permissions],
        expiresAt: grant.expiresAt?.toISOString() ?? null,
      });
    }
  }

  const members = [...byMember.values()].sort(
    (a, b) => a.principalType.localeCompare(b.principalType) || a.principalId.localeCompare(b.principalId),
  );
  if (!everyone) return { members, removed: [] };

  // Everyone removed, so their reports stay reachable: removal ends access,
  // not the work of rotating what they saw.
  const removed = all
    .filter((row) => !row.active && !isConfiguredRootAdmin(row, ctx.rootAdmins))
    .map((row) => ({ type: row.type, id: row.id }));
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
  const isRootAdmin = isConfiguredRootAdmin(member, ctx.rootAdmins);
  const now = new Date();
  // Everyone, not just them: the service tokens they issued belong to others.
  const all = await loadMembers(ctx.db, {}, now);
  const found = all.find((row) => row.type === member.type && row.id === member.id);
  if (found === undefined && !isRootAdmin) throw notFound('no such member');
  const active = isRootAdmin || found?.active === true;

  const activity = await memberActivity(ctx.db, [member.id]);
  const removal = active
    ? undefined
    : activity
        .filter((row) => {
          if (row.action !== 'directory.remove') return false;
          const metadata = JSON.parse(row.metadata) as { principalType?: unknown; principalId?: unknown };
          return metadata.principalType === member.type && metadata.principalId === member.id;
        })
        .at(-1);

  const held = found?.credentials ?? [];
  const issued = all
    .filter((row) => row.active)
    .flatMap((row) => row.credentials.map((credential) => ({ service: row.id, ...credential })))
    .filter((credential) => credential.kind === 'service' && credential.createdBy === member.id)
    .sort((a, b) => compare(a.service, b.service) || a.createdAt.getTime() - b.createdAt.getTime());

  const { exposed, rotated } = exposure([member], activity).get(formatMember(member))!;
  return {
    principalType: member.type,
    principalId: member.id,
    status: active ? 'active' : 'removed',
    instanceRole: isRootAdmin ? 'root-admin' : ((found?.instanceRole ?? 'user') as 'user' | 'owner'),
    isRootAdmin,
    removedAt: removal?.occurredAt ?? null,
    removedBy: removal?.actorId ?? null,
    live: {
      grants: (found?.grants ?? []).filter(isLive(now)).length,
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
    conflict('root admins are managed by COFFRE_ROOT_ADMINS'),
    denied(ctx, action, 'configured_root_admin', {
      metadata: { principalType: member.type, principalId: member.id },
    }),
  );
}

/**
 * Add a member, bring back a removed one, or change whether they are an
 * owner. Adding someone who is already a member as they are changes nothing.
 */
export async function putMember(
  ctx: ApiContext,
  member: MemberRef,
  input: { owner?: boolean },
): Promise<{ member: string; instanceRole: 'user' | 'owner'; created: boolean }> {
  const instanceRole = input.owner === true ? 'owner' : 'user';
  const fields = { principalType: member.type, principalId: member.id, instanceRole };
  return audited(ctx, async (tx, log) => {
    requireOwner(ctx, 'directory.create', { metadata: fields });
    if (isConfiguredRootAdmin(member, ctx.rootAdmins)) throw rootAdminRefusal(ctx, 'directory.create', member);
    if (member.type === 'service' && instanceRole === 'owner') {
      throw new Refusal(
        conflict('service accounts cannot be instance owners'),
        denied(ctx, 'directory.create', 'service_cannot_be_owner', { metadata: fields }),
      );
    }

    const key = { principalType: member.type, principalId: member.id };
    // Locked, so a removal racing this re-add or role change waits for it.
    let [existing] = await lock(tx, principals, key);
    const createdBy = ctx.caller.principal.id;
    if (existing === undefined) {
      if ((await insertIfAbsent(tx, principals, { ...key, instanceRole, createdBy, active: true })) === 1) {
        log.push(allowed(ctx, 'directory.create', { metadata: fields }));
        return { member: formatMember(member), instanceRole, created: true };
      }
      // Someone added them a moment ago: answer as if this add came second.
      [existing] = await lock(tx, principals, key);
    }
    if (!existing.active) {
      await update(tx, principals, key, { instanceRole, active: true, createdAt: new Date(), createdBy });
    } else {
      // `owner` left out keeps the current role, as in any merge.
      const role = input.owner === undefined ? (existing.instanceRole as 'user' | 'owner') : instanceRole;
      if (role !== existing.instanceRole) {
        await update(tx, principals, key, { instanceRole: role });
        log.push(allowed(ctx, 'directory.update', { metadata: { ...fields, instanceRole: role } }));
      }
      return { member: formatMember(member), instanceRole: role, created: false };
    }
    log.push(allowed(ctx, 'directory.create', { metadata: fields }));
    return { member: formatMember(member), instanceRole, created: true };
  });
}

/**
 * Offboard a member: expire every grant, sign out every session, revoke
 * their tokens and sign-in accounts, and mark them removed. Re-adding them
 * later is a fresh start. Returns their report, which is what to rotate.
 */
export async function removeMember(
  ctx: ApiContext,
  member: MemberRef,
): Promise<{ revoked: { grants: number; sessions: number; tokens: number; identities: number }; report: OffboardingReport }> {
  const fields = { principalType: member.type, principalId: member.id };
  const revoked = await audited(ctx, async (tx, log) => {
    requireOwner(ctx, 'directory.remove', { metadata: fields });
    if (isConfiguredRootAdmin(member, ctx.rootAdmins)) throw rootAdminRefusal(ctx, 'directory.remove', member);

    const key = { principalType: member.type, principalId: member.id };
    // Locking the row makes a sign-in or token issue that races this wait, then see them removed.
    const [found] = await lock(tx, principals, key);
    if (found === undefined || !found.active) {
      throw new Refusal(
        notFound('no such member'),
        denied(ctx, 'directory.remove', 'unknown_principal', { metadata: fields }),
      );
    }

    const now = new Date();
    const [held] = await loadMembers(tx, { member }, now);
    const liveGrants = held.grants.filter(isLive(now));
    const liveCredentials = held.credentials;
    const liveIdentities = held.identities;

    const revokedBy = ctx.caller.principal.id;
    const ids = (rows: { id: string }[]) => rows.map((row) => row.id);
    if (liveGrants.length > 0) await update(tx, grants, { id: ids(liveGrants) }, { expiresAt: now });
    await update(tx, principals, key, { active: false });
    if (liveCredentials.length > 0) {
      await update(tx, credentials, { id: ids(liveCredentials) }, { revokedAt: now, revokedBy });
    }
    if (liveIdentities.length > 0) {
      await update(tx, identities, { id: ids(liveIdentities) }, { revokedAt: now, revokedBy });
    }

    const counts = {
      grants: liveGrants.length,
      sessions: liveCredentials.filter((row) => row.kind !== 'service').length,
      tokens: liveCredentials.filter((row) => row.kind === 'service').length,
      identities: liveIdentities.length,
    };
    const perProject = new Map<string, number>();
    for (const grant of liveGrants) {
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
