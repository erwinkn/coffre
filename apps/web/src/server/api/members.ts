import { and, asc, count, desc, eq, gt, inArray, isNull, like, or } from 'drizzle-orm';

import { ROLES, type Permission, type Role } from '../../../../../packages/core/src/access.ts';
import type { Queryable } from '../../../../../packages/db/src/database.ts';
import { canonicalTimestamp } from '../../../../../packages/db/src/audit.ts';
import { forUpdate } from '../../../../../packages/db/src/dialect.ts';
import {
  auditLog,
  credentials,
  environments,
  grants,
  identities,
  principals,
  projects,
  secrets,
  secretVersions,
} from '../../../../../packages/db/src/schema.ts';
import { can, isConfiguredRootAdmin } from './caller.ts';
import { allowed, audited, denied, Refusal, requireOwner, type ApiContext } from './context.ts';
import { conflict, forbidden, notFound } from './errors.ts';
import { formatMember, type MemberRef, type Path } from './paths.ts';

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
};

/** Someone no longer a member, and how many of their report's values are left. */
export type RemovedMember = {
  principalType: 'user' | 'service';
  principalId: string;
  /** The length of their report's `exposed`. */
  toRotate: number;
};

const live = (now: Date) => or(isNull(grants.expiresAt), gt(grants.expiresAt, now));

/** Rows of `table` that belong to `member`. */
const heldBy = (table: typeof grants | typeof credentials | typeof identities, member: MemberRef) =>
  and(eq(table.principalType, member.type), eq(table.principalId, member.id));

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
  const now = new Date();
  const rows = await ctx.db
    .select({
      principalType: principals.principalType,
      principalId: principals.principalId,
      instanceRole: principals.instanceRole,
      grantId: grants.id,
      role: grants.role,
      expiresAt: grants.expiresAt,
      projectId: projects.id,
      project: projects.slug,
      environment: environments.slug,
    })
    .from(principals)
    .leftJoin(
      grants,
      and(
        eq(grants.principalType, principals.principalType),
        eq(grants.principalId, principals.principalId),
        live(now),
      ),
    )
    .leftJoin(environments, eq(environments.id, grants.environmentId))
    .leftJoin(projects, or(eq(projects.id, grants.projectId), eq(projects.id, environments.projectId)))
    .where(eq(principals.active, true))
    .orderBy(asc(principals.principalType), asc(principals.principalId), asc(projects.slug), asc(environments.slug));

  const manages = (projectId: string) => can(caller, 'grant.manage', { projectId });
  if (!caller.isOwner && !caller.grants.some((grant) => manages(grant.projectId))) {
    throw forbidden('only owners, and members with grant.manage on a project, can list members');
  }
  const inPath = (row: (typeof rows)[number]) =>
    query.path === undefined ||
    (row.project === query.path.project &&
      (query.path.environment === undefined || row.environment === query.path.environment));

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
  if (caller.isOwner && query.path === undefined) {
    for (const id of ctx.rootAdmins) entry('user', id, 'user');
  }
  for (const row of rows) {
    const type = row.principalType as 'user' | 'service';
    const hasGrant = row.grantId !== null && row.projectId !== null;
    const visible = hasGrant && (caller.isOwner || manages(row.projectId!)) && inPath(row);
    if (visible) {
      const role = row.role as Role;
      entry(type, row.principalId, row.instanceRole).grants.push({
        id: row.grantId!,
        project: row.project!,
        environment: row.environment,
        role,
        roleName: ROLES[role].name,
        permissions: [...ROLES[role].permissions],
        expiresAt: row.expiresAt?.toISOString() ?? null,
      });
    } else if (caller.isOwner && query.path === undefined) {
      entry(type, row.principalId, row.instanceRole);
    }
  }

  const members = [...byMember.values()].sort(
    (a, b) => a.principalType.localeCompare(b.principalType) || a.principalId.localeCompare(b.principalId),
  );
  const removed = caller.isOwner && query.path === undefined ? await listRemoved(ctx) : [];
  return { members, removed };
}

type Seen = { secretId: string; version: number; wrote: boolean; at: string };

/**
 * Everything these members read or wrote, and each live secret's current
 * version: a value they saw that is still current is one to rotate.
 */
async function exposure(
  db: Queryable,
  members: MemberRef[],
): Promise<Map<string, { exposed: ExposedSecret[]; rotated: number }>> {
  const result = new Map(members.map((member) => [formatMember(member), { exposed: [] as ExposedSecret[], rotated: 0 }]));
  if (members.length === 0) return result;

  const rows = await db
    .select({
      actorType: auditLog.actorType,
      actorId: auditLog.actorId,
      action: auditLog.action,
      secretId: auditLog.secretId,
      metadata: auditLog.metadata,
      occurredAt: auditLog.occurredAt,
    })
    .from(auditLog)
    .where(
      and(
        inArray(auditLog.actorId, members.map((member) => member.id)),
        eq(auditLog.decision, 'allow'),
        inArray(auditLog.action, ['secret.read', 'secret.write', 'secret.import']),
      ),
    )
    .orderBy(asc(auditLog.seq));

  // Per member, per secret, per version: whether they wrote it, and when they last saw it.
  const seen = new Map<string, Map<string, Map<number, Seen>>>();
  for (const row of rows) {
    const key = formatMember({ type: row.actorType as 'user' | 'service', id: row.actorId });
    if (row.secretId === null || !result.has(key)) continue;
    const version = (JSON.parse(row.metadata) as { version?: unknown }).version;
    if (typeof version !== 'number') continue;
    const bySecret = seen.get(key) ?? new Map<string, Map<number, Seen>>();
    seen.set(key, bySecret);
    const byVersion = bySecret.get(row.secretId) ?? new Map<number, Seen>();
    bySecret.set(row.secretId, byVersion);
    const previous = byVersion.get(version);
    byVersion.set(version, {
      secretId: row.secretId,
      version,
      wrote: (previous?.wrote ?? false) || row.action !== 'secret.read',
      at: canonicalTimestamp(row.occurredAt),
    });
  }

  const touched = [...new Set([...seen.values()].flatMap((bySecret) => [...bySecret.keys()]))];
  if (touched.length === 0) return result;
  const current = await db
    .select({
      secretId: secrets.id,
      key: secrets.key,
      version: secretVersions.version,
      project: projects.slug,
      environment: environments.slug,
    })
    .from(secrets)
    .innerJoin(environments, and(eq(environments.id, secrets.environmentId), isNull(environments.archivedAt)))
    .innerJoin(projects, and(eq(projects.id, secrets.projectId), isNull(projects.archivedAt)))
    .innerJoin(secretVersions, eq(secretVersions.id, secrets.currentVersionId))
    .where(and(inArray(secrets.id, touched), isNull(secrets.archivedAt)))
    .orderBy(asc(projects.slug), asc(environments.slug), asc(secrets.key));

  for (const [key, bySecret] of seen) {
    const report = result.get(key)!;
    for (const secret of current) {
      const byVersion = bySecret.get(secret.secretId);
      if (byVersion === undefined) continue;
      const hit = byVersion.get(secret.version);
      if (hit === undefined) {
        report.rotated += 1;
        continue;
      }
      report.exposed.push({
        project: secret.project,
        environment: secret.environment,
        key: secret.key,
        version: secret.version,
        how: hit.wrote ? 'wrote' : 'read',
        at: hit.at,
      });
    }
  }
  return result;
}

/**
 * Everyone removed, so their reports stay reachable: removal ends access,
 * not the work of rotating what they saw.
 */
async function listRemoved(ctx: ApiContext): Promise<RemovedMember[]> {
  const rows = await ctx.db
    .select({ principalType: principals.principalType, principalId: principals.principalId })
    .from(principals)
    .where(eq(principals.active, false))
    .orderBy(asc(principals.principalType), asc(principals.principalId));
  const removed = rows
    .map((row) => ({ type: row.principalType as 'user' | 'service', id: row.principalId }))
    .filter((member) => !isConfiguredRootAdmin(member, ctx.rootAdmins));
  const exposed = await exposure(ctx.db, removed);
  return removed.map((member) => ({
    principalType: member.type,
    principalId: member.id,
    toRotate: exposed.get(formatMember(member))!.exposed.length,
  }));
}

/**
 * Who someone is to this instance and what to rotate if they leave. Owners
 * only. Works for removed members too: that is when it matters most.
 */
export async function memberReport(ctx: ApiContext, member: MemberRef): Promise<OffboardingReport> {
  if (!ctx.caller.isOwner) throw forbidden('only owners may see what someone has access to');
  const isRootAdmin = isConfiguredRootAdmin(member, ctx.rootAdmins);
  const where = and(eq(principals.principalType, member.type), eq(principals.principalId, member.id));
  const [found] = await ctx.db
    .select({ instanceRole: principals.instanceRole, active: principals.active })
    .from(principals)
    .where(where);
  if (found === undefined && !isRootAdmin) throw notFound('no such member');
  const active = isRootAdmin || found?.active === true;
  const now = new Date();

  // The newest removal. Removals are rare, and the id narrows them further;
  // the metadata is checked exactly below.
  const removal = active
    ? undefined
    : (
        await ctx.db
          .select({ occurredAt: auditLog.occurredAt, actorId: auditLog.actorId, metadata: auditLog.metadata })
          .from(auditLog)
          .where(
            and(
              eq(auditLog.action, 'directory.remove'),
              eq(auditLog.decision, 'allow'),
              isNull(auditLog.projectId),
              like(auditLog.metadata, `%${JSON.stringify(member.id).slice(1, -1)}%`),
            ),
          )
          .orderBy(desc(auditLog.seq))
      ).find((row) => {
        const metadata = JSON.parse(row.metadata) as { principalType?: unknown; principalId?: unknown };
        return metadata.principalType === member.type && metadata.principalId === member.id;
      });

  const [liveGrants] = await ctx.db
    .select({ n: count() })
    .from(grants)
    .where(and(heldBy(grants, member), live(now)));
  const liveCredentials = await ctx.db
    .select({ kind: credentials.kind, n: count() })
    .from(credentials)
    .where(and(heldBy(credentials, member), isNull(credentials.revokedAt), gt(credentials.expiresAt, now)))
    .groupBy(credentials.kind);
  const [liveIdentities] = await ctx.db
    .select({ n: count() })
    .from(identities)
    .where(and(heldBy(identities, member), isNull(identities.revokedAt)));

  const issued = await ctx.db
    .select({
      id: credentials.id,
      service: credentials.principalId,
      label: credentials.label,
      hint: credentials.tokenHint,
      expiresAt: credentials.expiresAt,
      lastUsedAt: credentials.lastUsedAt,
    })
    .from(credentials)
    .innerJoin(
      principals,
      and(
        eq(principals.principalType, credentials.principalType),
        eq(principals.principalId, credentials.principalId),
        eq(principals.active, true),
      ),
    )
    .where(
      and(
        eq(credentials.kind, 'service'),
        eq(credentials.createdBy, member.id),
        isNull(credentials.revokedAt),
        gt(credentials.expiresAt, now),
      ),
    )
    .orderBy(asc(credentials.principalId), asc(credentials.createdAt));

  const { exposed, rotated } = (await exposure(ctx.db, [member])).get(formatMember(member))!;
  const sessions = liveCredentials.filter((row) => row.kind !== 'service').reduce((sum, row) => sum + row.n, 0);
  return {
    principalType: member.type,
    principalId: member.id,
    status: active ? 'active' : 'removed',
    instanceRole: isRootAdmin ? 'root-admin' : ((found?.instanceRole ?? 'user') as 'user' | 'owner'),
    isRootAdmin,
    removedAt: removal ? canonicalTimestamp(removal.occurredAt) : null,
    removedBy: removal?.actorId ?? null,
    live: {
      grants: liveGrants.n,
      sessions,
      tokens: liveCredentials.find((row) => row.kind === 'service')?.n ?? 0,
      identities: liveIdentities.n,
    },
    exposed,
    rotated,
    issuedTokens: issued.map((token) => ({
      ...token,
      expiresAt: token.expiresAt.toISOString(),
      lastUsedAt: token.lastUsedAt?.toISOString() ?? null,
    })),
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

    const where = and(eq(principals.principalType, member.type), eq(principals.principalId, member.id));
    const [existing] = await forUpdate(
      tx.select({ active: principals.active, instanceRole: principals.instanceRole }).from(principals).where(where),
    );
    const createdBy = ctx.caller.principal.id;
    if (existing === undefined) {
      await tx.insert(principals).values({
        principalType: member.type,
        principalId: member.id,
        instanceRole,
        createdBy,
        active: true,
      });
    } else if (!existing.active) {
      await tx.update(principals).set({ instanceRole, active: true, createdAt: new Date(), createdBy }).where(where);
    } else {
      // `owner` left out keeps the current role, as in any merge.
      const role = input.owner === undefined ? (existing.instanceRole as 'user' | 'owner') : instanceRole;
      if (role !== existing.instanceRole) {
        await tx.update(principals).set({ instanceRole: role }).where(where);
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

    const where = and(eq(principals.principalType, member.type), eq(principals.principalId, member.id));
    // Locking the row makes a sign-in or token issue that races this wait, then see them removed.
    const [found] = await forUpdate(tx.select({ active: principals.active }).from(principals).where(where));
    if (found === undefined || !found.active) {
      throw new Refusal(
        notFound('no such member'),
        denied(ctx, 'directory.remove', 'unknown_principal', { metadata: fields }),
      );
    }

    const now = new Date();
    const liveGrants = await tx
      .select({ id: grants.id, projectId: grants.projectId, environmentProjectId: environments.projectId })
      .from(grants)
      .leftJoin(environments, eq(environments.id, grants.environmentId))
      .where(and(heldBy(grants, member), live(now)));
    const liveCredentials = await tx
      .select({ id: credentials.id, kind: credentials.kind })
      .from(credentials)
      .where(and(heldBy(credentials, member), isNull(credentials.revokedAt), gt(credentials.expiresAt, now)));
    const liveIdentities = await tx
      .select({ id: identities.id })
      .from(identities)
      .where(and(heldBy(identities, member), isNull(identities.revokedAt)));

    const revokedBy = ctx.caller.principal.id;
    if (liveGrants.length > 0) {
      await tx.update(grants).set({ expiresAt: now }).where(inArray(grants.id, liveGrants.map((row) => row.id)));
    }
    await tx.update(principals).set({ active: false }).where(where);
    if (liveCredentials.length > 0) {
      await tx
        .update(credentials)
        .set({ revokedAt: now, revokedBy })
        .where(inArray(credentials.id, liveCredentials.map((row) => row.id)));
    }
    if (liveIdentities.length > 0) {
      await tx
        .update(identities)
        .set({ revokedAt: now, revokedBy })
        .where(inArray(identities.id, liveIdentities.map((row) => row.id)));
    }

    const counts = {
      grants: liveGrants.length,
      sessions: liveCredentials.filter((row) => row.kind !== 'service').length,
      tokens: liveCredentials.filter((row) => row.kind === 'service').length,
      identities: liveIdentities.length,
    };
    const perProject = new Map<string, number>();
    for (const grant of liveGrants) {
      const projectId = grant.projectId ?? grant.environmentProjectId!;
      perProject.set(projectId, (perProject.get(projectId) ?? 0) + 1);
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
