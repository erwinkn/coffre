import { randomUUID } from 'node:crypto';

import { ROLES, type Permission, type Role } from '@coffre/core/access';
import type { Queryable } from '@coffre/db';
import { credentials, identities } from '@coffre/db/schema';

import { actorParts } from '../db/audit.ts';
import {
  revokePriorMembership,
  memberActivity,
  members as loadMembers,
  memberStanding,
  places,
  updateAuth,
  type MemberRow,
  type StoredGrant,
} from '../db/queries.ts';
import { can } from './caller.ts';
import { audited, denied, Refusal, requireOwner, withRefusals, type ApiContext } from './context.ts';
import { conflict, forbidden, notFound, vaultRefused } from './errors.ts';
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

/** A stored grant, placed by slug. */
type PlacedGrant = { project: string; environment: string | null; projectId: string; role: Role; expiresAt: string | null };

/** The slugs of every project and environment, by id: grants name places only by id. */
async function slugs(db: Queryable): Promise<Map<string, string>> {
  return new Map(
    (await places(db)).flatMap((project) => [
      [project.id, project.slug] as const,
      ...project.environments.map((environment) => [environment.id, environment.slug] as const),
    ]),
  );
}

function placed(grants: StoredGrant[], names: Map<string, string>): PlacedGrant[] {
  return grants.flatMap((grant) => {
    const project = names.get(grant.projectId);
    const environment = grant.environmentId === null ? null : names.get(grant.environmentId);
    // A grant on a place that is gone names nothing anyone can reach.
    if (project === undefined || environment === undefined) return [];
    return [{
      project,
      environment,
      projectId: grant.projectId,
      role: grant.role as Role,
      expiresAt: grant.expiresAt === null ? null : new Date(grant.expiresAt).toISOString(),
    }];
  });
}

/** Someone in the directory, as the rows and the vault's findings say. */
type Listed = {
  member: MemberRef;
  /** Null for a root admin the vault has not met yet: it makes their row on first use. */
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
  const [rows, { rootAdmins }] = await Promise.all([
    loadMembers(ctx.db, ctx.chainKey, member === undefined ? {} : { member }, now),
    ctx.vault.about(),
  ]);
  const byPrincipal = new Map(rows.map((row) => [formatMember(row), row]));
  const roots = new Set(rootAdmins);
  const wanted = member === undefined ? null : formatMember(member);
  const principals = new Set([...byPrincipal.keys(), ...rootAdmins.filter((root) => wanted === null || root === wanted)]);
  return [...principals].sort().map((principal) => {
    const row = byPrincipal.get(principal) ?? null;
    const isRootAdmin = roots.has(principal);
    const status = isRootAdmin ? 'active' : row!.tampered ? 'tampered' : row!.status;
    return { member: parseGrantee(principal) as MemberRef, row, isRootAdmin, status, grants: status === 'active' ? row?.grants ?? [] : [] };
  });
}

function instanceRole(listed: Listed): Member['instanceRole'] {
  return listed.isRootAdmin ? 'root-admin' : listed.row?.owner === true && listed.status === 'active' ? 'owner' : 'user';
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

  const [all, names] = await Promise.all([directory(ctx, new Date()), slugs(ctx.db)]);
  const members: Member[] = [];
  for (const listed of all) {
    if (listed.status === 'removed') continue;
    const visible = placed(listed.grants, names)
      .filter((grant) => (caller.isOwner || manages(grant.projectId)) && inPath(grant))
      .sort(byPlace);
    if (!everyone && visible.length === 0) continue;
    const ref = listed.member;
    const member = formatMember(ref);
    members.push({
      member,
      principalType: ref.type,
      principalId: ref.id,
      instanceRole: instanceRole(listed),
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
  if (!everyone) return { members, removed: [] };

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
 * Who someone is to this instance and what to rotate if they leave. Owners
 * only. Works for removed members too: that is when it matters most.
 */
export async function memberReport(ctx: ApiContext, member: MemberRef): Promise<OffboardingReport> {
  if (!ctx.caller.isOwner) throw forbidden('only owners may see what someone has access to');
  // Everyone, not just them: the service tokens they issued belong to others.
  const everyone = await directory(ctx, new Date());
  const listed = everyone.find((entry) => formatMember(entry.member) === formatMember(member));
  if (listed === undefined) throw notFound('no such member');
  const { row, status } = listed;
  const active = status === 'active';

  const held = row?.credentials ?? [];
  const issued = everyone
    .filter((entry) => entry.status === 'active')
    .flatMap((entry) => (entry.row?.credentials ?? []).map((credential) => ({ service: entry.member.id, ...credential })))
    .filter((credential) => credential.kind === 'service' && credential.createdBy === member.id)
    .sort((a, b) => compare(a.service, b.service) || a.createdAt.getTime() - b.createdAt.getTime());

  const activity = await memberActivity(ctx.db, [member.id]);
  const { exposed, rotated } = exposure([member], activity).get(formatMember(member))!;
  return {
    principalType: member.type,
    principalId: member.id,
    status,
    instanceRole: instanceRole(listed),
    isRootAdmin: listed.isRootAdmin,
    // When and by whom, as the vault wrote it: the removal is its decision.
    removedAt: status === 'removed' ? row!.statusChangedAt.toISOString() : null,
    removedBy: status === 'removed' ? parseGrantee(row!.statusChangedBy).id : null,
    live: {
      grants: listed.grants.length,
      sessions: held.filter((credential) => credential.kind !== 'service').length,
      tokens: held.filter((credential) => credential.kind === 'service').length,
      identities: row?.identities.length ?? 0,
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
 * The vault decides and keeps who is in, in the member row their sessions
 * and tokens hang off.
 */
export async function putMember(
  ctx: ApiContext,
  member: MemberRef,
  input: { owner?: boolean },
): Promise<{ member: string; instanceRole: 'user' | 'owner'; created: boolean }> {
  const principal = formatMember(member);
  const fields = { principalType: member.type, principalId: member.id, instanceRole: input.owner === true ? 'owner' : 'user' };
  return withRefusals(ctx, async () => {
    requireOwner(ctx, 'member.add', { metadata: fields });
    if ((await ctx.vault.about()).rootAdmins.includes(principal)) throw rootAdminRefusal(ctx, 'member.add', member);
    if (member.type === 'service' && input.owner === true) {
      throw new Refusal(
        conflict('service accounts cannot be instance owners'),
        denied(ctx, 'member.add', 'service_cannot_be_owner', { metadata: fields }),
      );
    }

    // The vault logs the change, as `member.add`, `member.restore` or `member.owner`.
    const result = await ctx.vault.admit({
      actor: formatMember(ctx.caller.principal),
      principal,
      owner: input.owner,
      requestId: ctx.requestId,
      operationId: randomUUID(),
    });
    if (!result.ok) throw vaultRefused(result.refusal);
    // Housekeeping: rows of an earlier membership are dead already, by their generation.
    await audited(ctx, (tx) => revokePriorMembership(tx, ctx.chainKey, member, result.generation, ctx.caller.principal.id));
    return { member: principal, instanceRole: result.owner ? 'owner' : 'user', created: result.created };
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
  const revoked = await withRefusals(ctx, async () => {
    requireOwner(ctx, 'member.remove', { metadata: fields });
    if ((await ctx.vault.about()).rootAdmins.includes(principal)) throw rootAdminRefusal(ctx, 'member.remove', member);
    // As the row says: a member whose record failed the vault's check is removed to start them over.
    if ((await memberStanding(ctx.db, principal))?.status !== 'active') {
      throw new Refusal(
        notFound('no such member'),
        denied(ctx, 'member.remove', 'unknown_principal', { metadata: fields }),
      );
    }

    // The vault logs the removal, and one `access.revoke` per grant it took, so each project's log shows it.
    const result = await ctx.vault.remove({
      actor: formatMember(ctx.caller.principal),
      principal,
      requestId: ctx.requestId,
      operationId: randomUUID(),
    });
    if (!result.ok) throw vaultRefused(result.refusal);
    const { generation } = result;
    return audited(ctx, async (tx) => {
      const now = new Date();
      const [held] = await loadMembers(tx, ctx.chainKey, { member }, now);
      const liveCredentials = (held?.credentials ?? []).filter((row) => row.generation < generation);
      const liveIdentities = (held?.identities ?? []).filter((row) => row.generation < generation);
      const revokedBy = ctx.caller.principal.id;
      const ids = (rows: { id: string }[]) => rows.map((row) => row.id);
      if (liveCredentials.length > 0) {
        await updateAuth(tx, ctx.chainKey, credentials, { id: ids(liveCredentials) }, { revokedAt: now, revokedBy });
      }
      if (liveIdentities.length > 0) {
        await updateAuth(tx, ctx.chainKey, identities, { id: ids(liveIdentities) }, { revokedAt: now, revokedBy });
      }

      return {
        grants: result.revoked.length,
        sessions: liveCredentials.filter((row) => row.kind !== 'service').length,
        tokens: liveCredentials.filter((row) => row.kind === 'service').length,
        identities: liveIdentities.length,
      };
    });
  });
  return { revoked, report: await memberReport(ctx, member) };
}
