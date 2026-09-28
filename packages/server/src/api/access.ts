import { assignableToEnvironment, ROLES, type Role } from '../../../core/src/access.ts';
import { places } from '../db/queries.ts';
import type { AccessChange } from '../../../vault/src/types.ts';
import { allowed, audited, denied, need, Refusal, vaultRefusal, type ApiContext } from './context.ts';
import { badRequest, conflict, notFound } from './errors.ts';
import { formatGrantee, formatMember, formatPath, parsePath, type GranteeRef } from './paths.ts';

/** A role, a role until a date, or `null` to take access away. */
export type AccessValue = Role | { role: Role; until: string | null } | null;

export type { AccessChange };

type Wanted = {
  path: string;
  project: string;
  environment: string | undefined;
  role: Role | null;
  expiresAt: Date | null;
};

/** `2026-12-31` means the end of that day, UTC; a full timestamp means itself. */
function parseUntil(until: string, now: Date): Date {
  const date = /^\d{4}-\d{2}-\d{2}$/.test(until) ? new Date(`${until}T23:59:59.999Z`) : new Date(until);
  if (Number.isNaN(date.getTime())) throw badRequest(`"${until}" is not a date`);
  if (date <= now) throw badRequest(`"${until}" is in the past`);
  return date;
}

/**
 * Set what one member holds, declaratively: each path names a project or an
 * environment, and says which role they should have there, or `null` for
 * none. Places left out are left alone. One vault call: all of it or none.
 *
 *   { "api": "developer", "api/prod": { "role": "viewer", "until": "2026-12-31" }, "web": null }
 *
 * Each place needs `grant.manage` on its project. A member holds at most one
 * role per place, so naming a new role replaces the old one. A sync, as
 * `sync:<id>`, holds grants the same way; taking its grant away stops it.
 *
 * The app checks first, to answer in its own words; the vault holds the
 * grants and checks again, so a bug here cannot grant what the rules forbid.
 */
export async function setAccess(
  ctx: ApiContext,
  grantee: GranteeRef,
  patch: Record<string, AccessValue>,
): Promise<{ changes: Record<string, AccessChange> }> {
  const now = new Date();
  const wanted: Wanted[] = Object.entries(patch).map(([raw, value]) => {
    const path = parsePath(raw, [1, 2]);
    const role = value === null ? null : typeof value === 'string' ? value : value.role;
    const until = value !== null && typeof value === 'object' ? value.until : null;
    return {
      path: formatPath(path),
      project: path.project,
      environment: path.environment,
      role,
      expiresAt: until === null ? null : parseUntil(until, now),
    };
  });
  if (new Set(wanted.map((want) => want.path)).size !== wanted.length) {
    throw badRequest('name each place once');
  }
  if (wanted.length === 0) return { changes: {} };

  const principal = formatGrantee(grantee);
  return audited(ctx, async (tx, log) => {
    const known = await places(tx);
    const located = wanted.map((want) => {
      const project = known.find((place) => place.slug === want.project);
      if (project === undefined) throw notFound(`no project "${want.project}"`);
      if (want.environment === undefined) return { ...want, projectId: project.id, environmentId: null };
      const environment = project.environments.find((place) => place.slug === want.environment);
      if (environment === undefined) throw notFound(`no environment "${want.path}"`);
      return { ...want, projectId: project.id, environmentId: environment.id };
    });

    const subject = { principalType: grantee.type, principalId: grantee.id };
    const scoped = (want: (typeof located)[number]) => ({
      projectId: want.projectId,
      environmentId: want.environmentId,
    });
    for (const want of located) {
      need(ctx, 'grant.manage', { projectId: want.projectId }, want.role === null ? 'grant.revoke' : 'grant.create', {
        ...scoped(want),
        metadata: { ...subject, role: want.role },
      });
    }

    const standing = await ctx.vault.access(principal);
    const refuse = (want: (typeof located)[number], message: string, reason: string) =>
      new Refusal(
        conflict(message),
        denied(ctx, 'grant.create', reason, { ...scoped(want), metadata: { ...subject, role: want.role } }),
      );
    for (const want of located) {
      if (want.role === null) continue;
      // A sync becomes a member with its first grant; anyone else is added first.
      if (standing.status === 'unknown' && grantee.type !== 'sync') {
        throw refuse(want, 'add them as a member before granting access', 'principal_not_registered');
      }
      if (standing.status === 'removed') {
        throw refuse(want, 'they were removed; add them as a member again before granting access', 'principal_inactive');
      }
      if (want.environmentId !== null && !assignableToEnvironment(want.role)) {
        throw refuse(
          want,
          `${want.role} includes permissions that only make sense on a whole project; grant it on "${want.project}"`,
          'role_is_project_scoped',
        );
      }
    }

    const result = await ctx.vault.setAccess({
      actor: formatMember(ctx.caller.principal),
      principal,
      requestId: ctx.requestId,
      changes: located.map((want) => ({
        ...scoped(want),
        role: want.role,
        expiresAt: want.expiresAt?.toISOString() ?? null,
      })),
    });
    if (!result.ok) {
      const granting = located.some((want) => want.role !== null);
      throw vaultRefusal(ctx, result.refusal, granting ? 'grant.create' : 'grant.revoke', { metadata: subject });
    }

    const changes: Record<string, AccessChange> = {};
    for (const [i, want] of located.entries()) {
      const change = result.changes[i];
      changes[want.path] = change;
      if (change === 'unchanged') continue;
      const before = standing.grants.find(
        (grant) => grant.projectId === want.projectId && grant.environmentId === want.environmentId,
      );
      const action = { created: 'grant.create', updated: 'grant.update', revoked: 'grant.revoke' }[change];
      const grant =
        want.role === null
          ? { role: before?.role ?? null }
          : { role: want.role, roleName: ROLES[want.role].name, expiresAt: want.expiresAt?.toISOString() ?? null };
      log.push(allowed(ctx, action, {
        ...scoped(want),
        metadata: { ...subject, ...(change === 'updated' ? { from: before?.role ?? null } : {}), ...grant },
      }));
    }
    return { changes };
  });
}
