import { randomUUID } from 'node:crypto';

import { assignableToEnvironment, EVERY_PROJECT, type Role } from '@coffre/core/access';
import { slug } from '@coffre/core/schemas';
import { canGrantEveryProject } from '@coffre/db/grants';
import type { AccessChange } from '@coffre/core/vault';

import { memberStanding, places } from '../db/queries.ts';
import { denied, need, Refusal, requireOwner, withRefusals, type ApiContext } from './context.ts';
import { ApiError, badRequest, conflict, notFound, vaultRefused } from './errors.ts';
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
 * environment, or every project (`*`) or one environment slug in every
 * project (`*` and the slug), and says which role they should have there, or
 * `null` for none. Places left out are left alone. One vault call: all of it
 * or none.
 *
 *   { "api": "developer", "api/prod": { "role": "viewer", "until": "2026-12-31" }, "web": null, "*": "viewer" }
 *
 * Each place needs `grant.manage` on its project; every project, an instance
 * owner. A member holds at most one role per place, so naming a new role
 * replaces the old one.
 *
 * The app checks first, to answer in its own words; the vault holds the
 * grants and checks again, so a bug here cannot grant what the rules forbid.
 * The vault logs each change it makes, as `access.grant` or `access.revoke`,
 * and what it refuses; the app logs only what it refused itself.
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
  return withRefusals(ctx, async () => {
    const known = await places(ctx.db);
    const located = wanted.map((want) => {
      if (want.project === EVERY_PROJECT) {
        if (want.environment !== undefined && !slug.safeParse(want.environment).success) {
          throw badRequest(`"${want.environment}" is not an environment slug`);
        }
        return { ...want, projectId: null, environmentId: null, environmentSlug: want.environment ?? null };
      }
      const project = known.find((place) => place.slug === want.project);
      if (project === undefined) throw notFound(`no project "${want.project}"`);
      if (want.environment === undefined) return { ...want, projectId: project.id, environmentId: null, environmentSlug: null };
      const environment = project.environments.find((place) => place.slug === want.environment);
      if (environment === undefined) throw notFound(`no environment "${want.path}"`);
      return { ...want, projectId: project.id, environmentId: environment.id, environmentSlug: null };
    });

    const subject = { principalType: grantee.type, principalId: grantee.id };
    // Every project is no place a log entry can name by id: its path says it.
    const scoped = (want: (typeof located)[number]) =>
      want.projectId === null
        ? { metadata: { ...subject, role: want.role, place: want.path } }
        : { projectId: want.projectId, environmentId: want.environmentId, metadata: { ...subject, role: want.role } };
    for (const want of located) {
      const action = want.role === null ? 'access.revoke' : 'access.grant';
      if (want.projectId === null) requireOwner(ctx, action, scoped(want));
      else need(ctx, 'grant.manage', { projectId: want.projectId }, action, scoped(want));
    }
    if (located.some((want) => want.projectId === null) && !(await canGrantEveryProject(ctx.db))) {
      throw new ApiError('unavailable', "grants on every project need this release's database migration: an owner runs `coffre migrate`");
    }

    // As the row says, to answer in the app's words; the vault decides.
    const standing = await memberStanding(ctx.db, principal);
    const refuse = (want: (typeof located)[number], message: string, reason: string) =>
      new Refusal(conflict(message), denied(ctx, 'access.grant', reason, scoped(want)));
    for (const want of located) {
      if (want.role === null) continue;
      // Members are admitted before they can be granted access.
      if (standing === null) {
        throw refuse(want, 'add them as a member before granting access', 'principal_not_registered');
      }
      if (standing?.status === 'removed') {
        throw refuse(want, 'they were removed; add them as a member again before granting access', 'principal_inactive');
      }
      if ((want.environmentId !== null || want.environmentSlug !== null) && !assignableToEnvironment(want.role)) {
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
      operationId: randomUUID(),
      credentialId: ctx.provenance,
      changes: located.map((want) => ({
        projectId: want.projectId,
        environmentId: want.environmentId,
        environmentSlug: want.environmentSlug,
        role: want.role,
        expiresAt: want.expiresAt?.toISOString() ?? null,
      })),
    });
    if (!result.ok) throw vaultRefused(result.refusal);
    const changes: Record<string, AccessChange> = {};
    for (const [i, want] of located.entries()) changes[want.path] = result.changes[i];
    return { changes };
  });
}
