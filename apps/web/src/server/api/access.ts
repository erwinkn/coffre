import { randomUUID } from 'node:crypto';

import { and, eq, inArray, isNull, or } from 'drizzle-orm';

import { assignableToEnvironment, ROLES, type Role } from '../../../../../packages/core/src/access.ts';
import type { AuditEntry } from '../../../../../packages/db/src/audit.ts';
import { forUpdate } from '../../../../../packages/db/src/dialect.ts';
import { environments, grants, principals, projects } from '../../../../../packages/db/src/schema.ts';
import { allowed, audited, denied, need, Refusal, type ApiContext } from './context.ts';
import { badRequest, conflict, notFound } from './errors.ts';
import { formatPath, parsePath, type MemberRef } from './paths.ts';

/** A role, a role until a date, or `null` to take access away. */
export type AccessValue = Role | { role: Role; until: string | null } | null;

export type AccessChange = 'created' | 'updated' | 'revoked' | 'unchanged';

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
 * none. Places left out are left alone. One transaction: all of it or none.
 *
 *   { "api": "developer", "api/prod": { "role": "viewer", "until": "2026-12-31" }, "web": null }
 *
 * Each place needs `grant.manage` on its project. A member holds at most one
 * role per place, so naming a new role replaces the old one.
 */
export async function setAccess(
  ctx: ApiContext,
  member: MemberRef,
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

  return audited(ctx, async (tx, log) => {
    // Every named place, in one query.
    const places = await tx
      .select({ projectId: projects.id, project: projects.slug, environmentId: environments.id, environment: environments.slug })
      .from(projects)
      .leftJoin(environments, eq(environments.projectId, projects.id))
      .where(inArray(projects.slug, [...new Set(wanted.map((want) => want.project))]));
    const located = wanted.map((want) => {
      const project = places.find((place) => place.project === want.project);
      if (project === undefined) throw notFound(`no project "${want.project}"`);
      if (want.environment === undefined) return { ...want, projectId: project.projectId, environmentId: null };
      const environment = places.find(
        (place) => place.project === want.project && place.environment === want.environment,
      );
      if (environment === undefined) throw notFound(`no environment "${want.path}"`);
      return { ...want, projectId: project.projectId, environmentId: environment.environmentId! };
    });

    const subject = { principalType: member.type, principalId: member.id };
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

    // Lock the member, so a removal racing this cannot leave a grant behind.
    const [principal] = await forUpdate(
      tx
        .select({ active: principals.active })
        .from(principals)
        .where(and(eq(principals.principalType, member.type), eq(principals.principalId, member.id))),
    );
    const refuse = (want: (typeof located)[number], message: string, reason: string) =>
      new Refusal(
        conflict(message),
        denied(ctx, 'grant.create', reason, { ...scoped(want), metadata: { ...subject, role: want.role } }),
      );
    for (const want of located) {
      if (want.role === null) continue;
      if (principal === undefined) {
        throw refuse(want, 'add them as a member before granting access', 'principal_not_registered');
      }
      if (!principal.active) {
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

    const projectIds = located.filter((want) => want.environmentId === null).map((want) => want.projectId);
    const environmentIds = located.flatMap((want) => want.environmentId ?? []);
    const existing = await forUpdate(
      tx
        .select({
          id: grants.id,
          projectId: grants.projectId,
          environmentId: grants.environmentId,
          role: grants.role,
          expiresAt: grants.expiresAt,
        })
        .from(grants)
        .where(
          and(
            eq(grants.principalType, member.type),
            eq(grants.principalId, member.id),
            or(
              ...(projectIds.length > 0 ? [and(inArray(grants.projectId, projectIds), isNull(grants.environmentId))] : []),
              ...(environmentIds.length > 0 ? [inArray(grants.environmentId, environmentIds)] : []),
            ),
          ),
        ),
    );

    const changes: Record<string, AccessChange> = {};
    const createdBy = ctx.caller.principal.id;
    for (const want of located) {
      const row = existing.find((grant) =>
        want.environmentId === null
          ? grant.environmentId === null && grant.projectId === want.projectId
          : grant.environmentId === want.environmentId,
      );
      const isLive = row !== undefined && (row.expiresAt === null || row.expiresAt > now);
      const expiresAt = want.expiresAt?.toISOString() ?? null;
      const entry = (action: string, metadata: Record<string, unknown>): AuditEntry =>
        allowed(ctx, action, { ...scoped(want), metadata: { ...subject, ...metadata } });

      if (want.role === null) {
        if (!isLive) {
          changes[want.path] = 'unchanged';
          continue;
        }
        await tx.update(grants).set({ expiresAt: now }).where(eq(grants.id, row.id));
        log.push(entry('grant.revoke', { grantId: row.id, role: row.role }));
        changes[want.path] = 'revoked';
        continue;
      }

      const grant = { role: want.role, roleName: ROLES[want.role].name, expiresAt };
      if (row === undefined) {
        const id = randomUUID();
        await tx.insert(grants).values({
          id,
          principalType: member.type,
          principalId: member.id,
          projectId: want.environmentId === null ? want.projectId : null,
          environmentId: want.environmentId,
          role: want.role,
          expiresAt: want.expiresAt,
          createdBy,
        });
        log.push(entry('grant.create', { grantId: id, ...grant }));
        changes[want.path] = 'created';
      } else if (isLive && row.role === want.role && row.expiresAt?.getTime() === want.expiresAt?.getTime()) {
        changes[want.path] = 'unchanged';
      } else if (isLive) {
        await tx.update(grants).set({ role: want.role, expiresAt: want.expiresAt }).where(eq(grants.id, row.id));
        log.push(entry('grant.update', { grantId: row.id, from: row.role, ...grant }));
        changes[want.path] = 'updated';
      } else {
        // An expired grant is the same place's row: bring it back as a new grant.
        // The runtime role may not rewrite created_at; the log has when it came back.
        await tx
          .update(grants)
          .set({ role: want.role, expiresAt: want.expiresAt, createdBy })
          .where(eq(grants.id, row.id));
        log.push(entry('grant.create', { grantId: row.id, ...grant }));
        changes[want.path] = 'created';
      }
    }
    return { changes };
  });
}
