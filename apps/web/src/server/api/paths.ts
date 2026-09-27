import { and, eq, sql } from 'drizzle-orm';

import type { Queryable } from '../../../../../packages/db/src/database.ts';
import { environments, projects, secrets } from '../../../../../packages/db/src/schema.ts';
import { badRequest } from './errors.ts';

/** `market`, `market/prod` or `market/prod/DATABASE_URL`. */
export type Path = { project: string; environment?: string; key?: string };

export type ResolvedPath = {
  project: { id: string; slug: string; name: string; archived: boolean };
  environment: { id: string; slug: string; name: string; archived: boolean } | null;
  secret: { id: string; key: string; archived: boolean; currentVersionId: string | null } | null;
};

/** Split `market/prod/KEY`; the depth says what it names. */
export function parsePath(path: string, depths: readonly (1 | 2 | 3)[] = [1, 2, 3]): Path {
  const parts = path.trim().replace(/^\/+|\/+$/g, '').split('/');
  if (parts.some((part) => part === '') || !depths.includes(parts.length as 1 | 2 | 3)) {
    const shapes = { 1: 'project', 2: 'project/environment', 3: 'project/environment/KEY' };
    throw badRequest(`name a ${depths.map((depth) => shapes[depth]).join(' or ')}`);
  }
  const [project, environment, key] = parts;
  return { project, environment, key };
}

export function formatPath(path: Path): string {
  return [path.project, path.environment, path.key].filter((part) => part !== undefined).join('/');
}

const none = sql`1 = 0`;

/**
 * A path's project, environment and secret, each with its archived flag, in
 * one join. Null when the project does not exist; a missing environment or
 * secret comes back as null in its place.
 */
export async function resolvePath(db: Queryable, path: Path): Promise<ResolvedPath | null> {
  const [row] = await db
    .select({
      projectId: projects.id,
      projectSlug: projects.slug,
      projectName: projects.name,
      projectArchivedAt: projects.archivedAt,
      environmentId: environments.id,
      environmentSlug: environments.slug,
      environmentName: environments.name,
      environmentArchivedAt: environments.archivedAt,
      secretId: secrets.id,
      secretKey: secrets.key,
      secretArchivedAt: secrets.archivedAt,
      currentVersionId: secrets.currentVersionId,
    })
    .from(projects)
    .leftJoin(
      environments,
      path.environment === undefined
        ? none
        : and(eq(environments.projectId, projects.id), eq(environments.slug, path.environment)),
    )
    .leftJoin(
      secrets,
      path.key === undefined
        ? none
        : and(eq(secrets.environmentId, environments.id), eq(secrets.key, path.key)),
    )
    .where(eq(projects.slug, path.project))
    .limit(1);

  if (row === undefined) return null;
  return {
    project: {
      id: row.projectId,
      slug: row.projectSlug,
      name: row.projectName,
      archived: row.projectArchivedAt !== null,
    },
    environment:
      row.environmentId === null
        ? null
        : {
            id: row.environmentId,
            slug: row.environmentSlug!,
            name: row.environmentName!,
            archived: row.environmentArchivedAt !== null,
          },
    secret:
      row.secretId === null
        ? null
        : {
            id: row.secretId,
            key: row.secretKey!,
            archived: row.secretArchivedAt !== null,
            currentVersionId: row.currentVersionId,
          },
  };
}
