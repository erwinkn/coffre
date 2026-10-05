import { and, eq, gt, isNull, or } from 'drizzle-orm';

import { tablesOf, type Queryable } from './database.ts';

/**
 * One grant, as `vault_grants` holds it: on a project (`environmentId`
 * null), one of its environments (`projectId` is the environment's
 * project), every project (both ids null), or one environment slug in every
 * project (`environmentSlug`). Only the vault writes grants; the app reads
 * them for its lists.
 */
export type GrantRow = {
  principal: string;
  projectId: string | null;
  environmentId: string | null;
  environmentSlug: string | null;
  role: string;
  /** Milliseconds since the epoch, or null for no end. */
  expiresAt: number | null;
  grantedAt: number;
  grantedBy: string;
};

/**
 * Grants, lapsed ones too unless `liveAt` says when to judge them: one
 * member's, or everyone's; `everyProject`, only those on every project.
 */
export async function readGrants(
  db: Queryable,
  filter: { principal?: string; liveAt?: number; everyProject?: boolean } = {},
): Promise<GrantRow[]> {
  const { vaultGrants, environments } = tablesOf(db);
  const rows = await db
    .select({ grant: vaultGrants, environmentProjectId: environments.projectId })
    .from(vaultGrants)
    .leftJoin(environments, eq(environments.id, vaultGrants.environmentId))
    .where(
      and(
        filter.principal === undefined ? undefined : eq(vaultGrants.principal, filter.principal),
        filter.liveAt === undefined ? undefined : or(isNull(vaultGrants.expiresAt), gt(vaultGrants.expiresAt, filter.liveAt)),
        filter.everyProject === true ? and(isNull(vaultGrants.projectId), isNull(vaultGrants.environmentId)) : undefined,
      ),
    );
  return rows.map(({ grant, environmentProjectId }) => ({ ...grant, projectId: grant.projectId ?? environmentProjectId }));
}

/** Add a grant; an environment's row names only the environment. */
export async function insertGrant(db: Queryable, grant: GrantRow): Promise<void> {
  const { vaultGrants } = tablesOf(db);
  await db.insert(vaultGrants).values({ ...grant, projectId: grant.environmentId === null ? grant.projectId : null });
}
