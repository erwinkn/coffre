import type { GrantRow, ProjectSummary } from '../shared/models';

/** "Owner", "Viewer: all" or "Developer: prod": a grant by its role's name, as the instance names it, and where. */
export function projectAccessLabel(
  grant: Pick<GrantRow, 'role' | 'roleName' | 'environmentSlug'>,
): string {
  if (grant.role === 'owner') return grant.roleName;
  return `${grant.roleName}: ${grant.environmentSlug ?? 'all'}`;
}

/** A project on someone's Access tab: their grants there, or why those could not be read. */
export type ProjectAccess = { project: ProjectSummary; grants: GrantRow[]; grantsError: string | null };

/** A row of the Access tab: one of their grants, or a project whose grants could not be read. */
export type AccessRow =
  | { project: ProjectSummary; grant: GrantRow; error: null }
  | { project: ProjectSummary; grant: null; error: string };

/**
 * The Access tab's rows, project by project: a row per grant, and a project
 * whose read failed keeps a row of its own that says why, so a failure
 * never reads as no access.
 */
export function accessRows(access: ProjectAccess[]): AccessRow[] {
  return access.flatMap(({ project, grants, grantsError }): AccessRow[] =>
    grantsError === null
      ? grants.map((grant) => ({ project, grant, error: null }))
      : [{ project, grant: null, error: grantsError }],
  );
}
