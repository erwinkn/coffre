import type { ProjectSummary } from '../shared/models';

export type ProjectEnvironment = ProjectSummary['environments'][number];
export type DetailedProjectEnvironment = ProjectEnvironment & {
  details: NonNullable<ProjectEnvironment['details']>;
};

export function hasEnvironmentDetails(
  environment: ProjectEnvironment,
): environment is DetailedProjectEnvironment {
  return environment.details !== null;
}

export function isActiveAccessibleEnvironment(
  environment: ProjectEnvironment,
): environment is ProjectEnvironment & {
  accessible: true;
  details: { archivedAt: null; secretCount: number };
} {
  return environment.accessible
    && environment.details !== null
    && environment.details.archivedAt === null;
}

/**
 * What the Projects table lists for a project: its live environments, less
 * those known to hold no secret (`empty`, counted apart). An environment
 * the caller cannot open has no count, so it is never empty.
 */
export function listedEnvironments(environments: readonly ProjectEnvironment[]): {
  listed: ProjectEnvironment[];
  empty: number;
} {
  const live = environments.filter(
    (environment) => environment.details === null || environment.details.archivedAt === null,
  );
  const listed = live.filter((environment) => environment.details?.secretCount !== 0);
  return { listed, empty: live.length - listed.length };
}
