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
