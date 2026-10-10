import { inScope, ROLE_NAMES, ROLES, type Permission, type Role, type Scope } from '@coffre/core/access';

import type { ProjectSummary } from '../shared/models';

/** What `givable` reads of the shell: the projects, what you hold in each environment, and the setting. */
type Holder = {
  projects: readonly ProjectSummary[];
  environments: readonly { project: string; environment: string; permissions: Permission[] }[];
  /** The instance's setting as `/me` says it, projects by slug, those you see; null for a service account. */
  serviceSetup: Scope | null;
};

/**
 * The roles you may give a service account at a project, or one of its
 * environments, as the server decides it (`givesService` in
 * @coffre/core/access): any, where you manage access; otherwise, inside the
 * instance's setting, those whose every permission you hold there.
 *
 *   a Developer of every dev, at market/dev   viewer, developer
 *   the same, at market                       none: a project takes holding all of it
 */
export function givable(holder: Holder, project: ProjectSummary, environment: string | null): Role[] {
  const held = environment === null
    ? project.permissions
    : holder.environments.find((entry) => entry.project === project.slug && entry.environment === environment)?.permissions ?? [];
  if (held.includes('grant.manage')) return [...ROLE_NAMES];
  const setting = holder.serviceSetup;
  // The setting names projects by slug here, so a place is matched by its slugs.
  const place = environment === null
    ? { projectId: project.slug }
    : { projectId: project.slug, environmentId: environment, environmentSlug: environment };
  if (setting === null || !inScope(setting, place)) return [];
  return ROLE_NAMES.filter((role) => ROLES[role].permissions.every((permission) => held.includes(permission)));
}

/** The projects where you may give a service account something: on the project, or on one of its environments. */
export function serviceProjects(holder: Holder): ProjectSummary[] {
  return holder.projects.filter((project) =>
    givable(holder, project, null).length > 0 ||
    project.environments.some((environment) => givable(holder, project, environment.slug).length > 0));
}
