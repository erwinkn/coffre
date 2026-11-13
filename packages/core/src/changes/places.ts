/** The changes of projects and environments (`packages/vault/src/ops/places.ts`). */
export type PlacesChanges = ProjectCreate | EnvironmentCreate;

export type PlacesAnswers = {
  'project.create': { id: string };
  /** Its slug is the one asked for, or, for a personal config, the one made for it, which only a list for deletion shows. */
  'environment.create': { id: string; slug: string; protected: boolean };
};

/**
 * Make a project, as an Admin or Owner of the instance whose scope takes in
 * new projects, on a session's credential. Its slug is free: no project has
 * it, archived ones included. A slug is 1 to 63 of `a-z`, `0-9` and `-`,
 * starting with a letter or digit; past that the call is a fault, not a
 * refusal: the app checks it first.
 */
export type ProjectCreate = {
  op: 'project.create';
  project: string;
};

/**
 * Make an environment in a live project, as one who manages its
 * environments (`environment.manage`): its slug free in the project,
 * shaped as a project's and none of a project's pages (`PROJECT_PAGES`).
 * With `parent`, a fork that inherits from that environment, live, never
 * a personal config, which the caller reads, and which inherits from two
 * at most, so that the fork inherits from three. A fork of a protected
 * environment is protected, whatever `protected` says.
 *
 * With `mine`, the caller's personal config of `environment` instead: a
 * person's, who reads or uses it, live, never a personal config itself,
 * with two parents at most. One per person per environment. Its slug is
 * made here, and it is protected as its environment is, through it.
 */
export type EnvironmentCreate = { op: 'environment.create'; project: string; environment: string } & (
  | { mine: false; parent: string | null; protected: boolean }
  | { mine: true }
);
