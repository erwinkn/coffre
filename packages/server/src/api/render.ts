import { personalOf } from '@coffre/core/schemas';

import { places, resolvePath, type PlaceRow, type ResolvedPath } from '../db/queries.ts';
import { projectsReached } from './caller.ts';
import type { ApiContext } from './context.ts';

/**
 * One page's render on the server: every API call it makes, in process
 * (`pageClient`), as one caller, whom it checks once. What they all read
 * of the instance, the projects and environments the caller reaches, is
 * read once for them all, and each path they name is found in it. A
 * render changes nothing (a change from one has no origin to show, and is
 * refused), so what its first call read holds for its last: on Workers,
 * each statement is a round trip, and the environment page's three calls
 * each read the tree, or resolved its path, again.
 */
export class Render {
  #reached: Promise<PlaceRow[]> | null = null;

  /** The places the render's caller reaches, read the first time a call asks. */
  reached(read: () => Promise<PlaceRow[]>): Promise<PlaceRow[]> {
    return (this.#reached ??= read());
  }
}

/**
 * The projects the caller reaches, with their environments (`projectsReached`)
 * and their team keys: what `me` and the project list show. Once a render.
 */
export function reachedPlaces(ctx: Pick<ApiContext, 'db' | 'caller' | 'render'>): Promise<PlaceRow[]> {
  const read = () => places(ctx.db, { within: projectsReached(ctx.caller) ?? undefined, teamKeys: true });
  return ctx.render === undefined ? read() : ctx.render.reached(read);
}

/** One project and its environments: from the render's places, which hold every project its caller reaches; else read alone. */
export async function projectPlaces(ctx: Pick<ApiContext, 'db' | 'caller' | 'render'>, projectId: string): Promise<PlaceRow | undefined> {
  const kept = ctx.render === undefined ? undefined : (await reachedPlaces(ctx)).find((project) => project.id === projectId);
  return kept ?? (await places(ctx.db, { within: [projectId] }))[0];
}

/**
 * A project or an environment, as `resolvePath` finds it: in a render,
 * from its places, with no statement, where they hold it; a key, a
 * personal config (`dev@me`) and a place the caller does not reach are
 * looked up, as outside one.
 */
export async function placeAt(
  ctx: Pick<ApiContext, 'db' | 'caller' | 'render'>,
  path: { project: string; environment?: string; key?: string },
  options: { owner?: string | null } = {},
): Promise<ResolvedPath | null> {
  if (ctx.render !== undefined && path.key === undefined && (path.environment === undefined || personalOf(path.environment) === null)) {
    const project = (await reachedPlaces(ctx)).find((each) => each.slug === path.project);
    const environment = path.environment === undefined ? null : project?.environments.find((each) => each.slug === path.environment);
    if (project !== undefined && environment !== undefined) {
      return {
        project: { id: project.id, slug: project.slug, name: project.name, archivedAt: project.archivedAt },
        environment: environment === null
          ? null
          : { id: environment.id, slug: environment.slug, name: environment.name, archivedAt: environment.archivedAt, parentId: environment.parentId, parentSlug: environment.parentSlug, owner: environment.owner },
        secret: null,
      };
    }
  }
  return resolvePath(ctx.db, path, options);
}
