import type { Answers, Called, Change, EnvironmentEdit, EnvironmentEdited, ProjectEdit, ProjectEdited } from '@coffre/core/vault';
import { ownsProject, runsInstance, type Permission } from '@coffre/core/access';
import { displayName, environmentSlug, folderName, personalOf, slug } from '@coffre/core/schemas';
import { z } from 'zod';

import { keyCounts, personalConfigs, places, type PlaceRow } from '../../db/queries/places.ts';
import { can, permissionsAt, placeOf, projectsReached } from '../caller.ts';
import type { ApiContext } from '../context.ts';
import { ApiError, badRequest, conflict, refusal } from '../errors.ts';
import { route } from '../route.ts';

/**
 * Projects and environments (docs/design/0.16.md, "The server"): their
 * lists, and their changes, each one call to the vault, which decides it.
 * A place goes by its slug: `name`, a label from before 0.6.2 that older
 * CLIs still send, is taken and changes nothing, and every answer gives the
 * slug as one.
 */

/** A change of the vault's, worded: its answer, or its refusal thrown with `what` it was about. */
async function changed<O extends Change['op']>(ctx: ApiContext, change: Extract<Change, { op: O }>, what: string): Promise<Answers[O]> {
  const answer = await ctx.vault.change<O>({ ...ctx.shown, ...change });
  if ('refused' in answer) throw refusal(answer.refused, what);
  return answer.answer;
}

/**
 * The one change a patch asks for. A patch names one: each is a change of
 * its own in the vault, and two in one request would leave the first made
 * when the second is refused. A slug it already has is no change.
 */
function oneChange<T>(asked: (T | null)[], noChange: T): T {
  const changes = asked.filter((change) => change !== null);
  if (changes.length > 1) throw badRequest('one change at a time: a new slug, archived, the folder or the protection');
  return changes[0] ?? noChange;
}

const projectView = (left: ProjectEdited) => ({ slug: left.slug, name: left.slug, archivedAt: left.archivedAt, folder: left.folder });
const environmentView = (left: EnvironmentEdited) => ({ slug: left.slug, name: left.slug, archivedAt: left.archivedAt, protected: left.protected });

const notServed = (what: string) => new ApiError('not_implemented', `${what} is not served yet`);

/** Whether the caller reads or uses values at a place: a role that writes or archives there also reads or uses, so this is who lists its keys. */
const lists = (who: Called, place: ReturnType<typeof placeOf>) => can(who, 'secret.read', place) || can(who, 'secret.use', place);

type Environment = PlaceRow['environments'][number];

/** A project's environment as the projects' list shows it: `dev@me` for the caller's own personal config, which only they see. */
type Listed = {
  slug: string;
  /** @deprecated The slug, which older CLIs print. */
  name: string;
  /** Whether the caller may open its keys. */
  accessible: boolean;
  /** The environment it inherits from, by slug, or null. */
  parent: string | null;
  /** Whether it is protected: a personal config as the environment it is a config of is. */
  protected: boolean;
  /** Whether the caller may take its protection off: an Owner of the project, on no credential's scope (R30). False for a personal config. */
  unprotectable: boolean;
  personal: boolean;
  /** Null when the caller may only know it by name; `secretCount`, the keys it resolves to, its own and those it inherits, when they may open it. */
  details: { archivedAt: string | null; secretCount: number | null } | null;
};

type ProjectSummary = {
  slug: string;
  /** @deprecated The slug, which older CLIs print. */
  name: string;
  archivedAt: string | null;
  folder: string | null;
  /** What the caller may do at project scope. */
  permissions: Permission[];
  environments: Listed[];
  /** Distinct live key names across the live environments the caller may open; null when they may open none, or the project is archived. */
  secretCount: number | null;
};

export const placeRoutes = {
  /**
   * The projects the caller can see, and their environments: anything they
   * hold anywhere in one shows it, an environment grant included, which
   * shows the names of its siblings and nothing in them. An archived
   * project, to whoever runs the instance or manages it. One call to the
   * vault and two statements, however many projects, environments and keys
   * there are: the places the caller reaches, then the keys of those they
   * may open.
   */
  ...route('GET /projects', {
    run: async (ctx): Promise<{ projects: ProjectSummary[] }> => {
      const who = await ctx.caller();
      const known = await places(ctx.db, projectsReached(who));
      const runs = runsInstance(who.holds);
      const shown: { project: PlaceRow; environments: Environment[]; manages: boolean; permissions: Permission[] }[] = [];
      for (const project of known) {
        const at = { projectId: project.id };
        // Someone else's personal config is no place of theirs: not listed, and showing the project to nobody.
        const environments = project.environments.filter((environment) => environment.owner === null || environment.owner === who.principal);
        const permissions = permissionsAt(who, at);
        if (permissions.length === 0 && !environments.some((environment) => permissionsAt(who, placeOf(project, environment)).length > 0)) continue;
        if (project.archived && !runs && !permissions.includes('project.manage')) continue;
        shown.push({ project, environments, manages: permissions.includes('environment.manage') || permissions.includes('grant.manage'), permissions });
      }
      // The keys of what the caller may open, archived environments included; the project's names among its live ones only.
      const open = shown.flatMap(({ project, environments }) => environments.filter((environment) => lists(who, placeOf(project, environment))).map((environment) => ({ project, environment })));
      const counted = open.filter(({ project, environment }) => !project.archived && !environment.archived).map(({ environment }) => environment.id);
      const counts = open.length === 0 ? { environments: new Map<string, number>(), projects: new Map<string, number>() } : await keyCounts(ctx.db, open.map(({ environment }) => environment.id), counted);
      const opened = new Set(open.map(({ environment }) => environment.id));
      const projects = shown.map(({ project, environments, manages, permissions }): ProjectSummary => ({
        slug: project.slug,
        name: project.slug,
        archivedAt: project.archivedAt,
        folder: project.folder,
        permissions,
        environments: environments.map((environment): Listed => {
          const personal = environment.owner !== null;
          const listedAs = personal ? `${environment.parent?.slug ?? '?'}@me` : environment.slug;
          const accessible = opened.has(environment.id);
          // A protected environment is one by its row, or by the vault's list.
          const guarded = (row: { id: string; protected: boolean } | null) => row !== null && (row.protected || who.holds.policy.protected.includes(row.id));
          return {
            slug: listedAs,
            name: listedAs,
            accessible,
            parent: environment.parent?.slug ?? null,
            protected: guarded(personal ? environment.parent : environment),
            unprotectable: !personal && ownsProject(who.holds, project.id),
            personal,
            details: !manages && !accessible ? null : { archivedAt: environment.archivedAt, secretCount: accessible ? (counts.environments.get(environment.id) ?? 0) : null },
          };
        }),
        // An archived project's environments are none of `counted`.
        secretCount: environments.some((environment) => counted.includes(environment.id)) ? (counts.projects.get(project.id) ?? 0) : null,
      }));
      return { projects };
    },
  }),

  /**
   * A project's personal configs, for whoever manages its environments:
   * whose, of what, and their keys' names, never a value. One call to the
   * vault and one statement. A project the caller may not list them in is
   * answered as one that is not there.
   */
  ...route('GET /personal/:project', {
    run: async (ctx, { params }) => {
      const who = await ctx.caller();
      const project = await personalConfigs(ctx.db, params.project, projectsReached(who));
      if (project === null || !can(who, 'environment.manage', { projectId: project.id })) throw refusal('no_access', params.project);
      return { configs: project.configs.map(({ of, ...config }) => ({ ...config, of: of ?? '?' })) };
    },
  }),

  /**
   * Make a project: an Admin or Owner of the instance whose scope takes in
   * new projects. One that is there already is refused, `exists`, where 0.14
   * answered it unchanged.
   */
  ...route('PUT /projects/:project', {
    input: z.object({ name: displayName.optional() }),
    run: async (ctx, { params }) => {
      await changed(ctx, { op: 'project.create', project: params.project }, params.project);
      return { project: { slug: params.project, name: params.project, archivedAt: null }, created: true };
    },
  }),

  /**
   * Edit a project, by whoever manages it: a new slug, archived or
   * restored, or filed in a folder, or in none. One of them a request.
   */
  ...route('PATCH /projects/:project', {
    input: z.object({ name: displayName, slug, archived: z.boolean(), folder: folderName.nullable() }).partial().strict(),
    run: async (ctx, { params, input }) => {
      const { project } = params;
      const edit = oneChange<ProjectEdit>(
        [
          input.slug === undefined || input.slug === project ? null : { op: 'project.update', project, slug: input.slug },
          input.archived === undefined ? null : { op: input.archived ? 'project.archive' : 'project.restore', project },
          input.folder === undefined ? null : { op: 'project.move', project, folder: input.folder },
        ],
        // Nothing to change: its slug, which is so already, says what it is.
        { op: 'project.update', project, slug: project },
      );
      // A new slug that is taken is the new slug's refusal.
      return { project: projectView(await changed(ctx, edit, edit.op === 'project.update' ? edit.slug : project)) };
    },
  }),

  /** Delete a project for good: the vault does not erase a place yet. */
  ...route('DELETE /projects/:project', {
    run: async () => {
      throw notServed('deleting a project for good');
    },
  }),

  /**
   * Make an environment, by whoever manages its project's environments; with
   * `from` and `inherit`, a fork that inherits from that environment, live,
   * by one who reads it too. `market/dev@me` makes the caller's personal
   * config of dev: a person's, who reads or uses dev. One that is there is
   * refused, `exists`. A fork that copies values, or holds references to
   * its parent's, is not served yet.
   */
  ...route('PUT /projects/:project/:environment', {
    input: z.object({ name: displayName.optional(), from: slug.optional(), references: z.boolean().optional(), inherit: z.boolean().optional() }),
    run: async (ctx, { params, input }) => {
      const { project } = params;
      const of = personalOf(params.environment);
      const path = `${project}/${params.environment}`;
      if (of !== null) {
        if (input.from !== undefined || input.inherit !== undefined || input.references !== undefined) throw badRequest('a personal config inherits from the environment it is a config of: no `from`');
        const made = await changed(ctx, { op: 'environment.create', project, environment: of, mine: true }, path);
        return { environment: { slug: params.environment, name: params.environment, archivedAt: null, protected: made.protected }, created: true, forked: null };
      }
      const named = environmentSlug.safeParse(params.environment);
      if (!named.success) throw badRequest(named.error.issues[0]?.message ?? `"${params.environment}" is not a valid environment`);
      const { from } = input;
      if (from === undefined && (input.inherit === true || input.references === true)) throw badRequest('a fork names the environment it forks: `from`');
      if (input.inherit === true && input.references === true) throw badRequest('a fork inherits its parent, or holds references to it: not both');
      if (from !== undefined && input.inherit !== true) throw notServed(`a fork that ${input.references === true ? 'holds references to' : 'copies'} its parent's values (\`inherit\` makes one that inherits them)`);
      if (from === params.environment) throw conflict('an environment cannot be forked into itself');
      const made = await changed(ctx, { op: 'environment.create', project, environment: params.environment, mine: false, parent: from ?? null, protected: false }, path);
      return {
        environment: { slug: params.environment, name: params.environment, archivedAt: null, protected: made.protected },
        created: true,
        forked: from === undefined ? null : { from, keys: 0, references: 0, copied: [], inherits: true },
      };
    },
  }),

  /**
   * Edit an environment, by whoever manages its project's environments: a
   * new slug, archived or restored, with its personal configs, or protected.
   * Its protection is taken off by an Owner of the project alone. One of
   * them a request; a personal config is edited with its environment.
   */
  ...route('PATCH /projects/:project/:environment', {
    input: z.object({ name: displayName, slug: environmentSlug, archived: z.boolean(), protected: z.boolean() }).partial().strict(),
    run: async (ctx, { params, input }) => {
      const { project, environment } = params;
      if (personalOf(environment) !== null) throw badRequest('a personal config is archived, restored and protected with the environment it is a config of');
      const at = { project, environment };
      const edit = oneChange<EnvironmentEdit>(
        [
          input.slug === undefined || input.slug === environment ? null : { op: 'environment.update', ...at, slug: input.slug },
          input.archived === undefined ? null : { op: input.archived ? 'environment.archive' : 'environment.restore', ...at },
          input.protected === undefined ? null : { op: input.protected ? 'environment.protect' : 'environment.unprotect', ...at },
        ],
        { op: 'environment.update', ...at, slug: environment },
      );
      return { environment: environmentView(await changed(ctx, edit, `${project}/${edit.op === 'environment.update' ? edit.slug : environment}`)) };
    },
  }),

  /** Delete an environment for good: the vault does not erase a place yet. */
  ...route('DELETE /projects/:project/:environment', {
    run: async () => {
      throw notServed('deleting an environment for good');
    },
  }),

  /**
   * Rename a folder of projects: every project filed there, at once, by
   * whoever manages each of them. A folder is a label, so renaming onto one
   * that is there merges them.
   */
  ...route('PATCH /folders/:folder', {
    input: z.object({ name: folderName }).strict(),
    run: async (ctx, { params, input }) => {
      const { moved } = await changed(ctx, { op: 'folder.refile', folder: params.folder, to: input.name }, params.folder);
      return { folder: input.name, moved };
    },
  }),

  /** Empty a folder of projects: each one stays where it is, in no folder. */
  ...route('DELETE /folders/:folder', {
    run: async (ctx, { params }) => {
      const { moved } = await changed(ctx, { op: 'folder.refile', folder: params.folder, to: null }, params.folder);
      return { folder: null, moved };
    },
  }),
};
