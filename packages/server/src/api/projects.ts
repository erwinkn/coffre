import { randomUUID } from 'node:crypto';

import { runsInstance, type InstanceRole, type Permission, type Scope } from '@coffre/core/access';
import type { Queryable, Transaction } from '@coffre/db';
import { isUniqueViolation } from '@coffre/db/dialect';
import { environments, projects } from '@coffre/db/schema';


import {
  deletionScope,
  dismissalsAcross,
  distinctSecretCounts,
  eraseVersions,
  forksOf,
  insert,
  liveEnvironment,
  liveKeysIn,
  parentsOf,
  places,
  projectsInFolder,
  resolvePath,
  tombstoneSlug,
  update,
  type Doomed,
  type PlaceRow,
  type ResolvedPath,
  fileProject,
  projectFolderOf,
} from '../db/queries.ts';
import { COFFRE_VERSION } from '../version.ts';
import { can, canAnywhere, permissionsAt, placeOf, seesProject } from './caller.ts';
import { allowed, audited, denied, Refusal, requireInstance, requireProjectMaker, withRefusals, type ApiContext } from './context.ts';
import { ApiError, conflict, forbidden, notFound, vaultRefused } from './errors.ts';
import { scopeView } from './members.ts';
import { scopeByPath, serviceSettingFor, setsUp, type ScopeByPath } from './services.ts';
import { formatMember } from './paths.ts';
import { resolveKeys, type Held } from './inheritance.ts';
import { endReferences, referencesAt, refuseIfRead } from './references.ts';

export type Me = {
  principal: { type: 'user' | 'service'; id: string };
  /**
   * False for someone signed in but not a member: `/me` is the one call that
   * answers them, so the UI can say who they are and that the door is shut.
   */
  registered: boolean;
  /** Refused by the vault: their record failed its integrity check. */
  tampered: boolean;
  instanceRole: InstanceRole;
  /** Where their instance role applies, projects by slug. */
  scope: Scope;
  /** Whether they run the instance: an admin or owner with no scope. */
  runsInstance: boolean;
  canReadAudit: boolean;
  /** Whether they set up any service account: who runs the instance, or a person who could give one a grant somewhere. */
  setsUpServices: boolean;
  /**
   * Where a person sets up service accounts without running the instance:
   * the instance's setting, projects by slug, those they see; null for a
   * service account. Inside it, they give one what they hold there.
   */
  serviceSetup: Scope | null;
  /**
   * What this deployment's configuration turns on, as `signin({ … })` says:
   * MCP clients (`mcp`), as the endpoint they connect to,
   * `https://secrets.acme.example/mcp`, or null when it serves none; and CI
   * runs signing in by their ID tokens (`workloads`). Read here, never
   * inferred from a route answering 404 or from where a page was served.
   */
  features: { mcp: string | null; workloads: boolean };
  /**
   * The personal token the request came in on: its label, when it ends and
   * what it reaches, by path. Null for a session, or anything else.
   * `environments` and the rest are already what it reaches.
   */
  personalToken: { id: string; label: string; expiresAt: string; scope: ScopeByPath } | null;
  /** Every live environment the caller holds something in, and what. */
  environments: { project: string; environment: string; permissions: Permission[] }[];
};

export type ProjectEnvironmentSummary = {
  slug: string;
  /** @deprecated A place goes by its slug since 0.6.2; kept for older CLIs, which print it. */
  name: string;
  /** True when the caller may open the environment's secret metadata page. */
  accessible: boolean;
  /** The environment it inherits from, by slug: a fork's (docs/design/forking.md). Null for none. */
  parent: string | null;
  /**
   * Omitted for environments that the caller may only know by name. A
   * fork's count is of the keys it resolves to: its own, and those it inherits.
   */
  details: { archivedAt: string | null; secretCount: number | null } | null;
};

export type ProjectSummary = {
  slug: string;
  /** @deprecated A place goes by its slug since 0.6.2; kept for older CLIs, which print it. */
  name: string;
  archivedAt: string | null;
  /** The folder it is listed in, or null for none. */
  folder: string | null;
  /** What the caller may do at project scope. */
  permissions: Permission[];
  environments: ProjectEnvironmentSummary[];
  /**
   * Distinct live secret names across the live environments the caller can
   * open: the same key in dev and prod is one secret. Null when they can open
   * none, or the project is archived.
   */
  secretCount: number | null;
};

const iso = (value: Date | null) => value?.toISOString() ?? null;

export async function me(ctx: ApiContext): Promise<Me> {
  const { caller } = ctx;
  const reachable: Me['environments'] = [];
  const [known, setting] = await Promise.all([places(ctx.db), serviceSettingFor(ctx.vault, caller)]);
  for (const project of known) {
    if (project.archivedAt !== null) continue;
    for (const environment of project.environments) {
      if (environment.archivedAt !== null) continue;
      const permissions = permissionsAt(caller, placeOf(project, environment));
      if (permissions.length === 0) continue;
      reachable.push({ project: project.slug, environment: environment.slug, permissions });
    }
  }
  return {
    principal: caller.principal,
    registered: caller.registered,
    tampered: caller.tampered,
    instanceRole: caller.role,
    scope: scopeView(caller.scope, known),
    runsInstance: runsInstance(caller),
    canReadAudit: canAnywhere(caller, 'audit.read'),
    setsUpServices: setsUp(caller, setting, known),
    // A scope names projects the caller may not see (D95): those they do, by slug.
    serviceSetup: setting === null ? null : scopeView(setting, runsInstance(caller) ? known : known.filter((project) => seesProject(caller, project))),
    features: { mcp: ctx.mcp?.resource ?? null, workloads: ctx.workloads !== null },
    personalToken: ctx.personalToken === null ? null : { ...ctx.personalToken, scope: scopeByPath(caller.credentialScope ?? [], known)! },
    environments: reachable,
  };
}

/**
 * The projects the caller can see: anything they hold anywhere in one, by
 * a grant or their instance role, makes it visible. An environment grant
 * shows the project without conferring authority over it, so `permissions`
 * are the project-scope ones, and the caller learns the names of
 * environments they hold nothing in, not their contents.
 */
export async function listProjects(ctx: ApiContext): Promise<{ projects: ProjectSummary[] }> {
  const { caller } = ctx;
  const summaries: ProjectSummary[] = [];
  // The projects whose secrets the caller may count, and where they may.
  const counted: { summary: ProjectSummary; projectId: string; environmentIds: string[] }[] = [];
  const [known, folders] = await Promise.all([places(ctx.db), projectFolderOf(ctx.db)]);
  const resolved = await forkKeys(ctx.db, known);
  for (const project of known) {
    const slugOf = new Map(project.environments.map((environment) => [environment.id, environment.slug]));
    const parent = (environment: { parentId: string | null }) => (environment.parentId === null ? null : (slugOf.get(environment.parentId) ?? null));
    if (!seesProject(caller, project)) continue;
    const scope = { projectId: project.id };
    if (project.archivedAt !== null && !runsInstance(caller) && !can(caller, 'project.manage', scope)) {
      continue;
    }
    const manages =
      can(caller, 'environment.manage', scope) || can(caller, 'grant.manage', scope);

    const summary: ProjectSummary = {
      slug: project.slug,
      name: project.name,
      archivedAt: iso(project.archivedAt),
      folder: folders.get(project.id) ?? null,
      permissions: permissionsAt(caller, scope),
      environments: project.environments.map((environment) => {
        // Every role that writes or archives also reads, so read is the test.
        const secretAccess = can(caller, 'secret.read', placeOf(project, environment));
        if (!manages && !secretAccess) {
          return { slug: environment.slug, name: environment.name, accessible: false, parent: parent(environment), details: null };
        }
        return {
          slug: environment.slug,
          name: environment.name,
          accessible: secretAccess,
          parent: parent(environment),
          details: {
            archivedAt: iso(environment.archivedAt),
            secretCount: secretAccess ? (resolved.get(environment.id)?.size ?? environment.secretCount) : null,
          },
        };
      }),
      secretCount: null,
    };
    summaries.push(summary);

    const environmentIds = project.environments
      .filter(
        (environment) =>
          environment.archivedAt === null &&
          can(caller, 'secret.read', placeOf(project, environment)),
      )
      .map((environment) => environment.id);
    if (project.archivedAt === null && environmentIds.length > 0) {
      counted.push({ summary, projectId: project.id, environmentIds });
    }
  }

  // One query counts every project, rather than one list per environment. A
  // project with forks counts the names its environments resolve to, which
  // its environments' own rows may not hold: a fork inherits them.
  const distinct = await distinctSecretCounts(ctx.db, counted.flatMap((entry) => entry.environmentIds));
  for (const { summary, projectId, environmentIds } of counted) {
    const names = environmentIds.some((id) => resolved.has(id))
      ? new Set(environmentIds.flatMap((id) => [...(resolved.get(id)?.keys() ?? [])])).size
      : undefined;
    summary.secretCount = names ?? distinct.get(projectId) ?? 0;
  }
  return { projects: summaries };
}

/**
 * The keys each environment resolves to, its own and those it inherits, in
 * the projects that have a fork: two queries for all of them, none without.
 */
async function forkKeys(db: Queryable, known: readonly PlaceRow[]): Promise<Map<string, Map<string, Held>>> {
  const forked = known.filter((project) => project.environments.some((environment) => environment.parentId !== null));
  const ids = forked.flatMap((project) => project.environments.map((environment) => environment.id));
  if (ids.length === 0) return new Map();
  const [live, dismissed] = await Promise.all([liveKeysIn(db, ids), dismissalsAcross(db, ids)]);
  return resolveKeys(forked.flatMap((project) => project.environments), live, dismissed);
}

export type PlaceView = {
  slug: string;
  /** @deprecated A place goes by its slug since 0.6.2; kept for older CLIs, which print it. */
  name: string;
  archivedAt: string | null;
};
export type ProjectView = PlaceView & { folder: string | null };

function slugTaken(what: 'project' | 'environment', slug: string): Error {
  return conflict(`a ${what} named "${slug}" already exists`);
}

/**
 * Create a project, or leave it as it is if it already exists: `PUT` names
 * the thing it creates, so sending it twice is harmless. Admins and owners
 * whose scope takes in new projects only (`makesProjects`).
 */
export async function putProject(
  ctx: ApiContext,
  place: ResolvedPath | null,
  slug: string,
  input: { name?: string },
): Promise<{ project: PlaceView; created: boolean }> {
  // A place goes by its slug. Its name, which releases before 0.6.2 show, is the slug unless an older client sends one.
  const name = input.name ?? slug;
  const put = await audited(ctx, async (tx, log) => {
    requireProjectMaker(ctx, 'project.create', { metadata: { slug } });
    if (place !== null) {
      const { project } = place;
      return { id: project.id, project: { slug, name: project.name, archivedAt: iso(project.archivedAt) }, created: false };
    }
    const id = randomUUID();
    try {
      await insert(tx, projects, { id, slug, name });
    } catch (error) {
      if (isUniqueViolation(error)) throw slugTaken('project', slug);
      throw error;
    }
    log.push(allowed(ctx, 'project.create', { projectId: id, metadata: { slug, name } }));
    return { id, project: { slug, name, archivedAt: null }, created: true };
  });
  const { id: _, ...made } = put;
  return made;
}

type PlacePatch = { name?: string; slug?: string; archived?: boolean };
type ProjectPatch = PlacePatch & { folder?: string | null };

/**
 * What a patch changes on a project or environment: its name and slug, and
 * its archivedAt, left undefined when the patch does not move it.
 */
function placeChanges(
  current: { slug: string; name: string; archivedAt: Date | null },
  patch: PlacePatch,
): { renames: { name?: string; slug?: string }; archivedAt: Date | null | undefined } {
  const renames: { name?: string; slug?: string } = {};
  if (patch.name !== undefined && patch.name !== current.name) renames.name = patch.name;
  if (patch.slug !== undefined && patch.slug !== current.slug) renames.slug = patch.slug;
  let archivedAt: Date | null | undefined;
  if (patch.archived === true && current.archivedAt === null) archivedAt = new Date();
  if (patch.archived === false && current.archivedAt !== null) archivedAt = null;
  return { renames, archivedAt };
}

/**
 * The place a request names, resolved again under the log's head, which
 * every change to a place takes first. The router resolved it before the
 * transaction: one deleted since, or re-slugged, is no longer at that path,
 * and a change by its id would undo the deletion's tombstone.
 */
async function stillThere(tx: Transaction, place: ResolvedPath): Promise<ResolvedPath> {
  const { project, environment } = place;
  const now = await resolvePath(tx, { project: project.slug, environment: environment?.slug });
  if (now === null || now.project.id !== project.id) throw notFound(`no project "${project.slug}"`);
  if (environment !== null && now.environment?.id !== environment.id) {
    throw notFound(`no environment "${project.slug}/${environment.slug}"`);
  }
  return now;
}

/** Rename, re-slug, archive or restore a project, or move it to a folder. */
export async function patchProject(
  ctx: ApiContext,
  place: ResolvedPath,
  patch: ProjectPatch,
): Promise<{ project: ProjectView }> {
  const { project } = place;
  const { renames, archivedAt } = placeChanges(project, patch);
  const renamed = Object.keys(renames).length > 0;
  const before = patch.folder === undefined ? null : (await projectFolderOf(ctx.db)).get(project.id) ?? null;
  const moving = patch.folder !== undefined && patch.folder !== before;
  return audited(ctx, async (tx, log) => {
    await stillThere(tx, place);
    if (archivedAt != null) await refuseIfRead(ctx, tx, project.slug, { projectId: project.id }, 'project.archive', { projectId: project.id });
    if (renamed || archivedAt !== undefined) {
      try {
        await update(tx, projects, { id: project.id }, { ...renames, archivedAt });
      } catch (error) {
        if (!isUniqueViolation(error)) throw error;
        throw new Refusal(
          slugTaken('project', renames.slug!),
          denied(ctx, 'project.update', 'slug_taken', { projectId: project.id, metadata: { slug: renames.slug } }),
        );
      }
    }
    if (renamed) {
      log.push(allowed(ctx, 'project.update', {
        projectId: project.id,
        metadata: { from: project.slug, ...renames },
      }));
    }
    if (archivedAt !== undefined) {
      log.push(allowed(ctx, archivedAt === null ? 'project.restore' : 'project.archive', {
        projectId: project.id,
        metadata: { slug: renames.slug ?? project.slug },
      }));
    }
    if (moving) {
      await fileProject(tx, project.id, patch.folder!);
      log.push(allowed(ctx, 'project.move', {
        projectId: project.id,
        metadata: { slug: renames.slug ?? project.slug, from: before, to: patch.folder },
      }));
    }
    return {
      project: {
        slug: renames.slug ?? project.slug,
        name: renames.name ?? project.name,
        archivedAt: iso(archivedAt === undefined ? project.archivedAt : archivedAt),
        folder: patch.folder === undefined ? before : patch.folder,
      },
    };
  });
}

/**
 * Create an environment unless it exists. Needs `environment.manage` on the
 * project. A fork (forks.ts) creates it this way, and its entry says which
 * environment it forks.
 */
export async function putEnvironment(
  ctx: ApiContext,
  place: ResolvedPath,
  slug: string,
  input: { name?: string },
  { from, parentId = null }: { from?: string; parentId?: string | null } = {},
): Promise<{ environment: PlaceView; created: boolean }> {
  const { project, environment } = place;
  const name = input.name ?? slug;
  if (environment !== null) {
    const existing = { slug, name: environment.name, archivedAt: iso(environment.archivedAt) };
    return { environment: existing, created: false };
  }
  return audited(ctx, async (tx, log) => {
    // The project as it is under the head: archived, or deleted, since the router found it, it takes nothing new.
    if ((await stillThere(tx, place)).project.archivedAt !== null) {
      throw new Refusal(
        conflict(`${project.slug} is archived; restore it before adding environments`),
        denied(ctx, 'environment.create', 'project_archived', {
          projectId: project.id,
          metadata: { environmentSlug: slug },
        }),
      );
    }
    // The parent too: archived or deleted since the fork checked it, it is no parent.
    if (parentId !== null && !(await liveEnvironment(tx, parentId))) {
      throw new Refusal(
        conflict(`${project.slug}/${from} was archived or deleted meanwhile: it is no parent`),
        denied(ctx, 'environment.create', 'parent_archived', { projectId: project.id, metadata: { environmentSlug: slug, from } }),
      );
    }
    const id = randomUUID();
    try {
      await insert(tx, environments, { id, projectId: project.id, slug, name, parentId });
    } catch (error) {
      if (isUniqueViolation(error)) throw slugTaken('environment', slug);
      throw error;
    }
    log.push(allowed(ctx, 'environment.create', {
      projectId: project.id,
      environmentId: id,
      metadata: { slug, name, ...(from === undefined ? {} : { from }), ...(parentId === null ? {} : { inherits: from }) },
    }));
    return { environment: { slug, name, archivedAt: null }, created: true };
  });
}

/** What renaming or removing a folder did: the folder they are in now, none for a removal, and what moved. */
export type Refiled = { folder: string | null; moved: string[] };

/**
 * Rename a folder of projects, or take every project out of it (`to`
 * null): one transaction under the log's head, one `project.move` per
 * project. A folder is only a label, so renaming onto one that exists
 * merges the two. It takes `project.manage` on every project filed there;
 * refused otherwise, since a folder half renamed would be two folders.
 */
export async function refileProjects(ctx: ApiContext, folder: string, to: string | null): Promise<Refiled> {
  const operationId = randomUUID();
  return audited(ctx, async (tx, log) => {
    const filed = await projectsInFolder(tx, folder);
    // A folder none of whose projects the caller sees is, to them, no folder.
    const seen = filed.filter((project) => seesProject(ctx.caller, project));
    if (seen.length === 0) throw notFound(`no folder "${folder}" among your projects`);
    if (filed.some((project) => !can(ctx.caller, 'project.manage', { projectId: project.id }))) {
      throw new Refusal(
        forbidden(`renaming or removing the folder "${folder}" takes project.manage on every project in it`),
        denied(ctx, 'project.move', 'missing_project_manage', { operationId, metadata: { folder, to } }),
      );
    }
    if (to !== folder) {
      for (const project of filed) {
        await fileProject(tx, project.id, to);
        log.push(allowed(ctx, 'project.move', { projectId: project.id, operationId, metadata: { slug: project.slug, from: folder, to } }));
      }
    }
    return { folder: to, moved: filed.map((project) => project.slug) };
  });
}

/**
 * Rename, re-slug, archive or restore an environment. A new slug can bring
 * in those whose instance role is scoped to it, and take out those scoped
 * to the old one: scopes match environments by slug.
 */
export async function patchEnvironment(
  ctx: ApiContext,
  place: ResolvedPath,
  patch: PlacePatch,
): Promise<{ environment: PlaceView }> {
  const { project, environment } = place;
  if (environment === null) throw notFound('no such environment');
  const { renames, archivedAt } = placeChanges(environment, patch);
  const renamed = Object.keys(renames).length > 0;
  const scope = { projectId: project.id, environmentId: environment.id };
  return audited(ctx, async (tx, log) => {
    await stillThere(tx, place);
    if (archivedAt != null) await refuseIfRead(ctx, tx, `${project.slug}/${environment.slug}`, scope, 'environment.archive', scope);
    // A fork is restored only while every environment it inherits from is live.
    if (archivedAt === null && environment.parentId !== null) {
      const parents = await parentsOf(tx, environment.id);
      const gone = parents === null ? { slug: '(a chain made around coffre)', deleted: true } : parents.find((parent) => parent.archivedAt !== null || parent.deleted);
      if (gone !== undefined) {
        throw new Refusal(
          conflict(`${project.slug}/${environment.slug} inherits from ${project.slug}/${gone.slug}, which is ${gone.deleted ? 'deleted' : 'archived'}: restore that first`),
          denied(ctx, 'environment.restore', 'parent_archived', { ...scope, metadata: { parent: gone.slug } }),
        );
      }
    }
    // A live fork reads its parent's keys: archiving the parent would leave it half empty (docs/design/forking.md).
    const forks = archivedAt == null ? [] : (await forksOf(tx, environment.id)).map((fork) => fork.slug);
    if (forks.length > 0) {
      throw new Refusal(
        conflict(`${project.slug}/${environment.slug} is inherited by ${forks.map((fork) => `${project.slug}/${fork}`).join(', ')}: archive ${forks.length === 1 ? 'it' : 'them'} first`),
        denied(ctx, 'environment.archive', 'inherited', { ...scope, metadata: { forks } }),
      );
    }
    if (renamed || archivedAt !== undefined) {
      try {
        await update(tx, environments, { id: environment.id }, { ...renames, archivedAt });
      } catch (error) {
        if (!isUniqueViolation(error)) throw error;
        throw new Refusal(
          slugTaken('environment', renames.slug!),
          denied(ctx, 'environment.update', 'slug_taken', { ...scope, metadata: { slug: renames.slug } }),
        );
      }
    }
    if (renamed) {
      log.push(allowed(ctx, 'environment.update', {
        ...scope,
        metadata: { from: environment.slug, ...renames },
      }));
    }
    if (archivedAt !== undefined) {
      log.push(allowed(ctx, archivedAt === null ? 'environment.restore' : 'environment.archive', {
        ...scope,
        metadata: { environmentSlug: renames.slug ?? environment.slug },
      }));
    }
    return {
      environment: {
        slug: renames.slug ?? environment.slug,
        name: renames.name ?? environment.name,
        archivedAt: iso(archivedAt === undefined ? environment.archivedAt : archivedAt),
      },
    };
  });
}

/** What deleting a project or an environment takes, or took. */
export type Deletion = {
  /** `market` or `market/prod`, as it was named. */
  path: string;
  /** The slug its tombstone keeps, which frees the old one: `market~deleted-2026-10-05`. */
  tombstone: string;
  /** The environments it takes: a project's every one, or the one. */
  environments: string[];
  /** The keys named there. The tombstone keeps their names, never their values. */
  keys: number;
  /** The versions whose values it erases: each one's ciphertext and wrapped data key. */
  versions: number;
  /** The grants there, lapsed ones too, which the vault revokes. */
  grants: { member: string; place: string; role: string }[];
  /** The references into it from elsewhere, and out of it, which the vault ends: each holder, and the source it reads. */
  references: { holder: string; source: string }[];
  /** Members who hold nothing anywhere afterwards: a service among them may be offboarded. */
  stranded: string[];
};

export type DeletionResult = { dryRun: boolean; deletion: Deletion };

/**
 * Delete an archived project, or an archived environment, for good. Every
 * secret version under it is erased, its ciphertext and wrapped data key
 * emptied, the vault revokes every grant on it, and it leaves every list.
 * What stays is a tombstone with names only, the place's row and its keys'
 * and versions' rows, because the signed log names them, under a slug no
 * live place can hold, `market~deleted-2026-10-05`: the old one is free,
 * and what takes it next is never mistaken for it in the log. Backups taken
 * before still hold the encrypted values. Instance owners only; `dryRun`
 * says what it would take and changes nothing.
 *
 * The vault revokes the grants first, one call per member, and the app then
 * erases and renames in one transaction with its entry, under the log's
 * head: there it finds the place still archived and holding no grant and
 * no live reference, or refuses with a 409, a place restored meanwhile
 * kept, a grant set or a reference made meanwhile left for the next
 * attempt to revoke or end. Each step finds only what is left, so a
 * deletion cut off or refused between them finishes when asked again.
 * Once it commits, the vault grants nothing there.
 */
export async function deletePlace(ctx: ApiContext, place: ResolvedPath, { dryRun }: { dryRun: boolean }): Promise<DeletionResult> {
  const { project, environment } = place;
  const what = environment === null ? 'project' : 'environment';
  const action = `${what}.delete`;
  const path = environment === null ? project.slug : `${project.slug}/${environment.slug}`;
  const doomed: Doomed = { projectId: project.id, environmentId: environment?.id ?? null };
  const fields = { ...doomed, metadata: { path } };
  const notArchived = () => new Refusal(
    conflict(`${path} is not archived: \`coffre ${what === 'project' ? 'projects' : 'environments'} archive ${path}\` first`),
    denied(ctx, action, 'not_archived', fields),
  );
  // The place itself: an environment under an archived project is archived only once it is.
  const archived = (at: ResolvedPath) => (environment === null ? at.project.archivedAt : (at.environment?.archivedAt ?? null)) !== null;

  return withRefusals(ctx, async () => {
    requireInstance(ctx, action, fields, `delete ${what === 'project' ? 'a project' : 'an environment'} for good`);
    if (!archived(place)) throw notArchived();
    // A fork, archived or not, keeps its parent: deleted, it would leave the fork naming a tombstone forever.
    const forked = async (db: Queryable) => (environment === null ? [] : (await forksOf(db, environment.id, { archived: true })).map((fork) => fork.slug));
    const parentOf = (forks: string[]) => new Refusal(
      conflict(`${path} is the parent of ${forks.map((fork) => `${project.slug}/${fork}`).join(', ')}: delete ${forks.length === 1 ? 'it' : 'them'} first`),
      denied(ctx, action, 'inherited', { ...fields, metadata: { path, forks } }),
    );
    const forks = await forked(ctx.db);
    if (forks.length > 0) throw parentOf(forks);

    const [scope, references] = await Promise.all([deletionScope(ctx.db, doomed), referencesAt(ctx.db, doomed)]);
    const deletion = (tombstone: string, versions = scope.versions): Deletion => ({
      path,
      tombstone,
      environments: scope.environments.map((candidate) => candidate.slug),
      keys: scope.keys,
      versions,
      grants: scope.grants.map((grant) => ({
        member: grant.principal,
        place: grant.environmentId === null
          ? project.slug
          : `${project.slug}/${scope.environments.find((candidate) => candidate.id === grant.environmentId)?.slug ?? grant.environmentId}`,
        role: grant.role,
      })),
      references: references.map(({ view }) => ({ holder: view.holder, source: view.source })),
      stranded: scope.stranded,
    });
    const slug = environment?.slug ?? project.slug;
    const within = environment === null ? null : { projectId: project.id };
    if (dryRun) {
      return { dryRun: true, deletion: deletion(await tombstoneSlug(ctx.db, slug, new Date(), within)) };
    }

    const operationId = randomUUID();
    const byMember = new Map<string, typeof scope.grants>();
    for (const grant of scope.grants) byMember.set(grant.principal, [...(byMember.get(grant.principal) ?? []), grant]);
    for (const [principal, grants] of byMember) {
      const result = await ctx.vault.setAccess({
        actor: formatMember(ctx.caller.principal),
        principal,
        requestId: ctx.requestId,
        operationId,
        credentialId: ctx.provenance,
        credentialScope: ctx.caller.credentialScope,
        changes: grants.map((grant) => ({ projectId: grant.projectId, environmentId: grant.environmentId, role: null, expiresAt: null })),
      });
      if (!result.ok) throw vaultRefused(result.refusal);
    }
    // No reference follows a tombstone, nor holds one: one made meanwhile, the place restored and archived again, is found under the head.
    await endReferences(ctx, references, operationId);

    return audited(ctx, async (tx, log) => {
      // Again, under the log's head, which every change to a place takes first.
      const now = await resolvePath(tx, { project: project.slug, environment: environment?.slug });
      if (now === null || now.project.id !== project.id || (environment !== null && now.environment?.id !== environment.id)) {
        throw conflict(`${path} changed while it was being deleted: look again, and ask again`);
      }
      if (!archived(now)) {
        throw new Refusal(
          conflict(`${path} was restored while it was being deleted: nothing was erased, but the grants on it were revoked`),
          denied(ctx, action, 'restored', fields),
        );
      }
      const forksNow = await forked(tx);
      if (forksNow.length > 0) throw parentOf(forksNow);
      // A grant set there since the vault revoked them would outlive the place, named by no path that could revoke it.
      if ((await deletionScope(tx, doomed)).grants.length > 0) {
        throw new Refusal(
          conflict(`${path} was granted while it was being deleted: ask again, and that grant is revoked too`),
          denied(ctx, action, 'granted_meanwhile', fields),
        );
      }
      // Nor may a reference made there since the vault ended them: held in a tombstone, no path could break it, and its source could never be archived.
      if ((await referencesAt(tx, doomed)).length > 0) {
        throw new Refusal(
          conflict(`${path} was given a reference while it was being deleted: ask again, and that reference is ended too`),
          denied(ctx, action, 'referenced_meanwhile', fields),
        );
      }
      const tombstone = await tombstoneSlug(tx, slug, new Date(), within);
      const versions = await eraseVersions(tx, doomed);
      if (environment === null) await update(tx, projects, { id: project.id }, { slug: tombstone });
      else await update(tx, environments, { id: environment.id }, { slug: tombstone });
      const done = deletion(tombstone, versions);
      log.push(allowed(ctx, action, {
        ...doomed,
        operationId,
        metadata: { path, tombstone, keys: done.keys, versions, grants: done.grants.length, references: done.references.length },
      }));
      return { dryRun: false, deletion: done };
    });
  });
}
