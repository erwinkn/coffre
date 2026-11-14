import { randomUUID } from 'node:crypto';

import { UNWRITTEN_FORK_MS } from '@coffre/core/access';
import type { Queryable, Transaction } from '@coffre/db';
import { isUniqueViolation } from '@coffre/db/dialect';
import { environments, projects } from '@coffre/db/schema';

import { deletionScope, eraseVersions, forksOf, insert, liveEnvironment, resolvePath, tombstoneSlug, update, type Doomed, type ResolvedPath } from '../db/queries.ts';
import { can, placeOf } from './caller.ts';
import { allowed, type ApiContext, audited, denied, missing, Refusal, requireInstance, through, vaultCredential, withRefusals } from './context.ts';
import { conflict, forbidden, notFound, vaultRefused } from './errors.ts';
import { formatMember } from './paths.ts';
import { protectedFor } from './roles.ts';
import { endReferences, referencesAt } from './references.ts';

// 0.14's places, what is left of them: deleting a place for good, and making a fork's environment
// (forks.ts), the source for those changes until the vault makes them. Lists and every other change of a
// project or an environment are served on the 0.16 contract (routes/places.ts).

const iso = (value: Date | null) => value?.toISOString() ?? null;

export type PlaceView = {
  slug: string;
  /** @deprecated A place goes by its slug since 0.6.2; kept for older CLIs, which print it. */
  name: string;
  archivedAt: string | null;
};
/** An environment's: whether it is protected too, a personal config as its parent is. */
export type EnvironmentView = PlaceView & { protected: boolean };

function slugTaken(what: 'project' | 'environment', slug: string): Error {
  return conflict(`a ${what} named "${slug}" already exists`);
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
  {
    from,
    parentId = null,
    id = randomUUID(),
    protectedAt,
  }: {
    from?: string;
    parentId?: string | null;
    /** Its id, made before it is: a fork's, which the vault protects first (`protectIds`), the request going on as of that. */
    id?: string;
    /** When the vault protected that id, for a fork of a protected environment. */
    protectedAt?: number;
  } = {},
): Promise<{ environment: EnvironmentView; created: boolean }> {
  const { project, environment } = place;
  const name = input.name ?? slug;
  if (environment !== null) {
    const existing = { slug, name: environment.name, archivedAt: iso(environment.archivedAt), protected: protectedFor(ctx.caller, environment) };
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
    // A protected fork's row comes well within the ten minutes the policy keeps its id without one (`UNWRITTEN_FORK_MS`): later,
    // the policy may have dropped it, and the row would protect it again with no change any request is fenced on.
    if (protectedAt !== undefined && Date.now() - protectedAt > UNWRITTEN_FORK_MS / 2) {
      throw conflict(`${project.slug}/${slug} took too long to fork: fork again`);
    }
    // The parent too: archived or deleted since the fork checked it, it is no parent.
    if (parentId !== null && !(await liveEnvironment(tx, parentId))) {
      throw new Refusal(
        conflict(`${project.slug}/${from} was archived or deleted meanwhile: it is no parent`),
        denied(ctx, 'environment.create', 'parent_archived', { projectId: project.id, metadata: { environmentSlug: slug, from } }),
      );
    }
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
    return { environment: { slug, name, archivedAt: null, protected: protectedFor(ctx.caller, { id }) }, created: true };
  });
}

/**
 * Delete a personal config for good: its owner may, and the project's
 * maintainers (`environment.manage`), which is how offboarding cleans up.
 * It need not be archived first, and holds no grant or reference to undo:
 * its values are erased and its slug made a tombstone, as any place's.
 */
async function deletePersonal(ctx: ApiContext, place: ResolvedPath, { dryRun }: { dryRun: boolean }): Promise<DeletionResult> {
  const { project, environment } = place;
  const config = environment!;
  const path = `${project.slug}/${config.parentSlug ?? '?'}@${config.owner!.replace(/^user:/, '')}`;
  const doomed: Doomed = { projectId: project.id, environmentId: config.id };
  return withRefusals(ctx, async () => {
    const theirs = ctx.caller.principal.type === 'user' && formatMember(ctx.caller.principal) === config.owner;
    if (!theirs && !can(ctx.caller, 'environment.manage', placeOf(project, null))) {
      throw new Refusal(
        forbidden(`a personal config is deleted by its owner, or by whoever manages ${project.slug}'s environments`),
        denied(ctx, 'environment.delete', missing('environment.manage'), { ...doomed, metadata: { path } }),
      );
    }
    const scope = await deletionScope(ctx.db, doomed);
    const deletion = (tombstone: string, versions = scope.versions): Deletion => ({
      path, tombstone, environments: [config.slug], keys: scope.keys, versions, grants: [], references: [], stranded: [],
    });
    if (dryRun) return { dryRun: true, deletion: deletion(await tombstoneSlug(ctx.db, config.slug, new Date(), { projectId: project.id })) };
    const operationId = randomUUID();
    return audited(ctx, async (tx, log) => {
      const now = await resolvePath(tx, { project: project.slug, environment: config.slug });
      if (now?.environment?.id !== config.id) throw conflict(`${path} changed while it was being deleted: look again, and ask again`);
      const erased = await erasePersonal(ctx, tx, doomed, config.slug, operationId, { path });
      log.push(erased.entry);
      return { dryRun: false, deletion: deletion(erased.tombstone, erased.versions) };
    });
  });
}

/** Erase a personal config's values and make its slug a tombstone, under the head: the entry that says so. */
async function erasePersonal(ctx: ApiContext, tx: Transaction, doomed: Doomed, slug: string, operationId: string, metadata: Record<string, unknown>) {
  const tombstone = await tombstoneSlug(tx, slug, new Date(), { projectId: doomed.projectId });
  const versions = await eraseVersions(tx, doomed);
  await update(tx, environments, { id: doomed.environmentId! }, { slug: tombstone });
  return { tombstone, versions, entry: allowed(ctx, 'environment.delete', { ...doomed, operationId, metadata: { ...metadata, personal: true, tombstone, versions } }) };
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

  if (environment?.owner != null) return deletePersonal(ctx, place, { dryRun });
  return withRefusals(ctx, async () => {
    requireInstance(ctx, action, fields, `delete ${what === 'project' ? 'a project' : 'an environment'} for good`);
    if (!archived(place)) throw notArchived();
    // A fork, archived or not, keeps its parent: deleted, it would leave the fork naming a tombstone forever.
    // A personal config does not: it is deleted with it.
    const forked = async (db: Queryable) => (environment === null ? [] : (await forksOf(db, environment.id, { archived: true })).filter((fork) => fork.owner === null).map((fork) => fork.slug));
    const parentOf = (forks: string[]) => new Refusal(
      conflict(`${path} is the parent of ${forks.map((fork) => `${project.slug}/${fork}`).join(', ')}: delete ${forks.length === 1 ? 'it' : 'them'} first`),
      denied(ctx, action, 'inherited', { ...fields, metadata: { path, forks } }),
    );
    const forks = await forked(ctx.db);
    if (forks.length > 0) throw parentOf(forks);

    const [scope, references] = await Promise.all([deletionScope(ctx.db, doomed), referencesAt(ctx.db, doomed)]);
    // An environment's personal configs go with it: what they erase is counted with it, each named by whose it is.
    const personal = environment === null ? [] : (await forksOf(ctx.db, environment.id, { archived: true })).filter((fork) => fork.owner !== null);
    const personalScopes = await Promise.all(personal.map((config) => deletionScope(ctx.db, { projectId: project.id, environmentId: config.id })));
    const personalKeys = personalScopes.reduce((sum, each) => sum + each.keys, 0);
    const personalVersions = personalScopes.reduce((sum, each) => sum + each.versions, 0);
    const deletion = (tombstone: string, versions = scope.versions + personalVersions): Deletion => ({
      path,
      tombstone,
      environments: [
        ...scope.environments.map((candidate) => candidate.slug),
        ...personal.map((config) => `${environment!.slug}@${config.owner!.replace(/^user:/, '')}`),
      ],
      keys: scope.keys + personalKeys,
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
        credentialId: vaultCredential(ctx),
        ...through(ctx.caller),
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
      let versions = await eraseVersions(tx, doomed);
      if (environment === null) await update(tx, projects, { id: project.id }, { slug: tombstone });
      else await update(tx, environments, { id: environment.id }, { slug: tombstone });
      // Its personal configs with it: none outlives the environment it is a config of.
      const configs = environment === null ? [] : (await forksOf(tx, environment.id, { archived: true })).filter((fork) => fork.owner !== null);
      for (const config of configs) {
        const erased = await erasePersonal(ctx, tx, { projectId: project.id, environmentId: config.id }, config.slug, operationId, { path, with: environment!.slug });
        versions += erased.versions;
        log.push(erased.entry);
      }
      const done = deletion(tombstone, versions);
      log.push(allowed(ctx, action, {
        ...doomed,
        operationId,
        metadata: { path, tombstone, keys: done.keys, versions, grants: done.grants.length, references: done.references.length, ...(configs.length === 0 ? {} : { personal: configs.length }) },
      }));
      return { dryRun: false, deletion: done };
    });
  });
}
