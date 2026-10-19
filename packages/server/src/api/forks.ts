import { randomUUID } from 'node:crypto';

import { environmentSecrets, fileSecrets, MAX_PARENTS, parentsOf, resolvePath, type ResolvedPath } from '../db/queries.ts';
import { can, placeOf } from './caller.ts';
import { asking, audited, need, withRefusals, type ApiContext } from './context.ts';
import { badRequest, conflict, forbidden, notFound, vaultRefused } from './errors.ts';
import { openValues, plain } from './keys.ts';
import { putEnvironment, type EnvironmentView } from './projects.ts';
import { protectedFor, protectIds, rowWritten } from './roles.ts';
import { protectedSources, readableValues, resolveValues, unreadParents, type Readable } from './references.ts';
import { checkEnvironment, setSecrets, type SecretValue } from './secrets.ts';

/**
 * What a fork did: the environment it forked, how many keys it made, how
 * many of them references, and which it copied where references were asked
 * for: a key whose source the forker reads only through the parent.
 */
export type Forked = { from: string; keys: number; references: number; copied: string[]; inherits: boolean };

/**
 * Fork `from` into `slug`, a new environment of the same project: each
 * live key of `from`, with its folder, and none of its history
 * (docs/design/environments.md, "Forks").
 *
 * By default each key is a copy of its current value. Copying is reading:
 * the caller needs read on `from`, and the vault logs one `secret.read` per
 * key, with the purpose `copy`, then the writes, as any write. With
 * `references`, each key is a reference to its parent's key instead, or,
 * where that key is itself a reference, to its source, one hop: the forker
 * needs their own read on each source, and a key whose source they read
 * only through the parent is copied, and named in `copied`.
 *
 * The environment is created first, since the vault's entries for the new
 * keys name it; a fork that stops after that leaves it empty, and forking
 * into an existing environment with no live secrets fills it, so running
 * the same fork again finishes it.
 */
export async function forkEnvironment(
  ctx: ApiContext,
  place: ResolvedPath,
  slug: string,
  input: { name?: string; from: string; references: boolean; inherit: boolean },
): Promise<{ environment: EnvironmentView; created: boolean; forked: Forked }> {
  const { project } = place;
  const { from } = input;
  return withRefusals(ctx, async () => {
    if (from === slug) throw conflict('an environment cannot be forked into itself');
    if (input.inherit && input.references) throw badRequest('a fork inherits its parent, or holds references to it: not both');
    const source = await resolvePath(ctx.db, { project: project.slug, environment: from });
    if (source?.environment == null || source.project.archivedAt !== null || source.environment.archivedAt !== null) {
      throw notFound(`${project.slug} has no environment ${from} to fork`);
    }
    // A personal config's values are its owner's alone: nobody forks one, not even its owner.
    if (source.environment.owner !== null) throw conflict(`${project.slug}/${from} is a personal config: fork the environment it is a config of`);
    const sourcePlace = { projectId: project.id, environmentId: source.environment.id };
    need(ctx, 'secret.read', placeOf(project, source.environment), 'environment.fork', { metadata: { from, slug } });
    if (input.inherit) return inheritFrom(ctx, place, slug, source, input.name);
    if (place.environment !== null) {
      if (place.environment.archivedAt !== null) throw conflict(`${project.slug}/${slug} is archived; restore it before forking into it`);
      // Filled, a fork that inherits would be neither a copy nor a fork of what it inherits.
      if (place.environment.parentId !== null) throw conflict(`${project.slug}/${slug} inherits from another environment: a fork goes into a new or empty one that inherits nothing`);
      const live = (await environmentSecrets(ctx.db, place.environment.id)).filter((secret) => secret.archivedAt === null);
      if (live.length > 0) throw conflict(`${project.slug}/${slug} already has secrets: a fork goes into a new or empty environment`);
    }
    // What the fork reads, checked before anything is made: a reference that cannot be read stops it.
    const readable = protectedSources(ctx.caller, await readableValues(ctx.db, source, sourcePlace));
    const unread = unreadParents(ctx, project.id, readable);
    if (unread.size > 0) {
      const which = [...unread].map(([parent, keys]) => `${keys.join(', ')} from ${project.slug}/${parent}`);
      throw forbidden(`${project.slug}/${from} inherits ${which.join('; ')}, which you cannot read`);
    }
    if (readable.unreadable.length > 0) throw conflict(readable.unreadable.map((unread) => unread.reason).join('; '));
    const plan = input.references ? referencesFor(ctx, readable.items) : new Map<string, string>();

    // From here, as of the protection it made, if any: each transaction below commits only while that is the newest change.
    const { ctx: protecting, id, protectedAt } = await protectedFork(ctx, place, source);
    const { environment, created } = await putEnvironment(protecting, place, slug, { name: input.name }, { from, id, protectedAt });
    const forking = rowWritten(protecting, id, slug);
    const copies = readable.items.filter((item) => !plan.has(item.key));
    // It keeps a sensitive value sensitive in its copy (below), and says so: the vault opens one to copy for no app that does not.
    const opened = await openValues(forking.vault, { ...asking(forking, randomUUID()), purpose: 'copy', keepsSensitive: true }, copies);
    if (!opened.ok) throw vaultRefused(opened.refusal);
    // A null-prototype record: a key named __proto__ is a key like any other.
    const patch: Record<string, SecretValue> = Object.create(null);
    // A copy is held as its value was: a plain one stays plain, its forker having read it as anyone who lists its
    // environment does, and a sensitive one sensitive, its forker never handed it.
    copies.forEach((item, i) => (patch[item.key] = plain(item) ? { value: opened.values[i]!, plain: true }
      : item.secret.sensitive === true ? { value: opened.values[i]!, sensitivity: 'sensitive' } : opened.values[i]!));
    for (const [key, path] of plan) patch[key] = { ref: path };
    const forked = { from, keys: readable.items.length, references: plan.size, copied: input.references ? copies.map((item) => item.key) : [], inherits: false };
    if (readable.items.length === 0) return { environment, created, forked };

    const target = await resolvePath(ctx.db, { project: project.slug, environment: slug });
    if (target?.environment == null) throw notFound(`${project.slug}/${slug} went away while it was being forked`);
    // Each copied key still reads what was opened, `from` resolved again under the head the copy is written under:
    // the same version, through the same reference, held in the same environment. A key written, marked sensitive,
    // retargeted or overridden since it was opened would be copied as it was, and held looser than it is. The
    // version says its level too: a mark is a new version. One left unprotected, as its source was when the caller was
    // loaded, is written only while still so (`audited`): or the values stay where they were.
    await setSecrets(forking, target, { ...patch }, async (tx) => {
      const now = new Map((await resolveValues(tx, source, sourcePlace)).items.map((item) => [item.key, item]));
      const moved = copies.find((item) => {
        const current = now.get(item.key);
        return current?.secretVersionId !== item.secretVersionId || current.via?.reference !== item.via?.reference
          || current.parent?.environmentId !== item.parent?.environmentId;
      });
      if (moved !== undefined) throw conflict(`${project.slug}/${from}/${moved.key} changed while it was forked: fork again, into the same environment`);
    });

    // Each key keeps its folder, where it is held: an inherited key, its parent's.
    const filed = readable.items.flatMap(({ key, folder }) => (folder === null || !(key in patch) ? [] : [{ key, folder }]));
    if (filed.length > 0) {
      const ids = new Map((await environmentSecrets(ctx.db, target.environment.id)).map((secret) => [secret.key, secret.id]));
      await audited(forking, async (tx) => {
        // Under the head, as every write to a place: the new environment may have gone since the copy.
        await checkEnvironment(tx, target, { projectId: project.id, environmentId: target.environment!.id });
        await fileSecrets(tx, filed.map(({ key, folder }) => ({ secretId: ids.get(key)!, folder })));
      });
    }
    return { environment, created, forked };
  });
}

/**
 * A fork that inherits: a new environment whose keys are its parent's,
 * read live, until it sets or removes its own (docs/design/forking.md).
 * Nothing is copied or read now. Its parent is set once, here, and a chain
 * stops at `MAX_PARENTS`.
 */
async function inheritFrom(
  ctx: ApiContext,
  place: ResolvedPath,
  slug: string,
  parent: ResolvedPath,
  name: string | undefined,
): Promise<{ environment: EnvironmentView; created: boolean; forked: Forked }> {
  const from = parent.environment!.slug;
  if (place.environment !== null) throw conflict(`${place.project.slug}/${slug} already exists: a fork that inherits is a new environment`);
  const above = await parentsOf(ctx.db, parent.environment!.id);
  if (above === null || above.length >= MAX_PARENTS) {
    throw conflict(`${place.project.slug}/${from} already inherits from ${MAX_PARENTS} environments: fork one higher up`);
  }
  const { ctx: forking, id, protectedAt } = await protectedFork(ctx, place, parent);
  const { environment, created } = await putEnvironment(forking, place, slug, { name }, { from, parentId: parent.environment!.id, id, protectedAt });
  return { environment, created, forked: { from, keys: 0, references: 0, copied: [], inherits: true } };
}

/**
 * A fork of a protected environment is protected from its first moment
 * (docs/design/roles.md): the vault protects its id, made here for one not
 * there yet, before its row is written or a value copied into it. A
 * refusal stops the fork with nothing made. The request as of that, and
 * the id. One left unprotected, as its source was for the caller, is
 * written, and its values copied, only while no policy change came since
 * (`audited`): its source protected meanwhile, the fork would not be.
 */
async function protectedFork(ctx: ApiContext, place: ResolvedPath, source: ResolvedPath): Promise<{ ctx: ApiContext; id?: string; protectedAt?: number }> {
  if (!protectedFor(ctx.caller, source.environment!)) return { ctx };
  const id = place.environment?.id ?? randomUUID();
  const protectedAt = Date.now();
  return { ctx: await protectIds(ctx, place.project.id, [id]), id, protectedAt };
}

/**
 * The source each key of a fork as references points at, by path: where
 * its value is held, the parent's key, a key the parent inherits, or a
 * reference's source, one hop. Only where the forker reads that source by
 * their own grants: reading it through the parent is no read on it for
 * making a reference. The rest are copied.
 */
function referencesFor(ctx: ApiContext, items: readonly Readable[]): Map<string, string> {
  const plan = new Map<string, string>();
  for (const { key, secret } of items) {
    const at = { projectId: secret.projectId, environmentId: secret.environmentId, environmentSlug: secret.path.split('/')[1]! };
    if (can(ctx.caller, 'secret.read', at)) plan.set(key, secret.path);
  }
  return plan;
}
