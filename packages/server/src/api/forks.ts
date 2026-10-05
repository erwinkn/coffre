import { randomUUID } from 'node:crypto';

import { environmentSecrets, resolvePath, type ResolvedPath } from '../db/queries.ts';
import { can, placeOf } from './caller.ts';
import { asking, audited, need, withRefusals, type ApiContext } from './context.ts';
import { conflict, notFound, vaultRefused } from './errors.ts';
import { fileSecrets, secretFoldersIn } from './folders.ts';
import { openValues } from './keys.ts';
import { putEnvironment, type InheritedGrant, type PlaceView } from './projects.ts';
import { currentReferences, placeOfRow, readableValues, requireReferences } from './references.ts';
import { checkEnvironment, setSecrets, type SecretValue } from './secrets.ts';

/**
 * What a fork did: the environment it forked, how many keys it made, how
 * many of them references, and which it copied where references were asked
 * for: a key whose source the forker reads only through the parent.
 */
export type Forked = { from: string; keys: number; references: number; copied: string[] };

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
  input: { name: string; from: string; references: boolean },
): Promise<{ environment: PlaceView; created: boolean; inherited: InheritedGrant[]; forked: Forked }> {
  const { project } = place;
  const { from } = input;
  return withRefusals(ctx, async () => {
    if (from === slug) throw conflict('an environment cannot be forked into itself');
    const source = await resolvePath(ctx.db, { project: project.slug, environment: from });
    if (source?.environment == null || source.project.archivedAt !== null || source.environment.archivedAt !== null) {
      throw notFound(`${project.slug} has no environment ${from} to fork`);
    }
    if (input.references) await requireReferences(ctx.db);
    const sourcePlace = { projectId: project.id, environmentId: source.environment.id };
    need(ctx, 'secret.read', placeOf(project, source.environment), 'environment.fork', { metadata: { from, slug } });
    if (place.environment !== null) {
      if (place.environment.archivedAt !== null) throw conflict(`${project.slug}/${slug} is archived; restore it before forking into it`);
      const live = (await environmentSecrets(ctx.db, place.environment.id)).filter((secret) => secret.archivedAt === null);
      if (live.length > 0) throw conflict(`${project.slug}/${slug} already has secrets: a fork goes into a new or empty environment`);
    }
    // What the fork reads, checked before anything is made: a reference that cannot be read stops it.
    const readable = await readableValues(ctx.db, source, sourcePlace);
    if (readable.unreadable.length > 0) throw conflict(readable.unreadable.join('; '));
    const plan = input.references ? await referencesFor(ctx, readable.items.map((item) => item.key), source) : new Map<string, string>();

    const { environment, created, inherited } = await putEnvironment(ctx, place, slug, { name: input.name }, { from });
    const copies = readable.items.filter((item) => !plan.has(item.key));
    const opened = await openValues(ctx.vault, { ...asking(ctx, randomUUID()), purpose: 'copy' }, copies);
    if (!opened.ok) throw vaultRefused(opened.refusal);
    // A null-prototype record: a key named __proto__ is a key like any other.
    const patch: Record<string, SecretValue> = Object.create(null);
    copies.forEach((item, i) => (patch[item.key] = opened.values[i]!));
    for (const [key, path] of plan) patch[key] = { ref: path };
    const forked = { from, keys: readable.items.length, references: plan.size, copied: input.references ? copies.map((item) => item.key) : [] };
    if (readable.items.length === 0) return { environment, created, inherited, forked };

    const target = await resolvePath(ctx.db, { project: project.slug, environment: slug });
    if (target?.environment == null) throw notFound(`${project.slug}/${slug} went away while it was being forked`);
    await setSecrets(ctx, target, { ...patch });

    // Each key keeps its folder.
    const sourceRows = await environmentSecrets(ctx.db, source.environment.id);
    const folders = await secretFoldersIn(ctx.db, source.environment.id);
    const filed = sourceRows.flatMap((row) => {
      const folder = folders.get(row.id);
      return folder === undefined || !(row.key in patch) ? [] : [{ key: row.key, folder }];
    });
    if (filed.length > 0) {
      const ids = new Map((await environmentSecrets(ctx.db, target.environment.id)).map((secret) => [secret.key, secret.id]));
      await audited(ctx, async (tx) => {
        // Under the head, as every write to a place: the new environment may have gone since the copy.
        await checkEnvironment(tx, target, { projectId: project.id, environmentId: target.environment!.id });
        await fileSecrets(tx, filed.map(({ key, folder }) => ({ secretId: ids.get(key)!, folder })), ctx.caller.principal.id);
      });
    }
    return { environment, created, inherited, forked };
  });
}

/**
 * The source each key of a fork as references points at, by path: the
 * parent's key, or that key's own source when it is a reference, one hop.
 * Only where the forker reads that source by their own grants: reading it
 * through the parent is no read on it for making a reference. The rest are
 * copied.
 */
async function referencesFor(ctx: ApiContext, keys: readonly string[], parent: ResolvedPath): Promise<Map<string, string>> {
  const rows = (await environmentSecrets(ctx.db, parent.environment!.id)).filter((row) => keys.includes(row.key));
  const held = await currentReferences(ctx.db, rows.filter((row) => row.current === null).map((row) => row.id));
  const plan = new Map<string, string>();
  for (const row of rows) {
    const reference = held.get(row.id);
    if (reference === undefined) {
      plan.set(row.key, `${parent.project.slug}/${parent.environment!.slug}/${row.key}`);
      continue;
    }
    const source = reference.source!;
    if (can(ctx.caller, 'secret.read', placeOfRow(source))) plan.set(row.key, reference.view.source);
  }
  return plan;
}
