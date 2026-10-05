import { randomUUID } from 'node:crypto';

import { environmentSecrets, resolvePath, type ResolvedPath } from '../db/queries.ts';
import { placeOf } from './caller.ts';
import { asking, audited, need, withRefusals, type ApiContext } from './context.ts';
import { conflict, notFound, vaultRefused } from './errors.ts';
import { fileSecrets, secretFoldersIn } from './folders.ts';
import { openValues } from './keys.ts';
import { putEnvironment, type InheritedGrant, type PlaceView } from './projects.ts';
import { checkEnvironment, currentEnvelopes, secretRef, setSecrets } from './secrets.ts';

/** What a fork did: the environment it forked, and how many keys it copied. */
export type Forked = { from: string; keys: number };

/**
 * Fork `from` into `slug`, a new environment of the same project: each
 * live key of `from`, with its current value and folder, and none of its
 * history (docs/design/environments.md, "Forks").
 *
 * Copying is reading: the caller needs read on `from`, and the vault logs
 * one `secret.read` per key, with the purpose `copy`, then the writes, as
 * any write. The environment is created first, since the vault's entries
 * for the new keys name it; a fork that stops after that leaves it empty,
 * and forking into an existing environment with no live secrets fills it,
 * so running the same fork again finishes it.
 */
export async function forkEnvironment(
  ctx: ApiContext,
  place: ResolvedPath,
  slug: string,
  input: { name: string; from: string },
): Promise<{ environment: PlaceView; created: boolean; inherited: InheritedGrant[]; forked: Forked }> {
  const { project } = place;
  const { from } = input;
  return withRefusals(ctx, async () => {
    if (from === slug) throw conflict('an environment cannot be forked into itself');
    const source = await resolvePath(ctx.db, { project: project.slug, environment: from });
    if (source?.environment == null || source.project.archivedAt !== null || source.environment.archivedAt !== null) {
      throw notFound(`${project.slug} has no environment ${from} to fork`);
    }
    const sourcePlace = { projectId: project.id, environmentId: source.environment.id };
    need(ctx, 'secret.read', placeOf(project, source.environment), 'environment.fork', { metadata: { from, slug } });
    if (place.environment !== null) {
      if (place.environment.archivedAt !== null) throw conflict(`${project.slug}/${slug} is archived; restore it before forking into it`);
      const live = (await environmentSecrets(ctx.db, place.environment.id)).filter((secret) => secret.archivedAt === null);
      if (live.length > 0) throw conflict(`${project.slug}/${slug} already has secrets: a fork goes into a new or empty environment`);
    }

    const { environment, created, inherited } = await putEnvironment(ctx, place, slug, { name: input.name }, { from });
    const rows = await currentEnvelopes(ctx.db, source.environment.id);
    if (rows.length === 0) return { environment, created, inherited, forked: { from, keys: 0 } };

    const opened = await openValues(
      ctx.vault,
      { ...asking(ctx, randomUUID()), purpose: 'copy' },
      rows.map((row) => ({
        secretVersionId: row.secretVersionId,
        secret: secretRef(source, sourcePlace, { id: row.secretId, key: row.key }, row.version),
        envelope: row.envelope,
      })),
    );
    if (!opened.ok) throw vaultRefused(opened.refusal);
    // A null-prototype record: a key named __proto__ is a key like any other.
    const values: Record<string, string> = Object.create(null);
    rows.forEach((row, i) => (values[row.key] = opened.values[i]));

    const target = await resolvePath(ctx.db, { project: project.slug, environment: slug });
    if (target?.environment == null) throw notFound(`${project.slug}/${slug} went away while it was being forked`);
    await setSecrets(ctx, target, { ...values });

    // Each key keeps its folder.
    const folders = await secretFoldersIn(ctx.db, source.environment.id);
    const filed = rows.flatMap((row) => {
      const folder = folders.get(row.secretId);
      return folder === undefined ? [] : [{ key: row.key, folder }];
    });
    if (filed.length > 0) {
      const ids = new Map((await environmentSecrets(ctx.db, target.environment.id)).map((secret) => [secret.key, secret.id]));
      await audited(ctx, async (tx) => {
        // Under the head, as every write to a place: the new environment may have gone since the copy.
        await checkEnvironment(tx, target, { projectId: project.id, environmentId: target.environment!.id });
        await fileSecrets(tx, filed.map(({ key, folder }) => ({ secretId: ids.get(key)!, folder })), ctx.caller.principal.id);
      });
    }
    return { environment, created, inherited, forked: { from, keys: rows.length } };
  });
}
