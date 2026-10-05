import { randomUUID } from 'node:crypto';

import { dismissedKeys } from '@coffre/db/schema';

import { dismissalsIn, environmentSecrets, liveKeysIn, places, secretFolderOf, update, upsert, type ResolvedPath } from '../db/queries.ts';
import { can, placeOf } from './caller.ts';
import { allowed, audited, type ApiContext } from './context.ts';
import { ApiError, notFound } from './errors.ts';
import { checkEnvironment } from './secrets.ts';

/**
 * Missing keys: those the project's other environments have and this one
 * does not, with Add and Dismiss (docs/design/environments.md). Key names
 * are metadata, so only environments the caller reads are compared.
 * Dismissals are the team's.
 */

/** A key missing here: the environments that have it, and its folder there, when they agree. */
export type MissingKey = { key: string; in: string[]; folder: string | null };

/** A missing key the team dismissed, and who and when. */
export type DismissedKey = MissingKey & { dismissedBy: string; dismissedAt: string };

function live(place: ResolvedPath): { projectId: string; environmentId: string } {
  if (place.project.archivedAt !== null || place.environment === null || place.environment.archivedAt !== null) {
    throw notFound('unknown project or environment');
  }
  return { projectId: place.project.id, environmentId: place.environment.id };
}

/**
 * What this environment lacks of the live keys in the other live
 * environments of its project that the caller reads, the dismissed apart.
 * A key archived here is not missing: archiving it was a decision.
 */
export async function missingKeys(ctx: ApiContext, place: ResolvedPath): Promise<{ missing: MissingKey[]; dismissed: DismissedKey[] }> {
  const here = live(place);
  const project = (await places(ctx.db)).find((each) => each.id === here.projectId)!;
  const others = project.environments.filter((environment) =>
    environment.id !== here.environmentId && environment.archivedAt === null
    && can(ctx.caller, 'secret.read', placeOf(project, environment)));
  const [present, elsewhere, dismissals] = await Promise.all([
    environmentSecrets(ctx.db, here.environmentId),
    liveKeysIn(ctx.db, others.map((environment) => environment.id)),
    dismissalsIn(ctx.db, here.environmentId),
  ]);
  const folders = new Map<string, string>();
  for (const environment of others) for (const [id, folder] of await secretFolderOf(ctx.db, environment.id)) folders.set(id, folder);
  const slugOf = new Map(others.map((environment) => [environment.id, environment.slug]));
  const has = new Set(present.map((secret) => secret.key));
  const found = new Map<string, { in: string[]; folders: Set<string | null> }>();
  for (const secret of elsewhere) {
    if (has.has(secret.key)) continue;
    const entry = found.get(secret.key) ?? { in: [], folders: new Set() };
    entry.in.push(slugOf.get(secret.environmentId)!);
    entry.folders.add(folders.get(secret.id) ?? null);
    found.set(secret.key, entry);
  }
  const keys = [...found.entries()]
    .map(([key, entry]): MissingKey => ({ key, in: entry.in.sort(), folder: entry.folders.size === 1 ? [...entry.folders][0]! : null }))
    .sort((a, b) => (a.key < b.key ? -1 : 1));
  const dismissedBy = new Map(dismissals.map((row) => [row.key, row]));
  return {
    missing: keys.filter((entry) => !dismissedBy.has(entry.key)),
    // Only what is still missing from somewhere you read: a name from elsewhere is not yours to learn here.
    dismissed: keys.flatMap((entry) => {
      const row = dismissedBy.get(entry.key);
      return row === undefined ? [] : [{ ...entry, dismissedBy: row.dismissedBy, dismissedAt: row.dismissedAt.toISOString() }];
    }),
  };
}

/** What a dismissal patch did to each key it named. */
export type DismissalOutcome = 'dismissed' | 'restored' | 'unchanged';

/**
 * Dismiss keys (`true`) or restore them (`null`), as a merge patch: "Dismiss
 * all" is one call, one operation, an entry per key. Shared by the team:
 * stored, logged, and listed until restored.
 */
export async function setDismissals(
  ctx: ApiContext,
  place: ResolvedPath,
  patch: Record<string, true | null>,
): Promise<{ operationId: string; keys: Record<string, DismissalOutcome> }> {
  const here = live(place);
  const operationId = randomUUID();
  return audited(ctx, async (tx, log) => {
    // Under the head, as every write to a place: one archived or deleted since the router found it takes no dismissal.
    await checkEnvironment(tx, place, here);
    const before = new Set((await dismissalsIn(tx, here.environmentId)).map((row) => row.key));
    const now = new Date();
    const by = ctx.caller.principal.id;
    const keys: Record<string, DismissalOutcome> = {};
    for (const [key, value] of Object.entries(patch)) {
      if ((value === true) === before.has(key)) {
        keys[key] = 'unchanged';
        continue;
      }
      if (value === true) {
        await upsert(tx, dismissedKeys, [{ environmentId: here.environmentId, key, dismissedAt: now, dismissedBy: by, restoredAt: null, restoredBy: null }], {
          target: ['environmentId', 'key'],
          columns: ['dismissedAt', 'dismissedBy', 'restoredAt', 'restoredBy'],
        });
      } else {
        await update(tx, dismissedKeys, { environmentId: here.environmentId, key }, { restoredAt: now, restoredBy: by });
      }
      keys[key] = value === true ? 'dismissed' : 'restored';
      log.push(allowed(ctx, value === true ? 'missing.dismiss' : 'missing.restore', { ...here, operationId, metadata: { key } }));
    }
    return { operationId, keys };
  });
}
