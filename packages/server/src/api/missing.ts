import { randomUUID } from 'node:crypto';

import type { Transaction } from '@coffre/db';
import { dismissedKeys, secrets } from '@coffre/db/schema';

import { dismissalsAcross, dismissalsIn, keysAcross, lock, update, upsert, type ResolvedPath } from '../db/queries.ts';
import { allowed, audited, denied, Refusal, type ApiContext } from './context.ts';
import { ApiError, conflict, notFound } from './errors.ts';
import { inheritedRows, resolveKeys } from './inheritance.ts';
import { projectPlaces } from './render.ts';
import { checkEnvironment } from './secrets.ts';

/**
 * Missing keys: those the project's other environments have and this one
 * does not, with Add and Dismiss (docs/design/environments.md). Every
 * sibling is compared, read or not: within a project, key names are not
 * secret, only values are. Dismissals are the team's.
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
 * environments of its project, the dismissed apart: a reader of dev learns
 * that prod has `STRIPE_KEY`, never its value, and nothing of another project.
 * A key archived here is not missing: archiving it was a decision.
 *
 * Forks compare what they resolve to (docs/design/forking.md): a key a
 * fork inherits is no more missing there than in its parent, and one it
 * removed is a dismissal already. An environment is never missing a key
 * that only its own forks hold: `EU_REGION` in prod-eu does not flag prod.
 */
export async function missingKeys(ctx: ApiContext, place: ResolvedPath): Promise<{ missing: MissingKey[]; dismissed: DismissedKey[] }> {
  const here = live(place);
  const project = (await projectPlaces(ctx, here.projectId))!;
  const below = forksBelow(project.environments, here.environmentId);
  // Personal configs are nobody's siblings: theirs are no team's keys, and nobody else may learn what they hold.
  const others = project.environments.filter((environment) =>
    environment.id !== here.environmentId && environment.archivedAt === null && !below.has(environment.id) && environment.owner === null);
  const ids = project.environments.map((environment) => environment.id);
  const [keys, removed] = await Promise.all([keysAcross(ctx.db, ids, here.environmentId), dismissalsAcross(ctx.db, ids)]);
  const liveKeys = keys.filter((row) => row.archivedAt === null);
  const dismissals = removed.filter((row) => row.environmentId === here.environmentId);
  const resolved = resolveKeys(project.environments, liveKeys, removed);
  // A key archived here is held all the same.
  const has = new Set([...keys.filter((row) => row.environmentId === here.environmentId).map((row) => row.key), ...resolved.get(here.environmentId)!.keys()]);
  const found = new Map<string, { in: string[]; folders: Set<string | null> }>();
  for (const other of others) {
    for (const [key, held] of resolved.get(other.id)!) {
      if (has.has(key)) continue;
      const entry = found.get(key) ?? { in: [], folders: new Set() };
      entry.in.push(other.slug);
      entry.folders.add(held.folder);
      found.set(key, entry);
    }
  }
  const absent = [...found.entries()]
    .map(([key, entry]): MissingKey => ({ key, in: entry.in.sort(), folder: entry.folders.size === 1 ? [...entry.folders][0]! : null }))
    .sort((a, b) => (a.key < b.key ? -1 : 1));
  const dismissedBy = new Map(dismissals.map((row) => [row.key, row]));
  return {
    missing: absent.filter((entry) => !dismissedBy.has(entry.key)),
    // Only what is still missing: a dismissal of a key no sibling has any more is moot.
    dismissed: absent.flatMap((entry) => {
      const row = dismissedBy.get(entry.key);
      return row === undefined ? [] : [{ ...entry, dismissedBy: row.dismissedBy, dismissedAt: row.dismissedAt.toISOString() }];
    }),
  };
}

/**
 * In a fork, a dismissal removes a key it inherits. One it holds a live
 * value of is served whatever is dismissed, so removing it would say one
 * thing and do another: refused, under the head, which every write that
 * makes a row live holds too, so none lands between the check and the
 * removal.
 */
async function refuseOwnRemovals(ctx: ApiContext, tx: Transaction, place: ResolvedPath, keys: readonly string[], operationId: string): Promise<void> {
  if (keys.length === 0) return;
  const own = (await lock(tx, secrets, { projectId: place.project.id, environmentId: place.environment!.id, key: [...keys] })).filter((row) => row.archivedAt === null);
  if (own.length === 0) return;
  const held = (await inheritedRows(tx, place.environment!.id))?.held ?? new Map();
  const path = `${place.project.slug}/${place.environment!.slug}`;
  const [first] = own;
  const how = held.has(first!.key) ? `\`coffre reset ${path}/${first!.key}\` first, then remove it` : `\`coffre archive ${path}/${first!.key}\` takes it out`;
  throw new Refusal(
    conflict(`${path} holds ${own.map((row) => row.key).join(', ')} of its own, which removing would not stop it serving: ${how}`),
    denied(ctx, 'missing.dismiss', 'held_here', { projectId: place.project.id, environmentId: place.environment!.id, operationId, metadata: { keys: own.map((row) => row.key) } }),
  );
}

/** The environments below one, forks of its forks too, from each environment's parent. */
function forksBelow(environments: readonly { id: string; parentId: string | null }[], environmentId: string): Set<string> {
  const below = new Set<string>();
  for (let grew = true; grew;) {
    grew = false;
    for (const environment of environments) {
      if (environment.parentId === null || below.has(environment.id)) continue;
      if (environment.parentId !== environmentId && !below.has(environment.parentId)) continue;
      below.add(environment.id);
      grew = true;
    }
  }
  return below;
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
    if (place.environment!.parentId !== null) await refuseOwnRemovals(ctx, tx, place, Object.keys(patch).filter((key) => patch[key] === true), operationId);
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
