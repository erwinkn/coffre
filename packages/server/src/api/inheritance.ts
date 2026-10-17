import type { Queryable } from '@coffre/db';

import { dismissalsIn, environmentSecrets, forksOf, MAX_PARENTS, parentsOf, type ParentRow, type SecretRow } from '../db/queries.ts';

/**
 * Forks, by key name alone (docs/design/forking.md): what an environment
 * inherits, overrides and removes. A key is settled by the nearest
 * environment of the chain that holds it live or removed it, a dismissal;
 * `readableValues` follows the same rule for values.
 */

/** Where a key an environment resolves to is held: its own environment, or a parent. */
export type Held = { environmentId: string; folder: string | null };

/**
 * Each environment's keys, its own live ones and those it inherits, from
 * every environment's live keys and dismissals at once: the missing-keys
 * comparison and the project list's counts. A chain that loops, written
 * around the app, is followed no further than `MAX_PARENTS`; a read of it
 * refuses.
 */
export function resolveKeys(
  environments: readonly { id: string; parentId: string | null }[],
  live: readonly { environmentId: string; key: string; folder: string | null }[],
  dismissed: readonly { environmentId: string; key: string }[],
): Map<string, Map<string, Held>> {
  const parentOf = new Map(environments.map((environment) => [environment.id, environment.parentId]));
  const own = new Map<string, Map<string, Held>>(environments.map((environment) => [environment.id, new Map()]));
  for (const row of live) own.get(row.environmentId)?.set(row.key, { environmentId: row.environmentId, folder: row.folder });
  const removed = new Map<string, Set<string>>();
  for (const row of dismissed) removed.set(row.environmentId, (removed.get(row.environmentId) ?? new Set()).add(row.key));

  const resolved = new Map<string, Map<string, Held>>();
  const resolve = (id: string, depth: number): Map<string, Held> => {
    const known = resolved.get(id);
    if (known !== undefined) return known;
    const keys = new Map(own.get(id));
    const parentId = parentOf.get(id) ?? null;
    if (parentId !== null && parentOf.has(parentId) && depth < MAX_PARENTS) {
      const without = removed.get(id) ?? new Set();
      for (const [key, held] of resolve(parentId, depth + 1)) if (!keys.has(key) && !without.has(key)) keys.set(key, held);
    }
    // Cached only from the top of a chain: one met deeper may have been cut short by the depth.
    if (depth === 0) resolved.set(id, keys);
    return keys;
  };
  for (const environment of environments) resolve(environment.id, 0);
  return resolved;
}

/** A key a fork's parent resolves to: its row, and the environment it is held in. */
export type InheritedRow = { row: SecretRow; from: ParentRow };

/**
 * What a fork inherits, row by row: its parents nearest first, each key
 * its parent resolves to with the row that holds it, and the keys the
 * fork removed. `cut` names, for a key some parent has a row of but none
 * passes down, the nearest parent that stopped it, by archiving or
 * removing it: what a removal of it stands for once it no longer removes
 * anything. Null for a chain that loops or runs past `MAX_PARENTS`,
 * written around the app. Two queries a level, at most three levels, in
 * whatever transaction `db` is: a caller that lists reads in one snapshot.
 */
export async function inheritedRows(
  db: Queryable,
  environmentId: string,
): Promise<{ parents: ParentRow[]; held: Map<string, InheritedRow>; removed: Set<string>; cut: Map<string, ParentRow> } | null> {
  const parents = await parentsOf(db, environmentId);
  if (parents === null) return null;
  const held = new Map<string, InheritedRow>();
  const cut = new Map<string, ParentRow>();
  // Every key a parent has a row of: a dismissal of anything else is a missing key's, not a removal.
  const known = new Set<string>();
  const removed = new Set((await dismissalsIn(db, environmentId)).map((row) => row.key));
  // The keys a nearer parent settled: those it holds, and those it removed.
  const settled = new Set<string>();
  for (const parent of parents) {
    for (const row of await environmentSecrets(db, parent.id)) {
      known.add(row.key);
      if (settled.has(row.key)) continue;
      if (row.archivedAt === null) {
        held.set(row.key, { row, from: parent });
        settled.add(row.key);
      } else if (!cut.has(row.key)) cut.set(row.key, parent);
    }
    for (const dismissal of await dismissalsIn(db, parent.id)) {
      if (settled.has(dismissal.key)) continue;
      settled.add(dismissal.key);
      if (!cut.has(dismissal.key)) cut.set(dismissal.key, parent);
    }
  }
  for (const key of cut.keys()) if (held.has(key) || !known.has(key)) cut.delete(key);
  return { parents, held, removed, cut };
}

/**
 * Every environment below this one, forks of forks included, archived or
 * not, nearest first: those a rename in it carries down to. Deleted ones
 * name no parent a rename could reach.
 */
export async function descendantsOf(db: Queryable, environmentId: string): Promise<{ id: string; slug: string }[]> {
  const found: { id: string; slug: string }[] = [];
  let level = [environmentId];
  for (let depth = 0; depth < MAX_PARENTS && level.length > 0; depth++) {
    const next: { id: string; slug: string }[] = [];
    for (const id of level) next.push(...(await forksOf(db, id, { archived: true })));
    found.push(...next);
    level = next.map((fork) => fork.id);
  }
  return found;
}
