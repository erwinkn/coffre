import { readsSensitive, useOnly } from '@coffre/core/access';
import type { Called } from '@coffre/core/vault';

import type { ChainRead, EnvironmentRow, ProjectRow, SecretRow } from '../db/queries/secrets.ts';
import { can, placeOf, type Place } from './caller.ts';

/**
 * What a read of an environment would hand the caller, key by key, worked
 * out from the app's rows and the vault's answer about the caller, opening
 * nothing: the rules of a use (`decide` in `@coffre/vault`'s use.ts) for
 * a read that hands values back, `POST /reveals` of a whole environment.
 * What a page says of a key's readability, and the environment's version,
 * which is a reveal's own (`versionOf`). It decides nothing: a reveal asks
 * the vault, which decides again on rows whose MACs it checks.
 */

/** Parents an environment may have above it, as a use follows them. */
export const MAX_PARENTS = 3;

/** A key the caller would be handed: the row asked for, and the one holding its value, which differs for a reference. */
export type Given = { key: string; asked: SecretRow; held: SecretRow; version: number };
export type Refused = { key: string; refused: string };

export type Decided = { project: ProjectRow; base: EnvironmentRow; first: EnvironmentRow; layers: EnvironmentRow[]; items: (Given | Refused)[] };

/** A place that is there: not archived, and not a deletion's tombstone. */
export const live = (row: { archived: boolean; deleted: boolean }) => !row.archived && !row.deleted;

/** An environment as a permission check names it, with the parent a personal config holds what it holds by. */
export function placeAt(project: { id: string }, environment: EnvironmentRow, environments: ReadonlyMap<string, EnvironmentRow>): Place {
  const parent = environment.parentId === null ? null : (environments.get(environment.parentId) ?? null);
  return placeOf(project, { ...environment, parent });
}

/**
 * Whether anyone reads at an environment, as the vault decides before any
 * grant: a personal config only while its parent is there and live. Cy's
 * config of an archived dev answers no one, whether named `dev@me` or
 * `dev-cy`.
 */
export function readsAt(row: EnvironmentRow, environments: ReadonlyMap<string, EnvironmentRow>): boolean {
  if (row.owner === null) return true;
  const parent = row.parentId === null ? undefined : environments.get(row.parentId);
  return parent !== undefined && live(parent);
}

/**
 * What an environment inherits from, nearest first, as a use follows it:
 * three parents at most, four above a personal config read as `dev@me`
 * (`mine`), not when named by its own slug. Null for a chain a use refuses
 * as broken: a parent not there, archived, in another project, or one too
 * many. b4 → b3 → b2 → b1 → prod inherits nothing, and neither does a fork
 * of an archived environment; Cy's config of b3 inherits prod's keys as
 * `b3@me`, and nothing as `b3-cy`.
 */
export function parentsOf(first: EnvironmentRow, environments: ReadonlyMap<string, EnvironmentRow>, mine: boolean): EnvironmentRow[] | null {
  const parents: EnvironmentRow[] = [];
  for (let id = first.parentId; id !== null; id = parents.at(-1)!.parentId) {
    const parent = environments.get(id);
    if (parent === undefined || !live(parent) || parent.projectId !== first.projectId || parents.length >= MAX_PARENTS + (mine ? 1 : 0)) return null;
    parents.push(parent);
  }
  return parents;
}

/**
 * The use of `read` by `who`, as the vault would decide it for a reveal of
 * the whole environment: refused as a whole for where, `no_access` when
 * there is no such place or the caller may not read it, `broken_chain`
 * when what it inherits from is not there; else each key it resolves to,
 * given or refused with the vault's reason. `mine`: `dev@me`, the
 * caller's personal config of it, or the environment while they have none.
 */
export function decideRead(who: Called, read: ChainRead, mine: boolean): Decided | { refused: string } {
  const { project, base } = read;
  if (project === null || !live(project) || base === null || !live(base)) return { refused: 'no_access' };
  const first = (mine && read.mine !== null && live(read.mine) ? read.mine : null) ?? base;
  const environments = read.environments;
  /** Whether the caller reads the keys an environment holds. */
  const may = (row: EnvironmentRow): boolean => readsAt(row, environments) && can(who, 'secret.read', placeAt(project, row, environments));
  if (!may(first)) return { refused: 'no_access' };

  // The environment, then what it inherits from, nearest first: a key is the nearest one's.
  const parents = parentsOf(first, environments, first !== base);
  if (parents === null) return { refused: 'broken_chain' };
  const layers = [first, ...parents];

  const rows = [...read.secrets.values()];
  const keyed = new Map(rows.filter((row) => !row.archived).map((row) => [`${row.environmentId} ${row.key}`, row]));
  const dismissed = new Set(read.dismissed.map((row) => `${row.environmentId} ${row.key}`));
  const given = (key: string, asked: SecretRow, layer: EnvironmentRow): Given | Refused => {
    if (!may(layer)) return { key, refused: 'parent_unreadable' };
    let held = asked;
    if (asked.sourceId !== null) {
      // A reference reads its source's value, never through another reference, nor into or out of a personal config.
      const source = read.secrets.get(asked.sourceId);
      const where = source && environments.get(source.environmentId);
      const whose = source && read.projects.get(source.projectId);
      if (source === undefined || source.archived || source.sourceId !== null || layer.owner !== null) return { key, refused: 'unreadable' };
      if (where === undefined || !live(where) || where.owner !== null || whose === undefined || !live(whose)) return { key, refused: 'unreadable' };
      held = source;
    }
    if (held.currentVersion === null) return { key, refused: held === asked ? 'no_value' : 'unreadable' };
    if (held.current === null) return { key, refused: 'unreadable' };
    // Handed back: a workload only what its credential lists where the value is held, a person no sensitive value, a service account one on an Owner's credential.
    if (held.nature !== 'plain' && useOnly(who.holds, { projectId: held.projectId, environmentId: held.environmentId, secretId: held.id })) return { key, refused: 'use_only' };
    if (held.nature === 'sensitive' && who.holds.service !== true) return { key, refused: 'sensitive' };
    if (held.nature === 'sensitive' && !readsSensitive(who.holds, held.projectId)) return { key, refused: 'not_owner_issued' };
    return { key, asked, held, version: held.currentVersion };
  };
  const resolve = (key: string): Given | Refused => {
    for (const layer of layers) {
      const asked = keyed.get(`${layer.id} ${key}`);
      if (asked !== undefined) return given(key, asked, layer);
      // A fork that dismissed a key has none, whatever its parents hold.
      if (dismissed.has(`${layer.id} ${key}`)) break;
    }
    return { key, refused: 'unknown_key' };
  };
  const every = [...new Set(rows.filter((row) => !row.archived && layers.some((layer) => layer.id === row.environmentId)).map((row) => row.key))].sort();
  const items = every.map(resolve).filter((item) => !('refused' in item) || item.refused !== 'unknown_key');
  return { project, base, first, layers, items };
}

/** What a whole environment's read leaves out and names, and what it leaves out as not there: any other refusal of a key refuses the read. */
export const LEFT_OUT = new Set(['sensitive', 'use_only', 'unknown_key', 'no_value']);

/**
 * The key that refuses a whole environment's read, or none: past a key's
 * name, a fork says nothing of what its reader cannot read, so a parent
 * the caller does not read is told first.
 */
export function stopOf(items: readonly ({ key: string } | Refused)[]): Refused | undefined {
  const stops = items.filter((item): item is Refused => 'refused' in item && !LEFT_OUT.has(item.refused));
  return stops.find((item) => item.refused === 'parent_unreadable') ?? stops[0];
}
