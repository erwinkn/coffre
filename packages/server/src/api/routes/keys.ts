import { ownsProject, type Permission } from '@coffre/core/access';
import { parseRecipe, recipeProblem, type Generation } from '@coffre/core/recipe';
import { secretKey, slug } from '@coffre/core/schemas';
import type { Called } from '@coffre/core/vault';
import { z } from 'zod';

import { chainOf, historyOf, keyNamesOf, referencesOf, type EnvironmentRow, type Nature, type ProjectRow, type SecretRow } from '../../db/queries/secrets.ts';
import { can, permissionsAt, placeOf, type Place } from '../caller.ts';
import { badRequest, refusal } from '../errors.ts';
import { parsePath } from '../paths.ts';
import { route } from '../route.ts';
import { readersAt } from './members.ts';
import { environmentOf, stopOf, versionOf } from './secrets.ts';

/**
 * An environment's keys as its pages list them (docs/design/0.16.md,
 * "Pages"): the keys, a key's versions, the references into and out of a
 * place, what an environment is missing, and its version. Never a value,
 * but a plain one's copy for the pages. The lists are each one call to the
 * vault, `caller`, and one statement; what the caller may see is worked
 * out from the vault's answer about them. The version is the vault's
 * alone, `peek`. A place that is not there and one they may not list are
 * the same refusal, `no_access`.
 */

/** Parents an environment may have above it, as a use follows them. */
const MAX_PARENTS = 3;

/** A place that is there: not archived, and not a deletion's tombstone. */
const live = (row: { archived: boolean; deleted: boolean }) => !row.archived && !row.deleted;

/** An environment as a permission check names it, with the parent a personal config holds what it holds by. */
function placeAt(project: { id: string }, environment: EnvironmentRow, environments: ReadonlyMap<string, EnvironmentRow>): Place {
  const parent = environment.parentId === null ? null : (environments.get(environment.parentId) ?? null);
  return placeOf(project, { ...environment, parent });
}

/**
 * Whether anyone lists an environment, as the vault reads one before any
 * grant: a personal config only while its parent is there and live. Cy's
 * config of an archived dev answers no one, whether named `dev@me` or
 * `dev-cy`.
 */
function readsAt(row: EnvironmentRow, environments: ReadonlyMap<string, EnvironmentRow>): boolean {
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
function parentsOf(first: EnvironmentRow, environments: ReadonlyMap<string, EnvironmentRow>, mine: boolean): EnvironmentRow[] | null {
  const parents: EnvironmentRow[] = [];
  for (let id = first.parentId; id !== null; id = parents.at(-1)!.parentId) {
    const parent = environments.get(id);
    if (parent === undefined || !live(parent) || parent.projectId !== first.projectId || parents.length >= MAX_PARENTS + (mine ? 1 : 0)) return null;
    parents.push(parent);
  }
  return parents;
}

/** Whether the caller reads or uses values at a place, which is who lists its keys: a role that writes there also reads or uses. */
const lists = (who: Called, place: Place) => can(who, 'secret.read', place) || can(who, 'secret.use', place);

/** A reference's state, as 0.14 named them: whether it reads its source's value, and why not. */
type ReferenceState = 'live' | 'broken' | 'source_archived' | 'source_deleted' | 'source_is_reference' | 'source_empty';

/** A reference as the API shows it: where it is held, what it reads, and whether it does. */
export type ReferenceView = {
  /** The secret that is the reference. */
  id: string;
  holder: string;
  source: string;
  state: ReferenceState;
  /** The source's current version, while it reads. */
  version: number | null;
  /**
   * Who pointed it at its source, and when: its row's, under the vault's MAC. An ended reference is none, its row
   * keeps no source, so nothing says who ended one: null, where 0.14 answered them, and the log has it.
   */
  createdBy: string | null;
  createdAt: string | null;
  endedBy: null;
  endedAt: null;
};

/** An environment's key as its list shows it: no value. */
type ListedKey = {
  key: string;
  /**
   * The reference it is, when it has no value of its own, and whether the
   * caller lists its source's environment; the source by its id too, which
   * a value written over it names to replace that reference and no other
   * (`replaces` in @coffre/core/changes/secrets).
   */
  reference: (ReferenceView & { sourceId: string; canOpenSource: boolean }) | null;
  folder: string | null;
  archived: boolean;
  /** Its own current version; a reference has none, and reads its source's. */
  version: number | null;
  /** The id of the version it resolves to, its own or, in a fork, the one it inherits. */
  versionId: string | null;
  /** When the value it reads was written: its current version's, or a live reference's source's. */
  updatedAt: string | null;
  /** Who wrote its own current version; null for a reference. */
  updatedBy: string | null;
  /** How its current value was made, when a client generated it: what Regenerate makes the next one by. */
  generated: Generation | null;
  /**
   * A plain value itself, from the copy its version keeps for the pages:
   * its own, or its source's through a live reference, and, inherited, only
   * to a lister of the parent that holds it. Null for any other, a secret
   * whose version carries a copy included: never opened.
   */
  value: string | null;
  /** Who sees its current value: its own, or a live reference's source's. Null where there is no value to read. */
  sensitivity: Nature | null;
  /**
   * Whether the caller may see its current value, as 0.14 said it: a plain
   * one listed here, or a secret where they read it, here and, inherited,
   * on the parent that holds it. False for a sensitive value, an archived
   * key, and where there is no value. The vault decides again at the
   * reveal.
   */
  readable: boolean;
  /**
   * In a fork, the key its parents hold under this name: `inherited`, no
   * row here; `overridden`, a value or reference of its own over the
   * parent's; `removed`, the parent's key this fork does without. `from`
   * is the environment that holds it; `changed`, that the parent's value
   * is newer than the override; `reset`, that the fork's own value was
   * reset to it and is kept, archived; `held`, false for a removal of a key
   * no parent passes down now. Null outside forks, and for a key only this
   * environment holds.
   */
  parent: { from: string; state: 'inherited' | 'overridden' | 'removed'; changed: boolean; reset: boolean; held: boolean } | null;
};

/** Whether a place is protected: by its row, or by the vault's list. */
const guarded = (who: Called, row: { id: string; protected: boolean }) => row.protected || who.holds.policy.protected.includes(row.id);

/** A whole place's slugs, and the environment the request named, `dev@me` resolved: the caller's personal config of it, or the environment while they have none. */
function resolvedHere(read: { project: ProjectRow | null; base: EnvironmentRow | null; mine: EnvironmentRow | null }, path: string): { project: ProjectRow; base: EnvironmentRow; here: EnvironmentRow } {
  const { project, base, mine } = read;
  if (project === null || !live(project) || base === null || !live(base)) throw refusal('no_access', path);
  return { project, base, here: mine !== null && live(mine) ? mine : base };
}

/**
 * How each live key's current value was made, by secret id, for those a
 * client generated. A key pair's half is one only beside the other: both
 * live, sharing their pair's id and recipe, each holding its half.
 */
function generations(rows: readonly SecretRow[]): Map<string, Generation> {
  const made = rows.filter((row) => !row.archived && row.currentVersion !== null && row.recipe !== null);
  const halves = new Map<string, { private?: SecretRow; public?: SecretRow }>();
  for (const row of made) {
    if (row.pairId === null || row.pairHalf === null) continue;
    const both = halves.get(row.pairId) ?? {};
    both[row.pairHalf] = row;
    halves.set(row.pairId, both);
  }
  // A recipe that does not parse makes nothing.
  const kindOf = (recipe: string) => (recipeProblem(recipe) === null ? parseRecipe(recipe).kind : null);
  const out = new Map<string, Generation>();
  for (const row of made) {
    const recipe = row.recipe!;
    const kind = kindOf(recipe);
    if (row.pairId === null) {
      if (kind !== null && kind !== 'pair') out.set(row.id, { recipe });
      continue;
    }
    const both = halves.get(row.pairId)!;
    if (kind !== 'pair' || both.private === undefined || both.public === undefined) continue;
    if (both.private.recipe !== recipe || both.public.recipe !== recipe) continue;
    out.set(row.id, { recipe, pair: { private: both.private.key, public: both.public.key } });
  }
  return out;
}

/** Where a secret is, by slugs, from the rows a read found. */
function pathIn(places: { projects: ReadonlyMap<string, ProjectRow>; environments: ReadonlyMap<string, EnvironmentRow> }, secret: SecretRow): string {
  return `${places.projects.get(secret.projectId)?.slug ?? '?'}/${places.environments.get(secret.environmentId)?.slug ?? '?'}/${secret.key}`;
}

/** Whether a reference reads its source, and why not, as a use would read it. */
function stateOf(places: { projects: ReadonlyMap<string, ProjectRow>; environments: ReadonlyMap<string, EnvironmentRow> }, holder: SecretRow, source: SecretRow | undefined): ReferenceState {
  const where = source && places.environments.get(source.environmentId);
  const whose = source && places.projects.get(source.projectId);
  if (source === undefined || where === undefined || whose === undefined || where.deleted || whose.deleted) return 'source_deleted';
  if (source.archived || where.archived || whose.archived) return 'source_archived';
  if (source.sourceId !== null) return 'source_is_reference';
  // A personal config's values are its owner's alone: nothing reads one from elsewhere, and a reference held in one reads nothing.
  const held = places.environments.get(holder.environmentId);
  if (where.owner !== null || (held !== undefined && held.owner !== null)) return 'broken';
  if (source.currentVersion === null) return 'source_empty';
  return 'live';
}

export function referenceView(places: Parameters<typeof stateOf>[0], holder: SecretRow, source: SecretRow | undefined): ReferenceView {
  const state = stateOf(places, holder, source);
  return {
    id: holder.id,
    holder: pathIn(places, holder),
    source: source === undefined ? '?' : pathIn(places, source),
    state,
    version: state === 'live' ? source!.currentVersion : null,
    createdBy: holder.sourceSetBy,
    createdAt: holder.sourceSetAt,
    endedBy: null,
    endedAt: null,
  };
}

/**
 * Each environment's keys, its own live ones and those it inherits, by
 * name, with the folder where it is held: the nearest environment of the
 * chain that holds it live or dismissed it settles it, as a use does. A
 * chain a use refuses as broken (`parentsOf`) passes nothing down.
 */
function resolveKeys(
  environments: readonly EnvironmentRow[],
  keys: readonly { environmentId: string; key: string; folder: string | null; archived: boolean }[],
  dismissed: readonly { environmentId: string; key: string }[],
): Map<string, Map<string, string | null>> {
  const byId = new Map(environments.map((environment) => [environment.id, environment]));
  const own = new Map<string, Map<string, string | null>>(environments.map((environment) => [environment.id, new Map()]));
  for (const row of keys) if (!row.archived) own.get(row.environmentId)?.set(row.key, row.folder);
  const removed = new Map<string, Set<string>>();
  for (const row of dismissed) removed.set(row.environmentId, (removed.get(row.environmentId) ?? new Set()).add(row.key));
  const resolve = (environment: EnvironmentRow): Map<string, string | null> => {
    const found = new Map(own.get(environment.id));
    const without = new Set(removed.get(environment.id));
    // A personal config is a missing-key page's only through `dev@me`: its slug names no place there.
    for (const parent of parentsOf(environment, byId, environment.owner !== null) ?? []) {
      for (const [key, folder] of own.get(parent.id) ?? []) if (!found.has(key) && !without.has(key)) found.set(key, folder);
      for (const key of removed.get(parent.id) ?? []) without.add(key);
    }
    return found;
  };
  return new Map(environments.map((environment) => [environment.id, resolve(environment)]));
}

/** The environments below one, forks of its forks too. */
function forksBelow(environments: readonly EnvironmentRow[], environmentId: string): Set<string> {
  const below = new Set<string>();
  for (let grew = true; grew; ) {
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

/** A key's history, a page at a time: the newest first. */
const HISTORY_PAGE = 20;

export const keyRoutes = {
  /**
   * An environment's keys, who last changed each and when, never a value.
   * A fork lists what it inherits too, each key under `parent`, and
   * `parents` names the environments it inherits from, nearest first. An
   * inherited key's name, folder and standing are any lister's; its
   * version and age, a lister's of the parent that holds it. `dev@me` is
   * the caller's personal config of dev, or dev while they have none.
   */
  ...route('GET /secrets/:project/:environment', {
    run: async (ctx, { params }) => {
      const who = await ctx.caller();
      const { environment, mine } = environmentOf(params.environment);
      const path = `${params.project}/${params.environment}`;
      const read = await chainOf(ctx.db, params.project, environment, mine ? who.principal : null);
      const { project, base, here } = resolvedHere(read, path);
      const { environments } = read;
      const at = placeAt(project, here, environments);
      if (!readsAt(here, environments) || !lists(who, at)) throw refusal('no_access', path);

      // What it inherits from, nearest first, as a use follows it: a chain it refuses lists nothing.
      const parents = parentsOf(here, environments, here !== base);
      if (parents === null) throw refusal('broken_chain', path);
      const secrets = [...read.secrets.values()];
      const rowsAt = (id: string) => secrets.filter((row) => row.environmentId === id);
      const dismissedAt = (id: string) => read.dismissed.filter((row) => row.environmentId === id).map((row) => row.key);

      // A key a parent passes down: the nearest that holds it live, unless a nearer one dismissed it. `cut`: for a key some parent has a row of but none passes down, the nearest that stopped it.
      const held = new Map<string, { row: SecretRow; from: EnvironmentRow }>();
      const cut = new Map<string, EnvironmentRow>();
      const known = new Set<string>();
      const settled = new Set<string>();
      for (const parent of parents) {
        for (const row of rowsAt(parent.id)) {
          known.add(row.key);
          if (settled.has(row.key)) continue;
          if (!row.archived) {
            held.set(row.key, { row, from: parent });
            settled.add(row.key);
          } else if (!cut.has(row.key)) cut.set(row.key, parent);
        }
        for (const key of dismissedAt(parent.id)) {
          if (settled.has(key)) continue;
          settled.add(key);
          if (!cut.has(key)) cut.set(key, parent);
        }
      }
      for (const key of cut.keys()) if (held.has(key) || !known.has(key)) cut.delete(key);
      const removed = new Set(dismissedAt(here.id));

      const rows = rowsAt(here.id);
      const own = new Set(rows.filter((row) => !row.archived).map((row) => row.key));
      const made = generations([...rows, ...[...held].filter(([key]) => !own.has(key) && !removed.has(key)).map(([, { row }]) => row)]);
      const sourceOf = (row: SecretRow) => (row.sourceId === null ? undefined : read.secrets.get(row.sourceId));
      const liveSource = (row: SecretRow) => {
        const source = sourceOf(row);
        return row.sourceId !== null && stateOf(read, row, source) === 'live' ? source! : null;
      };
      const writtenAt = (row: SecretRow): string | null => row.current?.createdAt ?? liveSource(row)?.current?.createdAt ?? null;
      // A plain value's copy: its own, or its source's through a live reference. The query gives none for a secret.
      const plainOf = (row: SecretRow): string | null => (row.sourceId === null ? (row.current?.plaintext ?? null) : (liveSource(row)?.current?.plaintext ?? null));
      const view = (row: SecretRow): Omit<ListedKey, 'parent' | 'readable'> => {
        const source = sourceOf(row);
        const reference = row.sourceId === null ? null : referenceView(read, row, source);
        const sourceAt = source === undefined ? undefined : environments.get(source.environmentId);
        return {
          key: row.key,
          reference: reference === null ? null : { ...reference, sourceId: row.sourceId!, canOpenSource: sourceAt !== undefined && lists(who, placeAt({ id: source!.projectId }, sourceAt, environments)) },
          folder: row.folder,
          archived: row.archived,
          version: row.currentVersion,
          versionId: row.current?.id ?? null,
          updatedAt: writtenAt(row),
          updatedBy: row.current?.createdBy ?? null,
          generated: made.get(row.id) ?? null,
          value: plainOf(row),
          sensitivity: row.nature ?? liveSource(row)?.nature ?? null,
        };
      };
      // Told of a parent's key, its version, age and plain value, as a lister of the parent is.
      const told = (from: EnvironmentRow) => lists(who, placeAt(project, from, environments));
      // Whether the caller reads values where they are held, as 0.14 said it (v0.14.7 api/secrets.ts:387-391): a Contributor only uses, and
      // reads their own values in dev@me, none of dev's. A plain value is any lister's; a sensitive one, nobody's.
      const readsHere = can(who, 'secret.read', at);
      const readsFrom = (from: EnvironmentRow) => can(who, 'secret.read', placeAt(project, from, environments));
      const readable = (key: Pick<ListedKey, 'value' | 'sensitivity'>, reader: boolean) => key.sensitivity !== null && key.sensitivity !== 'sensitive' && (key.value !== null || reader);

      // An override reset to the parent's: listed once, as inherited or removed, saying its own value is kept.
      const reset = new Set(rows.filter((row) => row.archived && (held.has(row.key) || (removed.has(row.key) && cut.has(row.key)))).map((row) => row.key));
      const keys: ListedKey[] = rows.filter((row) => !reset.has(row.key)).map((row) => {
        const shown = view(row);
        const listed = { ...shown, readable: !row.archived && readable(shown, readsHere) };
        const parent = row.archived ? undefined : held.get(row.key);
        if (parent === undefined) return { ...listed, parent: null };
        const [mine, theirs] = [writtenAt(row), writtenAt(parent.row)];
        const changed = told(parent.from) && mine !== null && theirs !== null && Date.parse(theirs) > Date.parse(mine);
        return { ...listed, parent: { from: parent.from.slug, state: 'overridden', changed, reset: false, held: true } };
      });
      for (const [key, { row, from }] of held) {
        if (own.has(key)) continue;
        const isRemoved = removed.has(key);
        const shown = !isRemoved && told(from);
        const listed = {
          ...view(row),
          ...(shown ? {} : { reference: null, version: null, versionId: null, updatedAt: null, updatedBy: null, generated: null, value: null, sensitivity: null }),
          // A removed key resolves to nothing here, and has nothing to regenerate.
          ...(isRemoved ? { generated: null, value: null, sensitivity: null } : {}),
        };
        keys.push({
          ...listed,
          archived: false,
          // Read through here, so by a reader of here and of the parent that holds it.
          readable: readable(listed, readsHere && readsFrom(from)),
          parent: { from: from.slug, state: isRemoved ? 'removed' : 'inherited', changed: false, reset: reset.has(key), held: true },
        });
      }
      // A removal of a key a parent archived or removed since: doing nothing until that parent brings it back. Listed, to be restored.
      for (const key of removed) {
        const from = cut.get(key);
        if (from === undefined || own.has(key)) continue;
        keys.push({
          key, reference: null, folder: null, archived: false, version: null, versionId: null, updatedAt: null, updatedBy: null, generated: null, value: null, sensitivity: null, readable: false,
          parent: { from: from.slug, state: 'removed', changed: false, reset: reset.has(key), held: false },
        });
      }
      keys.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
      const personal = here.owner !== null;
      return {
        permissions: permissionsAt(who, at) as Permission[],
        keys,
        parents: parents.map((parent) => parent.slug),
        personal: mine ? { of: base.slug, fallback: !personal } : null,
        // A personal config is protected as the environment it is a config of is.
        protected: guarded(who, personal ? base : here),
        /** Whether the caller may take its protection off: an Owner of its project, on no credential's scope. False for a personal config. */
        unprotectable: !personal && ownsProject(who.holds, project.id),
        /** Whether the caller may make a sensitive value of its own a secret in place: an Owner of its project. */
        loosenable: ownsProject(who.holds, project.id),
        rotateAfterDays: ctx.rotateAfterDays,
      };
    },
  }),

  /**
   * A key's versions, the newest first, 20 at a time: `before` asks for
   * those older than a version, and `more` says there are. Who wrote each
   * and when, and how it is kept, never its value. The key is the
   * environment's own: an inherited one's history is its parent's.
   */
  ...route('GET /secrets/:project/:environment/:key/versions', {
    input: z.object({ before: z.string().regex(/^[1-9][0-9]{0,8}$/, 'before is a version: a whole number from 1').transform(Number).optional() }).strict(),
    run: async (ctx, { params, input }) => {
      const who = await ctx.caller();
      const { environment, mine } = environmentOf(params.environment);
      const path = `${params.project}/${params.environment}`;
      const found = await historyOf(ctx.db, { project: params.project, environment, owner: mine ? who.principal : null, key: params.key }, input.before ?? null, HISTORY_PAGE + 1);
      const { project, here } = resolvedHere(found, path);
      const environments = new Map([found.base!, ...[found.parent, found.mine].filter((row) => row !== null)].map((row) => [row.id, row]));
      if (!readsAt(here, environments) || !lists(who, placeAt(project, here, environments))) throw refusal('no_access', path);
      const { secret } = found;
      if (secret === null) throw refusal('unknown_key', `${path}/${params.key}`);
      return {
        key: secret.key,
        archived: secret.archived,
        versions: found.versions.slice(0, HISTORY_PAGE).map((version) => {
          const current = version.version === secret.currentVersion;
          return {
            version: version.version,
            createdAt: version.createdAt,
            createdBy: version.createdBy,
            current,
            kek: version.kek,
            // How a value was made is kept for the current one alone, on its secret's row.
            recipe: current ? secret.recipe : null,
            plain: version.plain,
            sensitivity: (version.plain ? 'plain' : version.sensitive ? 'sensitive' : 'secret') as Nature,
          };
        }),
        more: found.versions.length > HISTORY_PAGE,
      };
    },
  }),

  /**
   * The references into and out of a place, `market`, `market/prod` or
   * `market/prod/KEY`: those it lends and those it holds. Each is listed to
   * whoever lists, or manages the access of, either end. A place the caller
   * holds nothing in, and shown none of, answers as one that is not there.
   * Who reads through one, `readers`, is shown to whoever manages either
   * project's access, as 0.14.7 showed it: the members who read its
   * holder's environment (`readersAt`), at one more statement for the page,
   * and null to anyone else.
   */
  ...route('GET /references', {
    input: z.object({ path: z.string().max(400) }).strict(),
    run: async (ctx, { input }) => {
      const path = parsePath(input.path, [1, 2, 3]);
      if (!slug.safeParse(path.project).success || (path.environment !== undefined && !slug.safeParse(path.environment).success) || (path.key !== undefined && !secretKey.safeParse(path.key).success)) {
        throw badRequest(`"${input.path.slice(0, 80)}" names no project, environment or secret`);
      }
      const who = await ctx.caller();
      const found = await referencesOf(ctx.db, path.project);
      const { project, environments, secrets } = found;
      const team = [...environments.values()].filter((row) => project !== null && row.projectId === project.id && !row.deleted && (row.owner === null || row.owner === who.principal));
      const named = path.environment === undefined ? null : team.find((row) => row.slug === path.environment && row.owner === null);
      if (project === null || project.deleted || named === undefined) throw refusal('no_access', input.path);
      // Whether the caller holds anything at the place named: in the project, anywhere in it; in an environment, there.
      const holds = named === null
        ? permissionsAt(who, { projectId: project.id }).length > 0 || team.some((row) => permissionsAt(who, placeAt(project, row, environments)).length > 0)
        : permissionsAt(who, placeAt(project, named, environments)).length > 0;
      const at = (end: SecretRow) => end.projectId === project.id && (named === null || end.environmentId === named.id) && (path.key === undefined || end.key === path.key);
      const placeOfEnd = (end: SecretRow) => placeAt({ id: end.projectId }, environments.get(end.environmentId)!, environments);
      const reaches = (end: SecretRow) => environments.has(end.environmentId) && (lists(who, placeOfEnd(end)) || can(who, 'grant.manage', { projectId: end.projectId }));
      const references = found.holders.flatMap((id) => {
        const holder = secrets.get(id)!;
        const source = holder.sourceId === null ? undefined : secrets.get(holder.sourceId);
        if (!(at(holder) || (source !== undefined && at(source)))) return [];
        if (!(reaches(holder) || (source !== undefined && reaches(source)))) return [];
        const where = environments.get(holder.environmentId);
        const whose = found.projects.get(holder.projectId);
        const manages = [holder, ...(source === undefined ? [] : [source])].some((end) => can(who, 'grant.manage', { projectId: end.projectId }));
        return [{
          ...referenceView(found, holder, source),
          // Where its readers read, for a manager's.
          readAt: manages && where !== undefined ? placeOfEnd(holder) : null,
          canBreak: (where !== undefined && can(who, 'secret.write', placeOfEnd(holder))) || (source !== undefined && can(who, 'grant.manage', { projectId: source.projectId })),
          holderArchived: holder.archived || where === undefined || where.archived || whose === undefined || whose.archived,
        }];
      });
      // A place the caller holds nothing in answers as one not there, unless a reference they reach by its other end names it: that end shows it already.
      if (!holds && references.length === 0) throw refusal('no_access', input.path);
      references.sort((a, b) => (a.holder < b.holder ? -1 : a.holder > b.holder ? 1 : 0));
      // Their readers, for a manager's: one statement for them all, none when there are none.
      const readers = await readersAt(ctx.db, who, references.flatMap(({ readAt }) => (readAt === null ? [] : [readAt])), new Date());
      let next = 0;
      return { references: references.map(({ readAt, ...reference }) => ({ ...reference, readers: readAt === null ? null : readers[next++]! })) };
    },
  }),

  /**
   * What an environment lacks of the live keys in its project's other live
   * environments, the dismissed apart: a lister of dev learns that prod has
   * `STRIPE_KEY`, never its value. A key archived here is not missing, nor
   * one it inherits, nor one only its own forks hold. Personal configs are
   * nobody's siblings.
   */
  ...route('GET /projects/:project/:environment/missing', {
    run: async (ctx, { params }) => {
      const who = await ctx.caller();
      const { environment, mine } = environmentOf(params.environment);
      const path = `${params.project}/${params.environment}`;
      const found = await keyNamesOf(ctx.db, params.project, mine ? who.principal : null);
      const base = found.environments.find((row) => row.slug === environment && row.owner === null) ?? null;
      const config = base === null ? null : (found.environments.find((row) => row.parentId === base.id && row.owner === who.principal && live(row)) ?? null);
      const { project, here } = resolvedHere({ project: found.project, base, mine: config }, path);
      const environments = new Map(found.environments.map((row) => [row.id, row]));
      if (!lists(who, placeAt(project, here, environments))) throw refusal('no_access', path);
      const below = forksBelow(found.environments, here.id);
      const others = found.environments.filter((row) => row.id !== here.id && live(row) && !below.has(row.id) && row.owner === null);
      const resolved = resolveKeys(found.environments, found.keys, found.dismissed);
      const has = new Set([...found.keys.filter((row) => row.environmentId === here.id).map((row) => row.key), ...resolved.get(here.id)!.keys()]);
      const missing = new Map<string, { in: string[]; folders: Set<string | null> }>();
      for (const other of others) {
        for (const [key, folder] of resolved.get(other.id)!) {
          if (has.has(key)) continue;
          const entry = missing.get(key) ?? { in: [], folders: new Set() };
          entry.in.push(other.slug);
          entry.folders.add(folder);
          missing.set(key, entry);
        }
      }
      const keys = [...missing.entries()]
        .map(([key, entry]) => ({ key, in: entry.in.sort(), folder: entry.folders.size === 1 ? [...entry.folders][0]! : null }))
        .sort((a, b) => (a.key < b.key ? -1 : 1));
      const dismissedBy = new Map(found.dismissed.filter((row) => row.environmentId === here.id).map((row) => [row.key, row]));
      return {
        missing: keys.filter((entry) => !dismissedBy.has(entry.key)),
        // Only what is still missing: a dismissal of a key no sibling has any more is moot.
        dismissed: keys.flatMap((entry) => {
          const row = dismissedBy.get(entry.key);
          return row === undefined ? [] : [{ ...entry, dismissedBy: row.dismissedBy, dismissedAt: row.dismissedAt }];
        }),
      };
    },
  }),

  /**
   * The version of what a read of the environment would hand the caller,
   * which changes whenever that does: `coffre export --watch` asks it
   * before reading, and compares it with the read's own (`POST /reveals`).
   * One call to the vault, `peek`, which decides as a reveal of the whole
   * environment would and opens and writes nothing, and no statement of the
   * app's; refused as that reveal would be. The bulk cap is not asked, as
   * 0.14 did not: it bounds the values a principal is handed, and a version
   * hands none. A caller past it sees the version move, and its read is
   * refused `bulk_limit`.
   */
  ...route('GET /projects/:project/:environment/version', {
    run: async (ctx, { params }) => {
      const path = `${params.project}/${params.environment}`;
      const answer = await ctx.vault.peek({ ...ctx.shown, project: params.project, ...environmentOf(params.environment), keys: null, purpose: 'run', upstream: null });
      if ('refused' in answer) throw refusal(answer.refused, path);
      const stop = stopOf(answer.items);
      if (stop !== undefined) throw refusal(stop.refused, `${path}/${stop.key}`);
      return { version: versionOf(answer.items.flatMap((item) => ('refused' in item ? [] : [item]))) };
    },
  }),
};
