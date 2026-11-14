import { createHash, randomBytes, randomUUID } from 'node:crypto';

import { allows, makesProjects, ownsProject, runsInstance, useOnly } from '@coffre/core/access';
import { CREDENTIAL_NAME } from '@coffre/core/identity';
import { PROJECT_PAGES } from '@coffre/core/pages';
import { tombstoneOf } from '@coffre/core/schemas';
import type { Answers, EnvironmentCopy, EnvironmentCreate, EnvironmentEdit, EnvironmentEdited, FolderRefile, Forked, PlaceDelete, PlaceDeleted, PlacesChanges, Presented, ProjectCreate, ProjectEdit, ProjectEdited } from '@coffre/core/vault';
import { dismissedKeys, environments, grants, principals, projects, secrets, secretVersions } from '@coffre/db/schema';
import { sql, type SQL } from 'drizzle-orm';

import { callerParts, live, refusedTo, type Asking } from '../caller.ts';
import { amended, copying, drop, overweight, part, put, type Operation, type Part, type Parts, type Plan, type Refusal, type Seen, type Unsealed, type Value, type Write } from '../change.ts';
import type { Said } from '../entry.ts';
import type { Fresh, Row, Sealed, Wire } from '../rows.ts';
import { natureOf } from '../value.ts';
import type { Deciding } from '../vault.ts';
import { asking, NOWHERE } from './asking.ts';
import type { Operations } from './index.ts';
import { MOST_KEYS, presented, text } from './input.ts';

/** A place's slug as one is made: a tombstone's `~` is the vault's alone (`PLACE_SLUG` in @coffre/db/schema). */
const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;
/** An environment's: none of a project's pages, which sit where its environments do. */
const environmentSlug = (slug: unknown): slug is string => typeof slug === 'string' && SLUG.test(slug) && !(PROJECT_PAGES as readonly string[]).includes(slug);

/** The most environments one inherits from, as a use reads them (use.ts). */
const MAX_PARENTS = 3;

/** A project's id by its slug, as SQL: the set `callerParts` reads the caller's holdings in. */
const projectOf = (slug: string) => sql`(SELECT p.id FROM projects p WHERE p.slug = ${slug})`;

/** The ids of the environment of `project` by its slug, and of those it inherits from, `depth` of them at most. */
const chainIds = (project: SQL, slug: string, depth: number) => sql`(WITH RECURSIVE chain (id, parent_id, depth) AS (
    SELECT e.id, e.parent_id, 0 FROM environments e WHERE e.project_id = ${project} AND e.slug = ${slug}
    UNION SELECT e.id, e.parent_id, chain.depth + 1 FROM environments e JOIN chain ON e.id = chain.parent_id WHERE chain.depth < ${depth}
  ) SELECT id FROM chain)`;

/** The same, each with how far it is from the one named: 0 for it, 1 for its parent. */
const chainDepths = (project: SQL, slug: string, depth: number) => sql`(WITH RECURSIVE chain (id, parent_id, depth) AS (
    SELECT e.id, e.parent_id, 0 FROM environments e WHERE e.project_id = ${project} AND e.slug = ${slug}
    UNION SELECT e.id, e.parent_id, chain.depth + 1 FROM environments e JOIN chain ON e.id = chain.parent_id WHERE chain.depth < ${depth}
  ) SELECT id, depth FROM chain)`;

/** The environment of `project` by its slug, and those it inherits from, nearest first, `depth` of them at most. */
const chainFrom = (project: SQL, slug: string, depth: number) => part(environments, sql`${environments.id} IN ${chainIds(project, slug, depth)}`);

/**
 * An id for a row a decision makes, of a number it cannot know before its
 * read: drawn from `seed`, drawn before it, and what the row is. A decision
 * draws nothing, so made again it makes the same ids. Shaped as a version 4
 * UUID, which Postgres keeps as written.
 */
function drawn(seed: Buffer, what: string): string {
  const hash = createHash('sha256').update(seed).update(what).digest();
  hash[6] = (hash[6]! & 0x0f) | 0x40;
  hash[8] = (hash[8]! & 0x3f) | 0x80;
  const hex = hash.subarray(0, 16).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

const NO_ACCESS: Refusal = { refused: 'no_access' };

/** The entry's fields every operation here gives the same way. */
const by = (caller: Asking, shown: ReturnType<typeof presented>) => ({ kept: true, actor: caller.principal, credential: caller.credential.id, request: shown.request, ip: shown.ip });

/**
 * A project (docs/design/0.16.md, "A change"): made by an Admin or Owner of
 * the instance whose scope takes in new projects, who holds it by that
 * role, so it gives them nothing more, as 0.14 gave nothing.
 */
function projectCreate(input: Presented & ProjectCreate, vault: Deciding): Operation<Parts, Answers['project.create']> {
  const shown = presented(input);
  const { project: slug } = input;
  if (typeof slug !== 'string' || !SLUG.test(slug)) throw new TypeError('a project is made by a slug of 1 to 63 of a-z, 0-9 and -, starting with a letter or digit');
  const id = randomUUID();

  const read = {
    // About no project yet: the caller's instance role is all that decides.
    ...callerParts(shown.token, NOWHERE),
    // The slug is free: read, so that two makings of one at once see each other's.
    taken: part(projects, sql`${projects.slug} = ${slug}`),
  };
  return {
    read,
    // The project a refusal was about is the one there under that slug, if any.
    denied: refusedTo('project.create', shown, vault.workloads, { where: { project: slug }, objects: (seen: Seen<typeof read>) => seen.taken.filter((row) => row.slug === slug && live(row)).map((row) => `project:${row.id}`) }),
    decide(seen: Seen<typeof read>, at: number) {
      const caller = asking(seen, shown, vault, at);
      if ('refused' in caller) return caller;
      // A role with no row is no role: an instance role whose row was not read makes nothing.
      if (!makesProjects(caller.holds) || !Object.hasOwn(caller.holds.policy.instanceRoles, caller.holds.role)) return { refused: 'no_access' };
      if (seen.taken.length > 0) return { refused: 'exists' };
      const row = { id, slug, name: slug, createdAt: new Date(at), archivedAt: null, folder: null };
      return {
        writes: [put(projects, row)],
        entry: { ...by(caller, shown), action: 'project.create', objects: [`project:${id}`, `principal:${caller.principal}`, `credential:${caller.credential.id}`], detail: { slug } },
        answer: { id },
      };
    },
  };
}

/**
 * An environment in a project, a fork that inherits from one or copies
 * one, or the caller's personal config of one (docs/design/forking.md):
 * what `EnvironmentCreate` says. A fork that copies is made in this one
 * change, with its keys: each value copied is opened and sealed again by
 * the engine (`Value`'s `copy`), as a restore's is, and the decision never
 * holds it. Its keys are resolved as a use resolves them (use.ts): the
 * nearest environment of `from`'s chain that holds a key live or dismissed
 * it settles it.
 */
function environmentCreate(input: Presented & EnvironmentCreate, vault: Deciding): Operation<Parts, Answers['environment.create']> {
  const shown = presented(input);
  const { project: projectSlug, environment: named, mine } = input;
  const copy = mine ? undefined : input.copy;
  const parentSlug = mine ? named : input.parent;
  if (!text(projectSlug) || typeof mine !== 'boolean' || (mine ? !text(named) || (input as { copy?: unknown }).copy !== undefined : !environmentSlug(named) || !(parentSlug === null || text(parentSlug)) || typeof input.protected !== 'boolean' || !copies(copy, parentSlug))) {
    throw new TypeError("an environment is made in a project by its slug, of 1 to 63 of a-z, 0-9 and -, none of a project's pages, with the environment it inherits from, the one it copies or neither, and whether it is protected; or as the caller's personal config of one");
  }
  const id = randomUUID();
  // The ids of a copy's keys and values, which the read says how many of: drawn from this.
  const seed = randomBytes(32);
  // A personal config's slug is never shown but to delete it: its environment's, and enough at random that two never meet.
  const slug = mine ? `${named.slice(0, 48)}-p-${randomBytes(4).toString('hex')}` : named;
  // The environment read by its slug: the one it inherits from, the one it copies, or none.
  const baseSlug = copy?.from ?? parentSlug;

  const project = projectOf(projectSlug);
  const principal = sql`(SELECT c.principal FROM credentials c WHERE c.token_hash = decode(${shown.token.toString('hex')}, 'hex'))`;
  // A copy's: the environments whose keys it copies, and the sources of the references among them, live, which may be in other projects.
  const layers = copy === undefined ? NONE : chainIds(project, copy.from, MAX_PARENTS);
  const referred = sql`(SELECT s.source_id FROM secrets s WHERE s.project_id = ${project} AND s.environment_id IN ${layers} AND s.archived_at IS NULL AND s.source_id IS NOT NULL)`;
  // The values the copy may copy, read only if they weigh no more than a change copies: each key's as `copied` resolves it,
  // the nearest layer's live key unless a nearer one dismissed it, or that key's source's. Not one a parent's key is
  // overridden by, nor one a reference to a sensitive source keeps, nor, in a fork by references, one its forker refers
  // to, which is any but a sensitive value of the layer's own (referred to by whoever uses it there) and a source's that
  // is not sensitive (by whoever reads it there): what it refers to, it reads no version of.
  const depths = copy === undefined ? NONE : chainDepths(project, copy.from, MAX_PARENTS);
  const weighing = copying(copy === undefined ? sql`false` : sql`(${secretVersions.secretId}, ${secretVersions.version}) IN (
    SELECT coalesce(src.id, s.id), coalesce(src.current_version, s.current_version) FROM (SELECT DISTINCT ON (k.key) k.secret FROM (
        SELECT s.key, s.id AS secret, c.depth, 0 AS dismissed FROM secrets s JOIN ${depths} AS c ON c.id = s.environment_id WHERE s.project_id = ${project} AND s.archived_at IS NULL
        UNION ALL SELECT d.key, NULL, c.depth, 1 FROM dismissed_keys d JOIN ${depths} AS c ON c.id = d.environment_id WHERE d.restored_at IS NULL
      ) k ORDER BY k.key, k.depth, k.dismissed) passed
    JOIN secrets s ON s.id = passed.secret LEFT JOIN secrets src ON src.id = s.source_id
    WHERE ${copy.references ? sql`(s.source_id IS NULL AND s.nature = 'sensitive') OR (src.id IS NOT NULL AND src.nature <> 'sensitive')` : sql`s.source_id IS NULL OR src.nature <> 'sensitive'`})`);
  const read = {
    // A reference's source may be in another project, whose grants and protections the caller is weighed by too.
    ...callerParts(shown.token, copy === undefined ? project : sql`(SELECT p.id FROM projects p WHERE p.slug = ${projectSlug} UNION SELECT s.project_id FROM secrets s WHERE s.id IN ${referred})`),
    project: part(projects, sql`${projects.slug} = ${projectSlug}`),
    // The environment it inherits from or copies, and those that one does, nearest first: one more than may be, so that a chain too long shows.
    chain: baseSlug === null ? part(environments, sql`false`) : chainFrom(project, baseSlug, MAX_PARENTS),
    // Every key of those environments, archived ones too: a row edited behind the vault may be a key, live or not, and is not guessed at.
    held: part(secrets, sql`${secrets.projectId} = ${project} AND ${secrets.environmentId} IN ${layers}`),
    dismissed: part(dismissedKeys, sql`${dismissedKeys.environmentId} IN ${layers}`),
    source: part(secrets, sql`${secrets.id} IN ${referred}`),
    sourcePlace: part(environments, sql`${environments.id} IN (SELECT s.environment_id FROM secrets s WHERE s.id IN ${referred})`),
    sourceProject: part(projects, sql`${projects.id} IN (SELECT s.project_id FROM secrets s WHERE s.id IN ${referred})`),
    version: weighing.part,
    // What would hold its place: the slug in the project, and for a personal config, the caller's of that environment.
    taken: part(environments, sql`(${environments.projectId} = ${project} AND ${environments.slug} = ${slug})${mine
      ? sql` OR (${environments.parentId} = (SELECT e.id FROM environments e WHERE e.project_id = ${project} AND e.slug = ${named}) AND ${environments.owner} = ${principal} AND strpos(${environments.slug}, '~') = 0)`
      : sql``}`),
  };
  /** The project named, the environment it inherits from or copies and the one already under its slug, as far as they are there: undefined for one that is not, null for none asked. */
  const placed = (seen: Seen<typeof read>) => {
    const place = seen.project.find((row) => row.slug === projectSlug && live(row));
    return {
      place,
      parent: place === undefined || baseSlug === null ? null : seen.chain.find((row) => row.projectId === place.id && row.slug === baseSlug && live(row) && row.owner === null),
      there: place === undefined ? undefined : seen.taken.find((row) => row.projectId === place.id && row.slug === slug && live(row)),
    };
  };
  return {
    read,
    ...(copy === undefined ? {} : { beside: { weighed: weighing.weighed } }),
    // A personal config is named by the environment it is of, the page its maker was on; anything else by its own slug, and its parent's if it has one.
    denied: refusedTo('environment.create', shown, vault.workloads, {
      where: { project: projectSlug, environment: named, ...(mine || parentSlug === null ? {} : { parent: parentSlug }), ...(copy === undefined ? {} : { from: copy.from }) },
      objects: (seen: Seen<typeof read>) => {
        const { place, parent, there } = placed(seen);
        return [...(place === undefined ? [] : [`project:${place.id}`]), ...(there === undefined ? [] : [`environment:${there.id}`]), ...(parent == null ? [] : [`environment:${parent.id}`])];
      },
    }),
    decide(seen: Seen<typeof read>, at: number, unsealed: Unsealed<typeof read>, _checked: undefined, beside?: Readonly<Record<string, readonly Wire[]>>) {
      const caller = asking(seen, shown, vault, at);
      if ('refused' in caller) return caller;
      const { place, parent } = placed(seen);
      if (place === undefined || parent === undefined) return { refused: 'no_access' };
      if (mine) {
        // A personal config is a person's, of an environment they read or use: it takes nothing more there.
        if (!caller.principal.startsWith('user:')) return { refused: 'not_a_person' };
        if (!caller.may('secret.read', parent!) && !caller.may('secret.use', parent!)) return { refused: 'no_access' };
      } else {
        if (!allows(caller.holds, 'environment.manage', { projectId: place.id })) return { refused: 'no_access' };
        // A fork reads its parent's values from its first moment, and a copy holds them: who makes either reads them too.
        if (parent !== null && !caller.may('secret.read', parent)) return { refused: 'no_access' };
      }
      // A copy inherits from nothing: its source's chain is read as a use reads it, below.
      const chained = parent === null || copy !== undefined ? null : chainOf(parent, seen.chain);
      if (chained !== null && chained !== 'ok') return { refused: chained };
      if (seen.taken.some((row) => (row.projectId === place.id && row.slug === slug) || (mine && row.parentId === parent!.id && row.owner === caller.principal))) return { refused: 'exists' };

      // A fork of a protected environment is protected, a copy as one that inherits.
      const guarded = !mine && (input.protected || parent?.protected === true);
      const row = { id, projectId: place.id, slug, name: slug, createdAt: new Date(at), archivedAt: null, parentId: copy === undefined ? (parent?.id ?? null) : null, owner: mine ? caller.principal : null, protected: guarded, frozenCredentials: [] };
      const forked = copy === undefined ? undefined : copied(seen, unsealed, { caller, place, from: parent!, made: row, copy, seed, at, heavy: overweight(beside?.weighed) });
      if (forked !== undefined && 'refused' in forked) return forked;
      return {
        // The environment first, which its keys are made in.
        writes: [put(environments, row), ...(forked?.writes ?? [])],
        values: forked?.values ?? [],
        entry: {
          ...by(caller, shown),
          action: 'environment.create',
          objects: [...new Set([`project:${place.id}`, `environment:${id}`, ...(parent === null ? [] : [`environment:${parent.id}`]), `principal:${caller.principal}`, `credential:${caller.credential.id}`, ...(forked?.objects ?? [])])],
          // A copy's: `from`, the environment it copies, whether references were asked for, and each key made, as `secret.write` says one.
          detail: { slug, protected: guarded, ...(parent === null ? {} : mine ? { personal: parent.slug } : copy === undefined ? { inherits: parent.slug } : { from: parent.slug, references: copy.references, keys: forked!.lines }) },
        },
        // A personal config is protected as its environment is, through it: its own row never says so.
        answer: { id, slug, protected: mine ? parent!.protected : guarded, ...(forked === undefined ? {} : { forked: forked.forked }) },
      };
    },
  };
}

/** What reads nothing, as the set of environments a making that copies none reads keys in. */
const NONE = sql`(SELECT NULL::uuid WHERE false)`;

/** Whether a making asks for a copy as the contract says one: of an environment by its slug, references or not, and so with no parent. */
const copies = (copy: unknown, parent: string | null): copy is EnvironmentCopy | undefined =>
  copy === undefined || (typeof copy === 'object' && copy !== null && text((copy as EnvironmentCopy).from) && typeof (copy as EnvironmentCopy).references === 'boolean' && parent === null);

/** The rows a fork that copies reads beyond any making's. */
type CopyParts = {
  chain: Part<typeof environments>;
  held: Part<typeof secrets>;
  dismissed: Part<typeof dismissedKeys>;
  source: Part<typeof secrets>;
  sourcePlace: Part<typeof environments>;
  sourceProject: Part<typeof projects>;
  version: Part<typeof secretVersions>;
};

/**
 * A fork's keys, copied or made references (`EnvironmentCopy`): each key
 * `from` reads now, as a use finds it, in the environment `made`. The
 * rows they are decided on are each the vault's, or none is guessed past
 * (`unreadable`): a key, a dismissal or a source edited behind it may be
 * what the fork would hold.
 */
function copied(
  seen: Seen<CopyParts>,
  unsealed: Unsealed<CopyParts>,
  { caller, place, from, made, copy, seed, at, heavy }: { caller: Asking; place: Row<typeof projects>; from: Row<typeof environments>; made: Fresh<typeof environments>; copy: EnvironmentCopy; seed: Buffer; at: number; heavy: boolean },
): Refusal | { writes: Write[]; values: Value[]; lines: Record<string, unknown>[]; objects: string[]; forked: Forked } {
  if (unsealed.chain + unsealed.held + unsealed.dismissed + unsealed.source + unsealed.sourcePlace + unsealed.sourceProject > 0) return { refused: 'unreadable' };
  // `from`, then what it inherits from, nearest first, as a use reads them: a parent gone, archived or out of the project cuts the chain.
  const layers = [from];
  for (let last = from; last.parentId !== null; ) {
    const above = seen.chain.find((row) => row.id === last.parentId);
    if (above === undefined || !live(above) || above.projectId !== place.id || layers.length > MAX_PARENTS) return { refused: 'broken_chain' };
    layers.push(above);
    last = above;
  }
  // Each live key by where it is, of this project: a row is held to what it is used for, not to the conditions it was read by.
  const keyed = new Map(seen.held.filter((row) => row.archivedAt === null && row.projectId === place.id).map((row) => [`${row.environmentId} ${row.key}`, row]));
  const off = new Set(seen.dismissed.filter((row) => row.restoredAt === null).map((row) => `${row.environmentId} ${row.key}`));
  const sources = new Map(seen.source.map((row) => [row.id, row]));
  const versions = new Map(seen.version.map((row) => [`${row.secretId} ${row.version}`, row]));
  const names = [...new Set([...keyed.values()].filter((row) => layers.some((layer) => layer.id === row.environmentId)).map((row) => row.key))].sort();
  const now = new Date(at);
  const writes: Write[] = [];
  const values: Value[] = [];
  const lines: Record<string, unknown>[] = [];
  const objects = new Set<string>();
  const forked: Forked = { keys: 0, references: 0, copied: [] };
  for (const key of names) {
    // The nearest environment that holds the key live, or dismissed it: one that dismissed it passes nothing down.
    let asked: Row<typeof secrets> | undefined;
    let layer = from;
    for (const each of layers) {
      asked = keyed.get(`${each.id} ${key}`);
      layer = each;
      if (asked !== undefined || off.has(`${each.id} ${key}`)) break;
    }
    if (asked === undefined) continue;
    // A key inherited is read where it is held: the forker reads that environment too.
    if (!caller.may('secret.read', layer)) return { refused: 'parent_unreadable' };
    // Where the value is held: the key, or the source a reference reads, one hop, live, in a live place and no personal config.
    let held = asked;
    let where = layer;
    if (asked.sourceId !== null) {
      const source = sources.get(asked.sourceId);
      const there = source && seen.sourcePlace.find((row) => row.id === source.environmentId && row.projectId === source.projectId);
      const whose = source && seen.sourceProject.find((row) => row.id === source.projectId);
      if (source === undefined || source.archivedAt !== null || source.sourceId !== null || there === undefined || !live(there) || there.owner !== null || whose === undefined || !live(whose)) return { refused: 'unreadable' };
      held = source;
      where = there;
    }
    // A key with no value, a reference broken, has nothing to copy; a source with none is a reference that reads nothing.
    if (held.currentVersion === null) {
      if (held === asked) continue;
      return { refused: 'unreadable' };
    }
    // A key with a value says its nature, under its MAC.
    const nature = held.nature;
    if (nature === null) return { refused: 'unreadable' };
    // A workload moves no value it only uses where it is held to a place whose keys it may read: neither by a copy nor a reference.
    if (nature !== 'plain' && useOnly(caller.holds, { projectId: held.projectId, environmentId: held.environmentId, secretId: held.id })) return { refused: 'use_only' };
    // A reference is made as `secret.write` makes one: its maker reads the source where it is held, and uses it there if it is sensitive.
    const refers = caller.may('secret.read', where) && (nature !== 'sensitive' || caller.may('secret.use', where));
    // A sensitive value of another key's, reached through a reference, stays a reference to it: a copy would hold it where its project does not.
    const kept = held !== asked && nature === 'sensitive';
    if (kept && !refers) return { refused: 'no_access' };
    const secret = drawn(seed, `secret ${key}`);
    const row = { id: secret, projectId: place.id, environmentId: made.id, key, createdAt: now, updatedAt: now, archivedAt: null, folder: asked.folder, recipe: null, pairId: null, pairHalf: null };
    if ((copy.references || kept) && refers) {
      writes.push(put(secrets, { ...row, versions: 0, currentVersion: null, sourceId: held.id, sourceSetAt: now, sourceSetBy: caller.principal, nature: null }));
      lines.push({ key, secret, refers: held.id, ...(asked.folder === null ? {} : { folder: asked.folder }) });
      forked.references += 1;
    } else {
      // Its value, labelled as its row says it, or none: the engine holds the version to its label as it opens it. Past what
      // a change copies, the read took no version: too much, not gone.
      const version = versions.get(`${held.id} ${held.currentVersion}`);
      if (version === undefined) return { refused: heavy ? 'too_much_to_copy' : 'unreadable' };
      if (natureOf(version) !== nature) return { refused: 'unreadable' };
      writes.push(put(secrets, { ...row, versions: 1, currentVersion: 1, sourceId: null, sourceSetAt: null, sourceSetBy: null, nature }));
      // Kept as it was, and opened and sealed again by the engine: nobody else holds it. Its first date is its source's, as a
      // restore's is: its forker did not write it (the member report's `created_at = first_written_at`), and never saw it.
      values.push({ version: { id: drawn(seed, `version ${key}`), secretId: secret, version: 1, createdAt: now, createdBy: caller.principal, sensitive: nature === 'sensitive', firstWrittenAt: version.firstWrittenAt, plaintext: nature === 'plain' ? version.plaintext : null }, copy: version });
      lines.push({ key, secret, version: 1, nature, copied: held.id, ...(asked.folder === null ? {} : { folder: asked.folder }) });
      if (copy.references) forked.copied.push(key);
    }
    forked.keys += 1;
    // Each key's pages find the fork, and a source elsewhere's place.
    objects.add(`secret:${secret}`);
    objects.add(`secret:${held.id}`);
    if (where.projectId !== place.id) objects.add(`project:${where.projectId}`);
    if (held !== asked) objects.add(`environment:${where.id}`);
  }
  // Each value copied is opened and sealed again in this one change: past what a write seals, a fork refers or inherits instead.
  if (values.length > MOST_KEYS) return { refused: 'too_many_keys' };
  return { writes, values, lines, objects: [...objects], forked };
}

/**
 * Whether one more environment may inherit from `parent`: every
 * environment above it is read, live and of its project, and it has two at
 * most, so that the new one has three. A missing one breaks the chain: a
 * row someone deleted refuses, it never shortens the chain.
 */
export function chainOf(parent: Row<typeof environments>, rows: readonly Row<typeof environments>[]): 'ok' | 'broken_chain' | 'too_deep' {
  let above = 0;
  for (let last = parent; last.parentId !== null; above += 1) {
    if (above + 1 >= MAX_PARENTS) return 'too_deep';
    const next = rows.find((row) => row.id === last.parentId);
    if (next === undefined || !live(next) || next.projectId !== parent.projectId) return 'broken_chain';
    last = next;
  }
  return 'ok';
}


/** A place a deletion has left no tombstone of: archived or not, it is there to edit. */
const standing = (row: { slug: string }) => !row.slug.includes('~');

/** A row as an edit leaves it: the one read, with what changes. */
function edited<T extends Sealed>(table: T, was: Row<T>, changes: Partial<Fresh<T>>) {
  const { mac: _, ...kept } = was as Row<T> & { mac: unknown };
  return put(table, { ...kept, ...changes } as Fresh<T>, was);
}

/** A project as an edit leaves it: the row read, with what changes. */
function projectLeft(was: Row<typeof projects>, changes: Partial<Fresh<typeof projects>> = {}): ProjectEdited {
  const now = { ...was, ...changes };
  return { id: now.id, slug: now.slug, archivedAt: now.archivedAt?.toISOString() ?? null, folder: now.folder };
}

/** An environment as an edit leaves it. */
function environmentLeft(was: Row<typeof environments>, changes: Partial<Fresh<typeof environments>> = {}): EnvironmentEdited {
  const now = { ...was, ...changes };
  return { id: now.id, slug: now.slug, archivedAt: now.archivedAt?.toISOString() ?? null, protected: now.protected };
}

/** A project's edit: its row written with `changes`, or none when nothing changes, the entry, and the project as it leaves it. */
function projectEdit(place: Row<typeof projects>, changes: Partial<Fresh<typeof projects>> | null, entry: Said): Plan<ProjectEdited> {
  return { writes: changes === null ? [] : [edited(projects, place, changes)], entry, answer: projectLeft(place, changes ?? {}) };
}

/**
 * Whether the caller owns the project, as 0.14 decided it for taking a
 * protection off (`ownsProject`, R30): an Owner by a grant on it, or by an
 * instance role whose scope takes in all of it, on no credential's scope,
 * and a person. A role with no row is no role: neither counts without the
 * Owner role's row read.
 */
export function owns(caller: Asking, projectId: string): boolean {
  const { holds } = caller;
  const { roles, instanceRoles } = holds.policy;
  return ownsProject({ ...holds, role: Object.hasOwn(instanceRoles, holds.role) ? holds.role : 'member', grants: holds.grants.filter((grant) => Object.hasOwn(roles, grant.role)) }, projectId);
}

type EditRead = ReturnType<typeof callerParts> & { project: ReturnType<typeof part<typeof projects>>; environment: ReturnType<typeof part<typeof environments>> };

/** What an edit's decision is given: who asks, the place they named, found, and an entry that names it. */
type Asked<E extends Parts> = {
  caller: Asking;
  place: Row<typeof projects>;
  seen: Seen<EditRead & E>;
  at: number;
  entry(detail: Record<string, unknown>, objects?: readonly string[]): Said;
};

/**
 * An edit of a project, or of an environment in one: who asks, the place
 * by its slugs, and what else the edit reads (`read`, given the project's
 * and the environment's ids as SQL). A place is there archived too, never
 * as a deletion's tombstone, and an environment is never a personal
 * config: either is no place, and the answer is the one for a place the
 * caller may not edit. A refusal is logged naming the place as asked and
 * the rows found of it.
 */
function editing<E extends Parts, A>(
  input: Presented & { op: string; project: string },
  environmentSlug: string | undefined,
  vault: Deciding,
  how: { where?: Record<string, string>; read?(project: SQL, environment: SQL): E; decide(asked: Asked<E> & { environment: Row<typeof environments> | undefined }): Plan<A> | Refusal },
): Operation<Parts, A> {
  const shown = presented(input);
  const { op: action, project: projectSlug } = input;
  if (!text(projectSlug)) throw new TypeError('an edit names a project by its slug');
  const project = projectOf(projectSlug);
  const environment = environmentSlug === undefined ? sql`(SELECT NULL::uuid WHERE false)` : sql`(SELECT e.id FROM environments e WHERE e.project_id = ${project} AND e.slug = ${environmentSlug})`;
  const base: EditRead = {
    ...callerParts(shown.token, project),
    project: part(projects, sql`${projects.slug} = ${projectSlug}`),
    environment: part(environments, environmentSlug === undefined ? sql`false` : sql`${environments.projectId} = ${project} AND ${environments.slug} = ${environmentSlug}`),
  };
  const read = { ...base, ...how.read?.(project, environment) } as EditRead & E;
  /** The place named, as far as it is there. */
  const placed = (seen: Seen<EditRead>) => {
    const place = seen.project.find((row) => row.slug === projectSlug && standing(row));
    const there = place === undefined ? undefined : seen.environment.find((row) => row.projectId === place.id && row.slug === environmentSlug && standing(row) && row.owner === null);
    return { place, there };
  };
  return {
    read,
    denied: refusedTo(action, shown, vault.workloads, {
      where: { project: projectSlug, ...(environmentSlug === undefined ? {} : { environment: environmentSlug }), ...how.where },
      objects: (seen: Seen<EditRead>) => {
        const { place, there } = placed(seen);
        return [...(place === undefined ? [] : [`project:${place.id}`]), ...(there === undefined ? [] : [`environment:${there.id}`])];
      },
    }),
    decide(seen: Seen<EditRead & E>, at: number) {
      const caller = asking(seen, shown, vault, at);
      if ('refused' in caller) return caller;
      const { place, there } = placed(seen as Seen<EditRead>);
      if (place === undefined || (environmentSlug !== undefined && there === undefined)) return NO_ACCESS;
      const entry = (detail: Record<string, unknown>, objects: readonly string[] = []): Said => ({
        ...by(caller, shown),
        action,
        objects: [`project:${place.id}`, ...(there === undefined ? [] : [`environment:${there.id}`]), ...objects, `principal:${caller.principal}`, `credential:${caller.credential.id}`],
        detail,
      });
      return how.decide({ caller, place, environment: there, seen, at, entry });
    },
  };
}

const onProject = <E extends Parts, A>(input: Presented & ProjectEdit, vault: Deciding, how: { where?: Record<string, string>; read?(project: SQL): E; decide(asked: Asked<E>): Plan<A> | Refusal }) =>
  editing<E, A>(input, undefined, vault, how);

function onEnvironment<E extends Parts, A>(input: Presented & EnvironmentEdit, vault: Deciding, how: { where?: Record<string, string>; read?(project: SQL, environment: SQL): E; decide(asked: Asked<E> & { environment: Row<typeof environments> }): Plan<A> | Refusal }) {
  if (!text(input.environment)) throw new TypeError('an edit names an environment by its slug in its project');
  // `editing` decides only once it has found the environment named.
  return editing<E, A>(input, input.environment, vault, { ...how, decide: (asked) => how.decide(asked as Asked<E> & { environment: Row<typeof environments> }) });
}

/** The project's own permission, for each of its edits. */
const manages = (caller: Asking, place: Row<typeof projects>) => allows(caller.holds, 'project.manage', { projectId: place.id });
/** Its environments', for each of theirs. */
const managesEnvironments = (caller: Asking, place: Row<typeof projects>) => allows(caller.holds, 'environment.manage', { projectId: place.id });

/**
 * The references held outside a place that read a value in it, with what
 * says whether each reads now: its source, and the environments and the
 * projects at both ends. `inside` is a condition on the source, `s`, and
 * `outside` on the reference, `h`.
 */
function readers(inside: SQL, outside: SQL) {
  const held = (column: SQL) => sql`SELECT ${column} FROM secrets h JOIN secrets s ON s.id = h.source_id WHERE ${inside} AND ${outside}`;
  return {
    reader: part(secrets, sql`${secrets.id} IN (${held(sql`h.id`)})`),
    source: part(secrets, sql`${secrets.id} IN (${held(sql`s.id`)})`),
    end: part(environments, sql`${environments.id} IN (${held(sql`h.environment_id`)}) OR ${environments.id} IN (${held(sql`s.environment_id`)})`),
    endProject: part(projects, sql`${projects.id} IN (${held(sql`h.project_id`)})`),
  };
}

/**
 * What archiving a place would stop (D41): each reference held outside it
 * that reads a value in it now, as a use would (use.ts). One the read found
 * and cannot clear, its source, environment or project not read, stops it
 * all the same: a row not read is never taken to say a reference reads
 * nothing. A reference held where nothing reads, archived or in a personal
 * config, stops nothing; nor one whose source reads nothing already: a
 * reference itself, or a key with no value yet (0.14's `source_empty`).
 */
function stopped(seen: Seen<ReturnType<typeof readers>>, inside: (row: Row<typeof secrets>) => boolean): Row<typeof secrets>[] {
  const reads = (environmentId: string) => {
    const at = seen.end.find((row) => row.id === environmentId);
    return at === undefined || (live(at) && at.owner === null);
  };
  return seen.reader.filter((holder) => {
    if (holder.sourceId === null || inside(holder) || holder.archivedAt !== null || !reads(holder.environmentId)) return false;
    const whose = seen.endProject.find((row) => row.id === holder.projectId);
    if (whose !== undefined && !live(whose)) return false;
    const source = seen.source.find((row) => row.id === holder.sourceId);
    return source === undefined || (inside(source) && source.archivedAt === null && source.sourceId === null && source.currentVersion !== null && reads(source.environmentId));
  });
}

/** A folder's name as the table checks it (`projects_folder_check`): 1 to 64 characters, no `/`, no control character, no space at either end. */
const folder = (name: unknown): name is string | null =>
  name === null || (typeof name === 'string' && [...name].length >= 1 && [...name].length <= 64 && name === name.trim() && !/[/\p{Cc}]/u.test(name));

type Op<C extends { op: string }, K extends C['op']> = Presented & Extract<C, { op: K }>;

/** A project's new slug, free as a new project's must be: archived ones' included. */
function projectUpdate(input: Op<ProjectEdit, 'project.update'>, vault: Deciding): Operation<Parts, Answers['project.update']> {
  const { slug } = input;
  if (typeof slug !== 'string' || !SLUG.test(slug)) throw new TypeError('a project is re-slugged to 1 to 63 of a-z, 0-9 and -, starting with a letter or digit');
  return onProject(input, vault, {
    where: { slug },
    read: () => ({ taken: part(projects, sql`${projects.slug} = ${slug}`) }),
    decide({ caller, place, seen, entry }) {
      if (!manages(caller, place)) return NO_ACCESS;
      if (place.slug !== slug && seen.taken.some((row) => row.slug === slug)) return { refused: 'exists' };
      return projectEdit(place, place.slug === slug ? null : { slug }, entry({ from: place.slug, slug }));
    },
  });
}

/** A project archived: refused while a reference held outside it reads a value in it. */
function projectArchive(input: Op<ProjectEdit, 'project.archive'>, vault: Deciding): Operation<Parts, Answers['project.archive']> {
  return onProject(input, vault, {
    read: (project) => readers(sql`s.project_id = ${project}`, sql`h.project_id <> ${project}`),
    decide({ caller, place, seen, at, entry }) {
      if (!manages(caller, place)) return NO_ACCESS;
      if (place.archivedAt !== null) return projectEdit(place, null, entry({ slug: place.slug }));
      if (stopped(seen, (row) => row.projectId === place.id).length > 0) return { refused: 'referenced' };
      return projectEdit(place, { archivedAt: new Date(at) }, entry({ slug: place.slug }));
    },
  });
}

/** A project brought back. */
function projectRestore(input: Op<ProjectEdit, 'project.restore'>, vault: Deciding): Operation<Parts, Answers['project.restore']> {
  return onProject(input, vault, {
    decide({ caller, place, entry }) {
      if (!manages(caller, place)) return NO_ACCESS;
      return projectEdit(place, place.archivedAt === null ? null : { archivedAt: null }, entry({ slug: place.slug }));
    },
  });
}

/** A project filed in a folder, or in none. A folder is a label: one that no project is in is no folder. */
function projectMove(input: Op<ProjectEdit, 'project.move'>, vault: Deciding): Operation<Parts, Answers['project.move']> {
  const { folder: to } = input;
  if (!folder(to)) throw new TypeError('a project is filed in a folder of 1 to 64 characters, with no "/", no control character and no space at either end, or in none');
  return onProject(input, vault, {
    decide({ caller, place, entry }) {
      if (!manages(caller, place)) return NO_ACCESS;
      return projectEdit(place, place.folder === to ? null : { folder: to }, entry({ slug: place.slug, from: place.folder, to }));
    },
  });
}

/**
 * A folder of projects renamed, or emptied: every project filed there, in
 * one change, by whoever manages each one. The projects are read by the
 * folder, and the caller's holdings in them.
 */
function folderRefile(input: Presented & FolderRefile, vault: Deciding): Operation<Parts, Answers['folder.refile']> {
  const shown = presented(input);
  const { folder: from, to } = input;
  if (from === null || !folder(from) || !folder(to)) throw new TypeError('a folder is renamed to one of 1 to 64 characters, with no "/", no control character and no space at either end, or emptied');
  const filed = sql`(SELECT p.id FROM projects p WHERE p.folder = ${from})`;
  const read = { ...callerParts(shown.token, filed), filed: part(projects, sql`${projects.folder} = ${from}`) };
  /** The projects filed there, a deletion's tombstones left out. */
  const there = (seen: Seen<typeof read>) => seen.filed.filter((row) => row.folder === from && standing(row));
  return {
    read,
    // A folder's name is no slug, which is all a refusal logs of what was asked: the projects filed there name it.
    denied: refusedTo('folder.refile', shown, vault.workloads, { objects: (seen: Seen<typeof read>) => there(seen).map((row) => `project:${row.id}`) }),
    decide(seen: Seen<typeof read>, at: number) {
      const caller = asking(seen, shown, vault, at);
      if ('refused' in caller) return caller;
      const projectsThere = there(seen);
      // Half a folder renamed would be two folders: all of them, or none.
      if (projectsThere.length === 0 || projectsThere.some((row) => !manages(caller, row))) return NO_ACCESS;
      const moved = projectsThere.map((row) => row.slug).sort();
      return {
        writes: to === from ? [] : projectsThere.map((row) => edited(projects, row, { folder: to })),
        entry: { ...by(caller, shown), action: 'folder.refile', objects: [...projectsThere.map((row) => `project:${row.id}`), `principal:${caller.principal}`, `credential:${caller.credential.id}`], detail: { folder: from, to, projects: moved } },
        answer: { moved },
      };
    },
  };
}

/** An environment's new slug, free in its project. */
function environmentUpdate(input: Op<EnvironmentEdit, 'environment.update'>, vault: Deciding): Operation<Parts, Answers['environment.update']> {
  const { slug } = input;
  if (!environmentSlug(slug)) throw new TypeError("an environment is re-slugged to 1 to 63 of a-z, 0-9 and -, none of a project's pages");
  return onEnvironment(input, vault, {
    where: { slug },
    read: (project) => ({ taken: part(environments, sql`${environments.projectId} = ${project} AND ${environments.slug} = ${slug}`) }),
    decide({ caller, place, environment, seen, entry }) {
      if (!managesEnvironments(caller, place)) return NO_ACCESS;
      if (environment.slug !== slug && seen.taken.some((row) => row.projectId === place.id && row.slug === slug)) return { refused: 'exists' };
      return { writes: environment.slug === slug ? [] : [edited(environments, environment, { slug })], entry: entry({ from: environment.slug, slug }), answer: environmentLeft(environment, { slug }) };
    },
  });
}

/** The environments that inherit from one, personal configs included, as SQL. */
const childrenOf = (environment: SQL) => ({ child: part(environments, sql`${environments.parentId} = ${environment}`) });

/**
 * An environment archived, with its personal configs: refused while a
 * live fork inherits from it, which would read nothing of it then, or a
 * reference held outside it reads a value in it.
 */
function environmentArchive(input: Op<EnvironmentEdit, 'environment.archive'>, vault: Deciding): Operation<Parts, Answers['environment.archive']> {
  return onEnvironment(input, vault, {
    read: (project, environment) => ({ ...childrenOf(environment), ...readers(sql`s.project_id = ${project} AND s.environment_id = ${environment}`, sql`h.environment_id <> ${environment}`) }),
    decide({ caller, place, environment, seen, at, entry }) {
      if (!managesEnvironments(caller, place)) return NO_ACCESS;
      if (environment.archivedAt !== null) return { writes: [], entry: entry({ slug: environment.slug }), answer: environmentLeft(environment) };
      // In an archived project, nothing is read from it already.
      if (place.archivedAt === null && stopped(seen, (row) => row.environmentId === environment.id).length > 0) return { refused: 'referenced' };
      const children = seen.child.filter((row) => row.parentId === environment.id && row.projectId === place.id && live(row));
      if (children.some((row) => row.owner === null)) return { refused: 'inherited' };
      const archivedAt = new Date(at);
      return {
        writes: [edited(environments, environment, { archivedAt }), ...children.map((row) => edited(environments, row, { archivedAt }))],
        entry: entry({ slug: environment.slug, ...(children.length === 0 ? {} : { personal: children.map((row) => row.slug) }) }, children.map((row) => `environment:${row.id}`)),
        answer: environmentLeft(environment, { archivedAt }),
      };
    },
  });
}

/**
 * An environment brought back, with its personal configs: while every one
 * it inherits from is live, and each is read, of its project, three at
 * most. A personal config archived on its own comes back too, as in 0.14.
 */
function environmentRestore(input: Op<EnvironmentEdit, 'environment.restore'>, vault: Deciding): Operation<Parts, Answers['environment.restore']> {
  return onEnvironment(input, vault, {
    read: (project, environment) => ({ ...childrenOf(environment), chain: chainFrom(project, input.environment, MAX_PARENTS + 1) }),
    decide({ caller, place, environment, seen, entry }) {
      if (!managesEnvironments(caller, place)) return NO_ACCESS;
      if (environment.archivedAt === null) return { writes: [], entry: entry({ slug: environment.slug }), answer: environmentLeft(environment) };
      const parents = ancestry(environment, seen.chain);
      if (parents !== 'ok') return { refused: parents };
      const children = seen.child.filter((row) => row.parentId === environment.id && row.projectId === place.id && row.owner !== null && standing(row) && row.archivedAt !== null);
      return {
        writes: [edited(environments, environment, { archivedAt: null }), ...children.map((row) => edited(environments, row, { archivedAt: null }))],
        entry: entry({ slug: environment.slug, ...(children.length === 0 ? {} : { personal: children.map((row) => row.slug) }) }, children.map((row) => `environment:${row.id}`)),
        answer: environmentLeft(environment, { archivedAt: null }),
      };
    },
  });
}

/**
 * Whether what an environment inherits from is live: each one above it
 * read, of its project, no personal config, and three at most. One
 * archived or deleted is `parent_archived`; a chain that cannot be read
 * through is `broken_chain`.
 */
function ancestry(environment: Row<typeof environments>, rows: readonly Row<typeof environments>[]): 'ok' | 'parent_archived' | 'broken_chain' {
  let above = 0;
  for (let last = environment; last.parentId !== null; above += 1) {
    if (above >= MAX_PARENTS) return 'broken_chain';
    const next = rows.find((row) => row.id === last.parentId);
    if (next === undefined || next.projectId !== environment.projectId || next.owner !== null) return 'broken_chain';
    if (!live(next)) return 'parent_archived';
    last = next;
  }
  return 'ok';
}

/**
 * An environment protected, or its protection taken off, as 0.14 did
 * (docs/design/roles.md, section 2): by whoever manages its project's
 * environments, never by a workload's session; taken off by an Owner of the
 * project alone.
 */
function protection(on: boolean) {
  return (input: Op<EnvironmentEdit, 'environment.protect' | 'environment.unprotect'>, vault: Deciding): Operation<Parts, EnvironmentEdited> =>
    onEnvironment(input, vault, {
      decide({ caller, place, environment, entry }) {
        if (!managesEnvironments(caller, place)) return NO_ACCESS;
        // A workload's session changes no one's access (docs/design/workload-access.md, D15).
        if (caller.workload !== null) return { refused: 'workload_cannot_issue' };
        // Taking it off widens what people hold there (R30).
        if (!on && !owns(caller, place.id)) return NO_ACCESS;
        return { writes: environment.protected === on ? [] : [edited(environments, environment, { protected: on })], entry: entry({ slug: environment.slug }), answer: environmentLeft(environment, { protected: on }) };
      },
    });
}

/**
 * An upstream credential frozen in a live environment, or the freeze lifted
 * (docs/design/workload-access.md, section 8.2): frozen by whoever writes
 * there, lifted by an Owner of the project.
 */
function freezing(on: boolean) {
  return (input: Op<EnvironmentEdit, 'upstream.freeze' | 'upstream.thaw'>, vault: Deciding): Operation<Parts, EnvironmentEdited> => {
    const { upstream } = input;
    if (typeof upstream !== 'string' || !CREDENTIAL_NAME.test(upstream)) throw new TypeError('an upstream credential is named as the deployment names it: a-z, then up to 31 of a-z, 0-9 and -');
    return onEnvironment(input, vault, {
      where: { upstream },
      decide({ caller, place, environment, entry }) {
        if (!live(place) || !live(environment)) return NO_ACCESS;
        if (on ? !caller.may('secret.write', environment) : !owns(caller, place.id)) return NO_ACCESS;
        const frozen = environment.frozenCredentials.includes(upstream);
        const next = on ? [...environment.frozenCredentials, upstream].sort() : environment.frozenCredentials.filter((name) => name !== upstream);
        return { writes: frozen === on ? [] : [edited(environments, environment, { frozenCredentials: next })], entry: entry({ slug: environment.slug, upstream }), answer: environmentLeft(environment) };
      },
    });
  };
}

/**
 * The most versions holding a value that one deletion erases. Its write is
 * one statement, which the change lock and `WRITE_MS` bound; emptying a
 * version is a row rewritten in place, and this many take well under a
 * second of it (docs/design/0.16.md, "Deleting a place"). Past it, nothing
 * is erased: a project's environments are deleted one at a time first.
 */
export const MOST_ERASED = 20_000;

/** A personal config as its deletion names it: `dev@ada@acme.example`, its environment's slug and its owner's email or id. */
const configName = (parent: string, owner: string) => `${parent}@${owner.replace(/^user:/, '')}`;

/**
 * A place deleted for good (`PlaceDelete`), as 0.14.7's `deletePlace`
 * did it, in one change where 0.14 took a vault call per member, another
 * for the references and a transaction: nothing between them to finish
 * when asked again, nor to re-check. What it reads: the project, its
 * environments, the grants on them and their members' other grants, the
 * references into them and out of them with where each end is, and,
 * beside, how many keys and versions are there. What it writes: the
 * place's row under its tombstone's slug (and its personal configs'),
 * each grant dropped, each reference's holder amended to none, and every
 * version emptied (`Plan.erase`).
 */
function placeDelete(input: Presented & PlaceDelete, vault: Deciding): Operation<Parts, PlaceDeleted> {
  const shown = presented(input);
  const { op: action, project: projectSlug } = input;
  const named = input.op === 'environment.delete' ? input.environment : null;
  const mine = input.op === 'environment.delete' && input.mine;
  if (!text(projectSlug) || (input.op === 'environment.delete' && (!text(named) || typeof input.mine !== 'boolean'))) {
    throw new TypeError("a deletion names a project by its slug, or an environment in one by its slug, or the caller's personal config of one");
  }
  const project = projectOf(projectSlug);
  const principal = sql`(SELECT c.principal FROM credentials c WHERE c.token_hash = decode(${shown.token.toString('hex')}, 'hex'))`;
  /** The environment named, as SQL: for `mine`, the caller's standing config of it. */
  const environment = named === null
    ? null
    : mine
      ? sql`(SELECT e.id FROM environments e WHERE e.project_id = ${project} AND e.owner = ${principal} AND strpos(e.slug, '~') = 0
          AND e.parent_id = (SELECT p.id FROM environments p WHERE p.project_id = ${project} AND p.slug = ${named}))`
      : sql`(SELECT e.id FROM environments e WHERE e.project_id = ${project} AND e.slug = ${named})`;
  /** Where the deletion takes keys, as SQL on a secret `s`: the project's, or the environment's and its standing personal configs'. */
  const within = environment === null
    ? sql`s.project_id = ${project}`
    : sql`s.environment_id IN (SELECT e.id FROM environments e WHERE e.id = ${environment} OR (e.parent_id = ${environment} AND e.owner IS NOT NULL AND strpos(e.slug, '~') = 0))`;
  /** Where a grant on it is, as SQL on a grant `g`. */
  const granted = environment === null
    ? sql`(g.project_id = ${project} OR g.environment_id IN (SELECT e.id FROM environments e WHERE e.project_id = ${project}))`
    : sql`g.environment_id = ${environment}`;
  const holders = sql`SELECT s.id FROM secrets s WHERE s.source_id IS NOT NULL AND (${within} OR s.source_id IN (SELECT s.id FROM secrets s WHERE ${within}))`;
  const ends = sql`SELECT h.id FROM secrets h WHERE h.id IN (${holders}) UNION SELECT h.source_id FROM secrets h WHERE h.id IN (${holders})`;
  const read = {
    ...callerParts(shown.token, project),
    // The project, and its tombstones, whose slugs a new one is not.
    project: part(projects, sql`${projects.slug} = ${projectSlug} OR strpos(${projects.slug}, ${`${projectSlug}~deleted-`}) = 1`),
    // Every environment of it: those it takes, a fork that keeps one, and the tombstones a new one's slug is not.
    places: part(environments, sql`${environments.projectId} = ${project}`),
    // Each member with a grant on it, and every grant they hold: those it revokes, and whether any is left.
    grantee: part(principals, sql`${principals.id} IN (SELECT g.principal FROM grants g WHERE ${granted})`),
    held: part(grants, sql`${grants.principal} IN (SELECT g.principal FROM grants g WHERE ${granted})`),
    // Each reference held in it, or reading a value in it, and its source, with the environments and projects at both ends.
    end: part(secrets, sql`${secrets.id} IN (${ends})`),
    endPlace: part(environments, sql`${environments.id} IN (SELECT s.environment_id FROM secrets s WHERE s.id IN (${ends}))`),
    endProject: part(projects, sql`${projects.id} IN (SELECT s.project_id FROM secrets s WHERE s.id IN (${ends}))`),
  };
  // What no decision of access goes by: how many keys are there, and how many of their versions hold a value.
  const beside = {
    counted: sql`SELECT jsonb_build_object(
      'keys', (SELECT count(*) FROM secrets s WHERE ${within}),
      'versions', (SELECT count(*) FROM secret_versions v JOIN secrets s ON s.id = v.secret_id WHERE ${within}
        AND (octet_length(v.ciphertext) > 0 OR octet_length(v.wrapped_dek) > 0 OR v.plaintext IS NOT NULL))) AS row`,
  };
  /** The place named, as far as it is there: the project, and the environment or personal config. */
  const placed = (seen: Seen<typeof read>) => {
    const place = seen.project.find((row) => row.slug === projectSlug && standing(row));
    if (place === undefined || named === null) return { place, there: undefined };
    const ofProject = (row: Row<typeof environments>) => row.projectId === place.id && standing(row);
    if (!mine) return { place, there: seen.places.find((row) => ofProject(row) && row.slug === named) };
    const parent = seen.places.find((row) => ofProject(row) && row.slug === named && row.owner === null);
    // The caller's own: their principal's row, which the caller's parts read.
    const caller = seen.principal[0]?.id;
    return { place, there: parent && seen.places.find((row) => ofProject(row) && row.parentId === parent.id && row.owner !== null && row.owner === caller) };
  };
  return {
    read,
    beside,
    denied: refusedTo(action, shown, vault.workloads, {
      where: { project: projectSlug, ...(named === null ? {} : { environment: named }) },
      objects: (seen: Seen<typeof read>) => {
        const { place, there } = placed(seen);
        return [...(place === undefined ? [] : [`project:${place.id}`]), ...(there === undefined ? [] : [`environment:${there.id}`])];
      },
    }),
    decide(seen: Seen<typeof read>, at: number, _unsealed, _checked, rode) {
      const caller = asking(seen, shown, vault, at);
      if ('refused' in caller) return caller;
      const { place, there } = placed(seen);
      if (place === undefined || (named !== null && there === undefined)) return NO_ACCESS;
      const ofPlace = (row: Row<typeof environments>) => row.projectId === place.id;
      const parentOf = there?.owner == null ? undefined : seen.places.find((row) => ofPlace(row) && row.id === there.parentId);
      const personal = there !== undefined && there.owner !== null;
      if (personal) {
        // A personal config: its owner's, or whoever manages the project's environments, archived or not (0.14's `deletePersonal`).
        if (there.owner !== caller.principal && !allows(caller.holds, 'environment.manage', { projectId: place.id })) return NO_ACCESS;
      } else {
        // A role with no row is no role, as for making a project.
        if (!runsInstance(caller.holds) || !Object.hasOwn(caller.holds.policy.instanceRoles, caller.holds.role)) return NO_ACCESS;
        if ((there ?? place).archivedAt === null) return { refused: 'not_archived' };
        // A fork, archived or not, keeps its parent: a personal config does not, and goes with it.
        if (there !== undefined && seen.places.some((row) => ofPlace(row) && row.parentId === there.id && row.owner === null && standing(row))) return { refused: 'inherited' };
      }
      const counted = (rode?.counted?.[0] ?? {}) as { keys?: number; versions?: number };
      const keys = Number(counted.keys ?? 0);
      const versions = Number(counted.versions ?? 0);
      if (versions > MOST_ERASED) return { refused: 'too_large' };

      const day = new Date(at);
      /** The first tombstone of `slug` that day that none of `taken` holds. */
      const tombstone = (slug: string, taken: readonly { slug: string }[]) => {
        let n = 1;
        while (taken.some((row) => row.slug === tombstoneOf(slug, day, n))) n += 1;
        return tombstoneOf(slug, day, n);
      };
      const configs = there === undefined || personal ? [] : seen.places.filter((row) => ofPlace(row) && row.parentId === there.id && row.owner !== null && standing(row));
      const taken = seen.places.filter(ofPlace);
      const gone = there === undefined ? [] : [there, ...configs];
      const marks = gone.map((row) => ({ row, slug: tombstone(row.slug, taken) }));
      const mark = there === undefined ? tombstone(place.slug, seen.project) : marks[0]!.slug;
      const inside = (environmentId: string, projectId: string) => (there === undefined ? projectId === place.id : gone.some((row) => row.id === environmentId));

      // The grants on it, lapsed ones too; and who holds nothing elsewhere then, with no instance role to keep them in.
      const doomed = seen.held.filter((grant) => (there === undefined
        ? grant.projectId === place.id || seen.places.some((row) => ofPlace(row) && row.id === grant.environmentId)
        : grant.environmentId === there.id));
      const environmentSlug = (id: string | null) => seen.places.find((row) => row.id === id)?.slug ?? id;
      const stranded = seen.grantee
        .filter((member) => doomed.some((grant) => grant.principal === member.id) && member.role === 'member')
        .filter((member) => seen.held.every((grant) => grant.principal !== member.id || doomed.includes(grant) || (grant.expiresAt !== null && grant.expiresAt.getTime() <= at)))
        .map((member) => member.id)
        .sort();

      // The references into it and out of it: each holder reads nothing since, as a reference holds no value of its own.
      const pathOf = (secret: Row<typeof secrets> | undefined) => {
        const where = secret && seen.endPlace.find((row) => row.id === secret.environmentId && row.projectId === secret.projectId);
        const whose = where && seen.endProject.find((row) => row.id === where.projectId);
        return whose === undefined ? '(gone)' : `${whose.slug}/${where!.owner === null ? where!.slug : configName(seen.endPlace.find((row) => row.id === where!.parentId)?.slug ?? '?', where!.owner)}/${secret!.key}`;
      };
      const ended = seen.end.filter((holder) => holder.sourceId !== null && (inside(holder.environmentId, holder.projectId)
        || seen.end.some((source) => source.id === holder.sourceId && inside(source.environmentId, source.projectId))));

      const path = there === undefined ? place.slug : `${place.slug}/${personal ? configName(parentOf?.slug ?? '?', there.owner!) : there.slug}`;
      const answer: PlaceDeleted = {
        path,
        tombstone: mark,
        environments: there === undefined
          // Every standing one, personal configs too, as 0.14.7 listed them: their values go with it.
          ? seen.places.filter((row) => ofPlace(row) && standing(row))
            .map((row) => (row.owner === null ? row.slug : configName(seen.places.find((parent) => parent.id === row.parentId)?.slug ?? '?', row.owner))).sort()
          : personal ? [there.slug] : [there.slug, ...configs.map((row) => configName(there.slug, row.owner!))],
        keys,
        versions,
        grants: doomed.map((grant) => ({ member: grant.principal, place: grant.environmentId === null ? place.slug : `${place.slug}/${environmentSlug(grant.environmentId)}`, role: grant.role }))
          .sort((a, b) => a.member.localeCompare(b.member) || a.place.localeCompare(b.place)),
        references: ended.map((holder) => ({ holder: pathOf(holder), source: pathOf(seen.end.find((row) => row.id === holder.sourceId)) }))
          .sort((a, b) => a.holder.localeCompare(b.holder) || a.source.localeCompare(b.source)),
        stranded,
      };
      return {
        writes: [
          ...(there === undefined ? [amended(projects, place, { slug: mark })] : marks.map(({ row, slug }) => amended(environments, row, { slug }))),
          ...doomed.map((grant) => drop(grants, grant)),
          ...ended.map((holder) => amended(secrets, holder, { sourceId: null, sourceSetAt: null, sourceSetBy: null, updatedAt: new Date(at) })),
        ],
        erase: there === undefined ? { projects: [place] } : { environments: gone },
        entry: {
          ...by(caller, shown),
          action,
          objects: [...new Set([
            `project:${place.id}`,
            ...gone.map((row) => `environment:${row.id}`),
            ...doomed.map((grant) => `principal:${grant.principal}`),
            ...ended.flatMap((holder) => [`secret:${holder.id}`, `secret:${holder.sourceId}`]),
            `principal:${caller.principal}`,
            `credential:${caller.credential.id}`,
          ])],
          detail: {
            path,
            tombstone: mark,
            keys,
            versions,
            grants: doomed.length,
            references: ended.length,
            ...(personal ? { personal: true } : configs.length === 0 ? {} : { personal: configs.map((row) => row.slug) }),
          },
        },
        answer,
      };
    },
  };
}

/** The changes of projects and environments (docs/design/0.16.md, "A change"). */
export const placeOperations: Operations<PlacesChanges> = {
  'project.create': projectCreate,
  'environment.create': environmentCreate,
  'project.update': projectUpdate,
  'project.archive': projectArchive,
  'project.restore': projectRestore,
  'project.move': projectMove,
  'folder.refile': folderRefile,
  'environment.update': environmentUpdate,
  'environment.archive': environmentArchive,
  'environment.restore': environmentRestore,
  'environment.protect': protection(true),
  'environment.unprotect': protection(false),
  'upstream.freeze': freezing(true),
  'upstream.thaw': freezing(false),
  'project.delete': placeDelete,
  'environment.delete': placeDelete,
};
