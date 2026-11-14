import { randomBytes, randomUUID } from 'node:crypto';

import { allows, makesProjects, ownsProject } from '@coffre/core/access';
import { CREDENTIAL_NAME } from '@coffre/core/identity';
import { PROJECT_PAGES } from '@coffre/core/pages';
import type { Answers, EnvironmentCreate, EnvironmentEdit, EnvironmentEdited, FolderRefile, PlacesChanges, Presented, ProjectCreate, ProjectEdit, ProjectEdited } from '@coffre/core/vault';
import { environments, projects, secrets } from '@coffre/db/schema';
import { sql, type SQL } from 'drizzle-orm';

import { callerParts, live, refusedTo, type Asking } from '../caller.ts';
import { part, put, type Operation, type Parts, type Plan, type Refusal, type Seen } from '../change.ts';
import type { Said } from '../entry.ts';
import type { Fresh, Row, Sealed } from '../rows.ts';
import type { Deciding } from '../vault.ts';
import { asking, NOWHERE } from './asking.ts';
import type { Operations } from './index.ts';
import { presented, text } from './input.ts';

/** A place's slug as one is made: a tombstone's `~` is the vault's alone (`PLACE_SLUG` in @coffre/db/schema). */
const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;
/** An environment's: none of a project's pages, which sit where its environments do. */
const environmentSlug = (slug: unknown): slug is string => typeof slug === 'string' && SLUG.test(slug) && !(PROJECT_PAGES as readonly string[]).includes(slug);

/** The most environments one inherits from, as a use reads them (use.ts). */
const MAX_PARENTS = 3;

/** A project's id by its slug, as SQL: the set `callerParts` reads the caller's holdings in. */
const projectOf = (slug: string) => sql`(SELECT p.id FROM projects p WHERE p.slug = ${slug})`;

/** The environment of `project` by its slug, and those it inherits from, nearest first, `depth` of them at most. */
const chainFrom = (project: SQL, slug: string, depth: number) =>
  part(environments, sql`${environments.id} IN (WITH RECURSIVE chain (id, parent_id, depth) AS (
    SELECT e.id, e.parent_id, 0 FROM environments e WHERE e.project_id = ${project} AND e.slug = ${slug}
    UNION SELECT e.id, e.parent_id, chain.depth + 1 FROM environments e JOIN chain ON e.id = chain.parent_id WHERE chain.depth < ${depth}
  ) SELECT id FROM chain)`);

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
 * An environment in a project, a fork that inherits from one, or the
 * caller's personal config of one (docs/design/forking.md): what
 * `EnvironmentCreate` says. Forks that copy their parent's values come
 * when the engine copies a stored value.
 */
function environmentCreate(input: Presented & EnvironmentCreate, vault: Deciding): Operation<Parts, Answers['environment.create']> {
  const shown = presented(input);
  const { project: projectSlug, environment: named, mine } = input;
  const parentSlug = mine ? named : input.parent;
  if (!text(projectSlug) || typeof mine !== 'boolean' || (mine ? !text(named) : !environmentSlug(named) || !(parentSlug === null || text(parentSlug)) || typeof input.protected !== 'boolean')) {
    throw new TypeError("an environment is made in a project by its slug, of 1 to 63 of a-z, 0-9 and -, none of a project's pages, with the environment it inherits from or none, and whether it is protected; or as the caller's personal config of one");
  }
  const id = randomUUID();
  // A personal config's slug is never shown but to delete it: its environment's, and enough at random that two never meet.
  const slug = mine ? `${named.slice(0, 48)}-p-${randomBytes(4).toString('hex')}` : named;

  const project = projectOf(projectSlug);
  const principal = sql`(SELECT c.principal FROM credentials c WHERE c.token_hash = decode(${shown.token.toString('hex')}, 'hex'))`;
  const read = {
    ...callerParts(shown.token, project),
    project: part(projects, sql`${projects.slug} = ${projectSlug}`),
    // The environment it inherits from, and those that one does, nearest first: one more than may be, so that a chain too long shows.
    chain: parentSlug === null ? part(environments, sql`false`) : chainFrom(project, parentSlug, MAX_PARENTS),
    // What would hold its place: the slug in the project, and for a personal config, the caller's of that environment.
    taken: part(environments, sql`(${environments.projectId} = ${project} AND ${environments.slug} = ${slug})${mine
      ? sql` OR (${environments.parentId} = (SELECT e.id FROM environments e WHERE e.project_id = ${project} AND e.slug = ${named}) AND ${environments.owner} = ${principal} AND strpos(${environments.slug}, '~') = 0)`
      : sql``}`),
  };
  /** The project named, the environment it inherits from and the one already under its slug, as far as they are there: undefined for one that is not, null for no parent asked. */
  const placed = (seen: Seen<typeof read>) => {
    const place = seen.project.find((row) => row.slug === projectSlug && live(row));
    return {
      place,
      parent: place === undefined || parentSlug === null ? null : seen.chain.find((row) => row.projectId === place.id && row.slug === parentSlug && live(row) && row.owner === null),
      there: place === undefined ? undefined : seen.taken.find((row) => row.projectId === place.id && row.slug === slug && live(row)),
    };
  };
  return {
    read,
    // A personal config is named by the environment it is of, the page its maker was on; anything else by its own slug, and its parent's if it has one.
    denied: refusedTo('environment.create', shown, vault.workloads, {
      where: { project: projectSlug, environment: named, ...(mine || parentSlug === null ? {} : { parent: parentSlug }) },
      objects: (seen: Seen<typeof read>) => {
        const { place, parent, there } = placed(seen);
        return [...(place === undefined ? [] : [`project:${place.id}`]), ...(there === undefined ? [] : [`environment:${there.id}`]), ...(parent == null ? [] : [`environment:${parent.id}`])];
      },
    }),
    decide(seen: Seen<typeof read>, at: number) {
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
        // A fork reads its parent's values from its first moment: who makes one reads them too.
        if (parent !== null && !caller.may('secret.read', parent)) return { refused: 'no_access' };
      }
      const chained = parent === null ? null : chainOf(parent, seen.chain);
      if (chained !== null && chained !== 'ok') return { refused: chained };
      if (seen.taken.some((row) => (row.projectId === place.id && row.slug === slug) || (mine && row.parentId === parent!.id && row.owner === caller.principal))) return { refused: 'exists' };

      const guarded = !mine && (input.protected || parent?.protected === true);
      const row = { id, projectId: place.id, slug, name: slug, createdAt: new Date(at), archivedAt: null, parentId: parent?.id ?? null, owner: mine ? caller.principal : null, protected: guarded, frozenCredentials: [] };
      return {
        writes: [put(environments, row)],
        entry: {
          ...by(caller, shown),
          action: 'environment.create',
          objects: [`project:${place.id}`, `environment:${id}`, ...(parent === null ? [] : [`environment:${parent.id}`]), `principal:${caller.principal}`, `credential:${caller.credential.id}`],
          detail: { slug, protected: guarded, ...(parent === null ? {} : mine ? { personal: parent.slug } : { inherits: parent.slug }) },
        },
        // A personal config is protected as its environment is, through it: its own row never says so.
        answer: { id, slug, protected: mine ? parent!.protected : guarded },
      };
    },
  };
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
function owns(caller: Asking, projectId: string): boolean {
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
};
