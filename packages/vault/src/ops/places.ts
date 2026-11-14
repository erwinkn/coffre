import { randomBytes, randomUUID } from 'node:crypto';

import { allows, makesProjects } from '@coffre/core/access';
import { PROJECT_PAGES } from '@coffre/core/pages';
import type { Answers, EnvironmentCreate, PlacesChanges, Presented, ProjectCreate } from '@coffre/core/vault';
import { environments, projects } from '@coffre/db/schema';
import { sql, type SQL } from 'drizzle-orm';

import { callerFrom, callerParts, live, type Asking } from '../caller.ts';
import { part, put, type Operation, type Parts, type Refusal, type Seen } from '../change.ts';
import type { Row } from '../rows.ts';
import type { Deciding } from '../vault.ts';
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

/**
 * Who asks, as every operation here takes them: one whose credential
 * stands, and changes things. A workload's session that stands and is
 * stopped is told why; a narrowed one uses values and changes nothing.
 */
function asking(seen: Seen<ReturnType<typeof callerParts>>, shown: ReturnType<typeof presented>, vault: Deciding, at: number): Asking | Refusal {
  const caller = callerFrom(seen, shown, vault.workloads, at);
  if (caller === null) return { refused: 'unauthenticated' };
  if (caller.workload?.stop != null) return { refused: caller.workload.stop };
  if (caller.workload?.narrowed === true) return { refused: 'narrowed' };
  return caller;
}

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
    ...callerParts(shown.token, sql`(SELECT NULL::uuid WHERE false)`),
    // The slug is free: read, so that two makings of one at once see each other's.
    taken: part(projects, sql`${projects.slug} = ${slug}`),
  };
  return {
    read,
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
    chain: part(environments, parentSlug === null ? sql`false` : sql`${environments.id} IN (WITH RECURSIVE chain (id, parent_id, depth) AS (
      SELECT e.id, e.parent_id, 0 FROM environments e WHERE e.project_id = ${project} AND e.slug = ${parentSlug}
      UNION SELECT e.id, e.parent_id, chain.depth + 1 FROM environments e JOIN chain ON e.id = chain.parent_id WHERE chain.depth < ${MAX_PARENTS}
    ) SELECT id FROM chain)`),
    // What would hold its place: the slug in the project, and for a personal config, the caller's of that environment.
    taken: part(environments, sql`(${environments.projectId} = ${project} AND ${environments.slug} = ${slug})${mine
      ? sql` OR (${environments.parentId} = (SELECT e.id FROM environments e WHERE e.project_id = ${project} AND e.slug = ${named}) AND ${environments.owner} = ${principal} AND strpos(${environments.slug}, '~') = 0)`
      : sql``}`),
  };
  return {
    read,
    decide(seen: Seen<typeof read>, at: number) {
      const caller = asking(seen, shown, vault, at);
      if ('refused' in caller) return caller;
      const place = seen.project.find((row) => row.slug === projectSlug && live(row));
      if (place === undefined) return { refused: 'no_access' };
      const parent = parentSlug === null ? null : seen.chain.find((row) => row.projectId === place.id && row.slug === parentSlug && live(row) && row.owner === null);
      if (parent === undefined) return { refused: 'no_access' };
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
        answer: { id, slug, protected: guarded },
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
function chainOf(parent: Row<typeof environments>, rows: readonly Row<typeof environments>[]): 'ok' | 'broken_chain' | 'too_deep' {
  let above = 0;
  for (let last = parent; last.parentId !== null; above += 1) {
    if (above + 1 >= MAX_PARENTS) return 'too_deep';
    const next = rows.find((row) => row.id === last.parentId);
    if (next === undefined || !live(next) || next.projectId !== parent.projectId) return 'broken_chain';
    last = next;
  }
  return 'ok';
}

/** The changes of projects and environments (docs/design/0.16.md, "A change"). */
export const placeOperations: Operations<PlacesChanges> = { 'project.create': projectCreate, 'environment.create': environmentCreate };
