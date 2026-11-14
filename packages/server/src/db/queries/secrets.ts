import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

/**
 * The secrets area's page reads (docs/design/0.16.md, "Pages"): keys, their
 * versions and references, never a value but a plain one's copy for the
 * pages. Each is one statement, whatever
 * the instance holds; the rows it reads are those of the place it names.
 * Read as they are, their MACs unchecked: they say what a page lists, and
 * decide no use and no change.
 */

export type Nature = 'plain' | 'secret' | 'sensitive';

/** A project as these reads find it. `deleted`: the tombstone a deletion leaves. */
export type ProjectRow = { id: string; slug: string; archived: boolean; deleted: boolean };

export type EnvironmentRow = { id: string; projectId: string; slug: string; parentId: string | null; owner: string | null; archived: boolean; deleted: boolean; protected: boolean };

/** A secret's row with its current version's, which says who wrote it and when: no value, no ciphertext. Times are ISO 8601. */
export type SecretRow = {
  id: string;
  projectId: string;
  environmentId: string;
  key: string;
  archived: boolean;
  folder: string | null;
  sourceId: string | null;
  /** Who pointed it at its source, and when, while it is a reference. */
  sourceSetBy: string | null;
  sourceSetAt: string | null;
  currentVersion: number | null;
  nature: Nature | null;
  recipe: string | null;
  pairId: string | null;
  pairHalf: 'private' | 'public' | null;
  /**
   * Its current version's row, null when it has none or that row is not
   * there. `plaintext`, the copy for the pages a plain value keeps: only
   * while the secret's row says it is plain, never a secret's.
   */
  current: { id: string; createdAt: string; createdBy: string; plaintext: string | null } | null;
};

/**
 * An environment as a read of it resolves: the project, the environment
 * named, the caller's personal config of it when asked, the environments
 * it inherits from, the keys all of them hold, archived ones included, the
 * live dismissals among them, and what the references among those keys
 * read, with where that is.
 */
export type ChainRead = {
  project: ProjectRow | null;
  base: EnvironmentRow | null;
  mine: EnvironmentRow | null;
  projects: Map<string, ProjectRow>;
  environments: Map<string, EnvironmentRow>;
  secrets: Map<string, SecretRow>;
  dismissed: { environmentId: string; key: string }[];
};

type Wire = Record<string, unknown>;

const iso = (value: unknown): string => new Date(value as string).toISOString();

/** A project's, an environment's and a secret's rows as JSON, of the row aliased `t`, and the rows they read back as. */
export const PROJECT = sql`jsonb_build_object('id', t.id, 'slug', t.slug, 'archived', t.archived_at IS NOT NULL)`;
export const ENVIRONMENT = sql`jsonb_build_object('id', t.id, 'projectId', t.project_id, 'slug', t.slug, 'parentId', t.parent_id, 'owner', t.owner, 'archived', t.archived_at IS NOT NULL, 'protected', t.protected)`;
export const SECRET = sql`jsonb_build_object('id', t.id, 'projectId', t.project_id, 'environmentId', t.environment_id, 'key', t.key, 'archived', t.archived_at IS NOT NULL, 'folder', t.folder,
  'sourceId', t.source_id, 'sourceSetBy', t.source_set_by, 'sourceSetAt', t.source_set_at, 'currentVersion', t.current_version, 'nature', t.nature, 'recipe', t.recipe, 'pairId', t.pair_id, 'pairHalf', t.pair_half,
  'current', (SELECT jsonb_build_object('id', v.id, 'createdAt', v.created_at, 'createdBy', v.created_by, 'plaintext', CASE WHEN t.nature = 'plain' THEN v.plaintext END)
    FROM secret_versions v WHERE v.secret_id = t.id AND v.version = t.current_version))`;

export const projectOf = (row: Wire): ProjectRow => ({ id: row.id as string, slug: row.slug as string, archived: row.archived as boolean, deleted: (row.slug as string).includes('~') });
export const environmentOf = (row: Wire): EnvironmentRow => ({
  id: row.id as string,
  projectId: row.projectId as string,
  slug: row.slug as string,
  parentId: row.parentId as string | null,
  owner: row.owner as string | null,
  archived: row.archived as boolean,
  deleted: (row.slug as string).includes('~'),
  protected: row.protected as boolean,
});
export const secretOf = (row: Wire): SecretRow => {
  const current = row.current as Wire | null;
  return {
    id: row.id as string,
    projectId: row.projectId as string,
    environmentId: row.environmentId as string,
    key: row.key as string,
    archived: row.archived as boolean,
    folder: row.folder as string | null,
    sourceId: row.sourceId as string | null,
    sourceSetBy: row.sourceSetBy as string | null,
    sourceSetAt: row.sourceSetAt == null ? null : iso(row.sourceSetAt),
    currentVersion: row.currentVersion as number | null,
    nature: row.nature as Nature | null,
    recipe: row.recipe as string | null,
    pairId: row.pairId as string | null,
    pairHalf: row.pairHalf as SecretRow['pairHalf'],
    current: current === null ? null : { id: current.id as string, createdAt: iso(current.createdAt), createdBy: current.createdBy as string, plaintext: (current.plaintext ?? null) as string | null },
  };
};

/**
 * `project/environment`, read as a use reads it (`@coffre/vault`'s use.ts),
 * every key: one statement. `owner`, when the caller asked for their
 * personal config of it (`dev@me`): theirs, if they have one. The chain is
 * followed by `parent_id` until it ends or closes on itself; whether it is
 * whole, and not too long, is the reader's to say.
 */
export async function chainOf(db: Queryable, project: string, environment: string, owner: string | null): Promise<ChainRead> {
  const rows = await rowsOf<{ part: 'project' | 'base' | 'mine' | 'environment' | 'secret' | 'dismissed'; row: Wire }>(
    db,
    sql`
      WITH RECURSIVE
        p AS (SELECT * FROM projects WHERE slug = ${project}),
        base AS (SELECT e.* FROM environments e, p WHERE e.project_id = p.id AND e.slug = ${environment}),
        mine AS (SELECT e.* FROM environments e, base WHERE ${owner}::text IS NOT NULL AND e.parent_id = base.id AND e.owner = ${owner}::text AND strpos(e.slug, '~') = 0 AND e.archived_at IS NULL),
        -- UNION, not UNION ALL: a loop written around the vault ends where it closes.
        chain AS (SELECT id, parent_id FROM base UNION SELECT id, parent_id FROM mine UNION SELECT e.id, e.parent_id FROM environments e JOIN chain ON e.id = chain.parent_id),
        keyed AS (SELECT s.* FROM secrets s WHERE s.project_id = (SELECT id FROM p) AND s.environment_id IN (SELECT id FROM chain)),
        held AS (SELECT * FROM keyed UNION SELECT s.* FROM secrets s WHERE s.id IN (SELECT source_id FROM keyed))
      SELECT 'base' AS part, ${ENVIRONMENT} AS row FROM base t
      UNION ALL SELECT 'mine', ${ENVIRONMENT} FROM mine t
      UNION ALL SELECT 'project', ${PROJECT} FROM projects t WHERE t.id IN (SELECT id FROM p UNION SELECT project_id FROM held)
      UNION ALL SELECT 'environment', ${ENVIRONMENT} FROM environments t WHERE t.id IN (SELECT id FROM chain UNION SELECT environment_id FROM held)
      UNION ALL SELECT 'secret', ${SECRET} FROM held t
      UNION ALL SELECT 'dismissed', jsonb_build_object('environmentId', t.environment_id, 'key', t.key) FROM dismissed_keys t WHERE t.environment_id IN (SELECT id FROM chain) AND t.restored_at IS NULL`,
  );
  const read: ChainRead = { project: null, base: null, mine: null, projects: new Map(), environments: new Map(), secrets: new Map(), dismissed: [] };
  for (const { part, row } of rows) {
    if (part === 'base') read.base = environmentOf(row);
    else if (part === 'mine') read.mine = environmentOf(row);
    else if (part === 'project') read.projects.set(row.id as string, projectOf(row));
    else if (part === 'environment') read.environments.set(row.id as string, environmentOf(row));
    else if (part === 'secret') read.secrets.set(row.id as string, secretOf(row));
    else read.dismissed.push({ environmentId: row.environmentId as string, key: row.key as string });
  }
  read.project = [...read.projects.values()].find((row) => row.slug === project) ?? null;
  return read;
}

/** A version of a key as its history lists it: who wrote it and when, how it is kept, never its value. */
export type VersionRow = { version: number; createdAt: string; createdBy: string; kek: string; plain: boolean; sensitive: boolean };

/**
 * `key` in `project/environment` (or the caller's personal config of it,
 * for `owner`), and its versions below `before` (all, for null), newest
 * first, `limit` of them: one statement. `place` is null when there is no
 * such project or environment; `secret` when the environment holds no row
 * of that key, archived or not. `parent`: the environment's parent, which
 * decides who reads a personal config named by its own slug.
 */
export async function historyOf(
  db: Queryable,
  at: { project: string; environment: string; owner: string | null; key: string },
  before: number | null,
  limit: number,
): Promise<{ project: ProjectRow | null; base: EnvironmentRow | null; parent: EnvironmentRow | null; mine: EnvironmentRow | null; secret: SecretRow | null; versions: VersionRow[] }> {
  const rows = await rowsOf<{ part: 'project' | 'base' | 'parent' | 'mine' | 'secret' | 'version'; row: Wire }>(
    db,
    sql`
      WITH
        p AS (SELECT * FROM projects WHERE slug = ${at.project}),
        base AS (SELECT e.* FROM environments e, p WHERE e.project_id = p.id AND e.slug = ${at.environment}),
        parent AS (SELECT e.* FROM environments e, base WHERE e.id = base.parent_id),
        mine AS (SELECT e.* FROM environments e, base WHERE ${at.owner}::text IS NOT NULL AND e.parent_id = base.id AND e.owner = ${at.owner}::text AND strpos(e.slug, '~') = 0 AND e.archived_at IS NULL),
        k AS (SELECT s.* FROM secrets s, p WHERE s.project_id = p.id AND s.key = ${at.key} AND s.environment_id = coalesce((SELECT id FROM mine), (SELECT id FROM base)))
      SELECT 'project' AS part, ${PROJECT} AS row FROM p t
      UNION ALL SELECT 'base', ${ENVIRONMENT} FROM base t
      UNION ALL SELECT 'parent', ${ENVIRONMENT} FROM parent t
      UNION ALL SELECT 'mine', ${ENVIRONMENT} FROM mine t
      UNION ALL SELECT 'secret', ${SECRET} FROM k t
      UNION ALL (SELECT 'version', jsonb_build_object('version', v.version, 'createdAt', v.created_at, 'createdBy', v.created_by, 'kek', v.kek_provider || ':' || v.kek_id,
          'plain', v.plaintext IS NOT NULL, 'sensitive', v.sensitive)
        FROM secret_versions v JOIN k ON v.secret_id = k.id
        WHERE ${before}::int IS NULL OR v.version < ${before}::int
        ORDER BY v.version DESC LIMIT ${limit})`,
  );
  const found: Awaited<ReturnType<typeof historyOf>> = { project: null, base: null, parent: null, mine: null, secret: null, versions: [] };
  for (const { part, row } of rows) {
    if (part === 'project') found.project = projectOf(row);
    else if (part === 'base') found.base = environmentOf(row);
    else if (part === 'parent') found.parent = environmentOf(row);
    else if (part === 'mine') found.mine = environmentOf(row);
    else if (part === 'secret') found.secret = secretOf(row);
    else found.versions.push({ version: row.version as number, createdAt: iso(row.createdAt), createdBy: row.createdBy as string, kek: row.kek as string, plain: row.plain as boolean, sensitive: row.sensitive as boolean });
  }
  // UNION ALL keeps no order between its parts: the versions are put back in theirs.
  found.versions.sort((a, b) => b.version - a.version);
  return found;
}

/**
 * The references of `project`: every secret of it that reads another, and
 * every secret elsewhere that reads one of it, each with its source; with
 * the project's environments and every place either end is in, a personal
 * config's parent too, which its access is read through. One statement; the
 * rows it reads are the project's keys and the references.
 */
export async function referencesOf(db: Queryable, project: string): Promise<{ project: ProjectRow | null; projects: Map<string, ProjectRow>; environments: Map<string, EnvironmentRow>; secrets: Map<string, SecretRow>; holders: string[] }> {
  const rows = await rowsOf<{ part: 'project' | 'environment' | 'secret' | 'holder'; row: Wire }>(
    db,
    sql`
      WITH
        p AS (SELECT * FROM projects WHERE slug = ${project}),
        holders AS (
          SELECT s.* FROM secrets s WHERE s.project_id = (SELECT id FROM p) AND s.source_id IS NOT NULL
          UNION SELECT s.* FROM secrets s WHERE s.source_id IN (SELECT id FROM secrets WHERE project_id = (SELECT id FROM p))
        ),
        ends AS (SELECT * FROM holders UNION SELECT s.* FROM secrets s WHERE s.id IN (SELECT source_id FROM holders))
      SELECT 'holder' AS part, jsonb_build_object('id', t.id) AS row FROM holders t
      UNION ALL SELECT 'secret', ${SECRET} FROM ends t
      UNION ALL SELECT 'project', ${PROJECT} FROM projects t WHERE t.id IN (SELECT id FROM p UNION SELECT project_id FROM ends)
      UNION ALL SELECT 'environment', ${ENVIRONMENT} FROM environments t WHERE t.project_id = (SELECT id FROM p) OR t.id IN (SELECT environment_id FROM ends)
        OR t.id IN (SELECT e.parent_id FROM environments e WHERE e.owner IS NOT NULL AND e.id IN (SELECT environment_id FROM ends))`,
  );
  const found = { project: null as ProjectRow | null, projects: new Map<string, ProjectRow>(), environments: new Map<string, EnvironmentRow>(), secrets: new Map<string, SecretRow>(), holders: [] as string[] };
  for (const { part, row } of rows) {
    if (part === 'holder') found.holders.push(row.id as string);
    else if (part === 'secret') found.secrets.set(row.id as string, secretOf(row));
    else if (part === 'project') found.projects.set(row.id as string, projectOf(row));
    else found.environments.set(row.id as string, environmentOf(row));
  }
  found.project = [...found.projects.values()].find((row) => row.slug === project) ?? null;
  return found;
}

/**
 * `project`'s environments, the team's and `owner`'s personal configs, each
 * with its keys (name, folder, archived) and its live dismissals: what the
 * missing keys compare. One statement; nobody else's personal config is
 * read past its row.
 */
export async function keyNamesOf(db: Queryable, project: string, owner: string | null): Promise<{ project: ProjectRow | null; environments: EnvironmentRow[]; keys: { environmentId: string; key: string; folder: string | null; archived: boolean }[]; dismissed: { environmentId: string; key: string; dismissedBy: string; dismissedAt: string }[] }> {
  const rows = await rowsOf<{ part: 'project' | 'environment' | 'key' | 'dismissed'; row: Wire }>(
    db,
    sql`
      WITH
        p AS (SELECT * FROM projects WHERE slug = ${project}),
        e AS (SELECT * FROM environments WHERE project_id = (SELECT id FROM p) AND (owner IS NULL OR owner = ${owner}::text))
      SELECT 'project' AS part, ${PROJECT} AS row FROM p t
      UNION ALL SELECT 'environment', ${ENVIRONMENT} FROM e t
      UNION ALL SELECT 'key', jsonb_build_object('environmentId', s.environment_id, 'key', s.key, 'folder', s.folder, 'archived', s.archived_at IS NOT NULL) FROM secrets s
        WHERE s.project_id = (SELECT id FROM p) AND s.environment_id IN (SELECT id FROM e)
      UNION ALL SELECT 'dismissed', jsonb_build_object('environmentId', d.environment_id, 'key', d.key, 'dismissedBy', d.dismissed_by, 'dismissedAt', d.dismissed_at) FROM dismissed_keys d
        WHERE d.environment_id IN (SELECT id FROM e) AND d.restored_at IS NULL`,
  );
  const found: Awaited<ReturnType<typeof keyNamesOf>> = { project: null, environments: [], keys: [], dismissed: [] };
  for (const { part, row } of rows) {
    if (part === 'project') found.project = projectOf(row);
    else if (part === 'environment') found.environments.push(environmentOf(row));
    else if (part === 'key') found.keys.push({ environmentId: row.environmentId as string, key: row.key as string, folder: row.folder as string | null, archived: row.archived as boolean });
    else found.dismissed.push({ environmentId: row.environmentId as string, key: row.key as string, dismissedBy: row.dismissedBy as string, dismissedAt: iso(row.dismissedAt) });
  }
  return found;
}
