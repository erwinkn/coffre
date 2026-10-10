import {
  administers,
  convertEveryProjectGrants,
  EVERYWHERE,
  isInstanceRole,
  isScope,
  normalScope,
  unscoped,
  type Conversion,
  type InstanceRole,
  type Role,
  type Scope,
} from '@coffre/core/access';
import { isTombstone } from '@coffre/core/schemas';
import { ACCESS_ACTIONS } from '@coffre/core/vault';
import { and, eq, gt, inArray, isNull, or, sql, type SQL } from 'drizzle-orm';

import { tablesOf, type Queryable } from './database.ts';

/**
 * One grant, as `vault_grants` holds it: on a project (`environmentId`
 * null), or one of its environments (`projectId` is the environment's
 * project). A grant on every project of 0.4 names neither, and
 * `environmentSlug` the one environment slug it covers in each, until the
 * vault replaces it. Only the vault writes grants; the app reads them for
 * its lists.
 */
export type GrantRow = {
  principal: string;
  projectId: string | null;
  environmentId: string | null;
  environmentSlug: string | null;
  role: string;
  /** Milliseconds since the epoch, or null for no end. */
  expiresAt: number | null;
  grantedAt: number;
  grantedBy: string;
};

/** Grants, lapsed ones too unless `liveAt` says when to judge them: one member's, or everyone's. */
export async function readGrants(
  db: Queryable,
  filter: { principal?: string; liveAt?: number } = {},
): Promise<GrantRow[]> {
  const { vaultGrants, environments } = tablesOf(db);
  const rows = await db
    .select({ grant: vaultGrants, environmentProjectId: environments.projectId })
    .from(vaultGrants)
    .leftJoin(environments, eq(environments.id, vaultGrants.environmentId))
    .where(
      and(
        filter.principal === undefined ? undefined : eq(vaultGrants.principal, filter.principal),
        filter.liveAt === undefined ? undefined : or(isNull(vaultGrants.expiresAt), gt(vaultGrants.expiresAt, filter.liveAt)),
      ),
    );
  return rows.map(({ grant, environmentProjectId }) => ({ ...grant, projectId: grant.projectId ?? environmentProjectId }));
}

/** Add a grant; an environment's row names only the environment. */
export async function insertGrant(db: Queryable, grant: GrantRow): Promise<void> {
  const { vaultGrants } = tablesOf(db);
  await db.insert(vaultGrants).values({ ...grant, projectId: grant.environmentId === null ? grant.projectId : null });
}

/** A member's instance role and its scope, as `vault_members` stores them. */
export type StoredRole = { owner: boolean; role: string | null; scope: string | null };

/**
 * A member's instance role and its scope, as their row says: a row no vault
 * of 0.5 wrote has no role, and its `owner` says whether they are an Admin.
 * A role or a scope the vault would never have written reads as holding
 * nothing (the vault then refuses the row by its MAC); a member's scope is
 * everywhere, since a member's role reaches nothing.
 */
export function storedRole({ owner, role, scope }: StoredRole): { role: InstanceRole; scope: Scope } {
  const named: InstanceRole = role === null ? (owner ? 'admin' : 'member') : isInstanceRole(role) ? role : 'member';
  if (named === 'member' || scope === null) return { role: named, scope: EVERYWHERE };
  let parsed: unknown = null;
  try {
    parsed = JSON.parse(scope);
  } catch {}
  return { role: named, scope: isScope(parsed) ? normalScope(parsed) : NOWHERE };
}

/** A scope that takes in nothing: what a stored scope nobody can read means. */
const NOWHERE: Scope = { projects: { only: [] }, environments: { only: [] } };

/** The columns that store a member's instance role and scope: `owner` too, for a vault of 0.4 to read. */
export function roleColumns(role: InstanceRole, scope: Scope): StoredRole {
  const normal = normalScope(scope);
  return { owner: administers(role), role, scope: role === 'member' || unscoped(normal) ? null : JSON.stringify(normal) };
}

/** What the vault does, when this version first runs, to one member's grants on every project of 0.4. */
export type EveryProjectPreview = {
  principal: string;
  /** Each, as a path (`*`, or `*` and the slug it covers), its role and its end. */
  before: { place: string; role: string; expiresAt: number | null }[];
  conversion: Conversion;
  /** The places the conversion names, by id: `market`, `market/dev`. */
  paths: Record<string, string>;
};

/**
 * What the vault will make of the grants on every project of 0.4 that live
 * members hold, by the rule it converts them with
 * (`convertEveryProjectGrants`), from the rows as they are: what
 * `coffre migrate` says before the vault does it. A display: the vault
 * reads again, under its locks, when it converts. Left out, as the vault
 * leaves them: a member it found changed around it (`tamperedMembers`).
 * A root admin's it leaves too while they are one, until they are not;
 * which they are, the vault's configuration says and the database does
 * not, so they are listed.
 */
export async function everyProjectPreview(db: Queryable, at: number): Promise<EveryProjectPreview[]> {
  const { vaultMembers, projects, environments } = tablesOf(db);
  const held = (await readGrants(db, { liveAt: at })).filter((grant) => grant.projectId === null && grant.environmentId === null);
  if (held.length === 0) return [];
  const [members, grants, places, inside, tampered] = await Promise.all([
    db.select({ principal: vaultMembers.principal, status: vaultMembers.status, owner: vaultMembers.owner, role: vaultMembers.role, scope: vaultMembers.scope }).from(vaultMembers),
    readGrants(db, { liveAt: at }),
    db.select({ id: projects.id, slug: projects.slug }).from(projects),
    db.select({ id: environments.id, projectId: environments.projectId, slug: environments.slug }).from(environments),
    tamperedMembers(db),
  ]);
  // A deleted place keeps its row under a tombstone's slug, its own or its project's: no grant reaches it.
  const live = places.filter((project) => !isTombstone(project.slug)).map((project) => ({
    id: project.id,
    environments: inside.filter((environment) => environment.projectId === project.id && !isTombstone(environment.slug)).map(({ id, slug }) => ({ id, slug })),
  }));
  const paths = Object.fromEntries(places.flatMap((project) => [
    [project.id, project.slug],
    ...inside.filter((environment) => environment.projectId === project.id).map((environment) => [environment.id, `${project.slug}/${environment.slug}`]),
  ]));
  return [...new Set(held.map((grant) => grant.principal))].sort().flatMap((principal) => {
    const member = members.find((row) => row.principal === principal);
    // The vault leaves a member it found changed around it as they are, as it does anyone not active.
    if (member?.status !== 'active' || tampered.has(principal)) return [];
    const theirs = held.filter((grant) => grant.principal === principal);
    return [{
      principal,
      before: theirs.map((grant) => ({ place: grant.environmentSlug === null ? '*' : `*/${grant.environmentSlug}`, role: grant.role, expiresAt: grant.expiresAt })),
      conversion: convertEveryProjectGrants({
        person: principal.startsWith('user:'),
        role: principal.startsWith('user:') ? storedRole(member).role : 'member',
        everyProject: theirs.map((grant) => ({ environmentSlug: grant.environmentSlug, role: grant.role as Role, expiresAt: grant.expiresAt })),
        grants: grants
          .filter((grant) => grant.principal === principal && grant.projectId !== null)
          .map((grant) => ({ projectId: grant.projectId, environmentId: grant.environmentId, role: grant.role as Role, expiresAt: grant.expiresAt })),
        projects: live,
      }),
      paths,
    }];
  });
}

/**
 * The members the vault has found changed around it, and not started over
 * since: its newest `vault.tampered` about them, for their row (`mac`) or
 * an older one put back (`stale`), is newer than its newest entry changing
 * what they hold. Read from the log, which the vault writes and the app
 * reads: the vault's own findings, which the app has no key to make. Both
 * reads go by the log's (author, action, seq) and (author, subject, seq)
 * indexes, and findings are few.
 */
export async function tamperedMembers(db: Queryable, principal?: string): Promise<Set<string>> {
  const { auditLog } = tablesOf(db);
  const newest = (actions: readonly string[], extra?: SQL) =>
    db
      .select({ principal: auditLog.subjectPrincipal, seq: sql<string>`max(${auditLog.seq})`.mapWith(BigInt) })
      .from(auditLog)
      .where(
        and(
          eq(auditLog.author, 'vault'),
          inArray(auditLog.action, [...actions]),
          principal === undefined ? undefined : eq(auditLog.subjectPrincipal, principal),
          extra,
        ),
      )
      .groupBy(auditLog.subjectPrincipal);
  const found = await newest(['vault.tampered'], inArray(auditLog.code, ['mac', 'stale']));
  if (found.length === 0) return new Set();
  const changed = new Map(
    (await newest(ACCESS_ACTIONS, and(eq(auditLog.decision, 'allow'), inArray(auditLog.subjectPrincipal, found.map((row) => row.principal!)))))
      .map((row) => [row.principal!, row.seq]),
  );
  return new Set(found.filter((row) => row.seq > (changed.get(row.principal!) ?? -1n)).map((row) => row.principal!));
}
