import {
  administers,
  convertEveryProjectGrants,
  EVERYWHERE,
  isInstanceRole,
  isScope,
  normalScope,
  unscoped,
  type Conversion,
  type ConversionInput,
  type InstanceRole,
  type Role,
  type Scope,
} from '@coffre/core/access';
import type { StoredEntry } from '@coffre/core/audit';
import { ACCESS_ACTIONS } from '@coffre/core/vault';
import { and, asc, desc, eq, gt, inArray, isNull, like, lt, or, sql, type SQL } from 'drizzle-orm';

import { tablesOf, type Queryable } from './database.ts';
import { tombstone, truth } from './dialect.ts';
import { entryColumns, LOOK_BACK, newestAuthentic, newestVaultEntries, type Authenticity, type Newest } from './log.ts';

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

/** Every project not deleted, with its environments not deleted: what a grant on every project of 0.4 reached. */
export async function liveProjects(db: Queryable): Promise<ConversionInput['projects']> {
  const { projects, environments } = tablesOf(db);
  const [found, inside] = await Promise.all([
    db.select({ id: projects.id, deleted: truth(tombstone(projects.slug)) }).from(projects).orderBy(asc(projects.id)),
    db.select({ id: environments.id, projectId: environments.projectId, slug: environments.slug, deleted: truth(tombstone(environments.slug)) }).from(environments).orderBy(asc(environments.id)),
  ]);
  return found.filter((project) => !project.deleted).map((project) => ({
    id: project.id,
    environments: inside.filter((environment) => environment.projectId === project.id && !environment.deleted).map(({ id, slug }) => ({ id, slug })),
  }));
}

/**
 * What the vault makes of a member's grants on every project of 0.4
 * (`convertEveryProjectGrants`), from their instance role and their grants
 * as stored, those live at `at`: the vault as it converts them, under their
 * row's lock, and `coffre migrate` before, from the rows as they are. The
 * role is the one their row holds: the vault converts these before it makes
 * the root admins of 0.5 Owners.
 */
export function everyProjectConversion(
  principal: string,
  role: InstanceRole,
  grants: readonly GrantRow[],
  at: number,
  projects: ConversionInput['projects'],
): Conversion {
  const person = principal.startsWith('user:');
  const live = grants.filter((grant) => grant.expiresAt === null || grant.expiresAt > at);
  return convertEveryProjectGrants({
    person,
    role: person ? role : 'member',
    everyProject: live
      .filter((grant) => grant.projectId === null && grant.environmentId === null)
      .map((grant) => ({ environmentSlug: grant.environmentSlug, role: grant.role as Role, expiresAt: grant.expiresAt })),
    grants: live
      .filter((grant) => grant.projectId !== null)
      .map((grant) => ({ projectId: grant.projectId, environmentId: grant.environmentId, role: grant.role as Role, expiresAt: grant.expiresAt })),
    projects,
  });
}

/** The action of the vault's entry that says it turned the root admins of 0.5 into Owners, once. */
export const ROOT_ADMINS_CONVERT = 'root-admins.convert';

/**
 * Whom the vault still turns from root admins of 0.5 into Owners of the
 * whole instance, by `check`. Before any entry of its own says it did
 * (`ROOT_ADMINS_CONVERT`): `whole`, everyone its configuration names, if
 * an entry of its own gave one a row as a root admin (`{ "rootAdmin": true
 * }`), `rooted` those it did; none on an instance that had no root admin
 * who signed in, which then only says so. After one, `rooted` is those a
 * vault of 0.5 gave such a row since, still serving beside this version
 * during its first deploy or rolled back to, and nobody has changed since,
 * the row's entry their newest: 0.5 held them root admins, while everyone
 * else stays as 0.6 left them, someone demoted or removed meanwhile
 * included. The vault makes Owners only of those its configuration names.
 * Null when there is nothing to do, and when LOOK_BACK forged in its name
 * hide whether one does. The vault checks with its MACs; `coffre migrate`,
 * holding no key, takes every entry in its name for its own, so a forged
 * one can make it say less than the vault will do.
 */
export async function rootAdminsToConvert(db: Queryable, check: Authenticity): Promise<{ whole: boolean; rooted: string[] } | null> {
  const converted = await newestAuthentic((before) => newestVaultEntries(db, ROOT_ADMINS_CONVERT, LOOK_BACK.page, before), check);
  if (converted === 'unreached') return null;
  const after = typeof converted === 'string' ? undefined : converted.seq;
  const { auditLog } = tablesOf(db);
  const rows = (await db
    .select(entryColumns(db))
    .from(auditLog)
    .where(and(
      eq(auditLog.author, 'vault'),
      eq(auditLog.action, 'member.add'),
      eq(auditLog.actor, 'system:vault'),
      eq(auditLog.decision, 'allow'),
      like(auditLog.metadata, '%"rootAdmin":true%'),
      after === undefined ? undefined : gt(auditLog.seq, after),
    ))
    .orderBy(asc(auditLog.seq))
    .limit(LOOK_BACK.page * LOOK_BACK.pages)) as StoredEntry[];
  const rooted: StoredEntry[] = [];
  for (const entry of rows) {
    if (check.authentic(entry)) rooted.push(entry);
    else check.forged(entry);
  }
  if (after === undefined) return { whole: true, rooted: [...new Set(rooted.map((entry) => entry.subjectPrincipal!))] };
  if (rooted.length === 0) return null;
  const untouched: string[] = [];
  for (const entry of rooted) {
    const newest = await newestAccess(db, entry.subjectPrincipal!, check);
    if (typeof newest !== 'string' && newest.seq === entry.seq) untouched.push(entry.subjectPrincipal!);
  }
  return { whole: false, rooted: [...new Set(untouched)] };
}

/** What the vault does, when this version first runs, to one member's grants on every project of 0.4. */
export type EveryProjectPreview = {
  principal: string;
  /** Each, as a path (`*`, or `*` and the slug it covers), its role and its end. */
  before: { place: string; role: string; expiresAt: number | null }[];
  conversion: Conversion;
  /** The places the conversion names, by id: `market`, `market/dev`. */
  paths: Record<string, string>;
  /**
   * Whether the vault has reported their row changed around it since the
   * last change to what they hold (`tamperedMembers`), by the entries in its
   * name: then it leaves them as they are, unless the report is forged.
   */
  reported: boolean;
};

/**
 * What the vault will make of the grants on every project of 0.4 that live
 * members hold, by the rule it converts them with
 * (`convertEveryProjectGrants`), from the rows as they are: what
 * `coffre migrate` says before the vault does it. A display: the vault
 * reads again, under its locks, when it converts, and checks what this
 * cannot, holding no key: each row's MAC, and each entry's in its name. So
 * a member it has reported changed around it is listed, and marked
 * `reported`, by the vault's own rule (`tamperedMembers`) over the entries as
 * they read: whether that report is the vault's own, or forged so as to
 * hide what it will do, only the vault can tell. Any member the vault
 * converts is listed.
 */
export async function everyProjectPreview(db: Queryable, at: number): Promise<EveryProjectPreview[]> {
  const { vaultMembers, projects, environments } = tablesOf(db);
  const grants = await readGrants(db, { liveAt: at });
  const held = grants.filter((grant) => grant.projectId === null && grant.environmentId === null);
  if (held.length === 0) return [];
  const holders = [...new Set(held.map((grant) => grant.principal))].sort();
  const [members, places, inside, live, tampered] = await Promise.all([
    db.select({ principal: vaultMembers.principal, status: vaultMembers.status, owner: vaultMembers.owner, role: vaultMembers.role, scope: vaultMembers.scope }).from(vaultMembers),
    db.select({ id: projects.id, slug: projects.slug }).from(projects),
    db.select({ id: environments.id, projectId: environments.projectId, slug: environments.slug }).from(environments),
    liveProjects(db),
    // The vault's own rule (`reportStands`), over every entry in its name, for everyone in two queries.
    tamperedMembers(db),
  ]);
  // A deleted place keeps its row under a tombstone's slug, its own or its project's, named as it was.
  const paths = Object.fromEntries(places.flatMap((project) => [
    [project.id, project.slug],
    ...inside.filter((environment) => environment.projectId === project.id).map((environment) => [environment.id, `${project.slug}/${environment.slug}`]),
  ]));
  return holders.flatMap((principal) => {
    const member = members.find((row) => row.principal === principal);
    if (member?.status !== 'active') return [];
    const theirs = held.filter((grant) => grant.principal === principal);
    return [{
      principal,
      before: theirs.map((grant) => ({ place: grant.environmentSlug === null ? '*' : `*/${grant.environmentSlug}`, role: grant.role, expiresAt: grant.expiresAt })),
      conversion: everyProjectConversion(principal, storedRole(member).role, grants.filter((grant) => grant.principal === principal), at, live),
      paths,
      reported: tampered.has(principal),
    }];
  });
}

/** A service token or trust binding of 0.4, which carries no scope of its own yet. */
export type Unsealed = { kind: 'token' | 'binding'; id: string; principal: string };

/**
 * The live service tokens and trust bindings of active service accounts
 * that carry no scope yet, as 0.4 made them: what the app seals with each
 * account's grants once a process (`sealScopes`), and what `coffre migrate`
 * says it will. A credential a binding issued carries its binding's.
 */
export async function unsealedCredentials(db: Queryable, at: Date): Promise<Unsealed[]> {
  const { credentials, serviceBindings, vaultMembers } = tablesOf(db);
  const [tokens, bindings] = await Promise.all([
    db
      .select({ id: credentials.id, principal: credentials.principal })
      .from(credentials)
      .innerJoin(vaultMembers, and(eq(vaultMembers.principal, credentials.principal), eq(vaultMembers.generation, credentials.generation)))
      .where(and(
        eq(credentials.kind, 'service'),
        isNull(credentials.scope),
        sql`${credentials.createdBy} NOT LIKE 'binding:%'`,
        isNull(credentials.revokedAt),
        gt(credentials.expiresAt, at),
        eq(vaultMembers.status, 'active'),
      )),
    db
      .select({ id: serviceBindings.id, principal: serviceBindings.principal })
      .from(serviceBindings)
      .innerJoin(vaultMembers, and(eq(vaultMembers.principal, serviceBindings.principal), eq(vaultMembers.generation, serviceBindings.generation)))
      .where(and(isNull(serviceBindings.scope), isNull(serviceBindings.revokedAt), eq(vaultMembers.status, 'active'))),
  ]);
  return [
    ...tokens.map((row) => ({ kind: 'token' as const, ...row })),
    ...bindings.map((row) => ({ kind: 'binding' as const, ...row })),
  ].sort((a, b) => a.principal.localeCompare(b.principal) || a.kind.localeCompare(b.kind) || a.id.localeCompare(b.id));
}

/**
 * The members the vault has found changed around it, and not started over
 * since, as a reader without its key can tell: `reportStands`' rule, taking
 * every entry in the vault's name as its own, for everyone at once, where
 * the app lists members and `coffre migrate` marks them. Their newest
 * `vault.tampered`, for their row (`mac`) or an older one put back
 * (`stale`), is newer than the newest entry changing what they hold. Both
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
  const found = await newest(['vault.tampered'], inArray(auditLog.code, [...TAMPER_CODES]));
  if (found.length === 0) return new Set();
  const changed = new Map(
    (await newest(ACCESS_ACTIONS, and(eq(auditLog.decision, 'allow'), inArray(auditLog.subjectPrincipal, found.map((row) => row.principal!)))))
      .map((row) => [row.principal!, row.seq]),
  );
  return new Set(found.filter((row) => row.seq > (changed.get(row.principal!) ?? -1n)).map((row) => row.principal!));
}

/** The codes of the vault's reports that a member's row was changed around it: their row's MAC fails (`mac`), or an older one was put back (`stale`). */
const TAMPER_CODES = ['mac', 'stale'] as const;

/**
 * Whether the vault's report that `principal`'s row was changed around it
 * stands: one of its own is newer than its newest entry changing what they
 * hold, and only starting them over, or another change, settles it. While
 * one stands the vault leaves their grants on every project of 0.4 as they
 * are. Both entries as `check`, the vault's MACs, tells them apart,
 * passing over those forged in its name; a reader without its key takes
 * them all as the vault's (`tamperedMembers`). Only reports after that
 * entry are read, so older ones, forged or not, never hide one. From
 * LOOK_BACK forged entries on, of either kind, one may stand, so it is
 * taken to.
 */
export async function reportStands(db: Queryable, principal: string, check: Authenticity): Promise<boolean> {
  const access = await newestAccess(db, principal, check);
  if (access === 'unreached') return true;
  const after = typeof access === 'string' ? -1n : access.seq;
  const report = await newestAuthentic((before) => tamperReportsAbout(db, principal, LOOK_BACK.page, after, before), check);
  return report === 'unreached' || typeof report !== 'string';
}

/** The newest access entry about `principal` that `check` finds the vault's own. */
export function newestAccess(db: Queryable, principal: string, check: Authenticity): Promise<Newest> {
  return newestAuthentic((before) => accessEntriesAbout(db, principal, LOOK_BACK.page, before), check);
}

/** Up to `limit` of the vault's allowed access entries about `principal` before `before` (the newest when undefined), newest first. */
export async function accessEntriesAbout(db: Queryable, principal: string, limit: number, before?: bigint): Promise<StoredEntry[]> {
  const { auditLog } = tablesOf(db);
  const rows = await db
    .select(entryColumns(db))
    .from(auditLog)
    .where(
      and(
        eq(auditLog.author, 'vault'),
        eq(auditLog.subjectPrincipal, principal),
        inArray(auditLog.action, [...ACCESS_ACTIONS]),
        eq(auditLog.decision, 'allow'),
        before === undefined ? undefined : lt(auditLog.seq, before),
      ),
    )
    .orderBy(desc(auditLog.seq))
    .limit(limit);
  return rows as StoredEntry[];
}

/**
 * Up to `limit` of the vault's reports that `principal`'s row was changed
 * around it (`TAMPER_CODES`), after `after` and before `before` (the newest
 * when undefined), newest first.
 */
async function tamperReportsAbout(db: Queryable, principal: string, limit: number, after: bigint, before?: bigint): Promise<StoredEntry[]> {
  const { auditLog } = tablesOf(db);
  const rows = await db
    .select(entryColumns(db))
    .from(auditLog)
    .where(
      and(
        eq(auditLog.author, 'vault'),
        eq(auditLog.subjectPrincipal, principal),
        eq(auditLog.action, 'vault.tampered'),
        inArray(auditLog.code, [...TAMPER_CODES]),
        gt(auditLog.seq, after),
        before === undefined ? undefined : lt(auditLog.seq, before),
      ),
    )
    .orderBy(desc(auditLog.seq))
    .limit(limit);
  return rows as StoredEntry[];
}
