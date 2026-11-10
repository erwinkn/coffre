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
  type BuiltinRole,
  type Role,
  type Scope,
} from '@coffre/core/access';
import type { StoredEntry } from '@coffre/core/audit';
import { and, asc, desc, eq, gt, inArray, isNull, like, lt, or, sql, type SQL } from 'drizzle-orm';

import { tablesOf, type Queryable } from './database.ts';
import { prepared } from './prepared.ts';
import { engineOf, rowsOf, tombstone, truth } from './dialect.ts';
import { accessAllowed, changeNamed, changesOf, entriesOf, entryColumns, keyedBy, logObject, newestAuthentic, type Authenticity, type Newest } from './log.ts';

/**
 * One grant, as `grants` holds it: on a project (`environmentId`
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
  // A member's grants, which every check reads, built once (`prepared`); any other filter, as asked.
  const rows = filter.principal !== undefined && filter.liveAt === undefined
    ? await grantsOf(db, { principal: filter.principal })
    : await grantRows(db, filter.principal === undefined ? undefined : eq(tablesOf(db).grants.principal, filter.principal), filter.liveAt);
  return rows.map(({ grant, environmentProjectId }) => ({ ...grant, projectId: grant.projectId ?? environmentProjectId }));
}

function grantRows(db: Queryable, principal: SQL | undefined, liveAt?: number) {
  const { grants, environments } = tablesOf(db);
  return db
    .select({ grant: grants, environmentProjectId: environments.projectId })
    .from(grants)
    .leftJoin(environments, eq(environments.id, grants.environmentId))
    .where(and(principal, liveAt === undefined ? undefined : or(isNull(grants.expiresAt), gt(grants.expiresAt, liveAt))));
}

const grantsOf = prepared((db) => grantRows(db, eq(tablesOf(db).grants.principal, sql.placeholder('principal'))));

/** Add a grant; an environment's row names only the environment. */
export async function insertGrant(db: Queryable, grant: GrantRow): Promise<void> {
  const { grants } = tablesOf(db);
  await db.insert(grants).values({ ...grant, projectId: grant.environmentId === null ? grant.projectId : null });
}

/** A member's instance role and its scope, as `principals` stores them. */
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
 * the Owners its deployment names.
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
      .map((grant) => ({ environmentSlug: grant.environmentSlug, role: grant.role as BuiltinRole, expiresAt: grant.expiresAt })),
    grants: live
      .filter((grant) => grant.projectId !== null)
      .map((grant) => ({ projectId: grant.projectId, environmentId: grant.environmentId, role: grant.role as BuiltinRole, expiresAt: grant.expiresAt })),
    projects,
  });
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
  const { principals, projects, environments } = tablesOf(db);
  const grants = await readGrants(db, { liveAt: at });
  const held = grants.filter((grant) => grant.projectId === null && grant.environmentId === null);
  if (held.length === 0) return [];
  const holders = [...new Set(held.map((grant) => grant.principal))].sort();
  const [members, places, inside, live, tampered] = await Promise.all([
    db.select({ principal: principals.principal, status: principals.status, owner: principals.owner, role: principals.role, scope: principals.scope }).from(principals),
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

/**
 * A service token or trust binding whose scope this release has not sealed
 * yet: none of its own, as 0.4 made it (`scope` null), or one that does not
 * say where it reads sensitive values, as a release before 0.11 made it. By
 * whom it was issued, `createdBy`, a person's email.
 */
export type Unsealed = { kind: 'token' | 'binding'; id: string; principal: string; createdBy: string; scope: string | null };

/**
 * The live service tokens and trust bindings of active service accounts
 * whose scope is not sealed yet (`Unsealed`): what the app seals once a
 * process (`sealScopes`), and what `coffre migrate` says it will. A
 * credential a binding issued carries its binding's.
 */
export async function unsealedCredentials(db: Queryable, at: Date): Promise<Unsealed[]> {
  const { credentials, serviceBindings, principals } = tablesOf(db);
  // Every scope this release writes for a service says, at each place it names, whether it reads the sensitive values
  // there; one that names none, sealed while its account held nothing, is sealed (`unsealedScope` in @coffre/server).
  const unsealed = (scope: typeof credentials.scope | typeof serviceBindings.scope) =>
    or(isNull(scope), and(like(scope, '%"projectId"%'), sql`${scope} NOT LIKE '%"sensitive":%'`));
  const [tokens, bindings] = await Promise.all([
    db
      .select({ id: credentials.id, principal: credentials.principal, createdBy: credentials.createdBy, scope: credentials.scope })
      .from(credentials)
      .innerJoin(principals, and(eq(principals.principal, credentials.principal), eq(principals.generation, credentials.generation)))
      .where(and(
        eq(credentials.kind, 'service'),
        unsealed(credentials.scope),
        sql`${credentials.createdBy} NOT LIKE 'binding:%'`,
        isNull(credentials.revokedAt),
        gt(credentials.expiresAt, at),
        eq(principals.status, 'active'),
      )),
    db
      .select({ id: serviceBindings.id, principal: serviceBindings.principal, createdBy: serviceBindings.createdBy, scope: serviceBindings.scope })
      .from(serviceBindings)
      .innerJoin(principals, and(eq(principals.principal, serviceBindings.principal), eq(principals.generation, serviceBindings.generation)))
      .where(and(unsealed(serviceBindings.scope), isNull(serviceBindings.revokedAt), eq(principals.status, 'active'))),
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
 * the app lists members and `coffre migrate` marks them. A finding about
 * their row (`mac`) or an older one put back (`stale`) stands by
 * `findingStands`: one 0.15's log weighed, while the change it names is
 * still their newest; one of 0.14's, while it is newer than their newest
 * access entry. Two statements, neither of which reads a member's findings
 * past the newest of a kind (T248, R48): the members any finding is about,
 * a step of `audit_log_tamper_idx` each (`reportedMembers`); then for each,
 * as for one (`findingsAt`), their newest finding of 0.14's, whether one of
 * 0.15's names their newest change, and their newest access entry, a probe
 * each. Grouped, the findings were read whole: 295 pages at 10,000 reports
 * about one member, 1,177 at 40,000, for two groups (Sol r6 of #556).
 */
export async function tamperedMembers(db: Queryable, principal?: string): Promise<Set<string>> {
  const members = principal === undefined ? await reportedMembers(db) : [principal];
  if (members.length === 0) return new Set();
  const keys = members.map((member) => logObject('principal', member));
  const postgres = engineOf(db) === 'postgres';
  const [member, object] = postgres ? [sql`k.principal`, sql`k.object`] : [sql`json_extract(k.value, '$[0]')`, sql`json_extract(k.value, '$[1]')`];
  const { legacy, named } = findingsAt(db, member, object);
  const found = await rowsOf<{ principal: string; legacy: string | number | null; access: string | number | null; named: number | boolean }>(db, sql`
    SELECT ${member} AS principal, ${legacy} AS legacy, ${newestAccessOf(db, member)} AS access, ${named} AS named
      FROM ${postgres
        ? sql`unnest(${sql.param(members)}::text[], ${sql.param(keys)}::text[]) AS k (principal, object)`
        : sql`json_each(${JSON.stringify(members.map((one, i) => [one, keys[i]]))}) k`}`);
  return new Set(found.filter((row) => findingStands({
    legacy: row.legacy === null ? null : BigInt(row.legacy),
    access: row.access === null ? null : BigInt(row.access),
    named: Number(row.named) === 1,
  })).map((row) => String(row.principal)));
}

/**
 * The members the vault's findings are about, each once: a skip of
 * `audit_log_tamper_idx`, keyed by member first, from one member to the
 * next, a step each however many findings about them (T248, R48). As a
 * `DISTINCT` or a `GROUP BY`, every finding is read.
 */
async function reportedMembers(db: Queryable): Promise<string[]> {
  const { auditLog } = tablesOf(db);
  const next = (after: SQL | null) => sql`(SELECT ${auditLog.subjectPrincipal} FROM ${auditLog} WHERE ${entriesOf('tamper')}
    AND ${auditLog.subjectPrincipal} ${after === null ? sql`IS NOT NULL` : sql`> ${after}`} ORDER BY ${auditLog.subjectPrincipal} LIMIT 1)`;
  // A `select` around the `WITH`: a plain read, sent with the others asked beside it (`plainRead`, `groupReads`).
  const rows = await rowsOf<{ principal: string }>(db, sql`
    SELECT principal FROM (WITH RECURSIVE reported (principal) AS (SELECT ${next(null)} UNION ALL SELECT ${next(sql`r.principal`)} FROM reported r WHERE r.principal IS NOT NULL)
    SELECT principal FROM reported) AS reported WHERE principal IS NOT NULL`);
  return rows.map((row) => String(row.principal));
}

/** A member's newest access entry's `seq`, in SQL, `member` the SQL that names them: a step of `audit_log_access_idx` (R48). */
function newestAccessOf(db: Queryable, member: SQL): SQL<string | null> {
  const { auditLog } = tablesOf(db);
  const about = keyedBy(db, auditLog.subjectPrincipal, auditLog.seq, 'desc', member, sql`ARRAY[${member}]`);
  return sql`(SELECT CAST(${auditLog.seq} AS text) FROM ${auditLog} WHERE ${accessAllowed()} AND ${about.where} ORDER BY ${sql.join(about.orderBy, sql`, `)} LIMIT 1)`;
}

/** What a finding names for a member 0.15's log holds no change of (`changeName`). */
const NO_CHANGE = 'none';

/**
 * How a finding names the change of a member's it weighed (`findingMetadata`): by the change's MAC, in hex, "none"
 * for a member the log held none of. By its MAC, not its number: a change's MAC covers every column but its number,
 * which a database writer can change (`changeHolds`, @coffre/vault). Weighed by number, they would renumber the
 * newest change up, and the finding about it would settle with no change since; or renumber it up before the check
 * and back after, and the finding would name a number no later change reaches (formal/Findings.tla, NamesChange;
 * review r1 of #476). A MAC is the vault's, and as unique as the change it covers.
 */
export function changeName(mac: Uint8Array | null): string {
  return mac === null ? NO_CHANGE : Buffer.from(mac).toString('hex');
}

/**
 * Under 0.15's log, a `vault.tampered` about a member names, in its
 * metadata, the newest change of theirs it weighed: `{"change": "<its
 * name>"}` (`changeName`; T179 PR 4a). A finding without it is 0.14's.
 */
export function findingMetadata(change: string): string {
  return JSON.stringify({ change });
}

/**
 * The change a finding names (`findingMetadata`), in SQL: null for 0.14's, which names none. Only a JSON string
 * counts, on both engines alike: a finding with any other `change` was written around the vault, and is weighed by
 * 0.14's rule (a reader with no key takes every entry in the vault's name as its own; the vault's MAC tells them
 * apart, `reportStands`). A name that is no change's names none that is newest, and settles at once.
 */
function weighedBy(db: Queryable): SQL<string | null> {
  return changeNamed(engineOf(db), tablesOf(db).auditLog.metadata);
}

/**
 * Whether a member's findings stand: the newest of 0.14's (`legacy`, its
 * seq) is newer than their newest access entry (`access`); or a finding of
 * 0.15's log names their newest change (`named`). A change after the one
 * a finding names is one the vault made after checking their row, which
 * only a row that checks out passes: what clears it, as 0.14's access entry
 * did. Any finding, not the newest alone: findings commit in an order of
 * their own, so a later one may have weighed an older change
 * (formal/Findings.tla, EveryFinding).
 */
export function findingStands(newest: { legacy: bigint | null; access: bigint | null; named: boolean }): boolean {
  const { legacy, access, named } = newest;
  return (legacy !== null && legacy > (access ?? -1n)) || named;
}

/** A member's newest change's name (`changeName`) in SQL, `object` its object in the log: one probe of `log_changes_object_idx` (R48). */
function newestNamed(db: Queryable, object: SQL): SQL<string> {
  const hex = engineOf(db) === 'postgres' ? sql`encode(c.mac, 'hex')` : sql`lower(hex(c.mac))`;
  const newest = changesOf(db, 'c', object);
  return sql`coalesce((SELECT ${hex} FROM log_changes c WHERE ${newest.where} ORDER BY ${newest.order} LIMIT 1), ${sql.raw(`'${NO_CHANGE}'`)})`;
}

/**
 * The name of each member's newest change in 0.15's log (`changeName`), "none" for those with none: one probe of
 * `log_changes_object_idx` each, however long their histories (R48). Unchecked: the newest by number, which a reader
 * with the vault's key holds to its MAC and their row first (`#onLog`).
 */
export async function newestChangeNames(db: Queryable, principals: readonly string[]): Promise<Map<string, string>> {
  if (principals.length === 0) return new Map();
  const keys = principals.map((principal) => logObject('principal', principal));
  const rows = await rowsOf<{ object: string; name: string }>(db, engineOf(db) === 'postgres'
    ? sql`SELECT k.object, ${newestNamed(db, sql`k.object::uuid`)} AS name FROM unnest(${sql.param(keys)}::text[]) AS k (object)`
    : sql`SELECT k.value AS object, ${newestNamed(db, sql`k.value`)} AS name FROM json_each(${JSON.stringify(keys)}) k`);
  const names = new Map(rows.map((row) => [String(row.object), row.name] as const));
  return new Map(principals.map((principal, i) => {
    // Each engine hands back the key it was given; a key that came back otherwise would name "none" for a member
    // with changes, which the member page (`findingsOf`, in SQL) would not.
    const name = names.get(keys[i]!);
    if (name === undefined) throw new Error(`newestChangeNames: no row for ${keys[i]}`);
    return [principal, name] as const;
  }));
}

/**
 * Of a member's findings, as `findingStands` weighs them, in SQL: the newest of 0.14's (its seq), and whether one of
 * 0.15's names their newest change (1 or 0), read beside the rest of a statement (`memberAccess`).
 */
export function findingsOf(db: Queryable, principal: string): { legacy: SQL<string | null>; named: SQL<number> } {
  return findingsAt(db, sql`${principal}`, sql`${logObject('principal', principal)}`);
}

/**
 * Whether the vault's report that `principal`'s row was changed around it
 * stands (`findingStands`), each finding as `check`, the vault's MACs,
 * tells them apart, passing over those forged in its name; a reader
 * without its key takes them all as the vault's (`tamperedMembers`). While
 * one stands the vault leaves their grants on every project of 0.4 as they
 * are. One of 0.15's log stands while the change it names is their newest
 * (`newest`, its name): only those naming it are read. One of 0.14's, while
 * it is newer than their newest access entry changing what they hold: only
 * those after that entry are read. So older ones, forged or not, never hide
 * one. From LOOK_BACK forged entries on, of either kind, one may stand, so
 * it is taken to. `newest` is the change the decision that asks checked
 * with their row (`#onLog`): its MAC, and their row's seal against it;
 * null when it checked none (0.14's log alone, where no finding of 0.15's
 * is the vault's), and only 0.14's are weighed. Never the newest read
 * again, whose number no MAC covers (review r1 of #476).
 */
export async function reportStands(db: Queryable, principal: string, check: Authenticity, newest: string | null): Promise<boolean> {
  if (newest !== null) {
    const named = await newestAuthentic((limit, before) => tamperReportsAbout(db, principal, limit, { names: newest }, before), check);
    if (named === 'unreached' || typeof named !== 'string') return true;
  }
  const access = await newestAccess(db, principal, check);
  if (access === 'unreached') return true;
  const after = typeof access === 'string' ? -1n : access.seq;
  const report = await newestAuthentic((limit, before) => tamperReportsAbout(db, principal, limit, { after }, before), check);
  return report === 'unreached' || typeof report !== 'string';
}

/**
 * The newest access entry about `principal` that `check` finds the vault's own; at or below `through`, if given.
 * `starts`, if given, before each page it reads, which it may refuse by throwing (a use that lost its race).
 */
export function newestAccess(db: Queryable, principal: string, check: Authenticity, through?: bigint, starts?: () => void): Promise<Newest> {
  return newestAuthentic((limit, before) => {
    starts?.();
    return accessEntriesAbout(db, principal, limit, before ?? (through === undefined ? undefined : through + 1n));
  }, check);
}

/** Up to `limit` of the vault's allowed access entries about `principal` before `before` (the newest when undefined), newest first. */
export async function accessEntriesAbout(db: Queryable, principal: string, limit: number, before?: bigint): Promise<StoredEntry[]> {
  const principals = [principal];
  const rows = before === undefined ? await newestAccessEntries(db, { principal, principals, limit }) : await accessEntriesBefore(db, { principal, principals, limit, before });
  return rows as StoredEntry[];
}

/** A principal's allowed access entries, newest first: steps of `audit_log_access_idx` (`keyedBy`; T239, T245, R48). */
function accessEntries(db: Queryable, before?: SQL) {
  const { auditLog } = tablesOf(db);
  const about = keyedBy(db, auditLog.subjectPrincipal, auditLog.seq, 'desc', sql.placeholder('principal'), sql.placeholder('principals'));
  return db
    .select(entryColumns(db))
    .from(auditLog)
    .where(and(accessAllowed(), about.where, before))
    .orderBy(...about.orderBy)
    .limit(sql.placeholder('limit'));
}

// What every check of a member reads first, built once (`prepared`).
const newestAccessEntries = prepared((db) => accessEntries(db));
const accessEntriesBefore = prepared((db) => accessEntries(db, lt(tablesOf(db).auditLog.seq, sql.placeholder('before'))));

/**
 * Up to `limit` of the vault's reports that `principal`'s row was changed
 * around it (`KINDS.tamper`: their row's MAC fails, `mac`, or an older one was put back, `stale`), before `before` (the newest when undefined),
 * newest first: of 0.15's log, those that name the change `names`; of
 * 0.14's, those after seq `after`.
 */
async function tamperReportsAbout(
  db: Queryable, principal: string, limit: number, which: { names: string } | { after: bigint }, before?: bigint,
): Promise<StoredEntry[]> {
  const { auditLog } = tablesOf(db);
  const weighed = weighedBy(db);
  const about = reportsAbout(db, sql`${principal}`);
  const rows = await db
    .select(entryColumns(db))
    .from(auditLog)
    .where(
      and(
        entriesOf('tamper'),
        about.where,
        'names' in which ? sql`${weighed} = ${which.names}` : and(sql`${weighed} IS NULL`, gt(auditLog.seq, which.after)),
        before === undefined ? undefined : lt(auditLog.seq, before),
      ),
    )
    .orderBy(about.order)
    .limit(limit);
  return rows as StoredEntry[];
}

/**
 * `findingsOf` of the member `principal` names, a value or a column of the statement's (`tamperedMembers`), `object`
 * their object in 0.15's log: a probe of `audit_log_tamper_idx` each, and one of `log_changes_object_idx`.
 */
function findingsAt(db: Queryable, principal: SQL, object: SQL): { legacy: SQL<string | null>; named: SQL<number> } {
  const { auditLog: log } = tablesOf(db);
  const weighed = weighedBy(db);
  const about = reportsAbout(db, principal);
  const of = sql`${entriesOf('tamper')} AND ${about.where}`;
  return {
    // The newest of 0.14's by `audit_log_tamper_idx`, `(member, change, seq)`: as the greatest `seq`, Postgres walked
    // the member's reports of 0.15's back, or the vault's entries, 1,088 pages behind 20,000 of them (T245).
    legacy: sql`(SELECT CAST(${log.seq} AS text) FROM ${log} WHERE ${of} AND ${weighed} IS NULL ORDER BY ${about.order} LIMIT 1)`,
    named: sql`(CASE WHEN EXISTS (SELECT 1 FROM ${log} WHERE ${of} AND ${weighed} = ${newestNamed(db, object)}) THEN 1 ELSE 0 END)`,
  };
}

/**
 * A member's tamper reports of one kind, 0.15's naming one change or
 * 0.14's naming none, newest first: steps of `audit_log_tamper_idx`,
 * `(member, change, seq)`, however many of the other kind, or of other
 * changes, came since. On Postgres through `= ANY` of the member, ordered
 * by the member, the change, then `seq` (`keyedBy`); `principal` a value, or a column of the statement's: ordered by `seq`
 * alone, Postgres walked `audit_log_vault_idx` back, 1,397 pages behind
 * 40,000 reports naming another change (T245, R48).
 */
function reportsAbout(db: Queryable, principal: SQL): { where: SQL; order: SQL } {
  const { auditLog } = tablesOf(db);
  if (engineOf(db) !== 'postgres') return { where: sql`${auditLog.subjectPrincipal} = ${principal}`, order: sql`${auditLog.seq} DESC` };
  return {
    where: sql`${auditLog.subjectPrincipal} = ANY(ARRAY[CAST(${principal} AS text)])`,
    order: sql`${auditLog.subjectPrincipal} DESC, ${weighedBy(db)} DESC, ${auditLog.seq} DESC`,
  };
}
