import type { GrantPlace } from '@coffre/core/access';
import type { Author } from '@coffre/core/audit';
import { ACCESS_ACTIONS, type Checkpoint } from '@coffre/core/vault';
import type { Envelope } from '@coffre/core/envelope';
import { tombstoneOf } from '@coffre/core/schemas';
import { own, tablesOf, type Queryable, type Transaction } from '@coffre/db';
import { readGrants } from '@coffre/db/grants';
import * as dialect from '@coffre/db/dialect';
import { canonicalTimestamp, changedRows, clock, clockMillis, forUpdate, migrationLedger, tombstone, truth, type Table } from '@coffre/db/dialect';
import type * as schema from '@coffre/db/schema';
import { and, asc, count, countDistinct, desc, eq, getTableColumns, getTableName, gt, gte, inArray, isNull, like, lt, not, notInArray, or, sql, type AnyColumn, type SQL } from 'drizzle-orm';

import { authMac, checkAuthRow, issuingBinding, verifyAuthRow, type AuthRow, type AuthTable } from '../auth-rows.ts';

/**
 * Every query coffre runs, and nowhere else: named reads returning all
 * that their callers need, generic writes, and a lock.
 * The server works on what these return and never writes SQL; lint keeps
 * drizzle out of the server and the pages.
 *
 * Each query builds on the tables of the database it is given (`tablesOf`),
 * so the one text runs on Postgres and SQLite; see portable.ts. The
 * server names a table for the generic writes by importing schema.ts, and
 * `own` swaps in the database's twin.
 *
 * Ordinary writes do not check first and do not read back. A unique constraint
 * answers "is it taken", and a conditional update's row count answers "was
 * it still there"; the response is built from what was written. Signed rows
 * authenticate their old contents before a state change is signed.
 */

// --- generic writes -----------------------------------------------------------

type Tables = typeof schema;
type Row<T extends Table> = T['$inferSelect'];
type NewRow<T extends Table> = T['$inferInsert'];

/**
 * Which rows: each named column equals its value, is null, or is one of a
 * list. `{ syncId, key: ['A', 'B'], removedAt: null }`.
 */
export type Match<T extends Table> = {
  [K in keyof Row<T>]?: Row<T>[K] | NonNullable<Row<T>[K]>[];
};

function matching<T extends Table>(table: T, match: Match<T>): SQL | undefined {
  const columns = getTableColumns(table) as Record<string, ReturnType<typeof getTableColumns>[string]>;
  return and(
    ...Object.entries(match)
      .filter(([, value]) => value !== undefined)
      .map(([name, value]) => {
        const column = columns[name];
        if (value === null) return isNull(column);
        return Array.isArray(value) ? inArray(column, value) : eq(column, value);
      }),
  );
}

export async function insert<T extends Table>(db: Queryable, table: T, rows: NewRow<T> | NewRow<T>[]): Promise<void> {
  if (Array.isArray(rows) && rows.length === 0) return;
  await db.insert(own(db, table)).values(rows as never);
}

/** Insert the rows whose unique keys are free; returns how many that was. */
export async function insertIfAbsent<T extends Table>(
  db: Queryable,
  table: T,
  rows: NewRow<T> | NewRow<T>[],
): Promise<number> {
  const all = Array.isArray(rows) ? rows : [rows];
  if (all.length === 0) return 0;
  return dialect.insertIfAbsent(db, own(db, table), all);
}

/** Insert the rows, or where one repeats the unique key `target`, overwrite its `columns`. */
export async function upsert<T extends Table>(
  db: Queryable,
  table: T,
  rows: NewRow<T>[],
  { target, columns }: { target: (keyof Row<T>)[]; columns: (keyof Row<T>)[] },
): Promise<void> {
  if (rows.length === 0) return;
  await dialect.upsert(db, own(db, table), rows, target, columns);
}

/**
 * Set columns on the matching rows; returns how many matched. Matching on
 * the old value (`{ id, revokedAt: null }`) makes it a compare-and-set.
 */
export async function update<T extends Table>(
  db: Queryable,
  table: T,
  match: Match<T>,
  set: Partial<NewRow<T>>,
): Promise<number> {
  const mine = own(db, table);
  return changedRows(await db.update(mine).set(set as never).where(matching(mine, match)));
}

/** State changes authenticate the old row first and cannot overwrite a concurrent change. */
export async function updateAuth<T extends Tables['identities'] | Tables['credentials'] | Tables['deviceAuthorizations'] | Tables['serviceBindings']>(
  db: Queryable,
  chainKey: Buffer,
  table: T,
  match: Match<T>,
  changes: Partial<NewRow<T>>,
): Promise<number> {
  const mine = own(db, table);
  const kind = getTableName(table) as AuthTable;
  const rows = await db.select().from(mine as Table).where(matching(mine, match));
  let changed = 0;
  for (const raw of rows) {
    const row = raw as AuthRow;
    // An unauthenticated row is dead; never sign its claimed contents again.
    if (!checkAuthRow(chainKey, kind, row)) continue;
    const next = { ...row, ...changes } as AuthRow;
    changed += await update(db, table, { ...match, id: row.id, authMac: row.authMac } as Match<T>, {
      ...changes, authMac: authMac(chainKey, kind, next),
    } as Partial<NewRow<T>>);
  }
  return changed;
}

/**
 * Lock the matching rows until the transaction ends, and read them as they
 * are once the lock is ours. Only for real races; each caller says which.
 */
export async function lock<T extends Table>(tx: Transaction, table: T, match: Match<T>): Promise<Row<T>[]> {
  const mine = own(tx, table);
  return (await forUpdate(tx, tx.select().from(mine as Table).where(matching(mine, match)))) as Row<T>[];
}

// --- places -----------------------------------------------------------------

export type ResolvedPath = {
  project: { id: string; slug: string; name: string; archivedAt: Date | null };
  environment: { id: string; slug: string; name: string; archivedAt: Date | null } | null;
  secret: {
    id: string;
    key: string;
    archivedAt: Date | null;
    currentVersionId: string | null;
    /** 0 before the first version. */
    currentVersion: number;
  } | null;
};

const none = sql`1 = 0`;

/** A place that is not deleted: its slug is no tombstone's (`@coffre/core/schemas`). */
function standing(slug: AnyColumn): SQL {
  return not(tombstone(slug));
}

/**
 * A path's project, environment and secret. Null when the project does not
 * exist; a missing environment or secret comes back as null in its place.
 * A deleted place is missing too, unless asked for its `tombstones`, by
 * which the log is still read: `market~deleted-2026-10-05`.
 */
export async function resolvePath(
  db: Queryable,
  path: { project: string; environment?: string; key?: string },
  { tombstones = false }: { tombstones?: boolean } = {},
): Promise<ResolvedPath | null> {
  const { projects, environments, secrets } = tablesOf(db);
  const alive = (slug: AnyColumn) => (tombstones ? undefined : standing(slug));
  const [row] = await db
    .select({ project: projects, environment: environments, secret: secrets })
    .from(projects)
    .leftJoin(
      environments,
      path.environment === undefined
        ? none
        : and(eq(environments.projectId, projects.id), eq(environments.slug, path.environment), alive(environments.slug)),
    )
    .leftJoin(
      secrets,
      path.key === undefined ? none : and(eq(secrets.environmentId, environments.id), eq(secrets.key, path.key)),
    )
    .where(and(eq(projects.slug, path.project), alive(projects.slug)))
    .limit(1);
  if (row === undefined) return null;
  const { project, environment, secret } = row;
  return {
    project: { id: project.id, slug: project.slug, name: project.name, archivedAt: project.archivedAt },
    environment:
      environment === null
        ? null
        : { id: environment.id, slug: environment.slug, name: environment.name, archivedAt: environment.archivedAt },
    secret:
      secret === null
        ? null
        : {
            id: secret.id,
            key: secret.key,
            archivedAt: secret.archivedAt,
            currentVersionId: secret.currentVersionId,
            currentVersion: secret.currentVersion,
          },
  };
}

export type PlaceRow = {
  id: string;
  slug: string;
  name: string;
  archivedAt: Date | null;
  environments: { id: string; slug: string; name: string; archivedAt: Date | null; secretCount: number }[];
};

/**
 * Every project with its environments and their live secret counts, by
 * slug. Deleted ones are left out, unless asked for their `tombstones`, to
 * name an id the log holds.
 */
export async function places(db: Queryable, { tombstones = false }: { tombstones?: boolean } = {}): Promise<PlaceRow[]> {
  const { projects, environments, secrets } = tablesOf(db);
  const alive = (slug: AnyColumn) => (tombstones ? undefined : standing(slug));
  const rows = await db
    .select({
      project: projects,
      environment: environments,
      secretCount: count(secrets.id),
    })
    .from(projects)
    .leftJoin(environments, and(eq(environments.projectId, projects.id), alive(environments.slug)))
    .leftJoin(secrets, and(eq(secrets.environmentId, environments.id), isNull(secrets.archivedAt)))
    .where(alive(projects.slug))
    .groupBy(projects.id, environments.id)
    .orderBy(asc(projects.slug), asc(environments.slug));

  const found: PlaceRow[] = [];
  for (const { project, environment, secretCount } of rows) {
    let place = found.at(-1);
    if (place?.id !== project.id) {
      place = { id: project.id, slug: project.slug, name: project.name, archivedAt: project.archivedAt, environments: [] };
      found.push(place);
    }
    if (environment === null) continue;
    place.environments.push({
      id: environment.id,
      slug: environment.slug,
      name: environment.name,
      archivedAt: environment.archivedAt,
      secretCount: Number(secretCount),
    });
  }
  return found;
}

/**
 * How many distinct live secret names each project holds across the given
 * environments: the same key in dev and prod is one secret.
 */
export async function distinctSecretCounts(db: Queryable, environmentIds: string[]): Promise<Map<string, number>> {
  if (environmentIds.length === 0) return new Map();
  const { secrets } = tablesOf(db);
  const rows = await db
    .select({ projectId: secrets.projectId, count: countDistinct(secrets.key) })
    .from(secrets)
    .where(and(inArray(secrets.environmentId, environmentIds), isNull(secrets.archivedAt)))
    .groupBy(secrets.projectId);
  return new Map(rows.map((row) => [row.projectId, Number(row.count)]));
}

// --- deleting a place ----------------------------------------------------------

/** A project, or one of its environments: what a deletion takes. */
export type Doomed = { projectId: string; environmentId: string | null };

/** A grant, lapsed or live, on a place being deleted: an environment's names its project too, as the vault's changes do. */
export type DoomedGrant = { principal: string; projectId: string; environmentId: string | null; role: string; expiresAt: number | null };

/**
 * What deleting a place would take: how many keys it names, how many of
 * their versions still hold a value, and every grant on it, lapsed ones
 * too, with who would hold nothing else afterwards. The grants are the
 * vault's to revoke; a list of them is a read (`members` reads them too).
 */
export async function deletionScope(db: Queryable, place: Doomed): Promise<{
  /** The environments it takes, by slug: a project's every live one, or the one. */
  environments: { id: string; slug: string }[];
  keys: number;
  versions: number;
  grants: DoomedGrant[];
  /** Members, not owners, whose every live grant is among `grants`. */
  stranded: string[];
}> {
  const { secrets, secretVersions, vaultGrants, vaultMembers, environments } = tablesOf(db);
  const under = secretsUnder(secrets, place);
  // Every grant on the instance, the place's and all others: few rows, and what tells who is left holding nothing.
  const [going, [keys], [versions], held] = await Promise.all([
    db.select({ id: environments.id, slug: environments.slug }).from(environments).where(and(
      eq(environments.projectId, place.projectId),
      place.environmentId === null ? standing(environments.slug) : eq(environments.id, place.environmentId),
    )).orderBy(asc(environments.slug)),
    db.select({ n: count() }).from(secrets).where(under),
    db.select({ n: count() }).from(secretVersions).innerJoin(secrets, eq(secrets.id, secretVersions.secretId))
      .where(and(under, holdsValue(secretVersions))),
    db.select({
      principal: vaultGrants.principal,
      projectId: sql<string>`coalesce(${vaultGrants.projectId}, ${environments.projectId})`,
      environmentId: vaultGrants.environmentId,
      role: vaultGrants.role,
      expiresAt: vaultGrants.expiresAt,
      owner: vaultMembers.owner,
    })
      .from(vaultGrants)
      .innerJoin(vaultMembers, eq(vaultMembers.principal, vaultGrants.principal))
      .leftJoin(environments, eq(environments.id, vaultGrants.environmentId))
      .orderBy(asc(vaultGrants.principal)),
  ]);
  const doomed = (grant: (typeof held)[number]) =>
    place.environmentId === null ? grant.projectId === place.projectId : grant.environmentId === place.environmentId;
  const grants = held.filter(doomed).map(({ owner: _, ...grant }) => grant);
  const now = Date.now();
  const stranded = [...new Set(grants.map((grant) => grant.principal))].filter((principal) =>
    held.every((grant) => grant.principal !== principal
      || (!grant.owner && (doomed(grant) || (grant.expiresAt !== null && grant.expiresAt <= now)))));
  return { environments: going, keys: Number(keys.n), versions: Number(versions.n), grants, stranded };
}

function secretsUnder(secrets: Tables['secrets'], place: Doomed): SQL {
  return and(
    eq(secrets.projectId, place.projectId),
    place.environmentId === null ? undefined : eq(secrets.environmentId, place.environmentId),
  )!;
}

/** A version that still holds its value: an erased one has an empty ciphertext and wrapped key. */
function holdsValue(secretVersions: Tables['secretVersions']): SQL {
  return or(sql`length(${secretVersions.ciphertext}) > 0`, sql`length(${secretVersions.wrappedDek}) > 0`)!;
}

/**
 * Empty the ciphertext and wrapped data key of every version under a place:
 * the one change a version takes (`secret_versions_erase_only`). Its row
 * stays, which the log names. Returns how many still held a value.
 */
export async function eraseVersions(tx: Transaction, place: Doomed): Promise<number> {
  const { secrets, secretVersions } = tablesOf(tx);
  const under = tx.select({ id: secrets.id }).from(secrets).where(secretsUnder(secrets, place));
  const empty = Buffer.alloc(0);
  return changedRows(await tx.update(secretVersions)
    .set({ ciphertext: empty, wrappedDek: empty })
    .where(and(inArray(secretVersions.secretId, under), holdsValue(secretVersions))));
}

/**
 * The slug a deleted place keeps, `market~deleted-2026-10-05`, or
 * `market~deleted-2026-10-05-2` for the second that day: one that no
 * tombstone beside it holds yet. A deletion reads it under the log's
 * head, which every change of a slug takes first, so no other can claim it
 * before it commits.
 */
export async function tombstoneSlug(db: Queryable, slug: string, day: Date, within: { projectId: string } | null): Promise<string> {
  const { projects, environments } = tablesOf(db);
  const base = tombstoneOf(slug, day);
  const rows = within === null
    ? await db.select({ slug: projects.slug }).from(projects).where(like(projects.slug, `${base}%`))
    : await db.select({ slug: environments.slug }).from(environments)
      .where(and(eq(environments.projectId, within.projectId), like(environments.slug, `${base}%`)));
  const taken = new Set(rows.map((row) => row.slug));
  let n = 1;
  while (taken.has(tombstoneOf(slug, day, n))) n += 1;
  return tombstoneOf(slug, day, n);
}

// --- members and sign-in ------------------------------------------------------

/**
 * A member as the database names it, the vault's way: `user:<email>` for a
 * person, `token:<id>` for a service. The API's `service` stays out of storage.
 */
export function principalOf(member: { type: string; id: string }): string {
  return `${member.type === 'service' ? 'token' : 'user'}:${member.id}`;
}

/** `principalOf` undone. */
export function memberOf(principal: string): { type: 'user' | 'service'; id: string } {
  const colon = principal.indexOf(':');
  return { type: principal.slice(0, colon) === 'token' ? 'service' : 'user', id: principal.slice(colon + 1) };
}

/**
 * A member's status and generation as the vault last committed them, or
 * null for no member: `user:…`, `token:…` or `sync:…`. Read without a lock:
 * a member's row is the vault's to lock. Inside a transaction that holds
 * the log's head, any change the vault is making waits for it, so what this
 * reads holds until it commits.
 */
export async function memberStanding(db: Queryable, principal: string): Promise<{ status: string; generation: number } | null> {
  const { vaultMembers } = tablesOf(db);
  const [row] = await db
    .select({ status: vaultMembers.status, generation: vaultMembers.generation })
    .from(vaultMembers)
    .where(eq(vaultMembers.principal, principal));
  return row ?? null;
}

/**
 * A grant as `vault_grants` holds it: on a project, one of its environments
 * (with its project), every project (`projectId` null), or one environment
 * slug in every project.
 */
export type StoredGrant = GrantPlace & { role: string; expiresAt: number | null };

/** A live grant on every project, of an active member: `environmentSlug` is the one slug it covers, or null for all. */
export type EveryProjectGrant = { principal: string; environmentSlug: string | null; role: string; expiresAt: number | null };

/**
 * The live grants on every project that active members hold, as stored,
 * but those of members the vault has found changed around it, as lists
 * leave them out: who reaches a project or an environment the moment it is
 * made. A display, as lists are; the vault decides.
 */
export async function everyProjectGrants(db: Queryable, now: Date): Promise<EveryProjectGrant[]> {
  const { vaultMembers } = tablesOf(db);
  const grants = await readGrants(db, { everyProject: true, liveAt: now.getTime() });
  if (grants.length === 0) return [];
  const [rows, tampered] = await Promise.all([
    db
      .select({ principal: vaultMembers.principal })
      .from(vaultMembers)
      .where(and(inArray(vaultMembers.principal, [...new Set(grants.map((grant) => grant.principal))]), eq(vaultMembers.status, 'active'))),
    tamperedMembers(db),
  ]);
  const active = new Set(rows.map((row) => row.principal));
  return grants
    .filter((grant) => active.has(grant.principal) && !tampered.has(grant.principal))
    .map(({ principal, environmentSlug, role, expiresAt }) => ({ principal, environmentSlug, role, expiresAt }))
    .sort((a, b) => compareText(a.principal, b.principal) || compareText(a.environmentSlug ?? '', b.environmentSlug ?? ''));
}

const compareText = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

export type MemberRow = {
  type: 'user' | 'service';
  id: string;
  createdAt: Date;
  /** As the vault last wrote their row. */
  status: 'active' | 'removed';
  owner: boolean;
  generation: number;
  statusChangedAt: Date;
  statusChangedBy: string;
  /**
   * Their live grants, as stored. The vault checks a member's row and
   * grants against its MAC whenever they are used, which the app cannot:
   * a list shows them as the database has them.
   */
  grants: StoredGrant[];
  /**
   * Whether the vault has found their row or grants changed around it
   * since it last changed what they hold: its newest `vault.tampered`
   * about them is newer than its newest access entry. The vault refuses
   * them until an owner removes them.
   */
  tampered: boolean;
  /** Live credentials: neither revoked nor expired. */
  credentials: {
    id: string;
    kind: string;
    generation: number;
    label: string | null;
    tokenHint: string;
    identityId: string | null;
    /** The provider of the account that opened a session. */
    provider: string | null;
    createdAt: Date;
    createdBy: string;
    expiresAt: Date;
    lastUsedAt: Date | null;
    lastUsedIp: string | null;
  }[];
  /** Sign-in accounts still bound. */
  identities: {
    id: string;
    provider: string;
    subject: string;
    issuerHash: string;
    generation: number;
    email: string | null;
    createdAt: Date;
    lastSignInAt: Date | null;
  }[];
};

/**
 * The members the vault has found changed around it, and not started over
 * since: its newest `vault.tampered` about them, for their row (`mac`) or
 * an older one put back (`stale`), is newer than its newest entry changing
 * what they hold. Read from the log, which the vault writes and the app
 * reads: the vault's own findings, which the app has no key to make. Both
 * reads go by the log's (author, action, seq) and (author, subject, seq)
 * indexes, and findings are few.
 */
async function tamperedMembers(db: Queryable, principal?: string): Promise<Set<string>> {
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

/** The vault retains removed members too: an access entry without its row means tampering. */
export async function missingMembers(db: Queryable, member?: { type: string; id: string }): Promise<string[]> {
  const { auditLog, vaultMembers } = tablesOf(db);
  const rows = await db.selectDistinct({ principal: auditLog.subjectPrincipal })
    .from(auditLog)
    .leftJoin(vaultMembers, eq(vaultMembers.principal, auditLog.subjectPrincipal))
    .where(and(
      eq(auditLog.author, 'vault'),
      eq(auditLog.decision, 'allow'),
      inArray(auditLog.action, [...ACCESS_ACTIONS]),
      or(sql`${auditLog.subjectPrincipal} LIKE 'user:%'`, sql`${auditLog.subjectPrincipal} LIKE 'token:%'`),
      isNull(vaultMembers.principal),
      member === undefined ? undefined : eq(auditLog.subjectPrincipal, principalOf(member)),
    ));
  return rows.map((row) => row.principal!);
}

/**
 * People and services in the vault's directory, with their live sessions,
 * tokens and sign-in accounts: one of them, or everyone. What they may
 * reach is the vault's to say; offboarding and the account page read this.
 */
export async function members(
  db: Queryable,
  chainKey: Buffer,
  filter: { member?: { type: string; id: string } },
  now: Date,
): Promise<MemberRow[]> {
  const { vaultMembers, credentials, identities } = tablesOf(db);
  const principal = filter.member === undefined ? undefined : principalOf(filter.member);
  const of = (column: typeof vaultMembers.principal | typeof credentials.principal | typeof identities.principal) =>
    principal === undefined ? undefined : eq(column, principal);
  // Read binary columns directly. Relational JSON encodes bytea on Postgres
  // and cannot hold blobs on SQLite, so it cannot carry these MACs unchanged.
  const [rows, held, bound, granted, tampered] = await Promise.all([
    db
      .select({
        principal: vaultMembers.principal,
        createdAt: vaultMembers.createdAt,
        status: vaultMembers.status,
        owner: vaultMembers.owner,
        generation: vaultMembers.generation,
        statusChangedAt: vaultMembers.statusChangedAt,
        statusChangedBy: vaultMembers.statusChangedBy,
      })
      .from(vaultMembers)
      // A sync is a member too, but signs nothing in.
      .where(and(of(vaultMembers.principal), or(sql`${vaultMembers.principal} LIKE 'user:%'`, sql`${vaultMembers.principal} LIKE 'token:%'`)))
      .orderBy(asc(vaultMembers.principal)),
    // Live ones only, through `credentials_live_idx`: a CI service leaves an expired one behind each run.
    db.select().from(credentials).where(and(of(credentials.principal), isNull(credentials.revokedAt), gt(credentials.expiresAt, now))),
    db.select().from(identities).where(of(identities.principal)),
    readGrants(db, { ...(principal === undefined ? {} : { principal }), liveAt: now.getTime() }),
    tamperedMembers(db, principal),
  ]);
  const validIdentities = bound.filter((row) => checkAuthRow(chainKey, 'identities', row));
  const providers = new Map(validIdentities.filter((row) => row.revokedAt === null).map((row) => [row.id, row.provider]));
  // A session is dead too when the account it depends on cannot authenticate.
  const validCredentials = held.filter((row) => checkAuthRow(chainKey, 'credentials', row)
    && (row.identityId === null || providers.has(row.identityId)));
  return rows.map((row) => ({
    ...memberOf(row.principal),
    createdAt: new Date(row.createdAt),
    status: row.status as MemberRow['status'],
    owner: row.owner,
    generation: row.generation,
    statusChangedAt: new Date(row.statusChangedAt),
    statusChangedBy: row.statusChangedBy,
    grants: granted
      .filter((grant) => grant.principal === row.principal)
      .map(({ projectId, environmentId, environmentSlug, role, expiresAt }) => ({ projectId, environmentId, environmentSlug, role, expiresAt })),
    tampered: tampered.has(row.principal),
    credentials: validCredentials.filter((credential) => credential.principal === row.principal
      && credential.revokedAt === null && credential.expiresAt > now)
      .map(({ tokenHash: _hash, authMac: _mac, principal: _principal, revokedAt: _at, revokedBy: _by, ...credential }) => ({
        ...credential,
        provider: credential.identityId === null ? null : providers.get(credential.identityId) ?? null,
      })),
    identities: validIdentities.filter((identity) => identity.principal === row.principal
      && identity.revokedAt === null).map((identity) => ({
      id: identity.id,
      provider: identity.provider,
      subject: identity.subject,
      issuerHash: identity.issuerHash,
      generation: identity.generation,
      email: identity.email,
      createdAt: identity.createdAt,
      lastSignInAt: identity.lastSignInAt,
    })),
  }));
}

/**
 * Every allowed read, write and import of a secret by these actors, the
 * restores of the secrets they touched, and every removal from the
 * instance, oldest first. Each row that names a secret carries it as it is
 * now: its key, current version, and whether it or its place is archived.
 */
export async function memberActivity(db: Queryable, actorIds: string[]) {
  const { auditLog, secrets, environments, projects } = tablesOf(db);
  const allowed = eq(auditLog.decision, 'allow');
  const seen = and(
    allowed,
    inArray(auditLog.actor, actorIds.flatMap((id) => [`user:${id}`, `token:${id}`])),
    inArray(auditLog.action, ['secret.read', 'secret.write']),
  );
  const touched = db.select({ id: auditLog.secretId }).from(auditLog).where(seen);
  const rows = await db
    .select({
      actor: auditLog.actor,
      action: auditLog.action,
      secretId: auditLog.secretId,
      metadata: auditLog.metadata,
      occurredAt: auditLog.occurredAt,
      key: secrets.key,
      currentVersion: secrets.currentVersion,
      archived: truth(sql`${secrets.archivedAt} IS NOT NULL OR ${environments.archivedAt} IS NOT NULL OR ${projects.archivedAt} IS NOT NULL`),
      project: projects.slug,
      environment: environments.slug,
    })
    .from(auditLog)
    .leftJoin(secrets, eq(secrets.id, auditLog.secretId))
    .leftJoin(environments, eq(environments.id, secrets.environmentId))
    .leftJoin(projects, eq(projects.id, secrets.projectId))
    .where(
      or(
        seen,
        and(allowed, eq(auditLog.action, 'secret.restore'), inArray(auditLog.secretId, touched)),
      ),
    )
    .orderBy(asc(auditLog.seq));
  return rows.map(shown);
}

/** The person an account at a provider is bound to, if it is. */
export async function findIdentity(
  db: Queryable,
  chainKey: Buffer,
  account: { provider: string; issuerHash: string; subject: string },
) {
  const { identities } = tablesOf(db);
  const rows = await db
    .select()
    .from(identities)
    .where(
      and(eq(identities.provider, account.provider), eq(identities.issuerHash, account.issuerHash), eq(identities.subject, account.subject)),
    );
  for (const row of rows) verifyAuthRow(chainKey, 'identities', row);
  return rows.find((row) => row.revokedAt === null) ?? null;
}

/**
 * A credential by its token's hash or by id, with whether its sign-in
 * account is still bound. Revoked and expired ones too: the caller decides
 * what is live, and the vault whether its principal is still a member.
 *
 * It reads the database clock as well, which keeps it out of Hyperdrive's
 * query cache: Hyperdrive caches no query that calls a stable or volatile
 * function, CURRENT_TIMESTAMP among them. Every request looks its
 * credential up outside a transaction, so on a Hyperdrive config created
 * without `--caching-disabled`, a token revoked or a session signed out
 * would otherwise keep working for up to a minute.
 */
export async function findCredential(db: Queryable, chainKey: Buffer, by: { tokenHash: Buffer } | { id: string }) {
  const { credentials, identities } = tablesOf(db);
  const [row] = await db
    .select({ credential: credentials, identity: identities, now: clock(db) })
    .from(credentials)
    .leftJoin(identities, eq(identities.id, credentials.identityId))
    .where('tokenHash' in by ? eq(credentials.tokenHash, by.tokenHash) : eq(credentials.id, by.id));
  if (row === undefined) return null;
  verifyAuthRow(chainKey, 'credentials', row.credential);
  if (row.identity !== null) verifyAuthRow(chainKey, 'identities', row.identity);
  if (row.credential.identityId !== null && row.identity === null) throw new Error('credential identity is missing');
  const binding = issuingBinding(row.credential.createdBy);
  return {
    ...row.credential,
    /** For a credential a trust binding issued: whether that binding still stands. Null for any other. */
    bindingStands: binding === null ? null : await bindingStands(db, chainKey, binding, row.credential.principal, row.credential.generation),
    identityRevokedAt: row.identity?.revokedAt ?? null,
    identityProvider: row.identity?.provider ?? null,
    identityIssuerHash: row.identity?.issuerHash ?? null,
    subject: row.identity?.subject ?? null,
    now: row.now,
  };
}

// --- trust bindings -----------------------------------------------------------

export type BindingRow = Tables['serviceBindings']['$inferSelect'];

/**
 * A service's live bindings, oldest first: made in its current generation,
 * its row not revoked, its MAC the app's, and no tombstone. A row that fails
 * its MAC is reported and passed over; a row put back after its binding was
 * removed is passed over by its tombstone, whatever the row says. A removal
 * moves the generation past every binding at once.
 */
export async function liveBindings(db: Queryable, chainKey: Buffer, principal: string, generation: number): Promise<BindingRow[]> {
  const { serviceBindings } = tablesOf(db);
  const rows = await db
    .select()
    .from(serviceBindings)
    .where(and(eq(serviceBindings.principal, principal), eq(serviceBindings.generation, generation), isNull(serviceBindings.revokedAt)))
    .orderBy(asc(serviceBindings.createdAt), asc(serviceBindings.id));
  const genuine = rows.filter((row) => checkAuthRow(chainKey, 'service_bindings', row));
  const dead = await tombstoned(db, genuine.map((row) => row.id));
  return genuine.filter((row) => !dead.has(row.id));
}

/**
 * One binding of `principal`'s, by ID: revoked or not, tombstoned or not.
 * Null for none, or for a row that fails its MAC, which is reported.
 */
export async function findBinding(db: Queryable, chainKey: Buffer, principal: string, id: string): Promise<BindingRow | null> {
  const { serviceBindings } = tablesOf(db);
  const [row] = await db
    .select()
    .from(serviceBindings)
    .where(and(eq(serviceBindings.id, id), eq(serviceBindings.principal, principal)));
  return row !== undefined && checkAuthRow(chainKey, 'service_bindings', row) ? row : null;
}

/**
 * Which of these bindings have a tombstone: an app entry `token.unbind`,
 * allowed, naming the binding's ID. A denied attempt is logged under the
 * same action and never counts. Every such entry counts, never only the
 * latest; their MACs are not checked, since a forged tombstone can only
 * refuse. One read through `audit_log_unbind_idx`, whose expression this
 * repeats.
 */
export async function tombstoned(db: Queryable, ids: readonly string[]): Promise<Set<string>> {
  if (ids.length === 0) return new Set();
  const { auditLog } = tablesOf(db);
  const bindingId = dialect.engineOf(db) === 'postgres'
    ? sql<string>`((${auditLog.metadata})::jsonb ->> 'bindingId')`
    : sql<string>`json_extract(${auditLog.metadata}, '$.bindingId')`;
  const rows = await db
    .select({ id: bindingId })
    .from(auditLog)
    .where(and(eq(auditLog.author, 'app'), eq(auditLog.action, 'token.unbind'), eq(auditLog.decision, 'allow'), inArray(bindingId, [...ids])));
  return new Set(rows.map((row) => row.id));
}

/** The expression `audit_log_unbind_idx` indexes: the binding an entry names. */
function namedBinding(db: Queryable): SQL<string> {
  const { auditLog } = tablesOf(db);
  return dialect.engineOf(db) === 'postgres'
    ? sql<string>`((${auditLog.metadata})::jsonb ->> 'bindingId')`
    : sql<string>`json_extract(${auditLog.metadata}, '$.bindingId')`;
}

/** Whether the binding `id` (a column or a value) has a tombstone: an allowed app `token.unbind` naming it. */
function hasTombstone(db: Queryable, id: SQL | string): SQL {
  const { auditLog } = tablesOf(db);
  return sql`EXISTS (SELECT 1 FROM ${auditLog} WHERE ${auditLog.author} = 'app' AND ${auditLog.action} = 'token.unbind'
    AND ${auditLog.decision} = 'allow' AND ${namedBinding(db)} = ${id})`;
}

/**
 * What an exchange may match, in one read: the service's live bindings on
 * this issuer, in its current generation as its member row says, with no
 * tombstone, each MAC-checked. A service holds at most `MAX_BINDINGS`, made
 * so under the log's head; more than that here is a database changed
 * around the app, and matches nothing.
 */
export async function exchangeCandidates(db: Queryable, chainKey: Buffer, principal: string, issuer: string, max: number): Promise<BindingRow[]> {
  const { serviceBindings, vaultMembers } = tablesOf(db);
  const id = dialect.engineOf(db) === 'postgres' ? sql`${serviceBindings.id}::text` : sql`${serviceBindings.id}`;
  const rows = await db
    .select({ binding: serviceBindings })
    .from(serviceBindings)
    .innerJoin(vaultMembers, and(eq(vaultMembers.principal, serviceBindings.principal), eq(vaultMembers.generation, serviceBindings.generation)))
    .where(and(
      eq(serviceBindings.principal, principal),
      eq(serviceBindings.issuer, issuer),
      isNull(serviceBindings.revokedAt),
      sql`NOT ${hasTombstone(db, id)}`,
    ))
    .orderBy(asc(serviceBindings.createdAt), asc(serviceBindings.id))
    .limit(max + 1);
  if (rows.length > max) {
    console.error({ event: 'bindings_over_limit', principal, issuer }, 'a service holds more bindings than any can');
    return [];
  }
  return rows.map((row) => row.binding).filter((row) => checkAuthRow(chainKey, 'service_bindings', row));
}

/**
 * Whether a credential's binding still stands: its row the app's, not
 * revoked, no tombstone, of the same member and generation. It reads the
 * database clock, as `findCredential` does, so that Hyperdrive never
 * answers it from its cache: a cached "no tombstone" would let a credential
 * whose rows were put back after its binding was removed sign in again. A
 * query of its own, not a join in `findCredential`, which every request
 * runs and which must work before the migration that made bindings.
 */
export async function bindingStands(db: Queryable, chainKey: Buffer, bindingId: string, principal: string, generation: number): Promise<boolean> {
  const { serviceBindings } = tablesOf(db);
  const [row] = await db
    .select({ binding: serviceBindings, tombstoned: truth(hasTombstone(db, bindingId)), now: clock(db) })
    .from(serviceBindings)
    .where(eq(serviceBindings.id, bindingId));
  return row !== undefined && !row.tombstoned && row.binding.revokedAt === null
    && row.binding.principal === principal && row.binding.generation === generation
    && checkAuthRow(chainKey, 'service_bindings', row.binding);
}

/**
 * The exchanges that issued these credentials, by credential ID: each one's
 * entry and the run its issuer asserted. One read through
 * `audit_log_exchange_idx`, whose expression this repeats.
 */
export async function exchangesOf(db: Queryable, credentialIds: readonly string[]): Promise<Map<string, { seq: bigint; run: Record<string, unknown> }>> {
  if (credentialIds.length === 0) return new Map();
  const { auditLog } = tablesOf(db);
  const credentialId = dialect.engineOf(db) === 'postgres'
    ? sql<string>`((${auditLog.metadata})::jsonb ->> 'credentialId')`
    : sql<string>`json_extract(${auditLog.metadata}, '$.credentialId')`;
  const rows = await db
    .select({ credentialId, seq: auditLog.seq, metadata: auditLog.metadata })
    .from(auditLog)
    .where(and(eq(auditLog.author, 'app'), eq(auditLog.action, 'token.exchange'), eq(auditLog.decision, 'allow'), inArray(credentialId, [...credentialIds])));
  return new Map(rows.map((row) => {
    const run = (JSON.parse(row.metadata) as { run?: unknown }).run;
    return [row.credentialId, { seq: row.seq, run: typeof run === 'object' && run !== null ? (run as Record<string, unknown>) : {} }];
  }));
}

/**
 * Whether this token, by its signing input's hash, was exchanged already.
 * Uncached, as `bindingStands` is: a cached "not yet" would send a replay
 * on to the vault and the commit, which refuses it only there.
 */
export async function tokenConsumed(db: Queryable, hash: Buffer): Promise<boolean> {
  const { consumedTokens } = tablesOf(db);
  const [row] = await db.select({ hash: consumedTokens.hash, now: clock(db) }).from(consumedTokens).where(eq(consumedTokens.hash, hash));
  return row !== undefined;
}

/** Spend a token: false when it was spent already, which the primary key decides. */
export async function consumeToken(db: Queryable, hash: Buffer): Promise<boolean> {
  return (await insertIfAbsent(db, tablesOf(db).consumedTokens, { hash })) === 1;
}

/**
 * How many credentials a binding issued since `since`, up to `atMost`: the
 * count stops there. Through `credentials_issued_by_idx`, it visits that
 * binding's last minute, not the expired history a CI service runs up.
 */
export async function exchangesSince(db: Queryable, principal: string, createdBy: string, since: Date, atMost: number): Promise<number> {
  const { credentials } = tablesOf(db);
  const rows = await db
    .select({ id: credentials.id })
    .from(credentials)
    .where(and(eq(credentials.principal, principal), eq(credentials.createdBy, createdBy), gt(credentials.createdAt, since)))
    .limit(atMost);
  return rows.length;
}

export async function insertBinding(db: Queryable, chainKey: Buffer, row: Omit<NewRow<Tables['serviceBindings']>, 'authMac'> & {
  id: string; principal: string; generation: number; profile: string; issuer: string; jwksUri: string; claims: string;
}): Promise<void> {
  const signed = { ...row, revokedAt: null };
  await insert(db, tablesOf(db).serviceBindings, { ...signed, authMac: authMac(chainKey, 'service_bindings', signed) });
}

/** Retire directory records from older memberships, including a sweep that rolled back. */
export async function revokePriorMembership(
  db: Queryable,
  chainKey: Buffer,
  principal: { type: string; id: string },
  generation: number,
  revokedBy: string,
): Promise<void> {
  const { credentials, identities } = tablesOf(db);
  const revokedAt = new Date();
  const older = (table: typeof credentials | typeof identities) =>
    and(eq(table.principal, principalOf(principal)), lt(table.generation, generation), isNull(table.revokedAt));
  // Expired credentials are dead already, and a CI service leaves one behind each run.
  const tables = [
    [credentials, and(older(credentials), gt(credentials.expiresAt, revokedAt))],
    [identities, older(identities)],
  ] as const;
  for (const [table, where] of tables) {
    for (const row of await db.select().from(table).where(where)) {
      if (!checkAuthRow(chainKey, getTableName(table) as AuthTable, row)) continue;
      await updateAuth(db, chainKey, table, { id: row.id, authMac: row.authMac }, { revokedAt, revokedBy });
    }
  }
}

/**
 * Revoke a member's credentials still live at `at`, or only those
 * `createdBy` issued: not revoked, not expired. Expired ones are dead
 * already, and a CI service's run to thousands; through
 * `credentials_live_idx`, the work is what is live, whatever the history.
 */
export async function revokeLiveCredentials(
  db: Queryable,
  chainKey: Buffer,
  live: { principal: string; createdBy?: string; at: Date },
  changes: { revokedAt: Date; revokedBy: string },
): Promise<number> {
  const { credentials } = tablesOf(db);
  const rows = await db.select({ id: credentials.id }).from(credentials).where(and(
    eq(credentials.principal, live.principal),
    isNull(credentials.revokedAt),
    gt(credentials.expiresAt, live.at),
    live.createdBy === undefined ? undefined : eq(credentials.createdBy, live.createdBy),
  ));
  if (rows.length === 0) return 0;
  return updateAuth(db, chainKey, credentials, { id: rows.map((row) => row.id), revokedAt: null }, changes);
}

/** Device authorizations: one by either of its codes, or every one still waiting for a decision. */
export async function findDeviceAuthorizations(
  db: Queryable,
  chainKey: Buffer,
  by: { userCode: string } | { deviceCodeHash: Buffer } | { openAt: Date },
) {
  const { deviceAuthorizations } = tablesOf(db);
  const rows = await db
    .select()
    .from(deviceAuthorizations)
    .where(
      'userCode' in by
        ? eq(deviceAuthorizations.userCode, by.userCode)
        : 'deviceCodeHash' in by
          ? eq(deviceAuthorizations.deviceCodeHash, by.deviceCodeHash)
          : and(isNull(deviceAuthorizations.decidedAt), gt(deviceAuthorizations.expiresAt, by.openAt)),
    );
  for (const row of rows) verifyAuthRow(chainKey, 'device_authorizations', row);
  return rows;
}

// --- secrets ------------------------------------------------------------------

/** The committed state to compare after the vault prepares a write or restore. */
export async function secretHeads(db: Queryable, environmentId: string, by: { keys: string[] } | { id: string }) {
  const { secrets } = tablesOf(db);
  return db.select({
    id: secrets.id,
    key: secrets.key,
    currentVersion: secrets.currentVersion,
    archivedAt: secrets.archivedAt,
  }).from(secrets).where(and(
    eq(secrets.environmentId, environmentId),
    'id' in by ? eq(secrets.id, by.id) : inArray(secrets.key, by.keys),
  ));
}

const envelopeColumns = (secretVersions: Tables['secretVersions']) => ({
  envelopeVersion: secretVersions.envelopeVersion,
  kekProvider: secretVersions.kekProvider,
  kekId: secretVersions.kekId,
  kekVersion: secretVersions.kekVersion,
  wrappedDek: secretVersions.wrappedDek,
  iv: secretVersions.iv,
  authTag: secretVersions.authTag,
  ciphertext: secretVersions.ciphertext,
});

function envelopeOf(row: Envelope): Envelope {
  return {
    envelopeVersion: row.envelopeVersion,
    kekProvider: row.kekProvider,
    kekId: row.kekId,
    kekVersion: row.kekVersion,
    wrappedDek: row.wrappedDek,
    iv: row.iv,
    authTag: row.authTag,
    ciphertext: row.ciphertext,
  };
}

export type SecretRow = {
  id: string;
  key: string;
  archivedAt: Date | null;
  /** Null before the first version. */
  current: {
    id: string;
    version: number;
    createdAt: Date;
    createdBy: string;
    envelope: Envelope;
  } | null;
};

/**
 * An environment's secrets, archived ones included, each with its current
 * version and ciphertext; or just one of them. Listing, revealing, running
 * and exporting all read this.
 */
export async function environmentSecrets(
  db: Queryable,
  environmentId: string,
  secretId?: string,
): Promise<SecretRow[]> {
  const { secrets, secretVersions, projects, environments } = tablesOf(db);
  const rows = await db
    .select({
      id: secrets.id,
      key: secrets.key,
      archivedAt: secrets.archivedAt,
      versionId: secretVersions.id,
      version: secretVersions.version,
      createdAt: secretVersions.createdAt,
      createdBy: secretVersions.createdBy,
      ...envelopeColumns(secretVersions),
    })
    .from(secrets)
    .innerJoin(projects, eq(projects.id, secrets.projectId))
    .innerJoin(environments, eq(environments.id, secrets.environmentId))
    .leftJoin(secretVersions, eq(secretVersions.id, secrets.currentVersionId))
    .where(and(
      eq(secrets.environmentId, environmentId),
      isNull(projects.archivedAt),
      isNull(environments.archivedAt),
      secretId === undefined ? undefined : eq(secrets.id, secretId),
    ))
    .orderBy(asc(secrets.key));
  return rows.map((row) => ({
    id: row.id,
    key: row.key,
    archivedAt: row.archivedAt,
    current:
      row.versionId === null
        ? null
        : {
            id: row.versionId,
            version: row.version!,
            createdAt: row.createdAt!,
            createdBy: row.createdBy!,
            envelope: envelopeOf(row as Envelope),
          },
  }));
}

/** Every version of a secret, newest first. */
export async function secretHistory(
  db: Queryable,
  secretId: string,
): Promise<{ id: string; version: number; createdAt: Date; createdBy: string; envelope: Envelope }[]> {
  const { secretVersions } = tablesOf(db);
  const rows = await db
    .select({
      id: secretVersions.id,
      version: secretVersions.version,
      createdAt: secretVersions.createdAt,
      createdBy: secretVersions.createdBy,
      ...envelopeColumns(secretVersions),
    })
    .from(secretVersions)
    .where(eq(secretVersions.secretId, secretId))
    .orderBy(desc(secretVersions.version));
  return rows.map((row) => ({
    id: row.id,
    version: row.version,
    createdAt: row.createdAt,
    createdBy: row.createdBy,
    envelope: envelopeOf(row),
  }));
}


// --- the audit log ------------------------------------------------------------

/**
 * The chain head and the database clock, in one statement. Locked, it is
 * where every appender queues, which is what keeps the chain a chain. The
 * clock is the database's, not an application server's, so entries from
 * several servers still order by time (CDR 2024/1774 Art 12(2)(f)).
 */
export async function auditHead(db: Queryable): Promise<{ nextSeq: bigint; headHash: Buffer } | null> {
  const { auditChainHead } = tablesOf(db);
  const [head] = await db
    .select({ nextSeq: auditChainHead.nextSeq, headHash: auditChainHead.headHash })
    .from(auditChainHead)
    .limit(1);
  return head ?? null;
}

const auditColumns = (auditLog: Tables['auditLog']) => ({
  seq: auditLog.seq,
  author: auditLog.author,
  keyId: auditLog.keyId,
  occurredAt: auditLog.occurredAt,
  actor: auditLog.actor,
  action: auditLog.action,
  decision: auditLog.decision,
  code: auditLog.code,
  subjectPrincipal: auditLog.subjectPrincipal,
  projectId: auditLog.projectId,
  environmentId: auditLog.environmentId,
  secretId: auditLog.secretId,
  secretVersionId: auditLog.secretVersionId,
  operationId: auditLog.operationId,
  requestId: auditLog.requestId,
  sourceIp: auditLog.sourceIp,
  relatedSeq: auditLog.relatedSeq,
  metadata: auditLog.metadata,
});

/** When an entry happened, as the API shows it. */
function shown<Row extends { occurredAt: number }>(row: Row): Omit<Row, 'occurredAt'> & { occurredAt: string } {
  return { ...row, occurredAt: new Date(row.occurredAt).toISOString() };
}

/** Rows in chain order from `fromSeq`, with every field as it was hashed. */
export async function auditRange(db: Queryable, fromSeq = 0n, limit = 1000) {
  const { auditLog } = tablesOf(db);
  const rows = await db
    .select({ ...auditColumns(auditLog), prevHash: auditLog.prevHash, mac: auditLog.mac, hash: auditLog.hash })
    .from(auditLog)
    .where(gte(auditLog.seq, fromSeq))
    .orderBy(asc(auditLog.seq))
    .limit(limit);
  return rows.map((row) => ({ ...row, author: row.author as Author, decision: row.decision as 'allow' | 'deny' }));
}

export type AuditFilter = {
  /** Entries in any of these projects or environments, for a caller who reads only those. */
  within?: { projectIds: string[]; environmentIds: string[] };
  projectId?: string;
  environmentId?: string;
  secretId?: string;
  /** Entries by any of these actors, as the log stores them: `user:ada@acme.example`. */
  actors?: string[];
  decision?: string;
  /** Entries with none of these actions, filtered here so a page stays full. */
  excludeActions?: readonly string[];
  /** Entries older than this, for paging backwards. */
  beforeSeq?: bigint;
  limit: number;
};

/** The conditions of `filter`, as a WHERE clause on the log. */
function auditWhere(auditLog: ReturnType<typeof tablesOf>['auditLog'], filter: Omit<AuditFilter, 'limit'>): SQL | undefined {
  const { within } = filter;
  return and(
    within === undefined
      ? undefined
      : or(inArray(auditLog.projectId, within.projectIds), inArray(auditLog.environmentId, within.environmentIds)),
    filter.projectId === undefined ? undefined : eq(auditLog.projectId, filter.projectId),
    filter.environmentId === undefined ? undefined : eq(auditLog.environmentId, filter.environmentId),
    filter.secretId === undefined ? undefined : eq(auditLog.secretId, filter.secretId),
    filter.actors === undefined ? undefined : inArray(auditLog.actor, filter.actors),
    filter.decision === undefined ? undefined : eq(auditLog.decision, filter.decision),
    filter.excludeActions === undefined || filter.excludeActions.length === 0
      ? undefined
      : notInArray(auditLog.action, [...filter.excludeActions]),
    filter.beforeSeq === undefined ? undefined : lt(auditLog.seq, filter.beforeSeq),
  );
}

/**
 * A page of the log, both authors, newest first, with the slugs of the
 * places each entry names and the key of its secret.
 */
export async function auditPage(db: Queryable, filter: AuditFilter) {
  const { auditLog, projects, environments, secrets } = tablesOf(db);
  const rows = await db
    .select({ ...auditColumns(auditLog), project: projects.slug, environment: environments.slug, key: secrets.key })
    .from(auditLog)
    .leftJoin(projects, eq(projects.id, auditLog.projectId))
    .leftJoin(environments, eq(environments.id, auditLog.environmentId))
    .leftJoin(secrets, eq(secrets.id, auditLog.secretId))
    .where(auditWhere(auditLog, filter))
    .orderBy(desc(auditLog.seq))
    .limit(filter.limit);
  return rows.map(shown);
}

/** The newest of one author's allowed entries of `action`, with the database's clock beside it. */
function newestEntry(db: Queryable, author: 'app' | 'vault', action: string) {
  const { auditLog } = tablesOf(db);
  return db
    .select({ seq: auditLog.seq, occurredAt: auditLog.occurredAt, metadata: auditLog.metadata, now: clockMillis(db) })
    .from(auditLog)
    .where(and(eq(auditLog.author, author), eq(auditLog.action, action), eq(auditLog.decision, 'allow')))
    .orderBy(desc(auditLog.seq))
    .limit(1);
}

/**
 * The newest checkpoint the vault signed: its newest `audit.checkpoint`,
 * whose signature whoever shows it checks with the vault's public key.
 */
export async function latestCheckpoint(db: Queryable): Promise<Checkpoint | null> {
  const [row] = await newestEntry(db, 'vault', 'audit.checkpoint');
  return row === undefined ? null : (JSON.parse(row.metadata) as Checkpoint);
}

/**
 * How many entries of each of `actions` match `filter`, but for its
 * exclusions and limit, from `fromSeq` on: one grouped count. Both authors
 * are named so that the log's (author, action, seq) index serves it, a
 * range per action, without reading the entries themselves when nothing
 * else is filtered on.
 */
export async function auditActionCounts(
  db: Queryable,
  filter: AuditFilter,
  actions: readonly string[],
  fromSeq?: bigint,
): Promise<{ action: string; count: number }[]> {
  const { auditLog } = tablesOf(db);
  return db
    .select({ action: auditLog.action, count: count() })
    .from(auditLog)
    .where(
      and(
        inArray(auditLog.author, ['app', 'vault']),
        inArray(auditLog.action, [...actions]),
        fromSeq === undefined ? undefined : gte(auditLog.seq, fromSeq),
        auditWhere(auditLog, { ...filter, excludeActions: undefined }),
      ),
    )
    .groupBy(auditLog.action);
}

/**
 * What readiness reads: the newest heartbeat, with its age by the
 * database's clock, so a skewed application server cannot hide a stale
 * one; and the newest checkpoint the vault signed.
 */
export async function readiness(db: Queryable): Promise<{
  beat: { seq: bigint; ageSeconds: number } | null;
  checkpoint: Checkpoint | null;
}> {
  const [[beat], checkpoint] = await Promise.all([newestEntry(db, 'app', 'audit.heartbeat'), latestCheckpoint(db)]);
  return { beat: beat === undefined ? null : { seq: beat.seq, ageSeconds: (beat.now - beat.occurredAt) / 1000 }, checkpoint };
}

/** How many migrations the database has applied. */
export async function appliedMigrations(db: Queryable): Promise<number> {
  const [applied] = await db.select({ n: count() }).from(migrationLedger(db));
  return applied?.n ?? 0;
}
