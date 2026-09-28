import { and, asc, count, desc, eq, getTableColumns, gt, gte, inArray, isNull, lt, or, sql, type SQL } from 'drizzle-orm';

import type { Envelope } from '../../core/src/envelope.ts';
import { own, tablesOf, type Queryable, type Transaction } from './database.ts';
import * as dialect from './dialect.ts';
import { canonicalTimestamp, changedRows, clock, forUpdate, migrationLedger, truth, type Table } from './dialect.ts';
import type * as schema from './schema.ts';

/**
 * Every query coffre runs, and nowhere else: named reads, each returning all
 * that its callers need in one statement, four generic writes, and a lock.
 * The server works on what these return and never writes SQL; lint keeps
 * drizzle out of apps/web.
 *
 * Each query builds on the tables of the database it is given (`tablesOf`),
 * so the one text runs on Postgres, MySQL and SQLite; see portable.ts. The
 * server names a table for the generic writes by importing schema.ts, and
 * `own` swaps in the database's twin.
 *
 * Writes do not check first and do not read back. A unique constraint
 * answers "is it taken", and a conditional update's row count answers "was
 * it still there"; the response is built from what was written.
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

/**
 * A path's project, environment and secret. Null when the project does not
 * exist; a missing environment or secret comes back as null in its place.
 */
export async function resolvePath(
  db: Queryable,
  path: { project: string; environment?: string; key?: string },
): Promise<ResolvedPath | null> {
  const { projects, environments, secrets } = tablesOf(db);
  const [row] = await db
    .select({ project: projects, environment: environments, secret: secrets })
    .from(projects)
    .leftJoin(
      environments,
      path.environment === undefined
        ? none
        : and(eq(environments.projectId, projects.id), eq(environments.slug, path.environment)),
    )
    .leftJoin(
      secrets,
      path.key === undefined ? none : and(eq(secrets.environmentId, environments.id), eq(secrets.key, path.key)),
    )
    .where(eq(projects.slug, path.project))
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

/** Every project with its environments and their live secret counts, by slug. */
export async function places(db: Queryable): Promise<PlaceRow[]> {
  const { projects, environments, secrets } = tablesOf(db);
  const rows = await db
    .select({
      project: projects,
      environment: environments,
      secretCount: count(secrets.id),
    })
    .from(projects)
    .leftJoin(environments, eq(environments.projectId, projects.id))
    .leftJoin(secrets, and(eq(secrets.environmentId, environments.id), isNull(secrets.archivedAt)))
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

// --- members and sign-in ------------------------------------------------------

export type MemberRow = {
  type: 'user' | 'service';
  id: string;
  createdAt: Date;
  /** Live credentials: neither revoked nor expired. */
  credentials: {
    id: string;
    kind: string;
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
    email: string | null;
    createdAt: Date;
    lastSignInAt: Date | null;
  }[];
};

/**
 * Principals in the directory with their live sessions, tokens and sign-in
 * accounts: one of them, or everyone, by type and id. What they may reach
 * is the vault's to say; offboarding and the account page read this.
 */
export async function members(
  db: Queryable,
  filter: { member?: { type: string; id: string } },
  now: Date,
): Promise<MemberRow[]> {
  const { principals, credentials, identities } = tablesOf(db);
  const { member } = filter;
  const rows = await db.query.principals.findMany({
    where: member === undefined ? undefined : and(eq(principals.principalType, member.type), eq(principals.principalId, member.id)),
    orderBy: [asc(principals.principalType), asc(principals.principalId)],
    with: {
      credentials: {
        columns: { tokenHash: false },
        where: and(isNull(credentials.revokedAt), gt(credentials.expiresAt, now)),
        with: { identity: { columns: { provider: true } } },
      },
      identities: { where: isNull(identities.revokedAt) },
    },
  });
  return rows.map((row) => ({
    type: row.principalType as MemberRow['type'],
    id: row.principalId,
    createdAt: row.createdAt,
    credentials: row.credentials.map(({ identity, principalType: _type, principalId: _id, revokedAt: _at, revokedBy: _by, ...credential }) => ({
      ...credential,
      provider: identity?.provider ?? null,
    })),
    identities: row.identities.map((identity) => ({
      id: identity.id,
      provider: identity.provider,
      subject: identity.subject,
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
    inArray(auditLog.actorId, actorIds),
    inArray(auditLog.action, ['secret.read', 'secret.write', 'secret.import']),
  );
  const touched = db.select({ id: auditLog.secretId }).from(auditLog).where(seen);
  const rows = await db
    .select({
      actorType: auditLog.actorType,
      actorId: auditLog.actorId,
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
        and(allowed, eq(auditLog.action, 'secret.rollback'), inArray(auditLog.secretId, touched)),
        and(allowed, eq(auditLog.action, 'directory.remove'), isNull(auditLog.projectId)),
      ),
    )
    .orderBy(asc(auditLog.seq));
  return rows.map((row) => ({ ...row, occurredAt: canonicalTimestamp(row.occurredAt) }));
}

/** The person an account at a provider is bound to, if it is. */
export async function findIdentity(
  db: Queryable,
  account: { provider: string; subject: string },
): Promise<{ id: string; principalId: string } | null> {
  const { identities } = tablesOf(db);
  const [row] = await db
    .select({ id: identities.id, principalId: identities.principalId })
    .from(identities)
    .where(
      and(eq(identities.provider, account.provider), eq(identities.subject, account.subject), isNull(identities.revokedAt)),
    );
  return row ?? null;
}

/**
 * A credential by its token's hash or by id, with whether its sign-in
 * account is still bound. Revoked and expired ones too: the caller decides
 * what is live, and the vault whether its principal is still a member.
 */
export async function findCredential(db: Queryable, by: { tokenHash: Buffer } | { id: string }) {
  const { credentials, identities } = tablesOf(db);
  const [row] = await db
    .select({
      id: credentials.id,
      kind: credentials.kind,
      principalType: credentials.principalType,
      principalId: credentials.principalId,
      expiresAt: credentials.expiresAt,
      revokedAt: credentials.revokedAt,
      lastUsedAt: credentials.lastUsedAt,
      identityRevokedAt: identities.revokedAt,
      subject: identities.subject,
    })
    .from(credentials)
    .leftJoin(identities, eq(identities.id, credentials.identityId))
    .where('tokenHash' in by ? eq(credentials.tokenHash, by.tokenHash) : eq(credentials.id, by.id));
  return row ?? null;
}

/** Device authorizations: one by either of its codes, or every one still waiting for a decision. */
export async function findDeviceAuthorizations(
  db: Queryable,
  by: { userCode: string } | { deviceCodeHash: Buffer } | { openAt: Date },
) {
  const { deviceAuthorizations } = tablesOf(db);
  return db
    .select()
    .from(deviceAuthorizations)
    .where(
      'userCode' in by
        ? eq(deviceAuthorizations.userCode, by.userCode)
        : 'deviceCodeHash' in by
          ? eq(deviceAuthorizations.deviceCodeHash, by.deviceCodeHash)
          : and(isNull(deviceAuthorizations.decidedAt), gt(deviceAuthorizations.expiresAt, by.openAt)),
    );
}

// --- secrets ------------------------------------------------------------------

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
 * version and ciphertext; or just one of them. Listing, revealing and
 * syncing all read this.
 */
export async function environmentSecrets(
  db: Queryable,
  environmentId: string,
  secretId?: string,
): Promise<SecretRow[]> {
  const { secrets, secretVersions } = tablesOf(db);
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
    .leftJoin(secretVersions, eq(secretVersions.id, secrets.currentVersionId))
    .where(and(eq(secrets.environmentId, environmentId), secretId === undefined ? undefined : eq(secrets.id, secretId)))
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

// --- syncs --------------------------------------------------------------------

export type SyncRow = Tables['syncs']['$inferSelect'] & {
  project: string;
  environment: string;
  projectArchivedAt: Date | null;
  environmentArchivedAt: Date | null;
  credential: { projectId: string; environmentId: string; project: string; environment: string; key: string };
  /** What the sync last pushed and has not since removed, per key. */
  recorded: { key: string; versionId: string | null }[];
};

/** Syncs, archived ones included, with their place, their credential's path and what they pushed; oldest first. */
export async function findSyncs(
  db: Queryable,
  filter: { id?: string; environmentId?: string; createdBy?: string; provider?: string },
): Promise<SyncRow[]> {
  const { syncs } = tablesOf(db);
  const rows = await db.query.syncs.findMany({
    where: and(
      filter.id === undefined ? undefined : eq(syncs.id, filter.id),
      filter.environmentId === undefined ? undefined : eq(syncs.environmentId, filter.environmentId),
      filter.createdBy === undefined ? undefined : eq(syncs.createdBy, filter.createdBy),
      filter.provider === undefined ? undefined : eq(syncs.provider, filter.provider),
    ),
    orderBy: [asc(syncs.createdAt)],
    with: {
      project: { columns: { slug: true, archivedAt: true } },
      environment: { columns: { slug: true, archivedAt: true } },
      credential: {
        columns: { key: true, projectId: true, environmentId: true },
        with: { project: { columns: { slug: true } }, environment: { columns: { slug: true } } },
      },
      keys: { columns: { key: true, secretVersionId: true }, where: (keys, { isNull }) => isNull(keys.removedAt) },
    },
  });
  return rows.map(({ project, environment, credential, keys, ...sync }) => ({
    ...sync,
    project: project.slug,
    environment: environment.slug,
    projectArchivedAt: project.archivedAt,
    environmentArchivedAt: environment.archivedAt,
    credential: {
      projectId: credential.projectId,
      environmentId: credential.environmentId,
      project: credential.project.slug,
      environment: credential.environment.slug,
      key: credential.key,
    },
    recorded: keys.map((key) => ({ key: key.key, versionId: key.secretVersionId })),
  }));
}

// --- the audit log ------------------------------------------------------------

/**
 * The chain head and the database clock, in one statement. Locked, it is
 * where every appender queues, which is what keeps the chain a chain. The
 * clock is the database's, not an application server's, so entries from
 * several servers still order by time (CDR 2024/1774 Art 12(2)(f)).
 */
export async function auditHead(
  db: Queryable,
  { lock: locking = false } = {},
): Promise<{ nextSeq: bigint; headHash: Buffer; now: string } | null> {
  const { auditChainHead } = tablesOf(db);
  const query = db
    .select({ nextSeq: auditChainHead.nextSeq, headHash: auditChainHead.headHash, now: clock(db) })
    .from(auditChainHead)
    .limit(1);
  const [head] = locking ? await forUpdate(db, query) : await query;
  return head === undefined ? null : { ...head, now: canonicalTimestamp(head.now) };
}

const auditColumns = (auditLog: Tables['auditLog']) => ({
  seq: auditLog.seq,
  occurredAt: auditLog.occurredAt,
  actorType: auditLog.actorType,
  actorId: auditLog.actorId,
  action: auditLog.action,
  decision: auditLog.decision,
  projectId: auditLog.projectId,
  environmentId: auditLog.environmentId,
  secretId: auditLog.secretId,
  bundleId: auditLog.bundleId,
  requestId: auditLog.requestId,
  sourceIp: auditLog.sourceIp,
  metadata: auditLog.metadata,
});

/** Rows in chain order from `fromSeq`, with every field as it was hashed. */
export async function auditRange(db: Queryable, fromSeq = 0n, limit = 1000) {
  const { auditLog } = tablesOf(db);
  const rows = await db
    .select({ ...auditColumns(auditLog), prevHash: auditLog.prevHash, hash: auditLog.hash })
    .from(auditLog)
    .where(gte(auditLog.seq, fromSeq))
    .orderBy(asc(auditLog.seq))
    .limit(limit);
  return rows.map((row) => ({ ...row, occurredAt: canonicalTimestamp(row.occurredAt) }));
}

export type AuditFilter = {
  /** Entries in any of these projects or environments, for a caller who reads only those. */
  within?: { projectIds: string[]; environmentIds: string[] };
  projectId?: string;
  environmentId?: string;
  secretId?: string;
  actorType?: string;
  actorId?: string;
  decision?: string;
  /** Entries older than this, for paging backwards. */
  beforeSeq?: bigint;
  limit: number;
};

/** A page of the log, newest first, with the slugs of the places each entry names. */
export async function auditPage(db: Queryable, filter: AuditFilter) {
  const { auditLog, projects, environments } = tablesOf(db);
  const { within } = filter;
  const rows = await db
    .select({ ...auditColumns(auditLog), project: projects.slug, environment: environments.slug })
    .from(auditLog)
    .leftJoin(projects, eq(projects.id, auditLog.projectId))
    .leftJoin(environments, eq(environments.id, auditLog.environmentId))
    .where(
      and(
        within === undefined
          ? undefined
          : or(inArray(auditLog.projectId, within.projectIds), inArray(auditLog.environmentId, within.environmentIds)),
        filter.projectId === undefined ? undefined : eq(auditLog.projectId, filter.projectId),
        filter.environmentId === undefined ? undefined : eq(auditLog.environmentId, filter.environmentId),
        filter.secretId === undefined ? undefined : eq(auditLog.secretId, filter.secretId),
        filter.actorType === undefined ? undefined : eq(auditLog.actorType, filter.actorType),
        filter.actorId === undefined ? undefined : eq(auditLog.actorId, filter.actorId),
        filter.decision === undefined ? undefined : eq(auditLog.decision, filter.decision),
        filter.beforeSeq === undefined ? undefined : lt(auditLog.seq, filter.beforeSeq),
      ),
    )
    .orderBy(desc(auditLog.seq))
    .limit(filter.limit);
  return rows.map((row) => ({ ...row, occurredAt: canonicalTimestamp(row.occurredAt) }));
}

/** When the scheduler last wrote to the log, and the database clock now. */
export async function heartbeat(db: Queryable): Promise<{ lastBeatAt: Date; now: string } | null> {
  const { auditHeartbeat } = tablesOf(db);
  const [row] = await db
    .select({ lastBeatAt: auditHeartbeat.lastBeatAt, now: clock(db) })
    .from(auditHeartbeat);
  return row === undefined ? null : { lastBeatAt: row.lastBeatAt, now: canonicalTimestamp(row.now) };
}

/** How many migrations the database has applied. */
export async function appliedMigrations(db: Queryable): Promise<number> {
  const [applied] = await db.select({ n: count() }).from(migrationLedger(db));
  return applied?.n ?? 0;
}
