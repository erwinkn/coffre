import { and, asc, count, desc, eq, getTableColumns, gt, gte, inArray, isNull, lt, or, sql, type SQL } from 'drizzle-orm';

import type { Envelope } from '../../core/src/envelope.ts';
import type { Queryable, Transaction } from './database.ts';
import {
  canonicalTimestamp,
  changedRows,
  forUpdate,
  ignoreConflicts,
  migrations,
  onConflictUpdate,
  type Table,
} from './dialect.ts';
import {
  auditChainHead,
  auditHeartbeat,
  auditLog,
  credentials,
  deviceAuthorizations,
  environments,
  grants,
  identities,
  principals,
  projects,
  secrets,
  secretVersions,
  syncs,
} from './schema.ts';

/**
 * Every query coffre runs, and nowhere else: named reads, each returning all
 * that its callers need in one statement, four generic writes, and a lock.
 * The server works on what these return and never writes SQL; lint keeps
 * drizzle out of apps/web.
 *
 * Writes do not check first and do not read back. A unique constraint
 * answers "is it taken", and a conditional update's row count answers "was
 * it still there"; the response is built from what was written.
 */

// --- generic writes -----------------------------------------------------------

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
  await db.insert(table).values(rows as never);
}

/** Insert the rows whose unique keys are free; returns how many that was. */
export async function insertIfAbsent<T extends Table>(
  db: Queryable,
  table: T,
  rows: NewRow<T> | NewRow<T>[],
): Promise<number> {
  if (Array.isArray(rows) && rows.length === 0) return 0;
  return changedRows(await ignoreConflicts(db.insert(table).values(rows as never)));
}

/** Insert the rows, or where one repeats the unique key `target`, overwrite its `columns`. */
export async function upsert<T extends Table>(
  db: Queryable,
  table: T,
  rows: NewRow<T>[],
  { target, columns }: { target: (keyof Row<T>)[]; columns: (keyof Row<T>)[] },
): Promise<void> {
  if (rows.length === 0) return;
  await onConflictUpdate(db.insert(table).values(rows as never), table, target, columns);
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
  return changedRows(await db.update(table).set(set as never).where(matching(table, match)));
}

/**
 * Lock the matching rows until the transaction ends, and read them as they
 * are once the lock is ours. Only for real races; each caller says which.
 */
export async function lock<T extends Table>(tx: Transaction, table: T, match: Match<T>): Promise<Row<T>[]> {
  return (await forUpdate(tx.select().from(table as Table).where(matching(table, match)))) as Row<T>[];
}

// --- the caller and places ----------------------------------------------------

export type HeldGrant = {
  id: string;
  /** The project the grant is in, also for a grant on one of its environments. */
  projectId: string;
  /** Null for a grant on the whole project. */
  environmentId: string | null;
  role: string;
  expiresAt: Date | null;
};

/** A principal's standing and live grants, or null when there is no such principal. */
export async function callerGrants(
  db: Queryable,
  principal: { type: string; id: string },
  now: Date,
): Promise<{ active: boolean; instanceRole: string; grants: HeldGrant[] } | null> {
  const rows = await db
    .select({
      active: principals.active,
      instanceRole: principals.instanceRole,
      id: grants.id,
      grantProjectId: grants.projectId,
      environmentId: grants.environmentId,
      environmentProjectId: environments.projectId,
      role: grants.role,
      expiresAt: grants.expiresAt,
    })
    .from(principals)
    .leftJoin(
      grants,
      and(
        eq(grants.principalType, principals.principalType),
        eq(grants.principalId, principals.principalId),
        or(isNull(grants.expiresAt), gt(grants.expiresAt, now)),
      ),
    )
    .leftJoin(environments, eq(environments.id, grants.environmentId))
    .where(and(eq(principals.principalType, principal.type), eq(principals.principalId, principal.id)));
  if (rows.length === 0) return null;
  const held: HeldGrant[] = [];
  for (const row of rows) {
    const projectId = row.grantProjectId ?? row.environmentProjectId;
    if (row.id === null || projectId === null) continue;
    held.push({ id: row.id, projectId, environmentId: row.environmentId, role: row.role!, expiresAt: row.expiresAt });
  }
  return { active: rows[0].active, instanceRole: rows[0].instanceRole, grants: held };
}

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
  instanceRole: string;
  active: boolean;
  createdAt: Date;
  /** Every grant, expired ones included: revoking expires a grant, and granting again reuses it. */
  grants: {
    id: string;
    projectId: string;
    project: string;
    /** Null for a grant on the whole project. */
    environmentId: string | null;
    environment: string | null;
    role: string;
    expiresAt: Date | null;
  }[];
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
 * Principals with everything they hold: one of them, or everyone, by type
 * and id. The member list, offboarding, access changes and the account page
 * all read this.
 */
export async function members(
  db: Queryable,
  filter: { member?: { type: string; id: string } },
  now: Date,
): Promise<MemberRow[]> {
  const { member } = filter;
  const rows = await db.query.principals.findMany({
    where: member === undefined ? undefined : and(eq(principals.principalType, member.type), eq(principals.principalId, member.id)),
    orderBy: [asc(principals.principalType), asc(principals.principalId)],
    with: {
      grants: {
        with: {
          project: { columns: { slug: true } },
          environment: { columns: { slug: true, projectId: true }, with: { project: { columns: { slug: true } } } },
        },
      },
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
    instanceRole: row.instanceRole,
    active: row.active,
    createdAt: row.createdAt,
    grants: row.grants.map((grant) => ({
      id: grant.id,
      projectId: grant.projectId ?? grant.environment!.projectId,
      project: grant.project?.slug ?? grant.environment!.project.slug,
      environmentId: grant.environmentId,
      environment: grant.environment?.slug ?? null,
      role: grant.role,
      expiresAt: grant.expiresAt,
    })),
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
      archived: sql<boolean>`${secrets.archivedAt} IS NOT NULL OR ${environments.archivedAt} IS NOT NULL OR ${projects.archivedAt} IS NOT NULL`,
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
  const [row] = await db
    .select({ id: identities.id, principalId: identities.principalId })
    .from(identities)
    .where(
      and(eq(identities.provider, account.provider), eq(identities.subject, account.subject), isNull(identities.revokedAt)),
    );
  return row ?? null;
}

/**
 * A credential by its token's hash or by id, with whether its principal is
 * active and its sign-in account still bound. Revoked and expired ones too:
 * the caller decides what is live.
 */
export async function findCredential(db: Queryable, by: { tokenHash: Buffer } | { id: string }) {
  const [row] = await db
    .select({
      id: credentials.id,
      kind: credentials.kind,
      principalType: credentials.principalType,
      principalId: credentials.principalId,
      expiresAt: credentials.expiresAt,
      revokedAt: credentials.revokedAt,
      lastUsedAt: credentials.lastUsedAt,
      active: principals.active,
      identityRevokedAt: identities.revokedAt,
      subject: identities.subject,
    })
    .from(credentials)
    .innerJoin(
      principals,
      and(eq(principals.principalType, credentials.principalType), eq(principals.principalId, credentials.principalId)),
    )
    .leftJoin(identities, eq(identities.id, credentials.identityId))
    .where('tokenHash' in by ? eq(credentials.tokenHash, by.tokenHash) : eq(credentials.id, by.id));
  return row ?? null;
}

/** Device authorizations: one by either of its codes, or every one still waiting for a decision. */
export async function findDeviceAuthorizations(
  db: Queryable,
  by: { userCode: string } | { deviceCodeHash: Buffer } | { openAt: Date },
) {
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

const envelopeColumns = {
  envelopeVersion: secretVersions.envelopeVersion,
  kekProvider: secretVersions.kekProvider,
  kekId: secretVersions.kekId,
  kekVersion: secretVersions.kekVersion,
  wrappedDek: secretVersions.wrappedDek,
  iv: secretVersions.iv,
  authTag: secretVersions.authTag,
  ciphertext: secretVersions.ciphertext,
};

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
  const rows = await db
    .select({
      id: secrets.id,
      key: secrets.key,
      archivedAt: secrets.archivedAt,
      versionId: secretVersions.id,
      version: secretVersions.version,
      createdAt: secretVersions.createdAt,
      createdBy: secretVersions.createdBy,
      ...envelopeColumns,
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
  const rows = await db
    .select({
      id: secretVersions.id,
      version: secretVersions.version,
      createdAt: secretVersions.createdAt,
      createdBy: secretVersions.createdBy,
      ...envelopeColumns,
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

export type SyncRow = typeof syncs.$inferSelect & {
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
  const query = db
    .select({ nextSeq: auditChainHead.nextSeq, headHash: auditChainHead.headHash, now: sql<string>`CURRENT_TIMESTAMP` })
    .from(auditChainHead)
    .limit(1);
  const [head] = locking ? await forUpdate(query) : await query;
  return head === undefined ? null : { ...head, now: canonicalTimestamp(head.now) };
}

const auditColumns = {
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
};

/** Rows in chain order from `fromSeq`, with every field as it was hashed. */
export async function auditRange(db: Queryable, fromSeq = 0n, limit = 1000) {
  const rows = await db
    .select({ ...auditColumns, prevHash: auditLog.prevHash, hash: auditLog.hash })
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
  const { within } = filter;
  const rows = await db
    .select({ ...auditColumns, project: projects.slug, environment: environments.slug })
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
  const [row] = await db
    .select({ lastBeatAt: auditHeartbeat.lastBeatAt, now: sql<string>`CURRENT_TIMESTAMP` })
    .from(auditHeartbeat);
  return row === undefined ? null : { lastBeatAt: row.lastBeatAt, now: canonicalTimestamp(row.now) };
}

/** How many migrations the database has applied. */
export async function appliedMigrations(db: Queryable): Promise<number> {
  const [applied] = await db.select({ n: count() }).from(migrations);
  return applied?.n ?? 0;
}
