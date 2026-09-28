import { sql } from 'drizzle-orm';
import {
  bigint,
  boolean,
  check,
  customType,
  datetime,
  foreignKey,
  index,
  int,
  mysqlTable,
  primaryKey,
  text,
  unique,
  uniqueIndex,
  varchar,
  type AnyMySqlColumn,
} from 'drizzle-orm/mysql-core';

import { canonicalTimestamp } from './dialect.ts';
import { asPostgres } from './portable.ts';
import { ACTIVE_SUBJECT, relationsOf } from './relations.ts';

/**
 * The schema in schema.ts, for MySQL 8.4. Same tables, columns, keys and row
 * types (portable.ts checks); only the column types differ:
 *
 * - A string that is part of a key is a `varchar` sized to what the server
 *   accepts, since MySQL indexes no `text`. Ids are `varchar(36)`, with no
 *   default: the application makes every id.
 * - Bytes are `longblob` (a `blob` holds 64 KiB, less than a secret with its
 *   envelope), or `varbinary` for the fixed-size hashes that are keys.
 * - Times are `datetime` in UTC, which is what Drizzle reads and writes.
 * - Comparisons are case-sensitive: the baseline migration sets the database
 *   collation to `utf8mb4_bin`, so `API_KEY` and `api_key` are two secrets.
 */

const longblob = customType<{ data: Buffer }>({
  dataType: () => 'longblob',
});

const varbinary = customType<{ data: Buffer; config: { length: number } }>({
  dataType: (config) => `varbinary(${config!.length})`,
});

/** audit_log.occurred_at: kept to the microsecond, read as text. See canonicalTimestamp. */
const instant = customType<{ data: string; driverData: string }>({
  dataType: () => 'datetime(6)',
  toDriver: (value) => canonicalTimestamp(value).replace('T', ' ').slice(0, -1),
});

const time = (name: string) => datetime(name, { fsp: 3 });
const now = sql`(UTC_TIMESTAMP(3))`;
const createdAt = () => time('created_at').notNull().default(now);
const id = (name = 'id') => varchar(name, { length: 36 });
const slug = () => varchar('slug', { length: 63 });
const principalType = () => varchar('principal_type', { length: 16 });
/** An email address or a service name; the API accepts up to this. */
const principalId = () => varchar('principal_id', { length: 330 });

export const projects = mysqlTable(
  'projects',
  {
    id: id().primaryKey(),
    slug: slug().notNull(),
    name: text().notNull(),
    createdAt: createdAt(),
    archivedAt: time('archived_at'),
  },
  (table) => [
    unique('projects_slug_key').on(table.slug),
    check('projects_slug_check', sql`regexp_like(${table.slug}, '^[a-z0-9][a-z0-9-]{0,62}$', 'c')`),
  ],
);

export const environments = mysqlTable(
  'environments',
  {
    id: id().primaryKey(),
    projectId: id('project_id').notNull(),
    slug: slug().notNull(),
    name: text().notNull(),
    createdAt: createdAt(),
    archivedAt: time('archived_at'),
  },
  (table) => [
    unique('environments_project_id_slug_key').on(table.projectId, table.slug),
    unique('environments_project_scoped').on(table.id, table.projectId),
    check('environments_slug_check', sql`regexp_like(${table.slug}, '^[a-z0-9][a-z0-9-]{0,62}$', 'c')`),
    foreignKey({
      name: 'environments_project_id_fkey',
      columns: [table.projectId],
      foreignColumns: [projects.id],
    }).onDelete('restrict'),
  ],
);

export const secrets = mysqlTable(
  'secrets',
  {
    id: id().primaryKey(),
    projectId: id('project_id').notNull(),
    environmentId: id('environment_id').notNull(),
    key: varchar({ length: 128 }).notNull(),
    createdAt: createdAt(),
    updatedAt: time('updated_at').notNull().default(now),
    currentVersionId: id('current_version_id').references((): AnyMySqlColumn => secretVersions.id, {
      onDelete: 'no action',
    }),
    currentVersion: int('current_version').notNull().default(0),
    archivedAt: time('archived_at'),
  },
  (table) => [
    unique('secrets_project_id_environment_id_key_key').on(table.projectId, table.environmentId, table.key),
    check('secrets_key_check', sql`regexp_like(${table.key}, '^[A-Za-z_][A-Za-z0-9_]{0,127}$', 'c')`),
    foreignKey({
      name: 'secrets_project_id_fkey',
      columns: [table.projectId],
      foreignColumns: [projects.id],
    }).onDelete('restrict'),
    foreignKey({
      name: 'secrets_environment_id_fkey',
      columns: [table.environmentId],
      foreignColumns: [environments.id],
    }).onDelete('restrict'),
    foreignKey({
      name: 'secrets_environment_in_project',
      columns: [table.environmentId, table.projectId],
      foreignColumns: [environments.id, environments.projectId],
    }),
    index('secrets_lookup_idx').on(table.projectId, table.environmentId, table.key),
  ],
);

export const secretVersions = mysqlTable(
  'secret_versions',
  {
    id: id().primaryKey(),
    secretId: id('secret_id').notNull(),
    version: int().notNull(),
    envelopeVersion: int('envelope_version').notNull(),
    ciphertext: longblob().notNull(),
    iv: varbinary({ length: 12 }).notNull(),
    authTag: varbinary('auth_tag', { length: 16 }).notNull(),
    wrappedDek: longblob('wrapped_dek').notNull(),
    kekProvider: text('kek_provider').notNull(),
    kekId: text('kek_id').notNull(),
    kekVersion: text('kek_version').notNull(),
    createdAt: createdAt(),
    createdBy: text('created_by').notNull(),
  },
  (table) => [
    unique('secret_versions_secret_id_version_key').on(table.secretId, table.version),
    check('secret_versions_version_check', sql`${table.version} > 0`),
    check('secret_versions_iv_check', sql`octet_length(${table.iv}) = 12`),
    check('secret_versions_auth_tag_check', sql`octet_length(${table.authTag}) = 16`),
    foreignKey({
      name: 'secret_versions_secret_id_fkey',
      columns: [table.secretId],
      foreignColumns: [secrets.id],
    }).onDelete('restrict'),
    index('secret_versions_secret_idx').on(table.secretId, table.version),
  ],
);

export const principals = mysqlTable(
  'principals',
  {
    principalType: principalType().notNull(),
    principalId: principalId().notNull(),
    instanceRole: text('instance_role').notNull().default(sql`('user')`),
    createdAt: createdAt(),
    createdBy: text('created_by').notNull(),
    active: boolean().notNull().default(true),
  },
  (table) => [
    primaryKey({
      name: 'principals_pkey',
      columns: [table.principalType, table.principalId],
    }),
    check('principals_principal_type_check', sql`${table.principalType} IN ('user', 'service')`),
    check('principals_instance_role_check', sql`${table.instanceRole} IN ('user', 'owner')`),
    check(
      'principals_service_role_check',
      sql`${table.principalType} = 'user' OR ${table.instanceRole} = 'user'`,
    ),
    check(
      'principals_user_id_lowercase',
      sql`${table.principalType} <> 'user' OR ${table.principalId} = lower(${table.principalId})`,
    ),
  ],
);

export const grants = mysqlTable(
  'grants',
  {
    id: id().primaryKey(),
    principalType: principalType().notNull(),
    principalId: principalId().notNull(),
    environmentId: id('environment_id'),
    createdAt: createdAt(),
    createdBy: text('created_by').notNull(),
    projectId: id('project_id'),
    role: text().notNull(),
    expiresAt: time('expires_at'),
  },
  (table) => [
    check('grants_principal_type_check', sql`${table.principalType} IN ('user', 'service')`),
    check(
      'grants_exactly_one_scope',
      sql`(${table.projectId} IS NULL) <> (${table.environmentId} IS NULL)`,
    ),
    foreignKey({
      name: 'grants_principal_fkey',
      columns: [table.principalType, table.principalId],
      foreignColumns: [principals.principalType, principals.principalId],
    }).onDelete('restrict'),
    foreignKey({
      name: 'grants_environment_id_fkey',
      columns: [table.environmentId],
      foreignColumns: [environments.id],
    }).onDelete('restrict'),
    foreignKey({
      name: 'grants_project_id_fkey',
      columns: [table.projectId],
      foreignColumns: [projects.id],
    }).onDelete('restrict'),
    check(
      'grants_role_check',
      sql`${table.role} IN ('viewer', 'developer', 'maintainer', 'access-manager', 'auditor', 'owner')`,
    ),
    index('grants_lookup_idx').on(table.principalType, table.principalId, table.environmentId),
    uniqueIndex('grants_environment_unique').on(table.principalType, table.principalId, table.environmentId),
    uniqueIndex('grants_project_unique').on(table.principalType, table.principalId, table.projectId),
  ],
);

export const auditLog = mysqlTable(
  'audit_log',
  {
    seq: bigint({ mode: 'bigint' }).primaryKey(),
    id: id().notNull(),
    occurredAt: instant('occurred_at').notNull().default(sql`(UTC_TIMESTAMP(6))`),
    actorType: varchar('actor_type', { length: 16 }).notNull(),
    actorId: varchar('actor_id', { length: 330 }).notNull(),
    action: text().notNull(),
    decision: text().notNull(),
    projectId: id('project_id'),
    environmentId: id('environment_id'),
    secretId: id('secret_id'),
    bundleId: id('bundle_id'),
    requestId: text('request_id'),
    sourceIp: text('source_ip'),
    metadata: text().notNull().default(sql`('{}')`),
    prevHash: varbinary('prev_hash', { length: 32 }).notNull(),
    hash: varbinary({ length: 32 }).notNull(),
  },
  (table) => [
    unique('audit_log_id_key').on(table.id),
    check('audit_log_actor_type_check', sql`${table.actorType} IN ('user', 'service', 'system')`),
    check('audit_log_decision_check', sql`${table.decision} IN ('allow', 'deny')`),
    check('audit_log_metadata_check', sql`json_valid(${table.metadata})`),
    check('audit_log_prev_hash_check', sql`octet_length(${table.prevHash}) = 32`),
    check('audit_log_hash_check', sql`octet_length(${table.hash}) = 32`),
    foreignKey({
      name: 'audit_log_project_id_fkey',
      columns: [table.projectId],
      foreignColumns: [projects.id],
    }).onDelete('restrict'),
    foreignKey({
      name: 'audit_log_environment_id_fkey',
      columns: [table.environmentId],
      foreignColumns: [environments.id],
    }).onDelete('restrict'),
    foreignKey({
      name: 'audit_log_secret_id_fkey',
      columns: [table.secretId],
      foreignColumns: [secrets.id],
    }).onDelete('restrict'),
    index('audit_log_occurred_idx').on(table.occurredAt),
    index('audit_log_actor_idx').on(table.actorType, table.actorId, table.occurredAt),
    index('audit_log_secret_idx').on(table.secretId, table.occurredAt),
    index('audit_log_environment_idx').on(table.environmentId, table.occurredAt),
    index('audit_log_bundle_idx').on(table.bundleId),
  ],
);

export const auditChainHead = mysqlTable(
  'audit_chain_head',
  {
    onlyRow: boolean('only_row').primaryKey().default(true),
    nextSeq: bigint('next_seq', { mode: 'bigint' }).notNull().default(sql`0`),
    headHash: varbinary('head_hash', { length: 32 }).notNull(),
    updatedAt: time('updated_at').notNull().default(now),
  },
  (table) => [
    check('audit_chain_head_only_row_check', sql`${table.onlyRow} = true`),
    check('audit_chain_head_head_hash_check', sql`octet_length(${table.headHash}) = 32`),
  ],
);

export const auditCheckpoints = mysqlTable(
  'audit_checkpoints',
  {
    id: id().primaryKey(),
    seq: bigint({ mode: 'bigint' }).notNull(),
    headHash: varbinary('head_hash', { length: 32 }).notNull(),
    createdAt: createdAt(),
    exportedAt: time('exported_at'),
    exportTarget: text('export_target'),
  },
  (table) => [
    check('audit_checkpoints_head_hash_check', sql`octet_length(${table.headHash}) = 32`),
  ],
);

export const auditHeartbeat = mysqlTable(
  'audit_heartbeat',
  {
    onlyRow: boolean('only_row').primaryKey().default(true),
    lastBeatAt: time('last_beat_at').notNull().default(now),
    lastSeq: bigint('last_seq', { mode: 'bigint' }).notNull().default(sql`0`),
  },
  (table) => [check('audit_heartbeat_only_row_check', sql`${table.onlyRow} = true`)],
);

export const identities = mysqlTable(
  'identities',
  {
    id: id().primaryKey(),
    provider: varchar({ length: 32 }).notNull(),
    subject: varchar({ length: 255 }).notNull(),
    principalType: principalType().notNull(),
    principalId: principalId().notNull(),
    email: text(),
    createdAt: createdAt(),
    createdBy: text('created_by').notNull(),
    lastSignInAt: time('last_sign_in_at'),
    revokedAt: time('revoked_at'),
    revokedBy: text('revoked_by'),
    activeSubject: varchar('active_subject', { length: 255 }).generatedAlwaysAs(ACTIVE_SUBJECT, { mode: 'stored' }),
  },
  (table) => [
    check('identities_principal_type_check', sql`${table.principalType} = 'user'`),
    check('identities_provider_check', sql`regexp_like(${table.provider}, '^[a-z0-9][a-z0-9-]{0,31}$', 'c')`),
    foreignKey({
      name: 'identities_principal_fkey',
      columns: [table.principalType, table.principalId],
      foreignColumns: [principals.principalType, principals.principalId],
    }).onDelete('restrict'),
    uniqueIndex('identities_active_subject').on(table.provider, table.activeSubject),
    index('identities_principal_idx').on(table.principalType, table.principalId),
  ],
);

export const credentials = mysqlTable(
  'credentials',
  {
    id: id().primaryKey(),
    kind: text().notNull(),
    tokenHash: varbinary('token_hash', { length: 32 }).notNull(),
    tokenHint: text('token_hint').notNull(),
    principalType: principalType().notNull(),
    principalId: principalId().notNull(),
    identityId: id('identity_id'),
    label: text(),
    createdAt: createdAt(),
    createdBy: text('created_by').notNull(),
    expiresAt: time('expires_at').notNull(),
    lastUsedAt: time('last_used_at'),
    lastUsedIp: text('last_used_ip'),
    revokedAt: time('revoked_at'),
    revokedBy: text('revoked_by'),
  },
  (table) => [
    unique('credentials_token_hash_key').on(table.tokenHash),
    check('credentials_kind_check', sql`${table.kind} IN ('browser', 'cli', 'service')`),
    check(
      'credentials_kind_matches_principal',
      sql`(${table.kind} = 'service') = (${table.principalType} = 'service')`,
    ),
    check('credentials_token_hash_check', sql`octet_length(${table.tokenHash}) = 32`),
    foreignKey({
      name: 'credentials_principal_fkey',
      columns: [table.principalType, table.principalId],
      foreignColumns: [principals.principalType, principals.principalId],
    }).onDelete('restrict'),
    foreignKey({
      name: 'credentials_identity_id_fkey',
      columns: [table.identityId],
      foreignColumns: [identities.id],
    }).onDelete('restrict'),
    index('credentials_principal_idx').on(table.principalType, table.principalId),
  ],
);

export const deviceAuthorizations = mysqlTable(
  'device_authorizations',
  {
    id: id().primaryKey(),
    deviceCodeHash: varbinary('device_code_hash', { length: 32 }).notNull(),
    userCode: varchar('user_code', { length: 32 }).notNull(),
    clientLabel: text('client_label'),
    clientIp: text('client_ip'),
    createdAt: createdAt(),
    expiresAt: time('expires_at').notNull(),
    decidedAt: time('decided_at'),
    decision: text(),
    principalType: principalType(),
    principalId: principalId(),
    consumedAt: time('consumed_at'),
  },
  (table) => [
    unique('device_authorizations_device_code_hash_key').on(table.deviceCodeHash),
    unique('device_authorizations_user_code_key').on(table.userCode),
    check(
      'device_authorizations_decision_check',
      sql`${table.decision} IS NULL OR ${table.decision} IN ('approved', 'denied')`,
    ),
    check(
      'device_authorizations_approval_names_principal',
      sql`(${table.decision} = 'approved') = (${table.principalId} IS NOT NULL)`,
    ),
    foreignKey({
      name: 'device_authorizations_principal_fkey',
      columns: [table.principalType, table.principalId],
      foreignColumns: [principals.principalType, principals.principalId],
    }).onDelete('restrict'),
  ],
);

export const syncs = mysqlTable(
  'syncs',
  {
    id: id().primaryKey(),
    projectId: id('project_id').notNull(),
    environmentId: id('environment_id').notNull(),
    provider: text().notNull(),
    config: text().notNull(),
    credentialSecretId: id('credential_secret_id').notNull(),
    createdAt: createdAt(),
    createdBy: text('created_by').notNull(),
    pausedAt: time('paused_at'),
    archivedAt: time('archived_at'),
    leaseUntil: time('lease_until'),
    lastRunAt: time('last_run_at'),
    lastStatus: text('last_status'),
    lastError: text('last_error'),
  },
  (table) => [
    check('syncs_config_check', sql`json_valid(${table.config})`),
    check(
      'syncs_last_status_check',
      sql`${table.lastStatus} IS NULL OR ${table.lastStatus} IN ('ok', 'partial', 'failed')`,
    ),
    foreignKey({
      name: 'syncs_environment_in_project',
      columns: [table.environmentId, table.projectId],
      foreignColumns: [environments.id, environments.projectId],
    }).onDelete('restrict'),
    foreignKey({
      name: 'syncs_credential_secret_id_fkey',
      columns: [table.credentialSecretId],
      foreignColumns: [secrets.id],
    }).onDelete('restrict'),
    index('syncs_environment_idx').on(table.environmentId),
  ],
);

export const syncKeys = mysqlTable(
  'sync_keys',
  {
    syncId: id('sync_id').notNull(),
    key: varchar({ length: 128 }).notNull(),
    secretVersionId: id('secret_version_id'),
    pushedAt: time('pushed_at').notNull().default(now),
    removedAt: time('removed_at'),
  },
  (table) => [
    primaryKey({ name: 'sync_keys_pkey', columns: [table.syncId, table.key] }),
    foreignKey({
      name: 'sync_keys_sync_id_fkey',
      columns: [table.syncId],
      foreignColumns: [syncs.id],
    }).onDelete('restrict'),
    foreignKey({
      name: 'sync_keys_secret_version_id_fkey',
      columns: [table.secretVersionId],
      foreignColumns: [secretVersions.id],
    }).onDelete('restrict'),
  ],
);

export const {
  principalsRelations,
  grantsRelations,
  credentialsRelations,
  identitiesRelations,
  environmentsRelations,
  secretsRelations,
  syncsRelations,
  syncKeysRelations,
} = relationsOf(
  asPostgres({ projects, environments, secrets, secretVersions, principals, grants, identities, credentials, syncs, syncKeys }),
);
