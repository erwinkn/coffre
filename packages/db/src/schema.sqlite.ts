import { sql } from 'drizzle-orm';
import {
  blob,
  check,
  customType,
  foreignKey,
  index,
  integer,
  primaryKey,
  sqliteTable,
  text,
  unique,
  uniqueIndex,
  type AnySQLiteColumn,
} from 'drizzle-orm/sqlite-core';

import { asPostgres } from './portable.ts';
import { ACTIVE_SUBJECT, relationsOf } from './relations.ts';

/**
 * The schema in schema.ts, for SQLite (through libsql). Same tables,
 * columns, keys and row types (portable.ts checks); only the storage
 * differs:
 *
 * - Ids and strings are `text`, with no default for ids: the application
 *   makes every id.
 * - Bytes are `blob`.
 * - Times are integer milliseconds since the epoch, except
 *   audit_log.occurred_at, which is the canonical text of canonicalTimestamp
 *   and so sorts in time order.
 * - Patterns are checked with GLOB, which is case-sensitive and needs no
 *   extension, rather than a regular expression.
 */

const bytes = (name: string) => blob(name, { mode: 'buffer' });

/** A 64-bit integer read as a bigint, like Postgres's bigint in 'bigint' mode. */
const int64 = customType<{ data: bigint; driverData: number | bigint }>({
  dataType: () => 'integer',
  fromDriver: (value) => BigInt(value),
});

const time = (name: string) => integer(name, { mode: 'timestamp_ms' });
const now = sql`(CAST(unixepoch('subsec') * 1000 AS INTEGER))`;
const createdAt = () => time('created_at').notNull().default(now);
const flag = (name: string) => integer(name, { mode: 'boolean' });

/** `^[a-z0-9][a-z0-9-]{0,max-1}$`, in GLOB. */
const isSlug = (column: AnySQLiteColumn, max: number) =>
  sql`length(${column}) BETWEEN 1 AND ${sql.raw(String(max))} AND ${column} GLOB '[a-z0-9]*' AND ${column} NOT GLOB '*[^a-z0-9-]*'`;

export const projects = sqliteTable(
  'projects',
  {
    id: text().primaryKey(),
    slug: text().notNull(),
    name: text().notNull(),
    createdAt: createdAt(),
    archivedAt: time('archived_at'),
  },
  (table) => [
    unique('projects_slug_key').on(table.slug),
    check('projects_slug_check', isSlug(table.slug, 63)),
  ],
);

export const environments = sqliteTable(
  'environments',
  {
    id: text().primaryKey(),
    projectId: text('project_id').notNull(),
    slug: text().notNull(),
    name: text().notNull(),
    createdAt: createdAt(),
    archivedAt: time('archived_at'),
  },
  (table) => [
    unique('environments_project_id_slug_key').on(table.projectId, table.slug),
    unique('environments_project_scoped').on(table.id, table.projectId),
    check('environments_slug_check', isSlug(table.slug, 63)),
    foreignKey({
      name: 'environments_project_id_fkey',
      columns: [table.projectId],
      foreignColumns: [projects.id],
    }).onDelete('restrict'),
  ],
);

export const secrets = sqliteTable(
  'secrets',
  {
    id: text().primaryKey(),
    projectId: text('project_id').notNull(),
    environmentId: text('environment_id').notNull(),
    key: text().notNull(),
    createdAt: createdAt(),
    updatedAt: time('updated_at').notNull().default(now),
    currentVersionId: text('current_version_id').references((): AnySQLiteColumn => secretVersions.id, {
      onDelete: 'no action',
    }),
    currentVersion: integer('current_version').notNull().default(0),
    archivedAt: time('archived_at'),
  },
  (table) => [
    unique('secrets_project_id_environment_id_key_key').on(table.projectId, table.environmentId, table.key),
    check(
      'secrets_key_check',
      sql`length(${table.key}) BETWEEN 1 AND 128 AND ${table.key} GLOB '[A-Za-z_]*' AND ${table.key} NOT GLOB '*[^A-Za-z0-9_]*'`,
    ),
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

export const secretVersions = sqliteTable(
  'secret_versions',
  {
    id: text().primaryKey(),
    secretId: text('secret_id').notNull(),
    version: integer().notNull(),
    envelopeVersion: integer('envelope_version').notNull(),
    ciphertext: bytes('ciphertext').notNull(),
    iv: bytes('iv').notNull(),
    authTag: bytes('auth_tag').notNull(),
    wrappedDek: bytes('wrapped_dek').notNull(),
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

export const principals = sqliteTable(
  'principals',
  {
    principalType: text('principal_type').notNull(),
    principalId: text('principal_id').notNull(),
    instanceRole: text('instance_role').notNull().default('user'),
    createdAt: createdAt(),
    createdBy: text('created_by').notNull(),
    active: flag('active').notNull().default(true),
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
    // SQLite's lower() folds ASCII only; the server lowercases every email
    // with toLowerCase() before it gets here.
    check(
      'principals_user_id_lowercase',
      sql`${table.principalType} <> 'user' OR ${table.principalId} = lower(${table.principalId})`,
    ),
  ],
);

export const grants = sqliteTable(
  'grants',
  {
    id: text().primaryKey(),
    principalType: text('principal_type').notNull(),
    principalId: text('principal_id').notNull(),
    environmentId: text('environment_id'),
    createdAt: createdAt(),
    createdBy: text('created_by').notNull(),
    projectId: text('project_id'),
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

export const auditLog = sqliteTable(
  'audit_log',
  {
    seq: int64('seq').primaryKey(),
    id: text().notNull(),
    occurredAt: text('occurred_at').notNull().default(sql`(strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))`),
    actorType: text('actor_type').notNull(),
    actorId: text('actor_id').notNull(),
    action: text().notNull(),
    decision: text().notNull(),
    projectId: text('project_id'),
    environmentId: text('environment_id'),
    secretId: text('secret_id'),
    bundleId: text('bundle_id'),
    requestId: text('request_id'),
    sourceIp: text('source_ip'),
    metadata: text().notNull().default('{}'),
    prevHash: bytes('prev_hash').notNull(),
    hash: bytes('hash').notNull(),
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

export const auditChainHead = sqliteTable(
  'audit_chain_head',
  {
    onlyRow: flag('only_row').primaryKey().default(true),
    nextSeq: int64('next_seq').notNull().default(sql`0`),
    headHash: bytes('head_hash').notNull(),
    updatedAt: time('updated_at').notNull().default(now),
  },
  (table) => [
    check('audit_chain_head_only_row_check', sql`${table.onlyRow}`),
    check('audit_chain_head_head_hash_check', sql`octet_length(${table.headHash}) = 32`),
  ],
);

export const auditCheckpoints = sqliteTable(
  'audit_checkpoints',
  {
    id: text().primaryKey(),
    seq: int64('seq').notNull(),
    headHash: bytes('head_hash').notNull(),
    createdAt: createdAt(),
    exportedAt: time('exported_at'),
    exportTarget: text('export_target'),
  },
  (table) => [
    check('audit_checkpoints_head_hash_check', sql`octet_length(${table.headHash}) = 32`),
  ],
);

export const auditHeartbeat = sqliteTable(
  'audit_heartbeat',
  {
    onlyRow: flag('only_row').primaryKey().default(true),
    lastBeatAt: time('last_beat_at').notNull().default(now),
    lastSeq: int64('last_seq').notNull().default(sql`0`),
  },
  (table) => [check('audit_heartbeat_only_row_check', sql`${table.onlyRow}`)],
);

export const identities = sqliteTable(
  'identities',
  {
    id: text().primaryKey(),
    provider: text().notNull(),
    subject: text().notNull(),
    principalType: text('principal_type').notNull(),
    principalId: text('principal_id').notNull(),
    email: text(),
    createdAt: createdAt(),
    createdBy: text('created_by').notNull(),
    lastSignInAt: time('last_sign_in_at'),
    revokedAt: time('revoked_at'),
    revokedBy: text('revoked_by'),
    activeSubject: text('active_subject').generatedAlwaysAs(ACTIVE_SUBJECT, { mode: 'stored' }),
  },
  (table) => [
    check('identities_principal_type_check', sql`${table.principalType} = 'user'`),
    check('identities_provider_check', isSlug(table.provider, 32)),
    foreignKey({
      name: 'identities_principal_fkey',
      columns: [table.principalType, table.principalId],
      foreignColumns: [principals.principalType, principals.principalId],
    }).onDelete('restrict'),
    uniqueIndex('identities_active_subject').on(table.provider, table.activeSubject),
    index('identities_principal_idx').on(table.principalType, table.principalId),
  ],
);

export const credentials = sqliteTable(
  'credentials',
  {
    id: text().primaryKey(),
    kind: text().notNull(),
    tokenHash: bytes('token_hash').notNull(),
    tokenHint: text('token_hint').notNull(),
    principalType: text('principal_type').notNull(),
    principalId: text('principal_id').notNull(),
    identityId: text('identity_id'),
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

export const deviceAuthorizations = sqliteTable(
  'device_authorizations',
  {
    id: text().primaryKey(),
    deviceCodeHash: bytes('device_code_hash').notNull(),
    userCode: text('user_code').notNull(),
    clientLabel: text('client_label'),
    clientIp: text('client_ip'),
    createdAt: createdAt(),
    expiresAt: time('expires_at').notNull(),
    decidedAt: time('decided_at'),
    decision: text(),
    principalType: text('principal_type'),
    principalId: text('principal_id'),
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

export const syncs = sqliteTable(
  'syncs',
  {
    id: text().primaryKey(),
    projectId: text('project_id').notNull(),
    environmentId: text('environment_id').notNull(),
    provider: text().notNull(),
    config: text().notNull(),
    credentialSecretId: text('credential_secret_id').notNull(),
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

export const syncKeys = sqliteTable(
  'sync_keys',
  {
    syncId: text('sync_id').notNull(),
    key: text().notNull(),
    secretVersionId: text('secret_version_id'),
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
