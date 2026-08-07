import { sql } from 'drizzle-orm';
import {
  bigint,
  boolean,
  check,
  customType,
  foreignKey,
  index,
  integer,
  pgTable,
  primaryKey,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
  type AnyPgColumn,
} from 'drizzle-orm/pg-core';

const bytea = customType<{ data: Buffer }>({
  dataType: () => 'bytea',
});

const createdAt = () => timestamp('created_at', { withTimezone: true }).notNull().defaultNow();

export const projects = pgTable(
  'projects',
  {
    id: uuid().primaryKey().defaultRandom(),
    slug: text().notNull(),
    name: text().notNull(),
    createdAt: createdAt(),
    archivedAt: timestamp('archived_at', { withTimezone: true }),
  },
  (table) => [
    unique('projects_slug_key').on(table.slug),
    check('projects_slug_check', sql`${table.slug} ~ '^[a-z0-9][a-z0-9-]{0,62}$'`),
    index('projects_active_idx').on(table.slug).where(sql`${table.archivedAt} IS NULL`),
  ],
);

export const environments = pgTable(
  'environments',
  {
    id: uuid().primaryKey().defaultRandom(),
    projectId: uuid('project_id').notNull(),
    slug: text().notNull(),
    name: text().notNull(),
    createdAt: createdAt(),
    archivedAt: timestamp('archived_at', { withTimezone: true }),
  },
  (table) => [
    unique('environments_project_id_slug_key').on(table.projectId, table.slug),
    unique('environments_project_scoped').on(table.id, table.projectId),
    check('environments_slug_check', sql`${table.slug} ~ '^[a-z0-9][a-z0-9-]{0,62}$'`),
    foreignKey({
      name: 'environments_project_id_fkey',
      columns: [table.projectId],
      foreignColumns: [projects.id],
    }).onDelete('restrict'),
    index('environments_active_idx')
      .on(table.projectId, table.slug)
      .where(sql`${table.archivedAt} IS NULL`),
  ],
);

export const secrets = pgTable(
  'secrets',
  {
    id: uuid().primaryKey().defaultRandom(),
    projectId: uuid('project_id').notNull(),
    environmentId: uuid('environment_id').notNull(),
    key: text().notNull(),
    createdAt: createdAt(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
    currentVersionId: uuid('current_version_id').references(
      (): AnyPgColumn => secretVersions.id,
      { onDelete: 'no action' },
    ),
    archivedAt: timestamp('archived_at', { withTimezone: true }),
  },
  (table) => [
    unique('secrets_project_id_environment_id_key_key').on(
      table.projectId,
      table.environmentId,
      table.key,
    ),
    check('secrets_key_check', sql`${table.key} ~ '^[A-Za-z_][A-Za-z0-9_]{0,127}$'`),
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
    index('secrets_active_idx')
      .on(table.projectId, table.environmentId, table.key)
      .where(sql`${table.archivedAt} IS NULL`),
  ],
);

export const secretVersions = pgTable(
  'secret_versions',
  {
    id: uuid().primaryKey().defaultRandom(),
    secretId: uuid('secret_id').notNull(),
    version: integer().notNull(),
    envelopeVersion: integer('envelope_version').notNull(),
    ciphertext: bytea().notNull(),
    iv: bytea().notNull(),
    authTag: bytea('auth_tag').notNull(),
    wrappedDek: bytea('wrapped_dek').notNull(),
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
    index('secret_versions_secret_idx').on(table.secretId, table.version.desc()),
  ],
);

export const permissions = pgTable(
  'permissions',
  {
    slug: text().primaryKey(),
    description: text().notNull(),
    minScope: text('min_scope').notNull(),
  },
  (table) => [
    check(
      'permissions_min_scope_check',
      sql`${table.minScope} IN ('environment', 'project')`,
    ),
  ],
);

export const roles = pgTable(
  'roles',
  {
    id: uuid().primaryKey().defaultRandom(),
    slug: text().notNull(),
    name: text().notNull(),
    description: text().notNull().default(''),
    isBuiltin: boolean('is_builtin').notNull().default(false),
    createdAt: createdAt(),
  },
  (table) => [
    unique('roles_slug_key').on(table.slug),
    check('roles_slug_check', sql`${table.slug} ~ '^[a-z0-9][a-z0-9-]{0,62}$'`),
  ],
);

export const rolePermissions = pgTable(
  'role_permissions',
  {
    roleId: uuid('role_id').notNull(),
    permission: text().notNull(),
  },
  (table) => [
    primaryKey({
      name: 'role_permissions_pkey',
      columns: [table.roleId, table.permission],
    }),
    foreignKey({
      name: 'role_permissions_role_id_fkey',
      columns: [table.roleId],
      foreignColumns: [roles.id],
    }).onDelete('cascade'),
    foreignKey({
      name: 'role_permissions_permission_fkey',
      columns: [table.permission],
      foreignColumns: [permissions.slug],
    }).onDelete('restrict'),
  ],
);

export const principals = pgTable(
  'principals',
  {
    principalType: text('principal_type').notNull(),
    principalId: text('principal_id').notNull(),
    instanceRole: text('instance_role').notNull().default('user'),
    createdAt: createdAt(),
    createdBy: text('created_by').notNull(),
    active: boolean().notNull().default(true),
  },
  (table) => [
    primaryKey({
      name: 'principals_pkey',
      columns: [table.principalType, table.principalId],
    }),
    check(
      'principals_principal_type_check',
      sql`${table.principalType} IN ('user', 'service')`,
    ),
    check('principals_instance_role_check', sql`${table.instanceRole} IN ('user', 'owner')`),
    check(
      'principals_service_role_check',
      sql`${table.principalType} = 'user' OR ${table.instanceRole} = 'user'`,
    ),
  ],
);

export const grants = pgTable(
  'grants',
  {
    id: uuid().primaryKey().defaultRandom(),
    principalType: text('principal_type').notNull(),
    principalId: text('principal_id').notNull(),
    environmentId: uuid('environment_id'),
    createdAt: createdAt(),
    createdBy: text('created_by').notNull(),
    projectId: uuid('project_id'),
    roleId: uuid('role_id').notNull(),
    expiresAt: timestamp('expires_at', { withTimezone: true }),
  },
  (table) => [
    check(
      'grants_principal_type_check',
      sql`${table.principalType} IN ('user', 'service')`,
    ),
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
    foreignKey({
      name: 'grants_role_id_fkey',
      columns: [table.roleId],
      foreignColumns: [roles.id],
    }).onDelete('restrict'),
    index('grants_lookup_idx').on(table.principalType, table.principalId, table.environmentId),
    uniqueIndex('grants_environment_unique')
      .on(table.principalType, table.principalId, table.environmentId, table.roleId)
      .where(sql`${table.environmentId} IS NOT NULL`),
    uniqueIndex('grants_project_unique')
      .on(table.principalType, table.principalId, table.projectId, table.roleId)
      .where(sql`${table.projectId} IS NOT NULL`),
    index('grants_project_lookup_idx')
      .on(table.principalType, table.principalId, table.projectId)
      .where(sql`${table.projectId} IS NOT NULL`),
  ],
);

export const auditLog = pgTable(
  'audit_log',
  {
    seq: bigint({ mode: 'bigint' }).primaryKey(),
    id: uuid().notNull().defaultRandom(),
    occurredAt: timestamp('occurred_at', { withTimezone: true }).notNull().defaultNow(),
    actorType: text('actor_type').notNull(),
    actorId: text('actor_id').notNull(),
    action: text().notNull(),
    decision: text().notNull(),
    projectId: uuid('project_id'),
    environmentId: uuid('environment_id'),
    secretId: uuid('secret_id'),
    bundleId: uuid('bundle_id'),
    requestId: text('request_id'),
    sourceIp: text('source_ip'),
    metadata: text().notNull().default('{}'),
    prevHash: bytea('prev_hash').notNull(),
    hash: bytea().notNull(),
  },
  (table) => [
    unique('audit_log_id_key').on(table.id),
    check('audit_log_actor_type_check', sql`${table.actorType} IN ('user', 'service', 'system')`),
    check('audit_log_decision_check', sql`${table.decision} IN ('allow', 'deny')`),
    check('audit_log_metadata_check', sql`${table.metadata}::jsonb IS NOT NULL`),
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
    index('audit_log_occurred_idx').on(table.occurredAt.desc()),
    index('audit_log_actor_idx').on(table.actorType, table.actorId, table.occurredAt.desc()),
    index('audit_log_secret_idx').on(table.secretId, table.occurredAt.desc()),
    index('audit_log_environment_idx').on(table.environmentId, table.occurredAt.desc()),
    index('audit_log_bundle_idx').on(table.bundleId).where(sql`${table.bundleId} IS NOT NULL`),
  ],
);

export const auditChainHead = pgTable(
  'audit_chain_head',
  {
    onlyRow: boolean('only_row').primaryKey().default(true),
    nextSeq: bigint('next_seq', { mode: 'bigint' }).notNull().default(sql`0`),
    headHash: bytea('head_hash').notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    check('audit_chain_head_only_row_check', sql`${table.onlyRow}`),
    check('audit_chain_head_head_hash_check', sql`octet_length(${table.headHash}) = 32`),
  ],
);

export const auditCheckpoints = pgTable(
  'audit_checkpoints',
  {
    id: uuid().primaryKey().defaultRandom(),
    seq: bigint({ mode: 'bigint' }).notNull(),
    headHash: bytea('head_hash').notNull(),
    createdAt: createdAt(),
    exportedAt: timestamp('exported_at', { withTimezone: true }),
    exportTarget: text('export_target'),
  },
  (table) => [
    check('audit_checkpoints_head_hash_check', sql`octet_length(${table.headHash}) = 32`),
  ],
);

export const auditHeartbeat = pgTable(
  'audit_heartbeat',
  {
    onlyRow: boolean('only_row').primaryKey().default(true),
    lastBeatAt: timestamp('last_beat_at', { withTimezone: true }).notNull().defaultNow(),
    lastSeq: bigint('last_seq', { mode: 'bigint' }).notNull().default(sql`0`),
  },
  (table) => [check('audit_heartbeat_only_row_check', sql`${table.onlyRow}`)],
);
