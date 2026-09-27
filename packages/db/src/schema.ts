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
    // A person is their email address, stored lowercased, so matching a
    // provider's verified email is plain equality on every database.
    check(
      'principals_user_id_lowercase',
      sql`${table.principalType} <> 'user' OR ${table.principalId} = lower(${table.principalId})`,
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
    /** One of the built-in roles in packages/core/src/access.ts. */
    role: text().notNull(),
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
    check(
      'grants_role_check',
      sql`${table.role} IN ('viewer', 'developer', 'maintainer', 'access-manager', 'auditor', 'owner')`,
    ),
    index('grants_lookup_idx').on(table.principalType, table.principalId, table.environmentId),
    // One grant per member per place. Revoking expires the row rather than
    // deleting it, and granting again reuses it.
    uniqueIndex('grants_environment_unique')
      .on(table.principalType, table.principalId, table.environmentId)
      .where(sql`${table.environmentId} IS NOT NULL`),
    uniqueIndex('grants_project_unique')
      .on(table.principalType, table.principalId, table.projectId)
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
    // A string, not a Date: the chain covers it to the microsecond, and a
    // Date keeps milliseconds. See canonicalTimestamp in audit.ts.
    occurredAt: timestamp('occurred_at', { withTimezone: true, mode: 'string' })
      .notNull()
      .defaultNow(),
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

/**
 * An account at a sign-in provider, bound to one principal.
 *
 * Looked up by (provider, subject), never by email. An email address is
 * recycled when someone leaves; the provider's subject is not, so binding to
 * it is what stops a new holder of an old address from inheriting its access.
 * The email is kept for display only.
 */
export const identities = pgTable(
  'identities',
  {
    id: uuid().primaryKey().defaultRandom(),
    provider: text().notNull(),
    subject: text().notNull(),
    principalType: text('principal_type').notNull(),
    principalId: text('principal_id').notNull(),
    email: text(),
    createdAt: createdAt(),
    createdBy: text('created_by').notNull(),
    lastSignInAt: timestamp('last_sign_in_at', { withTimezone: true }),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    revokedBy: text('revoked_by'),
  },
  (table) => [
    check('identities_principal_type_check', sql`${table.principalType} = 'user'`),
    check('identities_provider_check', sql`${table.provider} ~ '^[a-z0-9][a-z0-9-]{0,31}$'`),
    foreignKey({
      name: 'identities_principal_fkey',
      columns: [table.principalType, table.principalId],
      foreignColumns: [principals.principalType, principals.principalId],
    }).onDelete('restrict'),
    uniqueIndex('identities_active_subject')
      .on(table.provider, table.subject)
      .where(sql`${table.revokedAt} IS NULL`),
    index('identities_principal_idx').on(table.principalType, table.principalId),
  ],
);

/**
 * Bearer credentials coffre issues itself: browser sessions, CLI sessions and
 * service tokens.
 *
 * One table, so that revoking everything a principal holds is one statement.
 * Only a SHA-256 of each token is stored. Tokens carry 256 bits of entropy, so
 * a fast hash is enough; a database leak yields nothing that authenticates.
 */
export const credentials = pgTable(
  'credentials',
  {
    id: uuid().primaryKey().defaultRandom(),
    kind: text().notNull(),
    tokenHash: bytea('token_hash').notNull(),
    tokenHint: text('token_hint').notNull(),
    principalType: text('principal_type').notNull(),
    principalId: text('principal_id').notNull(),
    identityId: uuid('identity_id'),
    label: text(),
    createdAt: createdAt(),
    createdBy: text('created_by').notNull(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
    lastUsedIp: text('last_used_ip'),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
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
    index('credentials_principal_idx')
      .on(table.principalType, table.principalId)
      .where(sql`${table.revokedAt} IS NULL`),
  ],
);

/**
 * A CLI asking to be signed in from a browser (RFC 8628, device flow).
 *
 * The CLI holds the device code and polls with it; a signed-in person approves
 * the short user code in their browser. It works the same on a laptop and on
 * a server reached over SSH, which a localhost redirect does not.
 */
export const deviceAuthorizations = pgTable(
  'device_authorizations',
  {
    id: uuid().primaryKey().defaultRandom(),
    deviceCodeHash: bytea('device_code_hash').notNull(),
    userCode: text('user_code').notNull(),
    clientLabel: text('client_label'),
    clientIp: text('client_ip'),
    createdAt: createdAt(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    decidedAt: timestamp('decided_at', { withTimezone: true }),
    decision: text(),
    principalType: text('principal_type'),
    principalId: text('principal_id'),
    consumedAt: timestamp('consumed_at', { withTimezone: true }),
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

/**
 * An environment kept in step with a third-party service: GitHub Actions
 * secrets, Vercel or Railway variables, Worker secrets.
 *
 * The destination's API token is itself a coffre secret, referenced by id, so
 * it is encrypted, versioned and audited like everything else and never sits
 * in this table.
 */
export const syncs = pgTable(
  'syncs',
  {
    id: uuid().primaryKey().defaultRandom(),
    projectId: uuid('project_id').notNull(),
    environmentId: uuid('environment_id').notNull(),
    provider: text().notNull(),
    config: text().notNull(),
    credentialSecretId: uuid('credential_secret_id').notNull(),
    createdAt: createdAt(),
    createdBy: text('created_by').notNull(),
    pausedAt: timestamp('paused_at', { withTimezone: true }),
    archivedAt: timestamp('archived_at', { withTimezone: true }),
    leaseUntil: timestamp('lease_until', { withTimezone: true }),
    lastRunAt: timestamp('last_run_at', { withTimezone: true }),
    lastStatus: text('last_status'),
    lastError: text('last_error'),
  },
  (table) => [
    check('syncs_config_check', sql`${table.config}::jsonb IS NOT NULL`),
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
    index('syncs_environment_idx')
      .on(table.environmentId)
      .where(sql`${table.archivedAt} IS NULL`),
  ],
);

/**
 * What a sync last pushed, one row per key.
 *
 * Most destinations are write-only, so coffre cannot diff against them. It
 * diffs against this instead: a key is stale when its secret has moved past
 * the version recorded here. It is also the list of keys coffre may delete at
 * the destination; a key it never pushed is never removed.
 */
export const syncKeys = pgTable(
  'sync_keys',
  {
    syncId: uuid('sync_id').notNull(),
    key: text().notNull(),
    secretVersionId: uuid('secret_version_id'),
    pushedAt: timestamp('pushed_at', { withTimezone: true }).notNull().defaultNow(),
    removedAt: timestamp('removed_at', { withTimezone: true }),
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
