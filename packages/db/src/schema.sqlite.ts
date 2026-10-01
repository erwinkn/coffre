import { assignableToEnvironment, ROLE_NAMES } from '@coffre/core/access';
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
 * - Times are integer milliseconds since the epoch.
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

const ROLES = sql.raw(ROLE_NAMES.map((role) => `'${role}'`).join(', '));
const ENVIRONMENT_ROLES = sql.raw(ROLE_NAMES.filter(assignableToEnvironment).map((role) => `'${role}'`).join(', '));

export const vaultMembers = sqliteTable(
  'vault_members',
  {
    principal: text().primaryKey(),
    status: text().notNull(),
    owner: flag('owner').notNull().default(false),
    generation: integer().notNull().default(0),
    createdAt: integer('created_at', { mode: 'number' }).notNull(),
    createdBy: text('created_by').notNull(),
    statusChangedAt: integer('status_changed_at', { mode: 'number' }).notNull(),
    statusChangedBy: text('status_changed_by').notNull(),
    accessSeq: int64('access_seq').notNull(),
    mac: bytes('mac').notNull(),
  },
  (table) => [
    check('vault_members_mac_check', sql`octet_length(${table.mac}) = 32`),
    // `^(user|token|sync):[^[:space:]:][^[:space:]]*$`, without regular expressions.
    check(
      'vault_members_principal_check',
      sql`(${table.principal} GLOB 'user:?*' OR ${table.principal} GLOB 'token:?*' OR ${table.principal} GLOB 'sync:?*')
        AND substr(${table.principal}, instr(${table.principal}, ':') + 1, 1) <> ':'
        AND instr(${table.principal}, ' ') = 0 AND instr(${table.principal}, char(9)) = 0
        AND instr(${table.principal}, char(10)) = 0 AND instr(${table.principal}, char(13)) = 0`,
    ),
    check('vault_members_user_lowercase', sql`${table.principal} NOT LIKE 'user:%' OR ${table.principal} = lower(${table.principal})`),
    check('vault_members_status_check', sql`${table.status} IN ('active', 'removed')`),
    check('vault_members_owner_check', sql`NOT ${table.owner} OR (${table.status} = 'active' AND ${table.principal} LIKE 'user:%')`),
    check('vault_members_generation_check', sql`${table.generation} >= 0`),
  ],
);

export const vaultGrants = sqliteTable(
  'vault_grants',
  {
    principal: text().notNull(),
    projectId: text('project_id'),
    environmentId: text('environment_id'),
    role: text().notNull(),
    expiresAt: integer('expires_at', { mode: 'number' }),
    grantedAt: integer('granted_at', { mode: 'number' }).notNull(),
    grantedBy: text('granted_by').notNull(),
  },
  (table) => [
    check('vault_grants_one_place', sql`(${table.projectId} IS NULL) <> (${table.environmentId} IS NULL)`),
    check('vault_grants_role_check', sql`${table.role} IN (${ROLES})`),
    check('vault_grants_environment_role_check', sql`${table.environmentId} IS NULL OR ${table.role} IN (${ENVIRONMENT_ROLES})`),
    unique('vault_grants_on_project').on(table.principal, table.projectId),
    unique('vault_grants_on_environment').on(table.principal, table.environmentId),
    foreignKey({
      name: 'vault_grants_principal_fkey',
      columns: [table.principal],
      foreignColumns: [vaultMembers.principal],
    }).onDelete('restrict'),
    foreignKey({
      name: 'vault_grants_project_id_fkey',
      columns: [table.projectId],
      foreignColumns: [projects.id],
    }).onDelete('restrict'),
    foreignKey({
      name: 'vault_grants_environment_id_fkey',
      columns: [table.environmentId],
      foreignColumns: [environments.id],
    }).onDelete('restrict'),
  ],
);

export const auditLog = sqliteTable(
  'audit_log',
  {
    seq: int64('seq').primaryKey(),
    // Which component wrote the entry, under which of its keys; see
    // @coffre/core/audit for what its MAC and hash cover.
    author: text().notNull(),
    keyId: text('key_id').notNull(),
    // Milliseconds since the epoch, from the database's clock, read after the
    // append took the head's lock.
    occurredAt: integer('occurred_at', { mode: 'number' }).notNull(),
    // Who acted: `user:<email>`, `token:<id>`, `sync:<id>` or `system:<name>`.
    actor: text().notNull(),
    action: text().notNull(),
    decision: text().notNull(),
    code: text(),
    // The member an access change is about.
    subjectPrincipal: text('subject_principal'),
    projectId: text('project_id'),
    environmentId: text('environment_id'),
    secretId: text('secret_id'),
    secretVersionId: text('secret_version_id'),
    // One id for everything one action did: a reveal's keys, a write's versions.
    operationId: text('operation_id'),
    requestId: text('request_id'),
    sourceIp: text('source_ip'),
    // An earlier entry this one follows from, such as the wrap behind a write.
    relatedSeq: int64('related_seq'),
    metadata: text().notNull().default('{}'),
    prevHash: bytes('prev_hash').notNull(),
    mac: bytes('mac').notNull(),
    hash: bytes('hash').notNull(),
  },
  (table) => [
    check('audit_log_author_check', sql`${table.author} IN ('app', 'vault')`),
    check(
      'audit_log_actor_check',
      sql`${table.actor} GLOB 'user:?*' OR ${table.actor} GLOB 'token:?*' OR ${table.actor} GLOB 'sync:?*' OR ${table.actor} GLOB 'system:?*'`,
    ),
    check('audit_log_decision_check', sql`${table.decision} IN ('allow', 'deny')`),
    check('audit_log_metadata_check', sql`json_valid(${table.metadata})`),
    check('audit_log_prev_hash_check', sql`octet_length(${table.prevHash}) = 32`),
    check('audit_log_mac_check', sql`octet_length(${table.mac}) = 32`),
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
    foreignKey({
      name: 'audit_log_secret_version_id_fkey',
      columns: [table.secretVersionId],
      foreignColumns: [secretVersions.id],
    }).onDelete('restrict'),
    foreignKey({
      name: 'audit_log_related_seq_fkey',
      columns: [table.relatedSeq],
      foreignColumns: [table.seq],
    }).onDelete('restrict'),
    // Pages read backwards by seq, within a place or an actor.
    index('audit_log_project_idx').on(table.projectId, table.seq),
    index('audit_log_environment_idx').on(table.environmentId, table.seq),
    index('audit_log_secret_idx').on(table.secretId, table.seq),
    index('audit_log_actor_idx').on(table.actor, table.seq),
    index('audit_log_operation_idx').on(table.operationId, table.seq),
    index('audit_log_action_idx').on(table.author, table.action, table.seq),
    index('audit_log_releases_idx').on(table.author, table.actor, table.action, table.decision, table.occurredAt),
    index('audit_log_subject_idx').on(table.author, table.subjectPrincipal, table.seq),
  ],
);

export const auditChainHead = sqliteTable(
  'audit_chain_head',
  {
    onlyRow: flag('only_row').primaryKey().default(true),
    nextSeq: int64('next_seq').notNull().default(sql`0`),
    headHash: bytes('head_hash').notNull(),
  },
  (table) => [
    check('audit_chain_head_only_row_check', sql`${table.onlyRow}`),
    check('audit_chain_head_next_seq_check', sql`${table.nextSeq} >= 0`),
    check('audit_chain_head_head_hash_check', sql`octet_length(${table.headHash}) = 32`),
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
    authMac: bytes('auth_mac').notNull(),
    subject: text().notNull(),
    issuerHash: text('issuer_hash').notNull(),
    generation: integer().notNull(),
    // The member it signs in as, `user:<email>`, under the generation it was bound in.
    principal: text().notNull(),
    email: text(),
    createdAt: createdAt(),
    createdBy: text('created_by').notNull(),
    lastSignInAt: time('last_sign_in_at'),
    revokedAt: time('revoked_at'),
    revokedBy: text('revoked_by'),
    activeSubject: text('active_subject').generatedAlwaysAs(ACTIVE_SUBJECT, { mode: 'stored' }),
  },
  (table) => [
    check('identities_principal_check', sql`${table.principal} LIKE 'user:%'`),
    check('identities_provider_check', isSlug(table.provider, 32)),
    check('identities_auth_mac_check', sql`octet_length(${table.authMac}) = 32`),
    unique('identities_member_generation_key').on(table.id, table.principal, table.generation),
    foreignKey({
      name: 'identities_principal_fkey',
      columns: [table.principal],
      foreignColumns: [vaultMembers.principal],
    }).onDelete('restrict'),
    uniqueIndex('identities_active_subject').on(table.provider, table.issuerHash, table.activeSubject),
    index('identities_principal_idx').on(table.principal, table.generation),
  ],
);

export const credentials = sqliteTable(
  'credentials',
  {
    id: text().primaryKey(),
    kind: text().notNull(),
    authMac: bytes('auth_mac').notNull(),
    tokenHash: bytes('token_hash').notNull(),
    tokenHint: text('token_hint').notNull(),
    generation: integer().notNull(),
    // The member it acts as, `user:<email>` or `token:<id>`, under the generation it was issued in.
    principal: text().notNull(),
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
    check('credentials_principal_check', sql`${table.principal} LIKE 'user:%' OR ${table.principal} LIKE 'token:%'`),
    check('credentials_kind_matches_principal', sql`(${table.kind} = 'service') = (${table.principal} LIKE 'token:%')`),
    check('credentials_token_hash_check', sql`octet_length(${table.tokenHash}) = 32`),
    check('credentials_auth_mac_check', sql`octet_length(${table.authMac}) = 32`),
    foreignKey({
      name: 'credentials_principal_fkey',
      columns: [table.principal],
      foreignColumns: [vaultMembers.principal],
    }).onDelete('restrict'),
    // A session's account is its own member's, bound in the same generation.
    foreignKey({
      name: 'credentials_identity_id_fkey',
      columns: [table.identityId, table.principal, table.generation],
      foreignColumns: [identities.id, identities.principal, identities.generation],
    }).onDelete('restrict'),
    index('credentials_principal_idx').on(table.principal, table.generation),
  ],
);

export const deviceAuthorizations = sqliteTable(
  'device_authorizations',
  {
    id: text().primaryKey(),
    deviceCodeHash: bytes('device_code_hash').notNull(),
    authMac: bytes('auth_mac').notNull(),
    userCode: text('user_code').notNull(),
    clientLabel: text('client_label'),
    clientIp: text('client_ip'),
    createdAt: createdAt(),
    expiresAt: time('expires_at').notNull(),
    decidedAt: time('decided_at'),
    decision: text(),
    generation: integer().notNull().default(0),
    // Who approved it, `user:<email>`, once approved.
    principal: text(),
    consumedAt: time('consumed_at'),
  },
  (table) => [
    unique('device_authorizations_device_code_hash_key').on(table.deviceCodeHash),
    unique('device_authorizations_user_code_key').on(table.userCode),
    check('device_authorizations_auth_mac_check', sql`octet_length(${table.authMac}) = 32`),
    check(
      'device_authorizations_decision_check',
      sql`${table.decision} IS NULL OR ${table.decision} IN ('approved', 'denied')`,
    ),
    check(
      'device_authorizations_approval_names_principal',
      sql`(${table.decision} IS NULL AND ${table.decidedAt} IS NULL AND ${table.principal} IS NULL AND ${table.generation} = 0 AND ${table.consumedAt} IS NULL)
        OR (${table.decision} IS NOT NULL AND ${table.decidedAt} IS NOT NULL AND (
          (${table.decision} = 'denied' AND ${table.principal} IS NULL AND ${table.generation} = 0 AND ${table.consumedAt} IS NULL)
          OR (${table.decision} = 'approved' AND ${table.principal} IS NOT NULL AND ${table.principal} LIKE 'user:%')
        ))`,
    ),
    foreignKey({
      name: 'device_authorizations_principal_fkey',
      columns: [table.principal],
      foreignColumns: [vaultMembers.principal],
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
  environmentsRelations,
  secretsRelations,
  syncsRelations,
  syncKeysRelations,
} = relationsOf(
  asPostgres({ projects, environments, secrets, secretVersions, syncs, syncKeys }),
);
