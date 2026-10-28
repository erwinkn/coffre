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

/** A slug, or a tombstone's, `market~deleted-2026-10-05`: schema.ts's `PLACE_SLUG`, in GLOB. */
const isPlaceSlug = (column: AnySQLiteColumn) => {
  const base = sql`substr(${column}, 1, instr(${column}, '~') - 1)`;
  const suffix = sql`substr(${column}, instr(${column}, '~') + 1)`;
  return sql`(${isSlug(column, 63)}) OR (instr(${column}, '~') BETWEEN 2 AND 64 AND ${base} GLOB '[a-z0-9]*' AND ${base} NOT GLOB '*[^a-z0-9-]*' AND length(${suffix}) BETWEEN 1 AND 40 AND ${suffix} NOT GLOB '*[^a-z0-9-]*')`;
};

/** A folder's name; the app also refuses control characters, which GLOB has no class for. */
const folderCheck = (name: string, column: AnySQLiteColumn) =>
  check(name, sql`${column} IS NULL OR (length(${column}) BETWEEN 1 AND 64 AND ${column} NOT GLOB '*/*' AND ${column} = trim(${column}))`);

export const projects = sqliteTable(
  'projects',
  {
    id: text().primaryKey(),
    slug: text().notNull(),
    name: text().notNull(),
    createdAt: createdAt(),
    archivedAt: time('archived_at'),
    folder: text(),
  },
  (table) => [
    unique('projects_slug_key').on(table.slug),
    check('projects_slug_check', isPlaceSlug(table.slug)),
    folderCheck('projects_folder_check', table.folder),
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
    parentId: text('parent_id'),
    owner: text(),
    protected: flag('protected'),
    // 0.15's seal (schema.ts).
    seal: bytes('seal'),
  },
  (table) => [
    check('environments_seal_check', sql`${table.seal} IS NULL OR octet_length(${table.seal}) = 16`),
    unique('environments_project_id_slug_key').on(table.projectId, table.slug),
    unique('environments_project_scoped').on(table.id, table.projectId),
    check('environments_slug_check', isPlaceSlug(table.slug)),
    // An environment is never its own parent. Longer loops, written around the app, are refused at read (`parentsOf`).
    check('environments_parent_check', sql`${table.parentId} IS NULL OR ${table.parentId} <> ${table.id}`),
    check('environments_owner_check', sql`${table.owner} IS NULL OR (${table.parentId} IS NOT NULL AND ${table.owner} LIKE 'user:_%')`),
    uniqueIndex('environments_parent_id_owner_key').on(table.parentId, table.owner).where(sql`instr(${table.slug}, '~') = 0`),
    foreignKey({
      name: 'environments_project_id_fkey',
      columns: [table.projectId],
      foreignColumns: [projects.id],
    }).onDelete('restrict'),
    // Checked at the end of a statement, not at each row: one that deletes a fork and its parent together is no orphan.
    foreignKey({
      name: 'environments_parent_in_project',
      columns: [table.parentId, table.projectId],
      foreignColumns: [table.id, table.projectId],
    }).onDelete('no action'),
    index('environments_parent_idx').on(table.parentId),
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
    folder: text(),
    // 0.15's seal (schema.ts).
    seal: bytes('seal'),
  },
  (table) => [
    check('secrets_seal_check', sql`${table.seal} IS NULL OR octet_length(${table.seal}) = 16`),
    unique('secrets_project_id_environment_id_key_key').on(table.projectId, table.environmentId, table.key),
    check(
      'secrets_key_check',
      sql`length(${table.key}) BETWEEN 1 AND 128 AND ${table.key} GLOB '[A-Za-z_]*' AND ${table.key} NOT GLOB '*[^A-Za-z0-9_]*'`,
    ),
    folderCheck('secrets_folder_check', table.folder),
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
    // The live keys of an environment, which a read by environment alone (the places tree's counts, `liveKeysIn`) walks without the archived ones beside them; the one above leads with the project (T152, 0032).
    index('secrets_live_idx').on(table.environmentId).where(sql`${table.archivedAt} IS NULL`),
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
    // How a client made this value, `bytes:32:hex` (`@coffre/core/recipe`),
    // when it was generated rather than typed: Regenerate makes the next one
    // the same way. Null for a typed value, so writing one by hand clears it.
    recipe: text(),
    // A generated key pair's two versions, written together, share an id,
    // and each says which half it holds: 'private' or 'public'.
    pairId: text('pair_id'),
    pairHalf: text('pair_half'),
    // The value itself, for a plain one: a key marked not secret, an account's
    // id, which whoever lists the environment sees and a read serves without
    // the vault. Null for a secret. Its ciphertext is kept as any version's,
    // for what opens values through the vault (a reference, a fork's copy).
    plaintext: text(),
    // A sensitive value: never handed back to a person, Owners included, only
    // used for them through the credential proxy, or read by a service
    // account. Its data key's wrap binds it, so the vault opens a version
    // flipped back as nothing. Never plain too.
    sensitive: flag('sensitive').notNull().default(false),
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

export const dismissedKeys = sqliteTable(
  'dismissed_keys',
  {
    environmentId: text('environment_id').notNull(),
    key: text().notNull(),
    dismissedAt: time('dismissed_at').notNull().default(now),
    dismissedBy: text('dismissed_by').notNull(),
    restoredAt: time('restored_at'),
    restoredBy: text('restored_by'),
  },
  (table) => [
    primaryKey({ name: 'dismissed_keys_pkey', columns: [table.environmentId, table.key] }),
    check(
      'dismissed_keys_key_check',
      sql`length(${table.key}) BETWEEN 1 AND 128 AND ${table.key} GLOB '[A-Za-z_]*' AND ${table.key} NOT GLOB '*[^A-Za-z0-9_]*'`,
    ),
    foreignKey({
      name: 'dismissed_keys_environment_id_fkey',
      columns: [table.environmentId],
      foreignColumns: [environments.id],
    }).onDelete('restrict'),
  ],
);

export const vaultMembers = sqliteTable(
  'vault_members',
  {
    principal: text().primaryKey(),
    status: text().notNull(),
    owner: flag('owner').notNull().default(false),
    role: text(),
    scope: text(),
    generation: integer().notNull().default(0),
    createdAt: integer('created_at', { mode: 'number' }).notNull(),
    createdBy: text('created_by').notNull(),
    statusChangedAt: integer('status_changed_at', { mode: 'number' }).notNull(),
    statusChangedBy: text('status_changed_by').notNull(),
    accessSeq: int64('access_seq').notNull(),
    mac: bytes('mac').notNull(),
    // 0.15's seal (schema.ts).
    seal: bytes('seal'),
  },
  (table) => [
    check('vault_members_seal_check', sql`${table.seal} IS NULL OR octet_length(${table.seal}) = 16`),
    check('vault_members_mac_check', sql`octet_length(${table.mac}) = 32`),
    // `^(user|token):[^[:space:]:][^[:space:]]*$`, without regular expressions.
    check(
      'vault_members_principal_check',
      sql`(${table.principal} GLOB 'user:?*' OR ${table.principal} GLOB 'token:?*')
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
    environmentSlug: text('environment_slug'),
    role: text().notNull(),
    expiresAt: integer('expires_at', { mode: 'number' }),
    grantedAt: integer('granted_at', { mode: 'number' }).notNull(),
    grantedBy: text('granted_by').notNull(),
  },
  (table) => [
    check(
      'vault_grants_one_place',
      sql`((${table.projectId} IS NULL) <> (${table.environmentId} IS NULL) AND ${table.environmentSlug} IS NULL) OR (${table.projectId} IS NULL AND ${table.environmentId} IS NULL)`,
    ),
    check('vault_grants_environment_slug_check', sql`${table.environmentSlug} IS NULL OR (${isSlug(table.environmentSlug, 63)})`),
    // A role's id, one that ships or one an Owner made (`ROLE_ID`): which the instance's policy defines, and which of them an
    // environment may be granted, the vault decides, as the policy is now (docs/design/roles.md).
    check('vault_grants_role_check', sql`length(${table.role}) BETWEEN 2 AND 32 AND ${table.role} GLOB '[a-z]*' AND ${table.role} NOT GLOB '*[^a-z0-9-]*'`),
    unique('vault_grants_on_project').on(table.principal, table.projectId),
    unique('vault_grants_on_environment').on(table.principal, table.environmentId),
    unique('vault_grants_on_environment_slug').on(table.principal, table.environmentSlug),
    uniqueIndex('vault_grants_on_every_project')
      .on(table.principal)
      .where(sql`${table.projectId} IS NULL AND ${table.environmentId} IS NULL AND ${table.environmentSlug} IS NULL`),
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

/**
 * Each key the vault released to a principal, and when last: what its bulk
 * limit counts (R28), the distinct keys released within a window, without
 * reading the log. The database keeps it from the log itself, in the
 * transaction of each vault `secret.read` allowed: a trigger on
 * `audit_log` upserts a row for each key the entry names, as the count
 * read them from the entries before (an entry that names none, which only
 * a forged one is, counts as a key of its own, `entry:<seq>`). No login
 * writes it: the vault and the backup read it. A row a window old counts
 * for nothing: the vault's checkpoint forgets those a day and an hour old,
 * longer than any window, so a count reads about a day of keys.
 */
export const vaultReleases = sqliteTable(
  'vault_releases',
  {
    principal: text().notNull(),
    key: text().notNull(),
    releasedAt: integer('released_at', { mode: 'number' }).notNull(),
  },
  (table) => [primaryKey({ name: 'vault_releases_pkey', columns: [table.principal, table.key] })],
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
    // Who acted: `user:<email>`, `token:<id>` or `system:<name>`.
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
      sql`${table.actor} GLOB 'user:?*' OR ${table.actor} GLOB 'token:?*' OR ${table.actor} GLOB 'system:?*'`,
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
    // A binding's tombstone: the app's successful `token.unbind` naming it.
    index('audit_log_unbind_idx')
      .on(sql`json_extract(${table.metadata}, '$.bindingId')`)
      .where(sql`${table.author} = 'app' AND ${table.action} = 'token.unbind' AND ${table.decision} = 'allow'`),
    // Whether a target is frozen: its newest allowed freeze or lift (docs/design/workload-access.md, section 8.2).
    index('audit_log_freeze_idx')
      .on(sql`json_extract(${table.metadata}, '$.target')`, table.seq)
      .where(sql`${table.author} = 'app' AND ${table.action} IN ('workload.freeze', 'workload.unfreeze') AND ${table.decision} = 'allow'`),
    // An enrollment code's tombstone: the app's successful `enrollment.supersede` naming it.
    index('audit_log_supersede_idx')
      .on(sql`json_extract(${table.metadata}, '$.enrollmentId')`)
      .where(sql`${table.author} = 'app' AND ${table.action} = 'enrollment.supersede' AND ${table.decision} = 'allow'`),
    // The run a credential was issued for: its exchange's entry, by the credential's ID.
    index('audit_log_exchange_idx')
      .on(sql`json_extract(${table.metadata}, '$.credentialId')`)
      .where(sql`${table.author} = 'app' AND ${table.action} = 'token.exchange' AND ${table.decision} = 'allow'`),
    // The token a credential is, when one was issued: its creation's entry, by the credential's ID, whose label names a personal token's entries.
    index('audit_log_token_create_idx')
      .on(sql`json_extract(${table.metadata}, '$.targetCredentialId')`)
      .where(sql`${table.author} = 'app' AND ${table.action} = 'token.create' AND ${table.decision} = 'allow'`),
    index('audit_log_reference_end_idx')
      .on(table.relatedSeq)
      .where(sql`${table.author} = 'vault' AND ${table.action} = 'reference.end' AND ${table.decision} = 'allow'`),
    index('audit_log_also_project_idx')
      .on(sql`json_extract(${table.metadata}, '$.also.projectId')`, table.seq)
      .where(sql`json_extract(${table.metadata}, '$.also') IS NOT NULL`),
    index('audit_log_also_environment_idx')
      .on(sql`json_extract(${table.metadata}, '$.also.environmentId')`, table.seq)
      .where(sql`json_extract(${table.metadata}, '$.also') IS NOT NULL`),
    index('audit_log_also_secret_idx')
      .on(sql`json_extract(${table.metadata}, '$.also.secretId')`, table.seq)
      .where(sql`json_extract(${table.metadata}, '$.also') IS NOT NULL`),
  ],
);

export const secretReferences = sqliteTable(
  'secret_references',
  {
    id: text().primaryKey(),
    projectId: text('project_id').notNull(),
    environmentId: text('environment_id').notNull(),
    secretId: text('secret_id').notNull(),
    sourceProjectId: text('source_project_id').notNull(),
    sourceEnvironmentId: text('source_environment_id').notNull(),
    sourceSecretId: text('source_secret_id').notNull(),
    createdSeq: int64('created_seq').notNull(),
    createdAt: createdAt(),
    createdBy: text('created_by').notNull(),
    // 0.15's end of the reference (0028): when its holder stopped reading its source, broken, replaced or cut, written
    // with 0.14's `reference.end` in the vault's decision. The holder's object reads its newest row's source only while
    // this is null. Null on rows 0.14 ended: 0.14's log holds those ends, which the cutover (plan PR 9) writes here.
    endedAt: time('ended_at'),
  },
  (table) => [
    unique('secret_references_created_seq_key').on(table.createdSeq),
    foreignKey({
      name: 'secret_references_secret_id_fkey',
      columns: [table.secretId],
      foreignColumns: [secrets.id],
    }).onDelete('restrict'),
    foreignKey({
      name: 'secret_references_source_secret_id_fkey',
      columns: [table.sourceSecretId],
      foreignColumns: [secrets.id],
    }).onDelete('restrict'),
    foreignKey({
      name: 'secret_references_created_seq_fkey',
      columns: [table.createdSeq],
      foreignColumns: [auditLog.seq],
    }).onDelete('restrict'),
    index('secret_references_holder_idx').on(table.secretId, table.createdSeq),
    index('secret_references_source_idx').on(table.sourceSecretId),
    index('secret_references_project_idx').on(table.projectId),
    index('secret_references_source_project_idx').on(table.sourceProjectId),
    index('secret_references_created_by_idx').on(table.createdBy),
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

export const serviceBindings = sqliteTable(
  'service_bindings',
  {
    id: text().primaryKey(),
    authMac: bytes('auth_mac').notNull(),
    // The service it signs in as, `token:<id>`, under the generation it was bound in.
    principal: text().notNull(),
    generation: integer().notNull(),
    profile: text().notNull(),
    issuer: text().notNull(),
    // From the issuer's discovery when the binding was made, never refetched;
    // or, for keys uploaded with the binding, `sha256:<hex>` of `jwks`.
    jwksUri: text('jwks_uri').notNull(),
    // The issuer's public keys, uploaded with the binding (`uploadedKeys`), JSON; null when they are fetched.
    jwks: text(),
    // JSON, sorted by claim name.
    claims: text().notNull(),
    // What the credentials it issues reach (`CredentialScope`), JSON; null on a binding of 0.4 the app has not sealed yet.
    scope: text(),
    // What a workload's binding says beyond its claims (`BindingPolicy`), canonical JSON: null on a binding `/api/auth/oidc` takes, never on another (docs/design/workload-access.md, section 11).
    policy: text(),
    label: text(),
    createdAt: createdAt(),
    createdBy: text('created_by').notNull(),
    lastUsedAt: time('last_used_at'),
    revokedAt: time('revoked_at'),
    revokedBy: text('revoked_by'),
    // 0.15's seal (schema.ts).
    seal: bytes('seal'),
  },
  (table) => [
    check('service_bindings_seal_check', sql`${table.seal} IS NULL OR octet_length(${table.seal}) = 16`),
    check('service_bindings_principal_check', sql`${table.principal} LIKE 'token:%'`),
    check('service_bindings_auth_mac_check', sql`octet_length(${table.authMac}) = 32`),
    check('service_bindings_claims_check', sql`json_valid(${table.claims})`),
    foreignKey({
      name: 'service_bindings_principal_fkey',
      columns: [table.principal],
      foreignColumns: [vaultMembers.principal],
    }).onDelete('restrict'),
    index('service_bindings_principal_idx').on(table.principal, table.issuer),
    // What an exchange may match: a service's live bindings on an issuer, in a
    // generation, in the order it reads them, without the retired history.
    index('service_bindings_live_idx')
      .on(table.principal, table.issuer, table.generation, table.createdAt, table.id)
      .where(sql`${table.revokedAt} IS NULL`),
  ],
);

export const consumedTokens = sqliteTable(
  'consumed_tokens',
  {
    hash: bytes('hash').primaryKey(),
    consumedAt: time('consumed_at').notNull().default(now),
  },
  (table) => [check('consumed_tokens_hash_check', sql`octet_length(${table.hash}) = 32`)],
);

export const cappedAlerts = sqliteTable(
  'capped_alerts',
  {
    service: text().notNull(),
    kind: text().notNull(),
    raisedAt: time('raised_at').notNull(),
  },
  (table) => [primaryKey({ name: 'capped_alerts_pkey', columns: [table.service, table.kind] })],
);

/**
 * MCP clients that registered themselves (RFC 7591), the fallback to Client
 * ID Metadata Documents, which need no row. The ID is the client's
 * `client_id`. Its redirects are under its MAC: a database writer cannot add
 * one of their own to a client people have approved.
 */
export const oauthClients = sqliteTable(
  'oauth_clients',
  {
    id: text().primaryKey(),
    authMac: bytes('auth_mac').notNull(),
    // Its own claim, shown as unverified.
    name: text().notNull(),
    // JSON: a list of HTTPS or loopback URLs.
    redirectUris: text('redirect_uris').notNull(),
    createdAt: createdAt(),
    createdIp: text('created_ip'),
    revokedAt: time('revoked_at'),
  },
  (table) => [
    check('oauth_clients_auth_mac_check', sql`octet_length(${table.authMac}) = 32`),
    check('oauth_clients_redirect_uris_check', sql`json_valid(${table.redirectUris})`),
  ],
);

/**
 * One MCP client a person connected: one approved authorization, its
 * scopes, its code until the client redeems it, and the refresh token it
 * holds since. Access tokens have no row: each names its connection under a
 * MAC, and every request checks this row. Revoking it ends them all.
 */
export const mcpConnections = sqliteTable(
  'mcp_connections',
  {
    id: text().primaryKey(),
    authMac: bytes('auth_mac').notNull(),
    // The person it acts as, `user:<email>`, under the generation they approved it in.
    principal: text().notNull(),
    generation: integer().notNull(),
    // A metadata document's URL, or a registration's ID.
    clientId: text('client_id').notNull(),
    // As the consent page showed them: display only.
    clientName: text('client_name').notNull(),
    clientHost: text('client_host'),
    registration: text().notNull(),
    // Space-separated, in catalogue order: `read write`.
    scopes: text().notNull(),
    redirectUri: text('redirect_uri').notNull(),
    // Until the client redeems it: its SHA-256, its PKCE challenge, and 60 seconds.
    codeHash: bytes('code_hash'),
    codeChallenge: text('code_challenge'),
    codeExpiresAt: time('code_expires_at'),
    // From then on: the refresh token's SHA-256, and the one it replaced, whose reuse ends the connection.
    refreshHash: bytes('refresh_hash'),
    refreshPreviousHash: bytes('refresh_previous_hash'),
    expiresAt: time('expires_at').notNull(),
    createdAt: createdAt(),
    lastUsedAt: time('last_used_at'),
    lastUsedIp: text('last_used_ip'),
    revokedAt: time('revoked_at'),
    revokedBy: text('revoked_by'),
  },
  (table) => [
    check('mcp_connections_principal_check', sql`${table.principal} LIKE 'user:%'`),
    check('mcp_connections_registration_check', sql`${table.registration} IN ('cimd', 'dcr')`),
    check('mcp_connections_auth_mac_check', sql`octet_length(${table.authMac}) = 32`),
    check('mcp_connections_code_hash_check', sql`${table.codeHash} IS NULL OR octet_length(${table.codeHash}) = 32`),
    check('mcp_connections_refresh_hash_check', sql`${table.refreshHash} IS NULL OR octet_length(${table.refreshHash}) = 32`),
    foreignKey({
      name: 'mcp_connections_principal_fkey',
      columns: [table.principal],
      foreignColumns: [vaultMembers.principal],
    }).onDelete('restrict'),
    unique('mcp_connections_code_hash_key').on(table.codeHash),
    unique('mcp_connections_refresh_hash_key').on(table.refreshHash),
    index('mcp_connections_refresh_previous_idx').on(table.refreshPreviousHash),
    // A person's live connections: Connected apps, and the limit on how many.
    index('mcp_connections_live_idx').on(table.principal, table.expiresAt).where(sql`${table.revokedAt} IS NULL`),
  ],
);

/**
 * A change an MCP client asked for, waiting for its person on coffre's own
 * page: see schema.ts.
 */
export const mcpApprovals = sqliteTable(
  'mcp_approvals',
  {
    id: text().primaryKey(),
    connectionId: text('connection_id').notNull(),
    tool: text().notNull(),
    arguments: text().notNull(),
    digest: bytes('digest').notNull(),
    status: text().notNull().default('pending'),
    outcome: text(),
    createdAt: createdAt(),
    expiresAt: time('expires_at').notNull(),
    decidedAt: time('decided_at'),
    reportedAt: time('reported_at'),
  },
  (table) => [
    check('mcp_approvals_status_check', sql`${table.status} IN ('pending', 'approved', 'denied', 'cancelled', 'failed')`),
    check('mcp_approvals_digest_check', sql`octet_length(${table.digest}) = 32`),
    check('mcp_approvals_arguments_check', sql`json_valid(${table.arguments})`),
    foreignKey({
      name: 'mcp_approvals_connection_fkey',
      columns: [table.connectionId],
      foreignColumns: [mcpConnections.id],
    }).onDelete('restrict'),
    index('mcp_approvals_open_idx').on(table.connectionId, table.digest).where(sql`${table.reportedAt} IS NULL`),
  ],
);

/**
 * Enrollment codes (docs/design/workload-access.md, section 4.4): what CI
 * mints for a platform that signs no identity, and the app exchanges for a
 * workload's session at `/api/auth/workload`. Never a credential itself, and
 * only ever added: the log says which code a promote superseded. Its scope,
 * fixed at minting, is the binding's within what the minter held; the MAC
 * covers everything but its hint and creation time (auth-rows.ts in the server).
 */
export const enrollments = sqliteTable(
  'enrollments',
  {
    id: text().primaryKey(),
    authMac: bytes('auth_mac').notNull(),
    bindingId: text('binding_id').notNull(),
    // The SHA-256 of the code, `coffre_enr_…`, and enough of it to recognize.
    codeHash: bytes('code_hash').notNull(),
    codeHint: text('code_hint').notNull(),
    // `CredentialScope`, JSON: what its sessions reach, R32's sensitive per place.
    scope: text().notNull(),
    createdAt: createdAt(),
    // Who minted it, and with which of their credentials: a CI run's session.
    createdBy: text('created_by').notNull(),
    createdWith: text('created_with'),
    expiresAt: time('expires_at').notNull(),
  },
  (table) => [
    unique('enrollments_code_hash_key').on(table.codeHash),
    check('enrollments_auth_mac_check', sql`octet_length(${table.authMac}) = 32`),
    check('enrollments_code_hash_check', sql`octet_length(${table.codeHash}) = 32`),
    check('enrollments_scope_check', sql`json_valid(${table.scope})`),
    foreignKey({
      name: 'enrollments_binding_id_fkey',
      columns: [table.bindingId],
      foreignColumns: [serviceBindings.id],
    }).onDelete('restrict'),
    // A binding's codes, newest first, for its page.
    index('enrollments_binding_idx').on(table.bindingId, table.createdAt),
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
    // What a service or personal token reaches (`CredentialScope`), JSON: null for a session, one a binding issued (its binding's), or one of 0.4 the app has not sealed yet.
    scope: text(),
    // The environments a handle was made for, by id, each with whether it was asked for as `@me`, JSON: null for any other credential, or a handle of 0.8.
    places: text(),
    label: text(),
    createdAt: createdAt(),
    createdBy: text('created_by').notNull(),
    expiresAt: time('expires_at').notNull(),
    lastUsedAt: time('last_used_at'),
    lastUsedIp: text('last_used_ip'),
    revokedAt: time('revoked_at'),
    revokedBy: text('revoked_by'),
    // A workload's session (docs/design/workload-access.md, section 11), null on every other credential:
    // the thumbprint of the key its proofs are signed by, and its hard end.
    jkt: text(),
    notAfter: time('not_after'),
    // A `narrow` child's: its ancestors' IDs, root first, JSON, and its limits (`Constraints`), canonical JSON.
    ancestors: text(),
    constraints: text(),
    // The enrollment code a session was made from, and, where its binding says `approve`, who approved it.
    enrollmentId: text('enrollment_id'),
    approvedAt: time('approved_at'),
    approvedBy: text('approved_by'),
    // 0.15's seal (schema.ts).
    seal: bytes('seal'),
  },
  (table) => [
    check('credentials_seal_check', sql`${table.seal} IS NULL OR octet_length(${table.seal}) = 16`),
    unique('credentials_token_hash_key').on(table.tokenHash),
    check('credentials_kind_check', sql`${table.kind} IN ('browser', 'cli', 'service', 'personal', 'handle', 'workload')`),
    check('credentials_principal_check', sql`${table.principal} LIKE 'user:%' OR ${table.principal} LIKE 'token:%'`),
    check('credentials_kind_matches_principal', sql`(${table.kind} IN ('service', 'workload')) = (${table.principal} LIKE 'token:%')`),
    check('credentials_workload_jkt_check', sql`${table.kind} <> 'workload' OR ${table.jkt} IS NOT NULL`),
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
    // A member's credentials still live, however many have expired: a CI run
    // leaves one behind each time it signs in.
    index('credentials_live_idx').on(table.principal, table.expiresAt).where(sql`${table.revokedAt} IS NULL`),
    // What a trust binding issued lately, for its rate.
    index('credentials_issued_by_idx').on(table.principal, table.createdBy, table.createdAt),
    foreignKey({
      name: 'credentials_enrollment_id_fkey',
      columns: [table.enrollmentId],
      foreignColumns: [enrollments.id],
    }).onDelete('restrict'),
    // A code's sessions made by the exchange, ended ones too: its capacity and its tripwire's last hour, never a child.
    index('credentials_enrollment_roots_idx')
      .on(table.enrollmentId, table.createdAt)
      .where(sql`${table.kind} = 'workload' AND ${table.ancestors} IS NULL`),
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

/** 0.15's configuration objects (schema.ts). */
export const logConfig = sqliteTable(
  'log_config',
  {
    name: text().primaryKey(),
    value: text().notNull(),
    seal: bytes('seal'),
  },
  (table) => [
    check('log_config_name_check', sql`${table.name} IN ('policy', 'roles')`),
    check('log_config_value_check', sql`json_valid(${table.value})`),
    check('log_config_seal_check', sql`${table.seal} IS NULL OR octet_length(${table.seal}) = 16`),
  ],
);

/**
 * 0.15's log (schema.ts). SQLite has one writer, so the fence is implicit,
 * and nothing is partitioned: uses and tiles are one table each.
 */
export const logChanges = sqliteTable(
  'log_changes',
  {
    number: int64('number').primaryKey(),
    at: integer({ mode: 'number' }).notNull(),
    requestId: text('request_id').notNull(),
    object: text().notNull(),
    actor: text().notNull(),
    payload: text().notNull(),
    seal: bytes('seal'),
    mac: bytes('mac').notNull(),
  },
  (table) => [
    unique('log_changes_request_id_key').on(table.requestId),
    check('log_changes_seal_check', sql`${table.seal} IS NULL OR octet_length(${table.seal}) = 16`),
    check('log_changes_mac_check', sql`octet_length(${table.mac}) = 16`),
    index('log_changes_object_idx').on(table.object, table.number),
  ],
);

export const logUses = sqliteTable(
  'log_uses',
  {
    number: int64('number').notNull(),
    at: integer({ mode: 'number' }).notNull(),
    requestId: int64('request_id').notNull(),
    credential: text().notNull(),
    secret: text().notNull(),
    purpose: integer().notNull(),
    mac: bytes('mac').notNull(),
    place: text(),
  },
  (table) => [
    check('log_uses_mac_check', sql`octet_length(${table.mac}) = 16`),
    uniqueIndex('log_uses_request_idx').on(table.at, table.requestId),
  ],
);

export const logBulk = sqliteTable(
  'log_bulk',
  {
    principal: text().notNull(),
    secret: text().notNull(),
    last: integer({ mode: 'number' }).notNull(),
  },
  (table) => [primaryKey({ name: 'log_bulk_pkey', columns: [table.principal, table.secret] })],
);

export const logFence = sqliteTable(
  'log_fence',
  {
    onlyRow: flag('only_row').primaryKey().default(true),
    atFloor: integer('at_floor', { mode: 'number' }).notNull(),
  },
  (table) => [check('log_fence_only_row_check', sql`${table.onlyRow}`)],
);

export const logCheckpoints = sqliteTable(
  'log_checkpoints',
  {
    upto: int64('upto').primaryKey(),
    at: integer({ mode: 'number' }).notNull(),
    atFloor: integer('at_floor', { mode: 'number' }).notNull(),
    changesSize: int64('changes_size').notNull(),
    changesRoot: bytes('changes_root').notNull(),
    changesNote: text('changes_note').notNull(),
    usesSize: int64('uses_size').notNull(),
    usesRoot: bytes('uses_root').notNull(),
    usesNote: text('uses_note').notNull(),
  },
  (table) => [
    check('log_checkpoints_changes_root_check', sql`octet_length(${table.changesRoot}) = 32`),
    check('log_checkpoints_uses_root_check', sql`octet_length(${table.usesRoot}) = 32`),
    index('log_checkpoints_floor_idx').on(table.atFloor, table.upto),
  ],
);

export const logTiles = sqliteTable(
  'log_tiles',
  {
    tree: text().notNull(),
    level: integer().notNull(),
    leaf: int64('leaf').notNull(),
    hashes: bytes('hashes').notNull(),
  },
  (table) => [
    primaryKey({ name: 'log_tiles_pkey', columns: [table.tree, table.level, table.leaf] }),
    check('log_tiles_tree_check', sql`${table.tree} IN ('changes', 'uses')`),
    check('log_tiles_level_check', sql`${table.level} BETWEEN 0 AND 7`),
    // 256^8 is past 64 bits: the top level's one tile starts at 0.
    check('log_tiles_leaf_check', sql`${table.leaf} >= 0 AND ((${table.level} = 7 AND ${table.leaf} = 0) OR (${table.level} < 7 AND ${table.leaf} % (1 << (8 * (${table.level} + 1))) = 0))`),
    check('log_tiles_hashes_check', sql`octet_length(${table.hashes}) BETWEEN 32 AND 8192 AND octet_length(${table.hashes}) % 32 = 0`),
  ],
);

export const {
  environmentsRelations,
  secretsRelations,
} = relationsOf(
  asPostgres({ projects, environments, secrets, secretVersions }),
);
