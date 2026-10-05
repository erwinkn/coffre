import { assignableToEnvironment, ROLE_NAMES } from '@coffre/core/access';
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

import { ACTIVE_SUBJECT, relationsOf } from './relations.ts';

const bytea = customType<{ data: Buffer }>({
  dataType: () => 'bytea',
});

const createdAt = () => timestamp('created_at', { withTimezone: true }).notNull().defaultNow();

/**
 * A project's or environment's slug: `market`, or once deleted, its
 * tombstone's, `market~deleted-2026-10-05`. No live slug holds a `~`, so a
 * tombstone frees its slug and is never mistaken for what takes it next.
 */
const PLACE_SLUG = sql.raw(`'^[a-z0-9][a-z0-9-]{0,62}(~[a-z0-9-]{1,40})?$'`);

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
    check('projects_slug_check', sql`${table.slug} ~ ${PLACE_SLUG}`),
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
    check('environments_slug_check', sql`${table.slug} ~ ${PLACE_SLUG}`),
    foreignKey({
      name: 'environments_project_id_fkey',
      columns: [table.projectId],
      foreignColumns: [projects.id],
    }).onDelete('restrict'),
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
    // The number of the current version, 0 before the first. Versions only
    // append, so it is also the highest: the next one is this plus one.
    currentVersion: integer('current_version').notNull().default(0),
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

/** The role catalogue, as SQL: every role, and those an environment may be granted. */
const ROLES = sql.raw(ROLE_NAMES.map((role) => `'${role}'`).join(', '));
const ENVIRONMENT_ROLES = sql.raw(ROLE_NAMES.filter(assignableToEnvironment).map((role) => `'${role}'`).join(', '));

/**
 * The vault's member directory: everyone it has admitted, written by the
 * vault alone, read by both. A principal with no row is no member.
 * Principals are the strings coffre uses at its edges: `user:<email>`,
 * `token:<id>`, `sync:<id>`. Times are milliseconds since the epoch, each
 * the time of the vault's log entry that set it, so the log replays to
 * these rows exactly.
 */
export const vaultMembers = pgTable(
  'vault_members',
  {
    principal: text().primaryKey(),
    status: text().notNull(),
    // An instance owner, who manages every project and member. Root admins
    // come from the vault's configuration, never from a row.
    owner: boolean().notNull().default(false),
    // Advanced by each removal. A session, token or linked account issued
    // under an older generation is dead, whatever its own row says.
    generation: integer().notNull().default(0),
    createdAt: bigint('created_at', { mode: 'number' }).notNull(),
    createdBy: text('created_by').notNull(),
    statusChangedAt: bigint('status_changed_at', { mode: 'number' }).notNull(),
    statusChangedBy: text('status_changed_by').notNull(),
    // The vault's last access entry about the member: a row put back from
    // before a later change names an older one than the log has.
    accessSeq: bigint('access_seq', { mode: 'bigint' }).notNull(),
    // The vault's MAC over the row and the member's grants, lapsed ones too:
    // a grant added, edited or deleted outside the vault fails it.
    mac: bytea().notNull(),
  },
  (table) => [
    check('vault_members_mac_check', sql`octet_length(${table.mac}) = 32`),
    check('vault_members_principal_check', sql`${table.principal} ~ '^(user|token|sync):[^[:space:]:][^[:space:]]*$'`),
    // A person is their email address, lowercased, as in sign-in.
    check('vault_members_user_lowercase', sql`${table.principal} NOT LIKE 'user:%' OR ${table.principal} = lower(${table.principal})`),
    check('vault_members_status_check', sql`${table.status} IN ('active', 'removed')`),
    check('vault_members_owner_check', sql`NOT ${table.owner} OR (${table.status} = 'active' AND ${table.principal} LIKE 'user:%')`),
    check('vault_members_generation_check', sql`${table.generation} >= 0`),
  ],
);

/**
 * One role per member per place: a project, one of its environments, every
 * project (`*`, neither id), or the environment of one slug in every project
 * (neither id, and `environment_slug`). A revoked grant is deleted; an
 * expired one stays until its place is granted again, so the members page
 * can say it lapsed.
 */
export const vaultGrants = pgTable(
  'vault_grants',
  {
    principal: text().notNull(),
    projectId: uuid('project_id'),
    environmentId: uuid('environment_id'),
    environmentSlug: text('environment_slug'),
    role: text().notNull(),
    expiresAt: bigint('expires_at', { mode: 'number' }),
    grantedAt: bigint('granted_at', { mode: 'number' }).notNull(),
    grantedBy: text('granted_by').notNull(),
  },
  (table) => [
    check(
      'vault_grants_one_place',
      sql`((${table.projectId} IS NULL) <> (${table.environmentId} IS NULL) AND ${table.environmentSlug} IS NULL) OR (${table.projectId} IS NULL AND ${table.environmentId} IS NULL)`,
    ),
    check('vault_grants_environment_slug_check', sql`${table.environmentSlug} IS NULL OR ${table.environmentSlug} ~ '^[a-z0-9][a-z0-9-]{0,62}$'`),
    check('vault_grants_role_check', sql`${table.role} IN (${ROLES})`),
    check(
      'vault_grants_environment_role_check',
      sql`(${table.environmentId} IS NULL AND ${table.environmentSlug} IS NULL) OR ${table.role} IN (${ENVIRONMENT_ROLES})`,
    ),
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

export const auditLog = pgTable(
  'audit_log',
  {
    seq: bigint({ mode: 'bigint' }).primaryKey(),
    // Which component wrote the entry, under which of its keys; see
    // @coffre/core/audit for what its MAC and hash cover.
    author: text().notNull(),
    keyId: text('key_id').notNull(),
    // Milliseconds since the epoch, from the database's clock, read after the
    // append took the head's lock.
    occurredAt: bigint('occurred_at', { mode: 'number' }).notNull(),
    // Who acted: `user:<email>`, `token:<id>`, `sync:<id>` or `system:<name>`.
    actor: text().notNull(),
    action: text().notNull(),
    decision: text().notNull(),
    code: text(),
    // The member an access change is about.
    subjectPrincipal: text('subject_principal'),
    projectId: uuid('project_id'),
    environmentId: uuid('environment_id'),
    secretId: uuid('secret_id'),
    secretVersionId: uuid('secret_version_id'),
    // One id for everything one action did: a reveal's keys, a write's versions.
    operationId: uuid('operation_id'),
    requestId: text('request_id'),
    sourceIp: text('source_ip'),
    // An earlier entry this one follows from, such as the wrap behind a write.
    relatedSeq: bigint('related_seq', { mode: 'bigint' }),
    metadata: text().notNull().default('{}'),
    prevHash: bytea('prev_hash').notNull(),
    mac: bytea().notNull(),
    hash: bytea().notNull(),
  },
  (table) => [
    check('audit_log_author_check', sql`${table.author} IN ('app', 'vault')`),
    check('audit_log_actor_check', sql`${table.actor} ~ '^(user|token|sync|system):.+$'`),
    check('audit_log_decision_check', sql`${table.decision} IN ('allow', 'deny')`),
    check('audit_log_metadata_check', sql`${table.metadata}::jsonb IS NOT NULL`),
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
    // The bulk limit: one reader's recent releases.
    index('audit_log_releases_idx').on(table.author, table.actor, table.action, table.decision, table.occurredAt),
    // What the vault logged about one member, in order.
    index('audit_log_subject_idx').on(table.author, table.subjectPrincipal, table.seq),
    // A binding's tombstone: the app's successful `token.unbind` naming it.
    index('audit_log_unbind_idx')
      .on(sql`((${table.metadata})::jsonb ->> 'bindingId')`)
      .where(sql`${table.author} = 'app' AND ${table.action} = 'token.unbind' AND ${table.decision} = 'allow'`),
    // The run a credential was issued for: its exchange's entry, by the credential's ID.
    index('audit_log_exchange_idx')
      .on(sql`((${table.metadata})::jsonb ->> 'credentialId')`)
      .where(sql`${table.author} = 'app' AND ${table.action} = 'token.exchange' AND ${table.decision} = 'allow'`),
  ],
);

export const auditChainHead = pgTable(
  'audit_chain_head',
  {
    onlyRow: boolean('only_row').primaryKey().default(true),
    nextSeq: bigint('next_seq', { mode: 'bigint' }).notNull().default(sql`0`),
    headHash: bytea('head_hash').notNull(),
  },
  (table) => [
    check('audit_chain_head_only_row_check', sql`${table.onlyRow}`),
    check('audit_chain_head_next_seq_check', sql`${table.nextSeq} >= 0`),
    check('audit_chain_head_head_hash_check', sql`octet_length(${table.headHash}) = 32`),
  ],
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
    authMac: bytea('auth_mac').notNull(),
    subject: text().notNull(),
    issuerHash: text('issuer_hash').notNull(),
    generation: integer().notNull(),
    // The member it signs in as, `user:<email>`, under the generation it was bound in.
    principal: text().notNull(),
    email: text(),
    createdAt: createdAt(),
    createdBy: text('created_by').notNull(),
    lastSignInAt: timestamp('last_sign_in_at', { withTimezone: true }),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    revokedBy: text('revoked_by'),
    activeSubject: text('active_subject').generatedAlwaysAs(ACTIVE_SUBJECT),
  },
  (table) => [
    check('identities_principal_check', sql`${table.principal} LIKE 'user:%'`),
    check('identities_provider_check', sql`${table.provider} ~ '^[a-z0-9][a-z0-9-]{0,31}$'`),
    check('identities_auth_mac_check', sql`octet_length(${table.authMac}) = 32`),
    unique('identities_member_generation_key').on(table.id, table.principal, table.generation),
    foreignKey({
      name: 'identities_principal_fkey',
      columns: [table.principal],
      foreignColumns: [vaultMembers.principal],
    }).onDelete('restrict'),
    // An account is bound to one person at a time: the subject counts only
    // while the identity is not revoked (see ACTIVE_SUBJECT).
    uniqueIndex('identities_active_subject').on(table.provider, table.issuerHash, table.activeSubject),
    index('identities_principal_idx').on(table.principal, table.generation),
  ],
);

/**
 * A trust binding: which CI runs may sign in as a service, by the ID token
 * their platform signs (`@coffre/core/identity`'s workloads.ts). Immutable
 * but for its label, last use and revocation: a change is a new binding, and
 * the old one's `token.unbind` entry is its tombstone, which outlives any
 * row put back. The MAC covers what decides (auth-rows.ts in the server).
 */
export const serviceBindings = pgTable(
  'service_bindings',
  {
    id: uuid().primaryKey(),
    authMac: bytea('auth_mac').notNull(),
    // The service it signs in as, `token:<id>`, under the generation it was bound in.
    principal: text().notNull(),
    generation: integer().notNull(),
    profile: text().notNull(),
    issuer: text().notNull(),
    // From the issuer's discovery when the binding was made, never refetched.
    jwksUri: text('jwks_uri').notNull(),
    // JSON, sorted by claim name.
    claims: text().notNull(),
    label: text(),
    createdAt: createdAt(),
    createdBy: text('created_by').notNull(),
    lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    revokedBy: text('revoked_by'),
  },
  (table) => [
    check('service_bindings_principal_check', sql`${table.principal} LIKE 'token:%'`),
    check('service_bindings_auth_mac_check', sql`octet_length(${table.authMac}) = 32`),
    check('service_bindings_claims_check', sql`${table.claims}::jsonb IS NOT NULL`),
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

/**
 * ID tokens exchanged for a credential, each once: the SHA-256 of what its
 * signature covers, `header.payload` as received, so that no other
 * spelling of the same token counts as another. Kept whatever becomes of
 * the credential it bought; the primary key decides a race.
 */
export const consumedTokens = pgTable(
  'consumed_tokens',
  {
    hash: bytea('hash').primaryKey(),
    consumedAt: timestamp('consumed_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [check('consumed_tokens_hash_check', sql`octet_length(${table.hash}) = 32`)],
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
    authMac: bytea('auth_mac').notNull(),
    tokenHash: bytea('token_hash').notNull(),
    tokenHint: text('token_hint').notNull(),
    generation: integer().notNull(),
    // The member it acts as, `user:<email>` or `token:<id>`, under the generation it was issued in.
    principal: text().notNull(),
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
    // A member's credentials still live, however many have expired: a CI run
    // leaves one behind each time it signs in.
    index('credentials_live_idx').on(table.principal, table.expiresAt).where(sql`${table.revokedAt} IS NULL`),
    // What a trust binding issued lately, for its rate.
    index('credentials_issued_by_idx').on(table.principal, table.createdBy, table.createdAt),
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
    authMac: bytea('auth_mac').notNull(),
    userCode: text('user_code').notNull(),
    clientLabel: text('client_label'),
    clientIp: text('client_ip'),
    createdAt: createdAt(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    decidedAt: timestamp('decided_at', { withTimezone: true }),
    decision: text(),
    generation: integer().notNull().default(0),
    // Who approved it, `user:<email>`, once approved.
    principal: text(),
    consumedAt: timestamp('consumed_at', { withTimezone: true }),
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

// For Drizzle's relational queries; see relations.ts.
export const {
  environmentsRelations,
  secretsRelations,
} = relationsOf({ projects, environments, secrets, secretVersions });
