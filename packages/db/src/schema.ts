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
  smallint,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
  type AnyPgColumn,
} from 'drizzle-orm/pg-core';

import { ACTIVE_SUBJECT } from './active-subject.ts';

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

/**
 * The folder a project or a secret is listed in: a folder lists rows
 * together and does nothing else; it grants, hides and renames nothing. A
 * name, not a row of its own: 1 to 64 characters, no `/`, no control
 * character, no space at either end. Null is no folder.
 */
const folderCheck = (name: string, column: AnyPgColumn) =>
  check(name, sql`${column} IS NULL OR (char_length(${column}) BETWEEN 1 AND 64 AND ${column} !~ '[/[:cntrl:]]' AND ${column} = btrim(${column}))`);

export const projects = pgTable(
  'projects',
  {
    id: uuid().primaryKey().defaultRandom(),
    slug: text().notNull(),
    name: text().notNull(),
    createdAt: createdAt(),
    archivedAt: timestamp('archived_at', { withTimezone: true }),
    folder: text(),
  },
  (table) => [
    unique('projects_slug_key').on(table.slug),
    check('projects_slug_check', sql`${table.slug} ~ ${PLACE_SLUG}`),
    folderCheck('projects_folder_check', table.folder),
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
    // The environment it inherits from, in the same project: its keys are
    // this one's, but for those it sets or removes (docs/design/forking.md).
    // Set when it is made and never after, so no chain can loop.
    parentId: uuid('parent_id'),
    // A personal config's owner, `user:<email>`: a fork whose values only they
    // read, the vault binding each to them. Set when it is made and never after.
    owner: text(),
    // Whether it is protected, on 0.15's environment object (0.14 keeps it in
    // the policy's entries). Null until 0.15's cutover writes it.
    protected: boolean(),
    // 0.15's seal (0022_log_015): the vault's MAC over the object this row is part of, HMAC-SHA256 cut to 16
    // bytes, the same seal its newest change in `log_changes` records. Null until the row is sealed.
    seal: bytea(),
  },
  (table) => [
    check('environments_seal_check', sql`${table.seal} IS NULL OR octet_length(${table.seal}) = 16`),
    unique('environments_project_id_slug_key').on(table.projectId, table.slug),
    unique('environments_project_scoped').on(table.id, table.projectId),
    check('environments_slug_check', sql`${table.slug} ~ ${PLACE_SLUG}`),
    // An environment is never its own parent. Longer loops, written around the app, are refused at read (`parentsOf`).
    check('environments_parent_check', sql`${table.parentId} IS NULL OR ${table.parentId} <> ${table.id}`),
    check('environments_owner_check', sql`${table.owner} IS NULL OR (${table.parentId} IS NOT NULL AND ${table.owner} LIKE 'user:_%')`),
    // One personal config per person per environment; a deleted one, a tombstone, holds no place.
    uniqueIndex('environments_parent_id_owner_key').on(table.parentId, table.owner).where(sql`strpos(${table.slug}, '~') = 0`),
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
    // Within its environment: the same key elsewhere has its own.
    folder: text(),
    // 0.15's seal (0022_log_015): the vault's MAC over the object this row is part of, HMAC-SHA256 cut to 16
    // bytes, the same seal its newest change in `log_changes` records. Null until the row is sealed.
    seal: bytea(),
  },
  (table) => [
    check('secrets_seal_check', sql`${table.seal} IS NULL OR octet_length(${table.seal}) = 16`),
    unique('secrets_project_id_environment_id_key_key').on(
      table.projectId,
      table.environmentId,
      table.key,
    ),
    check('secrets_key_check', sql`${table.key} ~ '^[A-Za-z_][A-Za-z0-9_]{0,127}$'`),
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
    // How a client made this value, `bytes:32:hex` (`@coffre/core/recipe`),
    // when it was generated rather than typed: Regenerate makes the next one
    // the same way. Null for a typed value, so writing one by hand clears it.
    recipe: text(),
    // A generated key pair's two versions, written together, share an id,
    // and each says which half it holds: 'private' or 'public'.
    pairId: uuid('pair_id'),
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
    sensitive: boolean().notNull().default(false),
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

/**
 * Keys an environment is missing, which its team decided it does not need:
 * the project's other environments have them, and its missing-keys list
 * leaves them out until someone restores them (docs/design/environments.md).
 * One row per environment and key, updated in place: restoring sets
 * `restored_at`, dismissing again clears it.
 */
export const dismissedKeys = pgTable(
  'dismissed_keys',
  {
    environmentId: uuid('environment_id').notNull(),
    key: text().notNull(),
    dismissedAt: timestamp('dismissed_at', { withTimezone: true }).notNull().defaultNow(),
    dismissedBy: text('dismissed_by').notNull(),
    restoredAt: timestamp('restored_at', { withTimezone: true }),
    restoredBy: text('restored_by'),
  },
  (table) => [
    primaryKey({ name: 'dismissed_keys_pkey', columns: [table.environmentId, table.key] }),
    check('dismissed_keys_key_check', sql`${table.key} ~ '^[A-Za-z_][A-Za-z0-9_]{0,127}$'`),
    foreignKey({
      name: 'dismissed_keys_environment_id_fkey',
      columns: [table.environmentId],
      foreignColumns: [environments.id],
    }).onDelete('restrict'),
  ],
);

/**
 * The vault's member directory: everyone it has admitted, written by the
 * vault alone, read by both. A principal with no row is no member.
 * Principals are the strings coffre uses at its edges: `user:<email>`,
 * `token:<id>`. Times are milliseconds since the epoch, each
 * the time of the vault's log entry that set it, so the log replays to
 * these rows exactly.
 */
export const vaultMembers = pgTable(
  'vault_members',
  {
    principal: text().primaryKey(),
    status: text().notNull(),
    // An owner of 0.4: an Admin, unless `role` says otherwise. Written as
    // whether `role` administers, for a vault of 0.4 to read.
    owner: boolean().notNull().default(false),
    // A person's instance role (`INSTANCE_ROLES` in @coffre/core/access),
    // and where it applies, as JSON (`Scope`, projects by id); null on a row
    // no vault of 0.5 has written, which `owner` says all of.
    role: text(),
    scope: text(),
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
    // 0.15's seal (0022_log_015): the vault's MAC over the object this row is part of, HMAC-SHA256 cut to 16
    // bytes, the same seal its newest change in `log_changes` records. Null until the row is sealed.
    seal: bytea(),
  },
  (table) => [
    check('vault_members_seal_check', sql`${table.seal} IS NULL OR octet_length(${table.seal}) = 16`),
    check('vault_members_mac_check', sql`octet_length(${table.mac}) = 32`),
    check('vault_members_principal_check', sql`${table.principal} ~ '^(user|token):[^[:space:]:][^[:space:]]*$'`),
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
    // A role's id, one that ships or one an Owner made (`ROLE_ID`): which the instance's policy defines, and which of them an
    // environment may be granted, the vault decides, as the policy is now (docs/design/roles.md).
    check('vault_grants_role_check', sql`${table.role} ~ '^[a-z][a-z0-9-]{1,31}$'`),
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
 * longer than any window (`prune_vault_releases`), so a count reads about a
 * day of keys.
 */
export const vaultReleases = pgTable(
  'vault_releases',
  {
    principal: text().notNull(),
    key: text().notNull(),
    releasedAt: bigint('released_at', { mode: 'number' }).notNull(),
  },
  // The key alone is indexed: a read moves its keys' times on in place (a HOT update), leaving no index entry behind,
  // and the count reads the principal's keys from the key, a row each, however often they are read.
  (table) => [primaryKey({ name: 'vault_releases_pkey', columns: [table.principal, table.key] })],
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
    // Who acted: `user:<email>`, `token:<id>` or `system:<name>`.
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
    check('audit_log_actor_check', sql`${table.actor} ~ '^(user|token|system):.+$'`),
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
    // Whether a target is frozen: its newest allowed freeze or lift (docs/design/workload-access.md, section 8.2).
    index('audit_log_freeze_idx')
      .on(sql`((${table.metadata})::jsonb ->> 'target')`, table.seq.desc())
      .where(sql`${table.author} = 'app' AND ${table.action} IN ('workload.freeze', 'workload.unfreeze') AND ${table.decision} = 'allow'`),
    // An enrollment code's tombstone: the app's successful `enrollment.supersede` naming it.
    index('audit_log_supersede_idx')
      .on(sql`((${table.metadata})::jsonb ->> 'enrollmentId')`)
      .where(sql`${table.author} = 'app' AND ${table.action} = 'enrollment.supersede' AND ${table.decision} = 'allow'`),
    // The run a credential was issued for: its exchange's entry, by the credential's ID.
    index('audit_log_exchange_idx')
      .on(sql`((${table.metadata})::jsonb ->> 'credentialId')`)
      .where(sql`${table.author} = 'app' AND ${table.action} = 'token.exchange' AND ${table.decision} = 'allow'`),
    // The token a credential is, when one was issued: its creation's entry, by the credential's ID, whose label names a personal token's entries.
    index('audit_log_token_create_idx')
      .on(sql`((${table.metadata})::jsonb ->> 'targetCredentialId')`)
      .where(sql`${table.author} = 'app' AND ${table.action} = 'token.create' AND ${table.decision} = 'allow'`),
    // Whether a reference has ended: the vault's `reference.end` naming its creation.
    index('audit_log_reference_end_idx')
      .on(table.relatedSeq)
      .where(sql`${table.author} = 'vault' AND ${table.action} = 'reference.end' AND ${table.decision} = 'allow'`),
    // An entry about a reference names the other side, `also` in its
    // metadata, so that it is in both projects' logs: a read through
    // billing's reference is market's read, and billing's too.
    index('audit_log_also_project_idx')
      .on(sql`(((${table.metadata})::jsonb -> 'also') ->> 'projectId')`, table.seq)
      .where(sql`((${table.metadata})::jsonb -> 'also') IS NOT NULL`),
    index('audit_log_also_environment_idx')
      .on(sql`(((${table.metadata})::jsonb -> 'also') ->> 'environmentId')`, table.seq)
      .where(sql`((${table.metadata})::jsonb -> 'also') IS NOT NULL`),
    index('audit_log_also_secret_idx')
      .on(sql`(((${table.metadata})::jsonb -> 'also') ->> 'secretId')`, table.seq)
      .where(sql`((${table.metadata})::jsonb -> 'also') IS NOT NULL`),
  ],
);

/**
 * A reference: a secret whose value is another's, read live through it by
 * whoever reads the holder's environment (docs/design/environments.md).
 * The row only points: the reference is the vault's `reference.create`
 * entry at `created_seq`, which the vault checks at every read, and a
 * `reference.end` naming that entry ends it, whatever this table says. So
 * rows are only ever added.
 */
export const secretReferences = pgTable(
  'secret_references',
  {
    id: uuid().primaryKey(),
    // The holder: billing/prod/DATABASE_URL.
    projectId: uuid('project_id').notNull(),
    environmentId: uuid('environment_id').notNull(),
    secretId: uuid('secret_id').notNull(),
    // The source: market/prod/DATABASE_URL.
    sourceProjectId: uuid('source_project_id').notNull(),
    sourceEnvironmentId: uuid('source_environment_id').notNull(),
    sourceSecretId: uuid('source_secret_id').notNull(),
    createdSeq: bigint('created_seq', { mode: 'bigint' }).notNull(),
    createdAt: createdAt(),
    createdBy: text('created_by').notNull(),
    // 0.15's end of the reference (0028): when its holder stopped reading its source, broken, replaced or cut, written
    // with 0.14's `reference.end` in the vault's decision. The holder's object reads its newest row's source only while
    // this is null. Null on rows 0.14 ended: 0.14's log holds those ends, which the cutover (plan PR 9) writes here.
    endedAt: timestamp('ended_at', { withTimezone: true }),
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
    // A holder's newest reference; what reads its source; what a project lends; what someone made.
    index('secret_references_holder_idx').on(table.secretId, table.createdSeq),
    index('secret_references_source_idx').on(table.sourceSecretId),
    index('secret_references_project_idx').on(table.projectId),
    index('secret_references_source_project_idx').on(table.sourceProjectId),
    index('secret_references_created_by_idx').on(table.createdBy),
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
    // The instance it was made on, its public URL, which its object's seal covers (0040_binding_origin; PR 3b): null on one
    // made before, which is named on the instance's public URL.
    origin: text(),
    label: text(),
    createdAt: createdAt(),
    createdBy: text('created_by').notNull(),
    lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    revokedBy: text('revoked_by'),
    // 0.15's seal (0022_log_015): the vault's MAC over the object this row is part of, HMAC-SHA256 cut to 16
    // bytes, the same seal its newest change in `log_changes` records. Null until the row is sealed.
    seal: bytea(),
  },
  (table) => [
    check('service_bindings_seal_check', sql`${table.seal} IS NULL OR octet_length(${table.seal}) = 16`),
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
 * When a service's capped alert was last raised, by kind: the refusal of a
 * token signed by a key its uploaded keys lack (`unknown_key`) alerts once
 * an hour, however many isolates see it. One conditional write per refusal
 * decides (`claimAlert`), so that the many it caps never reach the log's
 * head. Only a request that a binding of the service on the token's issuer
 * gets as far as its keys writes here: a row per service, at most, per kind.
 */
export const cappedAlerts = pgTable(
  'capped_alerts',
  {
    service: text().notNull(),
    kind: text().notNull(),
    raisedAt: timestamp('raised_at', { withTimezone: true }).notNull(),
  },
  (table) => [primaryKey({ name: 'capped_alerts_pkey', columns: [table.service, table.kind] })],
);

/**
 * MCP clients that registered themselves (RFC 7591), the fallback to Client
 * ID Metadata Documents, which need no row. The ID is the client's
 * `client_id`. Its redirects are under its MAC: a database writer cannot add
 * one of their own to a client people have approved.
 */
export const oauthClients = pgTable(
  'oauth_clients',
  {
    id: uuid().primaryKey(),
    authMac: bytea('auth_mac').notNull(),
    // Its own claim, shown as unverified.
    name: text().notNull(),
    // JSON: a list of HTTPS or loopback URLs.
    redirectUris: text('redirect_uris').notNull(),
    createdAt: createdAt(),
    createdIp: text('created_ip'),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
  },
  (table) => [
    check('oauth_clients_auth_mac_check', sql`octet_length(${table.authMac}) = 32`),
    check('oauth_clients_redirect_uris_check', sql`${table.redirectUris}::jsonb IS NOT NULL`),
  ],
);

/**
 * One MCP client a person connected: one approved authorization, its
 * scopes, its code until the client redeems it, and the refresh token it
 * holds since. Access tokens have no row: each names its connection under a
 * MAC, and every request checks this row. Revoking it ends them all.
 */
export const mcpConnections = pgTable(
  'mcp_connections',
  {
    id: uuid().primaryKey(),
    authMac: bytea('auth_mac').notNull(),
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
    codeHash: bytea('code_hash'),
    codeChallenge: text('code_challenge'),
    codeExpiresAt: timestamp('code_expires_at', { withTimezone: true }),
    // From then on: the refresh token's SHA-256, and the one it replaced, whose reuse ends the connection.
    refreshHash: bytea('refresh_hash'),
    refreshPreviousHash: bytea('refresh_previous_hash'),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    createdAt: createdAt(),
    lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
    lastUsedIp: text('last_used_ip'),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
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
 * page (docs/design/mcp.md, section 7). It holds the tool and its arguments,
 * never a value: the page shows what they would do and, on Approve, does it,
 * once, as the person, through the connection. Its digest is of the tool
 * and arguments, which the page sends back with the decision, so what runs
 * is what the person read. Not MACed: a row changes nothing by itself.
 */
export const mcpApprovals = pgTable(
  'mcp_approvals',
  {
    id: uuid().primaryKey(),
    connectionId: uuid('connection_id').notNull(),
    tool: text().notNull(),
    // JSON: the tool's arguments, as checked when it was called.
    arguments: text().notNull(),
    // SHA-256 of the canonical JSON of the tool and its arguments.
    digest: bytea().notNull(),
    // pending, approved, denied, cancelled or failed; a pending one past its expiry has expired.
    status: text().notNull().default('pending'),
    // JSON: what the change answered, or why it failed. Never a value.
    outcome: text(),
    createdAt: createdAt(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    decidedAt: timestamp('decided_at', { withTimezone: true }),
    // When the client read the outcome: an identical call after that asks again.
    reportedAt: timestamp('reported_at', { withTimezone: true }),
  },
  (table) => [
    check('mcp_approvals_status_check', sql`${table.status} IN ('pending', 'approved', 'denied', 'cancelled', 'failed')`),
    check('mcp_approvals_digest_check', sql`octet_length(${table.digest}) = 32`),
    check('mcp_approvals_arguments_check', sql`${table.arguments}::jsonb IS NOT NULL`),
    foreignKey({
      name: 'mcp_approvals_connection_fkey',
      columns: [table.connectionId],
      foreignColumns: [mcpConnections.id],
    }).onDelete('restrict'),
    // A connection's approvals its client has not yet heard the end of: the ones a call rejoins, and the five it may wait on.
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
export const enrollments = pgTable(
  'enrollments',
  {
    id: uuid().primaryKey(),
    authMac: bytea('auth_mac').notNull(),
    bindingId: uuid('binding_id').notNull(),
    // The SHA-256 of the code, `coffre_enr_…`, and enough of it to recognize.
    codeHash: bytea('code_hash').notNull(),
    codeHint: text('code_hint').notNull(),
    // `CredentialScope`, JSON: what its sessions reach, R32's sensitive per place.
    scope: text().notNull(),
    createdAt: createdAt(),
    // Who minted it, and with which of their credentials: a CI run's session.
    createdBy: text('created_by').notNull(),
    createdWith: uuid('created_with'),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  },
  (table) => [
    unique('enrollments_code_hash_key').on(table.codeHash),
    check('enrollments_auth_mac_check', sql`octet_length(${table.authMac}) = 32`),
    check('enrollments_code_hash_check', sql`octet_length(${table.codeHash}) = 32`),
    check('enrollments_scope_check', sql`${table.scope}::jsonb IS NOT NULL`),
    foreignKey({
      name: 'enrollments_binding_id_fkey',
      columns: [table.bindingId],
      foreignColumns: [serviceBindings.id],
    }).onDelete('restrict'),
    // A binding's codes, newest first, for its page.
    index('enrollments_binding_idx').on(table.bindingId, table.createdAt.desc()),
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
    authMac: bytea('auth_mac').notNull(),
    tokenHash: bytea('token_hash').notNull(),
    tokenHint: text('token_hint').notNull(),
    generation: integer().notNull(),
    // The member it acts as, `user:<email>` or `token:<id>`, under the generation it was issued in.
    principal: text().notNull(),
    identityId: uuid('identity_id'),
    // What a service or personal token reaches (`CredentialScope`), JSON: null for a session, one a binding issued (its binding's), or one of 0.4 the app has not sealed yet.
    scope: text(),
    // The environments a handle was made for, by id, each with whether it was asked for as `@me`, JSON: null for any other credential, or a handle of 0.8.
    places: text(),
    label: text(),
    createdAt: createdAt(),
    createdBy: text('created_by').notNull(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
    lastUsedIp: text('last_used_ip'),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    revokedBy: text('revoked_by'),
    // A workload's session (docs/design/workload-access.md, section 11), null on every other credential:
    // the thumbprint of the key its proofs are signed by, and its hard end.
    jkt: text(),
    notAfter: timestamp('not_after', { withTimezone: true }),
    // A `narrow` child's: its ancestors' IDs, root first, JSON, and its limits (`Constraints`), canonical JSON.
    ancestors: text(),
    constraints: text(),
    // The enrollment code a session was made from, and, where its binding says `approve`, who approved it.
    enrollmentId: uuid('enrollment_id'),
    approvedAt: timestamp('approved_at', { withTimezone: true }),
    approvedBy: text('approved_by'),
    // 0.15's seal (0022_log_015): the vault's MAC over the object this row is part of, HMAC-SHA256 cut to 16
    // bytes, the same seal its newest change in `log_changes` records. Null until the row is sealed.
    seal: bytea(),
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

/**
 * 0.15's configuration objects (0022_log_015): decision inputs no other row
 * holds, one row each, sealed as every input is. `policy` holds the bulk
 * cap's count and window, which a use reads in its own statement; `roles`
 * the role tables. JSON, as the vault writes it. Written only through
 * `change_input`.
 */
export const logConfig = pgTable(
  'log_config',
  {
    name: text().primaryKey(),
    value: text().notNull(),
    seal: bytea(),
  },
  (table) => [
    check('log_config_name_check', sql`${table.name} IN ('policy', 'roles')`),
    check('log_config_value_check', sql`${table.value}::jsonb IS NOT NULL`),
    check('log_config_seal_check', sql`${table.seal} IS NULL OR octet_length(${table.seal}) = 16`),
  ],
);

/**
 * 0.15's log (0022_log_015, docs/design/hot-path-one.md): two tables numbered
 * from one sequence, `log_number`, each number taken under the fence's lock
 * (a credential's issue: under the issue lock, which the barrier waits for;
 * 0026), so that the number alone orders uses against changes. Nothing reads or
 * writes them before 0.15's vault; the vault login reads them and writes
 * them only through the migration's functions.
 *
 * A change: any write to a decision input, or to configuration, kept for
 * good. `object` is the input it changes (`log_object(kind, id)`), `seal`
 * that object's seal after it, `payload` what it does. The MAC is the
 * vault's, HMAC-SHA256 cut to 16 bytes, over everything but the number,
 * which the vault does not know when it asks.
 */
export const logChanges = pgTable(
  'log_changes',
  {
    number: bigint({ mode: 'bigint' }).primaryKey(),
    // Milliseconds since the epoch, the vault's clock when it asked.
    at: bigint({ mode: 'number' }).notNull(),
    // A request id names one change: a retry finds its entry.
    requestId: text('request_id').notNull(),
    object: uuid().notNull(),
    actor: text().notNull(),
    payload: text().notNull(),
    seal: bytea(),
    mac: bytea().notNull(),
  },
  (table) => [
    unique('log_changes_request_id_key').on(table.requestId),
    check('log_changes_seal_check', sql`${table.seal} IS NULL OR octet_length(${table.seal}) = 16`),
    check('log_changes_mac_check', sql`octet_length(${table.mac}) = 16`),
    // Each input's newest change, its seal from the index alone (INCLUDE (seal), in the migration's SQL: Drizzle
    // has no INCLUDE): one probe per input.
    index('log_changes_object_idx').on(table.object, table.number),
  ],
);

/**
 * A use, the slim row (R53): no principal (the credential's), no
 * environment (the secret's, or `place`), no kind (the table says it).
 * Partitioned by the day of `at` (`make_day`), which retention drops whole;
 * fixed-width columns first, and eight of them, so the row pads to nothing. One index, the
 * replay's: a retried call repeats its `at` and request id, both under its
 * MAC, and lands in the same day.
 */
export const logUses = pgTable(
  'log_uses',
  {
    number: bigint({ mode: 'bigint' }).notNull(),
    at: bigint({ mode: 'number' }).notNull(),
    // Random, unique within its millisecond.
    requestId: bigint('request_id', { mode: 'bigint' }).notNull(),
    credential: uuid().notNull(),
    secret: uuid().notNull(),
    // What the use was for, as @coffre/vault codes it (a use, a reveal…), plus 256 when it may keep a sensitive value:
    // one column, so that the row has eight and its null bitmap fits the header's padding (8 B a use, measured).
    purpose: smallint().notNull(),
    mac: bytea().notNull(),
    // The environment it was asked at, when not the secret's own (a fork, a reference).
    place: uuid(),
  },
  (table) => [
    check('log_uses_mac_check', sql`octet_length(${table.mac}) = 16`),
    uniqueIndex('log_uses_request_idx').on(table.at, table.requestId),
  ],
);

/**
 * The bulk cap (R28, R52): each principal's last logged use of each key, as
 * the start of that use's refresh period, written only by a use that holds
 * the principal's lock (exclusive to enter a key, shared to move it on:
 * 0028), at most once per refresh per key. A row older than the window, a
 * refresh, the deadline and a minute counts for nothing; `prune_bulk`
 * forgets it an hour after that.
 */
export const logBulk = pgTable(
  'log_bulk',
  {
    principal: text().notNull(),
    secret: uuid().notNull(),
    last: bigint({ mode: 'number' }).notNull(),
  },
  (table) => [primaryKey({ name: 'log_bulk_pkey', columns: [table.principal, table.secret] })],
);

/**
 * The fence's one row: the lowest `at` a use may still be written with,
 * raised by each checkpoint's barrier (`close_one`), never lowered. Made
 * by the migration; without it every use is refused.
 */
export const logFence = pgTable(
  'log_fence',
  {
    onlyRow: boolean('only_row').primaryKey().default(true),
    atFloor: bigint('at_floor', { mode: 'number' }).notNull(),
  },
  (table) => [check('log_fence_only_row_check', sql`${table.onlyRow}`)],
);

/**
 * A signed checkpoint: the pair of tree heads (W212), changes and uses, at
 * one `upto`, every number at or below which is final. One row, so that no
 * state holds one head without the other. `at_floor` is the floor its
 * barrier set: the next window's uses have an `at` at or above it.
 */
export const logCheckpoints = pgTable(
  'log_checkpoints',
  {
    upto: bigint({ mode: 'bigint' }).primaryKey(),
    at: bigint({ mode: 'number' }).notNull(),
    atFloor: bigint('at_floor', { mode: 'number' }).notNull(),
    changesSize: bigint('changes_size', { mode: 'bigint' }).notNull(),
    changesRoot: bytea('changes_root').notNull(),
    // The signed note (C2SP tlog-checkpoint), as witnesses get it.
    changesNote: text('changes_note').notNull(),
    usesSize: bigint('uses_size', { mode: 'bigint' }).notNull(),
    usesRoot: bytea('uses_root').notNull(),
    usesNote: text('uses_note').notNull(),
  },
  (table) => [
    check('log_checkpoints_changes_root_check', sql`octet_length(${table.changesRoot}) = 32`),
    check('log_checkpoints_uses_root_check', sql`octet_length(${table.usesRoot}) = 32`),
    // A day's retention cut, the first checkpoint whose floor is past the day's end (migration 0027).
    index('log_checkpoints_floor_idx').on(table.atFloor, table.upto),
  ],
);

/**
 * The two trees' tiles (C2SP tlog-tiles: height 8, up to 256 hashes of one
 * level). Partitioned by tree; the uses tree's leaf tiles (level 0) by
 * `leaf`, the first leaf a tile covers (`make_tiles`), so that retention
 * drops a table rather than deleting a day's rows (W212); its levels above,
 * which span far past their first leaf, in one table (W217).
 */
export const logTiles = pgTable(
  'log_tiles',
  {
    tree: text().notNull(),
    level: smallint().notNull(),
    // idx · 256^(level + 1): a tile's place, in its tree's leaves.
    leaf: bigint({ mode: 'bigint' }).notNull(),
    hashes: bytea().notNull(),
  },
  (table) => [
    primaryKey({ name: 'log_tiles_pkey', columns: [table.tree, table.level, table.leaf] }),
    check('log_tiles_tree_check', sql`${table.tree} IN ('changes', 'uses')`),
    check('log_tiles_level_check', sql`${table.level} BETWEEN 0 AND 7`),
    check('log_tiles_leaf_check', sql`${table.leaf} >= 0 AND ${table.leaf} % (256::numeric ^ (${table.level} + 1)) = 0`),
    check('log_tiles_hashes_check', sql`octet_length(${table.hashes}) BETWEEN 32 AND 8192 AND octet_length(${table.hashes}) % 32 = 0`),
  ],
);
