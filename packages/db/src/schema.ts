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

import { ACTIVE_SUBJECT, relationsOf } from './relations.ts';

/**
 * 0.16's schema (docs/design/0.16.md). Three rules hold across it.
 *
 * The vault's login writes every table, and the app's only reads.
 *
 * A row that turns into access carries the vault's MAC, `mac`: four bytes
 * that name the key, then an HMAC-SHA256 over the table's name, the row's
 * key and every other column but the ones that only say when a row was
 * last used (`last_used_at`, `last_used_ip`), which a use moves without a
 * change. An empty MAC verifies under no key: it is what
 * the upgrade from 0.14 leaves until the vault adopts the rows.
 *
 * Every time is a `timestamptz(3)`, milliseconds, so that a row reads back
 * from the database exactly as the vault wrote it. The vault supplies each
 * one: a row's MAC covers it, and the database's clock is not the vault's.
 */

const bytea = customType<{ data: Buffer }>({
  dataType: () => 'bytea',
});

const at = (name: string) => timestamp(name, { withTimezone: true, precision: 3 });

const mac = () => bytea().notNull().default(sql`'\\x'::bytea`);

/** A MAC is empty, or a key's four bytes and 32 of HMAC. */
const macCheck = (name: string, column: AnyPgColumn) => check(name, sql`octet_length(${column}) IN (0, 36)`);

/**
 * A project's or environment's slug: `market`, or once deleted, its
 * tombstone's, `market~deleted-2026-10-05`. No live slug holds a `~`, so a
 * tombstone frees its slug and is never mistaken for what takes it next.
 */
const PLACE_SLUG = sql.raw(`'^[a-z0-9][a-z0-9-]{0,62}(~[a-z0-9-]{1,40})?$'`);

/** A role's id, one that ships or one an Owner made (`ROLE_ID` in @coffre/core/access). */
const ROLE_ID = sql.raw(`'^[a-z][a-z0-9-]{1,31}$'`);

/**
 * The folder a project or a secret is listed in: a folder lists rows
 * together and does nothing else; it grants, hides and renames nothing. A
 * name, not a row of its own: 1 to 64 characters, no `/`, no control
 * character, no space at either end. Null is no folder.
 */
const folderCheck = (name: string, column: AnyPgColumn) =>
  check(name, sql`${column} IS NULL OR (char_length(${column}) BETWEEN 1 AND 64 AND ${column} !~ '[/[:cntrl:]]' AND ${column} = btrim(${column}))`);

// ---------------------------------------------------------------- Secrets

/**
 * Under a MAC for its slug: a request names a project by it, and a grant by
 * its id. With none, a database writer could swap two projects' slugs, and
 * whoever holds both would be handed one's values under the other's name.
 */
export const projects = pgTable(
  'projects',
  {
    id: uuid().primaryKey(),
    slug: text().notNull(),
    name: text().notNull(),
    createdAt: at('created_at').notNull(),
    archivedAt: at('archived_at'),
    folder: text(),
    mac: mac(),
  },
  (table) => [
    unique('projects_slug_key').on(table.slug),
    check('projects_slug_check', sql`${table.slug} ~ ${PLACE_SLUG}`),
    folderCheck('projects_folder_check', table.folder),
    macCheck('projects_mac_check', table.mac),
  ],
);

export const environments = pgTable(
  'environments',
  {
    id: uuid().primaryKey(),
    projectId: uuid('project_id').notNull(),
    slug: text().notNull(),
    name: text().notNull(),
    createdAt: at('created_at').notNull(),
    archivedAt: at('archived_at'),
    // The environment it inherits from, in the same project: its keys are
    // this one's, but for those it sets or removes (docs/design/forking.md).
    // Set when it is made and never after, so no chain can loop.
    parentId: uuid('parent_id'),
    // A personal config's owner, `user:<email>`: a fork whose values only they
    // read. Set when it is made and never after.
    owner: text(),
    // What restricts an environment lives in its row, so that deleting a row
    // only ever removes access: whether it is protected, and the upstream
    // credentials frozen in it, by name (docs/design/workload-access.md, section 8.2).
    protected: boolean().notNull(),
    frozenCredentials: text('frozen_credentials').array().notNull(),
    mac: mac(),
  },
  (table) => [
    unique('environments_project_id_slug_key').on(table.projectId, table.slug),
    unique('environments_project_scoped').on(table.id, table.projectId),
    check('environments_slug_check', sql`${table.slug} ~ ${PLACE_SLUG}`),
    // An environment is never its own parent. Longer loops, written around the vault, are refused at read.
    check('environments_parent_check', sql`${table.parentId} IS NULL OR ${table.parentId} <> ${table.id}`),
    check('environments_owner_check', sql`${table.owner} IS NULL OR (${table.parentId} IS NOT NULL AND ${table.owner} LIKE 'user:_%')`),
    macCheck('environments_mac_check', table.mac),
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
    id: uuid().primaryKey(),
    projectId: uuid('project_id').notNull(),
    environmentId: uuid('environment_id').notNull(),
    key: text().notNull(),
    createdAt: at('created_at').notNull(),
    updatedAt: at('updated_at').notNull(),
    // How many versions it has had: the newest's number, 0 before the first.
    // Versions only append, so the next one is this plus one. Under the MAC, so
    // that a number is never used twice, whatever becomes of the versions' rows.
    versions: integer().notNull(),
    // The version that is its value: the newest, or none. A reference has
    // none of its own, and neither does a secret whose reference ended, until
    // someone writes it a value: what it held before it pointed elsewhere was
    // replaced, and stays history.
    currentVersion: integer('current_version'),
    archivedAt: at('archived_at'),
    // Within its environment: the same key elsewhere has its own.
    folder: text(),
    // A reference: the secret whose value this one's is, read live through it
    // by whoever reads this one's environment (docs/design/environments.md).
    sourceId: uuid('source_id'),
    // How its current value is kept: 'plain', 'secret' or 'sensitive'. Null
    // when it has no value of its own. Here, under the MAC, so that a change
    // reads it: its version's row says it too, as its encryption names it.
    nature: text({ enum: ['plain', 'secret', 'sensitive'] }),
    // How a client made its current value, `bytes:32:hex`
    // (`@coffre/core/recipe`), when it was generated rather than typed:
    // Regenerate makes the next one the same way. Null for a typed value, so
    // writing one by hand clears it. Under the MAC: a writer who could edit
    // it could have the next value made one byte long.
    recipe: text(),
    // A generated key pair's two keys, written together, share an id, and
    // each says which half it holds: 'private' or 'public'.
    pairId: uuid('pair_id'),
    pairHalf: text('pair_half'),
    mac: mac(),
  },
  (table) => [
    unique('secrets_project_id_environment_id_key_key').on(table.projectId, table.environmentId, table.key),
    check('secrets_key_check', sql`${table.key} ~ '^[A-Za-z_][A-Za-z0-9_]{0,127}$'`),
    check('secrets_versions_check', sql`${table.versions} >= 0 AND (${table.currentVersion} IS NULL OR (${table.currentVersion} = ${table.versions} AND ${table.versions} > 0))`),
    check('secrets_source_check', sql`${table.sourceId} IS NULL OR (${table.sourceId} <> ${table.id} AND ${table.currentVersion} IS NULL)`),
    check('secrets_nature_check', sql`(${table.nature} IS NULL) = (${table.currentVersion} IS NULL) AND (${table.nature} IS NULL OR ${table.nature} IN ('plain', 'secret', 'sensitive'))`),
    check('secrets_recipe_check', sql`(${table.recipe} IS NULL AND ${table.pairId} IS NULL) OR ${table.currentVersion} IS NOT NULL`),
    check('secrets_pair_check', sql`(${table.pairId} IS NULL) = (${table.pairHalf} IS NULL) AND (${table.pairHalf} IS NULL OR ${table.pairHalf} IN ('private', 'public'))`),
    folderCheck('secrets_folder_check', table.folder),
    macCheck('secrets_mac_check', table.mac),
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
    foreignKey({
      name: 'secrets_source_id_fkey',
      columns: [table.sourceId],
      foreignColumns: [table.id],
    }).onDelete('restrict'),
    // What reads a secret through a reference: its key's page, and who a new value reaches.
    index('secrets_source_idx').on(table.sourceId).where(sql`${table.sourceId} IS NOT NULL`),
  ],
);

/** No MAC: a version's encryption names its secret, its number and whether it is plain or sensitive, so one moved or relabelled does not open (docs/design/0.16.md, "Value encryption", which says what that leaves unbound). */
export const secretVersions = pgTable(
  'secret_versions',
  {
    id: uuid().primaryKey(),
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
    createdAt: at('created_at').notNull(),
    createdBy: text('created_by').notNull(),
    // When its value was first written to its key: the version's own date, or
    // for a restore its source's, so a restore of a restore keeps the first.
    // What the member report holds each person's last sight of the key to: Bo
    // saw it on day 11, version 4 restores version 1, written on day 1, so
    // Bo knows the value. A copy for the pages, under no MAC, as `plaintext`:
    // no decision reads it.
    firstWrittenAt: at('first_written_at').notNull(),
    // The value itself, for a plain one: a key marked not secret, an account's
    // id, which whoever lists the environment sees. Null for a secret. A copy
    // for the pages, under no MAC: a use opens the ciphertext, never this.
    plaintext: text(),
    // A sensitive value: never handed back to a person, Owners included, only
    // used for them through the credential proxy, or read by a service
    // account. Never plain too.
    sensitive: boolean().notNull(),
  },
  (table) => [
    unique('secret_versions_secret_id_version_key').on(table.secretId, table.version),
    check('secret_versions_version_check', sql`${table.version} > 0`),
    check('secret_versions_iv_check', sql`octet_length(${table.iv}) = 12`),
    check('secret_versions_auth_tag_check', sql`octet_length(${table.authTag}) = 16`),
    check('secret_versions_plain_check', sql`${table.plaintext} IS NULL OR NOT ${table.sensitive}`),
    foreignKey({
      name: 'secret_versions_secret_id_fkey',
      columns: [table.secretId],
      foreignColumns: [secrets.id],
    }).onDelete('restrict'),
    // The versions someone wrote, from their own rows: what the member report asks of a member's writes.
    index('secret_versions_created_by_idx').on(table.createdBy, table.secretId),
  ],
);

/**
 * Keys an environment is missing, which its team decided it does not need:
 * the project's other environments have them, and its missing-keys list
 * leaves them out until someone restores them (docs/design/environments.md).
 * One row per environment and key, updated in place: restoring sets
 * `restored_at`, dismissing again clears it. Under a MAC: a fork that
 * dismissed a key does not inherit it, so a row decides what a use of the
 * fork is given.
 */
export const dismissedKeys = pgTable(
  'dismissed_keys',
  {
    environmentId: uuid('environment_id').notNull(),
    key: text().notNull(),
    dismissedAt: at('dismissed_at').notNull(),
    dismissedBy: text('dismissed_by').notNull(),
    restoredAt: at('restored_at'),
    restoredBy: text('restored_by'),
    mac: mac(),
  },
  (table) => [
    primaryKey({ name: 'dismissed_keys_pkey', columns: [table.environmentId, table.key] }),
    macCheck('dismissed_keys_mac_check', table.mac),
    check('dismissed_keys_key_check', sql`${table.key} ~ '^[A-Za-z_][A-Za-z0-9_]{0,127}$'`),
    foreignKey({
      name: 'dismissed_keys_environment_id_fkey',
      columns: [table.environmentId],
      foreignColumns: [environments.id],
    }).onDelete('restrict'),
  ],
);

// ----------------------------------------------------------------- Access

/**
 * Everyone the vault has admitted: a person, `user:<email>`, or a service
 * account, `token:<name>`. A principal with no row is no member, and a row
 * is never deleted: a removal says so in it.
 */
export const principals = pgTable(
  'principals',
  {
    id: text().primaryKey(),
    status: text().notNull(),
    // The instance role (`INSTANCE_ROLES` in @coffre/core/access) and where it applies, JSON (`Scope`, projects by id); null is everywhere.
    role: text().notNull(),
    scope: text(),
    // Advanced by each removal. A session, token or linked account issued
    // under an older generation is dead, whatever its own row says: removing
    // someone is to write their row and their accounts', which a unique
    // index would otherwise hold for good, however much else they hold.
    generation: integer().notNull(),
    createdAt: at('created_at').notNull(),
    createdBy: text('created_by').notNull(),
    statusChangedAt: at('status_changed_at').notNull(),
    statusChangedBy: text('status_changed_by').notNull(),
    // A service account whose every workload use is refused until the freeze is lifted (docs/design/workload-access.md, section 8.2).
    frozenAt: at('frozen_at'),
    mac: mac(),
  },
  (table) => [
    check('principals_id_check', sql`${table.id} ~ '^(user|token):[^[:space:]:][^[:space:]]*$'`),
    // A person is their email address, lowercased, as in sign-in.
    check('principals_user_lowercase', sql`${table.id} NOT LIKE 'user:%' OR ${table.id} = lower(${table.id})`),
    check('principals_status_check', sql`${table.status} IN ('active', 'removed')`),
    check('principals_role_check', sql`${table.role} ~ ${ROLE_ID}`),
    check('principals_generation_check', sql`${table.generation} >= 0`),
    check('principals_frozen_check', sql`${table.frozenAt} IS NULL OR ${table.id} LIKE 'token:%'`),
    macCheck('principals_mac_check', table.mac),
    // The active service accounts, found without reading a person's row: under a collation other than C, the primary key cannot find a prefix.
    index('principals_services_idx').on(table.id).where(sql`${table.status} = 'active' AND ${table.id} LIKE 'token:%'`),
  ],
);

/**
 * One role per principal per place: a project, or one of its environments,
 * which names only the environment. A revoked grant is deleted; an expired
 * one stays until its place is granted again, so the members page can say
 * it lapsed.
 */
export const grants = pgTable(
  'grants',
  {
    id: uuid().primaryKey(),
    principal: text().notNull(),
    // Its member's generation when it was granted: a removal moves that on, so a grant made before it reaches nothing after.
    generation: integer().notNull(),
    projectId: uuid('project_id'),
    environmentId: uuid('environment_id'),
    role: text().notNull(),
    expiresAt: at('expires_at'),
    grantedAt: at('granted_at').notNull(),
    grantedBy: text('granted_by').notNull(),
    mac: mac(),
  },
  (table) => [
    check('grants_one_place', sql`(${table.projectId} IS NULL) <> (${table.environmentId} IS NULL)`),
    check('grants_role_check', sql`${table.role} ~ ${ROLE_ID}`),
    macCheck('grants_mac_check', table.mac),
    unique('grants_on_project').on(table.principal, table.projectId),
    unique('grants_on_environment').on(table.principal, table.environmentId),
    foreignKey({
      name: 'grants_principal_fkey',
      columns: [table.principal],
      foreignColumns: [principals.id],
    }).onDelete('restrict'),
    foreignKey({
      name: 'grants_project_id_fkey',
      columns: [table.projectId],
      foreignColumns: [projects.id],
    }).onDelete('restrict'),
    foreignKey({
      name: 'grants_environment_id_fkey',
      columns: [table.environmentId],
      foreignColumns: [environments.id],
    }).onDelete('restrict'),
    // Who holds a place: its users and service accounts.
    index('grants_project_idx').on(table.projectId),
    index('grants_environment_idx').on(table.environmentId),
  ],
);

/**
 * Every role, the ones that ship too: a role with no row is no role, and a
 * grant that names it reaches nothing. `instance` tells an instance role
 * (Owner, Admin, Auditor, Member) from a role on a place, whose ids overlap.
 */
export const roles = pgTable(
  'roles',
  {
    instance: boolean().notNull(),
    id: text().notNull(),
    name: text().notNull(),
    description: text().notNull(),
    // `PERMISSIONS` in @coffre/core/access: what the role holds, and what it holds on a protected environment.
    permissions: text().array().notNull(),
    protected: text().array().notNull(),
    mac: mac(),
  },
  (table) => [
    primaryKey({ name: 'roles_pkey', columns: [table.instance, table.id] }),
    check('roles_id_check', sql`${table.id} ~ ${ROLE_ID}`),
    macCheck('roles_mac_check', table.mac),
  ],
);

/**
 * The instance's one policy row. An instance's key is the key this row is
 * under: a vault writes every row and entry under the key of the policy row
 * it read (docs/design/0.16.md, "Rotating the vault's key").
 */
export const policy = pgTable(
  'policy',
  {
    onlyRow: boolean('only_row').primaryKey().default(true),
    // Where people set up service accounts themselves (`ServiceSetting` in @coffre/core/access), JSON.
    serviceAccounts: text('service_accounts').notNull(),
    // Every workload use refused, instance-wide, until the freeze is lifted.
    workloadsFrozenAt: at('workloads_frozen_at'),
    changedAt: at('changed_at').notNull(),
    changedBy: text('changed_by').notNull(),
    mac: mac(),
  },
  (table) => [
    check('policy_only_row_check', sql`${table.onlyRow}`),
    check('policy_service_accounts_check', sql`${table.serviceAccounts}::jsonb IS NOT NULL`),
    macCheck('policy_mac_check', table.mac),
  ],
);

// ---------------------------------------------------------------- Sign-in

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
    id: uuid().primaryKey(),
    provider: text().notNull(),
    subject: text().notNull(),
    issuerHash: text('issuer_hash').notNull(),
    generation: integer().notNull(),
    // The member it signs in as, `user:<email>`, under the generation it was bound in.
    principal: text().notNull(),
    email: text(),
    createdAt: at('created_at').notNull(),
    createdBy: text('created_by').notNull(),
    lastSignInAt: at('last_sign_in_at'),
    revokedAt: at('revoked_at'),
    revokedBy: text('revoked_by'),
    activeSubject: text('active_subject').generatedAlwaysAs(ACTIVE_SUBJECT),
    mac: mac(),
  },
  (table) => [
    check('identities_principal_check', sql`${table.principal} LIKE 'user:%'`),
    check('identities_provider_check', sql`${table.provider} ~ '^[a-z0-9][a-z0-9-]{0,31}$'`),
    macCheck('identities_mac_check', table.mac),
    unique('identities_member_generation_key').on(table.id, table.principal, table.generation),
    foreignKey({
      name: 'identities_principal_fkey',
      columns: [table.principal],
      foreignColumns: [principals.id],
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
 * but for its label, last use, freeze and revocation: a change is a new
 * binding.
 */
export const bindings = pgTable(
  'bindings',
  {
    id: uuid().primaryKey(),
    // The service it signs in as, `token:<name>`, under the generation it was bound in.
    principal: text().notNull(),
    generation: integer().notNull(),
    profile: text().notNull(),
    issuer: text().notNull(),
    // From the issuer's discovery when the binding was made, never refetched;
    // or, for keys uploaded with the binding, `sha256:<hex>` of `jwks`.
    jwksUri: text('jwks_uri').notNull(),
    // The issuer's public keys, uploaded with the binding, JSON; null when they are fetched.
    jwks: text(),
    // JSON, sorted by claim name.
    claims: text().notNull(),
    // What the credentials it issues reach (`CredentialScope`), JSON; null, a binding of 0.4 never used since, reaches nothing.
    scope: text(),
    // What a workload's binding says beyond its claims (`BindingPolicy`), canonical JSON: null on a binding `/api/auth/oidc` takes.
    policy: text(),
    label: text(),
    createdAt: at('created_at').notNull(),
    createdBy: text('created_by').notNull(),
    lastUsedAt: at('last_used_at'),
    frozenAt: at('frozen_at'),
    revokedAt: at('revoked_at'),
    revokedBy: text('revoked_by'),
    mac: mac(),
  },
  (table) => [
    check('bindings_principal_check', sql`${table.principal} LIKE 'token:%'`),
    check('bindings_claims_check', sql`${table.claims}::jsonb IS NOT NULL`),
    macCheck('bindings_mac_check', table.mac),
    foreignKey({
      name: 'bindings_principal_fkey',
      columns: [table.principal],
      foreignColumns: [principals.id],
    }).onDelete('restrict'),
    // What an exchange may match: a service's live bindings on an issuer, in a
    // generation, in the order it reads them, without the revoked history.
    index('bindings_live_idx')
      .on(table.principal, table.issuer, table.generation, table.createdAt, table.id)
      .where(sql`${table.revokedAt} IS NULL`),
  ],
);

/**
 * What a caller presents: browser and CLI sessions, service and personal
 * tokens, handles, workloads' sessions and MCP connections. One table, so
 * that one read says who a caller is, whatever they hold.
 *
 * Only a SHA-256 of each token is stored. Tokens carry 256 bits of entropy,
 * so a fast hash is enough; a database leak yields nothing that
 * authenticates. An MCP connection's token is its authorization code until
 * the client redeems it (`challenge` is then its PKCE challenge, and
 * `expires_at` the code's 60 seconds), and its refresh token since, with
 * the one it replaced in `previous_token_hash`; its code stays in
 * `code_hash` for as long as it lasts. Either presented again ends the
 * connection. Each access token is a row of its own, which names its
 * connection in `ancestors`.
 *
 * A row is deleted a day after it expires.
 */
export const credentials = pgTable(
  'credentials',
  {
    id: uuid().primaryKey(),
    kind: text().notNull(),
    tokenHash: bytea('token_hash').notNull(),
    tokenHint: text('token_hint'),
    previousTokenHash: bytea('previous_token_hash'),
    codeHash: bytea('code_hash'),
    generation: integer().notNull(),
    // The member it acts as, `user:<email>` or `token:<name>`, under the generation it was issued in.
    principal: text().notNull(),
    identityId: uuid('identity_id'),
    // What a service or personal token reaches (`CredentialScope`), JSON: null for a session, or one a binding issued (its binding's).
    // On a token, null reaches nothing: 0.4 wrote such rows, and 0.14 gave each live one its scope.
    scope: text(),
    // The environments a handle was made for, by id, each with whether it was asked for as `@me`, JSON: null for any other credential.
    places: text(),
    label: text(),
    createdAt: at('created_at').notNull(),
    createdBy: text('created_by').notNull(),
    expiresAt: at('expires_at').notNull(),
    lastUsedAt: at('last_used_at'),
    lastUsedIp: text('last_used_ip'),
    frozenAt: at('frozen_at'),
    revokedAt: at('revoked_at'),
    revokedBy: text('revoked_by'),
    // A workload's session (docs/design/workload-access.md, section 11), null on every other credential:
    // the thumbprint of the key its proofs are signed by, and its hard end.
    jkt: text(),
    notAfter: at('not_after'),
    // A `narrow` child's: its ancestors' IDs, root first, JSON, and its limits (`Constraints`), canonical JSON.
    // The IDs exactly as `JSON.stringify` writes an array of them, lowercase and with no space: a use reads no other shape.
    ancestors: text(),
    constraints: text(),
    // The enrollment code a session was made from, and, where its binding says `approve`, who approved it.
    enrollmentId: uuid('enrollment_id'),
    approvedAt: at('approved_at'),
    approvedBy: text('approved_by'),
    // The CI run a binding issued it for: the claims of its ID token, JSON. Null on every other credential.
    run: text(),
    // An MCP connection's client, JSON: its id (a metadata document's URL, or a registration's), host, registration (`cimd` or `dcr`), redirect and scopes. Null on every other credential.
    client: text(),
    challenge: text(),
    mac: mac(),
  },
  (table) => [
    unique('credentials_token_hash_key').on(table.tokenHash),
    check('credentials_kind_check', sql`${table.kind} IN ('browser', 'cli', 'service', 'personal', 'handle', 'workload', 'mcp')`),
    check('credentials_principal_check', sql`${table.principal} LIKE 'user:%' OR ${table.principal} LIKE 'token:%'`),
    check('credentials_kind_matches_principal', sql`(${table.kind} IN ('service', 'workload')) = (${table.principal} LIKE 'token:%')`),
    check('credentials_workload_jkt_check', sql`${table.kind} <> 'workload' OR ${table.jkt} IS NOT NULL`),
    check('credentials_mcp_client_check', sql`(${table.kind} = 'mcp') = (${table.client} IS NOT NULL) AND (${table.challenge} IS NULL OR ${table.kind} = 'mcp')`),
    check('credentials_token_hash_check', sql`octet_length(${table.tokenHash}) = 32`),
    check('credentials_previous_token_hash_check', sql`${table.previousTokenHash} IS NULL OR octet_length(${table.previousTokenHash}) = 32`),
    unique('credentials_code_hash_key').on(table.codeHash),
    check('credentials_code_hash_check', sql`${table.codeHash} IS NULL OR (${table.kind} = 'mcp' AND octet_length(${table.codeHash}) = 32)`),
    macCheck('credentials_mac_check', table.mac),
    foreignKey({
      name: 'credentials_principal_fkey',
      columns: [table.principal],
      foreignColumns: [principals.id],
    }).onDelete('restrict'),
    // A session's account is its own member's, bound in the same generation.
    foreignKey({
      name: 'credentials_identity_id_fkey',
      columns: [table.identityId, table.principal, table.generation],
      foreignColumns: [identities.id, identities.principal, identities.generation],
    }).onDelete('restrict'),
    foreignKey({
      name: 'credentials_enrollment_id_fkey',
      columns: [table.enrollmentId],
      foreignColumns: [enrollmentCodes.id],
    }).onDelete('restrict'),
    // A member's credentials still live, however many have expired: a CI run
    // leaves one behind each time it signs in.
    index('credentials_live_idx').on(table.principal, table.expiresAt).where(sql`${table.revokedAt} IS NULL`),
    // What a trust binding issued lately, for its rate.
    index('credentials_issued_by_idx').on(table.principal, table.createdBy, table.createdAt),
    // A code's sessions made by the exchange, ended ones too: its capacity and its tripwire's last hour, never a child.
    index('credentials_enrollment_roots_idx')
      .on(table.enrollmentId, table.createdAt)
      .where(sql`${table.kind} = 'workload' AND ${table.ancestors} IS NULL`),
    // A refresh token presented again after it was replaced.
    index('credentials_previous_token_idx').on(table.previousTokenHash).where(sql`${table.previousTokenHash} IS NOT NULL`),
    // The MCP credentials of a registered client, by its id at the head of `client`: the upkeep's test of whether one is in use.
    index('credentials_client_idx').on(sql`(${table.client}::jsonb ->> 'id')`).where(sql`${table.client} IS NOT NULL`),
    // What the minute's upkeep deletes: the rows a day past their expiry.
    index('credentials_expiry_idx').on(table.expiresAt),
  ],
);

// --------------------------------------------------------------- One-shot

/**
 * A CLI asking to be signed in from a browser (RFC 8628, device flow).
 *
 * The CLI holds the device code and polls with it; a signed-in person approves
 * the short user code in their browser. It works the same on a laptop and on
 * a server reached over SSH, which a localhost redirect does not. The MAC
 * covers the approval: a row that says someone approved it becomes their
 * session.
 */
export const deviceLogins = pgTable(
  'device_logins',
  {
    id: uuid().primaryKey(),
    deviceCodeHash: bytea('device_code_hash').notNull(),
    userCode: text('user_code').notNull(),
    clientLabel: text('client_label'),
    clientIp: text('client_ip'),
    createdAt: at('created_at').notNull(),
    expiresAt: at('expires_at').notNull(),
    decidedAt: at('decided_at'),
    decision: text(),
    generation: integer().notNull().default(0),
    // Who approved it, `user:<email>`, once approved.
    principal: text(),
    consumedAt: at('consumed_at'),
    mac: mac(),
  },
  (table) => [
    unique('device_logins_device_code_hash_key').on(table.deviceCodeHash),
    unique('device_logins_user_code_key').on(table.userCode),
    macCheck('device_logins_mac_check', table.mac),
    check('device_logins_decision_check', sql`${table.decision} IS NULL OR ${table.decision} IN ('approved', 'denied')`),
    check(
      'device_logins_approval_names_principal',
      sql`(${table.decision} IS NULL AND ${table.decidedAt} IS NULL AND ${table.principal} IS NULL AND ${table.generation} = 0 AND ${table.consumedAt} IS NULL)
        OR (${table.decision} IS NOT NULL AND ${table.decidedAt} IS NOT NULL AND (
          (${table.decision} = 'denied' AND ${table.principal} IS NULL AND ${table.generation} = 0 AND ${table.consumedAt} IS NULL)
          OR (${table.decision} = 'approved' AND ${table.principal} IS NOT NULL AND ${table.principal} LIKE 'user:%')
        ))`,
    ),
    foreignKey({
      name: 'device_logins_principal_fkey',
      columns: [table.principal],
      foreignColumns: [principals.id],
    }).onDelete('restrict'),
    index('device_logins_expiry_idx').on(table.expiresAt),
  ],
);

/**
 * Enrollment codes (docs/design/workload-access.md, section 4.4): what CI
 * mints for a platform that signs no identity, exchanged for a workload's
 * session at `/api/auth/workload`. Never a credential itself. Its scope,
 * fixed at minting, is the binding's within what the minter held. A code a
 * promote superseded says so in its row, and renews no session after.
 */
export const enrollmentCodes = pgTable(
  'enrollment_codes',
  {
    id: uuid().primaryKey(),
    bindingId: uuid('binding_id').notNull(),
    // The SHA-256 of the code, `coffre_enr_…`, and enough of it to recognize.
    codeHash: bytea('code_hash').notNull(),
    codeHint: text('code_hint').notNull(),
    // `CredentialScope`, JSON: what its sessions reach.
    scope: text().notNull(),
    createdAt: at('created_at').notNull(),
    // Who minted it, and with which of their credentials: a CI run's session.
    createdBy: text('created_by').notNull(),
    createdWith: uuid('created_with'),
    expiresAt: at('expires_at').notNull(),
    supersededAt: at('superseded_at'),
    mac: mac(),
  },
  (table) => [
    unique('enrollment_codes_code_hash_key').on(table.codeHash),
    check('enrollment_codes_code_hash_check', sql`octet_length(${table.codeHash}) = 32`),
    check('enrollment_codes_scope_check', sql`${table.scope}::jsonb IS NOT NULL`),
    macCheck('enrollment_codes_mac_check', table.mac),
    foreignKey({
      name: 'enrollment_codes_binding_id_fkey',
      columns: [table.bindingId],
      foreignColumns: [bindings.id],
    }).onDelete('restrict'),
    // A binding's codes, newest first, for its page.
    index('enrollment_codes_binding_idx').on(table.bindingId, table.createdAt.desc()),
  ],
);

/**
 * ID tokens exchanged for a credential, each once: the SHA-256 of what its
 * signature covers, `header.payload` as received, so that no other
 * spelling of the same token counts as another. The primary key decides a
 * race. An exchange refuses a token issued over an hour ago, so a row two
 * hours old guards nothing, and the minute's upkeep deletes it.
 */
export const spentIdTokens = pgTable(
  'spent_id_tokens',
  {
    hash: bytea('hash').primaryKey(),
    spentAt: at('spent_at').notNull(),
  },
  (table) => [
    check('spent_id_tokens_hash_check', sql`octet_length(${table.hash}) = 32`),
    index('spent_id_tokens_spent_idx').on(table.spentAt),
  ],
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
    // Its own claim, shown as unverified.
    name: text().notNull(),
    // JSON: a list of HTTPS or loopback URLs.
    redirectUris: text('redirect_uris').notNull(),
    createdAt: at('created_at').notNull(),
    createdIp: text('created_ip'),
    revokedAt: at('revoked_at'),
    mac: mac(),
  },
  (table) => [
    check('oauth_clients_redirect_uris_check', sql`${table.redirectUris}::jsonb IS NOT NULL`),
    macCheck('oauth_clients_mac_check', table.mac),
  ],
);

/**
 * A change an MCP client asked for, waiting for its person on coffre's own
 * page (docs/design/mcp.md, section 7). It holds the tool and its arguments,
 * never a value: the page shows what they would do and, on Approve, does it,
 * once, as the person, through the connection. Its digest is of the tool
 * and arguments, which the page sends back with the decision, so what runs
 * is what the person read. No MAC: a row changes nothing by itself.
 */
export const mcpApprovals = pgTable(
  'mcp_approvals',
  {
    id: uuid().primaryKey(),
    // The MCP connection, a credential, that asked.
    connectionId: uuid('connection_id').notNull(),
    tool: text().notNull(),
    // JSON: the tool's arguments, as checked when it was called.
    arguments: text().notNull(),
    // SHA-256 of the canonical JSON of the tool and its arguments.
    digest: bytea().notNull(),
    // pending, approved, denied, cancelled or failed; a pending one past its expiry has expired.
    status: text().notNull(),
    // JSON: what the change answered, or why it failed. Never a value.
    outcome: text(),
    createdAt: at('created_at').notNull(),
    expiresAt: at('expires_at').notNull(),
    decidedAt: at('decided_at'),
    // When the client read the outcome: an identical call after that asks again.
    reportedAt: at('reported_at'),
  },
  (table) => [
    check('mcp_approvals_status_check', sql`${table.status} IN ('pending', 'approved', 'denied', 'cancelled', 'failed')`),
    check('mcp_approvals_digest_check', sql`octet_length(${table.digest}) = 32`),
    check('mcp_approvals_arguments_check', sql`${table.arguments}::jsonb IS NOT NULL`),
    // An approval goes with its connection, a day after that expires.
    foreignKey({
      name: 'mcp_approvals_connection_fkey',
      columns: [table.connectionId],
      foreignColumns: [credentials.id],
    }).onDelete('cascade'),
    // A connection's approvals its client has not yet heard the end of: the ones a call rejoins, and the five it may wait on.
    index('mcp_approvals_open_idx').on(table.connectionId, table.digest).where(sql`${table.reportedAt} IS NULL`),
  ],
);

// -------------------------------------------------------------------- Log

/**
 * Entries waiting for the signer, about a second: a request appends here
 * and nowhere else. `body` is the entry, canonical JSON, exactly the bytes
 * its hash and MAC cover. `kept` says which of the log's two trees it goes
 * under: the one kept for good, or the one that ages out (uses, and a
 * session's coming and going).
 */
export const logPending = pgTable(
  'log_pending',
  {
    id: bigint({ mode: 'bigint' }).primaryKey().generatedAlwaysAsIdentity(),
    kept: boolean().notNull(),
    body: text().notNull(),
    mac: bytea().notNull(),
  },
  (table) => [check('log_pending_mac_check', sql`octet_length(${table.mac}) = 36`)],
);

/**
 * The log, written by the signer alone, which numbers its entries: `seq` is
 * an entry's place in the log's one order, and `leaf` its place in its tree.
 * No MAC: the signer checked the entry's when it took it, and from then on
 * the tree vouches for it. No time either: an entry's is in its body, which
 * its hash covers.
 */
export const log = pgTable(
  'log',
  {
    seq: bigint({ mode: 'bigint' }).primaryKey(),
    kept: boolean().notNull(),
    leaf: bigint({ mode: 'bigint' }).notNull(),
    body: text().notNull(),
  },
  (table) => [
    // An entry by its place in its tree: a proof's, and the block of 256 a pruning takes.
    unique('log_leaf_key').on(table.kept, table.leaf),
    check('log_seq_check', sql`${table.seq} >= 0 AND ${table.leaf} >= 0 AND ${table.leaf} <= ${table.seq}`),
  ],
);

/**
 * One row per object an entry mentions: `project:<id>`, `environment:<id>`,
 * `secret:<id>`, `principal:<principal>`, `credential:<id>`. Every filtered
 * page of the log reads this one index, backwards.
 */
export const logIndex = pgTable(
  'log_index',
  {
    object: text().notNull(),
    seq: bigint({ mode: 'bigint' }).notNull(),
  },
  (table) => [primaryKey({ name: 'log_index_pkey', columns: [table.object, table.seq] })],
);

/**
 * Each tree's hashes, 256 to a row (`@coffre/core/log`): the tile at
 * (`level`, `number`) holds the nodes at tree level 8·level numbered
 * 256·number onwards, concatenated. A proof reads at most 8 rows.
 */
export const logTiles = pgTable(
  'log_tiles',
  {
    kept: boolean().notNull(),
    level: smallint().notNull(),
    number: bigint({ mode: 'bigint' }).notNull(),
    hashes: bytea().notNull(),
  },
  (table) => [
    primaryKey({ name: 'log_tiles_pkey', columns: [table.kept, table.level, table.number] }),
    check('log_tiles_hashes_check', sql`octet_length(${table.hashes}) BETWEEN 32 AND 8192 AND octet_length(${table.hashes}) % 32 = 0`),
    check('log_tiles_place_check', sql`${table.level} >= 0 AND ${table.number} >= 0`),
  ],
);

/**
 * The signed head, for the pages: the signer's own copy is the one that
 * counts. Both trees' sizes and roots under one MAC, written in one
 * statement, so the two never disagree about when. `aging_from` is the
 * first leaf of the aging tree that pruning has kept. No row until the
 * signer adopts the database.
 */
export const logHead = pgTable(
  'log_head',
  {
    onlyRow: boolean('only_row').primaryKey().default(true),
    // How many entries the log has numbered: the next one's `seq`.
    size: bigint({ mode: 'bigint' }).notNull(),
    keptSize: bigint('kept_size', { mode: 'bigint' }).notNull(),
    keptRoot: bytea('kept_root').notNull(),
    agingSize: bigint('aging_size', { mode: 'bigint' }).notNull(),
    agingRoot: bytea('aging_root').notNull(),
    agingFrom: bigint('aging_from', { mode: 'bigint' }).notNull(),
    signedAt: at('signed_at').notNull(),
    mac: bytea().notNull(),
  },
  (table) => [
    check('log_head_only_row_check', sql`${table.onlyRow}`),
    check('log_head_sizes_check', sql`${table.keptSize} >= 0 AND ${table.agingSize} >= 0 AND ${table.size} = ${table.keptSize} + ${table.agingSize} AND ${table.agingFrom} BETWEEN 0 AND ${table.agingSize}`),
    check('log_head_roots_check', sql`octet_length(${table.keptRoot}) = 32 AND octet_length(${table.agingRoot}) = 32`),
    check('log_head_mac_check', sql`octet_length(${table.mac}) = 36`),
  ],
);

/**
 * Who has seen which key, and when last: one row per principal and key,
 * moved on in place by a use, never pruned. Requests may not read the log,
 * and three things ask this: the bulk cap (a principal's keys within its
 * window), a key's last use, and what someone who leaves has seen. Bounded
 * by principals times keys.
 *
 * It points at no other table by a foreign key, on purpose. A use writes
 * it with no lock, and a foreign key's check would lock the principal's row
 * and the secret's against a change that deletes or renames them: a use and
 * a change could then wait on each other. Neither row is ever deleted, and
 * a row here that names nothing is read by no page.
 */
export const exposures = pgTable(
  'exposures',
  {
    principal: text().notNull(),
    secretId: uuid('secret_id').notNull(),
    seenAt: at('seen_at').notNull(),
  },
  (table) => [
    primaryKey({ name: 'exposures_pkey', columns: [table.principal, table.secretId] }),
    // A key's last use, for its environment's page. `seen_at` is in no index, so moving it on leaves none behind.
    index('exposures_secret_idx').on(table.secretId),
  ],
);

/**
 * 0.14's audit log, as the upgrade left it: the same rows, never written
 * again, with its key and one index of its sixteen, by action, which finds
 * the vault what it adopts (the newest policy and settings) without reading
 * every entry. The log's first entry records its last hash and number.
 * `coffre log export --archive` reads it, and nothing else does once the
 * vault has adopted the database.
 */
export const auditArchive = pgTable(
  'audit_archive',
  {
    seq: bigint({ mode: 'bigint' }).primaryKey(),
    author: text().notNull(),
    keyId: text('key_id').notNull(),
    // Milliseconds since the epoch, as 0.14 wrote them: its MAC covers the number.
    occurredAt: bigint('occurred_at', { mode: 'number' }).notNull(),
    actor: text().notNull(),
    action: text().notNull(),
    decision: text().notNull(),
    code: text(),
    subjectPrincipal: text('subject_principal'),
    projectId: uuid('project_id'),
    environmentId: uuid('environment_id'),
    secretId: uuid('secret_id'),
    secretVersionId: uuid('secret_version_id'),
    operationId: uuid('operation_id'),
    requestId: text('request_id'),
    sourceIp: text('source_ip'),
    relatedSeq: bigint('related_seq', { mode: 'bigint' }),
    metadata: text().notNull(),
    prevHash: bytea('prev_hash').notNull(),
    mac: bytea().notNull(),
    hash: bytea().notNull(),
  },
  (table) => [index('audit_archive_action_idx').on(table.author, table.action, table.seq)],
);

// For Drizzle's relational queries; see relations.ts.
export const {
  environmentsRelations,
  secretsRelations,
} = relationsOf({ projects, environments, secrets, secretVersions });
