import {
  customType,
  index,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  unique,
  uuid,
} from 'drizzle-orm/pg-core';

import type { AuditMetadata } from './model.ts';

const bytea = customType<{ data: Buffer }>({ dataType: () => 'bytea' });
const createdAt = () => timestamp('created_at', { mode: 'date', withTimezone: true }).notNull();

export const projects = pgTable(
  'projects',
  {
    id: uuid().primaryKey(),
    slug: text().notNull(),
    name: text().notNull(),
    createdAt: createdAt(),
    archivedAt: timestamp('archived_at', { mode: 'date', withTimezone: true }),
  },
  (table) => [unique('projects_slug_key').on(table.slug)],
);

export const environments = pgTable(
  'environments',
  {
    id: uuid().primaryKey(),
    projectId: uuid('project_id').notNull().references(() => projects.id),
    slug: text().notNull(),
    name: text().notNull(),
    createdAt: createdAt(),
    archivedAt: timestamp('archived_at', { mode: 'date', withTimezone: true }),
  },
  (table) => [unique('environments_project_slug_key').on(table.projectId, table.slug)],
);

export const secrets = pgTable(
  'secrets',
  {
    id: uuid().primaryKey(),
    projectId: uuid('project_id').notNull().references(() => projects.id),
    environmentId: uuid('environment_id').notNull().references(() => environments.id),
    key: text().notNull(),
    currentVersionId: uuid('current_version_id'),
    createdAt: createdAt(),
    archivedAt: timestamp('archived_at', { mode: 'date', withTimezone: true }),
  },
  (table) => [
    unique('secrets_environment_key_key').on(table.environmentId, table.key),
    index('secrets_lookup_idx').on(table.projectId, table.environmentId, table.key),
  ],
);

export const secretVersions = pgTable(
  'secret_versions',
  {
    id: uuid().primaryKey(),
    secretId: uuid('secret_id').notNull().references(() => secrets.id),
    version: integer().notNull(),
    ciphertext: bytea().notNull(),
    wrappedDek: bytea('wrapped_dek').notNull(),
    createdAt: createdAt(),
  },
  (table) => [unique('secret_versions_secret_version_key').on(table.secretId, table.version)],
);

export const auditChainHead = pgTable('audit_chain_head', {
  onlyRow: integer('only_row').primaryKey(),
  nextSeq: integer('next_seq').notNull(),
  headHash: bytea('head_hash').notNull(),
  updatedAt: timestamp('updated_at', { mode: 'date', withTimezone: true }).notNull(),
});

export const auditLog = pgTable(
  'audit_log',
  {
    seq: integer().primaryKey(),
    id: uuid().notNull().unique(),
    occurredAt: timestamp('occurred_at', { mode: 'date', withTimezone: true }).notNull(),
    actorId: text('actor_id').notNull(),
    action: text().notNull(),
    metadata: jsonb().$type<AuditMetadata>().notNull(),
    prevHash: bytea('prev_hash').notNull(),
    hash: bytea().notNull(),
  },
  (table) => [index('audit_log_actor_idx').on(table.actorId, table.occurredAt)],
);
