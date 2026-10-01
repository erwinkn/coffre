import {
  blob,
  index,
  integer,
  sqliteTable,
  text,
  unique,
} from 'drizzle-orm/sqlite-core';

import type { AuditMetadata } from './model.ts';

const id = (name: string) => text(name);
const bytes = (name: string) => blob(name, { mode: 'buffer' });
const createdAt = () => integer('created_at', { mode: 'timestamp_ms' }).notNull();

export const projects = sqliteTable(
  'projects',
  {
    id: id('id').primaryKey(),
    slug: text().notNull(),
    name: text().notNull(),
    createdAt: createdAt(),
    archivedAt: integer('archived_at', { mode: 'timestamp_ms' }),
  },
  (table) => [unique('projects_slug_key').on(table.slug)],
);

export const environments = sqliteTable(
  'environments',
  {
    id: id('id').primaryKey(),
    projectId: id('project_id').notNull().references(() => projects.id),
    slug: text().notNull(),
    name: text().notNull(),
    createdAt: createdAt(),
    archivedAt: integer('archived_at', { mode: 'timestamp_ms' }),
  },
  (table) => [unique('environments_project_slug_key').on(table.projectId, table.slug)],
);

export const secrets = sqliteTable(
  'secrets',
  {
    id: id('id').primaryKey(),
    projectId: id('project_id').notNull().references(() => projects.id),
    environmentId: id('environment_id').notNull().references(() => environments.id),
    key: text().notNull(),
    currentVersionId: id('current_version_id'),
    createdAt: createdAt(),
    archivedAt: integer('archived_at', { mode: 'timestamp_ms' }),
  },
  (table) => [
    unique('secrets_environment_key_key').on(table.environmentId, table.key),
    index('secrets_lookup_idx').on(table.projectId, table.environmentId, table.key),
  ],
);

export const secretVersions = sqliteTable(
  'secret_versions',
  {
    id: id('id').primaryKey(),
    secretId: id('secret_id').notNull().references(() => secrets.id),
    version: integer().notNull(),
    ciphertext: bytes('ciphertext').notNull(),
    wrappedDek: bytes('wrapped_dek').notNull(),
    createdAt: createdAt(),
  },
  (table) => [unique('secret_versions_secret_version_key').on(table.secretId, table.version)],
);

export const auditChainHead = sqliteTable('audit_chain_head', {
  onlyRow: integer('only_row').primaryKey(),
  nextSeq: integer('next_seq').notNull(),
  headHash: bytes('head_hash').notNull(),
  updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull(),
});

export const auditLog = sqliteTable(
  'audit_log',
  {
    seq: integer().primaryKey(),
    id: id('id').notNull().unique(),
    occurredAt: integer('occurred_at', { mode: 'timestamp_ms' }).notNull(),
    actorId: text('actor_id').notNull(),
    action: text().notNull(),
    metadata: text({ mode: 'json' }).$type<AuditMetadata>().notNull(),
    prevHash: bytes('prev_hash').notNull(),
    hash: bytes('hash').notNull(),
  },
  (table) => [index('audit_log_actor_idx').on(table.actorId, table.occurredAt)],
);
