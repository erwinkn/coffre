import {
  customType,
  datetime,
  index,
  int,
  json,
  mysqlTable,
  unique,
  varchar,
} from 'drizzle-orm/mysql-core';

import type { AuditMetadata } from './model.ts';

const bytes = customType<{ data: Buffer; driverData: Buffer }>({ dataType: () => 'longblob' });
const id = (name: string) => varchar(name, { length: 36 });
const createdAt = () => datetime('created_at', { fsp: 3, mode: 'date' }).notNull();

export const projects = mysqlTable(
  'projects',
  {
    id: id('id').primaryKey(),
    slug: varchar({ length: 63 }).notNull(),
    name: varchar({ length: 255 }).notNull(),
    createdAt: createdAt(),
    archivedAt: datetime('archived_at', { fsp: 3, mode: 'date' }),
  },
  (table) => [unique('projects_slug_key').on(table.slug)],
);

export const environments = mysqlTable(
  'environments',
  {
    id: id('id').primaryKey(),
    projectId: id('project_id').notNull().references(() => projects.id),
    slug: varchar({ length: 63 }).notNull(),
    name: varchar({ length: 255 }).notNull(),
    createdAt: createdAt(),
    archivedAt: datetime('archived_at', { fsp: 3, mode: 'date' }),
  },
  (table) => [unique('environments_project_slug_key').on(table.projectId, table.slug)],
);

export const secrets = mysqlTable(
  'secrets',
  {
    id: id('id').primaryKey(),
    projectId: id('project_id').notNull().references(() => projects.id),
    environmentId: id('environment_id').notNull().references(() => environments.id),
    key: varchar({ length: 128 }).notNull(),
    currentVersionId: id('current_version_id'),
    createdAt: createdAt(),
    archivedAt: datetime('archived_at', { fsp: 3, mode: 'date' }),
  },
  (table) => [
    unique('secrets_environment_key_key').on(table.environmentId, table.key),
    index('secrets_lookup_idx').on(table.projectId, table.environmentId, table.key),
  ],
);

export const secretVersions = mysqlTable(
  'secret_versions',
  {
    id: id('id').primaryKey(),
    secretId: id('secret_id').notNull().references(() => secrets.id),
    version: int().notNull(),
    ciphertext: bytes().notNull(),
    wrappedDek: bytes('wrapped_dek').notNull(),
    createdAt: createdAt(),
  },
  (table) => [unique('secret_versions_secret_version_key').on(table.secretId, table.version)],
);

export const auditChainHead = mysqlTable('audit_chain_head', {
  onlyRow: int('only_row').primaryKey(),
  nextSeq: int('next_seq').notNull(),
  headHash: bytes('head_hash').notNull(),
  updatedAt: datetime('updated_at', { fsp: 3, mode: 'date' }).notNull(),
});

export const auditLog = mysqlTable(
  'audit_log',
  {
    seq: int().primaryKey(),
    id: id('id').notNull().unique(),
    occurredAt: datetime('occurred_at', { fsp: 3, mode: 'date' }).notNull(),
    actorId: varchar('actor_id', { length: 255 }).notNull(),
    action: varchar({ length: 255 }).notNull(),
    metadata: json().$type<AuditMetadata>().notNull(),
    prevHash: bytes('prev_hash').notNull(),
    hash: bytes().notNull(),
  },
  (table) => [index('audit_log_actor_idx').on(table.actorId, table.occurredAt)],
);
