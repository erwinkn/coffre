import { relations, sql } from 'drizzle-orm';

import type * as schema from './schema.ts';

/**
 * What both schemas share beyond their columns: the relations and the
 * one generated column.
 *
 * Relations are for Drizzle's relational queries (`db.query.secrets.findMany({ with })`), which read a row and what hangs off it in one
 * statement on every dialect. They add no constraints; the foreign keys in
 * each schema do that. Each schema calls this with its own tables, so a
 * relational query on SQLite joins SQLite tables.
 */
export function relationsOf(t: Pick<
  typeof schema,
  | 'projects'
  | 'environments'
  | 'secrets'
  | 'secretVersions'
>) {
  return {
    environmentsRelations: relations(t.environments, ({ one }) => ({
      project: one(t.projects, { fields: [t.environments.projectId], references: [t.projects.id] }),
    })),

    secretsRelations: relations(t.secrets, ({ one }) => ({
      project: one(t.projects, { fields: [t.secrets.projectId], references: [t.projects.id] }),
      environment: one(t.environments, { fields: [t.secrets.environmentId], references: [t.environments.id] }),
    })),

  };
}

/**
 * `identities.active_subject`: the subject while the account is bound, null
 * once revoked. A unique index on (provider, issuer_hash, active_subject)
 * binds an account to one person at a time. Plain column names, so the
 * expression reads the same on both databases.
 */
export const ACTIVE_SUBJECT = sql`CASE WHEN revoked_at IS NULL THEN subject END`;
