import { relations, sql } from 'drizzle-orm';

import type * as schema from './schema.ts';

/**
 * What the three schemas share beyond their columns: the relations and the
 * one generated column.
 *
 * Relations are for Drizzle's relational queries (`db.query.principals
 * .findMany({ with })`), which read a row and what hangs off it in one
 * statement on every dialect. They add no constraints; the foreign keys in
 * each schema do that. Each schema calls this with its own tables, so a
 * relational query on MySQL joins MySQL tables.
 */
export function relationsOf(t: Pick<
  typeof schema,
  | 'projects'
  | 'environments'
  | 'secrets'
  | 'secretVersions'
  | 'principals'
  | 'identities'
  | 'credentials'
  | 'syncs'
  | 'syncKeys'
>) {
  return {
    principalsRelations: relations(t.principals, ({ many }) => ({
      credentials: many(t.credentials),
      identities: many(t.identities),
    })),

    credentialsRelations: relations(t.credentials, ({ one }) => ({
      principal: one(t.principals, {
        fields: [t.credentials.principalType, t.credentials.principalId],
        references: [t.principals.principalType, t.principals.principalId],
      }),
      identity: one(t.identities, { fields: [t.credentials.identityId], references: [t.identities.id] }),
    })),

    identitiesRelations: relations(t.identities, ({ one }) => ({
      principal: one(t.principals, {
        fields: [t.identities.principalType, t.identities.principalId],
        references: [t.principals.principalType, t.principals.principalId],
      }),
    })),

    environmentsRelations: relations(t.environments, ({ one }) => ({
      project: one(t.projects, { fields: [t.environments.projectId], references: [t.projects.id] }),
    })),

    secretsRelations: relations(t.secrets, ({ one }) => ({
      project: one(t.projects, { fields: [t.secrets.projectId], references: [t.projects.id] }),
      environment: one(t.environments, { fields: [t.secrets.environmentId], references: [t.environments.id] }),
    })),

    syncsRelations: relations(t.syncs, ({ one, many }) => ({
      project: one(t.projects, { fields: [t.syncs.projectId], references: [t.projects.id] }),
      environment: one(t.environments, { fields: [t.syncs.environmentId], references: [t.environments.id] }),
      credential: one(t.secrets, { fields: [t.syncs.credentialSecretId], references: [t.secrets.id] }),
      keys: many(t.syncKeys),
    })),

    syncKeysRelations: relations(t.syncKeys, ({ one }) => ({
      sync: one(t.syncs, { fields: [t.syncKeys.syncId], references: [t.syncs.id] }),
    })),
  };
}

/**
 * `identities.active_subject`: the subject while the account is bound, null
 * once revoked. A unique index on (provider, active_subject) binds an
 * account to one person at a time; Postgres said the same with a partial
 * index, which MySQL does not have. Plain column names, so the expression
 * reads the same on all three.
 */
export const ACTIVE_SUBJECT = sql`CASE WHEN revoked_at IS NULL THEN subject END`;
