import { asPostgres, type PostgresSchema } from '@coffre/db/portable';

import { TEST_ENGINE } from './engine.ts';

/**
 * The tables of the engine the suite runs on, under the names schema.ts
 * gives them. Tests import tables from here rather than from schema.ts, so
 * that what they read and write is encoded the way their database expects.
 */
const schema: PostgresSchema =
  TEST_ENGINE === 'sqlite'
    ? asPostgres(await import('@coffre/db/schema-sqlite'))
    : await import('@coffre/db/schema');

export const {
  projects,
  environments,
  secrets,
  secretVersions,
  principals,
  auditLog,
  auditChainHead,
  auditHeartbeat,
  identities,
  credentials,
  deviceAuthorizations,
  syncs,
  syncKeys,
} = schema;
