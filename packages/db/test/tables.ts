import { asPostgres, type PostgresSchema } from '../src/portable.ts';
import { TEST_ENGINE } from './engine.ts';

/**
 * The tables of the engine the suite runs on, under the names schema.ts
 * gives them. Tests import tables from here rather than from schema.ts, so
 * that what they read and write is encoded the way their database expects.
 */
const schema: PostgresSchema =
  TEST_ENGINE === 'mysql'
    ? asPostgres(await import('../src/schema.mysql.ts'))
    : TEST_ENGINE === 'sqlite'
      ? asPostgres(await import('../src/schema.sqlite.ts'))
      : await import('../src/schema.ts');

export const {
  projects,
  environments,
  secrets,
  secretVersions,
  principals,
  grants,
  auditLog,
  auditChainHead,
  auditCheckpoints,
  auditHeartbeat,
  identities,
  credentials,
  deviceAuthorizations,
  syncs,
  syncKeys,
} = schema;
