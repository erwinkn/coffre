import type { Vault } from '@coffre/core/vault';
import type { Database } from '@coffre/db';

import type { ResolvedConfig } from './config.ts';

/**
 * What a request is served with (docs/design/0.16.md, "The server"): the
 * app's database, for what its pages list, the vault, which decides every
 * use and change, and what the deployment's configuration says.
 */
export type CoffreRuntime = {
  db: Database;
  /** The vault Worker's binding, or a Node vault. */
  vault: Vault;
  auth: ResolvedConfig['auth'];
  publicUrl: string;
  /** What is known of the database's schema, for as long as the configuration lives: the isolate's, or the process's. */
  schema: { migrated: boolean };
};

/**
 * What a configuration knows of its database, for as long as it lives.
 * Settled values, never a pending read (AGENTS.md, "What an isolate keeps").
 */
const known = new WeakMap<ResolvedConfig, CoffreRuntime['schema']>();

/**
 * The app around a database: once per invocation on Workers, whose
 * database clients belong to one request; once per process on Node.
 */
export function createRuntime(config: ResolvedConfig, db: Database, vault: Vault): CoffreRuntime {
  let schema = known.get(config);
  if (schema === undefined) known.set(config, (schema = { migrated: false }));
  return { db, vault, auth: config.auth, publicUrl: config.publicUrl, schema };
}
