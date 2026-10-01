/**
 * coffre as a Node server:
 *
 *   import { serve, signin, github } from '@coffre/server/node';
 *   import { connectVault } from '@coffre/vault/node';
 *
 *   await serve({
 *     port: 3000,
 *     publicUrl: 'https://secrets.acme.example',
 *     database: process.env.DATABASE_URL,
 *     vault: connectVault('/run/coffre/vault.sock'),
 *     auth: signin({ providers: [github({ clientId: …, clientSecret: … })] }),
 *     auditChainKey: process.env.AUDIT_CHAIN_KEY,
 *   });
 *
 * One process serves the API, the pages and their static files, and runs
 * the scheduled job itself.
 */
import { fileURLToPath } from 'node:url';

import { migrateDatabase } from './db/migrate.ts';
import { serveWith, type ServeOptions, type Server } from './node-server.ts';

export * from './index.ts';
export type { ServeOptions, Server };

/** Bring the database up to date: what `coffre-server migrate` runs. */
export function migrate(database: string): Promise<void> {
  return migrateDatabase(database);
}

/** Serve coffre until `close()`. */
export async function serve(options: ServeOptions): Promise<Server> {
  // Loaded here rather than at the top, so tests of the rest need no UI build.
  const { createUi } = await import('@coffre/ui');
  return serveWith(options, createUi(), uiStaticFiles());
}

/** Where `@coffre/ui` keeps its static files, next to its server build. */
function uiStaticFiles(): string {
  return fileURLToPath(new URL('../client/', import.meta.resolve('@coffre/ui')));
}
