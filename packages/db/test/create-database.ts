import { migrateDatabase } from '../src/migrate.ts';
import { engineOfUrl } from '../src/connect.ts';

/**
 * Create the integration database at a MySQL or SQLite URL, empty and
 * migrated, for scripts/test-suite.sh. A MySQL database of that name is
 * dropped first; a SQLite file is expected not to exist yet.
 */
const url = process.argv[2];
if (!url) throw new Error('usage: create-database.ts <mysql:// or file: URL>');

if (engineOfUrl(url) === 'mysql') {
  const { createConnection } = await import('mysql2/promise');
  const target = new URL(url);
  const name = target.pathname.slice(1);
  target.pathname = '/';
  const server = await createConnection({ uri: target.toString() });
  try {
    await server.query(`DROP DATABASE IF EXISTS \`${name}\``);
    await server.query(`CREATE DATABASE \`${name}\``);
  } finally {
    await server.end();
  }
}

await migrateDatabase(url);
