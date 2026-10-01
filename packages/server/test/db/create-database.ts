import { migrateDatabase } from '../../src/db/migrate.ts';

/** Create and migrate the suite's SQLite file, which must not exist yet. */
const url = process.argv[2];
if (!url?.startsWith('file:')) throw new Error('usage: create-database.ts <file: URL>');

await migrateDatabase(url);
