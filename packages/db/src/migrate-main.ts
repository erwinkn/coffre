// `pnpm db:migrate`: the workspace's own migrator, for dev
// and the tests. A deployment runs `coffre-server migrate`.
import { backupLoginNote, migrateDatabase } from './migrate.ts';

const url = process.env.DATABASE_URL?.trim();
if (!url) throw new Error('DATABASE_URL is required');
const run = await migrateDatabase(url);
console.log('database schema is up to date');
const note = backupLoginNote(run);
if (note !== null) console.log(note);
