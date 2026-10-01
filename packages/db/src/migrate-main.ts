// `pnpm --dir packages/db migrate`: the workspace's own migrator, for dev
// and the tests. A deployment runs `coffre-server migrate`.
import { migrateDatabase } from './migrate.ts';

const url = process.env.DATABASE_URL?.trim();
if (!url) throw new Error('DATABASE_URL is required');
await migrateDatabase(url);
console.log('database schema is up to date');
