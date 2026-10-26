// `pnpm db:migrate [--backup-login <role>]`: the workspace's own migrator,
// for dev and the tests. A deployment runs `coffre-server migrate`.
import { parseArgs } from 'node:util';

import { migrateDatabase } from './migrate.ts';

const url = process.env.DATABASE_URL?.trim();
if (!url) throw new Error('DATABASE_URL is required');
const { values } = parseArgs({ options: { 'backup-login': { type: 'string' } }, strict: true });
await migrateDatabase(url, { backupLogin: values['backup-login'] });
console.log('database schema is up to date');
