#!/usr/bin/env node
// coffre-server migrate [database-url]
//
// Brings a database up to date with this version of coffre. The URL is the
// argument, or DATABASE_URL: a direct Postgres URL for a Workers deployment
// (not Hyperdrive's), or whatever `serve` is given on Node.

import { migrateDatabase } from '@coffre/db/migrate';

const USAGE = 'usage: coffre-server migrate [database-url]   (or set DATABASE_URL)';

const [command, url = process.env.DATABASE_URL?.trim(), ...rest] = process.argv.slice(2);
if (command === '--help' || command === '-h') {
  console.log(USAGE);
} else if (command !== 'migrate' || rest.length > 0) {
  console.error(USAGE);
  process.exitCode = 2;
} else if (!url) {
  console.error('coffre-server: no database URL: pass one, or set DATABASE_URL');
  process.exitCode = 2;
} else {
  await migrateDatabase(url);
  console.log('database schema is up to date');
}
