#!/usr/bin/env node
// The migration a release's conformance runs under `pnpm test:compat`
// (compat-check.sh): this checkout's migrations, on the database it names.
// With --only, none of them: the one SQL file given, for the check's own
// synthetic destructive migration.
//
//   node --conditions=coffre:source scripts/compat-migrate.mjs <url>
//   node scripts/compat-migrate.mjs --only <url> <file.sql>
import { readFileSync } from 'node:fs';

const args = process.argv.slice(2);
if (args[0] === '--only') {
    await apply(args[1], readFileSync(args[2], 'utf8'));
} else {
    const { migrateDatabase } = await import('@coffre/db/migrate');
    await migrateDatabase(args[0]);
}

async function apply(url, text) {
    if (url.startsWith('file:')) {
        const { DatabaseSync } = await import('node:sqlite');
        const db = new DatabaseSync(new URL(url).pathname);
        try {
            db.exec(text);
        } finally {
            db.close();
        }
        return;
    }
    const { default: pg } = await import('pg');
    const client = new pg.Client({ connectionString: url });
    await client.connect();
    try {
        await client.query(text);
    } finally {
        await client.end();
    }
}
