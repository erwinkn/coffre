#!/usr/bin/env node
// Fail if database code reached the browser bundle.
//
// The browser gets `start.ts` along with the pages, and a single import from
// it into server code can carry Drizzle, the schema and every query with it:
// a bundler keeps a module whose top level has side effects, such as
// `pgTable(...)`, even when nothing uses its exports. Nothing errors when that
// happens; the bundle just grows by the database layer. So look for it.
//
// Two markers: Drizzle's own `drizzle:` symbol keys, which any of its code
// carries, and the schema's snake_case table names, read from schema.ts so a
// new table is covered without editing this file. Single-word names such as
// `secrets` also appear in the pages' own copy, so they are not markers.

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const clientDir = join(root, 'apps/web/dist/client');

if (!existsSync(clientDir)) {
    console.error(`No client build at ${relative(root, clientDir)}; run the web build first.`);
    process.exit(1);
}

const schema = readFileSync(join(root, 'packages/db/src/schema.ts'), 'utf8');
const tables = [...schema.matchAll(/pgTable\(\s*'([a-z_]+)'/g)]
    .map((match) => match[1])
    .filter((name) => name.includes('_'));
if (tables.length === 0) {
    console.error('Read no table names from packages/db/src/schema.ts; the check would pass vacuously.');
    process.exit(1);
}
const markers = [
    { label: 'drizzle-orm', pattern: /drizzle:[A-Z]/ },
    ...tables.map((name) => ({ label: `table ${name}`, pattern: new RegExp(`\\b${name}\\b`) })),
];

function* scripts(dir) {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const path = join(dir, entry.name);
        if (entry.isDirectory()) yield* scripts(path);
        else if (/\.m?js$/.test(entry.name)) yield path;
    }
}

const problems = [];
let checked = 0;
for (const file of scripts(clientDir)) {
    checked += 1;
    const source = readFileSync(file, 'utf8');
    for (const { label, pattern } of markers) {
        if (pattern.test(source)) problems.push(`${relative(root, file)}: ${label}`);
    }
}

if (problems.length > 0) {
    console.error('Database code reached the browser bundle:');
    for (const problem of problems) console.error(`  ${problem}`);
    console.error('Something the browser loads imports server code; see apps/web/src/server/request-identity.ts.');
    process.exit(1);
}

console.log(`Client bundle check passed (${checked} scripts, no database code).`);
