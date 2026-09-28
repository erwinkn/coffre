#!/usr/bin/env node
// Fail if `@coffre/ui`'s build holds anything but pages.
//
// The UI renders; `@coffre/server` owns the API, the database and the
// configuration. Nothing errors when a page imports across that line: a
// bundler keeps a module whose top level has side effects, such as
// `pgTable(...)`, even when nothing uses its exports, and the build just grows
// by the database layer. So look for it, in both halves of the build: what
// the browser loads (`dist/client`) and what renders it (`dist/server`).
//
// The markers:
// - Drizzle's own `drizzle:` symbol keys, which any of its code carries, and
//   the schema's snake_case table names, read from schema.ts so a new table
//   is covered without editing this file. Single-word names such as
//   `secrets` also appear in the pages' own copy, so they are not markers.
// - The database drivers, by strings their code cannot do without.
// - A read of a `COFFRE_*` variable: the UI has no configuration.
// - The Agentation toolbar, which is for `vite dev` only.

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const distDir = join(root, 'packages/ui/dist');

for (const half of ['client', 'server']) {
    if (!existsSync(join(distDir, half))) {
        console.error(`No build at ${relative(root, join(distDir, half))}; run \`pnpm --dir packages/ui build\` first.`);
        process.exit(1);
    }
}

const schema = readFileSync(join(root, 'packages/server/src/db/schema.ts'), 'utf8');
const tables = [...schema.matchAll(/pgTable\(\s*'([a-z_]+)'/g)]
    .map((match) => match[1])
    .filter((name) => name.includes('_'));
if (tables.length === 0) {
    console.error('Read no table names from packages/server/src/db/schema.ts; the check would pass vacuously.');
    process.exit(1);
}
const markers = [
    { label: 'drizzle-orm', pattern: /drizzle:[A-Z]/ },
    ...tables.map((name) => ({ label: `table ${name}`, pattern: new RegExp(`\\b${name}\\b`) })),
    { label: 'pg', pattern: /cloudflare:sockets|pg-protocol|pgpass/ },
    { label: 'mysql2', pattern: /mysql2|mysql_native_password/ },
    { label: 'libsql', pattern: /@libsql|libsql/ },
    { label: 'a COFFRE_ variable read', pattern: /env\s*(\.|\[\s*['"`])COFFRE_/ },
    { label: 'agentation', pattern: /agentation-(theme|root|color)/ },
];

function* scripts(dir) {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const path = join(dir, entry.name);
        if (entry.isDirectory()) yield* scripts(path);
        else if (/\.(m?js|css)$/.test(entry.name)) yield path;
    }
}

const problems = [];
let checked = 0;
for (const file of scripts(distDir)) {
    checked += 1;
    const source = readFileSync(file, 'utf8');
    for (const { label, pattern } of markers) {
        if (pattern.test(source)) problems.push(`${relative(root, file)}: ${label}`);
    }
}

if (problems.length > 0) {
    console.error("Something other than pages reached @coffre/ui's build:");
    for (const problem of problems) console.error(`  ${problem}`);
    console.error('A page imports server code; pages reach the API only through context.client.');
    process.exit(1);
}

console.log(`UI bundle check passed (${checked} files: no database, driver, configuration or Agentation code).`);
