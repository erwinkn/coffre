#!/usr/bin/env node
// Fail if any dependency is specified as a range rather than an exact version.
//
// This exists because pnpm's savePrefix setting is read but not honoured on
// `pnpm add`, so the policy cannot be enforced by configuration alone. A
// control that silently does nothing is worse than no control, which is the
// whole reason this project exists.

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const EXACT = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const DEP_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies'];

const manifests = ['package.json', 'dev/package.json'];
for (const dir of ['packages', 'examples']) {
    const base = join(root, dir);
    if (!existsSync(base)) continue;
    for (const entry of readdirSync(base)) {
        const candidate = join(dir, entry, 'package.json');
        if (existsSync(join(root, candidate))) manifests.push(candidate);
    }
}

const problems = [];

for (const manifest of manifests) {
    const pkg = JSON.parse(readFileSync(join(root, manifest), 'utf8'));
    for (const field of DEP_FIELDS) {
        for (const [name, range] of Object.entries(pkg[field] ?? {})) {
            // Workspace links are not versions.
            if (range.startsWith('workspace:')) continue;
            if (!EXACT.test(range)) {
                problems.push(`${manifest}: ${field}.${name} = "${range}" is not an exact pin`);
            }
        }
    }
}

if (problems.length > 0) {
    console.error('Dependency pinning check FAILED:\n');
    for (const problem of problems) console.error(`  ${problem}`);
    console.error('\nUse: pnpm add --save-exact <pkg>@<version>');
    process.exit(1);
}

console.log(`Dependency pinning check passed (${manifests.length} manifests, all exact).`);
