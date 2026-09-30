#!/usr/bin/env node
// Fail if any dependency is specified as a range rather than an exact version,
// or if coffre's own packages drift apart: they move in lockstep, one version
// for all, each depending on the others through the workspace, and the
// examples pinning exactly that version, as `coffre init` writes them.
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
const read = (manifest) => JSON.parse(readFileSync(join(root, manifest), 'utf8'));

// The one version every package carries: the CLI's, which `init` writes.
const version = read('packages/cli/package.json').version;

for (const manifest of manifests) {
    const pkg = read(manifest);
    const inWorkspace = !manifest.startsWith('examples/');
    if (manifest.startsWith('packages/') && pkg.version !== version) {
        problems.push(`${manifest}: version ${pkg.version} is not ${version}, the other packages'`);
    }
    for (const field of DEP_FIELDS) {
        for (const [name, range] of Object.entries(pkg[field] ?? {})) {
            if (name.startsWith('@coffre/')) {
                const want = inWorkspace ? 'workspace:*' : version;
                if (range !== want) problems.push(`${manifest}: ${field}.${name} = "${range}" should be "${want}"`);
                continue;
            }
            if (!EXACT.test(range)) {
                problems.push(`${manifest}: ${field}.${name} = "${range}" is not an exact pin`);
            }
        }
    }
}

if (problems.length > 0) {
    console.error('Dependency pinning check FAILED:\n');
    for (const problem of problems) console.error(`  ${problem}`);
    console.error('\nUse: pnpm run add:dep <pkg>@<version>, and `pnpm bump <version>` to move every package.');
    process.exit(1);
}

console.log(`Dependency pinning check passed (${manifests.length} manifests, all exact; coffre ${version} throughout).`);
