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
import { actionPin } from './action-pin.mjs';

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

try {
    const pin = actionPin(readFileSync(join(root, 'action/action.yml'), 'utf8'));
    if (pin !== version) problems.push(`action/action.yml: CLI ${pin} is not ${version}, the packages' version`);
} catch (error) {
    problems.push(error.message);
}

// The one pnpm: the workspace's, which the examples pin too, so that a
// deployment `init` writes installs with it everywhere, Workers Builds and
// CI included, and each enforces minimumReleaseAge alike.
const pnpm = read('package.json').packageManager;

for (const manifest of manifests) {
    const pkg = read(manifest);
    const inWorkspace = !manifest.startsWith('examples/');
    if (!inWorkspace && pkg.packageManager !== pnpm) {
        problems.push(`${manifest}: packageManager ${pkg.packageManager ?? 'missing'} is not ${pnpm}, the workspace's`);
    }
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

// What a deployment's Start app shares with the pages: one copy of each, at
// the version @coffre/ui is built with, which each example pins exactly, as
// `coffre init` writes it and `coffre update` moves it.
const peers = read('packages/ui/package.json').peerDependencies ?? {};
for (const manifest of manifests.filter((path) => path.startsWith('examples/'))) {
    const pkg = read(manifest);
    for (const [name, wanted] of Object.entries(peers)) {
        const pin = pkg.dependencies?.[name] ?? pkg.devDependencies?.[name];
        if (pin !== wanted) problems.push(`${manifest}: ${name} is ${pin ?? 'missing'}, and @coffre/ui is built for ${wanted}`);
    }
}

// @coffre/server's routes and middleware go in that same app, so it peers on
// the same TanStack. Both name router-core, whose types their declarations
// import, at the version react-router itself depends on: another copy would
// lack react-router's additions to its `Route`, and coffre's routes would not
// fit the deployment's tree.
const server = read('packages/server/package.json');
for (const [name, wanted] of Object.entries(server.peerDependencies ?? {})) {
    if (name.startsWith('@tanstack/') && peers[name] !== wanted) {
        problems.push(`packages/server/package.json: peer ${name} is ${wanted}, and @coffre/ui's is ${peers[name] ?? 'missing'}`);
    }
}
const routerManifest = join(root, 'packages/ui/node_modules/@tanstack/react-router/package.json');
if (existsSync(routerManifest)) {
    const core = JSON.parse(readFileSync(routerManifest, 'utf8')).dependencies['@tanstack/router-core'];
    for (const manifest of ['packages/ui/package.json', 'packages/server/package.json']) {
        const pin = read(manifest).dependencies?.['@tanstack/router-core'];
        if (pin !== core) problems.push(`${manifest}: @tanstack/router-core is ${pin ?? 'missing'}, and react-router depends on ${core}`);
    }
}

if (problems.length > 0) {
    console.error('Dependency pinning check FAILED:\n');
    for (const problem of problems) console.error(`  ${problem}`);
    console.error('\nUse: pnpm run add:dep <pkg>@<version>, and `pnpm bump <version>` to move every package.');
    process.exit(1);
}

console.log(`Dependency pinning check passed (${manifests.length} manifests and the Action, all exact; coffre ${version} throughout).`);
