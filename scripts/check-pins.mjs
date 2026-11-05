#!/usr/bin/env node
// Fail if any dependency is specified as a range rather than an exact version,
// or if coffre's own packages drift apart: they move in lockstep, one version
// for all, each depending on the others through the workspace, and the
// examples pinning exactly that version, as `coffre init` writes them. Then
// hold every tracked workflow, Dockerfile, compose file, script and pnpm
// setting to what it fetches being pinned (scripts/pins.mjs).
//
// This exists because pnpm's savePrefix setting is read but not honoured on
// `pnpm add`, so the policy cannot be enforced by configuration alone. A
// control that silently does nothing is worse than no control, which is the
// whole reason this project exists.

import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { kindOf, problemsIn } from './pins.mjs';

const root = new URL('..', import.meta.url).pathname;
const EXACT = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const DEP_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
// What pnpm runs of a workspace project's own on install
// (pnpm.io/scripts#lifecycle-scripts): nothing, as of its dependencies'.
const INSTALL_SCRIPTS = ['pnpm:devPreinstall', 'preinstall', 'install', 'postinstall', 'preprepare', 'prepare', 'postprepare'];
// pnpm's settings live in pnpm-workspace.yaml, which scripts/pins.mjs reads.
const PNPM_SETTINGS = ['allowBuilds', 'onlyBuiltDependencies', 'onlyBuiltDependenciesFile', 'neverBuiltDependencies', 'dangerouslyAllowAllBuilds', 'minimumReleaseAge', 'minimumReleaseAgeExclude', 'strictDepBuilds', 'ignoreScripts'];

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
    for (const script of INSTALL_SCRIPTS) {
        if (pkg.scripts?.[script] !== undefined) problems.push(`${manifest}: scripts.${script} runs on install`);
    }
    for (const setting of PNPM_SETTINGS) {
        if (pkg.pnpm?.[setting] !== undefined) problems.push(`${manifest}: pnpm.${setting} belongs in pnpm-workspace.yaml, where check:pins reads it`);
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

// A Node deployment imports SQLite's driver itself, where its server's
// build leaves it out (examples/node/app/vite.config.ts): the one
// @coffre/db is built with.
const libsql = read('packages/db/package.json').dependencies['@libsql/client'];
const nodeDriver = read('examples/node/package.json').dependencies?.['@libsql/client'];
if (nodeDriver !== libsql) problems.push(`examples/node/package.json: @libsql/client is ${nodeDriver ?? 'missing'}, and @coffre/db's is ${libsql}`);

// The Node a deployment's workflow runs is the workspace's, which CI runs.
const node = (path) => readFileSync(join(root, path), 'utf8').match(/node-version: (\S+)/)?.[1];
const workspaceNode = node('.github/actions/prepare/action.yml');
const deployNode = node('examples/workers/.github/workflows/deploy.yml');
if (deployNode !== workspaceNode) problems.push(`examples/workers/.github/workflows/deploy.yml: node-version ${deployNode}, and CI's is ${workspaceNode}`);

const tracked = execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8' }).split('\0').filter(Boolean);
let files = 0;
for (const path of tracked) {
    if (kindOf(path) === null || !existsSync(join(root, path))) continue;
    files++;
    problems.push(...problemsIn(path, readFileSync(join(root, path), 'utf8'), { root: path === 'pnpm-workspace.yaml' }));
}

if (problems.length > 0) {
    console.error('Dependency pinning check FAILED:\n');
    for (const problem of problems) console.error(`  ${problem}`);
    console.error('\nUse: pnpm run add:dep <pkg>@<version>, and `pnpm bump <version>` to move every package.');
    console.error('Pin an action as owner/repo@<commit SHA> # v<version>, an image as name:tag@sha256:<index digest>, a download by its SHA-256;');
    console.error('a line that cannot be pinned says why: `# unpinned: <reason>`.');
    process.exit(1);
}

console.log(`Dependency pinning check passed (${manifests.length} manifests, all exact; coffre ${version} throughout; ${files} workflow, image, script and pnpm files pinned).`);
