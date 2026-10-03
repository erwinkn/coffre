#!/usr/bin/env node
// Move every coffre package to one new version, and the examples' pins with
// them, since `coffre init` copies those as they are.
//
//   pnpm bump 0.2.0
//
// It edits package.json files, the examples' pnpm with them, and the Action's CLI pin: building, tagging and publishing are
// separate steps, and none of them happens here.

import { readdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

import { bumpPins, pinPackageManager } from '../packages/cli/src/deployment.ts';
import { bumpAction } from './action-pin.mjs';

const root = new URL('..', import.meta.url).pathname;
const version = process.argv[2];
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version ?? '')) {
    console.error('usage: pnpm bump <version>, e.g. 0.2.0');
    process.exit(2);
}

// Validate before editing any manifest, so a malformed Action cannot leave
// half of a release bumped.
const actionPath = join(root, 'action/action.yml');
const action = bumpAction(readFileSync(actionPath, 'utf8'), version);

const manifests = (dir) =>
    readdirSync(join(root, dir))
        .map((entry) => join(dir, entry, 'package.json'))
        .filter((manifest) => existsSync(join(root, manifest)));

function edit(manifest, change) {
    const path = join(root, manifest);
    const pkg = JSON.parse(readFileSync(path, 'utf8'));
    change(pkg);
    writeFileSync(path, `${JSON.stringify(pkg, null, 2)}\n`);
}

for (const manifest of manifests('packages')) {
    edit(manifest, (pkg) => {
        pkg.version = version;
    });
}
// The examples as `coffre update` moves a deployment: every @coffre/* pin,
// and pnpm, the workspace's.
const pnpm = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).packageManager;
for (const example of readdirSync(join(root, 'examples'))) {
    const dir = join(root, 'examples', example);
    if (!existsSync(join(dir, 'package.json'))) continue;
    bumpPins(dir, version);
    pinPackageManager(dir, pnpm);
}
writeFileSync(actionPath, action);
console.log(`coffre ${version}: every package, both examples and the Action. Run pnpm install to relink the examples.`);

// For the release notes: whatever a published package pins that is younger
// than the minimumReleaseAge every deployment holds. Ranges below those pins
// do not matter: pnpm picks a version old enough when one fits. An exact pin
// leaves it no choice, and the deployment's install waits, or lets it
// through as `coffre update` offers. Best-effort: offline, it says so.
const AGE_DAYS = 7;
const pinned = new Set();
for (const manifest of manifests('packages')) {
    const pkg = JSON.parse(readFileSync(join(root, manifest), 'utf8'));
    if (pkg.private) continue;
    for (const [name, pin] of Object.entries(pkg.dependencies ?? {})) {
        if (!name.startsWith('@coffre/')) pinned.add(`${name}@${pin}`);
    }
}
try {
    const now = Date.now();
    const young = (
        await Promise.all(
            [...pinned].map(async (spec) => {
                const at = spec.lastIndexOf('@');
                const [name, pin] = [spec.slice(0, at), spec.slice(at + 1)];
                const response = await fetch(`https://registry.npmjs.org/${name.replace('/', '%2F')}`);
                if (!response.ok) throw new Error(`${name}: the registry answered ${response.status}`);
                const published = Date.parse((await response.json()).time?.[pin] ?? '');
                return now - published < AGE_DAYS * 86_400_000 ? { spec, clears: new Date(published + AGE_DAYS * 86_400_000) } : null;
            }),
        )
    ).filter((entry) => entry !== null);
    if (young.length === 0) {
        console.log(`Every dependency coffre ${version} pins is at least ${AGE_DAYS} days old: deployments install it at once.`);
    } else {
        const last = young.map(({ clears }) => clears).sort((a, b) => a - b).at(-1);
        console.log(
            `For the release notes: ${young.map(({ spec }) => spec).join(', ')} ${young.length === 1 ? 'is' : 'are'} younger than ` +
                `${AGE_DAYS} days, so a deployment's pnpm holds coffre ${version} back until ${last.toISOString().slice(0, 16).replace('T', ' ')} UTC: ` +
                'wait until then, or let them through as `coffre update` offers.',
        );
    }
} catch (error) {
    console.log(`Could not check how old coffre ${version}'s dependencies are: ${error.message}`);
}
