#!/usr/bin/env node
// Move every coffre package to one new version, and the examples' pins with
// them, since `coffre init` copies those as they are.
//
//   pnpm bump 0.2.0
//
// It edits package.json files and the Action's CLI pin: building, tagging and publishing are
// separate steps, and none of them happens here.

import { readdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

import { bumpPins } from '../packages/cli/src/deployment.ts';
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
// The examples as `coffre update` moves a deployment: every @coffre/* pin.
for (const example of readdirSync(join(root, 'examples'))) {
    if (existsSync(join(root, 'examples', example, 'package.json'))) bumpPins(join(root, 'examples', example), version);
}
writeFileSync(actionPath, action);
console.log(`coffre ${version}: every package, both examples and the Action. Run pnpm install to relink the examples.`);
