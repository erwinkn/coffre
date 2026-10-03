import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

const root = resolve(import.meta.dirname, '..');

function checkout(t) {
    const dir = mkdtempSync(join(tmpdir(), 'coffre-action-pin-'));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const files = ['package.json', 'dev/package.json', 'action/action.yml', 'scripts/bump.mjs', 'scripts/check-pins.mjs', 'scripts/action-pin.mjs',
        'packages/cli/src/deployment.ts', 'packages/cli/src/init.ts'];
    for (const base of ['packages', 'examples']) {
        for (const name of readdirSync(join(root, base))) files.push(`${base}/${name}/package.json`);
    }
    for (const file of files) {
        mkdirSync(dirname(join(dir, file)), { recursive: true });
        cpSync(join(root, file), join(dir, file));
    }
    symlinkSync(join(root, 'packages/cli/node_modules'), join(dir, 'packages/cli/node_modules'), 'dir');
    return dir;
}

function run(dir, script, ...args) {
    return spawnSync(process.execPath, [join(dir, 'scripts', script), ...args], { cwd: dir, encoding: 'utf8', timeout: 10_000 });
}

test('bump moves the Action with the packages and examples; check:pins rejects drift and ranges', (t) => {
    const dir = checkout(t);
    const bumped = run(dir, 'bump.mjs', '9.8.7-test.1');
    assert.equal(bumped.status, 0, bumped.stderr);
    assert.match(readFileSync(join(dir, 'action/action.yml'), 'utf8'), /npx -y @coffre\/cli@9\.8\.7-test\.1 export/);
    assert.equal(run(dir, 'check-pins.mjs').status, 0);
    for (const pin of ['9.8.6', '^9.8.7-test.1']) {
        const path = join(dir, 'action/action.yml');
        writeFileSync(path, readFileSync(join(root, 'action/action.yml'), 'utf8').replace(/@coffre\/cli@[^\s]+/, `@coffre/cli@${pin}`));
        const checked = run(dir, 'check-pins.mjs');
        assert.equal(checked.status, 1);
        assert.match(checked.stderr, /action\/action.yml/);
    }
});

test('a malformed or missing Action fails before bump edits any manifests', (t) => {
    const dir = checkout(t);
    const path = join(dir, 'action/action.yml');
    const before = readFileSync(join(dir, 'packages/cli/package.json'), 'utf8');
    writeFileSync(path, 'runs: {}\n');
    assert.notEqual(run(dir, 'bump.mjs', '9.8.7').status, 0);
    assert.equal(readFileSync(join(dir, 'packages/cli/package.json'), 'utf8'), before);
    rmSync(path);
    assert.equal(run(dir, 'check-pins.mjs').status, 1);
});

test('the Action refuses an unsupported Node before npx runs, with a clear minimum', (t) => {
    const dir = checkout(t);
    const bin = join(dir, 'bin');
    mkdirSync(bin);
    writeFileSync(join(bin, 'node'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
    writeFileSync(join(bin, 'npx'), '#!/bin/sh\necho npx-must-not-run\nexit 0\n', { mode: 0o755 });
    const text = readFileSync(join(dir, 'action/action.yml'), 'utf8');
    const block = text.match(/      run: \|\n((?:        [^\n]*\n?)+)/)[1];
    const shell = block.replace(/^        /gm, '');
    const ran = spawnSync('/bin/bash', ['-e', '-c', shell], { encoding: 'utf8', env: { PATH: bin }, timeout: 10_000 });
    assert.equal(ran.status, 1);
    assert.match(ran.stderr, /requires Node.js 20 or newer/);
    assert.doesNotMatch(ran.stdout, /npx-must-not-run/);
});
