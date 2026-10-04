import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

import { versionOnly } from './version-only.mjs';

const json = (value) => `${JSON.stringify(value, null, 2)}\n`;
const lock = `lockfileVersion: '9.0'
settings:
  autoInstallPeers: false
importers:
  examples/node:
    dependencies:
      '@coffre/core':
        specifier: 0.1.13
        version: link:../../packages/core
      third-party:
        specifier: 0.1.13
        version: 0.1.13
    devDependencies:
      '@coffre/cli':
        specifier: 0.1.13
        version: link:../../packages/cli
packages:
  third-party@0.1.13:
    resolution: {integrity: unchanged}
snapshots:
  third-party@0.1.13: {}
`;

function fixture(t, action = true, beforeCommit = () => {}) {
    const dir = mkdtempSync(join(tmpdir(), 'coffre-version-only-'));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const git = (...args) => execFileSync('git', ['-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', '-c', 'user.name=Version gate test', '-c', 'user.email=gate@example.test', ...args], { cwd: dir, encoding: 'utf8' }).trim();
    const write = (path, text) => {
        mkdirSync(dirname(join(dir, path)), { recursive: true });
        writeFileSync(join(dir, path), text);
    };
    const edit = (path, change) => write(path, change(readFileSync(join(dir, path), 'utf8')));
    const commit = () => { git('add', '-A'); git('commit', '-qm', 'fixture'); return git('rev-parse', 'HEAD'); };
    git('init', '-q');
    write('packages/cli/package.json', json({ name: '@coffre/cli', version: '0.1.13', scripts: { version: 'node scripts/version.js' }, devDependencies: { '@coffre/core': 'workspace:*' } }));
    write('packages/core/package.json', json({ name: '@coffre/core', version: '0.1.13' }));
    write('examples/node/package.json', json({ name: 'coffre-node', version: '0.0.0', dependencies: { '@coffre/core': '0.1.13', 'third-party': '0.1.13' }, devDependencies: { '@coffre/cli': '0.1.13' } }));
    write('pnpm-lock.yaml', lock);
    write('packages/core/src/untouched.ts', 'export const answer = 42;\n');
    if (action) write('action/action.yml', 'runs:\n  using: composite\n  steps:\n    - run: npx -y @coffre/cli@0.1.13 export --format github "$INPUT_ENVIRONMENT"\n');
    beforeCommit({ write, edit });
    const base = commit();
    for (const path of ['packages/cli/package.json', 'packages/core/package.json']) {
        edit(path, (text) => { const pkg = JSON.parse(text); pkg.version = '0.1.14'; return json(pkg); });
    }
    edit('examples/node/package.json', (text) => {
        const pkg = JSON.parse(text);
        pkg.dependencies['@coffre/core'] = pkg.devDependencies['@coffre/cli'] = '0.1.14';
        return json(pkg);
    });
    edit('pnpm-lock.yaml', (text) => text.replace(/('@coffre\/(?:cli|core)':\n        specifier: )0\.1\.13/g, '$10.1.14'));
    if (action) edit('action/action.yml', (text) => text.replace('@coffre/cli@0.1.13', '@coffre/cli@0.1.14'));
    return { dir, base, edit, write, commit, check: () => versionOnly(base, commit(), dir) };
}

test('a synchronized bump qualifies, including the exact Action pin or a legacy release without it', (t) => {
    for (const action of [true, false]) {
        const f = fixture(t, action);
        assert.deepEqual(f.check(), { versionOnly: true, version: '0.1.14', reason: 'Only synchronized release versions changed' });
    }
});

test('one extra code line selects every normal check', (t) => {
    const f = fixture(t);
    f.edit('packages/core/src/untouched.ts', (text) => `${text}export const extra = 1;\n`);
    assert.equal(f.check().versionOnly, false);
});

test('manifest changes beyond synchronized release fields cannot qualify', (t) => {
    const cases = [
        ['packages/cli/package.json', (text) => text.replace('node scripts/version.js', 'echo 0.1.14')],
        ['packages/cli/package.json', (text) => text.replace('workspace:*', '0.1.14')],
        ['packages/core/package.json', (text) => text.replace('0.1.14', '0.1.15')],
        ['packages/core/package.json', (text) => text.replace('0.1.14', '0.1.13')],
        ['examples/node/package.json', (text) => text.replace('"third-party": "0.1.13"', '"third-party": "0.1.14"')],
        ['examples/node/package.json', (text) => text.replace('"@coffre/core": "0.1.14"', '"@coffre/core": "0.1.13"')],
        ['packages/core/package.json', (text) => text.replace('  "version":', '  "version": "0.1.14",\n  "version":')],
        ['packages/core/package.json', (text) => text.replace('  ', '\t')],
        ['packages/core/package.json', () => '{bad json}'],
    ];
    for (const [path, change] of cases) {
        const f = fixture(t);
        f.edit(path, change);
        assert.equal(f.check().versionOnly, false, change.toString());
    }
});

test('lockfile context matters: other specifiers, links, settings and integrity stay unchanged', (t) => {
    for (const change of [
        (text) => text.replace('specifier: 0.1.13', 'specifier: 0.1.14'),
        (text) => text.replace('version: 0.1.13', 'version: 0.1.14'),
        (text) => text.replace('link:../../packages/core', 'link:../../packages/cli'),
        (text) => text.replace('link:../../packages/core', '0.1.14'),
        (text) => text.replace('autoInstallPeers: false', 'autoInstallPeers: true'),
        (text) => text.replace('integrity: unchanged', 'integrity: changed'),
        (text) => text.replace("'@coffre/core':\n        specifier: 0.1.14", "'@coffre/core':\n        specifier: 0.1.13"),
        (text) => `${text}\n# a release comment is also a change\n`,
    ]) {
        const f = fixture(t);
        f.edit('pnpm-lock.yaml', change);
        assert.equal(f.check().versionOnly, false, change.toString());
    }
});

test('Action changes beyond the literal pin, including a missing bump, require all checks', (t) => {
    for (const change of [
        (text) => text.replace('--format github', '--format shell'),
        (text) => text.replace('0.1.14', '0.1.13'),
        (text) => `${text}    - run: echo another command\n`,
    ]) {
        const f = fixture(t);
        f.edit('action/action.yml', change);
        assert.equal(f.check().versionOnly, false);
    }
});

test('deletions, renames, new files and permission changes are not version bumps', (t) => {
    for (const change of [
        (f) => rmSync(join(f.dir, 'packages/core/src/untouched.ts')),
        (f) => renameSync(join(f.dir, 'packages/core/package.json'), join(f.dir, 'packages/core/renamed.json')),
        (f) => f.write('CHANGELOG.md', 'Release notes\n'),
        (f) => chmodSync(join(f.dir, 'packages/core/package.json'), 0o755),
    ]) {
        const f = fixture(t);
        change(f);
        assert.equal(f.check().versionOnly, false);
    }
});

test('invalid or non-string versions never qualify, even when all fields agree', (t) => {
    for (const version of [['0.1.14'], '01.1.14', '0.1.14-rc..1', '0.1.14-01', '0.1.14\n', '9007199254740992.0.0', '0.1.14-' + 'r'.repeat(256)]) {
        const f = fixture(t);
        for (const path of ['packages/cli/package.json', 'packages/core/package.json']) {
            f.edit(path, (text) => { const pkg = JSON.parse(text); pkg.version = version; return json(pkg); });
        }
        f.edit('examples/node/package.json', (text) => {
            const pkg = JSON.parse(text);
            pkg.dependencies['@coffre/core'] = pkg.devDependencies['@coffre/cli'] = version;
            return json(pkg);
        });
        f.edit('pnpm-lock.yaml', (text) => text.replaceAll('specifier: 0.1.14', `specifier: ${String(version)}`));
        f.edit('action/action.yml', (text) => text.replace('@coffre/cli@0.1.14', `@coffre/cli@${String(version)}`));
        assert.equal(f.check().versionOnly, false);
    }
});

test('invalid UTF-8 cannot hide a non-version byte change behind replacement characters', (t) => {
    const f = fixture(t, true, ({ write }) => write('pnpm-lock.yaml', Buffer.concat([Buffer.from(lock + '# '), Buffer.from([0xfe])])));
    // The fixture's bump reads UTF-8 and rewrites it, changing the invalid
    // byte to U+FFFD. A permissive decoder would miss that unrelated edit.
    assert.equal(f.check().versionOnly, false);
});

test('an empty diff or unavailable refs select full validation; CLI output fails closed', (t) => {
    const f = fixture(t);
    assert.equal(versionOnly(f.base, f.base, f.dir).versionOnly, false);
    assert.equal(versionOnly('no-such-ref', 'HEAD', f.dir).versionOnly, false);
    const output = join(f.dir, 'output');
    const ran = spawnSync(process.execPath, [resolve(import.meta.dirname, 'version-only.mjs'), 'no-such-ref'], {
        cwd: f.dir, encoding: 'utf8', env: { ...process.env, GITHUB_OUTPUT: output }, timeout: 5000,
    });
    assert.equal(ran.status, 0, ran.stderr);
    assert.equal(JSON.parse(ran.stdout).versionOnly, false);
    assert.equal(readFileSync(output, 'utf8'), 'version_only=false\n');
});
