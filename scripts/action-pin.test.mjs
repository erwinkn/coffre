import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

import { versionOnly } from './version-only.mjs';

const root = resolve(import.meta.dirname, '..');

function checkout(t) {
    const dir = mkdtempSync(join(tmpdir(), 'coffre-action-pin-'));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const files = ['package.json', 'pnpm-workspace.yaml', 'pnpm-lock.yaml', '.npmrc', 'dev/package.json', 'action/action.yml', 'CHANGELOG.md',
        'scripts/bump.mjs', 'scripts/check-pins.mjs', 'scripts/action-pin.mjs', 'scripts/changelog.mjs', 'scripts/lockfile.mjs',
        'packages/cli/src/deployment.ts', 'packages/cli/src/init.ts'];
    for (const base of ['packages', 'examples']) {
        for (const name of readdirSync(join(root, base))) files.push(`${base}/${name}/package.json`);
    }
    for (const name of readdirSync(join(root, 'examples'))) files.push(`examples/${name}/pnpm-workspace.yaml`);
    for (const file of files) {
        mkdirSync(dirname(join(dir, file)), { recursive: true });
        cpSync(join(root, file), join(dir, file));
    }
    symlinkSync(join(root, 'packages/cli/node_modules'), join(dir, 'packages/cli/node_modules'), 'dir');
    return dir;
}

// Bump ends by asking npm's registry how old each pinned dependency is, a
// few seconds of fetches at best and the whole timeout on a slow day. These
// tests check what it writes, never that: offline, it says it could not.
const OFFLINE = 'data:text/javascript,globalThis.fetch = () => Promise.reject(new Error("offline in tests"));';

function run(dir, script, ...args) {
    return spawnSync(process.execPath, ['--import', OFFLINE, join(dir, 'scripts', script), ...args], { cwd: dir, encoding: 'utf8', timeout: 10_000 });
}

test('bump moves the Action with the packages and examples; check:pins rejects drift and ranges', (t) => {
    const dir = checkout(t);
    const bumped = run(dir, 'bump.mjs', '9.8.7-test.1');
    assert.equal(bumped.status, 0, bumped.stderr);
    assert.match(readFileSync(join(dir, 'action/action.yml'), 'utf8'), /npx -y @coffre\/cli@9\.8\.7-test\.1 "\$@"/);
    const today = new Date().toISOString().slice(0, 10);
    assert.equal(
        readFileSync(join(dir, 'CHANGELOG.md'), 'utf8'),
        readFileSync(join(root, 'CHANGELOG.md'), 'utf8').replace('\n## Unreleased\n', `\n## Unreleased\n\n## 9.8.7-test.1 (${today})\n`),
    );
    assert.equal(run(dir, 'check-pins.mjs').status, 0);
    for (const pin of ['9.8.6', '^9.8.7-test.1']) {
        const path = join(dir, 'action/action.yml');
        writeFileSync(path, readFileSync(join(root, 'action/action.yml'), 'utf8').replace(/@coffre\/cli@[^\s]+/, `@coffre/cli@${pin}`));
        const checked = run(dir, 'check-pins.mjs');
        assert.equal(checked.status, 1);
        assert.match(checked.stderr, /action\/action.yml/);
    }
});

test('a release is bump and a commit: pnpm takes its lockfile as it is, and the version-only gate its diff', (t) => {
    const dir = checkout(t);
    const git = (...args) => execFileSync('git', ['-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', '-c', 'user.name=Bump test', '-c', 'user.email=bump@example.test', ...args], { cwd: dir, encoding: 'utf8' }).trim();
    writeFileSync(join(dir, '.gitignore'), 'node_modules\n');
    git('init', '-q');
    git('add', '-A');
    git('commit', '-qm', 'base');
    const bumped = run(dir, 'bump.mjs', '9.8.7');
    assert.equal(bumped.status, 0, bumped.stderr);
    git('commit', '-qam', 'bump');
    assert.deepEqual(versionOnly('HEAD~1', 'HEAD', dir), { versionOnly: true, version: '9.8.7', reason: 'Only synchronized release versions changed' });
    // A frozen install fails on any manifest the lockfile disagrees with.
    const install = spawnSync('pnpm', ['install', '--frozen-lockfile', '--lockfile-only'], { cwd: dir, encoding: 'utf8', timeout: 60_000 });
    assert.equal(install.status, 0, install.stdout + install.stderr);
});

test('a lockfile without the examples\' pins fails before bump edits any manifests', (t) => {
    const dir = checkout(t);
    const before = readFileSync(join(dir, 'packages/cli/package.json'), 'utf8');
    const path = join(dir, 'pnpm-lock.yaml');
    writeFileSync(path, readFileSync(path, 'utf8').replace(/(\n {6}'@coffre\/cli':\n {8}specifier: )\S+/, '$1workspace:*'));
    assert.notEqual(run(dir, 'bump.mjs', '9.8.7').status, 0);
    assert.equal(readFileSync(join(dir, 'packages/cli/package.json'), 'utf8'), before);
});

test('bump leaves release notes without an Unreleased heading, or none, as they are', (t) => {
    const dir = checkout(t);
    const path = join(dir, 'CHANGELOG.md');
    writeFileSync(path, '# Release notes\n\n## 9.8.6 (2026-10-06)\n');
    assert.equal(run(dir, 'bump.mjs', '9.8.7').status, 0);
    assert.equal(readFileSync(path, 'utf8'), '# Release notes\n\n## 9.8.6 (2026-10-06)\n');
    rmSync(path);
    assert.equal(run(dir, 'bump.mjs', '9.8.8').status, 0);
    assert.equal(existsSync(path), false);
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

test('the Action takes one of a token or a service, and a service only with the job\'s ID token; the token goes on stdin', (t) => {
    const dir = checkout(t);
    const bin = join(dir, 'bin');
    mkdirSync(bin);
    writeFileSync(join(bin, 'node'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    // It says where its home is, and leaves a mark there, which must go with the step.
    writeFileSync(join(bin, 'npx'), `#!/bin/sh\necho "$HOME" >> '${join(dir, 'homes')}'\ntouch "$HOME/session"\necho "npx ran with: $*"\necho "stdin: $(cat)"\nexit 0\n`, { mode: 0o755 });
    // The shell's own tools, beside the fakes: cat, for the fake npx.
    const path = `${bin}:/usr/bin:/bin`;
    const text = readFileSync(join(dir, 'action/action.yml'), 'utf8');
    const shell = text.match(/      run: \|\n((?:        [^\n]*\n?)+)/)[1].replace(/^        /gm, '');
    // As GitHub passes them, a default included.
    const inputs = { INPUT_URL: 'https://coffre.example.com', INPUT_ENVIRONMENT: 'app/ci', INPUT_REQUIRE_COMPLETE: 'false' };
    const cli = `-y @coffre/cli@${text.match(/@coffre\/cli@(\S+)/)[1]}`;
    const run = (env) => spawnSync('/bin/bash', ['-e', '-c', shell], { encoding: 'utf8', env: { PATH: path, ...inputs, ...env }, timeout: 10_000 });
    for (const env of [{}, { INPUT_TOKEN: 'coffre_svc_x', INPUT_SERVICE: 'token:api-deploy' }]) {
        const ran = run(env);
        assert.equal(ran.status, 1);
        assert.match(ran.stderr, /needs one of token or service/);
    }
    const noIdToken = run({ INPUT_SERVICE: 'token:api-deploy' });
    assert.equal(noIdToken.status, 1);
    assert.match(noIdToken.stderr, /permissions: id-token: write/);
    const service = run({ INPUT_SERVICE: 'token:api-deploy', ACTIONS_ID_TOKEN_REQUEST_URL: 'https://runner.example/token' });
    assert.equal(service.status, 0, service.stderr);
    assert.equal(service.stdout, `npx ran with: ${cli} --url https://coffre.example.com --service token:api-deploy export --format github app/ci\nstdin: \n`);
    const token = run({ INPUT_TOKEN: 'coffre_svc_x' });
    assert.equal(token.status, 0, token.stderr);
    // The token piped to login, never an argument; the export as that session; and the session forgotten after.
    assert.equal(
        token.stdout,
        `npx ran with: ${cli} login https://coffre.example.com --token\nstdin: coffre_svc_x\n` +
            `npx ran with: ${cli} --url https://coffre.example.com export --format github app/ci\nstdin: \n`,
    );
    assert.ok(!token.stderr.includes('coffre_svc_x'));
    // Several environments, by spaces or lines as a YAML block gives them: a word each, read together.
    const several = run({ INPUT_SERVICE: 'token:api-deploy', ACTIONS_ID_TOKEN_REQUEST_URL: 'https://runner.example/token', INPUT_ENVIRONMENT: 'deploy/prod  auth/prod\nwww/prod\n' });
    assert.equal(several.status, 0, several.stderr);
    assert.equal(several.stdout, `npx ran with: ${cli} --url https://coffre.example.com --service token:api-deploy export --format github deploy/prod auth/prod www/prod\nstdin: \n`);
    // Each step's CLI had a home of its own, not the runner user's, and it went with the step.
    const homes = readFileSync(join(dir, 'homes'), 'utf8').trim().split('\n');
    assert.equal(new Set(homes).size, 3, 'one home per step, shared by its commands');
    for (const home of homes) {
        assert.notEqual(home, process.env.HOME);
        assert.equal(existsSync(home), false, `${home} outlived the step`);
    }
});

test('require-complete checks each environment before anything is read, and stops the step with an annotation for each that lacks keys', (t) => {
    const dir = checkout(t);
    const bin = join(dir, 'bin');
    mkdirSync(bin);
    writeFileSync(join(bin, 'node'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    // A fake CLI: `missing <env> --check` lacks keys in */prod, 50% off included, fails to check down/*, and passes elsewhere.
    writeFileSync(join(bin, 'npx'), `#!/bin/bash
echo "npx ran with: $*" >> '${join(dir, 'calls')}'
cat > /dev/null
for arg in "$@"; do
  case "$arg" in
    */prod) [ "\${*: -1}" = --check ] && { printf 'STRIPE_KEY                   in staging\\nPROMO_50%%                    in dev, staging\\n'; echo "coffre: $arg lacks 2 keys" >&2; exit 1; } ;;
    down/*) [ "\${*: -1}" = --check ] && { echo 'coffre: could not reach it' >&2; exit 1; } ;;
  esac
done
[ "\${*: -1}" != --check ] || echo "\${@: -2:1} has every key of its sibling environments"
exit 0
`, { mode: 0o755 });
    const text = readFileSync(join(dir, 'action/action.yml'), 'utf8');
    const shell = text.match(/      run: \|\n((?:        [^\n]*\n?)+)/)[1].replace(/^        /gm, '');
    const cli = `-y @coffre/cli@${text.match(/@coffre\/cli@(\S+)/)[1]}`;
    const run = (env) => {
        rmSync(join(dir, 'calls'), { force: true });
        const ran = spawnSync('/bin/bash', ['-e', '-o', 'pipefail', '-c', shell], {
            encoding: 'utf8',
            env: { PATH: `${bin}:/usr/bin:/bin`, INPUT_URL: 'https://coffre.example.com', INPUT_TOKEN: 'coffre_svc_x', ...env },
            timeout: 10_000,
        });
        return { ...ran, calls: existsSync(join(dir, 'calls')) ? readFileSync(join(dir, 'calls'), 'utf8').trim().split('\n') : [] };
    };
    const signIn = `npx ran with: ${cli} login https://coffre.example.com --token`;
    const login = `npx ran with: ${cli} --url https://coffre.example.com`;

    const refused = run({ INPUT_ENVIRONMENT: 'app/ci', INPUT_REQUIRE_COMPLETE: 'yes' });
    assert.equal(refused.status, 1);
    assert.match(refused.stderr, /require-complete is true or false/);
    assert.deepEqual(refused.calls, []);

    // Each environment checked, then none read: an annotation per incomplete one, its lines and % escaped.
    const stopped = run({ INPUT_ENVIRONMENT: 'market/prod app/ci api/prod', INPUT_REQUIRE_COMPLETE: 'true' });
    assert.equal(stopped.status, 1);
    assert.deepEqual(stopped.calls, [signIn, `${login} missing market/prod --check`, `${login} missing app/ci --check`, `${login} missing api/prod --check`]);
    const lacks = (environment) =>
        `::error title=${environment} lacks keys its sibling environments have::STRIPE_KEY                   in staging%0APROMO_50%25                    in dev, staging\n`;
    assert.equal(stopped.stdout, `${lacks('market/prod')}app/ci has every key of its sibling environments\n${lacks('api/prod')}`);
    assert.match(stopped.stderr, /coffre: market\/prod lacks 2 keys/);

    // One it could not check stops the step at once, with the CLI's own words and no annotation of missing keys.
    const unchecked = run({ INPUT_ENVIRONMENT: 'down/ci app/ci', INPUT_REQUIRE_COMPLETE: 'true' });
    assert.equal(unchecked.status, 1);
    assert.deepEqual(unchecked.calls, [signIn, `${login} missing down/ci --check`]);
    assert.equal(unchecked.stdout, '');
    assert.match(unchecked.stderr, /could not reach it/);

    // Complete, it says so and reads them as without the check; with a service, each call signs in as it.
    const complete = run({ INPUT_ENVIRONMENT: 'app/ci app/staging', INPUT_REQUIRE_COMPLETE: 'true' });
    assert.equal(complete.status, 0, complete.stderr);
    assert.equal(complete.stdout, 'app/ci has every key of its sibling environments\napp/staging has every key of its sibling environments\n');
    assert.deepEqual(complete.calls, [signIn, `${login} missing app/ci --check`, `${login} missing app/staging --check`, `${login} export --format github app/ci app/staging`]);
    const service = run({ INPUT_TOKEN: '', INPUT_SERVICE: 'token:api-deploy', ACTIONS_ID_TOKEN_REQUEST_URL: 'https://runner.example/token', INPUT_ENVIRONMENT: 'app/ci', INPUT_REQUIRE_COMPLETE: 'true' });
    assert.equal(service.status, 0, service.stderr);
    const as = `npx ran with: ${cli} --url https://coffre.example.com --service token:api-deploy`;
    assert.deepEqual(service.calls, [`${as} missing app/ci --check`, `${as} export --format github app/ci`]);
});
