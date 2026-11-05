import assert from 'node:assert/strict';
import test from 'node:test';
import { problemsIn } from './pins.mjs';

const SHA = '11d5960a326750d5838078e36cf38b85af677262';
const DIGEST = 'sha256:' + 'a'.repeat(64);
const one = (path, text, options) => problemsIn(path, text, options);

test('an action is pinned by its commit, its version beside it; the repository’s own is not', () => {
    const workflow = (uses) => `jobs:\n  a:\n    steps:\n      - uses: ${uses}\n`;
    assert.deepEqual(one('.github/workflows/a.yml', workflow(`actions/checkout@${SHA} # v4.4.0`)), []);
    assert.deepEqual(one('.github/workflows/a.yml', workflow('$/.github/actions/prepare')), []);
    assert.deepEqual(one('.github/workflows/a.yml', workflow('./action')), []);
    assert.match(one('.github/workflows/a.yml', workflow('actions/checkout@v4'))[0], /a\.yml:4: uses actions\/checkout@v4 is not owner\/repo@<commit SHA>/);
    assert.equal(one('.github/workflows/a.yml', workflow(`actions/checkout@${SHA}`)).length, 1, 'no version beside it');
    assert.equal(one('examples/workers/.github/workflows/deploy.yml', workflow('actions/setup-node@main')).length, 1);
    assert.equal(one('action/action.yml', `runs:\n  steps:\n    - uses: actions/cache@v4\n`).length, 1);
});

test('an image is name:tag@sha256:<digest>, in compose, a workflow, a Dockerfile or a command', () => {
    assert.deepEqual(one('docker-compose.yml', `services:\n  postgres:\n    image: postgres:16.14@${DIGEST}\n`), []);
    assert.match(one('docker-compose.yml', 'services:\n  postgres:\n    image: postgres:16.14\n')[0], /image postgres:16\.14 is not name:tag@sha256/);
    assert.equal(one('docker-compose.yml', `services:\n  p:\n    image: postgres@${DIGEST}\n`).length, 1, 'the tag, for people');
    assert.equal(one('.github/workflows/a.yml', 'jobs:\n  a:\n    services:\n      pg:\n        image: postgres:16\n').length, 1);
    assert.equal(one('.github/workflows/a.yml', 'jobs:\n  a:\n    container: node:24\n').length, 1);
    assert.deepEqual(one('packages/cli/Dockerfile', `FROM scratch AS cli\nFROM gcr.io/distroless/nodejs24-debian13:nonroot@${DIGEST}\nCOPY --from=cli / /\n`), []);
    assert.deepEqual(one('Dockerfile', `FROM node:24@${DIGEST} AS build\nFROM build\n`), []);
    assert.match(one('.cursor/Dockerfile', 'FROM ubuntu:24.04\n')[0], /FROM ubuntu:24\.04 is not/);
    assert.equal(one('scripts/a.sh', 'docker run --rm -p 127.0.0.1::5432 golang:1.25-alpine go run .\n').length, 1);
    assert.deepEqual(one('scripts/a.sh', `docker run --rm -e A=b -p 127.0.0.1::5432 "$image"\n`), []);
    assert.equal(one('.github/workflows/a.yml', 'run: docker buildx create --driver docker-container --use\n').length, 1, 'BuildKit’s default image');
    assert.equal(one('.github/workflows/a.yml', 'run: docker buildx create --driver-opt image=moby/buildkit:v0.34.1 --use\n').length, 1);
    assert.equal(one('.github/workflows/a.yml', 'run: docker buildx build --attest type=sbom,generator=docker/buildkit-syft-scanner:1.12.1 .\n').length, 1);
});

test('a download is written to a file whose SHA-256 is checked; never piped onward', () => {
    assert.deepEqual(one('scripts/a.sh', 'curl -fsSL -o "$file.part" "$url"\n[ "$(sha256 "$file.part")" = "$want" ] || exit 1\n'), []);
    assert.deepEqual(one('scripts/a.sh', 'curl -fsSL --retry 3 -o "$jar.part" \\\n  "$URL"\necho "$SHA  $jar.part" | sha256sum -c --quiet\n'), []);
    assert.match(one('scripts/a.sh', 'curl -fsSL -o tool.tgz https://example.com/tool.tgz\ntar -xzf tool.tgz\n')[0], /downloads tool\.tgz, and nothing checks its SHA-256/);
    assert.match(one('.cursor/Dockerfile', 'RUN curl -fsSL https://example.com/install.sh | bash\n')[0], /pipes a download onward/);
    assert.equal(one('.github/workflows/a.yml', '        run: wget -qO- https://example.com/key | gpg --dearmor\n').length, 1);
    // A health check of the stack itself fetches nothing.
    assert.deepEqual(one('scripts/a.sh', 'until curl -sf "$COFFRE_DEV_URL/livez" >/dev/null; do sleep 1; done\n'), []);
    assert.deepEqual(one('scripts/a.sh', '# curl https://example.com/x | sh, as nobody here does\n'), []);
});

test('a package runner names an exact version, and an install installs the lockfile', () => {
    assert.deepEqual(one('scripts/a.sh', 'npx -y @coffre/cli@0.15.0 --version\n'), []);
    assert.equal(one('scripts/a.sh', 'npx @coffre/cli --version\n').length, 1);
    assert.equal(one('scripts/a.sh', 'pnpm dlx wrangler@latest deploy\n').length, 1);
    assert.deepEqual(one('.github/workflows/a.yml', '        run: pnpm install --frozen-lockfile\n'), []);
    assert.match(one('.github/workflows/a.yml', '        run: pnpm install\n')[0], /pnpm install without --frozen-lockfile/);
    assert.equal(one('scripts/a.sh', 'pnpm --dir "$project" install --silent\n').length, 1);
    assert.equal(one('.cursor/environment.json', '{ "install": "nvm use 24\\ncorepack pnpm install" }\n').length, 1);
    assert.deepEqual(one('.github/workflows/a.yml', '        run: npm install --ignore-scripts --prefix "$dir" "$dir/coffre-cli-$version.tgz"\n'), []);
    assert.equal(one('.github/workflows/a.yml', '        run: npm install -g wrangler\n').length, 1);
    assert.equal(one('scripts/a.sh', 'pnpm add --save-exact jose\n').length, 1);
    assert.equal(one('.cursor/Dockerfile', 'RUN apt-get update && apt-get install -y curl\n').length, 1);
});

test('a line that cannot be pinned says why, on itself or right above it', () => {
    assert.deepEqual(one('scripts/a.sh', '# unpinned: init writes no lockfile\npnpm --dir "$project" install\n'), []);
    assert.deepEqual(one('scripts/a.sh', '# The first install.\n# unpinned: init writes no lockfile\n# More.\npnpm --dir "$project" install\n'), []);
    assert.deepEqual(one('.cursor/Dockerfile', '# unpinned: the archive serves its current versions\nRUN apt-get update \\\n    && apt-get install -y curl\n'), []);
    assert.equal(one('scripts/a.sh', '# unpinned:\npnpm --dir "$project" install\n').length, 1, 'a reason');
    assert.equal(one('scripts/a.sh', '# unpinned: why\n\npnpm --dir "$project" install\n').length, 1, 'right above');
});

test('a toolchain an action installs is an exact version, and a runner a named image', () => {
    assert.deepEqual(one('.github/workflows/a.yml', '        with:\n          node-version: 24.22.1\n          java-version: 17.0.9+9\n'), []);
    assert.match(one('.github/workflows/a.yml', '        with:\n          node-version: 24\n')[0], /node-version 24 is not an exact version/);
    assert.equal(one('.github/workflows/a.yml', '        with:\n          node-version: lts/*\n').length, 1);
    const matrix = (values) => `    strategy:\n      matrix:\n        node: [${values}]\n    steps:\n      - with:\n          node-version: \${{ matrix.node }}\n`;
    assert.deepEqual(one('.github/workflows/a.yml', matrix("'runner', '20.0.0', '24.22.1'")), []);
    assert.equal(one('.github/workflows/a.yml', matrix("'20.0.0', '20'")).length, 1);
    assert.equal(one('.github/workflows/a.yml', '    runs-on: ubuntu-latest\n').length, 1);
    assert.deepEqual(one('.github/workflows/a.yml', '    runs-on: ubuntu-24.04\n'), []);
});

test("pnpm waits a week, runs no install script nobody decided on, and saves exact versions", () => {
    const root = "savePrefix: ''\nallowBuilds:\n  esbuild: false\nstrictDepBuilds: true\nminimumReleaseAge: 10080\n";
    assert.deepEqual(one('pnpm-workspace.yaml', root, { root: true }), []);
    assert.match(one('pnpm-workspace.yaml', root.replace('10080', '4320'), { root: true })[0], /minimumReleaseAge 4320 is under 10080/);
    assert.equal(one('pnpm-workspace.yaml', root.replace('strictDepBuilds: true\n', ''), { root: true }).length, 1);
    assert.equal(one('pnpm-workspace.yaml', root.replace("savePrefix: ''\n", "savePrefix: '^'\n"), { root: true }).length, 1);
    assert.equal(one('pnpm-workspace.yaml', `${root}dangerouslyAllowAllBuilds: true\n`, { root: true }).length, 1);
    assert.match(one('pnpm-workspace.yaml', root.replace('esbuild: false', 'esbuild: true'), { root: true })[0], /allowBuilds esbuild: true needs/);
    assert.deepEqual(one('pnpm-workspace.yaml', root.replace('  esbuild: false', '  # Its binary is built from source here.\n  esbuild: true'), { root: true }), []);
    assert.equal(one('pnpm-workspace.yaml', `${root}minimumReleaseAgeExclude:\n  - '@coffre/*'\n`, { root: true }).length, 1, 'the workspace waits for coffre too');
    const example = "strictDepBuilds: true\nminimumReleaseAge: 10080\nminimumReleaseAgeExclude:\n  - '@coffre/*'\n";
    assert.deepEqual(one('examples/node/pnpm-workspace.yaml', example), []);
    assert.equal(one('examples/node/pnpm-workspace.yaml', `${example}  - 'wrangler'\n`).length, 1);
});
