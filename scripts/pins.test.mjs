import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, chmodSync, existsSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { problemsIn } from './pins.mjs';

const SHA = '11d5960a326750d5838078e36cf38b85af677262';
const DIGEST = 'sha256:' + 'a'.repeat(64);
const check = (path, text, options) => problemsIn(path, text, options);
const passes = (path, text, options) => assert.deepEqual(check(path, text, options), [], text);
const fails = (path, text, pattern, options) => {
    const problems = check(path, text, options);
    assert.equal(problems.length, 1, `${text}\n${problems.join('\n')}`);
    if (pattern) assert.match(problems[0], pattern);
};
const step = (yaml) => `jobs:\n  a:\n    runs-on: ubuntu-24.04\n    steps:\n      - ${yaml}\n`;
const run = (script) => step(`run: ${JSON.stringify(script)}`);

test('1. an action is this repository’s, or another’s by its commit', () => {
    passes('.github/workflows/a.yml', step(`uses: actions/checkout@${SHA} # v4.4.0`));
    passes('.github/workflows/a.yml', step('uses: $/.github/actions/prepare'));
    passes('.github/workflows/a.yml', step('uses: ./action'));
    passes('.github/workflows/a.yml', step(`uses: docker://alpine:3@${DIGEST}`));
    fails('.github/workflows/a.yml', step('uses: actions/checkout@v4'), /jobs\.a\.steps\[0\]\.uses: uses "actions\/checkout@v4" is not owner\/repo@<commit SHA>/);
    fails('.github/workflows/a.yml', step('uses: docker://alpine:3'));
    fails('.github/workflows/a.yml', 'jobs:\n  a:\n    uses: o/r/.github/workflows/b.yml@main\n');
    fails('action/action.yml', 'runs:\n  using: composite\n  steps:\n    - uses: actions/cache@v4\n');
    fails('.github/actions/prepare/action.yml', `runs:\n  using: composite\n  steps:\n    - {"uses": "actions/cache@v4"}\n`);
});

test('2. an image ends in its digest, in compose, a workflow and a Dockerfile', () => {
    passes('docker-compose.yml', `services:\n  postgres:\n    image: postgres:16.14@${DIGEST}\n`);
    fails('docker-compose.yml', 'services:\n  postgres:\n    image: postgres:16.14\n', /services\.postgres\.image: image "postgres:16\.14" is not/);
    fails('compose.yaml', "services:\n  'postgres': {image: postgres}\n");
    passes('.github/workflows/a.yml', `jobs:\n  a:\n    container: node:24@${DIGEST}\n    services:\n      pg:\n        image: postgres:16@${DIGEST}\n`);
    fails('.github/workflows/a.yml', 'jobs:\n  a:\n    container: node:24\n');
    fails('.github/workflows/a.yml', 'jobs:\n  a:\n    container:\n      image: node:24\n');
    fails('.github/workflows/a.yml', 'jobs:\n  a:\n    services:\n      pg: postgres:16\n');
    fails('.github/workflows/a.yml', 'jobs:\n  a:\n    services:\n      pg:\n        image: ${{ matrix.pg }}\n');
    passes('Dockerfile', `FROM node:24@${DIGEST} AS build\nFROM build\nFROM scratch\nFROM --platform=$BUILDPLATFORM node:24@${DIGEST}\n`);
    fails('Dockerfile', 'FROM ubuntu:24.04\n', /Dockerfile:1: FROM ubuntu:24\.04 is not/);
    fails('Dockerfile', 'FROM alpine AS alpine\n', /FROM alpine is not/);
    fails('Dockerfile', 'FROM build\nFROM node:24@' + DIGEST + ' AS build\n', /FROM build is not/);
    fails('Dockerfile', 'FROM node-${TARGETARCH}\n');
    passes('Dockerfile', '# unpinned: a stage above, by platform.\nFROM node-${TARGETARCH}\n');
    // An exempt FROM still names its stage.
    passes('Dockerfile', '# unpinned: an approved base.\nFROM alpine:3.22 AS build\nFROM build\n');
});

test('3. a Dockerfile’s ADD of a URL carries its SHA-256', () => {
    passes('Dockerfile', `FROM scratch\nADD --checksum=sha256:${'c'.repeat(64)} https://example.com/t.tgz /opt/\nADD coffre-cli.tgz /\n`);
    passes('Dockerfile', `FROM scratch\nADD --chmod=644 --checksum=sha256:${'c'.repeat(64)} \\\n    https://example.com/t.tgz /opt/\n`);
    fails('Dockerfile', 'FROM scratch\nADD https://example.com/t.tgz /opt/\n', /Dockerfile:2: ADD of a URL without --checksum/);
    fails('Dockerfile', 'FROM scratch\nADD --checksum=sha256:abc https://example.com/t.tgz /opt/\n');
    fails('Dockerfile', 'FROM scratch\nADD ["https://example.com/t.tgz", "/opt/"]\n');
    // Docker drops a comment or blank line inside an instruction, and reads on.
    fails('Dockerfile', 'FROM scratch\nADD \\\n    # the tool\n\n    https://example.com/t.tgz /opt/\n', /Dockerfile:2: ADD of a URL without --checksum/);
});

test('4. only scripts/fetch.sh downloads; a health check of this machine is marked', () => {
    passes('scripts/a.sh', '"$root/scripts/fetch.sh" "https://go.dev/dl/go$V.tar.gz" "$digest" "$file"\n');
    passes('scripts/fetch.sh', 'curl -fsSL --proto =https -o "$tmp" "$url"\n');
    // The copy the Terraform provider's mirror carries, and no other.
    passes('terraform-provider/scripts/fetch.sh', 'curl -fsSL --proto =https -o "$tmp" "$url"\n');
    fails('terraform-provider/scripts/tools.sh', 'curl -fsSL --proto =https -o "$tmp" "$url"\n', /curl downloads/);
    // The helper may download; nothing else in it is exempt.
    fails('scripts/fetch.sh', 'npm install some-tool\n', /fetches a package outside the lockfile/);
    fails('scripts/fetch.sh', 'pnpm install\n', /without --frozen-lockfile/);
    fails('scripts/fetch.sh', 'corepack enable\n', /corepack: Node drops it/);
    for (const line of ['curl -fsSL https://example.com/x -o x', 'wget https://example.com/x', '/usr/bin/curl -O "$url"', 'x=$(curl -s "$url")', 'sudo curl "$url"']) {
        fails('scripts/a.sh', `${line}\n`, /scripts\/a\.sh:1: (curl|wget) downloads: use scripts\/fetch\.sh/);
    }
    fails('Dockerfile', 'FROM scratch\nRUN apk add x \\\n    && curl -o /x https://example.com/x\n', /Dockerfile:2: curl downloads/);
    fails('.github/workflows/a.yml', run('set -e\ncurl -fsSL https://example.com/x | sh'), /steps\[0\]\.run, line 2: curl downloads/);
    fails('docker-compose.yml', `services:\n  a:\n    image: a:1@${DIGEST}\n    command: [curl, https://example.com]\n`);
    fails('.cursor/environment.json', JSON.stringify({ install: 'curl https://example.com | sh' }));
    // Comments, and words that are not curl.
    passes('scripts/a.sh', '# curl https://example.com\nlibcurl-config --version\necho curl-like\n');
    // A comment ends at its line, a trailing backslash's too.
    fails('scripts/a.sh', '# Download example \\\ncurl https://example.com/tool\n', /scripts\/a\.sh:2: curl downloads/);
    fails('Dockerfile', 'FROM scratch\n# fetch \\\nRUN curl https://example.com/tool\n', /Dockerfile:3: curl downloads/);
    fails('Dockerfile', 'FROM scratch\nRUN apk add x \\\n    # then the tool\n    && curl -o /x https://example.com/x\n', /Dockerfile:2: curl downloads/);
    // In a shell, a comment's own backslash continues nothing, and a comment line ends the command.
    fails('scripts/a.sh', 'echo one # note \\\ncurl https://example.com/tool\n', /scripts\/a\.sh:2: curl downloads/);
    fails('scripts/a.sh', 'echo one \\\n# note \\\ncurl https://example.com/tool\n', /scripts\/a\.sh:3: curl downloads/);
    // A health check: every URL this machine's.
    passes('scripts/a.sh', 'until curl -sf "http://127.0.0.1:$port/livez"; do sleep 1; done # pins: local\n');
    passes('scripts/a.sh', 'curl -sf http://localhost:3000/ http://[::1]:3000/ # pins: local\n');
    fails('scripts/a.sh', 'curl -sf http://127.0.0.1:3000/ https://example.com/ # pins: local\n');
    fails('scripts/a.sh', 'curl -sf http://127.0.0.1.example.com/ # pins: local\n');
    // Before an @ is a user and password: the host is example.com.
    fails('scripts/a.sh', 'curl -sf https://localhost:443@example.com/tool # pins: local\n');
    fails('scripts/a.sh', 'curl -sf http://localhost@example.com/ # pins: local\n');
    passes('scripts/a.sh', 'curl -sf http://localhost:3000/@example.com # pins: local\n');
    fails('scripts/a.sh', 'curl -sf http://127.0.0.1/ # pins: local, and more\n');
    fails('scripts/a.sh', 'curl -sf "$url" # pins: local\n');
});

test('5. nothing fetches a package outside the lockfile', () => {
    for (const line of ['npx wrangler deploy', 'pnpx x', 'bunx x', 'npm install x', 'npm i -g x', 'npm --prefix d install x', 'npm ci', 'npm exec -- x', 'npm x x',
        'npm up', 'pnpm dlx x', 'pnpm add x', 'pnpm up', 'pnpm --dir d add --save-exact "x@1.0.0"', 'yarn dlx x', 'gh release download v1', 'gh run download 1', 'git clone https://github.com/o/r',
        'git -C d clone u', 'nvm install 24', 'apt-get install -y x', 'sudo apt install x']) {
        fails('scripts/a.sh', `${line}\n`, /fetches a package outside the lockfile/);
    }
    fails('Dockerfile', 'FROM scratch\nRUN ["npm", "install"]\n');
    fails('Dockerfile', 'FROM scratch\nRUN npm \\\n    # dependencies\n    install -g example\n', /Dockerfile:2: .*fetches a package outside the lockfile/);
    fails('docker-compose.yml', `services:\n  a:\n    image: a:1@${DIGEST}\n    command: [npx, wrangler]\n`);
    fails('.github/workflows/a.yml', run('echo ok && pnpm add x'));
    // Each command apart; the words alone, or in a name, are none.
    passes('scripts/a.sh', 'pnpm run add:dep x\nnpm view x version\npnpm install --frozen-lockfile && pnpm exec tsc -i\ngit config x\nnvm use 24\ngh pr view\nnpm pack\n');
    passes('scripts/a.sh', '# unpinned: a published release, at its exact version.\npnpm --dir d add "x@1.0.0"\n');
    passes('scripts/a.sh', 'pnpm --dir d add "x@1.0.0" # unpinned: a published release\n');
    passes('.github/workflows/a.yml', run('# unpinned: our own tarball.\nnpm install ./x.tgz'));
});

test('6. pnpm install carries --frozen-lockfile, each command its own', () => {
    passes('scripts/a.sh', 'pnpm install --frozen-lockfile\npnpm install --frozen-lockfile=true\npnpm --filter x i --frozen-lockfile --prod\n');
    for (const line of ['pnpm install', 'pnpm i', 'pnpm --dir x install', 'pnpm install --frozen-lockfile=false', 'pnpm install; pnpm install --frozen-lockfile']) {
        fails('scripts/a.sh', `${line}\n`, /pnpm install without --frozen-lockfile/);
    }
    fails('docker-compose.yml', `services:\n  a:\n    image: a:1@${DIGEST}\n    command: [pnpm, install]\n`);
    fails('.github/workflows/a.yml', run('pnpm install'), /steps\[0\]\.run: pnpm install: pnpm install without/);
    // The second install is a command of its own: bash ends the first at the comment.
    fails('scripts/a.sh', 'pnpm install --frozen-lockfile \\\n# note \\\npnpm install\n', /scripts\/a\.sh:3: pnpm install: pnpm install without/);
    fails('scripts/a.sh', 'pnpm install --frozen-lockfile # note \\\npnpm install\n', /scripts\/a\.sh:2: pnpm install: pnpm install without/);
    fails('.github/workflows/a.yml', run('pnpm install --frozen-lockfile \\\n# note \\\npnpm install'), /line 3: pnpm install: pnpm install without/);
    passes('scripts/a.sh', 'pnpm install \\\n  --frozen-lockfile\n');
});

test('7. nothing runs Corepack', () => {
    fails('Dockerfile', 'FROM scratch\nRUN corepack enable && corepack prepare pnpm@11.28.9 --activate\n', /Dockerfile:2: corepack: Node drops it/);
    fails('scripts/a.sh', 'corepack pnpm install --frozen-lockfile\n', /scripts\/a\.sh:1: corepack/);
    fails('scripts/a.sh', 'COREPACK_ENABLE_STRICT=0 /usr/local/bin/corepack use pnpm@11.28.9\n');
    fails('.github/workflows/a.yml', run('corepack enable && pnpm install --frozen-lockfile'), /steps\[0\]\.run: corepack/);
    fails('.cursor/environment.json', JSON.stringify({ install: 'corepack pnpm install --frozen-lockfile' }), /install: corepack/);
    // Its name in a word of another, or an environment variable's, runs nothing.
    passes('scripts/a.sh', 'echo "$COREPACK_HOME" no-corepack-here\npnpm install --frozen-lockfile # pnpm, never Corepack\n');
});

test('8. a toolchain an action installs is an exact version, and a runner a named image', () => {
    const setup = (version) => step(`uses: actions/setup-node@${SHA}\n        with:\n          node-version: ${version}`);
    passes('.github/workflows/a.yml', setup('24.22.1'));
    passes('.github/workflows/a.yml', step(`uses: actions/setup-java@${SHA}\n        with:\n          Java-Version: 17.0.9+9`));
    for (const version of ['24', '24.x', 'lts/*', "'24.10'", 'latest']) fails('.github/workflows/a.yml', setup(version), /node-version .* is not an exact version/);
    const matrix = (node) => `jobs:\n  a:\n    strategy:\n      matrix:\n        node: ${node}\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/setup-node@${SHA}\n        with:\n          node-version: \${{ matrix.node }}\n`;
    passes('.github/workflows/a.yml', matrix("['runner', '20.0.0', '24.22.1']"));
    fails('.github/workflows/a.yml', matrix("['20.0.0', '22']"), /22 is not an exact version/);
    fails('.github/workflows/a.yml', matrix("'24.22.1'"), /has no list node/);
    fails('.github/workflows/a.yml', setup('${{ inputs.node }}'));
    fails('.github/workflows/a.yml', 'jobs:\n  a:\n    runs-on: ubuntu-latest\n', /runs-on ubuntu-latest moves/);
    fails('.github/workflows/a.yml', 'jobs:\n  a:\n    runs-on: [self-hosted, macos-latest]\n');
});

test('9. pnpm waits a week, fails on an install script nobody decided on, and saves exact versions', () => {
    const root = "minimumReleaseAge: 10080\nstrictDepBuilds: true\nsavePrefix: ''\nallowBuilds:\n  esbuild: false\n";
    passes('pnpm-workspace.yaml', root, { root: true });
    passes('examples/node/pnpm-workspace.yaml', "minimumReleaseAge: 10080\nstrictDepBuilds: true\nminimumReleaseAgeExclude:\n  - '@coffre/*'\n");
    fails('pnpm-workspace.yaml', root.replace('10080', '4320'), /minimumReleaseAge 4320 is under 10080/, { root: true });
    fails('pnpm-workspace.yaml', root.replace('10080', "'10080'"), /minimumReleaseAge "10080" is under/, { root: true });
    fails('pnpm-workspace.yaml', root.replace('strictDepBuilds: true', 'strictDepBuilds: false'), /strictDepBuilds is not true/, { root: true });
    fails('pnpm-workspace.yaml', `${root}dangerouslyAllowAllBuilds: true\n`, /runs every install script/, { root: true });
    fails('pnpm-workspace.yaml', root.replace("savePrefix: ''", "savePrefix: '^'"), /savePrefix is not ''/, { root: true });
    fails('pnpm-workspace.yaml', `${root}minimumReleaseAgeExclude: ['@coffre/*']\n`, /lets @coffre\/\* in/, { root: true });
    fails('examples/node/pnpm-workspace.yaml', "{strictDepBuilds: true, minimumReleaseAge: 10080, minimumReleaseAgeExclude: ['@coffre/*', wrangler]}\n", /lets wrangler in/);
    fails('pnpm-workspace.yaml', `${root}minimumReleaseAge: 0\n`, /duplicated mapping key/, { root: true });
});

test('scripts/fetch.sh keeps a download only if its SHA-256 is the pinned one', () => {
    const dir = mkdtempSync(join(tmpdir(), 'coffre-fetch-'));
    try {
        // A curl that writes $BODY to its -o, and counts its calls.
        const bin = join(dir, 'bin');
        writeFileSync(join(dir, 'calls'), '');
        spawnSync('mkdir', [bin]);
        writeFileSync(join(bin, 'curl'), `#!/bin/sh\nwhile [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac; done\necho "$out" >> "${join(dir, 'calls')}"\nprintf '%s' "$BODY" > "$out"\n`);
        chmodSync(join(bin, 'curl'), 0o755);
        const hello = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
        const fetch = (args, body = 'hello') => spawnSync('bash', [new URL('./fetch.sh', import.meta.url).pathname, ...args], { env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, BODY: body }, encoding: 'utf8' });
        const calls = () => readFileSync(join(dir, 'calls'), 'utf8').split('\n').filter(Boolean).length;
        const file = join(dir, 'cache', 'tool.tgz');

        const ok = fetch(['https://example.com/tool.tgz', hello, file]);
        assert.equal(ok.status, 0, ok.stderr);
        assert.equal(readFileSync(file, 'utf8'), 'hello');
        // Nothing left beside it.
        assert.deepEqual(readdirSync(join(dir, 'cache')), ['tool.tgz']);
        // Kept, once its hash is the pinned one: no second download.
        assert.equal(fetch(['https://example.com/tool.tgz', hello, file]).status, 0);
        assert.equal(calls(), 1);

        // Another body: refused, and nothing kept.
        const other = join(dir, 'other.tgz');
        const bad = fetch(['https://example.com/tool.tgz', hello, other], 'tampered');
        assert.equal(bad.status, 1);
        assert.match(bad.stderr, /not the pinned 2cf24dba/);
        assert.equal(existsSync(other), false);
        assert.deepEqual(readdirSync(dir).filter((name) => name.startsWith('other')), []);
        // A file there with another hash is fetched again, and refused again.
        writeFileSync(other, 'stale');
        assert.equal(fetch(['https://example.com/tool.tgz', hello, other], 'tampered').status, 1);

        // Only https, only a SHA-256, all three arguments.
        assert.equal(fetch(['http://example.com/tool.tgz', hello, other]).status, 2);
        assert.equal(fetch(['https://example.com/tool.tgz', 'abc', other]).status, 2);
        assert.equal(fetch(['https://example.com/tool.tgz', hello.toUpperCase(), other]).status, 2);
        assert.equal(fetch(['https://example.com/tool.tgz', hello]).status, 2);
        assert.equal(calls(), 3);
        // Each run downloads to a file of its own beside the target, never a shared one.
        const outs = readFileSync(join(dir, 'calls'), 'utf8').split('\n').filter(Boolean);
        assert.equal(new Set(outs).size, outs.length);
        for (const out of outs) assert.equal(out.startsWith(`${file}.`) || out.startsWith(`${other}.`), true, out);
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
});

test('scripts/fetch.sh beside itself keeps only the pinned bytes', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'coffre-fetch-'));
    try {
        // A curl that writes half its body, waits until every run's curl has
        // started (so none has found the file already there), then the rest.
        const bin = join(dir, 'bin');
        const runs = 12;
        spawnSync('mkdir', [bin]);
        writeFileSync(join(bin, 'curl'), `#!/bin/sh\nwhile [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac; done\nprintf '%s' "\${BODY%???}" > "$out"\necho >> "${join(dir, 'started')}"\ni=0; while [ "$(wc -l < "${join(dir, 'started')}")" -lt ${runs} ]; do i=$((i+1)); [ $i -lt 1000 ] || exit 9; sleep 0.01; done\nprintf '%s' "\${BODY#\${BODY%???}}" >> "$out"\n`);
        chmodSync(join(bin, 'curl'), 0o755);
        const hello = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
        const file = join(dir, 'cache', 'tool.tgz');
        const run = (body) => new Promise((resolve) => {
            const child = spawn('bash', [new URL('./fetch.sh', import.meta.url).pathname, 'https://example.com/tool.tgz', hello, file], { env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, BODY: body }, stdio: 'ignore' });
            child.on('exit', (code) => resolve({ body, code }));
        });
        const results = await Promise.all(Array.from({ length: runs }, (_, i) => run(i % 2 ? 'hello' : 'tampered')));
        for (const { body, code } of results) assert.equal(code, body === 'hello' ? 0 : 1, body);
        assert.equal(readFileSync(file, 'utf8'), 'hello');
        assert.deepEqual(readdirSync(join(dir, 'cache')), ['tool.tgz']);
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
});
