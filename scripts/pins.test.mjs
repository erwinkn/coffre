import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, chmodSync, existsSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { problemsIn } from './pins.mjs';

const SHA = '11d5960a326750d5838078e36cf38b85af677262';
const DIGEST = 'sha256:' + 'a'.repeat(64);
const one = (path, text, options) => problemsIn(path, text, options);

test('an action is pinned by its commit, its version beside it; the repository’s own is not', () => {
    const workflow = (uses) => `jobs:\n  a:\n    steps:\n      - uses: ${uses}\n`;
    assert.deepEqual(one('.github/workflows/a.yml', workflow(`actions/checkout@${SHA} # v4.4.0`)), []);
    assert.deepEqual(one('.github/workflows/a.yml', workflow('$/.github/actions/prepare')), []);
    assert.deepEqual(one('.github/workflows/a.yml', workflow('./action')), []);
    assert.match(one('.github/workflows/a.yml', workflow('actions/checkout@v4'))[0], /a\.yml: jobs\.a\.steps\[0\]\.uses: uses actions\/checkout@v4 is not owner\/repo@<commit SHA>/);
    assert.equal(one('.github/workflows/a.yml', workflow(`actions/checkout@${SHA}`)).length, 1, 'no version beside it');
    assert.equal(one('examples/workers/.github/workflows/deploy.yml', workflow('actions/setup-node@main')).length, 1);
    assert.equal(one('action/action.yml', `runs:\n  steps:\n    - uses: actions/cache@v4\n`).length, 1);
    // A quoted scalar, its comment after the quote.
    assert.deepEqual(one('.github/workflows/a.yml', workflow(`"actions/checkout@${SHA}" # v4.4.0`)), []);
    assert.deepEqual(one('.github/workflows/a.yml', workflow(`'actions/checkout@${SHA}' # v4.4.0`)), []);
    assert.equal(one('.github/workflows/a.yml', workflow('"actions/checkout@v4" # v4.4.0')).length, 1);
    // A reusable workflow, by its commit too; a step's `uses` in a flow mapping, its comment after it.
    assert.equal(one('.github/workflows/a.yml', 'jobs:\n  a:\n    uses: o/r/.github/workflows/b.yml@main\n').length, 1);
    assert.deepEqual(one('.github/workflows/a.yml', `jobs:\n  a:\n    steps:\n      - {uses: actions/checkout@${SHA}} # v4.4.0\n`), []);
    // A key named `uses` elsewhere is an input, a step's name or a job's: no action.
    assert.deepEqual(one('.github/workflows/a.yml', 'jobs:\n  uses:\n    steps:\n      - with:\n          uses: v4\n'), []);
});
test('an image is name:tag@sha256:<digest>, in compose, a workflow, a Dockerfile or a command', () => {
    assert.deepEqual(one('docker-compose.yml', `services:\n  postgres:\n    image: postgres:16.14@${DIGEST}\n`), []);
    assert.match(one('docker-compose.yml', 'services:\n  postgres:\n    image: postgres:16.14\n')[0], /image postgres:16\.14 is not name:tag@sha256/);
    assert.equal(one('docker-compose.yml', `services:\n  p:\n    image: postgres@${DIGEST}\n`).length, 1, 'the tag, for people');
    assert.equal(one('.github/workflows/a.yml', 'jobs:\n  a:\n    services:\n      pg:\n        image: postgres:16\n').length, 1);
    assert.equal(one('.github/workflows/a.yml', 'jobs:\n  a:\n    container: node:24\n').length, 1);
    // An image an expression names: the matrix's values, each pinned; any other, unread.
    const container = (image) => `jobs:\n  a:\n    strategy:\n      matrix:\n        node_image: ['${image}']\n    container: \${{ matrix.node_image }}\n`;
    assert.deepEqual(one('.github/workflows/a.yml', container(`node:24@${DIGEST}`)), []);
    assert.match(one('.github/workflows/a.yml', container('node:24'))[0], /image node:24 is not/);
    assert.match(one('.github/workflows/a.yml', 'jobs:\n  a:\n    container: ${{ inputs.image }}\n')[0], /image \$\{\{ inputs\.image \}\} is not/);
    assert.equal(one('.github/workflows/a.yml', 'jobs:\n  a:\n    services:\n      pg:\n        image: "${{ matrix.pg }}"\n').length, 1);
    assert.deepEqual(one('.github/workflows/a.yml', `jobs:\n  a:\n    container:\n      image: node:24@${DIGEST}\n`), [], 'a mapping');
    assert.deepEqual(one('packages/cli/Dockerfile', `FROM scratch AS cli\nFROM gcr.io/distroless/nodejs24-debian13:nonroot@${DIGEST}\nCOPY --from=cli / /\n`), []);
    assert.deepEqual(one('Dockerfile', `FROM node:24@${DIGEST} AS build\nFROM build\n`), []);
    assert.match(one('.cursor/Dockerfile', 'FROM ubuntu:24.04\n')[0], /FROM ubuntu:24\.04 is not/);
    // What else a Dockerfile pulls: COPY's and a mount's --from, the frontend, ADD's URLs.
    assert.match(one('Dockerfile', 'FROM scratch\nCOPY --from=ghcr.io/astral-sh/uv:latest /uv /uv\n')[0], /Dockerfile:2: COPY --from ghcr\.io\/astral-sh\/uv:latest is not/);
    assert.deepEqual(one('Dockerfile', `FROM scratch\nCOPY --from=ghcr.io/astral-sh/uv:0.9.0@${DIGEST} /uv /uv\nCOPY --from=0 /a /a\n`), []);
    assert.equal(one('Dockerfile', 'FROM scratch\nRUN --mount=type=bind,from=node:24,target=/n ls /n\n').length, 1);
    assert.match(one('Dockerfile', '# syntax=docker/dockerfile:1\nFROM scratch\n')[0], /Dockerfile:1: syntax docker\/dockerfile:1 is not/);
    assert.deepEqual(one('Dockerfile', `# syntax=docker/dockerfile:1.19@${DIGEST}\nFROM scratch\n`), []);
    assert.match(one('Dockerfile', 'FROM scratch\nADD https://example.com/tool.tar.gz /opt/\n')[0], /ADD https:\/\/example\.com\/tool\.tar\.gz without --checksum/);
    assert.deepEqual(one('Dockerfile', `FROM scratch\nADD --checksum=sha256:${'c'.repeat(64)} https://example.com/tool.tar.gz /opt/\nADD coffre-cli.tgz /\n`), []);
    assert.equal(one('Dockerfile', 'FROM scratch\nADD git@github.com:o/r.git#main /src\n').length, 1);
    assert.deepEqual(one('Dockerfile', `FROM scratch\nADD https://github.com/o/r.git#${SHA} /src\n`), []);
    assert.equal(one('Dockerfile', 'FROM scratch\nADD ["https://example.com/t.tgz", "/opt/"]\n').length, 1);
    // What Compose builds: a Dockerfile written in it, read as one, and a context
    // here, another service's, a repository at its commit or an image by its digest.
    const inline = (body) => `services:\n  app:\n    build:\n      dockerfile_inline: |\n${body.split('\n').map((line) => `        ${line}`).join('\n')}\n`;
    assert.match(one('docker-compose.yml', inline('FROM node:24'))[0], /dockerfile_inline, line 1: FROM node:24 is not/);
    assert.match(one('docker-compose.yml', inline(`FROM node:24@${DIGEST}\nADD https://example.com/t.tgz /t`))[0], /line 2: ADD https:\/\/example\.com\/t\.tgz without --checksum/);
    assert.deepEqual(one('docker-compose.yml', inline(`FROM node:24@${DIGEST}\nRUN pnpm install --frozen-lockfile`)), []);
    const build = (value) => `services:\n  app:\n    build: ${value}\n`;
    assert.match(one('docker-compose.yml', build('https://github.com/docker-library/hello-world.git'))[0], /services\.app\.build: build context https:\/\/github\.com\/docker-library\/hello-world\.git is what its server has today/);
    assert.equal(one('docker-compose.yml', build('{context: "git@github.com:o/r.git#main"}')).length, 1);
    assert.equal(one('docker-compose.yml', build('https://example.com/context.tar.gz')).length, 1);
    assert.deepEqual(one('docker-compose.yml', build(`{context: "https://github.com/o/r.git#${SHA}:dir"}`)), []);
    assert.deepEqual(one('docker-compose.yml', build('.')), []);
    assert.equal(one('docker-compose.yml', build('{context: ., additional_contexts: {base: "docker-image://alpine:3"}}')).length, 1);
    assert.equal(one('docker-compose.yml', build('{context: ., additional_contexts: ["base=docker-image://alpine:3", "db=service:db"]}')).length, 1);
    assert.deepEqual(one('docker-compose.yml', build(`{context: ., additional_contexts: {base: "docker-image://alpine:3@${DIGEST}", src: ../src, db: "service:db"}}`)), []);
    // r12: a stage is named once its FROM is read, so `FROM alpine AS alpine` pulls alpine.
    assert.match(one('Dockerfile', 'FROM alpine AS alpine\nRUN true\n')[0], /Dockerfile:1: FROM alpine is not/);
    assert.match(one('docker-compose.yml', inline('FROM alpine AS alpine'))[0], /dockerfile_inline, line 1: FROM alpine is not/);
    assert.deepEqual(one('Dockerfile', `FROM alpine:3.20@${DIGEST} AS base\nFROM base\nCOPY --from=base /a /b\n`), []);
    // r12: Compose's short spelling of a repository is one too.
    assert.match(one('docker-compose.yml', build('github.com/docker-library/hello-world.git'))[0], /build context github\.com\/docker-library\/hello-world\.git is what its server has today/);
    assert.deepEqual(one('docker-compose.yml', build(`github.com/docker-library/hello-world.git#${SHA}`)), []);
    // r12: the Dockerfile a build names has a name check:pins reads, and a Containerfile is one.
    assert.match(one('docker-compose.yml', build('{context: ., dockerfile: build.txt}'))[0], /services\.app\.build\.dockerfile: dockerfile "build\.txt": name it Dockerfile/);
    assert.deepEqual(one('docker-compose.yml', build('{context: ., dockerfile: docker/app.Dockerfile}')), []);
    assert.match(one('Containerfile', 'FROM alpine:latest\n')[0], /Containerfile:1: FROM alpine:latest is not/);
    assert.match(one('a.sh', 'docker buildx build --file "$DOCKERFILE" .\n')[0], /a\.sh:1: --file "\$DOCKERFILE": name it Dockerfile/);
    assert.match(one('a.sh', 'docker compose -f stack.yml up -d\n')[0], /a\.sh:1: -f stack\.yml: name it compose\.yaml/);
    assert.deepEqual(one('a.sh', 'docker build -f packages/cli/Dockerfile .\ndocker compose --file docker-compose.yml up\n'), []);
    // r12: a compose file Compose fetches, by `include:` or `extends:`, is no pin.
    assert.match(one('docker-compose.yml', 'include: [oci://registry.example.com/base:latest]\n')[0], /include\[0\]: "oci:\/\/registry\.example\.com\/base:latest" is a compose file Compose fetches/);
    assert.match(one('docker-compose.yml', 'include:\n  - path: [./a.yml, https://example.com/b.yml]\n')[0], /include\[0\]\.path: "https:\/\/example\.com\/b\.yml"/);
    assert.match(one('docker-compose.yml', 'services:\n  a:\n    extends: {file: "git@github.com:o/r.git", service: x}\n')[0], /services\.a\.extends\.file: .* is a compose file Compose fetches/);
    assert.deepEqual(one('docker-compose.yml', 'include: [./local.yml]\nservices:\n  a:\n    extends: {file: ./base.yml, service: x}\n'), []);
    assert.equal(one('.github/workflows/a.yml', 'run: docker buildx create --driver docker-container --use\n').length, 1, 'BuildKit’s default image');
    assert.equal(one('.github/workflows/a.yml', 'run: docker buildx create --driver-opt image=moby/buildkit:v0.34.1 --use\n').length, 1);
    assert.equal(one('.github/workflows/a.yml', 'run: docker buildx build --attest type=sbom,generator=docker/buildkit-syft-scanner:1.12.1 .\n').length, 1);
});

test('a download goes through scripts/fetch.sh or ADD --checksum; curl and wget are banned anywhere else', () => {
    assert.deepEqual(one('scripts/a.sh', '"$root/scripts/fetch.sh" "https://go.dev/dl/go$V.tar.gz" "$digest" "$file"\ntar -xzf "$file"\n'), []);
    assert.deepEqual(one('Dockerfile', `FROM scratch\nADD --chmod=644 --checksum=sha256:${'c'.repeat(64)} \\\n    https://example.com/tool.tar.gz /opt/\n`), []);
    // The helper itself is the one place curl runs.
    assert.deepEqual(one('scripts/fetch.sh', 'curl -fsSL --proto =https -o "$file.part" "$url"\n'), []);
    assert.match(one('scripts/a.sh', 'curl -fsSL -o t.tgz https://example.com/t.tgz\n')[0], /a\.sh:1: curl downloads: use scripts\/fetch\.sh/);
    // Checked or not, written or piped, however it is called: the name is enough.
    for (const line of [
        'curl -fsSL -o "$f" "$url" && echo "$SHA  $f" | sha256sum -c',
        'curl -fsSL https://example.com/i.sh | sh',
        'wget -qO- https://example.com/key | gpg --dearmor',
        'v="$(curl -fsSL https://example.com/version)"',
        'sudo -u ci -E curl -fsSL https://example.com/i.sh',
        'env -i PATH="$PATH" curl -o t https://example.com/t',
        'retry 3 curl -o t https://example.com/t',
        'timeout 60 wget https://example.com/t',
        'curl -fsS -o "$response" "$COFFRE_DEV_URL/api/me"',
        '/usr/bin/curl -o t https://example.com/t',
    ]) assert.equal(one('scripts/a.sh', `${line}\n`).length, 1, line);
    assert.equal(one('.github/workflows/a.yml', '        run: |\n          set -e\n          curl -fsSL https://example.com/i.sh | sh\n').length, 1, 'a run block');
    assert.equal(one('.github/workflows/a.yml', '        run: | # Install tools\n          curl -fsSL https://example.com/i.sh | sh\n').length, 1);
    assert.equal(one('.cursor/Dockerfile', 'FROM scratch\nRUN apt-get update \\\n    && curl -fsSL -o /k https://example.com/k\n').length, 1, 'a continued RUN');
    assert.equal(one('.cursor/environment.json', '{ "install": "curl -o t https://example.com/t\\ntar -xf t" }\n').length, 1);
    // A comment names it without running it; libcurl and the like are other words.
    assert.deepEqual(one('scripts/a.sh', '# curl https://example.com/x | sh, as nobody here does\npkg-config --libs libcurl\n'), []);
});

test('a health check of this machine is curl marked `# pins: local`, every URL on it loopback', () => {
    assert.deepEqual(one('scripts/a.sh', 'until curl -sf "http://127.0.0.1:$port/livez" >/dev/null; do sleep 1; done # pins: local\n'), []);
    assert.deepEqual(one('scripts/a.sh', 'curl -s http://localhost:8081/x -o "$out" # pins: local\ncurl -s "http://[::1]:3000/x" # pins: local\n'), []);
    // Not a variable, nor another host, nor any URL beside it; the marker on the line itself.
    assert.equal(one('scripts/a.sh', 'curl -sf "$COFFRE_DEV_URL/livez" # pins: local\n').length, 1, 'no URL it can read');
    assert.equal(one('scripts/a.sh', 'curl -sf https://example.com/livez # pins: local\n').length, 1);
    assert.equal(one('scripts/a.sh', 'curl -o t http://127.0.0.1:3000/x https://example.com/t # pins: local\n').length, 1, 'one URL elsewhere');
    assert.equal(one('scripts/a.sh', 'curl -o t https://localhost.example.com/t # pins: local\n').length, 1, 'a host named like it');
    assert.equal(one('scripts/a.sh', 'curl -o t http://127.0.0.1.example.com/t # pins: local\n').length, 1);
    assert.equal(one('scripts/a.sh', '# pins: local\ncurl -sf http://127.0.0.1:3000/livez\n').length, 1, 'on the line itself');
    assert.equal(one('scripts/a.sh', 'npx tool http://127.0.0.1:3000 # pins: local\n').length, 1, 'curl and wget alone');
});

test('a package runner, a registry install, a release download or a clone is banned by name', () => {
    for (const line of [
        'npx -y @coffre/cli@0.15.0 --version',
        'pnpx wrangler deploy',
        'bunx tsx a.ts',
        'npm exec -- wrangler deploy',
        'npm x wrangler',
        'npm --cache "$dir/cache" exec wrangler',
        'npm install -g wrangler',
        'npm i wrangler',
        'npm ci',
        'npm install-test',
        'npm it',
        'npm --prefix fixture install-ci-test',
        'npm cit',
        'npm clean-install',
        'npm isntall wrangler',
        'npm link wrangler',
        'npm dedupe',
        'npm pack @coffre/cli@0.15.0',
        'pnpm dlx wrangler@4.0.0 deploy',
        'pnpm --dir app add jose',
        'pnpm update',
        'pnpm create vite',
        'yarn dlx wrangler',
        'gh release download v1.0.0 --repo o/r',
        'gh release download --repo o/r --pattern "*.tgz"',
        'gh run download 123',
        // Options between a command's words.
        'gh release --repo o/r download v1.0.0',
        'gh run --repo o/r download 123',
        'git submodule --quiet update --init --remote',
        'git clone https://github.com/a/b.git',
        `git -C dir clone --revision=${SHA} https://github.com/a/b.git`,
        'nvm install 24',
        'nvm install 24.22.1',
        'corepack up',
        'corepack use pnpm@11.8.0',
        'sudo apt-get install -y jq',
        'pip install requests',
        'go install golang.org/x/tools/cmd/goimports@latest',
        'cargo install ripgrep',
    ]) assert.equal(one('scripts/a.sh', `${line}\n`).length >= 1, true, line);
    // What fetches nothing: a metadata read, a publish, a local pack, a pnpm script.
    assert.deepEqual(one('scripts/a.sh', 'npm view @coffre/cli version\nnpm --version\nnpm publish "$dir"/*.tgz\npnpm --filter @coffre/cli pack\npnpm run add:dep jose@6.2.3\ngo run . vectors\ngit -C "$dir" checkout main\n'), []);
    assert.deepEqual(one('scripts/a.sh', 'nvm alias default "$NODE_VERSION" && nvm use default && nvm which default\n'), []);
});

test('Corepack fetches the workspace’s pnpm alone', () => {
    const pnpm = { pnpm: '11.8.0' };
    assert.deepEqual(one('.cursor/Dockerfile', 'FROM scratch\nRUN corepack enable && corepack prepare pnpm@11.8.0 --activate\n', pnpm), []);
    assert.match(one('.cursor/Dockerfile', 'FROM scratch\nRUN corepack prepare pnpm@latest --activate\n', pnpm)[0], /pnpm@latest is not pnpm@11\.8\.0/);
    assert.equal(one('scripts/a.sh', 'corepack pnpm@latest install --frozen-lockfile\n', pnpm).length, 1);
    assert.equal(one('scripts/a.sh', 'corepack pnpm@11.7.0 install --frozen-lockfile\n', pnpm).length, 1);
    assert.equal(one('scripts/a.sh', 'corepack install -g yarn@4.5.0\n', pnpm).length, 1);
    assert.equal(one('scripts/a.sh', 'corepack prepare pnpm@11 --activate\n', pnpm).length, 1);
    assert.deepEqual(one('scripts/a.sh', 'corepack pnpm@11.8.0 install --frozen-lockfile\n', pnpm), []);
    // A name with no version is the latest.
    assert.match(one('scripts/a.sh', 'corepack install -g pnpm\n', pnpm)[0], /names no version: name pnpm@11\.8\.0/);
    assert.equal(one('scripts/a.sh', 'corepack prepare pnpm --activate\n', pnpm).length, 1);
    assert.equal(one('scripts/a.sh', 'corepack hydrate yarn\n', pnpm).length, 1);
    // packageManager's own, and pnpm's commands through Corepack, name none.
    assert.deepEqual(one('scripts/a.sh', 'corepack install\ncorepack enable pnpm\ncorepack pnpm install --frozen-lockfile\ncorepack install -g pnpm@11.8.0\n', pnpm), []);
    // pnpm at its version is pnpm: its bans and the frozen install hold.
    for (const line of [
        'corepack pnpm@11.8.0 dlx wrangler',
        'corepack pnpm@11.8.0 --dir app add jose',
        'corepack pnpm@11.8.0 install --no-frozen-lockfile',
        'corepack pnpm@11.8.0 install',
        'corepack npm@10.9.0 exec wrangler',
    ]) assert.equal(one('scripts/a.sh', `${line}\n`, pnpm).length >= 1, true, line);
});

test('pnpm install carries --frozen-lockfile, each command its own', () => {
    assert.deepEqual(one('.github/workflows/a.yml', '        run: pnpm install --frozen-lockfile\n'), []);
    assert.deepEqual(one('.cursor/environment.json', '{ "install": "nvm use 24\\ncorepack pnpm install --frozen-lockfile" }\n'), []);
    assert.deepEqual(one('scripts/a.sh', 'pnpm -C a install --frozen-lockfile && pnpm --filter b build\n'), []);
    assert.match(one('.github/workflows/a.yml', '        run: pnpm install\n')[0], /pnpm install without --frozen-lockfile/);
    assert.equal(one('scripts/a.sh', 'pnpm --dir "$project" install --silent\n').length, 1);
    assert.equal(one('scripts/a.sh', 'pnpm i\n').length, 1);
    assert.equal(one('scripts/a.sh', 'pnpm install && pnpm --dir other install --frozen-lockfile\n').length, 1);
    assert.equal(one('scripts/a.sh', 'pnpm install; echo --frozen-lockfile\n').length, 1);
    assert.equal(one('scripts/a.sh', 'pnpm i | tee log\n').length, 1);
    assert.equal(one('scripts/a.sh', 'pnpm install --frozen-lockfile=false\n').length, 1);
    assert.equal(one('scripts/a.sh', 'pnpm install-test\n').length, 1);
    assert.equal(one('scripts/a.sh', 'pnpm it\n').length, 1);
    assert.deepEqual(one('scripts/a.sh', 'pnpm install-test --frozen-lockfile\n'), []);
    assert.equal(one('.cursor/environment.json', '{ "install": "corepack pnpm install\\necho --frozen-lockfile" }\n').length, 1);
});

test('an argument list is the command its words make', () => {
    for (const [path, text] of [
        ['Dockerfile', 'RUN ["npm", "install"]\n'],
        ['Dockerfile', 'RUN ["pnpm","install"]\n'],
        ['Dockerfile', 'CMD ["sh", "-c", "npm ci && node a.js"]\n'],
        ['docker-compose.yml', 'services:\n  a:\n    command: [pnpm, install]\n'],
        ['docker-compose.yml', "services:\n  a:\n    entrypoint: ['npm', 'exec', 'wrangler']\n"],
        ['docker-compose.yml', 'services:\n  a:\n    command:\n      - pnpm\n      - install\n'],
        ['docker-compose.yml', 'services:\n  a:\n    command:\n    - npx\n    - wrangler\n'],
        ['docker-compose.yml', 'services:\n  a:\n    healthcheck:\n      test: ["CMD", "curl", "-f", "https://example.com"]\n'],
        ['action/action.yml', "runs:\n  using: docker\n  args:\n    - 'pnpm'\n    - 'install'\n"],
    ]) assert.ok(one(path, text, { pnpm: '11.8.0' }).length >= 1, text);
    assert.deepEqual(one('Dockerfile', 'RUN ["pnpm", "install", "--frozen-lockfile"]\nENTRYPOINT ["coffre"]\n'), []);
    assert.deepEqual(one('docker-compose.yml', 'services:\n  a:\n    command:\n    - pnpm\n    - install\n    - --frozen-lockfile\n'), []);
    assert.deepEqual(one('docker-compose.yml', "services:\n  a:\n    healthcheck:\n      test: ['CMD-SHELL', 'pg_isready -U coffre_owner -d coffre']\n"), []);
    assert.deepEqual(one('scripts/a.sh', 'jq ".[0,1]" a.json\nif [ -f a ]; then echo; fi\n'), []);
});

test('docker run, create or pull names its image by digest on the line', () => {
    assert.deepEqual(one('scripts/a.sh', `docker run --rm --name pg -it postgres:16.14@${DIGEST} psql\n`), []);
    assert.deepEqual(one('scripts/a.sh', `docker run --rm -d \\\n    -p 127.0.0.1::5432 \\\n    postgres:16.14@${DIGEST}\n`), [], 'a continued line');
    assert.deepEqual(one('scripts/a.sh', 'docker image inspect "$image"\ndocker image rm -f "$image"\ndocker compose up -d --pull always postgres\nusermod -aG docker ubuntu\n'), []);
    for (const line of [
        'docker run --rm -p 127.0.0.1::5432 golang:1.25-alpine go run .',
        'docker run --rm "$image"',
        'docker pull postgres',
        'docker image pull postgres:16.14',
        'docker container run --rm postgres:16.14',
        'docker container create --name pg postgres:16.14',
        'sudo docker run --rm postgres:16.14',
        'docker --context ci run --rm postgres:16.14',
        'docker container --debug run --rm postgres:16.14',
    ]) assert.equal(one('scripts/a.sh', `${line}\n`).length, 1, line);
    assert.deepEqual(one('scripts/a.sh', "# unpinned: compose's image, pinned there\ndocker run --rm \"$image\"\n"), []);
});

test('YAML is read as the data GitHub and Compose make of it, by js-yaml', () => {
    const workflow = (path) => (text) => one(path, text, { pnpm: '11.8.0' });
    const problems = workflow('.github/workflows/a.yml');
    const step = (run) => `jobs:\n  a:\n    steps:\n      - name: Install\n        run: ${run}\n      - run: pnpm build\n`;
    assert.deepEqual(problems(step('|\n          pnpm --dir app install --frozen-lockfile\n          pnpm build')), []);
    // Each line of a block is the shell's, wherever it is in the string.
    assert.match(problems(step('|\n          pnpm --dir app install\n          echo --frozen-lockfile'))[0], /a\.yml: jobs\.a\.steps\[0\]\.run, line 1: pnpm install without --frozen-lockfile/);
    // Folded, continued, indented by an indicator, anchored or tagged: the string YAML makes is read.
    for (const run of [
        '>-\n          pnpm --dir app\n          install',
        '>\n          gh release\n          download v1.0.0',
        // r8: YAML keeps these two lines apart; one install's flag is not the other's.
        '>2-\n            pnpm --dir cli install\n            pnpm --dir web install --frozen-lockfile',
        '|2\n            pnpm --dir web install',
        '&install !!str >-\n          pnpm --dir app install',
        'pnpm --dir app\n          install',
        '"pnpm --dir app\n          install"',
        '\n          pnpm --dir app install',
    ]) assert.ok(problems(step(run)).length >= 1, run);
    assert.deepEqual(problems(step('>-\n          pnpm --dir app\n          install --frozen-lockfile')), [], 'one command, folded');
    // r9: a quoted key is the key.
    assert.match(problems('jobs:\n  a:\n    steps:\n      - "uses": actions/checkout@v4\n')[0], /steps\[0\]\.uses: uses actions\/checkout@v4 is not/);
    assert.match(problems("jobs:\n  a:\n    'runs-on': ubuntu-latest\n")[0], /runs-on ubuntu-latest moves/);
    assert.match(problems('jobs:\n  a:\n    steps:\n      - "run": pnpm install\n')[0], /pnpm install without --frozen-lockfile/);
    // r9: an implicit pair in a flow list is a mapping, and a matrix's include entry.
    const node = (include) => `jobs:\n  a:\n    strategy:\n      matrix:\n        include: ${include}\n    steps:\n      - uses: actions/setup-node@${SHA} # v4.4.0\n        with:\n          node-version: \${{ matrix.node }}\n`;
    assert.match(problems(node("[node: '22']"))[0], /node-version 22 is not an exact version/);
    assert.match(problems(node("[node: '24.22.1', node: lts/*]"))[0], /node-version lts\/\* is not/);
    assert.deepEqual(problems(node("[node: '24.22.1', {node: 22.23.4, shard: 1/2}]")), []);
    // r8: flow mappings, wherever they are.
    assert.match(problems("jobs:\n  a:\n    services:\n      redis: {image: 'redis:7'}\n")[0], /services\.redis\.image: image redis:7 is not/);
    assert.match(problems(`jobs:\n  a:\n    steps:\n      - uses: actions/setup-node@${SHA} # v4.4.0\n        with: {node-version: '24'}\n`)[0], /node-version 24 is not an exact version/);
    assert.match(problems("jobs:\n  a:\n    steps: [{uses: 'actions/checkout@v4'}]\n")[0], /uses actions\/checkout@v4 is not/);
    assert.match(one('docker-compose.yml', 'services: {pg: {image: postgres:16}}\n')[0], /services\.pg\.image: image postgres:16 is not/);
    // Anchors, aliases and merge keys are what they point at.
    assert.match(problems('x: &install pnpm install\njobs:\n  a:\n    steps:\n      - run: *install\n').find((p) => p.includes('steps[0].run')), /without --frozen-lockfile/);
    assert.match(one('docker-compose.yml', 'x-base: &base\n  image: redis:7\nservices:\n  r:\n    <<: *base\n')[0], /services\.r\.image: image redis:7 is not/);
    // A string a matrix completes is read with each of its values.
    assert.match(problems('jobs:\n  a:\n    strategy:\n      matrix:\n        command: [build, install]\n    steps:\n      - run: pnpm ${{ matrix.command }}\n')[0], /pnpm install without --frozen-lockfile/);
    // r12: GitHub looks a matrix key up whatever its case, and by brackets; any other read of it fails.
    const matrix = (values, run) => `jobs:\n  a:\n    strategy:\n      matrix: ${values}\n    steps:\n      - run: ${run}\n`;
    assert.match(problems(matrix('{Command: [install]}', 'pnpm ${{ matrix.command }}'))[0], /pnpm install without --frozen-lockfile/);
    assert.match(problems(matrix('{command: [install]}', "pnpm ${{ matrix['command'] }}"))[0], /pnpm install without --frozen-lockfile/);
    assert.match(problems(matrix('{command: [install]}', 'pnpm ${{ Matrix.Command }}'))[0], /pnpm install without --frozen-lockfile/);
    assert.match(problems(matrix('{include: [{Command: install}]}', 'pnpm ${{ matrix.command }}'))[0], /pnpm install without --frozen-lockfile/);
    assert.match(problems(matrix('{c: [{x: install}]}', 'pnpm ${{ matrix.c.x }}'))[0], /\$\{\{ matrix\.c\.x \}\} reads the matrix in a form this cannot follow/);
    assert.match(problems(matrix('{c: [install]}', "pnpm ${{ format('{0}', matrix.c) }}"))[0], /reads the matrix in a form this cannot follow/);
    assert.match(problems(matrix("'${{ fromJSON(inputs.m) }}'", 'pnpm ${{ matrix.c }}'))[0], /\$\{\{ matrix\.c \}\}: no value this reads/);
    assert.deepEqual(problems(matrix('{shard: [1, 2]}', 'scripts/formal.sh --shard ${{ MATRIX.Shard }}')), []);
    // A description is prose, read too; a name GitHub or Compose reads as no image is none.
    assert.equal(one('action/action.yml', 'inputs:\n  url:\n    description: >-\n      Run curl https://example.com/i.sh\n').length, 1);
    assert.deepEqual(one('docker-compose.yml', `services:\n  image:\n    image: postgres:16.14@${DIGEST}\n`), []);
    assert.deepEqual(problems('jobs:\n  image:\n    runs-on: ubuntu-24.04\n    env:\n      image: whatever\n'), []);
    // What YAML cannot read, or reads twice, fails.
    assert.match(problems('jobs:\n  a:\n    runs-on: ubuntu-24.04\n    runs-on: ubuntu-latest\n')[0], /a\.yml: duplicated mapping key/);
    assert.match(problems('jobs:\n  a: [\n')[0], /a\.yml: unexpected end of the stream/);
});

test('a line that cannot be pinned says why, on itself or right above it', () => {
    assert.deepEqual(one('scripts/a.sh', '# unpinned: init writes no lockfile\npnpm --dir "$project" install\n'), []);
    assert.deepEqual(one('scripts/a.sh', '# The first install.\n# unpinned: init writes no lockfile\n# More.\npnpm --dir "$project" install\n'), []);
    assert.deepEqual(one('.cursor/Dockerfile', '# unpinned: the archive serves its current versions\nRUN apt-get update \\\n    && apt-get install -y curl\n'), []);
    assert.equal(one('scripts/a.sh', '# unpinned:\npnpm --dir "$project" install\n').length, 1, 'a reason');
    assert.equal(one('scripts/a.sh', '# unpinned: why\n\npnpm --dir "$project" install\n').length, 1, 'right above');
});

test('a toolchain an action installs is an exact version, and a runner a named image', () => {
    const setup = (with_) => `jobs:\n  a:\n    steps:\n      - uses: actions/setup-node@${SHA} # v4.4.0\n        with:\n${with_}`;
    assert.deepEqual(one('.github/workflows/a.yml', setup('          node-version: 24.22.1\n          java-version: 17.0.9+9\n')), []);
    assert.match(one('.github/workflows/a.yml', setup('          node-version: 24\n'))[0], /node-version 24 is not an exact version/);
    assert.equal(one('.github/workflows/a.yml', setup('          node-version: lts/*\n')).length, 1);
    assert.equal(one('action/action.yml', 'runs:\n  steps:\n    - with:\n        go-version: 1.25\n').length, 1, 'a composite action’s step');
    // GitHub reads an input's name whatever its case; pnpm/action-setup's is `version`.
    assert.match(one('.github/workflows/a.yml', setup("          Node-Version: '24'\n"))[0], /Node-Version 24 is not an exact version/);
    assert.match(one('.github/workflows/a.yml', setup('          NODE-VERSION: lts/*\n'))[0], /NODE-VERSION lts\/\* is not/);
    assert.match(one('.github/workflows/a.yml', setup('          version: 11\n'))[0], /version 11 is not an exact version/);
    assert.deepEqual(one('.github/workflows/a.yml', setup('          version: 11.8.0\n')), []);
    assert.match(one('.github/workflows/a.yml', `jobs:\n  a:\n    steps:\n      - uses: docker/x@${SHA} # v1.0.0\n        with:\n          Image: postgres:16\n`)[0], /image postgres:16 is not/);
    const matrix = (values) => `jobs:\n  a:\n    strategy:\n      matrix:\n        node: [${values}]\n    steps:\n      - with:\n          node-version: \${{ matrix.node }}\n`;
    assert.deepEqual(one('.github/workflows/a.yml', matrix("'runner', '20.0.0', '24.22.1'")), []);
    assert.equal(one('.github/workflows/a.yml', matrix("'20.0.0', '20'")).length, 1);
    assert.equal(one('.github/workflows/a.yml', matrix("'lts/*', '24.22.1'")).length, 1, '`runner` alone names no version');
    const block = (values) => `jobs:\n  a:\n    strategy:\n      matrix:\n        node:\n${values.map((v) => `          - ${v}\n`).join('')}    steps:\n      - with:\n          node-version: \${{ matrix.node }}\n`;
    assert.deepEqual(one('.github/workflows/a.yml', block(['24.22.1', "'22.23.4'"])), []);
    assert.match(one('.github/workflows/a.yml', block(['24.22.1', '24']))[0], /node-version 24 is not an exact version/);
    assert.match(one('.github/workflows/a.yml', 'jobs:\n  a:\n    steps:\n      - with:\n          node-version: ${{ matrix.node }}\n')[0], /no value this reads/);
    // An include adds its own jobs; each value is held too, block or flow.
    const job = (strategy) => `jobs:\n  a:\n    strategy:\n      matrix:\n${strategy}    steps:\n      - with:\n          node-version: \${{ matrix.node }}\n`;
    assert.match(one('.github/workflows/a.yml', job("        include:\n          - node: 24\n"))[0], /node-version 24 is not an exact version/);
    assert.match(one('.github/workflows/a.yml', job("        node: ['24.22.1']\n        include: [{node: '22'}]\n"))[0], /node-version 22 is not an exact version/);
    assert.match(one('.github/workflows/a.yml', job("        node: ['24.22.1']\n        include:\n          - os: linux\n            node: lts/*\n"))[0], /node-version lts\/\* is not/);
    assert.deepEqual(one('.github/workflows/a.yml', job("        node: ['24.22.1']\n        include:\n          - node: 22.23.4\n            experimental: true\n")), []);
    // The job's own matrix, wherever it is in the job; not another job's.
    assert.deepEqual(one('.github/workflows/a.yml', "jobs:\n  a:\n    container: ${{ matrix.image }}\n    strategy:\n      matrix:\n        image: ['node:24@" + DIGEST + "']\n"), []);
    assert.equal(one('.github/workflows/a.yml', "jobs:\n  a:\n    strategy:\n      matrix:\n        node: ['24.22.1']\n  b:\n    steps:\n      - with:\n          node-version: ${{ matrix.node }}\n").length, 1);
    assert.equal(one('.github/workflows/a.yml', "jobs:\n  a:\n    strategy:\n      matrix: ${{ fromJSON(needs.x.outputs.m) }}\n    steps:\n      - with:\n          node-version: ${{ matrix.node }}\n").length, 1, 'a matrix not written out');
    assert.equal(one('.github/workflows/a.yml', 'jobs:\n  a:\n    runs-on: ubuntu-latest\n').length, 1);
    assert.equal(one('.github/workflows/a.yml', 'jobs:\n  a:\n    runs-on: [self-hosted, ubuntu-latest]\n').length, 1);
    assert.equal(one('.github/workflows/a.yml', 'jobs:\n  a:\n    strategy:\n      matrix:\n        os: [ubuntu-24.04, macos-latest]\n    runs-on: ${{ matrix.os }}\n').length, 1);
    assert.deepEqual(one('.github/workflows/a.yml', 'jobs:\n  a:\n    runs-on: ubuntu-24.04\n'), []);
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
    // Any style YAML has is read as pnpm reads it.
    assert.match(one('pnpm-workspace.yaml', `${root}minimumReleaseAgeExclude: ['*']\n`, { root: true })[0], /lets \* in younger than a week/);
    assert.match(one('examples/node/pnpm-workspace.yaml', "{strictDepBuilds: true, minimumReleaseAge: 10080, minimumReleaseAgeExclude: ['@coffre/*', wrangler]}\n")[0], /lets wrangler in/);
    assert.match(one('pnpm-workspace.yaml', root.replace('allowBuilds:\n  esbuild: false\n', 'allowBuilds: { esbuild: true }\n'), { root: true })[0], /allowBuilds esbuild: true needs/);
    assert.match(one('pnpm-workspace.yaml', root.replace("savePrefix: ''", "'savePrefix': '^'"), { root: true })[0], /savePrefix is not ''/);
    assert.equal(one('pnpm-workspace.yaml', root.replace('  esbuild: false', '  esbuild: false\n  ? koffi\n'), { root: true }).length, 1, 'neither true nor false');
    assert.match(one('pnpm-workspace.yaml', root.replace('10080', "'10080'"), { root: true })[0], /minimumReleaseAge "10080" is under/, 'a string');
    assert.match(one('pnpm-workspace.yaml', `${root}minimumReleaseAge: 0\n`, { root: true })[0], /duplicated mapping key/);
    assert.match(one('pnpm-workspace.yaml', `${root}onlyBuiltDependencies:\n  - esbuild\n`, { root: true })[0], /allowBuilds is the one place/);
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
