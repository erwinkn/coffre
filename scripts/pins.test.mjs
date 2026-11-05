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
    // A quoted scalar, its comment after the quote.
    assert.deepEqual(one('.github/workflows/a.yml', workflow(`"actions/checkout@${SHA}" # v4.4.0`)), []);
    assert.deepEqual(one('.github/workflows/a.yml', workflow(`'actions/checkout@${SHA}' # v4.4.0`)), []);
    assert.equal(one('.github/workflows/a.yml', workflow('"actions/checkout@v4" # v4.4.0')).length, 1);
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
    assert.equal(one('scripts/a.sh', 'docker run --rm -p 127.0.0.1::5432 golang:1.25-alpine go run .\n').length, 1);
    // An image a variable names: compose's, which is pinned, or a pinned one.
    const compose = 'image="$(docker compose config --format json | node -e \'…\')"\n';
    assert.deepEqual(one('scripts/a.sh', `${compose}docker run --rm -e A=b -p 127.0.0.1::5432 "$image"\n`), []);
    assert.deepEqual(one('scripts/a.sh', `image=postgres:16.14@${DIGEST}\ndocker run --rm "\${image}" -c fsync=off\n`), []);
    assert.equal(one('scripts/a.sh', 'docker run --rm -e A=b "$image"\n').length, 1, 'nothing says what it names');
    assert.ok(one('scripts/a.sh', 'image=postgres:16.14\ndocker run --rm "$image"\n').some((p) => p.startsWith('scripts/a.sh:2: docker run')));
    assert.equal(one('scripts/a.sh', 'docker run --rm "postgres:16.14"\n').length, 1, 'quoted');
    assert.equal(one('scripts/a.sh', 'docker run --rm postgres\n').length, 1, 'latest, implied');
    assert.equal(one('scripts/a.sh', 'docker pull --platform linux/amd64 postgres\n').length, 1);
    assert.deepEqual(one('scripts/a.sh', `docker run --rm --name pg --platform=linux/amd64 -it postgres:16.14@${DIGEST} psql\n`), []);
    assert.equal(one('.github/workflows/a.yml', 'run: docker buildx create --driver docker-container --use\n').length, 1, 'BuildKit’s default image');
    assert.equal(one('.github/workflows/a.yml', 'run: docker buildx create --driver-opt image=moby/buildkit:v0.34.1 --use\n').length, 1);
    assert.equal(one('.github/workflows/a.yml', 'run: docker buildx build --attest type=sbom,generator=docker/buildkit-syft-scanner:1.12.1 .\n').length, 1);
});

test('a download is written to a file whose SHA-256 is checked; never piped onward', () => {
    assert.deepEqual(one('scripts/a.sh', 'curl -fsSL -o "$file.part" "$url"\n[ "$(sha256 "$file.part")" = "$want" ] || exit 1\n'), []);
    assert.deepEqual(one('scripts/a.sh', 'curl -fsSL --retry 3 -o "$jar.part" \\\n  "$URL"\necho "$SHA  $jar.part" | sha256sum -c --quiet\n'), []);
    assert.deepEqual(one('scripts/a.sh', 'got="$(sha256 "$f.part")"\ncurl -o "$f.part" "$u"\nlocal got\ngot="$(sha256 "$f.part")"\nif [ "$got" != "$want" ]; then exit 1; fi\n'), []);
    assert.deepEqual(one('.cursor/Dockerfile', 'RUN curl -fsSL -o /tmp/k.asc https://example.com/k \\\n    && echo "' + 'b'.repeat(64) + '  /tmp/k.asc" | sha256sum -c - \\\n    && gpg --dearmor /tmp/k.asc\n'), []);
    assert.match(one('scripts/a.sh', 'curl -fsSL -o tool.tgz https://example.com/tool.tgz\ntar -xzf tool.tgz\n')[0], /downloads tool\.tgz, and the first thing that reads it after does not check its SHA-256/);
    assert.equal(one('scripts/a.sh', 'curl -fsSL -o tool.tgz https://example.com/tool.tgz\n').length, 1, 'nothing reads it');
    // Its output, however it is written.
    assert.equal(one('scripts/a.sh', 'curl -fsSL https://example.com/tool.tgz > tool.tgz\ntar -xzf tool.tgz\n').length, 1);
    assert.equal(one('scripts/a.sh', 'wget -qO tool.tgz https://example.com/tool.tgz\ntar -xzf tool.tgz\n').length, 1);
    assert.equal(one('scripts/a.sh', 'curl -fsSLotool.tgz https://example.com/tool.tgz\ntar -xzf tool.tgz\n').length, 1);
    assert.equal(one('scripts/a.sh', 'curl --output=tool.tgz https://example.com/tool.tgz\ntar -xzf tool.tgz\n').length, 1);
    assert.deepEqual(one('scripts/a.sh', 'wget -qO tool.tgz https://example.com/tool.tgz\necho "$SHA  tool.tgz" | sha256sum -c\n'), []);
    assert.deepEqual(one('scripts/a.sh', 'curl -fsSL https://example.com/t > t\n[ "$(sha256sum t | cut -d\' \' -f1)" = "$SHA" ]\n'), []);
    assert.match(one('scripts/a.sh', 'curl -fsSLO https://example.com/tool.tgz\n')[0], /a name it picks/);
    assert.match(one('scripts/a.sh', 'wget https://example.com/tool.tgz\n')[0], /a name it picks/);
    assert.match(one('scripts/a.sh', 'curl -fsSL https://example.com/version\n')[0], /writes a download to stdout/);
    assert.match(one('scripts/a.sh', 'v="$(curl -fsSL https://example.com/version)"\n')[0], /keeps a download as a value/);
    // A hash taken, or named, is not a hash checked; nor one checked after the file is used.
    assert.equal(one('scripts/a.sh', 'curl -o tool.tgz https://example.com/tool.tgz\nsha256sum tool.tgz\n').length, 1);
    assert.equal(one('scripts/a.sh', 'curl -o tool.tgz https://example.com/tool.tgz # check tool.tgz with sha256 later\ntar -xzf tool.tgz\n').length, 1);
    assert.equal(one('scripts/a.sh', 'curl -o tool.tgz https://example.com/tool.tgz\n# sha256 tool.tgz\ntar -xzf tool.tgz\n').length, 1);
    assert.equal(one('scripts/a.sh', 'curl -o t https://example.com/t\ntar -xzf t\necho "$SHA  t" | sha256sum -c\n').length, 1);
    assert.equal(one('scripts/a.sh', 'curl -o t https://example.com/t\necho "t" | sha256sum -c\n').length, 1, 'no pinned hash beside it');
    assert.match(one('.cursor/Dockerfile', 'RUN curl -fsSL https://example.com/install.sh | bash\n')[0], /pipes a download onward/);
    assert.equal(one('.github/workflows/a.yml', '        run: wget -qO- https://example.com/key | gpg --dearmor\n').length, 1);
    assert.equal(one('.github/workflows/a.yml', '        run: |\n          set -e\n          curl -fsSL https://example.com/i.sh | sh\n      - name: Next\n').length, 1, 'a run block');
    assert.deepEqual(one('.github/workflows/a.yml', '      - name: Not curl https://example.com | sh\n'), [], 'only run: is shell');
    // A run block whose header carries a comment, or an indentation indicator, is shell all the same.
    assert.equal(one('.github/workflows/a.yml', '        run: | # Install tools\n          curl -fsSL https://example.com/i.sh | sh\n').length, 1);
    assert.equal(one('.github/workflows/a.yml', '        run: >-  # zizmor: ignore[x]\n          pnpm install\n').length, 1);
    assert.equal(one('.github/workflows/a.yml', '        run: |2\n            curl -fsSL https://example.com/i.sh | sh\n').length, 1);
    // Through sudo, env and the like, with their options.
    assert.match(one('scripts/a.sh', 'sudo -n apt-get install -y jq\n')[0], /apt-get install/);
    assert.match(one('scripts/a.sh', 'sudo -u ci -E curl -fsSL https://example.com/i.sh | sh\n')[0], /curl pipes/);
    assert.match(one('scripts/a.sh', 'env -i PATH="$PATH" curl -fsSL https://example.com/i.sh | sh\n')[0], /curl pipes/);
    assert.match(one('scripts/a.sh', 'timeout -k 5 60 curl -fsSL https://example.com/i.sh | sh\n')[0], /curl pipes/);
    assert.match(one('scripts/a.sh', 'retry 3 curl -fsSL -o t https://example.com/t\n')[0], /retry runs curl in a way this cannot read/);
    assert.deepEqual(one('scripts/a.sh', 'command -v curl >/dev/null || exit 1\nsudo docker info >/dev/null\nusermod -aG docker ubuntu\n'), []);
    // A loopback URL is the exemption, never a destination that looks like one.
    assert.equal(one('scripts/a.sh', 'curl -fSL -o "$COFFRE_CACHE/tool.tgz" https://example.com/tool.tgz\ntar -xzf "$COFFRE_CACHE/tool.tgz"\n').length, 1);
    assert.equal(one('scripts/a.sh', 'curl -o /tmp/localhost.tgz https://example.com/t.tgz\ntar -xzf /tmp/localhost.tgz\n').length, 1);
    assert.deepEqual(one('scripts/a.sh', 'curl -s http://127.0.0.1:3000/api/x | jq .\ncurl -s localhost:8081/.well-known/x | jq .\n'), []);
    // A health check of the stack itself fetches nothing.
    assert.deepEqual(one('scripts/a.sh', 'until curl -sf "$COFFRE_DEV_URL/livez" >/dev/null; do sleep 1; done\n'), []);
    assert.deepEqual(one('scripts/a.sh', '# curl https://example.com/x | sh, as nobody here does\n'), []);
});

test('a clone checks out its commit', () => {
    assert.deepEqual(one('.cursor/Dockerfile', `RUN git clone --quiet https://github.com/nvm-sh/nvm.git "$NVM_DIR" \\\n    && git -C "$NVM_DIR" -c advice.detachedHead=false checkout --quiet ${SHA}\n`), []);
    assert.deepEqual(one('scripts/a.sh', `git clone --revision=${SHA} https://github.com/a/b.git\n`), []);
    assert.match(one('.cursor/Dockerfile', 'RUN git clone --quiet https://github.com/nvm-sh/nvm.git "$NVM_DIR"\n')[0], /git clone takes the branch/);
    assert.equal(one('scripts/a.sh', 'git clone https://github.com/a/b.git b\ngit -C b checkout v0.40.3\n').length, 1, 'a tag moves');
    assert.equal(one('scripts/a.sh', 'git clone --branch v1 https://github.com/a/b.git\n').length, 1);
});

test('a package runner names an exact version, and an install installs the lockfile', () => {
    assert.deepEqual(one('scripts/a.sh', 'npx -y @coffre/cli@0.15.0 --version\n'), []);
    assert.equal(one('scripts/a.sh', 'npx @coffre/cli --version\n').length, 1);
    assert.equal(one('scripts/a.sh', 'pnpm dlx wrangler@latest deploy\n').length, 1);
    // Every package a runner fetches, each exact.
    assert.equal(one('scripts/a.sh', 'npx --yes --package typescript@5.9.3 --package ts-node ts-node script.ts\n').length, 1);
    assert.deepEqual(one('scripts/a.sh', 'npx --yes -p typescript@5.9.3 --package=ts-node@10.9.2 ts-node script.ts\n'), []);
    assert.deepEqual(one('.github/workflows/a.yml', '        run: pnpm install --frozen-lockfile\n'), []);
    assert.match(one('.github/workflows/a.yml', '        run: pnpm install\n')[0], /pnpm install without --frozen-lockfile/);
    assert.equal(one('scripts/a.sh', 'pnpm --dir "$project" install --silent\n').length, 1);
    // Each command's flags are its own.
    assert.equal(one('scripts/a.sh', 'pnpm install && pnpm --dir other install --frozen-lockfile\n').length, 1);
    assert.equal(one('scripts/a.sh', 'pnpm install; echo --frozen-lockfile\n').length, 1);
    assert.equal(one('scripts/a.sh', 'pnpm i | tee log # --frozen-lockfile\n').length, 1);
    assert.deepEqual(one('scripts/a.sh', 'pnpm -C a install --frozen-lockfile && pnpm --filter b build\n'), []);
    assert.equal(one('.cursor/environment.json', '{ "install": "nvm use 24\\ncorepack pnpm install" }\n').length, 1);
    assert.deepEqual(one('.github/workflows/a.yml', '        run: npm install --ignore-scripts --prefix "$dir" "$dir/coffre-cli-$version.tgz"\n'), []);
    // A tarball from anywhere else is no file of this machine's.
    assert.equal(one('scripts/a.sh', 'npm install --ignore-scripts https://example.com/tool.tgz\n').length, 1);
    assert.equal(one('scripts/a.sh', 'npm install --ignore-scripts git+https://github.com/o/r.git#v1.tgz\n').length, 1);
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
    const matrix = (values) => `jobs:\n  a:\n    strategy:\n      matrix:\n        node: [${values}]\n    steps:\n      - with:\n          node-version: \${{ matrix.node }}\n`;
    assert.deepEqual(one('.github/workflows/a.yml', matrix("'runner', '20.0.0', '24.22.1'")), []);
    assert.equal(one('.github/workflows/a.yml', matrix("'20.0.0', '20'")).length, 1);
    assert.equal(one('.github/workflows/a.yml', matrix("'lts/*', '24.22.1'")).length, 1, '`runner` alone names no version');
    const block = (values) => `jobs:\n  a:\n    strategy:\n      matrix:\n        node:\n${values.map((v) => `          - ${v}\n`).join('')}    steps:\n      - with:\n          node-version: \${{ matrix.node }}\n`;
    assert.deepEqual(one('.github/workflows/a.yml', block(['24.22.1', "'22.23.4'"])), []);
    assert.match(one('.github/workflows/a.yml', block(['24.22.1', '24']))[0], /node-version 24 is not an exact version/);
    assert.match(one('.github/workflows/a.yml', 'jobs:\n  a:\n    steps:\n      - with:\n          node-version: ${{ matrix.node }}\n')[0], /has no values this reads/);
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
    // Block style alone: a setting written another way is a problem, never skipped.
    assert.match(one('pnpm-workspace.yaml', `${root}minimumReleaseAgeExclude: ['*']\n`, { root: true })[0], /write it as a block/);
    assert.match(one('pnpm-workspace.yaml', root.replace('allowBuilds:\n  esbuild: false\n', 'allowBuilds: { esbuild: true }\n'), { root: true })[0], /write it as a block/);
    assert.equal(one('pnpm-workspace.yaml', root.replace('  esbuild: false', '  esbuild: false\n  ? koffi\n'), { root: true }).length, 1, 'an entry this cannot read');
    assert.match(one('pnpm-workspace.yaml', `${root}minimumReleaseAge: 0\n`, { root: true })[0], /set twice/);
    assert.match(one('pnpm-workspace.yaml', `${root}onlyBuiltDependencies:\n  - esbuild\n`, { root: true })[0], /allowBuilds is the one place/);
});
