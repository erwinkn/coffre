// What scripts/check-pins.mjs holds every tracked file to, besides the
// manifests: whatever CI, a Dockerfile or a script fetches is named by
// something that cannot move under it. An action by its commit, an image by
// its index digest (its tag beside it, for people), a download by its
// SHA-256, an install by the lockfile. zizmor holds the actions to their
// commits too (scripts/zizmor.sh); this needs no network and no binary.
//
// It reads no shell. A download goes through scripts/fetch.sh, which checks
// the file against the SHA-256 it is given, or a Dockerfile's
// `ADD --checksum=sha256:…`; every other fetcher (curl, wget, npx, `npm
// exec`, `gh release download`, `git clone`, …) is banned by name, on any
// line that is not a comment, however it is called. Its words in a message
// are banned too: reword the message. A fetch it has no name for, or one
// built to hide (`eval "$cmd"`, `node -e 'fetch(…)'`), is review's to catch.
// YAML is no text to it: js-yaml reads it into the data GitHub, Compose and
// pnpm read, and the checks walk that.
//
// Two markers, each on the line it covers:
//   `# pins: local`        curl or wget of this machine (127.0.0.1, localhost
//                          or [::1]) and nothing else: a health check.
//   `# unpinned: <reason>` anything that cannot be pinned, on the line or in
//                          the comment block right above it. The reason is
//                          the review.

import { loadAll } from 'js-yaml';

// `name:tag@sha256:<digest>`: the tag for people, the digest for Docker.
const IMAGE = /^[a-z0-9][a-z0-9._/-]*(?::\d+)?\/?[a-z0-9._/-]*:[A-Za-z0-9_][A-Za-z0-9._-]*@sha256:[0-9a-f]{64}$/;
const EXACT_VERSION = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/;

// The one file that downloads.
const FETCHER = 'scripts/fetch.sh';

// A program's name as a word of its own, or a path's last (`/usr/bin/curl`): not
// `libcurl`, `curl-config` or `/etc/docker/`.
const word = (name) => `(?<![\\w.-])${name}(?![\\w./-])`;
// The rest of a command: up to the next `;`, `&`, `|`, `)` or `\n`.
const REST = String.raw`(?:(?![;&|)]|\\n).)*?`;
// A program's version beside it, as Corepack runs one (`corepack pnpm@11.8.0 dlx`).
const AT_VERSION = String.raw`(?:@[^\s"'\`;&|)]*)?`;
// The space between two words of a command, and any words between them.
const THEN = String.raw`\s+(?:${REST}\s)?`;
// A program, any options, then its subcommands, each word of them after any
// options of its own (`gh release --repo o/r download`).
const command = (program, subcommands) => new RegExp(`${word(program)}${AT_VERSION}${THEN}(?:${subcommands})(?=[\\s"';&|)]|\\\\n|$)`);

// What fetches something no lockfile, digest or checksum holds.
const BANNED = [
    { pattern: new RegExp(word('(?:curl|wget)')), local: true, say: (m) => `${m} downloads: use scripts/fetch.sh <url> <sha256> <file> (a Dockerfile: ADD --checksum=sha256:…), or mark a health check of this machine \`# pins: local\`` },
    { pattern: new RegExp(word('(?:npx|pnpx|bunx|uvx|pipx)')), say: (m) => `${m} runs a package no lockfile holds` },
    { pattern: command('npm', 'exec|x|install|i|in|ins|inst|insta|instal|isnt|isnta|isntal|isntall|add|install-test|it|ci|clean-install|ic|install-clean|isntall-clean|install-ci-test|cit|clean-install-test|sit|update|up|upgrade|udpate|link|ln|dedupe|ddp|pack|create|init|innit|dlx'), say: () => 'npm fetches packages outside the lockfile: install with pnpm install --frozen-lockfile' },
    { pattern: command('pnpm', 'dlx|create|add|update|up|upgrade|self-update'), say: (m) => `${m} fetches packages outside the lockfile (add one with pnpm run add:dep)` },
    { pattern: command('yarn', 'dlx|add|create'), say: (m) => `${m} fetches packages outside the lockfile` },
    { pattern: command('gh', `(?:release|run|attestation)${THEN}download`), say: (m) => `${m} downloads: use scripts/fetch.sh <url> <sha256> <file>` },
    { pattern: command('git', `clone|submodule${THEN}update${THEN}--remote`), say: (m) => `${m} takes a branch as it is: fetch a file at its commit with scripts/fetch.sh` },
    { pattern: command('nvm', 'install|reinstall-packages|install-latest-npm'), say: (m) => `${m} checks Node against nodejs.org's own list: fetch the tarball by its SHA-256` },
    { pattern: command('corepack', 'up|use'), say: (m) => `${m} moves packageManager` },
    { pattern: command('(?:apt-get|apt)', 'install'), say: () => "apt-get install takes the archive's current versions" },
    { pattern: command('(?:pip|pip3|gem|cargo|brew)', 'install'), say: (m) => `${m} fetches packages no lockfile holds` },
    { pattern: command('go', 'install|get'), say: (m) => `${m} fetches modules outside go.sum` },
];
const PNPM_INSTALL = command('pnpm', 'install|i|install-test|it');
// Corepack's own subcommands that fetch, right after it (`corepack pnpm install` is pnpm's).
const COREPACK_FETCH = new RegExp(`${word('corepack')}${AT_VERSION}\\s+(?:install|prepare|hydrate)(?=[\\s"';&|)]|\\\\n|$)`);
// `docker run`, and its management command's spelling, `docker container run`;
// `docker buildx create`'s image is its `--driver-opt image=`, read below.
const DOCKER_PULLS = command('docker(?!\\s+buildx\\b)', `(?:(?:image|container|service)${THEN})?(?:run|create|pull)`);
const PINNED_IMAGE = /@sha256:[0-9a-f]{64}(?![0-9a-f])/;
const URL = /[a-z][a-z0-9+.-]*:\/\/[^\s"'`)]*/gi;
const LOOPBACK = /^https?:\/\/(?:127\.0\.0\.1|localhost|\[::1\])(?:[:/]|$)/;

/** The kinds of file whose contents fetch or run something. */
export function kindOf(path) {
    const name = path.split('/').at(-1);
    if (/(^|\/)\.github\/(workflows|actions)\/.+\.ya?ml$/.test(path) || /^action\.ya?ml$/.test(name)) return 'workflow';
    if (/^(docker-)?compose(\.[\w-]+)*\.ya?ml$/.test(name)) return 'compose';
    if (name === 'Dockerfile' || name.endsWith('.Dockerfile') || name.startsWith('Dockerfile.')) return 'dockerfile';
    if (name.endsWith('.sh')) return 'shell';
    if (path === '.cursor/environment.json') return 'json';
    if (name === 'pnpm-workspace.yaml') return 'workspace';
    return null;
}

/**
 * Every problem in one file: `path:line: what` in a script or a Dockerfile,
 * `path: <where in its data>: what` in YAML or JSON. `pnpm` is the
 * workspace's packageManager version, the one pnpm Corepack may fetch.
 */
export function problemsIn(path, text, { root = false, pnpm } = {}) {
    const kind = kindOf(path);
    if (kind === null) return [];
    const problems = new Set();
    if (kind === 'shell' || kind === 'dockerfile') {
        scan(text, kind, (index, message) => problems.add(`${path}:${index + 1}: ${message}`), { path, pnpm });
        return [...problems];
    }
    // YAML is read by js-yaml, as GitHub, Compose and pnpm read it: anchors,
    // quoted keys, flow collections and folded blocks are the data they make.
    let documents;
    try {
        documents = kind === 'json' ? [JSON.parse(text)] : loadAll(text);
    } catch (error) {
        return [`${path}: ${error.message.split('\n')[0]}`];
    }
    const report = (where, message) => problems.add(`${path}: ${where}: ${message}`);
    if (kind === 'workspace') workspace(documents, text, report, root);
    else for (const document of documents) data(document, kind, text, report, { path, pnpm });
    return [...problems];
}

// What a shell or Docker runs, line by line: a script, a Dockerfile, or a
// string in a workflow, compose file or JSON (a `run:`, a `command:`).
function scan(text, kind, report, { path, pnpm }) {
    const lines = text.split('\n');
    for (const { index, line, exempt } of logicalLines(lines, kind)) {
        if (exempt) continue;
        // A Dockerfile's frontend is an image BuildKit pulls.
        const syntax = kind === 'dockerfile' && line.match(/^#\s*syntax\s*=\s*(\S+)/i);
        if (syntax && !IMAGE.test(syntax[1])) report(index, `syntax ${syntax[1]} is not name:tag@sha256:<index digest>`);
        // Comments name commands without running them.
        if (/^\s*#/.test(line)) continue;
        if (kind === 'dockerfile') dockerfileLine(line, index, lines, report);
        // BuildKit in a container is an image too, and its default moves.
        if (/\bbuildx\s+create\b/.test(line) && !/image=/.test(line)) report(index, 'docker buildx create without a pinned --driver-opt image=');
        for (const option of line.matchAll(/\b(?:image|generator)=([^\s,"']+)/g)) {
            if (!IMAGE.test(option[1])) report(index, `image ${option[1]} is not name:tag@sha256:<index digest>`);
        }
        if (path !== FETCHER) fetches(argv(line), index, report, pnpm);
    }
}

// A Dockerfile's argument list is the command its words make: `RUN ["npm",
// "install"]` reads as `npm install`. (YAML's are lists in its data.)
const ARG = String.raw`"(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s,[\]"'#{}]+`;
const ARGV = new RegExp(String.raw`\[\s*(?:${ARG})(?:\s*,\s*(?:${ARG}))+\s*,?\s*\]`, 'g');
function argv(line) {
    return line.replace(ARGV, (list) => [...list.matchAll(new RegExp(ARG, 'g'))].map(([word]) => unquoted(word)).join(' '));
}

function unquoted(word) {
    if (word.startsWith('"')) {
        try { return JSON.parse(word); } catch { return word.slice(1, -1); }
    }
    return word.startsWith("'") ? word.slice(1, -1).replaceAll("''", "'") : word;
}

// What a line fetches by name: a banned fetcher, an unfrozen install, an
// image no digest names, a pnpm Corepack would fetch other than the workspace's.
function fetches(line, index, report, pnpm) {
    for (const { pattern, local, say } of BANNED) {
        const match = line.match(pattern);
        if (!match) continue;
        if (local && localOnly(line)) continue;
        report(index, say(match[0].trim().replace(/\s+/g, ' ')));
    }
    // Each `pnpm … install` up to the end of its command carries the flag.
    for (const match of line.matchAll(new RegExp(PNPM_INSTALL.source + REST + String.raw`(?=[;&|)]|\\n|$)`, 'g'))) {
        if (!/(?<![\w-])--frozen-lockfile(?:=true)?(?![\w=-])/.test(match[0])) report(index, 'pnpm install without --frozen-lockfile');
    }
    // An image a command pulls is named by its digest on the line itself.
    if (DOCKER_PULLS.test(line) && !PINNED_IMAGE.test(line)) {
        report(index, 'docker run, create or pull of an image this line does not name by @sha256:<index digest>');
    }
    // Corepack fetches the package manager it is named: the workspace's alone,
    // by its version (`corepack install -g pnpm` takes the latest).
    for (const match of line.matchAll(new RegExp(COREPACK_FETCH.source + REST + String.raw`(?=[;&|)]|\\n|$)`, 'g'))) {
        const bare = match[0].match(/(?<![\w./@-])(?:pnpm|yarn|npm)(?![\w./@-])/g);
        if (bare) report(index, `${match[0].trim().replace(/\s+/g, ' ')} names no version: name pnpm@${pnpm ?? '<the workspace packageManager version>'}`);
    }
    for (const match of line.matchAll(/(?<![\w./-])(pnpm|yarn|npm)@([^\s"'`;&|)]*)/g)) {
        if (match[1] !== 'pnpm' || match[2] !== pnpm) report(index, `${match[0]} is not pnpm@${pnpm ?? '<the workspace packageManager version>'}, the workspace's`);
    }
}

// `# pins: local` on a line whose every URL is this machine's.
function localOnly(line) {
    if (!/#\s*pins:\s*local\s*$/.test(line)) return false;
    const urls = line.replace(/#\s*pins:\s*local\s*$/, '').match(URL) ?? [];
    return urls.length > 0 && urls.every((url) => LOOPBACK.test(url));
}

// Shell's and Dockerfiles' backslash continuations joined into one line, each
// at the index of its first, with whether a `# unpinned: <reason>` covers it.
function logicalLines(lines, kind) {
    const joined = [];
    for (let k = 0; k < lines.length; k++) {
        const start = k;
        let line = lines[k];
        while (/\\\s*$/.test(line) && k + 1 < lines.length) {
            k++;
            // A Dockerfile's comment inside a continued RUN is no part of it.
            if (kind === 'dockerfile' && /^\s*#/.test(lines[k])) {
                line = line.replace(/\\\s*$/, '\\');
                continue;
            }
            line = line.replace(/\\\s*$/, ' ') + lines[k];
        }
        joined.push({ index: start, line, exempt: exempted(lines, start, line) });
    }
    return joined;
}

// The marker on the line, or on any line of the comment block right above it.
function exempted(lines, start, line) {
    if (/#\s*unpinned:\s*\S/.test(line)) return true;
    for (let i = start - 1; i >= 0 && /^\s*#/.test(lines[i]); i--) {
        if (/^\s*#\s*unpinned:\s*\S/.test(lines[i])) return true;
    }
    return false;
}

// What a Dockerfile's instructions fetch besides RUN's commands: FROM's
// image, COPY's and a mount's `--from` image, ADD's remote sources.
function dockerfileLine(line, index, lines, report) {
    const instruction = line.match(/^\s*([A-Za-z]+)\s+(.*)$/);
    if (!instruction) return;
    const name = instruction[1].toUpperCase();
    const named = stages(lines);
    const image = (ref, what) => {
        if (ref === 'scratch' || /^\d+$/.test(ref) || named.has(ref.toLowerCase()) || IMAGE.test(ref)) return;
        // A stage per platform (`FROM node-${TARGETARCH}`): each platform's is a stage above.
        const each = ref.toLowerCase().replace(/\$\{?targetarch\}?/g, '\0');
        if (each.includes('\0') && ['amd64', 'arm64'].every((arch) => named.has(each.replaceAll('\0', arch)))) return;
        report(index, `${what} ${ref} is not name:tag@sha256:<index digest>`);
    };
    const words = instruction[2].trim().split(/\s+/);
    const flags = words.filter((word, i) => word.startsWith('--') && words.slice(0, i).every((w) => w.startsWith('--')));
    if (name === 'FROM') image(words.find((word) => !word.startsWith('--')) ?? '', 'FROM');
    for (const flag of flags) {
        const from = flag.match(/^--from=(.+)$/) ?? flag.match(/^--mount=(?:.*,)?from=([^,]+)/);
        if (from && ['COPY', 'ADD', 'RUN'].includes(name)) image(from[1], name === 'RUN' ? 'RUN --mount from' : `${name} --from`);
    }
    if (name !== 'ADD') return;
    let sources = words.slice(flags.length);
    if (sources[0]?.startsWith('[')) {
        try { sources = JSON.parse(instruction[2].slice(instruction[2].indexOf('['))); } catch { return report(index, 'ADD in a form this cannot read'); }
    }
    const checksum = flags.some((flag) => /^--checksum=sha256:[0-9a-f]{64}$/.test(flag));
    for (const source of sources.slice(0, -1)) {
        const git = /^git@|^git:\/\/|\.git(?:#|$)/.test(source);
        if (git && !/#[0-9a-f]{40}$/.test(source)) report(index, `ADD ${source} takes the branch as it is: name its commit (#<sha>)`);
        else if (!git && /^[a-z][a-z0-9+.-]*:\/\//i.test(source) && !checksum) report(index, `ADD ${source} without --checksum=sha256:<pinned>`);
    }
}

function stages(lines) {
    const names = new Set();
    for (const line of lines) {
        const stage = line.match(/^\s*FROM\s+.+\s+AS\s+(\S+)\s*$/i);
        if (stage) names.add(stage[1].toLowerCase());
    }
    return names;
}

const isMapping = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const isScalar = (value) => ['string', 'number', 'boolean'].includes(typeof value);
const MATRIX = /\$\{\{\s*matrix\.([\w-]+)\s*\}\}/g;

// A workflow, an action, a compose file or .cursor/environment.json, as the
// data it is: every string is what a shell runs, a list of words the command
// they make (`command: [pnpm, install]`, a healthcheck's `test:`, an action's
// `args:`), and what names an action, an image, a runner or a toolchain, in
// the place GitHub or Compose reads it, is held to its pin. A `# unpinned:
// <reason>` is the shell's own comment, in the string it covers: YAML's
// comments are no part of its data.
function data(document, kind, text, report, options) {
    const visit = (node, path, job) => {
        const where = path.map((part, i) => (typeof part === 'number' ? `[${part}]` : i === 0 ? part : `.${part}`)).join('') || '(file)';
        if (kind !== 'json') held(node, path, where, job, { kind, text, report });
        // A Dockerfile written in the compose file is read as one.
        if (kind === 'compose' && typeof node === 'string' && at(path, 'services', '*', 'build', 'dockerfile_inline')) {
            return scan(node, 'dockerfile', (index, message) => report(`${where}, line ${index + 1}`, message), options);
        }
        if (typeof node === 'string') return commands(node, where, job, report, options);
        if (Array.isArray(node)) {
            if (node.length > 1 && node.every(isScalar)) return commands(node.join(' '), where, job, report, options);
            return node.forEach((item, i) => visit(item, [...path, i], job));
        }
        if (!isMapping(node)) return;
        // Each job reads its own matrix.
        for (const [key, value] of Object.entries(node)) visit(value, [...path, key], kind === 'workflow' && path.length === 1 && path[0] === 'jobs' ? value : job);
    };
    visit(document, [], undefined);
}

// Whether a path is the place a pattern names: `*` any key, `#` any index.
function at(path, ...pattern) {
    return path.length === pattern.length && pattern.every((part, i) => {
        if (part === '*') return typeof path[i] === 'string';
        if (part === '#') return typeof path[i] === 'number';
        if (part instanceof RegExp) return typeof path[i] === 'string' && part.test(path[i]);
        return part === path[i];
    });
}

// A string checked as the lines a shell runs, once for each value a matrix
// gives what it names (`run: pnpm ${{ matrix.command }}`).
function commands(text, where, job, report, options) {
    const multiline = text.includes('\n');
    for (const each of expanded(text, job)) {
        scan(each, 'shell', (index, message) => report(multiline ? `${where}, line ${index + 1}` : where, message), options);
    }
}

function expanded(text, job) {
    let texts = [text];
    for (const key of new Set([...text.matchAll(MATRIX)].map((match) => match[1]))) {
        const values = matrixValues(job, key) ?? [];
        const pattern = new RegExp(String.raw`\$\{\{\s*matrix\.${key}\s*\}\}`, 'g');
        texts = texts.flatMap((each) => [each, ...values.map((value) => each.replace(pattern, String(value)))]);
    }
    return texts;
}

// Every value the job's matrix gives `key`: its own, and each `include:`
// entry's. null when the matrix is not written out (`${{ fromJSON(…) }}`).
function matrixValues(job, key) {
    const matrix = isMapping(job) && isMapping(job.strategy) ? job.strategy.matrix : undefined;
    if (!isMapping(matrix)) return null;
    const own = matrix[key];
    const values = own === undefined ? [] : [own].flat();
    const include = matrix.include ?? [];
    if (!Array.isArray(include) || !include.every(isMapping)) return null;
    for (const entry of include) if (key in entry) values.push(entry[key]);
    return values;
}

// What one value names, read through the job's matrix when it is one of its
// values (`${{ matrix.node }}`): each value it takes, and whether a matrix gave it.
function named(value, job, where, report) {
    const matrix = typeof value === 'string' && value.match(/^\$\{\{\s*matrix\.([\w-]+)\s*\}\}$/);
    if (!matrix) return [{ value: String(value), fromMatrix: false }];
    const values = matrixValues(job, matrix[1]) ?? [];
    if (values.length === 0) report(where, `${value}: no value this reads; write the job's matrix out, its values in it`);
    return values.map((each) => ({ value: isScalar(each) ? String(each) : JSON.stringify(each), fromMatrix: true }));
}

// What GitHub and Compose read as an image, an action, a runner or a toolchain.
function held(value, path, where, job, { kind, text, report }) {
    const step = (...rest) => at(path, 'jobs', '*', 'steps', '#', ...rest) || at(path, 'runs', 'steps', '#', ...rest);
    const image = kind === 'compose'
        ? at(path, 'services', '*', 'image')
        : at(path, 'jobs', '*', 'container') && !isMapping(value) || at(path, 'jobs', '*', 'container', 'image')
            || at(path, 'jobs', '*', 'services', '*') && !isMapping(value) || at(path, 'jobs', '*', 'services', '*', 'image')
            || at(path, 'runs', 'image') || step('with', /^image$/i);
    if (image) {
        for (const each of [value].flat()) {
            if (!isScalar(each)) { report(where, `image ${JSON.stringify(each)} is not name:tag@sha256:<index digest>`); continue; }
            for (const { value: name } of named(each, job, where, report)) {
                // A Docker action's own Dockerfile, which check:pins reads too, or a registry's image.
                if (at(path, 'runs', 'image') && (/(^|\/)Dockerfile$/.test(name) || IMAGE.test(name.replace(/^docker:\/\//, '')))) continue;
                if (!IMAGE.test(name)) report(where, `image ${name} is not name:tag@sha256:<index digest>`);
            }
        }
    }
    // What Compose builds from: a directory here, or a repository at its
    // commit (`https://github.com/o/r.git#<sha>`), or an image by its digest.
    if (kind === 'compose') {
        const build = (...rest) => at(path, 'services', '*', 'build', ...rest);
        const contexts = build() && !isMapping(value) ? [value]
            : build('context') ? [value]
            : build('additional_contexts', '*') ? [value]
            // Its list form names each `name=source`.
            : build('additional_contexts') && Array.isArray(value) ? value.map((each) => (typeof each === 'string' ? each.replace(/^[^=]*=/, '') : each))
            : [];
        for (const each of contexts) context(each, where, report);
    }
    if (kind !== 'workflow') return;
    if (at(path, 'jobs', '*', 'uses') || step('uses')) uses(value, where, text, report);
    if (at(path, 'jobs', '*', 'runs-on')) {
        const labels = isMapping(value) ? [value.group, value.labels].flat().filter((label) => label !== undefined) : [value].flat();
        for (const label of labels) {
            for (const { value: runner } of named(label, job, where, report)) {
                if (/-latest\b/.test(runner) || runner.includes('${{')) report(where, `runs-on ${runner} moves: name the image's version (ubuntu-24.04)`);
            }
        }
    }
    // A toolchain an action installs: an exact version, or a matrix of them,
    // where `runner` names the runner's own (a step that installs none).
    // GitHub reads an input's name whatever its case (`Node-Version`), and
    // pnpm/action-setup's is `version`.
    if (step('with', /^(?:[a-z0-9_]+-)?version$/i)) {
        const key = path.at(-1);
        if (!isScalar(value)) return report(where, `${key} ${JSON.stringify(value)} is not an exact version`);
        for (const { value: version, fromMatrix } of named(value, job, where, report)) {
            if (fromMatrix && version === 'runner') continue;
            if (!EXACT_VERSION.test(version)) report(where, `${key} ${version} is not an exact version`);
        }
    }
}

// A build context: a path here, another service's (`service:db`), a
// repository at its commit, or an image by its digest. Any other URL (a
// branch, a tarball) is what its server has today.
function context(value, where, report) {
    if (!isScalar(value)) return report(where, `build context ${JSON.stringify(value)} is not a path, a repository at its commit or an image by its digest`);
    const source = String(value);
    if (source.startsWith('docker-image://')) {
        if (!IMAGE.test(source.slice('docker-image://'.length))) report(where, `build context ${source} is not docker-image://name:tag@sha256:<index digest>`);
        return;
    }
    if (!/^[a-z][a-z0-9+.-]*:\/\/|^git@/i.test(source)) return;
    const git = /^git@|^git:\/\/|\.git(?:#|$)/.test(source);
    if (!git || !/#[0-9a-f]{40}(?::[^#]*)?$/.test(source)) report(where, `build context ${source} is what its server has today: name a repository's commit (#<sha>)`);
}

// An action by its commit, `owner/repo@<sha> # v<version>`, the version for
// people: a comment, which YAML drops, so read on each line that names it.
function uses(value, at, text, report) {
    if (typeof value !== 'string') return report(at, `uses ${JSON.stringify(value)} is not owner/repo@<commit SHA> # v<version>`);
    if (value.startsWith('./') || value.startsWith('$/')) return;
    if (value.startsWith('docker://')) {
        if (!IMAGE.test(value.slice('docker://'.length))) report(at, `uses ${value} is not docker://name:tag@sha256:<index digest>`);
        return;
    }
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_./-]+@[0-9a-f]{40}$/.test(value)) return report(at, `uses ${value} is not owner/repo@<commit SHA> # v<version>`);
    const escaped = value.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
    const lines = text.split('\n').filter((line) => new RegExp(String.raw`uses['"]?\s*:\s*['"]?${escaped}`).test(line));
    const commented = new RegExp(String.raw`${escaped}['"]?\s*[}\]]*\s*#\s*v\d+(?:\.\d+)*\S*\s*$`);
    if (lines.length === 0 || !lines.every((line) => commented.test(line))) report(at, `uses ${value} has no # v<version> beside it, on its line`);
}

// pnpm's supply-chain settings, in the workspace's and each example's.
function workspace(documents, text, report, root) {
    if (documents.length !== 1 || !isMapping(documents[0])) return report('(file)', 'one mapping of pnpm settings');
    const settings = documents[0];
    const age = settings.minimumReleaseAge;
    // The policy's floor is 3 days (4320); coffre waits the week it always has.
    if (!(typeof age === 'number' && age >= 10080)) report('minimumReleaseAge', `minimumReleaseAge ${JSON.stringify(age) ?? 'missing'} is under 10080 (7 days)`);
    if (settings.strictDepBuilds !== true) report('strictDepBuilds', 'strictDepBuilds is not true: an install script nobody decided on must fail the install');
    if ('dangerouslyAllowAllBuilds' in settings) report('dangerouslyAllowAllBuilds', 'dangerouslyAllowAllBuilds runs every install script');
    for (const legacy of ['onlyBuiltDependencies', 'onlyBuiltDependenciesFile', 'neverBuiltDependencies']) {
        if (legacy in settings) report(legacy, `${legacy}: allowBuilds is the one place a build is decided`);
    }
    if ('ignoreScripts' in settings && settings.ignoreScripts !== true) report('ignoreScripts', 'ignoreScripts is not true');
    if (root && settings.savePrefix !== '') report('savePrefix', "savePrefix is not ''");
    // The examples, which `coffre init` writes, let coffre's own fixes in the
    // day they are published (AGENTS.md, "Dependencies"); nothing else waits less.
    const exclude = settings.minimumReleaseAgeExclude ?? [];
    if (!Array.isArray(exclude)) report('minimumReleaseAgeExclude', 'minimumReleaseAgeExclude is not a list');
    else exclude.forEach((name, i) => {
        if (root || name !== '@coffre/*') report(`minimumReleaseAgeExclude[${i}]`, `minimumReleaseAgeExclude lets ${name} in younger than a week`);
    });
    const builds = settings.allowBuilds ?? {};
    if (!isMapping(builds)) return report('allowBuilds', 'allowBuilds is not a mapping of package to true or false');
    const lines = text.split('\n');
    for (const [name, allowed] of Object.entries(builds)) {
        if (allowed === false) continue;
        // Its reason is a comment right above its entry, which YAML drops: read on the lines.
        const escaped = name.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
        const line = lines.findIndex((each) => new RegExp(String.raw`^\s+(['"]?)${escaped}\1\s*:\s*true\s*(#.*)?$`).test(each));
        const reason = line > 0 && /^\s*#\s*\S/.test(lines[line - 1]);
        if (allowed !== true || !reason) report(`allowBuilds.${name}`, `allowBuilds ${name}: ${allowed} needs \`true\` and its reason in a comment right above, or \`false\``);
    }
}
