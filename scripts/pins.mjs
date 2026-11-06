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
//
// Two markers, each on the line it covers:
//   `# pins: local`        curl or wget of this machine (127.0.0.1, localhost
//                          or [::1]) and nothing else: a health check.
//   `# unpinned: <reason>` anything that cannot be pinned, on the line or in
//                          the comment block right above it. The reason is
//                          the review.

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
 * Every problem in one file, as `path:line: what`. `pnpm` is the workspace's
 * packageManager version, the one pnpm Corepack may fetch.
 */
export function problemsIn(path, text, { root = false, pnpm } = {}) {
    const kind = kindOf(path);
    if (kind === null) return [];
    const lines = text.split('\n');
    const problems = [];
    const report = (index, message) => problems.push(`${path}:${index + 1}: ${message}`);
    if (kind === 'workspace') {
        workspace(lines, report, root);
        return problems;
    }
    for (const { index, line, exempt } of logicalLines(lines, kind, report)) {
        if (exempt) continue;
        // A Dockerfile's frontend is an image BuildKit pulls.
        const syntax = kind === 'dockerfile' && line.match(/^#\s*syntax\s*=\s*(\S+)/i);
        if (syntax && !IMAGE.test(syntax[1])) report(index, `syntax ${syntax[1]} is not name:tag@sha256:<index digest>`);
        // Comments name commands without running them.
        if (/^\s*#/.test(line)) continue;
        if (kind === 'workflow') workflowLine(line, index, lines, report);
        if (kind === 'workflow' || kind === 'compose') {
            const image = line.match(/^\s*(?:-\s+)?(?:image|container):\s*(.*?)\s*(?:#.*)?$/)?.[1].replace(/^(['"])(.*)\1$/, '$2');
            // A mapping's (`container:` above its `image:`) is on the lines below;
            // a matrix's `image:` is a value, held where it is used.
            if (image && !inMatrix(lines, index)) {
                const matrix = image.match(/^\$\{\{\s*matrix\.([\w-]+)\s*\}\}$/);
                const values = matrix ? matrixValues(lines, index, matrix[1]) : [image];
                if (values.length === 0) report(index, `image ${image}: no value this reads; name the image, or list it under the job's matrix`);
                for (const value of values) if (!IMAGE.test(value)) report(index, `image ${value} is not name:tag@sha256:<index digest>`);
            }
        }
        if (kind === 'dockerfile') dockerfileLine(line, index, lines, report);
        // BuildKit in a container is an image too, and its default moves.
        if (/\bbuildx\s+create\b/.test(line) && !/image=/.test(line)) report(index, 'docker buildx create without a pinned --driver-opt image=');
        for (const option of line.matchAll(/\b(?:image|generator)=([^\s,"']+)/g)) {
            if (!IMAGE.test(option[1])) report(index, `image ${option[1]} is not name:tag@sha256:<index digest>`);
        }
        if (path !== FETCHER) fetches(line, index, report, pnpm);
    }
    return problems;
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
// A YAML file's lines are checked for the forms this reads first (`yamlLines`).
function logicalLines(lines, kind, report) {
    if (kind === 'workflow' || kind === 'compose') yamlLines(lines, report);
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

// The YAML this reads line by line, where each line is what YAML reads: block
// mappings and lists, each value on its key's line, and `|` blocks, whose
// lines are the shell's own (and a `description`'s `>`, prose). Every other
// form YAML has is a problem here, never a value this misreads: a `>` block
// that is not a description's, or a value continued below its key
// (YAML folds them into lines this would have to rebuild), an indentation
// indicator (`|2`), a flow mapping (`with: {node-version: '24'}`) but a
// matrix's, which `matrixValues` reads.
function yamlLines(lines, report) {
    const indent = (line) => line.match(/^\s*/)[0].length;
    const content = (line) => line.trim() !== '' && !/^\s*#/.test(line);
    // A key (`- run:`, `"on":`) or a sequence entry's dash, then the value.
    // A flow collection (`{`, `[`) is a value, never the start of a key.
    const NODE = /^(\s*)((?:-(?:\s+|$))*)(?:((?:"[^"]*"|'[^']*'|[^\s#'"{[-][^:#]*?|-[^\s:#][^:#]*?)):(?=\s|$))?\s*(.*)$/;
    for (let i = 0; i < lines.length; i++) {
        if (!content(lines[i])) continue;
        const [, space, dashes, key, rest] = lines[i].match(NODE);
        if (key === undefined && dashes === '') {
            report(i, 'a YAML value continued below its key: write it on one line, or as a `|` block');
            continue;
        }
        // A key's value is past its column; an entry's, past its dash.
        const column = space.length + (key === undefined ? 0 : dashes.length);
        let end = i;
        while (end + 1 < lines.length && (!content(lines[end + 1]) || indent(lines[end + 1]) > column)) end++;
        while (end > i && lines[end].trim() === '') end--;
        const value = rest.replace(/(^|\s)#.*$/, '').trim().replace(/^(?:[&!]\S*(?:\s+|$))*/, '');
        const block = /^[|>][0-9+-]*$/.test(value);
        if (block) {
            // A `>` block folds its lines, which only prose may: a description runs nothing.
            const prose = key === 'description' && /^>[+-]?$/.test(value);
            if (!prose && !/^\|[+-]?$/.test(value)) report(i, `a YAML ${value} block: write it as \`|\`, \`|-\` or \`|+\`, its lines as the shell reads them`);
            i = end;
            continue;
        }
        if (/^[[{]/.test(value) && /(?<!\$)\{/.test(value) && !inMatrix(lines, i)) {
            report(i, 'a YAML flow mapping: write it as a block, one key a line');
        }
        if (value === '') continue;
        // A value on the key's line: what is past its column continues it.
        const below = lines.slice(i + 1, end + 1).findIndex(content);
        if (below >= 0) report(i + 1 + below, 'a YAML value continued below its key: write it on one line, or as a `|` block');
    }
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

function workflowLine(line, index, lines, report) {
    const uses = line.match(/^\s*(?:-\s+)?uses:\s*(.+?)\s*$/);
    if (uses) {
        // The scalar, quoted or not, then its comment.
        const [, , quoted, plain, comment = ''] = uses[1].match(/^(?:(['"])(.*?)\1|([^\s#]+))\s*(#.*)?$/) ?? [];
        const target = quoted ?? plain ?? uses[1];
        const local = target.startsWith('./') || target.startsWith('$/');
        const image = target.startsWith('docker://') && IMAGE.test(target.slice('docker://'.length));
        const pinned = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_./-]+@[0-9a-f]{40}$/.test(target) && /^# v\d+(?:\.\d+)*\S*$/.test(comment);
        if (!local && !image && !pinned) report(index, `uses ${target} is not owner/repo@<commit SHA> # v<version>`);
    }
    const runner = line.match(/^\s*runs-on:\s*(.+?)\s*$/);
    if (runner && /-latest\b/.test(runner[1])) report(index, `runs-on ${runner[1]} moves: name the image's version (ubuntu-24.04)`);
    // A toolchain an action installs: an exact version, or a matrix of them,
    // where `runner` names the runner's own (a step that installs none).
    const version = line.match(/^\s*([a-z]+)-version:\s*['"]?(\$\{\{[^}]*\}\}|[^'"#\s]+)/);
    if (version) {
        const matrix = version[2].match(/^\$\{\{\s*matrix\.([\w-]+)\s*\}\}$/);
        const values = matrix ? matrixValues(lines, index, matrix[1]) : [version[2]];
        if (values.length === 0) report(index, `${version[1]}-version matrix.${matrix[1]} has no values this reads: write them as a list under matrix`);
        for (const value of values) {
            if (matrix && value === 'runner') continue;
            if (!EXACT_VERSION.test(value)) report(index, `${version[1]}-version ${value} is not an exact version`);
        }
    }
}

// Whether the line is in a `matrix:`, one of the keys it sits under.
function inMatrix(lines, index) {
    let indent = lines[index].match(/^\s*/)[0].length;
    for (let i = index - 1; i >= 0 && indent > 0; i--) {
        if (lines[i].trim() === '' || /^\s*#/.test(lines[i])) continue;
        const own = lines[i].match(/^\s*/)[0].length;
        if (own >= indent) continue;
        if (/^\s*matrix:\s*(#.*)?$/.test(lines[i])) return true;
        indent = own;
    }
    return false;
}

// Every value the matrix key takes in the job of the line that uses it: its
// list, flow (`node: ['runner', '24.22.1']`) or one per line, and every
// `include:` entry's, block or flow. None, when the matrix is not written out
// (`matrix: ${{ fromJSON(…) }}`): then the caller reports it.
function matrixValues(lines, index, key) {
    const unquote = (value) => value.trim().replace(/^(['"])(.*)\1$/, '$2');
    const indent = (line) => line.match(/^\s*/)[0].length;
    const content = (line) => line.trim() !== '' && !/^\s*#/.test(line);
    // The job: from its key, the nearest line above at the jobs' indent, to the next.
    const jobs = lines.findIndex((line) => /^jobs:\s*(#.*)?$/.test(line));
    if (jobs < 0 || index < jobs) return [];
    const level = indent(lines.slice(jobs + 1).find(content) ?? '');
    let start = index;
    while (start > jobs && !(content(lines[start]) && indent(lines[start]) === level)) start--;
    let end = start + 1;
    while (end < lines.length && !(content(lines[end]) && indent(lines[end]) <= level)) end++;
    const matrix = lines.slice(start, end).findIndex((line) => /^\s*matrix:\s*(#.*)?$/.test(line)) + start;
    if (matrix < start) return [];
    const values = [];
    const entry = new RegExp(`^(\\s*(?:-\\s+)?)${key}:\\s*(.*?)\\s*(#.*)?$`);
    const inFlow = new RegExp(`[{,]\\s*${key}:\\s*([^,}]+)`, 'g');
    for (let i = matrix + 1; i < end && (!content(lines[i]) || indent(lines[i]) > indent(lines[matrix])); i++) {
        for (const flow of lines[i].matchAll(inFlow)) values.push(unquote(flow[1]));
        const own = lines[i].match(entry);
        if (!own) continue;
        const list = own[2].match(/^\[(.*)\]$/);
        if (list) values.push(...list[1].split(',').map(unquote).filter(Boolean));
        else if (own[2] !== '') values.push(unquote(own[2]));
        else {
            for (let j = i + 1; j < end && (!content(lines[j]) || indent(lines[j]) > own[1].length); j++) {
                const item = lines[j].match(/^\s*-\s+(.*?)\s*(#.*)?$/);
                if (item) values.push(unquote(item[1]));
                else if (content(lines[j])) values.push(lines[j].trim());
            }
        }
    }
    return values;
}

// pnpm's supply-chain settings, in the workspace's and each example's. This
// reads block style, the form pnpm writes; a setting written another way is a
// problem, never a setting this skips.
function workspace(lines, report, root) {
    const keys = new Map();
    lines.forEach((line, index) => {
        const key = line.match(/^(['"]?)([A-Za-z][\w-]*)\1:(.*)$/);
        if (!key) return;
        if (keys.has(key[2])) report(index, `${key[2]} is set twice: pnpm reads the last`);
        keys.set(key[2], { index, value: key[3].replace(/\s+#.*$/, '').trim() });
    });
    const at = (key) => keys.get(key)?.index ?? -1;
    const value = (key) => keys.get(key)?.value;
    const age = Number(value('minimumReleaseAge'));
    // The policy's floor is 3 days (4320); coffre waits the week it always has.
    if (!(age >= 10080)) report(Math.max(at('minimumReleaseAge'), 0), `minimumReleaseAge ${value('minimumReleaseAge') ?? 'missing'} is under 10080 (7 days)`);
    if (value('strictDepBuilds') !== 'true') report(Math.max(at('strictDepBuilds'), 0), 'strictDepBuilds is not true: an install script nobody decided on must fail the install');
    if (at('dangerouslyAllowAllBuilds') >= 0) report(at('dangerouslyAllowAllBuilds'), 'dangerouslyAllowAllBuilds runs every install script');
    for (const legacy of ['onlyBuiltDependencies', 'onlyBuiltDependenciesFile', 'neverBuiltDependencies']) {
        if (at(legacy) >= 0) report(at(legacy), `${legacy}: allowBuilds is the one place a build is decided`);
    }
    if (at('ignoreScripts') >= 0 && value('ignoreScripts') !== 'true') report(at('ignoreScripts'), 'ignoreScripts is not true');
    if (root && value('savePrefix') !== "''") report(Math.max(at('savePrefix'), 0), "savePrefix is not ''");
    for (const key of ['minimumReleaseAgeExclude', 'allowBuilds']) {
        if (value(key)) report(at(key), `${key}: ${value(key)}: write it as a block, one entry a line`);
    }
    // The examples, which `coffre init` writes, let coffre's own fixes in the
    // day they are published (AGENTS.md, "Dependencies"); nothing else waits less.
    for (const { index, line } of block(lines, at('minimumReleaseAgeExclude'))) {
        const name = line.match(/^\s*-\s+(['"]?)([^'"\s#]+)\1\s*(#.*)?$/)?.[2];
        if (root || name !== '@coffre/*') report(index, `minimumReleaseAgeExclude lets ${name ?? line.trim()} in younger than a week`);
    }
    for (const { index, line } of block(lines, at('allowBuilds'))) {
        const entry = line.match(/^\s+(['"]?)([^:'"\s]+)\1:\s*([^\s#]*)\s*(#.*)?$/);
        if (entry?.[3] === 'false') continue;
        const reason = /^\s*#\s*\S/.test(lines[index - 1] ?? '');
        if (entry?.[3] !== 'true' || !reason) report(index, `allowBuilds ${entry ? `${entry[2]}: ${entry[3]}` : line.trim()} needs \`true\` and its reason in a comment right above, or \`false\``);
    }
}

function block(lines, start) {
    if (start < 0) return [];
    const entries = [];
    for (let i = start + 1; i < lines.length && (/^\s/.test(lines[i]) || lines[i] === ''); i++) {
        if (/^\s+[^\s#]/.test(lines[i])) entries.push({ index: i, line: lines[i] });
    }
    return entries;
}
