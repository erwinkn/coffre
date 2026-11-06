// What scripts/check-pins.mjs holds every tracked workflow, action, compose
// file, Dockerfile, shell script and pnpm-workspace.yaml to, besides the
// manifests. Each rule is a plain check of what the file says:
//
//   1. An action, a job's or a step's `uses:`, is this repository's (`./…`,
//      `$/…`), `owner/repo@<40-hex commit>` or `docker://…@sha256:<digest>`.
//   2. An image ends in `@sha256:<64 hex>`: Compose's `services.<name>.image`,
//      a workflow job's `container` and `services`, a Dockerfile's `FROM`
//      (or `scratch`, or a stage an earlier `FROM … AS <name>` named).
//   3. A Dockerfile's `ADD` of a URL carries `--checksum=sha256:<64 hex>`.
//   4. Only scripts/fetch.sh downloads, checking the SHA-256 it is given:
//      `curl` and `wget` are banned everywhere else, except on a line marked
//      `# pins: local` whose every URL is 127.0.0.1, localhost or [::1].
//   5. Nothing fetches a package outside the lockfile: the commands in
//      PACKAGE_FETCHES below are banned.
//   6. A pnpm install (`pnpm … install`, or `pnpm i`) carries
//      `--frozen-lockfile`.
//   7. Nothing runs Corepack (`corepack`), which Node drops: pnpm comes from
//      pnpm/action-setup in a workflow, a checksummed tarball in a
//      Dockerfile, and switches itself to package.json's packageManager.
//   8. A step's `with: <tool>-version` is an exact version, or `${{
//      matrix.<key> }}` whose list in the job's `strategy.matrix` holds only
//      exact versions (and `runner`, the runner's own); `runs-on` names no
//      `…-latest` image.
//   9. pnpm-workspace.yaml waits 7 days (`minimumReleaseAge`), exempting
//      none (`@coffre/*` in the examples), fails on an install script nobody
//      decided on (`strictDepBuilds`), never runs them all
//      (`dangerouslyAllowAllBuilds`), and the root's saves exact versions.
//
// Rules 4 to 7 read lines: a script's or a Dockerfile's, backslash
// continuations joined, and each line of every string in a YAML or JSON
// file's data, as js-yaml reads it (and GitHub, Compose and pnpm). A list of
// words (`command: [pnpm, install]`, `RUN ["npm", "install"]`) is the line
// they make. Comment lines are skipped, and end at their line, a trailing
// backslash's too. scripts/fetch.sh is held to rules 5 to 7. Rules 5 and 6 read each command of a
// line apart, its part between `;`, `&` and `|`: the program's name, then a
// subcommand's anywhere after it, or a one- or two-letter alias (`npm i`)
// right after it. A line no rule can hold carries `# unpinned: <reason>` (in
// YAML, inside the string), on itself or in the comment block right above
// it; the reason is for review.
//
// That is all it checks. Anything else is the maintainer's, and is not
// enforced: an image a command pulls (`docker run`), a build context, an
// input or a setting not named above, a fetch through a program not named
// here or hidden from these names (`eval`, `node -e 'fetch(…)'`), and the like.

import { loadAll } from 'js-yaml';

const DIGEST = /@sha256:[0-9a-f]{64}$/;
const COMMIT = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_./-]+@[0-9a-f]{40}$/;
const EXACT_VERSION = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/;
const FETCHER = 'scripts/fetch.sh';

// A word: a program's name, or a path's last part (`/usr/bin/curl`), not
// `libcurl` or `curl-config`.
const word = (names) => String.raw`(?<![\w.-])(?:${names})(?=$|[\s'"\`)])`;
// A program, then one of its subcommands later in the same command (`pnpm
// --dir x add`); a one- or two-letter alias (`npm i`) only right after it.
const runs = (program, later, alias) => new RegExp(`${word(program)}(?:.*\\s${word(later)}${alias ? `|\\s+${word(alias)}` : ''})`);

const DOWNLOADERS = new RegExp(word('curl|wget'));
const COREPACK = new RegExp(word('corepack'));
const PACKAGE_FETCHES = [
    new RegExp(word('npx|pnpx|bunx')),
    runs('npm', 'exec|install|ci|install-test|add|update', 'i|x|it|up'),
    runs('pnpm', 'dlx|add|create|update', 'up'),
    runs('yarn', 'dlx|add|create'),
    runs('gh', 'download'),
    runs('git', 'clone'),
    runs('nvm', 'install'),
    runs('apt-get|apt', 'install'),
];
const PNPM_INSTALL = runs('pnpm', 'install', 'i');
const FROZEN = new RegExp(word('--frozen-lockfile(?:=true)?'));
const URL = /[a-z][a-z0-9+.-]*:\/\/[^\s"'`)]*/gi;
// The host itself, then at most a port: `https://localhost:443@example.com` is example.com's.
const LOOPBACK = /^https?:\/\/(?:127\.0\.0\.1|localhost|\[::1\])(?::[^/?#@\\]*)?(?:[/?#]|$)/;

/** The kinds of file this reads. */
export function kindOf(path) {
    const name = path.split('/').at(-1);
    if (/(^|\/)\.github\/(workflows|actions)\/.+\.ya?ml$/.test(path) || /^action\.ya?ml$/.test(name)) return 'workflow';
    if (/^(docker-)?compose(\.[\w-]+)*\.ya?ml$/.test(name)) return 'compose';
    if (/^(?:Dockerfile|Containerfile)(?:\..+)?$|\.(?:Dockerfile|Containerfile)$/.test(name)) return 'dockerfile';
    if (name.endsWith('.sh')) return 'shell';
    if (path === '.cursor/environment.json') return 'json';
    if (name === 'pnpm-workspace.yaml') return 'workspace';
    return null;
}

/**
 * Every problem in one file: `path:line: what` in a script or a Dockerfile,
 * `path: <where in its data>: what` in YAML or JSON.
 */
export function problemsIn(path, text, { root = false } = {}) {
    const kind = kindOf(path);
    if (kind === null) return [];
    const problems = new Set();
    if (kind === 'shell' || kind === 'dockerfile') {
        lines(text, kind, (index, message) => problems.add(`${path}:${index + 1}: ${message}`), { path });
        return [...problems];
    }
    let documents;
    try {
        documents = kind === 'json' ? [JSON.parse(text)] : loadAll(text);
    } catch (error) {
        return [`${path}: ${error.message.split('\n')[0]}`];
    }
    const report = (where, message) => problems.add(`${path}: ${where}: ${message}`);
    if (kind === 'workspace') workspace(documents, report, root);
    else for (const document of documents) data(document, kind, report, { path });
    return [...problems];
}

// Rules 3 to 7, line by line.
function lines(text, kind, report, { path }) {
    const raw = text.split('\n');
    const stages = new Set();
    for (let k = 0; k < raw.length; k++) {
        const index = k;
        // A comment ends at its line, backslash or not.
        if (/^\s*#/.test(raw[k])) continue;
        let line = raw[k];
        // In a shell, a backslash inside a comment continues nothing: `# note \` and
        // `cmd # note \` both end at their line, and a comment line ends the command.
        const continues = () => /\\\s*$/.test(line) && (kind === 'dockerfile' || !/(?:^|\s)#/.test(raw[k]));
        while (continues() && k + 1 < raw.length) {
            // Docker drops comment and blank lines inside an instruction.
            if (kind === 'dockerfile' && /^\s*(?:#.*)?$/.test(raw[k + 1])) {
                k++;
                continue;
            }
            if (/^\s*#/.test(raw[k + 1])) break;
            line = line.replace(/\\\s*$/, ' ') + raw[++k];
        }
        const skip = exempt(raw, index, line);
        if (kind === 'dockerfile') {
            // An exempt FROM still names its stage.
            dockerfile(line, stages, skip ? () => {} : (message) => report(index, message));
            // An argument list is the command its words make.
            line = line.replace(/"\s*,\s*"/g, ' ');
        }
        if (!skip) commands(line, (message) => report(index, message), { downloads: path === FETCHER });
    }
}

// `# unpinned: <reason>` on the line, or in the comment block right above it.
function exempt(raw, index, line) {
    if (/#\s*unpinned:\s*\S/.test(line)) return true;
    for (let i = index - 1; i >= 0 && /^\s*#/.test(raw[i]); i--) {
        if (/^\s*#\s*unpinned:\s*\S/.test(raw[i])) return true;
    }
    return false;
}

// Rules 2 and 3 in a Dockerfile.
function dockerfile(line, stages, report) {
    const from = line.match(/^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?/i);
    if (from) {
        const image = from[1];
        if (image !== 'scratch' && !stages.has(image.toLowerCase()) && !DIGEST.test(image)) report(`FROM ${image} is not name:tag@sha256:<index digest>`);
        if (from[2]) stages.add(from[2].toLowerCase());
    }
    const add = line.match(/^\s*ADD\s+(.*)$/i);
    if (add && add[1].includes('://') && !/(?:^|\s)--checksum=sha256:[0-9a-f]{64}(?=\s)/.test(add[1])) {
        report('ADD of a URL without --checksum=sha256:<pinned>');
    }
}

// Rules 4 to 7 on one line.
// scripts/fetch.sh may run a downloader; nothing else in it is exempt.
function commands(line, report, { downloads = false } = {}) {
    const downloader = line.match(DOWNLOADERS);
    if (downloader && !downloads && !localOnly(line)) {
        report(`${downloader[0]} downloads: use scripts/fetch.sh <url> <sha256> <file> (a Dockerfile: ADD --checksum=sha256:…), or mark a health check of this machine \`# pins: local\``);
    }
    for (const command of line.split(/[;&|]/)) {
        if (PACKAGE_FETCHES.some((pattern) => pattern.test(command))) report(`${command.trim()}: fetches a package outside the lockfile (add a dependency with pnpm run add:dep)`);
        if (PNPM_INSTALL.test(command) && !FROZEN.test(command)) report(`${command.trim()}: pnpm install without --frozen-lockfile`);
    }
    if (COREPACK.test(line)) report("corepack: Node drops it; pnpm switches itself to package.json's packageManager (in a workflow, pnpm/action-setup; in a Dockerfile, npm's tarball by its SHA-256)");
}

// `# pins: local` at the end of a line whose every URL is this machine's.
function localOnly(line) {
    const marker = /#\s*pins:\s*local\s*$/;
    if (!marker.test(line)) return false;
    const urls = line.replace(marker, '').match(URL) ?? [];
    return urls.length > 0 && urls.every((url) => LOOPBACK.test(url));
}

const isMapping = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const isScalar = (value) => ['string', 'number', 'boolean'].includes(typeof value);

// A workflow, an action, a compose file or .cursor/environment.json, as its
// data: rules 1, 2 and 8 where GitHub and Compose read an action, an image, a
// toolchain or a runner, and rules 4 to 7 on every string.
function data(document, kind, report, options) {
    const visit = (node, path, job) => {
        const where = path.map((part, i) => (typeof part === 'number' ? `[${part}]` : i === 0 ? part : `.${part}`)).join('') || '(file)';
        if (kind === 'workflow') workflow(node, path, job, (message) => report(where, message));
        if (kind === 'compose' && at(path, 'services', '*', 'image')) image(node, (message) => report(where, message));
        if (typeof node === 'string') {
            return lines(node, 'shell', (index, message) => report(node.includes('\n') ? `${where}, line ${index + 1}` : where, message), options);
        }
        if (Array.isArray(node)) {
            if (node.length > 0 && node.every(isScalar)) return lines(node.join(' '), 'shell', (_, message) => report(where, message), options);
            return node.forEach((item, i) => visit(item, [...path, i], job));
        }
        if (!isMapping(node)) return;
        for (const [key, value] of Object.entries(node)) visit(value, [...path, key], at(path, 'jobs') ? value : job);
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

function image(value, report) {
    if (typeof value !== 'string' || !DIGEST.test(value)) report(`image ${JSON.stringify(value)} is not name:tag@sha256:<index digest>`);
}

// Rules 1, 2 and 8 in a workflow or an action.
function workflow(value, path, job, report) {
    const step = (...rest) => at(path, 'jobs', '*', 'steps', '#', ...rest) || at(path, 'runs', 'steps', '#', ...rest);
    if (at(path, 'jobs', '*', 'uses') || step('uses')) {
        const pinned = typeof value === 'string' && (value.startsWith('./') || value.startsWith('$/') || COMMIT.test(value) || (value.startsWith('docker://') && DIGEST.test(value)));
        if (!pinned) report(`uses ${JSON.stringify(value)} is not owner/repo@<commit SHA>`);
    }
    if ((at(path, 'jobs', '*', 'container') || at(path, 'jobs', '*', 'services', '*')) && !isMapping(value)) image(value, report);
    if (at(path, 'jobs', '*', 'container', 'image') || at(path, 'jobs', '*', 'services', '*', 'image')) image(value, report);
    if (at(path, 'jobs', '*', 'runs-on')) {
        for (const label of [value].flat()) if (typeof label === 'string' && /-latest\b/.test(label)) report(`runs-on ${label} moves: name the image's version (ubuntu-24.04)`);
    }
    if (step('with', /-version$/i)) {
        const key = path.at(-1);
        const lookup = typeof value === 'string' && value.match(/^\$\{\{\s*matrix\.([\w-]+)\s*\}\}$/);
        if (!lookup) {
            if (!EXACT_VERSION.test(String(value))) report(`${key} ${value} is not an exact version`);
            return;
        }
        const values = job?.strategy?.matrix?.[lookup[1]];
        if (!Array.isArray(values)) return report(`${key} ${value}: the job's strategy.matrix has no list ${lookup[1]}`);
        for (const each of values) if (each !== 'runner' && !EXACT_VERSION.test(String(each))) report(`${key} ${value}: ${each} is not an exact version`);
    }
}

// Rule 9.
function workspace(documents, report, root) {
    if (documents.length !== 1 || !isMapping(documents[0])) return report('(file)', 'one mapping of pnpm settings');
    const settings = documents[0];
    const age = settings.minimumReleaseAge;
    if (!(typeof age === 'number' && age >= 10080)) report('minimumReleaseAge', `minimumReleaseAge ${JSON.stringify(age) ?? 'missing'} is under 10080 (7 days)`);
    // The examples, which `coffre init` writes, let coffre's own fixes in the
    // day they are published (AGENTS.md, "Dependencies"); nothing else waits less.
    const exclude = settings.minimumReleaseAgeExclude ?? [];
    if (!Array.isArray(exclude)) report('minimumReleaseAgeExclude', 'minimumReleaseAgeExclude is not a list');
    else exclude.forEach((name, i) => {
        if (root || name !== '@coffre/*') report(`minimumReleaseAgeExclude[${i}]`, `minimumReleaseAgeExclude lets ${name} in younger than a week`);
    });
    if (settings.strictDepBuilds !== true) report('strictDepBuilds', 'strictDepBuilds is not true: an install script nobody decided on must fail the install');
    if ('dangerouslyAllowAllBuilds' in settings) report('dangerouslyAllowAllBuilds', 'dangerouslyAllowAllBuilds runs every install script');
    if (root && settings.savePrefix !== '') report('savePrefix', "savePrefix is not ''");
}
