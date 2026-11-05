// What scripts/check-pins.mjs holds every tracked file to, besides the
// manifests: whatever CI, a Dockerfile or a script fetches is named by
// something that cannot move under it. An action by its commit, an image by
// its index digest (its tag beside it, for people), a tool by its version and
// its SHA-256, an install by the lockfile. zizmor holds the actions to their
// commits too (scripts/zizmor.sh); this needs no network and no binary.
//
// A line that cannot be pinned says why, on the line itself or in a comment
// right above it: `# unpinned: <reason>`. The reason is the review.

const DIGEST = /@sha256:[0-9a-f]{64}$/;
// `name:tag@sha256:<digest>`: the tag for people, the digest for Docker.
const IMAGE = /^[a-z0-9][a-z0-9._/-]*(?::\d+)?\/?[a-z0-9._/-]*:[A-Za-z0-9_][A-Za-z0-9._-]*@sha256:[0-9a-f]{64}$/;
const EXACT_VERSION = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/;
const SHA_USES = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_./-]+@[0-9a-f]{40} # v\d+(?:\.\d+)*\S*$/;
const LOOPBACK = /127\.0\.0\.1|localhost|\[::1\]|\$\{?COFFRE_/;

/** The kinds of file whose contents fetch or run something. */
export function kindOf(path) {
    const name = path.split('/').at(-1);
    if (/(^|\/)\.github\/(workflows|actions)\/.+\.ya?ml$/.test(path) || /^action\.ya?ml$/.test(name)) return 'workflow';
    if (/^(docker-)?compose(\.[\w-]+)*\.ya?ml$/.test(name)) return 'compose';
    if (name === 'Dockerfile' || name.endsWith('.Dockerfile') || name.startsWith('Dockerfile.')) return 'dockerfile';
    if (name.endsWith('.sh')) return 'shell';
    if (path === '.cursor/environment.json') return 'shell';
    if (name === 'pnpm-workspace.yaml') return 'workspace';
    return null;
}

/** Every problem in one file, as `path:line: what`. */
export function problemsIn(path, text, { root = false } = {}) {
    const kind = kindOf(path);
    if (kind === null) return [];
    const lines = text.split('\n');
    const problems = [];
    const report = (index, message) => problems.push(`${path}:${index + 1}: ${message}`);
    if (kind === 'workspace') {
        workspace(lines, report, root);
        return problems;
    }
    for (const { index, line, exempt } of logicalLines(lines, kind)) {
        // Comments name commands without running them; a JSON file has none.
        if (exempt || /^\s*#/.test(line)) continue;
        if (kind === 'workflow') workflowLine(line, index, lines, report);
        if (kind === 'workflow' || kind === 'compose') {
            const image = line.match(/^\s*(?:-\s+)?(?:image|container):\s*['"]?([^'"\s#]+)/);
            if (image && !image[1].startsWith('${{') && !IMAGE.test(image[1])) report(index, `image ${image[1]} is not name:tag@sha256:<index digest>`);
        }
        if (kind === 'dockerfile') {
            const from = line.match(/^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)/i);
            if (from && from[1] !== 'scratch' && !stages(lines).has(from[1].toLowerCase()) && !IMAGE.test(from[1])) {
                report(index, `FROM ${from[1]} is not name:tag@sha256:<index digest>`);
            }
        }
        commandLine(line, index, report, lines.slice(index + 1, index + 12).join('\n'));
    }
    return problems;
}

// Shell's and Dockerfiles' backslash continuations joined into one line, each
// at the index of its first, with whether a `# unpinned: <reason>` covers it.
function logicalLines(lines, kind) {
    const joined = [];
    for (let i = 0; i < lines.length; i++) {
        const start = i;
        let line = lines[i];
        while (/\\\s*$/.test(line) && i + 1 < lines.length) {
            i++;
            // A Dockerfile's comment inside a continued RUN is no part of it.
            if (kind === 'dockerfile' && /^\s*#/.test(lines[i])) {
                line = line.replace(/\\\s*$/, '\\');
                continue;
            }
            line = line.replace(/\\\s*$/, ' ') + lines[i];
        }
        const above = lines[start - 1] ?? '';
        const exempt = /#\s*unpinned:\s*\S/.test(line) || /^\s*#\s*unpinned:\s*\S/.test(above) || commentBlockExempts(lines, start);
        joined.push({ index: start, line, exempt });
    }
    return joined;
}

// A comment block of several lines right above may hold the marker on any of them.
function commentBlockExempts(lines, start) {
    for (let i = start - 1; i >= 0 && /^\s*#/.test(lines[i]); i--) {
        if (/^\s*#\s*unpinned:\s*\S/.test(lines[i])) return true;
    }
    return false;
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
        const target = uses[1].replace(/^['"]|['"]$/g, '');
        const local = target.startsWith('./') || target.startsWith('$/');
        const image = target.startsWith('docker://') && IMAGE.test(target.slice('docker://'.length));
        if (!local && !image && !SHA_USES.test(target)) report(index, `uses ${target} is not owner/repo@<commit SHA> # v<version>`);
    }
    const runner = line.match(/^\s*runs-on:\s*(.+?)\s*$/);
    if (runner && /-latest\b/.test(runner[1])) report(index, `runs-on ${runner[1]} moves: name the image's version (ubuntu-24.04)`);
    // A toolchain an action installs: an exact version, or a matrix of them.
    const version = line.match(/^\s*([a-z]+)-version:\s*['"]?(\$\{\{[^}]*\}\}|[^'"#\s]+)/);
    if (version) {
        const matrix = version[2].match(/^\$\{\{\s*matrix\.([\w-]+)\s*\}\}$/);
        const values = matrix ? matrixValues(lines, matrix[1]) : [version[2]];
        for (const value of values) {
            if (/^\d/.test(value) && !EXACT_VERSION.test(value)) report(index, `${version[1]}-version ${value} is not an exact version`);
            if (!/^\d/.test(value) && !matrix) report(index, `${version[1]}-version ${value} is not an exact version`);
        }
    }
}

// The values of a matrix key written as a flow list, `node: ['runner', '24.22.1']`.
function matrixValues(lines, key) {
    for (const line of lines) {
        const list = line.match(new RegExp(`^\\s*${key}:\\s*\\[(.*)\\]\\s*$`));
        if (list) return list[1].split(',').map((item) => item.trim().replace(/^['"]|['"]$/g, ''));
    }
    return [];
}

function commandLine(line, index, report, after) {
    // A download is written to a file and that file's SHA-256 checked before
    // anything reads it: never piped into a shell, gpg or tar.
    for (const fetch of line.matchAll(/\b(curl|wget)\b([^|;&]*)(\|?)/g)) {
        const [, tool, args, pipe] = fetch;
        if (LOOPBACK.test(args)) continue;
        const output = args.match(/(?:\s-o|\s-O|\s--output|\s--output-document)[\s=]+("[^"]+"|'[^']+'|\S+)/);
        if (pipe) {
            report(index, `${tool} pipes a download onward: write it to a file and check its SHA-256 first`);
        } else if (output) {
            const file = output[1].replace(/^["']|["']$/g, '');
            const checked = `${line}\n${after}`.split('\n').some((next) => /sha256|sha-256/i.test(next) && next.includes(file));
            if (!checked) report(index, `${tool} downloads ${file}, and nothing checks its SHA-256`);
        }
    }
    // A package runner names its package's exact version.
    for (const runner of line.matchAll(/\b(npx|pnpx|bunx|pnpm\s+dlx|yarn\s+dlx)\s+((?:-\S+\s+)*)(\S+)/g)) {
        const spec = runner[3].replace(/^["']|["']$/g, '');
        const version = spec.slice(spec.lastIndexOf('@') + 1);
        if (spec.lastIndexOf('@') <= 0 || !EXACT_VERSION.test(version)) report(index, `${runner[1]} ${spec} is not name@<exact version>`);
    }
    // An install installs what the lockfile says.
    const pnpmInstall = line.match(/\bpnpm\s+(?:--?\S+\s+(?:"[^"]*"\s+|\S+\s+)?)*(?:install|i)\b(.*)/);
    if (pnpmInstall && !/--frozen-lockfile/.test(pnpmInstall[1])) report(index, 'pnpm install without --frozen-lockfile');
    // npm, which this repository installs nothing with, only for a local tarball: what it fetches is that file.
    const npmInstall = line.match(/\bnpm\s+(?:install|i|add)\b(.*)/);
    if (npmInstall) {
        const args = npmInstall[1].split(/\s+/).filter(Boolean);
        const named = args.filter((arg, i) => !arg.startsWith('-') && args[i - 1] !== '--prefix');
        if (named.length === 0 || !named.every((arg) => /\.tgz["']?$/.test(arg))) report(index, 'npm install outside a lockfile');
    }
    const pnpmAdd = line.match(/\bpnpm\s+(?:--?\S+\s+(?:"[^"]*"\s+|\S+\s+)?)*add\b(.*)/);
    if (pnpmAdd) {
        for (const arg of pnpmAdd[1].split(/\s+/).filter((arg) => arg && !arg.startsWith('-'))) {
            const spec = arg.replace(/^["']|["']$/g, '');
            if (!EXACT_VERSION.test(spec.slice(spec.lastIndexOf('@') + 1))) report(index, `pnpm add ${spec} is not name@<exact version>`);
        }
    }
    if (/\bapt-get\s+install\b/.test(line)) report(index, "apt-get install takes the archive's current versions");
    // BuildKit in a container is an image too, and its default moves.
    if (/\bbuildx\s+create\b/.test(line) && !/image=/.test(line)) report(index, 'docker buildx create without a pinned --driver-opt image=');
    for (const option of line.matchAll(/\b(?:image|generator)=([^\s,"']+)/g)) {
        if (!IMAGE.test(option[1])) report(index, `image ${option[1]} is not name:tag@sha256:<index digest>`);
    }
    const docker = line.match(/\bdocker\s+(?:run|pull|create)\b(.*)/);
    if (docker) {
        for (const token of docker[1].split(/\s+/)) {
            if (/^[a-z][a-z0-9._/-]*:[A-Za-z0-9][A-Za-z0-9._-]*(@sha256:[0-9a-f]{64})?$/.test(token) && !DIGEST.test(token)) {
                report(index, `docker image ${token} is not name:tag@sha256:<index digest>`);
            }
        }
    }
}

// pnpm's supply-chain settings, in the workspace's and each example's.
function workspace(lines, report, root) {
    const at = (key) => lines.findIndex((line) => line.startsWith(`${key}:`));
    const value = (key) => lines[at(key)]?.slice(key.length + 1).trim();
    const age = Number(value('minimumReleaseAge'));
    // The policy's floor is 3 days (4320); coffre waits the week it always has.
    if (!(age >= 10080)) report(Math.max(at('minimumReleaseAge'), 0), `minimumReleaseAge ${value('minimumReleaseAge') ?? 'missing'} is under 10080 (7 days)`);
    if (value('strictDepBuilds') !== 'true') report(Math.max(at('strictDepBuilds'), 0), 'strictDepBuilds is not true: an install script nobody decided on must fail the install');
    if (at('dangerouslyAllowAllBuilds') >= 0) report(at('dangerouslyAllowAllBuilds'), 'dangerouslyAllowAllBuilds runs every install script');
    if (at('ignoreScripts') >= 0 && value('ignoreScripts') !== 'true') report(at('ignoreScripts'), 'ignoreScripts is not true');
    if (root && value('savePrefix') !== "''") report(Math.max(at('savePrefix'), 0), "savePrefix is not ''");
    // The examples, which `coffre init` writes, let coffre's own fixes in the
    // day they are published (AGENTS.md, "Dependencies"); nothing else waits less.
    const excluded = block(lines, 'minimumReleaseAgeExclude');
    for (const { index, line } of excluded) {
        const name = line.replace(/^\s*-\s*/, '').replace(/^['"]|['"]$/g, '');
        if (root || name !== '@coffre/*') report(index, `minimumReleaseAgeExclude lets ${name} in younger than a week`);
    }
    for (const { index, line } of block(lines, 'allowBuilds')) {
        const entry = line.match(/^\s+(['"]?[^:'"]+['"]?):\s*(\S+)/);
        if (!entry) continue;
        if (entry[2] === 'false') continue;
        const reason = /^\s*#\s*\S/.test(lines[index - 1] ?? '');
        if (entry[2] !== 'true' || !reason) report(index, `allowBuilds ${entry[1]}: ${entry[2]} needs \`true\` and its reason in a comment right above, or \`false\``);
    }
}

function block(lines, key) {
    const start = lines.findIndex((line) => line.startsWith(`${key}:`));
    if (start < 0) return [];
    const entries = [];
    for (let i = start + 1; i < lines.length && (/^\s/.test(lines[i]) || lines[i] === ''); i++) {
        if (/^\s+[^\s#]/.test(lines[i])) entries.push({ index: i, line: lines[i] });
    }
    return entries;
}
