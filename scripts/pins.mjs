// What scripts/check-pins.mjs holds every tracked file to, besides the
// manifests: whatever CI, a Dockerfile or a script fetches is named by
// something that cannot move under it. An action by its commit, an image by
// its index digest (its tag beside it, for people), a tool by its version and
// its SHA-256, a clone by its commit, an install by the lockfile. zizmor holds
// the actions to their commits too (scripts/zizmor.sh); this needs no network
// and no binary.
//
// It fails closed: a fetch it cannot read as pinned is a problem, whatever
// its form. It reads the commands people write, one at a time, not those
// built to hide (`eval "$cmd"`): review covers those, and a change that means
// to get past this can edit it anyway. What it catches is drift.
//
// A line that cannot be pinned says why, on the line itself or in a comment
// right above it: `# unpinned: <reason>`. The reason is the review.

// `name:tag@sha256:<digest>`: the tag for people, the digest for Docker.
const IMAGE = /^[a-z0-9][a-z0-9._/-]*(?::\d+)?\/?[a-z0-9._/-]*:[A-Za-z0-9_][A-Za-z0-9._-]*@sha256:[0-9a-f]{64}$/;
const EXACT_VERSION = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/;
const COMMIT = /^[0-9a-f]{40}$/;
// A URL of this machine's, or the dev stack's own: what it answers is no artifact.
const LOOPBACK = /^(?:https?:\/\/)?(?:127\.0\.0\.1|localhost|\[::1\])(?:[:/]|$)|^\$\{?COFFRE_DEV_[A-Z_]*URL\}?(?:\/|$)/;

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
    const logical = kind === 'json' ? jsonLines(text, lines) : logicalLines(lines, kind);
    for (const { index, line, exempt } of logical) {
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
    }
    if (kind !== 'compose') shell(script(logical, kind), report);
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
        joined.push({ index: start, line, exempt: exempted(lines, start, line) });
    }
    return joined;
}

// The shell lines of a JSON file: each string value's, at the line it is on.
function jsonLines(text, lines) {
    const strings = [];
    const walk = (value) => {
        if (typeof value === 'string') strings.push(value);
        else if (value && typeof value === 'object') Object.values(value).forEach(walk);
    };
    walk(JSON.parse(text));
    const out = [];
    for (const value of strings) {
        const at = Math.max(lines.findIndex((line) => line.includes(JSON.stringify(value).slice(1, -1))), 0);
        for (const line of value.split('\n')) out.push({ index: at, line, exempt: /#\s*unpinned:\s*\S/.test(line) });
    }
    return out;
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

// The file's shell, in order: a workflow's `run:`s, a Dockerfile's `RUN`s, a
// script's every line.
function script(logical, kind) {
    const out = [];
    let block = null;
    for (const { index, line, exempt } of logical) {
        let text = line;
        if (kind === 'workflow') {
            // A `run:`'s own line, or a line of its block: deeper than its key.
            const run = line.match(/^(\s*(?:-\s+)?)run:\s*(.*)$/);
            const indent = line.match(/^\s*/)[0].length;
            if (run) {
                block = /^[|>][-+0-9]*\s*(#.*)?$/.test(run[2]) ? run[1].length : null;
                text = block === null ? run[2] : '';
            } else if (block !== null && (line.trim() === '' || indent > block)) {
                text = line;
            } else {
                block = null;
                continue;
            }
        }
        if (kind === 'dockerfile') {
            const run = text.match(/^\s*RUN\s+(?:--\S+\s+)*(.*)$/i);
            if (!run) continue;
            text = run[1];
        }
        for (const command of commands(text)) out.push({ ...command, index, exempt });
    }
    return out;
}

const KEYWORDS = new Set(['if', 'then', 'else', 'elif', 'fi', 'do', 'done', 'while', 'until', 'for', 'case', 'esac', '!', '{', '}', 'local', 'export', 'readonly', 'declare']);
// The commands that run the command after them, with their options that take a value.
const WRAPPERS = new Map([
    ['sudo', { value: ['-u', '--user', '-g', '--group', '-C', '--close-from', '-D', '--chdir', '-h', '--host', '-p', '--prompt', '-r', '--role', '-t', '--type', '-U', '--other-user', '-T', '--command-timeout'] }],
    ['env', { value: ['-u', '--unset', '-C', '--chdir', '-S', '--split-string'] }],
    ['timeout', { value: ['-s', '--signal', '-k', '--kill-after'], operands: 1 }],
    ['nice', { value: ['-n', '--adjustment'] }],
    ['ionice', { value: ['-c', '--class', '-n', '--classdata'] }],
    ['stdbuf', { value: ['-i', '-o', '-e'] }],
    ['xargs', { value: ['-a', '--arg-file', '-d', '--delimiter', '-E', '-I', '-L', '--max-lines', '-n', '--max-args', '-P', '--max-procs', '-s', '--max-chars'] }],
    ['nohup', {}],
    ['exec', { value: ['-a'] }],
    ['time', { value: ['-f', '--format', '-o', '--output'] }],
    ['command', {}],
]);
// What only fetches, for a command whose program this cannot read: `docker`,
// `git` or `pnpm` as a word is as often a name (a group, a service) as a run.
const FETCHES = new Set(['curl', 'wget', 'apt-get', 'npx', 'pnpx', 'bunx']);
const ASSIGNMENT = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s;

/**
 * A line of shell as its simple commands, in the order they start: each its
 * words (quotes taken off), `argv` (the words after keywords and
 * assignments), its redirects, whether it pipes into the next or takes the
 * previous one's output, and `parent`, the command whose `$(…)` it runs in.
 */
export function commands(text) {
    const out = [];
    parse(text, out, null);
    for (const command of out) {
        const words = command.words;
        let i = 0;
        for (;;) {
            while (i < words.length && (KEYWORDS.has(words[i]) || ASSIGNMENT.test(words[i]))) i++;
            const wrapper = WRAPPERS.get(words[i]);
            if (!wrapper) break;
            // `command -v curl` looks it up and runs nothing.
            if (words[i] === 'command' && /^-[vV]$/.test(words[i + 1] ?? '')) {
                i = words.length;
                break;
            }
            for (i++; i < words.length && words[i].startsWith('-') && words[i] !== '-'; i++) {
                if (words[i] === '--') {
                    i++;
                    break;
                }
                if (!words[i].includes('=') && wrapper.value?.includes(words[i])) i++;
            }
            i += wrapper.operands ?? 0;
        }
        command.argv = words.slice(i);
        if (command.argv[0] === 'corepack') command.argv = command.argv.slice(1);
    }
    return out;
}

function parse(text, out, parent) {
    const fresh = (pipeIn) => ({ words: [], redirects: [], pipeIn, pipeOut: false, parent, pending: null });
    let command = fresh(false);
    let word = null;
    const endWord = () => {
        if (word === null) return;
        if (command.pending) {
            command.redirects.push({ ...command.pending, target: word });
            command.pending = null;
        } else command.words.push(word);
        word = null;
    };
    const end = (pipe) => {
        endWord();
        if (command.words.length > 0 || command.redirects.length > 0) {
            command.pipeOut = pipe;
            delete command.pending;
            out.push(command);
        }
        command = fresh(pipe);
    };
    // `$(…)`: its commands are the current one's children; the word keeps its text.
    const substitute = (at) => {
        const close = closing(text, at + 1);
        parse(text.slice(at + 2, close), out, command);
        return close;
    };
    for (let i = 0; i < text.length; i++) {
        const c = text[i];
        if (c === '\\') {
            word = (word ?? '') + (text[i + 1] ?? '');
            i++;
        } else if (c === "'") {
            const close = text.indexOf("'", i + 1);
            const stop = close < 0 ? text.length : close;
            word = (word ?? '') + text.slice(i + 1, stop);
            i = stop;
        } else if (c === '"') {
            let j = i + 1;
            let value = '';
            while (j < text.length && text[j] !== '"') {
                if (text[j] === '\\') {
                    value += text[j + 1] ?? '';
                    j += 2;
                } else if (text[j] === '$' && text[j + 1] === '(') {
                    const close = substitute(j);
                    value += text.slice(j, close + 1);
                    j = close + 1;
                } else value += text[j++];
            }
            word = (word ?? '') + value;
            i = j;
        } else if (c === '$' && text[i + 1] === '(') {
            const close = substitute(i);
            word = (word ?? '') + text.slice(i, close + 1);
            i = close;
        } else if (c === '$' && text[i + 1] === '{') {
            const close = text.indexOf('}', i);
            const stop = close < 0 ? text.length - 1 : close;
            word = (word ?? '') + text.slice(i, stop + 1);
            i = stop;
        } else if (/\s/.test(c)) {
            endWord();
        } else if (c === '#' && word === null) {
            break;
        } else if (c === ';' || c === '(' || c === ')') {
            if (c === ';' && text[i + 1] === ';') i++;
            end(false);
        } else if (c === '|') {
            if (text[i + 1] === '|') {
                i++;
                end(false);
            } else end(true);
        } else if (c === '&' && text[i + 1] === '>') {
            endWord();
            i++;
            const append = text[i + 1] === '>';
            if (append) i++;
            command.pending = { fd: 'all', op: append ? '>>' : '>' };
        } else if (c === '&') {
            if (text[i + 1] === '&') i++;
            end(false);
        } else if (c === '>' || c === '<') {
            let fd = c === '>' ? '1' : '0';
            if (word !== null && /^\d+$/.test(word)) {
                fd = word;
                word = null;
            } else endWord();
            let op = c;
            if (/[>&|]/.test(text[i + 1] ?? '')) op += text[++i];
            command.pending = { fd, op };
        } else word = (word ?? '') + c;
    }
    end(false);
}

// The `)` that closes the `(` at `open`.
function closing(text, open) {
    let depth = 0;
    for (let j = open; j < text.length; j++) {
        const c = text[j];
        if (c === '\\') j++;
        else if (c === "'") {
            j = text.indexOf("'", j + 1);
            if (j < 0) return text.length;
        } else if (c === '"') {
            for (j++; j < text.length && text[j] !== '"'; j++) if (text[j] === '\\') j++;
        } else if (c === '(') depth++;
        else if (c === ')' && --depth === 0) return j;
    }
    return text.length;
}

// The first word after the options, skipping the values of those that take one.
function operand(args, takesValue) {
    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        if (!arg.startsWith('-') || arg === '-') return { value: arg, at: i };
        if (!arg.includes('=') && takesValue.has(arg)) i++;
    }
    return null;
}

const PNPM_VALUE = new Set(['-C', '--dir', '-F', '--filter', '--filter-prod', '--reporter', '--loglevel', '--workspace-concurrency', '--store-dir', '--config']);
const DOCKER_VALUE = new Set(['-a', '--attach', '--add-host', '--cap-add', '--cap-drop', '--cgroupns', '--cidfile', '--cpus', '-c', '--cpu-shares', '--device', '--dns', '--entrypoint', '-e', '--env', '--env-file', '--expose', '--gpus', '-h', '--hostname', '--health-cmd', '--ip', '-l', '--label', '--log-driver', '--log-opt', '-m', '--memory', '--mount', '--name', '--network', '--net', '--platform', '-p', '--publish', '--pull', '--restart', '--security-opt', '--shm-size', '--stop-signal', '--stop-timeout', '--tmpfs', '-u', '--user', '--ulimit', '-v', '--volume', '--volumes-from', '-w', '--workdir']);
const NPX_VALUE = new Set(['-c', '--call', '--cache', '--userconfig']);
const SHA256 = /^(sha256|sha256sum|shasum)$/;
// Programs that take a command's name as a word and run nothing.
const NAMES = new Set(['echo', 'printf', 'which', 'type', 'hash', 'grep', 'rg', 'test', '[', '[[', 'case', 'need', 'require']);

function shell(list, report) {
    const assigned = new Map();
    for (const command of list) {
        for (const word of command.words) {
            const assignment = word.match(ASSIGNMENT);
            if (assignment) assigned.set(assignment[1], assignment[2]);
        }
    }
    list.forEach((command, at) => {
        if (command.exempt) return;
        const [program, ...args] = command.argv;
        const say = (message) => report(command.index, message);
        // A command that runs another this cannot pick out (`retry curl …`, `sudo --weird curl`).
        const hidden = command.argv.slice(1).find((word) => FETCHES.has(word));
        if (hidden && (program === undefined || program.startsWith('-') || !NAMES.has(program)) && !FETCHES.has(program)) {
            say(`${program} runs ${hidden} in a way this cannot read: run it directly, or say why with # unpinned:`);
        }
        if (program === 'curl' || program === 'wget') download(list, at, program, args, say);
        if (program === 'git' && operand(args, new Set(['-C', '-c']))?.value === 'clone') clone(list, at, args, say);
        if (program === 'docker' && ['run', 'create', 'pull'].includes(args[0])) {
            const image = operand(args.slice(1), DOCKER_VALUE)?.value;
            const variable = image?.match(/^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$/);
            // An image a variable names: a pinned one, or compose's, which is pinned.
            const value = variable ? assigned.get(variable[1]) : image;
            const pinned = value !== undefined && (IMAGE.test(value) || (variable && /docker compose config/.test(value)));
            if (!pinned) say(`docker ${args[0]} ${image ?? 'with no image'}: not name:tag@sha256:<index digest>`);
        }
        if (program === 'pnpm') {
            const sub = operand(args, PNPM_VALUE);
            const rest = sub ? args.slice(sub.at + 1) : [];
            if (sub && ['install', 'i'].includes(sub.value) && !args.some((arg) => /^--frozen-lockfile(=true)?$/.test(arg))) say('pnpm install without --frozen-lockfile');
            if (sub?.value === 'add') {
                for (const spec of rest.filter((arg) => !arg.startsWith('-'))) {
                    if (!EXACT_VERSION.test(spec.slice(spec.lastIndexOf('@') + 1))) say(`pnpm add ${spec} is not name@<exact version>`);
                }
            }
            if (sub?.value === 'dlx') runner('pnpm dlx', rest, say);
        }
        // A package runner names its package's exact version.
        if (['npx', 'pnpx', 'bunx'].includes(program)) runner(program, args, say);
        if (program === 'yarn' && args[0] === 'dlx') runner('yarn dlx', args.slice(1), say);
        // npm, which this repository installs nothing with, only for a local tarball: what it fetches is that file.
        if (program === 'npm' && ['install', 'i', 'add'].includes(operand(args, new Set(['--prefix']))?.value)) {
            const sub = operand(args, new Set(['--prefix']));
            const rest = args.slice(sub.at + 1);
            const named = rest.filter((arg, i) => !arg.startsWith('-') && rest[i - 1] !== '--prefix');
            // A file of this machine's: no scheme (`https:`, `git+ssh:`, `file:`), no `owner/repo#ref`.
            const local = (arg) => arg.endsWith('.tgz') && !/^[A-Za-z][A-Za-z0-9+.-]*:/.test(arg) && !arg.includes('#');
            if (named.length === 0 || !named.every(local)) say('npm install outside a lockfile');
        }
        if ((program === 'apt-get' || program === 'apt') && args.includes('install')) say("apt-get install takes the archive's current versions");
    });
}

function runner(name, args, say) {
    // Each --package names what it fetches; without one, the command does.
    const specs = [];
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '-p' || args[i] === '--package') specs.push(args[++i]);
        else if (args[i].startsWith('--package=')) specs.push(args[i].slice('--package='.length));
    }
    if (specs.length === 0) specs.push(operand(args, NPX_VALUE)?.value);
    for (const spec of specs) {
        const version = spec?.slice(spec.lastIndexOf('@') + 1);
        if (!spec || spec.lastIndexOf('@') <= 0 || !EXACT_VERSION.test(version)) say(`${name} ${spec ?? ''} is not name@<exact version>`);
    }
}

// A download is written to a file, and the first command that names the file
// after it checks its SHA-256 against a pinned one: never piped onward, kept
// as a value, or read before.
function download(list, at, program, args, say) {
    const command = list[at];
    // The URLs, and the variables that may hold one; a health check of this machine's fetches no artifact.
    const urls = args.filter((arg) => /^[a-z][a-z0-9+.-]*:\/\//i.test(arg) || /^(localhost|127\.0\.0\.1|\[::1\])/.test(arg) || arg.startsWith('$'));
    if (urls.length > 0 && urls.every((url) => LOOPBACK.test(url))) return;
    let file = null;
    let named = false;
    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        const long = arg.match(/^--(output|output-document)(?:=(.*))?$/);
        if (long && (program === 'curl') === (long[1] === 'output')) {
            file = long[2] ?? args[++i];
            continue;
        }
        if (/^--remote-name/.test(arg)) named = true;
        // A cluster of short options, the output's last (`-fsSLo f`, `-qO f`) or attached (`-ofile`).
        const flag = program === 'curl' ? 'o' : 'O';
        if (!/^-[^-]/.test(arg)) continue;
        const cluster = arg.slice(1);
        const where = cluster.indexOf(flag);
        if (program === 'curl' && /O/.test(cluster) && where < 0) named = true;
        if (where < 0) continue;
        file = where === cluster.length - 1 ? args[++i] : cluster.slice(where + 1);
    }
    const stdout = command.redirects.find((r) => (r.fd === '1' || r.fd === 'all') && r.op.startsWith('>') && r.op !== '>&');
    if ((file === null || file === '-') && stdout) file = stdout.target;
    if (file === '/dev/null') return;
    if (file === null || file === '-') {
        if (command.pipeOut) return say(`${program} pipes a download onward: write it to a file and check its SHA-256 first`);
        if (command.parent) return say(`${program} keeps a download as a value: write it to a file and check its SHA-256 first`);
        if (named || program === 'wget') return say(`${program} writes a download to a name it picks: name the file (${program === 'curl' ? '-o' : '-O'}) and check its SHA-256`);
        return say(`${program} writes a download to stdout: name the file (-o) and check its SHA-256`);
    }
    const next = list.findIndex((other, i) => i > at && other.words.some((word) => word.includes(file)));
    if (next < 0 || !verifies(list, next)) say(`${program} downloads ${file}, and the first thing that reads it after does not check its SHA-256`);
}

// `echo "<sha256>  <file>" | sha256sum -c`, or `[ "$(sha256 <file>)" = "$pinned" ]`,
// directly or through a variable it is kept in.
function verifies(list, at) {
    const command = list[at];
    if (['echo', 'printf'].includes(command.argv[0]) && command.pipeOut) {
        const check = list[at + 1];
        const pinned = command.words.some((word) => /[0-9a-f]{64}|\$/.test(word));
        return pinned && check?.pipeIn && SHA256.test(check.argv[0] ?? '') && check.argv.some((arg) => ['-c', '--check'].includes(arg));
    }
    if (!SHA256.test(command.argv[0] ?? '') || !command.parent) return false;
    const compares = (test) => ['[', '[[', 'test'].includes(test.argv[0]) && test.argv.some((arg) => ['=', '==', '!='].includes(arg));
    if (compares(command.parent)) return true;
    const kept = command.parent.argv.length === 0 && command.parent.words.map((word) => word.match(ASSIGNMENT)).find(Boolean);
    if (!kept) return false;
    const variable = new RegExp(`\\$\\{?${kept[1]}\\b`);
    return list.some((test, i) => i > at && compares(test) && test.words.some((word) => variable.test(word)));
}

// A clone names its commit: `--revision=<sha>`, or the next git command checks it out.
function clone(list, at, args, say) {
    const revision = args.findIndex((arg) => arg === '--revision' || arg.startsWith('--revision='));
    if (revision >= 0 && COMMIT.test(args[revision].startsWith('--revision=') ? args[revision].slice('--revision='.length) : args[revision + 1] ?? '')) return;
    const next = list.find((other, i) => i > at && other.argv[0] === 'git');
    const checksOut = next && ['checkout', 'switch', 'reset'].includes(operand(next.argv.slice(1), new Set(['-C', '-c']))?.value) && next.argv.some((arg) => COMMIT.test(arg));
    if (!checksOut) say('git clone takes the branch as it is: check out a commit (git -C <dir> checkout <sha>) right after');
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
