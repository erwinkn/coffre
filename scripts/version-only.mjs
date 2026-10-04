// The fast Validate path accepts only the exact edits a synchronized release
// makes. Every other change, including a parse error, gets the full suite.
import { execFileSync } from 'node:child_process';
import { appendFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { actionPin, bumpAction } from './action-pin.mjs';

const versionPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const validVersion = (value) => typeof value === 'string' && versionPattern.test(value)
    && (!value.includes('-') || value.slice(value.indexOf('-') + 1).split('.').every((id) => !/^\d+$/.test(id) || /^(0|[1-9]\d*)$/.test(id)));
const sections = ['dependencies', 'devDependencies'];
const canonical = (value) => `${JSON.stringify(value, null, 2)}\n`;

function bumpLockfile(text, pins, before, after) {
    let top, importer, section, dependency;
    const seen = new Set();
    const links = new Set();
    const key = (value) => value.replace(/^['"]|['"]$/g, '');
    const result = text.split('\n').map((line) => {
        const match = /^( *)([^ ].*):$/.exec(line);
        if (match) {
            switch (match[1].length) {
                case 0: top = match[2]; importer = section = dependency = undefined; break;
                case 2: importer = key(match[2]); section = dependency = undefined; break;
                case 4: section = key(match[2]); dependency = undefined; break;
                case 6: dependency = key(match[2]); break;
            }
        }
        const id = `${importer}/${section}/${dependency}`;
        if (top !== 'importers' || !pins.has(id)) return line;
        if (line === `        specifier: ${before}`) {
            seen.add(id);
            return `        specifier: ${after}`;
        }
        // A registry resolution would also need new package/snapshot entries.
        // Accept the workspace links bump currently writes, left unchanged.
        if (/^        version: link:\.\.\/\.\.\/packages\/[^/]+$/.test(line)) links.add(id);
        return line;
    }).join('\n');
    if (seen.size !== pins.size || links.size !== pins.size) throw new Error('Expected coffre lockfile specifiers are missing');
    return result;
}

export function versionOnly(base, head = 'HEAD', cwd = process.cwd()) {
    const full = (reason) => ({ versionOnly: false, reason });
    try {
        const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
        const git = (...args) => decoder.decode(execFileSync('git', args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] }));
        const commit = (ref) => git('rev-parse', '--verify', '--end-of-options', `${ref}^{commit}`).trim();
        base = commit(base);
        head = commit(head);
        const read = (sha, path) => git('show', `${sha}:${path}`);
        const paths = git('ls-tree', '-rz', '--name-only', base).split('\0').filter(Boolean);
        const packages = paths.filter((path) => /^packages\/[^/]+\/package\.json$/.test(path));
        const examples = paths.filter((path) => /^examples\/[^/]+\/package\.json$/.test(path));
        const before = JSON.parse(read(base, 'packages/cli/package.json')).version;
        const after = JSON.parse(read(head, 'packages/cli/package.json')).version;
        if (!validVersion(before) || !validVersion(after) || before === after) {
            return full('No new release version');
        }
        const expected = new Map();
        const pins = new Set();
        for (const path of [...packages, ...examples]) {
            const text = read(base, path);
            const pkg = JSON.parse(text);
            if (text !== canonical(pkg)) return full('Manifest formatting needs full validation');
            if (packages.includes(path)) {
                if (!pkg.name?.startsWith('@coffre/') || pkg.version !== before) return full('Package versions disagree');
                pkg.version = after;
            } else {
                for (const section of sections) {
                    for (const [name, pin] of Object.entries(pkg[section] ?? {})) {
                        if (!name.startsWith('@coffre/')) continue;
                        if (pin !== before) return full('Example pins disagree');
                        pkg[section][name] = after;
                        pins.add(`${path.slice(0, -'/package.json'.length)}/${section}/${name}`);
                    }
                }
            }
            expected.set(path, canonical(pkg));
        }
        expected.set('pnpm-lock.yaml', bumpLockfile(read(base, 'pnpm-lock.yaml'), pins, before, after));
        if (paths.includes('action/action.yml')) {
            const action = read(base, 'action/action.yml');
            if (actionPin(action) !== before) return full('Action pin disagrees');
            expected.set('action/action.yml', bumpAction(action, after));
        }

        // Raw metadata includes permissions, symlinks, additions and deletions.
        // Disable renames and diff helpers: inspect the actual Git objects.
        const diff = git('diff', '--raw', '-z', '--no-renames', '--no-ext-diff', '--no-textconv', base, head).split('\0');
        let changed = 0;
        for (let i = 0; i < diff.length - 1; i += 2) {
            const metadata = /^:([0-7]{6}) ([0-7]{6}) [0-9a-f]+ [0-9a-f]+ M$/.exec(diff[i]);
            const path = diff[i + 1];
            if (!metadata || metadata[1] !== '100644' || metadata[2] !== '100644' || !expected.has(path)) {
                return full('Change outside release versions');
            }
            changed++;
        }
        if (!changed) return full('Empty diff');
        // Check all manifests and pins, including omitted files: a partial
        // bump must not skip check:pins or the frozen-lockfile install.
        for (const [path, text] of expected) {
            if (read(head, path) !== text) return full(`Change beyond the expected version bump in ${path}`);
        }
        return { versionOnly: true, version: after, reason: 'Only synchronized release versions changed' };
    } catch {
        return full('Unable to prove a version-only diff');
    }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const result = versionOnly(process.argv[2], process.argv[3]);
    console.log(JSON.stringify(result));
    if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `version_only=${result.versionOnly}\n`);
}
