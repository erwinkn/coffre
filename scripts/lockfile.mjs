// The examples pin `@coffre/*` at the release's version, and pnpm-lock.yaml
// records each pin as its importer's specifier, linked to the workspace
// package. A release moves those specifiers and nothing else: `pnpm bump`
// writes this edit, and the version-only gate expects exactly it.
//
// `pins` names each moved pin as `<importer>/<section>/<name>`, e.g.
// `examples/node/devDependencies/@coffre/cli`. Throws when one of them is
// not in the lockfile at `before`, linked to a workspace package.
export function bumpLockfile(text, pins, before, after) {
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
        // Each pin stays linked to its workspace package, as it is.
        if (/^        version: link:\.\.\/\.\.\/packages\/[^/]+$/.test(line)) links.add(id);
        return line;
    }).join('\n');
    if (seen.size !== pins.size || links.size !== pins.size) throw new Error('Expected coffre lockfile specifiers are missing');
    return result;
}
