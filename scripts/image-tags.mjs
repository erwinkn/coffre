// The tags a release's CLI image gets (.github/workflows/release.yml): its
// version always; `<major>.<minor>` while it is the newest release of that
// line, and `latest` while it is the newest of all, as npm's versions say,
// so an image published late, for an older release, moves neither back. A
// pre-release gets its version alone.
//
//   node scripts/image-tags.mjs <version>
// prints each tag on a line of its own.
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const release = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const prerelease = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)-[0-9A-Za-z.-]+$/;

/** `version`'s tags, given every version npm has of the package, `version` among them. */
export function imageTags(version, published) {
    if (!published.includes(version)) throw new Error(`${version} is not on npm`);
    if (prerelease.test(version)) return [version];
    const parts = (text) => release.exec(text)?.slice(1, 4).map(Number);
    const own = parts(version);
    if (!own) throw new Error(`${version} is no version`);
    const newer = (other) => {
        const theirs = parts(other);
        if (!theirs) return false;
        const at = theirs.findIndex((part, i) => part !== own[i]);
        return at !== -1 && theirs[at] > own[at];
    };
    const releases = published.filter((other) => release.test(other));
    const tags = [version];
    const line = `${own[0]}.${own[1]}`;
    if (!releases.some((other) => other.startsWith(`${line}.`) && newer(other))) tags.push(line);
    if (!releases.some(newer)) tags.push('latest');
    return tags;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const version = process.argv[2];
    const published = JSON.parse(execFileSync('npm', ['view', '@coffre/cli', 'versions', '--json'], { encoding: 'utf8' }));
    console.log(imageTags(version, [published].flat()).join('\n'));
}
