// The release notes gather what is not yet released under `## Unreleased`.
// A release heads them with its version and day, under a new, empty
// `## Unreleased`: `pnpm bump` makes this edit, and the version-only gate
// accepts it, and no other edit of the notes.
const unreleased = '## Unreleased';

// Unchanged when the notes have no `## Unreleased` heading.
export function headChangelog(text, version, date) {
    const lines = text.split('\n');
    const at = lines.indexOf(unreleased);
    if (at !== -1) lines.splice(at, 1, unreleased, '', `## ${version} (${date})`);
    return lines.join('\n');
}

// The day the notes give `version`, when they head it as a release does: a
// real date, as YYYY-MM-DD.
export function releaseDate(text, version) {
    const lines = text.split('\n');
    const at = lines.indexOf(unreleased);
    if (at === -1 || lines[at + 1] !== '') return undefined;
    const heading = `## ${version} (`;
    const line = lines[at + 2] ?? '';
    const date = line.slice(heading.length, -1);
    if (!line.startsWith(heading) || !line.endsWith(')') || !/^\d{4}-\d{2}-\d{2}$/.test(date)) return undefined;
    const day = new Date(`${date}T00:00:00Z`);
    return !Number.isNaN(day.getTime()) && day.toISOString().startsWith(date) ? date : undefined;
}
