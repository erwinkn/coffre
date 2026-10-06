// coffre's route files in a deployment: what `coffre update` adds and
// removes of them, file by file, to show and then to make. A deployment
// gains each page a later release adds, and loses each it retires, but only
// a file exactly as coffre wrote it; one the deployment changed is its own.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

/** One file of a deployment: its text before, and after; null where there is none. */
export type FileChange = { path: string; was: string | null; becomes: string | null };

/** The move: the changes, in order; or why it makes none. */
export type Move = { changes: FileChange[] } | { problems: string[] };

/** A file's Git blob hash, with the line endings Git keeps: what names a file a release wrote. */
export function blob(text: string): string {
  const bytes = Buffer.from(text.replace(/\r\n/g, '\n'), 'utf8');
  return createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
}

/**
 * The first release `coffre update` moves a deployment from: 0.4.0 was a
 * clean break, and a deployment of an earlier one is deployed fresh
 * (docs/deploy.md).
 */
export const CLEAN_BREAK = '0.4.0';

/**
 * Each of coffre's route files, by the release that first wrote it. A
 * deployment moving past that release gains the file: a page coffre adds is
 * a file the deployment adds. One from a release it had already reached is
 * one it left out, and stays out. A test holds this to the template.
 */
export const ROUTE_FILES: Record<string, string> = Object.fromEntries(
  [
    '__root.tsx',
    'api.$.ts',
    'auth.$.ts',
    'livez.ts',
    'readyz.ts',
    'mcp.ts',
    '[.]well-known.$.ts',
    '_coffre.tsx',
    '_coffre/index.tsx',
    '_coffre/projects.index.tsx',
    '_coffre/projects.$project.tsx',
    '_coffre/projects.$project.index.tsx',
    '_coffre/projects.$project.users.tsx',
    '_coffre/projects.$project.service-accounts.tsx',
    '_coffre/projects.$project.settings.tsx',
    '_coffre/projects.$project_.$environment.tsx',
    '_coffre/audit.tsx',
    '_coffre/users.index.tsx',
    '_coffre/users.$user.tsx',
    '_coffre/users.$user.index.tsx',
    '_coffre/users.$user.activity.tsx',
    '_coffre/service-accounts.index.tsx',
    '_coffre/service-accounts.$account.tsx',
    '_coffre/service-accounts.$account.index.tsx',
    '_coffre/service-accounts.$account.access.tsx',
    '_coffre/service-accounts.$account.activity.tsx',
    '_coffre/settings.tsx',
    '_coffre/account.tsx',
    '_solo.tsx',
    '_solo/login.tsx',
    '_solo/unregistered.tsx',
    '_solo/auth.device.tsx',
    '_solo/oauth.authorize.tsx',
    '_solo/approvals.$approval.tsx',
  ].map((file) => [`app/src/routes/${file}`, CLEAN_BREAK]),
);

/**
 * The route files coffre wrote and no longer does, a page removed or
 * renamed: by the release that retired each, and the blobs of what releases
 * before it wrote there.
 */
export const RETIRED_ROUTE_FILES: Record<string, { since: string; blobs: readonly string[] }> = {
  // `/access`, which only sent old links on to `/users`.
  'app/src/routes/_coffre/access.tsx': { since: '0.4.1', blobs: ['d75015bd1e9553986e46bff01b729bd2b29a3a8d'] },
};

/**
 * Whether release `a` comes after release `b`, as semver orders them: by
 * major, minor and patch, then a prerelease before its release
 * (`0.2.1-beta.1` before `0.2.1`), prereleases by their parts.
 */
export function after(a: string, b: string): boolean {
  const parse = (version: string) => {
    const [core = '', pre] = version.split(/-(.*)/s);
    return { core: core.split('.').map((part) => Number.parseInt(part, 10) || 0), pre: pre === undefined ? null : pre.split('.') };
  };
  const [x, y] = [parse(a), parse(b)];
  for (let i = 0; i < 3; i++) if ((x.core[i] ?? 0) !== (y.core[i] ?? 0)) return (x.core[i] ?? 0) > (y.core[i] ?? 0);
  if (x.pre === null || y.pre === null) return x.pre === null && y.pre !== null;
  for (let i = 0; i < Math.max(x.pre.length, y.pre.length); i++) {
    const [p, q] = [x.pre[i], y.pre[i]];
    if (p === q) continue;
    if (p === undefined || q === undefined) return q === undefined;
    const [m, n] = [Number(p), Number(q)];
    if (!Number.isNaN(m) && !Number.isNaN(n)) return m > n;
    if (!Number.isNaN(m) || !Number.isNaN(n)) return Number.isNaN(m);
    return p > q;
  }
  return false;
}

/** coffre's layouts as file routes, under which a deployment mounts its pages. */
const LAYOUT_FILES = ['app/src/routes/_coffre.tsx', 'app/src/routes/_solo.tsx'];

/**
 * The page files a deployment at release `from` gains and loses moving to
 * the template's: those added since `from`, where it has none; and those
 * retired since, where it has exactly what coffre wrote. One retired that it
 * changed is its own: refused, with what to do. So is a deployment without
 * coffre's layouts as file routes, the only way coffre mounts.
 */
export function pageMove(
  dir: string,
  template: string,
  from: string,
  files: { added: Record<string, string>; retired: Record<string, { since: string; blobs: readonly string[] }> } = { added: ROUTE_FILES, retired: RETIRED_ROUTE_FILES },
): Move {
  if (LAYOUT_FILES.every((path) => read(dir, path) === null)) {
    return {
      problems: [
        `${LAYOUT_FILES.join(' and ')}, coffre's layouts as file routes, are both missing: coffre mounts as Start's file routes, as coffre init writes them (docs/deploy.md, "Your own routes")`,
      ],
    };
  }
  const changes: FileChange[] = [];
  const problems: string[] = [];
  for (const [path, added] of Object.entries(files.added)) {
    if (after(added, from) && read(dir, path) === null) changes.push({ path, was: null, becomes: readFileSync(join(template, path), 'utf8') });
  }
  for (const [path, { since: retired, blobs }] of Object.entries(files.retired)) {
    const was = read(dir, path);
    if (!after(retired, from) || was === null) continue;
    if (blobs.includes(blob(was))) changes.push({ path, was, becomes: null });
    else problems.push(`${path} is a page coffre ${retired} no longer has, and is not as coffre wrote it: delete it, or keep it as a page of the deployment's own`);
  }
  return problems.length > 0 ? { problems } : { changes };
}

const read = (dir: string, path: string) => (existsSync(join(dir, path)) ? readFileSync(join(dir, path), 'utf8') : null);

/** Make the changes, in order. */
export function applyChanges(dir: string, changes: readonly FileChange[]): void {
  for (const { path, becomes } of changes) {
    const file = join(dir, path);
    if (becomes === null) rmSync(file, { force: true });
    else {
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, becomes);
    }
  }
}

/**
 * A change as lines to show: a file added or removed whole, by its name, and
 * one edited, by the lines that go and come, a screenful at most.
 */
export function shownChange({ path, was, becomes }: FileChange, limit = 12): string[] {
  if (was === null) return [`+ ${path}, new`];
  if (becomes === null) return [`- ${path}`];
  const lines = lineDiff(was.split('\n'), becomes.split('\n'));
  const shown = lines.slice(0, limit).map((line) => `  ${line}`);
  return [`~ ${path}`, ...shown, ...(lines.length > limit ? [`  … and ${lines.length - limit} more lines`] : [])];
}

/** The lines removed (`- `) and added (`+ `) from `a` to `b`, in order, by their longest common run. */
export function lineDiff(a: string[], b: string[]): string[] {
  const lengths = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      lengths[i]![j] = a[i] === b[j] ? lengths[i + 1]![j + 1]! + 1 : Math.max(lengths[i + 1]![j]!, lengths[i]![j + 1]!);
    }
  }
  const out: string[] = [];
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    if (i < a.length && j < b.length && a[i] === b[j]) {
      i++;
      j++;
    } else if (i < a.length && (j === b.length || lengths[i + 1]![j]! >= lengths[i]![j + 1]!)) {
      out.push(`- ${a[i++]!.trim()}`);
    } else {
      out.push(`+ ${b[j++]!.trim()}`);
    }
  }
  return out.filter((line) => line.length > 2);
}
