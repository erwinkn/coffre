// A deployment of coffre 0.1, whose app imported prebuilt pages, made its
// own TanStack Start app, as `coffre init` writes one since 0.2: what
// changes, file by file, for `coffre update` to show, and then to make.
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { applyEdits, modify } from 'jsonc-parser';

import { KEEP_NAMES_WHY } from './deployment.ts';
import type { Kind } from './init.ts';

/** One file of a deployment: its text before, and after; null where there is none. */
export type FileChange = { path: string; was: string | null; becomes: string | null };

/** Whether the deployment in `dir` predates its own Start app: it has no app/vite.config.ts. */
export function needsStartApp(dir: string): boolean {
  return !existsSync(join(dir, 'app', 'vite.config.ts'));
}

const read = (dir: string, path: string) => (existsSync(join(dir, path)) ? readFileSync(join(dir, path), 'utf8') : null);

/** The template's text of a file this move writes as it is: the Vite config and the router. */
function templateText(template: string, path: string): string {
  return readFileSync(join(template, path), 'utf8');
}

/**
 * The app's entry, which configures coffre, given the pages as Start's
 * handler: its import, before coffre's, and `pages` first in what the
 * configuration returns, `(env) => ({ … })` or a body that `return { … }`s.
 * Null when neither is there to find. `lines`, what goes in, one per line.
 */
export function withPages(source: string, from: '@coffre/server/cloudflare' | '@coffre/server/node', lines: readonly string[]): string | null {
  if (/\bpages\s*[,:]/.test(source)) return source;
  const call = from === '@coffre/server/cloudflare' ? /\bcoffre\s*\(/ : /\bserve\s*\(/;
  const at = source.search(call);
  if (at === -1) return null;
  const rest = source.slice(at);
  const opening = /^[\s\S]*?(?:=>\s*\(\{|return\s*\{|serve\s*\(\s*\{)/.exec(rest);
  if (opening === null) return null;
  const end = at + opening[0].length;
  const indent = /\n([ \t]+)\S/.exec(source.slice(end))?.[1] ?? '  ';
  let text = `${source.slice(0, end)}${lines.map((line) => `\n${indent}${line}`).join('')}${source.slice(end)}`;
  if (from === '@coffre/server/cloudflare') {
    const imported = text.search(/^import [^\n]* from '@coffre\/server\/cloudflare';$/m);
    if (imported === -1) return null;
    text = `${text.slice(0, imported)}import pages from '@tanstack/react-start/server-entry';\n${text.slice(imported)}`;
  }
  return text;
}

/**
 * app/wrangler.jsonc for an app Vite builds: its entry, Start's server entry
 * of its own; no `assets`, which the build sets; and no `keep_names`, which
 * nothing bundles again for. Comments coffre wrote with those go too.
 */
export function startWrangler(text: string): string {
  const format = { formattingOptions: { insertSpaces: true, tabSize: 2, eol: '\n' } };
  let next = text
    .replace(new RegExp(`\\n[ \\t]*${KEEP_NAMES_WHY.map((line) => line.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('\\n[ \\t]*')}\\n[ \\t]*"keep_names": false,`), '')
    .replace(/\n[ \t]*\/\/ The pages' scripts, styles and fonts, all under \/_coffre\/assets\/\./, '');
  for (const [path, value] of [
    [['main'], 'src/server.ts'],
    [['assets'], undefined],
    [['keep_names'], undefined],
  ] as const) {
    next = applyEdits(next, modify(next, [...path], value, format));
  }
  return next;
}

/** A package.json, as an object, written as the template writes it: two spaces, a newline at the end. */
const json = (value: unknown) => `${JSON.stringify(value, null, 2)}\n`;

/**
 * package.json for a Start app: the scripts the template's are, where these
 * are 0.1's own (one changed by hand is the deployment's to keep), and the
 * template's dependencies the deployment lacks, at the template's versions.
 */
export function startManifest(text: string, template: string, was: Record<string, string>): string {
  const manifest = JSON.parse(text) as Record<string, Record<string, string> | unknown>;
  const wanted = JSON.parse(readFileSync(join(template, 'package.json'), 'utf8')) as Record<string, Record<string, string>>;
  const scripts = { ...(manifest.scripts as Record<string, string>) };
  for (const [name, script] of Object.entries(wanted.scripts ?? {})) {
    if (scripts[name] === undefined || scripts[name] === was[name]) scripts[name] = script;
  }
  // In the template's order, then what the deployment added.
  manifest.scripts = Object.fromEntries([
    ...Object.keys(wanted.scripts ?? {}).map((name) => [name, scripts[name]!] as const),
    ...Object.entries(scripts).filter(([name]) => !(name in (wanted.scripts ?? {}))),
  ]);
  const has = (name: string) =>
    (manifest.dependencies as Record<string, string> | undefined)?.[name] !== undefined ||
    (manifest.devDependencies as Record<string, string> | undefined)?.[name] !== undefined;
  for (const field of ['dependencies', 'devDependencies'] as const) {
    const own = { ...((manifest[field] as Record<string, string> | undefined) ?? {}) };
    for (const [name, version] of Object.entries(wanted[field] ?? {})) if (!has(name)) own[name] = version;
    manifest[field] = Object.fromEntries(Object.entries(own).sort(([a], [b]) => a.localeCompare(b)));
  }
  return json(manifest);
}

/** The scripts 0.1.18's `coffre init` wrote, which a move may replace. */
const SCRIPTS_0_1: Record<Kind, Record<string, string>> = {
  workers: {
    dev: 'wrangler dev -c app/wrangler.jsonc -c vault/wrangler.jsonc',
    build: 'wrangler deploy --dry-run -c vault/wrangler.jsonc && wrangler deploy --dry-run -c app/wrangler.jsonc',
    deploy: 'wrangler deploy -c vault/wrangler.jsonc && wrangler deploy -c app/wrangler.jsonc',
  },
  node: {},
};

/**
 * Every file the move changes in the deployment at `dir`, from the template
 * at `template`; or why it cannot: an entry it does not find coffre's
 * configuration in, to give the pages to.
 */
export function startAppMove(dir: string, kind: Kind, template: string): FileChange[] | { problem: string } {
  const changes: FileChange[] = [];
  const change = (path: string, becomes: string | null, was = read(dir, path)) => {
    if (was !== becomes) changes.push({ path, was, becomes });
  };
  for (const path of ['app/vite.config.ts', 'app/src/router.tsx']) change(path, templateText(template, path));
  if (kind === 'workers') {
    const entry = read(dir, 'app/src/worker.ts') ?? read(dir, 'app/src/server.ts');
    const given = entry === null ? null : withPages(entry, '@coffre/server/cloudflare', ['pages,']);
    if (given === null) {
      return { problem: "app/src/worker.ts: coffre(…)'s configuration is not where it can be found, to give it the pages" };
    }
    if (read(dir, 'app/src/worker.ts') !== null) change('app/src/worker.ts', null);
    change('app/src/server.ts', given);
    const wrangler = read(dir, 'app/wrangler.jsonc');
    if (wrangler !== null) change('app/wrangler.jsonc', startWrangler(wrangler));
  } else {
    const entry = read(dir, 'src/server.ts');
    const given =
      entry === null
        ? null
        : withPages(entry, '@coffre/server/node', ['// The pages: app/, built by `vite build app`.', "pages: new URL('../app/dist/', import.meta.url),"]);
    if (given === null) return { problem: "src/server.ts: serve({ … }) is not where it can be found, to give it the pages" };
    change('src/server.ts', given);
  }
  const manifest = read(dir, 'package.json');
  if (manifest !== null) change('package.json', startManifest(manifest, template, SCRIPTS_0_1[kind]));
  const ignored = read(dir, '.gitignore') ?? '';
  if (!ignored.split('\n').includes('dist')) change('.gitignore', `${ignored}${ignored === '' || ignored.endsWith('\n') ? '' : '\n'}dist\n`);
  return changes;
}

/** Make the changes. */
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
