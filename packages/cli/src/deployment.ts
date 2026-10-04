// A deployment's files, as `coffre setup` finds and fills them in: which
// kind the directory holds, and on Workers, each Worker's wrangler.jsonc,
// read and edited in place, its comments kept.
import { spawn } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { applyEdits, type JSONPath, modify, parse, type ParseError, printParseErrorCode } from 'jsonc-parser';

import { isEmpty, type Kind } from './init.ts';

/** What a directory holds: a deployment of either kind, nothing yet (`isEmpty`), or something else. */
export function deploymentKind(dir: string): Kind | 'empty' | 'other' {
  if (isEmpty(dir)) return 'empty';
  if (existsSync(join(dir, 'app', 'wrangler.jsonc')) && existsSync(join(dir, 'vault', 'wrangler.jsonc'))) return 'workers';
  if (existsSync(join(dir, 'src', 'vault.ts')) && existsSync(join(dir, 'vault.env.example'))) return 'node';
  return 'other';
}

/**
 * Install a deployment's packages, as its README says: pnpm, through
 * corepack when pnpm itself is missing. `purge`, when the person has said
 * yes already: a pnpm of another major than the one that installed
 * node_modules removes it first, and without a terminal it would ask, and
 * stop.
 */
export function install(dir: string, { purge = false }: { purge?: boolean } = {}): Promise<void> {
  const attempt = (command: string, args: string[]) =>
    new Promise<{ code: number | null; output: string } | null>((resolve) => {
      // Corepack would otherwise ask, on a stdin nobody types into, before fetching pnpm.
      const child = spawn(command, args, { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, COREPACK_ENABLE_DOWNLOAD_PROMPT: '0' } });
      let output = '';
      child.stdout.setEncoding('utf8').on('data', (chunk: string) => (output += chunk));
      child.stderr.setEncoding('utf8').on('data', (chunk: string) => (output += chunk));
      child.on('error', () => resolve(null));
      child.on('close', (code) => resolve({ code, output }));
    });
  return (async () => {
    // pnpm's box about its own new release would come after the error, and take its place.
    const args = ['install', '--config.update-notifier=false', ...(purge ? ['--config.confirm-modules-purge=false'] : [])];
    const ran = (await attempt('pnpm', args)) ?? (await attempt('corepack', ['pnpm', ...args]));
    if (ran === null) throw new Error('pnpm is not installed: corepack enable, or npm install -g pnpm, then run setup again');
    if (ran.code !== 0) {
      const held = heldBack(ran.output);
      throw held.length > 0 ? new HeldBack(held, installFailure(ran.output)) : new Error(installFailure(ran.output));
    }
  })();
}

/** A deployment's `@coffre/*` pins, as its package.json has them. */
export function coffrePins(dir: string): Record<string, string> {
  const manifest = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as Record<string, Record<string, string> | undefined>;
  const pins: Record<string, string> = {};
  for (const field of ['dependencies', 'devDependencies']) {
    for (const [name, version] of Object.entries(manifest[field] ?? {})) {
      if (name.startsWith('@coffre/')) pins[name] = version;
    }
  }
  return pins;
}

/**
 * Every `@coffre/*` pin in `dir`'s package.json, moved to `version`; the
 * rest left as it is. `@coffre/cli` joins the devDependencies when it is
 * not there yet: the deployment's pipeline migrates with it, `pnpm exec
 * coffre migrate`. What `pnpm bump` does to the examples, which `coffre
 * init` copies, and `coffre update` to a deployment.
 */
export function bumpPins(dir: string, version: string): void {
  const path = join(dir, 'package.json');
  const manifest = JSON.parse(readFileSync(path, 'utf8')) as Record<string, Record<string, string> | undefined>;
  for (const field of ['dependencies', 'devDependencies']) {
    for (const name of Object.keys(manifest[field] ?? {})) {
      if (name.startsWith('@coffre/')) manifest[field]![name] = version;
    }
  }
  if (manifest.dependencies?.['@coffre/cli'] === undefined && manifest.devDependencies?.['@coffre/cli'] === undefined) {
    manifest.devDependencies = Object.fromEntries(
      Object.entries({ ...manifest.devDependencies, '@coffre/cli': version }).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
    );
  }
  writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`);
}

/** A package pnpm would not install yet, and when it was published. */
export type Held = { spec: string; publishedAt: Date };

/** pnpm install refused packages younger than the deployment's minimumReleaseAge. */
export class HeldBack extends Error {
  readonly held: Held[];

  constructor(held: Held[], message: string) {
    super(message);
    this.held = held;
  }
}

/**
 * The packages pnpm held back, as its error names them: in a lockfile it
 * checked, or as the only versions a range allows when it resolved.
 */
export function heldBack(output: string): Held[] {
  if (!/MINIMUM_RELEASE_AGE|NO_MATURE_MATCHING_VERSION/.test(output)) return [];
  return [...output.matchAll(/^\s*(\S+@\d\S*) was published at (\S+?),?\s/gm)].map((match) => ({
    spec: match[1]!,
    publishedAt: new Date(match[2]!),
  }));
}

/** The deployment's minimumReleaseAge, in minutes, as its pnpm-workspace.yaml sets it; pnpm's own default, none, without one. */
export function minimumReleaseAge(dir: string): number {
  const path = join(dir, 'pnpm-workspace.yaml');
  const match = existsSync(path) ? /^minimumReleaseAge:\s*(\d+)/m.exec(readFileSync(path, 'utf8')) : null;
  return match === null ? 0 : Number(match[1]);
}

/** How every temporary exclusion `coffre update` writes ends: with when it lapses. */
const EXCLUDED = /^\s*- '([^']+)' # coffre update: until (\S+)/;

/**
 * Exclude `held` from minimumReleaseAge, each until it clears, named in the
 * deployment's pnpm-workspace.yaml with that date: never silently, and
 * removed by `removeCleared` once the date has passed.
 */
export function excludeUntil(dir: string, held: { spec: string; clears: Date }[], reason: string): void {
  const path = join(dir, 'pnpm-workspace.yaml');
  const lines = (existsSync(path) ? readFileSync(path, 'utf8') : '').replace(/\n*$/, '').split('\n');
  const entries = held.map(({ spec, clears }) => `  - '${spec}' # coffre update: until ${clears.toISOString()}, ${reason}`);
  const key = lines.findIndex((line) => /^minimumReleaseAgeExclude:/.test(line));
  if (key === -1) {
    lines.push('minimumReleaseAgeExclude:', ...entries);
  } else {
    let end = key + 1;
    while (end < lines.length && /^\s+(-|#)/.test(lines[end]!)) end++;
    lines.splice(end, 0, ...entries);
  }
  writeFileSync(path, `${lines.join('\n')}\n`);
}

/** Remove the exclusions `excludeUntil` wrote whose date has passed; the packages they named. */
export function removeCleared(dir: string, now: Date): string[] {
  const path = join(dir, 'pnpm-workspace.yaml');
  if (!existsSync(path)) return [];
  const removed: string[] = [];
  const kept = readFileSync(path, 'utf8')
    .split('\n')
    .filter((line) => {
      const match = EXCLUDED.exec(line);
      if (match === null || new Date(match[2]!.replace(/,$/, '')) > now) return true;
      removed.push(match[1]!);
      return false;
    });
  if (removed.length > 0) writeFileSync(path, kept.join('\n'));
  return removed;
}

/**
 * The pnpm a deployment runs, `packageManager` in its package.json, set to
 * `wanted`, coffre's: then a laptop, CI and Workers Builds all install with
 * one pnpm, which holds minimumReleaseAge alike. The value it had, when it
 * changed; null when it was right already.
 */
export function pinPackageManager(dir: string, wanted: string): string | undefined | null {
  const path = join(dir, 'package.json');
  const manifest = JSON.parse(readFileSync(path, 'utf8')) as { packageManager?: string } & Record<string, unknown>;
  if (manifest.packageManager === wanted) return null;
  const was = manifest.packageManager;
  let next: Record<string, unknown>;
  if (was !== undefined) {
    next = { ...manifest, packageManager: wanted };
  } else {
    // New: after "private", or "name", as the examples have it.
    const after = 'private' in manifest ? 'private' : 'name';
    next = {};
    for (const [field, value] of Object.entries(manifest)) {
      next[field] = value;
      if (field === after) next.packageManager = wanted;
    }
    next.packageManager ??= wanted;
  }
  writeFileSync(path, `${JSON.stringify(next, null, 2)}\n`);
  return was;
}

/**
 * Why pnpm install failed, in a sentence. The deployment's minimumReleaseAge
 * holds back every package published within the week, coffre's own
 * excepted, and that includes what coffre's packages depend on: say which,
 * and what to do, rather than pnpm's last lines.
 */
export function installFailure(output: string): string {
  if (/MINIMUM_RELEASE_AGE|NO_MATURE_MATCHING_VERSION/.test(output)) {
    const held = [...output.matchAll(/^\s*(\S+@\d\S*) was published at/gm)].map((match) => match[1]!);
    return (
      `pnpm held back ${held.length === 0 ? 'packages' : held.join(', ')}: published within this deployment's ` +
      'minimumReleaseAge (pnpm-workspace.yaml), a week. Install again once they are a week old, ' +
      'or add them to minimumReleaseAgeExclude if you trust them'
    );
  }
  return `pnpm install failed: ${output.trim().split('\n').slice(-3).join(' ')}`;
}

/** Each package's locked versions, from a pnpm lockfile's `packages:`. */
export function lockedVersions(lockfile: string): Map<string, Set<string>> {
  const versions = new Map<string, Set<string>>();
  const section = /^packages:\n([\s\S]*?)(?=^\S|(?![\s\S]))/m.exec(lockfile)?.[1] ?? '';
  for (const match of section.matchAll(/^  '?(@?[^@\s']+)@([^:('\s]+)/gm)) {
    const set = versions.get(match[1]!) ?? new Set<string>();
    set.add(match[2]!);
    versions.set(match[1]!, set);
  }
  return versions;
}

/** A package whose locked version a fresh resolution moved. */
export type Moved = { name: string; from: string[]; to: string[] };

/**
 * Resolve every package again, from nothing, under the deployment's policy:
 * what a lockfile another pnpm wrote held too young, pnpm 11 replaces with
 * the newest version old enough, when the ranges allow one. Only a fresh
 * resolution does that: `pnpm update` checks the lockfile first and stops
 * there, and a lockfile with the held entries cut out installs without
 * them. So every package may move within its range, and each move is
 * returned, to be said. On failure the lockfile is put back.
 */
export async function resolveAgain(dir: string): Promise<Moved[]> {
  const path = join(dir, 'pnpm-lock.yaml');
  const before = existsSync(path) ? readFileSync(path, 'utf8') : null;
  rmSync(path, { force: true });
  // pnpm's copy of it, in node_modules, which it would check just the same.
  rmSync(join(dir, 'node_modules', '.pnpm', 'lock.yaml'), { force: true });
  try {
    await install(dir, { purge: true });
  } catch (error) {
    if (before !== null) writeFileSync(path, before);
    throw error;
  }
  const [was, now] = [lockedVersions(before ?? ''), lockedVersions(existsSync(path) ? readFileSync(path, 'utf8') : '')];
  const moved: Moved[] = [];
  for (const name of [...new Set([...was.keys(), ...now.keys()])].sort()) {
    const [from, to] = [[...(was.get(name) ?? [])].sort(), [...(now.get(name) ?? [])].sort()];
    if (from.join() !== to.join()) moved.push({ name, from, to });
  }
  return moved;
}

/** What setup reads of a Worker's wrangler.jsonc. */
export type WorkerConfig = {
  /** Its path, relative to the deployment, as wrangler's `-c` takes it. */
  path: string;
  name: string;
  accountId: string | null;
  vars: Record<string, string>;
  hyperdrive: string | null;
  route: string | null;
};

/** A value the examples ship, standing for the operator's own. */
export function placeholder(value: string | null | undefined): boolean {
  return value === undefined || value === null || value === '' || /^replace-with-|example\.com\b/.test(value);
}

export function readWorker(dir: string, path: string): WorkerConfig {
  const errors: ParseError[] = [];
  const config = parse(readFileSync(join(dir, path), 'utf8'), errors, { allowTrailingComma: true }) as {
    name?: string;
    account_id?: string;
    vars?: Record<string, unknown>;
    hyperdrive?: { id?: string }[];
    routes?: (string | { pattern?: string })[];
  };
  if (errors.length > 0) throw new Error(`${path} is not valid: ${printParseErrorCode(errors[0]!.error)} at offset ${errors[0]!.offset}`);
  if (typeof config.name !== 'string') throw new Error(`${path} names no Worker`);
  const route = config.routes?.[0];
  return {
    path,
    name: config.name,
    accountId: config.account_id ?? null,
    vars: Object.fromEntries(Object.entries(config.vars ?? {}).filter((entry): entry is [string, string] => typeof entry[1] === 'string')),
    hyperdrive: placeholder(config.hyperdrive?.[0]?.id) ? null : config.hyperdrive![0]!.id!,
    route: typeof route === 'string' ? route : (route?.pattern ?? null),
  };
}

/** A value as the examples write one on a single line: `[{ "pattern": "…", "custom_domain": true }]`. */
function inline(value: unknown): string {
  return JSON.stringify(value, null, 1).replace(/\n\s*/g, ' ').replace(/\[ /g, '[').replace(/ \]/g, ']');
}

/** A change to a wrangler.jsonc: a value at a path, and, for a new property, the one it goes after. */
export type Change = { path: JSONPath; value: unknown; after?: string };

/** Make `changes` to the file at `path`, leaving the rest as it is, comments and all. Says which changed anything. */
export function editWorker(dir: string, path: string, changes: readonly Change[]): boolean[] {
  const MARK = '\u0000coffre\u0000';
  let text = readFileSync(join(dir, path), 'utf8');
  const changed = changes.map((change) => {
    const edits = modify(text, change.path, MARK, {
      formattingOptions: { insertSpaces: true, tabSize: 2, eol: '\n' },
      getInsertionIndex: change.after === undefined ? undefined : (properties) => properties.indexOf(change.after!) + 1,
    });
    const before = text;
    text = applyEdits(text, edits.map((edit) => ({ ...edit, content: edit.content.replace(JSON.stringify(MARK), inline(change.value)) })));
    return text !== before;
  });
  writeFileSync(join(dir, path), text);
  return changed;
}
