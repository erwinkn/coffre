// A deployment's files, as `coffre setup` finds and fills them in: which
// kind the directory holds, and on Workers, each Worker's wrangler.jsonc,
// read and edited in place, its comments kept.
import { spawn } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
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

/** Install a new deployment's packages, as its README says: pnpm, through corepack when pnpm itself is missing. */
export function install(dir: string): Promise<void> {
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
    const ran = (await attempt('pnpm', ['install'])) ?? (await attempt('corepack', ['pnpm', 'install']));
    if (ran === null) throw new Error('pnpm is not installed: corepack enable, or npm install -g pnpm, then run setup again');
    if (ran.code !== 0) throw new Error(installFailure(ran.output));
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
 * rest left as it is. What `pnpm bump` does to the examples, which `coffre
 * init` copies.
 */
export function bumpPins(dir: string, version: string): void {
  const path = join(dir, 'package.json');
  const manifest = JSON.parse(readFileSync(path, 'utf8')) as Record<string, Record<string, string> | undefined>;
  for (const field of ['dependencies', 'devDependencies']) {
    for (const name of Object.keys(manifest[field] ?? {})) {
      if (name.startsWith('@coffre/')) manifest[field]![name] = version;
    }
  }
  writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`);
}

/**
 * Why pnpm install failed, in a sentence. The deployment's minimumReleaseAge
 * holds back every package published within the week, coffre's own
 * excepted, and that includes what coffre's packages depend on: say which,
 * and what to do, rather than pnpm's last lines.
 */
export function installFailure(output: string): string {
  if (output.includes('MINIMUM_RELEASE_AGE')) {
    const held = [...output.matchAll(/^\s*(\S+@\d\S*) was published at/gm)].map((match) => match[1]!);
    return (
      `pnpm held back ${held.length === 0 ? 'packages' : held.join(', ')}: published within this deployment's ` +
      'minimumReleaseAge (pnpm-workspace.yaml), a week. Install again once they are a week old, ' +
      'or add them to minimumReleaseAgeExclude if you trust them'
    );
  }
  return `pnpm install failed: ${output.trim().split('\n').slice(-3).join(' ')}`;
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
