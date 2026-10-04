// A deployment of coffre 0.1, whose app imported prebuilt pages, made its
// own TanStack Start app, as `coffre init` writes one since 0.2: what
// changes, file by file, for `coffre update` to show, and then to make.
//
// It changes only what it knows. A file is replaced only when it is, byte
// for byte, one that a release of 0.1 wrote; in app/wrangler.jsonc and
// package.json, only values 0.1 wrote are changed. Anything else, a file
// edited or one already where 0.2 puts its own, and nothing changes: the move
// is the deployment's to make by hand (docs/deploy.md, "Upgrading to 0.2").
// The entry that holds coffre's configuration goes last, so a move cut short
// is found again, and finished, by the next run.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { applyEdits, modify, parse } from 'jsonc-parser';

import { KEEP_NAMES_WHY } from './deployment.ts';
import { templateFiles, type Kind } from './init.ts';

/** One file of a deployment: its text before, and after; null where there is none. */
export type FileChange = { path: string; was: string | null; becomes: string | null };

/** The move: the changes, in order, and what it leaves to the deployment; or why it makes none. */
export type Move = { changes: FileChange[]; notes: string[] } | { problems: string[] };

/** A file's Git blob hash, with the line endings Git keeps: what names a file 0.1 wrote. */
export function blob(text: string): string {
  const bytes = Buffer.from(text.replace(/\r\n/g, '\n'), 'utf8');
  return createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
}

/**
 * How a release's configuration differs from 0.1.18's, as text that 0.1.18's
 * entry and 0.2's both hold: [theirs, this release's]. Undone on 0.2's file,
 * they give that release's configuration in 0.2's shape: the same secrets,
 * the same features. A test holds each to the file the release wrote.
 */
type Difference = readonly [string, string];

/** An entry 0.1 wrote: its blob, the releases that wrote it, and how its configuration differs from the latest's. */
type Known = { blob: string; releases: string; differences: readonly Difference[] };

const WORKERS_WORKLOADS: Difference[] = [
  [
    "  /** What every CI run's exchange passes first: app/wrangler.jsonc's rate-limiting bindings. */\n" +
      '  WORKLOADS_PER_SOURCE: RateLimit;\n' +
      '  WORKLOADS_TOTAL: RateLimit;\n' +
      "  /** Set by conformance only: a binding's issuer may then be plain HTTP on loopback. Refused unless PUBLIC_URL is loopback too. */\n" +
      '  ALLOW_LOOPBACK_ISSUERS_FOR_DEVELOPMENT?: string;\n',
    '',
  ],
  [
    "    // CI runs may sign in as services with their platform's ID token, through\n" +
      '    // the trust bindings owners make (docs/design/oidc.md).\n' +
      '    workloads: {\n' +
      '      limits: { perSource: env.WORKLOADS_PER_SOURCE, total: env.WORKLOADS_TOTAL },\n' +
      "      allowLoopbackIssuersForDevelopment: env.ALLOW_LOOPBACK_ISSUERS_FOR_DEVELOPMENT === 'true',\n" +
      '    },\n',
    '',
  ],
];

const WORKERS_AUDIT_CHAIN_KEY: Difference[] = [
  ['  APP_KEY: string;\n', '  AUDIT_CHAIN_KEY: string;\n'],
  ['auditChainKey: env.APP_KEY,', 'auditChainKey: env.AUDIT_CHAIN_KEY,'],
];

/** app/src/worker.ts, as each release of 0.1 wrote it. */
export const WORKERS_ENTRIES: readonly Known[] = [
  { blob: 'a43b95e094a089bc191f1109412fe412e2f78257', releases: '0.1.16 to 0.1.18', differences: [] },
  { blob: '3f3d39fddb18476a1fe72bac8427e6962829205a', releases: '0.1.3 to 0.1.15', differences: WORKERS_WORKLOADS },
  { blob: '047d3c7cddb1d1fb8cca4ea29519d3855621da28', releases: '0.1.0 to 0.1.2', differences: [...WORKERS_WORKLOADS, ...WORKERS_AUDIT_CHAIN_KEY] },
];

const NODE_WORKLOADS: Difference[] = [
  ['github, processLimits, ', 'github, '],
  [
    "    // CI runs may sign in as services with their platform's ID token, through\n" +
      '    // the trust bindings owners make (docs/design/oidc.md). Each exchange\n' +
      '    // passes these first; they count in this process.\n' +
      '    workloads: {\n' +
      '      limits: processLimits({ perSource: 30, total: 300 }),\n' +
      "      // Set by conformance only: a binding's issuer may then be plain HTTP on\n" +
      '      // loopback. Refused unless PUBLIC_URL is loopback too.\n' +
      "      allowLoopbackIssuersForDevelopment: process.env.ALLOW_LOOPBACK_ISSUERS_FOR_DEVELOPMENT === 'true',\n" +
      '    },\n',
    '',
  ],
];

const NODE_AUDIT_CHAIN_KEY: Difference[] = [["auditChainKey: env('APP_KEY'),", "auditChainKey: env('AUDIT_CHAIN_KEY'),"]];

/** src/server.ts, as each release of 0.1 wrote it. */
export const NODE_ENTRIES: readonly Known[] = [
  { blob: 'b4a8ca3a0613cc67824bc1dc149be0bf3068a81a', releases: '0.1.16 to 0.1.18', differences: [] },
  { blob: '2ca6fd9803ecb0d2f4a35d14dc63d17e92a8d345', releases: '0.1.3 to 0.1.15', differences: NODE_WORKLOADS },
  { blob: 'bd78dc61ff7b45bd1215815298d5bd52fd6647da', releases: '0.1.2', differences: [...NODE_WORKLOADS, ...NODE_AUDIT_CHAIN_KEY] },
  { blob: 'b8d45d4df0bc42949265142bac2a38c2922e9609', releases: '0.1.0 and 0.1.1', differences: [...NODE_WORKLOADS, ...NODE_AUDIT_CHAIN_KEY] },
];

/** `text` with each difference undone; null if one is not there exactly once, which a test rules out for the template. */
export function undo(text: string, differences: readonly Difference[]): string | null {
  let out = text;
  for (const [latest, release] of differences) {
    const at = out.indexOf(latest);
    if (at === -1 || out.indexOf(latest, at + 1) !== -1) return null;
    out = `${out.slice(0, at)}${release}${out.slice(at + latest.length)}`;
  }
  return out;
}

/** The other files 0.1 wrote that 0.2 changes, by their blobs: replaced when unedited, else the deployment's. */
const OTHERS: Record<Kind, Record<string, readonly string[]>> = {
  workers: {
    'tsconfig.json': ['78e8fd222d471474dfb1fd74730ce3f4bf34ab5e'],
    '.gitignore': ['b6cb300bac13d42c00655aa522bb8390453d3baf'],
    'README.md': [
      '09584bd159515b72c058a9abc71ce8dc9fe01cc2',
      'd7905f2d1cf7c1a4fcdbfd74e1b09b801e3ed350',
      '80a59a93852ef84f8fd4f24d682381cf80e76dac',
      'c3fc6c4f69d81a2d22651d5b6db45415ecb49bd8',
      '5d1dd9c4715d63cb0d4118cf59619001302cd3d5',
      '9684426a4656c7869f5b9ad46b64b94125847f7e',
      '85319dbd8c5316bca4514fe01ed8b5145b41e8cf',
    ],
  },
  node: {
    'tsconfig.json': ['b4c0de7297dc6c517468286d58208393a21499ea'],
    '.gitignore': ['4e6394542e3ce4994115ea557789a37ff2653478'],
    'README.md': [
      'ae48ab4846b6e1265566e5a3341b3fc39f77e84e',
      '4326563b36c8c3d2433b2bbb8c6645c4716daa2d',
      'ce7123a2d3f0e75e0262469f408148e76a3fa656',
      '54ba6971c01578caa31f48cce4ee73caa3d291d4',
      '30ec64d21a1d274ab7f0b62129e3a5a035b8e21a',
      'bb0e51e2e9b61fe60ca7f0b6ae4e2e8265722ec2',
    ],
  },
};

/** server.env.example, as each release of 0.1 wrote it: .env.example since 0.2. */
const SERVER_ENV_EXAMPLES = [
  '0e6554f5585990049d6ec90c150ef280b4c2c23d',
  '3cf1335eb10e2e16f997f11052e46bd5a0986a8d',
  '5846ba5a1773b0cd8122bfe3e83519853196872a',
  'd9e929d46902e880e4f8ad23817d2fad97ba58dd',
];

/** The scripts 0.1 wrote, which 0.2's replace: every release's alike. */
const SCRIPTS_0_1: Record<Kind, Record<string, string>> = {
  workers: {
    dev: 'wrangler dev -c app/wrangler.jsonc -c vault/wrangler.jsonc',
    build: 'wrangler deploy --dry-run -c vault/wrangler.jsonc && wrangler deploy --dry-run -c app/wrangler.jsonc',
    deploy: 'wrangler deploy -c vault/wrangler.jsonc && wrangler deploy -c app/wrangler.jsonc',
  },
  node: {
    start: 'node --env-file=server.env src/server.ts',
  },
};

/** The files of 0.2's app that hold nothing of a deployment's own, written as the template has them: all of `app/` but its configuration and its Worker's settings. */
function appFiles(template: string): string[] {
  return templateFiles(template).filter((path) => path.startsWith('app/') && path !== 'app/src/coffre.ts' && path !== 'app/wrangler.jsonc');
}

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
    '_coffre.tsx',
    '_coffre/index.tsx',
    '_coffre/projects.index.tsx',
    '_coffre/projects.$project.index.tsx',
    '_coffre/projects.$project.$environment.tsx',
    '_coffre/audit.tsx',
    '_coffre/access.tsx',
    '_coffre/users.index.tsx',
    '_coffre/users.$user.tsx',
    '_coffre/tokens.index.tsx',
    '_coffre/tokens.$token.tsx',
    '_coffre/settings.tsx',
    '_coffre/account.tsx',
    '_solo.tsx',
    '_solo/login.tsx',
    '_solo/unregistered.tsx',
    '_solo/auth.device.tsx',
  ].map((file) => [`app/src/routes/${file}`, '0.2.0']),
);

/**
 * The route files coffre wrote and no longer does, a page removed or
 * renamed: by the release that retired each, and the blobs of what releases
 * before it wrote there. None yet.
 */
export const RETIRED_ROUTE_FILES: Record<string, { since: string; blobs: readonly string[] }> = {};

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

/** The first release whose deployments mount coffre as file routes: what one that has them is counted from. */
export const FIRST_FILE_ROUTES = '0.2.0';

/** coffre's layouts as file routes, under which a deployment mounts its pages. */
const LAYOUT_FILES = ['app/src/routes/_coffre.tsx', 'app/src/routes/_solo.tsx'];

/**
 * The page files a deployment with coffre's file routes, at release `from`,
 * gains and loses moving to the template's: those added since `from`, or
 * since file routes began if it is from before them, as one moved by hand
 * is, where it has none; and those retired since, where it has exactly what
 * coffre wrote. One retired that it changed is its own: refused, with what
 * to do. So is a deployment without coffre's layouts as file routes, the
 * only way coffre mounts.
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
        `${LAYOUT_FILES.join(' and ')}, coffre's layouts as file routes, are both missing: since 0.2 coffre mounts as Start's file routes, as coffre init writes them (docs/deploy.md, "Your own routes")`,
      ],
    };
  }
  const since = after(FIRST_FILE_ROUTES, from) ? FIRST_FILE_ROUTES : from;
  const changes: FileChange[] = [];
  const problems: string[] = [];
  for (const [path, added] of Object.entries(files.added)) {
    if (after(added, since) && read(dir, path) === null) changes.push({ path, was: null, becomes: readFileSync(join(template, path), 'utf8') });
  }
  for (const [path, { since: retired, blobs }] of Object.entries(files.retired)) {
    const was = read(dir, path);
    if (!after(retired, since) || was === null) continue;
    if (blobs.includes(blob(was))) changes.push({ path, was, becomes: null });
    else problems.push(`${path} is a page coffre ${retired} no longer has, and is not as coffre wrote it: delete it, or keep it as a page of the deployment's own`);
  }
  return problems.length > 0 ? { problems } : { changes, notes: [] };
}

/** 0.1's `assets`, the prebuilt pages in node_modules: the app's build sets its own now. */
const ASSETS_0_1 = '../node_modules/@coffre/ui/dist/client';

const BY_HAND = 'move it by hand, as docs/deploy.md, "Upgrading to 0.2", shows';

const read = (dir: string, path: string) => (existsSync(join(dir, path)) ? readFileSync(join(dir, path), 'utf8') : null);

/**
 * Every change that makes the deployment at `dir` its own Start app, from
 * the template at `template`, in the order to make them; none once it is
 * one; or, changing nothing, every reason it cannot be moved so.
 */
export function startAppMove(dir: string, kind: Kind, template: string): Move {
  const entryPath = kind === 'workers' ? 'app/src/worker.ts' : 'src/server.ts';
  const entry = read(dir, entryPath);
  const known = entry === null ? undefined : (kind === 'workers' ? WORKERS_ENTRIES : NODE_ENTRIES).find((k) => k.blob === blob(entry));
  if (known === undefined) {
    // Moved already, by an earlier run or by hand: what is there now is the deployment's.
    if (entry === null && existsSync(join(dir, 'app/src/coffre.ts'))) return { changes: [], notes: [] };
    if (entry === null) {
      return { problems: [`${entryPath}, where coffre 0.1 is configured, and app/src/coffre.ts, where 0.2 is, are both missing`] };
    }
    return { problems: [`${entryPath} is not as any release of coffre 0.1 wrote it, so its configuration is the deployment's own: ${BY_HAND}`] };
  }

  const problems: string[] = [];
  const changes: FileChange[] = [];
  const notes: string[] = [];
  const change = (path: string, becomes: string | null, was = read(dir, path)) => {
    if (was !== becomes) changes.push({ path, was, becomes });
  };
  // Published, the template's .gitignore is called gitignore (init.ts).
  const templateText = (path: string) =>
    readFileSync(join(template, path === '.gitignore' && !existsSync(join(template, path)) ? 'gitignore' : path), 'utf8');

  // The configuration, in 0.2's shape, as this release had it.
  const configPath = 'app/src/coffre.ts';
  const config = undo(templateText(configPath), known.differences);
  if (config === null) throw new Error(`${configPath} of the template no longer holds what ${known.releases} differ by`);

  // The app's files: written where there are none, left where they are
  // already as they would be written. One of the deployment's own there
  // would be overwritten: refused.
  const own = (path: string, becomes: string) => {
    const was = read(dir, path);
    if (was === null) changes.push({ path, was, becomes });
    else if (was !== becomes) problems.push(`${path} is there already, and is not what coffre 0.2 writes there: move it aside, or ${BY_HAND}`);
  };
  for (const path of appFiles(template)) own(path, templateText(path));
  own(configPath, config);

  if (kind === 'workers') {
    const wrangler = read(dir, 'app/wrangler.jsonc');
    if (wrangler === null) problems.push('app/wrangler.jsonc is missing');
    else {
      const moved = startWrangler(wrangler);
      if ('problem' in moved) problems.push(`app/wrangler.jsonc: ${moved.problem}`);
      else change('app/wrangler.jsonc', moved.text, wrangler);
    }
  }

  const manifest = read(dir, 'package.json');
  if (manifest === null) problems.push('package.json is missing');
  else {
    const moved = startManifest(manifest, template, SCRIPTS_0_1[kind]);
    if ('problem' in moved) problems.push(`package.json: ${moved.problem}`);
    else {
      change('package.json', moved.text, manifest);
      notes.push(...moved.kept);
    }
  }

  // Unedited, 0.2's; edited, the deployment's, with what it then lacks said.
  for (const [path, blobs] of Object.entries(OTHERS[kind])) {
    const was = read(dir, path);
    const becomes = templateText(path);
    if (was === null || blobs.includes(blob(was))) change(path, becomes, was);
    else if (was === becomes) continue;
    else if (path === '.gitignore') {
      if (!was.split(/\r?\n/).includes('dist')) change(path, `${was}${was.endsWith('\n') ? '' : '\n'}dist\n`, was);
    } else if (path === 'tsconfig.json') {
      notes.push(
        `tsconfig.json is the deployment's own, and stays so: for pnpm typecheck to check the app, add "jsx": "react-jsx" to its compilerOptions and "vite/client" to their types${kind === 'node' ? ', set their moduleResolution to "bundler", and add "app/src" to its include' : ''}`,
      );
    } else notes.push(`${path} is the deployment's own, and stays as it is`);
  }

  // On Node, the server's settings are .env, which srvx reads, and their template .env.example.
  if (kind === 'node') {
    change('.env.example', templateText('.env.example'));
    const example = read(dir, 'server.env.example');
    if (example !== null && SERVER_ENV_EXAMPLES.includes(blob(example))) change('server.env.example', null, example);
    notes.push('The server reads its settings from .env now, which srvx loads: rename server.env to .env where the server runs');
  }

  if (problems.length > 0) return { problems };
  // Last, the entry: until it changes, the move is not done, and the next run finishes it.
  change(entryPath, null, entry);
  return { changes, notes };
}

/**
 * app/wrangler.jsonc for an app Vite builds: its entry, Start's server entry
 * of its own; no `assets`, which the build sets; and no `keep_names`, which
 * nothing bundles again for. Comments coffre wrote with those go too. Each
 * only from the value 0.1 wrote; another is the deployment's, and refused.
 */
export function startWrangler(text: string): { text: string } | { problem: string } {
  const config = parse(text) as { main?: unknown; assets?: unknown; keep_names?: unknown } | undefined;
  if (config === undefined || typeof config !== 'object') return { problem: 'it does not parse' };
  if (config.main !== 'src/worker.ts' && config.main !== 'src/server.ts') {
    return { problem: `"main" is ${JSON.stringify(config.main)}, not the src/worker.ts coffre 0.1 wrote: ${BY_HAND}` };
  }
  const assets = config.assets as { directory?: unknown } | undefined;
  if (assets !== undefined && (Object.keys(assets).length !== 1 || assets.directory !== ASSETS_0_1)) {
    return { problem: `"assets" is not the ${ASSETS_0_1} coffre 0.1 wrote, and the app's build now sets its own: ${BY_HAND}` };
  }
  if (config.keep_names !== undefined && config.keep_names !== false) {
    return { problem: `"keep_names" is ${JSON.stringify(config.keep_names)}, not the false coffre 0.1 wrote: ${BY_HAND}` };
  }
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
  return { text: next };
}

/** A package.json, as an object, written as the template writes it: two spaces, a newline at the end. */
const json = (value: unknown) => `${JSON.stringify(value, null, 2)}\n`;

/**
 * package.json for a Start app: the template's scripts, in place of 0.1's;
 * and the template's dependencies the deployment lacks, at the template's
 * versions. A script that is neither 0.1's nor 0.2's is the deployment's:
 * refused where 0.1 wrote one, as it would still build 0.1's app; kept, and
 * named, where 0.1 wrote none, as Node's `build`.
 */
export function startManifest(
  text: string,
  template: string,
  was: Record<string, string>,
): { text: string; kept: string[] } | { problem: string } {
  const manifest = JSON.parse(text) as Record<string, Record<string, string> | unknown>;
  const wanted = JSON.parse(readFileSync(join(template, 'package.json'), 'utf8')) as Record<string, Record<string, string>>;
  const scripts = { ...(manifest.scripts as Record<string, string> | undefined) };
  const edited: string[] = [];
  const kept: string[] = [];
  for (const [name, script] of Object.entries(wanted.scripts ?? {})) {
    if (scripts[name] === undefined || scripts[name] === was[name]) scripts[name] = script;
    else if (scripts[name] !== script && name in was) edited.push(name);
    else if (scripts[name] !== script) {
      kept.push(`package.json's "${name}" script is the deployment's own, and stays so: coffre 0.2's is \`${script}\`, and the app needs what it does`);
    }
  }
  if (edited.length > 0) {
    const names = edited.map((name) => `"${name}"`).join(' and ');
    return {
      problem: `its ${names} ${edited.length === 1 ? 'script is' : 'scripts are'} not as coffre 0.1 wrote ${edited.length === 1 ? 'it' : 'them'}, and would still build 0.1's app: ${BY_HAND}`,
    };
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
  return { text: json(manifest), kept };
}

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
