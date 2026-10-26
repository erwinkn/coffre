// `coffre update`: this CLI, to coffre's latest release, the way it was
// installed; and, run in a deployment, its coffre packages too. Then what
// the release changes for the database: the migrations it adds, which
// `coffre migrate` applies before the new version is deployed.
import { spawn, spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, posix, sep, win32 } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

import { KNOWN_MIGRATIONS } from '@coffre/db/schema-version';

import {
  bumpPins,
  coffrePins,
  deploymentKind,
  excludeUntil,
  generateRouteTree,
  HeldBack,
  install,
  installAsLocked,
  installed,
  minimumReleaseAge,
  pinPackageManager,
  removeCleared,
  resolveAgain,
  ROUTE_TREE,
  movePins,
  START_PACKAGES,
  startPinMoves,
  type Held,
  type Moved,
  type PinMove,
} from './deployment.ts';
import { WORKFLOW } from './deploy-on-push.ts';
import { templateDir, type Kind } from './init.ts';
import { after as later, applyChanges, CLEAN_BREAK, type Move, pageMove, shownChange } from './layout.ts';
import { StepFailed, Steps } from './steps.ts';
import { Cancelled, listed, openTerminal, type Output, release, style } from './tty.ts';
import { cliVersion } from './version.ts';

const PACKAGE = '@coffre/cli';

/** How this CLI came to be here, which says how to update it. */
export type Install =
  /** `prefix` and `dir`: npm's global that npm no longer lists, where this CLI is, said by its path (`npmPrefixOf`). */
  | { kind: 'npm'; prefix?: string; dir?: string }
  | { kind: 'pnpm' }
  /** npx fetches what it is asked for each time: nothing stays to update. */
  | { kind: 'npx' }
  /** A checkout of coffre itself, as its own developers run it. */
  | { kind: 'checkout' }
  /** A dependency of a project, updated with that project's packages. */
  | { kind: 'project'; dir: string }
  | { kind: 'unknown'; path: string };

/**
 * Where each package manager's own global @coffre/cli is, as it says, through
 * its links: null when it has none. `pnpmHome`, only when pnpm could not
 * say: its PNPM_HOME, which holds its globals, pnpm 10's and 11's alike.
 */
export type Globals = { npm: string | null; pnpm: string | null; pnpmHome: string | null };

/**
 * How the CLI at `path`, a real path, was installed: under npx's cache, as
 * npm's or pnpm's global, as a dependency of a project, or in a checkout.
 * By what the managers say, not by the shape of the path: pnpm 11 keeps a
 * global package in its store's links/, where a project's may be too.
 * `isProject` says whether a directory is one that depends on @coffre/cli.
 */
export function installOf(
  path: string,
  globals: Globals,
  isProject: (dir: string) => boolean = dependsOnCli,
  shimmed: (prefix: string, dir: string) => boolean = hasShim,
): Install {
  const within = (dir: string | null) => dir !== null && (path === dir || path.startsWith(dir + sep));
  if (path.includes(`${sep}_npx${sep}`)) return { kind: 'npx' };
  if (within(globals.pnpm)) return { kind: 'pnpm' };
  if (within(globals.npm)) return { kind: 'npm' };
  if (within(globals.pnpmHome)) return { kind: 'pnpm' };
  // The project is where its node_modules starts: pnpm's own packages are further down, in node_modules/.pnpm.
  const modules = path.indexOf(`${sep}node_modules${sep}`);
  if (modules !== -1 && isProject(path.slice(0, modules))) return { kind: 'project', dir: path.slice(0, modules) };
  // A prefix npm no longer has as its own, after a Node reinstall: npm lists nothing there, but the layout says it.
  // The layout alone is not npm's: a project's may be the same. The shim npm made beside it says that it is.
  const moved = npmPrefixOf(path);
  if (moved !== null && shimmed(moved.prefix, moved.dir)) return { kind: 'npm', ...moved };
  if (modules !== -1) return { kind: 'unknown', path };
  if (path.includes(`${sep}packages${sep}cli${sep}`)) return { kind: 'checkout' };
  return { kind: 'unknown', path };
}

/**
 * The npm prefix a path is an install under, by npm's layout: `<prefix>/lib/node_modules/@coffre/cli`,
 * and on Windows `<prefix>\node_modules\@coffre\cli`. With `dir`, the package's own directory.
 * Null for any other path. A project's `node_modules` has the Windows layout too: the caller asks
 * whether the directory is a project first.
 */
export function npmPrefixOf(path: string, flavour: typeof posix | typeof win32 = sep === '\\' ? win32 : posix): { prefix: string; dir: string } | null {
  const tail = flavour === win32 ? ['node_modules', '@coffre', 'cli'] : ['lib', 'node_modules', '@coffre', 'cli'];
  const parts = path.split(flavour.sep);
  const at = parts.findIndex((_, i) => tail.every((name, j) => parts[i + j] === name) && i > 0);
  if (at === -1) return null;
  const above = parts.slice(0, at).join(flavour.sep);
  // The root has no name left: `/`, or `C:\`.
  const prefix = above === '' || /^[A-Za-z]:$/.test(above) ? above + flavour.sep : above;
  return { prefix, dir: parts.slice(0, at + tail.length).join(flavour.sep) };
}

/**
 * Whether npm's global bin for `coffre` is at `prefix` and is this package's: `bin/coffre`, a link
 * into `dir`; on Windows, `coffre.cmd` in the prefix itself, a script, which exists or not.
 */
function hasShim(prefix: string, dir: string): boolean {
  try {
    if (sep === '\\') return existsSync(join(prefix, 'coffre.cmd'));
    return realpathSync(join(prefix, 'bin', 'coffre')).startsWith(realpathSync(dir) + sep);
  } catch {
    return false;
  }
}

/** Whether `dir` is a project with @coffre/cli among its dependencies. */
function dependsOnCli(dir: string): boolean {
  try {
    const manifest = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as Record<string, Record<string, string> | undefined>;
    return ['dependencies', 'devDependencies', 'optionalDependencies'].some((field) => manifest[field]?.[PACKAGE] !== undefined);
  } catch {
    return false;
  }
}

/** The migrations a deployment's installed coffre ships, through its server's own @coffre/db; null before an install. */
export function deploymentMigrations(dir: string): string[] | null {
  try {
    // From where pnpm keeps the server, its dependencies beside it; by @coffre/db's package.json,
    // which every condition resolves alike. Its build copies the migrations into dist.
    const server = createRequire(realpathSync(join(dir, 'node_modules', '@coffre', 'server', 'package.json')));
    return journalTags(join(dirname(server.resolve('@coffre/db/package.json')), 'dist', 'migrations', 'postgres'));
  } catch {
    return null;
  }
}

function journalTags(folder: string): string[] {
  const journal = JSON.parse(readFileSync(join(folder, 'meta', '_journal.json'), 'utf8')) as { entries: { tag: string }[] };
  return journal.entries.map((entry) => entry.tag);
}

/**
 * What moving from version `from` to `to` asks of the database, said once it
 * is installed: the migrations `after` has and `before` did not.
 */
export function migrationsAdded(from: string, to: string, before: readonly string[], after: readonly string[]): string {
  const added = after.filter((tag) => !before.includes(tag));
  if (added.length === 0) return `coffre ${to} adds no migration to ${from}'s: just deploy it.`;
  return (
    `coffre ${to} adds ${added.length === 1 ? '1 migration' : `${added.length} migrations`} to ${from}'s ` +
    `(${listed(added, 'and')}): run \`pnpm exec coffre migrate\` here first, then deploy.`
  );
}

/**
 * What updates a global CLI to `version`. A moved npm prefix is named: npm's own
 * would put a copy there, and this one would shadow it on PATH.
 */
export function updateCommand(how: Install & { kind: 'npm' | 'pnpm' }, version: string): readonly [string, readonly string[]] {
  if (how.kind === 'pnpm') return ['pnpm', ['add', '-g', `${PACKAGE}@${version}`]];
  return ['npm', ['install', '-g', ...(how.prefix === undefined ? [] : ['--prefix', how.prefix]), `${PACKAGE}@${version}`]];
}

/** What there is to say, and do, about a CLI its update leaves as it is: not npm's or pnpm's global. */
export function notUpdated(how: Exclude<Install, { kind: 'npm' | 'pnpm' }>, latest: string, deployment: string | null): { text: string; details: string[] } {
  switch (how.kind) {
    case 'npx':
      return { text: 'Nothing to update: npx runs the version it is given', details: [`npx ${PACKAGE}@${latest} … runs ${latest}`] };
    case 'checkout':
      return { text: 'Nothing to update here: this CLI runs from a checkout of coffre', details: ['git pull, then pnpm install and pnpm build'] };
    case 'project':
      return how.dir === deployment
        ? { text: `This CLI is one of the deployment's packages, updated with them below`, details: [] }
        : { text: `Nothing updated: this CLI is a dependency of ${how.dir}`, details: [`update it there: its @coffre/cli pin, to ${latest}`] };
    case 'unknown':
      // Neither npm nor pnpm says this CLI is its global, nor is it a project's: say so, and what each would run.
      return {
        text: "Nothing updated: coffre can't tell how this CLI was installed",
        details: [
          `It runs from ${how.path}, which neither npm nor pnpm lists as its global, nor is it a project's`,
          `Installed with npm: npm install -g ${PACKAGE}@${latest}`,
          `With pnpm: pnpm add -g ${PACKAGE}@${latest}`,
          `In a project: its ${PACKAGE} pin, to ${latest}, then its install`,
        ],
      };
  }
}

/** coffre's latest release, as the registry has it. */
async function latestVersion(): Promise<string> {
  const registry = (process.env.npm_config_registry ?? 'https://registry.npmjs.org/').replace(/\/?$/, '/');
  const response = await fetch(`${registry}${PACKAGE}/latest`, { headers: { accept: 'application/json' } });
  if (!response.ok) throw new Error(`${registry} answered ${response.status} for ${PACKAGE}`);
  return ((await response.json()) as { version: string }).version;
}

/**
 * Where `manager` keeps its global @coffre/cli, as its `ls -g` says, through
 * its links: null when it has none, undefined when it cannot say (not
 * installed, or pnpm with its bin directory off PATH). Asked from the home
 * directory, as globals are installed, not a project that pins a pnpm.
 */
export function globalCli(manager: 'npm' | 'pnpm', env: NodeJS.ProcessEnv = process.env, cwd = homedir()): string | null | undefined {
  const ran = spawnSync(manager, ['ls', '-g', '--json', '--depth', '0', '--long'], {
    cwd,
    encoding: 'utf8',
    timeout: 15_000,
    env: { ...env, COREPACK_ENABLE_DOWNLOAD_PROMPT: '0' },
  });
  let listed: unknown;
  try {
    listed = JSON.parse(ran.stdout);
  } catch {
    return undefined;
  }
  // pnpm lists each global directory, npm its one prefix.
  for (const each of [listed].flat() as { dependencies?: Record<string, { path?: string }> }[]) {
    const path = each?.dependencies?.[PACKAGE]?.path;
    if (typeof path !== 'string') continue;
    try {
      return realpathSync(path);
    } catch {
      return null;
    }
  }
  return ran.status === 0 ? null : undefined;
}

/** How this CLI was installed, asking npm and pnpm where their globals are. */
function thisInstall(self: string): Install {
  const pnpm = globalCli('pnpm');
  const home = pnpm === undefined && process.env.PNPM_HOME ? process.env.PNPM_HOME : null;
  return installOf(self, { npm: globalCli('npm') ?? null, pnpm: pnpm ?? null, pnpmHome: home === null ? null : realOr(home) });
}

function realOr(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return path;
  }
}

/** A command, its output kept to explain a failure. */
function command(name: string, args: string[], cwd: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(name, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, COREPACK_ENABLE_DOWNLOAD_PROMPT: '0' } });
    let output = '';
    child.stdout.setEncoding('utf8').on('data', (chunk: string) => (output += chunk));
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => (output += chunk));
    child.on('error', () => reject(new Error(`${name} is not installed`)));
    child.on('close', (code) => {
      if (code === 0) return resolve();
      // A pnpm that holds back new releases says so; coffre's are only as new as the release itself.
      if (/minimumReleaseAge|minimum-release-age/i.test(output)) {
        return reject(
          new Error(
            `${name} holds back releases newer than its minimumReleaseAge, and this one is new: wait, or allow @coffre/* ` +
              '(minimumReleaseAgeExclude), as a deployment coffre init writes does',
          ),
        );
      }
      reject(new Error(`${name} ${args.join(' ')} failed: ${output.trim().split('\n').slice(-3).join(' ')}`));
    });
  });
}

/**
 * What moving a deployment to a release changes of it, by that release's
 * template: the page files it adds and retires since the version the
 * deployment pins (none when its pins are not one version), its Start app's
 * pins, and its pnpm.
 */
export type Plan = { pages: Move; start: PinMove[]; packageManager: string | null };

/** A version as a deployment pins it: exact, never a range. */
const EXACT = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
/** A packageManager pnpm, as corepack takes it: an exact version, perhaps with its hash. */
const PNPM = /^pnpm@\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+sha(?:1|224|256|384|512)\.[0-9a-f]+)?$/;
const ROUTES = 'app/src/routes/';

/**
 * A plan another release's CLI wrote, as this one may make it, or why not:
 * its page files under the routes directory, each as the deployment in
 * `dir` has it now; its pins among the Start app's packages, at exact
 * versions; its pnpm, an exact one. A field this release does not know is
 * left out, for a later release may say more; one it knows, of another
 * shape, refuses the whole plan, before anything is changed.
 */
export function parsePlan(said: unknown, dir: string): Plan {
  const object = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
  const nullable = (value: unknown) => value === null || typeof value === 'string';
  if (!object(said)) throw new Error('not a plan');
  const { pages, start, packageManager } = said;
  if (packageManager !== null && !(typeof packageManager === 'string' && PNPM.test(packageManager))) {
    throw new Error(`packageManager ${JSON.stringify(packageManager)} is not an exact pnpm`);
  }
  if (!Array.isArray(start)) throw new Error('start is not a list');
  const pins = start.map((pin): PinMove => {
    if (!object(pin) || typeof pin.name !== 'string' || typeof pin.from !== 'string' || typeof pin.to !== 'string') throw new Error('a start pin is not a name, from and to');
    if (!(START_PACKAGES as readonly string[]).includes(pin.name)) throw new Error(`${pin.name} is not one of the Start app's packages`);
    if (!EXACT.test(pin.to)) throw new Error(`${pin.name} ${JSON.stringify(pin.to)} is not an exact version`);
    return { name: pin.name, from: pin.from, to: pin.to };
  });
  if (!object(pages)) throw new Error('pages is not a move');
  let move: Move;
  if (Array.isArray(pages.problems)) {
    if (!pages.problems.every((problem) => typeof problem === 'string')) throw new Error('a page problem is not a line');
    move = { problems: pages.problems as string[] };
  } else if (Array.isArray(pages.changes)) {
    move = {
      changes: pages.changes.map((change) => {
        if (!object(change) || typeof change.path !== 'string' || !nullable(change.was) || !nullable(change.becomes)) throw new Error('a page change is not a path, was and becomes');
        const { path } = change;
        // Relative, in the routes directory, and said once: no `..`, `.`, empty or Windows segment.
        if (!path.startsWith(ROUTES) || path.includes('\\') || path.slice(ROUTES.length).split('/').some((part) => part === '' || part === '.' || part === '..')) {
          throw new Error(`${JSON.stringify(path)} is not a file in ${ROUTES}`);
        }
        // The file as the plan saw it, or the plan is another deployment's: what it changes, it must know.
        const now = existsSync(join(dir, path)) ? readFileSync(join(dir, path), 'utf8') : null;
        if (now !== change.was) throw new Error(`${path} is not as it says it was`);
        return { path, was: change.was as string | null, becomes: change.becomes as string | null };
      }),
    };
  } else throw new Error('pages has neither changes nor problems');
  return { pages: move, start: pins, packageManager: packageManager as string | null };
}

/** The plan for moving the deployment in `dir`, of `kind`, to this CLI's release. */
export function planHere(dir: string, kind: Kind): Plan {
  const template = templateDir(kind);
  const pinned = [...new Set(Object.values(coffrePins(dir)))];
  return {
    pages: pinned.length === 1 ? pageMove(dir, template, pinned[0]!) : { changes: [] },
    start: startPinMoves(dir, template),
    packageManager: templatePackageManager(kind),
  };
}

/**
 * The plan for moving the deployment in `dir` to `version`, as that
 * release's own CLI says: a CLI of an earlier release knows neither the
 * pages it adds nor the pins it is built with. Its `coffre update --plan
 * <dir>` writes the plan as one line of JSON, an answer kept as it is from
 * release to release, as earlier CLIs ask it, and held to it (parsePlan).
 * That CLI is the package the deployment's install fetches: npm installs it
 * in an empty project of its own, with the deployment's .npmrc, so from its
 * registry, and never runs a copy of the same version another project or
 * the global prefix has, as npx would. Running it runs that release's
 * code: asked only once the move is agreed to.
 */
export async function planOf(version: string, dir: string, env: NodeJS.ProcessEnv = process.env): Promise<Plan> {
  const scratch = mkdtempSync(join(tmpdir(), 'coffre-plan-'));
  try {
    // Its package.json stops npm's search for a project above it.
    writeFileSync(join(scratch, 'package.json'), '{ "private": true }\n');
    if (existsSync(join(dir, '.npmrc'))) copyFileSync(join(dir, '.npmrc'), join(scratch, '.npmrc'));
    await output('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', '--no-package-lock', `${PACKAGE}@${version}`], scratch, env);
    const root = join(scratch, 'node_modules', PACKAGE);
    const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { version?: unknown; bin?: Record<string, unknown> };
    if (manifest.version !== version) throw new Error(`npm installed ${String(manifest.version)}`);
    const bin = manifest.bin?.coffre;
    if (typeof bin !== 'string') throw new Error('it has no coffre command');
    const said = (await output(process.execPath, [join(root, bin), 'update', '--plan', dir], scratch, env)).trim().split('\n').at(-1) ?? '';
    return parsePlan(JSON.parse(said), dir);
  } catch (error) {
    throw new Error(`coffre ${version}'s own CLI could not say what it changes (${error instanceof Error ? error.message : String(error)})`);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

/** What a command writes, or the last line of what it says, when it fails. */
function output(name: string, args: string[], cwd: string, env: NodeJS.ProcessEnv): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(name, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'], env: { ...env, COREPACK_ENABLE_DOWNLOAD_PROMPT: '0' } });
    let [stdout, stderr] = ['', ''];
    child.stdout.setEncoding('utf8').on('data', (chunk: string) => (stdout += chunk));
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
    child.on('error', () => reject(new Error(`${name} is not installed`)));
    child.on('close', (code) => (code === 0 ? resolve(stdout) : reject(new Error(stderr.trim().split('\n').at(-1) || `${name} exited with ${code}`))));
  });
}

/** `coffre update --plan <dir>`: the plan, for an earlier release's CLI that asks it. */
function writePlan(dir: string): void {
  const kind = deploymentKind(dir);
  if (kind !== 'workers' && kind !== 'node') {
    process.stderr.write(`${dir} holds no deployment coffre init wrote\n`);
    process.exit(1);
  }
  process.stdout.write(`${JSON.stringify(planHere(dir, kind))}\n`);
}

export async function update(args: string[]): Promise<void> {
  let yes: boolean;
  let plan: string | undefined;
  try {
    ({ yes, plan } = parseArgs({ args, options: { yes: { type: 'boolean', default: false }, plan: { type: 'string' } }, strict: true }).values);
  } catch {
    process.stderr.write('usage: coffre update [--yes]\n');
    process.exit(2);
  }
  if (plan !== undefined) return writePlan(plan);
  const terminal = openTerminal();
  const out = terminal?.out ?? process.stderr;
  const s = style(out);
  const keys = () => terminal?.keys ?? null;
  const ask = async (question: string, step: { ask(question: string): Promise<boolean> }) => {
    if (yes) return true;
    if (keys() === null) throw new Error('Not a terminal, so nothing to confirm on: pass --yes to update without asking.');
    return step.ask(question);
  };

  const current = cliVersion();
  const self = realpathSync(fileURLToPath(import.meta.url));
  const how = thisInstall(self);
  const dir = process.cwd();
  const kind = deploymentKind(dir);
  const deployment = kind === 'workers' || kind === 'node' ? dir : null;
  const pins = deployment === null ? {} : coffrePins(deployment);
  const pinned = [...new Set(Object.values(pins))];

  if (s.ansi) out.write(`\n  ${s.bold('coffre update')}  ${s.dim(`this CLI${deployment === null ? '' : ', and this deployment'}`)}\n\n`);
  const steps = new Steps(
    out,
    ["Look up coffre's latest release", 'Update this CLI', ...(deployment === null ? [] : ["Update this deployment's coffre packages"])],
    keys,
    (error) => (error instanceof Error ? error.message : String(error)),
  );
  // What the database had to know of before, and of after: this CLI's migrations, or the deployment's.
  let before: readonly string[] = (deployment === null ? null : deploymentMigrations(deployment)) ?? KNOWN_MIGRATIONS.postgres;
  // The version those are: the deployment's, or this CLI's.
  const from = deployment !== null && pinned.length === 1 ? pinned[0]! : current;
  let after: readonly string[] | null = null;
  let latest = current;
  try {
    await steps.run(0, async () => {
      latest = await latestVersion();
      // The next step says when this CLI is up to date; when it is not, this one says what it is.
      return `coffre ${latest} is the latest release${current === latest ? '' : `; this CLI is ${current}`}`;
    });
    await steps.run(1, async (step) => {
      if (current === latest) return `This CLI is up to date, at ${current}`;
      if (how.kind !== 'npm' && how.kind !== 'pnpm') return notUpdated(how, latest, deployment);
      const run = updateCommand(how, latest);
      if (!(await ask(`Update this CLI from ${current} to ${latest}, with ${run[0]} ${run[1].join(' ')}?`, step))) {
        return { text: `This CLI stays at ${current}`, details: [] };
      }
      step.note(`Updating this CLI, with ${run[0]}`);
      await command(run[0], [...run[1]], homedir());
      // The new CLI's migrations ship in it, where its manager keeps it now: not where this one ran, under pnpm.
      const updated = how.kind === 'npm' && how.dir !== undefined ? how.dir : globalCli(how.kind);
      try {
        if (updated) after ??= journalTags(join(updated, 'dist', 'migrations', 'postgres'));
      } catch {
        // Without them, the release's migrations go unsaid; the update itself is done.
      }
      return `Updated this CLI from ${current} to ${latest}, with ${run[0]}`;
    });
    if (deployment !== null) {
      await steps.run(2, async (step) => {
        const was = pinned.length === 1 ? pinned[0]! : listed(pinned, 'and');
        // A deployment from before the clean break is deployed afresh, not moved.
        if (pinned.some((version) => later(CLEAN_BREAK, version))) {
          // Nothing to migrate either: what the new CLI's migrations add is no step for a deployment deployed afresh.
          after = null;
          return {
            text: `This deployment stays as it is, at ${was}: coffre ${CLEAN_BREAK} was a clean break, and moves no deployment from before it. Nothing was changed`,
            details: [`Deploy coffre ${latest} afresh, with coffre init (docs/deploy.md, "From a release before ${CLEAN_BREAK}")`],
          };
        }
        const atLatest = pinned.length === 1 && pinned[0] === latest;
        // What the release changes, as it says: this CLI's own template is its release's, perhaps an earlier one.
        // Its own CLI says it by running, so the move is agreed to before, once, and then made as it says.
        let plan: Plan;
        const agreed = current !== latest;
        if (!agreed) plan = planHere(deployment, kind as Kind);
        else {
          const question = atLatest
            ? `Bring this deployment's pages and pins to coffre ${latest}'s, as its own CLI says, and install it?`
            : `Move this deployment from ${was} to ${latest}, with the pages and pins its own CLI says, and install it?`;
          step.under([`To say what changes, coffre ${latest}'s own CLI runs, fetched with npm; then that changes, unasked`]);
          const accepted = await ask(question, step);
          step.under([]);
          if (!accepted) return { text: `This deployment stays as it is, at ${was}`, details: [] };
          step.note(`Asking coffre ${latest}'s own CLI what it changes`);
          try {
            plan = await planOf(latest, deployment);
          } catch (error) {
            // Not done, so not a success, which a pipeline would take it for.
            throw new Error(`${error instanceof Error ? error.message : String(error)}. Nothing was changed: run coffre ${latest}'s own, npx ${PACKAGE}@${latest} update`);
          }
        }
        const details: string[] = [];
        // Exclusions an earlier run wrote, whose packages have cleared since: gone first.
        const cleared = removeCleared(deployment, new Date());
        if (cleared.length > 0) details.push(`No longer excluded from minimumReleaseAge, now old enough: ${listed(cleared, 'and')}`);
        const pnpm = plan.packageManager;
        const repin = pnpm !== null && coffrePackageManager(deployment) !== pnpm;
        // The deployment gains the pages coffre has added since its release, and loses those it retired.
        const pages = plan.pages;
        if ('problems' in pages) {
          return {
            text: `This deployment stays as it is, at ${was}: coffre ${latest}'s pages are not all where this one's are. Nothing was changed`,
            details: [...details, ...pages.problems],
          };
        }
        const move = pages.changes;
        // What its Start app builds with, as the release's pages are built with.
        const shared = plan.start;
        if (atLatest && !repin && move.length === 0 && shared.length === 0) {
          return { text: `This deployment's coffre packages are at ${latest} already`, details };
        }
        // Asked here when no other release's code had to run to say what changes; shown first.
        if (!agreed) {
          const on = pnpm?.replace('@', ' ');
          const question = atLatest
            ? move.length > 0
              ? "Change coffre's page files, as above, and install it?"
              : repin
                ? `Pin this deployment to ${on}, as coffre installs with, and install it?`
                : `Move its Start app's packages to the versions coffre ${latest} is built with, and install it?`
            : `Move this deployment from ${was} to ${latest}${move.length > 0 ? ", with coffre's pages as above," : ''}${repin ? ` on ${on},` : ''} and install it?`;
          step.under([...move.flatMap((change) => shownChange(change)), ...(move.length > 0 ? [`~ ${ROUTE_TREE}, regenerated`] : []), ...shared.map(({ name, from, to }) => `~ ${name} ${from} → ${to}`)]);
          const accepted = await ask(question, step);
          step.under([]);
          if (!accepted) return { text: `This deployment stays as it is, at ${was}`, details };
        }

        // Put back byte for byte however this ends short of installed: the
        // deployment's pins, pnpm and lockfile stay as they were.
        const names = [...new Set(['package.json', 'pnpm-workspace.yaml', 'pnpm-lock.yaml', ...move.map(({ path }) => path), ...(move.length > 0 ? [ROUTE_TREE] : [])])];
        const files = names.map((name) => {
          const path = join(deployment, name);
          return { path, text: existsSync(path) ? readFileSync(path, 'utf8') : null };
        });
        const restore = () => {
          for (const { path, text } of files) {
            if (text === null) rmSync(path, { force: true });
            else writeFileSync(path, text);
          }
        };
        const kept = `${listed(names, 'and')} are as they were`;
        /**
         * No version old enough fits: wait, everything as it was, or let
         * these through by name, each until it is old enough. Never asked
         * without a terminal, nor with --yes: then it waits, and says so.
         */
        const decide = async (error: HeldBack): Promise<{ until: Date | null; lines: string[] }> => {
          const age = minimumReleaseAge(deployment);
          const clears = error.held
            .map(({ spec, publishedAt }) => ({ spec, clears: new Date(publishedAt.getTime() + age * 60_000) }))
            .sort((x, y) => x.clears.getTime() - y.clears.getTime());
          const last = clears.at(-1)!.clears;
          const lines = clears.map(({ spec, clears: at }) => `${spec}, old enough from ${when(at)}`);
          const heading =
            `pnpm holds back ${clears.length === 1 ? '1 package' : `${clears.length} packages`} younger than this ` +
            `deployment's minimumReleaseAge, ${days(age)}, and no older version fits`;
          if (yes || keys() === null) {
            throw new HeldBack(error.held, `${heading}: ${lines.join('; ')}. Run coffre update after ${when(last)}, or on a terminal to let them through until then`);
          }
          step.under(lines);
          const choice = await step.choose(heading, [
            `Wait: stay at ${was}, and run coffre update again after ${when(last)}`,
            `Proceed: let ${clears.length === 1 ? 'it' : 'these'} through until each is old enough, named in pnpm-workspace.yaml`,
          ]);
          step.under([]);
          if (choice === 0) {
            restore();
            return { until: last, lines: [...lines, `${kept}. Run coffre update again after ${when(last)}`] };
          }
          excludeUntil(deployment, clears, `for coffre ${latest}`);
          return {
            until: null,
            lines: [
              'Let through until each is old enough, named in pnpm-workspace.yaml:',
              ...clears.map(({ spec, clears: at }) => `  ${spec}, until ${when(at)}`),
              `The first coffre update after ${when(last)} removes them`,
            ],
          };
        };
        try {
          // Its migrations now are its installed server's: a fresh clone installs first, as its lockfile says.
          if (existsSync(join(deployment, 'pnpm-lock.yaml')) && !installed(deployment)) {
            step.note('Installing its packages as they are, to know its migrations');
            await installAsLocked(deployment);
            details.push('Installed its packages as they were, as pnpm-lock.yaml says, to know its migrations');
          }
          before = deploymentMigrations(deployment) ?? before;
          if (move.length > 0) {
            applyChanges(deployment, move);
            details.push(`Changed coffre's page files: ${listed(move.map(({ path }) => path), 'and')}`);
          }
          if (shared.length > 0) {
            movePins(deployment, shared);
            details.push(`Moved its Start app's ${listed(shared.map(({ name, to }) => `${name} to ${to}`), 'and')}, as coffre's pages are built with`);
          }
          bumpPins(deployment, latest);
          if (repin) {
            const replaced = pinPackageManager(deployment, pnpm!);
            details.push(`Pinned ${pnpm}${replaced ? `, not ${replaced}` : ''}: every install, here and in CI, holds minimumReleaseAge alike`);
          }
          step.note(`Installing coffre ${latest}'s packages, with pnpm`);
          try {
            await install(deployment, { purge: true });
          } catch (error) {
            if (!(error instanceof HeldBack)) throw error;
            // A lockfile another pnpm wrote can hold versions too young for
            // this one; resolving again picks versions old enough, when the
            // ranges allow, and needs nothing let through.
            step.note('Resolving again, for versions old enough');
            try {
              const moved = await resolveAgain(deployment);
              details.push(`Resolved again, for versions old enough, as ${error.held.map(({ spec }) => spec).join(', ')} held back:`, ...movedLines(moved, error.held));
            } catch (again) {
              if (!(again instanceof HeldBack)) throw again;
              const decided = await decide(again);
              if (decided.until !== null) {
                return { text: `This deployment stays at ${was}, until ${when(decided.until)}`, details: decided.lines };
              }
              step.note(`Installing coffre ${latest}'s packages, with pnpm`);
              const moved = await resolveAgain(deployment);
              details.push(...decided.lines, ...movedLines(moved, again.held));
            }
          }
        } catch (error) {
          restore();
          if (error instanceof Cancelled) throw error;
          const reason = error instanceof Error ? error.message : String(error);
          throw new Error(`${reason}. ${kept}${error instanceof HeldBack ? '' : '; node_modules may be incomplete, which pnpm install puts right'}`);
        }
        after = deploymentMigrations(deployment) ?? after;
        // The tree its build would write, from the files now there, by the version now installed: a diff that is whole.
        if (move.length > 0) {
          step.note('Regenerating its route tree');
          try {
            if (await generateRouteTree(deployment)) details.push(`Regenerated ${ROUTE_TREE}, as the build writes it, for those page files`);
          } catch (error) {
            details.push(`Could not regenerate ${ROUTE_TREE} (${error instanceof Error ? error.message : String(error)}): the next build writes it`);
          }
        }
        return {
          text: atLatest ? `Pinned ${pnpm}, and installed it` : `Moved this deployment from ${was} to ${latest}, and installed it`,
          details,
        };
      });
    }
  } catch (error) {
    if (error instanceof Cancelled) finish(out, `${s.red('✗')} cancelled; nothing after the last step done was changed`, 130);
    if (error instanceof StepFailed) finish(out, '', 1);
    finish(out, `${s.red('✗')} ${error instanceof Error ? error.message : String(error)}`, 1);
  } finally {
    steps.end();
    if (terminal !== null) release(terminal.keys);
  }

  out.write('\n');
  if (after !== null) {
    out.write(`  ${migrationsAdded(from, latest, before, after)}\n`);
    if (deployment !== null) {
      const deploy =
        kind === 'node'
          ? 'Restart the server to deploy it.'
          : existsSync(join(deployment, WORKFLOW))
            ? `Commit and push to main to deploy it, with ${WORKFLOW}.`
            : 'Deploy it with `pnpm run deploy`.';
      out.write(`  ${s.dim(deploy)}\n`);
    }
    out.write('\n');
  }
}

/** The pnpm coffre installs with, as the template of a deployment of `kind` pins it. */
function templatePackageManager(kind: Kind): string | null {
  try {
    return (JSON.parse(readFileSync(join(templateDir(kind), 'package.json'), 'utf8')) as { packageManager?: string }).packageManager ?? null;
  } catch {
    return null;
  }
}

function coffrePackageManager(dir: string): string | undefined {
  return (JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as { packageManager?: string }).packageManager;
}

/**
 * What a fresh resolution moved, the held packages first: every package
 * may move within its range, so each is said, up to a screenful.
 */
export function movedLines(moved: Moved[], held: Held[]): string[] {
  const named = new Set(held.map(({ spec }) => spec.slice(0, spec.lastIndexOf('@'))));
  const ordered = [...moved.filter(({ name }) => named.has(name)), ...moved.filter(({ name }) => !named.has(name))];
  const shown = ordered.slice(0, 8).map(({ name, from, to }) => `  ${name} ${from.join(', ') || 'none'} → ${to.join(', ') || 'none'}`);
  return ordered.length > shown.length ? [...shown, `  and ${ordered.length - shown.length} more, in pnpm-lock.yaml`] : shown;
}

/** A moment, to the minute, in UTC: when a package is old enough. */
export function when(date: Date): string {
  return `${date.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

function days(minutes: number): string {
  const d = minutes / (24 * 60);
  return Number.isInteger(d) ? `${d} day${d === 1 ? '' : 's'}` : `${minutes} minutes`;
}

function finish(out: Output, message: string, code: number): never {
  if (message !== '') out.write(`${message}\n`);
  process.exit(code);
}

