// `coffre update`: this CLI, to coffre's latest release, the way it was
// installed; and, run in a deployment, its coffre packages too. Then what
// the release changes for the database: the migrations it adds, which
// `coffre migrate` applies before the new version is deployed.
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { homedir } from 'node:os';
import { dirname, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

import { KNOWN_MIGRATIONS } from '@coffre/db/schema-version';

import {
  bumpPins,
  coffrePins,
  deploymentKind,
  excludeUntil,
  HeldBack,
  install,
  installAsLocked,
  installed,
  minimumReleaseAge,
  pinPackageManager,
  removeCleared,
  resolveAgain,
  movePins,
  startPinMoves,
  type Held,
  type Moved,
} from './deployment.ts';
import { templateDir, type Kind } from './init.ts';
import { after as later, applyChanges, CLEAN_BREAK, pageMove, shownChange } from './layout.ts';
import { StepFailed, Steps } from './steps.ts';
import { Cancelled, listed, openTerminal, type Output, release, style } from './tty.ts';
import { cliVersion } from './version.ts';

const PACKAGE = '@coffre/cli';

/** How this CLI came to be here, which says how to update it. */
export type Install =
  | { kind: 'npm' }
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
export function installOf(path: string, globals: Globals, isProject: (dir: string) => boolean = dependsOnCli): Install {
  const within = (dir: string | null) => dir !== null && (path === dir || path.startsWith(dir + sep));
  if (path.includes(`${sep}_npx${sep}`)) return { kind: 'npx' };
  if (within(globals.pnpm)) return { kind: 'pnpm' };
  if (within(globals.npm)) return { kind: 'npm' };
  if (within(globals.pnpmHome)) return { kind: 'pnpm' };
  // The project is where its node_modules starts: pnpm's own packages are further down, in node_modules/.pnpm.
  const modules = path.indexOf(`${sep}node_modules${sep}`);
  if (modules !== -1) return isProject(path.slice(0, modules)) ? { kind: 'project', dir: path.slice(0, modules) } : { kind: 'unknown', path };
  if (path.includes(`${sep}packages${sep}cli${sep}`)) return { kind: 'checkout' };
  return { kind: 'unknown', path };
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
  if (added.length === 0) return `coffre ${to} adds no migration to ${from}'s: deploying it is all.`;
  return (
    `coffre ${to} adds ${added.length === 1 ? '1 migration' : `${added.length} migrations`} to ${from}'s ` +
    `(${listed(added, 'and')}): run \`pnpm exec coffre migrate\` here first, then deploy.`
  );
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

export async function update(args: string[]): Promise<void> {
  let yes: boolean;
  try {
    ({ yes } = parseArgs({ args, options: { yes: { type: 'boolean', default: false } }, strict: true }).values);
  } catch {
    process.stderr.write('usage: coffre update [--yes]\n');
    process.exit(2);
  }
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
      return `coffre ${latest} is the latest release; this CLI is ${current}`;
    });
    await steps.run(1, async (step) => {
      if (current === latest) return `This CLI is up to date, at ${current}`;
      if (how.kind !== 'npm' && how.kind !== 'pnpm') return notUpdated(how, latest, deployment);
      const run = how.kind === 'npm' ? ['npm', ['install', '-g', `${PACKAGE}@${latest}`]] as const : ['pnpm', ['add', '-g', `${PACKAGE}@${latest}`]] as const;
      if (!(await ask(`Update this CLI from ${current} to ${latest}, with ${run[0]} ${run[1].join(' ')}?`, step))) {
        return { text: `This CLI stays at ${current}`, details: [] };
      }
      step.note(`Updating this CLI, with ${run[0]}`);
      await command(run[0], [...run[1]], homedir());
      // The new CLI's migrations ship in it, where its manager keeps it now: not where this one ran, under pnpm.
      const updated = globalCli(how.kind);
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
          return {
            text: `This deployment stays as it is, at ${was}: coffre ${CLEAN_BREAK} was a clean break, and moves no deployment from before it. Nothing was changed`,
            details: [`Deploy coffre ${latest} afresh, with coffre init (docs/deploy.md, "From a release before ${CLEAN_BREAK}")`],
          };
        }
        const details: string[] = [];
        // Exclusions an earlier run wrote, whose packages have cleared since: gone first.
        const cleared = removeCleared(deployment, new Date());
        if (cleared.length > 0) details.push(`No longer excluded from minimumReleaseAge, now old enough: ${listed(cleared, 'and')}`);
        const template = templateDir(kind as Kind);
        const pnpm = templatePackageManager(kind as Kind);
        const repin = pnpm !== null && coffrePackageManager(deployment) !== pnpm;
        // The deployment gains the pages coffre has added since its release, and loses those it retired.
        const pages = pinned.length !== 1 ? { changes: [] } : pageMove(deployment, template, pinned[0]!);
        if ('problems' in pages) {
          return {
            text: `This deployment stays as it is, at ${was}: coffre ${latest}'s pages are not all where this one's are. Nothing was changed`,
            details: [...details, ...pages.problems],
          };
        }
        const move = pages.changes;
        // What its Start app builds with, as the release's pages are built with.
        const shared = startPinMoves(deployment, template);
        const current = pinned.length === 1 && pinned[0] === latest;
        if (current && !repin && move.length === 0 && shared.length === 0) {
          return { text: `This deployment's coffre packages are at ${latest} already`, details };
        }
        const on = pnpm?.replace('@', ' ');
        const question = current
          ? move.length > 0
            ? "Change coffre's page files, as above, and install it?"
            : repin
              ? `Pin this deployment to ${on}, as coffre installs with, and install it?`
              : `Move its Start app's packages to the versions coffre ${latest} is built with, and install it?`
          : `Move this deployment from ${was} to ${latest}${move.length > 0 ? ", with coffre's pages as above," : ''}${repin ? ` on ${on},` : ''} and install it?`;
        step.under([...move.flatMap((change) => shownChange(change)), ...shared.map(({ name, from, to }) => `~ ${name} ${from} → ${to}`)]);
        const accepted = await ask(question, step);
        step.under([]);
        if (!accepted) return { text: `This deployment stays as it is, at ${was}`, details };

        // Put back byte for byte however this ends short of installed: the
        // deployment's pins, pnpm and lockfile stay as they were.
        const files = [...new Set(['package.json', 'pnpm-workspace.yaml', 'pnpm-lock.yaml', ...move.map(({ path }) => path)])].map((name) => {
          const path = join(deployment, name);
          return { path, text: existsSync(path) ? readFileSync(path, 'utf8') : null };
        });
        const restore = () => {
          for (const { path, text } of files) {
            if (text === null) rmSync(path, { force: true });
            else writeFileSync(path, text);
          }
        };
        const kept =
          move.length > 0
            ? `${listed([...new Set(['package.json', 'pnpm-workspace.yaml', 'pnpm-lock.yaml', ...move.map(({ path }) => path)])], 'and')} are as they were`
            : 'package.json, pnpm-workspace.yaml and pnpm-lock.yaml are as they were';
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
            details.push(`Pinned ${pnpm}${replaced ? `, not ${replaced}` : ''}: every install, here, in CI and on Workers Builds, holds minimumReleaseAge alike`);
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
        return {
          text: current ? `Pinned ${pnpm}, and installed it` : `Moved this deployment from ${was} to ${latest}, and installed it`,
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
      const deploy = kind === 'workers' ? '`pnpm run deploy`, or a push for Workers Builds, whose builds migrate first' : 'restarting the server';
      out.write(`  ${s.dim(`Deploy it as you do: ${deploy}.`)}\n`);
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

