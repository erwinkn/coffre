// `coffre update`: this CLI, to coffre's latest release, the way it was
// installed; and, run in a deployment, its coffre packages too. Then what
// the release changes for the database: the migrations it adds, which
// `coffre migrate` applies once the new version is deployed.
import { spawn, spawnSync } from 'node:child_process';
import { readFileSync, realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

import { KNOWN_MIGRATIONS } from '@coffre/db/schema-version';

import { bumpPins, coffrePins, deploymentKind, install } from './deployment.ts';
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
  | { kind: 'unknown' };

/**
 * How the CLI at `path` was installed: under npx's cache, a global root
 * (`npm root -g`, `pnpm root -g`), a project's node_modules, or a checkout.
 */
export function installOf(path: string, roots: { npm: string | null; pnpm: string | null }): Install {
  if (path.includes(`${sep}_npx${sep}`)) return { kind: 'npx' };
  // pnpm's global packages live in a store beside its root's node_modules.
  if (roots.pnpm !== null && path.startsWith(dirname(roots.pnpm) + sep)) return { kind: 'pnpm' };
  if (roots.npm !== null && path.startsWith(roots.npm + sep)) return { kind: 'npm' };
  const modules = path.lastIndexOf(`${sep}node_modules${sep}`);
  if (modules !== -1) return { kind: 'project', dir: path.slice(0, modules) };
  if (path.includes(`${sep}packages${sep}cli${sep}`)) return { kind: 'checkout' };
  return { kind: 'unknown' };
}

/** The migrations a deployment's installed coffre ships, through its server's own @coffre/db; null before an install. */
export function deploymentMigrations(dir: string): string[] | null {
  try {
    const server = createRequire(join(dir, 'node_modules', '@coffre', 'server', 'package.json'));
    return journalTags(join(dirname(server.resolve('@coffre/db/migrate')), 'migrations', 'postgres'));
  } catch {
    return null;
  }
}

function journalTags(folder: string): string[] {
  const journal = JSON.parse(readFileSync(join(folder, 'meta', '_journal.json'), 'utf8')) as { entries: { tag: string }[] };
  return journal.entries.map((entry) => entry.tag);
}

/**
 * What a release adds for the database, said once it is installed: the
 * migrations `after` has and `before` did not.
 */
export function migrationsAdded(version: string, before: readonly string[], after: readonly string[]): string {
  const added = after.filter((tag) => !before.includes(tag));
  if (added.length === 0) return `coffre ${version} adds no migration: deploying it is all.`;
  return (
    `coffre ${version} adds ${added.length === 1 ? '1 migration' : `${added.length} migrations`} (${listed(added, 'and')}): ` +
    'after deploying, run `coffre migrate`.'
  );
}

/** coffre's latest release, as the registry has it. */
async function latestVersion(): Promise<string> {
  const registry = (process.env.npm_config_registry ?? 'https://registry.npmjs.org/').replace(/\/?$/, '/');
  const response = await fetch(`${registry}${PACKAGE}/latest`, { headers: { accept: 'application/json' } });
  if (!response.ok) throw new Error(`${registry} answered ${response.status} for ${PACKAGE}`);
  return ((await response.json()) as { version: string }).version;
}

function globalRoot(manager: 'npm' | 'pnpm'): string | null {
  const ran = spawnSync(manager, ['root', '-g'], { encoding: 'utf8', timeout: 10_000 });
  const root = ran.status === 0 ? ran.stdout.trim() : '';
  return root === '' ? null : realpathSync(root);
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
    if (keys() === null) throw new Error('nothing here to confirm on: run coffre update on a terminal, or pass --yes');
    return step.ask(question);
  };

  const current = cliVersion();
  const self = realpathSync(fileURLToPath(import.meta.url));
  const how = installOf(self, { npm: globalRoot('npm'), pnpm: globalRoot('pnpm') });
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
  let after: readonly string[] | null = null;
  let latest = current;
  try {
    await steps.run(0, async () => {
      latest = await latestVersion();
      return `coffre ${latest} is the latest release; this CLI is ${current}`;
    });
    await steps.run(1, async (step) => {
      if (current === latest) return `This CLI is up to date, at ${current}`;
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
          return { text: 'Nothing updated: where this CLI was installed from is unclear', details: [`npm install -g ${PACKAGE}@${latest}, or pnpm add -g ${PACKAGE}@${latest}`] };
        default: {
          const run = how.kind === 'npm' ? ['npm', ['install', '-g', `${PACKAGE}@${latest}`]] as const : ['pnpm', ['add', '-g', `${PACKAGE}@${latest}`]] as const;
          if (!(await ask(`Update this CLI from ${current} to ${latest}, with ${run[0]} ${run[1].join(' ')}?`, step))) {
            return { text: `This CLI stays at ${current}`, details: [] };
          }
          step.note(`Updating this CLI, with ${run[0]}`);
          await command(run[0], [...run[1]], dir);
          // The new CLI is where this one was: its migrations ship beside it.
          after ??= journalTags(join(dirname(self), 'migrations', 'postgres'));
          return `Updated this CLI from ${current} to ${latest}, with ${run[0]}`;
        }
      }
    });
    if (deployment !== null) {
      await steps.run(2, async (step) => {
        if (pinned.length === 1 && pinned[0] === latest) return `This deployment's coffre packages are at ${latest} already`;
        const from = pinned.length === 1 ? pinned[0] : listed(pinned, 'and');
        if (!(await ask(`Move this deployment's coffre packages from ${from} to ${latest}, and install them?`, step))) {
          return { text: `This deployment stays at ${from}`, details: [] };
        }
        before = deploymentMigrations(deployment) ?? before;
        bumpPins(deployment, latest);
        step.note(`Installing coffre ${latest}'s packages, with pnpm`);
        await install(deployment);
        after = deploymentMigrations(deployment) ?? after;
        return {
          text: `Moved this deployment from ${from} to ${latest}, and installed it`,
          // Coffre's own packages are exempt from the deployment's minimumReleaseAge: a fix lands the day it is out.
          details: [`${listed(Object.keys(pins), 'and')}; your other packages still wait out minimumReleaseAge`],
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
    out.write(`  ${migrationsAdded(latest, before, after)}\n`);
    if (deployment !== null) {
      const deploy = kind === 'workers' ? '`pnpm run deploy`, or a push for Workers Builds' : 'restarting the server';
      out.write(`  ${s.dim(`Deploy it as you do: ${deploy}.`)}\n`);
    }
    out.write('\n');
  }
}

function finish(out: Output, message: string, code: number): never {
  if (message !== '') out.write(`${message}\n`);
  process.exit(code);
}

