// `coffre migrate`: bring a deployment's database up to the schema of the
// version it pins, with the migrations this CLI carries, which must be that
// version's. Its pipeline runs it in the deployment's folder before every
// deploy: the app it deploys serves nothing until its migrations have run
// (503 `migrating`), and the app before it keeps serving on the new schema
// until then, as every migration lets it.
//
// It asks for the database owner's direct URL, at a hidden prompt or on
// stdin, never the command line; shows what it will apply; and applies it
// under the migration lock, with the privileges reasserted. Without a
// terminal, only with --yes. With nothing to apply, it asks nothing: it
// reasserts the privileges, as every run does. --backup-login <role> grants
// that existing role the read-only group coffre_backup, on every run, asked
// or not; coffre never makes the role, and never revokes the group from it.
import { parseArgs } from 'node:util';

import { AfterMigrations, backupLoginProblem, DatabaseAhead, migrateDatabase, migrationStatus, NotOwner } from '@coffre/db/migrate';

import { readDatabaseUrl } from './database-url.ts';
import { coffrePins, deploymentKind } from './deployment.ts';
import { type Step, StepFailed, Steps } from './steps.ts';
import { Cancelled, type Keyboard, listed, openTerminal, type Output, release, style } from './tty.ts';
import { cliVersion } from './version.ts';

class MigrateError extends Error {}

/** A deployment's folder: where it is, and the one version its `@coffre/*` packages are pinned at. */
export type Deployment = { dir: string; version: string };

/** The deployment `dir` holds, as `coffre init` writes one; null for a folder that holds none. */
export function deploymentAt(dir: string): Deployment | null {
  const kind = deploymentKind(dir);
  if (kind !== 'workers' && kind !== 'node') return null;
  const versions = [...new Set(Object.values(coffrePins(dir)))];
  if (versions.length !== 1) {
    throw new MigrateError(
      `this deployment's @coffre/* packages are pinned at ${versions.length === 0 ? 'no version' : listed(versions, 'and')}, not one: ` +
        '`coffre update` moves them together',
    );
  }
  return { dir, version: versions[0]! };
}

/**
 * Why this CLI may not migrate a deployment that pins `pinned`: the
 * migrations it carries are its own version's. Null when they agree.
 */
export function pinProblem(cli: string, pinned: string): string | null {
  if (cli === pinned) return null;
  return `this deployment pins coffre ${pinned}, and this CLI is ${cli}, whose migrations are another version's: ` +
    "migrate with the deployment's own, `pnpm exec coffre migrate`, after `pnpm install`";
}

/**
 * A migration's refusal, as Postgres raised it: the migration's own sentence,
 * not the SQL around it.
 */
export function migrationFailure(error: unknown): string {
  if (error instanceof NotOwner) return `${error.message}. Nothing was changed`;
  // After the migrations' transaction: what it applied stays.
  if (error instanceof AfterMigrations) return error.message;
  for (let cause: unknown = error; cause instanceof Error; cause = cause.cause) {
    const code = (cause as { code?: unknown }).code;
    if (typeof code === 'string' && /^[0-9A-Z]{5}$/.test(code)) {
      return `${cause.message}. Nothing was changed: the migrations run in one transaction.`;
    }
  }
  return error instanceof Error ? error.message : String(error);
}

type Options = { yes: boolean; backupLogin?: string };

export async function migrate(args: string[]): Promise<void> {
  const secrets: string[] = [];
  const clean = (error: unknown) => redact(error instanceof Error ? error.message : String(error), secrets);
  let options: Options;
  try {
    options = parseOptions(args);
  } catch (error) {
    return fail(process.stderr, clean(error));
  }
  const terminal = openTerminal();
  const out = terminal?.out ?? process.stderr;
  try {
    const deployment = deploymentAt(process.cwd());
    if (deployment === null) {
      throw new MigrateError(
        "coffre migrate runs in a deployment's folder, as its pipeline does before each deploy, with the migrations of the version it pins: " +
          'there, `pnpm exec coffre migrate`',
      );
    }
    await migrateDeployment(deployment, options, out, terminal, secrets, clean);
  } catch (error) {
    if (error instanceof Cancelled) return fail(out, 'cancelled; nothing was changed', 130);
    if (!(error instanceof StepFailed)) return fail(out, clean(error));
    process.exit(1);
  } finally {
    if (terminal !== null) release(terminal.keys);
  }
}

/**
 * In a deployment's folder: its database to the schema of the version it
 * pins, which this CLI must be. What its pipeline runs before the deploy.
 */
async function migrateDeployment(
  deployment: Deployment,
  options: Options,
  out: Output,
  terminal: { keys: Keyboard } | null,
  secrets: string[],
  clean: (error: unknown) => string,
): Promise<void> {
  const s = style(out);
  const problem = pinProblem(cliVersion(), deployment.version);
  if (problem !== null) throw new MigrateError(problem);

  if (s.ansi) out.write(`\n  ${s.bold('coffre migrate')}  ${s.dim(`this deployment, coffre ${deployment.version}`)}\n\n`);
  const { url, secrets: typed } = await readDatabaseUrl(out, s, {
    question: "The database owner's connection string",
    hint: "Hidden as you type. The login that owns coffre's tables, direct: not a runtime login, not Hyperdrive.",
    command: 'coffre migrate',
  });
  secrets.push(...typed);
  const where = `${url.hostname}${decodeURIComponent(url.pathname)}`;
  let status: Awaited<ReturnType<typeof migrationStatus>>;
  try {
    status = await migrationStatus(url.href);
  } catch (error) {
    if (error instanceof NotOwner) throw new MigrateError(migrationFailure(error));
    if (!(error instanceof DatabaseAhead)) throw error;
    throw new MigrateError(
      `${where} is ahead of coffre ${deployment.version}: ${error.message.replace(/^the database /, '')}. ` +
        'Deploy that version, or, to go back, restore the database from before it (docs/restore.md). Nothing was changed',
    );
  }
  const { applied, pending, notOwner } = status;
  if (pending.length === 0) {
    // Nothing to apply now, but the next release's migrations would be refused: said while there is time.
    if (notOwner !== null) {
      if (options.backupLogin !== undefined) throw new MigrateError(`${notOwner.message}. Nothing was changed`);
      out.write(`${s.green('✓')} ${where} is up to date, at coffre ${deployment.version}'s schema: ${count(applied.length, 'migration')}, the last ${applied.at(-1)}\n`);
      out.write(`  ${s.dim(`The next migration needs another login: ${notOwner.message}`)}\n`);
      return;
    }
    // What every run does with nothing to apply: the privileges a restore leaves out, and the backup login's group.
    try {
      await migrateDatabase(url.href, { backupLogin: options.backupLogin });
    } catch (error) {
      throw new MigrateError(migrationFailure(error));
    }
    out.write(`${s.green('✓')} ${where} is up to date, at coffre ${deployment.version}'s schema: ${count(applied.length, 'migration')}, the last ${applied.at(-1)}; ${reasserted(options)}\n`);
    return;
  }
  if (notOwner !== null) throw new MigrateError(`${notOwner.message}. Nothing was changed`);
  if (!options.yes && terminal === null) {
    throw new MigrateError('Not a terminal, so nothing to confirm on: pass --yes to migrate without asking.');
  }
  out.write(`  ${count(pending.length, 'migration')} to apply to ${where}, for coffre ${deployment.version}: ${listed(pending, 'and')}\n\n`);
  const steps = new Steps(out, [`Apply ${listed(pending, 'and')}`], () => terminal?.keys ?? null, clean);
  try {
    await steps.run(0, (step) => apply(url, where, pending, step, options));
  } finally {
    steps.end();
  }
}

/** Apply `pending` to the database, asking first unless told yes. */
async function apply(url: URL, where: string, pending: string[], step: Step, options: Options): Promise<string> {
  if (!options.yes && !(await step.ask(`Apply ${count(pending.length, 'migration')} to ${where}?`))) throw new Cancelled();
  step.note(`Applying ${listed(pending, 'and')}`);
  try {
    await migrateDatabase(url.href, {
      backupLogin: options.backupLogin,
      onPlan(plan) {
        // Under the lock now: what was read before, or another run got there first.
        if (plan.pending.join() !== pending.join()) {
          throw new MigrateError(`another migration ran meanwhile: ${where} now lacks ${listed(plan.pending, 'and') || 'nothing'}`);
        }
      },
    });
  } catch (error) {
    if (error instanceof MigrateError) throw error;
    throw new MigrateError(migrationFailure(error));
  }
  return `Applied ${listed(pending, 'and')}, and ${reasserted(options)}`;
}

function reasserted({ backupLogin }: Options): string {
  return `reasserted the database's privileges${backupLogin === undefined ? '' : ` and ${backupLogin}'s membership in coffre_backup`}`;
}

function parseOptions(args: string[]): Options {
  let values;
  try {
    ({ values } = parseArgs({
      args,
      options: { yes: { type: 'boolean', default: false }, 'backup-login': { type: 'string' } },
      strict: true,
    }));
  } catch {
    // The error would quote the argument, which may be the connection string itself.
    const leaked = args.some((arg) => /postgres(ql)?:|@/i.test(arg));
    throw new MigrateError(
      'coffre migrate takes only --yes and --backup-login <role>. ' +
        `It asks for the database owner's connection string, at a hidden prompt or on stdin, ` +
        `never from the command line, where the shell's history and other users can read it.` +
        (leaked ? ' One of the arguments looks like one: change that password, which is in your shell history now.' : ''),
    );
  }
  const backupLogin = values['backup-login'];
  const problem = backupLogin === undefined ? null : backupLoginProblem(backupLogin);
  if (problem !== null) throw new MigrateError(problem);
  return { yes: values.yes, ...(backupLogin === undefined ? {} : { backupLogin }) };
}

function count(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

function redact(text: string, secrets: string[]): string {
  return secrets.filter((secret) => secret.length > 0).reduce((shown, secret) => shown.split(secret).join('…'), text);
}

function fail(out: Output, message: string, code = 1): never {
  const s = style(out);
  out.write(`${s.red('✗')} ${message}\n`);
  process.exit(code);
}

