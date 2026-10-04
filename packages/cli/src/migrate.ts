// `coffre migrate`: bring a database up to the schema a version of coffre
// ships, with the migrations this CLI carries, which are its version's.
//
// In a deployment's folder, as its pipeline runs it before the deploy: the
// deployment's own migrations, so this CLI must be the version it pins. It
// needs no session and asks no instance, which runs the previous version
// until the deploy, by design.
//
// Anywhere else, an instance's: it says which version it runs and how far
// its database is (`/me`, to owners and root admins), so this CLI goes ahead
// only when it is that same version, and asks it afterwards whether it sees
// the new schema and is ready.
//
// Either way it reads the database owner's direct URL from the file
// --database-url-file names, stdin for `-`, or a hidden prompt, never the
// command line; shows what it will apply; and applies it under the migration
// lock, with the privileges reasserted. Without a terminal, only with --yes.
import { parseArgs } from 'node:util';

import type { InstanceState } from '@coffre/client';
import { DatabaseAhead, migrateDatabase, migrationStatus } from '@coffre/db/migrate';

import { readDatabaseUrl } from './database-url.ts';
import { coffrePins, deploymentKind } from './deployment.ts';
import { type Step, StepFailed, Steps } from './steps.ts';
import { Cancelled, type Keyboard, listed, openTerminal, type Output, release, style } from './tty.ts';
import { cliVersion } from './version.ts';

/** What `coffre migrate` asks of the instance. */
export type Instance = {
  origin: string;
  /** Who is asking, and what the instance tells them of itself: nothing unless they are an owner. */
  me(): Promise<{ principal: { id: string }; instance: InstanceState | null }>;
  /** Its `/readyz`, as a monitor reads it. */
  ready(): Promise<{ ok: boolean; heartbeatAgeSeconds: number | null; checkpointed: boolean }>;
};

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

/** The migrations a database that has applied `applied` of `known` still lacks. */
export function pendingOf(state: InstanceState): string[] {
  return state.migrations.known.slice(state.migrations.applied);
}

/**
 * Why this CLI may not migrate an instance that runs `deployed`: it would
 * apply its own migrations, not the instance's. Null when they agree.
 */
export function versionProblem(cli: string, deployed: string, origin: string): string | null {
  if (cli === deployed) return null;
  return newer(deployed, cli)
    ? `${origin} runs coffre ${deployed}, and this CLI is ${cli}: run \`coffre update\` (to ${deployed}), then \`coffre migrate\` again`
    : `${origin} runs coffre ${deployed}, and this CLI is ${cli}, whose migrations it does not know yet: deploy ${cli} first, ` +
        `or migrate with the CLI it runs, \`npx @coffre/cli@${deployed} migrate\``;
}

/** Whether version `a` comes after `b`, by their numbers. */
function newer(a: string, b: string): boolean {
  const parts = (version: string) => version.split(/[.-]/).map((part) => Number.parseInt(part, 10) || 0);
  const [x, y] = [parts(a), parts(b)];
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) > (y[i] ?? 0);
  }
  return false;
}

/**
 * A migration's refusal, as Postgres raised it: the migration's own sentence,
 * not the SQL around it. `0001_remove_syncs` refuses while syncs remain.
 */
export function migrationFailure(error: unknown): string {
  for (let cause: unknown = error; cause instanceof Error; cause = cause.cause) {
    const code = (cause as { code?: unknown }).code;
    if (typeof code === 'string' && /^[0-9A-Z]{5}$/.test(code)) {
      return `${cause.message}. Nothing was changed: the migrations run in one transaction.`;
    }
  }
  return error instanceof Error ? error.message : String(error);
}

type Options = { yes: boolean; file: string | undefined };

/**
 * `connect` reaches the instance: the current one, or the one `--url` names,
 * with your session there. `session` names the session flags given, which
 * a deployment's folder has no use for.
 */
export async function migrate(args: string[], connect: () => Instance, session: string[]): Promise<void> {
  const secrets: string[] = [];
  const clean = (error: unknown) => redact(error instanceof Error ? error.message : String(error), secrets);
  let options: Options;
  try {
    options = parseOptions(args);
  } catch (error) {
    return fail(process.stderr, clean(error));
  }
  const { yes } = options;
  const terminal = openTerminal();
  const out = terminal?.out ?? process.stderr;
  const s = style(out);
  try {
    const deployment = deploymentAt(process.cwd());
    if (deployment !== null) {
      await migrateDeployment(deployment, options, session, out, terminal, secrets, clean);
      return;
    }
    const instance = connect();
    // Before anything is asked: whether there is anything to do, and whether this CLI may do it.
    const me = await instance.me();
    if (me.instance === null) {
      throw new MigrateError(
        `${instance.origin} tells only its owners and root admins its version, and you are signed in as ${me.principal.id}: ask one of them to run coffre migrate`,
      );
    }
    const problem = versionProblem(cliVersion(), me.instance.version, instance.origin);
    if (problem !== null) throw new MigrateError(problem);
    const pending = pendingOf(me.instance);
    if (pending.length === 0) {
      out.write(`${s.green('✓')} ${instance.origin}'s database is up to date, at coffre ${me.instance.version}'s schema\n`);
      return;
    }
    if (!yes && terminal === null) {
      throw new MigrateError('nothing here to confirm on: run coffre migrate on a terminal, or pass --yes to apply without asking');
    }

    if (s.ansi) out.write(`\n  ${s.bold('coffre migrate')}  ${s.dim(`${instance.origin}, coffre ${me.instance.version}`)}\n\n`);
    out.write(`  ${count(pending.length, 'migration')} to apply: ${listed(pending, 'and')}\n\n`);
    const { url, secrets: typed } = await readDatabaseUrl(out, s, {
      file: options.file,
      question: "The database owner's connection string",
      hint: "Hidden as you type. The login that owns coffre's tables, direct: not a runtime login, not Hyperdrive.",
      command: 'coffre migrate',
    });
    secrets.push(...typed);
    await run(url, instance, pending, out, () => terminal?.keys ?? null, yes, clean);
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
  session: string[],
  out: Output,
  terminal: { keys: Keyboard } | null,
  secrets: string[],
  clean: (error: unknown) => string,
): Promise<void> {
  const s = style(out);
  if (session.length > 0) {
    throw new MigrateError(
      `${listed(session, 'and')} ${session.length === 1 ? 'says' : 'say'} which instance to ask and how, and in a deployment's folder coffre migrate asks none: ` +
        `it migrates the database with ${deployment.dir}'s own migrations, before the deploy`,
    );
  }
  const problem = pinProblem(cliVersion(), deployment.version);
  if (problem !== null) throw new MigrateError(problem);

  if (s.ansi) out.write(`\n  ${s.bold('coffre migrate')}  ${s.dim(`this deployment, coffre ${deployment.version}`)}\n\n`);
  const { url, secrets: typed } = await readDatabaseUrl(out, s, {
    file: options.file,
    question: "The database owner's connection string",
    hint: "Hidden as you type. The login that owns coffre's tables, direct: not a runtime login, not Hyperdrive.",
    command: 'coffre migrate',
  });
  secrets.push(...typed);
  const where = `${url.hostname}${decodeURIComponent(url.pathname)}`;
  let status: { applied: string[]; pending: string[] };
  try {
    status = await migrationStatus(url.href);
  } catch (error) {
    if (!(error instanceof DatabaseAhead)) throw error;
    throw new MigrateError(
      `${where} is ahead of coffre ${deployment.version}: ${error.message.replace(/^the database /, '')}. ` +
        'Deploy that version, or, to go back, restore the database from before it (docs/restore.md). Nothing was changed',
    );
  }
  const { applied, pending } = status;
  if (pending.length === 0) {
    out.write(`${s.green('✓')} ${where} is up to date, at coffre ${deployment.version}'s schema: ${count(applied.length, 'migration')}, the last ${applied.at(-1)}\n`);
    return;
  }
  if (!options.yes && terminal === null) {
    throw new MigrateError('nothing here to confirm on: run coffre migrate on a terminal, or pass --yes to apply without asking');
  }
  out.write(`  ${count(pending.length, 'migration')} to apply to ${where}, for coffre ${deployment.version}: ${listed(pending, 'and')}\n\n`);
  const steps = new Steps(out, [`Apply ${listed(pending, 'and')}`], () => terminal?.keys ?? null, clean);
  try {
    await steps.run(0, (step) => apply(url, where, pending, step, options.yes));
  } finally {
    steps.end();
  }
}

/** Apply `pending` to the database, asking first unless told yes; what the instance's steps and the deployment's share. */
async function apply(url: URL, where: string, pending: string[], step: Step, yes: boolean): Promise<string> {
  if (!yes && !(await step.ask(`Apply ${count(pending.length, 'migration')} to ${where}?`))) throw new Cancelled();
  step.note(`Applying ${listed(pending, 'and')}`);
  try {
    await migrateDatabase(url.href, (plan) => {
      // Under the lock now: what was read before, or another run got there first.
      if (plan.pending.join() !== pending.join()) {
        throw new MigrateError(`another migration ran meanwhile: ${where} now lacks ${listed(plan.pending, 'and') || 'nothing'}`);
      }
    });
  } catch (error) {
    if (error instanceof MigrateError) throw error;
    throw new MigrateError(migrationFailure(error));
  }
  return `Applied ${listed(pending, 'and')}, and reasserted the database's privileges`;
}

/**
 * The steps: read the database's history and hold it to what the instance
 * reported, so that a URL to another database stops here; show what will be
 * applied and ask; apply it; then ask the instance what it now sees.
 */
async function run(
  url: URL,
  instance: Instance,
  pending: string[],
  out: Output,
  keys: () => Keyboard | null,
  yes: boolean,
  clean: (error: unknown) => string,
): Promise<void> {
  const where = `${url.hostname}${decodeURIComponent(url.pathname)}`;
  const steps = new Steps(
    out,
    [`Read ${where}'s migrations`, `Apply ${listed(pending, 'and')}`, `Check ${instance.origin} sees them`],
    keys,
    clean,
  );
  try {
    await steps.run(0, async () => {
      const status = await migrationStatus(url.href);
      if (status.pending.join() !== pending.join()) {
        throw new MigrateError(
          `${where} lacks ${status.pending.length === 0 ? 'no migration' : listed(status.pending, 'and')}, ` +
            `but ${instance.origin} reports ${listed(pending, 'and')} pending: is this its database? Nothing was changed`,
        );
      }
      return {
        text: `${where} has ${count(status.applied.length, 'migration')} applied, the last ${status.applied.at(-1) ?? 'none'}`,
        details: [],
      };
    });
    await steps.run(1, (step) => apply(url, where, pending, step, yes));
    await steps.run(2, async () => {
      const after = (await instance.me()).instance;
      const left = after === null ? pending : pendingOf(after);
      if (left.length > 0) {
        throw new MigrateError(`${instance.origin} still reports ${listed(left, 'and')} pending: is the URL its database's?`);
      }
      const ready = await instance.ready();
      if (!ready.ok) {
        throw new MigrateError(
          `${instance.origin} sees the new schema, but is not ready: ` +
            (ready.heartbeatAgeSeconds === null
              ? 'it has no audit heartbeat yet'
              : !ready.checkpointed
                ? 'no checkpoint signed by the vault covers its last heartbeat'
                : `its last heartbeat is ${Math.round(ready.heartbeatAgeSeconds)}s old`) +
            '. The migration is applied; see /readyz',
        );
      }
      return `${instance.origin} sees the new schema, and is ready`;
    });
  } finally {
    steps.end();
  }
}

function parseOptions(args: string[]): Options {
  try {
    const { values } = parseArgs({
      args,
      options: { yes: { type: 'boolean', default: false }, 'database-url-file': { type: 'string' } },
      strict: true,
    });
    const file = values['database-url-file'];
    if (file !== undefined && /postgres(ql)?:/i.test(file)) throw new Error('a database URL');
    return { yes: values.yes, file };
  } catch {
    // The error would quote the argument, which may be the connection string itself.
    const leaked = args.some((arg) => /postgres(ql)?:|@/i.test(arg));
    throw new MigrateError(
      'coffre migrate takes only --yes and --database-url-file; the session flags, --url among them, go before it: coffre --url <url> migrate. ' +
        `It reads the database owner's connection string from a hidden prompt, ` +
        `or the file --database-url-file names, - for stdin, never from the command line, where the shell's history and other users can read it.` +
        (leaked ? ' One of the arguments looks like one: change that password, which is in your shell history now.' : ''),
    );
  }
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

